"""Tests that recovery verification is isolated from downstream control planes."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


def runfiles_source_root():
    runfiles = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if not runfiles:
        return None
    runfiles_root = Path(runfiles)
    workspace = os.environ.get("TEST_WORKSPACE", "_main")
    candidates = [runfiles_root / "_main", runfiles_root / workspace]
    for candidate in candidates:
        if (candidate / "component.yaml").is_file():
            return candidate
    raise RuntimeError("cannot locate the bootstrap source root in Bazel runfiles")


def local_repository_root():
    if runfiles_source_root() is not None:
        raise RuntimeError("Bazel tests must use a staged runfiles repository")
    return Path(__file__).resolve().parents[2]


def build_bootstrapctl(destination):
    configured = os.environ.get("BOOTSTRAPCTL")
    if configured:
        return Path(configured)
    source_root = runfiles_source_root()
    if source_root is not None:
        candidate = source_root / "tooling" / "bootstrapctl_" / "bootstrapctl"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        raise RuntimeError("cannot locate bootstrapctl in Bazel runfiles")
    binary = Path(destination) / "bootstrapctl"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/bootstrapctl"],
        cwd=local_repository_root() / "tooling",
        check=True,
    )
    return binary


def repository_root(bootstrapctl, destination):
    source_root = runfiles_source_root()
    if source_root is None:
        return local_repository_root()
    result = subprocess.run(
        [str(bootstrapctl), "source-files"],
        text=True,
        capture_output=True,
        check=True,
    )
    relative_paths = json.loads(result.stdout)
    if (
        not isinstance(relative_paths, list)
        or not relative_paths
        or relative_paths != sorted(set(relative_paths))
        or any(
            not isinstance(value, str)
            or Path(value).is_absolute()
            or ".." in Path(value).parts
            for value in relative_paths
        )
    ):
        raise RuntimeError("bootstrapctl returned an invalid source file list")
    staged_root = Path(destination) / "repository"
    staged_root.mkdir(mode=0o700)
    for relative in relative_paths:
        source = source_root / relative
        if not source.is_file():
            raise RuntimeError(f"missing declared runfile: {relative}")
        target = staged_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    staged_paths = sorted(
        path.relative_to(staged_root).as_posix()
        for path in staged_root.rglob("*")
        if path.is_file()
    )
    if staged_paths != relative_paths or any(path.is_symlink() for path in staged_root.rglob("*")):
        raise RuntimeError("staged repository does not contain exactly the declared regular files")
    return staged_root


class IsolatedRestoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.bootstrapctl = build_bootstrapctl(cls._temporary.name)
        cls.repository_root = repository_root(cls.bootstrapctl, cls._temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def verify(self, root):
        clean_environment = {
            "PATH": os.environ.get("PATH", ""),
        }
        return subprocess.run(
            [str(self.bootstrapctl), "recovery-verify", "--root", str(root)],
            env=clean_environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_restore_contract_requires_no_primary_credentials(self):
        result = self.verify(self.repository_root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"mode": "isolated-source-simulation"', result.stdout)
        self.assertIn('"status": "source-qualified"', result.stdout)

    def test_workflow_distinguishes_source_simulation_from_connected_evidence(self):
        workflow = (
            self.repository_root / ".github" / "workflows" / "recovery-verification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('--arg mode "offline-source-simulation"', workflow)
        self.assertIn('--arg result "source-qualified"', workflow)
        self.assertIn('name: connected-read-only-verification', workflow)
        self.assertIn('primaryReplicaExportBytesEqual: true', workflow)
        self.assertIn('publicTrustMetadataSha256:', workflow)
        self.assertIn('publicTrustMetadataGeneration:', workflow)
        self.assertIn('restoreInventorySha256:', workflow)
        self.assertIn('restoreInventoryGeneration:', workflow)
        self.assertIn('primaryGeneration: $primaryGeneration', workflow)
        self.assertIn('replicaGeneration: $replicaGeneration', workflow)
        self.assertIn('exportGeneration: $exportGeneration', workflow)
        self.assertNotIn(
            'gcloud storage cat "gs://${primary_bucket}/${state_prefix}/default.tfstate"',
            workflow,
        )
        self.assertNotIn('--arg result "restored"', workflow)

    def test_connected_observation_and_apply_share_one_mutex(self):
        recovery_workflow = (
            self.repository_root / ".github" / "workflows" / "recovery-verification.yml"
        ).read_text(encoding="utf-8")
        apply_workflow = (
            self.repository_root / ".github" / "workflows" / "protected-apply.yml"
        ).read_text(encoding="utf-8")
        group = "group: bootstrap-ring0-state-mutation-observation"
        self.assertIn(group, recovery_workflow)
        self.assertIn(group, apply_workflow)

    def test_same_primary_and_recovery_backend_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(".git", "bazel-*", "__pycache__", ".terraform"),
            )
            path = clone / "recovery" / "restore-manifest.yaml"
            content = path.read_text(encoding="utf-8")
            content = content.replace(
                "backend: RECOVERY_STATE_BACKEND", "backend: ROOT_TRUST_STATE_BACKEND"
            )
            path.write_text(content, encoding="utf-8")
            result = self.verify(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be present and distinct", result.stderr)

    def test_unknown_restore_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(".git", "bazel-*", "__pycache__", ".terraform"),
            )
            path = clone / "recovery" / "restore-manifest.yaml"
            path.write_text(
                path.read_text(encoding="utf-8") + "\nunapprovedField: true\n",
                encoding="utf-8",
            )
            result = self.verify(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("field unapprovedField not found", result.stderr)

    def test_runtime_reference_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(".git", "bazel-*", "__pycache__", ".terraform"),
            )
            path = clone / "recovery" / "restore-manifest.yaml"
            content = path.read_text(encoding="utf-8").replace(
                "ROOT_TRUST_STATE_GENERATION", "UNREVIEWED_STATE_GENERATION"
            )
            path.write_text(content, encoding="utf-8")
            result = self.verify(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must equal the reviewed reference", result.stderr)

    def test_dependency_name_substrings_do_not_satisfy_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(".git", "bazel-*", "__pycache__", ".terraform"),
            )
            path = clone / "recovery" / "restore-manifest.yaml"
            content = path.read_text(encoding="utf-8").replace("- GKE", "- not-gke")
            path.write_text(content, encoding="utf-8")
            result = self.verify(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not in the reviewed restore contract", result.stderr)

    def test_duplicate_forbidden_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(".git", "bazel-*", "__pycache__", ".terraform"),
            )
            path = clone / "recovery" / "restore-manifest.yaml"
            content = path.read_text(encoding="utf-8").replace(
                "      - Argo CD", "      - GKE"
            )
            path.write_text(content, encoding="utf-8")
            result = self.verify(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be unique", result.stderr)


if __name__ == "__main__":
    unittest.main()
