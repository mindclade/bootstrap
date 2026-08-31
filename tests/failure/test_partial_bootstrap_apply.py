# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
"""Failure tests for plan/evidence integrity after a partial bootstrap attempt."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


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
            not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts
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


class PartialBootstrapApplyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.bootstrapctl = build_bootstrapctl(cls._temporary.name)
        cls.repository_root = repository_root(cls.bootstrapctl, cls._temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def saved_plan_fixture(
        self,
        directory,
        *,
        root_name="root-trust",
        initial_local_backend=False,
        mutated_entry=None,
    ):
        directory = Path(directory)
        opentofu_root = directory / "opentofu"
        shutil.copytree(self.repository_root / "opentofu", opentofu_root)
        root_directory = opentofu_root / "live" / root_name
        lock = b'provider "registry.opentofu.org/hashicorp/google" {\n  version = "7.42.0"\n}\n'
        provider_lock = directory / "generated-provider.lock.hcl"
        provider_lock.write_bytes(lock)
        if root_name == "root-trust":
            modules = {
                "audit_root": "audit-root",
                "break_glass": "break-glass",
                "buildkite_federation": "buildkite-federation",
                "github_federation": "github-federation",
                "gitops_federation": "gitops-federation",
                "recovery_state": "state-backend",
                "root_state": "state-backend",
                "signing_root": "signing-root",
                "workforce_identity": "workforce-identity",
            }
        elif root_name == "recovery-plane":
            modules = {"recovery_exports": "recovery-exports"}
        else:
            raise ValueError(f"unsupported fixture root: {root_name}")
        inventory = [{"Key": "", "Dir": "."}]
        inventory.extend(
            {
                "Key": key,
                "Source": f"../../modules/{folder}",
                "Dir": f"../../modules/{folder}",
            }
            for key, folder in modules.items()
        )
        root_files = ["main.tf", "outputs.tf", "providers.tf", "versions.tf"]
        if not initial_local_backend:
            root_files.insert(0, "backend.tf")
        archived_sources = {f"tfconfig/m-/{name}": root_directory / name for name in root_files}
        for key, folder in modules.items():
            for name in ("main.tf", "outputs.tf", "variables.tf"):
                archived_sources[f"tfconfig/m-{key}/{name}"] = (
                    opentofu_root / "modules" / folder / name
                )
        plan = directory / "tfplan"
        with zipfile.ZipFile(plan, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("tfplan", b"opaque-pinned-plan")
            archive.writestr("tfstate", b"{}")
            archive.writestr("tfstate-prev", b"{}")
            archive.writestr(".terraform.lock.hcl", lock)
            archive.writestr(
                "tfconfig/modules.json",
                json.dumps(inventory, separators=(",", ":")).encode(),
            )
            for name, source in archived_sources.items():
                content = source.read_bytes()
                if name == mutated_entry:
                    content += b"\n# unreviewed plan-only source\n"
                archive.writestr(name, content)
        return plan, opentofu_root, provider_lock

    def run_plan_source_check(
        self, plan, opentofu_root, provider_lock, *extra, root_name="root-trust"
    ):
        return subprocess.run(
            [
                str(self.bootstrapctl),
                "plan-source-check",
                "--root",
                root_name,
                "--opentofu-root",
                str(opentofu_root),
                "--provider-lock",
                str(provider_lock),
                "--saved-plan",
                str(plan),
                *extra,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_saved_plan_embeds_only_the_exact_reviewed_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            safe_directory = Path(directory) / "safe"
            safe_directory.mkdir()
            plan, opentofu_root, provider_lock = self.saved_plan_fixture(safe_directory)
            result = self.run_plan_source_check(plan, opentofu_root, provider_lock)
            self.assertEqual(result.returncode, 0, result.stderr)

            unsafe_directory = Path(directory) / "unsafe"
            unsafe_directory.mkdir()
            plan, opentofu_root, provider_lock = self.saved_plan_fixture(
                unsafe_directory,
                mutated_entry="tfconfig/m-signing_root/main.tf",
            )
            result = self.run_plan_source_check(plan, opentofu_root, provider_lock)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match the reviewed source bytes", result.stderr)

    def test_initial_local_backend_is_the_only_source_snapshot_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, opentofu_root, provider_lock = self.saved_plan_fixture(
                directory,
                initial_local_backend=True,
            )
            result = self.run_plan_source_check(
                plan,
                opentofu_root,
                provider_lock,
                "--initial-local-backend",
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            result = self.run_plan_source_check(plan, opentofu_root, provider_lock)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("saved plan archive must contain exactly", result.stderr)

    def test_recovery_plan_embeds_the_exact_recovery_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            plan, opentofu_root, provider_lock = self.saved_plan_fixture(
                directory,
                root_name="recovery-plane",
            )
            result = self.run_plan_source_check(
                plan,
                opentofu_root,
                provider_lock,
                root_name="recovery-plane",
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            result = self.run_plan_source_check(
                plan,
                opentofu_root,
                provider_lock,
                "--initial-local-backend",
                root_name="recovery-plane",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("only for root-trust", result.stderr)

    def test_tampered_partial_plan_invalidates_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            plan = directory / "plan.json"
            evidence = directory / "evidence.json"
            plan.write_text(
                json.dumps(
                    {
                        "format_version": "1.2",
                        "terraform_version": "1.12.6",
                        "resource_changes": [
                            {
                                "address": (
                                    'module.root_state.google_storage_bucket.state["primary"]'
                                ),
                                "mode": "managed",
                                "type": "google_storage_bucket",
                                "change": {
                                    "actions": ["create"],
                                    "after": {
                                        "project": "bootstrap-state-root",
                                        "name": "bootstrap-root-trust-state",
                                        "location": "US-CENTRAL1",
                                        "storage_class": "STANDARD",
                                        "deletion_policy": "PREVENT",
                                        "uniform_bucket_level_access": True,
                                        "public_access_prevention": "enforced",
                                        "force_destroy": False,
                                        "versioning": [{"enabled": True}],
                                        "encryption": [{"default_kms_key_name": "kms-key"}],
                                        "soft_delete_policy": [
                                            {"retention_duration_seconds": 2592000}
                                        ],
                                        "lifecycle_rule": [
                                            {
                                                "action": [{"type": "Delete"}],
                                                "condition": [
                                                    {
                                                        "days_since_noncurrent_time": 365,
                                                        "num_newer_versions": 3,
                                                        "send_age_if_zero": False,
                                                    }
                                                ],
                                            }
                                        ],
                                    },
                                    "after_unknown": {},
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            create = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "evidence",
                    "create",
                    "--repository-root",
                    str(self.repository_root),
                    "--root",
                    "root-trust",
                    "--plan",
                    str(plan),
                    "--output",
                    str(evidence),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            plan.write_text(
                '{"format_version":"1.2","terraform_version":"1.12.6","resource_changes":[]}',
                encoding="utf-8",
            )
            verify = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "evidence",
                    "verify",
                    "--repository-root",
                    str(self.repository_root),
                    "--plan",
                    str(plan),
                    "--evidence",
                    str(evidence),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(verify.returncode, 0)
            self.assertIn("plan digest mismatch", verify.stderr)

    def test_empty_noop_plan_is_not_a_configured_reconciliation(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.12.6",
                    "resource_changes": [],
                },
                handle,
            )
            handle.flush()
            result = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "plan-check",
                    "--root",
                    "root-trust",
                    "--plan",
                    handle.name,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configured Ring-0 resources", result.stderr)

    def test_tampered_evidence_summary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            plan = directory / "plan.json"
            evidence = directory / "evidence.json"
            plan.write_text(
                '{"format_version":"1.2","terraform_version":"1.12.6","resource_changes":[]}',
                encoding="utf-8",
            )
            create = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "evidence",
                    "create",
                    "--repository-root",
                    str(self.repository_root),
                    "--root",
                    "root-trust",
                    "--plan",
                    str(plan),
                    "--output",
                    str(evidence),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            payload["summary"]["creates"] = 1
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            verify = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "evidence",
                    "verify",
                    "--repository-root",
                    str(self.repository_root),
                    "--plan",
                    str(plan),
                    "--evidence",
                    str(evidence),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(verify.returncode, 0)
            self.assertIn("plan summary mismatch", verify.stderr)

    def test_evidence_round_trip_is_valid_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            plan = directory / "plan.json"
            evidence = directory / "evidence.json"
            plan.write_text(
                '{"format_version":"1.2","terraform_version":"1.12.6","resource_changes":[]}',
                encoding="utf-8",
            )
            evidence.write_text("replace me", encoding="utf-8")
            evidence.chmod(0o644)
            create = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "evidence",
                    "create",
                    "--repository-root",
                    str(self.repository_root),
                    "--root",
                    "recovery-plane",
                    "--plan",
                    str(plan),
                    "--output",
                    str(evidence),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(create.returncode, 0, create.stderr)
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["sourceTreeSha256"]), 64)
            verify = subprocess.run(
                [
                    str(self.bootstrapctl),
                    "evidence",
                    "verify",
                    "--repository-root",
                    str(self.repository_root),
                    "--plan",
                    str(plan),
                    "--evidence",
                    str(evidence),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_approval_receipt_requires_two_distinct_signers_and_exact_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            keys = []
            approvers = []
            for index, principal in enumerate(
                ("user:platform@example.com", "user:security@example.com"), 1
            ):
                private_key = directory / f"approver-{index}.key"
                public_key = directory / f"approver-{index}.pem"
                public_der = directory / f"approver-{index}.der"
                subprocess.run(
                    [
                        "openssl",
                        "ecparam",
                        "-name",
                        "prime256v1",
                        "-genkey",
                        "-noout",
                        "-out",
                        str(private_key),
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "openssl",
                        "pkey",
                        "-in",
                        str(private_key),
                        "-pubout",
                        "-out",
                        str(public_key),
                    ],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "openssl",
                        "pkey",
                        "-pubin",
                        "-in",
                        str(public_key),
                        "-outform",
                        "DER",
                        "-out",
                        str(public_der),
                    ],
                    check=True,
                    capture_output=True,
                )
                keys.append((private_key, public_key))
                approvers.append(
                    {
                        "principal": principal,
                        "publicKeySha256": hashlib.sha256(public_der.read_bytes()).hexdigest(),
                    }
                )

            receipt = {
                "schemaVersion": "mindclade.bootstrap/approval-receipt/v1",
                "operation": "apply",
                "sourceSha": "b" * 40,
                "root": "root-trust",
                "subjectKind": "opentofu-saved-plan",
                "subjectSha256": "a" * 64,
                "planRunId": "12345",
                "issuedAt": "2026-08-30T12:00:00Z",
                "expiresAt": "2026-08-30T13:00:00Z",
                "approvers": approvers,
            }
            receipt_path = directory / "receipt.json"
            receipt_path.write_text(json.dumps(receipt, separators=(",", ":")), encoding="utf-8")
            signature_paths = []
            for index, (private_key, _) in enumerate(keys, 1):
                signature = directory / f"signature-{index}.bin"
                subprocess.run(
                    [
                        "openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        str(private_key),
                        "-out",
                        str(signature),
                        str(receipt_path),
                    ],
                    check=True,
                    capture_output=True,
                )
                signature_paths.append(signature)

            command = [
                str(self.bootstrapctl),
                "approval",
                "verify",
                "--receipt",
                str(receipt_path),
                "--public-key-1",
                str(keys[0][1]),
                "--public-key-2",
                str(keys[1][1]),
                "--signature-1",
                str(signature_paths[0]),
                "--signature-2",
                str(signature_paths[1]),
                "--operation",
                "apply",
                "--source-sha",
                "b" * 40,
                "--root",
                "root-trust",
                "--subject-kind",
                "opentofu-saved-plan",
                "--subject-sha256",
                "a" * 64,
                "--plan-run-id",
                "12345",
                "--now",
                "2026-08-30T12:15:00Z",
            ]
            verified = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(verified.returncode, 0, verified.stderr)

            wrong_source = command.copy()
            source_index = wrong_source.index("--source-sha") + 1
            wrong_source[source_index] = "c" * 40
            rejected = subprocess.run(wrong_source, text=True, capture_output=True, check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("does not match the exact requested", rejected.stderr)

            expired = command.copy()
            now_index = expired.index("--now") + 1
            expired[now_index] = "2026-08-30T13:00:00Z"
            rejected = subprocess.run(expired, text=True, capture_output=True, check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not currently valid", rejected.stderr)

            receipt["approvers"][1]["principal"] = "user:platform@example.com"
            receipt_path.write_text(json.dumps(receipt, separators=(",", ":")), encoding="utf-8")
            rejected = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("distinct and sorted", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
