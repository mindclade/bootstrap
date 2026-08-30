"""Contract tests for the exact bootstrap tree and manifest schemas."""

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


def valid_render_values():
    """Return the complete, non-secret external-value contract for root trust."""
    return {
        "AUDIT_ANCHOR_SIGNER": "serviceAccount:audit-signer@mindclade-signing-root.iam.gserviceaccount.com",
        "AUDIT_COMPLIANCE_READER_GROUP": "group:audit-compliance@example.com",
        "AUDIT_PRIMARY_KMS_KEY": "audit-primary",
        "AUDIT_RECOVERY_KMS_KEY": "audit-recovery",
        "AUDIT_SECURITY_READER_GROUP": "group:audit-security@example.com",
        "BOOTSTRAP_HANDOFF_SIGNER": "serviceAccount:handoff-signer@mindclade-signing-root.iam.gserviceaccount.com",
        "BREAK_GLASS_APPROVER_1": "user:security-approver-1@example.com",
        "BREAK_GLASS_APPROVER_2": "user:security-approver-2@example.com",
        "BREAK_GLASS_NOTIFICATION_RECIPIENT": "security-operations@example.com",
        "BREAK_GLASS_REQUESTER_1": "user:platform-requester-1@example.com",
        "BREAK_GLASS_REQUESTER_2": "user:platform-requester-2@example.com",
        "BUILDKITE_OIDC_AUDIENCE": "https://buildkite.com/mindclade/bootstrap",
        "BUILDKITE_OIDC_ISSUER_URI": "https://agent.buildkite.com",
        "BUILDKITE_ORGANIZATION_SLUG": "mindclade",
        "BUILDKITE_PIPELINE_ID": "0184990a-4782-42b5-afc1-16715b10b8ff",
        "BUILDKITE_PIPELINE_SLUG": "bootstrap",
        "GCP_AUDIT_ROOT_PROJECT_ID": "mindclade-audit-root",
        "GCP_BILLING_ACCOUNT_ID": "ABCDEF-123456-ABCDEF",
        "GCP_IDENTITY_ROOT_PROJECT_ID": "mindclade-identity-root",
        "GCP_ORGANIZATION_ID": "123456789012",
        "GCP_RECOVERY_ROOT_PROJECT_ID": "mindclade-recovery-root",
        "GCP_SIGNING_ROOT_PROJECT_ID": "mindclade-signing-root",
        "GCP_STATE_ROOT_PROJECT_ID": "mindclade-state-root",
        "GITHUB_APPLY_WORKFLOW_REF": "mindclade/bootstrap/.github/workflows/protected-apply.yml@refs/heads/main",
        "GITHUB_OIDC_AUDIENCE": "https://github.com/mindclade/bootstrap",
        "GITHUB_OIDC_ISSUER_URI": "https://token.actions.githubusercontent.com",
        "GITHUB_REPOSITORY_ID": "987654321",
        "GITHUB_REPOSITORY_OWNER_ID": "12345678",
        "GITOPS_IMMUTABLE_SUBJECT": "repo:mindclade/platform-gitops:ref:refs/heads/main",
        "GITOPS_OIDC_AUDIENCE": "https://gitops.example.com/mindclade/bootstrap",
        "GITOPS_OIDC_ISSUER_URI": "https://gitops.example.com",
        "GITOPS_REPOSITORY": "mindclade/platform-gitops",
        "KMS_ADMIN_PRINCIPAL_1": "group:kms-administrators@example.com",
        "KMS_ADMIN_PRINCIPAL_2": "group:kms-security@example.com",
        "RECOVERY_ADMIN_GROUP": "group:recovery-administrators@example.com",
        "RECOVERY_EVIDENCE_SIGNER": "serviceAccount:recovery-signer@mindclade-signing-root.iam.gserviceaccount.com",
        "RECOVERY_EXPORT_KMS_KEY": "recovery-export",
        "RECOVERY_STATE_BUCKET": "mindclade-recovery-state",
        "RECOVERY_STATE_KMS_KEY": "recovery-state",
        "RECOVERY_STATE_REPLICA_BUCKET": "mindclade-recovery-state-replica",
        "RECOVERY_STATE_REPLICA_KMS_KEY": "recovery-state-replica",
        "ROOT_TRUST_ADMIN_GROUP": "group:root-trust-administrators@example.com",
        "ROOT_TRUST_STATE_BUCKET": "mindclade-root-trust-state",
        "ROOT_TRUST_STATE_KMS_KEY": "root-trust-state",
        "ROOT_TRUST_STATE_REPLICA_BUCKET": "mindclade-root-trust-state-replica",
        "ROOT_TRUST_STATE_REPLICA_KMS_KEY": "root-trust-state-replica",
        "SECURITY_APPROVER_GROUP": "group:security-approvers@example.com",
        "WORKFORCE_ADMIN_GROUP": "mindclade-workforce-administrators",
        "WORKFORCE_OIDC_CLIENT_ID": "mindclade-bootstrap",
        "WORKFORCE_OIDC_ISSUER_URI": "https://identity.example.com",
    }


def valid_recovery_context(values):
    project_number = "123456789012"
    provider_prefix = f"projects/{project_number}/locations/global/workloadIdentityPools"
    audience = values["GITHUB_OIDC_AUDIENCE"].rstrip("/")
    return {
        "federation": {
            "github": {
                "providers": {
                    role: f"{provider_prefix}/bootstrap-github-{role}/providers/github-actions-{role}"
                    for role in ("plan", "apply", "recovery")
                },
                "audiences": {
                    role: f"{audience}/{role}"
                    for role in ("plan", "apply", "recovery")
                },
            },
            "buildkite": {
                "provider": f"{provider_prefix}/bootstrap-buildkite/providers/buildkite",
                "audience": values["BUILDKITE_OIDC_AUDIENCE"],
            },
            "gitops": {
                "provider": f"{provider_prefix}/bootstrap-gitops/providers/gitops",
                "audience": values["GITOPS_OIDC_AUDIENCE"],
            },
        },
        "state_backends": {
            "root_trust": {
                "project_id": values["GCP_STATE_ROOT_PROJECT_ID"],
                "bucket": values["ROOT_TRUST_STATE_BUCKET"],
                "prefix": "root-trust",
                "replica_project_id": values["GCP_RECOVERY_ROOT_PROJECT_ID"],
                "replica_bucket": values["ROOT_TRUST_STATE_REPLICA_BUCKET"],
            },
            "recovery_plane": {
                "project_id": values["GCP_RECOVERY_ROOT_PROJECT_ID"],
                "bucket": values["RECOVERY_STATE_BUCKET"],
                "prefix": "recovery-plane",
                "replica_project_id": values["GCP_STATE_ROOT_PROJECT_ID"],
                "replica_bucket": values["RECOVERY_STATE_REPLICA_BUCKET"],
            },
        },
        "signing_roots": {
            name: {
                "primary_version": (
                    "projects/mindclade-signing-root/locations/us-central1/"
                    f"keyRings/bootstrap-signing/cryptoKeys/{name}/cryptoKeyVersions/1"
                )
            }
            for name in ("audit-anchor", "bootstrap-handoff", "recovery-evidence")
        },
    }


class ManifestSchemaContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory()
        cls.bootstrapctl = build_bootstrapctl(cls._temporary.name)
        cls.repository_root = repository_root(cls.bootstrapctl, cls._temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def validate(self, root):
        return subprocess.run(
            [str(self.bootstrapctl), "validate", "--root", str(root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def render_root(
        self,
        directory,
        values,
        output_name="bootstrap.auto.tfvars.json",
        repository_root=None,
    ):
        values_path = Path(directory) / "bootstrap-values.json"
        values_path.write_text(json.dumps(values), encoding="utf-8")
        output_path = Path(directory) / output_name
        result = subprocess.run(
            [
                str(self.bootstrapctl),
                "render-vars",
                "--root",
                str(repository_root or self.repository_root),
                "--composition",
                "root-trust",
                "--values",
                str(values_path),
                "--output",
                str(output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        return result, output_path

    def render_recovery(self, directory, values, context, output_name="recovery.auto.tfvars.json"):
        values_path = Path(directory) / "bootstrap-values.json"
        values_path.write_text(json.dumps(values), encoding="utf-8")
        context_path = Path(directory) / "recovery-context.json"
        context_path.write_text(json.dumps(context), encoding="utf-8")
        output_path = Path(directory) / output_name
        result = subprocess.run(
            [
                str(self.bootstrapctl),
                "render-vars",
                "--root",
                str(self.repository_root),
                "--composition",
                "recovery-plane",
                "--values",
                str(values_path),
                "--context",
                str(context_path),
                "--output",
                str(output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        return result, output_path

    def test_authoritative_repository_validates(self):
        result = self.validate(self.repository_root)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["files"], 96)
        self.assertEqual(payload["manifests"], 7)

    def test_every_schema_is_closed(self):
        schemas = sorted((self.repository_root / "schemas" / "v1").glob("*.schema.json"))
        self.assertEqual(len(schemas), 7)
        for path in schemas:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(schema.get("additionalProperties", True), path.name)
            self.assertEqual(schema.get("type"), "object", path.name)

    def test_provider_packages_are_installed_only_from_exact_hash_verified_mirrors(self):
        linux_amd64 = "zh:5b4bac33f039f94384a0b3468f63266fac023f69c00ebbc573d957b861f67171"
        darwin_arm64 = "zh:f028a366d9c7f427d3ed1a34df22c4476b6ebed4e8884b23e448ef1fb170eb44"
        justfile = (self.repository_root / "justfile").read_text(encoding="utf-8")
        workflow = (
            self.repository_root / ".github" / "workflows" / "protected-apply.yml"
        ).read_text(encoding="utf-8")
        for checksum in (linux_amd64.removeprefix("zh:"), darwin_arm64.removeprefix("zh:")):
            self.assertIn(checksum, justfile)
        self.assertIn(linux_amd64.removeprefix("zh:"), workflow)
        for content in (justfile, workflow):
            self.assertIn("providers mirror", content)
            self.assertIn("filesystem_mirror", content)
            self.assertIn('exclude = ["hashicorp/google"]', content)
            self.assertIn("terraform-provider-google_7.42.0_", content)
            self.assertIn('version     = "7.42.0"', content)
        self.assertGreaterEqual(workflow.count("Prepare the exact reviewed Google provider package"), 2)

    def test_custom_role_bindings_use_known_canonical_role_ids(self):
        cases = (
            (
                "opentofu/modules/audit-root/main.tf",
                'role    = "projects/${each.value.project_id}/roles/${google_project_iam_custom_role.plan_read[each.key].role_id}"',
                "role    = google_project_iam_custom_role.plan_read[each.key].name",
            ),
            (
                "opentofu/modules/signing-root/main.tf",
                'role          = "projects/${var.project_id}/roles/${google_project_iam_custom_role.recovery_metadata.role_id}"',
                "role          = google_project_iam_custom_role.recovery_metadata.name",
            ),
            (
                "opentofu/live/root-trust/main.tf",
                'role   = "organizations/${var.bootstrap.organization_id}/roles/${google_organization_iam_custom_role.plan_read.role_id}"',
                "role   = google_organization_iam_custom_role.plan_read.name",
            ),
            (
                "opentofu/live/root-trust/main.tf",
                'role   = "organizations/${var.bootstrap.organization_id}/roles/${google_organization_iam_custom_role.recovery_sink_read.role_id}"',
                "role   = google_organization_iam_custom_role.recovery_sink_read.name",
            ),
            (
                "opentofu/live/root-trust/main.tf",
                'role   = "organizations/${var.bootstrap.organization_id}/roles/${google_organization_iam_custom_role.apply_iam.role_id}"',
                "role   = google_organization_iam_custom_role.apply_iam.name",
            ),
        )
        for path_name, expected, computed_name in cases:
            with self.subTest(path=path_name, role=expected):
                content = (self.repository_root / path_name).read_text(encoding="utf-8")
                self.assertIn(expected, content)
                self.assertNotIn(computed_name, content)

    def test_federated_credentials_leave_the_checkout_before_validation(self):
        protected_apply = (
            self.repository_root / ".github" / "workflows" / "protected-apply.yml"
        ).read_text(encoding="utf-8")
        recovery = (
            self.repository_root / ".github" / "workflows" / "recovery-verification.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(protected_apply.count("GOOGLE_GHA_CREDS_PATH"), 2)
        self.assertGreaterEqual(protected_apply.count("${RUNNER_TEMP}/"), 2)
        self.assertIn("Move the generated recovery credentials outside the source tree", recovery)
        self.assertIn("GOOGLE_GHA_CREDS_PATH", recovery)

    def test_protected_apply_binds_backend_and_saved_plan_source_exactly(self):
        workflow = (
            self.repository_root / ".github" / "workflows" / "protected-apply.yml"
        ).read_text(encoding="utf-8")
        readme = (self.repository_root / "README.md").read_text(encoding="utf-8")
        self.assertNotIn(
            "inputs.root == 'root-trust' && vars.ROOT_TRUST_STATE_BUCKET",
            workflow,
        )
        self.assertGreaterEqual(
            workflow.count("Select the exact backend for the requested root"), 2
        )
        self.assertGreaterEqual(workflow.count("plan-source-check"), 2)
        self.assertIn("savedPlanSha256", workflow)
        self.assertIn("--initial-local-backend", readme)

    def test_source_qualification_installs_exact_hash_verified_just(self):
        checksum = "b0ef600f0df20d5ae91ae931627c499fc52b477ffe5f5ea7b7b3ec616b16c778"
        for name in ("pull-request.yml", "recovery-verification.yml"):
            workflow = (
                self.repository_root / ".github" / "workflows" / name
            ).read_text(encoding="utf-8")
            self.assertIn('JUST_VERSION: "1.55.1"', workflow)
            self.assertIn(checksum, workflow)
            self.assertIn("just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz", workflow)
            self.assertIn("sha256sum --check --strict", workflow)
            self.assertIn('= "just ${JUST_VERSION}"', workflow)

    def test_workflow_security_contract_fails_closed(self):
        cases = (
            (
                ".github/workflows/pull-request.yml",
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "actions/checkout@v7",
                "exact immutable allowlist",
            ),
            (
                ".github/workflows/pull-request.yml",
                "  pull_request:\n",
                "  pull_request_target:\n",
                "exactly the approved triggers",
            ),
            (
                ".github/workflows/protected-apply.yml",
                "permissions:\n  contents: read\n",
                "permissions:\n  contents: write\n",
                "contents: read only",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "5dc43da4f750f33873dc25e94587128709e819e544b7be9016b255316153c3a8",
                "0dc43da4f750f33873dc25e94587128709e819e544b7be9016b255316153c3a8",
                "exact version, checksum",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                'cron: "17 7 1 1,4,7,10 *"',
                'cron: "0 0 * * *"',
                "exact quarterly schedule",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "if: github.event_name == 'workflow_dispatch' && inputs.connected",
                "if: always()",
                "manual-only",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "and ((.exclusions // []) == [])",
                "and true",
                "four exact enabled, exclusion-free",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "path: ${{ runner.temp }}/connected-evidence/",
                "path: ${{ runner.temp }}/recovery-inventory/",
                "only the exact redacted signed bundle",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "git diff --exit-code -- .",
                "git diff --quiet -- .",
                "recheck the checkout and live main SHA",
            ),
            (
                ".github/dependabot.yml",
                "package-ecosystem: opentofu",
                "package-ecosystem: terraform",
                "ecosystems and roots",
            ),
        )
        for path_name, original, replacement, diagnostic in cases:
            with self.subTest(path=path_name, mutation=replacement), tempfile.TemporaryDirectory() as directory:
                clone = Path(directory) / "bootstrap"
                shutil.copytree(
                    self.repository_root,
                    clone,
                    ignore=shutil.ignore_patterns(
                        ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                    ),
                )
                path = clone / path_name
                content = path.read_text(encoding="utf-8")
                self.assertIn(original, content)
                path.write_text(content.replace(original, replacement, 1), encoding="utf-8")
                result = self.validate(clone)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)

    def test_unknown_manifest_field_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "manifests" / "trust-anchors.yaml"
            path.write_text(path.read_text(encoding="utf-8") + "\nunapprovedField: true\n", encoding="utf-8")
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("validate manifests/trust-anchors.yaml", result.stderr)

    def test_broken_cross_manifest_reference_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "manifests" / "recovery-policy.yaml"
            content = path.read_text(encoding="utf-8")
            path.write_text(
                content.replace("recoveryBackendRef: recovery-plane", "recoveryBackendRef: missing-backend"),
                encoding="utf-8",
            )
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("references unknown identifier", result.stderr)

    def test_signing_rotation_window_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "manifests" / "signing-roots.yaml"
            content = path.read_text(encoding="utf-8")
            path.write_text(
                content.replace("2026-11-27T00:00:00Z", "2026-11-26T00:00:00Z"),
                encoding="utf-8",
            )
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exactly a 90-day activation window", result.stderr)

    def test_signing_rotation_requires_a_bounded_overlap(self):
        declaration = (
            "        v20260829:\n"
            '          activationWindowStart: "2026-08-29T00:00:00Z"\n'
            '          rotationDeadline: "2026-11-27T00:00:00Z"\n'
        )
        cases = (
            (
                "one-day-overlap",
                "        v20261126:\n"
                '          activationWindowStart: "2026-11-26T00:00:00Z"\n'
                '          rotationDeadline: "2027-02-24T00:00:00Z"\n',
                True,
                "",
            ),
            (
                "no-overlap",
                "        v20261127:\n"
                '          activationWindowStart: "2026-11-27T00:00:00Z"\n'
                '          rotationDeadline: "2027-02-25T00:00:00Z"\n',
                False,
                "must overlap",
            ),
            (
                "excessive-overlap",
                "        v20261125:\n"
                '          activationWindowStart: "2026-11-25T00:00:00Z"\n'
                '          rotationDeadline: "2027-02-23T00:00:00Z"\n',
                False,
                "maximum 24-hour rotation overlap",
            ),
        )
        for name, next_version, accepted, diagnostic in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                clone = Path(directory) / "bootstrap"
                shutil.copytree(
                    self.repository_root,
                    clone,
                    ignore=shutil.ignore_patterns(
                        ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                    ),
                )
                path = clone / "manifests" / "signing-roots.yaml"
                content = path.read_text(encoding="utf-8")
                self.assertIn(declaration, content)
                path.write_text(
                    content.replace(declaration, declaration + next_version, 1),
                    encoding="utf-8",
                )
                result = self.validate(clone)
                if accepted:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(diagnostic, result.stderr)

    def test_signing_active_version_must_be_declared(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "manifests" / "signing-roots.yaml"
            content = path.read_text(encoding="utf-8")
            path.write_text(
                content.replace("activeVersionRef: v20260829", "activeVersionRef: v20261127", 1),
                encoding="utf-8",
            )
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("activeVersionRef must identify a declared version", result.stderr)

    def test_second_yaml_document_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "manifests" / "trust-anchors.yaml"
            path.write_text(
                path.read_text(encoding="utf-8") + "\n---\nkind: IgnoredDocument\n",
                encoding="utf-8",
            )
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("multiple YAML documents are not allowed", result.stderr)

    def test_authoritative_source_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            target = Path(directory) / "external-trust-anchors.yaml"
            source = clone / "manifests" / "trust-anchors.yaml"
            shutil.copy2(source, target)
            source.unlink()
            source.symlink_to(target)
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symlinks=[manifests/trust-anchors.yaml]", result.stderr)

    def test_component_maturity_contract_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "component.yaml"
            content = path.read_text(encoding="utf-8").replace(
                "maturity: production", "maturity: experimental"
            )
            path.write_text(content, encoding="utf-8")
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("owner/maturity/authority contract is invalid", result.stderr)

    def test_audit_lock_requires_bound_qualification_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = Path(directory) / "bootstrap"
            shutil.copytree(
                self.repository_root,
                clone,
                ignore=shutil.ignore_patterns(
                    ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                ),
            )
            path = clone / "manifests" / "audit-roots.yaml"
            original = path.read_text(encoding="utf-8")
            path.write_text(original.replace("    locked: false", "    locked: true"), encoding="utf-8")
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qualificationEvidence", result.stderr)

            evidence = "\n".join(
                [
                    "    locked: true",
                    "    qualificationEvidence:",
                    f'      artifactSha256: "sha256:{"1" * 64}"',
                    f'      signatureSha256: "sha256:{"2" * 64}"',
                    '      signingKeyRef: "audit-anchor:v20260829"',
                    f'      qualifiedSourceSha: "{"a" * 40}"',
                    '      qualifiedAt: "2026-08-29T12:00:00Z"',
                ]
            )
            path.write_text(original.replace("    locked: false", evidence), encoding="utf-8")
            result = self.validate(clone)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

            rendered, output = self.render_root(
                directory,
                valid_render_values(),
                "locked.auto.tfvars.json",
                clone,
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr + rendered.stdout)
            audit = json.loads(output.read_text(encoding="utf-8"))["bootstrap"]["audit"]
            self.assertTrue(audit["lock_after_qualification"])
            self.assertEqual(
                audit["qualification_evidence"]["signing_key_ref"],
                "audit-anchor:v20260829",
            )

            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "audit-anchor:v20260829", "audit-anchor:v20261127"
                ),
                encoding="utf-8",
            )
            result = self.validate(clone)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must equal the active audit-anchor version", result.stderr)

    def test_root_trust_render_is_private_exact_and_deterministic(self):
        values = valid_render_values()
        with tempfile.TemporaryDirectory() as directory:
            first, first_output = self.render_root(directory, values, "first.auto.tfvars.json")
            self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
            first_bytes = first_output.read_bytes()
            first_payload = json.loads(first_bytes)
            self.assertEqual(set(first_payload), {"bootstrap"})
            self.assertIsInstance(first_payload["bootstrap"], dict)
            self.assertEqual(
                first_payload["bootstrap"]["recovery_administrator_principal"],
                values["RECOVERY_ADMIN_GROUP"],
            )
            self.assertEqual(first_payload["bootstrap"]["buildkite"]["build_branch"], "main")
            self.assertEqual(
                first_payload["bootstrap"]["buildkite"]["step_key"],
                "bootstrap-ring0-signing",
            )
            self.assertNotIn("WORKFORCE_OIDC_CLIENT_SECRET", first_bytes.decode("utf-8"))
            self.assertNotIn("client_secret", first_payload["bootstrap"]["workforce"])
            self.assertFalse(
                first_payload["bootstrap"]["audit"]["lock_after_qualification"]
            )
            self.assertIsNone(
                first_payload["bootstrap"]["audit"]["qualification_evidence"]
            )
            signing_key = first_payload["bootstrap"]["signing"]["keys"]["audit-anchor"]
            self.assertEqual(signing_key["active_version_ref"], "v20260829")
            self.assertEqual(
                signing_key["versions"],
                {
                    "v20260829": {
                        "activation_window_start": "2026-08-29T00:00:00Z",
                        "rotation_deadline": "2026-11-27T00:00:00Z",
                    }
                },
            )
            self.assertEqual(first_output.stat().st_mode & 0o777, 0o600)

            reversed_values = dict(reversed(list(values.items())))
            second, second_output = self.render_root(
                directory,
                reversed_values,
                "second.auto.tfvars.json",
            )
            self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
            self.assertEqual(second_output.read_bytes(), first_bytes)
            self.assertEqual(
                json.loads(second.stdout)["outputSha256"],
                json.loads(first.stdout)["outputSha256"],
            )

    def test_root_trust_render_rejects_missing_value(self):
        values = valid_render_values()
        del values["GCP_ORGANIZATION_ID"]
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_root(directory, values)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing=[GCP_ORGANIZATION_ID]", result.stderr)
            self.assertFalse(output.exists())

    def test_root_trust_render_rejects_workforce_secret(self):
        values = valid_render_values()
        values["WORKFORCE_OIDC_CLIENT_SECRET"] = "must-never-be-rendered"
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_root(directory, values)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not contain WORKFORCE_OIDC_CLIENT_SECRET", result.stderr)
            self.assertNotIn("must-never-be-rendered", result.stderr + result.stdout)
            self.assertFalse(output.exists())

    def test_root_trust_render_rejects_out_of_band_contact_details(self):
        values = valid_render_values()
        values["RECOVERY_CONTACT_1"] = "recovery-primary@example.com"
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_root(directory, values)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "must not contain out-of-band reference RECOVERY_CONTACT_1",
                result.stderr,
            )
            self.assertNotIn("recovery-primary@example.com", result.stderr + result.stdout)
            self.assertFalse(output.exists())

    def test_recovery_administrator_is_an_independent_group(self):
        for invalid_principal, message in (
            (
                "group:recovery-administrators@example",
                "must be one explicit group email principal",
            ),
            (
                "serviceAccount:recovery-admin@example.iam.gserviceaccount.com",
                "must be one explicit group email principal",
            ),
            (
                "group:root-trust-administrators@example.com",
                "must be distinct from root, security, and signing principals",
            ),
            (
                "group:security-approvers@example.com",
                "must be distinct from root, security, and signing principals",
            ),
        ):
            with self.subTest(principal=invalid_principal), tempfile.TemporaryDirectory() as directory:
                values = valid_render_values()
                values["RECOVERY_ADMIN_GROUP"] = invalid_principal
                result, output = self.render_root(directory, values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse(output.exists())

    def test_root_trust_render_rejects_unknown_value(self):
        values = valid_render_values()
        values["UNDECLARED_BOOTSTRAP_SETTING"] = "disallowed"
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_root(directory, values)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unknown=[UNDECLARED_BOOTSTRAP_SETTING]", result.stderr)
            self.assertFalse(output.exists())

    def test_root_trust_render_rejects_whitespace_values(self):
        for invalid_value in (" ", " audience-with-surrounding-space "):
            with self.subTest(value=repr(invalid_value)), tempfile.TemporaryDirectory() as directory:
                values = valid_render_values()
                values["GITOPS_OIDC_AUDIENCE"] = invalid_value
                result, output = self.render_root(directory, values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid=[GITOPS_OIDC_AUDIENCE]", result.stderr)
                self.assertFalse(output.exists())

    def test_root_trust_render_requires_canonical_buildkite_identity(self):
        invalid_values = {
            "BUILDKITE_OIDC_ISSUER_URI": "https://agent.buildkite.com.example",
            "BUILDKITE_PIPELINE_ID": "------------------------------------",
        }
        for name, invalid_value in invalid_values.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                values = valid_render_values()
                values[name] = invalid_value
                result, output = self.render_root(directory, values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Buildkite", result.stderr)
                self.assertFalse(output.exists())

    def test_root_trust_render_requires_canonical_iam_principals(self):
        invalid_values = {
            "AUDIT_SECURITY_READER_GROUP": "group:not-an-email",
            "KMS_ADMIN_PRINCIPAL_1": "principal://not-a-canonical-principal",
            "AUDIT_ANCHOR_SIGNER": "serviceAccount:not-an-email",
        }
        for name, invalid_value in invalid_values.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                values = valid_render_values()
                values[name] = invalid_value
                result, output = self.render_root(directory, values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("canonical", result.stderr)
                self.assertFalse(output.exists())

    def test_recovery_render_binds_deployed_root_context(self):
        values = valid_render_values()
        context = valid_recovery_context(values)
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_recovery(directory, values, context)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            payload = json.loads(output.read_text(encoding="utf-8"))["recovery"]
            self.assertEqual(
                payload["public_trust_metadata"]["state_backends"],
                {
                    "root-trust": {
                        key: context["state_backends"]["root_trust"][key]
                        for key in ("bucket", "prefix", "replica_bucket")
                    },
                    "recovery-plane": {
                        key: context["state_backends"]["recovery_plane"][key]
                        for key in ("bucket", "prefix", "replica_bucket")
                    },
                },
            )
            self.assertEqual(
                payload["public_trust_metadata"]["federation_audiences"]["github-apply"],
                context["federation"]["github"]["audiences"]["apply"],
            )
            self.assertEqual(payload["minimum_retained_state_generations"], 3)
            self.assertEqual(
                payload["source_state_backends"],
                {
                    "root-trust": {
                        "project_id": values["GCP_STATE_ROOT_PROJECT_ID"],
                        "bucket": values["ROOT_TRUST_STATE_BUCKET"],
                        "prefix": "root-trust",
                    },
                    "recovery-plane": {
                        "project_id": values["GCP_RECOVERY_ROOT_PROJECT_ID"],
                        "bucket": values["RECOVERY_STATE_BUCKET"],
                        "prefix": "recovery-plane",
                    },
                },
            )

    def test_recovery_render_rejects_root_context_drift(self):
        values = valid_render_values()
        for field, mutate in (
            (
                "audience",
                lambda context: context["federation"]["github"]["audiences"].__setitem__(
                    "apply", "https://github.com/mindclade/bootstrap/drifted"
                ),
            ),
            (
                "replica",
                lambda context: context["state_backends"]["root_trust"].__setitem__(
                    "replica_bucket", "drifted-root-trust-replica"
                ),
            ),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                context = valid_recovery_context(values)
                mutate(context)
                result, output = self.render_recovery(directory, values, context)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("does not match deployed root-trust inputs", result.stderr)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
