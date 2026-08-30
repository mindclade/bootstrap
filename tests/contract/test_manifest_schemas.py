"""Contract tests for the exact bootstrap tree and manifest schemas."""

import hashlib
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
        "CONNECTED_OBSERVATION_EVIDENCE_SIGNER": "serviceAccount:connected-observation@mindclade-identity-root.iam.gserviceaccount.com",
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
        "GITHUB_CI_EVIDENCE_JOB_WORKFLOW_REF": (
            "mindclade/.github/.github/workflows/reusable-required-check.yml@" + "a" * 40
        ),
        "GITHUB_OIDC_ISSUER_URI": "https://token.actions.githubusercontent.com",
        "GITHUB_CONFIG_PLAN_EVIDENCE_SIGNER": "serviceAccount:github-config-plan@mindclade-identity-root.iam.gserviceaccount.com",
        "GITOPS_IMMUTABLE_SUBJECT": "repo:mindclade/gitops:ref:refs/heads/main",
        "GITOPS_OIDC_AUDIENCE": "https://gitops.example.com/mindclade/bootstrap",
        "GITOPS_OIDC_ISSUER_URI": "https://gitops.example.com",
        "GITOPS_REPOSITORY": "mindclade/gitops",
        "INFRASTRUCTURE_LIVE_DISASTER_RECOVERY_WORKFLOW_SHA": "b" * 40,
        "INFRASTRUCTURE_DEVELOPMENT_EXPORT_SIGNER": "serviceAccount:development-apply@mindclade-identity-root.iam.gserviceaccount.com",
        "INFRASTRUCTURE_STAGING_EXPORT_SIGNER": "serviceAccount:staging-apply@mindclade-identity-root.iam.gserviceaccount.com",
        "INFRASTRUCTURE_PRODUCTION_EXPORT_SIGNER": "serviceAccount:production-apply@mindclade-identity-root.iam.gserviceaccount.com",
        "INFRASTRUCTURE_RESTRICTED_EXPORT_SIGNER": "serviceAccount:restricted-apply@mindclade-identity-root.iam.gserviceaccount.com",
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
    identity_project_number = "123456789012"
    recovery_project_number = "210987654321"
    identity_provider_prefix = (
        f"projects/{identity_project_number}/locations/global/workloadIdentityPools"
    )
    recovery_provider_prefix = (
        f"projects/{recovery_project_number}/locations/global/workloadIdentityPools"
    )
    return {
        "federation": {
            "github": {
                "providers": {
                    "plan": f"{identity_provider_prefix}/bootstrap-github-plan/providers/github-actions-plan",
                    "apply": f"{identity_provider_prefix}/bootstrap-github-apply/providers/github-actions-apply",
                    "recovery": f"{recovery_provider_prefix}/bootstrap-github-recovery/providers/github-actions-recovery",
                },
                "audiences": {
                    role: "sts.googleapis.com"
                    for role in ("plan", "apply", "recovery")
                },
            },
            "buildkite": {
                "provider": f"{identity_provider_prefix}/bootstrap-buildkite/providers/buildkite",
                "audience": values["BUILDKITE_OIDC_AUDIENCE"],
            },
            "gitops": {
                "provider": f"{identity_provider_prefix}/bootstrap-gitops/providers/gitops",
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
                ),
                "public_key_pem_sha256": hashlib.sha256(
                    f"test-only-public-key-fixture:{name}".encode("utf-8")
                ).hexdigest(),
            }
            for name in (
                "audit-anchor",
                "bootstrap-handoff",
                "connected-observation-evidence",
                "github-config-plan-evidence",
                "infrastructure-export",
                "recovery-evidence",
            )
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

    def validate_recovery_module_variables(self, directory, rendered_output):
        validation_root = Path(directory) / "recovery-variable-validation"
        validation_root.mkdir(mode=0o700)
        shutil.copyfile(
            self.repository_root / "opentofu/modules/recovery-exports/variables.tf",
            validation_root / "variables.tf",
        )
        rendered = json.loads(rendered_output.read_text(encoding="utf-8"))["recovery"]
        variables_path = validation_root / "recovery.auto.tfvars.json"
        variables_path.write_text(json.dumps(rendered), encoding="utf-8")
        environment = os.environ.copy()
        environment.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0"})
        initialized = subprocess.run(
            ["tofu", "init", "-backend=false", "-input=false"],
            cwd=validation_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            initialized.returncode,
            0,
            initialized.stderr + initialized.stdout,
        )
        return subprocess.run(
            [
                "tofu",
                "plan",
                "-input=false",
                "-lock=false",
                "-refresh=false",
                f"-var-file={variables_path}",
            ],
            cwd=validation_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def validate_rendered_root_plan(self, directory, rendered_output):
        validation_root = Path(directory) / "root-plan-validation"
        opentofu_root = validation_root / "opentofu"
        shutil.copytree(self.repository_root / "opentofu", opentofu_root)
        live_root = opentofu_root / "live" / "root-trust"
        (live_root / "backend.tf").unlink()
        variables_path = live_root / "bootstrap.auto.tfvars.json"
        shutil.copyfile(rendered_output, variables_path)

        plugin_cache = Path(self._temporary.name) / "tofu-plugin-cache"
        plugin_cache.mkdir(mode=0o700, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "GOOGLE_OAUTH_ACCESS_TOKEN": "dummy-token",
                "TF_DATA_DIR": str(validation_root / "tofu-data"),
                "TF_IN_AUTOMATION": "1",
                "TF_INPUT": "0",
                "TF_PLUGIN_CACHE_DIR": str(plugin_cache),
            }
        )
        provider_mirror = environment.get("BOOTSTRAP_PROVIDER_MIRROR")
        if provider_mirror:
            mirror_path = Path(provider_mirror)
            self.assertTrue(mirror_path.is_absolute())
            self.assertTrue(mirror_path.is_dir())
            self.assertFalse(mirror_path.is_symlink())
            cli_config = validation_root / "provider-installation.tfrc"
            cli_config.write_text(
                "provider_installation {\n"
                "  filesystem_mirror {\n"
                f'    path    = "{mirror_path}"\n'
                '    include = ["hashicorp/google"]\n'
                "  }\n"
                "  direct {\n"
                '    exclude = ["hashicorp/google"]\n'
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            environment["TF_CLI_CONFIG_FILE"] = str(cli_config)

        initialized = subprocess.run(
            ["tofu", "init", "-backend=false", "-input=false", "-no-color"],
            cwd=live_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(
            initialized.returncode,
            0,
            initialized.stderr + initialized.stdout,
        )
        saved_plan = validation_root / "root.tfplan"
        planned = subprocess.run(
            [
                "tofu",
                "plan",
                "-refresh=false",
                "-lock=false",
                "-input=false",
                "-no-color",
                f"-out={saved_plan}",
                f"-var-file={variables_path}",
                "-var=workforce_oidc_client_secret=0123456789abcdef0123456789abcdef",
                "-var=workforce_oidc_client_secret_version=1",
            ],
            cwd=live_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        if planned.returncode != 0:
            return planned, None

        rendered_plan = subprocess.run(
            ["tofu", "show", "-json", str(saved_plan)],
            cwd=live_root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(
            rendered_plan.returncode,
            0,
            rendered_plan.stderr + rendered_plan.stdout,
        )
        plan_json = validation_root / "root.tfplan.json"
        plan_json.write_text(rendered_plan.stdout, encoding="utf-8")
        checked = subprocess.run(
            [
                str(self.bootstrapctl),
                "plan-check",
                "--root",
                "root-trust",
                "--plan",
                str(plan_json),
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        return planned, checked

    def test_authoritative_repository_validates(self):
        result = self.validate(self.repository_root)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["files"], 98)
        self.assertEqual(payload["manifests"], 7)

    @unittest.skipIf(
        runfiles_source_root() is not None,
        "evaluated OpenTofu plans run in the direct Python CI gate before Bazel",
    )
    def test_rendered_root_trust_variables_produce_an_evaluated_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            rendered, output = self.render_root(directory, valid_render_values())
            self.assertEqual(rendered.returncode, 0, rendered.stderr + rendered.stdout)
            planned, checked = self.validate_rendered_root_plan(directory, output)
            self.assertEqual(planned.returncode, 0, planned.stderr + planned.stdout)
            self.assertIn("Plan:", planned.stdout)
            self.assertIsNotNone(checked)
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)

    @unittest.skipIf(
        runfiles_source_root() is not None,
        "OpenTofu variable validation runs in the direct Python CI gate before Bazel",
    )
    def test_rendered_recovery_variables_pass_module_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            rendered, output = self.render_recovery(
                directory,
                valid_render_values(),
                valid_recovery_context(valid_render_values()),
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr + rendered.stdout)
            validated = self.validate_recovery_module_variables(directory, output)
            self.assertEqual(validated.returncode, 0, validated.stderr + validated.stdout)

    def test_every_schema_is_closed(self):
        schemas = sorted((self.repository_root / "schemas" / "v1").glob("*.schema.json"))
        self.assertEqual(len(schemas), 7)
        for path in schemas:
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(schema.get("additionalProperties", True), path.name)
            self.assertEqual(schema.get("type"), "object", path.name)

    def test_ci_evidence_extension_is_additive_within_federation_v1(self):
        schema = json.loads(
            (self.repository_root / "schemas" / "v1" / "federation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        providers = schema["properties"]["spec"]["properties"][
            "workloadIdentityProviders"
        ]
        self.assertIn("github-ci-evidence", providers["properties"])
        self.assertIn("github-ci-evidence", providers["required"])
        self.assertIn("github-config", providers["properties"])
        self.assertIn("github-config", providers["required"])
        self.assertIn("github-infrastructure", providers["properties"])
        self.assertIn("github-infrastructure", providers["required"])

    def test_recovery_and_infrastructure_federation_boundaries_are_separated(self):
        module = (
            self.repository_root
            / "opentofu"
            / "modules"
            / "github-federation"
            / "main.tf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "pool_project_id    = var.service_account_project_ids.recovery", module
        )
        self.assertIn("project                   = each.value.pool_project_id", module)
        self.assertIn(
            'resource "google_iam_workload_identity_pool" "infrastructure_live"',
            module,
        )
        self.assertIn(
            '"assertion.workflow_sha == assertion.sha"', module
        )
        self.assertIn(
            '"assertion.repository_visibility == \'private\'"', module
        )
        self.assertIn('"assertion.repository ==', module)
        self.assertNotIn('"attribute.repo"', module)
        self.assertNotIn("assertion.repo ==", module)
        self.assertNotIn(":context:", module)
        self.assertNotIn("%3A", module)
        self.assertIn(":environment:${each.value.environment}:workflow_ref:", module)
        self.assertIn("allowed_audiences = [each.value.audience]", module)
        self.assertIn('allowed_audiences = ["sts.googleapis.com"]', module)

    def test_github_subject_mappings_are_bounded_and_role_separated(self):
        module = (
            self.repository_root
            / "opentofu"
            / "modules"
            / "github-federation"
            / "main.tf"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "'bootstrap-${each.key}:' + assertion.repository_id", module
        )
        self.assertIn(
            "'github-config-${each.key}:' + assertion.repository_id", module
        )
        self.assertIn(
            "'infrastructure-live-${each.key}:' + assertion.repository_id", module
        )
        self.assertIn(
            "'infrastructure-live-drift-plan:' + assertion.repository_id", module
        )
        self.assertIn(
            "'ci-evidence-${each.key}:' + assertion.repository_id", module
        )
        self.assertNotIn('= "assertion.sub"', module)

        bootstrap_repository = "1350991612"
        github_config_repository = "1350986053"
        infrastructure_repository = "1350992171"
        estate_repositories = (
            "1350980188",
            "1350986053",
            "1350991612",
            "1350991963",
            "1350992171",
            "1351193819",
        )
        contracts = [
            ("bootstrap-plan", bootstrap_repository, "bootstrap-plan"),
            ("bootstrap-apply", bootstrap_repository, "bootstrap-apply"),
            ("bootstrap-recovery", bootstrap_repository, "bootstrap-recovery"),
            ("github-config-plan", github_config_repository, "github-config"),
            ("github-config-apply", github_config_repository, "github-config"),
            *[
                (
                    f"infrastructure-live-{environment}-{role}",
                    infrastructure_repository,
                    "infrastructure-live",
                )
                for environment in (
                    "development",
                    "staging",
                    "production",
                    "restricted",
                )
                for role in ("plan", "apply")
            ],
            (
                "infrastructure-live-drift-plan",
                infrastructure_repository,
                "infrastructure-live",
            ),
            *[
                ("ci-evidence-writer", repository_id, "github-ci-evidence")
                for repository_id in estate_repositories
            ],
            (
                "ci-evidence-verifier",
                infrastructure_repository,
                "github-ci-evidence",
            ),
        ]
        values_by_pool = {}
        for role, repository_id, pool in contracts:
            with self.subTest(role=role, repository_id=repository_id):
                expression = f"'{role}:' + assertion.repository_id"
                value = f"{role}:{repository_id}"
                self.assertLessEqual(len(expression), 127)
                self.assertLessEqual(len(value), 127)
                values_by_pool.setdefault(pool, []).append(value)
        for pool, values in values_by_pool.items():
            with self.subTest(pool=pool):
                self.assertEqual(len(values), len(set(values)))

        github_config_provider = module.split(
            'resource "google_iam_workload_identity_pool_provider" "github_config"',
            1,
        )[1].split(
            'resource "google_service_account" "github_config"',
            1,
        )[0]
        github_config_mapping = github_config_provider.split(
            "attribute_mapping = {", 1
        )[1].split("\n  }\n\n  attribute_condition", 1)[0]
        self.assertIn('"attribute.ref"', github_config_mapping)
        self.assertNotIn('"attribute.environment"', github_config_mapping)
        self.assertNotIn("assertion.environment", github_config_mapping)
        self.assertIn(
            '"attribute.github_config_identity" = "\'${each.key}\'"',
            github_config_mapping,
        )
        self.assertIn(
            "/attribute.github_config_identity/${each.key}", module
        )
        self.assertNotIn(
            "/attribute.repository_id/${var.github_config.repository_id}", module
        )

    def test_recovery_audience_preflight_accepts_exact_provider_audience(self):
        workflow = (
            self.repository_root
            / ".github"
            / "workflows"
            / "recovery-verification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '[[ "${WIF_AUDIENCE}" == "sts.googleapis.com" ]]',
            workflow,
        )
        self.assertNotIn('"${WIF_AUDIENCE}" == https://*', workflow)
        self.assertNotIn('"${WIF_AUDIENCE}" == //iam.googleapis.com/*', workflow)

    def test_github_provider_display_names_fit_google_api_limits(self):
        module = (
            self.repository_root
            / "opentofu"
            / "modules"
            / "github-federation"
            / "main.tf"
        ).read_text(encoding="utf-8")
        self.assertIn('display_name                       = "infra-live ${each.key}"', module)
        self.assertNotIn(
            'display_name                       = "infrastructure-live ${each.key}"',
            module,
        )

        infrastructure_identities = (
            "development-plan",
            "development-apply",
            "staging-plan",
            "staging-apply",
            "production-plan",
            "production-apply",
            "restricted-plan",
            "restricted-apply",
        )
        contracts = [
            *[
                (
                    f"bootstrap GitHub {role}",
                    f"Claim-restricted GitHub provider for bootstrap {role} operations",
                )
                for role in ("plan", "apply", "recovery")
            ],
            *[
                (
                    f"github-config {role}",
                    f"Exact activation-gated GitHub trust for github-config {role}",
                )
                for role in ("plan", "apply")
            ],
            *[
                (
                    f"infra-live {identity}",
                    f"Exact immutable GitHub trust for infrastructure-live {identity}",
                )
                for identity in infrastructure_identities
            ],
            (
                "infrastructure-live drift plan",
                "Exact activation-gated GitHub trust for infrastructure-live drift observation",
            ),
            *[
                (
                    f"GitHub CI evidence {role}",
                    f"Claim-restricted GitHub CI evidence {role} identity",
                )
                for role in ("writer", "verifier")
            ],
        ]
        self.assertEqual(len(contracts), 16)
        for display_name, description in contracts:
            with self.subTest(display_name=display_name):
                self.assertLessEqual(len(display_name.encode("utf-8")), 32)
                self.assertLessEqual(len(description.encode("utf-8")), 256)

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

    def test_ci_evidence_federation_is_disabled_isolated_and_keyless(self):
        module = (
            self.repository_root
            / "opentofu"
            / "modules"
            / "github-federation"
            / "main.tf"
        ).read_text(encoding="utf-8")
        variables = (
            self.repository_root
            / "opentofu"
            / "modules"
            / "github-federation"
            / "variables.tf"
        ).read_text(encoding="utf-8")
        manifest = (
            self.repository_root / "manifests" / "identity-federation.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("activationEnabled: false", manifest)
        self.assertIn('pool_id == "github-ci-evidence"', variables)
        self.assertIn('resource "google_iam_workload_identity_pool" "ci_evidence"', module)
        self.assertIn(
            "var.ci_evidence.activation_enabled ? local.ci_evidence_identities : {}",
            module,
        )
        self.assertIn('"attribute.evidence_role"', module)
        self.assertIn("/attribute.evidence_role/${each.key}", module)
        self.assertIn("assertion.job_workflow_ref ==", module)
        self.assertIn("assertion.job_workflow_sha ==", module)
        self.assertIn("assertion.workflow_sha ==", module)
        self.assertIn("assertion.repository_visibility in ['internal', 'private']", module)
        self.assertIn("assertion.runner_environment == 'github-hosted'", module)
        self.assertIn("Omitting allowed_audiences", module)
        self.assertNotIn("var.ci_evidence.writer.audience", module)
        self.assertNotIn("var.ci_evidence.verifier.audience", module)
        outputs = (
            self.repository_root
            / "opentofu"
            / "modules"
            / "github-federation"
            / "outputs.tf"
        ).read_text(encoding="utf-8")
        self.assertIn('key => "https://iam.googleapis.com/${provider.name}"', outputs)
        self.assertNotIn("google_service_account_key", module)

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
        for name in ("recovery-verification.yml",):
            workflow = (
                self.repository_root / ".github" / "workflows" / name
            ).read_text(encoding="utf-8")
            self.assertIn('JUST_VERSION: "1.55.1"', workflow)
            self.assertIn(checksum, workflow)
            self.assertIn("just-${JUST_VERSION}-x86_64-unknown-linux-musl.tar.gz", workflow)
            self.assertIn("sha256sum --check --strict", workflow)
            self.assertIn('= "just ${JUST_VERSION}"', workflow)

    def test_pull_request_qualification_uses_the_locked_nix_contract(self):
        workflow = (
            self.repository_root / ".github" / "workflows" / "pull-request.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25",
            workflow,
        )
        self.assertIn("nix build --no-update-lock-file .#toolchain", workflow)
        self.assertIn("nix flake check --no-update-lock-file", workflow)
        self.assertIn(
            "nix develop --no-update-lock-file .#ci --command just ci", workflow
        )

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
                ".github/workflows/protected-apply.yml",
                "    environment: trusted-build\n",
                "    environment: unapproved-plan\n",
                "job plan must use environment trusted-build",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "    environment: infrastructure-apply\n",
                "    environment: unapproved-recovery\n",
                "job observation must use environment infrastructure-apply",
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
                "if: github.event_name == 'workflow_dispatch' && inputs.observe_controls",
                "if: always()",
                "manual-only",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "and ((.exclusions // []) == [])",
                "and true",
                "six exact enabled, exclusion-free",
            ),
            (
                ".github/workflows/recovery-verification.yml",
                "path: ${{ runner.temp }}/observation-evidence/",
                "path: ${{ runner.temp }}/recovery-inventory/",
                "explicitly non-qualifying redacted signed bundle",
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

    def test_component_readiness_contract_fails_closed(self):
        cases = (
            (
                "maturity: pre-production",
                "maturity: production",
                "owner/readiness/authority contract is invalid",
            ),
            (
                "production_authority: false",
                "production_authority: true",
                "owner/readiness/authority contract is invalid",
            ),
            (
                "owner: security",
                "owner: platform-operations",
                "owner/readiness/authority contract is invalid",
            ),
            (
                "trust_tier: ring-0",
                "trust_tier: ordinary",
                "owner/readiness/authority contract is invalid",
            ),
            (
                "recovery_tier: isolated-ring-0",
                "recovery_tier: routine",
                "owner/readiness/authority contract is invalid",
            ),
            (
                "    - platform-operations",
                "    - security",
                "dependency/ownership contract is invalid",
            ),
            (
                "mindclade.dev/trust-tier: ring-0",
                "mindclade.dev/trust-tier: ordinary",
                "metadata contract is incomplete",
            ),
            (
                "mindclade.dev/recovery-tier: isolated-ring-0",
                "mindclade.dev/recovery-tier: routine",
                "metadata contract is incomplete",
            ),
        )
        for original, replacement, error in cases:
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                clone = Path(directory) / "bootstrap"
                shutil.copytree(
                    self.repository_root,
                    clone,
                    ignore=shutil.ignore_patterns(
                        ".git", ".terraform", ".terraform.lock.hcl", "bazel-*", "__pycache__"
                    ),
                )
                path = clone / "component.yaml"
                content = path.read_text(encoding="utf-8").replace(original, replacement)
                path.write_text(content, encoding="utf-8")
                result = self.validate(clone)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)

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
                first_payload["bootstrap"]["root_administrator_principal"],
                values["ROOT_TRUST_ADMIN_GROUP"],
            )
            self.assertEqual(
                first_payload["bootstrap"]["recovery_administrator_principal"],
                values["RECOVERY_ADMIN_GROUP"],
            )
            self.assertEqual(first_payload["bootstrap"]["buildkite"]["build_branch"], "main")
            self.assertEqual(
                first_payload["bootstrap"]["buildkite"]["step_key"],
                "bootstrap-ring0-signing",
            )
            self.assertEqual(
                first_payload["bootstrap"]["gitops"]["repository"],
                "mindclade/gitops",
            )
            self.assertEqual(
                first_payload["bootstrap"]["gitops"]["subject"],
                "repo:mindclade/gitops:ref:refs/heads/main",
            )
            ci_evidence = first_payload["bootstrap"]["github_ci_evidence"]
            self.assertFalse(ci_evidence["activation_enabled"])
            self.assertEqual(ci_evidence["pool_id"], "github-ci-evidence")
            self.assertEqual(ci_evidence["repository_owner_id"], "316676129")
            self.assertEqual(
                ci_evidence["repository_ids"],
                {
                    "bootstrap": "1350991612",
                    "dot-github": "1350980188",
                    "github-config": "1350986053",
                    "gitops": "1350991963",
                    "infrastructure-live": "1350992171",
                    "mindclade": "1351193819",
                },
            )
            self.assertEqual(
                ci_evidence["writer"]["job_workflow_ref"],
                values["GITHUB_CI_EVIDENCE_JOB_WORKFLOW_REF"],
            )
            self.assertEqual(
                ci_evidence["verifier"]["workflow_sha"],
                values["INFRASTRUCTURE_LIVE_DISASTER_RECOVERY_WORKFLOW_SHA"],
            )
            self.assertNotEqual(
                ci_evidence["writer"]["service_account_id"],
                ci_evidence["verifier"]["service_account_id"],
            )
            github_config = first_payload["bootstrap"]["github_config"]
            self.assertFalse(github_config["activation_enabled"])
            self.assertEqual(github_config["pool_id"], "github-config")
            self.assertEqual(
                {
                    subject["id"]
                    for identity in github_config["identities"].values()
                    for subject in identity["subjects"]
                },
                {
                    "github-config-drift-plan",
                    "github-config-protected-plan",
                    "github-config-protected-apply",
                },
            )
            infrastructure = first_payload["bootstrap"]["github_infrastructure"]
            expected_identities = {
                f"{environment}-{role}"
                for environment in (
                    "development",
                    "staging",
                    "production",
                    "restricted",
                )
                for role in ("plan", "apply")
            }
            self.assertEqual(set(infrastructure["identities"]), expected_identities)
            self.assertEqual(infrastructure["pool_id"], "infrastructure-live")
            self.assertEqual(infrastructure["repository_owner_id"], "316676129")
            self.assertEqual(infrastructure["repository_id"], "1350992171")
            self.assertEqual(
                infrastructure["drift"],
                {
                    "activation_enabled": False,
                    "subject_id": "infrastructure-drift-plan",
                    "provider_id": "infrastructure-plan",
                    "service_account_id": "infrastructure-plan",
                    "workflow_ref": "mindclade/infrastructure-live/.github/workflows/drift-detection.yml@refs/heads/main",
                    "environment": "trusted-build",
                    "audience": "sts.googleapis.com",
                },
            )
            self.assertEqual(
                {
                    identity["audience"]
                    for identity in infrastructure["identities"].values()
                },
                {
                    f"https://github.mindclade.io/oidc/infrastructure-live/{environment}/{role}"
                    for environment in (
                        "development",
                        "staging",
                        "production",
                        "restricted",
                    )
                    for role in ("plan", "apply")
                },
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
            self.assertEqual(
                set(first_payload["bootstrap"]["signing"]["keys"]),
                {
                    "audit-anchor",
                    "bootstrap-handoff",
                    "connected-observation-evidence",
                    "github-config-plan-evidence",
                    "infrastructure-export",
                    "recovery-evidence",
                },
            )
            activation = first_payload["bootstrap"]["github_activation"]
            self.assertEqual(activation["state"], "blocked")
            self.assertEqual(len(activation["active_subject_ids"]), 11)
            self.assertEqual(len(activation["gated_subject_ids"]), 5)
            self.assertEqual(
                set(activation["active_subject_ids"])
                | set(activation["gated_subject_ids"]),
                {
                    "github-config-drift-plan",
                    "github-config-protected-plan",
                    "github-config-protected-apply",
                    "bootstrap-protected-plan",
                    "bootstrap-protected-apply",
                    "bootstrap-recovery-verification",
                    "infrastructure-drift-plan",
                    "infrastructure-ci-evidence-verifier",
                    *{
                        f"infrastructure-live-{environment}-{role}"
                        for environment in (
                            "development",
                            "staging",
                            "production",
                            "restricted",
                        )
                        for role in ("plan", "apply")
                    },
                },
            )
            signing_outputs = (
                self.repository_root
                / "opentofu"
                / "modules"
                / "signing-root"
                / "outputs.tf"
            ).read_text(encoding="utf-8")
            self.assertIn("public_key_pem", signing_outputs)
            self.assertIn("public_key_pem_sha256", signing_outputs)
            self.assertNotIn("public_key_sha256", signing_outputs)
            self.assertIn('protection_level = "HSM"', signing_outputs)
            self.assertIn("sha256(", signing_outputs)
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

    def test_root_trust_render_requires_canonical_gitops_identity(self):
        invalid_values = {
            "GITOPS_REPOSITORY": "mindclade/platform-gitops",
            "GITOPS_IMMUTABLE_SUBJECT": (
                "repo:mindclade/platform-gitops:ref:refs/heads/main"
            ),
        }
        for name, invalid_value in invalid_values.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                values = valid_render_values()
                values[name] = invalid_value
                result, output = self.render_root(directory, values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("GitOps", result.stderr)
                self.assertFalse(output.exists())

    def test_root_trust_render_rejects_mutable_ci_evidence_workflows(self):
        invalid_values = {
            "GITHUB_CI_EVIDENCE_JOB_WORKFLOW_REF": (
                "mindclade/.github/.github/workflows/reusable-required-check.yml@main"
            ),
            "INFRASTRUCTURE_LIVE_DISASTER_RECOVERY_WORKFLOW_SHA": "main",
        }
        for name, invalid_value in invalid_values.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                values = valid_render_values()
                values[name] = invalid_value
                result, output = self.render_root(directory, values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CI evidence", result.stderr)
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
                set(payload["public_trust_metadata"]["signing_key_versions"]),
                {
                    "audit-anchor",
                    "bootstrap-handoff",
                    "connected-observation-evidence",
                    "github-config-plan-evidence",
                    "infrastructure-export",
                    "recovery-evidence",
                },
            )
            self.assertEqual(
                payload["public_trust_metadata"]["signing_public_key_pem_sha256"],
                {
                    name: details["public_key_pem_sha256"]
                    for name, details in context["signing_roots"].items()
                },
            )
            self.assertEqual(
                set(payload["public_trust_metadata"]["signing_windows"]),
                {"audit-anchor", "bootstrap-handoff", "recovery-evidence"},
            )
            self.assertEqual(
                {
                    payload["public_trust_metadata"]["federation_audiences"][name]
                    for name in ("github-plan", "github-apply", "github-recovery")
                },
                {"sts.googleapis.com"},
            )
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

    def test_recovery_render_requires_connected_public_key_digests(self):
        values = valid_render_values()
        context = valid_recovery_context(values)
        del context["signing_roots"]["connected-observation-evidence"]["public_key_pem_sha256"]
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_recovery(directory, values, context)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("public_key_pem_sha256", result.stderr)
            self.assertFalse(output.exists())

    def test_recovery_render_requires_recovery_project_federation_isolation(self):
        values = valid_render_values()
        context = valid_recovery_context(values)
        identity_number = context["federation"]["github"]["providers"]["plan"].split("/")[1]
        recovery_provider = context["federation"]["github"]["providers"]["recovery"]
        recovery_number = recovery_provider.split("/")[1]
        context["federation"]["github"]["providers"]["recovery"] = (
            recovery_provider.replace(
                f"projects/{recovery_number}/",
                f"projects/{identity_number}/",
                1,
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.render_recovery(directory, values, context)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("distinct recovery-project number", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
