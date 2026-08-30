# Mindclade Bootstrap

This repository defines Mindclade's Ring-0 bootstrap authority: protected state backends, root audit retention, human and workload federation, non-exportable signing roots, time-limited break-glass access, and independently encrypted recovery exports. `BLUEPRINT.md` is the authoritative path manifest.

Bootstrap has no authority over ordinary cloud infrastructure, GitHub governance, Kubernetes clusters, Argo CD reconciliation, application workloads, releases, or tenant data. Those responsibilities begin only after a signed handoff to their owning repositories.

## Qualification model

There are three distinct gates:

1. **Source qualification** is credential-free. `just validate` checks the exact tree, strict manifests/schemas/references, secret hygiene, OpenTofu formatting and backend-free validation, and Rego policy. `just test` runs Go/Bazel and contract, plan, failure, and isolated-recovery tests. Validation downloads Google provider `7.42.0` into a temporary local mirror, verifies the exact package bytes against the reviewed checksum for the current supported platform (`linux_amd64` or `darwin_arm64`), disables direct installation for that provider, and initializes both roots only from the verified mirror. An offline operator may supply an absolute `BOOTSTRAP_PROVIDER_MIRROR`; the same exact package hash is still mandatory. Generated lock files are excluded by the blueprint and are not committed. Bazel dependencies are exact-versioned and resolved with Bazel Central Registry integrity metadata; the blueprint likewise excludes a generated `MODULE.bazel.lock`, so source qualification does not claim a committed transitive Bazel lock. A pass proves only that this source is internally qualified.
2. **Connected planning** uses the manually dispatched `protected-apply` workflow at the current protected-main SHA. The `infrastructure-plan` environment federates a plan-only identity and compiles the exact seven versioned manifests plus an exact non-secret string map into a mode-`0600` variable file outside the checkout. Recovery context is read from root-trust outputs with the plan identity. Policy rejects deletion or replacement. Evidence directly hashes the JSON plan and each manifest; its source SHA binds the policy, compiler, tooling, workflow, and OpenTofu source in that commit. Because `tofu show -json` omits expression operators and other apply-time HCL details, `plan-source-check` also compares every HCL byte and the provider lock embedded in the saved-plan archive with the reviewed root. The one-day bundle binds that binary plan's SHA-256, resolved-variable digest, root, backend coordinates, run, and six-hour expiry.
3. **Application** is a separate `infrastructure-apply` environment and identity with independent reviewers. It downloads only the plan produced earlier in the same workflow run, rechecks protected main, every bundle hash, embedded source snapshot, plan evidence, root-aware plan policy, and expiry, and applies that saved binary without replanning.

No local command in this repository performs a routine apply. `plan-resource-check` is a resource-level diagnostic, while `evidence create` and `evidence verify` bind and classify a plan digest; none of those commands authorizes a plan. Only root-aware `plan-check --root <root-trust|recovery-plane>` proves complete composition coverage, and the protected workflow requires it again immediately before applying the verified saved plan. Never treat a source-only result, speculative plan, workflow definition, or README procedure as deployment evidence.

The `production` lifecycle/maturity and `production_authority: true` fields in `component.yaml` classify this repository as the authoritative production Ring-0 source. They do not assert that any commit is activated or that any external control exists; only the separate source and connected gates above establish those facts.

### Activation gates

The protected workflows remain intentionally unusable until the private repository is on a GitHub plan that supports protected environments and required reviewers for this use, `@mindclade/platform-operations` and `@mindclade/security` exist with disjoint reviewers, and protected-main rulesets require `pull-request / required`. Organization policy must restrict actions to the immutable pins in this repository; prevent reviewer self-approval; protect workflow, CODEOWNERS, and manifest changes; enable and independently verify the repository's immutable OIDC-subject setting; and configure exact OIDC repository/workflow/ref/environment subjects and audiences. Each GitHub provider requires the immutable subject form, `repo:OWNER@OWNER_ID/REPOSITORY@REPOSITORY_ID:environment:ENVIRONMENT`, in addition to independently checking both numeric IDs and the workflow, ref, and environment claims. Environment variables and federated service accounts are populated only from qualified root-trust outputs. The `infrastructure-plan` environment holds `BOOTSTRAP_VALUES_JSON`, an exact map from every non-secret manifest environment-reference name to a string value except the deliberately omitted `RECOVERY_CONTACT_1` and `RECOVERY_CONTACT_2` out-of-band records, as well as both backend bucket coordinates and the plan identity's provider, service account, and audience. Contact details stay only in the independent recovery contact system and the compiler rejects them if supplied through GitHub. Both `infrastructure-plan` and `infrastructure-apply` must hold the same `WORKFORCE_OIDC_CLIENT_SECRET` as an encrypted environment secret and the same `WORKFORCE_OIDC_CLIENT_SECRET_VERSION` as a positive integer environment variable; neither may be available to pull-request or recovery jobs. The apply environment does not receive the non-secret values map: it consumes only the saved, reviewed plan and independently re-enters the ephemeral secret. The `recovery-verification` environment receives only qualified recovery outputs plus `GCP_ORGANIZATION_ID` and `GCP_AUDIT_PROJECT_ID`; its custom organization role can describe the four fixed sinks but cannot list sinks or read log entries. The external pipeline must populate `BUILDKITE_OIDC_AUDIENCE` from the qualified root-trust output and request tokens with `buildkite-agent oidc request-token --audience "${BUILDKITE_OIDC_AUDIENCE}" --subject-claim pipeline_id`, so both `aud` and `sub` exactly equal the values required by the provider condition; only the protected `main` branch's dedicated `bootstrap-ring0-signing` step may request the signer identity. Missing any gate is a failed activation, not permission to bypass it.

The workforce pool and its exported administrator-group `principalSet` are authentication anchors only. This repository does not bind that principal set to a resource role, and the output itself grants no authority; any downstream authorization requires a separate reviewed binding in its owning repository.

`RECOVERY_ADMIN_GROUP` is a directly bound group containing independently authenticated named accounts. The compiler requires it to be distinct from root, Security, and signing principals. Its only project binding is on `recovery-root`, with exactly `roles/cloudkms.admin`, `roles/iam.roleAdmin`, `roles/iam.serviceAccountAdmin`, `roles/logging.admin`, `roles/resourcemanager.projectIamAdmin`, `roles/serviceusage.serviceUsageAdmin`, `roles/storage.admin`, and `roles/storagetransfer.user`. This independent human path does not make every mutation independent: the protected `bootstrap-apply` identity remains a shared, reviewed automation path with the source-managed recovery administration needed to apply an approved saved plan. Protect that path with the apply environment and two-party review; never describe it as the independent recovery administrator.

## Local source checks

Use the pinned Go, Python, Bazel, OpenTofu, and Conftest versions encoded by the repository and CI:

```bash
just validate
just test
```

Generated plans, state, backend files, credentials, provider/Bazel lock files, and evidence are deliberately ignored and must remain outside the tracked tree. OpenTofu validation installs Google provider `7.42.0` only from the temporary verified mirror after matching the package itself to `5b4bac33f039f94384a0b3468f63266fac023f69c00ebbc573d957b861f67171` (`linux_amd64`) or `f028a366d9c7f427d3ed1a34df22c4476b6ebed4e8884b23e448ef1fb170eb44` (`darwin_arm64`). Merely finding a checksum in a generated lock file is not qualification. Do not run `tofu apply`, state operations, import, destroy, force-unlock, or backend migration as ordinary development commands.

## One-time first apply and state migration

The first root-trust apply is exceptional because it creates both remote backends and the federation needed by subsequent protected workflows. Perform this only in a scheduled bootstrap ceremony with explicit written authorization for the exact plan and exact migration. Two named operators—one Platform Operations, one Security—must be present. Commands below are a gated procedure, not authorization to execute them.

1. Freeze the protected-main SHA as `APPROVED_SOURCE_SHA`. Resolve every non-secret manifest `valueFrom.env` reference through the approved runtime-input channel into an exact JSON string map named `bootstrap-values.json` on an encrypted operator workstation. Do not include `WORKFORCE_OIDC_CLIENT_SECRET`; the compiler rejects missing, unknown, duplicate, empty, padded, multiline, and secret inputs. The approved encrypted secret broker must separately populate a high-entropy workforce secret of at least 32 characters as `TF_VAR_workforce_oidc_client_secret` and its positive monotonic `TF_VAR_workforce_oidc_client_secret_version` directly in the ceremony process environment without terminal output, command-line arguments, shell history, or disk writes. The secret is an ephemeral OpenTofu input routed only to the provider's write-only field: re-enter it from the broker before applying a saved plan if the process boundary changes. It must never be persisted in tfvars, plan JSON/binaries, state, artifacts, logs, or evidence.
2. Establish short-lived bootstrap credentials from the independently authenticated human process. The identity must have only the temporary organization/billing permissions reviewed for this ceremony.

   Canonical root source does not grant `roles/resourcemanager.projectCreator` or `roles/billing.user` to `bootstrap-apply`. Project creation and billing linkage remain confined to this temporary ceremony identity, which must be revoked at exit; the protected apply identity never receives standing authority to create arbitrary projects or attach billing accounts.
3. Create a dedicated encrypted ceremony directory outside the repository and record its path as `CEREMONY_DIR`. Because the canonical root deliberately declares the not-yet-created GCS backend, make an exact ceremony copy that omits only that declaration. OpenTofu then selects its default local backend in the encrypted directory. From the repository root:

   ```bash
   umask 077
   export REPOSITORY_ROOT="$(pwd -P)"
   test "$(git rev-parse --show-toplevel)" = "${REPOSITORY_ROOT}"
   case "${CEREMONY_DIR}" in /*) ;; *) exit 1 ;; esac
   test -d "${CEREMONY_DIR}"
   test ! -L "${CEREMONY_DIR}"
   export CEREMONY_DIR="$(cd "${CEREMONY_DIR}" && pwd -P)"
   case "${CEREMONY_DIR}/" in "${REPOSITORY_ROOT}/"*) exit 1 ;; esac
   export TF_VAR_workforce_oidc_client_secret
   export TF_VAR_workforce_oidc_client_secret_version
   test -n "${TF_VAR_workforce_oidc_client_secret}"
   test "${#TF_VAR_workforce_oidc_client_secret}" -ge 32
   [[ "${TF_VAR_workforce_oidc_client_secret_version}" =~ ^[1-9][0-9]*$ ]]
   [[ "${APPROVED_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]
   test "$(git rev-parse HEAD)" = "${APPROVED_SOURCE_SHA}"
   test -z "$(git status --porcelain=v1 --untracked-files=all)"
   test -f "${CEREMONY_DIR}/bootstrap-values.json"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl render-vars \
     --root "${REPOSITORY_ROOT}" \
     --composition root-trust \
     --values "${CEREMONY_DIR}/bootstrap-values.json" \
     --output "${CEREMONY_DIR}/bootstrap.auto.tfvars.json"
   test "$(python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' "${CEREMONY_DIR}/bootstrap.auto.tfvars.json")" = "600"
   install -d -m 0700 "${CEREMONY_DIR}/local-root"
   rsync -a \
     --exclude='.terraform/' \
     --exclude='.terraform.lock.hcl' \
     --exclude='live/root-trust/backend.tf' \
     "${REPOSITORY_ROOT}/opentofu/" "${CEREMONY_DIR}/local-root/opentofu/"
   export LOCAL_ROOT="${CEREMONY_DIR}/local-root/opentofu/live/root-trust"
   test ! -e "${LOCAL_ROOT}/backend.tf"
   diff -qr -x backend.tf \
     "${REPOSITORY_ROOT}/opentofu" "${CEREMONY_DIR}/local-root/opentofu"
   cmp "${REPOSITORY_ROOT}/opentofu/live/recovery-plane/backend.tf" \
     "${CEREMONY_DIR}/local-root/opentofu/live/recovery-plane/backend.tf"
   case "$(uname -s)/$(uname -m)" in
     Linux/x86_64)
       export PROVIDER_PLATFORM=linux_amd64
       export PROVIDER_CHECKSUM=5b4bac33f039f94384a0b3468f63266fac023f69c00ebbc573d957b861f67171
       ;;
     Darwin/arm64)
       export PROVIDER_PLATFORM=darwin_arm64
       export PROVIDER_CHECKSUM=f028a366d9c7f427d3ed1a34df22c4476b6ebed4e8884b23e448ef1fb170eb44
       ;;
     *) exit 1 ;;
   esac
   install -d -m 0700 \
     "${CEREMONY_DIR}/provider-mirror"
   tofu -chdir="${LOCAL_ROOT}" get
   tofu -chdir="${LOCAL_ROOT}" providers mirror \
     -platform="${PROVIDER_PLATFORM}" \
     "${CEREMONY_DIR}/provider-mirror"
   export PROVIDER_PACKAGE="${CEREMONY_DIR}/provider-mirror/registry.opentofu.org/hashicorp/google/terraform-provider-google_7.42.0_${PROVIDER_PLATFORM}.zip"
   test -f "${PROVIDER_PACKAGE}"
   test ! -L "${PROVIDER_PACKAGE}"
   if command -v sha256sum >/dev/null 2>&1; then
     export ACTUAL_PROVIDER_CHECKSUM="$(sha256sum "${PROVIDER_PACKAGE}" | cut -d ' ' -f1)"
   else
     export ACTUAL_PROVIDER_CHECKSUM="$(shasum -a 256 "${PROVIDER_PACKAGE}" | cut -d ' ' -f1)"
   fi
   test "${ACTUAL_PROVIDER_CHECKSUM}" = "${PROVIDER_CHECKSUM}"
   printf 'provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n    include = ["hashicorp/google"]\n  }\n  direct {\n    exclude = ["hashicorp/google"]\n  }\n}\n' \
     "${CEREMONY_DIR}/provider-mirror" \
     >"${CEREMONY_DIR}/provider-installation.tfrc"
   export TF_CLI_CONFIG_FILE="${CEREMONY_DIR}/provider-installation.tfrc"
   tofu -chdir="${LOCAL_ROOT}" init -input=false
   grep -Fq 'version     = "7.42.0"' \
     "${LOCAL_ROOT}/.terraform.lock.hcl"
   test "$(tofu -chdir="${LOCAL_ROOT}" workspace show)" = "default"
   tofu -chdir="${LOCAL_ROOT}" plan \
     -input=false \
     -var-file="${CEREMONY_DIR}/bootstrap.auto.tfvars.json" \
     -out="${CEREMONY_DIR}/root-trust.bootstrap.tfplan"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl plan-source-check \
     --root root-trust \
     --opentofu-root "${REPOSITORY_ROOT}/opentofu" \
     --provider-lock "${LOCAL_ROOT}/.terraform.lock.hcl" \
     --saved-plan "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" \
     --initial-local-backend
   diff -qr \
     -x backend.tf \
     -x .terraform \
     -x .terraform.lock.hcl \
     "${REPOSITORY_ROOT}/opentofu" "${CEREMONY_DIR}/local-root/opentofu"
   tofu -chdir="${LOCAL_ROOT}" show \
     -json "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" \
     >"${CEREMONY_DIR}/root-trust.bootstrap.tfplan.json"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl plan-check \
     --root root-trust \
     --plan "${CEREMONY_DIR}/root-trust.bootstrap.tfplan.json"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl evidence create \
     --repository-root "${REPOSITORY_ROOT}" \
     --plan "${CEREMONY_DIR}/root-trust.bootstrap.tfplan.json" \
     --root root-trust \
     --output "${CEREMONY_DIR}/root-trust.bootstrap.evidence.json"
   if command -v sha256sum >/dev/null 2>&1; then
     export SAVED_PLAN_SHA256="$(sha256sum "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" | cut -d ' ' -f1)"
   else
     export SAVED_PLAN_SHA256="$(shasum -a 256 "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" | cut -d ' ' -f1)"
   fi
   [[ "${SAVED_PLAN_SHA256}" =~ ^[0-9a-f]{64}$ ]]
   readonly SAVED_PLAN_SHA256
   ```

4. Both operators inspect the redacted plan summary, verify zero deletions/replacements, verify state/recovery project separation, and sign the plan/evidence digests. Stop on any unexpected resource, IAM member, provider, output, or unresolved value.
5. Only after the change record explicitly authorizes that saved plan, apply that exact binary once:

   ```bash
   if command -v sha256sum >/dev/null 2>&1; then
     export CURRENT_SAVED_PLAN_SHA256="$(sha256sum "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" | cut -d ' ' -f1)"
   else
     export CURRENT_SAVED_PLAN_SHA256="$(shasum -a 256 "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" | cut -d ' ' -f1)"
   fi
   test "${CURRENT_SAVED_PLAN_SHA256}" = "${SAVED_PLAN_SHA256}"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl plan-source-check \
     --root root-trust \
     --opentofu-root "${REPOSITORY_ROOT}/opentofu" \
     --provider-lock "${LOCAL_ROOT}/.terraform.lock.hcl" \
     --saved-plan "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" \
     --initial-local-backend
   diff -qr \
     -x backend.tf \
     -x .terraform \
     -x .terraform.lock.hcl \
     "${REPOSITORY_ROOT}/opentofu" "${CEREMONY_DIR}/local-root/opentofu"
   cmp "${REPOSITORY_ROOT}/opentofu/live/recovery-plane/backend.tf" \
     "${CEREMONY_DIR}/local-root/opentofu/live/recovery-plane/backend.tf"
   tofu -chdir="${LOCAL_ROOT}" show \
     -json "${CEREMONY_DIR}/root-trust.bootstrap.tfplan" \
     >"${CEREMONY_DIR}/root-trust.bootstrap.preapply.tfplan.json"
   cmp "${CEREMONY_DIR}/root-trust.bootstrap.tfplan.json" \
     "${CEREMONY_DIR}/root-trust.bootstrap.preapply.tfplan.json"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl plan-check \
     --root root-trust \
     --plan "${CEREMONY_DIR}/root-trust.bootstrap.preapply.tfplan.json"
   go -C "${REPOSITORY_ROOT}/tooling" run ./cmd/bootstrapctl evidence verify \
     --repository-root "${REPOSITORY_ROOT}" \
     --plan "${CEREMONY_DIR}/root-trust.bootstrap.preapply.tfplan.json" \
     --evidence "${CEREMONY_DIR}/root-trust.bootstrap.evidence.json"
   tofu -chdir="${LOCAL_ROOT}" apply \
     -input=false \
     "${CEREMONY_DIR}/root-trust.bootstrap.tfplan"
   ```

6. Set `MIGRATION_BACKUP_PATH` to an independently controlled encrypted evidence location outside `CEREMONY_DIR`; copy and compare the local state before migration. Record the newly created root-trust backend bucket in `ROOT_TRUST_STATE_BUCKET` from the reviewed non-sensitive output. Reverify bucket CMEK, uniform access, public-access prevention, versioning, 30-day soft delete, deletion protection, and native locking. Then obtain a second explicit approval for this exact local-to-remote migration:

   ```bash
   test -n "${MIGRATION_BACKUP_PATH}"
   install -m 0600 \
     "${LOCAL_ROOT}/terraform.tfstate" \
     "${MIGRATION_BACKUP_PATH}"
   cmp "${LOCAL_ROOT}/terraform.tfstate" "${MIGRATION_BACKUP_PATH}"
   tofu -chdir="${LOCAL_ROOT}" output -json state_backends \
     >"${CEREMONY_DIR}/state-backends.output.json"
   export ROOT_TRUST_STATE_BUCKET="$(
     jq -er '.root_trust.bucket' \
       "${CEREMONY_DIR}/state-backends.output.json"
   )"
   install -m 0600 \
     opentofu/live/root-trust/backend.tf \
     "${LOCAL_ROOT}/backend.tf"
   tofu -chdir="${LOCAL_ROOT}" init \
     -migrate-state \
     -force-copy \
     -backend-config="bucket=${ROOT_TRUST_STATE_BUCKET}" \
     -backend-config="prefix=root-trust"
   export TF_DATA_DIR="${CEREMONY_DIR}/canonical-remote-data"
   tofu -chdir=opentofu/live/root-trust init \
     -input=false \
     -backend-config="bucket=${ROOT_TRUST_STATE_BUCKET}" \
     -backend-config="prefix=root-trust"
   tofu -chdir=opentofu/live/root-trust plan \
     -input=false \
     -detailed-exitcode \
     -var-file="${CEREMONY_DIR}/bootstrap.auto.tfvars.json"
   ```

   Exit code `0` is required. Exit code `1` is an error and `2` is an unexpected diff; either stops the ceremony. Move any local state and backup left by migration into the approved encrypted evidence vault, verify the independent copy, and confirm no state remains in the repository or normal workstation storage.

7. Configure GitHub protected-main rules, selected-action policy, the repository's immutable OIDC-subject setting, immutable OIDC issuer/audience/repository-ID/workflow/ref/environment conditions, and the `infrastructure-plan`, `infrastructure-apply`, and `recovery-verification` environments from reviewed outputs. Independently read back the OIDC setting before enabling the workflows. Store the exact non-secret string map as `BOOTSTRAP_VALUES_JSON` only in the plan environment, excluding the two out-of-band recovery contact records; do not store opaque `TF_VAR_bootstrap` or `TF_VAR_recovery` objects. Configure the plan, apply, and recovery OIDC audiences explicitly and keep their identities distinct. For root-trust, plan and apply independently inject the same required workforce OIDC client secret and positive monotonic version without printing either. The bundle binds a SHA-256 digest derived from that high-entropy secret and version so apply can prove parity without storing the value; it also binds the compiler-produced variable-file digest. CI rejects any plan JSON containing concrete secret or write-only material before artifact upload. Apply and recovery environments require Security review.
8. Initialize `recovery-plane` directly against its already-created remote backend. Its first plan/apply must use `protected-apply`; never bootstrap it with local state. Run the quarterly offline and connected recovery checks before declaring Ring-0 qualified.
9. Lock audit retention only after audit ingestion, independent read access, evidence signing, replicated-backend recovery, and break-glass behavior pass qualification. The initial manifest declares `lockAfterQualification.locked: false`. Activating the irreversible lock requires a separately reviewed source change to `true` and a `qualificationEvidence` record binding the signed artifact and signature SHA-256 digests, active `audit-anchor:vYYYYMMDD`, qualified source SHA, and canonical UTC qualification time. Policy permits only an existing bucket's `false`-to-`true` transition; create-locked and unlock plans fail. Apply that exact protected plan, then record the signed handoff, revoke the temporary ceremony identity, unset both workforce OIDC `TF_VAR_` values, and close all local material.

## Operations and recovery

- [State backend unavailable](runbooks/state-backend-unavailable.md)
- [Root identity compromise](runbooks/root-identity-compromise.md)
- [Signing root recovery](runbooks/signing-root-recovery.md)
- [Break-glass activation](runbooks/break-glass-activation.md)
- [Independent contacts](recovery/independent-contact-procedure.md)
- [Offline evidence](recovery/offline-evidence-procedure.md)
- [Quarterly drill](recovery/quarterly-drill-procedure.md)

The quarterly workflow is offline with respect to cloud state by default. Its `isolated-source-simulation` job qualifies source and validates the restore contract; it does not read state, deploy infrastructure, restore a backend, or prove that restoration succeeded. Connected verification is manual, read-only, independently approved, and uses its own workload identity. It selects every state, metadata, and inventory object by an explicit generation URI, hashes those exact bytes, and binds the generation strings and digests into a redacted control summary for six logical buckets and two state roots. The signed evidence binds that summary's digest, the canonical active recovery-evidence KMS key-version, and the public-key digest. Raw bucket names, inventory, plaintext state, credentials, and private key material are never uploaded. Actual restoration requires a separately authorized controlled read of an exact retained generation and digest into an isolated destination.

Native cross-bucket replication continuously copies only each root's new and updated `<root>/default.tfstate` to its regional replica. Separate continuous recovery exports copy those same exact state objects into the recovery export bucket. Neither path propagates transient `.tflock` objects or source deletions, and lifecycle rules preserve at least the three newest generations once they exist. Native replication is forward-only: connected qualification remains failed until every primary, replica, and export has observed at least three genuine post-job state generations, or a separately authorized and verified backfill has occurred. Never synthesize state mutations merely to satisfy the count. The fixed logical objects `trust/public-trust-metadata.json` and `restore/inventory.json` are versioned; source removal uses `ABANDON` so configuration changes do not delete retained data. Recovery must select the exact recorded generation and SHA-256 digest, never an unqualified current object name.

Four organization-level audit sinks mirror Admin Activity and security-event filters into both the primary audit bucket and the recovery audit bucket. Signing versions follow the append-only 90-day process in [Signing root recovery](runbooks/signing-root-recovery.md): pre-stage a declared HSM version with a required overlap of more than zero and no more than 24 hours, distribute and qualify its public key, then switch `activeVersionRef` during that overlap in a separate reviewed change without removing historical declarations. GitHub's 90-day drill artifact is transient distribution evidence; the signed drill result must also be copied through the independently controlled evidence process into storage with at least the required 2,555-day retention.

`manifests/identity-federation.yaml` declares the exact effective role-name union for the GitHub plan, apply, and recovery identities, including the source-defined configuration-read roles and `bootstrapOrganizationIamApply`. That apply role contains only `resourcemanager.organizations.getIamPolicy` and `resourcemanager.organizations.setIamPolicy`, which the provider needs to read-modify-write the exact source-managed organization bindings; it is usable only through the protected apply federation path and is guarded by the plan policy. If that role's own organization binding is lost, the apply identity cannot self-repair it: restore the binding through the approved break-glass or cold-ceremony path, then run the protected plan. The composition roots remain authoritative for each role's project, resource, IAM condition, and time boundary; the compiler and plan checker reject drift between the declarative identity contract and those grants.

## Ownership

`@mindclade/platform-operations` and `@mindclade/security` jointly own every path. CODEOWNERS and protected environments must enforce independent review; repository files cannot enforce those external settings by themselves. Report security issues through the private process in [SECURITY.md](SECURITY.md).
