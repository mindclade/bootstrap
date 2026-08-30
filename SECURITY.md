# Security Policy

## Reporting

Do not open a public issue for a suspected vulnerability, exposed credential, identity-policy gap, state disclosure, signing anomaly, or recovery-control failure. Use this repository's private GitHub vulnerability-reporting channel. If GitHub or its federation is suspected, contact the independently maintained Mindclade Security contact from the corporate incident directory.

Include the affected commit/resource reference, observed behavior, time window, and a minimal reproduction. Share sensitive evidence only through the approved encrypted incident system. Never paste credentials, OIDC assertions, service-account keys, state, plan binaries, backend/object names, raw audit logs, personal contact details, or private key material into GitHub content.

Security and Platform Operations will acknowledge through an independently authenticated channel, assign severity, preserve evidence, and coordinate remediation. Public disclosure is coordinated only after affected trust paths are contained and recovery evidence is complete.

## Supported source

Only the protected `main` branch is supported. A commit is source-qualified only when the stable `pull-request / required` check passes. That status does not prove connected deployment. Connected changes require a fresh protected-apply plan, the protected environments, two-party review, and digest-bound plan evidence. Signed evidence is required for recovery verification and the final handoff ceremony.

## Ring-0 invariants

- No plaintext secrets or long-lived cloud keys are stored in source, manifests, variables, state evidence, artifacts, or logs.
- The mandatory workforce CODE-flow client secret enters root-trust plan and apply only through their protected environment secret stores (or the encrypted ceremony broker), with the same positive monotonic write-only version. The value is high-entropy and at least 32 characters, sensitive and ephemeral, is re-entered at apply, and is never placed in tfvars, source, plan/state persistence, artifacts, command arguments, logs, or evidence. Plan provenance contains only a one-way SHA-256 binding derived from the secret plus its version so the apply job can verify parity.
- OpenTofu variables are compiled from the exact manifests and an exact non-secret string map. Opaque root variable objects, secret entries, unknown keys, implicit defaults, and in-repository compiler outputs are rejected; provenance binds the resulting variable-file digest.
- Every saved plan is checked twice for an exact embedded HCL and provider-lock byte match with the reviewed root, and provenance binds the complete saved-plan SHA-256. Plan JSON references alone are never treated as proof of computed IAM-expression semantics.
- Federation binds exact issuer, audience, subject, repository/pipeline/controller, workflow, ref, and environment claims; wildcard principals are prohibited.
- Federated ADC files are generated only transiently and are moved from the checkout into mode-`0600` runner-temporary storage before any source digest, tree validation, evidence operation, or subsequent OpenTofu or `gcloud` command.
- Plan, apply, recovery, key-administrator, signer, break-glass requester, and approver identities remain distinct and minimum-privilege.
- The protected apply identity has no standing project-creator or billing-user grant. Those permissions belong only to the independently authorized initial ceremony identity and are revoked when the ceremony closes.
- The direct recovery-administrator group contains independently authenticated named accounts, is distinct from root, Security, and signing principals, and receives only the exact eight declared roles on the recovery project. The protected apply identity remains a separate shared automation path whose recovery administration is usable only through a reviewed saved-plan apply; do not represent that path as independent human recovery access.
- State remains CMEK-encrypted, versioned, soft-delete protected, uniformly accessed, publicly inaccessible, deletion protected, and continuously replicated across isolated projects and regions. Native replica and separate recovery-export paths select only each root's exact `default.tfstate`, preserve at least the three newest generations once present, and never propagate lock objects or source deletes. Forward-only replication does not backfill old generations; connected qualification requires three genuine post-job generations at every copy, or a separately authorized verified backfill, and must never manufacture state mutations to reach that count.
- Recovery metadata and inventory use fixed logical object names in versioned, locked buckets. Configuration removal abandons rather than deletes them; connected verification reads only explicit generation URIs and signs the selected generation strings and SHA-256 digests. Recovery verification and protected apply share one Ring-0 concurrency mutex so a source-managed state mutation cannot race the signed observation.
- Four organization audit sinks mirror Admin Activity and security-event filters to both primary and recovery log buckets. Audit buckets are created unlocked; a signed qualification-evidence record is mandatory for the one-way existing-bucket transition to locked, and create-locked or unlock plans fail closed.
- Signing private keys remain non-exportable HSM material. Versions are append-only `vYYYYMMDD` declarations with exact 90-day windows and a required overlap of more than zero and no more than 24 hours; activation is a separate reviewed `activeVersionRef` change during that overlap after public-key distribution and qualification. Signer IAM is conditioned on the exact active CryptoKeyVersion resource and its declared UTC window. A compromised historical version may be disabled without deleting its declaration or public verification material. Recovery uses canonical key-version references and public-key digests only, with no export or implicit fallback.
- Break-glass is named-human, two-approver, justified, notified, and at most two hours; Owner, Editor, and Viewer are forbidden.
- Bootstrap grants no downstream authority over GitHub governance, normal infrastructure, GKE, Argo CD, applications, releases, or tenant data.

Generated OpenTofu lock files are not source. Validation requires Google provider `7.42.0`, verifies the downloaded package bytes against the reviewed `linux_amd64` or `darwin_arm64` checksum, disables direct installation for that provider, and initializes only from the verified temporary mirror. A checksum merely present in a generated lock file is insufficient. Bazel dependencies are exact-versioned and use Bazel Central Registry integrity metadata, but the blueprint excludes a generated `MODULE.bazel.lock`; do not claim a committed transitive dependency lock.

The scheduled isolated job proves only source and restore-contract consistency. Connected read-only evidence additionally binds a redacted control-summary digest, canonical active KMS key-version, and public-key digest. Neither result proves a restoration or deployment; that requires an authorized controlled read and an isolated destination.

Any proposed exception is a security incident/control gap, not an inline waiver. Stop the affected workflow and involve both `@mindclade/security` and `@mindclade/platform-operations`.
