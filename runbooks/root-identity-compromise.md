# Root Identity Compromise

## Trigger and containment

Use this runbook for suspected compromise of workforce federation, GitHub/Buildkite/GitOps workload federation, plan/apply service accounts, PAM approvers, or independent recovery identities. Stop protected applies and connected recovery verification. Do not use the suspected IdP, repository session, or collaboration channel to authenticate responders.

1. Open an incident through the [independent contact procedure](../recovery/independent-contact-procedure.md).
2. Classify affected providers, immutable subject conditions, audiences, service accounts, sessions, and human groups from independently retained public metadata.
3. Preserve audit and federation evidence by digest. Do not paste tokens, assertions, credential files, or raw logs into the case.
4. Revoke or disable compromised sessions and providers only through independently authenticated, explicitly approved operator action. Never broaden a subject condition as a temporary workaround.
5. If the direct recovery path is needed, authenticate a named independent account from `RECOVERY_ADMIN_GROUP`. Verify that the group is distinct from root, Security, and signing principals and has only the exact eight declared roles on `recovery-root`: Cloud KMS Admin, Role Admin, Service Account Admin, Logging Admin, Project IAM Admin, Service Usage Admin, Storage Admin, and Storage Transfer User. Do not use it outside that project.
6. If normal administration is unavailable, use [break-glass activation](break-glass-activation.md); requesters and approvers must remain disjoint. `identity-root-administration` restores identity controls, while `recovery-root-administration` is confined to the eight recovery roles.
7. Do not confuse the protected apply identity with independent recovery access. It remains a shared automation path and may be used only after GitHub/OIDC trust is re-established, protected-main is verified, and the exact saved plan receives independent review.

## Re-establish trust

1. Verify source and last-known-good identity manifests offline.
2. Re-establish the workforce IdP/provider with exact issuer, audience, user/group mappings, and named administrator groups. Runtime secret material is supplied through the approved secret channel and never committed.
3. Re-establish each workload pool/provider independently. GitHub claims must bind the approved organization, repository, workflow path, protected ref, and environment; Buildkite and GitOps claims must bind their immutable pipeline or controller identities. Wildcards are forbidden.
4. Rotate service-account impersonation paths and revoke superseded grants. Do not create service-account keys.
5. Verify the four organization audit sinks still mirror Admin Activity and security-event filters into both the primary and recovery buckets.
6. Run a read-only connected plan from a fresh protected-main SHA and have Security compare every IAM change to the manifest and policy evidence.

## Exit criteria

Independent audit evidence shows no unexplained access, all affected sessions/providers are revoked or replaced, exact claims pass policy tests, the direct recovery group has only recovery-project scope, plan/apply/recovery/requester/approver identities remain distinct, and two reviewers approve restoration. Bootstrap identities must still have no authority over GKE, Argo CD, workloads, or normal infrastructure. Source qualification or connected read-only evidence alone is not proof that identity recovery or restoration occurred.
