# Break-glass Activation

Break-glass access is a time-limited Google PAM entitlement, not a standing role. It is used only when normal Ring-0 administration cannot safely resolve an active incident. It never grants Owner, Editor, or Viewer and never grants downstream cluster, GitOps, workload, or normal-infrastructure authority.

The source defines four exact entitlements: `identity-root-administration` (`roles/iam.workloadIdentityPoolAdmin`, `roles/iam.serviceAccountAdmin`, `roles/resourcemanager.projectIamAdmin`, `roles/serviceusage.serviceUsageAdmin`); `root-trust-administration` (`roles/resourcemanager.projectIamAdmin`, `roles/iam.securityAdmin`); `recovery-root-administration` (`roles/cloudkms.admin`, `roles/iam.roleAdmin`, `roles/iam.serviceAccountAdmin`, `roles/logging.admin`, `roles/resourcemanager.projectIamAdmin`, `roles/serviceusage.serviceUsageAdmin`, `roles/storage.admin`, `roles/storagetransfer.user`); and `signing-root-administration` (`roles/cloudkms.admin`). Each is confined to its declared project.

The directly bound `RECOVERY_ADMIN_GROUP` is separate from PAM break-glass. Its independent named accounts and exact recovery-project role set must not be used as evidence that a PAM entitlement was requested or approved. The protected apply identity is likewise a shared reviewed automation path, not break-glass.

## Request

1. Open an incident through an authenticated channel and record the exact entitlement, target project, complete role set activated by that entitlement, requested duration, and concrete justification. Activate only one entitlement unless a separate justification and approval covers another.
2. Confirm the requester is a named human in the configured requester group. Service accounts, federated workloads, shared identities, and anonymous/on-call aliases cannot request access.
3. Set duration to the shortest viable interval and never more than two hours.
4. Notify both independent Security approvers through the configured channels.

## Approval and activation

1. Two named Security approvers independently validate the incident and requested scope.
2. Approvers must be different from the requester and from one another. A responder with overlapping requester/approver membership is ineligible.
3. Each approver records approval in PAM; chat or ticket acknowledgement is not authorization.
4. The requester activates only the approved entitlement and confirms its target, complete effective role set, and expiry before performing any action.
5. Keep a command/action log in the protected incident system. Do not record credentials, state, tokens, private keys, or sensitive plan output.

## Closure

End the grant immediately after the required action; do not wait for expiry. Verify the PAM grant is inactive, inspect audit logs with an independent operator, preserve signed evidence, and review every change through an exact OpenTofu plan. Any self-approval, missing second approval, scope expansion, notification failure, or duration beyond two hours requires immediate revocation and incident escalation.
