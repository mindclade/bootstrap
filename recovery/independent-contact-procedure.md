# Independent Contact Procedure

This procedure establishes an authenticated, out-of-band recovery bridge when the normal identity or collaboration plane cannot be trusted. Personal contact details are maintained in the independently controlled recovery contact system referenced by `RECOVERY_CONTACT_1` and `RECOVERY_CONTACT_2`; they never belong in this repository, state, workflow output, or evidence.

## Preconditions

- An incident or scheduled drill has a unique case identifier in the independent record system.
- One Platform Operations operator and one Security operator are available. They must be different people and neither may approve their own access.
- At least one communication path is independent of GitHub, the primary workforce IdP, GKE, Argo CD, and application workloads.
- `RECOVERY_ADMIN_GROUP` is a direct group whose members are independently authenticated named accounts, not shared credentials, service accounts, ordinary root administrators, signing principals, or break-glass approvers. Its effective access must be limited to the recovery project and the exact eight source-declared roles.

## Procedure

1. The initiating operator retrieves `RECOVERY_CONTACT_1` from the offline contact record and states only the case identifier, callback code, and requested role.
2. The contacted Security operator terminates the inbound contact and calls back through the independently recorded channel. Do not accept a number, address, or link supplied in the inbound request.
3. Both operators compare the case identifier, the current restore-manifest digest, and a newly generated verbal nonce. Record only their confirmations and timestamps, not personal contact details.
4. Repeat the callback through `RECOVERY_CONTACT_2`. The second contact must verify the first operator through a different trusted channel.
5. Establish the recovery bridge using the independently controlled system. Admit only the named operators and record joins, leaves, decisions, and evidence digests.
6. Independently verify the named recovery administrator's direct group membership and effective recovery-project scope. The eight allowed roles are Cloud KMS Admin, Role Admin, Service Account Admin, Logging Admin, Project IAM Admin, Service Usage Admin, Storage Admin, and Storage Transfer User. Stop on any organization-wide grant, other-project grant, extra role, indirect group chain, or shared identity.
7. Security declares whether the primary identity plane is trusted, degraded, or compromised. If compromised, follow [Root Identity Compromise](../runbooks/root-identity-compromise.md) before any connected action.
8. Treat the protected apply identity separately. It is a shared, reviewed automation path for source-managed changes and is not proof that the independent recovery administrator authenticated. Use it only after its GitHub/OIDC trust path is independently re-established and an exact saved plan receives the required review.
9. Close the bridge after evidence is signed and independently copied. Both operators attest that temporary access was revoked and that no credentials or private keys entered the record.

## Fail-closed conditions

Stop if a callback cannot be completed, identities disagree, the case identifier is missing, the manifest digest differs, direct group membership or exact recovery-only scope cannot be proved, an operator would self-approve, or the only available channel depends on a forbidden recovery dependency. Escalation does not relax these conditions.
