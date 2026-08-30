# Quarterly Recovery Drill

The scheduled workflow runs the isolated source simulation on the first day of January, April, July, and October. A connected check is separately selected and approved; it uses the dedicated recovery identity for read-only inventory and evidence signing. Passing source checks alone is not proof that connected recovery is operational.

## Objectives

- Prove source and restore-contract consistency without implying that the automated job restored anything.
- Prove that exact state, public-trust metadata, and restore-inventory generations can be selected by digest; perform an actual read into an isolated destination only under separate written authorization.
- Meet an eight-hour recovery-time objective and a 24-hour recovery-point objective.
- Prove that two independent operators can authenticate, select exact generations, verify signatures, and produce redacted evidence.
- Find and remediate drift in contacts, permissions, retention, encryption, backend isolation, or procedures.

## Drill sequence

1. Security opens a drill case and samples the independent contacts using [Independent Contact Procedure](independent-contact-procedure.md).
2. Verify the direct recovery-administrator group contains only independent named accounts and has exactly the eight declared roles on the recovery project, with no other-project or organization binding. Record only the result and evidence digest. The protected apply identity is a separate shared, reviewed automation path and does not satisfy this check.
3. Platform Operations records exact eligible root-trust and recovery-plane state generations in each primary, replica, and recovery export, plus exact public-trust metadata and restore-inventory generations and SHA-256 digests. Keep bucket names, object paths, state, and credentials out of the case.
4. Both operators freeze the source SHA, restore-manifest digest, evidence-expiry cutoff, and selected generation/digest pairs before verification begins.
5. Run the default `recovery-verification` workflow. Preserve its GitHub-attested `offline-source-simulation` result and independently verify the attestation. Its `source-qualified` result is not restoration or deployment evidence.
6. Perform [Offline Evidence Procedure](offline-evidence-procedure.md) on an isolated workstation. Record elapsed time and every fail-closed outcome; `just recovery-verify` checks the source contract only.
7. If the connected portion is approved, manually dispatch `recovery-verification` with `connected=true`. The protected recovery environment must require Security approval and must federate only the recovery workflow subject to its distinct read-only identity. Recovery verification and protected apply use the same Ring-0 concurrency group; do not bypass that mutex or run a source-managed state mutation during the observation.
8. Verify the connected evidence's KMS signature, source SHA, run identity, redacted control-summary digest, canonical active recovery-evidence key-version, and public-key digest. Confirm that every selected primary, replica, export, public-metadata, and restore-inventory generation is an explicit numeric generation bound to the signed summary. Confirm at least three generations of each exact `default.tfstate` in its primary, replica, and export, and confirm selected-latest-byte equality across all three. The temporary raw inventory and plaintext read streams must not be uploaded.
9. Confirm the signed redacted summary reports four enabled organization audit sinks, exact configuration verification, one shared organization writer identity, and the canonical configuration digest. Independently reproduce that digest from exact `describe` calls for the two Admin Activity and two security-event sinks, and verify the summary also covers the six logical buckets without exposing names or writer identities.
10. Copy the redacted signed result through the independently controlled evidence process into retention of at least 2,555 days. Verify the copied digest from an independent session; the 90-day GitHub artifact is only a transient distribution copy.
11. Demonstrate the decision path for state-backend loss, root-identity compromise, signing-root unavailability, and break-glass activation. Do not create access, restore state, or change cloud resources in a routine drill. A restoration exercise needs a separate authorization, a controlled read of exact generations, and an isolated destination.
12. Security and Platform Operations sign the drill result, label each result as source simulation, connected read-only verification, or authorized isolated restoration, assign remediation owners/dates, and confirm all temporary sessions and media are closed.

## Acceptance

The routine control drill passes only when both operators independently reproduce the digests, all signatures verify, evidence is fresh and preserved for at least 2,555 days, each primary/replica/export state copy retains at least three generations, latest bytes match across all three, the sampled generations meet the recovery-point objective, and no forbidden dependency or downstream authority is used. This result does not prove the recovery-time objective or a successful restore. Those claims require a separately authorized isolated restoration with measured completion time. A partial, waived, or mislabeled check is a failed drill and opens a tracked control gap.
