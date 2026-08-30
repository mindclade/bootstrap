## Change

Describe the bootstrap invariant, manifest contract, policy, workflow, or recovery behavior changed.

## Evidence

- [ ] `just validate` passed.
- [ ] `just test` passed.
- [ ] Any connected plan was produced by `protected-apply` from this exact protected-main SHA.
- [ ] Plan and evidence output is attached by digest only; no state, credentials, plan binary, or sensitive values are pasted here.

## Security and recovery review

- [ ] No plaintext secret, service-account key, private signing key, credential file, or sensitive output was added.
- [ ] IAM remains exact-subject, minimum privilege, and separated across plan, apply, recovery, approver, and requester identities.
- [ ] State remains encrypted, versioned, soft-delete protected, non-public, and isolated from recovery copies.
- [ ] The change does not grant bootstrap identities authority over clusters, GitOps reconciliation, application workloads, or normal infrastructure.
- [ ] Replacement and deletion behavior is identified; v1 protected apply must reject both.
- [ ] Recovery procedures and evidence expectations were updated when the recovery contract changed.

## Approval record

Link the change record and identify the independent Platform Operations and Security reviewers. Do not include personal contact details or secret material.
