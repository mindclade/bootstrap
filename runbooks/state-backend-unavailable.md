# State Backend Unavailable

## Trigger and safety boundary

Use this runbook when root-trust or recovery-plane state cannot be read or locked. Stop all protected applies immediately. Do not use `-lock=false`, force-unlock, recreate a bucket, import resources, delete state, select an unverified generation, or fall back to local state.

## Triage

1. Open an incident case and start the [independent contact procedure](../recovery/independent-contact-procedure.md).
2. Identify which backend is affected using its non-secret manifest reference; do not paste bucket names, object paths, or state into chat or tickets.
3. From a read-only recovery identity, distinguish access denial, regional/service outage, KMS unavailability, object/version loss, retention-policy failure, replication/export lag, and lock contention.
4. Verify audit logs and the last signed evidence from an independent copy. Treat unexplained IAM, key, retention, or generation changes as compromise.
5. Verify the exact `<root>/default.tfstate` object has at least three retained generations in its primary, regional replica, and recovery export. Lock objects are deliberately absent from replicas and exports, and source deletes are deliberately not propagated; neither condition is a replication fault.
6. Suspend the `protected-apply` environment until Security records a disposition.

## Recovery decision

- For a provider outage, wait for service restoration while preserving the apply freeze. Do not bypass backend locking.
- For an authorization fault with trusted identity, repair access only through a separately reviewed Ring-0 plan after the backend is readable enough to prove current state.
- For loss or corruption, choose an explicit versioned `default.tfstate` generation from the independently encrypted recovery export. Do not select a `.tflock`, a logical object name without a generation, or an unqualified latest object. Two operators must verify its SHA-256 digest, evidence signature, source binding, and age under [offline evidence procedure](../recovery/offline-evidence-procedure.md).
- Select exact generations and digests for `trust/public-trust-metadata.json` and `restore/inventory.json` as well. Their fixed names are versioned, and source configuration removal abandons rather than deletes retained objects.
- Actual restoration requires written authorization for a controlled object-generation read into a new isolated, encrypted destination. Compare the recovered state inventory and lineage offline before authorizing any primary-location write. A source simulation or connected read-only check is not restoration evidence.

## Exit criteria

The backend is encrypted with the expected CMEK, versioning and 30-day soft delete remain enabled, public access prevention and uniform access are enforced, each primary/replica/export retains at least three verified state generations, latest expected copies agree by digest, a normal lock can be acquired on the primary, an exact reviewed plan has no unexplained changes, and signed incident evidence exists in two independent locations. Re-enable applies only after separate Platform Operations and Security approval.
