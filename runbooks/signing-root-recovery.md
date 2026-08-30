# Signing Root Recovery

## Invariant

Cloud KMS P-256 private keys are HSM-protected and non-exportable. Recovery restores public keys, key-version references, signed evidence, policy, and administrative control; it never exports, reconstructs, or claims possession of private key material.

Every key version is source-declared under `versions` with an immutable `vYYYYMMDD` reference. Its UTC activation timestamp must match that date and its deadline must be exactly 90 days later. Declarations are append-only, consecutive windows must overlap by more than zero and no more than 24 hours, and `activeVersionRef` identifies the only source-selected active version. Signer IAM permits `roles/cloudkms.signerVerifier` only when the request targets that exact numeric CryptoKeyVersion and occurs inside its declared half-open UTC window. There is no automatic fallback and a deadline is never extended in place.

## Scheduled rotation

1. Open a change record early enough to pre-stage the replacement. Choose `vYYYYMMDD` from its canonical UTC `activationWindowStart`; set `rotationDeadline` to exactly 90 days later and ensure the new window overlaps the prior window by more than zero and no more than 24 hours.
2. Append the new declaration to the affected key's `versions` map. Do not remove or alter any historical declaration, and leave `activeVersionRef` on the current version.
3. Source-qualify the change, then create and apply a separately reviewed protected root-trust plan. The plan must add only the declared non-exportable HSM `EC_SIGN_P256_SHA256` version and related expected metadata; any destroy, replacement, gap, or mutation of a prior version fails closed.
4. Record the new canonical numeric CryptoKeyVersion resource, export only its public key, calculate its SHA-256 digest, and distribute both through the independent trust channels. Requalify every verifier and evidence consumer before activation. Pre-staging alone does not make the version active.
5. During the declared overlap—at or after `activationWindowStart` and before the prior window expires—make a second source change that switches only `activeVersionRef`. Keep every version declaration. Apply the separately reviewed root-trust plan, then update recovery-plane public trust metadata through its own protected plan so its exact versioned generation binds the canonical active key-version.
6. Verify new signatures with the distributed public key and compare the canonical version and public-key digest with independent records. Confirm the signer IAM condition names only that exact version and window. Preserve old public keys and version references for historical verification; never silently fall back to them for new signatures.

## Response

1. Freeze protected apply and evidence publication when an active required key version is disabled, destroyed, unavailable, unexpectedly rotated, outside its declared window, or suspected compromised.
2. Establish independently authenticated Platform Operations and Security responders. A signer must not administer its own key.
3. Verify the affected key resource, purpose, version, protection level, rotation record, and prior public key against two independent evidence copies.
4. For transient KMS unavailability, retain the freeze and wait; never substitute a software key or an unrecorded version.
5. For disabled but trusted material, any enablement requires an explicit change record, separate key-administrator approval, and audit capture.
6. For suspected compromise, disable the affected version to stop new signatures, preserve its declaration and public key for historical verification, and use the append-only procedure to create a replacement HSM version through a reviewed Ring-0 change. Historical declarations may be `DISABLED`; the source-selected active version must be `ENABLED`. Do not shorten the process by editing/removing the compromised declaration, creating a software key, exporting material, extending its expired IAM window, or configuring fallback. Rebind trust metadata only after public-key distribution and qualification.
7. Re-sign only new evidence. Never rewrite or backdate old evidence; preserve its original signature and compromised-status annotation.

## Qualification and exit

Verify algorithm `EC_SIGN_P256_SHA256`, HSM protection, deletion protection, administrator/signer separation, exact 90-day source windows with a required overlap of more than zero and no more than 24 hours, immutable historical declarations, an enabled canonical active key-version, exact-version/time-bounded signer IAM, public-key digest, and successful independent signature verification. Historical versions may be enabled or disabled but never source-deleted. Connected recovery evidence must bind the canonical active recovery-evidence version and public-key digest and must be created within its declared window. Resume applies or recovery evidence only after audit anchoring and two-person approval. If the audit-anchoring key is affected, treat all unanchored evidence as untrusted until independently reconciled. A source-qualified rotation change is not evidence that a version was created, activated, distributed, or used.
