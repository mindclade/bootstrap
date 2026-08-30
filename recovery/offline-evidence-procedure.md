# Offline Evidence Procedure

Use this procedure to inspect Ring-0 recovery inputs without accessing the primary control plane. Keep source qualification separate from artifact and restoration evidence: the automated `isolated-source-simulation` qualifies source and the restore contract only. It does not read state, verify live retention, deploy infrastructure, restore a backend, or prove recovery.

## Prepare the isolated verifier

1. Start a clean, encrypted workstation with networking disabled and a trusted clock source recorded in the drill or incident case.
2. Import the approved source archive, pinned verifier tools and dependency cache, `restore-manifest.yaml`, recovery export manifest, selected state generations, the exact generated metadata/inventory generations, connected evidence JSON, its redacted control summary, detached signature, and signing public key through read-only media.
3. Record the media identifier and SHA-256 digest for every imported file. Do not import cloud credentials, service-account keys, KMS private material, kubeconfigs, GitOps credentials, or application secrets.
4. Confirm the source commit and tree digest against two independently held records.

## Verify

1. Set `BOOTSTRAP_PROVIDER_MIRROR` to the absolute path of the imported read-only provider mirror, then run `just validate` from the clean source tree. OpenTofu qualification verifies the actual Google provider `7.42.0` package against the reviewed checksum for the workstation platform, disables direct installation, and initializes only from that mirror. Temporary provider and Bazel lock files remain outside the blueprint. Bazel inputs are exact-versioned and use Bazel Central Registry integrity metadata, which is not the same as a committed transitive lock.
2. Run `just recovery-verify`. It validates only the source-controlled restore contract: strict runtime reference names, distinct primary/recovery backends and projects, the exact artifact references, the configured maximum age, the independent-operator requirement, forbidden dependencies, and required procedure files. It does not read artifacts, determine evidence age, verify a signature, inspect a bucket, or restore state.
3. Separately calculate the digest of every imported artifact. Verify each selected state, `trust/public-trust-metadata.json`, and `restore/inventory.json` object against its recorded generation and SHA-256 digest. These are fixed logical names in versioned buckets; never substitute the current generation or an object name alone for an explicit reference.
4. Verify `SHA256SUMS`, the connected evidence's control-summary digest, restore-manifest digest, canonical `projects/.../cryptoKeyVersions/<number>` reference, and public-key digest. Confirm that the redacted summary contains only the four-sink configuration digest and pass booleans, logical bucket controls, exact selected generation strings, retained-generation counts, state/metadata/inventory digests, and equality results; reject raw sink writer identities, bucket names, inventories, or state.
5. Verify the detached P-256/SHA-256 evidence signature with that exact public key. Compare the canonical key-version and public-key digest with two independent trust records; never fall back to another version.
6. Determine freshness from the signed verification time and the restore manifest's maximum-age rule using the recorded trusted clock. This check is separate from `just recovery-verify`.
7. If restoration is explicitly authorized, perform a controlled read of the selected generation into a newly provisioned isolated, encrypted destination. Parse state only with offline tooling, confirm expected resource addresses and provider schema compatibility, and do not contact providers, refresh state, or write to a primary backend.
8. Have the independent operator repeat generation, digest, freshness, and signature verification from the original read-only media before any restored material is accepted.

## Record and dispose

Create a redacted result containing only the case identifier, source/tree digests, manifest/evidence/control-summary digests, selected generation numbers, verification time, canonical public signing-key version and digest, pass/fail result, and operator role attestations. Say explicitly whether the activity was source simulation, artifact verification, or an authorized isolated restoration. Sign the result using the approved recovery-evidence key only when connected signing is authorized. Preserve no plaintext state in the result.

After independent evidence copies are confirmed, sanitize the temporary workstation under the approved media-handling process. Never claim recovery of a Cloud KMS private key: the key is non-exportable, and only public trust metadata and key-version references are recoverable.
