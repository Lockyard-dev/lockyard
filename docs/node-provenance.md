# Node result provenance and image admission

This document describes the E14/E15 security contract implemented by the node executor and CLI. Final production acceptance is tracked separately; cryptographic and control-protocol tests do not establish successful resource-enforced container execution.

A node signs a typed result manifest with Ed25519. The verifier must already trust the public key for the expected node and workspace through an authenticated channel. A key included beside a result, or a matching key ID, does not establish trust. The signature binds the complete request's SHA-256, job/node/workspace identity, resolved Git revision, immutable image identity, image admission evidence, terminal execution state, exit/error information and retained artifact byte hashes, lengths, truncation and error indicators. The request hash binds arguments and prompts without copying their text into the manifest. File entries are limited to `output.log` and `result.patch`; no received filename is used as a destination path.

The signed payload is canonical typed JSON in a versioned envelope. The signature input includes a purpose-specific domain and a length prefix. Image attestations and result manifests cannot be substituted for one another. Unknown fields, ambiguous payload encoding, unsupported algorithms, mismatched context, oversized documents and unauthenticated changes are rejected. An interrupted execution with an unknown outcome cannot be signed as a completed result. A valid signature attests the node's statement; it does not prove that an untrusted administrator ran the job correctly. Execution hosts and their administrators are trusted under the agreed model.

Private signing keys are PKCS#8 files created without overwrite, owned by the node account and private to that account. Key reads reject symlinks, hardlinks, non-regular files, unsafe permissions and non-private containing directories. The key is never an environment variable, command argument, manifest field, cloud database field or container mount. Only the public key is distributed. Give every node its own signing key; sharing a workspace encryption key does not require sharing node signing identities. Signed manifests travel inside the existing end-to-end encrypted job response, so the broker cannot inspect their content.

Every executable image must be referenced by an immutable lowercase SHA-256 identifier, either a local `sha256:<64 hex>` configuration ID or a registry `repository@sha256:<64 hex>` digest. A mutable tag alone is not admitted. A runner's explicit supply-chain policy names an attestation, its actual SBOM and vulnerability report files, trusted attester public keys, maximum evidence ages, vulnerability severity counts and explicitly denied vulnerability identifiers. Admission verifies the signature, exact image subject, configured expiration, evidence ages, actual evidence byte lengths and hashes, supported SBOM JSON format, report subject, scanner/database age and vulnerability policy. The runtime's actual image configuration ID must additionally match the signed statement before a container is started. Resource limits and isolation remain separate mandatory gates.

The offline image attestation contract supports customer-managed trusted attesters. An attester signs the image identity, actual image configuration identity, validity window and digests/sizes of an SPDX or CycloneDX JSON SBOM and a strict vulnerability report. Lockyard verifies these assertions and their referenced bytes locally. It does not independently contact an upstream registry transparency log or run a scanner merely by checking the attestation. A customer scanner adapter must produce the report and the trusted attester must vouch for its subject and evidence. Neither a digest alone nor an unsigned SBOM is treated as an image signature.

The supported vulnerability report is versioned typed JSON with the image subject digest, scan time, database update time, scanner name/version and distinct vulnerability ID/package findings. Severities are `critical`, `high`, `medium`, `low`, `negligible` or `unknown`. Unsupported severities and unexpected fields fail closed. Policy thresholds are explicit; an explicit denied ID overrides severity allowances. Reports and SBOMs have hard byte limits and non-regular/symlink evidence paths are rejected. The supported SBOM header checks identify SPDX 2.2/2.3 JSON or CycloneDX 1.4–1.6 JSON; the customer attester remains responsible for the accuracy and full standards conformance of the package inventory.

No part of this policy weakens the container capability gate. The managed development daemon currently lacks CPU, RAM and PID enforcement, so the available local runtime cannot provide a successful resource-enforced execution proof. Focused cryptographic and admission tests are not that proof.

The node initializer creates `state-dir/result-signing.pk8` and returns the public configuration as `result_signing` in its receipt. To configure a separate customer attester, first create a private containing directory owned by the node account, then run:

```sh
lockyard node signing-key --output /private/policy/attester.pk8 --json
lockyard node sign-image-attestation --input /private/policy/statement.json --key-file /private/policy/attester.pk8 --output /private/policy/image-attestation.json --json
```

The unsigned statement follows the `ImageAttestation` type; it names the exact image reference/configuration digest, validity window and actual evidence digests/sizes. Keep the private attester key outside executable checkouts and container mounts. The public key is configured in `container.supply_chain.trusted_signers`. Signing a local statement is an explicit customer assertion; it does not run a scanner.

A controller pins a worker's independently authenticated result key in node configuration:

```toml
[result_trust.build-server]
public_key = "REPLACE_WITH_PINNED_64_LOWERCASE_HEX_PUBLIC_KEY"
```

`job patch` requires this pin, an authenticated completed manifest and complete patch metadata. It downloads only up to the signed length, checks the actual bytes, syncs them and creates the requested destination without overwrite. Missing pins, pending/failed signing, signature/context mismatch, truncation, digest mismatch and failed durable writes prevent successful patch download. Neither a valid signature nor a verified download applies the patch automatically.

```sh
lockyard job manifest build-server JOB_ULID --config /private/controller.toml --output ./result-manifest.json --json
lockyard job verify-manifest --manifest ./result-manifest.json --public-key PINNED_PUBLIC_KEY --node build-server --workspace WORKSPACE_ID --job JOB_ULID --revision EXPECTED_COMMIT --image-digest sha256:EXPECTED_IMAGE_DIGEST --patch ./result.patch --json
```

The explicit verification command enforces the independently supplied revision and image digest as well as node/workspace/job identity. An optional `--request-sha256` binds an independently retained full request hash. `--log` and `--patch` require complete artifacts without collection errors and verify their saved bytes. Verification without either file checks the manifest's authenticity and returns its outcome and completeness flags. The automatic downloader authenticates the worker's statement and checks consistency with returned job metadata; selecting an independently approved image/revision remains the controller's dispatch policy.

Result signatures are recovered for completed durable records that lost only the signature write. Recovery never executes the job again. A legacy record without immutable image provenance fails signature recovery explicitly. A changed result signer requires an authenticated trust update; keys are not rotated on a schedule, and a compromised key is not kept trusted automatically to make historical results appear valid.

Downloads require an output directory owned by the invoking user and without group/world write permission. For a shared location such as `/tmp`, create an owned mode0700 subdirectory first. Patch/archive downloads retain one exclusive no-follow file descriptor through streaming and verification, publish without replacing an existing destination, and never reopen a writable temporary by pathname.
