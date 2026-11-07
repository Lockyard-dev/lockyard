# Customer-local workspace-key rotation

Rotate a workspace key after a member/node is revoked or a key is compromised. There is no periodic master-key rotation. This workflow uses only local customer files and customer-delivered capsules; it does not send a new key, recovery phrase, private signing key or wrapping secret to the Lockyard cloud.

An organization pins its own Ed25519 rotation authority independently on every retained node. A cloud Owner role, directory response or included public key cannot replace that pin. The owner prepares a fresh random 256-bit workspace key and RFC 9180 HPKE capsules for an explicit local roster of retained P-256 node TLS certificates. HPKE uses DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM. The Rust HPKE/RustCrypto libraries implement those primitives; this is not a claim that this application has received an external cryptographic audit or FIPS certification.

The signed plan binds the workspace, exact next epoch, old/new key IDs, revocation/compromise cause, history policy, authority, expiry, every recipient certificate fingerprint and every capsule digest. The Ed25519 authorization signs a bounded canonical digest statement including the workspace/epoch/new key ID. The whole recipient plan is hashed without truncation, including at the maximum 512-node roster. Capsules authenticate the header and recipient node/certificate as associated data. A revoked node excluded from the roster has no capsule it can decrypt. The cloud cannot substitute a chosen key or recipient without invalidating the pinned authority's authorization.

## Establish the authority once

Generate the authority on the owner's trusted local machine, preferably offline, after importing its local workspace key. Normal private authority files must be direct children of the protected global `lockyard/keys/rotation-authorities` directory; arbitrary paths and overrides are refused. The command creates that private subdirectory when its already-private global keys parent exists:

```sh
ROTATION_AUTHORITY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/lockyard/keys/rotation-authorities"
lockyard node key-rotation authority-generate --output "$ROTATION_AUTHORITY_DIR/authority.pk8"
```

The command prints only the public key and authority key ID. Keep the private PKCS#8 file outside repositories, node workload mounts, cloud configuration and synchronization. Independently verify the public key on each retained node, then pin it explicitly:

```sh
lockyard node key-rotation authority-pin --config /private/node.toml --public-key VERIFIED_64_HEX_PUBLIC_KEY
```

Pinning is create-only. Authority replacement/recovery is deliberately a separate customer-controlled trust-provisioning action; a received rotation bundle cannot change it. The pin is private authentication configuration, not a new workspace key.

## Prepare and review

Revoke the departed user's human sessions/membership and relevant machine credentials first. The human revocation API persists `revoked_at` and returns `Lockyard-Key-Rotation-Required: member_revocation`; this is a request to run this local workflow, not proof of cryptographic completion. A compromised machine's credential retirement and direct certificate policy remain separate controls.

Create a private JSON roster using independently approved local certificate files. Include the owner node that prepares/verifies completion. Node IDs, certificate fingerprints and P-256 public keys must be unique. Preparation also rejects public-key reuse from locally known excluded or replaced peer certificates. After private-key compromise, generate a fresh TLS keypair: issuing a new certificate around the same compromised key does not revoke its holder. The owner must independently check the full recipient inventory; a certificate alone cannot prove that its private key was never shared with an unknown third party:

```json
[
  {"node_id":"owner","certificate":"/private/owner/node-cert.der"},
  {"node_id":"worker","certificate":"/private/worker/node-cert.der"}
]
```

```sh
lockyard node key-rotation prepare --config /private/owner.toml \
  --roster /private/rotation/remaining-nodes.json --reason member-revocation \
  --history discard --epoch 1 --expires-at-ms ABSOLUTE_UNIX_MILLISECONDS \
  --output /private/rotation/draft.json
```

Expiry must be in the future and no more than seven days after creation. Later rotations advance the installed local epoch exactly once. Review the printed workspace, cause, history policy, authority, old/new key IDs and complete node/certificate roster. The unsigned draft cannot be installed. Approve its exact printed `plan_sha256`:

```sh
lockyard node key-rotation commit --draft /private/rotation/draft.json \
  --signing-key "$ROTATION_AUTHORITY_DIR/authority.pk8" --approve-plan REVIEWED_PLAN_SHA256 \
  --output /private/rotation/committed.json
```

The committed file contains public metadata and opaque recipient capsules. Deliver it through a customer-approved offline/authenticated channel to each retained node. Even an untrusted transport cannot change its contents successfully, but delivery metadata may still be sensitive. Automatic cloud capsule transport is not part of this implementation.

## Drain, stop, apply and collect receipts

On every retained node, request local operator drain and inspect its status:

```sh
lockyard node drain --config /private/node.toml
lockyard node drain-status --config /private/node.toml
```

Drain stops admission of new work. Already admitted work continues and exact existing IDs remain reconcilable. Wait for local queued/running work, unresolved execution and active distributed workflow steps to reach zero. Reconcile an uncertain execution explicitly; rotation never replays it. Stop the daemon and standalone executor processes. All daemons sharing the same local workspace-key file must be stopped; they hold a shared key lock throughout their lifetimes.

```sh
lockyard node key-rotation apply --config /private/node.toml \
  --bundle /private/rotation/committed.json --output /private/rotation/node-receipt.json
```

Apply verifies the independent authority pin, complete signed plan, recipient certificate/private key, HPKE capsule, epoch and key commitment. It acquires the host/executor locks plus the exclusive workspace-key lock and inspects persisted work without opening an executor or launching recovery. It requires durable local drain. Key/configuration/state updates use fsynced staging and a forward-only recovery journal. A pending local or shared-key journal blocks startup. The installed configuration removes excluded or replaced direct peers and rebuilds its TLS roots from the remaining explicit peer certificates. Independent result-signing trust is cleared and must be explicitly reviewed/repinned; a TLS certificate does not authenticate an unrelated result-signing key.

Each completion receipt contains the node's certificate, a signature under its independently approved TLS identity and authenticated proof of possession of the new workspace key. It is bound to the exact plan, epoch and reconciled direct-trust state. A shared local key file also carries an epoch binding: another local node state cannot start on the new key until it applies the same signed plan to its own trust configuration.

Restart each daemon in its persisted drained state. Use a fresh output path when recovering a lost receipt or interrupted install:

```sh
lockyard node key-rotation recover --config /private/node.toml \
  --bundle /private/rotation/committed.json --output /private/rotation/recovered-receipt.json
```

Recovery reverifies the pinned authorization and finishes the exact pending transaction forward. It never rolls back to an old key. It can reissue a receipt for an exactly matching durable completed install, including after plan expiry; it cannot use an expired, never-installed plan to perform a fresh rotation. A retained node that missed the installation window requires explicit customer reconciliation and fresh current-key onboarding under a new node identity/state; retire its old identity and preserve unresolved old execution evidence. Do not reset or replay its old job journal to bypass expiry. Offline expiry is an intentional fail-closed boundary, not automatic delayed completion.

On the already updated owner node, collect and verify all receipts:

```sh
lockyard node key-rotation status --config /private/owner.toml \
  --bundle /private/rotation/committed.json \
  --receipt /private/rotation/owner-receipt.json \
  --receipt /private/rotation/worker-receipt.json
```

Status lists installation for every approved node and reports `complete: true` only after every distinct approved node has a valid receipt. An unavailable or partitioned retained node keeps completion false. Review direct policies, machine retirement and independent result-signing pins, then explicitly resume each node with `lockyard node resume --config /private/node.toml`. Group completion and resume are customer-operated; a cloud server cannot authorize them on the customer's behalf.

## Retained human clients

Node receipt completion covers the explicit node roster. Browser and other human clients need the new workspace key through a separate customer-controlled channel. From the updated owner's configured local checkout, `lockyard cloud key show-phrase` requires typing `SHOW` before displaying the current recovery phrase locally. Deliver it only to approved retained people through the customer's private channel; import it locally into the trusted browser/client. The phrase never belongs in a cloud message, URL, ticket, log or rotation metadata file. This manual human distribution is not an automatically verified part of node receipt completion.

The owner must also advance the public cloud key identifier with `lockyard cloud encryption require` from that same updated local environment. That command sends the public key ID and required-encryption setting, never the key or phrase. Until this metadata is updated, browser/ordinary cloud SDK key-ID checks can correctly reject a new local key as a mismatch. Perform this explicit metadata operation during the customer-maintained drain window; the offline rotation commands do not silently make network writes. A browser's existing nonextractable signing key is not a Node TLS HPKE recipient, so this release does not claim automatic in-browser capsule installation.

## History and revocation limits

`--history retain-private-history` keeps the previous raw key only in the protected customer-local `lockyard/keys/history/<workspace>/<old-key-id>.key` directory. It is not mounted into ordinary workloads or automatically used to authenticate RPC. Retention here provides recovery material for explicitly authorized local history processing; transparent multi-key browser/API history decryption is not implemented. Current RPC accepts only the current key context. Old captured RPC frames cannot read a cached response after a new-key restart.

`--history discard` creates no history copy. It does not securely erase media, backups, pre-existing orphan hardlinks, old ciphertext/plaintext caches, or another participant's previously saved keys/history. Previously retained history keys remain under their earlier explicit retention choice. Encrypted old history may remain unreadable on a customer client that discarded its old key.

Revoking a token or rotating a shared key cannot make a departed member forget old history or a previously known key. An isolated old-key group may continue communicating among itself. Cryptographic revocation is complete for the retained group only when every retained node has installed the new epoch and direct certificate policies are reconciled. It is not instantaneous for offline nodes. Trusted customer execution hosts and their administrators can access code they are authorized to execute; protection against an untrusted host/administrator or malicious delivered browser bundle is outside this trust boundary.

No real customer key or configuration is rotated by the development acceptance fixtures. Real deployment requires private customer storage, independent authority/certificate provisioning, tested recovery and the separate container resource-enforcement gate.
