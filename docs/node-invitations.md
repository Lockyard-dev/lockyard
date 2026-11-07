# One-use node enrollment

Node invitations bootstrap a Unix node through verified HTTPS and the encrypted relay. The inviting device needs an **owner** credential and the local workspace key. Ordinary workspace agents continue to dispatch work; invitation administration does not restrict that dispatch entitlement.

Native node IDs cannot start with `web_`; that namespace is reserved for browser identities and cannot be claimed through machine invitations.

On the recipient server, prepare fresh private state and a public identity request:

```sh
lockyard node prepare-join --node-id worker-1 --tls-name worker-1.example \
  --state-dir /srv/lockyard/worker-1 --request /srv/lockyard/worker-1-request.json
```

The parent directory must already exist. The command creates private TLS and result-signing keys with mode `0600` inside a directory with mode `0700`. The request contains public certificates and signing identity, and can be shared without confidentiality. Its origin and certificate fingerprint must be authenticated before an owner grants it access. Preserve mode `0600` when transferring files for these commands.

On the inviting device:

```sh
lockyard node invite --config /private/owner-node.toml \
  --request /private/worker-1-request.json --output /private/worker-1.invite.json \
  --expires-seconds 900 --credential-days 30
```

The configured workspace must be the canonical Cloud workspace UUID. The relay URL uses verified HTTPS/WSS, and the public proxy must preserve the external `Host` and `PathBase`. A custom broker CA may be configured through `relay.tls_roots`; verification is never disabled.

The transferable invitation contains a high-entropy secret and public routing/trust metadata. **It contains no workspace key or encrypted key bundle.** The bundle is retained by the broker as ciphertext until successful first redemption. Transfer the invitation confidentially and authenticate its origin. The separate `*.pending` owner receipt contains retry material and must stay on the inviting device. If creation loses its response, resume that exact receipt:

```sh
lockyard node invite --config /private/owner-node.toml \
  --resume /private/worker-1.invite.json.pending
```

The owner command also writes a `*.result-trust.json` proposal containing the recipient's public result-signing pin and request digest. Review and install that pin in the owner's `result_trust` configuration before accepting signed patches. The command does not change a running daemon's trust configuration.

On the recipient, use the same prepared state directory:

```sh
lockyard node join --invite /private/worker-1.invite.json \
  --state-dir /srv/lockyard/worker-1 --config /srv/lockyard/worker-1.toml
lockyard node serve --config /srv/lockyard/worker-1.toml
```

Joining saves a local workspace key, a distinct machine bearer, broker trust anchors and private node configuration. It also returns public result-signing configuration for the executor. Configure the local checkout, container runtime and allowed runner profiles separately before enabling execution. An invitation initializes relay connectivity; direct QUIC still requires explicit certificate pairing and direct peer policy, as described in [nodes.md](nodes.md).

The machine bearer is restricted to its bound node's registration, directory and relay connection. It cannot call registry, coordination, invitation or administration APIs. A runner that needs Cloud MCP coordination uses a separate explicitly configured job credential; the machine bearer is not a substitute.

The recipient persists its random bearer, hash and certificate signature before sending a redemption request. If the reply is lost, repeat the same join command with the same invitation and state directory. The broker transaction creates one identity. An identical authenticated claim can recover that identity until 24 hours after invitation expiry, provided the machine credential is still live. A different token hash, node or certificate cannot consume another grant. This is one grant with bounded retry recovery, not a ban on identical transport retries. After a completed join, a repeat verifies the saved local state without creating another identity.

First redemption must occur before expiry. The default is 15 minutes, with an explicit range of 60 seconds through 24 hours. Machine credentials default to 30 days and can be configured up to 366 days; they must outlive the invitation. The broker discards encrypted bundles after the recovery window. Unredeemed invitation metadata is retained for 30 days after expiry. A redeemed invitation remains a revocation handle until its machine credential expires, plus 30 days. These control-plane lifetimes are distinct from project job retention.

Revoke an invitation and any machine credential it already granted:

```sh
lockyard node invite-revoke INVITATION_ULID --config /private/owner-node.toml
```

Revoking the issuer invalidates its unused invitations. Existing grants are separate revocable machine identities. A revocation does not erase a workspace key already delivered to a trusted endpoint, retroactively hide old history, or revoke manually paired direct certificates. Remove direct trust and perform the separately managed workspace-key rotation when revoking a member or responding to compromise. Already authorized execution retains its existing offline behavior; connection revocation is not a process-kill command.

For deliberate replacement or credential renewal under the same node name, first inspect its exact generation. This owner-only lookup includes expired and revoked bindings:

```sh
lockyard node binding worker-1 --config /private/owner-node.toml
lockyard node retire worker-1 --credential-id OLD_CREDENTIAL_UUID \
  --certificate-sha256 OLD_CERTIFICATE_SHA256 --config /private/owner-node.toml
```

Retirement requires the expected credential ID and certificate. It revokes that dedicated machine identity, invalidates queued work and replies bound to that generation, releases its name/session reservation and preserves a compact retirement receipt. An identical retry returns the old receipt and cannot retire a replacement generation. A shared owner/agent credential is rejected by this operation so an unrelated controller or administrator is not revoked accidentally.

After retirement, prepare a fresh recipient state directory and issue a fresh invitation for the same name. Review any changed result-signing pin explicitly; an existing independent pin is never silently replaced. Old direct QUIC trust must be removed separately, and the old daemon must be stopped before replacing its physical endpoint. Cloud retirement fences relay generations, while already authorized execution keeps its offline behavior. The broker does not replay old queued work into the replacement identity.

The broker stores only the claim proof's SHA-256 hash, the client-generated bearer hash, public identity and routing metadata, and ciphertext. Separate HMAC domains derive the claim proof and encryption key, so a proof received by the broker cannot decrypt the bundle. The recipient's P-256 certificate signature binds the invitation, workspace, full public request digest, issuer, broker namespace, lifetimes and bearer hash. AES-GCM binds the encrypted key/trust bundle to the same invitation context. Execution hosts and their administrators remain trusted endpoints.
