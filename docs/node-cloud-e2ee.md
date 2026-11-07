# Cloud content inside node jobs

Node RPC payloads always use authenticated workspace encryption, independently of the legacy workspace encryption preference. Verified QUIC mTLS or HTTPS/WSS protects the connection in addition to that encryption. The cloud receives routing metadata and ciphertext, without the workspace key.

For a node job, the executor also sets `LOCKYARD_REQUIRE_E2EE=1` and `LOCKYARD_E2EE_WORKSPACE_ID` to its actual workspace identity. It passes both variables, `XDG_CONFIG_HOME`, and the explicit job cloud context into Codex's MCP child. A cloud-enabled profile gets a fresh private, read-only copy of the one approved workspace key; host home directories and the original key store are not mounted. Helpers used to collect the patch receive neither the key nor the cloud credential.

The Cloud client verifies the server's workspace identity and loads that local key before content operations. Legacy `encryption=off` still encrypts in this mode. A missing key, missing policy endpoint, mismatched workspace/key ID, disabled context, or attempt to rebind the required workspace fails closed. Required-mode calls bypass the legacy user-agent socket because its handshake does not attest an encryption policy.

Content transformations follow the embedded API schemas and content-field table. Required mode rejects unknown API operations, unknown query parameters, full-text `q` searches, unsupported arbitrary JSON, and legacy bulk imports before sending them. Serialize structured board content to text locally. Perform full-text filtering after decrypting records locally. Outgoing declared timestamps use canonical UTC text with milliseconds, or bounded epoch milliseconds where supported. Coordination identities, paths, labels, counters and fixed liveness fields remain routing metadata.

Responses authenticate encrypted content, including array results, typed event payloads and their documented aliases. Unsupported event payload types or plaintext/tampered content produce an error. An existing `lyenc1` prefix alone is insufficient: a queued outgoing envelope must authenticate with the bound workspace key before transmission.

Required-mode responses reject unknown fields, invalid field types, unclassified JSON and legacy claim/queue metadata. Nullable nested DTOs are traversed as well. Presence accepts only the same fixed resource/liveness metadata allowed on writes, and metadata-only events use explicit field/type allowlists. These checks classify routing metadata; they do not authenticate its values with the workspace key. Authenticated `legacy_raw` text remains readable. Opaque catalog reads and non-null legacy `hold_until_ref` values are unsupported in required mode until their API contracts can classify them safely; ordinary optional-encryption clients retain their compatibility behavior.

This protects the product's normal data paths. Execution hosts and their administrators are trusted, and all workspace members share access to its key. A job deliberately given a secret can transform it or send it over its allowed network; exact-byte output filtering is not protection against arbitrary malicious encoding. Revocation does not erase a key or historical plaintext already obtained by a member.

## Evidence

The Cloud-client regression suite covers forced encryption with the old setting off, missing keys/policy, workspace binding, plaintext/invalid responses, query and JSON bypasses, existing-envelope authentication, arrays, event aliases and bounded liveness timestamps. Envelopes require canonical base64 spelling. Local key copies publish a complete fsynced temporary file atomically without replacing an existing key; interrupted private temporaries do not block retry. `tools/ci/required-e2ee-mcp.py` additionally runs the actual CLI MCP child against isolated synthetic HTTP and Unix fixtures. It verifies encryption, local reply decryption, refused writes and zero contacts to an unverified legacy agent.

These tests do not establish successful execution inside a resource-enforced container, a model-provider call, or production network SLOs. Those have separate acceptance evidence.

## Node RPC key separation

RPC version2 derives a fresh child encryption key for each authenticated frame context with HKDF-SHA256. The salt is `lockyard-node-rpc-v2`; the info is compact JSON `[workspace, authenticated_field]`. The authenticated field binds version, request/response kind, unique frame ID, source, target, operation, correlation and any retention/incarnation pins. Existing AEAD also binds workspace and that field. The envelope key ID identifies the child key, so it is not the workspace master-key ID. A public independent HKDF/AES-GCM vector lives in `crates/lockyard-node/tests/fixtures/rpc-v2.json` and is shared with browser tests.

This avoids putting the entire high-rate node fleet's encryption traffic under one AES-GCM key and does not periodically rotate the customer workspace master key. The backend stores and forwards the exact RPC version and requires a matching response version. Version1 remains readable for legacy read requests; mutations require version2 and have no downgrade fallback. Transport ALPN/subprotocol and delivery ACK framing retain their own version1 names.

Drain and reconcile pending mutation requests before a daemon/protocol upgrade. A legacy mutation that cannot be delivered remains uncertain until explicitly reconciled; the client does not generate a replacement execution automatically.

Required-mode claim conflict notes are authenticated in `zones/check` holders, queued claim conflicts and HTTP409 error details. Unknown conflict shapes and unauthenticated/plaintext note values fail locally. Required-mode server error messages are replaced with fixed HTTP-status text; known typed error metadata remains available, and the stored freeze reason is decrypted with its original `reason` context. This closes compatibility JSON slots that the generated schema alone cannot classify.
