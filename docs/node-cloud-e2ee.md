# Cloud content inside node jobs

Node RPC payloads always use authenticated workspace encryption, independently of the legacy workspace encryption preference. Verified QUIC mTLS or HTTPS/WSS protects the connection in addition to that encryption. The cloud receives routing metadata and ciphertext, without the workspace key.

For a node job, the executor also sets `LOCKYARD_REQUIRE_E2EE=1` and `LOCKYARD_E2EE_WORKSPACE_ID` to its actual workspace identity. It passes both variables, `XDG_CONFIG_HOME`, and the explicit job cloud context into Codex's MCP child. A cloud-enabled profile gets a fresh private, read-only copy of the one approved workspace key; host home directories and the original key store are not mounted. Helpers used to collect the patch receive neither the key nor the cloud credential.

The Cloud client verifies the server's workspace identity and loads that local key before content operations. Legacy `encryption=off` still encrypts in this mode. A missing key, missing policy endpoint, mismatched workspace/key ID, disabled context, or attempt to rebind the required workspace fails closed. Required-mode calls bypass the legacy user-agent socket because its handshake does not attest an encryption policy.

Content transformations follow the embedded API schemas and content-field table. Required mode rejects unknown API operations, unknown query parameters, full-text `q` searches, unsupported arbitrary JSON, and legacy bulk imports before sending them. Serialize structured board content to text locally. Perform full-text filtering after decrypting records locally. Declared timestamps in this mode use canonical UTC text with milliseconds, or bounded epoch milliseconds where supported. Coordination identities, paths, labels, counters and fixed liveness fields remain routing metadata.

Responses authenticate encrypted content, including array results, typed event payloads and their documented aliases. Unsupported event payload types or plaintext/tampered content produce an error. An existing `lyenc1` prefix alone is insufficient: a queued outgoing envelope must authenticate with the bound workspace key before transmission.

This protects the product's normal data paths. Execution hosts and their administrators are trusted, and all workspace members share access to its key. A job deliberately given a secret can transform it or send it over its allowed network; exact-byte output filtering is not protection against arbitrary malicious encoding. Revocation does not erase a key or historical plaintext already obtained by a member.

## Evidence

The Cloud-client regression suite covers forced encryption with the old setting off, missing keys/policy, workspace binding, plaintext/invalid responses, query and JSON bypasses, existing-envelope authentication, arrays, event aliases and bounded liveness timestamps. Envelopes require canonical base64 spelling. Local key copies publish a complete fsynced temporary file atomically without replacing an existing key; interrupted private temporaries do not block retry. `tools/ci/required-e2ee-mcp.py` additionally runs the actual CLI MCP child against isolated synthetic HTTP and Unix fixtures. It verifies encryption, local reply decryption, refused writes and zero contacts to an unverified legacy agent.

These tests do not establish successful execution inside a resource-enforced container, a model-provider call, or production network SLOs. Those have separate acceptance evidence.
