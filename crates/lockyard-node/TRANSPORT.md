# Node transport

Node RPC payloads always use the locally imported workspace key. This applies even
when the workspace's older coordination fields do not require encryption. All
workspace participants share the key; Cloud stores and forwards ciphertext without
having that key. Execution hosts and their operators are trusted recipients.

`PayloadCodec` authenticates version, frame kind, request ID, source, target,
operation, and reply correlation as associated data. Direct and relayed frames use
the same `RpcFrame`. Metadata remains visible for routing and authorization.

## Direct connections

QUIC connections require mutual TLS, configured trust anchors, a registered SHA-256
certificate pin, and a configured node identity. A peer's explicit
`allowed_operations` list controls incoming requests. A caller cannot choose its
authenticated source identity through a payload.

`generate_identity` creates a certificate and PKCS8 private key in a private
directory. It refuses to overwrite existing identity files. `load_identity` checks
private key ownership and file permissions on Unix. Exchange the public certificate
and fingerprint through an authenticated control plane; private keys stay local.

`DirectClient` caches up to 128 live peer connections. Independent RPC and result
flows use independent bidirectional streams. A connection permits 16 concurrent
streams, with bounded flow control and a 256 KiB application frame limit. A listener
processes up to 128 handshakes concurrently. Keepalives run every 15 seconds, with a
60-second idle timeout. TLS early data is disabled. Configured direct peer policy
changes take effect when the listener is restarted.

## Relay connections

`RelayConfig::new` derives the WebSocket route from the configured Cloud URL and node
identity. The authenticated upgrade includes a bearer credential,
`X-Lockyard-Session`, and the `lockyard-node.v1` subprotocol. TLS certificates and
hostnames are verified against native roots and any explicitly supplied additional
trust anchors. Plain WebSockets are limited to an explicitly configured loopback
URL. Inherited HTTPS proxy and `NO_PROXY` settings are honored.

`RelayClient` maintains a persistent connection, bounded 16-message input and output
queues, ping/pong keepalives, and reconnect backoff. It exposes connection events
without dumping credentials or HTTP response bodies. A broken write has an unknown
delivery outcome. The transport does not replay messages automatically.

The caller retains an encrypted frame until a durable broker acknowledgement.
Replaying a frame ID requires resending the exact encrypted frame: encrypting the
same application content again produces a new nonce and therefore a different
frame. The executor separately deduplicates the stable job ID and complete job
specification. Transport delivery and job execution completion are separate events.

## Validation

Transport tests cover certificate trust and pins, anonymous client rejection,
authenticated source and operation enforcement, a stalled handshake alongside a
valid peer, oversized frames, mandatory encryption, routing metadata tampering,
private persistent identities, WebSocket authentication, TLS trust configuration,
and explicit replay after reconnect. Performance measurements must distinguish cold
connection establishment from warm encrypted RPCs and report their actual network
topology. Loopback measurements do not establish Internet or NAT performance.
