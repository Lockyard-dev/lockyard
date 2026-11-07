# Unified access revocation (EP-05 / revocations_v1)

A workspace uses a dedicated Ed25519 revocation signer, independent of encryption,
TLS, result signing and owner job approvals. An owner obtains its public key through
an authenticated HTTPS connection using the configured TLS roots, pins the workspace,
server origin, key ID and public key, and provisions that pin through the encrypted
node invitation or protected local node configuration. A list never supplies its own
trust. Replacing a signing key requires explicit provisioning; polling cannot replace it.

For an existing owner configuration, explicitly provision a new private config:

```sh
lockyard node revocation-trust --config owner.toml --output owner-enforced.toml
```

Review the new file and restart the daemon using that path. Invitations created
from it carry the pinned trust inside their encrypted bundle. A configuration
without revocation settings remains a legacy node without this enforcement.

```
lockyard revoke token <uuid> --node-config /absolute/node.toml --json
lockyard revoke identity worker --credential-id <uuid> --certificate-sha256 <64-lowercase-hex> --node-config /absolute/node.toml --json
lockyard revoke cert-pin <64-lowercase-hex> --node-config /absolute/node.toml --json
lockyard revoke sso-session <local-token-uuid> --node-config /absolute/node.toml --json
```

The `identity` form addresses a particular machine generation, rather than all future
uses of its node name. The `sso-session` argument is the local bearer session token ID,
rather than an external identity-provider session ID. The Cloud authenticates the
owner and enforces workspace, last-owner and dedicated-machine checks. Neither raw
credentials nor signed payloads appear in human-readable output.

Both MCP tool lists expose the same `revoke_access` definition. Its arguments are
`{"target":{"kind":"token","token_id":"…"},"node_config":"/absolute/node.toml"}`;
the other target variants use the same HTTP tagged union. `structuredContent` is the
same JSON returned by the CLI, and `isError` is true for a partial or unknown outcome.

The client persists an operation's protocol, path, canonical body and idempotency key
before POST. It verifies the signed receipt, fetches every page of the materialized
closure with a fresh challenge and `since=max(0,receipt.epoch-1)`, checks contiguous epoch coverage and the original target at the receipt epoch, then asks the running
local daemon to apply and fan out that closure. A token/session proof alone cannot
establish which direct certificate pins were revoked. Each peer acknowledges all
closure pages or remains pending; a closed QUIC connection before its response leaves
that peer pending even when it may already have applied the deny. Older peers without
the capability receive no new operation and remain pending.

Required direct sessions negotiate `revocations_v1` and `revocations_enforced:true`
in authenticated encrypted `node.ping` messages before ordinary RPC. Permit
`node.ping` in peer operation policies. Negotiation belongs to the current TLS
session; a new connection negotiates again. An unconfigured or legacy peer is
refused before the original direct operation is delivered.

The response is
`{epoch,cloud_committed,local_applied,direct:{acked,pending},propagation_complete,code?}`.
CLI exit 0 means confirmed Cloud commit plus local application and all configured
reachable peer acknowledgements. Exit 2 means confirmed commit with incomplete direct
propagation. Exit 1 means definite failure or unknown commit; an unknown outcome has
`cloud_committed:null,code:"revocation_commit_unknown"`. Missing node configuration
leaves `local_applied:false` and propagation incomplete; the client cannot enumerate
unknown peers in that case. A closure download failure after commit retains
`cloud_committed:true` and exit 2.

An ambiguous POST is replayed once immediately with the original bytes and key.
An authentication failure on that replay cannot prove the first POST did not commit.
Unknown outcomes remain private in `.lockyard/private-revocations/`; restarting does
not generate another key or blindly replay an operation whose ledger retention is
unknown. Reconciliation after such a restart awaits an endpoint receipt lookup or a
specified server retention guarantee. A confirmed receipt resumes closure/application
without another POST. Another live owner credential for the same workspace must be
selected explicitly if the original bearer revoked itself. State and trust files are
atomically written mode 0600 in a mode 0700 directory and protected against concurrent
operations; they contain no bearer credential.

`revoke` and MCP `revoke_access` require previously provisioned trust. Without a
pinned signer, they return `revocation_signer_untrusted` with a `node revocation-trust`
setup hint before a Cloud mutation, without requesting `/revocations/key` or creating
a trust file. Use the explicit provisioning command above and supply the resulting
node configuration. Equivalent URL spellings use the same canonical trust/cache
scope. The enrolled pin and custom TLS roots are used; a response cannot override either.

Node startup requires a new challenge refresh before admitting direct sessions. A
complete refresh runs every 30 seconds, on reconnect and on untrusted SSE hints; a
notification is never authorization. Every page has the same signed snapshot, expiry,
nonce and epoch boundaries. Partial refreshes preserve learned denies and never renew
freshness. The monotonic offline limit defaults to 600 seconds and is configurable
as `revocations.max_offline_seconds` from 60 through 86400 seconds inclusive; node
configuration outside this range is rejected. At age greater than or equal to the
limit, `revocations_stale` forbids new direct sessions and new streams on cached
connections; an already started operation can finish. A
verified deny is published before matching live/cached connections are closed with
QUIC code `0x105` and reason `revoked`. The five-second closure deadline begins when
verified bytes arrive, rather than at the Cloud commit during polling or offline use.

The node's entire serialized `revocations.json` has a 32 MiB (33,554,432-byte)
budget, including signed documents, current/prior trust and epochs. A page still has
its separate 32 KiB payload and 64 KiB envelope limits. Exceeding the state budget
returns local `revocation_state_unavailable`: application/refresh is not acknowledged,
`complete_epoch` and freshness do not advance, and the previous durable file remains.
Already learned denies and `observed_epoch` remain enforced in the current process,
including closure and cache pruning of matching connections. Old denies or signed
evidence are never removed to make room. The offline fence keeps the deadline from
the last successful complete refresh; after restart, a new online refresh is required
before direct admission. An oversized saved file rejects startup without deleting it.

`tests/fixtures/revocations-v1.json` contains deterministic full, delta, empty and
multipage envelopes, canonical payload bytes and domain-framed signing bytes. The
fixture includes token, machine and SSO materialized pin closures. It was signed by an
independent Ed25519 implementation and verified by Rust; execution in the .NET server
suite and real multi-replica Cloud acceptance remain server deliverables. A legacy or
unsigned server cannot enable required direct admission.
