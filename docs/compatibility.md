<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Compatibility boundaries

EP-12 compatibility belongs exclusively to `lockyard-compat/src/legacy_v1.rs`.
`lockyard-core` and `lockyard-node` cannot depend on that crate. CLI, MCP, SDK,
and persisted-workflow adapters validate canonical `TaskId` and `BusTaskId`
through the same boundary; domain lookup retains the complete string.

Registry/local integer or digits input becomes `D-n`; bus input becomes `BT-n`.
Only an explicitly local boundary accepts `T-n`. Positive ordinals are bounded
by 9007199254740991. Canonical IDs retain prefixes and leading zeros. Protocol 2
returns strings. Protocol 1 numeric projection refuses IDs that cannot be
reconstructed exactly, including area-prefixed and padded IDs.

The full MCP `ToolRegistry` owns all definitions, handlers, aliases, and compact
visibility. The compact catalog has 16 tools: `revoke_access`, `start_work`,
`check`, `update`, `handover`, `finish_work`, `status`, `tasks`, `task_bulk`,
`registry_import`, `area_list`, `area_create`, `area_update`, `cloud_protocol`,
`task_add`, and `zone_renew`. Compact projects these definitions; `check` resolves
to the same handler, description, and schema as `zone_check`. `cloud_drain`,
`cloud_drain_status`, and `zone_catalog_put` are full-only.

Compact `task_add` requires `area` in its schema and rejects omission before
calling the shared handler; task numbers retain that area's prefix. Full
`task_add` keeps its existing optional `area` and default-area behavior.
Local `task_add` supports `general` (`D-*`); other registry areas require cloud mode.
Compact `zone_renew` accepts an optional `ttl` of 1–240 minutes (default 30).
The current `fence` is required only in cloud mode; local claims renew without
a fence. It uses the existing renewal handler, including refusals for foreign
and expired claims and, in cloud mode, stale fences. Full-catalog behavior
remains unchanged. Visibility never supplies authorization.

Since 0.3.5, cloud `start_work` and CLI `zone claim` apply requested idle holds with a separate renewal
after ordinary acquisition, using the acquired claim's fence and lease length. They work with
deployed servers that only support `hold_reason` and `hold_until` on renewal. A reason without
a deadline uses `expires_at`; a deadline without a reason is invalid. Failed hold renewal releases
only a claim created by this call, preserving a pre-existing reused claim and reporting the error.
Legacy replies without an operation-scoped creation receipt also preserve the claim on failure;
an empty earlier claim list cannot distinguish creation from concurrent same-session reuse.
Local mode validates hold inputs and takes the claim without renewal or stored hold fields; local
claims are not released for inactivity.
The optional public `idle_release_at` claim timestamp is accepted when present and omitted otherwise.

Compact `finish_work` and CLI `zone release` require an explicit id or an explicit all selector
when the agent owns several claims. Without either selector they release a sole claim by id, or
return zero when none are owned. Combining id with `all: true` / `--all` is invalid. Incoming
handover offers are excluded from ownership. `finish_work` refuses ambiguous ownership before
task submission; local `handover` also requires an id for multiple owned claims.

Compact MCP `status` adds `lost` containing up to ten recent losses, excluding timestamps
older than 120 minutes and retaining entries whose timestamp is absent. A failed loss lookup returns
`lost: null` while preserving the remaining status fields. CLI `status --json`
does not fetch lost claims and retains its existing fields and request count. The agent daemon
keeps historical lost entries separate from live claims. Checks, activity, and release use live
claims, so an idle-loss record for a still-live claim id cannot mark the whole claim as lost.

Claim, queue, and presence DTOs use canonical `session` in domain serialization.
Their historical `agent` field is accepted only by the schema-specific SDK codec;
CLI/MCP JSON now emits `session`. Nested/bare dirty-path task IDs and bus task
IDs use that same codec. Conflicting aliases are rejected, never silently chosen.

New owner-close content uses `owner_word` AAD. Only an established owner-close
context may use `OwnerDecisionV1Reader`: `owner_word` first, then historical
`value` only after authentication failure. Ordinary evidence/reason fields do
not receive that fallback. Exact replay preserves existing ciphertext and keys.

Counters are observable through `lockyard_compat::counters()` and local
`compat.jsonl` diagnostics, without cloud access. The directory is
`LOCKYARD_DIAGNOSTICS_DIR`, otherwise `$XDG_STATE_HOME/lockyard/diagnostics`,
otherwise `$HOME/.local/state/lockyard/diagnostics`. Counters record only fixed
kind/source/protocol labels, never IDs, sessions, plaintext, or ciphertext:

- `lockyard_compat_conversions_total{kind,source,protocol}` increments once per
  converted field at each input/output boundary. Kinds include legacy task IDs,
  task receipts, and wire shapes; malformed and canonical values do not count.
- `lockyard_compat_aad_value_reads_total{source}` increments only after successful
  historical owner-decision decryption; canonical reads and failures do not count.

07 February 2027 00:00 UTC is the earliest release-3 removal date for numeric,
bare-digits, local T-ID, and legacy header/response syntax. Release 3 supports
3/2 and retires protocol 1; rejected wire syntax reports `legacy_input_removed`.
Protocol 2 does not change on a timer. A delayed release requires an updated
published date. Removal also requires 30 observed days of zero legacy wire
counters, upgraded supported clients, staged offline-outbox census, and tested
rollback. Unknown offline copies are never considered migrated.

Historical AAD `value` reads have no calendar sunset. Removal requires verified
re-encryption of all retained copies/backups with customer-held keys and an
agreed contract release. Unknown or nonzero inventory retains the isolated
reader and metric until the next review. Immutable archives need a versioned
archive reader. Unsupported offline records are quarantined with
`legacy_upgrade_required`, preserving original keys/ciphertext/schema.

Workflow receipts retain the exact input plan and operation/idempotency keys.
Comparison projects only a historical resolved-plan ID field to the canonical
string schema. Unknown writes stay unknown and are never automatically repeated.
Workflow failure classification recognizes known refusals of the requested effect
with their matching HTTP status; a refused legacy zone claim may still admit the
caller to its queue. An explicit resume after `version_conflict` or
`task_already_claimed` first verifies completed ownership and reads the refused
step's current state. A permitted new attempt receives a fresh key and retains
the rejected key/error in its receipt history. Changed pinned versions, live
assignments, unavailable reads, and old receipts without matching HTTP evidence
stop before another write and require reconciliation or a new chosen operation.
Unknown codes, invalid response authentication, and idempotency conflicts retain
the reconciliation barrier and their original operation/key/body.

Both CI gates are required: `scripts/ep12-architecture.py` verifies AST structure
and dependency direction; `scripts/ep12-production-scan.py` inventories production
AST declarations/literals for the exact EP-12 grep. Parse errors and empty scope
fail closed. Only the exact compatibility path is allowlisted. Negative fixtures
cover docs, inline/external tests, DTO fields, legitimate binder calls, legal
compatibility declarations, and production copies/renamed policies.

Existing test expectations changed only where EP-12 requires canonical strings
instead of numeric task IDs/numeric schemas, canonical session fields in place
of domain agent aliases, and where EP-10 requires
`cloud_protocol` on the compact surface. Historical numeric inputs, exact replay,
and area-preserving lookup remain covered. Claims, fences, messages, and handover
claim IDs retain their separate numeric identities.

W4 also changes owner-context authentication failures to the stable
`content_authentication_failed` code in every encryption mode; a failed owner
word is never presented as a display placeholder. Protocol fixtures now echo the
selected version and repository, and modern error fixtures carry stable codes.
Creation receipts reuse the claim decoder/classification; ProblemDetails text is
explicit clear protocol metadata, not encrypted application content.

Local SQLite generation 7 adds canonical task keys and dual event references.
Stop old binaries before switching. A per-connection generation function guards
all user-table mutations, so a connection left open by an older binary fails
before writing; new opens by old binaries reject the newer schema version.
The integer keys remain storage surrogates. Workspace/package version 0.2.1
satisfies the existing changed-crate version gate; this is not a deployment.

Short-lived local writers retain the SQLite WAL between commands instead of
checkpointing and removing WAL/SHM at every close. Each commit uses
`synchronous=FULL`; the normal 1000-page automatic checkpoint remains enabled.
Committed rows are read from the WAL when the next process opens the database.
Short CLI exits leave the WAL in place. Long-lived MCP, monitor, agent and node
processes attempt `wal_checkpoint(TRUNCATE)` on graceful shutdown after their work
has stopped. SQLite excludes concurrent writers during the checkpoint. A busy
reader/writer or another checkpoint can prevent completion: the process logs the
failure and preserves the WAL, so shutdown alone is not a general backup boundary.
Use `lockyard db backup <path>` for backups, including after short CLI writes.
It takes a consistent SQLite backup API snapshot without checkpointing the source,
finalizes a standalone database without WAL/SHM, and atomically publishes it with
private Unix permissions `0600`. Existing files, directories and symlinks (including
dangling links) are refused. The destination's parent must already exist. Restore
only a previously completed snapshot with all project processes stopped; do not
copy only a live `lockyard.db` or drop sidecars containing committed data.
Cloud pending-journal syncs, ownership guards and frozen replay bytes are unchanged.
The CLI's broken-database fixture removes retained WAL/SHM before corrupting the
main file; otherwise SQLite legitimately recovers it from the WAL. All hook-denial
expectations remain unchanged; platform performance thresholds are documented in
[performance budgets](performance.md).

Typed catalog schema/manifest artifacts are prepared from EP-07. The concurrent
cloud generator still needs equivalent additions; cross-repository byte parity
must be restored before server integration acceptance. See the W4 core report.

W4 round 2 keeps an unknown outbox write queued and reports `outcome_unknown`
to its waiter. A restarted durable sender can replay only the saved wire body,
key, path and protocol for the coordination endpoints whose receipt ledger is
guaranteed for 30 days; replay stops one minute before that boundary. Neither
replay nor restart resets the original send time. Missing age or original-request
identity, unsupported endpoints and expired records stay quarantined for receipt
or domain-state reconciliation. A failed replay cannot prove the first attempt
failed, including a new authentication or protocol refusal.

Pending acknowledgement binds the original method, path, session, repository and
body digest before randomized encryption. A mismatch leaves the recovery record
intact. Repository qualification is identical for sending and acknowledging, with
no network probe during acknowledgement. Older journals without that digest stay
pending until explicit reconciliation. Generic transports now validate the entire
strict typed catalog before expanding any name; optional legacy support remains
an explicit SDK adapter.

W4 round 3 retains the original encrypted bytes after pre-execution rate limits,
relay backpressure and freeze/drain refusals (EP-10 / ERRORS). Matching calls reuse
the frozen protocol, path, body and key. A durable refusal marker is cleared before
each send; uncertainty or a changed encryption context requires reconciliation.
Older records without an encryption-context binding also stay quarantined.
Concurrent sends and acknowledgements share exclusive journal ownership. Journal
preflight therefore precedes discovery: the preflight regression now requires zero
HTTP requests instead of one discovery request, strengthening its no-send guard.
