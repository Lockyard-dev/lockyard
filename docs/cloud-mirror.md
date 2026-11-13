<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->

# Cloud zone mirror — local-fast hook guarantee

## Goal

A Claude Code (or other) edit hook must answer in milliseconds. Talking to the cloud server on every
`PreToolUse` is too slow (field runs saw ~1 s). The background agent therefore keeps a **local
mirror** of the workspace's zone claims, fed by the server event stream (long-poll
`GET /api/v1/events`), and the hook asks that mirror over a Unix socket.

## Guarantee

1. **Fresh view → answer from memory.** While the view's generation matches the last absorbed event
   generation and both the monotonic and wall clocks say the view is younger than `Timing::fresh`
   (default **30 seconds**), a path check is answered from the in-process claim list. No HTTP. The
   measured p95 on a quiet machine is under 5 ms (unit test
   `a_fresh_view_answers_from_memory_in_under_5_ms_with_no_server_call`); the CI budget is p95 ≤ 15 ms
   for the local hook path.
2. **Stale view → fail closed.** If the view is older than `Timing::fresh`, or an event arrived that
   the snapshot has not absorbed, the hook does **not** treat the path as free. The agent may make
   one short server call (deadline 800 ms); if that also fails, the check is `Unknown` and the hook
   **denies** the edit. A laptop that slept with a frozen mirror cannot allow a write the server
   would refuse.
3. **No agent process → deny edits.** Cloud mode without `lockyard agent` has no mirror; PreToolUse
   edit tools are refused with a message to start the agent.
4. **Leases are server time.** The mirror never compares a claim's `expires_at` to the client's
   clock. A claim leaves the view only when the server says so (release, expiry event, refresh).
   The 30-second freshness bound is the fence on the *mirror*, not a second lease.

## Events and reconcile

The agent long-polls the coordination event stream and invalidates the view on zone events, then
refreshes claims from the server. A periodic upkeep pass also refreshes so a missed event costs
latency, not a permanent lie. The same "events accelerate, reconcile is truth" rule applies to the
filesystem monitor on disk.

The lost list may contain `idle`, `expired`, or `unused_grant` entries as well as takeover losses.
An idle shrink can release only clean paths while retaining the claim's dirty paths. The agent
keeps lost history separate from live claims; check, activity, and release decisions use the live
claims. A historical lost entry for the same id cannot invalidate the claim's remaining paths.

## Local agent `zone_snapshot` protocol

Since 0.3.6, a local snapshot carries independent board freshness metadata alongside the zone
claims. Send one JSON line to the local agent socket:

```json
{"workspace":"your-team","op":"zone_snapshot","session":"alice"}
```

The snapshot handler copies the board from the in-process view. It never contacts the transport,
invokes a board refresh, or waits for one. Existing background upkeep refreshes the board
proactively, including before any client asks to read it. Registering a new session may nudge
background upkeep independently of the snapshot read. Consumers with a short local deadline
can read the snapshot without falling back to a network request; this protocol contract does
not establish a platform-specific 40 ms latency bound.

The following reply fields are additive and optional; a field whose value is unknown is omitted,
not serialized as `null`. Older clients may ignore fields they do not recognize, and newer clients
must accept replies from older agents with none of these fields:

| Field | JSON type | Meaning |
|---|---|---|
| `board` | array of board entries | Present only when the board is initialized and `board_fresh(Timing::fresh)` holds. Includes all cached entries, including entries with `zone: null`; it is not filtered by the requesting session or zone. An initialized, fresh empty board is `[]`. |
| `board_source` | string | `"view"` when `board` is present; `"none"` when the board is stale or uninitialized. No server source is used by this operation. |
| `board_age_ms` | nonnegative integer | Elapsed monotonic milliseconds since the cached board timestamp, included even when stale; omitted when that timestamp is unknown. A successful board refresh or clean event-stream confirmation updates the timestamp. |

Board freshness is independent of the existing zone `source` and `age_ms` fields. Consumers must
inspect `board_source` and the presence of `board` before treating an empty board as authoritative.
For example, these board fields distinguish fresh empty, stale, and uninitialized snapshots:

```json
{"board":[],"board_source":"view","board_age_ms":12}
{"board_source":"none","board_age_ms":31000}
{"board_source":"none"}
```

Every entry preserves its `key`, JSON `value`, optional `zone`, author in `session`, `expires_at`,
`created_at` and the existing `updated_at` field. A global entry has `zone: null`. Timestamps retain
the server's spelling (normally RFC 3339 strings); local timestamp values may be epoch milliseconds.
Legacy entries that do not supply provenance decode with `session: ""` and `created_at: 0`, meaning
the author and creation time are unknown.
For example, a fresh snapshot with a zone freeze and a global announcement can return:

```json
{
  "source": "view",
  "claims": [],
  "queue": [],
  "requests": [],
  "lost": [],
  "age_ms": 10,
  "board": [
    {
      "key": "freeze",
      "value": {"reason": "release in progress"},
      "zone": "api",
      "session": "lead",
      "expires_at": "2026-11-12T12:00:00Z",
      "created_at": "2026-11-12T11:00:00Z",
      "updated_at": "2026-11-12T11:00:00Z"
    },
    {
      "key": "notice",
      "value": "Review the release announcement",
      "zone": null,
      "session": "lead",
      "expires_at": null,
      "created_at": "2026-11-12T10:00:00Z",
      "updated_at": "2026-11-12T10:00:00Z"
    }
  ],
  "board_source": "view",
  "board_age_ms": 12
}
```

## What this is not

The mirror is not authoritative for mutations. Every claim, renew, release and mail send still goes
to the server with an idempotency key. The mirror exists only so **reads that gate an edit** stay
local-fast without going open when wrong.

## CLI status (0.3.7)

`lockyard status --json` uses a separate authoritative read path. It probes the additive
`status_read_v1` capability, checking the URL, workspace and caller token when available. The
probe receives `min(100 ms, remaining / 20)`. Tokenless access preserves the existing authenticated
agent behavior and endpoint/workspace checks; it grants no new access to a foreign endpoint.
Required encryption contexts continue to use their own verified direct client.

`LOCKYARD_STATUS_DEADLINE_MS` sets the whole CLI wait, default 6000 ms, accepted range 1..=60000 ms.
An empty value uses the default; invalid values fail closed and name the variable and accepted range.
Setup and network reads get
99% of that limit (5940 ms by default); local decoration has a separate 50 ms cap. After probing,
the aggregate gets `min(1500 ms, remaining / 4)`, keeping the uncontended warm route's tight limit.
At least three quarters of the then-remaining read budget is reserved for one direct fallback.
For example, with all 100 ms spent probing, 5840 ms remains; the aggregate gets 1460 ms and a hung
aggregate leaves 4380 ms for direct discovery and reads. Earlier setup time reduces both shares.
An absent or old daemon skips the aggregate. No fixed agent wait is subtracted from a shorter
configured deadline. The consuming hook has an 8-second hard-call timeout and a separate
0.85-second soft-call timeout; the latter can terminate a cold call before its CLI deadline.

Direct status clients retain only a modern protocol-2 negotiation hint in the existing private,
origin/credential-scoped journal directory (`status-protocol.cache`). The hint expires after 30 seconds
on the maximum of wall and boot-monotonic ages; future/stale clocks, a different boot, invalid private
file permissions, symlinks, corrupt data and legacy hints all cause a normal discovery miss. On macOS
where sandbox policy denies the native boot ID, both clock ages and a derived boot epoch within one
second are required. This fallback is a negotiation hint only, validated again by live response echoes.
Unsupported protocol responses invalidate the hint and perform normal negotiation. Loading a hint does
not refresh its age. Workspace encryption policy, claims, mail, work and assignments remain live reads
(or the documented unread view); ordinary commands do not opt into this hint. This removes a repeated
discovery round trip across separate cold CLI processes while preserving the claims-first order.

A direct or cold-agent read first completes the authoritative claims request on one connection,
performing discovery/encryption negotiation once and warming the pool. The two mandatory assigned-task
page chains precede optional mail and work. A one-shot direct client reads these sections in sequence
on its existing connection; the long-lived agent pool overlaps their independent reads.
A successful authoritative claims response marks the connection usable for later aggregates, even if a later task read in that first aggregate times out. That first cold aggregate keeps claims-first ordering; later aggregates overlap the independent reads. Each assignment cursor remains sequential
and complete. Claims and assigned tasks must succeed; an unavailable mandatory read exits nonzero.
Mail has the entire remaining deadline, while its failure and optional work failure do not fail
status. JSON keeps list-valued `claims` and `tasks`, task assignees/stages/update timestamps, and
additive per-section availability/source/age metadata.

The daemon admits three running aggregates and queues up to 128 callers inside their request deadlines.
Identical session/repository callers can join a pending generation during its short collection window;
the read starts after every member arrived. Once dispatched, that generation accepts no new callers,
even while its HTTP read is still in flight. A later caller starts or joins a later pending generation.
Completed generations are never reused. Thus every successful caller receives claims from a network
read that began after that caller's request. Queue expiry and an underlying cold-agent network timeout fall back through the CLI to one cold
claims-first read. Rate limiting and protocol/data errors remain explicit failures. The daemon's shared client caps all HTTP workers, including background upkeep and
long polls, at eight. One worker is reserved for writes and one for event long polls; general reads
can use at most six. Additional writes/polls may borrow a general slot when available. Waiting for a
worker consumes the same deadline. Bounded general admissions are FIFO, so new upkeep/section reads
cannot overtake existing waiters. Reserved writes/polls bypass that general queue; cancellation and
deadline expiry remove their general tickets immediately. Ordinary uncapped direct clients keep their
previous admission policy. A new status session is registered before reading unread state, but its
upkeep wake is deferred until a successful live aggregate completes, avoiding redundant refreshes
competing with that aggregate. Other commands retain their registration/wake behavior.
After queueing and setup, the daemon gives HTTP `remaining - min(25 ms, remaining/20)`, reserving the small balance for expiry checks, JSON and IPC. Mail still receives the whole HTTP budget, so its optional timeout can return an agent answer before the socket deadline.

Claims are **never** served from the zone mirror by this path, including after a network gap,
sleep/wake, event invalidation or restart. Expiry and idle expiry are checked after other reads and
again before output. HTTP `Date` supplies a conservative server-time upper bound (second rounding
plus request elapsed time). Each observation uses `max(previous advanced value, new value)` so an
older response cannot resurrect an expired lease. Without Date, freshness explicitly reports
`claims_clock_source: "local_fallback"` and `claims_local_safety_margin_ms: 30000`: advancing the local
comparison by 30 seconds shortens the apparent lease by that margin. This finite margin cannot prove
safety against arbitrary clock skew. An unknown expiry fails closed. A revoke after the server read
can race any read-only client; mutations still require the current fence.

Only unread counts may use the in-memory view. An initialized, generation-clean count younger than
30 seconds on both monotonic and wall clocks may be served as fresh. Otherwise status tries the network
for its remaining deadline. If that fails, the agent retains its last known count, including a dirty
or old count, with `stale: true` and its conservative `age_ms`; unknown remains `null`, never an invented
zero, with `freshness.sections.unread.source: "unknown"` and `available: false`.
No persistent claim/status cache is introduced.

While queued or running, each status handler checks local peer EOF/errors using the same
UnixStream/Windows LocalStream read abstraction, at 5 ms queue wakes plus a 1 ms bounded read
(subject to OS scheduling). It removes that caller independently of the network worker. Empty pending
generations are discarded before HTTP; the last departing member cancels a running generation and its
result is dropped. Ping adds an optional `status_read_abandoned` hint only while such a running
zero-member generation remains AND every generation is occupied; while one is free the agent still
answers and callers stay on it. A direct (cold) read fetches claims first and then the remaining
sections one after another on the same connection. With the hint set, a status caller with its own matching credentials skips that local
agent allocation and starts its direct read immediately, preserving almost the full CLI deadline.
Tokenless callers retain the authenticated-agent route. Older agents omit the hint; older CLIs ignore
it. This advisory snapshot can race EOF detection, so it is not itself a hard real-time guarantee.
One departing member never cancels live coalesced members. Each member keeps its own
wait deadline; dispatch uses the latest member deadline, so a departed short-budget caller cannot
shorten another member's read. Pipelined local requests are preserved while checking for EOF.

The HTTP pool retains eight idle connections per host. Cancellation stops worker-admission waits,
discovery-lock waits and retry pauses within a 10 ms poll, and prevents subsequent page/section reads.
ureq 2 cannot interrupt an already blocked request: ordinary HTTP header/body waits use its original
remaining status budget (at most 2600 ms). TLS handshake uses blocking socket timeouts initialized
from that budget; no absolute handshake bound under continual peer progress is established here.
TCP connect has a separate fixed 2-second cap, and OS DNS has no finite library cancellation bound.
Already-started synchronous JSON decoding is also not token-preemptible. A cancelled response is dropped as soon as transport returns;
its HTTP permit and the aggregate slot stay held until that blocked operation finishes. The CLI outer
watchdog bounds its own userspace wait, but cannot release an agent worker stuck in OS DNS. Tests run on macOS use the Unix socket implementation. The existing Windows named-pipe code
uses the same status request and queue logic, but these Unix-only integration/latency tests do not
establish native Windows execution parity.

Registry capability `registry_assignee_session_v1` enables
`/api/v1/registry/items?status=active&limit=200&assignee_session=<session>` and the corresponding
`review` chain. Status percent-encodes the session and keeps the same filter on every page. The
server selects matching current, unreleased assignments before paging, independently of their
optional `session` field. Session derivation splits `assignment.executor` at most twice on `:` and
uses the complete remainder after the second colon; with zero or one colon it uses the entire
executor. Comparison is exact and case-sensitive. Omitted, empty or whitespace-only filter values
apply no filter; other values are not trimmed. The `actor` filter remains an actor **kind**, so an
agent name must not be passed as `actor`.

Support must already be known from the negotiated protocol's capabilities (its JSON array or
`Lockyard-Capabilities` header, including the existing bounded negotiation cache), or a
comma-separated `Lockyard-Capabilities` header on a registry
response in this status read. Protocol 1 and 2 can both advertise it; the selected protocol number
does not imply support. There is no speculative filtered request to an unannounced server.

The completeness contract is per chain: choose filtered or unfiltered once immediately before its
first page, using only the knowledge available then. A registry header learned later can enable a
later chain, but never changes an unfiltered chain already in progress or skips any of its pages.
Every returned item is still checked locally against its current assignment using the same session
derivation. If any filtered response lacks the capability header, status retains all fetched items,
restarts that chain at its first unfiltered page, and reads every page with the old filters. An
unconfirmed error response also stops filtered retries; losing the capability during protocol
renegotiation triggers the same replay. It does
not reuse a cursor across different filters. A mandatory chain that cannot complete fails closed.
Only two filtered chains whose every response confirmed support report
`freshness.assignment_filter: "server"`; every other result retains `"client_fallback"`.

This applies inside both direct and agent status reads without changing CLI/agent messages. An older
agent keeps its previous complete client filtering; an older CLI accepts the existing status fields
and additive freshness metadata. An older server receives the existing unfiltered request sequence.
