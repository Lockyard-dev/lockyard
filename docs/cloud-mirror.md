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
