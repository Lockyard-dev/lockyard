# Lockyard Cloud protocol v1

The contract between the server (`lockyard-cloud`, closed) and the client (`lockyard`, open). The two sides are built in
parallel from this file alone. Everything is scoped to a workspace, carried by the bearer token.

## Principles

- All state lives on the server. A client keeps only a write outbox for outages.
- Every write takes an `Idempotency-Key` (ULID). A repeat returns the first result.
- Every change appends to one event stream with a monotonic `seq` per workspace.
- Coordination data is short-lived and plain. Task content keeps the existing sealed envelope.
- Time is server time. Clients never compare their own clock to a lease.

## Auth and identity

`Authorization: Bearer <token>`, as the existing registry: stored hashed, a role per token (`agent lead owner exporter
importer`), revocable, with an expiry. `X-Lockyard-Session: <name>` names the session, and the actor is
`token:<id>:<session>`. The name matches `[A-Za-z0-9_.:-]{1,128}`.

## Errors

JSON `{"error": {"code", "message", "details"}}`. Codes: 400 invalid, 401, 403, 404 (also for another workspace), 409
conflict with `details.conflicts` or `details.version`, 412 fencing token stale, 429 with `Retry-After`.

## Presence

- `POST /api/v1/presence` `{client, model?, role?, version?, cwd?, dnd_until?}`: heartbeat. Answers with `server_time`.
- `GET /api/v1/presence?active_within=<seconds>`: sessions with `last_seen`, `client`, `role`, `dnd_until`.

## Zones

A claim holds paths. Paths are `/`-separated and relative to the workspace root; `.` is the root. Overlap is by path
component, and an exact file overlaps its parent folder.

`Claim`: `id, session, actor, note, zone?, paths[], mode (exclusive|shared), purpose (work|deploy), lazy (bool), fence (int),
created_at, expires_at, hold_until?, hold_reason?, last_activity_at, version`.

- `POST /api/v1/zones/claims` `{paths[], note, ttl_minutes, mode, purpose, lazy, zone?, zones?[], queue_wait_seconds?}`.
  All paths or none. Shared claims coexist with shared claims only. Own claims never conflict. Conflict: 409 with holders.
  `lazy: true` with empty paths creates a claim that grows through `add-path`. `fence` rises with each ownership change
  of a path, and a client passes it on protected operations.
- `POST /api/v1/zones/claims/{id}/add-path` `{path}`: adds a path atomically. 409 if another session holds it, and then the
  caller joins that path's queue.
- `POST /api/v1/zones/claims/{id}/renew` `{ttl_minutes, hold_reason?, hold_until?}`. TTL at most 240, hold at most 240. An
  expired claim cannot be renewed.
- `POST /api/v1/zones/claims/{id}/narrow` `{paths[]}`: shrinks to a subset.
- `DELETE /api/v1/zones/claims/{id}` `{note?, leave_dirty?}`. Bulk: `DELETE /api/v1/zones/claims?session=<own>`.
- `GET /api/v1/zones/claims`: active claims, with `?session=` and `?path=`.
- `POST /api/v1/zones/check` `{paths[], fence?}`: for each path, free, own, or the holder. It writes nothing, and it is the
  call hooks make.

### Queue

FIFO per overlapping request.

- `POST /api/v1/zones/queue` `{paths[], note, mode, purpose, ttl_minutes (1..480), zones?[]}`: a long wait entry, at most 3 per
  session. Own overlapping claims are refused. A whole zone waits for every overlapping sub-path, and a multi-zone entry is
  all or none.
- `GET /api/v1/zones/queue`, `DELETE /api/v1/zones/queue/{id}`.
- When paths free up, the server grants under one transaction to the first live entry: it creates the claim and emits
  `zone.granted`, with 20 minutes to the first action. A grant unused in that time is released and the next entry goes.
- A short `queue_wait_seconds` on a claim keeps a place for 120 seconds and a free zone is reserved for the first in line
  for 60 seconds. Other callers get 409 with `details.priority_of`.

### Requests and handover

- `POST /api/v1/zones/requests` `{paths[], text, urgent, need_by?}`: asks the holder. Expires in 24 hours.
- `POST /api/v1/zones/requests/{id}/answer` `{reply?, eta?}`. A late ETA is flagged in events.
- `POST /api/v1/zones/claims/{id}/handover` `{to}`: pending for 30 minutes. `POST .../accept` moves ownership and raises the
  fence. On release the claim returns to the original owner when that owner is live.
- Releasing a requested zone emits `zone.released` to whoever asked.

### Liveness

A session is unavailable after 15 minutes with no heartbeat or tool activity, or when a client reports `session_end`
or `api_failure` through `POST /api/v1/presence`. Claims of an unavailable session stop blocking and may be taken by anyone,
which emits `zone.lost` to that session. A live heartbeat alone never loses a claim. Idle claims with no activity for 20
minutes and no hold are shrunk by the server to their dirty paths, reported by clients through
`POST /api/v1/zones/claims/{id}/dirty` `{paths[]}`, and released if there are none.

## Bus

`Message`: `id, thread_id, in_reply_to?, kind (ask|notice|event), from_session, from_client, to (session|*), zone?, re?,
status?, needs (none|reply|ack), body, key?, expires_at, created_at`.

- `POST /api/v1/bus/messages`: body at most 8 KiB for agents, a limit configurable per role. The same `key` repeats the same
  id, and a different body under it is 409. Without a key, an equal body to the same addressee within 10 minutes is dropped
  with `deduplicated: true`. At most 10 messages to one addressee in 5 minutes, then 429. `notice` expires after 2 hours,
  or a `ttl_minutes` from 30 to 1440. Unknown addressee: 404.
- `POST /api/v1/bus/messages/{id}/reply` `{body}`: the participants only. It inherits the thread and counts as an ack.
- `POST /api/v1/bus/messages/{id}/ack`.
- `GET /api/v1/bus/inbox?all=&peek=&limit=`: oldest first, at most 50 unread kept per addressee, older folded into a
  `skipped` count. It marks returned mail as seen unless `peek`.
- `GET /api/v1/bus/threads/{id}`.
- `GET /api/v1/bus/overdue`: own messages needing an ack, past 15 minutes.
- Mail is kept for 7 days, or 3 days from the last activity of a thread.

### Board

`POST /api/v1/bus/board` `{key, value, zone?, ttl_minutes}`, `DELETE /api/v1/bus/board/{key}`, `GET /api/v1/bus/board?zone=`.
History is kept for 30 days. The roles `lead` and `owner` only can write.

## Work tasks

Task offers between agents, separate from backlog items. `task` fields: `id, title, to, re?, zone?, accept, brief?, status
(offer|claimed|review|accepted|failed|expired|cancelled), lease_until, assignee, report?, commits[], version`.

- `POST /api/v1/bus/tasks`, `.../{id}/claim`, `/beat`, `/done`, `/accept`, `/reject`, `/fail`, `/cancel`, `/handoff`, `/take`.
- Lease 15 minutes, renewed by `beat`. `?version=` gives compare and swap, 409 on mismatch. An expired lease emits an event to
  the lead. `offer`, `accept`, `reject` and `cancel` need the role `lead`, with one exception in v1.2. The role `agent` is limited to 3 claimed tasks.

## Backlog

`/api/v1/registry/*`: the existing registry as it stands, moved unchanged. Its contract is `CONTRACT.md`, and its URL prefix
changes from `/api/registry` to `/api/v1/registry`.

## Events

- `GET /api/v1/events?after=<seq>&wait=<seconds up to 25>&session=<own>&types=`: long poll, returns events after a sequence.
  It polls the database no more than every 500 ms. Events about other sessions are filtered to what the session may see.
- Types: `presence.*`, `zone.claimed`, `zone.released`, `zone.expired`, `zone.lost`, `zone.queued`, `zone.granted`,
  `zone.requested`, `zone.answered`, `zone.handover`, `bus.message`, `bus.ack`, `board.changed`, `task.*`, and the existing
  registry events under `registry.*`.
- Events are kept for 30 days for coordination types. Registry events are kept forever.

## Migration

- `POST /api/v1/import/zones` `{catalog}` stores the workspace's zone catalog (the names, paths and groups) as data. The role
  `importer` only.
- `POST /api/v1/import/bus` imports open threads, the board and unfinished tasks, idempotently by `legacy_id`.
