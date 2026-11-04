# Lockyard Cloud protocol: answers v1.2

These settle the open points and override the earlier files.

- **Two event streams.** `/api/v1/events` carries coordination events. The registry keeps its own stream at
  `/api/v1/registry/events`. A client polls both. `seq` is per stream.
- **Registry errors.** The registry keeps its 422 for contract violations. The unified envelope applies to coordination.
- **Zones are the client's concept.** The server knows paths only. `zone` and `zones` fields are labels stored on a record.
  A client expands a zone into paths, and a multi-zone queue entry is one entry with all those paths, granted all or none.
  `POST /api/v1/import/zones` keeps the catalog as an opaque JSON document that clients can read with `GET /api/v1/zones/catalog`.
- **Fencing.** `add-path`, `renew`, `narrow`, `activity`, release and handover take an optional `fence`. A stale fence is 412.
- **Tool activity** means `POST /api/v1/presence` and `POST .../activity`, nothing else.
- **Inbox reads are not writes.** Marking happens through `/inbox/seen` and `/inbox/claim`, each with an `Idempotency-Key`.
- **Work task transitions.** `claim`: from `offered`, by the addressee, or by anyone when `to` is `*`. `beat`, `done`, `fail`,
  `handoff`: by the assignee, from `claimed`. `done` goes to `review`. `accept`, `reject`: by the lead, from `review` (see below for a vanished lead), and
  `reject` returns to `claimed` with a new lease. `handoff` `{to}` sets `to` and returns to `offered` with the assignee cleared;
  the receiver uses `take`, which is `claim` under a required version. `cancel`: by the lead, from any non-final state.
  `decline`: by the addressee, from `offered`. A lease that expires moves the task to `expired` and emits `task.expired`
  to the lead.
- **Human sign-in** is out of scope for now. Tokens only.

## Agreed shapes, v1.3

These were settled when the client first ran against the server. They override the earlier files.

- **Lists and records** are bare JSON: an array, or the object itself. `inbox` is `{messages, skipped}`.
- **Timestamps** are RFC 3339 text in both directions. The server refuses numbers.
- **409 on a claim.** `details.conflicts[]` has `path, held_path, claim_id, session, note, paths, mode, purpose, expires_at`,
  one entry per claim. Without holders it has `details.priority_of`: someone waits ahead of the caller.
- **`zones/check`** answers a bare array of `{path, status (free|own|held), holder, fence}`. `holder` has the shape of a
  conflict entry and is null unless `status` is `held`. A client refuses an item with no status, and never reads one as free.
- **`inbox/claim`** answers `{claimed: [ids]}`. Delivery is per session, with no channel field: a message under a live lease is
  left out, so a second reader gets an empty list rather than an error.
- **A declined task** ends as `cancelled` with `declined_at`. There is no `declined` status.
- **`reason`** on `reject`, `fail`, `cancel` and `decline` is stored on the task.
- **`GET /api/v1/bus/tasks/{id}`** reads one task.
- **Presence** rows carry `version` as the client's text and a nested `activity {tool_running, tool_started_at, state, meta}`.
  `active_within` goes up to 604800.
- **Zone events visible to every session:** `zone.claimed`, `zone.released`, `zone.expired`, `zone.lost`, `zone.granted` and
  `zone.handover`. Claims are public inside a workspace, and an agent process keeps its view current from them under its own
  session `lockyard-agent-<uid>`. Other events stay filtered to their audience.
- **`GET /api/v1/registry/events`** is NDJSON and any role that reads the registry may poll it.
- **Freeze** needs a `reason` only to switch on.
- **Tokens.** A service token of role `owner` may list, issue and revoke tokens, because there is no sign-in. Any other role
  gets 403.
- **Client defaults.** `kind` is required on a message, and a client that was given none sends `ask`. `ttl_minutes` is
  required on the board, and a client that was given none sends 1440. `inbox` takes `limit` up to 50.
- **The backlog from the command line.** `lockyard task` maps onto `/api/v1/registry`: open is `ready`, `blocked` and `intake`,
  claimed is `active`, accepted is `done`. Ids print as `T-<n>` for the item `D-<n>`, and both spellings are accepted.

## The vanished lead

`accept` and `reject` belong to the lead of the task. When that lead is unavailable, a token of role `owner` or `dispatcher`
may do them, except on work the same session did. While the lead is live they get 403. A different `lead` still gets 403.
