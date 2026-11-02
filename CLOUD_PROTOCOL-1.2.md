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
  `handoff`: by the assignee, from `claimed`. `done` goes to `review`. `accept`, `reject`: by the lead, from `review`, and
  `reject` returns to `claimed` with a new lease. `handoff` `{to}` sets `to` and returns to `offered` with the assignee cleared;
  the receiver uses `take`, which is `claim` under a required version. `cancel`: by the lead, from any non-final state.
  `decline`: by the addressee, from `offered`. A lease that expires moves the task to `expired` and emits `task.expired`
  to the lead.
- **Human sign-in** is out of scope for now. Tokens only.
