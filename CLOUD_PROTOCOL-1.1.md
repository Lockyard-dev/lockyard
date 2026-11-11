# Lockyard Cloud protocol: amendments v1.1

These override anything in the v1 protocol file.

## Identifiers and workspace

- All ids of claims, queue entries, requests, messages and work tasks are integers from one per-workspace sequence per
  kind. JSON numbers. Imported records keep `legacy_id` as text.
- The workspace comes from the token only. There is no workspace header, and `workspace` in a client config is a label.
- Work task status `offer` is spelled `offered`.

## Two-phase mail

- `GET /api/v1/bus/inbox` never marks by default. `POST /api/v1/bus/inbox/seen` `{ids[]}` marks after the client has
  shown the mail. `peek` is removed. A client that dies between the two sees the mail again: a duplicate over a loss.
- `POST /api/v1/bus/inbox/claim` `{ids[], lease_seconds}`: gives one delivery channel the exclusive right to show a
  message for the lease, so that two hooks do not show one letter.

## Cross-session view

`GET /api/v1/bus/undelivered?older_than_seconds=`: role `lead` or a new role `dispatcher`. Lists unseen mail across sessions,
with addressee and age, for a wake-up service. Wake-up logic stays with the client.

## Liveness

- `POST /api/v1/presence` gains `activity`: `tool_running (bool)`, `tool_started_at`, `state`
  (`working|idle|ended|api_failure`), and `meta` (opaque object up to 2 KiB, for example pid and address).
- `state: ended` or `api_failure` makes the session unavailable at once.
- A session with `tool_running: true` stays live for 240 minutes from `tool_started_at`, with no heartbeat needed.
- `POST /api/v1/zones/claims/{id}/takeover` `{reason}`: role `lead`, a non-empty reason, refused while the holder's heartbeat
  is under 15 minutes old, and always emits `zone.lost` and an audit event.

## Claim fields

`Claim` gains `meta` (opaque object up to 4 KiB, for flags such as a change reference or a deploy mode), `excluded_paths[]`,
`return_to?`, `hold_until_ref?` (a queue entry or request id this claim is conditionally held for), `last_activity_at`,
`last_write_at`.

- `POST /api/v1/zones/claims/{id}/activity` `{write (bool), paths?[]}`: the client batches these, at most once per 10 seconds
  per claim. Idle shrinking counts only this signal.

## Foreign dirty paths

`POST /api/v1/zones/dirty` `{paths: [{path, owner_session?, reason?, task_id?}]}` replaces `claims/{id}/dirty`. Clients detect
dirt, the server stores who owns it. `GET /api/v1/zones/dirty?path=`, `POST /api/v1/zones/dirty/disown` `{paths[]}`, and
`POST /api/v1/zones/dirty/adopt` `{paths[], reason}`, which is refused for a path with a known live owner. A grant or a handover
copies open dirty paths of the zone to the new holder as foreign.

## Work tasks

Fields gain `lead`, `executor`, `slot_token?`, and actions gain `decline`. On `done`, dirt attributed to the executor passes to
its lead.

## Event payloads

Zone events carry `claim_id, session, paths[], note, reason, fence`. Bus events carry `id, from, to, thread_id, kind, needs`.
`GET /api/v1/zones/lost?session=` lists lost claims.
Newer servers also include entries with reasons `idle`, `expired`, and `unused_grant`. An `idle`
entry may describe a partial shrink while the same claim id remains live with fewer paths; clients
must not treat that entry as proof that the whole claim has been lost. Compact MCP `status` in
core 0.3.5 returns up to ten recent entries in `lost`; CLI `status --json` makes no extra request.

## Cutover

- Zones are not copied. Before a cutover clients drain: no live claims, or each holder claims again on the server.
- `GET /api/v1/export/coordination` (role `owner` or `exporter`) dumps claims, queue, requests, dirty paths, threads, board
  and tasks, so a rollback can rebuild local state.
- `POST /api/v1/admin/freeze` `{on, reason}` (role `owner`) makes every coordination write answer 503 with `Retry-After`, for
  the window of a switch.
