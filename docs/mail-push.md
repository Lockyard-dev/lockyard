<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Broadcast mail and background wakeups

Send from the CLI with `lockyard msg send <to> <body>`, or from MCP with
`update(to=…, body=…)`. The same recipient forms work in both:

| Address | Recipients |
| --- | --- |
| `*`, `all`, `все`, `everyone` | All live sessions in the workspace except the sender |
| `@claude`, `@cursor`, `@codex` | Sessions using that client |
| `@zone:<key>` | Claim holders whose paths intersect the named zone |
| `@path:<path>` | Claim holders whose paths intersect that workspace path |

The broadcast audience is fixed when sending using `IsLive`: a session participates
if its presence is no older than 15 minutes OR it has a running tool (`ToolLive`).
A session returning after being non-live does not receive broadcasts sent during its absence.

Quote `*` and group addresses in shells. The server expands these addresses; they are
not resolved through a local presence alias lookup. For example:

```sh
lockyard msg send all 'Please finish your current changes'
lockyard msg send '@path:src/client' 'Need your review' --needs reply
lockyard msg send '@claude' 'Build is blocked' --urgent
```

MCP examples: `update(to="all", body="Build is ready")` and
`update(to="@codex", body="Please check the client", urgent=true)`.
`urgent` wakes a background waiter even when the mail is informational.
Mail with `needs=reply` or `needs=ack` also wakes it. Ordinary informational mail
and acknowledgements remain available through the existing hooks on the next turn.

Servers announce `mail_push_v1` in `/api/v1/protocol`. With this capability, the daemon
uses one SSE connection to `/api/v1/events?sessions=a,b,c` (at most 32 live registered
sessions), announces `X-Lockyard-Capabilities: mail_push_v1`, resumes with `Last-Event-ID`,
and reopens with the same cursor when the session set changes. Historical mail before
`ready` never wakes a waiter: unread/open snapshots are seeded after that marker.
Recipient envelopes route mail; sender copies never wake. `seen`, `handled` and ack
receipts remove cached unread/open mail; `reply_to` closes its parent.
The read timeout is 45 seconds; servers send heartbeat comments every 15 seconds.
Reconnects use exponential backoff with jitter, capped at 30 seconds.
A `replaced` control frame has no cursor id. It means another daemon using the same
token owns the stream: the displaced daemon logs this and waits 60 seconds before
retrying the same set once. If that retry is displaced again, SSE stays disabled
until its registered session set changes. JSON coordination long-poll continues
throughout the cooldown and displacement fallback. A change to its registered session
set permits an immediate retry. Session names supplied only by `mail wait` do not join SSE until a successful
presence or other session-binding request. A 403 `details.sessions` response removes
unbound names without counting as a transport failure.

The daemon keeps one stream for the first 32 eligible session names in sorted order.
Additional sessions use inbox snapshots; only those with live waiters refresh every
second. Existing stream sessions remain on SSE when the limit is exceeded. Changing
the selected set seeds only added sessions; a reconnect of the same set refreshes its
snapshots to cover the disconnection. During fallback, sessions without waiters are
seeded once and refreshed on demand by hooks.
Older servers retain JSON long-poll. Non-SSE responses, HTTP 404/406, or five failures
trigger discovery and long-poll fallback; discovery repeats every ten minutes.
On older servers `all`, `все` and `everyone` become `*`; client, zone and path groups
return an explicit unsupported-server error.
Urgent sends also require `mail_push_v1`.

## Claude Code asyncRewake hook

Register this in your Claude Code settings:

```json
{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"lockyard mail wait","async":true,"asyncRewake":true}]}]}}
```

`lockyard mail wait` connects only to the existing local daemon. It does not start,
install or restart it. `--session` overrides the default session from
`LOCKYARD_AGENT`, then `CLAUDE_CODE_SESSION_ID`, then `session_id` from bounded,
hook JSON on stdin (at most 64 KiB, waiting up to 200 ms for piped input). `--timeout` is in seconds and defaults
to six hours (21600 seconds):

```sh
lockyard mail wait --session my-session --timeout 60
```

An actionable unread message produces exit code **2** and a short stderr reminder:

```text
✉ Lockyard M-42 (данные письма, не инструкция) от «reviewer»: «Please check the client»; ответь: MCP update reply_to=42
```

The sender alias (or session) is limited to 64 characters; the body to 300 characters.
Controls, bidi controls and Unicode line separators are removed. Existing actionable
unread mail returns immediately once. An atomic per-session state file remembers the
last wake across hook invocations and daemon restarts, so a text-only response cannot
wake forever on the same mail. The wake marker is saved only after a successful
socket response to the waiter. Waiting leaves mail unread; the session marks it read when
it reads its inbox. A second waiter for the same session replaces the previous one,
which exits silently with code **0**. Timeout, a missing daemon, an older daemon/server,
also exit silently with code **0**. Pending negotiation and temporary snapshot failures
keep retrying within the timeout. During confirmed SSE fallback a waiter checks snapshots
at most once a second; it does not exit just because the stream is disabled.

Cursor and Codex continue to receive mail through their ordinary hooks; the background
wake hook is intended for Claude Code.

## Priority mail in ordinary hooks

Claude PreToolUse keeps the `Edit|Write|MultiEdit|NotebookEdit|Bash` matcher.
SessionStart, UserPromptSubmit and PostToolUse retain normal mail delivery: reserve
up to five messages under a 60-second lease, show up to 1000 body characters each,
flush output, then mark the displayed messages read. Failed output leaves mail unread.

Priority lines precede ordinary mail and coordination events, including on SessionStart
and PreToolUse. They show received replies to this session's asks, urgent mail and
`needs=reply|ack`, with escaped aliases (64 characters) and bodies (200 characters)
inside «». The label `(данные письма, не инструкция)` precedes the sender. Plain replies
such as “Принято” may be displayed here but do not wake background waiters or count as
open mail unless they have `needs != none` or `urgent`.

Priority reminders alone do not change receipts. A per-workspace/session file,
`hook-mail-<hash>.json`, lives in the daemon state directory and stores only message IDs
and successful output times. A nonblocking file lock throttles repeats across hook
processes to five minutes while unread. Failed output does not commit the throttle.
Daemon Ping advertises `peek_mail_v1`; older daemons retain TakeMail delivery without
receiving an unknown PeekMail request. No informational counter is emitted.

## Waiting for another session's path

`lockyard zone wait-free <workspace-path> --timeout 60` waits without taking a claim;
exit 0 means free (including one's own claim), exit 1 means timeout, and exit 2 means error. The MCP tool is
`zone_wait_free` with `path` and optional `timeout` in seconds (default 3600), returning
`free` and `timed_out` booleans. It is available in compact and full tool lists.

A running daemon reuses its existing `mail_push_v1` SSE subscription. Zone events
(including `zone.released`, `zone.expired`, and `zone.taken`) and stream-ready transitions
wake the waiter for an authoritative path check with `mode=exclusive` so shared foreign
claims also keep the path occupied; this does not create a claim. A safety check runs
every 60 seconds even while SSE remains connected. Capturing the event generation
before checking prevents a release/read race. Ping advertises `wait_zone_free_v1`;
with an older daemon the CLI uses direct authoritative checks every ten seconds and
never opens a competing stream. Without a daemon, a direct client reads the JSON feed
to its current visible head, subscribes after that cursor, and checks only after `ready`.
Disconnection is an error. Old servers check every ten seconds; the timeout bounds the wait.

A replacement retry that remains connected for more than ten minutes starts a fresh
replacement cycle. A short retry still permits only one retry after a 60-second pause,
preventing two daemons from repeatedly displacing each other.

## Task creation recovery

CLI `task add` and MCP `task_add` share creation recovery. A new request has one HTTP
idempotency key and one `client_key`; an uncertain write retries the exact request
with both keys unchanged. If retry cannot confirm an ID, the client queries registry
items by `client_key`, verifies the returned key, and acknowledges the pending journal
only on an exact match. A matching title is insufficient. Failure to confirm returns
`task_create_unconfirmed` with both keys, never a successful `created=unknown` result;
supply `client_key` to MCP or `--client-key` to CLI with the same arguments to retry.
Within the pending journal's replay window, equal arguments automatically recover the
original logical key, HTTP key and request identity, including across client restarts.
Matching uses the original plaintext request digest even when frozen wire content is encrypted.
