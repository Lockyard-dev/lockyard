<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->

# `--json` output schemas

Every CLI command that prints a result accepts global `--json`. On success the process writes one
JSON value to stdout (plus a trailing newline) and nothing else. On failure it writes

```json
{"error": {"kind": "<stable>", "message": "<human text with a next step>"}}
```

to stderr and exits non-zero. `kind` values are stable: `no_project`, `invalid`, `not_found`,
`denied`, `conflict`, `stale_fence`, `frozen`, `unavailable`, `protocol`, `needs_cloud`,
`needs_local`, `io`, `database`.

## Common success shapes

| Command | Top-level fields |
|---|---|
| `about` | `version` |
| `init` | `root` |
| `who` | array of `{id, last_seen, …}` |
| `status` (local) | `unread`, `claims`, `tasks`, `machine_level`, `unannounced` |
| `status` (cloud) | `unread`, `claims`, `tasks`, `work`, `offers`, `machine_level`, `unannounced` |
| `doctor` | `ok` (bool), `checks` (`[{check, ok, detail}]`) |
| `monitor` (on stop) | `delivered`, `unannounced`, `rounds`, `backend` (`native` \| `poll` \| `none` \| `off`) |
| `zone claim` / list | claim objects with `id`, `session`, `paths`, `fence`, `expires_at`, … |
| `zone check` | path check with `status` (`free` \| `own` \| `held` \| `unknown`) |
| `msg inbox` | `{messages: [...], skipped?}` |
| `msg send` | the sent message (`id`, `to`, `body`, …) |
| `msg sent` | receipts with `status` (`sent` \| `delivered` \| `read` \| `replied` \| `failed`) |

In cloud CLI and MCP `status`, `tasks` contains only registry tasks assigned to the current session. Since
0.3.4, cloud status uses paginated server-side `active` and `review` filters and omits the former
full-registry `backlog` field. Both statuses retain an assignee; other status transitions release it.
Empty pages require two registry requests; claims, work and unread-mail calls are separate.
Consumers that need all registry tasks must explicitly call `lockyard task list --json` or MCP
`task_list`. Local status output and task listing are unchanged. MCP status omits the CLI-specific
`machine_level` and `unannounced` fields.

Monitor **events** while running (also under `--json`) are one object per line:

```json
{"event":"mail","id":1,"from":"bob","body":"…"}
{"event":"unannounced","path":"src/a.rs","holder":"alice","claim":7,"hits":1}
```

Field names and `kind` strings are part of the public contract; additive fields may appear. The 0.3.4
cloud status removal of `backlog` is an explicit migration described above.
