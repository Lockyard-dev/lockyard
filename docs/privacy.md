<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->

# Privacy

## Local mode

Nothing leaves the machine. Claims, mail, tasks and the announcement journal live under
`.lockyard/` in the project. There is no phone-home, crash reporter or usage analytics in the
Lockyard binary.

## Cloud mode — data inventory

When `mode = "cloud"` is set and the agent is logged in, the client sends to the configured server:

| Data | Purpose |
|---|---|
| Bearer token | Authenticate the session |
| Session name (`LOCKYARD_AGENT` / `--agent`) | Attribute claims and mail |
| Path lists on claims, checks, dirty reports | Coordinate who edits what |
| Bus message bodies the agents write | Deliver mail between agents |
| Presence heartbeats (client, optional model/cwd) | Liveness |
| Event-stream cursors | Keep the local mirror current |
| Task content (optionally sealed) | Long-lived work offers |

The client does **not** upload source files, git history, shell history or editor buffers unless an
agent puts that text into a bus message or task on purpose.

## Telemetry

Lockyard ships with **no telemetry**. `install.sh` downloads only the release assets it needs and
sends nothing else. The binary does not open connections in local mode.

## Credentials on disk

Device-login tokens are stored in `~/.config/lockyard/credentials.toml` (or `$XDG_CONFIG_HOME`),
mode 0600, keyed by server URL. `lockyard cloud logout` removes the entry for that server.
