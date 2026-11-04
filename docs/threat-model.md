<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->

# Threat model

Lockyard coordinates **cooperating** coding agents. It is not an access-control system for hostile
processes on the same machine.

## Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Zone claims (who holds which paths) | Local SQLite, or the cloud server | Coordination; not secrets |
| Bus messages | Same | May contain code or credentials the agents chose to write |
| Cloud bearer token | `~/.config/lockyard/credentials.toml` (mode 0600) | Secret — grants the caller's role on that server |
| Task sealed envelopes (cloud) | Server; client holds keys only when encryption is configured | Content the team chose to seal |
| Announcement journal | `.lockyard/announced-writes.jsonl` | Not secret; proves a hook allowed a path |

## What the lock stops

- A second agent that asks the edit hook (Claude Code `PreToolUse`) before writing a held path is
  refused. The refusal is the permission decision of the hook.
- Claim, renew, handover and related writes that carry a fencing token are refused when the token is
  stale (`stale_fence`).
- In **cloud mode**, the hook answers from the local agent mirror. The mirror is trusted for at most
  `Timing::fresh` (default 30 seconds of process time, and the same bound on wall time so a laptop
  sleep cannot keep a frozen view). If the mirror is older than that, or the agent is not running,
  the hook **denies** the edit. It never answers "free" from a view the server may already have
  changed. See [cloud-mirror.md](cloud-mirror.md).

## What the lock does not stop

- Shell writes, editors, build tools, and any path that never hits the hook. `lockyard monitor`
  watches claimed paths with `notify` and records unannounced writes; it mails the holder and shows
  them in `status` / `doctor`. By then the file is already changed. Detection, not prevention —
  stated again in the README limits.
- An agent that lies about its name. There is no cryptographic agent identity in local mode.
- A process that deletes or edits `.lockyard/` itself.
- Network attackers against a misconfigured cloud server; that boundary is the server's.

## Tokens and cloud trust

- Cloud calls use `Authorization: Bearer <token>`. The CLI stores the token only after device login,
  under mode 0600, and never prints it.
- A server URL must be trusted (`lockyard cloud trust` or `LOCKYARD_URL`) before a token is sent
  there.
- The local mirror is not a second source of truth: every mutating call still goes to the server
  with idempotency keys. The mirror exists so the hook stays local-fast.

## Encryption scope

- Local mode does not encrypt the store. Protect the disk as you would any project checkout.
- Cloud task content can use the sealed envelope when the team configures encryption keys; zone
  claims, presence and bus metadata travel in the clear on the wire as the protocol defines.
- Lockyard does not encrypt agent mail bodies end-to-end in v0.1.

## Assumptions

- Agents that use Lockyard intend to cooperate and will run the hook where the client supports one.
- The machine's filesystem and process list are trusted by the people using that machine.
- Clock skew between agents in local mode is bounded enough that lease expiry is meaningful; cloud
  mode uses server time for leases and never compares them to the client's clock.
