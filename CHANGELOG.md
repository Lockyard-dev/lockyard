<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Changelog

All notable changes to Lockyard are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `lockyard monitor`: event-driven mail delivery and detection of writes outside the hook
  (`notify` + 10 s reconcile). `status` / `doctor` surface unannounced writes.
- Cloud zone mirror fail-closed guarantee documented in `docs/cloud-mirror.md`; a stale or
  missing mirror refuses edits.
- CI performance budget (`perf_budget`): hook decision p95 ≤ 15 ms, msg send p95 ≤ 20 ms.
- Supply chain: Sigstore cosign keyless signatures, CycloneDX SBOM, `cargo deny`, npm/PyPI
  Trusted Publishing; `install.sh` verifies signatures when `cosign` is present.
- `SECURITY.md`, `docs/threat-model.md`, `docs/privacy.md`, `docs/json-schemas.md`.

### Changed

- Hook announces allowed edits; outside-hook writes are detection-only (README limits).
- Errors include a next step; credentials and journals use crash-safe replace/fsync.

## [0.1.0] - 2026-11-04

First release published to crates.io, npm, PyPI and GitHub Releases.

### Added

- Work zones: a claim is a lease on a path and everything below it, a second claim on the same
  path is refused, and a lease that stops being renewed frees the path.
- A message bus with direct and broadcast mail, replies and seven-day retention, and tasks that
  outlive a session and cannot be accepted by the agent that did the work.
- Message receipts (`sent`, `delivered`, `read`, `replied`, `failed`) in the local store and the
  cloud client, shown by `lockyard msg sent`.
- `lockyard setup` writes configuration instead of printing it: it detects installed clients,
  merges their MCP configuration without clobbering it, installs the edit hook where the client
  documents a blocking pre-edit hook, and adds a marked instruction block to the project's agent
  instruction file. `--dry-run` shows the plan, `--uninstall` removes what it added, `--print`
  keeps the old behaviour.
- `lockyard doctor` reports what is configured on this machine: MCP entries, hooks, store,
  agent name and, in cloud mode, whether the server answers.
- Clients: Gemini CLI and GitHub Copilot CLI join Claude Code, Codex and Cursor. The README
  states per client what Lockyard registers, whether edits can be blocked and how mail arrives.
- `lockyard mcp` exposes six composite tools by default (`start_work`, `check`, `update`,
  `handover`, `finish_work`, `status`). `lockyard mcp --tools full`, or `LOCKYARD_MCP_TOOLS=full`,
  keeps every tool (66 in this release) for integrations built against them.
- `lockyard cloud login` and `lockyard cloud logout`: device authorization against the cloud
  server, with the browser opened when possible and the token stored with mode 0600.
- `install.sh`: a POSIX one-liner that downloads the matching GitHub release asset, verifies it
  against the release `SHA256SUMS` and installs into `~/.local/bin` without sudo or telemetry.
- `server.json` for the official MCP registry and `glama.json` for the Glama listing.
- A runnable two-agent example in `examples/two-agents/`.
- The npm wrapper's launcher, `packages/npm/bin/lockyard.js`, which the published manifest has
  always pointed at.

### Fixed

- `.gitignore` carried a bare `bin/` rule, which silently excluded the npm launcher from the
  repository and would have published an npm package that cannot run.

[Unreleased]: https://github.com/lockyard-dev/lockyard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lockyard-dev/lockyard/releases/tag/v0.1.0
