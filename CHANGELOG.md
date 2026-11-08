<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Changelog

All notable changes to Lockyard are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-11-08

### Changed

- Reuse pinned Windows directory handles for SQLite preflight while preserving fresh file ACL and reparse checks.
- Avoid the SQLite writer lock for fresh heartbeats and load local hook machine settings only for command checks.
- Enforce raw subprocess p95 budgets: hook decision ≤ 15 ms once on every OS; message send ≤ 20 ms once on macOS/Linux and ≤ 35 ms best of three on Windows through one shared gate (owner decision 2026-11-08; hosted send outliers in CI run 42508801763). Product and build failures remain immediate.
- Keep CLI, Windows SQLite syscall and authenticated pipe profiling opt-in for CI/tests; require the Windows hot-journal recovery regression in both Windows jobs.

## [0.3.1] - 2026-11-08

### Fixed

- Join terminal executor workers before releasing the last caller handle, eliminating the state-lock race during immediate restart.
- Preserve pending-journal fixture failures without destructor double panics and enable Windows CI panic backtraces.

## [0.3.0] - 2026-11-08

### Added

- Cloud client APIs publish and retrieve signed job results with exact-byte idempotent replay and explicit quota resumption.
- Nodes publish saved terminal result manifests and reconcile legacy tombstones against locally verified cloud results.

### Changed

- Advance the synchronized Rust, npm, PyPI and MCP registry versions to `0.3.0` for the new signed-result APIs.

## [0.2.2] - 2026-11-08

- Support Windows agent, hook, CLI and MCP coordination over user-private named pipes.
- Protect Windows keys and managed state with owner-only ACLs and reject reparse points.
- Add Windows workspace build, warnings-as-errors and named-pipe claim arbitration CI.
- Keep node job execution unavailable when native container limits cannot be enforced.

## [0.2.1] - 2026-11-07

- Authenticate and decrypt typed zone catalogs locally with persistent revision protection.
- Negotiate HTTP protocol generations and preserve uncertain writes without changing their wire bytes.
- Unify task identities, compatibility diagnostics, owner-decision AAD and MCP tool definitions.
- Gate compatibility boundaries with AST checks and a production symbol scan.

## [Unreleased]

### Added

- `lockyard monitor`: event-driven mail delivery and detection of writes outside the hook
  (`notify` + 10 s reconcile). `status` / `doctor` surface unannounced writes.
- Cloud zone mirror fail-closed guarantee documented in `docs/cloud-mirror.md`; a stale or
  missing mirror refuses edits.
- CI performance budget (`perf_budget`): hook decision p95 ≤ 15 ms once everywhere; msg send p95 ≤ 20 ms once on macOS/Linux, ≤ 35 ms best of three on Windows.
- Supply chain: Sigstore cosign keyless signatures, CycloneDX SBOM, `cargo deny`, npm/PyPI
  Trusted Publishing; `install.sh` verifies signatures when `cosign` is present.
- `SECURITY.md`, `docs/threat-model.md`, `docs/privacy.md`, `docs/json-schemas.md`.

### Changed

- Hook announces allowed edits; outside-hook writes are detection-only (README limits).
- Errors include a next step; credentials and journals use crash-safe replace/fsync.

## [0.2.0] - 2026-11-07

### Added

- Native Linux job isolation with delegated cgroups v2, namespaces and seccomp; diagnostics explain missing host capabilities.
- Automatic reconciliation of old unsigned tombstones, with explicit review for unresolved records.
- Build identity in version/diagnostics, same-version signed build updates, and CI crate-version bump enforcement.

### Changed

- Linux selects native isolation by default; Docker remains an explicit option.
- Missing revocation trust is rejected before creating private revocation state.

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
