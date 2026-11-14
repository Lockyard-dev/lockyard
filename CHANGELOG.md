<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Changelog

All notable changes to Lockyard are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.9] - 2026-11-14

### Fixed

- `msg inbox` marks mail read only when stdout is a terminal; a pipe or redirect behaves like `--peek`. Scripts that need the mark pass `--mark-read`.
- MCP `update` with `to`/`body` always peeks mail after sending a note, so sending never marks the inbox read.

### Added

- Client-side open mail: asks that still need this agent's reply stay visible after a mark-read. `status` prints them and exposes `open_mail` in JSON; `msg open` lists only those letters; `zone renew` / MCP `zone_renew` add `open_mail_count`.
- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.9`.

## [0.3.8] - 2026-11-13

### Added

- CLI `task add --path <file-or-directory>` (repeatable) and both MCP `task_add` catalogs accept workspace-relative task paths. Servers announcing `registry_auto_area_v1` derive the area from these paths; `--area` / `area` is an optional override. Missing paths are refused before creating an item.
- Normalize task paths with the claim-path resolver, including absolute paths inside the workspace and forward-slash output. `task show` and MCP task results display paths returned by the registry. Explain path/area server errors, including repository roots for tasks spanning repositories.

### Changed

- Older servers retain their previous area behavior, receive no task paths, and produce a warning when paths were supplied. Compact MCP calls still require `area` for these servers. Local task storage remains unchanged and does not persist paths.
- Keep MCP startup and tool discovery fully local. Both catalogs use one `task_add` schema with only `title` required; calls validate paths or area after checking the server capability.
- Refresh automatic-area support from the latest successful server response, including removal after a rollback. The background agent forwards live protocol capabilities without adding cached support; missing-area refusals explain how to repeat the command and do not cause a retry.
- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.8`.

## [0.3.7] - 2026-11-13

### Changed

- Cloud CLI `status` warms a cold connection with claims first, then reads the two assigned-task page chains, mail and work in sequence on that connection. A status-capable local agent reuses its authenticated HTTP pool and overlaps warm reads. Bounded admission queues simultaneous callers, coalesces only requests collected before a new claims read starts, and admits three concurrent generations within eight shared HTTP workers, reserving one worker each for outbox writes and event long polls; FIFO general-worker admission prevents later upkeep from overtaking queued reads, and new status sessions defer their upkeep wake until their live answer completes. Disconnected local callers leave admission immediately; only a generation with no remaining members is cancelled. A credentialed CLI skips the local wait when Ping reports abandoned in-flight work and every generation is occupied, preserving its direct-read budget; old peers and tokenless access remain compatible. JSON retains its existing fields and adds freshness metadata.
- Cloud status uses the registry's `assignee_session` filter only after the server announces `registry_assignee_session_v1` through negotiated capabilities or a registry response header in the same read. Each task chain fixes its choice before its first page and still filters current assignment executors locally. Missing capability confirmation on a filtered response retains the fetched tasks and replays every unfiltered page; older servers keep the existing complete local-filter path. `freshness.assignment_filter` is `server` only when both chains used the filter and every response confirmed it, otherwise `client_fallback`. The CLI/agent wire format is unchanged.
- Claims always require a server read begun after the caller arrived; completed answers and zone snapshots are never reused. Expiry and idle expiry are rechecked before output using a monotonic server-time upper bound, or an explicit local-clock fallback with a 30-second safety margin. Assigned tasks remain mandatory for Stop hooks. Mail receives the remaining deadline; an unavailable read retains the last known count with explicit stale age when the agent has one.
- Default the CLI status deadline to 6 seconds, configurable from 1 to 60000 ms with `LOCKYARD_STATUS_DEADLINE_MS` (empty uses the default; invalid values fail closed with the accepted range). Agent probing and aggregate waits use fractions of the remaining budget, preserving time for one claims-first direct fallback. Discovery, paging, worker admission, retries and `Retry-After` share the deadline; a mandatory read that cannot complete fails closed. Local diagnostics retain a separate short budget.
- Direct status clients reuse a private, origin/credential-scoped modern negotiation hint for at most 30 seconds; encryption policy and status data stay authoritative network reads, and unsupported responses renegotiate.
- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.7`.

### Added

- A reproducible delayed-link status benchmark that requires successful cold reads, compares cold p95 against 0.3.6, checks warm latency ceilings, and reports ten simultaneous agent callers plus a hard caller after twenty soft CLI processes are killed at 850 ms. Regression coverage pins claims-first overlap, bounded queue/single-flight freshness, rate limiting, monotonic expiry, slow/unavailable mail and JSON provenance.

## [0.3.6] - 2026-11-12

### Added

- The agent's memory-only `zone_snapshot` reply includes optional `board`, `board_source` and `board_age_ms` fields. A fresh initialized board includes every entry, including global entries, and an empty board is `[]`. Stale or uninitialized boards omit `board` and report `board_source: "none"`; an age is included when known.
- Preserve board authors and creation timestamps alongside keys, values, zones and expiry timestamps in local snapshots.
- Add regression coverage confirming the existing proactive background board refresh starts without a client's first board read, and `zone_snapshot` never directly invokes a refresh or contacts the transport.

### Changed

- Advance the synchronized Rust, npm, PyPI and MCP registry versions to `0.3.6`.
- Document the additive local agent snapshot contract and independent board freshness metadata in `docs/cloud-mirror.md`.

## [0.3.5] - 2026-11-11

### Added

- Compact MCP `start_work` and CLI `zone claim` accept cloud idle holds through `hold_reason` and optional RFC 3339 `hold_until`. A reason alone holds until `expires_at`; a deadline requires a reason. Acquisition followed by fenced renewal remains compatible with deployed servers. A failed hold releases only the claim created by that call. Local mode validates these inputs and takes the claim without storing a hold, since local claims are not released for inactivity.
- Accept the optional public claim timestamp `idle_release_at` from newer servers, while preserving older-server replies.
- Compact MCP `status` includes `lost` with up to ten recent losses, excluding timestamps older than 120 minutes and retaining entries without timestamps. A failed loss lookup returns `lost: null` while preserving the rest of status. CLI `status --json` keeps its existing output and request count.

### Fixed

- Compact `finish_work` and CLI `zone release` release a sole owned claim by explicit id when no selector is given. Multiple claims require an id or explicit `all: true` / `--all`; combining id and all is invalid. Incoming handover offers do not count as owned claims, and `finish_work` validates before submitting a task. Local `handover` also refuses an ambiguous claim selection. The full MCP `zone_release` tool follows the same rule and accepts `all: true`.
- Cover the agent daemon's separate lost history and live claims with a regression: a partial idle-loss record for a live claim id keeps its remaining paths valid.

### Changed

- Advance the synchronized Rust, npm, PyPI and MCP registry versions to `0.3.5`.
- Document that cloud claims without a hold are released after 20 minutes without reported activity.

## [0.3.4] - 2026-11-10

### Fixed

- Cloud CLI and MCP `status` fetch assigned tasks through paginated server-side `active` and `review` filters instead of scanning the entire task registry, reusing one HTTP client across requests. Other statuses release their assignment.
- Remove the full registry `backlog` field from cloud `status` JSON. Use `lockyard task list --json` or the MCP `task_list` tool when the full registry is needed. Local status and task listing behavior are unchanged.

### Changed

- Advance the synchronized Rust, npm, PyPI and MCP registry versions to `0.3.4`.

## [0.3.3] - 2026-11-09

### Added

- Expose `task_add` and `zone_renew` in the 16-tool compact MCP catalog: `revoke_access`, `start_work`, `check`, `update`, `handover`, `finish_work`, `status`, `tasks`, `task_bulk`, `registry_import`, `area_list`, `area_create`, `area_update`, `cloud_protocol`, `task_add`, and `zone_renew`.
- Require an explicit `area` for compact `task_add`, preserving the area's task prefix and the full catalog's existing optional-area behavior. Local `task_add` supports `general` (`D-*`); other registry areas require cloud mode. Compact `zone_renew` accepts an optional `ttl` of 1–240 minutes (default 30); the current `fence` is required only in cloud mode. Local claims renew without a fence, using the existing ownership and expiry checks; cloud renewals also check for stale fences.

### Changed

- Advance the synchronized Rust, npm, PyPI and MCP registry versions to `0.3.3`.

## [0.3.2] - 2026-11-08

### Changed

- Reuse pinned Windows directory handles for SQLite preflight while preserving fresh file ACL and reparse checks.
- Avoid the SQLite writer lock for fresh heartbeats and load local hook machine settings only for command checks.
- Enforce raw subprocess p95 ceilings: hook decision ≤ 15 ms; message send ≤ 20 ms on macOS/Linux and ≤ 35 ms on Windows (owner decision 2026-11-08; hosted send outliers in CI run 42508801763). Product and build failures remain immediate.
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
- CI performance budget (`perf_budget`): hook decision p95 ≤ 15 ms; msg send p95 ≤ 20 ms on macOS/Linux and ≤ 35 ms on Windows.
- Supply chain: Sigstore cosign keyless signatures, CycloneDX SBOM, `cargo deny`, npm/PyPI
  Trusted Publishing; `install.sh` verifies signatures when `cosign` is present.
- `SECURITY.md`, `docs/threat-model.md`, `docs/privacy.md`, `docs/json-schemas.md`.

### Changed

- Use the best of all three attempts independently for GitHub-hosted macOS hook/send budgets (15/20 ms unchanged; owner decision 2026-11-09 after CI run 42517683446). macOS and Windows wrappers share one gate; Windows keeps hook once/send best of three at 15/35 ms, Linux keeps one attempt at 15/20 ms. Every attempt reports p95; product/build failures stop immediately.
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
