<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Changelog

All notable changes to Lockyard are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.18] - 2026-11-25

- Show the registry's submit warnings: single and batch submissions keep `warnings`, the CLI prints
  each on stderr as `warning: …`, `--json` and MCP `tasks(action=submit)` / `finish_work` return them.
- Send the full 40-hex `commit_sha` in clear with `<sha>:<path>` commit evidence, so an encrypted
  workspace can check that the commit is reachable from `dev`. A short SHA is resolved offline in the
  task's checkout through the object database only (exactly one commit, all `GIT_*` variables
  removed, no replace objects, no lazy fetch); a path behind an uninitialised submodule gives no
  checkout. Without a resolved SHA an encrypted submission warns that acceptance will be refused.
  Batch acceptance sends it too; a retried create keeps its original key and body.
- Refuse "file is not in revision" locally only when `git ls-tree` proves the path is absent, so a
  partial clone with a missing blob no longer blocks a valid submission.
- Explain the acceptance refusals `commit_not_in_dev`, `commit_outside_task_repository`,
  `commit_evidence_invalid` and `commit_reachability_unknown` with a next step.
- Send cloud commit evidence as `<sha>:<path>` without the "On behalf of" prefix.

## [0.3.17] - 2026-11-24

- Add `lockyard task triage <id>` (cloud mode): moves an intake item to ready. Fields
  come from flags, then the item, then defaults (code / agent / P2 / code_accepted / none).
  `--area` takes the hyphenated area id, the exact key or a unique prefix of an active area;
  any selector the registry could read differently is refused, and an item without an area
  needs `--area`. The command never creates an area.
- Update `url` to 2.5.9 (RUSTSEC-2026-0592).

## [0.3.16] - 2026-11-19

- Route mail waits and cloud hooks with the session's selected credential; keep
  direct long-poll wake cursors separate across credentials, servers and workspaces.
- Keep operations without replay proof in a private unknown journal outside
  the active write budget. Reconcile with `doctor --repair-pending` or archive
  selected records with `doctor --forget-unknown <id|--all> --confirm`.
- Bind tokenless service access to the authenticated agent credential product.
  Offline status marks the last available service snapshot with its cache age.
- Carry Claude session product identity through CLI, MCP and forwarded cloud requests.
- Require `LOCKYARD_CLAUDE_MCP=1` in Claude Code's `.mcp.json` under
  `mcpServers.lockyard.env` for automatic MCP Claude-key selection. A resolved session UUID
  is required; a set `CLAUDE_CODE_SESSION_ID` must match. Explicit token files and parent
  claims disable it. CLI selection still requires the matching nonempty session variable.
  Help and doctor explain the marker and selection reasons without credential values;
  CLI/MCP retain the shared agent-key fallback for `session_name_bound`.
- Keep MCP status claims and tasks available when the optional mail counter fails;
  return `unread: null` with `unread_unavailable: true` instead of failing the tool.
- Protect agent key files with private atomic token output and session recovery guidance.
- Clarify MCP body/TTL fields, idle release deadlines and hold renewal.
- Explain sandbox network failures and distinguish upstream maintenance from protocol errors.

## [0.3.15] - Unreleased

### Added

- Workspace SSE mail delivery when the server advertises `mail_push_v1`, with resumable
  cursors, heartbeat read timeout and reconnect backoff. Older servers retain long-poll.
- `lockyard mail wait` and daemon socket subscriptions for Claude Code `asyncRewake`:
  urgent/reply/ack mail wakes the session; timeout and unavailable services stay silent.
- Broadcast aliases and client/zone/path groups in MCP `update` and CLI `msg send`, plus
  MCP `urgent` and CLI `--urgent`. See [mail push and hook setup](docs/mail-push.md).

## [0.3.14] - 2026-11-16

### Fixed

- Restore the `.long-poll` maintenance hint only while holding the shared pending-journal
  flock (LY-0019). Loading a journal that already has the hint takes no flock; if another
  owner holds the journal, the load still succeeds and the hint is restored by a later
  open. Hint cleanup also requires the shared flock; `zone wait`
  continues to release it throughout the HTTP long poll (LY-0010).
- Release pending-journal and operation flocks explicitly when their guard drops (LY-0020).
  A child process forked meanwhile shares the open file description, so closing alone left
  the journal "busy" until that child exec'd or exited.
- Unit tests of the cloud client no longer race on the process-wide key directory, and the
  fake server closes its listener and workers and reuses connections (LY-0020).

### Added

- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.14`.

## [0.3.13] - 2026-11-15

### Fixed

- Supply the exclusive default before forwarding claim/queue calls through old agents.
  Only a new agent Ping confirming negotiated `soft_zones_v1` permits omission. Claim
  reuse and acquisition receipts apply the same capability-dependent default.
- Claim/wait/queue mode is optional: `--shared` / `--exclusive` and MCP `shared:true|false`
  select a mode explicitly. Servers advertising `soft_zones_v1` choose the omitted default;
  older servers receive `exclusive` for compatibility with 579d557. Status shows mode,
  and wave-4 metadata is accepted by the strict E2EE response classifier (LC-0019/0020).

- `zone wait` / long-poll claims release the local pending-write journal flock while the
  HTTP response is open, so sibling `zone release` / `finish_work` / `start_work` / `task add`
  are not blocked (LY-0010).
- MCP `update` accepts `reply_to` + `body`, `handled:[ids]`, returns new mail by default
  (`all:true` for the whole mailbox), and annotates `queued:true` with a delivery hint
  (LY-0011). Status omits task bodies by default and keeps claim `fence` for renew.
- `zone_renew` / CLI `zone renew` fill `fence` from the caller's own claim in status; foreign
  claims still need an explicit fence (LY-0012).
- MCP `tasks`/`task_list`/`area_list` `structuredContent` is always an object; CLI
  `task list --json` escapes control characters in titles/bodies (LY-0013).
- MCP `task_add` documents and validates `p0_category` enum values; uncertain writes confirm
  creation by retrying the exact POST with the same `client_key`, retiring its pending journal
  record after confirmation; an unconfirmed retry still reports unknown (LY-0014).
- `zone add-path` accepts multiple paths; claim/narrow/add-path paths are workspace-root
  relative; absolute paths are accepted. A path found only relative to a subrepository cwd
  produces a workspace-root hint. Unknown catalog zones explain how to use paths; TTL errors
  name minutes (LY-0015).
- Lost-claim errors use server reasons/times and point to the new `status --lost`; `finish_work`
  lists `released_ids`, `already_gone`, and per-claim `failed` without stopping on one failure
  (LY-0016).
- Unencrypted claims carry a sanitized session label (up to 64 ASCII characters) and process
  IDs in `meta`; unencrypted outgoing mail carries the label in `from_client` (LY-0017).
  Encrypted workspaces omit this identity metadata. Strict E2EE accepts bounded identity
  metadata on other clients' claims. Server 579d557 does not persist a reply sender label.
- `update` validates `handled` IDs and `mail_handled_v1` before sending. A handling failure
  after sending returns `sent` and `handled_error` without marking the send as failed.
- Long polls retain per-key ownership while releasing the shared journal. A verified success
  survives a journal reacquisition failure; a durable completion marker retires the pending
  record on the next journal acquisition.
- Short writes keep the original journal path without per-key sidecar files or extra flushes.
  Per-key locks are created only when a long poll releases the journal. A lazy `.long-poll`
  directory flags maintenance across processes; acquisitions skip sidecar scans while it is
  absent, and cleanup removes the hint once no active locks or completion markers remain.
- Build identity watches HEAD, local branch refs and packed refs; changes to loose remote
  refs no longer force a full rebuild of dependents between identical test invocations.
- Concurrent writes with the same key, including calls in the same process, wait for journal
  ownership within their call deadline and report `journal_busy` if it expires.
- Invalid pending completion markers move to `.completed.bad-<timestamp>` quarantine with a
  warning; unrelated writes continue and the original pending record remains recoverable.

### Added

- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.13`.

## [0.3.12] - 2026-11-15

### Fixed

- Status keeps the caller's own claims when the server marks `holder_available: false`
  (stale presence). Those claims stay visible in text and JSON with a keepalive hint;
  other sessions' unavailable claims still stop blocking (LC-0011).
- `lockyard agent install` writes `~/.local/state/lockyard/agent-config.toml` (url,
  workspace, repository) and sets WorkingDirectory to the state root (or `$HOME`). The
  running service reads only that copy — it does not open the project tree before the
  socket — so launchd no longer hangs in `getcwd` on a Desktop workspace waiting for
  macOS Full Disk Access (LY-0007). **Existing units are not rewritten automatically:
  run `lockyard agent install` again after upgrading.** `agent status` warns when the
  process is alive but the socket file is missing, and when the copied config is older
  than the project's `.lockyard/config.toml`.
- Optional agent reads serialize `attempt_timeout_ms` on `Call` so the daemon applies it as
  the ureq HTTP request timeout; a hung server frees the agent thread within that budget
  (LY-0008).
- Exit code `5` (no cloud access) fires only when there is no token *and* the agent path
  failed; a running agent still serves tokenless `status` / mail / path-request CLI.
- Path-request peeks on `status` / `zone renew` / `zone activity` use `get_with_timeout`
  (≤300 ms). A failed or skipped peek sets `incoming_requests_unknown` and never writes
  an empty `incoming_requests` array.

### Added

- Status, `zone renew`, and `zone activity` surface unanswered path requests aimed at the
  caller's claims (`incoming_requests` in JSON; a `lockyard zone answer` hint in text)
  via `GET /api/v1/zones/requests` (META-0032).
- Without a cloud token and without a usable agent, `status`, `msg inbox`/`open`, and
  `zone requests` print a clear no-access message and exit with code `5` (META-0033).
- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.12`.

## [0.3.11] - 2026-11-14

### Fixed

- Open mail follows the server's per-reader handled state when the cloud announces `mail_open_v1`:
  `status` / `msg open` / renew enrichment call `GET /bus/inbox?open=true` instead of closing only on
  shared `status=ack`. Broadcasts this agent already answered no longer stay open after the server
  cutover. Capability is read only from a fresh negotiated cache or the latest Lockyard-Capabilities
  observation (agent ping/status) — never GET /api/v1/protocol on the status/renew/msg-open hot path.
  Capability is checked first inside the caller budget; a capability error omits the open list rather
  than falling back to the legacy filter. An open=true response without mail_open_v1 in
  Lockyard-Capabilities also omits the list. Shared status=info/ack rows are dropped even on the
  server-selected page. Servers without the capability keep the 0.3.10 client-side filter.


### Added

- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.11`.
  After upgrading, restart the agent (`launchctl kickstart -k …` / `lockyard agent restart`) so
  long-lived processes pick up the new mail_open_v1 status field and observation path.

## [0.3.10] - 2026-11-14

### Fixed

- Local pending-journal contention (`pending journal is busy`) waits and retries inside the same call-deadline clock used for HTTP retries (default wait budget 5 s when no deadline is set); the error is a dedicated `JournalBusy` variant and the text no longer blames the network.
- Workspace encryption keys are re-read from `~/.config/lockyard/keys/<workspace>.key` when missing in memory; an on-disk key is accepted only when its `key_id` matches the workspace encryption setting, otherwise `key id mismatch`. One resolved key is used for both request encryption and response decryption in a call.
- CLI cloud token discovery no longer reads editor/MCP host configs (`.mcp.json`, `~/.claude.json`, …). Order is `LOCKYARD_TOKEN` → `LOCKYARD_TOKEN_FILE` → login credentials → `~/.config/lockyard/token`. Canonical `owner-token` is refused unless `LOCKYARD_TOKEN_FILE` names it explicitly. The refusal lists only those four sources and hints that MCP gets its token from its own settings.
- MCP `area_list` returns `structuredContent` as an object `{"areas":[…]}` (MCP schema), not a bare array — a breaking shape change for clients that expected a bare array in `structuredContent`.
- Stale MCP clients that call `task_add` with only `area` on a `registry_auto_area_v1` server get an explicit reconnect/`--path` hint (no `tools/list_changed` notification).

### Added

- CLI `zone claim --paths-file`, `task add --body-file` / `--acceptance-file` (regular files only, relative to the current directory unless absolute; body ≤64 KiB; paths ≤1000 lines; NUL refused), `zone claim|renew --hold-for <minutes>` (1–240, client computes absolute `hold_until`), `lockyard keepalive [<id>|--all]` (does not extend the lease; use `zone renew`), and `lockyard ping`.
- Compact MCP `keepalive` (presence + claim activity; shared with CLI; `--all` / `all` with zero claims reports "no claims of yours").
- Advance synchronized Rust, npm, PyPI and MCP registry versions to `0.3.10`.

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
