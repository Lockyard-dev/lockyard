# Lockyard core — packaging catch-up, 04.11.2026

Six commits on `e484b55`. `cargo fmt --check` and `clippy --all-targets -D warnings` clean.

1. **Honest install.** 0.1.0 in Cargo, npm, PyPI, `server.json` and the Python package's `__version__` (left at
   0.0.1); a version gate in CI and on each tag keeps them together. README lists exactly four channels:
   `install.sh`, cargo, npm, pip. **The npm package could not have run:** a bare `bin/` rule in `.gitignore`
   excluded `packages/npm/bin/lockyard.js`, the file the manifest points at. Added, with tests. `CHANGELOG.md`.
2. **`install.sh`.** POSIX sh, macOS/Linux × arm64/x64, verifies SHA-256 against the release `SHA256SUMS`, installs
   to `~/.local/bin`, no sudo, no telemetry. `tests/install-sh.test.sh` runs it offline with stubbed `curl`/`uname`
   against a fake release: 12 checks, including a tampered archive and an unlisted asset.
3. **`lockyard setup` writes.** Merges MCP config, installs the hook, adds a marked block to the instruction file;
   backup before every write, idempotent, `--dry-run`, `--uninstall`, `--print`, `--client`, and it refuses to
   rewrite a config file it cannot parse. `lockyard doctor` checks project, store, agent name, mode, cloud and each
   detected client. 24 unit tests, 2 CLI tests.
4. **Clients.** Gemini CLI and GitHub Copilot CLI added. A README table says per client what is registered, whether
   an edit can be refused and when mail arrives. **Only Claude Code gets a hook**: nothing else documents a pre-edit
   hook that can deny, and a hook that cannot refuse reads like protection without being any (`lockyard hook
   cursor|codex` still work by hand). Mail is "on the next turn" everywhere — nothing here documents a supported way
   to interrupt a running turn, so nothing claims to.
5. **Compact MCP.** Six composite tools by default, 66 under `--tools full` or `LOCKYARD_MCP_TOOLS=full` (flag
   wins). Composites are ordered runs of the same tools, so a conflict is refused identically; `start_work` gives
   its zone back if the task cannot be claimed. 7 unit tests, 2 CLI tests across both surfaces.
6. **Receipts.** `sent → delivered → read → replied`, or `failed` for mail that ages out unseen; `lockyard msg sent`
   shows them. 7 store tests, 1 CLI test, 1 cloud-client test.
7. **`cloud login` / `logout`.** The contract's device flow behind a `DevicePost` seam with injected waiting, so the
   pacing rules are tested without a server: 16 tests. Token stored 0600 in `~/.config/lockyard/credentials.toml`,
   never printed; env still wins over it.
8. **Registries.** `server.json`, `glama.json`, publishing order in `PUBLISHING.md`.
9. **Two-agent demo.** `examples/two-agents/run.sh` plus a README transcript; `--check` fails if any step differs
   and CI runs it. It caught a wrong claim while being written.
10. **CI.** fmt/clippy/test on ubuntu/macos/windows; packages, installer and the example as their own jobs. Release
    builds five targets, smoke-runs each, publishes archives + `SHA256SUMS` + `install.sh` before any registry.

**Tests: 310 pass** — core 90, cloud client 86, binary 102, cli 22, e2e 1; plus npm 4, Python 4, install.sh 12,
check-versions 10. Both new gates were watched failing: `if false` in `check-versions.sh` fails its test, and
breaking the checksum comparison fails two install.sh checks.

## Not done, and why

- **35 tests cannot run here** (31 `agent::daemon`/`agent::socket`/`guard::recovery`, 4 in `tests/cloud.rs`). This
  sandbox denies `AF_UNIX bind()` — `Errno 1, Operation not permitted`, for a plain Python bind too — so each one
  fails starting the agent socket, before reaching Lockyard code. Same count as before these changes. **They need a
  run on an unsandboxed machine before release.**
- Setup's unit tests write Claude's settings to an injected path and check Cursor at plan level only: this sandbox
  refuses to create `.claude/` or `.cursor/` anywhere. `Site::discover` is tested separately to pin the real paths.
- No web research was possible (search unavailable), so every client capability claim is conservative and
  corroborated only by what the code already does. **`server.json`'s field names (`runtimeArguments`,
  `environmentVariables`) and its `2025-12-11` schema date need checking against the live registry schema before
  publishing** — the date is copied from a published manifest, not from the spec.

## The cloud side must match

- `GET /api/v1/bus/sent?limit=N` → `{"messages":[{id,to,body,created_at,status,delivered_at,read_at,replied_at}]}`,
  `status` one of `sent|delivered|read|replied|failed`. An unknown value is shown as sent, not rejected.
- `POST /api/v1/messages/{id}/receipt {"status":"read"}` is sent when a recipient marks mail read. It is **not**
  sent for `delivered`: reading the inbox must stay a read — hooks run it on every edit, and a frozen server must
  not turn that into a refusal — so **the server records `delivered` itself when its inbox endpoint hands a message
  out**. If that is wrong, say so and the client will send it.
- Device login is implemented as written: `POST /api/v1/auth/device`, `.../device/token`, 428/429/403/410/200. The
  client refuses a grant whose `server_url` is not the server it asked, and reads a missing one as that server.
- Credentials: `~/.config/lockyard/credentials.toml` (or `$XDG_CONFIG_HOME`), keyed by server URL, mode 0600. The
  contract says "where `lockyard cloud` already keeps credentials"; there was no such file, so this defines it.
