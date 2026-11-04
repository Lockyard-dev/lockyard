# Lockyard client: result

**Done, all four deliverables.** Typed DTOs and `CloudBackend` for the whole protocol; CLI, MCP tools and hooks on one config-selected backend; two-phase hook mail; `lockyard agent` with socket, view, durable outbox and launchd/systemd units. Unused local tables are dropped by migration v4.

**Real run (this Mac, clean tree):** fmt and clippy `-D warnings` clean. 200 tests pass: core 63, cloud client 35, binary 75, cli 16, cloud end-to-end 11. Eight repeat runs of the binary's suites: no flakes.

**Bitten tests, one mutation each:**
- Marking before print: 2 failed.
- Claim delayed in the outbox: 3 failed.
- Stale view answered from memory: 2 failed.

**Not done:**
- `task` in cloud mode is refused; `CONTRACT.md` is absent, so the registry is not wrapped. Use `work`.
- No test against a real server.
- launchd/systemd activation never ran; only unit files were tested.
- CLI exit 4 (`unknown`) has no end-to-end test.
- No agent on Windows; hooks allow there.

**Protocol assumptions:**
- Lists arrive bare or under a plural name; records bare or under a singular name.
- 409 holders: `details.conflicts[]` with path, session, claim_id, note.
- `zones/check` answers `{paths: [{path, status, holder}]}`.
- `inbox/claim` answers `{claimed: []}`; no list means all granted. It has no channel field, so the server must refuse a second claim from one session.
- `GET /bus/tasks` and `/bus/tasks/{id}` exist; final status `declined`.
- Timestamps are integers or text.
- `activity` is nested, including `meta`.
- Catalog shape: `zones.<name>`, `groups.<name>`.
- Zone events reach the agent's own session `lockyard-agent-<uid>`.
- One agent serves one workspace (one token).
- Idempotency keys outlive outages.
