# Client setup and diagnostics

`lockyard setup claude`, `lockyard setup codex` and `lockyard setup cursor` still
print configuration snippets without writing files. These explicit actions manage
the selected integration:

```sh
lockyard setup claude --preview --json
lockyard setup claude --apply
lockyard setup claude --check --json
lockyard setup claude --remove
lockyard doctor --client claude --smoke --json
```

Claude uses project `.mcp.json` and `.claude/settings.json`; Cursor uses project
`.cursor/mcp.json`; Codex uses `$CODEX_HOME/config.toml` when `CODEX_HOME` is set
to a non-empty path, otherwise `~/.codex/config.toml`. Preview, apply, check,
remove and `doctor --client codex` all use that same effective path. From a project subdirectory,
the project integrations use the nearest `.lockyard` root. Without a project they
use the current directory. Codex and Cursor setup currently install MCP only;
they do not claim that edit hooks are activated. Claude setup merges the supported
edit/tool hooks. Reload the coding client after configuration changes.

Export `LOCKYARD_AGENT` with a unique name before starting each coding client.
Codex's managed MCP entry forwards `LOCKYARD_AGENT`, `LOCKYARD_URL`,
`LOCKYARD_TOKEN_FILE`, `LOCKYARD_TOKEN`, `LOCKYARD_NODE_CONFIG`, `XDG_CONFIG_HOME`,
`LOCKYARD_REQUIRE_E2EE` and `LOCKYARD_E2EE_WORKSPACE_ID` from the client environment
to the Lockyard process. This preserves node configuration, the selected local
key store and an already-required encryption policy. Cloud mode requires the trusted URL and either token source;
prefer a private token file. Setup stores these variable names, never their
values. Existing unchanged managed Codex
entries upgrade with `lockyard setup codex --apply`; `--check` reports the older
entry as missing until it is upgraded. Customized entries are preserved and
reported as conflicts.

Preview reports intended file changes and conflicts without writing or showing
existing configuration values. Apply preserves unrelated MCP entries, settings,
hooks and TOML comments. A different existing `lockyard` server is a conflict:
setup does not replace it. Identical pre-existing entries are left user-owned.
Each changed existing file has a private backup beside it. An ownership sidecar
ending in `.lockyard-setup.json` records the individual entries that setup added.
Remove deletes only matching managed entries, preserving later user changes and
unrelated configuration. A modified managed entry is reported as a conflict,
not overwritten. Backups are retained for recovery and can contain sensitive
values from the original configuration; they are created with private permissions.

Installation is atomic per file, not across several files. Inspect all `files`
results after a partial failure, correct the reported prerequisite, and rerun.
Repeated apply does not duplicate hooks or servers. No shell startup files,
credentials, Git hooks, or cloud environment settings are installed by these commands.

Doctor checks the project, configuration, session identity, local database
presence, and selected client configuration. For cloud mode it checks explicit
server trust, credential binding presence, daemon URL/workspace/token alignment,
view freshness and rejected outbox state without printing tokens or fingerprints.
It does not contact the server or claim that a present credential is authorized.
Warnings identify missing daemon/freshness/enforcement capabilities separately
from failed prerequisites. Failed checks make the command exit nonzero while
preserving the structured report on stdout.

`--smoke` runs real CLI processes in a separate, temporary local project: agent A
claims a path, agent B must receive conflict exit code 3, A releases, and B must
then claim successfully. The temporary project is removed and the caller's zones
and client settings are untouched. This tests installed CLI/local coordination;
it is not proof that a running coding client loaded MCP or that cloud authorization
works. Validate those in the intended client and cloud workspace separately.
