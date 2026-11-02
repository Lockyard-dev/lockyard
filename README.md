# Lockyard

Coordination for coding agents. When several agents work on one codebase they collide: they edit the same files,
repeat each other's work and lose track of what is done. Lockyard gives them work zones so that only one agent touches
a path at a time, a shared bus to talk, and tasks that survive a session. By default all of it lives in one SQLite
file under `.lockyard/` in your project, and nothing leaves the machine. Teams across machines use [cloud
mode](#cloud-mode).

**Status: early release.** Install with Cargo, npm or pip. npm and pip packages include the native Lockyard executable.

```sh
cargo install lockyard
lockyard init
export LOCKYARD_AGENT=alice
```

Or install the native executable through npm or pip:

```sh
npm install -g lockyard
python3 -m pip install lockyard
```

`lockyard setup claude`, `lockyard setup codex` and `lockyard setup cursor` print configuration snippets for MCP; the
Claude setup also prints the edit hook settings. Set `LOCKYARD_AGENT` to a unique name for each agent. The MCP server
starts with `lockyard mcp` and communicates over standard input and output.

## Zones

A claim is a lease on paths. It covers everything below them, and an expired lease frees the path, so a crashed agent
cannot hold a zone forever. Leases last 30 minutes unless you pass `--ttl`, up to 240.

```sh
lockyard zone claim src/api docs --note "new auth flow"
lockyard zone check src/api/mod.rs     # exit 3 when another agent holds the path
lockyard zone renew
lockyard zone release
```

## Bus

```sh
lockyard who
lockyard msg send bob "I am done with src/api"
lockyard msg send '*' "main is broken, do not merge"
lockyard msg inbox
lockyard msg reply M-4 "fixed in abc1234"
```

The address must be an agent seen in this project, so a typo fails instead of losing the message. Mail is kept for
seven days.

## Tasks

A task moves from open to claimed to review to accepted. The agent that did the work cannot accept it, and submitting
requires evidence. A claim that stops being renewed can be taken by another agent.

```sh
lockyard task add "Rate limit the login route" --body "Details here"
lockyard task claim T-1
lockyard task submit T-1 --evidence "abc1234, 42/42 tests"
lockyard task accept T-1               # by a different agent
lockyard task reject T-1 --reason "the test never fails"
```

## Claude Code

`lockyard setup claude` prints settings for `.claude/settings.json` and an MCP server entry for `.mcp.json`. The hook
denies `Edit`, `Write`, `MultiEdit`
and `NotebookEdit` on a path another agent holds, and shows unread mail in the agent's context. The agent's name is the
session id unless `LOCKYARD_AGENT` is set. If the hook itself fails, the tool call goes through and the failure is printed
on stderr.

## Cloud mode

Local mode has zones, mail, tasks, the board and presence. Everything else needs cloud mode, and says so when asked for
in local mode: `zone wait`, `queue`, `unwait`, `request`, `answer`, `handover`, `accept`, `narrow`, `add-path`,
`takeover`, `dirty`, `msg ack`, `msg thread`, `events`, `work`, `task plan` and `cloud`.

Create `.lockyard/config.toml`:

```toml
mode = "cloud"
url = "https://your-server.example"
workspace = "your-team"
```

The workspace is a label: the server takes the real one from the token. The token comes from `LOCKYARD_TOKEN` or from
the file named by `LOCKYARD_TOKEN_FILE`, and never from the config file. A session can be addressed once it has sent a
heartbeat: `lockyard presence beat`, or any hook through the agent process.

### Tokens

The server starts with one owner token, set by `LOCKYARD_BOOTSTRAP_TOKEN`. Use it to make the others, then keep it safe.

```sh
LOCKYARD_TOKEN=$OWNER lockyard cloud token create alice --role agent --days 90   # the raw token prints once
LOCKYARD_TOKEN=$OWNER lockyard cloud token list
LOCKYARD_TOKEN=$OWNER lockyard cloud token revoke <id>
```

Roles are `agent`, `lead`, `owner`, `exporter`, `importer` and `dispatcher`.

### Tasks in cloud mode

`lockyard task` works on the server's backlog, and the agent that writes an item sets its urgency itself. An item is
ready at once, without triage. It needs an area, and the first area of the workspace is used unless you pass `--area`. A
lead or an owner creates the first one on their first `task add`.

```sh
lockyard task add "Rate limit the login route" --priority P1 --type code --target code_accepted
lockyard task add "Checkout is down" --priority P0 --p0-category prod_outage --evidence "probe 12:04"
lockyard task plan D-14 --priority P2 --due 2026-12-01T00:00:00Z
```

`T-14` and `D-14` name the same item. A lease lasts two hours whatever `--ttl` says. Only a lead or an owner accepts,
rejects or cancels, and an item can be cancelled only while nobody holds it. `task submit` records its evidence as a commit, or
as a CI run for the target `ci_passed`. A target that needs a deploy probe cannot be closed from here. Task offers between
agents stay in `lockyard work`.

### The agent process

Hooks in cloud mode talk only to `lockyard agent`, one background process per user. It keeps a view of claims, unread
counts and the board, so `zone check` answers in milliseconds.

```sh
export LOCKYARD_TOKEN_FILE=~/.config/lockyard/token
lockyard agent install     # a launchd or systemd user unit
lockyard agent status
lockyard agent uninstall
```

- The view is used while it is fresher than 30 seconds. After that one server call gets 800 ms, and then the answer is
  `unknown`: a hook allows the edit and notes it on stderr, and `zone check` exits 4.
- Mail, heartbeats and activity go through a durable outbox under `$XDG_STATE_HOME/lockyard`, or
  `~/.local/state/lockyard`, so they survive an outage and arrive in order. Claims never wait in it: during an outage
  they fail, because a claim that lands minutes late is worse than one that was refused.
- One agent serves one workspace, the one its token belongs to. A hook in any other workspace allows and says why.
- One agent serves one token. A command run with another token goes straight to the server, so it keeps its own role.
- With no agent running, the command line calls the server itself, and hooks allow and say so.

## Testing against a real server

`crates/lockyard/tests/e2e.rs` drives the real binary as several agents. It needs `LOCKYARD_E2E_URL`, `LOCKYARD_E2E_OWNER_TOKEN`
and `LOCKYARD_E2E_SERVER`, a shell command that runs the server in the foreground on a database that survives a restart.
The suite starts and stops that server itself. Without the URL it skips, and with `CI=true` it fails instead.

## Limits

- Lockyard prevents accidents between cooperating agents. Agent names are not authenticated, and an agent can pretend to
  be another one.
- The hook sees file edit tools only. A file changed by a shell command is not checked.
- Subagents of one Claude Code session share its session id, so they count as one agent.
- On macOS and Windows, path comparisons fold ASCII case to match their usual case-insensitive file systems. Other
  platforms compare paths exactly.
- In local mode all agents must run on one machine.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
