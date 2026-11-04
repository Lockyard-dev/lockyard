# Lockyard

Coordination for coding agents. When several agents work on one codebase they collide: they edit the same files,
repeat each other's work and lose track of what is done. Lockyard gives them work zones so that only one agent touches
a path at a time, a shared bus to talk, and tasks that survive a session. By default all of it lives in one SQLite
file under `.lockyard/` in your project, and nothing leaves the machine. Teams across machines use [cloud
mode](#cloud-mode).

**Status: 0.1.0, the first release.**

## Install

Four channels, all built from the same tagged commit by one release workflow. Pick whichever matches the machine.

```sh
curl -fsSL https://raw.githubusercontent.com/lockyard-dev/lockyard/main/install.sh | sh   # macOS, Linux
cargo install lockyard                                                                   # any platform with Rust
npm install -g lockyard                                                                  # ships the native binary
python3 -m pip install lockyard                                                          # ships the native binary
```

The one-line installer downloads the release archive for your operating system and processor, checks it against the
`SHA256SUMS` published with the release, and puts a single executable in `~/.local/bin`. It needs no `sudo`, sends
nothing anywhere and reports nothing back. Set `LOCKYARD_INSTALL_DIR` to put it elsewhere, or `LOCKYARD_VERSION` to
install a particular release. On Windows, use npm or `cargo install`.

The npm and pip packages are thin wrappers: they pull in one prebuilt binary for the current platform
(macOS arm64 and x64, Linux x64 and arm64, Windows x64) and run it. `cargo install` builds from source and so works
anywhere Rust does.

## Start

```sh
lockyard init                 # create .lockyard/ in the repository
lockyard setup                # configure every agent tool found on this machine
export LOCKYARD_AGENT=alice   # the name the other agents see
lockyard doctor               # check it all took
```

`lockyard setup` writes: it merges an MCP server entry into each client's configuration, installs the edit hook where
the client has one, and adds a short block between `<!-- lockyard:start -->` markers to the instruction file the
client reads. Every file it touches is copied to `<name>.lockyard-backup` first, running it twice changes nothing the
second time, and `lockyard setup --uninstall` takes it all back out. `--dry-run` shows what would happen,
`--client claude` limits it to one tool, and `--print` keeps the old behaviour of printing snippets to paste by hand.

## What works with which tool

Lockyard does three things for an agent, and not every tool supports all three.

| Tool | MCP tools | Blocks an edit of a held path | Mail delivery |
|---|---|---|---|
| Claude Code | yes, `.mcp.json` | **yes** — `PreToolUse` hook, answered with a deny | at the next tool use or prompt, through the same hook |
| Codex CLI | yes, `~/.codex/config.toml` | no hook installed | on the next turn, when the agent calls `check` or `msg inbox` |
| Cursor | yes, `.cursor/mcp.json` | no hook installed | on the next turn, as above |
| Gemini CLI | yes, `.gemini/settings.json` | no hook installed | on the next turn, as above |
| GitHub Copilot CLI | yes, `~/.copilot/mcp-config.json` | no hook installed | on the next turn, as above |

"Blocks an edit" means Lockyard can refuse a write to a path another agent holds, before it happens. Only Claude Code
documents a pre-edit hook whose answer can deny the call, so only there does `lockyard setup` wire one: a hook that
runs but cannot refuse is worse than no hook, because it reads like protection and is not. `lockyard hook cursor` and
`lockyard hook codex` exist and work if you wire them into something yourself.

Without a blocking hook, coordination rests on the agent asking — which is what the instruction block that
`lockyard setup` adds tells it to do, and what the MCP tools make cheap. The lock model is the same either way: a
claim conflict is refused, with exit code 3 on the command line and an error from the MCP tool.

"Mail delivery" is honest about waking an agent up: no tool here offers a documented way for an outside process to
interrupt a running turn. Mail arrives the next time the agent does anything — which, with the Claude Code hook
installed, is its next tool call.

## MCP

```sh
lockyard mcp                  # six tools: start_work, check, update, handover, finish_work, status
lockyard mcp --tools full     # every tool, for a client that can handle a long list
```

The six are the whole working loop: `start_work` claims paths and takes a task, `check` asks whether a path is free,
`update` sends a message and reads the inbox, `handover` gives work to another agent, `finish_work` submits evidence
and releases, `status` says where everything stands. Each is the same sequence of the underlying tools, so a refusal
is a refusal in both surfaces. `LOCKYARD_MCP_TOOLS=full` does the same as the flag, and the flag wins.

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
lockyard msg sent
```

The address must be an agent seen in this project, so a typo fails instead of losing the message. Mail is kept for
seven days.

`lockyard msg sent` answers "did it land?" for each of your own messages: `sent` means written down, `delivered`
means it was put in front of the other agent, `read` means they marked it read, `replied` means they answered, and
`failed` means it aged out without ever being shown. A sender who can tell those apart stops repeating themselves.

See [examples/two-agents](examples/two-agents) for the whole thing — a claim, a refusal, a message and a handover —
as a script you can run.

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

`lockyard setup --client claude` writes `.claude/settings.json`, `.mcp.json` and a block in `CLAUDE.md`. The hook
denies `Edit`, `Write`, `MultiEdit` and `NotebookEdit` on a path another agent holds, and shows unread mail in the
agent's context. The agent's name is the session id unless `LOCKYARD_AGENT` is set. If the hook itself fails, the tool
call goes through and the failure is printed on stderr.

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

Then sign in:

```sh
lockyard cloud login --url https://your-server.example
lockyard cloud logout --url https://your-server.example
```

`login` asks the server for a code, opens the sign-in page in a browser (`--no-browser` just prints the link), and
waits while you approve it there. The token it is given is written to `~/.config/lockyard/credentials.toml` with
permissions `0600`, under the server it belongs to, and is never printed. A URL typed after `--url` is trusted as
part of signing in; a URL that only came out of a project file has to be trusted first, because that file arrives
with the clone.

The workspace is a label: the server takes the real one from the token. The token comes from `LOCKYARD_TOKEN`, then
the file named by `LOCKYARD_TOKEN_FILE`, then the credentials file — never from the project config, so a CI job that
exports a token is unaffected by whoever is logged in on the machine. A session can be addressed once it has sent a
heartbeat: `lockyard presence beat`, or any hook through the agent process.
Before the client or `lockyard agent` sends a user token to the URL in a project file, trust that URL with
`lockyard cloud trust https://your-server.example`. This adds it to
`~/.config/lockyard/trusted-servers` (or `$XDG_CONFIG_HOME/lockyard/trusted-servers`) with private file permissions.
Alternatively, set `LOCKYARD_URL` to the trusted server URL. Hooks connect only to the local agent socket and do not
need either setting.

### Tokens

The server starts with one owner token, set by `LOCKYARD_BOOTSTRAP_TOKEN`. Use it to make the others, then keep it safe.

```sh
LOCKYARD_TOKEN=$OWNER lockyard cloud token create alice --role agent --days 90   # the raw token prints once
LOCKYARD_TOKEN=$OWNER lockyard cloud token list
LOCKYARD_TOKEN=$OWNER lockyard cloud token revoke <id>
```

Roles are `agent`, `lead`, `owner`, `exporter`, `importer` and `dispatcher`.

### Encrypted workspace content

When a workspace enables client-side content encryption, content fields are stored as `lyenc1` envelopes; paths,
sessions, zones, states, ids, and keys remain clear so coordination continues to work. A client without the workspace
key displays encrypted fields as locked. Create or import the local key with `lockyard cloud key create` or
`lockyard cloud key import` (the latter reads a 24-word BIP-39 phrase from stdin); `lockyard cloud key show-phrase`
requires typing `SHOW`. Keys live in `~/.config/lockyard/keys/` with private permissions and must be backed up using
the recovery phrase. The server cannot search encrypted registry text; search must run locally in a client that holds
the key. Bus secret scrubbing happens before encryption.

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

## Machine guard

`lockyard machine` reports local memory, swap, disk and load pressure in any folder. `lockyard run --heavy -- <command>`
uses a local slot, waits while pressure is high, and pauses only the process group it started when memory or disk reaches
the critical threshold. While its supervisor is running, it resumes that group after pressure falls. A shell hook also
refuses configured heavy commands while pressure is at hold. Machine thresholds and heavy commands are shared across
projects in `~/.config/lockyard/machine.toml` (or `$XDG_CONFIG_HOME/lockyard/machine.toml`); memory thresholds default to
percentages of installed memory. The guard lowers the chance of a hang. It cannot stop work started outside Lockyard or
guarantee that a machine cannot hang.

## Testing against a real server

`crates/lockyard/tests/e2e.rs` drives the real binary as several agents. It needs `LOCKYARD_E2E_URL`, `LOCKYARD_E2E_OWNER_TOKEN`
and `LOCKYARD_E2E_SERVER`, a shell command that runs the server in the foreground on a database that survives a restart.
The suite starts and stops that server itself. Without the URL it skips, and with `LOCKYARD_E2E_REQUIRED=1` it fails instead.

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
