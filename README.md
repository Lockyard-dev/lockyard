# Lockyard

Coordination for coding agents. When several agents work on one codebase they collide: they edit the same files,
repeat each other's work and lose track of what is done. Lockyard gives them work zones so that only one agent touches
a path at a time, a shared bus to talk, and tasks that survive a session. By default all of it lives in one SQLite
file under `.lockyard/` in your project, and nothing leaves the machine. Teams across machines use [cloud
mode](#cloud-mode).

**Version: 0.3.9.**

## Install

Four channels, all built from the same tagged commit by one release workflow. Pick whichever matches the machine.

```sh
curl -fsSL https://raw.githubusercontent.com/lockyard-dev/lockyard/main/install.sh | sh   # macOS, Linux
cargo install lockyard                                                                   # any platform with Rust
npm install -g lockyard                                                                  # ships the native binary
python3 -m pip install lockyard                                                          # ships the native binary
```

The one-line installer downloads the release archive for your operating system and processor, checks it against the
`SHA256SUMS` published with the release, and — when [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
is on `PATH` — verifies the Sigstore signature too. It puts a single executable in `~/.local/bin`, needs no `sudo`,
sends nothing anywhere and reports nothing back. Set `LOCKYARD_INSTALL_DIR` to put it elsewhere, or `LOCKYARD_VERSION`
to install a particular release. On Windows, use npm or `cargo install`. Release assets also include a CycloneDX SBOM.

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
| Claude Code | yes, `.mcp.json` | **yes** — `PreToolUse` hook, answered with a deny | immediately with `lockyard monitor`, else at the next tool use or prompt |
| Codex CLI | yes, `~/.codex/config.toml` | no hook installed | immediately with `lockyard monitor`, else on the next turn |
| Cursor | yes, `.cursor/mcp.json` | no hook installed | immediately with `lockyard monitor`, else on the next turn |
| Gemini CLI | yes, `.gemini/settings.json` | no hook installed | immediately with `lockyard monitor`, else on the next turn |
| GitHub Copilot CLI | yes, `~/.copilot/mcp-config.json` | no hook installed | immediately with `lockyard monitor`, else on the next turn |

"Blocks an edit" means Lockyard can refuse a write to a path another agent holds, before it happens. Only Claude Code
documents a pre-edit hook whose answer can deny the call, so only there does `lockyard setup` wire one: a hook that
runs but cannot refuse is worse than no hook, because it reads like protection and is not. `lockyard hook cursor` and
`lockyard hook codex` exist and work if you wire them into something yourself.

Without a blocking hook, coordination rests on the agent asking — which is what the instruction block that
`lockyard setup` adds tells it to do, and what the MCP tools make cheap. The lock model is the same either way: a
claim conflict is refused, with exit code 3 on the command line and an error from the MCP tool.

"Mail delivery" without a monitor is honest about waking an agent up: no tool here offers a documented way for an
outside process to interrupt a running turn. Run `lockyard monitor` in the project (or as a background agent job) to
print new mail and unannounced writes as the store changes; the file-system events are an accelerator, and a 10-second
reconcile still runs because FSEvents and inotify can drop events. Without the monitor, mail arrives the next time the
agent does anything — which, with the Claude Code hook installed, is its next tool call.

## Mail marks and open asks

`lockyard msg inbox` marks a page read only when its stdout is a terminal. Piping or redirecting is the same as `--peek`; scripts that must mark use `--mark-read`. MCP `update` with `to` and `body` sends a note without marking inbox mail. Asks that still need your reply stay visible as open mail in `status`, `msg open`, and `open_mail_count` on renew, even after a mark-read, until you reply or ack (server per-reader handled state is LC-0004).

## MCP

```sh
lockyard mcp                  # 16 compact tools (listed below)
lockyard mcp --tools full     # every tool, for a client that can handle a long list
```

The compact catalog contains `revoke_access`, `start_work`, `check`, `update`, `handover`, `finish_work`, `status`,
`tasks`, `task_bulk`, `registry_import`, `area_list`, `area_create`, `area_update`, `cloud_protocol`, `task_add`,
and `zone_renew`.

The working loop uses `start_work` to claim paths and take a task, `check` to ask whether a path is free,
`update` to send a message and read the inbox, `handover` to give work to another agent, `finish_work` to submit
evidence and release, and `status` to show where everything stands. On servers announcing
`registry_auto_area_v1`, `task_add` requires `paths`, an array of files or directories relative to the workspace
root; the server determines the area. `area` is an optional override. For older servers, compact mode still
requires `area`, while full mode keeps its existing default. Paths are omitted with a warning on older servers.
Startup and `tools/list` use a local catalog and do not contact the server or background agent. Both catalogs
declare only `title` required for `task_add`; the server capability is checked when the tool is called, and
missing paths or area are explained in the refusal.
Local `task_add` supports `area: "general"` with `D-*` numbers and does not persist paths; other registry areas
require cloud mode. `zone_renew` extends an owned, live claim with an optional `ttl` of 1–240 minutes
(default 30). Cloud mode requires the current `fence`; local claims renew without a fence. Foreign and expired
claims are refused, as are stale fences in cloud mode. Underlying authorization and refusal behavior are shared
by both surfaces. `LOCKYARD_MCP_TOOLS=full` does the same as the flag, and the flag wins.

`start_work` accepts `hold_reason` and an optional RFC 3339 `hold_until`. A deadline requires a reason.
In cloud mode, a reason alone holds the claim until its `expires_at`. It first acquires the claim, then renews that claim
with its returned fence and the hold, so deployed servers do not need new claim-request fields. If the hold
fails, a claim created by this call is released; a reused claim is preserved and the call reports an error.
Legacy replies without a creation receipt preserve the claim on failure, since its creation cannot be proven.
Without `hold_reason`, the server releases the claim after 20 minutes without reported activity.
Local mode validates these inputs and takes the claim without renewal or stored hold fields, since local
claims are not released for inactivity.

`finish_work` accepts `id` to release one claim or `all: true` to release all owned claims. With neither,
it releases a sole owned claim, does nothing when there are none, and refuses when there are several,
listing their ids before submitting any task. `id` and `all: true` cannot be combined. Incoming handover
offers do not count as owned claims. Local `handover` also requires `id` when several claims are owned.
Compact MCP `status` includes `lost: []` or up to ten recent losses with `claim_id`, `paths`, `reason`,
and `lost_at`. Losses older than 120 minutes are omitted; entries without a timestamp are included.
If the loss lookup fails, `lost` is `null` and the remaining status fields are still returned.

For configuration snippets, use `lockyard setup --print --client claude`, `--client codex` or `--client cursor`. Set `LOCKYARD_AGENT` to a unique name for each agent. The MCP server communicates over standard input and output. The Codex configuration forwards the agent identity and configured Cloud URL/token variables; export them before starting Codex.

## Zones

A claim is a lease on paths. It covers everything below them, and an expired lease frees the path, so a crashed agent
cannot hold a zone forever. Leases last 30 minutes unless you pass `--ttl`, up to 240.

```sh
lockyard zone claim src/api docs --note "new auth flow"
lockyard zone check src/api/mod.rs     # exit 3 when another agent holds the path
lockyard zone renew
lockyard zone release
```

`zone claim` accepts `--hold-reason "waiting for review"` and an optional RFC 3339
`--hold-until 2026-11-11T21:45:00Z`, using the same cloud acquire-then-renew hold path as `start_work`.
Local mode validates these flags and takes the claim without storing a hold. In cloud mode,
without `--hold-until`, the hold lasts until the claim expires. A deadline without a reason is refused;
the server enforces its 240-minute hold limit. Claims may include the optional public `idle_release_at`
timestamp when the server supplies it; older servers omit it.

`zone release <id>` releases that claim. With no id it releases a sole owned claim or returns zero when
there are none. If several claims are owned, it lists their ids and requires an id or explicit `--all`.
An id and `--all` cannot be combined. This protects other processes using the same agent name.

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
# Optional: the same stable repository ID in every checkout of this repository.
# repository = "api"
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
ready at once, without triage. Servers announcing `registry_auto_area_v1` require the files or directories the task
concerns, passed with repeatable `--path`; the server determines the area. Paths are relative to the workspace
root (the nearest parent containing `.lockyard`), even when running from a subdirectory. Absolute paths inside
that root are accepted; outside paths are refused. `--area` is an optional override, sent unchanged. Split work
across repositories into one task per repository. On older servers, paths are omitted with a warning and the
existing area selection remains: `--area` or the first area, created by a lead/owner when needed.

```sh
lockyard task add "Rate limit the login route" --path platform/src/login.rs --priority P1 --type code --target code_accepted
lockyard task add "Checkout is down" --path platform/src/checkout --priority P0 --p0-category prod_outage --evidence "probe 12:04"
lockyard task plan D-14 --priority P2 --due 2026-12-01T00:00:00Z
```

`T-14` and `D-14` name the same item. A lease lasts two hours whatever `--ttl` says. Only a lead or an owner accepts,
rejects or cancels, and an item can be cancelled only while nobody holds it. `task submit` records its evidence as a commit, or
as a CI run for the target `ci_passed`. A target that needs a deploy probe cannot be closed from here. Task offers between
agents stay in `lockyard work`.

`lockyard status --json` and the MCP `status` tool return the current session's assigned registry tasks in
`tasks`. Cloud status follows pages for `active` and `review`, the statuses that retain an assignee; empty
pages require two registry requests. It does not fetch or return the full registry in a `backlog` field.
Use `lockyard task list --json` (or MCP `task_list`) for the full task list. Local status keeps its existing
behavior.

Compact MCP `status` additionally fetches recent lost claims. CLI `lockyard status --json` keeps its
existing fields and request count; it does not fetch the lost list.

### The agent process

Hooks in cloud mode talk only to `lockyard agent`, one background process per user. It keeps a view of claims, unread
counts and the board, so `zone check` answers in milliseconds.

```sh
export LOCKYARD_TOKEN_FILE=~/.config/lockyard/token
lockyard agent install     # a launchd or systemd user unit
lockyard agent status
lockyard agent uninstall
```

- The view is used while it is fresher than 30 seconds. After that one server call gets 800 ms; if the answer is still
  `unknown`, the edit hook denies the edit and `zone check` exits 4.
- Mail, heartbeats and activity go through a durable outbox under `$XDG_STATE_HOME/lockyard`, or
  `~/.local/state/lockyard`, so they survive an outage and arrive in order. Claims never wait in it: during an outage
  they fail, because a claim that lands minutes late is worse than one that was refused.
- One agent serves one workspace, the one its token belongs to. Without a matching agent and fresh mirror, an edit
  hook denies the edit and says to start the agent.
- One agent serves one token. A command run with another token goes straight to the server, so it keeps its own role.
- With no agent running, the command line calls the server itself, and cloud edit hooks deny until the agent starts.

## Machine guard

`lockyard machine` reports local memory, swap, disk and load pressure in any folder. `lockyard run --heavy -- <command>`
uses a local slot, waits while pressure is high, and pauses only the process group it started when memory or disk reaches
the critical threshold. While its supervisor is running, it resumes that group after pressure falls. A shell hook also
refuses configured heavy commands while pressure is at hold. Machine thresholds and heavy commands are shared across
projects in `~/.config/lockyard/machine.toml` (or `$XDG_CONFIG_HOME/lockyard/machine.toml`); memory thresholds default to
percentages of installed memory. The guard lowers the chance of a hang. It cannot stop work started outside Lockyard or
guarantee that a machine cannot hang.

## Testing against a real server

Local CLI p95 budgets are 15 ms for hooks on every OS and 20 ms for sends on
macOS/Linux, 35 ms on Windows, with one attempt per gate. See
[performance budgets and opt-in diagnostics](docs/performance.md).

`crates/lockyard/tests/e2e.rs` drives the real binary as several agents. It needs `LOCKYARD_E2E_URL`, `LOCKYARD_E2E_OWNER_TOKEN`
and `LOCKYARD_E2E_SERVER`, a shell command that runs the server in the foreground on a database that survives a restart.
The suite starts and stops that server itself. Without the URL it skips, and with `LOCKYARD_E2E_REQUIRED=1` it fails instead.

## Development workflows

`lockyard task ready`, `task search`, `task links` and `task why-blocked` expose the cloud registry's
native task states and dependency information. `lockyard context` builds a bounded briefing for a new
session, and `work handoff --report ... --commit ...` carries context to the next agent.

An explicit `lockyard workflow run <operation-id> --plan plan.json` records each coordination step.
Retries preserve completed steps and stop on uncertain writes or stale ownership; the workflow is not
an atomic transaction. See [context, handoff and workflows](docs/context-workflows.md).

`lockyard doctor --smoke` verifies local coordination with two temporary agents. Client configuration
changes are opt-in with `setup <client> --preview`, `--apply`, `--check` and `--remove`.
See [managed client setup](docs/onboarding.md).

For several repositories sharing cloud tasks and messages, configure distinct stable repository IDs.
See [repository namespaces](docs/repositories.md) before changing an active project's identity.

## Limits

- Lockyard prevents accidents between cooperating agents. In local mode, agent names are cooperative identities rather than
  authenticated users, and an agent can pretend to be another one. Cloud sessions are bound to workspace tokens; a credential role is not proof of a physical human identity.
- The hook sees file edit tools only. A file changed by a shell command (`sed -i`, an editor, a build script) is **not
  refused**. `lockyard monitor` can notice it, mail the holder and show it in `status` / `doctor` — that is detection,
  not prevention. By the time the event arrives the write has already happened.
- Subagents of one Claude Code session share its session id, so they count as one agent.
- In local mode, paths use NFC normalization and Unicode case-insensitive comparison on every operating system.
  Cloud path comparison follows the repository's server catalog policy so different client operating systems agree.
- In local mode all agents must run on one machine.
- Cloud edit checks answer from a local mirror (see [docs/cloud-mirror.md](docs/cloud-mirror.md)); a stale or missing
  mirror refuses the edit rather than guess.

## Security and privacy

- [SECURITY.md](SECURITY.md) — private disclosure to hello@lockyard.dev
- [docs/threat-model.md](docs/threat-model.md) — what the lock does and does not stop
- [docs/privacy.md](docs/privacy.md) — local mode sends nothing; cloud data inventory; no telemetry
- [docs/json-schemas.md](docs/json-schemas.md) — stable `--json` shapes

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
