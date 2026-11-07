// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

mod agent;
mod context;
mod guard;
mod hook;
mod mcp;
#[cfg(unix)]
mod node_cli;
mod onboarding;
mod open;
mod workflow;

use clap::{Args, Parser, Subcommand};
use lockyard_core::bus::BROADCAST;
use lockyard_core::proto::{
    AccessAnswer, AccessRequest, ActivityRequest, BoardEntry, BoardWrite, CheckStatus, Claim,
    ClaimMode, ClaimQuery, ClaimRequest, DirtyPath, EventQuery, Freeze, InboxPage, InboxQuery,
    Message, PresenceBeat, Purpose, QueueRequest, ReleaseRequest, RenewRequest, SendRequest,
    SessionActivity, SessionState, Stamp, Stream, TokenRequest, WorkAction, WorkOffer, WorkStep,
    WorkTask, expand_zones, rfc3339,
};
use lockyard_core::tasks::{Status, Task, TaskPlan, TaskSpec};
use lockyard_core::zones::DEFAULT_TTL_MINUTES;
use lockyard_core::{Backend, Error, Result, Store};
use open::Opened;
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A path is held by another agent.
const EXIT_CONFLICT: u8 = 3;
const EXIT_FAILURE: u8 = 1;
/// A check could not learn the state of a path in time.
const EXIT_UNKNOWN: u8 = 4;
/// Messages `lockyard msg inbox` prints at most.
const INBOX_LIMIT: usize = 200;
/// The server keeps a place in line for this long.
const MAX_SHORT_WAIT_SECONDS: u64 = 120;
const WAIT_RETRY: Duration = Duration::from_secs(2);
/// One try of a short wait. Longer than this, the answer could outlast the read limit of a long poll.
const WAIT_SLICE_SECONDS: u64 = 25;
const DEFAULT_TOKEN_DAYS: i64 = 90;
const DAY_MS: i64 = 86_400_000;
/// Lease of a queued claim unless the caller asks for another one.
const DEFAULT_QUEUE_MINUTES: i64 = 60;

#[derive(Parser)]
#[command(name = "lockyard", version, about = lockyard_core::SUMMARY)]
struct Cli {
    /// Name of this agent. Defaults to LOCKYARD_AGENT, then CLAUDE_CODE_SESSION_ID.
    #[arg(long, global = true)]
    agent: Option<String>,
    /// Print JSON instead of text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a project in the current folder.
    Init,
    /// Show the version and the homepage.
    About,
    /// List the agents seen in this project.
    Who,
    /// Show this agent's mail count, all active claims and unfinished tasks.
    Status,
    /// Show local machine pressure. Works outside a project.
    Machine,
    /// Run a command through the local heavy-work gate.
    Run(RunArgs),
    /// Claim paths so that no other agent edits them.
    #[command(subcommand)]
    Zone(ZoneCommand),
    /// Talk to other agents.
    #[command(subcommand)]
    Msg(MsgCommand),
    /// Work that outlives a session.
    #[command(subcommand)]
    Task(TaskCommand),
    /// Task offers between agents. Needs cloud mode.
    #[command(subcommand)]
    Work(WorkCommand),
    /// Short shared values.
    #[command(subcommand)]
    Board(BoardCommand),
    /// Read the event streams. Needs cloud mode.
    Events(EventsArgs),
    /// Live sessions.
    #[command(subcommand)]
    Presence(PresenceCommand),
    /// The background process of cloud mode. Without a subcommand it runs in the foreground.
    Agent(AgentArgs),
    /// Administration of the cloud workspace.
    #[command(subcommand)]
    Cloud(CloudCommand),
    /// Agent integrations.
    #[command(subcommand)]
    Hook(HookCommand),
    /// Print setup snippets for agent tools.
    Setup {
        client: SetupClient,
        #[arg(long, conflicts_with_all=["check", "remove", "preview"])]
        apply: bool,
        #[arg(long, conflicts_with_all=["apply", "remove", "preview"])]
        check: bool,
        #[arg(long, conflicts_with_all=["apply", "check", "preview"])]
        remove: bool,
        #[arg(long, conflicts_with_all=["apply", "check", "remove"])]
        preview: bool,
    },
    /// Check effective integration and project readiness without changing configuration.
    Doctor {
        #[arg(long)]
        client: Option<String>,
        #[arg(long)]
        smoke: bool,
    },
    /// Read a bounded briefing without marking mail read or renewing leases.
    Context {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 8192)]
        max_bytes: usize,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Execute or inspect explicit resumable coordination steps.
    #[command(subcommand)]
    Workflow(WorkflowCommand),
    /// Manage a remote orchestration node.
    #[cfg(unix)]
    #[command(subcommand)]
    Node(node_cli::NodeCommand),
    /// Submit and inspect remote jobs.
    #[cfg(unix)]
    #[command(subcommand)]
    Job(node_cli::JobCommand),
    /// Run the MCP server over standard input and output.
    Mcp,
}

#[derive(Subcommand)]
enum WorkflowCommand {
    /// Execute a JSON plan. Completed steps are not repeated; uncertain writes require reconciliation.
    Run {
        /// Stable operation identifier, retained for retries.
        id: String,
        /// JSON plan file, or - to read stdin. Paths in plans are project-relative.
        #[arg(long)]
        plan: PathBuf,
    },
    /// Inspect receipts without performing writes or retrying steps.
    Inspect { id: String },
}

#[derive(Args)]
struct RunArgs {
    /// Acquire a machine slot and wait while the machine is under pressure.
    #[arg(long)]
    heavy: bool,
    /// Stop waiting after this many seconds (default: 1800).
    #[arg(long, default_value_t = 1800)]
    max_wait: u64,
    /// Command and arguments, after `--`.
    #[arg(last = true, required = true)]
    command: Vec<std::ffi::OsString>,
}

#[derive(clap::ValueEnum, Clone)]
enum SetupClient {
    Claude,
    Codex,
    Cursor,
}

#[derive(Args)]
struct Ttl {
    /// Lease in minutes.
    #[arg(long, default_value_t = DEFAULT_TTL_MINUTES)]
    ttl: i64,
}

#[derive(Args)]
struct ClaimStyle {
    /// Share the paths with other shared claims.
    #[arg(long)]
    shared: bool,
    /// Claim for a deploy rather than for work.
    #[arg(long)]
    deploy: bool,
    /// A named zone or group of the catalog. Repeat for several.
    #[arg(long = "zone")]
    zones: Vec<String>,
}

impl ClaimStyle {
    fn mode(&self) -> ClaimMode {
        if self.shared {
            ClaimMode::Shared
        } else {
            ClaimMode::Exclusive
        }
    }

    fn purpose(&self) -> Purpose {
        if self.deploy {
            Purpose::Deploy
        } else {
            Purpose::Work
        }
    }
}

#[derive(Subcommand)]
enum ZoneCommand {
    /// Claim paths, all of them or none.
    Claim {
        paths: Vec<String>,
        /// What the claim is for.
        #[arg(long, default_value = "")]
        note: String,
        #[command(flatten)]
        ttl: Ttl,
        /// Start empty and grow through add-path.
        #[arg(long)]
        lazy: bool,
        #[command(flatten)]
        style: ClaimStyle,
        /// A JSON object stored with the claim.
        #[arg(long, value_parser = parse_json)]
        meta: Option<Value>,
    },
    /// Claim paths, holding a place in line for a short time.
    Wait {
        paths: Vec<String>,
        #[arg(long, default_value = "")]
        note: String,
        #[command(flatten)]
        ttl: Ttl,
        /// How long to wait, at most 120.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[command(flatten)]
        style: ClaimStyle,
    },
    /// Join the long queue for paths. Without paths, list this agent's entries.
    Queue {
        paths: Vec<String>,
        #[arg(long, default_value = "")]
        note: String,
        /// Minutes the entry stays in line, 1 to 480.
        #[arg(long, default_value_t = DEFAULT_QUEUE_MINUTES)]
        ttl: i64,
        #[command(flatten)]
        style: ClaimStyle,
    },
    /// Leave the queue.
    Unwait {
        #[arg(value_parser = parse_id)]
        id: i64,
    },
    /// Ask the holder of paths for them.
    Request {
        #[arg(required = true)]
        paths: Vec<String>,
        #[arg(long)]
        text: String,
        #[arg(long)]
        urgent: bool,
        #[arg(long)]
        need_by: Option<String>,
    },
    /// List unexpired requests sent by or addressed to this agent.
    Requests,
    /// Answer a request.
    Answer {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long)]
        reply: Option<String>,
        #[arg(long)]
        eta: Option<String>,
    },
    /// Offer a claim to another agent.
    Handover {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long)]
        to: String,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// Accept a claim offered to this agent.
    Accept {
        #[arg(value_parser = parse_id)]
        id: i64,
    },
    /// Shrink a claim to some of its paths.
    Narrow {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(required = true)]
        paths: Vec<String>,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// Add one path to a claim.
    AddPath {
        #[arg(value_parser = parse_id)]
        id: i64,
        path: String,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// Take the claim of an unresponsive session. Needs the lead role and a reason.
    Takeover {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long)]
        reason: String,
    },
    /// Uncommitted paths and who owns them.
    #[command(subcommand)]
    Dirty(DirtyCommand),
    /// Report tool activity on a claim.
    Activity {
        #[arg(value_parser = parse_id)]
        id: i64,
        paths: Vec<String>,
        /// The activity wrote to files.
        #[arg(long)]
        write: bool,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// List claims this agent lost.
    Lost,
    /// Show the zone catalog.
    Catalog,
    /// Extend one claim, or all of this agent's claims.
    Renew {
        #[arg(value_parser = parse_id)]
        id: Option<i64>,
        #[command(flatten)]
        ttl: Ttl,
        /// Why the claim stays held while idle.
        #[arg(long)]
        hold_reason: Option<String>,
        #[arg(long)]
        hold_until: Option<String>,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// Release one claim, or all of this agent's claims.
    Release {
        #[arg(value_parser = parse_id)]
        id: Option<i64>,
        #[arg(long)]
        note: Option<String>,
        /// Uncommitted changes stay behind on purpose.
        #[arg(long)]
        leave_dirty: bool,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// List active claims.
    List {
        /// Only this agent's claims.
        #[arg(long)]
        session: Option<String>,
        /// Only claims that touch this path.
        #[arg(long)]
        path: Option<String>,
    },
    /// Exit 3 if another agent holds this path, 4 if that cannot be learned in time.
    Check { path: String },
}

#[derive(Subcommand)]
enum DirtyCommand {
    /// Report paths with uncommitted changes.
    Report {
        #[arg(required = true)]
        paths: Vec<String>,
        /// The session that owns the changes.
        #[arg(long)]
        owner: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, value_parser = parse_id)]
        task: Option<i64>,
    },
    /// List reported paths.
    List { path: Option<String> },
    /// Say these paths are not this agent's.
    Disown {
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Take over paths that have no live owner.
    Adopt {
        #[arg(required = true)]
        paths: Vec<String>,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand)]
enum MsgCommand {
    /// Send to an agent, or to `*` for everyone.
    Send {
        to: String,
        body: String,
        /// ask, notice or event.
        #[arg(long)]
        kind: Option<String>,
        /// none, reply or ack.
        #[arg(long)]
        needs: Option<String>,
        #[arg(long)]
        zone: Option<String>,
        #[arg(long)]
        re: Option<String>,
        /// Repeating this key repeats the same message.
        #[arg(long)]
        key: Option<String>,
        /// Minutes a notice stays, 30 to 1440.
        #[arg(long)]
        ttl: Option<i64>,
    },
    /// Answer a message.
    Reply {
        #[arg(value_parser = parse_id)]
        id: i64,
        body: String,
    },
    /// Show unread mail and mark it read once it is printed.
    Inbox {
        /// Include mail already read.
        #[arg(long)]
        all: bool,
        /// Do not mark anything read.
        #[arg(long)]
        peek: bool,
    },
    /// Show the count of unread mail.
    Unread,
    /// Confirm a message that needs an ack.
    Ack {
        #[arg(value_parser = parse_id)]
        id: i64,
    },
    /// Show a whole thread.
    Thread {
        #[arg(value_parser = parse_id)]
        id: i64,
    },
    /// List sent messages still waiting for an ack.
    Overdue,
    /// List unseen mail across sessions. Needs the lead or dispatcher role.
    Undelivered {
        /// Only mail older than this.
        #[arg(long, default_value_t = 0)]
        older_than: i64,
    },
}

#[derive(Subcommand)]
enum TaskCommand {
    /// Cloud registry items that are actionable, with raw states and dependency links.
    Ready {
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        area: Option<String>,
        #[arg(long = "type")]
        kind: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u16,
    },
    /// Search cloud registry metadata. Encrypted content is not searched by the server.
    Search {
        query: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        area: Option<String>,
        #[arg(long = "type")]
        kind: Option<String>,
        #[arg(long)]
        priority: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u16,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Explain dependency and scheduling blockers using the server's visibility rules.
    WhyBlocked {
        #[arg(value_parser=parse_id)]
        id: i64,
    },
    /// Show full cloud registry dependency links, without reducing statuses.
    Links {
        #[arg(value_parser=parse_id)]
        id: i64,
    },
    /// Add a typed dependency link at an explicitly observed version.
    Link {
        #[arg(value_parser=parse_id)]
        id: i64,
        #[arg(value_parser=parse_id)]
        to: i64,
        #[arg(long, default_value = "blocks")]
        kind: String,
        #[arg(long)]
        if_version: i64,
        /// ULID retained across retries. Generated if omitted and printed in the result.
        #[arg(long)]
        key: Option<String>,
    },
    /// Add an open task.
    Add {
        title: String,
        #[arg(long, default_value = "")]
        body: String,
        /// What closes the task. Cloud mode; the title by default.
        #[arg(long)]
        acceptance: Option<String>,
        /// P0, P1, P2 or P3. Cloud mode; P2 by default.
        #[arg(long)]
        priority: Option<String>,
        /// Required with P0: player_money, security_breach, prod_outage or cert_slip.
        #[arg(long)]
        p0_category: Option<String>,
        /// Item type, such as code, ops or finding. Cloud mode.
        #[arg(long = "type")]
        kind: Option<String>,
        /// What done means, such as code_accepted or ci_passed. Cloud mode.
        #[arg(long)]
        target: Option<String>,
        /// auto, owner or none. Cloud mode.
        #[arg(long)]
        verification: Option<String>,
        /// Key of the area. Cloud mode; the first area by default.
        #[arg(long)]
        area: Option<String>,
        /// Due date as RFC 3339 text. Cloud mode.
        #[arg(long)]
        due: Option<String>,
        /// Evidence stored at once. P0 needs it. Cloud mode.
        #[arg(long)]
        evidence: Option<String>,
    },
    /// Change the urgency of a task. Needs cloud mode.
    Plan {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long)]
        priority: Option<String>,
        #[arg(long)]
        p0_category: Option<String>,
        #[arg(long)]
        due: Option<String>,
    },
    /// List unfinished tasks.
    List {
        /// Include accepted and cancelled tasks.
        #[arg(long)]
        all: bool,
        /// Only this status: open, claimed, review, accepted or cancelled.
        #[arg(long, value_parser = parse_status)]
        status: Option<Status>,
    },
    /// Show a task and its history.
    Show {
        #[arg(value_parser = parse_id)]
        id: i64,
    },
    /// Take a task.
    Claim {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[command(flatten)]
        ttl: Ttl,
    },
    /// Extend the lease on a held task.
    Renew {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[command(flatten)]
        ttl: Ttl,
    },
    /// Give a held task back.
    Release {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Hand a held task to review.
    Submit {
        #[arg(value_parser = parse_id)]
        id: i64,
        /// What proves the work is done.
        #[arg(long)]
        evidence: String,
    },
    /// Accept another agent's submitted work.
    Accept {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Return submitted work to its assignee.
    Reject {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long)]
        reason: String,
    },
    /// Cancel a task you wrote.
    Cancel {
        #[arg(value_parser = parse_id)]
        id: i64,
        #[arg(long, default_value = "")]
        note: String,
    },
}

#[derive(Args)]
struct WorkRef {
    #[arg(value_parser = parse_id)]
    id: i64,
    /// Act only if the task is still at this version.
    #[arg(long)]
    if_version: Option<i64>,
}

#[derive(Subcommand)]
enum WorkCommand {
    /// Offer a task to an agent, or to `*`.
    Offer {
        title: String,
        #[arg(long)]
        to: String,
        /// What counts as done.
        #[arg(long)]
        accept: String,
        #[arg(long)]
        brief: Option<String>,
        #[arg(long)]
        re: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    /// List work tasks.
    List,
    /// Show one work task.
    Show {
        #[arg(value_parser = parse_id)]
        id: i64,
    },
    /// Take an offered task.
    Claim(WorkRef),
    /// Renew the lease on a held task.
    Beat(WorkRef),
    /// Send a held task to review.
    Done {
        #[command(flatten)]
        task: WorkRef,
        #[arg(long)]
        report: Option<String>,
        /// A commit of this work. Repeat for several.
        #[arg(long = "commit")]
        commits: Vec<String>,
    },
    /// Accept reviewed work.
    Accept(WorkRef),
    /// Return reviewed work to its assignee.
    Reject {
        #[command(flatten)]
        task: WorkRef,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Give up on a held task.
    Fail {
        #[command(flatten)]
        task: WorkRef,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Cancel a task that is not final.
    Cancel {
        #[command(flatten)]
        task: WorkRef,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Offer a held task to another agent.
    Handoff {
        #[command(flatten)]
        task: WorkRef,
        #[arg(long)]
        to: String,
        /// Context, checks, risks and next steps for the receiving agent.
        #[arg(long)]
        report: Option<String>,
        /// A commit relevant to this handoff. Repeat for several.
        #[arg(long = "commit")]
        commits: Vec<String>,
    },
    /// Take a task handed to this agent. Needs the version.
    Take {
        #[arg(value_parser = parse_id)]
        id: i64,
        /// The version seen in `work show`.
        #[arg(long)]
        if_version: i64,
    },
    /// Refuse an offered task.
    Decline {
        #[command(flatten)]
        task: WorkRef,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand)]
enum BoardCommand {
    /// Set a value.
    Set {
        key: String,
        value: String,
        #[arg(long)]
        zone: Option<String>,
        /// Minutes the value stays.
        #[arg(long)]
        ttl: Option<i64>,
    },
    /// Show one value.
    Get { key: String },
    /// Remove a value.
    Rm { key: String },
    /// List values.
    List {
        #[arg(long)]
        zone: Option<String>,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum StreamName {
    Coordination,
    Registry,
}

#[derive(Args)]
struct EventsArgs {
    /// Show events after this sequence.
    #[arg(long, default_value_t = 0)]
    after: i64,
    /// Wait for news, at most 25 seconds.
    #[arg(long, default_value_t = 0)]
    wait: u64,
    #[arg(long, value_enum, default_value = "coordination")]
    stream: StreamName,
    /// Only these types. Repeat for several.
    #[arg(long = "type")]
    types: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum StateName {
    Working,
    Idle,
    Ended,
    ApiFailure,
}

#[derive(Subcommand)]
enum PresenceCommand {
    /// List sessions active lately.
    List {
        /// Seconds of silence that still count as active.
        #[arg(long, default_value_t = 900)]
        active_within: i64,
    },
    /// Send one heartbeat.
    Beat {
        #[arg(long, default_value = "cli")]
        client: String,
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        /// Do not disturb until this time.
        #[arg(long)]
        dnd_until: Option<i64>,
        /// Report that a tool is running.
        #[arg(long)]
        tool_running: bool,
        #[arg(long, value_enum)]
        state: Option<StateName>,
        /// A JSON object stored with the session.
        #[arg(long, value_parser = parse_json)]
        meta: Option<Value>,
    },
}

#[derive(Args)]
struct AgentArgs {
    #[command(subcommand)]
    command: Option<AgentCommand>,
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Install a launchd or systemd user unit and start it. Needs LOCKYARD_TOKEN_FILE.
    Install {
        /// Write the unit without starting it.
        #[arg(long)]
        no_start: bool,
    },
    /// Stop the unit and remove it.
    Uninstall {
        /// Remove the unit without stopping it.
        #[arg(long)]
        no_start: bool,
    },
    /// Show whether the process runs and how fresh its view is.
    Status,
}

#[derive(Subcommand)]
enum CloudCommand {
    /// Trust a server URL before sending a user token to it.
    Trust { url: String },
    /// Dump coordination state. Needs the owner or exporter role.
    Export,
    /// Freeze or unfreeze coordination writes. Needs the owner role.
    Freeze {
        #[arg(value_parser = parse_switch, action = clap::ArgAction::Set)]
        state: bool,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Store the zone catalog from a JSON file. Needs the importer role.
    ImportZones { file: PathBuf },
    /// Import threads, the board and tasks from a JSON file. Needs the importer role.
    ImportBus { file: PathBuf },
    /// Import registry items. Needs the importer role.
    ImportRegistry { file: PathBuf },
    /// Service tokens of the workspace. Needs the owner role.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Manage this client's local workspace encryption key.
    #[command(subcommand)]
    Key(KeyCommand),
    /// View or change workspace content encryption. Changes need the owner role.
    #[command(subcommand)]
    Encryption(EncryptionCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate and store a workspace key locally.
    Create,
    /// Show the recovery phrase after typing SHOW.
    ShowPhrase,
    /// Read a 24 word recovery phrase from stdin and store its key.
    Import,
}

#[derive(Subcommand)]
enum EncryptionCommand {
    /// Show encryption mode and whether this machine has the matching key.
    Status,
    /// Require client-side content encryption. Needs the owner role and a local key.
    Require,
    /// Turn off the workspace encryption requirement. Needs the owner role.
    Off,
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a token. The raw token prints once and cannot be read again.
    Create {
        name: String,
        /// agent, lead, owner, exporter, importer or dispatcher.
        #[arg(long)]
        role: String,
        /// Days until it expires, at most 366.
        #[arg(long, default_value_t = DEFAULT_TOKEN_DAYS)]
        days: i64,
    },
    /// List tokens, never their raw value.
    List,
    /// Revoke a token.
    Revoke { id: String },
}

#[derive(Subcommand)]
enum HookCommand {
    /// Handle a Claude Code hook event from stdin.
    Claude,
    /// Handle a Codex hook event from stdin.
    Codex,
    /// Handle a Cursor hook event from stdin.
    Cursor,
}

/// Accepts `12`, `T-12`, `D-12`, `Z-12`, `M-12`, `W-12` and `Q-12`.
fn parse_id(text: &str) -> std::result::Result<i64, String> {
    let digits = text
        .strip_prefix(['T', 'D', 'Z', 'M', 'W', 'Q', 't', 'd', 'z', 'm', 'w', 'q'])
        .and_then(|rest| rest.strip_prefix('-'))
        .unwrap_or(text);
    digits
        .parse()
        .map_err(|_| format!("{text:?} is not an id, expected a number such as 12 or T-12"))
}

fn parse_status(text: &str) -> std::result::Result<Status, String> {
    Status::parse(text).ok_or_else(|| {
        format!("{text:?} is not a status: use open, claimed, review, accepted or cancelled")
    })
}

fn parse_json(text: &str) -> std::result::Result<Value, String> {
    serde_json::from_str(text).map_err(|error| format!("not JSON: {error}"))
}

fn parse_switch(text: &str) -> std::result::Result<bool, String> {
    match text {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("{text:?} is not on or off")),
    }
}

pub(crate) fn now_ms() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
}

pub(crate) fn env_agent() -> Option<String> {
    ["LOCKYARD_AGENT", "CLAUDE_CODE_SESSION_ID"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

fn resolve_agent(flag: Option<&String>) -> Result<String> {
    flag.cloned().or_else(env_agent).ok_or_else(|| {
        Error::Invalid(
            "this command needs an agent name: set LOCKYARD_AGENT or pass --agent".into(),
        )
    })
}

/// Work to do once a command's output is out, such as marking printed mail.
pub(crate) type After = Box<dyn FnOnce() -> Result<()>>;

/// Output of one command: the data for `--json` and the lines for a person.
struct Output {
    json: Value,
    text: String,
    after: Option<After>,
    exit: u8,
}

fn output(data: &impl Serialize, text: impl Into<String>) -> Result<Output> {
    let json = serde_json::to_value(data)
        .map_err(|error| Error::Invalid(format!("cannot encode output: {error}")))?;
    Ok(Output {
        json,
        text: text.into(),
        after: None,
        exit: 0,
    })
}

fn minutes_left(expires_at: i64, now: i64) -> i64 {
    ((expires_at - now).max(0) + 59_999) / 60_000
}

/// Local leases count down on the local clock. A cloud lease is shown as the server stated it.
fn claim_line(claim: &Claim, clock: Option<i64>) -> String {
    let left = match (&claim.expires_at, clock) {
        (Stamp::Millis(expires_at), Some(now)) => {
            format!("{} min left", minutes_left(*expires_at, now))
        }
        (stamp, _) => format!("until {stamp}"),
    };
    let mut line = format!(
        "Z-{}  {}  {}  {left}",
        claim.id,
        claim.session,
        claim.paths.join(" ")
    );
    if !claim.note.is_empty() {
        line.push_str("  ");
        line.push_str(&claim.note);
    }
    for dirty in &claim.foreign_dirty_paths {
        let path = serde_json::to_string(&dirty.path).unwrap_or_else(|_| "\"?\"".into());
        let owner = dirty
            .owner_session
            .as_deref()
            .map(|owner| serde_json::to_string(owner).unwrap_or_else(|_| "\"?\"".into()))
            .unwrap_or_else(|| "unknown owner".into());
        line.push_str(&format!(
            "\nForeign uncommitted work: {path} (owner: {owner})"
        ));
    }
    line
}

fn message_line(message: &Message) -> String {
    let scope = if message.to == BROADCAST {
        " to all"
    } else {
        ""
    };
    format!(
        "M-{}  {}{}: {}",
        message.id,
        message.from,
        scope,
        escape_controls(&message.body)
    )
}

fn escape_controls(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            ch if ch.is_control() => format!("\\u{{{:x}}}", ch as u32),
            ch => ch.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod output_escape_tests {
    #[test]
    fn preserves_cyrillic_and_emoji() {
        assert_eq!(
            super::escape_controls("Почта 😀\nready"),
            "Почта 😀\\nready"
        );
    }
}

fn sent_line(message: &Message) -> String {
    match (message.queued, message.deduplicated) {
        (true, _) => "queued: the server is out of reach, the agent will send it".to_string(),
        (_, true) => format!("already sent as M-{}", message.id),
        _ => format!("sent M-{}", message.id),
    }
}

fn task_line(task: &Task) -> String {
    let assignee = task.assignee.as_deref().unwrap_or("-");
    format!(
        "T-{}  {}  {}  {}",
        task.id,
        task.raw_status.as_deref().unwrap_or(task.status.as_str()),
        assignee,
        task.title
    )
}

fn work_line(task: &WorkTask) -> String {
    let status = serde_json::to_value(task.status).ok();
    let status = status.as_ref().and_then(Value::as_str).unwrap_or_default();
    let assignee = task
        .assignee
        .as_deref()
        .or(task.to.as_deref())
        .unwrap_or("-");
    format!(
        "W-{}  {status}  {assignee}  v{}  {}",
        task.id, task.version, task.title
    )
}

fn board_line(entry: &BoardEntry) -> String {
    format!("{} = {}", entry.key, entry.text())
}

fn join<T>(items: &[T], line: impl Fn(&T) -> String, empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.iter().map(line).collect::<Vec<_>>().join("\n")
}

/// The clock to count local leases on. Cloud leases are not counted at all.
fn clock(opened: &Opened) -> Option<i64> {
    (!opened.backend.is_cloud()).then(now_ms)
}

/// Paths named on the command line plus those of named zones. The server knows paths only.
fn with_zones(
    opened: &Opened,
    cwd: &Path,
    raw: &[String],
    zones: &[String],
) -> Result<Vec<String>> {
    let mut paths = opened.zone_paths(cwd, raw)?;
    if !zones.is_empty() {
        for path in expand_zones(&opened.backend.catalog()?, zones)? {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

fn zone_label(zones: &[String]) -> Option<String> {
    match zones {
        [one] => Some(one.clone()),
        _ => None,
    }
}

fn claim_request(paths: Vec<String>, note: String, ttl: i64, style: &ClaimStyle) -> ClaimRequest {
    ClaimRequest {
        paths,
        note,
        ttl_minutes: ttl,
        mode: style.mode(),
        purpose: style.purpose(),
        zone: zone_label(&style.zones),
        zones: if style.zones.len() > 1 {
            style.zones.clone()
        } else {
            Vec::new()
        },
        ..ClaimRequest::default()
    }
}

/// Keeps asking for a claim until it is granted or the wait ends. Each try is its own write, because a
/// repeat under one key would only repeat the first refusal.
pub(crate) fn wait_for_claim(
    backend: &mut dyn Backend,
    agent: &str,
    mut request: ClaimRequest,
    seconds: u64,
) -> Result<Claim> {
    if seconds > MAX_SHORT_WAIT_SECONDS {
        return Err(Error::Invalid(format!(
            "a short wait is at most {MAX_SHORT_WAIT_SECONDS} seconds, use zone queue"
        )));
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let slice = left.as_secs().min(WAIT_SLICE_SECONDS);
        request.queue_wait_seconds = Some(i64::try_from(slice).unwrap_or(0));
        match backend.claim(agent, &request, now_ms()) {
            Err(Error::Conflict(_) | Error::Contended(_)) if !left.is_zero() => {
                std::thread::sleep(WAIT_RETRY.min(left));
            }
            other => return other,
        }
    }
}

fn run_zone(
    mut opened: Opened,
    command: ZoneCommand,
    agent: Option<&String>,
    cwd: &Path,
) -> Result<Output> {
    let now = now_ms();
    let lease = clock(&opened);
    match command {
        ZoneCommand::Claim {
            paths,
            note,
            ttl,
            lazy,
            style,
            meta,
        } => {
            let agent = resolve_agent(agent)?;
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let mut request = claim_request(paths, note, ttl.ttl, &style);
            request.lazy = lazy;
            request.meta = meta;
            let claim = opened.backend.claim(&agent, &request, now)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Wait {
            paths,
            note,
            ttl,
            seconds,
            style,
        } => {
            let agent = resolve_agent(agent)?;
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let request = claim_request(paths, note, ttl.ttl, &style);
            let claim = wait_for_claim(opened.backend.as_mut(), &agent, request, seconds)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Queue {
            paths,
            note,
            ttl,
            style,
        } => {
            let agent = resolve_agent(agent)?;
            if paths.is_empty() && style.zones.is_empty() {
                let entries = opened.backend.queue_list(&agent)?;
                let line = |entry: &lockyard_core::proto::QueueEntry| {
                    format!("Q-{}  {}", entry.id, entry.paths.join(" "))
                };
                let text = join(&entries, line, "nothing queued");
                return output(&entries, text);
            }
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let request = QueueRequest {
                paths,
                note,
                ttl_minutes: ttl,
                mode: style.mode(),
                purpose: style.purpose(),
                zones: style.zones.clone(),
            };
            let entry = opened.backend.queue_add(&agent, &request)?;
            let verb = if entry.granted { "granted" } else { "queued" };
            output(&entry, format!("{verb} Q-{}", entry.id))
        }
        ZoneCommand::Unwait { id } => {
            opened.backend.queue_cancel(&resolve_agent(agent)?, id)?;
            output(&json!({"cancelled": id}), format!("left the queue: Q-{id}"))
        }
        ZoneCommand::Request {
            paths,
            text,
            urgent,
            need_by,
        } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            let request = AccessRequest {
                paths,
                text,
                urgent,
                need_by,
            };
            let record = opened
                .backend
                .zone_request(&resolve_agent(agent)?, &request)?;
            output(&record, format!("requested as R-{}", record.id))
        }
        ZoneCommand::Requests => {
            let records = opened.backend.zone_requests(&resolve_agent(agent)?)?;
            output(&records, format!("{} active requests", records.len()))
        }
        ZoneCommand::Answer { id, reply, eta } => {
            let record = opened.backend.zone_answer(
                &resolve_agent(agent)?,
                id,
                &AccessAnswer { reply, eta },
            )?;
            output(&record, format!("answered R-{}", record.id))
        }
        ZoneCommand::Handover { id, to, fence } => {
            let record = opened
                .backend
                .handover(&resolve_agent(agent)?, id, &to, fence)?;
            output(&record, format!("Z-{id} offered to {to}"))
        }
        ZoneCommand::Accept { id } => {
            let claim = opened.backend.handover_accept(&resolve_agent(agent)?, id)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Narrow { id, paths, fence } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            let claim = opened
                .backend
                .narrow(&resolve_agent(agent)?, id, &paths, fence)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::AddPath { id, path, fence } => {
            let path = opened.zone_path(cwd, &path)?;
            let claim = opened
                .backend
                .add_path(&resolve_agent(agent)?, id, &path, fence)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Takeover { id, reason } => {
            let claim = opened
                .backend
                .takeover(&resolve_agent(agent)?, id, &reason)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Dirty(command) => run_dirty(opened, command, agent, cwd),
        ZoneCommand::Activity {
            id,
            paths,
            write,
            fence,
        } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            let request = ActivityRequest {
                write,
                paths,
                fence,
            };
            opened
                .backend
                .activity(&resolve_agent(agent)?, id, &request)?;
            output(&json!({"reported": id}), format!("reported Z-{id}"))
        }
        ZoneCommand::Lost => {
            let lost = opened.backend.lost(&resolve_agent(agent)?)?;
            let line = |claim: &lockyard_core::proto::LostClaim| {
                format!("Z-{}  {}", claim.claim_id, claim.paths.join(" "))
            };
            let text = join(&lost, line, "no lost claims");
            output(&lost, text)
        }
        ZoneCommand::Catalog => {
            let catalog = opened.backend.catalog()?;
            let text = catalog.to_string();
            output(&catalog, text)
        }
        ZoneCommand::Renew {
            id,
            ttl,
            hold_reason,
            hold_until,
            fence,
        } => {
            let agent = resolve_agent(agent)?;
            let request = RenewRequest {
                ttl_minutes: ttl.ttl,
                hold_reason,
                hold_until,
                fence,
            };
            let renewed = opened.backend.renew(&agent, id, &request, now)?;
            output(&json!({ "renewed": renewed }), format!("renewed {renewed}"))
        }
        ZoneCommand::Release {
            id,
            note,
            leave_dirty,
            fence,
        } => {
            let agent = resolve_agent(agent)?;
            let request = ReleaseRequest {
                note,
                leave_dirty,
                fence,
            };
            let released = opened.backend.release(&agent, id, &request, now)?;
            output(
                &json!({ "released": released }),
                format!("released {released}"),
            )
        }
        ZoneCommand::List { session, path } => {
            let path = path.map(|raw| opened.zone_path(cwd, &raw)).transpose()?;
            let claims = opened.backend.claims(&ClaimQuery { session, path }, now)?;
            let text = join(
                &claims,
                |claim| claim_line(claim, lease),
                "no active claims",
            );
            output(&claims, text)
        }
        ZoneCommand::Check { path } => {
            let agent = resolve_agent(agent)?;
            let path = opened.zone_path(cwd, &path)?;
            let mut checks =
                opened
                    .backend
                    .check(&agent, std::slice::from_ref(&path), None, now)?;
            let found = (!checks.is_empty()).then(|| checks.remove(0));
            match found {
                None => output(&json!({ "free": true }), "free"),
                Some(check) => match check.status {
                    CheckStatus::Held => match check.holder {
                        Some(holder) => Err(Error::Conflict(vec![holder])),
                        None => Err(Error::Contended(format!("{path} is held"))),
                    },
                    CheckStatus::Own => output(&json!({ "free": true, "own": true }), "own"),
                    CheckStatus::Free => output(&json!({ "free": true }), "free"),
                    CheckStatus::Unknown => {
                        let mut out = output(&json!({ "unknown": true }), "unknown")?;
                        out.exit = EXIT_UNKNOWN;
                        Ok(out)
                    }
                },
            }
        }
    }
}

fn run_dirty(
    mut opened: Opened,
    command: DirtyCommand,
    agent: Option<&String>,
    cwd: &Path,
) -> Result<Output> {
    let agent = resolve_agent(agent)?;
    match command {
        DirtyCommand::Report {
            paths,
            owner,
            reason,
            task,
        } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            let report: Vec<DirtyPath> = paths
                .into_iter()
                .map(|path| DirtyPath {
                    path,
                    owner_session: owner.clone(),
                    reason: reason.clone(),
                    task_id: task,
                })
                .collect();
            opened.backend.dirty_report(&agent, &report)?;
            output(&report, format!("reported {}", report.len()))
        }
        DirtyCommand::List { path } => {
            let path = path.map(|raw| opened.zone_path(cwd, &raw)).transpose()?;
            let list = opened.backend.dirty_list(&agent, path.as_deref())?;
            let line = |entry: &DirtyPath| {
                format!(
                    "{}  {}",
                    entry.path,
                    entry.owner_session.as_deref().unwrap_or("-")
                )
            };
            let text = join(&list, line, "nothing dirty");
            output(&list, text)
        }
        DirtyCommand::Disown { paths } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            opened.backend.dirty_disown(&agent, &paths)?;
            output(
                &json!({"disowned": paths}),
                format!("disowned {}", paths.len()),
            )
        }
        DirtyCommand::Adopt { paths, reason } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            opened.backend.dirty_adopt(&agent, &paths, &reason)?;
            output(
                &json!({"adopted": paths}),
                format!("adopted {}", paths.len()),
            )
        }
    }
}

fn inbox_text(page: &InboxPage) -> String {
    let mut text = join(&page.messages, message_line, "no new mail");
    if page.skipped > 0 {
        text.push_str(&format!("\n{} older messages skipped", page.skipped));
    }
    text
}

fn run_msg(opened: Opened, command: MsgCommand, agent: Option<&String>) -> Result<Output> {
    let now = now_ms();
    let agent = resolve_agent(agent)?;
    let mut backend = opened.backend;
    match command {
        MsgCommand::Send {
            to,
            body,
            kind,
            needs,
            zone,
            re,
            key,
            ttl,
        } => {
            let request = SendRequest {
                to,
                body,
                kind,
                needs,
                zone,
                re,
                key,
                ttl_minutes: ttl,
            };
            let message = backend.send(&agent, &request, now)?;
            output(&message, sent_line(&message))
        }
        MsgCommand::Reply { id, body } => {
            let message = backend.reply(&agent, id, &body, now)?;
            output(&message, sent_line(&message))
        }
        MsgCommand::Inbox { all, peek } => {
            let page = backend.inbox(
                &agent,
                InboxQuery {
                    all,
                    limit: INBOX_LIMIT,
                },
                now,
            )?;
            let text = inbox_text(&page);
            let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
            let mut out = output(&page.messages, text)?;
            if !peek && !ids.is_empty() {
                // Marked only after the mail is on screen: a duplicate over a loss.
                out.after = Some(Box::new(move || {
                    backend.inbox_seen(&agent, &ids, now_ms()).map(|_| ())
                }));
            }
            Ok(out)
        }
        MsgCommand::Unread => {
            let unread = backend.unread(&agent)?;
            output(&json!({"unread": unread}), format!("unread mail: {unread}"))
        }
        MsgCommand::Ack { id } => {
            backend.ack(&agent, id)?;
            output(&json!({"acked": id}), format!("acked M-{id}"))
        }
        MsgCommand::Thread { id } => {
            let messages = backend.thread(&agent, id)?;
            let text = join(&messages, message_line, "empty thread");
            output(&messages, text)
        }
        MsgCommand::Overdue => {
            let messages = backend.overdue(&agent)?;
            let text = join(&messages, message_line, "nothing overdue");
            output(&messages, text)
        }
        MsgCommand::Undelivered { older_than } => {
            let list = backend.undelivered(&agent, older_than)?;
            let line = |entry: &lockyard_core::proto::Undelivered| {
                format!(
                    "M-{}  to {}  {} s old",
                    entry.id, entry.to, entry.age_seconds
                )
            };
            let text = join(&list, line, "nothing undelivered");
            output(&list, text)
        }
    }
}

fn run_task(mut opened: Opened, command: TaskCommand, agent: Option<&String>) -> Result<Output> {
    let now = now_ms();
    let store = opened.backend.as_mut();
    let changed = match command {
        TaskCommand::Ready {
            actor,
            area,
            kind,
            limit,
        } => {
            let data = store
                .registry_ready(&json!({"actor":actor,"area":area,"type":kind,"limit":limit}))?;
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::Search {
            query,
            status,
            actor,
            area,
            kind,
            priority,
            limit,
            cursor,
        } => {
            let data = store.registry_search(&json!({"q":query,"status":status,"actor":actor,"area":area,"type":kind,"priority":priority,"limit":limit,"cursor":cursor}))?;
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::WhyBlocked { id } => {
            let data = store.registry_blockers(id)?;
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::Links { id } => {
            let item = store.registry_item(id)?;
            let data = json!({"id":item["id"],"status":item["status"],"version":item["version"],"links":item["links"]});
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::Link {
            id,
            to,
            kind,
            if_version,
            key,
        } => {
            let key = key.unwrap_or_else(lockyard_cloud_client::ulid);
            let item =
                store.registry_link(&resolve_agent(agent)?, id, to, &kind, if_version, &key)?;
            let data = json!({"idempotency_key":key,"item":item});
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::List { all, status } => {
            let tasks = store.tasks(status, all)?;
            let text = join(&tasks, task_line, "no tasks");
            return output(&tasks, text);
        }
        TaskCommand::Show { id } => {
            let task = store.task(id)?;
            let history = store.task_history(id)?;
            let mut lines = vec![task_line(&task)];
            if !task.body.is_empty() {
                lines.push(task.body.clone());
            }
            if let Some(evidence) = &task.evidence {
                lines.push(format!("evidence: {evidence}"));
            }
            lines.extend(history.iter().map(|event| {
                format!("{} {} {}", event.agent, event.action, event.note)
                    .trim_end()
                    .to_string()
            }));
            let data = json!({ "task": task, "history": history });
            return output(&data, lines.join("\n"));
        }
        TaskCommand::Add {
            title,
            body,
            acceptance,
            priority,
            p0_category,
            kind,
            target,
            verification,
            area,
            due,
            evidence,
        } => store.add_task(
            &resolve_agent(agent)?,
            &TaskSpec {
                title,
                body,
                acceptance,
                priority,
                p0_category,
                kind,
                target,
                verification,
                area,
                due_at: due,
                evidence,
            },
            now,
        )?,
        TaskCommand::Plan {
            id,
            priority,
            p0_category,
            due,
        } => store.plan_task(
            &resolve_agent(agent)?,
            id,
            &TaskPlan {
                priority,
                p0_category,
                due_at: due,
            },
        )?,
        TaskCommand::Claim { id, ttl } => {
            store.claim_task(&resolve_agent(agent)?, id, ttl.ttl, now)?
        }
        TaskCommand::Renew { id, ttl } => {
            store.renew_task(&resolve_agent(agent)?, id, ttl.ttl, now)?
        }
        TaskCommand::Release { id, note } => {
            store.release_task(&resolve_agent(agent)?, id, &note, now)?
        }
        TaskCommand::Submit { id, evidence } => {
            store.submit_task(&resolve_agent(agent)?, id, &evidence, now)?
        }
        TaskCommand::Accept { id, note } => {
            store.accept_task(&resolve_agent(agent)?, id, &note, now)?
        }
        TaskCommand::Reject { id, reason } => {
            store.reject_task(&resolve_agent(agent)?, id, &reason, now)?
        }
        TaskCommand::Cancel { id, note } => {
            store.cancel_task(&resolve_agent(agent)?, id, &note, now)?
        }
    };
    output(&changed, task_line(&changed))
}

fn work_step(reference: &WorkRef) -> WorkStep {
    WorkStep {
        version: reference.if_version,
        ..WorkStep::default()
    }
}

fn run_work(mut opened: Opened, command: WorkCommand, agent: Option<&String>) -> Result<Output> {
    let agent = resolve_agent(agent)?;
    let backend = opened.backend.as_mut();
    let (id, action, step) = match command {
        WorkCommand::Offer {
            title,
            to,
            accept,
            brief,
            re,
            zone,
        } => {
            let task = backend.work_offer(
                &agent,
                &WorkOffer {
                    title,
                    to,
                    accept,
                    re,
                    zone,
                    brief,
                },
            )?;
            return output(&task, work_line(&task));
        }
        WorkCommand::List => {
            let tasks = backend.work_list(&agent)?;
            let text = join(&tasks, work_line, "no work tasks");
            return output(&tasks, text);
        }
        WorkCommand::Show { id } => {
            let task = backend.work_get(&agent, id)?;
            return output(&task, work_line(&task));
        }
        WorkCommand::Claim(task) => (task.id, WorkAction::Claim, work_step(&task)),
        WorkCommand::Beat(task) => (task.id, WorkAction::Beat, work_step(&task)),
        WorkCommand::Accept(task) => (task.id, WorkAction::Accept, work_step(&task)),
        WorkCommand::Done {
            task,
            report,
            commits,
        } => (
            task.id,
            WorkAction::Done,
            WorkStep {
                report,
                commits,
                ..work_step(&task)
            },
        ),
        WorkCommand::Reject { task, reason } => (
            task.id,
            WorkAction::Reject,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Fail { task, reason } => (
            task.id,
            WorkAction::Fail,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Cancel { task, reason } => (
            task.id,
            WorkAction::Cancel,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Decline { task, reason } => (
            task.id,
            WorkAction::Decline,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Handoff {
            task,
            to,
            report,
            commits,
        } => (
            task.id,
            WorkAction::Handoff,
            WorkStep {
                to: Some(to),
                report,
                commits,
                ..work_step(&task)
            },
        ),
        WorkCommand::Take { id, if_version } => (
            id,
            WorkAction::Take,
            WorkStep {
                version: Some(if_version),
                ..WorkStep::default()
            },
        ),
    };
    let task = backend.work_step(&agent, id, action, &step)?;
    output(&task, work_line(&task))
}

fn run_board(mut opened: Opened, command: BoardCommand, agent: Option<&String>) -> Result<Output> {
    let now = now_ms();
    let backend = opened.backend.as_mut();
    match command {
        BoardCommand::Set {
            key,
            value,
            zone,
            ttl,
        } => {
            let write = BoardWrite {
                key,
                value,
                zone,
                ttl_minutes: ttl,
            };
            let entry = backend.board_set(&resolve_agent(agent)?, &write, now)?;
            output(&entry, board_line(&entry))
        }
        BoardCommand::Get { key } => match backend.board_get(&key, now)? {
            Some(entry) => output(&entry, board_line(&entry)),
            None => Err(Error::NotFound(format!("board key {key:?} not found"))),
        },
        BoardCommand::Rm { key } => {
            let removed = backend.board_remove(&resolve_agent(agent)?, &key)?;
            output(
                &json!({"removed": removed}),
                if removed { "removed" } else { "no such key" },
            )
        }
        BoardCommand::List { zone } => {
            let entries = backend.board_list(zone.as_deref(), now)?;
            let text = join(&entries, board_line, "the board is empty");
            output(&entries, text)
        }
    }
}

fn run_events(opened: &Opened, args: EventsArgs, agent: Option<&String>) -> Result<Output> {
    let stream = match args.stream {
        StreamName::Coordination => Stream::Coordination,
        StreamName::Registry => Stream::Registry,
    };
    let query = EventQuery {
        stream,
        after: args.after,
        wait_seconds: args.wait,
        session: agent.cloned().or_else(env_agent),
        types: args.types,
    };
    let page = opened.backend.events(&query)?;
    let line = |event: &lockyard_core::proto::Event| format!("{}  {}", event.seq, event.kind);
    let text = join(&page.events, line, "no events");
    output(&page.events, text)
}

fn run_presence(
    mut opened: Opened,
    command: PresenceCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let now = now_ms();
    match command {
        PresenceCommand::List { active_within } => {
            let live = opened.backend.presence(active_within, now)?;
            let line = |entry: &lockyard_core::proto::Presence| {
                format!("{}  {}  {}", entry.session, entry.client, entry.last_seen)
            };
            let text = join(&live, line, "nobody active");
            output(&live, text)
        }
        PresenceCommand::Beat {
            client,
            role,
            model,
            cwd,
            dnd_until,
            tool_running,
            state,
            meta,
        } => {
            let state = state.map(|name| match name {
                StateName::Working => SessionState::Working,
                StateName::Idle => SessionState::Idle,
                StateName::Ended => SessionState::Ended,
                StateName::ApiFailure => SessionState::ApiFailure,
            });
            let activity =
                (tool_running || state.is_some() || meta.is_some()).then(|| SessionActivity {
                    tool_running,
                    tool_started_at: tool_running.then_some(Stamp::Millis(now)),
                    state,
                    meta,
                });
            let beat = PresenceBeat {
                client,
                model,
                role,
                version: Some(lockyard_core::VERSION.to_string()),
                cwd,
                dnd_until: dnd_until.map(Stamp::Millis),
                activity,
            };
            opened
                .backend
                .heartbeat(&resolve_agent(agent)?, &beat, now)?;
            output(&json!({"beat": true}), "beat")
        }
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|error| Error::Invalid(format!("{}: {error}", path.display())))
}

fn run_cloud(mut opened: Opened, command: CloudCommand, agent: Option<&String>) -> Result<Output> {
    let backend = opened.backend.as_mut();
    if !backend.is_cloud() {
        return Err(Error::needs_cloud("this command"));
    }
    let agent = agent
        .cloned()
        .or_else(env_agent)
        .unwrap_or_else(|| "lockyard-cli".to_string());
    let answer = match command {
        CloudCommand::Trust { .. } => unreachable!("trust is handled before opening the project"),
        CloudCommand::Export => backend.export()?,
        CloudCommand::Freeze { state, reason } => {
            backend.freeze(&agent, &Freeze { on: state, reason })?
        }
        CloudCommand::ImportZones { file } => backend.import_zones(&agent, &read_json(&file)?)?,
        CloudCommand::ImportBus { file } => backend.import_bus(&agent, &read_json(&file)?)?,
        CloudCommand::ImportRegistry { file } => {
            backend.registry_import(&agent, &read_json(&file)?)?
        }
        CloudCommand::Token(command) => return run_token(backend, command, &agent),
        CloudCommand::Key(_) => {
            unreachable!("local key commands are handled before opening the cloud backend")
        }
        CloudCommand::Encryption(_) => {
            unreachable!("workspace encryption commands use the direct client")
        }
    };
    let text = answer.to_string();
    output(&answer, text)
}

/// The agent must start while the server is away, so the encryption setting it last saw is kept
/// in its state folder and used until the server answers again. A setting the server sends wins.
#[cfg(unix)]
fn agent_client(client: lockyard_cloud_client::Client) -> Result<lockyard_cloud_client::Client> {
    use lockyard_cloud_client::{ClientError, WorkspaceEncryption};
    let cache = agent::state_root()?.join("encryption.json");
    let session = format!("lockyard-agent-{}", agent::uid());
    match client.workspace_encryption(&session) {
        Ok(setting) => {
            if let Ok(text) = serde_json::to_string(&setting) {
                let _ = std::fs::create_dir_all(cache.parent().unwrap_or(&cache));
                let _ = std::fs::write(&cache, text);
            }
            Ok(client.apply_content_encryption(setting)?)
        }
        Err(ClientError::NotFound(_)) => Ok(client),
        Err(
            error @ (ClientError::Transport(_)
            | ClientError::Frozen(_)
            | ClientError::RateLimited(_)
            | ClientError::Http(_)),
        ) => {
            match std::fs::read_to_string(&cache)
                .ok()
                .and_then(|text| serde_json::from_str::<WorkspaceEncryption>(&text).ok())
            {
                Some(setting) => Ok(client.apply_content_encryption(setting)?),
                None => {
                    eprintln!(
                        "lockyard agent: encryption setting unavailable ({error}); starting without it until the server answers"
                    );
                    Ok(client)
                }
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn run_cloud_key(cwd: &Path, command: KeyCommand) -> Result<Output> {
    use lockyard_cloud_client::WorkspaceKey;
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let config = lockyard_core::config::Config::load(&root)?;
    let (url, _) = open::endpoint(&config)?;
    let client = open::direct_client(&url)?;
    let setting = client.workspace_encryption("lockyard-cli")?;
    let workspace = setting.workspace_id;
    match command {
        KeyCommand::Create => {
            let (key, _phrase) = WorkspaceKey::generate().map_err(Error::Invalid)?;
            key.store_for_workspace(&workspace)
                .map_err(Error::Invalid)?;
            output(
                &json!({"created":true,"key_id":key.key_id()}),
                format!("created local key {}", key.key_id()),
            )
        }
        KeyCommand::ShowPhrase => {
            eprint!("Type SHOW to display this workspace recovery phrase: ");
            std::io::stderr().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if confirmation.trim() != "SHOW" {
                return Err(Error::Invalid(
                    "recovery phrase display was not confirmed".into(),
                ));
            }
            let key = WorkspaceKey::load_for_workspace(&workspace)
                .map_err(Error::Invalid)?
                .ok_or_else(|| Error::Invalid("no local key exists for this workspace".into()))?;
            let phrase = key.phrase();
            output(&json!({"recovery_phrase":phrase}), phrase)
        }
        KeyCommand::Import => {
            let mut phrase = String::new();
            std::io::stdin().read_to_string(&mut phrase)?;
            let key = WorkspaceKey::from_phrase(&phrase).map_err(Error::Invalid)?;
            key.store_for_workspace(&workspace)
                .map_err(Error::Invalid)?;
            output(
                &json!({"imported":true,"key_id":key.key_id()}),
                format!("imported local key {}", key.key_id()),
            )
        }
    }
}

fn run_cloud_encryption(cwd: &Path, command: EncryptionCommand) -> Result<Output> {
    use lockyard_cloud_client::WorkspaceKey;
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let config = lockyard_core::config::Config::load(&root)?;
    let (url, _) = open::endpoint(&config)?;
    let client = open::direct_client(&url)?;
    let setting = client.workspace_encryption("lockyard-cli")?;
    let key = WorkspaceKey::load_for_workspace(&setting.workspace_id).map_err(Error::Invalid)?;
    match command {
        EncryptionCommand::Status => {
            let local_id = key.as_ref().map(WorkspaceKey::key_id);
            let matches = match (&local_id, &setting.key_id) {
                (Some(local), Some(server)) => local == server,
                _ => false,
            };
            let text = format!(
                "encryption {}, key id {}, local key {}",
                setting.encryption,
                setting.key_id.as_deref().unwrap_or("none"),
                if matches {
                    "matches"
                } else if local_id.is_some() {
                    "does not match"
                } else {
                    "missing"
                }
            );
            output(
                &json!({"encryption":setting.encryption,"key_id":setting.key_id,"local_key_matches":matches}),
                text,
            )
        }
        EncryptionCommand::Require => {
            let key = key.ok_or_else(|| Error::Invalid(
                "no local workspace key exists; create one with `lockyard cloud key create` or import it with `lockyard cloud key import`".into(),
            ))?;
            let id = key.key_id();
            client.set_workspace_encryption("lockyard-cli", "required", Some(&id))?;
            output(
                &json!({"encryption":"required","key_id":id}),
                format!("encryption required with key {id}"),
            )
        }
        EncryptionCommand::Off => {
            client.set_workspace_encryption("lockyard-cli", "off", None)?;
            output(&json!({"encryption":"off"}), "encryption off")
        }
    }
}

fn run_token(backend: &mut dyn Backend, command: TokenCommand, agent: &str) -> Result<Output> {
    let line = |token: &Value| {
        let field = |name: &str| token[name].as_str().unwrap_or("-").to_string();
        let revoked = if token["revoked_at"].is_string() {
            "  revoked"
        } else {
            ""
        };
        format!(
            "{}  {}  {}  until {}{revoked}",
            field("id"),
            field("role"),
            field("name"),
            field("expires_at")
        )
    };
    match command {
        TokenCommand::Create { name, role, days } => {
            let request = TokenRequest {
                name,
                role,
                expires_at: rfc3339(now_ms().saturating_add(days.saturating_mul(DAY_MS))),
            };
            let answer = backend.token_create(agent, &request)?;
            let raw = answer["raw"].as_str().unwrap_or_default();
            let text = format!(
                "{}\nThis token is shown once:\n{raw}",
                line(&answer["token"])
            );
            output(&answer, text)
        }
        TokenCommand::List => {
            let answer = backend.tokens()?;
            let rows = answer.as_array().map_or(&[][..], Vec::as_slice);
            let text = join(rows, line, "no tokens");
            output(&answer, text)
        }
        TokenCommand::Revoke { id } => {
            let answer = backend.token_revoke(agent, &id)?;
            let text = line(&answer);
            output(&answer, text)
        }
    }
}

fn run_status(opened: &Opened, agent: Option<&String>) -> Result<Output> {
    let now = now_ms();
    let lease = clock(opened);
    let backend = opened.backend.as_ref();
    let claims = backend.claims(&ClaimQuery::default(), now)?;
    let agent = agent.cloned().or_else(env_agent);
    let unread = agent
        .as_deref()
        .map(|name| backend.unread(name))
        .transpose()?;
    let mut lines = Vec::new();
    let machine_config = guard::project_config(&std::env::current_dir().unwrap_or_default());
    let machine_level = guard::snapshot(&machine_config).ok().map(|report| {
        let name = match report.level {
            lockyard_core::machine::Level::Ok => "ok",
            lockyard_core::machine::Level::Warn => "warn",
            lockyard_core::machine::Level::Hold => "hold",
            lockyard_core::machine::Level::Critical => "critical",
        };
        lines.push(format!("machine: {name}"));
        name
    });
    if let Some(unread) = unread {
        lines.push(format!("unread mail: {unread}"));
    }
    lines.push(join(
        &claims,
        |claim| claim_line(claim, lease),
        "no active claims",
    ));
    if backend.is_cloud() {
        let session = agent.as_deref().unwrap_or("lockyard-cli");
        let work = backend.work_list(session)?;
        lines.push(join(&work, work_line, "no work tasks"));
        let tasks = backend.tasks(None, false)?;
        lines.push(join(&tasks, task_line, "no tasks"));
        let data = json!({ "unread": unread, "claims": claims, "work": work, "tasks": tasks, "machine_level": machine_level });
        return output(&data, lines.join("\n"));
    }
    let tasks = backend.tasks(None, false)?;
    lines.push(join(&tasks, task_line, "no tasks"));
    let data = json!({ "unread": unread, "claims": claims, "tasks": tasks, "machine_level": machine_level });
    output(&data, lines.join("\n"))
}

fn run_hook(command: HookCommand, agent: Option<String>, cwd: &Path) {
    let tool = match command {
        HookCommand::Claude => hook::Tool::Claude,
        HookCommand::Codex => hook::Tool::Codex,
        HookCommand::Cursor => hook::Tool::Cursor,
    };
    let mut input = String::new();
    let read = std::io::stdin().read_to_string(&mut input);
    let mut out = std::io::stdout().lock();
    let answer = read.map_err(Error::Io).and_then(|_| {
        hook::run(
            tool,
            &input,
            agent.or_else(env_agent_explicit),
            cwd,
            now_ms(),
            &mut out,
        )
    });
    if let Err(error) = answer {
        eprintln!("lockyard hook: {error}");
    }
}

fn setup(client: SetupClient) -> String {
    let server = r#"{
  "mcpServers": {
    "lockyard": { "command": "lockyard", "args": ["mcp"] }
  }
}"#;
    let mut sections = match client {
        SetupClient::Claude => vec![
            format!("Add to .claude/settings.json:\n{}", hook::SETTINGS),
            format!("Add to .mcp.json:\n{server}"),
        ],
        SetupClient::Codex => vec![
            "Add to ~/.codex/config.toml:\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]\nenv_vars = [\"LOCKYARD_AGENT\", \"LOCKYARD_URL\", \"LOCKYARD_TOKEN_FILE\", \"LOCKYARD_TOKEN\", \"LOCKYARD_NODE_CONFIG\", \"XDG_CONFIG_HOME\", \"LOCKYARD_REQUIRE_E2EE\", \"LOCKYARD_E2EE_WORKSPACE_ID\"]"
                .to_string(),
        ],
        SetupClient::Cursor => vec![format!("Add to .cursor/mcp.json:\n{server}")],
    };
    sections.push("Set LOCKYARD_AGENT to a unique name for each agent.".to_string());
    sections.join("\n\n")
}

/// Inside a hook the event names the session, so only an explicit name overrides it.
fn env_agent_explicit() -> Option<String> {
    std::env::var("LOCKYARD_AGENT")
        .ok()
        .filter(|value| !value.is_empty())
}

#[cfg(unix)]
fn run_agent(args: AgentArgs, cwd: &Path) -> Result<Output> {
    use agent::daemon::{AgentConfig, Daemon};
    use agent::service;
    use agent::socket::AgentSocket;
    use lockyard_cloud_client::Client;
    use lockyard_core::config::{Config, Mode};
    let project = || -> Result<(PathBuf, Config)> {
        let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
        let config = Config::load(&root)?;
        if config.mode != Mode::Cloud {
            return Err(Error::needs_cloud("lockyard agent"));
        }
        Ok((root, config))
    };
    match args.command {
        None => {
            let (_, config) = project()?;
            let (url, workspace) = open::endpoint(&config)?;
            open::trusted_url(&url)?;
            let token = Config::token()?;
            let token_id = lockyard_cloud_client::token_id(&token);
            let client = agent_client(Client::new(&url, token)?)?;
            let settings = AgentConfig {
                url,
                workspace,
                token_id,
                socket: agent::socket_path(),
                state_root: agent::state_root()?,
                timing: Default::default(),
            };
            Daemon::start(settings, client)?.wait();
            output(&Value::Null, "")
        }
        Some(AgentCommand::Install { no_start }) => {
            let (root, _) = project()?;
            let path = service::install(&root, !no_start)?;
            let shown = path.display().to_string();
            output(&json!({"unit": shown}), format!("installed {shown}"))
        }
        Some(AgentCommand::Uninstall { no_start }) => {
            let path = service::uninstall(!no_start)?;
            let shown = path.display().to_string();
            output(&json!({"unit": shown}), format!("removed {shown}"))
        }
        Some(AgentCommand::Status) => {
            let installed = service::installed()?;
            let socket = agent::socket_path();
            match AgentSocket::status(&socket, Duration::from_secs(1)) {
                Ok(status) => {
                    let age = status
                        .view_age_ms
                        .map_or("none".to_string(), |ms| format!("{ms} ms"));
                    let text = format!(
                        "running, pid {}, workspace {}, view age {age}, outbox {}, rejected {}",
                        status.pid, status.workspace, status.outbox, status.rejected
                    );
                    output(
                        &json!({"running": true, "installed": installed, "status": status}),
                        text,
                    )
                }
                Err(_) => output(
                    &json!({"running": false, "installed": installed}),
                    format!(
                        "not running, unit {}",
                        if installed {
                            "installed"
                        } else {
                            "not installed"
                        }
                    ),
                ),
            }
        }
    }
}

#[cfg(not(unix))]
fn run_agent(_: AgentArgs, _: &Path) -> Result<Output> {
    Err(Error::Invalid("lockyard agent needs a Unix socket".into()))
}

fn run(cli: Cli, cwd: &Path) -> Result<Output> {
    let Cli { agent, command, .. } = cli;
    let name = agent.clone().or_else(env_agent);
    let open = || open::open(cwd, name.as_deref());
    match command {
        Command::Init => {
            let store = Store::init(cwd)?;
            let root = store.root().display().to_string();
            output(
                &json!({ "root": root }),
                format!("Lockyard project at {root}"),
            )
        }
        Command::About => output(
            &json!({ "version": lockyard_core::VERSION }),
            lockyard_core::about(),
        ),
        Command::Machine => {
            guard::recover();
            let report = guard::report(guard::project_config(cwd)).map_err(Error::Io)?;
            output(&report, guard::text(&report))
        }
        Command::Run(args) => {
            if !args.heavy {
                return Err(Error::Invalid(
                    "use `lockyard run --heavy -- <command>` for heavy work".into(),
                ));
            }
            let status = guard::run_heavy(guard::project_config(cwd), &args.command, args.max_wait)
                .map_err(Error::Io)?;
            let mut out = output(
                &json!({"success": status.success(), "code": status.code()}),
                "",
            )?;
            out.exit = status.code().unwrap_or(EXIT_FAILURE as i32).clamp(0, 255) as u8;
            Ok(out)
        }
        Command::Who => {
            let opened = open()?;
            let now = now_ms();
            let agents = opened.backend.agents()?;
            let line = |entry: &lockyard_core::proto::AgentSeen| match &entry.last_seen {
                Stamp::Millis(last) if !opened.backend.is_cloud() => {
                    format!("{}  seen {} min ago", entry.id, (now - last) / 60_000)
                }
                other => format!("{}  seen {other}", entry.id),
            };
            let text = join(&agents, line, "no agents yet");
            output(&agents, text)
        }
        Command::Status => run_status(&open()?, agent.as_ref()),
        Command::Zone(command) => run_zone(open()?, command, agent.as_ref(), cwd),
        Command::Msg(command) => run_msg(open()?, command, agent.as_ref()),
        Command::Task(command) => run_task(open()?, command, agent.as_ref()),
        Command::Work(command) => run_work(open()?, command, agent.as_ref()),
        Command::Board(command) => run_board(open()?, command, agent.as_ref()),
        Command::Events(args) => run_events(&open()?, args, agent.as_ref()),
        Command::Presence(command) => run_presence(open()?, command, agent.as_ref()),
        Command::Agent(args) => run_agent(args, cwd),
        Command::Cloud(CloudCommand::Trust { url }) => {
            open::trust_url(&url)?;
            output(&json!({"trusted": url}), format!("trusted {url}"))
        }
        Command::Cloud(CloudCommand::Key(command)) => run_cloud_key(cwd, command),
        Command::Cloud(CloudCommand::Encryption(command)) => run_cloud_encryption(cwd, command),
        Command::Cloud(command) => run_cloud(open()?, command, agent.as_ref()),
        Command::Hook(command) => {
            run_hook(command, agent, cwd);
            output(&Value::Null, "")
        }
        Command::Setup {
            client,
            apply,
            check,
            remove,
            preview,
        } => {
            if !(apply || check || remove || preview) {
                let text = setup(client);
                return output(&json!({ "setup": text }), text);
            }
            let client = match client {
                SetupClient::Claude => "claude",
                SetupClient::Codex => "codex",
                SetupClient::Cursor => "cursor",
            };
            let action = if apply {
                onboarding::SetupAction::Apply
            } else if check {
                onboarding::SetupAction::Check
            } else if remove {
                onboarding::SetupAction::Remove
            } else {
                onboarding::SetupAction::Preview
            };
            let data = onboarding::setup(cwd, client, action)?;
            let mut result = output(&data, onboarding::text(&data))?;
            if data["ok"] == false {
                result.exit = EXIT_FAILURE;
            }
            Ok(result)
        }
        Command::Doctor { client, smoke } => {
            let data = onboarding::doctor(cwd, agent.as_deref(), client.as_deref(), smoke)?;
            let mut result = output(&data, onboarding::text(&data))?;
            if data["ok"] == false {
                result.exit = EXIT_FAILURE;
            }
            Ok(result)
        }
        Command::Context {
            limit,
            max_bytes,
            cursor,
        } => {
            let mut opened = open()?;
            let data = context::snapshot(
                opened.backend.as_mut(),
                &resolve_agent(agent.as_ref())?,
                now_ms(),
                &context::ContextOptions {
                    limit,
                    max_bytes,
                    cursor,
                },
            )?;
            output(&data, data.to_string())
        }
        Command::Workflow(WorkflowCommand::Inspect { id }) => {
            let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
            let data = workflow::inspect(&root, &id)?;
            output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            )
        }
        Command::Workflow(WorkflowCommand::Run { id, plan }) => {
            let mut bytes = Vec::new();
            if plan.as_os_str() == "-" {
                std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            } else {
                std::fs::File::open(plan)?
                    .take(65537)
                    .read_to_end(&mut bytes)?;
            }
            if bytes.len() > 65536 {
                return Err(Error::Invalid("workflow plan exceeds 65536 bytes".into()));
            }
            let plan: Value = serde_json::from_slice(&bytes)
                .map_err(|error| Error::Invalid(format!("invalid workflow JSON: {error}")))?;
            let mut opened = open()?;
            let data = workflow::run(
                &opened.root,
                opened.backend.as_mut(),
                &resolve_agent(agent.as_ref())?,
                now_ms(),
                &id,
                &plan,
            )?;
            let mut result = output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            )?;
            if data["ok"] != true {
                result.exit = EXIT_FAILURE;
            }
            Ok(result)
        }
        #[cfg(unix)]
        Command::Node(command) => node_output(node_cli::node(command)?),
        #[cfg(unix)]
        Command::Job(command) => node_output(node_cli::job(command)?),
        Command::Mcp => output(&Value::Null, ""),
    }
}

#[cfg(unix)]
fn node_output(data: Value) -> Result<Output> {
    let failed = data.get("ok") == Some(&Value::Bool(false))
        || data.pointer("/reply/ok") == Some(&Value::Bool(false));
    let mut out = output(
        &data,
        serde_json::to_string_pretty(&data).unwrap_or_default(),
    )?;
    if failed {
        out.exit = EXIT_FAILURE;
    }
    Ok(out)
}

fn current_dir() -> Result<PathBuf> {
    Ok(std::env::current_dir()?)
}

fn report(error: &Error, json: bool) {
    if json {
        eprintln!(
            "{}",
            json!({"error": {"kind": error.kind(), "message": error.to_string()}})
        );
    } else {
        eprintln!("{error}");
    }
}

/// Prints one result. A failed print leaves `after` undone: mail that never reached anyone stays unread.
fn deliver(out: &Output, json: bool) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    if json {
        if !out.json.is_null() {
            writeln!(stdout, "{}", out.json)?;
        }
    } else if !out.text.is_empty() {
        writeln!(stdout, "{}", out.text)?;
    }
    stdout.flush()
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    if matches!(&cli.command, Command::Mcp) {
        let agent = cli.agent.clone().or_else(env_lockyard_agent);
        return match current_dir().and_then(|cwd| mcp::serve(agent, &cwd).map_err(Error::Io)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(EXIT_FAILURE)
            }
        };
    }
    let is_hook = matches!(&cli.command, Command::Hook(_));
    match current_dir().and_then(|cwd| run(cli, &cwd)) {
        Ok(_) if is_hook => ExitCode::SUCCESS,
        Ok(mut out) => {
            if let Err(error) = deliver(&out, json) {
                report(&Error::Io(error), json);
                return ExitCode::from(EXIT_FAILURE);
            }
            if let Some(after) = out.after.take()
                && let Err(error) = after()
            {
                report(&error, json);
                return ExitCode::from(EXIT_FAILURE);
            }
            ExitCode::from(out.exit)
        }
        Err(error @ (Error::Conflict(_) | Error::Contended(_))) => {
            report(&error, json);
            ExitCode::from(EXIT_CONFLICT)
        }
        Err(error) => {
            report(&error, json);
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn env_lockyard_agent() -> Option<String> {
    std::env::var("LOCKYARD_AGENT")
        .ok()
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn work_handoff_accepts_context_and_commit_references() {
        let cli = Cli::try_parse_from([
            "lockyard",
            "work",
            "handoff",
            "W-12",
            "--to",
            "next",
            "--if-version",
            "3",
            "--report",
            "Tests passed; next verify staging",
            "--commit",
            "abc123",
            "--commit",
            "def456",
        ])
        .unwrap();
        let Command::Work(WorkCommand::Handoff {
            task,
            to,
            report,
            commits,
        }) = cli.command
        else {
            panic!("expected work handoff")
        };
        assert_eq!(task.id, 12);
        assert_eq!(task.if_version, Some(3));
        assert_eq!(to, "next");
        assert_eq!(report.as_deref(), Some("Tests passed; next verify staging"));
        assert_eq!(commits, ["abc123", "def456"]);
    }

    #[test]
    fn ids_read_with_or_without_a_prefix() {
        assert_eq!(parse_id("12"), Ok(12));
        assert_eq!(parse_id("T-12"), Ok(12));
        assert_eq!(parse_id("z-3"), Ok(3));
        assert_eq!(parse_id("W-3"), Ok(3));
        assert!(parse_id("T12").is_err());
        assert!(parse_id("nope").is_err());
    }

    #[test]
    fn minutes_round_up_and_stop_at_zero() {
        assert_eq!(minutes_left(60_001, 0), 2);
        assert_eq!(minutes_left(60_000, 0), 1);
        assert_eq!(minutes_left(0, 5), 0);
    }

    #[test]
    fn a_cloud_lease_is_shown_and_never_counted_down() {
        let claim: Claim = serde_json::from_value(json!({
            "id": 1,
            "session": "a",
            "expires_at": 90_000,
            "foreign_dirty_paths": [{"path": "src/a.rs", "owner_session": "other"}]
        }))
        .unwrap();
        assert!(claim_line(&claim, Some(30_000)).contains("1 min left"));
        assert!(claim_line(&claim, None).contains("until 90000"));
        assert!(claim_line(&claim, None).contains("Foreign uncommitted work: \"src/a.rs\""));
        assert!(claim_line(&claim, None).contains("owner: \"other\""));
    }

    struct Scripted {
        answers: Vec<Result<Claim>>,
        waits: Vec<Option<i64>>,
    }

    impl Backend for Scripted {
        fn touch_agent(&mut self, _: &str, _: i64) -> Result<()> {
            Ok(())
        }
        fn agents(&self) -> Result<Vec<lockyard_core::proto::AgentSeen>> {
            unreachable!()
        }
        fn claim(&mut self, _: &str, request: &ClaimRequest, _: i64) -> Result<Claim> {
            self.waits.push(request.queue_wait_seconds);
            self.answers.remove(0)
        }
        fn renew(&mut self, _: &str, _: Option<i64>, _: &RenewRequest, _: i64) -> Result<usize> {
            unreachable!()
        }
        fn release(
            &mut self,
            _: &str,
            _: Option<i64>,
            _: &ReleaseRequest,
            _: i64,
        ) -> Result<usize> {
            unreachable!()
        }
        fn claims(&self, _: &ClaimQuery, _: i64) -> Result<Vec<Claim>> {
            unreachable!()
        }
        fn check(
            &self,
            _: &str,
            _: &[String],
            _: Option<i64>,
            _: i64,
        ) -> Result<Vec<lockyard_core::proto::PathCheck>> {
            unreachable!()
        }
        fn send(&mut self, _: &str, _: &SendRequest, _: i64) -> Result<Message> {
            unreachable!()
        }
        fn reply(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Message> {
            unreachable!()
        }
        fn inbox(&mut self, _: &str, _: InboxQuery, _: i64) -> Result<InboxPage> {
            unreachable!()
        }
        fn unread(&self, _: &str) -> Result<i64> {
            unreachable!()
        }
        fn inbox_seen(&mut self, _: &str, _: &[i64], _: i64) -> Result<usize> {
            unreachable!()
        }
        fn inbox_claim(&mut self, _: &str, _: &str, _: &[i64], _: i64, _: i64) -> Result<Vec<i64>> {
            unreachable!()
        }
        fn tasks(&self, _: Option<Status>, _: bool) -> Result<Vec<Task>> {
            unreachable!()
        }
        fn task(&self, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn task_history(&self, _: i64) -> Result<Vec<lockyard_core::tasks::TaskEvent>> {
            unreachable!()
        }
        fn add_task(&mut self, _: &str, _: &TaskSpec, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn claim_task(&mut self, _: &str, _: i64, _: i64, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn renew_task(&mut self, _: &str, _: i64, _: i64, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn release_task(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn submit_task(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn accept_task(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn reject_task(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn cancel_task(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn board_set(&mut self, _: &str, _: &BoardWrite, _: i64) -> Result<BoardEntry> {
            unreachable!()
        }
        fn board_get(&self, _: &str, _: i64) -> Result<Option<BoardEntry>> {
            unreachable!()
        }
        fn board_remove(&mut self, _: &str, _: &str) -> Result<bool> {
            unreachable!()
        }
        fn board_list(&self, _: Option<&str>, _: i64) -> Result<Vec<BoardEntry>> {
            unreachable!()
        }
        fn heartbeat(&mut self, _: &str, _: &PresenceBeat, _: i64) -> Result<()> {
            unreachable!()
        }
        fn presence(&self, _: i64, _: i64) -> Result<Vec<lockyard_core::proto::Presence>> {
            unreachable!()
        }
    }

    fn claim() -> Claim {
        serde_json::from_value(json!({"id": 1})).unwrap()
    }

    #[test]
    fn a_short_wait_retries_a_conflict_and_stops_on_anything_else() {
        let mut backend = Scripted {
            answers: vec![Err(Error::Contended("reserved".into())), Ok(claim())],
            waits: Vec::new(),
        };
        assert_eq!(
            wait_for_claim(&mut backend, "a", ClaimRequest::default(), 3)
                .unwrap()
                .id,
            1
        );
        assert_eq!(backend.waits.len(), 2);
        assert!(backend.waits[0].is_some());

        let mut failing = Scripted {
            answers: vec![Err(Error::Frozen("x".into()))],
            waits: Vec::new(),
        };
        assert!(matches!(
            wait_for_claim(&mut failing, "a", ClaimRequest::default(), 3),
            Err(Error::Frozen(_))
        ));
        assert_eq!(failing.waits.len(), 1);
    }

    #[test]
    fn a_short_wait_gives_up_at_its_limit_and_refuses_a_long_one() {
        let mut backend = Scripted {
            answers: vec![Err(Error::Contended("reserved".into()))],
            waits: Vec::new(),
        };
        assert!(matches!(
            wait_for_claim(&mut backend, "a", ClaimRequest::default(), 0),
            Err(Error::Contended(_))
        ));
        assert!(wait_for_claim(&mut backend, "a", ClaimRequest::default(), 121).is_err());
    }
}
