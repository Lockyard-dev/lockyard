// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum ZoneCommand {
    /// Claim paths, all of them or none.
    Claim {
        paths: Vec<String>,
        /// Read additional paths from a regular UTF-8 file relative to the current directory
        /// (unless absolute); one path per line (# comments and blanks ignored); at most 1000 paths; NUL refused.
        #[arg(long = "paths-file", value_name = "FILE")]
        paths_file: Option<PathBuf>,
        /// What the claim is for.
        #[arg(long, default_value = "")]
        note: String,
        #[command(flatten)]
        ttl: Ttl,
        /// Why the claim stays held while idle; defaults to holding until its expiry.
        #[arg(long)]
        hold_reason: Option<String>,
        /// Hold until this RFC 3339 timestamp; requires --hold-reason.
        #[arg(long, conflicts_with = "hold_for")]
        hold_until: Option<String>,
        /// Hold for this many minutes from now (1-240); client writes absolute hold_until.
        #[arg(
            long = "hold-for",
            value_name = "MINUTES",
            conflicts_with = "hold_until"
        )]
        hold_for: Option<i64>,
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
        /// ISO 8601 timestamp, for example 2026-11-05T15:00:00Z.
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
        #[arg(long, conflicts_with = "hold_for")]
        hold_until: Option<String>,
        /// Hold for this many minutes from now (1-240); client writes absolute hold_until.
        #[arg(
            long = "hold-for",
            value_name = "MINUTES",
            conflicts_with = "hold_until"
        )]
        hold_for: Option<i64>,
        #[arg(long)]
        fence: Option<i64>,
    },
    /// Release one claim; with several claims, give an id or --all.
    Release {
        #[arg(value_parser = parse_id)]
        id: Option<i64>,
        /// Release all this agent's claims. Cannot be combined with an id.
        #[arg(long)]
        all: bool,
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
#[command(defer = true)]
pub(super) enum DirtyCommand {
    /// Report paths with uncommitted changes.
    Report {
        #[arg(required = true)]
        paths: Vec<String>,
        /// The session that owns the changes.
        #[arg(long)]
        owner: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, value_parser = task_key)]
        task: Option<String>,
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
#[command(defer = true)]
pub(super) enum MsgCommand {
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
    /// Show unread mail. Marks it read only when stdout is a terminal; piping acts like --peek.
    Inbox {
        /// Include mail already read.
        #[arg(long)]
        all: bool,
        /// Do not mark anything read.
        #[arg(long)]
        peek: bool,
        /// Mark the shown page read even when stdout is not a terminal (scripts).
        #[arg(long, conflicts_with = "peek")]
        mark_read: bool,
    },
    /// Show asks that still need a reply or ack from this agent, without marking them read.
    ///
    /// A broadcast ask another recipient answered looks closed here (shared server `status=ack`);
    /// per-reader handled state is LC-0004.
    Open,
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
    /// Show this agent's own messages and how far each one got.
    Sent {
        /// How many of the newest to show.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// List unseen mail across sessions. Needs the lead or dispatcher role.
    Undelivered {
        /// Only mail older than this.
        #[arg(long, default_value_t = 0)]
        older_than: i64,
    },
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum TaskCommand {
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
        #[arg(value_parser=task_key)]
        id: String,
    },
    /// Show full cloud registry dependency links, without reducing statuses.
    Links {
        #[arg(value_parser=task_key)]
        id: String,
    },
    /// Add a typed dependency link at an explicitly observed version.
    Link {
        #[arg(value_parser=task_key)]
        id: String,
        #[arg(value_parser=task_key)]
        to: String,
        #[arg(long, default_value = "blocks")]
        kind: String,
        #[arg(long)]
        if_version: i64,
        /// ULID retained across retries. Generated if omitted and printed in the result.
        #[arg(long)]
        key: Option<String>,
    },
    /// Add an open task about files or directories; the server determines its area.
    Add {
        title: String,
        /// File or directory relative to the workspace root. Repeat for each path.
        /// Required when the server supports automatic areas.
        #[arg(long = "path", value_name = "PATH")]
        paths: Vec<String>,
        #[arg(long, default_value = "")]
        body: String,
        /// Read the task body from a regular UTF-8 file relative to the current directory
        /// (unless absolute); at most 64 KiB; NUL refused.
        #[arg(long = "body-file", value_name = "FILE")]
        body_file: Option<PathBuf>,
        /// What closes the task. Cloud mode; the title by default.
        #[arg(long, conflicts_with = "acceptance_file")]
        acceptance: Option<String>,
        /// Read acceptance criteria from a regular UTF-8 file relative to the current directory
        /// (unless absolute); at most 64 KiB; NUL refused.
        #[arg(
            long = "acceptance-file",
            value_name = "FILE",
            conflicts_with = "acceptance"
        )]
        acceptance_file: Option<PathBuf>,
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
        /// Optional area override, sent as given. The server derives the area from --path.
        #[arg(long)]
        area: Option<String>,
        /// Prefix to use when creating the default area.
        #[arg(long)]
        prefix: Option<String>,
        /// Number padding to use when creating the default area.
        #[arg(long)]
        pad: Option<u8>,
        /// Due date as RFC 3339 text. Cloud mode.
        #[arg(long)]
        due: Option<String>,
        /// Evidence stored at once. P0 needs it. Cloud mode.
        #[arg(long)]
        evidence: Option<String>,
    },
    /// Change the urgency of a task. Needs cloud mode.
    Plan {
        #[arg(value_parser = task_key)]
        id: String,
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
        /// Work that can be taken now: open, predecessors closed, no live lease.
        /// On the server this is the ready queue. Locally it is the open list.
        #[arg(long)]
        ready: bool,
    },
    /// Show a task and its history.
    Show {
        #[arg(value_parser = task_key)]
        id: String,
    },
    /// Take a task.
    Claim {
        #[arg(value_parser = task_key)]
        id: String,
        #[command(flatten)]
        ttl: Ttl,
    },
    /// Extend the lease on a held task.
    Renew {
        #[arg(value_parser = task_key)]
        id: String,
        #[command(flatten)]
        ttl: Ttl,
    },
    /// Give a held task back.
    Release {
        #[arg(value_parser = task_key)]
        id: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Hand a held task to review.
    Submit {
        #[arg(value_parser = task_key)]
        id: String,
        /// What proves the work is done.
        #[arg(long)]
        evidence: String,
    },
    /// Record a Codex review. PASS stays in review. REJECT returns the task.
    Review {
        #[arg(value_parser = task_key)]
        id: String,
        /// `pass` or `reject`.
        #[arg(long)]
        decision: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Accept another agent's submitted work. Only Claude, after a Codex PASS.
    Accept {
        #[arg(value_parser = task_key)]
        id: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Return submitted work to its assignee.
    Reject {
        #[arg(value_parser = task_key)]
        id: String,
        #[arg(long)]
        reason: String,
        /// Required when the work is already accepted. Appended; older proof stays in the history.
        #[arg(long, default_value = "")]
        evidence: String,
    },
    /// Cancel a task you wrote.
    Cancel {
        #[arg(value_parser = task_key)]
        id: String,
        #[arg(long, default_value = "")]
        note: String,
    },
}

#[derive(Args)]
pub(super) struct WorkRef {
    #[arg(value_parser = bus_key)]
    pub(super) id: String,
    /// Act only if the task is still at this version.
    #[arg(long)]
    pub(super) if_version: Option<i64>,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum WorkCommand {
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
        #[arg(value_parser = bus_key)]
        id: String,
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
        #[arg(value_parser = bus_key)]
        id: String,
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
#[command(defer = true)]
pub(super) enum BoardCommand {
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
