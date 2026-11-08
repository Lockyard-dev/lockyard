// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[derive(Parser)]
#[command(name = "lockyard", version = lockyard_core::BUILD_VERSION, about = lockyard_core::SUMMARY)]
pub(super) struct Cli {
    /// Name of this agent. Defaults to LOCKYARD_AGENT, then CLAUDE_CODE_SESSION_ID.
    #[arg(long, global = true)]
    pub(super) agent: Option<String>,
    /// Print JSON instead of text.
    #[arg(long, global = true)]
    pub(super) json: bool,
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum Command {
    /// Create a project in the current folder.
    Init,
    /// Show the version and the homepage.
    About,
    /// Maintain the local coordination database.
    #[command(subcommand)]
    Db(DbCommand),
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
    /// Show mail and writes made outside the hook as they happen.
    Monitor(MonitorArgs),
    /// Configure agent tools, or inspect a named client's managed integration.
    Setup(SetupArgs),
    /// Check project readiness; optional client or smoke diagnostics are read-only.
    Doctor {
        /// Inspect Linux execution enforcement for this node configuration.
        #[arg(long)]
        node_config: Option<PathBuf>,
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
    #[command(subcommand)]
    Node(node_cli::NodeCommand),
    /// Submit and inspect remote jobs.
    #[command(subcommand)]
    Job(node_cli::JobCommand),
    /// Revoke Cloud credentials and propagate signed denies to direct peers.
    #[command(subcommand)]
    Revoke(crate::revoke_access::RevokeCommand),
    /// Run the MCP server over standard input and output.
    Mcp(McpArgs),
}

#[derive(Subcommand)]
pub(super) enum DbCommand {
    /// Create a private, standalone snapshot without replacing an existing path.
    Backup {
        /// Destination file, relative to the current working directory unless absolute.
        path: PathBuf,
    },
}

#[derive(Args)]
pub(super) struct SetupArgs {
    /// Managed integration client; preserves the cloud setup CLIENT command form.
    #[arg(value_enum, conflicts_with = "clients")]
    pub(super) client: Option<SetupClient>,
    #[arg(long, requires = "client", conflicts_with_all = ["check", "remove", "preview", "dry_run", "uninstall", "print"])]
    pub(super) apply: bool,
    #[arg(long, requires = "client", conflicts_with_all = ["apply", "remove", "preview", "dry_run", "uninstall", "print"])]
    pub(super) check: bool,
    #[arg(long, requires = "client", conflicts_with_all = ["apply", "check", "preview", "dry_run", "uninstall", "print"])]
    pub(super) remove: bool,
    #[arg(long, requires = "client", conflicts_with_all = ["apply", "check", "remove", "dry_run", "uninstall", "print"])]
    pub(super) preview: bool,
    /// claude, codex, cursor, gemini, copilot or all. Default: the ones found here.
    #[arg(long = "client")]
    pub(super) clients: Vec<String>,
    /// Show what would be written and write nothing.
    #[arg(long)]
    pub(super) dry_run: bool,
    /// Take back what setup wrote.
    #[arg(long)]
    pub(super) uninstall: bool,
    /// Print the snippets instead of writing any file.
    #[arg(long)]
    pub(super) print: bool,
}

#[derive(clap::ValueEnum, Clone, Copy)]
pub(super) enum SetupClient {
    Claude,
    Codex,
    Cursor,
}

#[derive(Args)]
pub(super) struct McpArgs {
    /// compact (six composite tools, the default) or full (every tool).
    #[arg(long = "tools")]
    pub(super) tools: Option<String>,
}

#[derive(Args)]
pub(super) struct MonitorArgs {
    /// How often to re-read the store even when the file system said nothing (seconds).
    #[arg(long, default_value = "10")]
    pub(super) reconcile: u64,
    /// Do not print new mail.
    #[arg(long)]
    pub(super) no_mail: bool,
    /// Do not watch claimed paths for writes outside the hook.
    #[arg(long)]
    pub(super) no_zones: bool,
    /// Stop after the first mail or unannounced write.
    #[arg(long)]
    pub(super) once: bool,
    /// Stop after this many seconds, whether or not anything arrived.
    #[arg(long)]
    pub(super) timeout: Option<u64>,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum WorkflowCommand {
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
pub(super) struct RunArgs {
    /// Acquire a machine slot and wait while the machine is under pressure.
    #[arg(long)]
    pub(super) heavy: bool,
    /// Stop waiting after this many seconds (default: 1800).
    #[arg(long, default_value_t = 1800)]
    pub(super) max_wait: u64,
    /// Command and arguments, after `--`.
    #[arg(last = true, required = true)]
    pub(super) command: Vec<std::ffi::OsString>,
}

#[derive(Args)]
pub(super) struct Ttl {
    /// Lease in minutes.
    #[arg(long, default_value_t = DEFAULT_TTL_MINUTES)]
    pub(super) ttl: i64,
}

#[derive(Args)]
pub(super) struct ClaimStyle {
    /// Share the paths with other shared claims.
    #[arg(long)]
    pub(super) shared: bool,
    /// Claim for a deploy rather than for work.
    #[arg(long)]
    pub(super) deploy: bool,
    /// A named zone or group of the catalog. Repeat for several.
    #[arg(long = "zone")]
    pub(super) zones: Vec<String>,
}

impl ClaimStyle {
    pub(super) fn mode(&self) -> ClaimMode {
        if self.shared {
            ClaimMode::Shared
        } else {
            ClaimMode::Exclusive
        }
    }

    pub(super) fn purpose(&self) -> Purpose {
        if self.deploy {
            Purpose::Deploy
        } else {
            Purpose::Work
        }
    }
}
