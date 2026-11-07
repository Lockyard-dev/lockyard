// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[derive(clap::ValueEnum, Clone, Copy)]
pub(super) enum StreamName {
    Coordination,
    Registry,
}

#[derive(Args)]
pub(super) struct EventsArgs {
    /// Show events after this sequence.
    #[arg(long, default_value_t = 0)]
    pub(super) after: i64,
    /// Wait for news, at most 25 seconds.
    #[arg(long, default_value_t = 0)]
    pub(super) wait: u64,
    #[arg(long, value_enum, default_value = "coordination")]
    pub(super) stream: StreamName,
    /// Only these types. Repeat for several.
    #[arg(long = "type")]
    pub(super) types: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Copy)]
pub(super) enum StateName {
    Working,
    Idle,
    Ended,
    ApiFailure,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum PresenceCommand {
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
pub(super) struct AgentArgs {
    #[command(subcommand)]
    pub(super) command: Option<AgentCommand>,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum AgentCommand {
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
#[command(defer = true)]
pub(super) enum CloudCommand {
    /// Trust a server URL before sending a user token to it.
    Trust { url: String },
    /// Sign in to a cloud workspace from the browser and store the token for this machine.
    Login {
        /// The server to sign in to. Taken from this project's config when left out.
        #[arg(long)]
        url: Option<String>,
        /// Print the code and URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Forget the token stored for a server on this machine.
    Logout {
        /// The server to forget. Taken from this project's config when left out.
        #[arg(long)]
        url: Option<String>,
    },
    /// Dump coordination state. Needs the owner or exporter role.
    Export,
    /// Freeze or unfreeze coordination writes. Needs the owner role.
    Freeze {
        #[arg(value_parser = parse_switch, action = clap::ArgAction::Set)]
        state: bool,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Free a session name still bound to an old token, e.g. after the agent's token was reissued.
    /// Needs the owner or lead role. A name also frees itself after seven silent days with no mail left.
    ReleaseSession { session: String },
    /// Store the zone catalog from a JSON file. Needs the importer role.
    ImportZones { file: PathBuf },
    /// Import threads, the board and tasks from a JSON file. Needs the importer role.
    ImportBus { file: PathBuf },
    /// Import registry items. Needs the importer role.
    ImportRegistry { file: PathBuf },
    /// Manage registry areas.
    #[command(subcommand)]
    Area(CloudAreaCommand),
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
#[command(defer = true)]
pub(super) enum CloudAreaCommand {
    List,
    Create {
        key: String,
        name: String,
        prefix: String,
        #[arg(long, default_value_t = 4)]
        pad: u8,
    },
    Update {
        key: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        pad: Option<u8>,
    },
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum KeyCommand {
    /// Generate and store a workspace key locally.
    Create,
    /// Show the recovery phrase after typing SHOW.
    ShowPhrase,
    /// Read a 24 word recovery phrase from stdin and store its key.
    Import,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum EncryptionCommand {
    /// Show encryption mode and whether this machine has the matching key.
    Status,
    /// Require client-side content encryption. Needs the owner role and a local key.
    Require,
    /// Turn off the workspace encryption requirement. Needs the owner role.
    Off,
}

#[derive(Subcommand)]
#[command(defer = true)]
pub(super) enum TokenCommand {
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
#[command(defer = true)]
pub(super) enum HookCommand {
    /// Refuse a path claimed by another session.
    Check {
        #[arg(long)]
        path: String,
    },
    /// Handle a Claude Code hook event from stdin.
    Claude,
    /// Handle a Codex hook event from stdin.
    Codex,
    /// Handle a Cursor hook event from stdin.
    Cursor,
}
