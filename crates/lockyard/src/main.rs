// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

mod hook;
mod mcp;

use clap::{Args, Parser, Subcommand};
use lockyard_core::bus::{BROADCAST, Message};
use lockyard_core::tasks::{Status, Task};
use lockyard_core::zones::{Claim, DEFAULT_TTL_MINUTES};
use lockyard_core::{Error, Result, Store, ZonePath};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// A path is held by another agent.
const EXIT_CONFLICT: u8 = 3;
const EXIT_FAILURE: u8 = 1;
/// Messages `lockyard msg inbox` prints at most.
const INBOX_LIMIT: usize = 200;

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
    /// Claim paths so that no other agent edits them.
    #[command(subcommand)]
    Zone(ZoneCommand),
    /// Talk to other agents.
    #[command(subcommand)]
    Msg(MsgCommand),
    /// Work that outlives a session.
    #[command(subcommand)]
    Task(TaskCommand),
    /// Agent integrations.
    #[command(subcommand)]
    Hook(HookCommand),
    /// Print setup snippets for agent tools.
    Setup { client: SetupClient },
    /// Run the MCP server over standard input and output.
    Mcp,
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

#[derive(Subcommand)]
enum ZoneCommand {
    /// Claim paths, all of them or none.
    Claim {
        #[arg(required = true)]
        paths: Vec<String>,
        /// What the claim is for.
        #[arg(long, default_value = "")]
        note: String,
        #[command(flatten)]
        ttl: Ttl,
    },
    /// Extend one claim, or all of this agent's claims.
    Renew {
        #[arg(value_parser = parse_id)]
        id: Option<i64>,
        #[command(flatten)]
        ttl: Ttl,
    },
    /// Release one claim, or all of this agent's claims.
    Release {
        #[arg(value_parser = parse_id)]
        id: Option<i64>,
    },
    /// List active claims.
    List,
    /// Exit 3 if another agent holds this path.
    Check { path: String },
}

#[derive(Subcommand)]
enum MsgCommand {
    /// Send to an agent, or to `*` for everyone.
    Send { to: String, body: String },
    /// Answer a message.
    Reply {
        #[arg(value_parser = parse_id)]
        id: i64,
        body: String,
    },
    /// Show unread mail and mark it read.
    Inbox {
        /// Include mail already read.
        #[arg(long)]
        all: bool,
        /// Do not mark anything read.
        #[arg(long)]
        peek: bool,
    },
}

#[derive(Subcommand)]
enum TaskCommand {
    /// Add an open task.
    Add {
        title: String,
        #[arg(long, default_value = "")]
        body: String,
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

#[derive(Subcommand)]
enum HookCommand {
    /// Handle a Claude Code hook event from stdin.
    Claude,
    /// Handle a Codex hook event from stdin.
    Codex,
    /// Handle a Cursor hook event from stdin.
    Cursor,
}

/// Accepts `12`, `T-12`, `Z-12` and `M-12`.
fn parse_id(text: &str) -> std::result::Result<i64, String> {
    let digits = text
        .strip_prefix(['T', 'Z', 'M', 't', 'z', 'm'])
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

fn resolve_agent(flag: Option<String>) -> Result<String> {
    flag.or_else(env_agent).ok_or_else(|| {
        Error::Invalid(
            "this command needs an agent name: set LOCKYARD_AGENT or pass --agent".into(),
        )
    })
}

/// Output of one command: the data for `--json` and the lines for a person.
struct Output {
    json: serde_json::Value,
    text: String,
}

fn output(data: &impl Serialize, text: impl Into<String>) -> Result<Output> {
    let json = serde_json::to_value(data)
        .map_err(|error| Error::Invalid(format!("cannot encode output: {error}")))?;
    Ok(Output {
        json,
        text: text.into(),
    })
}

fn minutes_left(expires_at: i64, now: i64) -> i64 {
    ((expires_at - now).max(0) + 59_999) / 60_000
}

fn claim_line(claim: &Claim, now: i64) -> String {
    let mut line = format!(
        "Z-{}  {}  {}  {} min left",
        claim.id,
        claim.agent,
        claim.paths.join(" "),
        minutes_left(claim.expires_at, now)
    );
    if !claim.note.is_empty() {
        line.push_str("  ");
        line.push_str(&claim.note);
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
        message.id, message.from, scope, message.body
    )
}

fn task_line(task: &Task) -> String {
    let assignee = task.assignee.as_deref().unwrap_or("-");
    format!(
        "T-{}  {}  {}  {}",
        task.id, task.status, assignee, task.title
    )
}

fn join<T>(items: &[T], line: impl Fn(&T) -> String, empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.iter().map(line).collect::<Vec<_>>().join("\n")
}

fn zone_paths(store: &Store, cwd: &Path, raw: &str) -> Result<ZonePath> {
    ZonePath::resolve(store.root(), cwd, raw)?
        .ok_or_else(|| Error::Invalid(format!("{raw} is outside this project")))
}

fn run_zone(
    store: &mut Store,
    command: ZoneCommand,
    agent: Option<String>,
    cwd: &Path,
) -> Result<Output> {
    let now = now_ms();
    match command {
        ZoneCommand::Claim { paths, note, ttl } => {
            let agent = resolve_agent(agent)?;
            let paths = paths
                .iter()
                .map(|raw| zone_paths(store, cwd, raw))
                .collect::<Result<Vec<_>>>()?;
            let claim = store.claim(&agent, &paths, &note, ttl.ttl, now)?;
            let text = claim_line(&claim, now);
            output(&claim, text)
        }
        ZoneCommand::Renew { id, ttl } => {
            let agent = resolve_agent(agent)?;
            let renewed = store.renew(&agent, id, ttl.ttl, now)?;
            output(
                &serde_json::json!({ "renewed": renewed }),
                format!("renewed {renewed}"),
            )
        }
        ZoneCommand::Release { id } => {
            let agent = resolve_agent(agent)?;
            let released = store.release(&agent, id, now)?;
            output(
                &serde_json::json!({ "released": released }),
                format!("released {released}"),
            )
        }
        ZoneCommand::List => {
            let claims = store.claims(now)?;
            let text = join(&claims, |claim| claim_line(claim, now), "no active claims");
            output(&claims, text)
        }
        ZoneCommand::Check { path } => {
            let agent = resolve_agent(agent)?;
            let path = zone_paths(store, cwd, &path)?;
            match store.check(&agent, &path, now)? {
                Some(conflict) => Err(Error::Conflict(vec![conflict])),
                None => output(&serde_json::json!({ "free": true }), "free"),
            }
        }
    }
}

fn run_msg(store: &mut Store, command: MsgCommand, agent: Option<String>) -> Result<Output> {
    let now = now_ms();
    let agent = resolve_agent(agent)?;
    match command {
        MsgCommand::Send { to, body } => {
            let message = store.send(&agent, &to, &body, now)?;
            output(&message, format!("sent M-{}", message.id))
        }
        MsgCommand::Reply { id, body } => {
            let message = store.reply(&agent, id, &body, now)?;
            output(&message, format!("sent M-{}", message.id))
        }
        MsgCommand::Inbox { all, peek } => {
            let mail = store.inbox(&agent, all, !peek, INBOX_LIMIT, now)?;
            let text = join(&mail, message_line, "no new mail");
            output(&mail, text)
        }
    }
}

fn run_task(store: &mut Store, command: TaskCommand, agent: Option<String>) -> Result<Output> {
    let now = now_ms();
    let changed = match command {
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
            let data = serde_json::json!({ "task": task, "history": history });
            return output(&data, lines.join("\n"));
        }
        TaskCommand::Add { title, body } => {
            store.add_task(&resolve_agent(agent)?, &title, &body, now)?
        }
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

fn run_status(store: &Store, agent: Option<String>) -> Result<Output> {
    let now = now_ms();
    let claims = store.claims(now)?;
    let tasks = store.tasks(None, false)?;
    let agent = agent.or_else(env_agent);
    let unread = agent
        .as_deref()
        .map(|name| store.unread(name))
        .transpose()?;
    let mut lines = Vec::new();
    if let Some(unread) = unread {
        lines.push(format!("unread mail: {unread}"));
    }
    lines.push(join(
        &claims,
        |claim| claim_line(claim, now),
        "no active claims",
    ));
    lines.push(join(&tasks, task_line, "no tasks"));
    let data = serde_json::json!({ "unread": unread, "claims": claims, "tasks": tasks });
    output(&data, lines.join("\n"))
}

fn run_hook(command: HookCommand, agent: Option<String>, cwd: &Path) -> Output {
    let text = match command {
        client @ (HookCommand::Claude | HookCommand::Codex | HookCommand::Cursor) => {
            let mut input = String::new();
            let read = std::io::stdin().read_to_string(&mut input);
            let answer = read.map_err(Error::Io).and_then(|_| {
                match client {
                    HookCommand::Claude => hook::claude(&input, agent.or_else(env_agent_explicit), cwd, now_ms()),
                    HookCommand::Codex => hook::codex(&input, agent.or_else(env_agent_explicit), cwd, now_ms()),
                    HookCommand::Cursor => hook::cursor(&input, agent.or_else(env_agent_explicit), cwd, now_ms()),
                }
            });
            answer.unwrap_or_else(|error| {
                eprintln!("lockyard hook: {error}");
                None
            })
        }
    };
    Output {
        json: serde_json::Value::Null,
        text: text.unwrap_or_default(),
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
            "Add to ~/.codex/config.toml:\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]"
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

fn run(cli: Cli, cwd: &Path) -> Result<Output> {
    let Cli { agent, command, .. } = cli;
    match command {
        Command::Init => {
            let store = Store::init(cwd)?;
            let root = store.root().display().to_string();
            output(
                &serde_json::json!({ "root": root }),
                format!("Lockyard project at {root}"),
            )
        }
        Command::About => output(
            &serde_json::json!({ "version": lockyard_core::VERSION }),
            lockyard_core::about(),
        ),
        Command::Who => {
            let store = Store::discover(cwd)?;
            let now = now_ms();
            let agents = store.agents()?;
            let text = join(
                &agents,
                |agent| {
                    format!(
                        "{}  seen {} min ago",
                        agent.id,
                        (now - agent.last_seen) / 60_000
                    )
                },
                "no agents yet",
            );
            output(&agents, text)
        }
        Command::Status => run_status(&Store::discover(cwd)?, agent),
        Command::Zone(command) => run_zone(&mut Store::discover(cwd)?, command, agent, cwd),
        Command::Msg(command) => run_msg(&mut Store::discover(cwd)?, command, agent),
        Command::Task(command) => run_task(&mut Store::discover(cwd)?, command, agent),
        Command::Hook(command) => Ok(run_hook(command, agent, cwd)),
        Command::Setup { client } => Ok(Output {
            json: serde_json::Value::Null,
            text: setup(client),
        }),
        Command::Mcp => Ok(Output {
            json: serde_json::Value::Null,
            text: String::new(),
        }),
    }
}

fn current_dir() -> Result<PathBuf> {
    Ok(std::env::current_dir()?)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    let result = if matches!(&cli.command, Command::Mcp) {
        let agent = cli.agent.clone().or_else(env_lockyard_agent);
        return match current_dir().and_then(|cwd| mcp::serve(agent, &cwd).map_err(Error::Io)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(EXIT_FAILURE)
            }
        };
    } else {
        current_dir().and_then(|cwd| run(cli, &cwd))
    };
    match result {
        Ok(out) if json => {
            println!("{}", out.json);
            ExitCode::SUCCESS
        }
        Ok(out) => {
            if !out.text.is_empty() {
                println!("{}", out.text);
            }
            ExitCode::SUCCESS
        }
        Err(Error::Conflict(conflicts)) => {
            let error = Error::Conflict(conflicts);
            eprintln!("{error}");
            ExitCode::from(EXIT_CONFLICT)
        }
        Err(error) => {
            eprintln!("{error}");
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
    fn ids_read_with_or_without_a_prefix() {
        assert_eq!(parse_id("12"), Ok(12));
        assert_eq!(parse_id("T-12"), Ok(12));
        assert_eq!(parse_id("z-3"), Ok(3));
        assert!(parse_id("T12").is_err());
        assert!(parse_id("nope").is_err());
    }

    #[test]
    fn minutes_round_up_and_stop_at_zero() {
        assert_eq!(minutes_left(60_001, 0), 2);
        assert_eq!(minutes_left(60_000, 0), 1);
        assert_eq!(minutes_left(0, 5), 0);
    }
}
