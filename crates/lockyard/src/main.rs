// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

mod agent;
mod context;
mod guard;
mod hook;
mod mcp;
mod monitor;
mod node_cli;
mod onboarding;
mod open;
mod revoke_access;
mod setup;
mod shutdown;
mod workflow;

use clap::{Args, Parser, Subcommand};
use lockyard_core::bus::BROADCAST;
use lockyard_core::proto::{
    AccessAnswer, AccessRequest, ActivityRequest, BoardEntry, BoardWrite, CheckStatus, Claim,
    ClaimMode, ClaimQuery, ClaimRequest, DirtyPath, EventQuery, Freeze, InboxPage, InboxQuery,
    Message, PresenceBeat, Purpose, QueueRequest, ReleaseRequest, RenewRequest, SendRequest,
    SessionActivity, SessionState, Stamp, Stream, TokenRequest, WorkAction, WorkOffer, WorkStep,
    WorkTask, rfc3339,
};
use lockyard_core::tasks::{Status, Task, TaskPlan, TaskSpec};
use lockyard_core::zones::{DEFAULT_TTL_MINUTES, validate_claim_path_count};
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

#[path = "cli/base.rs"]
mod cli_base;
use cli_base::*;
#[path = "cli/types_coordination.rs"]
mod cli_types_coordination;
use cli_types_coordination::*;
#[path = "cli/types_admin.rs"]
mod cli_types_admin;
use cli_types_admin::*;
#[path = "cli/output.rs"]
mod cli_output;
use cli_output::*;
#[path = "cli/zones.rs"]
mod cli_zones;
use cli_zones::*;
#[path = "cli/messages.rs"]
mod cli_messages;
use cli_messages::*;
#[path = "cli/tasks.rs"]
mod cli_tasks;
use cli_tasks::*;
#[path = "cli/coordination.rs"]
mod cli_coordination;
use cli_coordination::*;
#[path = "cli/cloud.rs"]
mod cli_cloud;
use cli_cloud::*;
#[path = "cli/status.rs"]
mod cli_status;
use cli_status::*;
#[path = "cli/integration.rs"]
mod cli_integration;
use cli_integration::*;
#[path = "cli/agent.rs"]
mod cli_agent;
use cli_agent::*;
#[path = "cli/db.rs"]
mod cli_db;
use cli_db::*;

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

fn task_key(text: &str) -> std::result::Result<String, String> {
    lockyard_compat::LegacyCompatibilityV1::task_id(
        &Value::String(text.into()),
        lockyard_compat::TaskDomain::Registry,
        lockyard_compat::Source::Cli,
        2,
    )
}

fn bus_key(text: &str) -> std::result::Result<String, String> {
    lockyard_compat::LegacyCompatibilityV1::task_id(
        &Value::String(text.into()),
        lockyard_compat::TaskDomain::Bus,
        lockyard_compat::Source::Cli,
        2,
    )
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

fn run(cli: Cli, cwd: &Path) -> Result<Output> {
    let Cli {
        agent,
        json,
        command,
    } = cli;
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
            &json!({ "version": lockyard_core::VERSION, "build": lockyard_core::build_info() }),
            lockyard_core::about(),
        ),
        Command::Db(command) => run_db(command, cwd),
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
        Command::Cloud(CloudCommand::Login { url, no_browser }) => {
            run_cloud_login(cwd, url, no_browser)
        }
        Command::Cloud(CloudCommand::Logout { url }) => run_cloud_logout(cwd, url),
        Command::Cloud(CloudCommand::Key(command)) => run_cloud_key(cwd, command),
        Command::Cloud(CloudCommand::Encryption(command)) => run_cloud_encryption(cwd, command),
        Command::Cloud(command) => run_cloud(open()?, command, agent.as_ref()),
        Command::Revoke(command) => {
            let (target, config) = command.parts();
            let result = revoke_access::execute(cwd, target, config)?;
            let exit = result.exit();
            let summary = if let Some(hint) = result.hint.as_deref() {
                format!(
                    "{}: {hint}",
                    result.code.as_deref().unwrap_or("revocation failed")
                )
            } else if result.propagation_complete {
                "Access revoked and propagated".into()
            } else {
                "Revocation incomplete; inspect JSON outcome".into()
            };
            let mut rendered = output(&result, summary)?;
            rendered.exit = exit;
            Ok(rendered)
        }
        Command::Hook(command) => run_hook(command, agent, cwd),
        Command::Monitor(args) => run_monitor(args, agent.as_ref(), cwd, json),
        Command::Setup(args) => run_setup(args, cwd),
        Command::Doctor {
            client,
            smoke,
            node_config,
        } => {
            if let Some(path) = node_config.as_deref() {
                let data = node_cli::native_doctor(path)?;
                let exit = if data["healthy"].as_bool() == Some(true) {
                    0
                } else {
                    1
                };
                let mut rendered = output(
                    &data,
                    serde_json::to_string_pretty(&data)
                        .map_err(|error| Error::Invalid(error.to_string()))?,
                )?;
                rendered.exit = exit;
                return Ok(rendered);
            }

            if client.is_none() && !smoke {
                let data = onboarding::doctor(cwd, agent.as_deref(), None, false)?;
                // Invalid configuration is intentionally summarized without leaking tokens.
                if data["checks"].as_array().is_some_and(|checks| {
                    checks
                        .iter()
                        .any(|check| check["name"] == "configuration" && check["state"] == "failed")
                }) {
                    return onboarding_output(data);
                }
                run_doctor(cwd, agent.as_ref())
            } else {
                onboarding_output(onboarding::doctor(
                    cwd,
                    agent.as_deref(),
                    client.as_deref(),
                    smoke,
                )?)
            }
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
        Command::Node(command) => node_output(node_cli::node(command)?),
        Command::Job(command) => node_output(node_cli::job(command)?),
        Command::Mcp(_) => output(&Value::Null, ""),
    }
}

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
        let mut detail =
            json!({"code":error.kind(),"kind":error.kind(),"message":error.to_string()});
        if let Error::Cloud {
            code,
            status,
            details,
            ..
        } = error
        {
            detail["code"] = json!(code);
            detail["status"] = json!(status);
            detail["details"] = details.clone();
        }
        eprintln!("{}", json!({"error":detail}));
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
    let _total = lockyard_core::perf::Span::new("process.main");
    #[cfg(windows)]
    let _sqlite_io = {
        // SAFETY: CLI startup is single-threaded here; no SQLite connection or
        // runtime has been created. The opt-in VFS probes forward every syscall.
        unsafe { lockyard_core::perf::windows_sqlite::install_before_threads() };
        struct FlushSqliteIo;
        impl Drop for FlushSqliteIo {
            fn drop(&mut self) {
                lockyard_core::perf::windows_sqlite::flush();
            }
        }
        FlushSqliteIo
    };
    #[cfg(unix)]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|value| value == "__native-sandbox")
    {
        return ExitCode::from(lockyard_node::native::sandbox_main() as u8);
    }
    let parsing = lockyard_core::perf::Span::new("process.parse");
    let cli = Cli::parse();
    drop(parsing);
    let json = cli.json;
    if let Command::Mcp(args) = &cli.command {
        let surface = match mcp::Surface::choose(args.tools.as_deref()) {
            Ok(surface) => surface,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(EXIT_FAILURE);
            }
        };
        // As --help promises: LOCKYARD_AGENT, then CLAUDE_CODE_SESSION_ID. Without the fallback a Claude Code
        // session spoke under the shared anonymous name (D-3178 bug hunt, item 1).
        let agent = cli.agent.clone().or_else(env_agent);
        return match current_dir()
            .and_then(|cwd| mcp::serve(agent, &cwd, surface).map_err(Error::Io))
        {
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
                if error.kind() == std::io::ErrorKind::BrokenPipe {
                    return ExitCode::SUCCESS;
                }
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
        Err(
            error @ (Error::Conflict(_)
            | Error::Contended(_)
            | Error::Cloud {
                status: Some(409), ..
            }),
        ) => {
            report(&error, json);
            ExitCode::from(EXIT_CONFLICT)
        }
        Err(error) => {
            report(&error, json);
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

#[cfg(test)]
#[path = "cli/output_escape_tests.rs"]
mod output_escape_tests;

#[cfg(test)]
#[path = "cli/tests.rs"]
mod tests;
