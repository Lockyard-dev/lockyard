// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

mod agent;
mod context;
mod guard;
mod hook;
mod keepalive;
mod mail_wait;
mod mcp;
mod monitor;
mod node_cli;
mod notifications;
mod onboarding;
mod open;
mod open_mail;
mod revoke_access;
mod session_label;
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
use lockyard_core::tasks::{Status, Task, TaskPlan, TaskSpec, TaskTriage};
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
/// Cloud mail / path-request commands without a usable token (META-0033).
const EXIT_NO_CLOUD_ACCESS: u8 = 5;
const NO_CLOUD_ACCESS_TEXT: &str =
    "почта и запросы путей недоступны: нет доступа к облаку (LOCKYARD_TOKEN_FILE …)";
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
    env_agent_from(|name| std::env::var(name).ok())
}

fn env_agent_from(mut lookup: impl FnMut(&str) -> Option<String>) -> Option<String> {
    ["LOCKYARD_AGENT", "CLAUDE_CODE_SESSION_ID"]
        .iter()
        .find_map(|name| lookup(name).filter(|value| !value.is_empty()))
}

fn resolve_agent(flag: Option<&String>) -> Result<String> {
    flag.cloned().or_else(env_agent).ok_or_else(|| {
        Error::Invalid(
            "this command needs an agent name: set LOCKYARD_AGENT or pass --agent".into(),
        )
    })
}

/// When cloud mode has no token and the agent path is unavailable, mail and path-request
/// surfaces exit with a dedicated code. A running agent still serves tokenless CLI callers
/// (`status_read` / `cloud()`).
fn no_cloud_access_output(cwd: &Path, session: Option<&str>) -> Result<Option<Output>> {
    use lockyard_core::config::{Config, Mode};
    let Some(root) = lockyard_core::paths::find_root(cwd) else {
        return Ok(None);
    };
    let config = Config::load(&root)?;
    if config.mode != Mode::Cloud {
        return Ok(None);
    }
    let Ok((url, workspace)) = open::endpoint(&config) else {
        return Ok(None);
    };
    if lockyard_core::config::optional_session_token(&url, session.unwrap_or("lockyard-cli"))?
        .is_some()
    {
        return Ok(None);
    }
    let socket = crate::agent::socket_path_for(&url, &workspace);
    // An existing endpoint may be busy. Let the normal command route wait within its
    // own budget instead of turning a short handshake timeout into "no access".
    // This guard is used by mail/path-request commands, never PreToolUse.
    if socket.exists() {
        return Ok(None);
    }
    let probe = no_access_probe_budget();
    // Also probe named pipes on Windows, which have no filesystem socket entry.
    if no_access_probe_allows_route(
        crate::agent::socket::AgentSocket::status(&socket, probe),
        &url,
        &workspace,
    ) {
        return Ok(None);
    }
    let mut out = output(
        &json!({"error": "no_cloud_access", "exit": EXIT_NO_CLOUD_ACCESS}),
        NO_CLOUD_ACCESS_TEXT,
    )?;
    out.exit = EXIT_NO_CLOUD_ACCESS;
    Ok(Some(out))
}

fn no_access_probe_allows_route(
    result: std::io::Result<crate::agent::wire::AgentStatus>,
    url: &str,
    workspace: &str,
) -> bool {
    match result {
        Ok(status) => {
            status.url.trim_end_matches('/') == url.trim_end_matches('/')
                && status.workspace == workspace
        }
        // A busy pipe or slow handshake is inconclusive; the command keeps its normal budget.
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
    }
}

fn no_access_probe_budget() -> std::time::Duration {
    std::time::Duration::from_millis(250)
}

/// Outcome of an optional path-request peek on a hot path.
#[derive(Debug, Clone)]
enum IncomingFetch {
    /// Local mode / not a cloud surface — omit the field entirely.
    NotApplicable,
    /// Cloud path where requests were not read or the read failed — never an empty array.
    Unknown,
    /// Successful read (possibly empty).
    Known(Vec<lockyard_core::proto::AccessRecord>),
}

fn attach_incoming(data: &mut Value, lines: &mut Vec<String>, fetch: IncomingFetch) {
    match fetch {
        IncomingFetch::Known(records) => {
            data["incoming_requests"] = incoming_requests_json(&records);
            lines.extend(incoming_request_lines(&records));
        }
        IncomingFetch::Unknown => {
            data["incoming_requests_unknown"] = json!(true);
        }
        IncomingFetch::NotApplicable => {}
    }
}

/// Unanswered path requests aimed at this session's claims (META-0032).
fn incoming_path_requests(
    records: Vec<lockyard_core::proto::AccessRecord>,
    session: &str,
) -> Vec<lockyard_core::proto::AccessRecord> {
    records
        .into_iter()
        .filter(|record| {
            record.reply.is_none()
                && record.from != session
                && record
                    .holder
                    .as_deref()
                    .is_none_or(|holder| holder == session)
        })
        .collect()
}

fn incoming_request_lines(records: &[lockyard_core::proto::AccessRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| {
            format!(
                "запрос пути R-{} от {} на {} — ответь `lockyard zone answer`",
                record.id,
                record.from,
                record.paths.join(" ")
            )
        })
        .collect()
}

fn incoming_requests_json(records: &[lockyard_core::proto::AccessRecord]) -> Value {
    json!(
        records
            .iter()
            .map(|record| {
                json!({
                    "id": record.id,
                    "from": record.from,
                    "paths": record.paths,
                    "at": record.created_at,
                })
            })
            .collect::<Vec<_>>()
    )
}

/// Work to do once a command's output is out, such as marking printed mail.
pub(crate) type After = Box<dyn FnOnce() -> Result<()>>;

fn run(cli: Cli, cwd: &Path) -> Result<Output> {
    let Cli {
        agent,
        token_file,
        json,
        command,
    } = cli;
    if let Some(path) = token_file {
        // CLI dispatch precedes all worker threads and cloud clients.
        unsafe {
            std::env::set_var("LOCKYARD_TOKEN_FILE", path);
        }
    }
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
        Command::Status { lost } => {
            if let Some(out) = no_cloud_access_output(cwd, name.as_deref())? {
                return Ok(out);
            }
            if lost {
                run_zone(open()?, ZoneCommand::Lost, agent.as_ref(), cwd)
            } else {
                run_status_command(cwd, agent.as_ref())
            }
        }
        Command::Zone(command) => {
            if matches!(command, ZoneCommand::Requests)
                && let Some(out) = no_cloud_access_output(cwd, name.as_deref())?
            {
                return Ok(out);
            }
            let opened = if matches!(command, ZoneCommand::WaitFree { .. }) {
                open::open_zone_wait(cwd, name.as_deref())?
            } else {
                open()?
            };
            run_zone(opened, command, agent.as_ref(), cwd)
        }
        Command::Mail(_) => unreachable!("mail wait is handled before opening a backend"),
        Command::Msg(command) => {
            if matches!(command, MsgCommand::Inbox { .. } | MsgCommand::Open)
                && let Some(out) = no_cloud_access_output(cwd, name.as_deref())?
            {
                return Ok(out);
            }
            run_msg(open()?, command, agent.as_ref())
        }
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
        Command::Cloud(command @ CloudCommand::ReleaseSession { .. }) => run_cloud(
            open::open(cwd, None)?,
            command,
            Some(&"lockyard-cli".to_string()),
        ),
        Command::Cloud(command) => run_cloud(open()?, command, agent.as_ref()),
        Command::Keepalive { id, all } => run_keepalive(open()?, agent.as_ref(), id, all),
        Command::Ping { path } => run_ping(cwd, agent.as_ref(), path),
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
            repair_pending,
            forget_unknown,
            confirm,
            client,
            smoke,
            node_config,
        } => {
            if repair_pending || forget_unknown.is_some() {
                if forget_unknown.is_some() && !confirm {
                    return Err(Error::Invalid("repeat `lockyard doctor --forget-unknown <id|--all>` with --confirm to move the selected operations to the quarantine log".into()));
                }
                let root = lockyard_core::paths::find_root(cwd)
                    .ok_or_else(|| Error::Invalid("no Lockyard project found".into()))?;
                let config = lockyard_core::config::Config::load(&root)?;
                let (url, _) = open::endpoint(&config)?;
                open::trusted_url(&url)?;
                let session = agent
                    .clone()
                    .or_else(env_agent)
                    .unwrap_or_else(|| "lockyard-cli".into());
                // Reconcile with original credentials and wire bytes; preserve all rows offline.
                let token = lockyard_core::config::Config::token_for_session(&url, &session)?;
                let client = lockyard_cloud_client::Client::new(&url, token)?
                    .with_trusted_replica(open::trusted_drain_replica);
                if let Some(selection) = forget_unknown {
                    let count =
                        client.forget_unknown_journal(open::pending_journal_root()?, &selection)?;
                    return output(
                        &serde_json::json!({"forgotten_unknown":count}),
                        format!("Archived {count} unknown operations in quarantine.log."),
                    );
                }
                let report = client
                    .with_pending_encryption_policy()
                    .repair_pending_journal(open::pending_journal_root()?)?;
                let mut diagnostics = Vec::new();
                if !report.unknown_ids.is_empty() {
                    diagnostics.push(format!("Unknown ids: {}", report.unknown_ids.join(", ")));
                }
                for id in &report.drain_instance_mismatch {
                    diagnostics.push(format!(
                        "Drain {id}: original replica unresolved. Contact its trusted origin to verify the outcome, or archive with `lockyard doctor --forget-unknown {id} --confirm`."
                    ));
                }
                return output(
                    &serde_json::json!({"pending_repair":report,"network":!report.network_required}),
                    format!(
                        "Pending reconciliation: {} applied, {} rejected, {} quarantined, {} eligible records remaining. {} {} {}",
                        report.applied,
                        report.rejected,
                        report.quarantined,
                        report.remaining,
                        if report.outcome_unknown > 0 {
                            format!(
                                "{} outcome_unknown without safe replay. Current state matches {} requests.",
                                report.outcome_unknown, report.state_observed
                            )
                        } else {
                            String::new()
                        },
                        if report.network_required {
                            "Нужна сеть (network required); unresolved operations retained."
                        } else {
                            ""
                        },
                        diagnostics.join("\n"),
                    ),
                );
            }
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
            // serde_json::to_string escapes all controls; Display is the same, but keep one path.
            let encoded = serde_json::to_string(&out.json)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writeln!(stdout, "{encoded}")?;
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
    if let Some(path) = &cli.token_file {
        // Startup precedes MCP, mail wait and all worker threads.
        unsafe {
            std::env::set_var("LOCKYARD_TOKEN_FILE", path);
        }
    }
    if let Command::Mail(MailCommand::Wait { session, timeout }) = &cli.command {
        let session = session
            .clone()
            .or_else(env_agent)
            .or_else(mail_wait::hook_session);
        return ExitCode::from(
            session
                .and_then(|session| {
                    current_dir()
                        .ok()
                        .map(|cwd| mail_wait::run(&cwd, &session, Duration::from_secs(*timeout)))
                })
                .unwrap_or(0),
        );
    }
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
    let is_zone_wait = matches!(&cli.command, Command::Zone(ZoneCommand::WaitFree { .. }));
    let is_hook = matches!(&cli.command, Command::Hook(_));
    let is_service = matches!(&cli.command, Command::Agent(args) if args.command.is_none());
    let session = cli.agent.clone().or_else(env_agent);
    let result = current_dir().and_then(|cwd| run(cli, &cwd));
    if !is_service
        && let (Ok(cwd), Some(session)) = (current_dir(), session)
        && let Some(warning) = open::session_key_warning(&cwd, &session)
    {
        eprintln!("{warning}");
    }
    match result {
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
        Err(error) if is_zone_wait => {
            report(&error, json);
            ExitCode::from(2)
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
