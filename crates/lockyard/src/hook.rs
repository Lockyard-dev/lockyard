// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Agent tool hooks. They stop an edit of a path another agent holds and deliver unread mail.
//!
//! A coordination tool must not wedge the agent it serves for mail and presence: when those fail the
//! hook reports on stderr and continues. Zone checks are different: an unknown or unreachable view
//! refuses the edit (fail closed), so a stale mirror can never allow a write the server would refuse.
//!
//! Mail delivery has two phases: reserve the mail, write it out, and only then mark it seen. A hook that
//! dies in between shows the mail again next time, a duplicate over a loss.
//!
//! In cloud mode a hook talks to the agent socket and nothing else: no HTTP and no async runtime.

use lockyard_core::config::{Config, Mode};
use lockyard_core::proto::{Event, InboxQuery, Message};
use lockyard_core::zones::Conflict;
use lockyard_core::{Backend, Result, Store, ZonePath};
use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Mail shown per hook call. The rest arrives on the next one.
const MAIL_PER_CALL: usize = 5;
/// Characters of one message shown in context.
const MAIL_BODY_CHARS: usize = 1000;
/// How long one hook holds the exclusive right to show a message.
const DELIVERY_LEASE_SECONDS: i64 = 60;

const EDIT_TOOLS: [&str; 10] = [
    "Edit",
    "Write",
    "MultiEdit",
    "NotebookEdit",
    "edit",
    "write",
    "multi_edit",
    "notebook_edit",
    "edit_file",
    "write_file",
];

/// Lines for `.claude/settings.json`.
pub const SETTINGS: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit|NotebookEdit|Bash",
        "hooks": [{ "type": "command", "command": "lockyard hook claude" }]
      }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "lockyard hook claude" }] }
    ],
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "lockyard hook claude" }] }
    ],
    "SessionEnd": [
      { "hooks": [{ "type": "command", "command": "lockyard hook claude" }] }
    ]
  }
}"#;

/// Which tool sent the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Claude,
    Codex,
    Cursor,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }
}

/// When in a tool call a hook runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Moment {
    Before,
    After,
    Prompt,
    End,
}

/// What a hook learned about a path.
#[derive(Debug, PartialEq)]
enum Verdict {
    Free,
    Held(Box<Conflict>),
    /// The state could not be learned in time. A hook refuses the edit (fail closed).
    Unknown,
}

/// What a hook needs, in either mode.
trait Port {
    fn root(&self) -> &Path;
    fn check(&mut self, agent: &str, path: &str, now: i64) -> Result<Verdict>;
    /// `None` means the count is unknown.
    fn unread(&mut self, agent: &str) -> Result<Option<i64>>;
    /// Reserves mail for this hook. `None` means unknown.
    fn take_mail(&mut self, agent: &str, limit: usize, now: i64) -> Result<Option<Vec<Message>>>;
    fn mark_seen(&mut self, agent: &str, ids: &[i64], now: i64) -> Result<()>;
    fn take_events(&mut self, _agent: &str) -> Result<Option<Vec<Event>>> {
        Ok(Some(Vec::new()))
    }
    fn ack_events(&mut self, _agent: &str, _through: i64) -> Result<()> {
        Ok(())
    }
    fn report(&mut self, agent: &str, moment: Moment, written: Vec<String>);
}

struct LocalPort {
    store: Store,
    root: PathBuf,
    now: i64,
}

impl Port for LocalPort {
    fn root(&self) -> &Path {
        &self.root
    }

    fn check(&mut self, agent: &str, path: &str, now: i64) -> Result<Verdict> {
        let path = ZonePath::stored(path.to_string());
        Ok(match self.store.check(agent, &path, now)? {
            Some(conflict) => Verdict::Held(Box::new(conflict)),
            None => Verdict::Free,
        })
    }

    fn unread(&mut self, agent: &str) -> Result<Option<i64>> {
        Ok(Some(Backend::unread(&self.store, agent)?))
    }

    fn take_mail(&mut self, agent: &str, limit: usize, now: i64) -> Result<Option<Vec<Message>>> {
        let page = Backend::inbox(
            &mut self.store,
            agent,
            InboxQuery { all: false, limit },
            now,
        )?;
        let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
        let channel = format!("hook-{}", std::process::id());
        let granted = Backend::inbox_claim(
            &mut self.store,
            agent,
            &channel,
            &ids,
            DELIVERY_LEASE_SECONDS,
            now,
        )?;
        Ok(Some(
            page.messages
                .into_iter()
                .filter(|message| granted.contains(&message.id))
                .collect(),
        ))
    }

    fn mark_seen(&mut self, agent: &str, ids: &[i64], now: i64) -> Result<()> {
        Backend::inbox_seen(&mut self.store, agent, ids, now)?;
        Ok(())
    }

    fn report(&mut self, agent: &str, _moment: Moment, _written: Vec<String>) {
        let _ = self.store.touch_best_effort(agent, self.now);
    }
}

#[cfg(unix)]
mod cloud;
/// Reads one event from `input` and writes the hook's answer to `out`.
pub fn run(
    tool: Tool,
    input: &str,
    agent_override: Option<String>,
    fallback_cwd: &Path,
    now: i64,
    out: &mut dyn Write,
) -> Result<()> {
    let Ok(mut event) = serde_json::from_str::<Value>(input) else {
        return Ok(());
    };
    if tool == Tool::Cursor {
        normalize_cursor(&mut event);
    }
    match run_event(tool, &event, agent_override, fallback_cwd, now, out) {
        Err(error) if is_pre_tool_edit(&event) => deny_failed_check(tool, &event, error, out),
        answer => answer,
    }
}

fn run_event(
    tool: Tool,
    event: &Value,
    agent_override: Option<String>,
    fallback_cwd: &Path,
    now: i64,
    out: &mut dyn Write,
) -> Result<()> {
    let text = |key: &str| event.get(key).and_then(Value::as_str);
    let cwd = text("cwd").map_or_else(|| fallback_cwd.to_path_buf(), PathBuf::from);
    let Some(root) = lockyard_core::paths::find_root(&cwd) else {
        return deny_unchecked_edit(
            tool,
            event,
            "Lockyard cannot check this edit because no project root is available. Run the client from the project, then retry.",
            out,
        );
    };
    let Some(agent) = agent_override.or_else(|| text("session_id").map(str::to_string)) else {
        return deny_unchecked_edit(
            tool,
            event,
            "Lockyard cannot check this edit because the client did not provide a session identity. Restart the client session, then retry.",
            out,
        );
    };
    let config = match Config::load(&root) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("lockyard hook: config unavailable ({error}).");
            return deny_unchecked_edit(
                tool,
                event,
                "Lockyard: project configuration is unavailable, so this edit cannot be checked. Fix `.lockyard/config.toml` or run `lockyard doctor`, then retry.",
                out,
            );
        }
    };
    if config.mode == Mode::Cloud {
        return run_cloud(tool, event, &agent, &cwd, root, &config, now, out);
    }
    let store = Store::open(&root)?;
    let mut port = LocalPort { store, root, now };
    let machine = lockyard_core::machine::MachineConfig::load_user();
    handle(tool, &mut port, event, &agent, &cwd, now, &machine, out)
}

fn is_pre_tool_edit(event: &Value) -> bool {
    event.get("hook_event_name").and_then(Value::as_str) == Some("PreToolUse")
        && event
            .get("tool_name")
            .and_then(Value::as_str)
            .is_some_and(|name| EDIT_TOOLS.contains(&name))
}

fn deny_failed_check(
    tool: Tool,
    event: &Value,
    error: lockyard_core::Error,
    out: &mut dyn Write,
) -> Result<()> {
    eprintln!("lockyard hook: edit check unavailable ({error}).");
    deny_unchecked_edit(
        tool,
        event,
        "Lockyard cannot check this edit because its zone check failed. Run `lockyard doctor` and retry when coordination is available.",
        out,
    )
}

/// Refuses an edit when the hook lacks information required to check its lock.
fn deny_unchecked_edit(tool: Tool, event: &Value, reason: &str, out: &mut dyn Write) -> Result<()> {
    if !is_pre_tool_edit(event) {
        return Ok(());
    }
    let text = if tool == Tool::Cursor {
        json!({"permission":"deny","agent_message":reason}).to_string()
    } else {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
        .to_string()
    };
    emit(out, &text)
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_cloud(
    tool: Tool,
    event: &Value,
    agent: &str,
    cwd: &Path,
    root: PathBuf,
    config: &Config,
    now: i64,
    out: &mut dyn Write,
) -> Result<()> {
    // The legacy agent handshake cannot attest the workspace key or required encryption
    // policy. Like open::cloud, never use it in a required-E2EE context, even if a
    // marker is empty or invalid. Mail and presence remain nonblocking; edits still require
    // an authoritative zone check and fail closed when the legacy peer cannot provide one.
    if std::env::var_os("LOCKYARD_REQUIRE_E2EE").is_some()
        || std::env::var_os("LOCKYARD_E2EE_WORKSPACE_ID").is_some()
    {
        eprintln!(
            "lockyard hook: cloud coordination unavailable in required E2EE mode; refusing unchecked edits; mail delivery unavailable."
        );
        return deny_unchecked_edit(
            tool,
            event,
            "Lockyard cannot check this edit because the local agent cannot verify the required E2EE workspace policy. Use an agent that supports this encryption policy, then retry.",
            out,
        );
    }
    let (url, workspace) = crate::open::endpoint(config)?;
    let Some(mut port) = cloud::connect(&url, &workspace, root, tool) else {
        // Fail closed: without the agent there is no zone mirror, so an edit cannot be allowed.
        return deny_cloud_unavailable(tool, event, out);
    };
    let machine = lockyard_core::machine::MachineConfig::load_user();
    handle(tool, &mut port, event, agent, cwd, now, &machine, out)
}

/// Refuses a PreToolUse edit when cloud mode has no agent process to answer from.
fn deny_cloud_unavailable(tool: Tool, event: &Value, out: &mut dyn Write) -> Result<()> {
    if event.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse") {
        eprintln!(
            "lockyard hook: no agent process for this workspace. Start one with `lockyard agent install`."
        );
        return Ok(());
    }
    // Non-edit tools still need a running agent for presence, but they are not refused here.
    let is_edit = event
        .get("tool_name")
        .and_then(Value::as_str)
        .is_some_and(|name| EDIT_TOOLS.contains(&name));
    if !is_edit {
        eprintln!(
            "lockyard hook: no agent process for this workspace. Start one with `lockyard agent install`."
        );
        return Ok(());
    }
    let reason = "Lockyard: cloud mode needs a running agent to answer zone checks. \
                  Start one with `lockyard agent install`, then retry the edit.";
    let text = if tool == Tool::Cursor {
        json!({"permission":"deny","agent_message":reason}).to_string()
    } else {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
        .to_string()
    };
    emit(out, &text)
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
fn run_cloud(
    tool: Tool,
    event: &Value,
    _: &str,
    _: &Path,
    _: PathBuf,
    _: &Config,
    _: i64,
    out: &mut dyn Write,
) -> Result<()> {
    eprintln!("lockyard hook: the agent process needs a Unix socket.");
    deny_cloud_unavailable(tool, event, out)
}

/// Cursor events may provide the path directly; normalize that shape before using the common decision.
fn normalize_cursor(event: &mut Value) {
    if let Some(name) = event.get("hook_event_name").and_then(Value::as_str) {
        let normalized = match name {
            "preToolUse" => Some("PreToolUse"),
            "postToolUse" => Some("PostToolUse"),
            "beforeSubmitPrompt" => Some("UserPromptSubmit"),
            "sessionStart" => Some("SessionStart"),
            "sessionEnd" => Some("SessionEnd"),
            _ => None,
        };
        if let Some(normalized) = normalized {
            event["hook_event_name"] = Value::String(normalized.into());
        }
    }
    if event.get("session_id").is_none()
        && let Some(session) = event.get("conversation_id").cloned()
    {
        event["session_id"] = session;
    }
    if event.get("cwd").is_none()
        && let Some(root) = event
            .get("workspace_roots")
            .and_then(Value::as_array)
            .and_then(|roots| roots.first())
            .cloned()
    {
        event["cwd"] = root;
    }
    if event.get("tool_input").is_none()
        && let Some(path) = event.get("file_path").cloned()
    {
        event["tool_input"] = json!({"file_path": path});
    }
}

#[allow(clippy::too_many_arguments)]
fn handle(
    tool: Tool,
    port: &mut dyn Port,
    event: &Value,
    agent: &str,
    cwd: &Path,
    now: i64,
    machine: &lockyard_core::machine::MachineConfig,
    out: &mut dyn Write,
) -> Result<()> {
    match event.get("hook_event_name").and_then(Value::as_str) {
        Some("PreToolUse") => {
            let answer = match pre_tool_use(port, event, agent, cwd, now, machine) {
                Ok(answer) => answer,
                Err(error) => return deny_failed_check(tool, event, error, out),
            };
            if answer.is_none() {
                port.report(agent, Moment::Before, Vec::new());
            }
            match answer {
                Some(text) if tool == Tool::Cursor => {
                    let decision: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let reason = decision
                        .pointer("/hookSpecificOutput/permissionDecisionReason")
                        .and_then(Value::as_str)
                        .unwrap_or("This edit conflicts with a work zone.");
                    emit(
                        out,
                        &json!({"permission":"deny","agent_message":reason}).to_string(),
                    )
                }
                Some(text) => emit(out, &text),
                None => Ok(()),
            }
        }
        Some(name @ "PostToolUse") => {
            let written = edited_path(port.root(), event, cwd)?.into_iter().collect();
            port.report(agent, Moment::After, written);
            deliver_mail(port, name, agent, now, out)
        }
        Some(name @ "UserPromptSubmit") => {
            port.report(agent, Moment::Prompt, Vec::new());
            deliver_mail(port, name, agent, now, out)
        }
        Some(name @ "SessionStart") => deliver_mail(port, name, agent, now, out),
        Some("SessionEnd") => {
            port.report(agent, Moment::End, Vec::new());
            Ok(())
        }
        _ => Ok(()),
    }
}

fn emit(out: &mut dyn Write, text: &str) -> Result<()> {
    out.write_all(text.as_bytes())?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

/// The project path an edit tool targets, if this event is one.
fn edited_path(root: &Path, event: &Value, cwd: &Path) -> Result<Option<String>> {
    let tool = event.get("tool_name").and_then(Value::as_str);
    if !tool.is_some_and(|name| EDIT_TOOLS.contains(&name)) {
        return Ok(None);
    }
    let input = event.get("tool_input");
    let target = ["file_path", "notebook_path"]
        .iter()
        .find_map(|key| input?.get(key)?.as_str());
    let Some(target) = target else {
        return Ok(None);
    };
    Ok(ZonePath::resolve(root, cwd, target)?.map(|path| path.as_str().to_string()))
}

fn has_edit_target(event: &Value) -> bool {
    event
        .get("tool_name")
        .and_then(Value::as_str)
        .is_some_and(|name| EDIT_TOOLS.contains(&name))
        && ["file_path", "notebook_path"].iter().any(|key| {
            event
                .get("tool_input")
                .and_then(|input| input.get(key))
                .and_then(Value::as_str)
                .is_some()
        })
}

fn pre_tool_use(
    port: &mut dyn Port,
    event: &Value,
    agent: &str,
    cwd: &Path,
    now: i64,
    config: &lockyard_core::machine::MachineConfig,
) -> Result<Option<String>> {
    if let Some(command) = event
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
    {
        let heavy = command_is_heavy(command, &config.heavy_commands());
        if heavy {
            match crate::guard::cached_level(config) {
                Ok(level) => {
                    use lockyard_core::machine::Level;
                    if level as u8 >= Level::Hold as u8 {
                        return Ok(Some(json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Lockyard is holding heavy work under machine pressure. Use `lockyard run --heavy -- <command>` or wait, then check `lockyard machine`."}}).to_string()));
                    }
                    if level == Level::Warn {
                        eprintln!(
                            "lockyard hook: machine pressure is at warn; heavy command allowed."
                        );
                    }
                }
                Err(error) => eprintln!(
                    "lockyard hook: machine state unavailable ({error}); allowing heavy command."
                ),
            }
        }
    }
    if event
        .get("tool_name")
        .and_then(Value::as_str)
        .is_some_and(|name| EDIT_TOOLS.contains(&name))
        && !has_edit_target(event)
    {
        return Ok(Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Lockyard cannot check this edit because the client did not provide a file path. Retry with a path-bearing edit operation.",
            }
        }).to_string()));
    }
    let Some(path) = edited_path(port.root(), event, cwd)? else {
        return Ok(None);
    };
    let conflict = match port.check(agent, &path, now)? {
        Verdict::Free => {
            // Record that this edit was allowed through the hook, so a later write can be told
            // apart from one that never asked (shell `sed -i`, an editor, a build script).
            if let Err(error) = lockyard_core::outside::announce(port.root(), agent, &path, now) {
                eprintln!("lockyard hook: could not record allowed write to {path}: {error}");
            }
            return Ok(None);
        }
        // Fail closed: a stale or unreachable mirror must never allow an edit the server would
        // refuse. The agent process refreshes the view; until it does, the edit waits.
        Verdict::Unknown => {
            let reason = format!(
                "Lockyard: the zone view for {path} is not fresh enough to allow this edit. \
                 Wait a moment, or check `lockyard agent status` and `lockyard doctor`."
            );
            return Ok(Some(
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                })
                .to_string(),
            ));
        }
        Verdict::Held(conflict) => conflict,
    };
    let reason = format!(
        "Lockyard: {conflict}. Wait for the claim to end, or ask the holder with `lockyard msg send {} \"...\"`.",
        conflict.agent
    );
    Ok(Some(
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })
        .to_string(),
    ))
}

#[path = "hook/shell.rs"]
mod shell;
use shell::*;
#[path = "hook/mail.rs"]
mod mail;
use mail::*;

#[cfg(test)]
mod tests;
