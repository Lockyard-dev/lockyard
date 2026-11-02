// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives the real binary, the way agents do: separate processes on one project.

use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn lockyard(dir: &Path, agent: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(args)
        .current_dir(dir)
        .env("LOCKYARD_AGENT", agent)
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap()
}

fn ok(dir: &Path, agent: &str, args: &[&str]) -> String {
    let result = lockyard(dir, agent, args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), "setup", &["init"]);
    dir
}

#[test]
fn version_about_and_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let version = ok(dir.path(), "a", &["--version"]);
    assert_eq!(
        version.trim(),
        format!("lockyard {}", lockyard_core::VERSION)
    );
    assert!(ok(dir.path(), "a", &["about"]).contains(lockyard_core::HOMEPAGE));
    assert_eq!(lockyard(dir.path(), "a", &["nope"]).status.code(), Some(2));
    assert_eq!(lockyard(dir.path(), "a", &[]).status.code(), Some(2));
}

#[test]
fn commands_outside_a_project_say_so() {
    let dir = tempfile::tempdir().unwrap();
    let result = lockyard(dir.path(), "a", &["zone", "list"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("lockyard init"));
}

#[test]
fn a_write_without_an_agent_name_is_refused() {
    let dir = project();
    let result = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["zone", "claim", "src"])
        .current_dir(dir.path())
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("LOCKYARD_AGENT"));
}

#[test]
fn zones_collide_across_folders_and_exit_with_the_conflict_code() {
    let dir = project();
    let deep = dir.path().join("src/deep");
    std::fs::create_dir_all(&deep).unwrap();
    ok(
        dir.path(),
        "a",
        &["zone", "claim", "src", "--note", "refactor"],
    );

    let refused = lockyard(&deep, "b", &["zone", "claim", "x.rs"]);
    assert_eq!(refused.status.code(), Some(3));
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("src/deep/x.rs is held by a"));
    assert!(message.contains("refactor"));

    assert_eq!(
        lockyard(&deep, "b", &["zone", "check", "x.rs"])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(ok(&deep, "a", &["zone", "check", "x.rs"]).trim(), "free");

    ok(dir.path(), "a", &["zone", "release"]);
    ok(&deep, "b", &["zone", "claim", "x.rs"]);
}

#[test]
fn a_path_outside_the_project_cannot_be_claimed() {
    let dir = project();
    let result = lockyard(dir.path(), "a", &["zone", "claim", "../elsewhere"]);
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn one_process_wins_a_race_for_a_path() {
    let dir = project();
    let racers: Vec<_> = (0..12)
        .map(|index| {
            Command::new(env!("CARGO_BIN_EXE_lockyard"))
                .args(["zone", "claim", "src"])
                .current_dir(dir.path())
                .env("LOCKYARD_AGENT", format!("agent-{index}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let codes: Vec<_> = racers
        .into_iter()
        .map(|mut racer| racer.wait().unwrap().code())
        .collect();
    assert_eq!(codes.iter().filter(|code| **code == Some(0)).count(), 1);
    assert_eq!(codes.iter().filter(|code| **code == Some(3)).count(), 11);
}

#[test]
fn a_full_conversation_and_task_cycle_over_json() {
    let dir = project();
    let root = dir.path();
    ok(root, "lead", &["who"]);
    ok(root, "worker", &["zone", "list"]);
    ok(root, "lead", &["zone", "list"]);

    let added = ok(
        root,
        "lead",
        &["--json", "task", "add", "ship it", "--body", "details"],
    );
    let added: Value = serde_json::from_str(&added).unwrap();
    assert_eq!(added["status"], "open");
    let id = added["id"].to_string();

    ok(root, "worker", &["task", "claim", &id]);
    ok(
        root,
        "worker",
        &["task", "submit", &id, "--evidence", "ran the tests"],
    );
    let own = lockyard(root, "worker", &["task", "accept", &id]);
    assert_eq!(own.status.code(), Some(1));
    ok(root, "lead", &["task", "accept", &format!("T-{id}")]);
    assert_eq!(ok(root, "lead", &["task", "list"]).trim(), "no tasks");
    assert!(ok(root, "lead", &["task", "show", &id]).contains("ran the tests"));
}

#[test]
fn mail_needs_a_known_addressee_and_reads_once() {
    let dir = project();
    let root = dir.path();
    assert_eq!(
        lockyard(root, "a", &["msg", "send", "ghost", "hi"])
            .status
            .code(),
        Some(1)
    );
    ok(root, "b", &["msg", "inbox"]);
    ok(root, "a", &["msg", "send", "b", "hi there"]);
    assert!(ok(root, "b", &["msg", "inbox", "--peek"]).contains("hi there"));
    assert!(ok(root, "b", &["status"]).contains("unread mail: 1"));
    assert!(ok(root, "b", &["msg", "inbox"]).contains("hi there"));
    assert_eq!(ok(root, "b", &["msg", "inbox"]).trim(), "no new mail");
}

#[test]
fn the_board_and_presence_work_in_local_mode() {
    let dir = project();
    let root = dir.path();
    ok(root, "a", &["board", "set", "deploy", "ready"]);
    assert_eq!(
        ok(root, "a", &["board", "get", "deploy"]).trim(),
        "deploy = ready"
    );
    let listed: Value = serde_json::from_str(&ok(root, "a", &["--json", "board", "list"])).unwrap();
    assert_eq!(listed[0]["value"], "ready");
    ok(root, "a", &["presence", "beat"]);
    assert!(ok(root, "a", &["presence", "list"]).contains("cli"));
    ok(root, "a", &["board", "rm", "deploy"]);
    assert_eq!(
        lockyard(root, "a", &["board", "get", "deploy"])
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn cloud_only_commands_explain_themselves_in_local_mode() {
    let dir = project();
    let root = dir.path();
    for args in [
        &["zone", "wait", "src"][..],
        &["zone", "queue", "src"],
        &["zone", "queue"],
        &["zone", "unwait", "1"],
        &["zone", "request", "src", "--text", "please"],
        &["zone", "answer", "1"],
        &["zone", "handover", "1", "--to", "b"],
        &["zone", "accept", "1"],
        &["zone", "narrow", "1", "src"],
        &["zone", "add-path", "1", "src"],
        &["zone", "takeover", "1", "--reason", "gone"],
        &["zone", "dirty", "list"],
        &["zone", "claim", "src", "--shared"],
        &["msg", "ack", "1"],
        &["msg", "thread", "1"],
        &["events"],
        &["work", "list"],
        &["cloud", "export"],
        &["agent"],
    ] {
        let result = lockyard(root, "a", args);
        assert_eq!(result.status.code(), Some(1), "{args:?}");
        let message = String::from_utf8_lossy(&result.stderr);
        assert!(message.contains("needs cloud mode"), "{args:?}: {message}");
    }
}

#[test]
fn errors_are_json_under_the_json_flag() {
    let dir = project();
    let result = lockyard(dir.path(), "a", &["--json", "work", "list"]);
    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "needs_cloud");
}

#[test]
fn every_new_command_accepts_the_json_flag() {
    let dir = project();
    let setup: Value =
        serde_json::from_str(&ok(dir.path(), "a", &["--json", "setup", "claude"])).unwrap();
    assert!(
        setup["setup"]
            .as_str()
            .unwrap()
            .contains("lockyard hook claude")
    );
    let board: Value =
        serde_json::from_str(&ok(dir.path(), "a", &["--json", "board", "list"])).unwrap();
    assert!(board.is_array());
}

#[test]
fn printed_mail_is_marked_after_the_output_and_peek_marks_nothing() {
    let dir = project();
    let root = dir.path();
    ok(root, "b", &["msg", "inbox"]);
    ok(root, "a", &["msg", "send", "b", "hello"]);
    assert_eq!(ok(root, "b", &["msg", "unread"]).trim(), "unread mail: 1");
    ok(root, "b", &["msg", "inbox", "--peek"]);
    assert_eq!(ok(root, "b", &["msg", "unread"]).trim(), "unread mail: 1");
    ok(root, "b", &["msg", "inbox"]);
    assert_eq!(ok(root, "b", &["msg", "unread"]).trim(), "unread mail: 0");
}

fn hook(dir: &Path, event: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["hook", "claude"])
        .current_dir(dir)
        .env_remove("LOCKYARD_AGENT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(event.to_string().as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn the_hook_process_denies_a_held_path_in_the_shape_claude_code_reads() {
    let dir = project();
    ok(dir.path(), "other", &["zone", "claim", "src"]);
    let result = hook(
        dir.path(),
        &json!({
            "hook_event_name": "PreToolUse",
            "session_id": "me",
            "cwd": dir.path(),
            "tool_name": "Write",
            "tool_input": { "file_path": dir.path().join("src/new.rs") },
        }),
    );
    assert!(result.status.success());
    let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_broken_project_never_blocks_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join(".lockyard");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("lockyard.db"), "not a database, not at all").unwrap();
    let result = hook(
        dir.path(),
        &json!({ "hook_event_name": "PostToolUse", "session_id": "me", "cwd": dir.path() }),
    );
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("lockyard hook"));
}

fn mcp(dir: &Path, agent: &str, input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["mcp"])
        .current_dir(dir)
        .env("LOCKYARD_AGENT", agent)
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn mcp_stdio_initializes_lists_claims_and_reports_conflicts_and_parse_errors() {
    let dir = project();
    let init = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
    );
    let init: Value = serde_json::from_slice(&init.stdout).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    let list = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
    );
    let list: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(list["result"]["tools"].as_array().unwrap().len() > 20);

    let claim = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"zone_claim\",\"arguments\":{\"paths\":[\"src\"]}}}\n",
    );
    let claim: Value = serde_json::from_slice(&claim.stdout).unwrap();
    assert_eq!(claim["result"]["isError"], false);

    let conflict = mcp(
        dir.path(),
        "second",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"zone_claim\",\"arguments\":{\"paths\":[\"src/file.rs\"]}}}\n",
    );
    let conflict: Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(conflict["result"]["isError"], true);
    assert!(
        conflict["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("first")
    );

    let bad = mcp(dir.path(), "first", "{bad json}\n");
    let bad: Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(bad["error"]["code"], -32700);
}
