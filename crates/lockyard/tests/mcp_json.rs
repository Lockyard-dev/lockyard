// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn raw_call(request: &str) -> Value {
    let project = tempfile::tempdir().unwrap();
    raw_call_in(project.path(), None, request)
}

fn raw_call_in(project: &Path, agent: Option<&str>, request: &str) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .args(["mcp", "--tools", "full"])
        .current_dir(project)
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID");
    if let Some(agent) = agent {
        command.env("LOCKYARD_AGENT", agent);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn local_mcp_status_preserves_owned_claimed_and_review_tasks() {
    let project = tempfile::tempdir().unwrap();
    let mut store = lockyard_core::Store::init(project.path()).unwrap();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let claimed = store.add_task("alice", "owned active", "", now).unwrap();
    let review = store.add_task("alice", "owned review", "", now).unwrap();
    let foreign = store.add_task("bob", "foreign active", "", now).unwrap();
    store.add_task("alice", "unassigned", "", now).unwrap();
    let cancelled = store.add_task("alice", "cancelled", "", now).unwrap();
    store
        .claim_task("alice", claimed.id.as_str(), 10, now)
        .unwrap();
    store
        .claim_task("alice", review.id.as_str(), 10, now)
        .unwrap();
    store
        .submit_task("alice", review.id.as_str(), "evidence", now)
        .unwrap();
    store
        .claim_task("bob", foreign.id.as_str(), 10, now)
        .unwrap();
    store
        .claim_task("alice", cancelled.id.as_str(), 10, now)
        .unwrap();
    store
        .cancel_task("alice", cancelled.id.as_str(), "", now)
        .unwrap();
    drop(store);
    let response = raw_call_in(
        project.path(),
        Some("alice"),
        &json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":"status", "arguments":{}}})
            .to_string(),
    );
    assert_ne!(response["result"]["isError"], true, "{response}");
    let status = &response["result"]["structuredContent"];
    assert!(status.get("backlog").is_none());
    let tasks = status["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 2, "{status}");
    assert_eq!(tasks[0]["id"], claimed.id.as_str());
    assert_eq!(tasks[0]["status"], "claimed");
    assert_eq!(tasks[1]["id"], review.id.as_str());
    assert_eq!(tasks[1]["status"], "review");
    assert!(tasks.iter().all(|task| task["assignee"] == "alice"));
}

#[test]
fn raw_mcp_catalog_rejects_duplicate_zone_and_group_names_before_project_or_transport() {
    for catalog in [
        r#"{"version":1,"zones":{"same":["a"],"same":["b"]}}"#,
        r#"{"version":1,"zones":{},"groups":{"same":["a"],"same":["b"]}}"#,
    ] {
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"zone_catalog_put","arguments":{{"catalog":{catalog},"expected_revision":0,"idempotency_key":"01M6VN9FQEEG3HKNSFMC32WVQN"}}}}}}"#
        );
        let response = raw_call(&request);
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["code"],
            "catalog_invalid"
        );
    }
}

#[test]
fn ordinary_raw_mcp_parse_errors_keep_json_rpc_error_semantics() {
    for request in [
        "{broken",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"task_show","arguments":{"id":"D-1","id":"D-2"}}}"#,
    ] {
        let response = raw_call(request);
        assert_eq!(response["error"]["code"], -32700);
        assert_eq!(response["id"], Value::Null);
        assert!(response.get("result").is_none());
    }
    let response = raw_call(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}).to_string());
    assert_eq!(response["result"], json!({}));
}
