// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives durable workflow receipts through the real binary and a deterministic claim race.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

struct State {
    claimed: bool,
    claim_response: Value,
    current: Value,
    claim_writes: usize,
    zone_writes: usize,
    task_reads: usize,
}

fn item(executor: &str, session: &str, epoch: &str) -> Value {
    json!({"id":"D-1","title":"work","status":"active","version":4,
        "assignment":{"executor":executor,"session":session,"claimed_at":epoch,
            "lease_expires_at":"2030-01-01T00:00:00Z","lease_active":true}})
}

fn original() -> Value {
    item("token:credential:me", "me", "2026-11-06T12:00:00Z")
}

fn server(claim_response: Value, current: Value) -> (String, Arc<Mutex<State>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(State {
        claimed: false,
        claim_response,
        current,
        claim_writes: 0,
        zone_writes: 0,
        task_reads: 0,
    }));
    let shared = Arc::clone(&state);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            answer(stream, &shared);
        }
    });
    (url, state)
}

fn answer(mut stream: TcpStream, state: &Mutex<State>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap();
    let path = parts.next().unwrap();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    reader.read_exact(&mut vec![0; length]).unwrap();
    let (status, body) = {
        let mut state = state.lock().unwrap();
        match (method, path) {
            ("GET", "/api/v1/workspace/encryption") => (
                200,
                json!({"encryption":"off","key_id":null,"workspace_id":"00000000-0000-0000-0000-000000000001"}),
            ),
            ("GET", "/api/v1/registry/items/D-1") => {
                state.task_reads += 1;
                (
                    200,
                    if state.claimed {
                        state.current.clone()
                    } else {
                        json!({"id":"D-1","status":"ready","version":1})
                    },
                )
            }
            ("POST", "/api/v1/registry/items/D-1/claim") => {
                state.claimed = true;
                state.claim_writes += 1;
                (200, state.claim_response.clone())
            }
            ("POST", "/api/v1/zones/claims") => {
                state.zone_writes += 1;
                if state.zone_writes == 1 {
                    (
                        409,
                        json!({"error":{"code":"conflict","message":"zone held"}}),
                    )
                } else {
                    (
                        200,
                        json!({"id":1,"session":"me","paths":["src"],"fence":7}),
                    )
                }
            }
            _ => (
                404,
                json!({"error":{"code":"not_found","message":"unexpected test route"}}),
            ),
        }
    };
    let body = body.to_string();
    write!(stream, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
}

fn project(url: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lockyard")).unwrap();
    std::fs::write(
        dir.path().join(".lockyard/config.toml"),
        format!("mode='cloud'\nurl='{url}'\nworkspace='workflow-test'\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("plan.json"),
        json!({"steps":[{"kind":"task_claim","id":1},{"kind":"zone_claim","paths":["src"]}]})
            .to_string(),
    )
    .unwrap();
    dir
}

fn run(dir: &Path, url: &str) -> Value {
    let runtime = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .current_dir(dir)
        .env("LOCKYARD_URL", url)
        .env("LOCKYARD_AGENT", "me")
        .env("LOCKYARD_TOKEN", "workflow-test-token")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", runtime.path().join("state"))
        .args(["workflow", "run", "race", "--plan", "plan.json", "--json"])
        .output()
        .unwrap();
    let receipt: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(
        output.status.code(),
        Some(if receipt["ok"] == true { 0 } else { 1 }),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    receipt
}

#[test]
fn task_receipt_keeps_claim_response_and_reassignment_blocks_resume() {
    let replacement = item(
        "token:other:replacement",
        "replacement",
        "2026-11-06T12:01:00Z",
    );
    let (url, state) = server(original(), replacement);
    let dir = project(&url);
    let first = run(dir.path(), &url);
    assert_eq!(first["steps"][0]["status"], "completed");
    assert_eq!(
        first["steps"][0]["result"]["registry_assignment"],
        original()["assignment"]
    );
    assert_eq!(first["steps"][1]["status"], "failed");
    assert_eq!(state.lock().unwrap().task_reads, 1, "no mutation read-back");
    let again = run(dir.path(), &url);
    assert_eq!(again["needs_reconciliation"]["kind"], "ownership_changed");
    assert_eq!(again["steps"][0], first["steps"][0]);
    let state = state.lock().unwrap();
    assert_eq!(state.claim_writes, 1);
    assert_eq!(state.zone_writes, 1);
}

#[test]
fn original_assignment_allows_resume_without_repeating_the_claim() {
    let (url, state) = server(original(), original());
    let dir = project(&url);
    let first = run(dir.path(), &url);
    assert_eq!(first["steps"][1]["status"], "failed");
    let again = run(dir.path(), &url);
    assert_eq!(again["ok"], true);
    assert_eq!(again["steps"][0], first["steps"][0]);
    let state = state.lock().unwrap();
    assert_eq!(state.claim_writes, 1);
    assert_eq!(state.zone_writes, 2);
    assert_eq!(state.task_reads, 2);
}

#[test]
fn invalid_claim_assignment_is_unknown_and_never_repeated() {
    let mut missing = original();
    missing["assignment"] = Value::Null;
    let mut no_epoch = original();
    no_epoch["assignment"]
        .as_object_mut()
        .unwrap()
        .remove("claimed_at");
    let foreign = item(
        "token:other:replacement",
        "replacement",
        "2026-11-06T12:01:00Z",
    );
    for response in [missing, no_epoch, foreign] {
        let (url, state) = server(response, original());
        let dir = project(&url);
        let first = run(dir.path(), &url);
        assert_eq!(first["steps"][0]["status"], "unknown");
        assert_eq!(first["steps"][1]["status"], "not_started");
        let again = run(dir.path(), &url);
        assert_eq!(again["steps"][0]["status"], "unknown");
        let state = state.lock().unwrap();
        assert_eq!(state.claim_writes, 1);
        assert_eq!(state.zone_writes, 0);
        assert_eq!(state.task_reads, 1);
    }
}

#[test]
fn old_readback_receipt_with_same_session_requires_reconciliation() {
    let replacement = item("token:other:me", "me", "2026-11-06T12:01:00Z");
    let (url, state) = server(original(), replacement.clone());
    let dir = project(&url);
    let mut first = run(dir.path(), &url);
    let result = first["steps"][0]["result"].as_object_mut().unwrap();
    result.remove("registry_assignment_source");
    result.insert(
        "registry_assignment".into(),
        replacement["assignment"].clone(),
    );
    let receipt = dir.path().join(".lockyard/workflows/race.json");
    std::fs::write(receipt, serde_json::to_vec(&first).unwrap()).unwrap();
    let again = run(dir.path(), &url);
    assert_eq!(
        again["needs_reconciliation"]["kind"],
        "current_ownership_unverified"
    );
    assert_eq!(state.lock().unwrap().zone_writes, 1);
}
