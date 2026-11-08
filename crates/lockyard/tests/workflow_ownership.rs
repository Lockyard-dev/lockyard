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
    zone_reads: usize,
    zone_keys: Vec<String>,
    zone_reads_at_write: Vec<usize>,
    zone_refresh_fails: bool,
    claim_refusal: Option<String>,
    before_claim: Value,
    claim_keys: Vec<String>,
    handoff_writes: usize,
    handoff_reads: usize,
    handoff_version: i64,
    handoff_keys: Vec<String>,
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
        zone_reads: 0,
        zone_keys: Vec::new(),
        zone_reads_at_write: Vec::new(),
        zone_refresh_fails: false,
        claim_refusal: None,
        before_claim: json!({"id":"D-1","status":"ready","version":1}),
        claim_keys: Vec::new(),
        handoff_writes: 0,
        handoff_reads: 0,
        handoff_version: 3,
        handoff_keys: Vec::new(),
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
    let mut protocol = None;
    let mut repository = None;
    let mut idempotency_key = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            } else if name.eq_ignore_ascii_case("lockyard-protocol") {
                protocol = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("x-lockyard-repository") {
                repository = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("idempotency-key") {
                idempotency_key = Some(value.trim().to_string());
            }
        }
    }
    reader.read_exact(&mut vec![0; length]).unwrap();
    let (status, body) = {
        let mut state = state.lock().unwrap();
        match (method, path) {
            ("GET", "/api/v1/protocol") => (
                200,
                json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":[]}),
            ),
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
                        state.before_claim.clone()
                    },
                )
            }
            ("POST", "/api/v1/registry/items/D-1/claim") => {
                state.claim_writes += 1;
                state
                    .claim_keys
                    .push(idempotency_key.expect("claim has a key"));
                if state.claim_writes == 1 && state.claim_refusal.is_some() {
                    let code = state.claim_refusal.as_deref().unwrap();
                    (
                        409,
                        json!({"type":format!("urn:lockyard:problem:{code}"),"title":"Claim conflict","status":409,"code":code,"detail":"task state changed","details":{}}),
                    )
                } else {
                    state.claimed = true;
                    (200, state.claim_response.clone())
                }
            }
            ("POST", "/api/v1/zones/claims") => {
                state.zone_writes += 1;
                state
                    .zone_keys
                    .push(idempotency_key.expect("write has a key"));
                let reads = state.zone_reads;
                state.zone_reads_at_write.push(reads);
                if state.zone_writes == 1 {
                    (
                        409,
                        json!({"type":"urn:lockyard:problem:version_conflict","title":"Claim conflict","status":409,"code":"version_conflict","detail":"zone claim state changed","details":{}}),
                    )
                } else {
                    (
                        200,
                        json!({"id":1,"session":"me","paths":["src"],"fence":7}),
                    )
                }
            }
            ("GET", "/api/v1/zones/claims?path=src") => {
                state.zone_reads += 1;
                if state.zone_refresh_fails {
                    (
                        503,
                        json!({"error":{"code":"server_draining","message":"read unavailable"}}),
                    )
                } else {
                    (200, json!([]))
                }
            }
            ("GET", "/api/v1/bus/tasks/BT-1") => {
                state.handoff_reads += 1;
                (
                    200,
                    json!({"id":"BT-1","status":"claimed","version":state.handoff_version,"assignee":"me"}),
                )
            }
            ("POST", "/api/v1/bus/tasks/BT-1/handoff?version=3") => {
                state.handoff_writes += 1;
                state
                    .handoff_keys
                    .push(idempotency_key.expect("handoff has a key"));
                if state.handoff_writes == 1 {
                    (
                        409,
                        json!({"type":"urn:lockyard:problem:version_conflict","title":"Handoff conflict","status":409,"code":"version_conflict","detail":"task state changed","details":{}}),
                    )
                } else {
                    (
                        200,
                        json!({"id":"BT-1","status":"review","version":4,"assignee":"me"}),
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
    let protocol = protocol
        .map(|version| format!("Lockyard-Protocol: {version}\r\n"))
        .unwrap_or_default();
    let repository = repository
        .map(|scope| format!("X-Lockyard-Repository: {scope}\r\n"))
        .unwrap_or_default();
    write!(stream, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{protocol}{repository}\r\n{body}", body.len()).unwrap();
}

fn project(url: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::create_dir(dir.path().join(".lockyard")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join(".lockyard"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
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
    run_with_umask(dir, url, None)
}

fn run_with_umask(dir: &Path, url: &str, mask: Option<TestMode>) -> Value {
    // Ignore caller TMPDIR: shared CI ancestors may be group-writable and are deliberately
    // rejected by private journals. The OS sticky temp root plus tempfile's 0700 child is private.
    #[cfg(unix)]
    let runtime_root = Path::new("/tmp").canonicalize().unwrap();
    #[cfg(not(unix))]
    let runtime_root = std::env::temp_dir();
    let runtime = tempfile::tempdir_in(runtime_root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(dir)
        .env("HOME", runtime.path())
        .env("LOCKYARD_URL", url)
        .env("LOCKYARD_AGENT", "me")
        .env("LOCKYARD_TOKEN", "workflow-test-token")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_CONFIG_HOME", runtime.path().join("config"))
        .env("XDG_STATE_HOME", runtime.path().join("state"))
        .env_remove("LOCKYARD_REQUIRE_E2EE")
        .env_remove("LOCKYARD_E2EE_WORKSPACE_ID")
        .args(["workflow", "run", "race", "--plan", "plan.json", "--json"]);
    #[cfg(unix)]
    if let Some(mask) = mask {
        use std::os::unix::process::CommandExt;
        // SAFETY: the post-fork closure calls only async-signal-safe umask and constructs Ok.
        unsafe {
            command.pre_exec(move || {
                libc::umask(mask);
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = mask;
    let output = command.output().unwrap();
    let receipt: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(
        output.status.code(),
        Some(if receipt["ok"] == true { 0 } else { 1 }),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    #[cfg(unix)]
    if mask.is_some() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(runtime.path().join("state"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    receipt
}

#[cfg(unix)]
#[test]
fn missing_private_state_is_created_securely_under_group_writable_umask() {
    let (url, state) = server(original(), original());
    let dir = project(&url);
    let first = run_with_umask(dir.path(), &url, Some(0o002));
    assert_eq!(first["steps"][0]["status"], "completed");
    assert_eq!(state.lock().unwrap().claim_writes, 1);
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
    assert_ne!(
        again["steps"][1]["idempotency_key"],
        first["steps"][1]["idempotency_key"]
    );
    assert_eq!(
        again["steps"][1]["rejected_attempts"][0]["idempotency_key"],
        first["steps"][1]["idempotency_key"]
    );
    let state = state.lock().unwrap();
    assert_eq!(state.claim_writes, 1);
    assert_eq!(state.zone_writes, 2);
    assert_eq!(state.task_reads, 2);
    assert_eq!(state.zone_reads, 1);
    assert_ne!(state.zone_keys[0], state.zone_keys[1]);
    assert_eq!(state.zone_reads_at_write, [0, 1]);
}

#[test]
fn refused_step_refresh_failure_preserves_key_and_blocks_new_write() {
    let (url, state) = server(original(), original());
    let dir = project(&url);
    let first = run(dir.path(), &url);
    state.lock().unwrap().zone_refresh_fails = true;
    let again = run(dir.path(), &url);
    assert_eq!(again["ok"], false);
    assert_eq!(
        again["needs_reconciliation"]["kind"],
        "refused_step_state_unverified"
    );
    assert_eq!(again["steps"][1], first["steps"][1]);
    let state = state.lock().unwrap();
    assert_eq!(state.zone_reads, 1);
    assert_eq!(state.zone_writes, 1);
    assert_eq!(state.zone_keys.len(), 1);
}

#[test]
fn task_claim_conflict_refreshes_state_and_key_on_explicit_resume() {
    for code in ["version_conflict", "task_already_claimed"] {
        let (url, state) = server(original(), original());
        state.lock().unwrap().claim_refusal = Some(code.into());
        let dir = project(&url);
        let first = run(dir.path(), &url);
        assert_eq!(first["steps"][0]["status"], "failed");
        let again = run(dir.path(), &url);
        assert_eq!(again["steps"][0]["status"], "completed");
        assert_ne!(
            again["steps"][0]["idempotency_key"],
            first["steps"][0]["idempotency_key"]
        );
        let state = state.lock().unwrap();
        assert_eq!(state.claim_writes, 2);
        assert_eq!(state.task_reads, 3, "refresh before the backend's CAS read");
        assert_ne!(state.claim_keys[0], state.claim_keys[1]);
    }
}

#[test]
fn task_claim_conflict_with_live_assignment_requires_new_operation() {
    let (url, state) = server(original(), original());
    {
        let mut state = state.lock().unwrap();
        state.claim_refusal = Some("task_already_claimed".into());
        state.before_claim = item("token:other", "other", "2026-11-06T12:01:00Z");
    }
    let dir = project(&url);
    let first = run(dir.path(), &url);
    let again = run(dir.path(), &url);
    assert_eq!(
        again["needs_reconciliation"]["kind"],
        "new_operation_required"
    );
    assert_eq!(again["steps"][0], first["steps"][0]);
    assert_eq!(state.lock().unwrap().claim_writes, 1);
}

#[test]
fn handoff_conflict_refreshes_pinned_version_or_requires_new_operation() {
    for version in [3, 4] {
        let (url, state) = server(original(), original());
        state.lock().unwrap().handoff_version = version;
        let dir = project(&url);
        std::fs::write(dir.path().join("plan.json"), json!({"steps":[{"kind":"work_handoff","id":"BT-1","to":"lead","report":"done","if_version":3}]}).to_string()).unwrap();
        let first = run(dir.path(), &url);
        assert_eq!(first["steps"][0]["status"], "failed");
        let again = run(dir.path(), &url);
        let state = state.lock().unwrap();
        assert_eq!(state.handoff_reads, 1);
        if version == 3 {
            assert_eq!(again["ok"], true);
            assert_ne!(state.handoff_keys[0], state.handoff_keys[1]);
        } else {
            assert_eq!(
                again["needs_reconciliation"]["kind"],
                "new_operation_required"
            );
            assert_eq!(again["steps"][0], first["steps"][0]);
            assert_eq!(state.handoff_writes, 1);
        }
    }
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
        assert_eq!(again["steps"][0], first["steps"][0]);
        assert_eq!(again["identity"], first["identity"]);
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

#[cfg(unix)]
type TestMode = libc::mode_t;
#[cfg(windows)]
type TestMode = u32;
