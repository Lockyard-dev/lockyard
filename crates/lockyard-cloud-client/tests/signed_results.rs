// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_cloud_client::{Client, WorkspaceKey};
use serde_json::json;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const WORKSPACE: &str = "00000000-0000-4000-8000-000000000001";
const DOCUMENT: &[u8] = b"{ \"original\": \"signed bytes\" }\n";

#[derive(Default)]
struct State {
    stored: Option<(Vec<u8>, String)>,
    drop_ack: bool,
    get_error: Option<(u16, &'static str)>,
    put_error: Option<(u16, &'static str, u64)>,
    tamper: bool,
    puts: usize,
    discoveries: usize,
}

fn fixture() -> (String, Arc<Mutex<State>>, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(State::default()));
    let shared = state.clone();
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                bytes.push(byte[0]);
            }
            let head = String::from_utf8(bytes).unwrap();
            if head.starts_with("GET /stop ") {
                return;
            }
            let header = |name: &str| {
                head.lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.trim().to_owned())
            };
            assert_eq!(header("Authorization").as_deref(), Some("Bearer fixture"));
            assert!(matches!(
                header("X-Lockyard-Session").as_deref(),
                Some("worker" | "owner")
            ));
            let length = header("Content-Length").map_or(0, |n| n.parse().unwrap());
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let mut state = shared.lock().unwrap();
            let (status, content_type, response, extra) = if head
                .starts_with("GET /api/v1/protocol ")
            {
                state.discoveries += 1;
                (200, "application/json", json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":["signed_results_v1"]}).to_string().into_bytes(), String::new())
            } else if head.starts_with("PUT ") {
                state.puts += 1;
                if let Some((status, code, retry)) = state.put_error {
                    let body = json!({"type":format!("urn:lockyard:problem:{code}"),"status":status,"code":code,"detail":"refused","details":null}).to_string();
                    write!(stream,"HTTP/1.1 {status} Refused\r\nLockyard-Protocol: 2\r\nContent-Type: application/problem+json\r\nRetry-After: {retry}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                    continue;
                }
                assert_eq!(
                    header("Content-Type").as_deref(),
                    Some("application/octet-stream")
                );
                assert!(header("Idempotency-Key").is_none());
                assert!(body.starts_with(b"lyenc1."));
                assert!(!String::from_utf8_lossy(&body).contains("signed bytes"));
                let expiry = header("Lockyard-Result-Expires-At").unwrap();
                if let Some(stored) = &state.stored {
                    assert_eq!(stored, &(body.clone(), expiry.clone()));
                }
                state.stored = Some((body, expiry));
                if state.drop_ack {
                    state.drop_ack = false;
                    continue;
                }
                (204, "application/octet-stream", Vec::new(), String::new())
            } else {
                let error = state
                    .get_error
                    .or_else(|| state.stored.is_none().then_some((404, "task_not_found")));
                if let Some((status, code)) = error {
                    (status, "application/problem+json", json!({"type":format!("urn:lockyard:problem:{code}"),"status":status,"code":code,"detail":"refused","details":null}).to_string().into_bytes(), String::new())
                } else {
                    let (mut body, expiry) = state.stored.clone().unwrap();
                    if state.tamper {
                        let last = body.len() - 1;
                        body[last] = if body[last] == b'A' { b'B' } else { b'A' };
                    }
                    (
                        200,
                        "application/octet-stream",
                        body,
                        format!("Lockyard-Result-Expires-At: {expiry}\r\n"),
                    )
                }
            };
            write!(stream, "HTTP/1.1 {status} Reply\r\nLockyard-Protocol: 2\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    (url, state, thread)
}

#[test]
fn signed_result_reconnects_after_proven_replica_refusal_with_frozen_bytes() {
    for (status, code) in [(400, "protocol_unsupported"), (503, "server_draining")] {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let (url, state, server) = fixture();
        state.lock().unwrap().put_error = Some((status, code, 0));
        let job = lockyard_cloud_client::ulid();
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60_000;
        let first = client(&url, directory.path());
        assert_eq!(
            first
                .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
                .unwrap_err()
                .code(),
            Some(code)
        );
        let pending = first.pending_operations().pop().unwrap();
        state.lock().unwrap().put_error = None;
        // Reconnect in the same process must invalidate the discovery cache too.
        while pending.result_retry_at.is_some_and(|deadline| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                < deadline
        }) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        first.replay_signed_result(&pending.key).unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.discoveries, 2, "{code} must refresh discovery");
        assert_eq!(state.puts, 2);
        assert_eq!(
            state.stored.as_ref(),
            Some(&(
                pending.body.clone().unwrap().into_bytes(),
                pending.result_expires_at.clone().unwrap()
            ))
        );
        drop(state);
        stop(&url, server);
    }
}
fn client(url: &str, journal: &std::path::Path) -> Client {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(journal, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    Client::new(url, "fixture".into())
        .unwrap()
        .with_content_encryption(WORKSPACE, Some(WorkspaceKey::from_entropy([19; 32])), true)
        .with_pending_journal(journal)
        .unwrap()
}
fn stop(url: &str, thread: std::thread::JoinHandle<()>) {
    let _ = ureq::get(&format!("{url}/stop")).call();
    thread.join().unwrap();
}

#[test]
fn signed_result_raw_bytes_round_trip_and_put_replay_after_restart() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (url, state, server) = fixture();
    let job = lockyard_cloud_client::ulid();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    state.lock().unwrap().drop_ack = true;
    let first = client(&url, directory.path());
    assert_eq!(
        first
            .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
            .unwrap_err()
            .code(),
        Some("outcome_unknown")
    );
    let original = state.lock().unwrap().stored.clone().unwrap();
    drop(first);
    let restored = client(&url, directory.path());
    restored
        .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
        .unwrap();
    restored
        .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
        .unwrap();
    assert_eq!(state.lock().unwrap().stored.as_ref(), Some(&original));
    assert_eq!(
        restored.get_signed_result("owner", "worker", &job).unwrap(),
        DOCUMENT
    );
    assert_eq!(state.lock().unwrap().puts, 3);
    stop(&url, server);
}

#[test]
fn signed_result_missing_revoked_foreign_workspace_and_tampered_bytes_are_errors() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (url, state, server) = fixture();
    let client = client(&url, directory.path());
    let job = lockyard_cloud_client::ulid();
    for (status, code) in [
        (404, "task_not_found"),
        (401, "credential_revoked"),
        (403, "revoked"),
    ] {
        state.lock().unwrap().get_error = Some((status, code));
        let error = client
            .get_signed_result("owner", "worker", &job)
            .unwrap_err();
        assert_eq!(error.code(), Some(code));
        assert_eq!(error.status(), Some(status));
    }
    state.lock().unwrap().get_error = None;
    client
        .put_signed_result(
            "worker",
            "worker",
            &job,
            DOCUMENT,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 60_000,
        )
        .unwrap();
    let original = state.lock().unwrap().stored.clone().unwrap();
    let foreign_workspace = "00000000-0000-4000-8000-000000000002";
    let key = WorkspaceKey::from_entropy([19; 32]);
    let purpose = format!("node-result/worker/{job}");
    // Use the same key and route so rejection specifically proves workspace AAD binding.
    let foreign = key
        .encrypt(
            foreign_workspace,
            &purpose,
            std::str::from_utf8(DOCUMENT).unwrap(),
        )
        .unwrap();
    assert_eq!(
        key.decrypt(foreign_workspace, &purpose, &foreign)
            .unwrap()
            .as_bytes(),
        DOCUMENT
    );
    state.lock().unwrap().stored = Some((foreign.into_bytes(), original.1.clone()));
    let error = client
        .get_signed_result("owner", "worker", &job)
        .unwrap_err();
    assert_eq!(error.code(), Some("content_authentication_failed"));
    assert_eq!(error.status(), None);
    state.lock().unwrap().stored = Some(original);
    state.lock().unwrap().tamper = true;
    let error = client
        .get_signed_result("owner", "worker", &job)
        .unwrap_err();
    assert_eq!(error.code(), Some("content_authentication_failed"));
    assert_eq!(error.status(), None);
    stop(&url, server);
}

#[test]
fn pending_result_rejects_changed_document_expiry_and_rotated_key_without_upload() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (url, state, server) = fixture();
    let job = lockyard_cloud_client::ulid();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    state.lock().unwrap().drop_ack = true;
    let first = client(&url, directory.path());
    assert!(
        first
            .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
            .is_err()
    );
    for (bytes, expiry) in [(b"changed".as_slice(), expiry), (DOCUMENT, expiry + 1000)] {
        assert_eq!(
            first
                .put_signed_result("worker", "worker", &job, bytes, expiry)
                .unwrap_err()
                .code(),
            Some("outcome_unknown")
        );
    }
    drop(first);
    let rotated = Client::new(&url, "fixture".into())
        .unwrap()
        .with_content_encryption(WORKSPACE, Some(WorkspaceKey::from_entropy([20; 32])), true)
        .with_pending_journal(directory.path())
        .unwrap();
    assert_eq!(
        rotated
            .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
            .unwrap_err()
            .code(),
        Some("outcome_unknown")
    );
    assert_eq!(state.lock().unwrap().puts, 1);
    stop(&url, server);
}

#[test]
fn quota_refusal_requires_explicit_resume_with_frozen_operation_and_retry_deadline() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (url, state, server) = fixture();
    state.lock().unwrap().put_error = Some((429, "relay_budget_exceeded", 1));
    let job = lockyard_cloud_client::ulid();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    let first = client(&url, directory.path());
    assert_eq!(
        first
            .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
            .unwrap_err()
            .code(),
        Some("relay_budget_exceeded")
    );
    let pending = first.pending_operations().pop().unwrap();
    assert!(!Client::result_permanently_refused(&pending));
    for _ in 0..2 {
        assert_eq!(
            first.replay_signed_result(&pending.key).unwrap_err().code(),
            Some("relay_budget_exceeded")
        );
    }
    assert_eq!(state.lock().unwrap().puts, 1);
    // Explicit resumption changes only the retry decision, including across restart.
    first.resume_signed_result(&pending.key).unwrap();
    drop(first);
    let restored = client(&url, directory.path());
    let resumed = restored.pending_operations().pop().unwrap();
    assert_eq!(resumed.body, pending.body);
    assert_eq!(resumed.key, pending.key);
    assert_eq!(resumed.result_expires_at, pending.result_expires_at);
    assert_eq!(resumed.result_retry_at, pending.result_retry_at);
    assert!(!Client::result_retry_ready(&resumed));
    assert!(restored.replay_signed_result(&pending.key).is_err());
    assert_eq!(state.lock().unwrap().puts, 1);
    state.lock().unwrap().put_error = None;
    while !Client::result_retry_ready(&resumed) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    restored.replay_signed_result(&pending.key).unwrap();
    assert_eq!(
        state.lock().unwrap().stored.as_ref(),
        Some(&(
            pending.body.unwrap().into_bytes(),
            pending.result_expires_at.unwrap()
        ))
    );
    restored
        .acknowledge_signed_result("worker", "worker", &job, DOCUMENT, expiry)
        .unwrap();
    assert!(restored.pending_operations().is_empty());
    stop(&url, server);
}

#[test]
fn frozen_result_replays_after_content_expiry_without_original_document() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let (url, state, server) = fixture();
    let job = lockyard_cloud_client::ulid();
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 300;
    state.lock().unwrap().drop_ack = true;
    let first = client(&url, directory.path());
    assert!(
        first
            .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
            .is_err()
    );
    let pending = first.pending_operations().pop().unwrap();
    let original = pending.body.clone();
    drop(first);
    std::thread::sleep(std::time::Duration::from_millis(350));
    let restored = client(&url, directory.path());
    restored.replay_signed_result(&pending.key).unwrap();
    assert_eq!(restored.pending_operations()[0].body, original);
    restored.resolve_pending(&pending.key).unwrap();
    assert!(restored.pending_operations().is_empty());
    assert_eq!(state.lock().unwrap().puts, 2);
    stop(&url, server);
}

#[test]
fn publication_refusal_and_retry_after_survive_restart_without_automatic_resend() {
    for (status, code) in [
        (401, "credential_revoked"),
        (403, "revoked"),
        (409, "idempotency_conflict"),
        (429, "relay_budget_exceeded"),
        (429, "rate_limited"),
        (503, "server_draining"),
        (503, "frozen"),
        (503, "temporarily_unavailable"),
    ] {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let (url, state, server) = fixture();
        let retry = if status == 503 { 1 } else { u64::MAX };
        state.lock().unwrap().put_error = Some((status, code, retry));
        let earliest_retry_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let job = lockyard_cloud_client::ulid();
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60_000;
        let first = client(&url, directory.path());
        let error = first
            .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
            .unwrap_err();
        assert_eq!(error.code(), Some(code));
        let pending = first.pending_operations().pop().unwrap();
        assert_eq!(pending.cause_code, code);
        if matches!(
            code,
            "rate_limited"
                | "relay_budget_exceeded"
                | "server_draining"
                | "frozen"
                | "temporarily_unavailable"
        ) {
            assert!(
                pending.result_retry_at.unwrap().saturating_mul(1000)
                    >= earliest_retry_ms.saturating_add(retry.saturating_mul(1000))
            );
        } else {
            assert!(pending.result_retry_at.is_none());
        }
        assert!(!Client::result_retry_ready(&pending));
        drop(first);
        let restored = client(&url, directory.path());
        assert_eq!(
            restored
                .replay_signed_result(&pending.key)
                .unwrap_err()
                .code(),
            Some(code)
        );
        assert_eq!(state.lock().unwrap().puts, 1);
        let replay = restored.pending_operations().pop().unwrap();
        assert_eq!(replay.body, pending.body);
        assert_eq!(replay.key, pending.key);
        assert_eq!(replay.path, pending.path);
        assert_eq!(replay.result_expires_at, pending.result_expires_at);
        assert_eq!(replay.result_retry_at, pending.result_retry_at);
        if status == 503 {
            state.lock().unwrap().put_error = None;
            while !Client::result_retry_ready(&replay) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            restored.replay_signed_result(&pending.key).unwrap();
            assert_eq!(state.lock().unwrap().puts, 2);
            assert_eq!(
                state.lock().unwrap().stored.as_ref(),
                Some(&(
                    pending.body.clone().unwrap().into_bytes(),
                    pending.result_expires_at.clone().unwrap()
                ))
            );
        }
        if code == "credential_revoked" {
            restored.quarantine_signed_result(&pending.key).unwrap();
            assert!(restored.pending_operations().is_empty());
            drop(restored);
            let restored = client(&url, directory.path());
            assert_eq!(
                restored
                    .put_signed_result("worker", "worker", &job, DOCUMENT, expiry)
                    .unwrap_err()
                    .code(),
                Some("outcome_unknown")
            );
            assert_eq!(state.lock().unwrap().puts, 1);
        }
        stop(&url, server);
    }
}
