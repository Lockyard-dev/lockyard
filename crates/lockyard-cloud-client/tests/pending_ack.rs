// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_cloud_client::{Call, Client, Transport, WorkspaceKey};
use serde_json::json;
use std::io::{Read, Write};

#[test]
fn deferred_ack_keeps_frozen_operation_until_outbox_completion_is_durable() {
    let (directory, url, call) = deferred_operation(false);
    let key = call.key.clone().unwrap();
    let restored = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    // This acknowledges the caller's already-durable outbox completion after restart.
    restored.acknowledge_write(&call).unwrap();
    assert!(restored.pending_operation(&key).is_none());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn deferred_ack_rejects_changed_operation_and_keeps_persisted_pending() {
    let (directory, url, call) = deferred_operation(false);
    let key = call.key.clone().unwrap();
    let mut changed_body = call.clone();
    changed_body.body = Some(json!({"title":"different"}));
    let mut changed_method = call.clone();
    changed_method.method = "DELETE".into();
    let mut changed_path = call.clone();
    changed_path.path.push_str("/A-1");
    let mut changed_session = call.clone();
    changed_session.session = "other-session".into();
    let mut changed_repository = call.clone();
    changed_repository.repository = Some("other-repository".into());
    for changed in [
        changed_body,
        changed_method,
        changed_path,
        changed_session,
        changed_repository,
    ] {
        let restored = Client::new(&url, "fixture-token".into())
            .unwrap()
            .with_pending_journal(&directory)
            .unwrap();
        assert_eq!(
            restored.acknowledge_write(&changed).unwrap_err().code(),
            Some("idempotency_conflict")
        );
        assert!(restored.pending_operation(&key).is_some());
        // Every rejection must also leave the on-disk operation intact across another restart.
    }
    let restored = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    let mut same_operation = call;
    same_operation.deadline_ms = Some(4_000);
    same_operation.attempt_timeout_ms = Some(200);
    same_operation.defer_pending_ack = false;
    restored.acknowledge_write(&same_operation).unwrap();
    assert!(restored.pending_operation(&key).is_none());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn deferred_ack_matches_original_request_after_encryption_and_restart() {
    let (directory, url, call) = deferred_operation(true);
    let key = call.key.clone().unwrap();
    let restored = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    let mut wire_body = call.clone();
    wire_body.body = Some(
        serde_json::from_str(
            restored
                .pending_operation(&key)
                .unwrap()
                .body
                .as_deref()
                .unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        restored.acknowledge_write(&wire_body).unwrap_err().code(),
        Some("idempotency_conflict")
    );
    assert!(restored.pending_operation(&key).is_some());
    restored.acknowledge_write(&call).unwrap();
    assert!(restored.pending_operation(&key).is_none());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn deferred_ack_quarantines_legacy_journal_without_original_digest() {
    let (directory, url, call) = deferred_operation(false);
    let scope = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let journals: Vec<_> = std::fs::read_dir(scope)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    assert_eq!(
        journals.len(),
        1,
        "exactly one pending operation is persisted"
    );
    let journal = &journals[0];
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journal).unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("request_digest");
    std::fs::write(journal, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let restored = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    assert_eq!(
        restored.acknowledge_write(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    assert!(
        restored
            .pending_operation(call.key.as_deref().unwrap())
            .is_some()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

fn deferred_operation(encrypted: bool) -> (std::path::PathBuf, String, Call) {
    let directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("ly-deferred-ack-{}", lockyard_cloud_client::ulid()));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for (index, stream) in listener.incoming().take(2).enumerate() {
            let mut stream = stream.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..end]);
                    let length = head
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let body = if index == 0 {
                json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":[]})
            } else {
                json!({"id":"A-1"})
            }
            .to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLockyard-Protocol: 2\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    let mut call = Call::write(
        "session",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title":"original"}),
    );
    call.defer_pending_ack = true;
    let key = call.key.clone().unwrap();
    let client = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    let client = if encrypted {
        client.with_content_encryption(
            "fixture-workspace",
            Some(WorkspaceKey::from_entropy([31; 32])),
            true,
        )
    } else {
        client
    };
    client.call(&call).unwrap();
    let pending = client
        .pending_operation(&key)
        .expect("the daemon has not yet durably completed its outbox entry");
    if encrypted {
        assert!(pending.body.as_deref().unwrap().contains("lyenc1."));
        assert!(!pending.body.as_deref().unwrap().contains("original"));
    } else {
        assert_eq!(pending.body.as_deref(), Some(r#"{"title":"original"}"#));
    }
    drop(client);
    let restored = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    assert_eq!(restored.pending_operation(&key).unwrap().body, pending.body);
    server.join().unwrap();
    (directory, url, call)
}
