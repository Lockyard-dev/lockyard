// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use lockyard_cloud_client::{Call, ClientError, CloudBackend, Transport};
use lockyard_core::proto::LostClaim;

fn mark(id: i64, at: Option<Stamp>) -> LostClaim {
    LostClaim {
        claim_id: id,
        session: "worker".into(),
        paths: vec![format!("src/{id}")],
        reason: Some("idle".into()),
        lost_at: at,
    }
}

#[test]
fn lost_status_keeps_the_last_two_hours_and_missing_timestamps() {
    let now = 10_000_000;
    let cutoff = now - 120 * 60 * 1000;
    let lost = recent_lost(
        vec![
            mark(1, Some(Stamp::Millis(cutoff - 1))),
            mark(2, Some(Stamp::Text(lockyard_core::proto::rfc3339(cutoff)))),
            mark(3, None),
            mark(4, Some(Stamp::Millis(now))),
        ],
        now,
    );
    assert_eq!(
        lost.iter()
            .map(|mark| mark["claim_id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        [4, 2, 3]
    );
    assert_eq!(lost[2]["lost_at"], Value::Null);
    assert!(lost.iter().all(|mark| mark.as_object().unwrap().len() == 4));
    assert_eq!(lost[0]["reason"], "idle");
    assert_eq!(lost[0]["paths"], json!(["src/4"]));
}

#[test]
fn lost_status_limits_output_to_the_ten_newest_marks() {
    let now = 10_000_000;
    let lost = recent_lost(
        (0..15)
            .map(|id| mark(id, Some(Stamp::Millis(now - id))))
            .rev()
            .collect(),
        now,
    );
    assert_eq!(lost.len(), 10);
    assert_eq!(
        lost.iter()
            .map(|mark| mark["claim_id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        (0..10).collect::<Vec<_>>()
    );
}

#[test]
fn compact_local_status_always_has_an_empty_lost_list() {
    let dir = tempfile::tempdir().unwrap();
    lockyard_core::Store::init(dir.path()).unwrap();
    let reply = crate::mcp::handle(
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "status", "arguments": {}}}),
        Some("worker"),
        dir.path(),
        Surface::Compact,
    )
    .unwrap();
    assert_eq!(reply["result"]["isError"], false);
    assert_eq!(reply["result"]["structuredContent"]["lost"], json!([]));
}

struct StatusCloud {
    lost: std::result::Result<Value, ClientError>,
}

impl Transport for StatusCloud {
    fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
        assert_eq!(call.method, "GET");
        assert_eq!(call.session, "worker");
        Ok(match call.path.as_str() {
            "/api/v1/bus/inbox" => json!({"messages": [], "skipped": 3}),
            "/api/v1/bus/inbox?all=true&limit=50" => json!({"messages": [], "skipped": 0}),
            "/api/v1/zones/claims?session=worker" => json!({"claims": [
                {"id": 11, "session": "worker", "paths": ["src/own"]},
                {"id": 12, "session": "lead", "paths": ["src/offered"]}
            ]}),
            "/api/v1/zones/lost?session=worker" => return self.lost.clone(),
            "/api/v1/bus/tasks" => json!({"tasks": [{
                "id": "BT-1", "title": "Work", "status": "claimed", "assignee": "worker"
            }]}),
            "/api/v1/registry/items?status=active&limit=200" => json!({"items": [{
                "id": "D-1", "title": "Task", "status": "active",
                "assignment": {"executor": "token:test:worker"}
            }]}),
            "/api/v1/registry/items?status=review&limit=200" => json!({"items": []}),
            other => panic!("unexpected status request: {other}"),
        })
    }
}

#[test]
fn compact_cloud_status_preserves_other_fields_when_lost_is_unavailable() {
    let read_status = |lost| {
        status(
            &mut CloudBackend::new(StatusCloud { lost }, "worker"),
            Some("worker"),
            10_000_000,
        )
        .unwrap()
    };
    let mut expected = read_status(Ok(json!({"lost": []})));
    assert_eq!(expected["lost"], json!([]));
    assert_eq!(expected["unread"], 3);
    assert_eq!(expected["claims"][0]["id"], 11);
    assert_eq!(expected["work"][0]["id"], "BT-1");
    assert_eq!(expected["offers"][0]["id"], 12);
    assert_eq!(expected["tasks"][0]["id"], "D-1");
    expected["lost"] = Value::Null;
    for lost in [
        Err(ClientError::Transport("lost endpoint unavailable".into())),
        Ok(json!({"lost": "invalid response"})),
    ] {
        assert_eq!(read_status(lost), expected);
    }
}
