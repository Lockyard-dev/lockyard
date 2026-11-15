// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

#[test]
fn preserves_cyrillic_and_emoji() {
    assert_eq!(
        super::escape_controls("Почта 😀\nready"),
        "Почта 😀\\nready"
    );
}

#[test]
fn escapes_bidi_controls_in_mail() {
    assert_eq!(
        super::escape_controls("safe\u{202e}hidden\u{2069}"),
        "safe\\u{202e}hidden\\u{2069}"
    );
}

#[test]
fn task_list_json_escapes_controls_in_titles() {
    let task: super::Task = serde_json::from_value(serde_json::json!({
        "id": "D-1",
        "title": "line\nbreak\u{202e}",
        "body": "body\t",
        "status": "open",
        "author": "a",
        "assignee": null,
        "lease_until": null,
        "evidence": null,
        "created_at": 1,
        "updated_at": 1
    }))
    .unwrap();
    let output = super::output(&vec![task], "").unwrap();
    let encoded = serde_json::to_string(&output.json).unwrap();
    assert!(encoded.contains("\\n"), "{encoded}");
    assert!(serde_json::from_str::<serde_json::Value>(&encoded).is_ok());
    let _ = serde_json::from_str::<serde_json::Value>(&encoded).unwrap();
}

#[test]
fn json_mail_body_helpers_escape_messages_and_receipts() {
    let message: super::Message = serde_json::from_value(serde_json::json!({
        "id": 1,
        "from": "a",
        "to": "b",
        "body": "safe\u{202e}hidden"
    }))
    .unwrap();
    let messages = super::safe_messages(vec![message]);
    assert_eq!(messages[0].body, "safe\\u{202e}hidden");

    let receipt = lockyard_core::bus::Receipt {
        id: 1,
        to: "b".into(),
        body: "safe\u{202e}hidden".into(),
        created_at: 0,
        reply_to: None,
        status: lockyard_core::bus::Delivery::Sent,
        delivered_at: None,
        read_at: None,
        replied_at: None,
    };
    let receipts = super::safe_receipts(vec![receipt]);
    assert_eq!(receipts[0].body, "safe\\u{202e}hidden");
}
