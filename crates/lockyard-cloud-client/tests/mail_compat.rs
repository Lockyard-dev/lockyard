// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_cloud_client::{WorkspaceKey, transform_fields};
use serde_json::json;

#[path = "fixtures/legacy_mail_decoder.rs"]
mod legacy_mail_decoder;

#[test]
fn v0_3_16_mail_body_is_readable_by_v0_3_14_and_v0_3_15() {
    let entropy = [13; 32];
    let writer = WorkspaceKey::from_entropy(entropy);
    // Both releases pass the decrypted body straight to the reader. Their decoder
    // and body AAD are identical, so they share the fixture taken from git.
    let reader = legacy_mail_decoder::WorkspaceKey::from_entropy(entropy);
    let cases = [
        (
            "/api/v1/bus/messages",
            Some("bob"),
            "Обычное письмо\nстрока 2",
        ),
        ("/api/v1/bus/messages", Some("*"), "Рассылка всем"),
        ("/api/v1/bus/messages/42/reply", None, "Ответ на письмо"),
    ];
    let sender = format!(
        "{}: {} (parent_pid={})",
        "c".repeat(64),
        "s".repeat(64),
        u32::MAX
    );

    for (route, to, body) in cases {
        let mut request = json!({"body": body, "from_client": sender});
        if let Some(to) = to {
            request["to"] = json!(to);
            request["kind"] = json!("notice");
        }
        transform_fields(&mut request, "POST", route, "w", Some(&writer), true).unwrap();
        let prepared = request.clone();
        transform_fields(&mut request, "POST", route, "w", Some(&writer), true).unwrap();
        assert_eq!(request, prepared);
        assert!(!request.to_string().contains(&sender));
        assert!(request["from_client"].as_str().unwrap().len() <= 256);
        let ciphertext = request["body"].as_str().unwrap();
        assert_eq!(
            reader.decrypt("w", "body", ciphertext).unwrap(),
            body,
            "{route} {to:?}"
        );

        let mut inbox = json!({"messages":[{
            "body": request["body"],
            "from_client": request["from_client"],
        }]});
        transform_fields(
            &mut inbox,
            "GET",
            "/api/v1/bus/inbox",
            "w",
            Some(&writer),
            false,
        )
        .unwrap();
        assert_eq!(inbox["messages"][0]["body"], body);
        assert_eq!(inbox["messages"][0]["from_client"], sender);
    }
}
