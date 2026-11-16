// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use lockyard_core::Store;

include!("tests/catalog.rs");
include!("tests/workflows.rs");

#[test]
fn mail_push_mcp_update_addresses_urgent_and_legacy_server() {
    use lockyard_cloud_client::{
        Client, CloudBackend,
        fake::{FakeServer, Reply},
    };
    use std::cell::RefCell;
    for push in [true, false] {
        let server =
            FakeServer::start_routed_with_capabilities(if push { &["mail_push_v1"] } else { &[] });
        let backend = RefCell::new(CloudBackend::new(
            Client::new(&server.url(), "test-token".into()).unwrap(),
            "alice",
        ));
        for to in [
            "*",
            "all",
            "все",
            "everyone",
            "@claude",
            "@cursor",
            "@codex",
            "@zone:client",
            "@path:src/lib.rs",
        ] {
            server.enqueue(
                "/api/v1/bus/messages",
                Reply::json(200, json!({"id":42,"to":to,"body":"test","from":"alice"})),
            );
            let args = json!({"to":to,"body":"test","urgent":push});
            let answer = run_composite_steps(
                "update",
                Args(&args),
                Some("alice"),
                Path::new("/unused"),
                &mut None,
                |name, arguments, _| match name {
                    "msg_send" => send_mail(
                        &mut *backend.borrow_mut(),
                        "alice",
                        Args(&arguments),
                        Some("codex"),
                        &|_| panic!("broadcast must bypass presence resolution"),
                    ),
                    "msg_inbox" => {
                        assert_eq!(arguments["peek"], true);
                        Ok(json!({"messages":[]}))
                    }
                    _ => panic!("unexpected step {name}"),
                },
            );
            if push || matches!(to, "*" | "all" | "все" | "everyone") {
                assert!(answer.is_ok(), "{to}: {answer:?}");
            } else {
                assert!(
                    answer
                        .unwrap_err()
                        .to_string()
                        .contains("сервер не поддерживает")
                );
            }
        }
        let sent: Vec<_> = server
            .requests()
            .into_iter()
            .filter(|r| r.path == "/api/v1/bus/messages")
            .collect();
        assert_eq!(sent.len(), if push { 9 } else { 4 });
        for (i, request) in sent.iter().enumerate() {
            assert_eq!(
                request.body["to"],
                if push {
                    [
                        "*",
                        "all",
                        "все",
                        "everyone",
                        "@claude",
                        "@cursor",
                        "@codex",
                        "@zone:client",
                        "@path:src/lib.rs",
                    ][i]
                } else {
                    "*"
                }
            );
            assert_eq!(request.body.get("urgent"), push.then_some(&json!(true)));
        }
        assert!(
            !server
                .requests()
                .iter()
                .any(|r| r.path.starts_with("/api/v1/presence"))
        );
    }
    let compact = tools(Surface::Compact);
    let update = compact.iter().find(|t| t["name"] == "update").unwrap();
    assert_eq!(
        update["inputSchema"]["properties"]["urgent"]["type"],
        "boolean"
    );
}
