// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn raw_call(request: &str) -> Value {
    let project = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["mcp", "--tools", "full"])
        .current_dir(project.path())
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID")
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
