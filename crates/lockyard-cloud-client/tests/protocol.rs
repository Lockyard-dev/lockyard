// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! EP-10 HTTP fixtures record discovery separately from the eventual operation.
use lockyard_cloud_client::{Call, Client, ClientError, Transport};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

struct Reply {
    status: u16,
    body: Value,
    protocol: Option<&'static str>,
    extra: &'static str,
}

impl Reply {
    fn json(status: u16, body: Value, protocol: Option<&'static str>) -> Self {
        Self {
            status,
            body,
            protocol,
            extra: "",
        }
    }
}

struct Server {
    url: String,
    seen: Arc<Mutex<Vec<Request>>>,
}

impl Server {
    fn start(replies: Vec<Reply>) -> Self {
        Self::start_with_hook(replies, |_| {})
    }

    fn start_with_hook(
        replies: Vec<Reply>,
        before_reply: impl Fn(&Request) + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let request = read_request(&mut stream);
                before_reply(&request);
                recorded.lock().unwrap().push(request);
                let reply = replies
                    .next()
                    .unwrap_or_else(|| Reply::json(500, json!({}), None));
                let body = reply.body.to_string();
                let echo = reply
                    .protocol
                    .map(|value| format!("Lockyard-Protocol: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}{}\r\n{}",
                    reply.status,
                    body.len(),
                    echo,
                    reply.extra,
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self { url, seen }
    }

    fn client(&self) -> Client {
        Client::new(&self.url, "fixture-token".into()).unwrap()
    }
    fn requests(&self) -> Vec<Request> {
        self.seen.lock().unwrap().clone()
    }
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let end = loop {
        if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap().split(' ').collect::<Vec<_>>();
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.to_string()))
        .collect::<Vec<_>>();
    let length = headers
        .iter()
        .find(|(key, _)| key == "content-length")
        .map(|(_, value)| value.parse::<usize>().unwrap())
        .unwrap_or(0);
    while bytes.len() < end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
    }
    Request {
        method: first[0].into(),
        path: first[1].into(),
        headers,
        body: String::from_utf8(bytes[end..end + length].to_vec()).unwrap(),
    }
}

fn discovery(protocol: u16, min: u16, max: u16, capabilities: &[&str]) -> Reply {
    Reply::json(
        200,
        json!({"selected_protocol":protocol,"min_protocol":min,"max_protocol":max,"capabilities":capabilities}),
        Some(if protocol == 1 { "1" } else { "2" }),
    )
}

fn problem(status: u16, code: &str, details: Value, protocol: Option<&'static str>) -> Reply {
    Reply::json(
        status,
        json!({"type":format!("urn:lockyard:problem:{code}"),"title":"Request refused","status":status,"detail":"fixture","instance":"urn:request:fixture","code":code,"details":details}),
        protocol,
    )
}

fn unsupported(min: u16, max: u16) -> Reply {
    let supported: Vec<u16> = (min..=max).collect();
    problem(
        400,
        "protocol_unsupported",
        json!({"min_protocol":min,"max_protocol":max,"supported_protocols":supported,"selected_protocol":null}),
        None,
    )
}

fn read() -> Call {
    Call::get("fixture-session", "/api/v1/zones/claims".into())
}
fn write() -> Call {
    Call::write(
        "fixture-session",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title":"original-body"}),
    )
}
fn serialized(error: ClientError) -> String {
    serde_json::to_string(&error).unwrap()
}

#[test]
fn auto_area_capability_is_negotiated_from_discovery_body_or_header() {
    for header_only in [false, true] {
        let mut reply = discovery(
            2,
            1,
            2,
            if header_only {
                &[]
            } else {
                &["registry_auto_area_v1"]
            },
        );
        if header_only {
            reply.extra =
                "Lockyard-Capabilities: registry_assignee_session_v1, registry_auto_area_v1\r\n";
        }
        let server = Server::start(vec![reply]);
        let client = server.client();
        assert!(client.registry_auto_area("fixture-session").unwrap());
        assert!(client.registry_auto_area("fixture-session").unwrap());
        assert_eq!(server.requests().len(), 1, "reuse discovery cache");
        assert_eq!(server.requests()[0].path, "/api/v1/protocol");
    }
}

#[test]
fn auto_area_capability_is_retained_from_a_later_response_header() {
    let mut later = Reply::json(200, json!([]), Some("2"));
    later.extra = "Lockyard-Capabilities: registry_assignee_session_v1, registry_auto_area_v1\r\n";
    let server = Server::start(vec![discovery(2, 1, 2, &[]), later]);
    let client = server.client();
    assert!(!client.registry_auto_area("fixture-session").unwrap());
    client.call(&read()).unwrap();
    assert!(client.registry_auto_area("fixture-session").unwrap());
    assert_eq!(
        server.requests().len(),
        2,
        "later header reuses existing discovery"
    );
}

#[test]
fn auto_area_capability_is_cleared_by_latest_successful_header() {
    for latest_header in [
        "",
        "Lockyard-Capabilities: registry_assignee_session_v1\r\n",
    ] {
        let mut enabled = Reply::json(200, json!([]), Some("2"));
        enabled.extra = "Lockyard-Capabilities: registry_auto_area_v1\r\n";
        let mut disabled = Reply::json(200, json!([]), Some("2"));
        disabled.extra = latest_header;
        let server = Server::start(vec![discovery(2, 1, 2, &[]), enabled, disabled]);
        let client = server.client();
        client.call(&read()).unwrap();
        assert!(client.registry_auto_area("fixture-session").unwrap());
        client.call(&read()).unwrap();
        assert!(!client.registry_auto_area("fixture-session").unwrap());
        assert_eq!(server.requests().len(), 3, "reuse HTTP negotiation only");
    }
}

#[test]
fn live_protocol_without_auto_area_clears_cached_body_or_header_confirmation() {
    for header_only in [false, true] {
        let mut initial = discovery(
            2,
            1,
            2,
            if header_only {
                &[]
            } else {
                &["registry_auto_area_v1"]
            },
        );
        if header_only {
            initial.extra = "Lockyard-Capabilities: registry_auto_area_v1\r\n";
        }
        let server = Server::start(vec![initial, discovery(2, 1, 2, &[])]);
        let client = server.client();
        assert!(client.registry_auto_area("fixture-session").unwrap());
        let value = client
            .call(&Call::get("fixture-session", "/api/v1/protocol".into()))
            .unwrap();
        assert_eq!(value["capabilities"], json!([]));
        assert!(!client.registry_auto_area("fixture-session").unwrap());
        assert_eq!(server.requests().len(), 2);
    }
}

#[test]
fn live_protocol_forwarding_uses_only_its_own_capability_header() {
    let mut enabled = discovery(2, 1, 2, &[]);
    enabled.extra = "Lockyard-Capabilities: registry_auto_area_v1\r\n";
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        enabled,
        discovery(2, 1, 2, &[]),
    ]);
    let client = server.client();
    assert!(!client.registry_auto_area("fixture-session").unwrap());
    let protocol_call = Call::get("fixture-session", "/api/v1/protocol".into());
    let enabled = client.call(&protocol_call).unwrap();
    assert_eq!(enabled["capabilities"], json!(["registry_auto_area_v1"]));
    assert!(client.registry_auto_area("fixture-session").unwrap());
    let disabled = client.call(&protocol_call).unwrap();
    assert_eq!(disabled["capabilities"], json!([]));
    assert!(!client.registry_auto_area("fixture-session").unwrap());
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn failed_response_does_not_replace_latest_auto_area_confirmation() {
    for supported in [false, true] {
        let initial = discovery(
            2,
            1,
            2,
            if supported {
                &["registry_auto_area_v1"]
            } else {
                &[]
            },
        );
        let mut refused = problem(403, "forbidden", json!({}), Some("2"));
        if !supported {
            refused.extra = "Lockyard-Capabilities: registry_auto_area_v1\r\n";
        }
        let server = Server::start(vec![initial, refused]);
        let client = server.client();
        assert_eq!(
            client.registry_auto_area("fixture-session").unwrap(),
            supported
        );
        assert_eq!(client.call(&read()).unwrap_err().code(), Some("forbidden"));
        assert_eq!(
            client.registry_auto_area("fixture-session").unwrap(),
            supported
        );
    }
}

#[test]
fn removed_auto_area_uses_legacy_area_lookup_despite_cached_negotiation() {
    use lockyard_core::{Backend, tasks::TaskSpec};
    let server = Server::start(vec![
        discovery(2, 1, 2, &["registry_auto_area_v1"]),
        Reply::json(200, json!([]), Some("2")),
        Reply::json(200, json!([{"id":"area-web", "key":"web"}]), Some("2")),
        Reply::json(200, json!({"id":"WEB-0001", "title":"t"}), Some("2")),
    ]);
    let client = server.client();
    assert!(client.registry_auto_area("fixture-session").unwrap());
    client.call(&read()).unwrap();
    let mut cloud = lockyard_cloud_client::CloudBackend::new(client, "fixture-session");
    let result = cloud.add_task(
        "fixture-session",
        &TaskSpec {
            title: "t".into(),
            paths: vec!["web/src/main.rs".into()],
            area: Some("web".into()),
            ..TaskSpec::default()
        },
        0,
    );
    let requests = server.requests();
    assert_eq!(
        requests.get(2).map(|request| request.path.as_str()),
        Some("/api/v1/registry/areas"),
        "rollback must use the legacy area lookup before creating a task"
    );
    result.unwrap();
    assert_eq!(requests.len(), 4);
    let body: Value = serde_json::from_str(&requests[3].body).unwrap();
    assert_eq!(body["area_id"], "area-web");
    assert!(body.get("paths").is_none());
}

#[test]
fn auto_area_rollback_refusal_explains_repeat_and_never_retries_the_write() {
    use lockyard_core::{Backend, tasks::TaskSpec};
    for (status, code, message, details) in [
        (400, "area_required", "Area is required", json!({})),
        (422, "invalid_request", "area_id is required", Value::Null),
        (
            422,
            "validation_error",
            "Validation rejected",
            json!({"area_id":["required"]}),
        ),
        (
            400,
            "invalid_request",
            "AreaId must be specified",
            Value::Null,
        ),
    ] {
        let mut refusal = problem(status, code, details.clone(), Some("2"));
        refusal.body["detail"] = json!(message);
        let server = Server::start(vec![
            discovery(2, 1, 2, &["registry_auto_area_v1"]),
            refusal,
            Reply::json(200, json!([{"id":"area-web", "key":"web"}]), Some("2")),
            Reply::json(200, json!({"id":"WEB-0001", "title":"t"}), Some("2")),
        ]);
        let mut cloud =
            lockyard_cloud_client::CloudBackend::new(server.client(), "fixture-session");
        let spec = TaskSpec {
            title: "t".into(),
            paths: vec!["web/src/main.rs".into()],
            area: Some("web".into()),
            ..TaskSpec::default()
        };
        let error = cloud.add_task("fixture-session", &spec, 0).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("Повтори команду"), "{text}");
        assert_eq!(text.matches("Повтори команду").count(), 1, "{text}");
        assert!(text.contains("--area <область>"), "{text}");
        assert!(text.contains(message), "{text}");
        match error {
            lockyard_core::Error::Cloud {
                code: actual_code,
                status: actual_status,
                details: actual_details,
                ..
            } => {
                assert_eq!(actual_code, code);
                assert_eq!(actual_status, Some(status));
                assert_eq!(actual_details, details);
            }
            other => panic!("lost refusal metadata: {other:?}"),
        }
        assert_eq!(
            server.requests().len(),
            2,
            "no automatic retry or area lookup"
        );
        cloud.add_task("fixture-session", &spec, 0).unwrap();
        let requests = server.requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[2].path, "/api/v1/registry/areas");
        let retry_body: Value = serde_json::from_str(&requests[3].body).unwrap();
        assert_eq!(retry_body["area_id"], "area-web");
        assert!(retry_body.get("paths").is_none());
        assert_ne!(
            requests[1].header("idempotency-key"),
            requests[3].header("idempotency-key")
        );
    }
}

#[test]
fn auto_area_task_creation_sends_paths_and_verbatim_optional_area_without_area_lookup() {
    use lockyard_core::{Backend, tasks::TaskSpec};
    for area in [None, Some("My-Override")] {
        let server = Server::start(vec![
            discovery(2, 1, 2, &["registry_auto_area_v1"]),
            Reply::json(
                200,
                json!({"id":"WEB-0001", "title":"t", "paths":["web/src/main.rs", "web/tests"]}),
                Some("2"),
            ),
        ]);
        let mut cloud =
            lockyard_cloud_client::CloudBackend::new(server.client(), "fixture-session");
        let spec = TaskSpec {
            title: "t".into(),
            paths: vec!["web/src/main.rs".into(), "web/tests".into()],
            area: area.map(str::to_string),
            ..TaskSpec::default()
        };
        let task = cloud.add_task("fixture-session", &spec, 0).unwrap();
        assert_eq!(task.paths, spec.paths);
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].path, "/api/v1/registry/items");
        let body: Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(body["paths"], json!(spec.paths));
        assert_eq!(body.get("area"), area.map(|area| json!(area)).as_ref());
        assert!(body.get("area_id").is_none());
    }
}

#[test]
fn auto_area_task_without_paths_is_refused_before_any_registry_request() {
    use lockyard_core::{Backend, tasks::TaskSpec};
    let server = Server::start(vec![discovery(2, 1, 2, &["registry_auto_area_v1"])]);
    let mut cloud = lockyard_cloud_client::CloudBackend::new(server.client(), "fixture-session");
    let error = cloud
        .add_task(
            "fixture-session",
            &TaskSpec {
                title: "t".into(),
                ..TaskSpec::default()
            },
            0,
        )
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("--path <путь>"), "{message}");
    assert!(message.contains("paths: ["), "{message}");
    assert!(
        message.contains("относительно корня рабочего места"),
        "{message}"
    );
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.requests()[0].path, "/api/v1/protocol");
}

#[test]
fn discovery_precedes_operations_and_echo_is_checked_on_every_response() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!([]), Some("2")),
        Reply::json(200, json!([]), None),
    ]);
    let client = server.client();
    client.call(&read()).unwrap();
    let error = client
        .call(&read())
        .expect_err("modern missing echo must fail");
    assert!(serialized(error).contains("protocol_response_invalid"));
    let seen = server.requests();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].path, "/api/v1/protocol");
    assert_eq!(seen[0].header("lockyard-protocol"), Some("2"));
    assert_eq!(
        seen[0].header("authorization"),
        Some("Bearer fixture-token")
    );
    assert_eq!(
        seen[0].header("x-lockyard-session"),
        Some("fixture-session")
    );
    assert_eq!(seen[1].header("lockyard-protocol"), Some("2"));
}

#[test]
fn client_downgrades_only_discovery_to_highest_common_version() {
    let server = Server::start(vec![
        unsupported(1, 1),
        discovery(1, 1, 1, &[]),
        Reply::json(200, json!([]), Some("1")),
    ]);
    server.client().call(&read()).unwrap();
    let seen = server.requests();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].path, "/api/v1/protocol");
    assert_eq!(seen[1].path, "/api/v1/protocol");
    assert_eq!(seen[1].header("lockyard-protocol"), Some("1"));
    assert_eq!(seen[2].header("lockyard-protocol"), Some("1"));
}

#[test]
fn incompatible_server_stops_before_mutation_without_a_downgrade_loop() {
    let server = Server::start(vec![unsupported(3, 4)]);
    let error = server.client().call(&write()).unwrap_err();
    assert!(serialized(error).contains("protocol_unsupported"));
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.requests()[0].method, "GET");
}

#[test]
fn domain_discovery_error_never_sends_the_requested_mutation() {
    let server = Server::start(vec![problem(400, "protocol_invalid", json!({}), None)]);
    let error = server.client().call(&write()).unwrap_err();
    assert!(serialized(error).contains("protocol_invalid"));
    assert_eq!(server.requests().len(), 1);
    assert_eq!(server.requests()[0].method, "GET");
}

#[test]
fn legacy_requires_a_safe_headerless_encryption_probe_before_mutation() {
    let server = Server::start(vec![
        Reply::json(404, json!({}), None),
        Reply::json(
            200,
            json!({"workspace_id":"w","encryption":"off","key_id":null}),
            None,
        ),
        Reply::json(200, json!({"id":"A-1"}), None),
    ]);
    let mut call = Call::write(
        "fixture-session",
        "POST",
        "/api/v1/zones/claims".into(),
        json!({"paths":["src"]}),
    );
    call.repository = Some(String::new());
    server.client().call(&call).unwrap();
    let seen = server.requests();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].path, "/api/v1/protocol");
    assert_eq!(seen[1].path, "/api/v1/workspace/encryption");
    assert_eq!(seen[1].method, "GET");
    assert_eq!(seen[1].header("lockyard-protocol"), None);
    assert_eq!(seen[2].header("lockyard-protocol"), None);
    assert_eq!(seen[2].header("x-lockyard-repository"), Some("-"));
}

#[test]
fn legacy_without_policy_probe_is_not_inferred_from_a_write_reply() {
    let server = Server::start(vec![
        Reply::json(404, json!({}), None),
        Reply::json(404, json!({}), None),
    ]);
    let _ = server.client().call(&write()).unwrap_err();
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.method == "GET")
    );
}

#[test]
fn typed_catalog_capability_is_required_before_sending_the_feature() {
    let server = Server::start(vec![discovery(2, 1, 2, &[])]);
    let call = Call::write(
        "fixture-session",
        "POST",
        "/api/v1/zones/catalog".into(),
        json!({"expected_revision":0,"catalog":{}}),
    );
    let error = server.client().call(&call).unwrap_err();
    assert!(serialized(error).contains("feature_unsupported"));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn supported_catalog_with_old_selected_version_requires_client_upgrade() {
    let server = Server::start(vec![
        unsupported(1, 1),
        discovery(1, 1, 1, &["zone_catalog_v1"]),
    ]);
    let call = Call::write(
        "fixture-session",
        "POST",
        "/api/v1/zones/catalog".into(),
        json!({"expected_revision":0,"catalog":{}}),
    );
    let error = server.client().call(&call).unwrap_err();
    assert!(serialized(error).contains("upgrade_required"));
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.method == "GET")
    );
}

#[test]
fn relay_budget_code_does_not_use_generic_http429_retry() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        problem(429, "relay_budget_exceeded", json!({}), Some("2")),
        Reply::json(200, json!({}), Some("2")),
    ]);
    let error = server.client().call(&write()).unwrap_err();
    assert!(serialized(error).contains("relay_budget_exceeded"));
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn unknown_code_stays_unknown_and_never_triggers_protocol_downgrade() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        problem(503, "future_server_code", json!({"safe":true}), Some("2")),
    ]);
    let mut call = write();
    call.deadline_ms = Some(2500);
    let error = server.client().call(&call).unwrap_err();
    assert!(serialized(error).contains("future_server_code"));
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn problem_details_preserve_stable_error_code_and_status() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        problem(
            400,
            "upgrade_required",
            json!({"min_protocol":2}),
            Some("2"),
        ),
    ]);
    let text = serialized(server.client().call(&read()).unwrap_err());
    assert!(text.contains("upgrade_required"), "{text}");
    assert!(text.contains("min_protocol"), "{text}");
    assert!(text.contains("400"), "{text}");
}

#[test]
fn contradictory_problem_envelopes_are_rejected() {
    let mut reply = problem(400, "upgrade_required", json!({}), Some("2"));
    reply.body["error"] = json!({"code":"feature_unsupported","message":"fixture","details":{}});
    let server = Server::start(vec![discovery(2, 1, 2, &[]), reply]);
    let error = server.client().call(&read()).unwrap_err();
    assert!(serialized(error).contains("protocol_response_invalid"));
}

#[test]
fn missing_write_echo_keeps_original_operation_and_never_blindly_replays() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":"A-1"}), None),
    ]);
    let call = write();
    let key = call.key.clone().unwrap();
    let error = server
        .client()
        .call(&call)
        .expect_err("an unverified write response is unknown");
    let text = serialized(error);
    assert!(text.contains("protocol_response_invalid"), "{text}");
    assert!(text.contains(&key), "pending key must be retained");
    assert!(
        text.contains("original-body"),
        "pending bytes must be retained"
    );
    assert!(text.contains("/api/v1/registry/items"));
    assert_eq!(server.requests().len(), 2);
    assert_eq!(server.requests()[1].body, call.body.unwrap().to_string());
}

#[test]
fn explicit_pending_replay_keeps_the_original_protocol_bytes_and_key() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":"A-1"}), None),
        Reply::json(200, json!({"id":"A-1"}), Some("2")),
    ]);
    let client = server.client();
    let call = write();
    assert!(client.call(&call).is_err());
    // Unknown ledger retention never authorizes an automatic second write, even when the
    // application accidentally repeats call(). A caller must reconcile the pending operation.
    let error = client.call(&call).unwrap_err();
    assert!(serialized(error).contains("outcome_unknown"));
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn replica_protocol_rejection_repeats_discovery_before_one_safe_write_retry() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        unsupported(1, 1),
        unsupported(1, 1),
        discovery(1, 1, 1, &[]),
        Reply::json(200, json!({"id":"A-1"}), Some("1")),
    ]);
    let client = server.client();
    let call = write();
    client.call(&call).unwrap();
    let seen = server.requests();
    assert_eq!(seen.len(), 5);
    assert_eq!(seen[1].path, "/api/v1/registry/items");
    assert_eq!(seen[2].path, "/api/v1/protocol");
    assert_eq!(seen[3].path, "/api/v1/protocol");
    assert_eq!(seen[4].header("lockyard-protocol"), Some("1"));
    assert_eq!(
        seen[1].header("idempotency-key"),
        seen[4].header("idempotency-key")
    );
    assert_eq!(seen[1].body, seen[4].body);
}

#[test]
fn modern_domain_error_with_wrong_echo_is_a_protocol_failure() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        problem(403, "forbidden", json!({}), Some("1")),
    ]);
    let error = server.client().call(&read()).unwrap_err();
    assert!(serialized(error).contains("protocol_response_invalid"));
}

#[test]
fn problem_status_must_match_the_actual_http_status() {
    let mut reply = problem(403, "forbidden", json!({}), Some("2"));
    reply.body["status"] = json!(400);
    let server = Server::start(vec![discovery(2, 1, 2, &[]), reply]);
    let error = server.client().call(&read()).unwrap_err();
    assert!(serialized(error).contains("protocol_response_invalid"));
}

#[test]
fn pending_journal_survives_restart_with_original_wire_bytes() {
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-protocol-journal-{}",
        lockyard_cloud_client::ulid()
    ));
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":"A-1"}), None),
    ]);
    let call = write();
    let key = call.key.clone().unwrap();
    let client = server.client().with_pending_journal(&directory).unwrap();
    assert!(client.call(&call).is_err());
    let pending = client.pending_operation(&key).unwrap();
    assert_eq!(
        pending.body.as_deref(),
        Some(server.requests()[1].body.as_str())
    );
    assert_eq!(pending.protocol.selected, 2);
    assert!(!format!("{pending:?}").contains("original-body"));
    drop(client);
    let restored = server.client().with_pending_journal(&directory).unwrap();
    let restored_pending = restored.pending_operation(&key).unwrap();
    assert_eq!(restored_pending.body, pending.body);
    assert_eq!(restored_pending.key, key);
    assert_eq!(
        restored.call(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    assert_eq!(server.requests().len(), 2);
    restored.resolve_pending(&key).unwrap();
    assert!(restored.pending_operation(&key).is_none());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn pending_journal_rejects_symlinked_directory_before_any_network_request() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-protocol-symlink-{}",
        lockyard_cloud_client::ulid()
    ));
    std::fs::create_dir(&root).unwrap();
    let actual = root.join("actual");
    std::fs::create_dir(&actual).unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&actual, &alias).unwrap();
    let server = Server::start(vec![]);
    let error = match server.client().with_pending_journal(&alias) {
        Ok(_) => panic!("symlinked journal must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, ClientError::Invalid(_)), "{error:?}");
    assert_eq!(error.code(), None, "no mutation could have been sent");
    assert!(server.requests().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn successful_write_removes_durable_pending_record() {
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-protocol-success-{}",
        lockyard_cloud_client::ulid()
    ));
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":"A-1"}), Some("2")),
    ]);
    let call = write();
    let client = server.client().with_pending_journal(&directory).unwrap();
    client.call(&call).unwrap();
    assert!(client.pending_operations().is_empty());
    drop(client);
    assert!(
        server
            .client()
            .with_pending_journal(&directory)
            .unwrap()
            .pending_operations()
            .is_empty()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_repository_write_echo_preserves_pending_operation() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":"A-1"}), Some("2")),
    ]);
    let client = server.client();
    let mut call = write();
    call.repository = Some("repository".into());
    let error = client.call(&call).unwrap_err();
    assert!(serialized(error).contains("protocol_response_invalid"));
    assert!(
        client
            .pending_operation(call.key.as_deref().unwrap())
            .is_some()
    );
}

#[test]
fn duplicate_repository_write_echo_preserves_pending_operation() {
    let mut reply = Reply::json(200, json!({"id":"A-1"}), Some("2"));
    reply.extra = "X-Lockyard-Repository: repository\r\nX-Lockyard-Repository: other\r\n";
    let server = Server::start(vec![discovery(2, 1, 2, &[]), reply]);
    let client = server.client();
    let mut call = write();
    call.repository = Some("repository".into());
    let error = client.call(&call).unwrap_err();
    assert!(serialized(error).contains("protocol_response_invalid"));
    assert!(
        client
            .pending_operation(call.key.as_deref().unwrap())
            .is_some()
    );
}

#[test]
fn legacy_repository_namespace_write_requires_the_minus_echo() {
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":"A-1"}), Some("2")),
    ]);
    let client = server.client();
    let mut call = write();
    call.repository = Some(String::new());
    let error = client.call(&call).unwrap_err();
    assert!(serialized(error).contains("protocol_response_invalid"));
    assert!(
        client
            .pending_operation(call.key.as_deref().unwrap())
            .is_some()
    );
    assert_eq!(
        server.requests()[1].header("x-lockyard-repository"),
        Some("-")
    );
}

#[test]
fn journal_preflight_failure_never_marks_an_unsent_mutation_unknown() {
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-protocol-preflight-{}",
        lockyard_cloud_client::ulid()
    ));
    let server = Server::start(vec![discovery(2, 1, 2, &[])]);
    let client = server.client().with_pending_journal(&directory).unwrap();
    let scope = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    // Exclusive journal ownership is checked before discovery as well as mutation send.
    // Replacing a still-empty journal directory with a file must cause no network requests.
    std::fs::remove_dir(&scope).unwrap();
    std::fs::write(&scope, "not a directory").unwrap();
    let call = write();
    let error = client.call(&call).unwrap_err();
    assert!(matches!(error, ClientError::Invalid(_)), "{error:?}");
    assert_eq!(error.code(), None);
    assert!(client.pending_operations().is_empty());
    assert!(server.requests().is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn post_send_journal_cleanup_failure_keeps_original_pending_operation() {
    use std::os::unix::fs::PermissionsExt;
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-protocol-cleanup-{}",
        lockyard_cloud_client::ulid()
    ));
    let journal = Arc::new(Mutex::new(None::<std::path::PathBuf>));
    let writer_journal = Arc::clone(&journal);
    let server = Server::start_with_hook(
        vec![
            discovery(2, 1, 2, &[]),
            Reply::json(200, json!({"id":"A-1"}), Some("2")),
        ],
        move |request| {
            if request.method == "POST" {
                // The request has been received and its pre-send file is already durable.
                let scope = writer_journal.lock().unwrap().clone().unwrap();
                assert_eq!(std::fs::read_dir(&scope).unwrap().count(), 1);
                std::fs::set_permissions(scope, std::fs::Permissions::from_mode(0o500)).unwrap();
            }
        },
    );
    let client = server.client().with_pending_journal(&directory).unwrap();
    let scope = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    *journal.lock().unwrap() = Some(scope.clone());
    let call = write();
    let key = call.key.as_deref().unwrap();
    let error = client.call(&call).unwrap_err();
    // Restore permissions before assertions so a failing regression leaves no inaccessible tempdir.
    std::fs::set_permissions(&scope, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(error, ClientError::OutcomeUnknown(_)), "{error:?}");
    let pending = client
        .pending_operation(key)
        .expect("cleanup never proves an unsent write");
    assert_eq!(
        pending.body.as_deref(),
        Some(server.requests()[1].body.as_str())
    );
    assert_eq!(pending.key, key);
    assert_eq!(pending.path, call.path);
    assert_eq!(
        client.call(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    assert_eq!(
        server.requests().len(),
        2,
        "never reissue after cleanup failure"
    );
    let restored = server.client().with_pending_journal(&directory).unwrap();
    assert_eq!(restored.pending_operation(key).unwrap().body, pending.body);
    assert_eq!(restored.pending_operation(key).unwrap().key, pending.key);
    std::fs::remove_dir_all(directory).unwrap();
}

fn catalog_write() -> Call {
    Call::write(
        "fixture-session",
        "POST",
        "/api/v1/zones/catalog".into(),
        json!({
            "expected_revision":0,
            "catalog":{"version":1,"zones":{"code":["src"]},"groups":{}}
        }),
    )
}

#[test]
fn server_catalog_invalid_is_a_definite_refusal_and_clears_pending() {
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-protocol-catalog-refusal-{}",
        lockyard_cloud_client::ulid()
    ));
    let server = Server::start(vec![
        discovery(2, 1, 2, &["zone_catalog_v1"]),
        problem(400, "catalog_invalid", json!({}), Some("2")),
    ]);
    let client = server
        .client()
        .with_content_encryption(
            "00000000-0000-0000-0000-000000000001",
            Some(lockyard_cloud_client::WorkspaceKey::from_entropy([47; 32])),
            true,
        )
        .with_pending_journal(&directory)
        .unwrap();
    let call = catalog_write();
    let error = client.call(&call).unwrap_err();
    assert_eq!(error.code(), Some("catalog_invalid"));
    assert_eq!(error.status(), Some(400));
    assert!(client.pending_operations().is_empty());
    assert!(
        server
            .client()
            .with_pending_journal(&directory)
            .unwrap()
            .pending_operations()
            .is_empty()
    );
    assert_eq!(server.requests().len(), 2);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn malformed_successful_catalog_response_keeps_the_frozen_mutation() {
    let mut reply = Reply::json(
        200,
        json!({"format":"lockyard.zone_catalog.v1","revision":1}),
        Some("2"),
    );
    reply.extra = "X-Lockyard-Repository: -\r\n";
    let server = Server::start(vec![discovery(2, 1, 2, &["zone_catalog_v1"]), reply]);
    let client = server.client().with_content_encryption(
        "00000000-0000-0000-0000-000000000001",
        Some(lockyard_cloud_client::WorkspaceKey::from_entropy([47; 32])),
        true,
    );
    let call = catalog_write();
    let error = client.call(&call).unwrap_err();
    assert!(matches!(error, ClientError::OutcomeUnknown(_)), "{error:?}");
    let pending = client
        .pending_operation(call.key.as_deref().unwrap())
        .unwrap();
    assert_eq!(pending.cause_code, "catalog_invalid");
    assert_eq!(pending.cause_status, None);
    assert_eq!(
        pending.body.as_deref(),
        Some(server.requests()[1].body.as_str())
    );
    assert_eq!(
        client.call(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn durable_outbox_replay_refusal_cannot_prove_the_original_write_failed() {
    for (status, code) in [
        (401, "unauthorized"),
        (403, "forbidden"),
        (400, "protocol_unsupported"),
        (503, "server_draining"),
    ] {
        let server = Server::start(vec![
            discovery(2, 1, 2, &[]),
            Reply::json(200, json!({"id":7}), None),
            problem(status, code, json!({}), Some("2")),
        ]);
        let client = server.client();
        let mut call = Call::write(
            "fixture-session",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"to":"other","body":"original-body"}),
        );
        call.defer_pending_ack = true;
        assert_eq!(
            client.call(&call).unwrap_err().code(),
            Some("outcome_unknown")
        );
        let original = client
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap();
        let error = client.call(&call).unwrap_err();
        assert_eq!(
            error.code(),
            Some("outcome_unknown"),
            "{status}/{code}: {error:?}"
        );
        assert_eq!(
            server.requests().len(),
            3,
            "one raw replay, no new discovery/downgrade"
        );
        let pending = client
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap();
        assert_eq!(pending.key, original.key);
        assert_eq!(pending.body, original.body);
        assert_eq!(pending.protocol, original.protocol);
        assert_eq!(pending.cause_code, code);
        let requests = server.requests();
        assert_eq!(requests[1].body, requests[2].body);
        assert_eq!(requests[1].path, requests[2].path);
        assert_eq!(
            requests[1].header("idempotency-key"),
            requests[2].header("idempotency-key")
        );
    }
}

#[test]
fn durable_outbox_replay_without_trusted_age_or_identity_stays_quarantined() {
    for (field, value) in [
        ("first_sent_unix_secs", Value::Null),
        ("first_sent_unix_secs", json!(0)),
        ("first_sent_unix_secs", json!(u64::MAX)),
        ("request_digest", Value::Null),
    ] {
        let directory = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("ly-unknown-age-{}", lockyard_cloud_client::ulid()));
        let server = Server::start(vec![
            discovery(2, 1, 2, &[]),
            Reply::json(200, json!({"id":7}), None),
        ]);
        let mut call = Call::write(
            "fixture-session",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"to":"other","body":"original-body"}),
        );
        call.defer_pending_ack = true;
        let client = server.client().with_pending_journal(&directory).unwrap();
        assert!(client.call(&call).is_err());
        drop(client);
        let scoped = std::fs::read_dir(&directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let journals: Vec<_> = std::fs::read_dir(scoped)
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
        let file = &journals[0];
        let mut record: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        record[field] = value;
        std::fs::write(file, serde_json::to_vec(&record).unwrap()).unwrap();
        let restored = server.client().with_pending_journal(&directory).unwrap();
        assert_eq!(
            restored.call(&call).unwrap_err().code(),
            Some("outcome_unknown")
        );
        assert_eq!(
            server.requests().len(),
            2,
            "quarantined record must not make a second POST"
        );
        assert_eq!(restored.pending_operations().len(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn durable_outbox_replay_cannot_replace_the_original_call() {
    for field in ["body", "method", "path", "session", "repository"] {
        let server = Server::start(vec![
            discovery(2, 1, 2, &[]),
            Reply::json(200, json!({"id":7}), None),
        ]);
        let client = server.client();
        let mut call = Call::write(
            "fixture-session",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"to":"other","body":"original-body"}),
        );
        call.defer_pending_ack = true;
        assert!(client.call(&call).is_err());
        let original = client
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap();
        match field {
            "body" => call.body = Some(json!({"body":"different"})),
            "method" => call.method = "DELETE".into(),
            "path" => call.path = "/api/v1/bus/messages/7/ack".into(),
            "session" => call.session = "other-session".into(),
            "repository" => call.repository = Some("other-repository".into()),
            _ => unreachable!(),
        }
        assert_eq!(
            client.call(&call).unwrap_err().code(),
            Some("outcome_unknown")
        );
        let pending = client
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap();
        assert_eq!(pending.body, original.body);
        assert_eq!(pending.path, original.path);
        assert_eq!(server.requests().len(), 2);
    }
}

#[test]
fn durable_outbox_initial_server_error_preserves_unknown_operation() {
    for (status, code) in [
        (503, "future_server_code"),
        (500, "frozen"),
        (500, "server_draining"),
        (502, "frozen"),
        (502, "server_draining"),
    ] {
        let server = Server::start(vec![
            discovery(2, 1, 2, &[]),
            problem(status, code, json!({"safe":true}), Some("2")),
        ]);
        let client = server.client();
        let mut call = Call::write(
            "fixture-session",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"to":"other","body":"original-body"}),
        );
        call.defer_pending_ack = true;
        let error = client.call(&call).unwrap_err();
        assert_eq!(error.code(), Some("outcome_unknown"), "{status}/{code}");
        let pending = client
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap();
        assert_eq!(pending.cause_code, code);
        assert_eq!(pending.cause_status, Some(status));
        assert_eq!(
            server.requests().len(),
            2,
            "no automatic retry of an uncertain refusal"
        );
    }
}

#[test]
fn durable_outbox_pending_without_required_encryption_context_stays_unknown() {
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-pending-context-{}",
        lockyard_cloud_client::ulid()
    ));
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        Reply::json(200, json!({"id":7}), None),
    ]);
    let mut call = Call::write(
        "fixture-session",
        "POST",
        "/api/v1/bus/messages".into(),
        json!({"to":"other","body":"original-body"}),
    );
    call.defer_pending_ack = true;
    let client = server.client().with_pending_journal(&directory).unwrap();
    assert_eq!(
        client.call(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    let pending = client
        .pending_operation(call.key.as_deref().unwrap())
        .unwrap();
    drop(client);
    let restored = server
        .client()
        .require_e2ee_for("expected-workspace")
        .unwrap()
        .with_pending_journal(&directory)
        .unwrap();
    assert_eq!(
        restored.call(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    assert_eq!(
        server.requests().len(),
        2,
        "missing context must not transmit pending bytes"
    );
    assert_eq!(
        restored
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap(),
        pending
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn encrypted_pre_execution_retry_preserves_body_and_key() {
    for (status, code) in [
        (429, "rate_limited"),
        (503, "frozen"),
        (503, "server_draining"),
        (429, "relay_budget_exceeded"),
    ] {
        let mut refusal = problem(status, code, json!({}), Some("2"));
        refusal.extra = "Retry-After: 2\r\n";
        let server = Server::start(vec![
            discovery(2, 1, 2, &[]),
            refusal,
            Reply::json(200, json!({"id":"A-1"}), Some("2")),
        ]);
        let client = server.client().with_content_encryption(
            "fixture-workspace",
            Some(lockyard_cloud_client::WorkspaceKey::from_entropy([31; 32])),
            true,
        );
        let mut call = Call::write(
            "fixture-session",
            "POST",
            "/api/v1/registry/items".into(),
            json!({"title":"original-body"}),
        );
        call.deadline_ms = Some(1000);
        assert_eq!(client.call(&call).unwrap_err().code(), Some(code));
        client.call(&call).unwrap();
        let requests = server.requests();
        assert_eq!(requests.len(), 3, "no discovery or preparation on retry");
        assert!(requests[1].body.contains("lyenc1."));
        assert!(!requests[1].body.contains("original-body"));
        assert_eq!(requests[1].body, requests[2].body, "{status}/{code}");
        assert_eq!(requests[1].path, requests[2].path);
        assert_eq!(
            requests[1].header("lockyard-protocol"),
            requests[2].header("lockyard-protocol")
        );
        assert_eq!(
            requests[1].header("idempotency-key"),
            requests[2].header("idempotency-key")
        );
        assert!(client.pending_operations().is_empty());
    }
}

fn refused_encrypted_write(
    status: u16,
    code: &str,
    defer_ack: bool,
) -> (Server, Client, Call, std::path::PathBuf) {
    let mut refusal = problem(status, code, json!({}), Some("2"));
    refusal.extra = "Retry-After: 2\r\n";
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        refusal,
        Reply::json(200, json!({"id":"A-1"}), Some("2")),
    ]);
    let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ly-refused-write-{}",
        lockyard_cloud_client::ulid()
    ));
    let client = server
        .client()
        .with_pending_journal(&directory)
        .unwrap()
        .with_content_encryption(
            "fixture-workspace",
            Some(lockyard_cloud_client::WorkspaceKey::from_entropy([31; 32])),
            true,
        );
    let mut call = Call::write(
        "fixture-session",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title":"original-body"}),
    );
    call.deadline_ms = Some(1000);
    call.defer_pending_ack = defer_ack;
    assert_eq!(client.call(&call).unwrap_err().code(), Some(code));
    (server, client, call, directory)
}

#[test]
fn pre_execution_retry_survives_restart_and_keeps_ack_boundary() {
    for (status, code) in [
        (429, "rate_limited"),
        (503, "frozen"),
        (503, "server_draining"),
    ] {
        for defer_ack in [false, true] {
            let (server, client, call, directory) =
                refused_encrypted_write(status, code, defer_ack);
            let key = call.key.as_deref().unwrap();
            let original = client
                .pending_operation(key)
                .expect("refusal must retain exact bytes");
            drop(client);
            let restored = server
                .client()
                .with_pending_journal(&directory)
                .unwrap()
                .with_content_encryption(
                    "fixture-workspace",
                    Some(lockyard_cloud_client::WorkspaceKey::from_entropy([31; 32])),
                    true,
                );
            restored.call(&call).unwrap();
            let requests = server.requests();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[1].body, requests[2].body);
            assert_eq!(
                requests[1].header("idempotency-key"),
                requests[2].header("idempotency-key")
            );
            if defer_ack {
                let pending = restored.pending_operation(key).unwrap();
                assert_eq!(pending.body, original.body);
                assert_eq!(pending.first_sent_unix_secs, original.first_sent_unix_secs);
                restored.acknowledge_write(&call).unwrap();
            }
            assert!(restored.pending_operations().is_empty());
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
}

#[test]
fn pre_execution_retry_rejects_changed_request_identity_without_sending() {
    let (server, client, call, directory) = refused_encrypted_write(429, "rate_limited", false);
    let original = client
        .pending_operation(call.key.as_deref().unwrap())
        .unwrap();
    let mut changes = vec![call.clone(); 5];
    changes[0].body = Some(json!({"title":"changed"}));
    changes[1].method = "DELETE".into();
    changes[2].path.push_str("/A-1");
    changes[3].session.push_str("-changed");
    changes[4].repository = Some("changed".into());
    for changed in changes {
        assert_eq!(
            client.call(&changed).unwrap_err().code(),
            Some("outcome_unknown")
        );
        assert_eq!(
            client
                .pending_operation(call.key.as_deref().unwrap())
                .unwrap(),
            original
        );
    }
    assert_eq!(server.requests().len(), 2);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn pre_execution_retry_must_sync_unknown_marker_before_sending() {
    let (server, client, call, directory) = refused_encrypted_write(429, "rate_limited", false);
    assert!(
        client
            .pending_operation(call.key.as_deref().unwrap())
            .is_some()
    );
    let moved = directory.with_extension("moved");
    std::fs::rename(&directory, &moved).unwrap();
    std::fs::write(&directory, "not a journal directory").unwrap();
    assert!(client.call(&call).is_err());
    assert_eq!(
        server.requests().len(),
        2,
        "failed journal transition must precede network"
    );
    std::fs::remove_file(directory).unwrap();
    std::fs::remove_dir_all(moved).unwrap();
}

#[test]
fn pre_execution_retry_seeded_restart_and_uncertainty_sequences() {
    for mut seed in [7_u64, 31, 991, 20261108] {
        let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ly-refusal-sequence-{}",
            lockyard_cloud_client::ulid()
        ));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let journal_directory = directory.clone();
        let markers = Arc::clone(&observed);
        let mut replies = vec![discovery(2, 1, 2, &[])];
        let mut codes = Vec::new();
        for _ in 0..16 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let (status, code) = [
                (429, "rate_limited"),
                (503, "frozen"),
                (503, "server_draining"),
                (429, "relay_budget_exceeded"),
            ][(seed >> 32) as usize % 4];
            let mut reply = problem(status, code, json!({}), Some("2"));
            reply.extra = "Retry-After: 2\r\n";
            replies.push(reply);
            codes.push(code);
        }
        // The last send may have committed: an invalid echo must revoke safe-retry permission.
        replies.push(Reply::json(200, json!({"id":"A-1"}), None));
        let server = Server::start_with_hook(replies, move |request| {
            if request.method == "POST" {
                let journal = std::fs::read_dir(&journal_directory)
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                let journal = std::fs::read_dir(journal)
                    .unwrap()
                    .map(Result::unwrap)
                    .map(|entry| entry.path())
                    .find(|path| path.extension().is_some_and(|ext| ext == "json"))
                    .unwrap();
                let pending: lockyard_cloud_client::PendingWrite =
                    serde_json::from_slice(&std::fs::read(journal).unwrap()).unwrap();
                markers.lock().unwrap().push(pending.pre_execution_rejected);
            }
        });
        let client = || {
            server
                .client()
                .with_pending_journal(&directory)
                .unwrap()
                .with_content_encryption(
                    "fixture-workspace",
                    Some(lockyard_cloud_client::WorkspaceKey::from_entropy([31; 32])),
                    true,
                )
        };
        let mut call = Call::write(
            "fixture-session",
            "POST",
            "/api/v1/registry/items".into(),
            json!({"title":"original-body"}),
        );
        call.deadline_ms = Some(1000);
        let key = call.key.as_deref().unwrap();
        let mut original = None;
        for code in codes {
            let restored = client();
            assert_eq!(restored.call(&call).unwrap_err().code(), Some(code));
            let pending = restored.pending_operation(key).unwrap();
            assert!(pending.pre_execution_rejected);
            let first = original.get_or_insert_with(|| pending.clone());
            assert_eq!(pending.body, first.body);
            assert_eq!(pending.first_sent_unix_secs, first.first_sent_unix_secs);
            let mut changed = call.clone();
            changed.body = Some(json!({"title":"changed"}));
            assert_eq!(
                restored.call(&changed).unwrap_err().code(),
                Some("outcome_unknown")
            );
        }
        let restored = client();
        assert_eq!(
            restored.call(&call).unwrap_err().code(),
            Some("outcome_unknown")
        );
        assert!(
            !restored
                .pending_operation(key)
                .unwrap()
                .pre_execution_rejected
        );
        drop(restored);
        assert_eq!(
            client().call(&call).unwrap_err().code(),
            Some("outcome_unknown")
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 18);
        for retry in &requests[2..] {
            assert_eq!(retry.body, requests[1].body);
            assert_eq!(retry.path, requests[1].path);
            assert_eq!(
                retry.header("idempotency-key"),
                requests[1].header("idempotency-key")
            );
            assert_eq!(
                retry.header("lockyard-protocol"),
                requests[1].header("lockyard-protocol")
            );
        }
        assert_eq!(
            *observed.lock().unwrap(),
            vec![false; 17],
            "every send follows a durable unknown marker"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn pre_execution_plaintext_journal_cannot_bypass_new_encryption_policy() {
    for required in [false, true] {
        for (path, body) in [
            (
                "/api/v1/registry/items",
                json!({"title":"previously unencrypted private content"}),
            ),
            ("/api/v1/registry/import", json!({"items":[]})),
        ] {
            let mut refusal = problem(429, "rate_limited", json!({}), Some("2"));
            refusal.extra = "Retry-After: 2\r\n";
            let server = Server::start(vec![
                discovery(2, 1, 2, &[]),
                refusal,
                Reply::json(200, json!({"id":"A-1"}), Some("2")),
            ]);
            let directory = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ly-refusal-encryption-policy-{}",
                lockyard_cloud_client::ulid()
            ));
            let client = server.client().with_pending_journal(&directory).unwrap();
            let mut call = Call::write("fixture-session", "POST", path.into(), body);
            call.deadline_ms = Some(1000);
            let key = call.key.as_deref().unwrap();
            assert_eq!(client.call(&call).unwrap_err().code(), Some("rate_limited"));
            let original = client.pending_operation(key).unwrap();
            assert_eq!(original.body, call.body.as_ref().map(Value::to_string));
            drop(client);

            let mut restored = server.client();
            if required {
                restored = restored.require_e2ee_for("fixture-workspace").unwrap();
            }
            let restored = restored
                .with_content_encryption(
                    "fixture-workspace",
                    Some(lockyard_cloud_client::WorkspaceKey::from_entropy([31; 32])),
                    true,
                )
                .with_pending_journal(&directory)
                .unwrap();
            assert_eq!(
                restored.call(&call).unwrap_err().code(),
                Some("outcome_unknown")
            );
            assert_eq!(
                server.requests().len(),
                2,
                "{path}, required={required}: changed encryption policy must quarantine old bytes"
            );
            let pending = restored.pending_operation(key).unwrap();
            assert_eq!(pending.body, original.body);
            assert_eq!(pending.key, original.key);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }
}

#[test]
fn pre_execution_protocol_rejection_quarantines_the_original_ciphertext() {
    let mut refusal = problem(429, "rate_limited", json!({}), Some("2"));
    refusal.extra = "Retry-After: 2\r\n";
    let server = Server::start(vec![
        discovery(2, 1, 2, &[]),
        refusal,
        unsupported(1, 1),
        Reply::json(200, json!({"id":"A-1"}), Some("2")),
    ]);
    let client = server.client().with_content_encryption(
        "fixture-workspace",
        Some(lockyard_cloud_client::WorkspaceKey::from_entropy([31; 32])),
        true,
    );
    let mut call = write();
    call.deadline_ms = Some(1000);
    let key = call.key.as_deref().unwrap();
    assert_eq!(client.call(&call).unwrap_err().code(), Some("rate_limited"));
    let original = client.pending_operation(key).unwrap();
    assert_eq!(
        client.call(&call).unwrap_err().code(),
        Some("protocol_unsupported")
    );
    assert_eq!(
        client.call(&call).unwrap_err().code(),
        Some("outcome_unknown")
    );
    let requests = server.requests();
    assert_eq!(
        requests.len(),
        3,
        "a terminal refusal cannot authorize fresh encryption under the old key"
    );
    assert_eq!(requests[1].body, requests[2].body);
    assert_eq!(
        requests[1].header("idempotency-key"),
        requests[2].header("idempotency-key")
    );
    let pending = client.pending_operation(key).unwrap();
    assert_eq!(pending.body, original.body);
    assert_eq!(pending.key, original.key);
}
