// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives the real binary in cloud mode against a fake server, with and without the agent process.

#![cfg(unix)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Renewal fixtures use a fixed server clock so subprocess scheduling cannot age a claim.
const RENEW_NOW_MS: i64 = 1_000_000;
const HOLD_EXPIRES_AT: &str = "2099-11-11T21:45:00Z";

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    body: Value,
    key: Option<String>,
    session: Option<String>,
}

#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    claims: Vec<Value>,
    inbox: Vec<Value>,
    seen_ids: Vec<i64>,
    sent: Vec<Value>,
    refuse_claims: Option<(u16, Value)>,
    refuse_claims_get: Option<(u16, Value)>,
    refuse_claims_get_once: Option<(u16, Value)>,
    refuse_inbox_get: Option<(u16, Value)>,
    refuse_work_get: Option<(u16, Value)>,
    claim_reused_on_post: Option<Value>,
    claim_created: Option<Value>,
    omit_claim_meta: bool,
    echo_reused_claim_meta: bool,
    refuse_renew: Option<(u16, Value)>,
    ignore_renew_hold: bool,
    refuse_release: Option<(u16, Value)>,
    refuse_registry_claim: bool,
    refuse_registry_get: Option<(u16, Value)>,
    refuse_filtered_registry_once: Option<(u16, Value)>,
    registry_hide_protocol_on_refusal: bool,
    check_reply: Option<Value>,
    catalog: Option<Value>,
    encryption_key_id: Option<String>,
    refuse_catalog_put: bool,
    registry_areas: Vec<Value>,
    registry_next_item: u64,
    registry_items: Vec<Value>,
    registry_assignee_session: bool,
    registry_assignee_protocol_hidden: bool,
    registry_assignee_protocol_header_hidden: bool,
    registry_assignee_header_hidden: bool,
    registry_assignee_filter_ignored: bool,
    registry_page_size: Option<usize>,
    latency: Latency,
    requests_started: usize,
    status_reads_in_flight: usize,
    max_status_reads_in_flight: usize,
    status_read_events: Vec<(String, bool)>,
    status_read_starts: Vec<(String, Option<String>)>,
    response_bytes: usize,
    request_timings: Vec<(String, Duration)>,
    connections: usize,
}

/// HTTP-level impairment model. TCP/TLS setup costs are delayed after accept, so this
/// needs no privileged network shaper and does not claim to exercise a TLS stack.
#[derive(Clone, Default)]
struct Latency {
    connect: Duration,
    handshake: Duration,
    response: Duration,
    stall_every: usize,
    stall: Duration,
    stall_route: Option<String>,
    /// Stall only inbox peeks that request all=true (open-mail), not mandatory unread.
    stall_inbox_all: bool,
    keep_alive: bool,
}

#[derive(Clone)]
struct Server {
    url: String,
    state: Arc<Mutex<State>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let shared = Arc::clone(&shared);
                thread::spawn(move || serve(stream, &shared));
            }
        });
        Self { url, state }
    }

    fn seen(&self, method: &str, route: &str) -> Vec<Seen> {
        let state = self.state.lock().unwrap();
        state
            .seen
            .iter()
            .filter(|r| r.method == method && r.path.split('?').next() == Some(route))
            .cloned()
            .collect()
    }

    /// POST/PUT/DELETE calls whose path ends with `tail` (for example `/bus/inbox/seen`).
    fn writes_to(&self, tail: &str) -> Vec<Seen> {
        let state = self.state.lock().unwrap();
        state
            .seen
            .iter()
            .filter(|r| {
                r.method != "GET"
                    && r.method != "HEAD"
                    && r.path
                        .split('?')
                        .next()
                        .is_some_and(|path| path.ends_with(tail))
            })
            .cloned()
            .collect()
    }
}

fn serve(mut stream: TcpStream, state: &Mutex<State>) {
    let latency = {
        let mut state = state.lock().unwrap();
        state.connections += 1;
        state.latency.clone()
    };
    thread::sleep(latency.connect + latency.handshake);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    loop {
        let request_started = Instant::now();
        let mut first = String::new();
        if !matches!(reader.read_line(&mut first), Ok(size) if size > 0) {
            return;
        }
        let mut parts = first.split(' ');
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        let (mut length, mut key, mut session, mut token, mut repository) =
            (0, None, None, None, None);
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.trim_end().split_once(": ") {
                match name.to_ascii_lowercase().as_str() {
                    "content-length" => length = value.parse().unwrap_or(0),
                    "idempotency-key" => key = Some(value.to_string()),
                    "x-lockyard-session" => session = Some(value.to_string()),
                    "authorization" => token = Some(value.to_string()),
                    "x-lockyard-repository" => repository = Some(value.to_string()),
                    _ => {}
                }
            }
        }
        let mut body = vec![0_u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let route = path.split('?').next().unwrap_or_default().to_string();
        let is_status_read = matches!(
            route.as_str(),
            "/api/v1/zones/claims"
                | "/api/v1/bus/inbox"
                | "/api/v1/bus/tasks"
                | "/api/v1/registry/items"
        ) && method == "GET";
        let request_number = {
            let mut state = state.lock().unwrap();
            state.requests_started += 1;
            if is_status_read {
                state.status_read_events.push((path.clone(), true));
                state
                    .status_read_starts
                    .push((path.clone(), session.clone()));
                state.status_reads_in_flight += 1;
                state.max_status_reads_in_flight = state
                    .max_status_reads_in_flight
                    .max(state.status_reads_in_flight);
            }
            state.requests_started
        };
        // Setup belongs to the accepted connection, but response impairments may change between
        // requests on a keep-alive connection (for example, an outage after agent warm-up).
        let latency = state.lock().unwrap().latency.clone();
        thread::sleep(latency.response);
        let stall_all_inbox =
            latency.stall_inbox_all && route == "/api/v1/bus/inbox" && path.contains("all=true");
        if (latency.stall_every > 0 && request_number % latency.stall_every == 0)
            || latency.stall_route.as_deref() == Some(&route)
            || stall_all_inbox
        {
            thread::sleep(latency.stall);
        }
        if route.ends_with("/events") {
            // A short long poll keeps the agent's threads moving and its view fresh.
            thread::sleep(Duration::from_millis(30));
        }
        let (status, answer, capabilities) = {
            let mut state = state.lock().unwrap();
            if !route.ends_with("/events") {
                let record = Seen {
                    method: method.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    key,
                    session: session.clone(),
                };
                state.seen.push(record);
            }
            let (status, answer) = if token.as_deref() != Some("Bearer test-token") {
                (
                    401,
                    json!({"error": {"code": "unauthorized", "message": "bad token"}}),
                )
            } else {
                route_reply(&mut state, &method, &path, &body, session.as_deref())
            };
            let capabilities = if state.registry_assignee_session
                && ((route.starts_with("/api/v1/registry/")
                    && !state.registry_assignee_header_hidden)
                    || (route == "/api/v1/protocol"
                        && !state.registry_assignee_protocol_header_hidden))
            {
                "Lockyard-Capabilities: registry_assignee_session_v1\r\n"
            } else {
                ""
            };
            (status, answer, capabilities)
        };
        let text = answer.to_string();
        {
            let mut state = state.lock().unwrap();
            state.response_bytes += text.len();
            state
                .request_timings
                .push((path.clone(), request_started.elapsed()));
            if is_status_read {
                state.status_read_events.push((path.clone(), false));
                state.status_reads_in_flight -= 1;
            }
        }
        let response = format!(
            "HTTP/1.1 {status} X\r\nLockyard-Protocol: 2\r\n{capabilities}X-Lockyard-Repository: {}\r\nCache-Control: no-store\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{text}",
            repository.as_deref().unwrap_or("-"),
            text.len(),
            if latency.keep_alive {
                "keep-alive"
            } else {
                "close"
            },
        );
        if stream.write_all(response.as_bytes()).is_err() || !latency.keep_alive {
            return;
        }
    }
}

fn query_value(path: &str, name: &str) -> Option<String> {
    let encoded = path.split_once('?')?.1.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then_some(value)
    })?;
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut bytes = encoded.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'%' => {
                let hex = [bytes.next()?, bytes.next()?];
                u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?
            }
            b'+' => b' ',
            byte => byte,
        });
    }
    String::from_utf8(decoded).ok()
}

fn route_reply(
    state: &mut State,
    method: &str,
    path: &str,
    body: &Value,
    session: Option<&str>,
) -> (u16, Value) {
    let route = path.split('?').next().unwrap_or_default();
    match (method, route) {
        ("GET", "/api/v1/protocol") => {
            let mut capabilities = vec!["zone_catalog_v1", "drain_v1"];
            if state.registry_assignee_session && !state.registry_assignee_protocol_hidden {
                capabilities.push("registry_assignee_session_v1");
            }
            (
                200,
                json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":capabilities}),
            )
        }
        ("GET", "/api/v1/zones/catalog") => (
            200,
            state
                .catalog
                .clone()
                .unwrap_or(json!({"zones":{"code":["src"]}})),
        ),
        ("POST", "/api/v1/zones/catalog") => {
            if state.refuse_catalog_put {
                return (
                    403,
                    json!({"type":"urn:lockyard:problem:forbidden","title":"Forbidden","status":403,"detail":"publisher role required","instance":"urn:request:test","code":"forbidden","details":null}),
                );
            }
            state.catalog = Some(body["catalog"].clone());
            (200, body["catalog"].clone())
        }
        ("POST", "/api/v1/zones/claims") => {
            if let Some(refusal) = state.refuse_claims.clone() {
                return refusal;
            }
            if let Some(mut claim) = state.claim_reused_on_post.clone() {
                state.claims.push(claim.clone());
                if state.echo_reused_claim_meta {
                    claim["meta"] = body["meta"].clone();
                }
                if let Some(created) = &state.claim_created {
                    claim["created"] = created.clone();
                }
                return (200, claim);
            }
            let id = state.claims.len() as i64 + 1;
            let claim = json!({"id": id, "session": "alice", "paths": body["paths"], "meta": body["meta"], "fence": 1, "expires_at": HOLD_EXPIRES_AT});
            state.claims.push(claim.clone());
            let mut reply = claim;
            if state.omit_claim_meta {
                reply.as_object_mut().unwrap().remove("meta");
            }
            if let Some(created) = &state.claim_created {
                reply["created"] = created.clone();
            }
            (200, reply)
        }
        ("GET", "/api/v1/zones/claims") => state
            .refuse_claims_get_once
            .take()
            .or_else(|| state.refuse_claims_get.clone())
            .unwrap_or_else(|| (200, json!({"claims": state.claims}))),
        ("POST", _) if route.starts_with("/api/v1/zones/claims/") && route.ends_with("/renew") => {
            if let Some(refusal) = state.refuse_renew.clone() {
                return refusal;
            }
            let id = route
                .trim_end_matches("/renew")
                .rsplit('/')
                .next()
                .unwrap()
                .parse::<i64>()
                .unwrap();
            let Some(claim) = state.claims.iter_mut().find(|claim| claim["id"] == id) else {
                return (
                    404,
                    json!({"error":{"code":"not_found","message":"claim does not exist"}}),
                );
            };
            if claim["session"].as_str() != session {
                return (
                    404,
                    json!({"error":{"code":"not_found","message":"claim is not yours"}}),
                );
            }
            let expires_at = claim["expires_at"]
                .as_i64()
                .or_else(|| {
                    claim["expires_at"]
                        .as_str()
                        .and_then(lockyard_core::proto::parse_rfc3339)
                })
                .unwrap();
            if expires_at <= RENEW_NOW_MS {
                return (
                    404,
                    json!({"error":{"code":"not_found","message":"claim has expired"}}),
                );
            }
            if claim["fence"] != body["fence"] {
                return (
                    412,
                    json!({"error":{"code":"stale_fence","message":"stale fence"}}),
                );
            }
            let ttl = body["ttl_minutes"].as_i64().unwrap();
            assert!((1..=240).contains(&ttl));
            if claim["expires_at"].is_number() {
                claim["expires_at"] = json!(RENEW_NOW_MS + ttl * 60_000);
            }
            if !state.ignore_renew_hold {
                for field in ["hold_reason", "hold_until"] {
                    if let Some(value) = body.get(field) {
                        claim[field] = value.clone();
                    }
                }
            }
            (200, claim.clone())
        }
        ("DELETE", "/api/v1/zones/claims") => {
            let before = state.claims.len();
            state
                .claims
                .retain(|claim| claim["session"].as_str() != session);
            (200, json!({"released":before - state.claims.len()}))
        }
        ("DELETE", _) if route.starts_with("/api/v1/zones/claims/") => {
            if let Some(refusal) = state.refuse_release.clone() {
                return refusal;
            }
            let id = route.rsplit('/').next().unwrap().parse::<i64>().unwrap();
            state.claims.retain(|claim| {
                claim["id"] != id
                    || (body.get("fence").is_some_and(|fence| !fence.is_null())
                        && claim["fence"] != body["fence"])
            });
            (200, json!({"released":1}))
        }
        ("GET", "/api/v1/presence") => (200, json!({"sessions":[]})),
        ("GET", "/api/v1/registry/areas") if !state.registry_areas.is_empty() => {
            (200, json!({"areas": state.registry_areas}))
        }
        ("GET", "/api/v1/registry/items") => {
            if let Some(refusal) = state.refuse_registry_get.clone() {
                return refusal;
            }
            if query_value(path, "assignee_session").is_some()
                && let Some(refusal) = state.refuse_filtered_registry_once.take()
            {
                if state.registry_hide_protocol_on_refusal {
                    state.registry_assignee_protocol_hidden = true;
                    state.registry_assignee_protocol_header_hidden = true;
                }
                return refusal;
            }
            let status = query_value(path, "status");
            let assignee = state
                .registry_assignee_session
                .then(|| query_value(path, "assignee_session"))
                .flatten()
                .filter(|_| !state.registry_assignee_filter_ignored)
                .filter(|session| !session.trim().is_empty());
            let limit = query_value(path, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(200)
                .min(state.registry_page_size.unwrap_or(usize::MAX));
            let offset = query_value(path, "cursor")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let items = state
                .registry_items
                .iter()
                .filter(|item| {
                    status
                        .as_deref()
                        .is_none_or(|status| item["status"].as_str() == Some(status))
                })
                .filter(|item| {
                    assignee.as_deref().is_none_or(|session| {
                        let assignment = &item["assignment"];
                        assignment["released_at"].is_null()
                            && assignment["executor"].as_str().is_some_and(|executor| {
                                executor.splitn(3, ':').nth(2).unwrap_or(executor) == session
                            })
                    })
                })
                .collect::<Vec<_>>();
            let next =
                (offset.saturating_add(limit) < items.len()).then(|| (offset + limit).to_string());
            let page = items
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();
            (200, json!({"items":page,"cursor":next}))
        }
        ("POST", "/api/v1/registry/items") if !state.registry_areas.is_empty() => {
            let area = state
                .registry_areas
                .iter()
                .find(|area| area["id"] == body["area_id"])
                .unwrap();
            state.registry_next_item += 1;
            let id = format!(
                "{}-{}",
                area["prefix"].as_str().unwrap(),
                state.registry_next_item
            );
            (200, json!({"id":id,"title":body["title"],"status":"ready"}))
        }
        ("GET", "/api/v1/registry/items/D-1") if state.refuse_registry_claim => (
            200,
            json!({"id":"D-1", "title":"taken", "status":"claimed", "version":1}),
        ),
        ("POST", "/api/v1/registry/items/D-1/claim") if state.refuse_registry_claim => (
            409,
            json!({"error":{"code":"conflict", "message":"task is already taken"}}),
        ),
        ("GET", "/api/v1/workspace/encryption") => (
            200,
            json!({"encryption": if state.encryption_key_id.is_some(){"required"}else{"off"}, "key_id": state.encryption_key_id, "workspace_id": "00000000-0000-0000-0000-000000000001"}),
        ),
        ("POST", "/api/v1/zones/check") => (
            200,
            state.check_reply.clone().unwrap_or_else(
                || json!({"paths": [{"path": body["paths"][0], "status": "free"}]}),
            ),
        ),
        ("GET", "/api/v1/bus/inbox") => {
            if let Some(refusal) = state.refuse_inbox_get.clone() {
                return refusal;
            }
            let all = query_value(path, "all").as_deref() == Some("true");
            let messages: Vec<Value> = state
                .inbox
                .iter()
                .filter(|message| {
                    all || message
                        .get("id")
                        .and_then(Value::as_i64)
                        .is_none_or(|id| !state.seen_ids.contains(&id))
                })
                .cloned()
                .collect();
            (200, json!({"messages": messages, "skipped": 0}))
        }
        ("POST", "/api/v1/bus/inbox/claim") => (200, json!({"claimed": body["ids"]})),
        ("POST", "/api/v1/bus/inbox/seen") => {
            let ids = body["ids"].as_array().cloned().unwrap_or_default();
            for id in &ids {
                if let Some(id) = id.as_i64()
                    && !state.seen_ids.contains(&id)
                {
                    state.seen_ids.push(id);
                }
            }
            (200, json!({"seen": ids.len()}))
        }
        ("POST", "/api/v1/bus/messages") => (
            200,
            json!({"id": 44, "from_session": "alice", "to": body["to"], "body": body["body"]}),
        ),
        ("GET", "/api/v1/bus/sent") => (200, json!({"messages": state.sent.clone()})),
        ("GET", "/api/v1/bus/board") => (200, json!([])),
        ("GET", "/api/v1/bus/tasks") => state
            .refuse_work_get
            .clone()
            .unwrap_or_else(|| (200, json!([]))),
        ("POST", "/api/v1/bus/tasks") => (
            200,
            json!({"id": 6, "title": body["title"], "status": "offered", "version": 1}),
        ),
        ("POST", "/api/v1/bus/tasks/BT-6/claim") => {
            (200, json!({"id": 6, "status": "claimed", "version": 2}))
        }
        _ if method == "POST" && route.contains("/bus/messages/") && route.ends_with("/reply") => {
            let id = route
                .rsplit('/')
                .nth(1)
                .and_then(|text| text.parse::<i64>().ok())
                .unwrap_or(0);
            for message in &mut state.inbox {
                if message.get("id").and_then(Value::as_i64) == Some(id) {
                    message["status"] = json!("ack");
                }
            }
            // Match the real server: the reply body may carry in_reply_to, but /bus/sent does not.
            let reply = json!({
                "id": 1000 + id,
                "from_session": session.unwrap_or("alice"),
                "to": "bob",
                "body": body["body"],
                "in_reply_to": id,
            });
            state.sent.push(json!({
                "id": 1000 + id,
                "from_session": session.unwrap_or("alice"),
                "to": "bob",
                "body": body["body"],
            }));
            (200, reply)
        }
        _ if route.ends_with("/events") => (200, json!({"events": []})),
        _ => (200, json!({"id": 1})),
    }
}

fn cloud_project(server: &Server) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join(".lockyard");
    std::fs::create_dir(&state).unwrap();
    let config = format!(
        "mode = 'cloud'\nurl = '{}'\nworkspace = 'team'\n",
        server.url
    );
    std::fs::write(state.join("config.toml"), config).unwrap();
    dir
}

fn binary(dir: &Path, runtime: &Path) -> Command {
    // Every caller owns this freshly-created tempdir; it is the private XDG state parent.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut command = Command::new(
        std::env::var_os("LOCKYARD_TEST_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_lockyard").into()),
    );
    let config = std::fs::read_to_string(dir.join(".lockyard/config.toml")).unwrap_or_default();
    let url = config
        .lines()
        .find_map(|line| line.strip_prefix("url = '")?.strip_suffix("'"))
        .unwrap_or_default();
    command
        .current_dir(dir)
        .env("LOCKYARD_URL", url)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", runtime.join("state"))
        .env("XDG_CONFIG_HOME", runtime.join("config"))
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_STATUS_DEADLINE_MS")
        .env_remove("LOCKYARD_TOKEN_FILE");
    command
}

#[test]
fn cloud_trust_writes_a_private_xdg_allowlist() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    let urls = ["https://trusted.example", "https://another.example"];
    for url in urls {
        let result = binary(dir.path(), runtime.path())
            .args(["cloud", "trust", url])
            .env("XDG_CONFIG_HOME", config_home.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let path = config_home.path().join("lockyard/trusted-servers");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{}\n{}\n", urls[0], urls[1])
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn an_untrusted_project_url_sends_no_token() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    let result = binary(dir.path(), runtime.path())
        .args(["zone", "list"])
        .env_remove("LOCKYARD_URL")
        .env("XDG_CONFIG_HOME", config_home.path())
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("lockyard cloud trust"));
    assert!(server.seen("GET", "/api/v1/zones/claims").is_empty());
}

fn cli(dir: &Path, runtime: &Path, args: &[&str]) -> Output {
    binary(dir, runtime)
        .args(args)
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap()
}

fn json_of(result: &Output) -> Value {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

fn mcp_calls(dir: &Path, runtime: &Path, surface: &str, calls: &[(&str, Value)]) -> Vec<Value> {
    let mut child = binary(dir, runtime)
        .args(["mcp", "--tools", surface])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for (id, (name, arguments)) in calls.iter().enumerate() {
        writeln!(
            input,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})
        )
        .unwrap();
    }
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let answers: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["result"].clone())
        .collect();
    assert_eq!(answers.len(), calls.len());
    answers
}

#[test]
fn compact_task_add_requires_area_and_uses_its_prefix_while_full_keeps_the_default() {
    let server = Server::start();
    server.state.lock().unwrap().registry_areas = vec![
        json!({"id":"general-id","key":"general","prefix":"D"}),
        json!({"id":"engine-id","key":"engine","prefix":"FE"}),
    ];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let invalid = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[
            ("task_add", json!({"title":"missing area"})),
            ("task_add", json!({"title":"null area","area":null})),
            ("task_add", json!({"title":"empty area","area":""})),
            ("task_add", json!({"title":"blank area","area":"  "})),
        ],
    );
    for answer in invalid {
        assert_eq!(answer["isError"], true, "{answer}");
        assert!(
            answer["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("area"),
            "{answer}"
        );
    }
    assert!(server.seen("GET", "/api/v1/registry/areas").is_empty());
    assert!(server.seen("POST", "/api/v1/registry/items").is_empty());

    let explicit = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[("task_add", json!({"title":"engine task","area":"engine"}))],
    );
    assert_eq!(explicit[0]["isError"], false, "{}", explicit[0]);
    assert_eq!(explicit[0]["structuredContent"]["id"], "FE-1");
    let fallback = mcp_calls(
        dir.path(),
        runtime.path(),
        "full",
        &[("task_add", json!({"title":"legacy default"}))],
    );
    assert_eq!(fallback[0]["isError"], false, "{}", fallback[0]);
    assert_eq!(fallback[0]["structuredContent"]["id"], "D-2");
    let writes = server.seen("POST", "/api/v1/registry/items");
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].body["area_id"], "engine-id");
    assert_eq!(writes[1].body["area_id"], "general-id");
}

#[test]
fn compact_zone_renew_checks_fence_and_ttl_before_sending_and_extends_the_claim() {
    let server = Server::start();
    let original_expiry = RENEW_NOW_MS + 30_000;
    server.state.lock().unwrap().claims = vec![json!({
        "id":1,"session":"alice","paths":["src"],"fence":7,"expires_at":original_expiry
    })];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let invalid = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[
            ("zone_renew", json!({"id":1,"ttl":30})),
            ("zone_renew", json!({"id":1,"ttl":30,"fence":null})),
            ("zone_renew", json!({"id":1,"ttl":30,"fence":"7"})),
            ("zone_renew", json!({"id":1,"ttl":0,"fence":7})),
            ("zone_renew", json!({"id":1,"ttl":241,"fence":7})),
        ],
    );
    for (answer, expected) in invalid.iter().zip([
        "fence is required in cloud mode",
        "fence is required in cloud mode",
        "fence must be an integer",
        "ttl must be 1 to 240 minutes",
        "ttl must be 1 to 240 minutes",
    ]) {
        assert_eq!(answer["isError"], true, "{answer}");
        assert_eq!(answer["content"][0]["text"], expected, "{answer}");
    }
    assert!(
        server
            .seen("POST", "/api/v1/zones/claims/1/renew")
            .is_empty()
    );
    assert_eq!(
        server.state.lock().unwrap().claims[0]["expires_at"],
        original_expiry
    );

    for (arguments, ttl) in [
        (json!({"id":1,"fence":7}), 30),
        (json!({"id":1,"ttl":1,"fence":7}), 1),
        (json!({"id":1,"ttl":240,"fence":7}), 240),
    ] {
        let renewed = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[("zone_renew", arguments)],
        );
        assert_eq!(renewed[0]["isError"], false, "{}", renewed[0]);
        assert_eq!(renewed[0]["structuredContent"]["renewed"], 1);
        let expiry = server.state.lock().unwrap().claims[0]["expires_at"]
            .as_i64()
            .unwrap();
        assert!(expiry > original_expiry);
        assert_eq!(expiry, RENEW_NOW_MS + ttl * 60_000);
    }
    let writes = server.seen("POST", "/api/v1/zones/claims/1/renew");
    assert_eq!(writes.len(), 3);
    for (write, ttl) in writes.iter().zip([30, 1, 240]) {
        assert_eq!(write.body["ttl_minutes"], ttl);
        assert_eq!(write.body["fence"], 7);
        assert_eq!(write.session.as_deref(), Some("alice"));
    }
}

#[test]
fn compact_zone_renew_preserves_stale_fence_foreign_and_expired_refusals() {
    let server = Server::start();
    let expiry = RENEW_NOW_MS + 60_000;
    server.state.lock().unwrap().claims = vec![
        // Fence 7 belongs to an earlier generation of this claim.
        json!({"id":1,"session":"alice","paths":["src"],"fence":8,"expires_at":expiry}),
        json!({"id":2,"session":"bob","paths":["docs"],"fence":9,"expires_at":expiry}),
        json!({"id":3,"session":"alice","paths":["tests"],"fence":10,"expires_at":0}),
    ];
    let original = server.state.lock().unwrap().claims.clone();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let refused = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[
            ("zone_renew", json!({"id":1,"ttl":30,"fence":7})),
            ("zone_renew", json!({"id":2,"ttl":30,"fence":9})),
            ("zone_renew", json!({"id":3,"ttl":30,"fence":10})),
        ],
    );
    for (answer, needle) in refused.iter().zip(["stale fence", "not yours", "expired"]) {
        assert_eq!(answer["isError"], true, "{answer}");
        assert!(
            answer["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains(needle),
            "{answer}"
        );
    }
    assert_eq!(server.state.lock().unwrap().claims, original);
    for id in [1, 2, 3] {
        assert_eq!(
            server
                .seen("POST", &format!("/api/v1/zones/claims/{id}/renew"))
                .len(),
            1
        );
    }
}

#[test]
fn start_work_cloud_applies_the_hold_with_a_fenced_renewal_after_claiming() {
    for explicit_until in [None, Some("2099-11-11T21:30:00Z")] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let mut arguments = json!({"paths":["src"],"ttl":45,"hold_reason":"waiting for review"});
        if let Some(until) = explicit_until {
            arguments["hold_until"] = json!(until);
        }
        let answers = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[("start_work", arguments)],
        );
        let answer = &answers[0];
        assert_eq!(answer["isError"], false, "{answer}");
        let until = explicit_until.unwrap_or(HOLD_EXPIRES_AT);
        assert_eq!(
            answer["structuredContent"]["claim"]["hold_reason"],
            "waiting for review"
        );
        assert_eq!(answer["structuredContent"]["claim"]["hold_until"], until);
        let claims = server.seen("POST", "/api/v1/zones/claims");
        let renewals = server.seen("POST", "/api/v1/zones/claims/1/renew");
        assert_eq!(claims.len(), 1);
        assert_eq!(renewals.len(), 1);
        assert_eq!(claims[0].body["ttl_minutes"], 45);
        assert!(claims[0].body.get("hold_reason").is_none());
        assert!(claims[0].body.get("hold_until").is_none());
        assert_eq!(renewals[0].body["ttl_minutes"], 45);
        assert_eq!(renewals[0].body["fence"], 1);
        assert_eq!(renewals[0].body["hold_reason"], "waiting for review");
        assert_eq!(renewals[0].body["hold_until"], until);
        let state = server.state.lock().unwrap();
        let claim_at = state
            .seen
            .iter()
            .position(|seen| seen.method == "POST" && seen.path == "/api/v1/zones/claims")
            .unwrap();
        let renew_at = state
            .seen
            .iter()
            .position(|seen| seen.method == "POST" && seen.path == "/api/v1/zones/claims/1/renew")
            .unwrap();
        assert!(
            claim_at < renew_at,
            "hold must use an ordinary claim followed by renewal"
        );
    }
}

#[test]
fn start_work_cloud_rejects_a_hold_deadline_without_a_reason_before_claiming() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[(
            "start_work",
            json!({"paths":["src"],"hold_until":HOLD_EXPIRES_AT}),
        )],
    );
    assert_eq!(answers[0]["isError"], true);
    assert!(
        answers[0]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hold_until requires hold_reason")
    );
    assert!(server.seen("POST", "/api/v1/zones/claims").is_empty());
    assert!(server.state.lock().unwrap().claims.is_empty());
}

#[test]
fn failed_start_work_hold_releases_only_a_proven_new_claim() {
    for scenario in ["created", "reused", "preexisting", "unknown"] {
        let server = Server::start();
        let existing = json!({"id":42,"session":"alice","paths":["src"],"fence":7,"expires_at":HOLD_EXPIRES_AT});
        {
            let mut state = server.state.lock().unwrap();
            state.refuse_renew = Some((
                412,
                json!({"error":{"code":"stale_fence","message":"hold refused"}}),
            ));
            match scenario {
                "created" => state.claim_created = Some(json!(true)),
                "reused" => {
                    state.claim_created = Some(json!(false));
                    state.claim_reused_on_post = Some(existing.clone());
                }
                "preexisting" => state.claims = vec![existing.clone()],
                "unknown" => {}
                _ => unreachable!(),
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let answers = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[(
                "start_work",
                json!({"paths":["src"],"hold_reason":"waiting","task":"D-1"}),
            )],
        );
        assert_eq!(answers[0]["isError"], true, "{scenario}: {}", answers[0]);
        assert!(
            answers[0]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("hold refused"),
            "{scenario}: {}",
            answers[0]
        );
        assert!(
            server
                .seen("POST", "/api/v1/registry/items/D-1/claim")
                .is_empty()
        );
        let id = if matches!(scenario, "reused" | "preexisting") {
            42
        } else {
            1
        };
        assert_eq!(
            server
                .seen("POST", &format!("/api/v1/zones/claims/{id}/renew"))
                .len(),
            1
        );
        let state = server.state.lock().unwrap();
        let deletes: Vec<_> = state
            .seen
            .iter()
            .filter(|seen| seen.method == "DELETE")
            .collect();
        if scenario == "created" {
            assert_eq!(deletes.len(), 1);
            assert_eq!(deletes[0].path, "/api/v1/zones/claims/1");
            assert_eq!(deletes[0].body["fence"], 1);
            assert!(state.claims.is_empty());
        } else {
            assert!(deletes.is_empty(), "{scenario}: {deletes:?}");
            assert_eq!(state.claims.len(), 1, "{scenario}");
            if matches!(scenario, "reused" | "preexisting") {
                assert_eq!(state.claims[0], existing);
            }
        }
        assert_eq!(
            state
                .seen
                .iter()
                .filter(|seen| seen.method == "POST" && seen.path == "/api/v1/zones/claims")
                .count(),
            usize::from(scenario != "preexisting")
        );
    }
}

#[test]
fn start_work_cloud_refuses_a_successful_renewal_that_did_not_install_the_hold() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.claim_created = Some(json!(true));
        state.ignore_renew_hold = true;
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[(
            "start_work",
            json!({"paths":["src"],"hold_reason":"waiting"}),
        )],
    );
    assert_eq!(answers[0]["isError"], true, "{}", answers[0]);
    assert!(
        answers[0]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("did not install the requested hold")
    );
    assert_eq!(server.seen("POST", "/api/v1/zones/claims/1/renew").len(), 1);
    let deletes = server.seen("DELETE", "/api/v1/zones/claims/1");
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].body["fence"], 1);
    assert!(server.state.lock().unwrap().claims.is_empty());
}

#[test]
fn finish_work_cloud_without_an_id_releases_only_a_sole_owned_claim() {
    for count in [0, 1, 2] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.claims = (0..count).map(|index| json!({"id":11+index,"session":"alice","paths":[format!("src/{index}")],"fence":7,"expires_at":HOLD_EXPIRES_AT})).collect();
            // An incoming handover is still owned by its sender.
            state.claims.push(json!({"id":91,"session":"bob","paths":["incoming"],"fence":9,"expires_at":HOLD_EXPIRES_AT,"offered_to_you":true}));
        }
        let original = server.state.lock().unwrap().claims.clone();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let arguments = if count == 2 {
            json!({"task":"D-1","evidence":"reviewed"})
        } else {
            json!({})
        };
        let answers = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[("finish_work", arguments)],
        );
        let answer = &answers[0];
        assert!(
            server.seen("DELETE", "/api/v1/zones/claims").is_empty(),
            "{answer}"
        );
        if count == 2 {
            assert_eq!(answer["isError"], true, "{answer}");
            let text = answer["content"][0]["text"].as_str().unwrap();
            for expected in ["11", "12", "id", "all: true"] {
                assert!(text.contains(expected), "{answer}");
            }
            assert!(
                server
                    .state
                    .lock()
                    .unwrap()
                    .seen
                    .iter()
                    .all(|seen| !seen.path.starts_with("/api/v1/registry/items/D-1")),
                "task submission must not start before claim selection"
            );
            assert_eq!(server.state.lock().unwrap().claims, original);
            assert!(server.seen("DELETE", "/api/v1/zones/claims/11").is_empty());
        } else {
            assert_eq!(answer["isError"], false, "{answer}");
            assert_eq!(answer["structuredContent"]["released"], count);
            assert_eq!(
                answer["structuredContent"]["released_ids"],
                if count == 1 { json!([11]) } else { json!([]) }
            );
            assert_eq!(
                server.seen("DELETE", "/api/v1/zones/claims/11").len(),
                count as usize
            );
            let remaining = server.state.lock().unwrap().claims.clone();
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0]["id"], 91);
        }
    }
}

#[test]
fn finish_work_cloud_all_is_explicit_and_cannot_be_combined_with_id() {
    for arguments in [
        json!({"all":true}),
        json!({"id":"11","all":true,"task":"D-1","evidence":"reviewed"}),
    ] {
        let server = Server::start();
        server.state.lock().unwrap().claims = vec![
            json!({"id":11,"session":"alice","paths":["src"],"fence":7}),
            json!({"id":12,"session":"alice","paths":["docs"],"fence":8}),
        ];
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let answers = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[("finish_work", arguments.clone())],
        );
        let answer = &answers[0];
        let bulk = server.seen("DELETE", "/api/v1/zones/claims");
        if arguments.get("id").is_some() {
            assert_eq!(answer["isError"], true, "{answer}");
            assert!(
                answer["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("not both")
            );
            assert!(bulk.is_empty());
            let state = server.state.lock().unwrap();
            assert!(state.seen.iter().all(|seen| seen.method != "DELETE"
                && !seen.path.starts_with("/api/v1/registry/items/D-1")));
            assert_eq!(state.claims.len(), 2);
        } else {
            assert_eq!(answer["isError"], false, "{answer}");
            assert_eq!(answer["structuredContent"]["released"], 2);
            assert_eq!(answer["structuredContent"]["released_ids"], json!([11, 12]));
            assert_eq!(bulk.len(), 1);
            assert_eq!(bulk[0].path, "/api/v1/zones/claims?session=alice");
            assert!(server.state.lock().unwrap().claims.is_empty());
        }
    }
}

#[test]
fn cloud_cli_status_json_keeps_its_existing_shape_without_fetching_lost_claims() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let result = cli(dir.path(), runtime.path(), &["--json", "status"]);
    let status = json_of(&result);
    assert!(status.get("lost").is_none(), "{status}");
    assert!(status["claims"].is_array(), "{status}");
    assert!(status["tasks"].is_array(), "{status}");
    assert!(status["work"].is_array(), "{status}");
    assert!(status["offers"].is_array(), "{status}");
    // Additive provenance is allowed. Every pre-existing field retains its JSON type/value.
    let mut compatibility = Value::Object(Default::default());
    for key in [
        "unread",
        "claims",
        "offers",
        "work",
        "tasks",
        "machine_level",
        "unannounced",
    ] {
        assert!(
            status.get(key).is_some(),
            "missing existing field {key}: {status}"
        );
        compatibility[key] = status[key].clone();
    }
    assert!(
        status["machine_level"].is_null()
            || matches!(
                status["machine_level"].as_str(),
                Some("ok" | "warn" | "hold" | "critical")
            )
    );
    compatibility["machine_level"] = json!("<machine-dependent>");
    // Pin stable provenance instead of discarding the entire additive freshness contract.
    compatibility["freshness"] = json!({
        "via": status["freshness"]["via"],
        "source": status["freshness"]["source"],
        "claims_cached": status["freshness"]["claims_cached"],
        "sections": {"claims": {
            "source": status["freshness"]["sections"]["claims"]["source"],
            "available": status["freshness"]["sections"]["claims"]["available"]
        }}
    });
    let golden: Value =
        serde_json::from_str(include_str!("status_compatibility_golden.json")).unwrap();
    assert_eq!(compatibility, golden);
    assert!(server.seen("GET", "/api/v1/zones/lost").is_empty());
    assert_eq!(server.seen("GET", "/api/v1/zones/claims").len(), 1);
    let registry = server.seen("GET", "/api/v1/registry/items");
    assert_eq!(registry.len(), 2);
    assert!(
        registry
            .iter()
            .any(|seen| seen.path == "/api/v1/registry/items?status=active&limit=200")
    );
    assert!(
        registry
            .iter()
            .any(|seen| seen.path == "/api/v1/registry/items?status=review&limit=200")
    );
}

#[test]
fn cloud_status_capability_filters_tasks_before_paging_for_direct_and_agent() {
    for through_agent in [false, true] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.registry_assignee_session = true;
            state.registry_page_size = Some(2);
            state.registry_items = (1..=132)
                .map(|index| {
                    json!({
                        "id": format!("D-{index}"), "title": "unrelated review", "status": "review",
                        "assignment": {"executor": "token:ab:other", "released_at": null}
                    })
                })
                .collect();
            for (id, status) in [(1000, "active"), (1001, "review")] {
                state.registry_items.push(json!({
                    "id": format!("D-{id}"), "title": "my task", "status": status,
                    "assignment": {"executor": "token:ab:alice", "session": "not-alice", "released_at": null}
                }));
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let _agent = through_agent.then(|| start_agent(dir.path(), runtime.path()));
        let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
        assert_eq!(
            status["freshness"]["assignment_filter"], "server",
            "{status}"
        );
        assert_eq!(
            status["freshness"]["via"],
            if through_agent { "agent" } else { "direct" },
            "{status}"
        );
        let ids = status["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|task| task["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["D-1000", "D-1001"]);
        let registry = server.seen("GET", "/api/v1/registry/items");
        assert_eq!(registry.len(), 2, "{registry:?}");
        for stage in ["active", "review"] {
            assert!(
                registry.iter().any(|request| {
                    query_value(&request.path, "status").as_deref() == Some(stage)
                        && query_value(&request.path, "assignee_session").as_deref()
                            == Some("alice")
                        && query_value(&request.path, "cursor").is_none()
                }),
                "one filtered page for {stage}: {registry:?}"
            );
        }
    }
}

#[test]
fn cloud_status_capability_http_headers_preserve_full_fallback_and_local_filtering() {
    for scenario in [
        "absent",
        "missing_header",
        "ignored",
        "header_only",
        "filtered_rate_limit",
        "rate_limit_deadline",
        "protocol_drop",
        "protocol_header_only",
    ] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.registry_assignee_session = scenario != "absent";
            state.registry_assignee_protocol_hidden =
                matches!(scenario, "header_only" | "protocol_header_only");
            state.registry_assignee_protocol_header_hidden = scenario == "header_only";
            state.registry_assignee_header_hidden = matches!(
                scenario,
                "missing_header" | "filtered_rate_limit" | "rate_limit_deadline"
            );
            state.registry_assignee_filter_ignored = scenario == "ignored";
            state.refuse_filtered_registry_once = match scenario {
                "filtered_rate_limit" | "rate_limit_deadline" => Some((
                    429,
                    json!({
                        "code": "rate_limited", "status": 429, "detail": "one-shot limit"
                    }),
                )),
                "protocol_drop" => Some((
                    400,
                    json!({
                        "code": "protocol_unsupported", "status": 400, "detail": "rediscover capabilities"
                    }),
                )),
                _ => None,
            };
            state.registry_hide_protocol_on_refusal = scenario == "protocol_drop";
            state.registry_page_size = Some(2);
            for (stage_index, stage) in ["active", "review"].into_iter().enumerate() {
                for index in 1..=3 {
                    state.registry_items.push(json!({
                        "id": format!("D-{}", stage_index * 3 + index),
                        "title": "unrelated task", "status": stage,
                        "assignment": {"executor": "token:ab:other", "released_at": null}
                    }));
                }
                state.registry_items.push(json!({
                    "id": format!("D-{}", 1000 + stage_index),
                    "title": "my last-page task", "status": stage,
                    "assignment": {"executor": "token:ab:alice", "session": "wrong", "released_at": null}
                }));
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let started = Instant::now();
        let output = if scenario == "rate_limit_deadline" {
            binary(dir.path(), runtime.path())
                .args(["--json", "status"])
                .env("LOCKYARD_AGENT", "alice")
                .env("LOCKYARD_TOKEN", "test-token")
                .env("LOCKYARD_STATUS_DEADLINE_MS", "500")
                .output()
                .unwrap()
        } else {
            cli(dir.path(), runtime.path(), &["--json", "status"])
        };
        if scenario == "rate_limit_deadline" {
            assert!(
                !output.status.success(),
                "an unaffordable Retry-After must fail closed"
            );
            let registry = server.seen("GET", "/api/v1/registry/items");
            let active = registry
                .iter()
                .filter(|request| query_value(&request.path, "status").as_deref() == Some("active"))
                .collect::<Vec<_>>();
            assert_eq!(
                active.len(),
                1,
                "no active-chain retry fits the deadline: {registry:?}"
            );
            assert_eq!(
                active[0].path,
                "/api/v1/registry/items?status=active&limit=200&assignee_session=alice",
                "no active-chain unfiltered replay may bypass Retry-After"
            );
            continue;
        }
        let status = json_of(&output);
        if scenario == "filtered_rate_limit" {
            assert!(
                started.elapsed() >= Duration::from_secs(1),
                "unfiltered replay must honor the mock's full Retry-After: 1"
            );
        }
        assert_eq!(
            status["freshness"]["assignment_filter"],
            if matches!(scenario, "ignored" | "protocol_header_only") {
                "server"
            } else {
                "client_fallback"
            },
            "{scenario}: {status}"
        );
        let ids = status["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|task| task["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["D-1000", "D-1001"], "{scenario}: {status}");
        let active = "/api/v1/registry/items?status=active&limit=200";
        let review = "/api/v1/registry/items?status=review&limit=200";
        let active_filtered = format!("{active}&assignee_session=alice");
        let review_filtered = format!("{review}&assignee_session=alice");
        let expected = match scenario {
            "absent" => vec![
                active.to_string(),
                format!("{active}&cursor=2"),
                review.to_string(),
                format!("{review}&cursor=2"),
            ],
            "missing_header" | "filtered_rate_limit" | "protocol_drop" => vec![
                active_filtered,
                active.to_string(),
                format!("{active}&cursor=2"),
                review.to_string(),
                format!("{review}&cursor=2"),
            ],
            "ignored" => vec![
                active_filtered.clone(),
                format!("{active_filtered}&cursor=2"),
                review_filtered.clone(),
                format!("{review_filtered}&cursor=2"),
            ],
            "header_only" => vec![
                active.to_string(),
                format!("{active}&cursor=2"),
                review_filtered,
            ],
            "protocol_header_only" => vec![active_filtered, review_filtered],
            _ => unreachable!(),
        };
        let registry = server.seen("GET", "/api/v1/registry/items");
        let paths = registry
            .iter()
            .map(|request| request.path.clone())
            .collect::<Vec<_>>();
        assert_eq!(paths, expected, "{scenario}");
        if matches!(scenario, "filtered_rate_limit" | "protocol_drop") {
            assert_eq!(
                registry
                    .iter()
                    .filter(|request| request.path.contains("assignee_session="))
                    .count(),
                1,
                "an unconfirmed error or lost negotiated capability must stop filtered retries: {scenario}"
            );
            assert_eq!(
                server.seen("GET", "/api/v1/protocol").len(),
                if scenario == "protocol_drop" { 2 } else { 1 },
                "{scenario}"
            );
        }
        if scenario == "absent" {
            assert!(
                server
                    .state
                    .lock()
                    .unwrap()
                    .seen
                    .iter()
                    .all(|request| { !request.path.contains("assignee_session=") }),
                "an unannounced capability must never be probed"
            );
        }
    }
}

#[test]
fn cloud_status_direct_reads_claims_first_then_each_section_in_turn_on_one_connection() {
    let server = Server::start();
    server.state.lock().unwrap().latency.response = Duration::from_millis(120);
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    let state = server.state.lock().unwrap();
    let events = &state.status_read_events;
    assert_eq!(
        events.len(),
        12,
        "exactly six status reads (open-mail inbox?all): {events:?}"
    );
    assert_eq!(
        events[0],
        ("/api/v1/zones/claims?session=alice".into(), true)
    );
    assert_eq!(
        events[1],
        ("/api/v1/zones/claims?session=alice".into(), false)
    );
    // A one-shot direct client holds one pooled connection after the claims read. Overlapping the
    // four follow-ups made each open its own connection (review round 3: 4 connections per call
    // and a slower cold p95 than 0.3.6), so they now run in turn; the agent still overlaps them.
    for pair in events[2..].chunks(2) {
        assert_eq!(
            pair[0].0, pair[1].0,
            "a read must finish before the next begins: {events:?}"
        );
        assert!(pair[0].1 && !pair[1].1, "{events:?}");
    }
    assert_eq!(state.max_status_reads_in_flight, 1, "{events:?}");
    let order: Vec<&str> = events[2..]
        .iter()
        .step_by(2)
        .map(|(path, _)| path.as_str())
        .collect();
    assert!(
        order[0].contains("/registry/") && order[1].contains("/registry/"),
        "both task chains precede optional mail and work: {events:?}"
    );
}

#[test]
fn cloud_status_stalled_claims_fail_cleanly_before_three_seconds() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.latency.stall_route = Some("/api/v1/zones/claims".into());
        state.latency.stall = Duration::from_secs(10);
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let output = binary(dir.path(), runtime.path())
        .args(["--json", "status"])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .env("LOCKYARD_STATUS_DEADLINE_MS", "2800")
        .output()
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "status exceeded its hard deadline: {:?}",
        started.elapsed()
    );
    assert!(
        !output.status.success(),
        "stalled mandatory claims returned success: {output:?}"
    );
    let error = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        error.contains("deadline") || error.contains("timed out") || error.contains("timeout"),
        "unclear error: {output:?}"
    );
}

#[test]
fn cloud_status_absent_agent_falls_back_to_authoritative_network() {
    let server = Server::start();
    server.state.lock().unwrap().latency = modelled_bad_link();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    // Cold TCP/TLS/discovery are paid on the first connection. This must succeed on the same
    // bad-link model as the benchmark, rather than only on an unimpaired localhost server.
    assert!(
        started.elapsed() < Duration::from_millis(6500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(status["freshness"]["via"], "direct");
    assert_eq!(status["freshness"]["claims_cached"], false);
    assert_eq!(server.seen("GET", "/api/v1/zones/claims").len(), 1);
}

#[test]
fn cloud_status_hung_agent_falls_back_within_the_probe_budget() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(socket(runtime.path()).parent().unwrap()).unwrap();
    std::fs::set_permissions(
        socket(runtime.path()).parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let listener = UnixListener::bind(socket(runtime.path())).unwrap();
    let accepted = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&accepted);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            seen.store(true, Ordering::Relaxed);
            thread::spawn(move || {
                let _held_open = stream;
                thread::sleep(Duration::from_secs(5));
            });
        }
    });
    let started = Instant::now();
    json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "hung agent consumed the status budget: {:?}",
        started.elapsed()
    );
    assert!(
        accepted.load(Ordering::Relaxed),
        "test did not reach the hung socket"
    );
    assert_eq!(server.seen("GET", "/api/v1/zones/claims").len(), 1);
}

#[test]
fn cloud_status_hung_aggregate_falls_back_to_authoritative_direct_reads() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = Server::start();
    server.state.lock().unwrap().latency = modelled_bad_link();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let folder = socket(runtime.path()).parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(socket(runtime.path())).unwrap();
    let aggregate_accepted = Arc::new(AtomicBool::new(false));
    let accepted = Arc::clone(&aggregate_accepted);
    let url = server.url.clone();
    thread::spawn(move || {
        for stream in listener.incoming().take(2).flatten() {
            let mut stream = stream;
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            match request["op"].as_str().unwrap() {
                "ping" => {
                    let reply = json!({"status": {
                        "url": url, "workspace": "team",
                        "token_id": lockyard_cloud_client::token_id("test-token"),
                        "status_read_v1": true, "pid": 1, "view_fresh": false,
                        "view_age_ms": null, "claims": 0, "board": 0, "sessions": 0,
                        "outbox": 0, "coordination_seq": 0, "registry_seq": 0
                    }});
                    writeln!(stream, "{reply}").unwrap();
                }
                "status_read" => {
                    assert_eq!(request["session"], "alice");
                    assert!(
                        request["deadline_ms"]
                            .as_u64()
                            .is_some_and(|ms| ms > 0 && ms <= 1500)
                    );
                    accepted.store(true, Ordering::SeqCst);
                    // Ping succeeds, but the subsequent aggregate never answers inside its
                    // 1.5-second budget. Keep the connection open to exercise timeout fallback.
                    thread::sleep(Duration::from_secs(4));
                }
                operation => panic!("unexpected fake-agent operation: {operation}"),
            }
        }
    });

    // This test isolates the aggregate timeout/fallback. Post-link OS image verification can
    // happen before main starts; the benchmark deliberately retains that raw cold-start cost.
    json_of(&cli(dir.path(), runtime.path(), &["--json", "about"]));
    let started = Instant::now();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    let elapsed = started.elapsed();
    assert!(
        aggregate_accepted.load(Ordering::SeqCst),
        "aggregate request was not accepted"
    );
    assert!(
        elapsed >= Duration::from_millis(1400),
        "aggregate did not wait for its timeout: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(6500),
        "aggregate fallback exceeded the status deadline: {elapsed:?}"
    );
    assert_eq!(status["freshness"]["via"], "direct");
    assert_eq!(status["claims"], json!([]));
    assert_eq!(status["tasks"], json!([]));
    assert_eq!(server.seen("GET", "/api/v1/zones/claims").len(), 1);
    assert_eq!(server.seen("GET", "/api/v1/registry/items").len(), 2);
}

#[test]
fn cloud_status_cold_and_restarted_agent_succeeds_on_the_modelled_bad_link() {
    let server = Server::start();
    server.state.lock().unwrap().latency = modelled_bad_link();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    for restart in 0..2 {
        {
            let mut state = server.state.lock().unwrap();
            state.claims = if restart == 0 {
                vec![json!({"id":71,"session":"alice","paths":["src"],"meta":{},
                    "fence":1,"expires_at":HOLD_EXPIRES_AT})]
            } else {
                vec![]
            };
        }
        // Start the actual daemon, waiting only for its local Ping. Do not first run status or
        // wait for its HTTP snapshots: this exercises a genuinely cold/newly restarted pool.
        let agent = start_agent_until(dir.path(), runtime.path(), false);
        let started = Instant::now();
        let output = cli(dir.path(), runtime.path(), &["--json", "status"]);
        let status = json_of(&output);
        assert!(
            started.elapsed() < Duration::from_millis(6500),
            "first status after agent start exceeded the deadline: {:?}",
            started.elapsed()
        );
        assert!(
            matches!(
                status["freshness"]["via"].as_str(),
                Some("agent" | "direct")
            ),
            "{status}"
        );
        assert_eq!(status["freshness"]["claims_cached"], false, "{status}");
        assert_eq!(
            status["freshness"]["sections"]["claims"]["source"], "network",
            "{status}"
        );
        assert_eq!(
            status["claims"].as_array().unwrap().len(),
            if restart == 0 { 1 } else { 0 },
            "agent restart reused an old claims answer: {status}"
        );
        assert!(status["tasks"].is_array(), "{status}");
        drop(agent);
    }
}

#[test]
fn cloud_status_running_agent_still_observes_claim_revocation() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![json!({
        "id": 71, "session": "alice", "paths": ["src"], "meta": {}, "fence": 1,
        "expires_at": HOLD_EXPIRES_AT
    })];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let before = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(before["freshness"]["via"], "agent");
    assert_eq!(before["claims"].as_array().unwrap().len(), 1);
    server.state.lock().unwrap().claims.clear();
    let after = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(
        after["claims"],
        json!([]),
        "revoked claim survived in daemon memory: {after}"
    );
}

#[test]
fn cloud_status_running_agent_preserves_tokenless_cli_support() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let output = binary(dir.path(), runtime.path())
        .args(["--json", "status"])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .output()
        .unwrap();
    let status = json_of(&output);
    assert_eq!(status["freshness"]["via"], "agent");
    assert_eq!(status["claims"], json!([]));
    assert_eq!(status["tasks"], json!([]));
}

#[test]
fn cloud_status_expired_and_idle_released_claims_are_never_reported_held() {
    for through_agent in [false, true] {
        let server = Server::start();
        server.state.lock().unwrap().claims = vec![
            json!({"id": 71, "session": "alice", "paths": ["expired"], "meta": {},
                "fence": 1, "expires_at": "2000-01-01T00:00:00Z"}),
            json!({"id": 72, "session": "alice", "paths": ["idle"], "meta": {},
                "fence": 1, "expires_at": HOLD_EXPIRES_AT, "idle_release_at": "2000-01-01T00:00:00Z"}),
        ];
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let _agent = through_agent.then(|| start_agent(dir.path(), runtime.path()));
        let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
        assert_eq!(
            status["claims"],
            json!([]),
            "expired claim reported as held: {status}"
        );
    }
}

#[test]
fn cloud_status_outage_never_uses_the_agents_last_claim_snapshot() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![json!({
        "id": 71, "session": "alice", "paths": ["src"], "meta": {}, "fence": 1,
        "expires_at": HOLD_EXPIRES_AT
    })];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    assert_eq!(
        json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]))["claims"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    server.state.lock().unwrap().refuse_claims_get = Some((
        503,
        json!({"error": {"code": "unavailable", "message": "network gap"}}),
    ));
    let started = Instant::now();
    let output = cli(dir.path(), runtime.path(), &["--json", "status"]);
    assert!(
        !output.status.success(),
        "last snapshot accepted during network gap: {output:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn cloud_status_task_assignees_and_stop_stages_are_preserved() {
    for through_agent in [false, true] {
        let server = Server::start();
        let item = |id: &str, stage: &str, executor: &str| {
            json!({
                "id": id, "title": id, "body": "", "status": stage, "version": 1,
                "created_by": "token:ab:writer", "assignment": {"executor": executor,
                "lease_expires_at": HOLD_EXPIRES_AT}, "evidence": []
            })
        };
        server.state.lock().unwrap().registry_items = vec![
            item("D-41", "active", "token:ab:alice"),
            item("D-42", "review", "token:ab:alice"),
            item("D-43", "review", "token:ab:other"),
            item("D-44", "ready", "token:ab:alice"),
        ];
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let _agent = through_agent.then(|| start_agent(dir.path(), runtime.path()));
        let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
        let tasks = status["tasks"].as_array().unwrap();
        assert_eq!(
            tasks.len(),
            2,
            "foreign or non-assigned stage included: {status}"
        );
        assert_eq!(tasks[0]["id"], "D-41");
        assert_eq!(tasks[0]["assignee"], "alice");
        assert_eq!(tasks[0]["stage"], "active");
        assert_eq!(tasks[1]["id"], "D-42");
        assert_eq!(tasks[1]["stage"], "review");
    }
}

#[test]
fn cloud_status_unconfirmed_tasks_fail_instead_of_looking_empty() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.latency.stall_route = Some("/api/v1/registry/items".into());
        state.latency.stall = Duration::from_secs(10);
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let output = binary(dir.path(), runtime.path())
        .args(["--json", "status"])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .env("LOCKYARD_STATUS_DEADLINE_MS", "2800")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Stop hook would mistake unconfirmed tasks for none: {output:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn cloud_status_optional_failures_are_explicit_and_keep_existing_json_fields() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        let refusal = Some((
            403,
            json!({"error": {"code": "forbidden", "message": "mail/work unavailable"}}),
        ));
        state.refuse_inbox_get = refusal.clone();
        state.refuse_work_get = refusal;
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert!(status["claims"].is_array());
    assert!(status["tasks"].is_array());
    assert!(status.get("unread").is_some());
    assert!(status["unread"].is_null());
    assert_eq!(status["work"], json!([]));
    assert_eq!(
        status["freshness"]["sections"]["unread"]["available"],
        false
    );
    assert_eq!(status["freshness"]["sections"]["work"]["available"], false);
}

#[test]
fn cloud_status_mail_has_the_remaining_deadline_instead_of_a_half_second_cutoff() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.inbox = vec![json!({"id":7,"from_session":"bob","to":"alice","body":"read me"})];
        state.latency.stall_route = Some("/api/v1/bus/inbox".into());
        state.latency.stall = Duration::from_millis(800);
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(
        status["unread"], 1,
        "slow mail was silently discarded: {status}"
    );
    assert_eq!(status["freshness"]["sections"]["unread"]["available"], true);
}

#[test]
fn cloud_status_optional_mail_timeout_keeps_a_warm_agent_answer() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.latency.response = Duration::from_millis(20);
        state.latency.keep_alive = true;
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let warm = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(warm["freshness"]["via"], "agent");
    {
        let mut state = server.state.lock().unwrap();
        state.latency.stall_route = Some("/api/v1/bus/inbox".into());
        state.latency.stall = Duration::from_secs(2);
    }
    // Bob has no prior unread observation. Mail must use its whole remaining read budget,
    // while leaving enough IPC time to deliver already-confirmed mandatory sections.
    let started = Instant::now();
    let output = binary(dir.path(), runtime.path())
        .args(["--json", "status"])
        .env("LOCKYARD_AGENT", "bob")
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap();
    let status = json_of(&output);
    // Direct fallback re-waits the stalled inbox and is the defect this test catches. Check
    // via=agent first: wall time alone flaked when the agent finished as the socket expired.
    assert_eq!(
        status["freshness"]["via"],
        "agent",
        "optional mail forced an unnecessary direct fallback after {:?}: {status}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_millis(1900),
        "optional mail forced an unnecessary direct fallback: {:?}",
        started.elapsed()
    );
    assert!(status["claims"].is_array(), "{status}");
    assert!(status["tasks"].is_array(), "{status}");
    assert_eq!(status["freshness"]["sections"]["claims"]["available"], true);
    assert_eq!(
        status["freshness"]["sections"]["tasks_active"]["available"],
        true
    );
    assert_eq!(
        status["freshness"]["sections"]["tasks_review"]["available"],
        true
    );
    assert!(
        status["unread"].is_null(),
        "unknown mail must not become zero: {status}"
    );
    assert_eq!(
        status["freshness"]["sections"]["unread"]["available"], false,
        "{status}"
    );
    assert!(
        status["freshness"]["sections"]["unread"]["elapsed_ms"]
            .as_u64()
            .is_some_and(|ms| ms >= 1000),
        "mail must retain its remaining budget rather than the old 500 ms cutoff: {status}"
    );
    let state = server.state.lock().unwrap();
    assert!(
        state.status_read_starts.iter().any(|(path, session)| {
            path == "/api/v1/bus/inbox" && session.as_deref() == Some("bob")
        }),
        "test did not actually start Bob's mail read"
    );
    assert!(
        state.seen.iter().all(|request| {
            request.path != "/api/v1/bus/inbox" || request.session.as_deref() != Some("bob")
        }),
        "mail unexpectedly completed before the deadline"
    );
    assert_eq!(
        state
            .seen
            .iter()
            .filter(|request| {
                request.path.starts_with("/api/v1/registry/items?")
                    && request.session.as_deref() == Some("bob")
            })
            .count(),
        2,
        "mandatory assigned-task reads must finish while mail is still pending"
    );
}

#[test]
fn cloud_status_rate_limiting_that_cannot_fit_fails_closed_and_names_the_cause() {
    for refuse_claims in [true, false] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            let refusal = Some((
                429,
                json!({"error":{"code":"rate_limited","message":"rate limiting test"}}),
            ));
            if refuse_claims {
                state.refuse_claims_get = refusal;
            } else {
                state.refuse_registry_get = refusal;
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        // Still below Retry-After=1s + the required 1s request estimate, while allowing
        // CLI setup on this constrained host. Client tests separately pin the 900ms case.
        let output = binary(dir.path(), runtime.path())
            .args(["--json", "status"])
            .env("LOCKYARD_AGENT", "alice")
            .env("LOCKYARD_TOKEN", "test-token")
            .env("LOCKYARD_STATUS_DEADLINE_MS", "1900")
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "mandatory rate-limited read must fail: {output:?}"
        );
        let error = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        assert!(
            error.contains("rate limit") || error.contains("rate_limit"),
            "{error}"
        );
        let state = server.state.lock().unwrap();
        let attempts = state
            .seen
            .iter()
            .filter(|seen| {
                seen.path.starts_with(if refuse_claims {
                    "/api/v1/zones/claims"
                } else {
                    "/api/v1/registry/items"
                })
            })
            .count();
        assert_eq!(
            attempts,
            if refuse_claims { 1 } else { 2 },
            "Retry-After=1 plus a request estimate cannot fit a 1900 ms deadline"
        );
    }
}

#[test]
fn cloud_status_rate_limiting_retries_when_retry_after_fits_the_deadline() {
    let server = Server::start();
    server.state.lock().unwrap().refuse_claims_get_once = Some((
        429,
        json!({"error":{"code":"rate_limited","message":"retry shortly"}}),
    ));
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let output = binary(dir.path(), runtime.path())
        .args(["--json", "status"])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .env("LOCKYARD_STATUS_DEADLINE_MS", "2800")
        .output()
        .unwrap();
    json_of(&output);
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "Retry-After was ignored"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "retry extended the deadline"
    );
    assert_eq!(server.seen("GET", "/api/v1/zones/claims").len(), 2);
}

#[test]
fn cloud_status_ten_agent_callers_wait_with_bounded_http_workers() {
    use std::os::unix::net::UnixStream;
    use std::sync::Barrier;
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.latency.response = Duration::from_millis(120);
        state.latency.keep_alive = true;
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    // Let upkeep finish the warm-up pass and go idle first: an idle upkeep that scans while the
    // ten callers are on the network is what once sent a duplicate inbox read (sixth section read).
    thread::sleep(Duration::from_millis(800));
    let (requests_before, connections_before) = {
        let mut state = server.state.lock().unwrap();
        state.max_status_reads_in_flight = 0;
        (
            state
                .status_read_events
                .iter()
                .filter(|(_, started)| *started)
                .count(),
            state.connections,
        )
    };
    let barrier = Arc::new(Barrier::new(10));
    thread::scope(|scope| {
        let handles = (0..10)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                let socket_path = socket(runtime.path());
                scope.spawn(move || {
                    let mut stream = UnixStream::connect(socket_path).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(7)))
                        .unwrap();
                    barrier.wait();
                    writeln!(
                        stream,
                        "{}",
                        json!({"workspace":"team", "op":"status_read",
                    "session":format!("session-{index}"), "repository":null,"deadline_ms":2600})
                    )
                    .unwrap();
                    let mut line = String::new();
                    BufReader::new(stream).read_line(&mut line).unwrap();
                    let response: Value = serde_json::from_str(&line).unwrap();
                    assert!(
                        response.get("error").is_none_or(Value::is_null),
                        "{response}"
                    );
                    let status = &response["status_read"];
                    assert!(status["claims"].is_array(), "{response}");
                    assert_eq!(status["freshness"]["claims_cached"], false, "{response}");
                    assert_eq!(
                        status["freshness"]["sections"]["claims"]["source"], "network",
                        "{response}"
                    );
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    let state = server.state.lock().unwrap();
    assert!(
        state.max_status_reads_in_flight <= 8,
        "global HTTP cap was exceeded"
    );
    assert!(
        state.connections - connections_before <= 8,
        "queue must not open a connection per caller"
    );
    for index in 0..10 {
        let session = format!("session-{index}");
        assert_eq!(
            state
                .seen
                .iter()
                .filter(|seen| seen.path == format!("/api/v1/zones/claims?session=session-{index}"))
                .count(),
            1,
            "each distinct session requires exactly one fresh claims read"
        );
        assert_eq!(
            state
                .status_read_starts
                .iter()
                .filter(
                    |(_, observed_session)| observed_session.as_deref() == Some(session.as_str())
                )
                .count(),
            6,
            "each caller uses five mandatory section reads plus one open-mail peek"
        );
    }
    let status_requests = state
        .status_read_events
        .iter()
        .filter(|(_, started)| *started)
        .count();
    assert!(
        status_requests - requests_before <= 70,
        "read count exceeded exactly 60 caller reads (5+open-mail) plus at most 10 upkeep reads"
    );
}

fn modelled_bad_link() -> Latency {
    Latency {
        connect: Duration::from_millis(80),
        handshake: Duration::from_secs(1),
        response: Duration::from_millis(300),
        stall_every: 33,
        stall: Duration::from_secs(1),
        stall_route: None,
        stall_inbox_all: false,
        keep_alive: true,
    }
}

/// Real executable benchmark, deliberately ignored in routine CI (about four minutes).
///
/// Run serially with two build jobs:
/// `LOCKYARD_STATUS_BASELINE_BIN=/absolute/path/to/old/lockyard cargo test -p lockyard --test cloud status_latency_benchmark -j 2 -- --ignored --nocapture --test-threads=1`
/// The baseline must be the pre-change binary. `LOCKYARD_STATUS_SAMPLES` defaults to 34.
/// `LOCKYARD_STATUS_CASE` optionally selects comma-separated printed case labels; after cases
/// need no baseline. To compare just the cold paths, select
/// `before_sequential_direct,after_concurrent_direct,after_assignee_filtered_direct`.
/// `LOCKYARD_STATUS_WARM_EXECUTABLE=1` explicitly runs `about` once before each measured case to
/// diagnose OS executable-loading costs. The default continues to measure raw cold execution.
/// The cancellation case kills twenty real CLI processes at 850 ms before measuring one hard
/// caller, repeating once per sample. It adds a one-second claims-only stall during each soft
/// phase so all twenty callers survive until killed, then restores the ordinary model. Reported
/// cancellation-case requests/bytes include those soft bursts, divided by hard samples only.
/// This HTTP mock models 300 ms RTT per request, 1 s TLS and 80 ms connect cost per
/// accepted connection, with a 1 s retransmission-like stall every 33 requests (3.03%).
/// Setup is an application-level delay, not real packet loss/TCP/TLS emulation.
#[test]
#[ignore = "opt-in latency benchmark; baseline case needs LOCKYARD_STATUS_BASELINE_BIN"]
fn status_latency_benchmark() {
    let selected = std::env::var("LOCKYARD_STATUS_CASE").ok();
    let selected = selected
        .as_deref()
        .map(|labels| labels.split(',').collect::<Vec<_>>());
    assert!(
        selected
            .as_ref()
            .is_none_or(|labels| labels.iter().all(|label| matches!(
                *label,
                "before_sequential_direct"
                    | "after_concurrent_direct"
                    | "after_assignee_filtered_direct"
                    | "after_warm_agent"
                    | "after_ten_concurrent_agent"
                    | "after_twenty_cancelled_soft_then_hard"
            ))),
        "LOCKYARD_STATUS_CASE must contain comma-separated printed case labels"
    );
    let runs = |label| {
        selected
            .as_ref()
            .is_none_or(|labels| labels.contains(&label))
    };
    let samples = std::env::var("LOCKYARD_STATUS_SAMPLES")
        .ok()
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(34);
    assert!(samples >= 2);
    let baseline = if runs("before_sequential_direct") {
        let executable = std::env::var_os("LOCKYARD_STATUS_BASELINE_BIN")
            .expect("set LOCKYARD_STATUS_BASELINE_BIN to the pre-change executable");
        Some(latency_case(
            "before_sequential_direct",
            Some(Path::new(&executable)),
            false,
            samples,
            1,
            0,
            false,
        ))
    } else {
        None
    };
    let cold = if runs("after_concurrent_direct") {
        Some(latency_case(
            "after_concurrent_direct",
            None,
            false,
            samples,
            1,
            0,
            false,
        ))
    } else {
        None
    };
    if runs("after_assignee_filtered_direct") {
        latency_case(
            "after_assignee_filtered_direct",
            None,
            false,
            samples,
            1,
            0,
            true,
        );
    }
    if runs("after_warm_agent") {
        latency_case("after_warm_agent", None, true, samples, 1, 0, false);
    }
    if runs("after_ten_concurrent_agent") {
        latency_case(
            "after_ten_concurrent_agent",
            None,
            true,
            samples,
            10,
            0,
            false,
        );
    }
    if runs("after_twenty_cancelled_soft_then_hard") {
        latency_case(
            "after_twenty_cancelled_soft_then_hard",
            None,
            true,
            samples,
            1,
            20,
            false,
        );
    }
    // Emit every case before comparing the cross-case acceptance threshold, so a failed
    // cold percentile still leaves every selected diagnostic row.
    if let (Some(baseline), Some(cold)) = (baseline, cold) {
        assert!(
            cold.p95 <= baseline.p95,
            "cold direct p95 {:?} regressed from 0.3.6 {:?}",
            cold.p95,
            baseline.p95
        );
    }
}

#[derive(Clone, Copy)]
struct LatencyStats {
    p95: Duration,
}

fn latency_case(
    label: &str,
    executable: Option<&Path>,
    warm_agent: bool,
    samples: usize,
    callers: usize,
    soft_callers_per_hard: usize,
    registry_assignee_session: bool,
) -> LatencyStats {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.latency = modelled_bad_link();
        state.registry_assignee_session = registry_assignee_session;
        // Keep the same 132 unrelated review items in every case. Capability-aware filtering
        // removes them before paging; fallback cases still transfer the roughly 470 KB payload.
        state.registry_items = (1..=132).map(|index| json!({
            "id": format!("D-{index}"), "title": "foreign review", "body": "x".repeat(3200),
            "status": "review", "version": 1, "target": "ci_passed",
            "created_by": "token:ab:writer", "created_at": "2026-11-02T10:00:00+00:00",
            "updated_at": "2026-11-02T10:00:00+00:00",
            "assignment": {"executor": "token:ab:other", "lease_expires_at": HOLD_EXPIRES_AT},
            "evidence": []
        })).collect();
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let warmed_executable = std::env::var("LOCKYARD_STATUS_WARM_EXECUTABLE").as_deref() == Ok("1");
    if warmed_executable {
        let started = Instant::now();
        let output = latency_command(dir.path(), runtime.path(), executable)
            .args(["--json", "about"])
            .env_remove("LOCKYARD_PERF_TRACE")
            .output()
            .unwrap();
        json_of(&output);
        eprintln!(
            "status_latency {label} executable_warmup=about wall_ms={} measured=false",
            started.elapsed().as_millis()
        );
    }
    let _agent = warm_agent.then(|| start_agent(dir.path(), runtime.path()));
    if warm_agent {
        for _ in 0..5 {
            json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
        }
    }
    let mut times = Vec::with_capacity(samples);
    let mut failures = 0;
    let (mut agent_routes, mut direct_routes) = (0, 0);
    let mut soft_killed = 0;
    let mut soft_completed_success = 0;
    let mut soft_completed_failure = 0;
    let mut soft_kill_max = Duration::ZERO;
    let (bytes_before, requests_before, connections_before) = {
        let mut state = server.state.lock().unwrap();
        state.max_status_reads_in_flight = 0;
        (
            state.response_bytes,
            state.requests_started,
            state.connections,
        )
    };
    // The concurrent case runs full groups of ten and reports its actual sample count.
    let samples = samples.div_ceil(callers) * callers;
    for batch in 0..samples / callers {
        if soft_callers_per_hard > 0 {
            assert_eq!(callers, 1, "one hard call must follow each soft burst");
            // Keep every soft CLI alive until the hook's real 850 ms kill point. Only
            // Claims GETs begun during this phase (including upkeep) receive an extra
            // one-second stall. Restore the ordinary model before starting the hard caller.
            // Existing HTTP reads retain the impairment captured at request start.
            {
                let mut state = server.state.lock().unwrap();
                state.latency.stall_route = Some("/api/v1/zones/claims".to_string());
                state.latency.stall = Duration::from_secs(1);
            }
            let mut children = (0..soft_callers_per_hard)
                .map(|caller| {
                    let started = Instant::now();
                    let child = latency_command(dir.path(), runtime.path(), executable)
                        .args(["--json", "status"])
                        .env("LOCKYARD_AGENT", format!("soft-{caller}"))
                        .env_remove("LOCKYARD_PERF_TRACE")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap();
                    (started, child)
                })
                .collect::<Vec<_>>();
            // Each child receives its own 850 ms budget, including executable startup.
            for (started, child) in &mut children {
                thread::sleep(Duration::from_millis(850).saturating_sub(started.elapsed()));
                let already_done = child.try_wait().unwrap();
                if already_done.is_none() {
                    child.kill().unwrap();
                    soft_kill_max = soft_kill_max.max(started.elapsed());
                }
                let status = child.wait().unwrap();
                if status.success() {
                    soft_completed_success += 1;
                } else if already_done.is_some() || status.code().is_some() {
                    soft_completed_failure += 1;
                } else {
                    soft_killed += 1;
                }
            }
            server.state.lock().unwrap().latency = modelled_bad_link();
        }
        let barrier = Arc::new(std::sync::Barrier::new(callers));
        let results = thread::scope(|scope| {
            let handles = (0..callers)
                .map(|caller| {
                    let index = batch * callers + caller;
                    let mut command = latency_command(dir.path(), runtime.path(), executable);
                    if callers > 1 {
                        command.env("LOCKYARD_AGENT", format!("parallel-{caller}"));
                    }
                    if index == 0 {
                        command.env("LOCKYARD_PERF_TRACE", "1");
                    } else {
                        command.env_remove("LOCKYARD_PERF_TRACE");
                    }
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        let started = Instant::now();
                        let output = command.args(["--json", "status"]).output().unwrap();
                        (index, started.elapsed(), output)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        for (index, wall, output) in results {
            times.push(wall);
            if soft_callers_per_hard > 0 {
                assert!(
                    wall < Duration::from_secs(8),
                    "hard caller exceeded the hook's eight-second wall bound after soft cancellation: {wall:?}"
                );
            }
            if index == 0 {
                eprintln!(
                    "status_latency {label} first_call firstwall_ms={} perf={:?}",
                    wall.as_millis(),
                    String::from_utf8_lossy(&output.stderr)
                        .lines()
                        .filter(|line| line.starts_with("perf_span "))
                        .collect::<Vec<_>>()
                );
            }
            if output.status.success() {
                let value = json_of(&output);
                assert_eq!(value["claims"], json!([]));
                assert_eq!(value["tasks"], json!([]));
                if executable.is_none() {
                    if registry_assignee_session {
                        assert_eq!(value["freshness"]["assignment_filter"], "server", "{value}");
                    }
                    assert_eq!(value["freshness"]["claims_cached"], false);
                    assert_eq!(
                        value["freshness"]["sections"]["claims"]["source"],
                        "network"
                    );
                    match value["freshness"]["via"].as_str() {
                        Some("agent") => agent_routes += 1,
                        Some("direct") => direct_routes += 1,
                        route => panic!("unexpected status route: {route:?}"),
                    }
                }
            } else {
                failures += 1;
                eprintln!(
                    "status_latency {label} sample={index} wall_ms={} failure={}",
                    wall.as_millis(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            if index == 0 && !warm_agent {
                let state = server.state.lock().unwrap();
                eprintln!(
                    "status_latency {label} first_call setup_cost_ms_per_connection=1080 connections={} request_ms={:?}",
                    state.connections,
                    state
                        .request_timings
                        .iter()
                        .map(|(path, duration)| (path, duration.as_millis()))
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    times.sort_unstable();
    let p50 = times[samples / 2];
    let p95 = times[(samples * 95 / 100).min(samples - 1)];
    let state = server.state.lock().unwrap();
    if registry_assignee_session {
        let registry = state
            .seen
            .iter()
            .filter(|request| {
                request.method == "GET" && request.path.starts_with("/api/v1/registry/items?")
            })
            .collect::<Vec<_>>();
        assert_eq!(registry.len(), samples * 2, "two task chains per call");
        assert!(
            registry.iter().all(|request| {
                query_value(&request.path, "assignee_session").as_deref() == Some("alice")
                    && query_value(&request.path, "cursor").is_none()
            }),
            "{registry:?}"
        );
    }
    eprintln!(
        "status_latency {label} samples={samples} callers={callers} warmed_executable={warmed_executable} p50_ms={} p95_ms={} max_ms={} failures={} server_body_bytes_per_call={} requests_per_call={:.2} new_connections={} concurrent_reads={} agent_routes={agent_routes} direct_routes={direct_routes} soft_callers_per_hard={soft_callers_per_hard} soft_killed={soft_killed} soft_completed_success={soft_completed_success} soft_completed_failure={soft_completed_failure} soft_kill_target_ms=850 soft_kill_max_ms={} soft_claim_stall_ms={}",
        p50.as_millis(),
        p95.as_millis(),
        times.last().unwrap().as_millis(),
        failures,
        (state.response_bytes - bytes_before) / samples,
        (state.requests_started - requests_before) as f64 / samples as f64,
        state.connections - connections_before,
        state.max_status_reads_in_flight,
        soft_kill_max.as_millis(),
        if soft_callers_per_hard > 0 { 1000 } else { 0 }
    );
    assert_eq!(
        failures, 0,
        "{label}: every sample must confirm mandatory claims/tasks"
    );
    if soft_callers_per_hard > 0 {
        assert_eq!(
            soft_killed,
            samples * soft_callers_per_hard,
            "the cancellation row requires every soft CLI to remain alive until killed"
        );
        assert_eq!(soft_completed_success, 0);
        assert_eq!(soft_completed_failure, 0);
    }
    if warm_agent && callers == 1 && soft_callers_per_hard == 0 {
        assert_eq!(
            agent_routes, samples,
            "warm calls must stay on the agent route"
        );
        assert!(
            p50 <= Duration::from_millis(500),
            "warm p50 {p50:?} exceeds 500 ms"
        );
        assert!(
            p95 <= Duration::from_millis(1500),
            "warm p95 {p95:?} exceeds 1500 ms"
        );
        assert!(*times.last().unwrap() < Duration::from_secs(3));
    }
    LatencyStats { p95 }
}

fn latency_command(dir: &Path, runtime: &Path, executable: Option<&Path>) -> Command {
    let mut command = binary(dir, runtime);
    if let Some(executable) = executable {
        let envs = command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(|value| value.to_os_string())))
            .collect::<Vec<_>>();
        command = Command::new(executable);
        command.current_dir(dir);
        for (key, value) in envs {
            if let Some(value) = value {
                command.env(key, value);
            } else {
                command.env_remove(key);
            }
        }
    }
    command
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token");
    command
}

#[test]
fn start_work_cloud_rollback_releases_only_its_own_acquisition() {
    for concurrent_reuse in [false, true] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.refuse_registry_claim = true;
            state.claim_created = Some(json!(!concurrent_reuse));
            if concurrent_reuse {
                // The GET snapshot was empty, but another same-session request
                // acquired this claim before our POST reached the server.
                state.claim_reused_on_post = Some(json!({
                    "id":42, "session":"alice", "paths":["src"], "fence":7,
                    "meta":{"lockyard_start_work_nonce":"01K00000000000000000000000"}
                }));
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let mut child = binary(dir.path(), runtime.path())
            .args(["mcp"])
            .env("LOCKYARD_AGENT", "alice")
            .env("LOCKYARD_TOKEN", "test-token")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/call",
                "params":{"name":"start_work", "arguments":{"paths":["src"], "task":"D-1"}}
            })
        )
        .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(answer["result"]["isError"], true);
        assert_eq!(
            server.seen("POST", "/api/v1/zones/claims").len(),
            1,
            "{answer}; seen={:?}",
            server.state.lock().unwrap().seen
        );
        assert_eq!(
            server
                .seen("POST", "/api/v1/registry/items/D-1/claim")
                .len(),
            1
        );
        let deletes: Vec<_> = server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|seen| seen.method == "DELETE")
            .cloned()
            .collect();
        if concurrent_reuse {
            assert!(
                deletes.is_empty(),
                "another attempt's claim was released: {deletes:?}"
            );
        } else {
            assert_eq!(deletes.len(), 1);
            assert_eq!(deletes[0].path, "/api/v1/zones/claims/1");
            assert_eq!(deletes[0].body["fence"], 1);
        }
    }
}

fn run_failed_start_work(server: &Server) -> Value {
    server.state.lock().unwrap().refuse_registry_claim = true;
    let dir = cloud_project(server);
    let runtime = tempfile::tempdir().unwrap();
    let mut child = binary(dir.path(), runtime.path())
        .args(["mcp"])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{"name":"start_work", "arguments":{"paths":["src"], "task":"D-1"}}
        })
    )
    .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(answer["result"]["isError"], true, "{answer}");
    assert_eq!(
        server
            .seen("POST", "/api/v1/registry/items/D-1/claim")
            .len(),
        1,
        "{answer}"
    );
    answer
}

fn failed_start_work(server: &Server) -> Value {
    let answer = run_failed_start_work(server);
    assert_eq!(
        server.seen("POST", "/api/v1/zones/claims").len(),
        1,
        "{answer}"
    );
    answer
}

#[test]
fn start_work_cloud_rolls_back_created_claim_without_meta() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.claim_created = Some(json!(true));
        state.omit_claim_meta = true;
    }
    failed_start_work(&server);
    let deletes = server.seen("DELETE", "/api/v1/zones/claims/1");
    assert_eq!(
        deletes.len(),
        1,
        "new claim was leaked when meta was absent"
    );
    assert_eq!(deletes[0].body["fence"], 1);
    assert!(server.state.lock().unwrap().claims.is_empty());
}

#[test]
fn start_work_cloud_preserves_reused_claim_even_when_request_meta_is_echoed() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.claim_reused_on_post = Some(json!({
            "id":42, "session":"alice", "paths":["src"], "fence":7
        }));
        state.claim_created = Some(json!(false));
        state.echo_reused_claim_meta = true;
    }
    failed_start_work(&server);
    assert!(
        server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .all(|r| r.method != "DELETE"),
        "a reused claim was released on reflected request metadata"
    );
    assert_eq!(server.state.lock().unwrap().claims[0]["id"], 42);
}

#[test]
fn start_work_cloud_preserves_unknown_creation_even_with_echoed_meta() {
    for created in [None, Some(Value::Null), Some(json!("true")), Some(json!(1))] {
        let server = Server::start();
        server.state.lock().unwrap().claim_created = created;
        failed_start_work(&server);
        assert!(
            server
                .state
                .lock()
                .unwrap()
                .seen
                .iter()
                .all(|r| r.method != "DELETE"),
            "an unknown creation outcome authorized rollback"
        );
    }
}

#[test]
fn start_work_cloud_requires_positive_id_and_fence_for_rollback() {
    for (id, fence) in [(0, Some(7)), (42, None), (42, Some(0)), (42, Some(-1))] {
        let server = Server::start();
        {
            let mut claim = json!({"id":id, "session":"alice", "paths":["src"]});
            if let Some(fence) = fence {
                claim["fence"] = json!(fence);
            }
            let mut state = server.state.lock().unwrap();
            state.claim_created = Some(json!(true));
            state.claim_reused_on_post = Some(claim);
        }
        failed_start_work(&server);
        assert!(
            server
                .state
                .lock()
                .unwrap()
                .seen
                .iter()
                .all(|r| r.method != "DELETE")
        );
    }
}

#[test]
fn start_work_cloud_preserves_task_error_when_fenced_cleanup_is_refused() {
    for status in [403, 412] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.claim_created = Some(json!(true));
            state.refuse_release = Some((
                status,
                json!({"error":{"code":"conflict", "message":"owner or fence changed"}}),
            ));
        }
        let answer = failed_start_work(&server);
        assert!(
            answer.to_string().contains("task is already taken"),
            "{answer}"
        );
        let deletes = server.seen("DELETE", "/api/v1/zones/claims/1");
        assert_eq!(deletes.len(), 1);
        assert_eq!(deletes[0].body["fence"], 1);
        assert_eq!(server.state.lock().unwrap().claims.len(), 1);
    }
}

#[test]
fn start_work_cloud_seeded_acquisition_scenarios_preserve_existing_leases() {
    let mut seed = 0xC03_u64;
    for case in 0..32 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let scenario = (seed >> 32) % 4;
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.omit_claim_meta = seed & 1 != 0;
            state.echo_reused_claim_meta = true;
            match scenario {
                0 => state.claims.push(
                    json!({"id":9, "session":"alice", "paths":["src"], "fence":3, "created":true}),
                ),
                1 => {
                    state.claim_reused_on_post =
                        Some(json!({"id":42, "session":"alice", "paths":["src"], "fence":7}));
                    state.claim_created = (seed & 2 != 0).then_some(json!(false));
                }
                2 => state.claim_created = Some(json!(true)),
                _ => state.claim_created = (seed & 2 != 0).then_some(Value::Null),
            }
        }
        run_failed_start_work(&server);
        let state = server.state.lock().unwrap();
        let deletes: Vec<_> = state.seen.iter().filter(|r| r.method == "DELETE").collect();
        if scenario == 2 {
            assert_eq!(deletes.len(), 1, "case {case}, seed {seed}");
            assert!(state.claims.is_empty(), "case {case}, seed {seed}");
        } else {
            assert!(deletes.is_empty(), "case {case}, seed {seed}");
            assert_eq!(state.claims.len(), 1, "case {case}, seed {seed}");
        }
        assert_eq!(
            state
                .seen
                .iter()
                .filter(|r| r.method == "POST" && r.path == "/api/v1/zones/claims")
                .count(),
            usize::from(scenario != 0)
        );
    }
}

#[test]
fn hook_check_refuses_unknown_and_incomplete_zone_answers() {
    for paths in [
        json!([{"path":"src", "status":"unknown"}]),
        json!([]),
        json!([{"path":"src", "status":"held"}]),
        json!([{"path":"different", "status":"free"}]),
    ] {
        let server = Server::start();
        server.state.lock().unwrap().check_reply = Some(json!({"paths":paths}));
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let result = cli(
            dir.path(),
            runtime.path(),
            &["hook", "check", "--path", "src"],
        );
        assert_eq!(
            server.seen("POST", "/api/v1/zones/check").len(),
            1,
            "fixture was not reached: {result:?}"
        );
        assert!(
            !result.status.success(),
            "unchecked hook check allowed {paths}: {result:?}"
        );
    }
}

#[test]
fn hook_check_refuses_unknown_from_the_agent_socket() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let folder = runtime.path().join("lockyard");
    std::fs::create_dir(&folder).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(socket(runtime.path())).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let peer_stop = stop.clone();
    let url = server.url.clone();
    let peer = thread::spawn(move || {
        let mut operations = Vec::new();
        while !peer_stop.load(Ordering::SeqCst) {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("socket fixture: {error}"),
            };
            // Accepted socket flags differ by platform. Fixture reads are blocking with a deadline.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let operation = request["op"].as_str().unwrap().to_string();
            let reply = if operation == "ping" {
                json!({"status":{
                    "url":url, "workspace":"team", "token_id":lockyard_cloud_client::token_id("test-token"),
                    "pid":1, "view_fresh":false, "view_age_ms":null, "claims":0, "board":0,
                    "sessions":0, "outbox":0, "coordination_seq":0, "registry_seq":0
                }})
            } else {
                assert_eq!(operation, "check");
                json!({"source":"none", "checks":[{"path":"src", "status":"unknown"}]})
            };
            operations.push(operation);
            writeln!(stream, "{reply}").unwrap();
        }
        operations
    });
    let result = cli(
        dir.path(),
        runtime.path(),
        &["hook", "check", "--path", "src"],
    );
    stop.store(true, Ordering::SeqCst);
    assert_eq!(peer.join().unwrap(), ["ping", "ping", "check"]);
    assert!(
        !result.status.success(),
        "unknown agent check allowed an edit: {result:?}"
    );
    assert!(
        server.state.lock().unwrap().seen.is_empty(),
        "the socket answer must not fall back to HTTP"
    );
}

#[test]
fn the_config_selects_the_cloud_backend_and_the_token_comes_only_from_the_environment() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let claim = json_of(&cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "claim", "src", "--note", "n", "--lazy"],
    ));
    assert_eq!(claim["id"], 1);
    let sent = &server.seen("POST", "/api/v1/zones/claims")[0];
    assert_eq!(sent.body["lazy"], true);
    assert_eq!(sent.session.as_deref(), Some("alice"));
    assert!(sent.key.is_some());

    let bare = binary(dir.path(), runtime.path())
        .args(["zone", "list"])
        .env_remove("LOCKYARD_TOKEN")
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bare.stderr).contains("LOCKYARD_TOKEN"));

    let token_file = runtime.path().join("token");
    std::fs::write(&token_file, "test-token\n").unwrap();
    std::fs::set_permissions(
        &token_file,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let listed = binary(dir.path(), runtime.path())
        .args(["--json", "zone", "list"])
        .env_remove("LOCKYARD_TOKEN")
        .env("LOCKYARD_TOKEN_FILE", &token_file)
        .output()
        .unwrap();
    assert_eq!(json_of(&listed).as_array().unwrap().len(), 1);
}

#[test]
fn a_token_in_the_config_file_is_refused() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let path = dir.path().join(".lockyard/config.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{text}token = 'secret'\n")).unwrap();
    let runtime = tempfile::tempdir().unwrap();
    assert_eq!(
        cli(dir.path(), runtime.path(), &["zone", "list"])
            .status
            .code(),
        Some(1)
    );
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn refusals_map_to_exit_codes_and_kinds() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let refusal = |status: u16, details: Value| {
        let body = json!({"error": {"code": "x", "message": "refused here", "details": details}});
        server.state.lock().unwrap().refuse_claims = Some((status, body));
    };
    let held =
        json!({"conflicts": [{"path": "src", "session": "bob", "claim_id": 3, "note": "busy"}]});
    refusal(409, held);
    let conflict = cli(dir.path(), runtime.path(), &["zone", "claim", "src"]);
    assert_eq!(conflict.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("src is held by bob"));
    refusal(409, json!({"priority_of": "carol"}));
    let reserved = cli(dir.path(), runtime.path(), &["zone", "claim", "src"]);
    assert_eq!(reserved.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&reserved.stderr).contains("carol"));
    for (status, kind) in [(403, "x"), (404, "x"), (412, "x"), (503, "x")] {
        refusal(status, Value::Null);
        let refused = cli(
            dir.path(),
            runtime.path(),
            &["--json", "zone", "claim", "src"],
        );
        assert_eq!(refused.status.code(), Some(1));
        let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
        assert_eq!(error["error"]["kind"], kind);
    }
}

#[test]
fn the_new_commands_reach_their_routes() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let root = dir.path();
    let run = |args: &[&str]| {
        let result = cli(root, runtime.path(), args);
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    run(&["zone", "queue", "src", "--note", "n", "--ttl", "90"]);
    run(&["zone", "unwait", "Q-3"]);
    run(&["zone", "request", "src", "--text", "please", "--urgent"]);
    run(&["zone", "answer", "4", "--reply", "soon"]);
    run(&["zone", "handover", "5", "--to", "bob", "--fence", "2"]);
    run(&["zone", "narrow", "5", "src", "--fence", "2"]);
    run(&["zone", "add-path", "5", "docs"]);
    run(&["zone", "takeover", "5", "--reason", "gone"]);
    run(&["zone", "dirty", "report", "src", "--owner", "bob"]);
    run(&["zone", "dirty", "disown", "src"]);
    run(&["zone", "dirty", "adopt", "src", "--reason", "left"]);
    run(&["msg", "ack", "9"]);
    run(&[
        "presence",
        "beat",
        "--state",
        "api-failure",
        "--tool-running",
    ]);
    run(&["cloud", "freeze", "on", "--reason", "switch"]);
    let offered = json_of(&cli(
        root,
        runtime.path(),
        &[
            "--json", "work", "offer", "t", "--to", "bob", "--accept", "tests",
        ],
    ));
    assert_eq!(offered["status"], "offered");
    let claimed = json_of(&cli(
        root,
        runtime.path(),
        &["--json", "work", "claim", "6", "--if-version", "1"],
    ));
    assert_eq!(claimed["status"], "claimed");
    for (method, route) in [
        ("POST", "/api/v1/zones/queue"),
        ("DELETE", "/api/v1/zones/queue/3"),
        ("POST", "/api/v1/zones/requests"),
        ("POST", "/api/v1/zones/requests/4/answer"),
        ("POST", "/api/v1/zones/claims/5/handover"),
        ("POST", "/api/v1/zones/claims/5/narrow"),
        ("POST", "/api/v1/zones/claims/5/add-path"),
        ("POST", "/api/v1/zones/claims/5/takeover"),
        ("POST", "/api/v1/zones/dirty"),
        ("POST", "/api/v1/zones/dirty/disown"),
        ("POST", "/api/v1/zones/dirty/adopt"),
        ("POST", "/api/v1/bus/messages/9/ack"),
        ("POST", "/api/v1/presence"),
        ("POST", "/api/v1/admin/freeze"),
        ("POST", "/api/v1/bus/tasks"),
    ] {
        assert_eq!(server.seen(method, route).len(), 1, "{method} {route}");
    }
    let claim = &server.seen("POST", "/api/v1/bus/tasks/BT-6/claim");
    assert!(claim[0].path.ends_with("?version=1"));
    let beat = &server.seen("POST", "/api/v1/presence")[0];
    assert_eq!(beat.body["activity"]["state"], "api_failure");
}

#[test]
fn the_task_commands_read_the_registry_in_cloud_mode() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let listed = cli(dir.path(), runtime.path(), &["task", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let state = server.state.lock().unwrap();
    assert!(
        state
            .seen
            .iter()
            .any(|seen| seen.path.starts_with("/api/v1/registry/items"))
    );
}

fn hook(dir: &Path, runtime: &Path, event: &Value) -> Output {
    // No token and no agent name: a hook in cloud mode can only reach the socket.
    let mut child = binary(dir, runtime)
        .args(["hook", "claude"])
        .env_remove("LOCKYARD_AGENT")
        .env_remove("LOCKYARD_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Kills the agent process when a test ends, however it ends.
struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_agent(dir: &Path, runtime: &Path) -> Agent {
    start_agent_until(dir, runtime, true)
}

fn start_agent_until(dir: &Path, runtime: &Path, wait_for_view: bool) -> Agent {
    let child = binary(dir, runtime)
        .arg("agent")
        .env("LOCKYARD_TOKEN", "test-token")
        .spawn()
        .unwrap();
    let agent = Agent(child);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let status = cli(dir, runtime, &["--json", "agent", "status"]);
        let status = json_of(&status);
        if status["running"] == true && (!wait_for_view || status["status"]["view_fresh"] == true) {
            return agent;
        }
        assert!(Instant::now() < end, "the agent never became ready");
        thread::sleep(Duration::from_millis(20));
    }
}

fn socket(runtime: &Path) -> PathBuf {
    runtime.join("lockyard/agent.sock")
}

fn pre_edit(root: &Path) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "session_id": "me",
        "cwd": root,
        "tool_name": "Edit",
        "tool_input": {"file_path": root.join("src/a.rs")},
    })
}

#[test]
fn without_an_agent_a_hook_denies_the_edit_and_sends_nothing() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let result = hook(dir.path(), runtime.path(), &pre_edit(dir.path()));
    assert!(result.status.success());
    let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        answer["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("needs a running agent")
    );
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn through_the_agent_a_hook_denies_a_held_path_from_memory() {
    let server = Server::start();
    server
        .state
        .lock()
        .unwrap()
        .claims
        .push(json!({"id": 1, "session": "bob", "paths": ["src"], "note": "busy"}));
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let checks_before = server.seen("POST", "/api/v1/zones/check").len();
    let result = hook(dir.path(), runtime.path(), &pre_edit(dir.path()));
    let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        answer["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("bob")
    );
    assert_eq!(
        server.seen("POST", "/api/v1/zones/check").len(),
        checks_before
    );

    let cli_check = cli(dir.path(), runtime.path(), &["zone", "check", "src/a.rs"]);
    assert_eq!(cli_check.status.code(), Some(3));
}

#[test]
fn through_the_agent_a_hook_delivers_mail_in_two_phases() {
    let server = Server::start();
    server
        .state
        .lock()
        .unwrap()
        .inbox
        .push(json!({"id": 7, "from_session": "bob", "to": "me", "body": "look at src"}));
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let event =
        json!({"hook_event_name": "UserPromptSubmit", "session_id": "me", "cwd": dir.path()});
    // The first hook registers the session; the agent reserves its mail in the background.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let result = hook(dir.path(), runtime.path(), &event);
        if String::from_utf8_lossy(&result.stdout).contains("look at src") {
            break;
        }
        assert!(
            Instant::now() < end,
            "the mail never reached a hook; last hook: {result:?}; server: {:?}",
            server.state.lock().unwrap().seen
        );
        thread::sleep(Duration::from_millis(20));
    }
    let claimed = server.seen("POST", "/api/v1/bus/inbox/claim");
    assert_eq!(claimed[0].body, json!({"ids": [7], "lease_seconds": 60}));
    let end = Instant::now() + Duration::from_secs(5);
    while server.seen("POST", "/api/v1/bus/inbox/seen").is_empty() {
        assert!(Instant::now() < end, "seen never arrived");
        thread::sleep(Duration::from_millis(10));
    }
    let seen = server.seen("POST", "/api/v1/bus/inbox/seen");
    assert_eq!(seen[0].body, json!({"ids": [7]}));
    assert!(seen[0].key.is_some());
    assert_eq!(seen[0].session.as_deref(), Some("me"));
}

#[test]
fn the_cli_goes_through_a_running_agent_and_needs_no_token() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let sent = binary(dir.path(), runtime.path())
        .args(["--json", "msg", "send", "bob", "hello"])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .output()
        .unwrap();
    assert_eq!(json_of(&sent)["id"], 44);
    assert_eq!(
        server.seen("POST", "/api/v1/bus/messages")[0]
            .session
            .as_deref(),
        Some("alice")
    );
}

#[test]
fn the_socket_and_its_folder_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let path = socket(runtime.path());
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
}

#[test]
fn install_refuses_a_bare_token_and_writes_a_unit_naming_the_file() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let home = tempfile::tempdir().unwrap();
    let bare = binary(dir.path(), home.path())
        .args(["agent", "install", "--no-start"])
        .env("HOME", home.path())
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bare.stderr).contains("LOCKYARD_TOKEN_FILE"));

    let token = home.path().join("token");
    std::fs::write(&token, "test-token").unwrap();
    let installed = binary(dir.path(), home.path())
        .args(["--json", "agent", "install", "--no-start"])
        .env("HOME", home.path())
        .env("LOCKYARD_TOKEN_FILE", &token)
        .output()
        .unwrap();
    let unit = json_of(&installed)["unit"].as_str().unwrap().to_string();
    let text = std::fs::read_to_string(&unit).unwrap();
    assert!(text.contains("LOCKYARD_TOKEN_FILE"));
    assert!(!text.contains("test-token"));

    let status = binary(dir.path(), home.path())
        .args(["--json", "agent", "status"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    let status = json_of(&status);
    assert_eq!(
        (status["installed"].as_bool(), status["running"].as_bool()),
        (Some(true), Some(false))
    );

    let removed = binary(dir.path(), home.path())
        .args(["agent", "uninstall", "--no-start"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(removed.status.success());
    assert!(!Path::new(&unit).exists());
}

fn required_catalog_fixture(server: &Server, dir: &Path, runtime: &Path) {
    use lockyard_cloud_client::{WorkspaceKey, catalog::seal_catalog};
    let workspace = "00000000-0000-0000-0000-000000000001";
    let key = WorkspaceKey::from_entropy([47; 32]);
    let key_dir = runtime.join("config/lockyard/keys");
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&key_dir)
        .unwrap();
    key.copy_to_private(&key_dir.join(format!("{workspace}.key")))
        .unwrap();
    let plaintext = lockyard_core::catalog::ZoneCatalogV1::from_json(
        r#"{"version":1,"zones":{"code":["src","tests"]},"groups":{"all":["code"]}}"#,
    )
    .unwrap();
    let wire = seal_catalog(&key, workspace, "api", 0, true, &plaintext).unwrap();
    let mut state = server.state.lock().unwrap();
    state.catalog = Some(serde_json::to_value(wire.catalog).unwrap());
    state.encryption_key_id = Some(key.key_id());
    drop(state);
    std::fs::write(
        dir.join(".lockyard/config.toml"),
        format!(
            "mode = 'cloud'\nurl = '{}'\nworkspace = 'team'\nrepository = 'api'\n",
            server.url
        ),
    )
    .unwrap();
}

#[test]
fn required_cli_zone_claim_uses_typed_encrypted_catalog() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let result = cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "claim", "--zone", "all"],
    );
    let answer = json_of(&result);
    assert_eq!(answer["paths"], json!(["src", "tests"]));
    let writes = server.seen("POST", "/api/v1/zones/claims");
    assert_eq!(writes.len(), 1);
    assert_eq!(
        writes[0].body["paths"],
        json!([
            ".lockyard-repository/api/src",
            ".lockyard-repository/api/tests"
        ])
    );
    assert!(writes[0].body.get("zones").is_none());
    assert!(writes[0].body.get("zone").is_none());
    server.state.lock().unwrap().catalog.as_mut().unwrap()["case_insensitive_paths"] = json!(false);
    let refused = cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "claim", "--zone", "code"],
    );
    assert!(!refused.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&refused.stderr).unwrap()["error"]["code"],
        "catalog_authentication_failed"
    );
    assert_eq!(server.seen("POST", "/api/v1/zones/claims").len(), 1);
}

#[test]
fn required_mcp_zones_share_verified_catalog_expander() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let mut child = binary(dir.path(), runtime.path())
        .args(["mcp", "--tools", "full"])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    for (id, zones) in [(1, json!(["code"])), (2, json!(["missing"]))] {
        writeln!(input,"{}",json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"zone_claim","arguments":{"zones":zones}}})).unwrap();
    }
    drop(input);
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let answers: Vec<Value> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_ne!(answers[0]["result"]["isError"], true, "{}", answers[0]);
    assert_eq!(
        answers[0]["result"]["structuredContent"]["paths"],
        json!(["src", "tests"])
    );
    assert_eq!(
        answers[1]["result"]["structuredContent"]["code"],
        "zone_unknown"
    );
    assert_eq!(server.seen("POST", "/api/v1/zones/claims").len(), 1);
}

#[test]
fn required_agent_named_catalog_preserves_strict_expansion_errors() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let _agent = start_agent(dir.path(), runtime.path());
    let refused = cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "claim", "--zone", "missing"],
    );
    assert!(!refused.status.success());
    let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(error["error"]["code"], "zone_unknown", "{error}");
    assert!(server.seen("POST", "/api/v1/zones/claims").is_empty());
}

#[test]
fn required_cli_catalog_put_encrypts_locally_and_preserves_publisher_denial() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let path = dir.path().join("catalog.json");
    std::fs::write(
        &path,
        r#"{"version":1,"zones":{"CATALOG-CONTENT-CANARY":["src"]},"groups":{}}"#,
    )
    .unwrap();
    let key = lockyard_cloud_client::ulid();
    let result = cli(
        dir.path(),
        runtime.path(),
        &[
            "--json",
            "cloud",
            "catalog-put",
            path.to_str().unwrap(),
            "--expected-revision",
            "1",
            "--key",
            &key,
        ],
    );
    let answer = json_of(&result);
    assert_eq!(answer["stored"], true);
    assert_eq!(answer["revision"], 2);
    let writes = server.seen("POST", "/api/v1/zones/catalog");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].key.as_deref(), Some(key.as_str()));
    assert_eq!(writes[0].body["expected_revision"], 1);
    assert!(
        writes[0].body["catalog"]["content"]
            .as_str()
            .unwrap()
            .starts_with("lyenc1.")
    );
    assert!(
        !writes[0]
            .body
            .to_string()
            .contains("CATALOG-CONTENT-CANARY")
    );
    let stored = server.state.lock().unwrap().catalog.clone();
    server.state.lock().unwrap().refuse_catalog_put = true;
    let key = lockyard_cloud_client::ulid();
    let refused = cli(
        dir.path(),
        runtime.path(),
        &[
            "--json",
            "cloud",
            "catalog-put",
            path.to_str().unwrap(),
            "--expected-revision",
            "2",
            "--key",
            &key,
        ],
    );
    assert!(!refused.status.success());
    let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(error["error"]["code"], "forbidden");
    assert_eq!(server.state.lock().unwrap().catalog, stored);
}

#[test]
fn msg_inbox_piped_does_not_mark_seen_unless_mark_read() {
    let server = Server::start();
    server.state.lock().unwrap().inbox = vec![json!({
        "id": 7,
        "from_session": "bob",
        "to": "alice",
        "body": "pipe me",
        "kind": "ask",
        "needs": "none",
        "created_at": 0
    })];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let piped = cli(dir.path(), runtime.path(), &["msg", "inbox"]);
    assert!(piped.status.success(), "{piped:?}");
    assert!(server.writes_to("/bus/inbox/seen").is_empty());
    let marked = cli(dir.path(), runtime.path(), &["msg", "inbox", "--mark-read"]);
    assert!(marked.status.success(), "{marked:?}");
    assert_eq!(server.writes_to("/bus/inbox/seen").len(), 1);
}

#[test]
fn mcp_update_with_a_note_does_not_mark_inbox_seen() {
    let server = Server::start();
    server.state.lock().unwrap().inbox = vec![json!({
        "id": 9,
        "from_session": "bob",
        "to": "alice",
        "body": "still open",
        "kind": "ask",
        "needs": "none",
        "created_at": 0
    })];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[("update", json!({"to": "bob", "body": "note only"}))],
    );
    assert_eq!(answers[0]["isError"], false, "{}", answers[0]);
    assert!(server.writes_to("/bus/inbox/seen").is_empty());
    assert_eq!(
        server.seen("POST", "/api/v1/bus/messages").len(),
        1,
        "the note must still be sent"
    );
}

#[test]
fn status_shows_open_mail_for_a_seen_unanswered_ask_until_reply() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.inbox = vec![json!({
            "id": 11,
            "from_session": "bob",
            "to": "alice",
            "body": "please claim src",
            "kind": "ask",
            "needs": "none",
            "created_at": 0
        })];
        state.seen_ids = vec![11];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(status["unread"], 0, "{status}");
    assert_eq!(status["open_mail"].as_array().unwrap().len(), 1, "{status}");
    assert_eq!(status["open_mail"][0]["id"], 11);
    let open = json_of(&cli(dir.path(), runtime.path(), &["--json", "msg", "open"]));
    assert_eq!(open.as_array().unwrap().len(), 1, "{open}");
    let replied = cli(
        dir.path(),
        runtime.path(),
        &["msg", "reply", "11", "claimed"],
    );
    assert!(replied.status.success(), "{replied:?}");
    let after = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(after["open_mail"].as_array().unwrap().len(), 0, "{after}");
    let open_after = json_of(&cli(dir.path(), runtime.path(), &["--json", "msg", "open"]));
    assert_eq!(open_after.as_array().unwrap().len(), 0, "{open_after}");
}

#[test]
fn zone_renew_reports_open_mail_count() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.claims = vec![json!({
            "id": 5,
            "session": "alice",
            "paths": ["src"],
            "fence": 2,
            "expires_at": "2099-01-01T00:00:00Z",
            "note": "n"
        })];
        state.inbox = vec![json!({
            "id": 3,
            "from_session": "bob",
            "to": "alice",
            "body": "renew me",
            "kind": "ask",
            "needs": "reply",
            "created_at": 0
        })];
        state.seen_ids = vec![3];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let renewed = json_of(&cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "renew", "5", "--fence", "2"],
    ));
    assert_eq!(renewed["open_mail_count"], 1, "{renewed}");
    let mcp = mcp_calls(
        dir.path(),
        runtime.path(),
        "full",
        &[("zone_renew", json!({"id": 5, "fence": 2}))],
    );
    assert_eq!(mcp[0]["isError"], false, "{}", mcp[0]);
    assert_eq!(mcp[0]["structuredContent"]["open_mail_count"], 1);
}

#[test]
fn status_omits_open_mail_when_all_inbox_hangs_after_mandatory_reads() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.inbox = vec![json!({
            "id": 11,
            "from_session": "bob",
            "to": "alice",
            "body": "please claim src",
            "kind": "ask",
            "needs": "none",
            "created_at": 0
        })];
        state.seen_ids = vec![11];
        state.latency.stall_inbox_all = true;
        state.latency.stall = Duration::from_secs(10);
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    let elapsed = started.elapsed();
    assert!(status.get("claims").is_some(), "{status}");
    assert!(
        status.get("open_mail").is_none(),
        "open_mail must be omitted on timeout: {status}"
    );
    assert_eq!(
        status["freshness"]["sections"]["open_mail"]["available"], false,
        "{status}"
    );
    assert!(
        elapsed <= Duration::from_secs(6),
        "status took {:?}, longer than the overall deadline",
        elapsed
    );
}

#[test]
fn status_closes_open_mail_on_ack_not_on_cloud_sent() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.inbox = vec![json!({
            "id": 11,
            "from_session": "bob",
            "to": "alice",
            "body": "please claim src",
            "kind": "ask",
            "needs": "none",
            "created_at": 0
        })];
        state.seen_ids = vec![11];
        // Pretend we replied: sent has no in_reply_to (server shape), ask still open.
        state.sent = vec![json!({
            "id": 1011,
            "from_session": "alice",
            "to": "bob",
            "body": "claimed"
        })];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(status["open_mail"].as_array().unwrap().len(), 1, "{status}");
    {
        let mut state = server.state.lock().unwrap();
        for message in &mut state.inbox {
            if message.get("id").and_then(Value::as_i64) == Some(11) {
                message["status"] = json!("ack");
            }
        }
    }
    let after = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    assert_eq!(after["open_mail"].as_array().unwrap().len(), 0, "{after}");
}

#[test]
fn mcp_status_returns_open_mail() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.inbox = vec![json!({
            "id": 11,
            "from_session": "bob",
            "to": "alice",
            "body": "please claim src",
            "kind": "ask",
            "needs": "none",
            "created_at": 0
        })];
        state.seen_ids = vec![11];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let mcp = mcp_calls(dir.path(), runtime.path(), "full", &[("status", json!({}))]);
    assert_eq!(mcp[0]["isError"], false, "{}", mcp[0]);
    let content = &mcp[0]["structuredContent"];
    assert_eq!(
        content["open_mail"].as_array().unwrap().len(),
        1,
        "{content}"
    );
}

#[test]
fn open_mail_escapes_controls_in_status() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        let mut ask = json!({
            "id": 11,
            "from_session": "bob",
            "to": "alice",
            "body": "please",
            "kind": "ask",
            "needs": "none",
            "created_at": 0
        });
        ask["from_session"] = Value::String("bo\nb".into());
        ask["body"] = Value::String("line\u{202e}hidden".into());
        state.inbox = vec![ask];
        state.seen_ids = vec![11];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    let mail = &status["open_mail"][0];
    assert_eq!(mail["from"], "bo\\nb", "{mail}");
    let subject = mail["subject"].as_str().unwrap();
    assert!(subject.contains("\\u{202e}"), "{mail}");
}
