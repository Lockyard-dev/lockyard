// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives the real binary in cloud mode against a fake server, with and without the agent process.

#![cfg(unix)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
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
    product: Option<String>,
    token: Option<String>,
}

#[derive(Default)]
struct State {
    api_offline: bool,
    notification_owners: std::collections::HashMap<String, String>,
    notification_events: Vec<Value>,
    notification_seed_race: Option<String>,
    survey_require_claude_accept: bool,
    survey_claude_session: Option<String>,
    survey_default_role: Option<String>,
    survey_bound_session: Option<String>,
    survey_agent_bound_session: Option<String>,
    coordination_event_sessions: std::collections::HashSet<String>,
    survey_handled_failure: bool,
    survey_release_failure_id: Option<i64>,
    survey_handled: bool,
    survey_soft_zones: bool,
    survey_uncertain_create: bool,
    survey_echo_client_key: bool,
    survey_lose_create_replies: bool,
    lose_token_create_reply: bool,
    require_encryption_after_mail: Option<String>,
    hold_next_mail_response: Option<std::sync::mpsc::Receiver<()>>,
    mail_repair: Option<MailRepair>,
    tokens_created: usize,
    survey_lost: Vec<Value>,
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
    refuse_add_path: Option<String>,
    queued_add_path: Option<String>,
    deferred_add_paths: Vec<(i64, String)>,
    grant_before_queue_cancel: bool,
    ignore_renew_hold: bool,
    refuse_release: Option<(u16, Value)>,
    refuse_registry_claim: bool,
    registry_submit_reply: Option<Value>,
    refuse_registry_accept: Option<(u16, Value)>,
    refuse_registry_create: Option<(u16, Value)>,
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

struct MailRepair {
    cursor: PathBuf,
    deliveries: std::collections::HashMap<String, Value>,
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

// Bound concurrent subprocess-heavy fixtures, rather than changing product deadlines.
// Each fixture still exercises its own concurrent CLI/MCP/daemon requests.
static FIXTURES: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());
struct FixturePermit;
impl FixturePermit {
    fn acquire() -> Self {
        let (count, ready) = &FIXTURES;
        let mut active = count.lock().unwrap();
        while *active >= 1 {
            active = ready.wait(active).unwrap();
        }
        *active += 1;
        Self
    }
}
impl Drop for FixturePermit {
    fn drop(&mut self) {
        *FIXTURES.0.lock().unwrap() -= 1;
        FIXTURES.1.notify_one();
    }
}

#[derive(Clone)]
struct Server {
    _permit: Arc<FixturePermit>,
    _lifecycle: Arc<ServerLifecycle>,
    url: String,
    state: Arc<Mutex<State>>,
}

struct ServerLifecycle {
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Drop for ServerLifecycle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.get_mut().unwrap().take() {
            worker.join().unwrap();
        }
    }
}

impl Server {
    fn start() -> Self {
        let permit = Arc::new(FixturePermit::acquire());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let shared = Arc::clone(&shared);
                        thread::spawn(move || serve(stream, &shared));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("fixture listener failed: {error}"),
                }
            }
        });
        Self {
            url,
            state,
            _permit: permit,
            _lifecycle: Arc::new(ServerLifecycle {
                stop,
                worker: Mutex::new(Some(worker)),
            }),
        }
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
        let (mut length, mut key, mut session, mut token, mut repository, mut product) =
            (0, None, None, None, None, None);
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
                    "x-lockyard-agent-product" => product = Some(value.to_string()),
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
        let (status, answer, capabilities, date, hold_mail) = {
            let mut state = state.lock().unwrap();
            if route == "/api/v1/events"
                && let Some(session) = &session
            {
                state.coordination_event_sessions.insert(session.clone());
            }
            if !route.ends_with("/events") || !state.notification_owners.is_empty() {
                let record = Seen {
                    method: method.clone(),
                    path: path.clone(),
                    body: body.clone(),
                    key: key.clone(),
                    session: session.clone(),
                    product: product.clone(),
                    token: token.clone(),
                };
                state.seen.push(record);
            }
            let (status, answer) = if state.api_offline {
                (
                    503,
                    json!({"error":{"code":"unavailable","message":"offline fixture"}}),
                )
            } else if !matches!(
                token.as_deref(),
                Some("Bearer test-token" | "Bearer claude-test-token")
            ) {
                (
                    401,
                    json!({"error": {"code": "unauthorized", "message": "bad token"}}),
                )
            } else if session.as_ref().is_some_and(|session| {
                state
                    .notification_owners
                    .get(session)
                    .is_some_and(|owner| Some(owner) != token.as_ref())
            }) || session.is_some()
                && (state.survey_bound_session.as_ref() == session.as_ref()
                    || (state.survey_agent_bound_session.as_ref() == session.as_ref()
                        && token.as_deref() == Some("Bearer claude-test-token")))
            {
                (
                    403,
                    json!({"error":{"code":"session_name_bound","message":"bound elsewhere"}}),
                )
            } else if method == "GET" && route == "/api/v1/registry/actor" {
                let role = state.survey_default_role.as_deref().unwrap_or("agent");
                let is_owner = role == "owner";
                let claude =
                    role == "agent" && token.as_deref() == Some("Bearer claude-test-token");
                (
                    200,
                    json!({
                        "identity":format!("token:{:032x}:{}", if claude {2} else {1}, session.as_deref().unwrap_or("alice")),
                        "role":role,
                        "is_owner":is_owner,
                        "can_accept_review":matches!(role, "lead" | "owner") || claude,
                        "can_relay_owner":is_owner,
                        "workspace_id":"00000000-0000-0000-0000-000000000001",
                    }),
                )
            } else if state.survey_require_claude_accept
                && route.ends_with("/transition")
                && (session.as_deref()
                    != Some(
                        state
                            .survey_claude_session
                            .as_deref()
                            .unwrap_or("survey-session"),
                    )
                    || token.as_deref() != Some("Bearer claude-test-token"))
            {
                (
                    409,
                    json!({"error":{"code":"claude_key_required","message":"Claude key required"}}),
                )
            } else if method == "POST"
                && route == "/api/v1/bus/messages"
                && let Some(repair) = state.mail_repair.as_mut()
            {
                let key = key.expect("outbox mail uses an idempotency key");
                let id = 44 + repair.deliveries.len();
                let first_mail = repair.deliveries.is_empty();
                let (receipt, just_committed) = match repair.deliveries.entry(key) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        (entry.into_mut(), false)
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => (
                        entry.insert(json!({"id":id,"from_session":"alice","to":body["to"],"body":body["body"]})),
                        true,
                    ),
                };
                // Lose the first receipt after commit. Withhold it from daemon retries
                // until doctor has reserved the operation and recorded its repair cursor.
                if (first_mail && just_committed) || (!just_committed && !repair.cursor.is_file()) {
                    return;
                }
                (200, receipt.clone())
            } else {
                route_reply(&mut state, &method, &path, &body, session.as_deref())
            };
            if state.lose_token_create_reply
                && method == "POST"
                && route == "/api/v1/registry/tokens"
            {
                return;
            }
            let date = if let Some(key_id) = &state.require_encryption_after_mail {
                if method == "POST"
                    && route == "/api/v1/bus/messages"
                    && state.encryption_key_id.is_none()
                {
                    state.encryption_key_id = Some(key_id.clone());
                    return; // Drop the receipt only after the policy changes.
                }
                "Date: Thu, 19 Nov 2026 10:21:00 GMT\r\n"
            } else if state.mail_repair.is_some() {
                "Date: Thu, 19 Nov 2026 10:21:00 GMT\r\n"
            } else {
                ""
            };
            let capabilities = if !state.notification_owners.is_empty() {
                "Lockyard-Capabilities: mail_push_v1\r\n"
            } else if state.registry_assignee_session
                && ((route.starts_with("/api/v1/registry/")
                    && !state.registry_assignee_header_hidden)
                    || (route == "/api/v1/protocol"
                        && !state.registry_assignee_protocol_header_hidden))
            {
                "Lockyard-Capabilities: registry_assignee_session_v1\r\n"
            } else {
                ""
            };
            let hold_mail = if method == "POST" && route == "/api/v1/bus/messages" {
                state.hold_next_mail_response.take()
            } else {
                None
            };
            (status, answer, capabilities, date, hold_mail)
        };
        if let Some(release) = hold_mail {
            let _ = release.recv_timeout(Duration::from_secs(10));
        }
        let text = if answer == json!("response lost after commit") {
            "{".into()
        } else {
            answer.to_string()
        };
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
            "HTTP/1.1 {status} X\r\nLockyard-Protocol: 2\r\n{date}{capabilities}X-Lockyard-Repository: {}\r\nCache-Control: no-store\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{text}",
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
        ("POST", "/api/v1/registry/items/D-1/evidence")
            if state.registry_submit_reply.is_some() =>
        {
            (200, json!({"id":"D-1","status":"active","version":2}))
        }
        ("POST", "/api/v1/registry/items/D-1/transition")
            if body["to"] == "review" && state.registry_submit_reply.is_some() =>
        {
            (200, state.registry_submit_reply.clone().unwrap())
        }
        ("POST", "/api/v1/registry/items/batch-transition") => (
            200,
            json!({"results":[{"id":"D-1","changed":true,"item":{"id":"D-1","status":"done"}}]}),
        ),
        ("POST", "/api/v1/registry/items/D-1/transition")
            if body["to"] == "done" && state.refuse_registry_accept.is_some() =>
        {
            state.refuse_registry_accept.clone().unwrap()
        }
        ("POST", "/api/v1/registry/items/D-1/transition") if state.survey_require_claude_accept => {
            (
                200,
                json!({"id":"D-1","title":"reviewed work","status":"done","version":2}),
            )
        }
        ("POST", "/api/v1/registry/tokens") => {
            state.tokens_created += 1;
            (
                200,
                json!({"raw":"new-secret-key","token":{"id":"new-id","role":body["role"],"name":body["name"]}}),
            )
        }
        ("POST", _)
            if route.starts_with("/api/v1/admin/sessions/") && route.ends_with("/release") =>
        {
            state.survey_bound_session = None;
            (200, json!({"released":true}))
        }
        ("GET", "/api/v1/presence") if state.survey_default_role.is_some() => (
            200,
            json!({"sessions":[{"session":session,"role":state.survey_default_role}]}),
        ),
        ("GET", "/api/v1/presence") if !state.notification_owners.is_empty() => {
            (200, json!({"sessions":[]}))
        }

        ("GET", "/api/v1/protocol") => {
            let mut capabilities = vec!["zone_catalog_v1", "drain_v1"];
            if !state.notification_owners.is_empty() {
                capabilities.push("mail_push_v1");
            }
            if state.survey_soft_zones {
                capabilities.push("soft_zones_v1");
            }
            if state.survey_handled {
                capabilities.push("mail_handled_v1");
            }
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
            let mut claim = json!({"id": id, "session": "alice", "paths": body["paths"], "meta": body["meta"], "fence": 1, "expires_at": HOLD_EXPIRES_AT});
            if let Some(mode) = body.get("mode") {
                claim["mode"] = mode.clone();
            }
            if state.survey_soft_zones {
                claim["mode"] = body.get("mode").cloned().unwrap_or_else(|| json!("shared"));
                claim["held"] = json!(false);
            }
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
        ("POST", _)
            if route.starts_with("/api/v1/zones/claims/")
                && (route.ends_with("/handover") || route.ends_with("/accept"))
                && state.claims.iter().any(|claim| {
                    route
                        .split('/')
                        .nth(5)
                        .and_then(|id| id.parse::<i64>().ok())
                        == claim["id"].as_i64()
                }) =>
        {
            let id: i64 = route.split('/').nth(5).unwrap().parse().unwrap();
            let claim = state
                .claims
                .iter_mut()
                .find(|claim| claim["id"] == id)
                .unwrap();
            if route.ends_with("/handover") {
                claim["handover_to"] = body["to"].clone();
            } else {
                assert_eq!(claim["handover_to"].as_str(), session);
                claim["session"] = json!(session);
                claim.as_object_mut().unwrap().remove("handover_to");
                claim["fence"] = json!(claim["fence"].as_i64().unwrap() + 1);
            }
            // Production handover keeps the exact original meta bytes.
            (200, claim.clone())
        }
        ("GET", "/api/v1/zones/claims") => state
            .refuse_claims_get_once
            .take()
            .or_else(|| state.refuse_claims_get.clone())
            .unwrap_or_else(|| {
                (200, {
                    let claims: Vec<_> = state
                        .claims
                        .iter()
                        .filter(|claim| {
                            query_value(path, "session")
                                .is_none_or(|session| claim["session"] == session)
                        })
                        .cloned()
                        .collect();
                    if state.encryption_key_id.is_some() {
                        json!(claims)
                    } else {
                        json!({"claims":claims})
                    }
                })
            }),
        ("POST", _)
            if route.starts_with("/api/v1/zones/claims/")
                && (route.ends_with("/add-path") || route.ends_with("/narrow")) =>
        {
            if route.ends_with("/add-path")
                && state.queued_add_path.is_some()
                && body["path"].as_str() == state.queued_add_path.as_deref()
            {
                let id = route.rsplit('/').nth(1).unwrap().parse().unwrap();
                state
                    .deferred_add_paths
                    .push((id, body["path"].as_str().unwrap().into()));
                return (200, json!({"queued":true,"priority_of":900,"conflicts":[]}));
            }
            if route.ends_with("/add-path")
                && body["path"].as_str() == state.refuse_add_path.as_deref()
                && state.refuse_add_path.is_some()
            {
                return (
                    409,
                    json!({"error":{"code":"conflict","message":"fixture path held"}}),
                );
            }
            let id = route.rsplit('/').nth(1).unwrap().parse::<i64>().unwrap();
            let Some(claim) = state.claims.iter_mut().find(|claim| claim["id"] == id) else {
                return (200, json!({"id":id,"session":"alice","paths":[],"fence":2}));
            };
            if route.ends_with("/narrow") {
                if let Some(except) = body.get("except") {
                    claim["excluded_paths"] = except.clone();
                } else {
                    claim["paths"] = body["paths"].clone();
                }
            } else {
                claim["paths"]
                    .as_array_mut()
                    .unwrap()
                    .push(body["path"].clone());
            }
            claim["fence"] = json!(claim["fence"].as_i64().unwrap_or(1) + 1);
            (200, claim.clone())
        }
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
            if state.survey_release_failure_id == Some(id) {
                return (
                    403,
                    json!({"error":{"code":"forbidden","message":"owner changed"}}),
                );
            }
            state.claims.retain(|claim| {
                claim["id"] != id
                    || (body.get("fence").is_some_and(|fence| !fence.is_null())
                        && claim["fence"] != body["fence"])
            });
            (200, json!({"released":1}))
        }
        ("GET", "/api/v1/presence") => (
            200,
            if state.encryption_key_id.is_some() {
                json!([])
            } else {
                json!({"sessions":[]})
            },
        ),
        ("POST", "/api/v1/presence") if state.encryption_key_id.is_some() => {
            (200, json!({"session":session.unwrap_or("alice")}))
        }
        ("GET", "/api/v1/registry/areas") if !state.registry_areas.is_empty() => {
            (200, json!({"areas": state.registry_areas}))
        }
        ("GET", "/api/v1/registry/items" | "/api/v1/registry/ready") => {
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
            let client_key = query_value(path, "client_key");
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
                    client_key
                        .as_deref()
                        .is_none_or(|key| item["client_key"].as_str() == Some(key))
                })
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
        ("GET", "/api/v1/zones/lost") => (200, json!({"lost":state.survey_lost})),
        ("POST", "/api/v1/bus/inbox/handled") if state.survey_handled => {
            if state.survey_handled_failure {
                return (
                    403,
                    json!({"error":{"code":"forbidden","message":"handling refused"}}),
                );
            }
            let ids = body["ids"].as_array().unwrap();
            for message in &mut state.inbox {
                if ids.contains(&message["id"]) {
                    message["status"] = json!("ack");
                }
            }
            for id in ids.iter().filter_map(Value::as_i64) {
                if !state.seen_ids.contains(&id) {
                    state.seen_ids.push(id);
                }
            }
            (200, json!({"handled":ids.len()}))
        }
        ("POST", "/api/v1/registry/items") if state.refuse_registry_create.is_some() => {
            state.refuse_registry_create.clone().unwrap()
        }
        ("POST", "/api/v1/registry/items") if state.survey_uncertain_create => {
            if state.survey_echo_client_key
                && let Some(task) = state
                    .registry_items
                    .iter()
                    .find(|task| task["client_key"] == body["client_key"])
            {
                return if state.survey_lose_create_replies {
                    (200, json!("response lost after commit"))
                } else {
                    (200, task.clone())
                };
            }
            let mut task =
                json!({"id":"FE-77","title":body["title"],"status":"ready","author":"alice"});
            if state.survey_echo_client_key {
                task["client_key"] = body["client_key"].clone();
            }
            state.registry_items.push(task);
            (200, json!("response lost after commit"))
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
        ("GET", _) if route.starts_with("/api/v1/registry/items/") => {
            let id = route.rsplit('/').next().unwrap();
            state
                .registry_items
                .iter()
                .find(|item| item["id"] == id)
                .cloned()
                .map(|item| (200, item))
                .unwrap_or((
                    404,
                    json!({"error":{"code":"not_found","message":"task missing"}}),
                ))
        }
        ("POST", _) if route.starts_with("/api/v1/registry/items/") && route.ends_with("/plan") => {
            let id = route.rsplit('/').nth(1).unwrap();
            let mut item = state
                .registry_items
                .iter()
                .find(|item| item["id"] == id)
                .cloned()
                .unwrap();
            item.as_object_mut()
                .unwrap()
                .extend(body.as_object().unwrap().clone());
            (200, item)
        }
        ("DELETE", "/api/v1/zones/queue/900") => {
            if state.grant_before_queue_cancel {
                for (id, path) in std::mem::take(&mut state.deferred_add_paths) {
                    if let Some(claim) = state.claims.iter_mut().find(|claim| claim["id"] == id) {
                        claim["paths"].as_array_mut().unwrap().push(json!(path));
                        claim["fence"] = json!(claim["fence"].as_i64().unwrap() + 1);
                    }
                }
                (
                    404,
                    json!({"error":{"code":"not_found","message":"queue already granted"}}),
                )
            } else {
                state.deferred_add_paths.clear();
                (200, json!({"id":900,"deleted":true}))
            }
        }
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
                    state.notification_owners.is_empty()
                        || message["to"].as_str() == session
                        || message["to"] == "*"
                })
                .filter(|message| {
                    let seen = message["id"]
                        .as_i64()
                        .is_some_and(|id| state.seen_ids.contains(&id));
                    // 2ca693e retains seen, unhandled questions before applying limit.
                    all || !seen || (message["needs"] == "reply" && message["status"] != "ack")
                })
                .cloned()
                .map(|mut message| {
                    if message["id"]
                        .as_i64()
                        .is_some_and(|id| state.seen_ids.contains(&id))
                    {
                        message["reader_state"] = json!("seen");
                        message["seen_at"] = json!(123);
                    }
                    message
                })
                .collect();
            let skipped = messages.len().saturating_sub(50);
            let limit = query_value(path, "limit")
                .and_then(|limit| limit.parse::<usize>().ok())
                .unwrap_or(50)
                .clamp(1, 50);
            let messages: Vec<_> = messages.into_iter().skip(skipped).take(limit).collect();
            if state.notification_seed_race.as_deref() == session && session.is_some() {
                let recipient = state.notification_seed_race.take().unwrap();
                // Another reader saw the arrival after this snapshot was constructed.
                state.seen_ids.push(88);
                state.notification_events.push(
                    json!({"seq":88,"type":"bus.message","session":recipient,
                    "payload":{"id":88,"thread_id":88,"from_session":"bob","to":recipient,
                    "role":"recipient","kind":"info","needs":"none","body":"arrived during seed"}}),
                );
            }
            (200, json!({"messages": messages, "skipped": skipped}))
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
        _ if route == "/api/v1/events" && !state.notification_owners.is_empty() => {
            if query_value(path, "sessions").is_some() {
                // Explicitly exercise the daemon's supported JSON long-poll fallback.
                return (
                    406,
                    json!({"error":{"code":"not_acceptable","message":"use JSON polling"}}),
                );
            }
            let after = query_value(path, "after")
                .and_then(|n| n.parse::<i64>().ok())
                .unwrap_or(0);
            let recipient = query_value(path, "session");
            let events: Vec<_> = state
                .notification_events
                .iter()
                .filter(|event| {
                    event["seq"].as_i64().unwrap() > after
                        && event["session"].as_str() == recipient.as_deref()
                })
                .cloned()
                .collect();
            (200, json!(events))
        }
        _ if route.ends_with("/events") => (200, json!([])),
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
    let config = std::fs::read_to_string(
        lockyard_core::paths::find_root(dir)
            .unwrap_or_else(|| dir.to_path_buf())
            .join(".lockyard/config.toml"),
    )
    .unwrap_or_default();
    let url = config
        .lines()
        .find_map(|line| line.strip_prefix("url = '")?.strip_suffix("'"))
        .unwrap_or_default();
    // These subprocesses simulate CLI and MCP hosts independently from the test runner.
    for (name, _) in std::env::vars_os() {
        let name_str = name.to_string_lossy();
        if name_str.starts_with("CODEX_") || name_str.starts_with("CURSOR_") {
            command.env_remove(name);
        }
    }
    command
        .current_dir(dir)
        .env("LOCKYARD_URL", url)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", runtime.join("state"))
        .env("XDG_CONFIG_HOME", runtime.join("config"))
        .env_remove("LOCKYARD_PARENT_CLAIM")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_CLAUDE_MCP")
        .env_remove("LOCKYARD_STATUS_DEADLINE_MS")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .env_remove("LOCKYARD_CLAUDE_TOKEN_FILE");
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

#[test]
fn registry_submit_reports_warnings_in_cli_and_mcp() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let warnings = json!(["check the dev branch", "check the repository"]);
    {
        let mut state = server.state.lock().unwrap();
        state.registry_items =
            vec![json!({"id":"D-1","status":"active","target":"ci_passed","version":1})];
        state.registry_submit_reply =
            Some(json!({"id":"D-1","status":"review","version":3,"warnings":warnings}));
    }
    let cli_args = ["task", "submit", "D-1", "--evidence", "CI run 5"];
    let plain = cli(dir.path(), runtime.path(), &cli_args);
    assert!(plain.status.success(), "{:?}", plain.stderr);
    let stderr = String::from_utf8(plain.stderr).unwrap();
    let actual: Vec<_> = stderr
        .lines()
        .filter(|line| line.starts_with("warning:"))
        .collect();
    assert_eq!(
        actual,
        [
            "warning: check the dev branch",
            "warning: check the repository"
        ]
    );

    let machine = cli(
        dir.path(),
        runtime.path(),
        &[&["--json"], cli_args.as_slice()].concat(),
    );
    assert_eq!(json_of(&machine)["warnings"], warnings);

    let answers = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[
            (
                "tasks",
                json!({"action":"submit","id":"D-1","evidence":"CI run 5"}),
            ),
            ("finish_work", json!({"task":"D-1","evidence":"CI run 5"})),
        ],
    );
    for answer in answers {
        assert_eq!(
            answer["structuredContent"]["warnings"], warnings,
            "{answer}"
        );
    }

    server.state.lock().unwrap().registry_submit_reply =
        Some(json!({"id":"D-1","status":"review","version":3}));
    let old_server = cli(
        dir.path(),
        runtime.path(),
        &[&["--json"], cli_args.as_slice()].concat(),
    );
    assert!(json_of(&old_server).get("warnings").is_none());
    assert!(!String::from_utf8_lossy(&old_server.stderr).contains("warning:"));
}

const COMMIT_EVIDENCE_WORKSPACE: &str = "00000000-0000-0000-0000-000000000001";

fn git_evidence_fixture(checkout: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(checkout)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}: {:?}", output.stderr);
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn encrypted_commit_evidence_fixture(
    server: &Server,
    root: &Path,
    runtime: &Path,
) -> (String, lockyard_cloud_client::WorkspaceKey) {
    use std::os::unix::fs::DirBuilderExt;

    let checkout = root.join("checkout");
    std::fs::create_dir_all(checkout.join("src")).unwrap();
    let git = |args: &[&str]| git_evidence_fixture(&checkout, args);
    git(&["init", "--template=", "--object-format=sha1"]);
    std::fs::write(checkout.join("src/file.txt"), "fixture").unwrap();
    git(&["add", "src/file.txt"]);
    let tree = git(&["write-tree"]);
    let sha = git(&["commit-tree", &tree, "-m", "Fixture"]);
    let key = lockyard_cloud_client::WorkspaceKey::from_entropy([47; 32]);
    let keys = runtime.join("config/lockyard/keys");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&keys)
        .unwrap();
    key.copy_to_private(&keys.join(format!("{COMMIT_EVIDENCE_WORKSPACE}.key")))
        .unwrap();
    {
        let mut state = server.state.lock().unwrap();
        state.encryption_key_id = Some(key.key_id());
        state.registry_items = vec![
            json!({"id":"D-1","status":"active","target":"code_accepted","version":1,"paths":["checkout/src/file.txt"]}),
        ];
        state.registry_submit_reply = Some(json!({"id":"D-1","status":"review","version":3}));
    }
    (sha, key)
}

#[test]
fn encrypted_registry_submission_resolves_task_sha_and_warns_when_unavailable() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (sha, key) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let caller = dir.path().join("caller");
    std::fs::create_dir(&caller).unwrap();
    let short_evidence = format!("{}:src/file.txt", &sha[..12]);
    let missing_evidence = "000000000000:src/file.txt";
    let finished = mcp_calls_env(
        &caller,
        runtime.path(),
        "compact",
        &[(
            "finish_work",
            json!({"task":"D-1","evidence":short_evidence}),
        )],
        &[("LOCKYARD_ON_BEHALF", "lead-task")],
    );
    let result = &finished[0]["structuredContent"];
    assert_eq!(result["task"]["status"], "review", "{finished:?}");
    assert!(result.get("warnings").is_none());

    let missing = cli(
        &caller,
        runtime.path(),
        &[
            "--json",
            "task",
            "submit",
            "D-1",
            "--evidence",
            missing_evidence,
        ],
    );
    let result = json_of(&missing);
    assert_eq!(result["status"], "review");
    assert!(
        result["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Приёмка в шифрованном workspace откажет")
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("warning: Не удалось развернуть SHA")
    );

    let evidence = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[0].body["commit_sha"], sha);
    assert!(evidence[1].body.get("commit_sha").is_none());
    for (request, original) in evidence
        .iter()
        .zip([short_evidence.as_str(), missing_evidence])
    {
        let value = request.body["value"].as_str().unwrap();
        assert!(value.starts_with("lyenc1."));
        assert_eq!(
            key.decrypt(COMMIT_EVIDENCE_WORKSPACE, "value", value)
                .unwrap(),
            original
        );
    }

    server.state.lock().unwrap().encryption_key_id = None;
    let plaintext = cli(
        &caller,
        runtime.path(),
        &[
            "--json",
            "task",
            "submit",
            "D-1",
            "--evidence",
            missing_evidence,
        ],
    );
    assert!(json_of(&plaintext).get("warnings").is_none());
    let evidence = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert_eq!(evidence[2].body["value"], missing_evidence);
    assert!(evidence[2].body.get("commit_sha").is_none());
}

#[test]
fn encrypted_registry_submission_accepts_a_promised_blob_missing_locally() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (sha, _) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let source = dir.path().join("checkout");
    git_evidence_fixture(&source, &["update-ref", "HEAD", &sha]);
    git_evidence_fixture(&source, &["config", "uploadpack.allowFilter", "true"]);
    git_evidence_fixture(
        dir.path(),
        &[
            "clone",
            "--no-local",
            "--no-checkout",
            "--filter=blob:none",
            "checkout",
            "partial",
        ],
    );
    let partial = dir.path().join("partial");
    let blob = git_evidence_fixture(&source, &["rev-parse", "HEAD:src/file.txt"]);
    assert_eq!(
        git_evidence_fixture(&partial, &["config", "--get", "remote.origin.promisor"]),
        "true"
    );
    let assert_blob_missing = || {
        let objects = git_evidence_fixture(
            &partial,
            &["rev-list", "--objects", "--missing=print", "HEAD"],
        );
        assert!(objects.lines().any(|line| line == format!("?{blob}")));
    };
    assert_blob_missing();
    server.state.lock().unwrap().registry_items[0]["paths"] = json!(["partial/src/file.txt"]);

    let evidence = format!("{}:src/file.txt", &sha[..12]);
    let response = cli(
        dir.path(),
        runtime.path(),
        &["--json", "task", "submit", "D-1", "--evidence", &evidence],
    );
    let result = json_of(&response);
    assert_eq!(result["status"], "review");
    assert!(result.get("warnings").is_none());
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert_eq!(requests[0].body["commit_sha"], sha);
    assert_blob_missing();
}

#[test]
fn encrypted_registry_submission_omits_sha_for_uninitialized_submodule_with_different_case() {
    assert_encrypted_submission_omits_sha_behind_gitlink("Nested", "nested");
}

#[test]
fn encrypted_registry_submission_omits_sha_for_uninitialized_submodule_with_unicode_case() {
    assert_encrypted_submission_omits_sha_behind_gitlink("neſted", "nested");
}

#[test]
fn encrypted_registry_submission_omits_sha_for_gitlink_with_decomposed_unicode() {
    assert_encrypted_submission_omits_sha_behind_gitlink("CAFE\u{0301}", "café");
}

#[test]
fn encrypted_registry_submission_omits_sha_for_gitlink_with_greek_caseless_match() {
    assert_encrypted_submission_omits_sha_behind_gitlink(
        "\u{0386}\u{0345}\u{0301}",
        "\u{03AC}\u{0345}\u{0301}",
    );
}

fn assert_encrypted_submission_omits_sha_behind_gitlink(gitlink: &str, task_component: &str) {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (parent_sha, _) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let checkout = dir.path().join("checkout");

    git_evidence_fixture(
        &checkout,
        &[
            "-c",
            "core.precomposeunicode=false",
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{parent_sha},{gitlink}"),
        ],
    );
    let index = git_evidence_fixture(&checkout, &["ls-files", "--stage", "-z"]);
    let gitlink_entry = format!("160000 {parent_sha} 0\t{gitlink}");
    assert!(
        index
            .split_terminator('\0')
            .any(|entry| entry == gitlink_entry)
    );
    assert!(!checkout.join(task_component).exists());
    server.state.lock().unwrap().registry_items[0]["paths"] =
        json!([format!("checkout/{task_component}/src/file.txt")]);

    let evidence = format!("{}:src/file.txt", &parent_sha[..12]);
    let response = cli(
        dir.path(),
        runtime.path(),
        &["--json", "task", "submit", "D-1", "--evidence", &evidence],
    );
    let result = json_of(&response);
    assert_eq!(result["status"], "review");
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert!(
        requests[0].body.get("commit_sha").is_none(),
        "expanded a short SHA in the parent repository behind gitlink {gitlink}"
    );
    assert!(
        result["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Не удалось развернуть SHA")
    );
    assert!(
        String::from_utf8_lossy(&response.stderr).contains("warning: Не удалось развернуть SHA")
    );
}

#[test]
fn encrypted_registry_submission_resolves_sha_only_in_the_submodule_checkout() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (parent_sha, _) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let checkout = dir.path().join("checkout");
    let source = tempfile::tempdir().unwrap();
    git_evidence_fixture(
        source.path(),
        &["init", "--template=", "--object-format=sha1"],
    );
    std::fs::create_dir(source.path().join("src")).unwrap();
    std::fs::write(source.path().join("src/file.txt"), "submodule fixture").unwrap();
    git_evidence_fixture(source.path(), &["add", "src/file.txt"]);
    let tree = git_evidence_fixture(source.path(), &["write-tree"]);
    let submodule_sha =
        git_evidence_fixture(source.path(), &["commit-tree", &tree, "-m", "Nested"]);
    git_evidence_fixture(source.path(), &["update-ref", "HEAD", &submodule_sha]);

    let git = |args: &[&str]| git_evidence_fixture(&checkout, args);
    git(&[
        "config",
        "-f",
        ".gitmodules",
        "submodule.nested.path",
        "nested",
    ]);
    git(&[
        "config",
        "-f",
        ".gitmodules",
        "submodule.nested.url",
        source.path().to_str().unwrap(),
    ]);
    git(&["add", ".gitmodules"]);
    git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{submodule_sha},nested"),
    ]);
    std::fs::create_dir(checkout.join("nested")).unwrap();
    server.state.lock().unwrap().registry_items[0]["paths"] =
        json!(["checkout/src/file.txt", "checkout/nested/src/file.txt"]);

    let submit = |sha: &str| {
        let evidence = format!("{}:src/file.txt", &sha[..12]);
        cli(
            dir.path(),
            runtime.path(),
            &["--json", "task", "submit", "D-1", "--evidence", &evidence],
        )
    };
    let response = submit(&parent_sha);
    let result = json_of(&response);
    assert_eq!(result["status"], "review");
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert!(
        requests[0].body.get("commit_sha").is_none(),
        "expanded a short SHA in the parent repository for an uninitialized submodule"
    );
    assert!(
        result["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Не удалось развернуть SHA")
    );
    assert!(
        String::from_utf8_lossy(&response.stderr).contains("warning: Не удалось развернуть SHA")
    );

    git(&["submodule", "update", "--init", "--", "nested"]);
    server.state.lock().unwrap().registry_items[0]["paths"] =
        json!(["checkout/nested/src/file.txt", "checkout/nested/src"]);
    let result = json_of(&submit(&submodule_sha));
    assert_eq!(result["status"], "review");
    assert!(result.get("warnings").is_none());
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert_eq!(requests[1].body["commit_sha"], submodule_sha);

    server.state.lock().unwrap().registry_items[0]["paths"] =
        json!(["checkout/nested/src/file.txt", "checkout/src/file.txt"]);
    let result = json_of(&submit(&submodule_sha));
    assert_eq!(result["status"], "review");
    assert!(result["warnings"].is_array());
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert!(
        requests[2].body.get("commit_sha").is_none(),
        "expanded a short SHA for paths in different initialized repositories"
    );
}

#[test]
fn encrypted_registry_submission_uses_object_prefix_over_same_named_branch() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (sha, _) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let checkout = dir.path().join("checkout");
    let git = |args: &[&str]| git_evidence_fixture(&checkout, args);
    let tree = git(&["write-tree"]);
    let other_sha = git(&["commit-tree", &tree, "-m", "Other fixture"]);
    let prefix = &sha[..12];
    git(&["branch", prefix, &other_sha]);

    let evidence = format!("{prefix}:src/file.txt");
    let response = cli(
        dir.path(),
        runtime.path(),
        &["--json", "task", "submit", "D-1", "--evidence", &evidence],
    );
    assert_eq!(json_of(&response)["status"], "review");
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert_eq!(
        requests[0].body["commit_sha"], sha,
        "object prefix was shadowed by a branch"
    );
}

#[test]
fn encrypted_registry_submission_ignores_git_ceiling_directories() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (sha, _) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let checkout = dir.path().join("checkout").canonicalize().unwrap();
    let evidence = format!("{}:src/file.txt", &sha[..12]);
    let response = mcp_calls_env(
        dir.path(),
        runtime.path(),
        "compact",
        &[("finish_work", json!({"task":"D-1","evidence":evidence}))],
        &[("GIT_CEILING_DIRECTORIES", checkout.to_str().unwrap())],
    );
    assert_eq!(response[0]["structuredContent"]["task"]["status"], "review");
    let requests = server.seen("POST", "/api/v1/registry/items/D-1/evidence");
    assert_eq!(
        requests[0].body["commit_sha"], sha,
        "Git ceiling hid the task checkout"
    );
}

#[test]
fn encrypted_registry_bulk_close_sends_open_commit_sha_and_encrypted_value() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let (sha, key) = encrypted_commit_evidence_fixture(&server, dir.path(), runtime.path());
    let evidence = format!("{}:src/file.txt", &sha[..12]);
    let response = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[("task_bulk", json!({"ids":["D-1"],"evidence":evidence}))],
    );
    assert_eq!(
        response[0]["structuredContent"]["results"][0]["changed"], true,
        "{response:?}"
    );
    let requests = server.seen("POST", "/api/v1/registry/items/batch-transition");
    assert_eq!(
        requests[0].body["evidence"]["commit_sha"], sha,
        "batch omitted the open commit SHA"
    );
    let value = requests[0].body["evidence"]["value"].as_str().unwrap();
    assert!(value.starts_with("lyenc1."));
    assert_eq!(
        key.decrypt(COMMIT_EVIDENCE_WORKSPACE, "value", value)
            .unwrap(),
        evidence
    );

    let response = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[(
            "task_bulk",
            json!({"ids":["D-1"],"evidence":"000000000000:src/file.txt"}),
        )],
    );
    let item = &response[0]["structuredContent"]["results"][0]["item"];
    assert!(
        item["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Не удалось развернуть SHA")
    );
    let requests = server.seen("POST", "/api/v1/registry/items/batch-transition");
    assert!(requests[1].body["evidence"].get("commit_sha").is_none());
}

#[test]
fn registry_accept_explains_all_commit_refusals_in_cli_and_mcp() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    server.state.lock().unwrap().registry_items =
        vec![json!({"id":"D-1","status":"review","version":1})];
    for (status, code, explanation, hint) in [
        (
            422,
            "commit_not_in_dev",
            "Коммит не входит в историю ветки dev",
            "Запушьте",
        ),
        (
            422,
            "commit_outside_task_repository",
            "Коммит указан для другого репозитория",
            "Пересдайте",
        ),
        (
            422,
            "commit_evidence_invalid",
            "Некорректное доказательство коммита",
            "<полный SHA>:<путь к файлу в коммите>",
        ),
        (
            503,
            "commit_reachability_unknown",
            "Сервер не смог проверить",
            "повторите приёмку",
        ),
    ] {
        server.state.lock().unwrap().refuse_registry_accept = Some((
            status,
            json!({"error":{"code":code,"message":"generic refusal"}}),
        ));
        let plain = cli(dir.path(), runtime.path(), &["task", "accept", "D-1"]);
        assert!(!plain.status.success());
        let stderr = String::from_utf8(plain.stderr).unwrap();
        assert!(
            stderr.contains(code) && stderr.contains(explanation) && stderr.contains(hint),
            "{stderr}"
        );

        let answers = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[("tasks", json!({"action":"accept","id":"D-1"}))],
        );
        let result = &answers[0];
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["code"], code);
        assert_eq!(result["structuredContent"]["status"], status);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(explanation) && text.contains(hint), "{text}");
    }
}

fn mcp_calls(dir: &Path, runtime: &Path, surface: &str, calls: &[(&str, Value)]) -> Vec<Value> {
    mcp_calls_env(dir, runtime, surface, calls, &[])
}

#[test]
fn mcp_forwards_queue_and_notice_ttls_at_their_limits() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let results = mcp_calls(
        dir.path(),
        runtime.path(),
        "full",
        &[
            ("zone_queue", json!({"paths":["src"], "ttl":480})),
            (
                "msg_send",
                json!({"to":"*", "body":"short notice", "kind":"notice", "ttl":30}),
            ),
            (
                "msg_send",
                json!({"to":"*", "body":"long notice", "kind":"notice", "ttl":1440}),
            ),
        ],
    );
    for result in results {
        assert_eq!(result["isError"], false, "{result}");
    }
    let queue = server.seen("POST", "/api/v1/zones/queue");
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].body["ttl_minutes"], 480);
    let mail = server.seen("POST", "/api/v1/bus/messages");
    assert_eq!(mail.len(), 2);
    assert_eq!(mail[0].body["ttl_minutes"], 30);
    assert_eq!(mail[1].body["ttl_minutes"], 1440);
}

fn mcp_calls_env(
    dir: &Path,
    runtime: &Path,
    surface: &str,
    calls: &[(&str, Value)],
    env: &[(&str, &str)],
) -> Vec<Value> {
    let mut child = binary(dir, runtime)
        .args(["mcp", "--tools", surface])
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .envs(env.iter().copied())
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
            ("zone_renew", json!({"id":1,"ttl":30,"fence":"7"})),
            ("zone_renew", json!({"id":1,"ttl":0,"fence":7})),
            ("zone_renew", json!({"id":1,"ttl":241,"fence":7})),
        ],
    );
    for (answer, expected) in invalid.iter().zip([
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
        (json!({"id":1,"ttl":30}), 30),
        (json!({"id":1,"ttl":30,"fence":null}), 30),
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
    assert_eq!(writes.len(), 5);
    for (write, ttl) in writes.iter().zip([30, 30, 30, 1, 240]) {
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
    for (answer, needle) in refused
        .iter()
        .zip(["stale fence", "status --lost", "expired"])
    {
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
            assert!(bulk.is_empty());
            for id in [11, 12] {
                assert_eq!(
                    server
                        .seen("DELETE", &format!("/api/v1/zones/claims/{id}"))
                        .len(),
                    1
                );
            }
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
    // Warm the binary so cold-start is not charged to the hung-socket budget.
    json_of(&cli(dir.path(), runtime.path(), &["--json", "about"]));
    let baseline = Instant::now();
    json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    let direct_ms = baseline.elapsed();
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
    server.state.lock().unwrap().seen.clear();
    let started = Instant::now();
    json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
    let hung = started.elapsed();
    // Absolute cap: probe ≤100 ms; must not spend the 1500 ms aggregate budget.
    assert!(
        hung < Duration::from_millis(900),
        "hung agent consumed the status budget: {hung:?} (direct baseline {direct_ms:?})"
    );
    // Relative: hung path may add the probe, not the aggregate timeout.
    assert!(
        hung < direct_ms + Duration::from_millis(400),
        "hung overhead {:?} exceeds probe budget over direct {:?}",
        hung.saturating_sub(direct_ms),
        direct_ms
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
fn cloud_status_without_token_or_agent_exits_with_no_cloud_access() {
    // META-0033: exit 5 only when the token is missing and the agent path is unavailable.
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let output = binary(dir.path(), runtime.path())
        .args(["--json", "status"])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let body = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    let text = format!("{body}{err}");
    assert!(
        text.contains("LOCKYARD_TOKEN_FILE") || text.contains("no_cloud_access"),
        "stdout={body} stderr={err}"
    );
}

#[test]
fn agent_service_opens_socket_when_project_root_is_unreadable() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    write_agent_service_config(dir.path(), runtime.path());
    let project = dir.path().canonicalize().unwrap();
    // Service starts without --root use the copy from a safe cwd (LY-0007).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let url = server.url.clone();
    let mut command = Command::new(
        std::env::var_os("LOCKYARD_TEST_BINARY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_lockyard").into()),
    );
    command
        .current_dir(runtime.path())
        .arg("agent")
        .env("LOCKYARD_URL", &url)
        .env("LOCKYARD_TOKEN", "test-token")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", runtime.path().join("state"))
        .env("XDG_CONFIG_HOME", runtime.path().join("config"))
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_TOKEN_FILE");
    std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o000)).unwrap();
    let restore = || {
        let _ = std::fs::set_permissions(&project, std::fs::Permissions::from_mode(0o755));
    };
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            restore();
            panic!("failed to spawn agent: {error}");
        }
    };
    let agent = Agent(child);
    let end = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while Instant::now() < end {
        if socket(runtime.path()).exists() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    restore();
    assert!(
        ready,
        "service agent never opened its socket with an unreadable project"
    );
    drop(agent);
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
fn cloud_status_outage_labels_the_agents_last_claim_snapshot() {
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
    let status = json_of(&output);
    assert_eq!(status["freshness"]["source"], "cached");
    assert_eq!(status["freshness"]["claims_cached"], true);
    assert_eq!(status["claims"][0]["id"], 71);
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
fn hook_check_validates_the_requested_path_in_nfc() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    for (requested, answered, accepted) in [
        ("src/café", "src/cafe\u{301}", true),
        ("src/s", "src/ſ", false),
    ] {
        server.state.lock().unwrap().check_reply =
            Some(json!({"paths": [{"path": answered, "status": "free"}]}));
        let result = cli(
            dir.path(),
            runtime.path(),
            &["hook", "check", "--path", requested],
        );
        assert_eq!(result.status.success(), accepted, "{result:?}");
    }
    assert_eq!(server.seen("POST", "/api/v1/zones/check").len(), 2);
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
    assert_eq!(peer.join().unwrap(), ["ping", "check"]);
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
    lockyard_core::fsio::replace(&token_file, b"test-token\n", 0o600).unwrap();
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

impl Agent {
    /// Join the temporary daemon's workers so journal assertions see no upkeep in flight.
    fn stop(mut self) {
        let result = unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM) };
        assert_eq!(result, 0, "cannot signal temporary test daemon");
        assert!(
            self.0.wait().unwrap().success(),
            "test daemon shutdown failed"
        );
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_agent(dir: &Path, runtime: &Path) -> Agent {
    start_agent_until(dir, runtime, true)
}

/// Service mode reads only `agent-config.toml` under XDG state (LY-0007).
fn write_agent_service_config(dir: &Path, runtime: &Path) {
    let config = std::fs::read_to_string(dir.join(".lockyard/config.toml")).unwrap();
    let url = config
        .lines()
        .find_map(|line| line.strip_prefix("url = '")?.strip_suffix("'"))
        .unwrap_or_default();
    let workspace = config
        .lines()
        .find_map(|line| line.strip_prefix("workspace = '")?.strip_suffix("'"))
        .unwrap_or("team");
    let state = runtime.join("state/lockyard");
    std::fs::create_dir_all(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let text = format!(
        "url = '{url}'\nworkspace = '{workspace}'\nproject_root = '{}'\n",
        root.display()
    );
    std::fs::write(state.join("agent-config.toml"), text).unwrap();
}

fn start_agent_until(dir: &Path, runtime: &Path, wait_for_view: bool) -> Agent {
    start_agent_until_env(dir, runtime, wait_for_view, &[])
}

fn start_agent_until_env(
    dir: &Path,
    runtime: &Path,
    wait_for_view: bool,
    env: &[(&str, &str)],
) -> Agent {
    if !runtime.join("state/lockyard/agent-config.toml").exists() {
        write_agent_service_config(dir, runtime);
    }
    let child = binary(dir, runtime)
        .env("LOCKYARD_TOKEN", "test-token")
        .envs(env.iter().copied())
        .arg("agent")
        .spawn()
        .unwrap();
    let agent = Agent(child);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        // Probe only our temporary daemon, after its socket exists; do not query
        // the installed service manager while this private child is starting.
        if socket(runtime).exists() {
            let status = cli(dir, runtime, &["--json", "agent", "status"]);
            let status = json_of(&status);
            if status["running"] == true
                && (!wait_for_view || status["status"]["view_fresh"] == true)
            {
                return agent;
            }
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
fn mail_through_agent_hook_reminds_without_reading_until_explicit_inbox() {
    let server = Server::start();
    server.state.lock().unwrap().inbox.push(
        json!({"id": 7, "from_session": "bob", "to": "me", "body": "look at src", "needs":"reply"}),
    );
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
    assert!(server.seen("POST", "/api/v1/bus/inbox/seen").is_empty());
    assert!(
        !String::from_utf8_lossy(&hook(dir.path(), runtime.path(), &event).stdout)
            .contains("look at src")
    );
    let read = binary(dir.path(), runtime.path())
        .args(["msg", "inbox", "--mark-read"])
        .env("LOCKYARD_AGENT", "me")
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap();
    assert!(read.status.success());
    let end = Instant::now() + Duration::from_secs(5);
    while server.seen("POST", "/api/v1/bus/inbox/seen").is_empty() {
        assert!(Instant::now() < end, "explicit inbox read was not marked");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        server.seen("POST", "/api/v1/bus/inbox/seen")[0].body,
        json!({"ids":[7]})
    );
}

#[test]
fn the_cli_goes_through_a_running_agent_and_needs_no_token() {
    for delayed in [false, true] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let _agent = start_agent(dir.path(), runtime.path());
        if delayed {
            server.state.lock().unwrap().latency = Latency {
                stall_route: Some("/api/v1/bus/messages".into()),
                stall: Duration::from_millis(2800),
                ..Latency::default()
            };
        }
        let sent = binary(dir.path(), runtime.path())
            .args(["--json", "msg", "send", "bob", "hello"])
            .env("LOCKYARD_AGENT", "alice")
            .env_remove("LOCKYARD_TOKEN")
            .output()
            .unwrap();
        let receipt = json_of(&sent);
        if receipt["queued"] == true {
            assert_eq!(receipt["id"], 0);
            assert!(receipt["key"].as_str().is_some_and(|key| !key.is_empty()));
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                let status = json_of(&cli(
                    dir.path(),
                    runtime.path(),
                    &["--json", "agent", "status"],
                ));
                if status["status"]["outbox"] == 0
                    && !server.seen("POST", "/api/v1/bus/messages").is_empty()
                {
                    break;
                }
                assert!(
                    Instant::now() < end,
                    "queued message was never delivered: {status}"
                );
                thread::sleep(Duration::from_millis(20));
            }
            let delivered = server.seen("POST", "/api/v1/bus/messages");
            assert!(
                delivered
                    .iter()
                    .any(|request| request.key.as_deref() == receipt["key"].as_str())
            );
        } else {
            assert_eq!(receipt["id"], 44);
        }
        if delayed {
            assert_eq!(
                receipt["queued"], true,
                "fixture must exercise the queued outcome"
            );
        }
        assert_eq!(
            server.seen("POST", "/api/v1/bus/messages")[0]
                .session
                .as_deref(),
            Some("alice")
        );
    }
}

#[test]
fn delegated_cli_uses_an_ordinary_agent_with_the_production_actor_dto() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let delegated_status = || {
        let output = binary(dir.path(), runtime.path())
            .args(["--json", "status"])
            .env("LOCKYARD_AGENT", "alice")
            .env("LOCKYARD_TOKEN", "test-token")
            .env("LOCKYARD_PARENT_CLAIM", "1336")
            .output()
            .unwrap();
        json_of(&output)
    };
    let warm = delegated_status();
    assert_eq!(warm["freshness"]["via"], "agent", "{warm}");
    server.state.lock().unwrap().refuse_claims_get = Some((
        503,
        json!({"error":{"code":"unavailable","message":"claims unavailable"}}),
    ));
    let status = delegated_status();
    assert_eq!(status["freshness"]["via"], "agent", "{status}");
    assert_eq!(status["freshness"]["claims_cached"], true, "{status}");
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
    lockyard_core::fsio::replace(&token, b"test-token", 0o600).unwrap();
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
        r#"{"version":1,"zones":{"code":["src","ſrc","tests"]},"groups":{"all":["code"]}}"#,
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
fn cli_and_mcp_merge_catalog_aliases_with_explicit_paths_in_nfc() {
    for mcp in [false, true] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        server.state.lock().unwrap().catalog =
            Some(json!({"zones": {"code": ["src/cafe\u{301}", "src/ſ"]}}));
        if mcp {
            let responses = mcp_calls(
                dir.path(),
                runtime.path(),
                "full",
                &[(
                    "zone_claim",
                    json!({"paths": ["src/café", "src/s"], "zones": ["code"]}),
                )],
            );
            assert_ne!(responses[0]["isError"], true, "{responses:?}");
        } else {
            let result = cli(
                dir.path(),
                runtime.path(),
                &[
                    "--json",
                    "zone",
                    "claim",
                    "src/café",
                    "src/s",
                    "--zone",
                    "code",
                ],
            );
            assert!(result.status.success(), "{result:?}");
        }
        let writes = server.seen("POST", "/api/v1/zones/claims");
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].body["paths"],
            json!(["src/café", "src/s", "src/ſ"])
        );
    }
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
fn offline_started_agent_catalog_put_and_get_work_after_cloud_key_create() {
    use lockyard_cloud_client::{Call, ipc_credential_proof};
    use std::os::unix::net::UnixStream;

    const CATALOG: &str = "/api/v1/zones/catalog";
    let server = Server::start();
    server.state.lock().unwrap().api_offline = true;
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent_until(dir.path(), runtime.path(), false);
    assert!(
        !runtime
            .path()
            .join("state/lockyard/encryption.json")
            .exists()
    );
    server.state.lock().unwrap().api_offline = false;
    let created = cli(
        dir.path(),
        runtime.path(),
        &["--json", "cloud", "key", "create"],
    );
    let key = json_of(&created);
    assert_eq!(key["created"], true);
    server.state.lock().unwrap().encryption_key_id = Some(key["key_id"].as_str().unwrap().into());

    let call = Call::write(
        "alice",
        "POST",
        CATALOG.into(),
        json!({"expected_revision":0,
            "catalog":{"version":1,"zones":{"private-zone":["src"]},"groups":{}}}),
    );
    let mut stream = UnixStream::connect(socket(runtime.path())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(
        stream,
        "{}",
        json!({"workspace":"team","op":"call","call":call,
            "credential_proof":ipc_credential_proof("test-token")})
    )
    .unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let answer: Value = serde_json::from_str(&line).unwrap();
    assert!(answer["error"].is_null(), "{answer}");
    assert_eq!(answer["value"]["verified"], true);
    assert_eq!(answer["value"]["revision"], 1);
    let writes = server.seen("POST", CATALOG);
    assert_eq!(writes.len(), 1);
    assert!(
        writes[0].body["catalog"]["content"]
            .as_str()
            .unwrap()
            .starts_with("lyenc1.")
    );
    let read = cli(dir.path(), runtime.path(), &["--json", "zone", "catalog"]);
    assert!(
        read.status.success(),
        "offline-started agent catalog read failed: {}",
        String::from_utf8_lossy(&read.stderr)
    );
    let catalog = json_of(&read);
    assert_eq!(catalog["zones"]["private-zone"], json!(["src"]));
}

#[test]
fn offline_started_agent_expands_encrypted_zones_on_its_first_catalog_read() {
    let server = Server::start();
    server.state.lock().unwrap().api_offline = true;
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent_until(dir.path(), runtime.path(), false);
    required_catalog_fixture(&server, dir.path(), runtime.path());
    server.state.lock().unwrap().api_offline = false;

    let claimed = cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "claim", "--zone", "code"],
    );
    let claim = json_of(&claimed);
    assert!(claim["paths"].as_array().unwrap().contains(&json!("src")));
    assert_eq!(server.seen("GET", "/api/v1/zones/catalog").len(), 1);
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
fn local_0100_r4_legacy_server_decides_caseless_claim_reuse() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    server.state.lock().unwrap().claims = vec![json!({
        "id": 1, "session": "alice", "paths": ["src/straße", "src/cafe\u{0301}"],
        "case_insensitive_paths": true
    })];

    for (path, expected_posts) in [
        ("src/straße/other.rs", 0),
        ("src/café/file.rs", 0),
        ("src/STRASSE/file.rs", 1),
    ] {
        let checks = mcp_calls(
            dir.path(),
            runtime.path(),
            "full",
            &[("zone_claim", json!({"paths": [path]}))],
        );
        assert_eq!(checks[0]["isError"], false, "{}", checks[0]);
        let posts = server.seen("POST", "/api/v1/zones/claims");
        assert_eq!(posts.len(), expected_posts, "{path}");
        if let Some(post) = posts.last() {
            assert_eq!(post.body["paths"], json!([path]));
        }
    }
}

#[test]
fn local_0100_r4_mcp_free_check_respects_own_exclusions() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    server.state.lock().unwrap().claims = vec![json!({
        "id": 1,
        "session": "alice",
        "paths": ["src/straße"],
        "excluded_paths": ["src/straße/private"],
        "case_insensitive_paths": true
    })];
    let checks = mcp_calls(
        dir.path(),
        runtime.path(),
        "full",
        &[
            ("zone_check", json!({"path": "src/STRASSE/private/file.rs"})),
            ("zone_check", json!({"path": "src/STRASSE/public/file.rs"})),
        ],
    );
    assert_eq!(checks[0]["structuredContent"], json!({"free": true}));
    assert_eq!(
        checks[1]["structuredContent"],
        json!({"free": false, "own": true, "holder": "you"})
    );
}

#[test]
fn mcp_zone_check_respects_the_own_claim_case_policy() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    for (fold_case, expected) in [
        (false, json!({"free": true})),
        (true, json!({"free": false, "own": true, "holder": "you"})),
    ] {
        server.state.lock().unwrap().claims = vec![json!({
            "id": 1,
            "session": "alice",
            "paths": ["src/ſ"],
            "case_insensitive_paths": fold_case
        })];
        let checks = mcp_calls(
            dir.path(),
            runtime.path(),
            "full",
            &[("zone_check", json!({"path": "src/s"}))],
        );
        assert_eq!(checks[0]["isError"], false, "{}", checks[0]);
        assert_eq!(checks[0]["structuredContent"], expected);
    }
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

include!("survey_client/mod.rs");
include!("survey_client/r2.rs");
include!("survey_client/r4.rs");
include!("survey_client/r3_i2.rs");

#[test]
fn task_add_cli_and_mcp_reconcile_two_lost_create_responses_without_duplicates() {
    for (use_mcp, use_agent) in [(false, false), (true, false), (false, true), (true, true)] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
            state.registry_items = (1..=250)
                .map(|id| json!({"id":format!("FE-{id}"),"title":"same title","status":"ready"}))
                .collect();
            state.registry_page_size = Some(20);
            state.survey_uncertain_create = true;
            state.survey_echo_client_key = true;
            state.survey_lose_create_replies = true;
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let agent = use_agent.then(|| start_agent(dir.path(), runtime.path()));
        if use_mcp {
            let answers = mcp_calls(
                dir.path(),
                runtime.path(),
                "compact",
                &[("task_add", json!({"title":"same title","area":"engine"}))],
            );
            assert_eq!(answers[0]["isError"], false, "{answers:?}");
            assert_eq!(answers[0]["structuredContent"]["id"], "FE-77");
            assert_eq!(answers[0]["structuredContent"]["created"], true);
        } else {
            let result = cli(
                dir.path(),
                runtime.path(),
                &["--json", "task", "add", "same title", "--area", "engine"],
            );
            assert_eq!(json_of(&result)["id"], "FE-77");
        }
        let writes = server.seen("POST", "/api/v1/registry/items");
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].body, writes[1].body);
        assert_eq!(writes[0].key, writes[1].key);
        let lookups = server.seen("GET", "/api/v1/registry/items");
        assert_eq!(lookups.len(), 1);
        assert!(lookups[0].path.contains("client_key="));
        assert_eq!(server.state.lock().unwrap().registry_items.len(), 251);
        // All create/receipt assertions above run against the live agent. Only then join
        // its background writers before requiring the *entire* journal to be empty.
        if let Some(agent) = agent {
            agent.stop();
        }
        let journal = runtime
            .path()
            .join("state/lockyard/pending-writes")
            .canonicalize()
            .unwrap();
        let client = lockyard_cloud_client::Client::new(&server.url, "test-token".into())
            .unwrap()
            .with_pending_journal(journal)
            .unwrap();
        assert!(
            client.pending_operations().is_empty(),
            "mcp={use_mcp} agent={use_agent}: {:?}",
            client.pending_operations()
        );
    }
}

#[test]
fn task_add_invalid_type_is_rejected_by_cli_before_any_network() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let result = cli(
        dir.path(),
        runtime.path(),
        &["task", "add", "invalid", "--type", "task"],
    );
    assert_eq!(result.status.code(), Some(2));
    let error = String::from_utf8_lossy(&result.stderr);
    for kind in lockyard_core::tasks::REGISTRY_TASK_TYPES {
        assert!(error.contains(kind), "{error}");
    }
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn task_add_400_rejections_are_not_unknown_or_retained_for_replay() {
    for body in [
        json!({"status":400,"code":"invalid_type","type":"urn:lockyard:problem:invalid_type",
               "detail":"invalid task type","details":{}}),
        json!({"status":400,"type":"https://tools.ietf.org/html/rfc9110#section-15.5.1",
               "title":"One or more validation errors occurred.",
               "errors":{"type":["The JSON value could not be converted to RegistryItemType."]}}),
    ] {
        for use_agent in [false, true] {
            for use_mcp in [false, true] {
                let server = Server::start();
                {
                    let mut state = server.state.lock().unwrap();
                    state.registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
                    state.refuse_registry_create = Some((400, body.clone()));
                }
                let dir = cloud_project(&server);
                let runtime = tempfile::tempdir().unwrap();
                let _agent = use_agent.then(|| start_agent(dir.path(), runtime.path()));
                let error = if use_mcp {
                    let replies = mcp_calls(
                        dir.path(),
                        runtime.path(),
                        "compact",
                        &[("task_add", json!({"title":"rejected","area":"engine"}))],
                    );
                    assert_eq!(replies[0]["isError"], true);
                    replies[0].to_string()
                } else {
                    let result = cli(
                        dir.path(),
                        runtime.path(),
                        &["--json", "task", "add", "rejected", "--area", "engine"],
                    );
                    assert!(!result.status.success());
                    format!(
                        "{}{}",
                        String::from_utf8_lossy(&result.stdout),
                        String::from_utf8_lossy(&result.stderr)
                    )
                };
                assert!(
                    error.contains("invalid_type") || error.contains("nothing created"),
                    "{error}"
                );
                assert!(
                    !error.contains("unknown") && !error.contains("unconfirmed"),
                    "{error}"
                );
                assert_eq!(server.seen("POST", "/api/v1/registry/items").len(), 1);
                assert!(server.state.lock().unwrap().registry_items.is_empty());
                let journal = runtime
                    .path()
                    .join("state/lockyard/pending-writes")
                    .canonicalize()
                    .unwrap();
                let client = lockyard_cloud_client::Client::new(&server.url, "test-token".into())
                    .unwrap()
                    .with_pending_journal(journal)
                    .unwrap();
                assert!(
                    client
                        .pending_operations()
                        .iter()
                        .all(|p| p.request_path != "/api/v1/registry/items")
                );
            }
        }
    }
}

#[test]
fn tokenless_mail_with_a_busy_agent_socket_does_not_exit_with_no_access() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(runtime.path().join("lockyard")).unwrap();
    std::fs::set_permissions(
        runtime.path().join("lockyard"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let listener = UnixListener::bind(socket(runtime.path())).unwrap();
    std::fs::set_permissions(
        socket(runtime.path()),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    // Return a real connection refusal after a busy interval. Previously the two
    // 100 ms probes returned exit 5 before this listener had time to respond.
    let worker = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < end,
                        "CLI never connected to the busy test socket"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test socket accept failed: {error}"),
            }
        };
        thread::sleep(Duration::from_millis(350));
        drop(stream);
    });
    let result = binary(dir.path(), runtime.path())
        .args(["msg", "inbox"])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .output()
        .unwrap();
    worker.join().unwrap();
    assert_ne!(result.status.code(), Some(5), "{result:?}");
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn manual_agent_root_wins_and_missing_copy_works_without_writing_one() {
    for (with_copy, explicit_root) in [(false, false), (false, true), (true, true)] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let path = runtime.path().join("state/lockyard/agent-config.toml");
        let original = if with_copy {
            write_agent_service_config(dir.path(), runtime.path());
            let installed = std::fs::read_to_string(&path)
                .unwrap()
                .replace(&server.url, "http://127.0.0.1:1");
            std::fs::write(&path, installed).unwrap();
            Some(std::fs::read(&path).unwrap())
        } else {
            None
        };
        let mut command = binary(dir.path(), runtime.path());
        command.arg("agent");
        if explicit_root {
            command.arg("--root").arg(dir.path());
        }
        let child = command
            .env("LOCKYARD_TOKEN", "test-token")
            .env_remove("LOCKYARD_AGENT_ROOT")
            .spawn()
            .unwrap();
        let mut agent = Agent(child);
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(agent.0.try_wait().unwrap().is_none(), "manual agent exited");
            if socket(runtime.path()).exists() {
                let result = cli(dir.path(), runtime.path(), &["--json", "agent", "status"]);
                let status = json_of(&result);
                if status["running"] == true {
                    assert_eq!(status["status"]["url"], server.url);
                    break;
                }
            }
            assert!(Instant::now() < end, "manual agent never opened socket");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(std::fs::read(&path).ok(), original);
    }
}

include!("rework_client/mod.rs");

#[path = "survey_client/nov18.rs"]
mod survey_nov18;

#[path = "survey_client/r4_session_key.rs"]
mod survey_r4_session_key;

#[path = "survey_client/r8_notifications.rs"]
mod survey_r8_notifications;

#[test]
fn running_agent_uses_live_encryption_for_the_first_outbox_send() {
    use lockyard_cloud_client::WorkspaceKey;
    use std::os::unix::fs::DirBuilderExt;
    const MAIL: &str = "/api/v1/bus/messages";
    const WORKSPACE: &str = "00000000-0000-0000-0000-000000000001";
    const BODY: &str = "queued while encryption was off";
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let key = WorkspaceKey::from_entropy([15; 32]);
    let keys = runtime.path().join("config/lockyard/keys");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&keys)
        .unwrap();
    key.copy_to_private(&keys.join(format!("{WORKSPACE}.key")))
        .unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let (release, hold) = std::sync::mpsc::channel();
    server.state.lock().unwrap().hold_next_mail_response = Some(hold);
    let send = |body: &str| {
        binary(dir.path(), runtime.path())
            .args(["--json", "msg", "send", "bob", body])
            .env("LOCKYARD_AGENT", "alice")
            .env_remove("LOCKYARD_TOKEN")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = send("hold the outbox");
    let end = Instant::now() + Duration::from_secs(8);
    while server.seen("POST", MAIL).is_empty() {
        assert!(Instant::now() < end, "first mail did not reach the server");
        thread::sleep(Duration::from_millis(20));
    }
    let second = send(BODY);
    loop {
        let status = json_of(&cli(
            dir.path(),
            runtime.path(),
            &["--json", "agent", "status"],
        ));
        if status["status"]["outbox"] == 2 {
            break;
        }
        assert!(Instant::now() < end, "second mail was not queued: {status}");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(server.seen("POST", MAIL).len(), 1);
    server.state.lock().unwrap().encryption_key_id = Some(key.key_id());
    release.send(()).unwrap();
    for child in [first, second] {
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "{result:?}");
    }
    while server.seen("POST", MAIL).len() < 2 {
        assert!(Instant::now() < end, "queued mail did not reach the server");
        thread::sleep(Duration::from_millis(20));
    }
    let writes = server.seen("POST", MAIL);
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].body["body"], "hold the outbox");
    let ciphertext = writes[1].body["body"].as_str().unwrap();
    assert!(
        writes[1].body["from_client"]
            .as_str()
            .unwrap()
            .starts_with("lyml1.")
    );
    assert_eq!(key.decrypt(WORKSPACE, "body", ciphertext).unwrap(), BODY);
}

#[test]
fn running_agent_attests_live_encryption_before_replaying_mail() {
    use lockyard_cloud_client::{PendingWrite, WorkspaceKey, credential_fingerprint};
    const MAIL: &str = "/api/v1/bus/messages";
    const BODY: &str = "plaintext before policy change";
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let key = WorkspaceKey::from_entropy([15; 32]);
    server.state.lock().unwrap().require_encryption_after_mail = Some(key.key_id());
    let _agent = start_agent(dir.path(), runtime.path());

    let _sent = binary(dir.path(), runtime.path())
        .args(["--json", "msg", "send", "bob", BODY])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .output()
        .unwrap();
    let writes = server.seen("POST", MAIL);
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].body["body"], BODY);
    let key = writes[0].key.as_deref().unwrap();
    let scope = credential_fingerprint(&format!("{}\0test-token", server.url));
    let path = runtime
        .path()
        .join("state/lockyard/pending-writes")
        .join(scope)
        .join(format!("{}.unknown", credential_fingerprint(key)));
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let status = json_of(&cli(
            dir.path(),
            runtime.path(),
            &["--json", "agent", "status"],
        ));
        if path.is_file() && status["status"]["outbox"] == 0 {
            break;
        }
        assert!(
            Instant::now() < end,
            "daemon did not park the replay: {status}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let parked: PendingWrite = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(parked.cause_code, "pending_encryption_mismatch");
    assert!(parked.first_sent_server_secs.is_some());
    assert!(parked.replay_paused && !parked.replay_stopped);
    assert_eq!(
        server.seen("POST", MAIL).len(),
        1,
        "the repeat leaked the saved body"
    );
    assert!(
        server
            .seen("GET", "/api/v1/workspace/encryption")
            .iter()
            .any(|read| {
                read.session
                    .as_deref()
                    .is_some_and(|s| s.starts_with("lockyard-pending-policy"))
            }),
        "the running daemon did not recheck the policy"
    );
}

#[test]
fn running_agent_finishes_mail_from_doctor_after_encryption_becomes_required() {
    agent_finishes_mail_from_doctor(true, None);
}

#[test]
fn agent_finishes_settled_mail_after_encryption_changes_from_off_to_required() {
    agent_finishes_mail_from_doctor(false, Some(true));
}

#[test]
fn agent_finishes_settled_mail_after_encryption_changes_from_required_to_off() {
    agent_finishes_mail_from_doctor(true, Some(false));
}

fn agent_finishes_mail_from_doctor(initial_required: bool, after_repair: Option<bool>) {
    use lockyard_cloud_client::{WorkspaceKey, credential_fingerprint};
    use std::os::unix::fs::DirBuilderExt;

    const MAIL: &str = "/api/v1/bus/messages";
    const WORKSPACE: &str = "00000000-0000-0000-0000-000000000001";
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let key = WorkspaceKey::from_entropy([15; 32]);
    let keys = runtime.path().join("config/lockyard/keys");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&keys)
        .unwrap();
    key.copy_to_private(&keys.join(format!("{WORKSPACE}.key")))
        .unwrap();
    let scope = credential_fingerprint(&format!("{}\0test-token", server.url));
    let journal = runtime
        .path()
        .join("state/lockyard/pending-writes")
        .join(scope);
    server.state.lock().unwrap().mail_repair = Some(MailRepair {
        cursor: journal.join(".repair-cursor"),
        deliveries: Default::default(),
    });
    let set_policy = |required: bool| {
        server.state.lock().unwrap().encryption_key_id = required.then(|| key.key_id());
    };
    if after_repair.is_some() {
        set_policy(initial_required);
    }
    let mut agent = Some(start_agent(dir.path(), runtime.path()));
    set_policy(initial_required);

    let send = |body: &str| {
        binary(dir.path(), runtime.path())
            .args(["--json", "msg", "send", "bob", body])
            .env("LOCKYARD_AGENT", "alice")
            .env_remove("LOCKYARD_TOKEN")
            .output()
            .unwrap()
    };
    let lost = send("committed with no response");
    assert!(!lost.status.success(), "{lost:?}");
    assert!(
        String::from_utf8_lossy(&lost.stderr).contains("outcome_unknown"),
        "{lost:?}"
    );
    let first = server.seen("POST", MAIL).into_iter().next().unwrap();
    let first_key = first.key.as_deref().unwrap();
    let record = journal.join(format!("{}.settled", credential_fingerprint(first_key)));

    if after_repair.is_some() {
        // Keep the outbox stopped across repair and the policy change so it cannot
        // read the receipt before both events have happened.
        drop(agent.take());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let repair = binary(dir.path(), runtime.path())
            .args(["--json", "doctor", "--repair-pending"])
            .env("LOCKYARD_TOKEN", "test-token")
            .output()
            .unwrap();
        let report = json_of(&repair);
        if report["pending_repair"]["applied"] == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "doctor could not settle the receipt: {report}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(record.is_file());
    let posts_before_next = server.seen("POST", MAIL);
    assert!(
        posts_before_next.len() >= 2,
        "doctor must replay the original key"
    );
    assert!(
        posts_before_next
            .iter()
            .all(|post| post.key == first.key && post.body == first.body)
    );
    let _resumed_agent = after_repair.map(|required| {
        let settled: Value = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        assert_eq!(settled["consumed"], false);
        set_policy(required);
        start_agent(dir.path(), runtime.path())
    });

    let second = send("next letter");
    assert!(second.status.success(), "{second:?}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let settled: Value = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        let status = json_of(&cli(
            dir.path(),
            runtime.path(),
            &["--json", "agent", "status"],
        ));
        if settled["consumed"] == true && status["status"]["outbox"] == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "agent did not complete both letters: {status}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let posts = server.seen("POST", MAIL);
    assert_eq!(posts.len(), posts_before_next.len() + 1);
    let second = posts.last().unwrap();
    assert_ne!(second.key, first.key);
    assert_eq!(second.session, first.session);
    let state = server.state.lock().unwrap();
    let deliveries = &state.mail_repair.as_ref().unwrap().deliveries;
    assert_eq!(deliveries.len(), 2);
    for (delivery_key, expected, required) in [
        (first_key, "committed with no response", initial_required),
        (
            second.key.as_deref().unwrap(),
            "next letter",
            after_repair.unwrap_or(initial_required),
        ),
    ] {
        let wire_body = deliveries[delivery_key]["body"].as_str().unwrap();
        if required {
            assert_eq!(key.decrypt(WORKSPACE, "body", wire_body).unwrap(), expected);
        } else {
            assert_eq!(wire_body, expected);
        }
    }
}

#[test]
fn r14_plaintext_pending_is_never_sent_by_cli_agent_or_doctor_under_e2ee() {
    use lockyard_cloud_client::{Call, Client, ClientError, Transport};
    const WORKSPACE: &str = "00000000-0000-0000-0000-000000000001";
    const PATH: &str = "/api/v1/registry/items";

    for entry in ["cli", "agent", "doctor"] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let journal = runtime
            .path()
            .canonicalize()
            .unwrap()
            .join("state/lockyard/pending-writes");
        let client = Client::new(&server.url, "test-token".into())
            .unwrap()
            .with_pending_journal(&journal)
            .unwrap();
        let call = Call::write(
            "alice",
            "POST",
            PATH.into(),
            json!({"title":"plaintext fixture"}),
        );
        server.state.lock().unwrap().refuse_registry_create = Some((
            500,
            json!({"error":{"code":"unavailable","message":"lost confirmation"}}),
        ));
        let Err(ClientError::OutcomeUnknown(pending)) = client.call(&call) else {
            panic!("fixture must leave a replayable operation");
        };
        let mut pending = *pending;
        pending.first_sent_unix_secs = pending.first_sent_unix_secs.map(|time| time - 120);
        let scope = journal.join(lockyard_cloud_client::credential_fingerprint(&format!(
            "{}\0test-token",
            server.url
        )));
        let record = scope.join(format!(
            "{}.json",
            lockyard_cloud_client::credential_fingerprint(&pending.key)
        ));
        lockyard_core::fsio::replace(&record, &serde_json::to_vec(&pending).unwrap(), 0o600)
            .unwrap();
        {
            let mut state = server.state.lock().unwrap();
            state.refuse_registry_create = None;
            state.seen.clear();
        }
        required_catalog_fixture(&server, dir.path(), runtime.path());

        let required = [
            ("LOCKYARD_REQUIRE_E2EE", "1"),
            ("LOCKYARD_E2EE_WORKSPACE_ID", WORKSPACE),
        ];
        let agent = if entry == "agent" {
            Some(start_agent_until_env(
                dir.path(),
                runtime.path(),
                false,
                &required,
            ))
        } else {
            let mut command = binary(dir.path(), runtime.path());
            command
                .env("LOCKYARD_TOKEN", "test-token")
                .envs(required)
                .arg("--json");
            let out = if entry == "doctor" {
                command.args(["doctor", "--repair-pending"])
            } else {
                command.args(["zone", "list"])
            }
            .output()
            .unwrap();
            assert!(
                out.status.success(),
                "{entry}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            if entry == "doctor" {
                let report = json_of(&out);
                assert_eq!(report["pending_repair"]["applied"], 0);
                assert_eq!(report["pending_repair"]["rejected"], 0);
                assert_eq!(report["pending_repair"]["remaining"], 0);
                assert_eq!(
                    report["pending_repair"]["unknown_ids"],
                    json!([pending.key])
                );
            }
            None
        };

        let cursor: String =
            serde_json::from_slice(&std::fs::read(scope.join(".repair-cursor")).unwrap()).unwrap();
        assert_eq!(
            cursor, pending.key,
            "{entry} did not examine the frozen write"
        );
        assert!(
            !server
                .seen("GET", "/api/v1/workspace/encryption")
                .is_empty(),
            "{entry}"
        );
        assert!(
            server.seen("POST", PATH).is_empty(),
            "{entry} sent the frozen plaintext"
        );
        assert!(!record.exists(), "{entry} kept the row active");
        let unknown = record.with_extension("unknown");
        let bytes = std::fs::read(&unknown).unwrap();
        let parked: lockyard_cloud_client::PendingWrite = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parked.cause_code, "pending_encryption_mismatch");
        assert_eq!(parked.body, pending.body);
        assert!(parked.replay_paused && !parked.replay_stopped);
        if entry == "doctor" {
            let forgotten = binary(dir.path(), runtime.path())
                .env("LOCKYARD_TOKEN", "test-token")
                .envs(required)
                .args([
                    "--json",
                    "doctor",
                    "--forget-unknown",
                    &pending.key,
                    "--confirm",
                ])
                .output()
                .unwrap();
            assert_eq!(json_of(&forgotten)["forgotten_unknown"], 1);
            assert!(!unknown.exists());
            assert_eq!(
                std::fs::read(record.with_extension("quarantine")).unwrap(),
                bytes
            );
        }
        drop(agent);
    }
}

#[test]
fn survey1118_ly0030_doctor_reconciles_pending_online() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let root = runtime
        .path()
        .canonicalize()
        .unwrap()
        .join("state/lockyard/pending-writes");
    let _client = lockyard_cloud_client::Client::new(&server.url, "test-token".into())
        .unwrap()
        .with_pending_journal(&root)
        .unwrap();
    let scope =
        lockyard_cloud_client::credential_fingerprint(&format!("{}\0test-token", server.url));
    let scoped = root.join(scope);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for i in 0..140 {
        let key = format!("fixture-{i}");
        let record = json!({"code":"outcome_unknown","cause_code":"transport","cause_status":null,
            "protocol":{"selected":2,"capabilities":[]},"method":"POST",
            "path":if i == 139 {"/api/v1/registry/items"} else {"/api/v1/presence"},
            "request_path":if i == 139 {"/api/v1/registry/items"} else {"/api/v1/presence"},
            "body":if i == 139 {r#"{"title":"durable fixture"}"#} else {"{}"},
            "key":key,"repository":null,"session":"alice","origin":server.url,
            "credential_scope":lockyard_cloud_client::credential_fingerprint("test-token"),
            "first_sent_unix_secs":if i == 139 { now } else { now - 31 * 24 * 3600 }});
        let path = scoped.join(format!(
            "{}.json",
            lockyard_cloud_client::credential_fingerprint(&key)
        ));
        lockyard_core::fsio::replace(&path, &serde_json::to_vec(&record).unwrap(), 0o600).unwrap();
    }
    let out = binary(dir.path(), runtime.path())
        .env_remove("LOCKYARD_AGENT")
        .env("LOCKYARD_TOKEN", "test-token")
        .args(["--json", "doctor", "--repair-pending"])
        .output()
        .unwrap();
    let result = json_of(&out);
    assert_eq!(result["pending_repair"]["quarantined"], 0, "{result}");
    assert_eq!(result["pending_repair"]["outcome_unknown"], 139, "{result}");
    assert_eq!(result["pending_repair"]["remaining"], 0, "{result}");
    assert_eq!(result["pending_repair"]["applied"], 1, "{result}");
    assert_eq!(result["network"], true);
    assert!(!server.state.lock().unwrap().seen.is_empty());
    assert!(!scoped.join("quarantine.log").exists());
    assert_eq!(
        std::fs::read_dir(&scoped)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "json" || ext == "unknown"))
            .count(),
        139,
    );
}

#[test]
fn survey1118_ly0030_doctor_offline_requires_network_and_preserves_all_records() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let root = runtime
        .path()
        .canonicalize()
        .unwrap()
        .join("state/lockyard/pending-writes");
    let _client = lockyard_cloud_client::Client::new(&server.url, "test-token".into())
        .unwrap()
        .with_pending_journal(&root)
        .unwrap();
    let scope =
        lockyard_cloud_client::credential_fingerprint(&format!("{}\0test-token", server.url));
    let scoped = root.join(scope);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for i in 0..140 {
        let key = format!("fixture-{i}");
        let record = json!({"code":"outcome_unknown","cause_code":"transport","cause_status":null,
            "protocol":{"selected":2,"capabilities":[]},"method":"POST",
            "path":if i == 139 {"/api/v1/registry/items"} else {"/api/v1/presence"},
            "request_path":if i == 139 {"/api/v1/registry/items"} else {"/api/v1/presence"},
            "body":if i == 139 {r#"{"title":"durable fixture"}"#} else {"{}"},
            "key":key,"repository":null,"session":"alice","origin":server.url,
            "credential_scope":lockyard_cloud_client::credential_fingerprint("test-token"),
            "first_sent_unix_secs":if i == 139 { now } else { now - 31 * 24 * 3600 }});
        let path = scoped.join(format!(
            "{}.json",
            lockyard_cloud_client::credential_fingerprint(&key)
        ));
        lockyard_core::fsio::replace(&path, &serde_json::to_vec(&record).unwrap(), 0o600).unwrap();
    }
    server.state.lock().unwrap().api_offline = true;
    let out = binary(dir.path(), runtime.path())
        .env_remove("LOCKYARD_AGENT")
        .env("LOCKYARD_TOKEN", "test-token")
        .args(["--json", "doctor", "--repair-pending"])
        .output()
        .unwrap();
    let result = json_of(&out);
    assert_eq!(result["pending_repair"]["quarantined"], 0, "{result}");
    assert_eq!(result["pending_repair"]["remaining"], 1, "{result}");
    assert_eq!(result["pending_repair"]["outcome_unknown"], 139, "{result}");
    assert_eq!(
        result["pending_repair"]["network_required"], true,
        "{result}"
    );
    assert_eq!(result["network"], false);
    assert!(!scoped.join("quarantine.log").exists());
    assert_eq!(
        std::fs::read_dir(&scoped)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "json" || extension == "unknown"))
            .count(),
        140
    );
}

#[test]
fn survey1118_r13_doctor_forgets_only_selected_unknown_operations_with_confirmation() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let root = runtime
        .path()
        .canonicalize()
        .unwrap()
        .join("state/lockyard/pending-writes");
    let _client = lockyard_cloud_client::Client::new(&server.url, "test-token".into())
        .unwrap()
        .with_pending_journal(&root)
        .unwrap();
    let scoped = root.join(lockyard_cloud_client::credential_fingerprint(&format!(
        "{}\0test-token",
        server.url
    )));
    let record_path = |key: &str| {
        scoped.join(format!(
            "{}.json",
            lockyard_cloud_client::credential_fingerprint(key)
        ))
    };
    for (key, path) in [
        ("first", "/api/v1/presence"),
        ("second", "/api/v1/presence"),
        ("active", "/api/v1/registry/items"),
    ] {
        let record = json!({"code":"outcome_unknown","cause_code":"transport","cause_status":null,
            "protocol":{"selected":2,"capabilities":[]},"method":"POST","path":path,
            "request_path":path,"body":"{}","key":key,"repository":null,"session":"alice","origin":server.url,
            "credential_scope":lockyard_cloud_client::credential_fingerprint("test-token")});
        lockyard_core::fsio::replace(
            &record_path(key),
            &serde_json::to_vec(&record).unwrap(),
            0o600,
        )
        .unwrap();
    }
    let run = |args: &[&str]| cli(dir.path(), runtime.path(), args);
    assert!(
        !run(&["doctor", "--forget-unknown", "first"])
            .status
            .success()
    );
    assert!(record_path("first").exists());
    assert!(!scoped.join("quarantine.log").exists());
    assert_eq!(
        json_of(&run(&[
            "--json",
            "doctor",
            "--forget-unknown",
            "first",
            "--confirm"
        ]))["forgotten_unknown"],
        1
    );
    assert!(record_path("first").with_extension("quarantine").exists());
    assert!(record_path("second").exists());
    assert_eq!(
        json_of(&run(&[
            "--json",
            "doctor",
            "--forget-unknown",
            "--all",
            "--confirm"
        ]))["forgotten_unknown"],
        1
    );
    assert!(record_path("second").with_extension("quarantine").exists());
    assert!(record_path("active").exists());
    let log = std::fs::read_to_string(scoped.join("quarantine.log")).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("operator_forgot_unknown"))
            .count(),
        2
    );
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn survey1118_ly0030_lost_token_issue_is_never_replayed_by_load_service_or_doctor() {
    use lockyard_cloud_client::{Call, Client, ClientError, Transport};

    let server = Server::start();
    server.state.lock().unwrap().lose_token_create_reply = true;
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let journal = runtime
        .path()
        .canonicalize()
        .unwrap()
        .join("state/lockyard/pending-writes");
    let open = || {
        Client::new(&server.url, "test-token".into())
            .unwrap()
            .with_pending_journal(&journal)
            .unwrap()
    };
    let client = open();
    let issue = Call::write(
        "alice",
        "POST",
        "/api/v1/registry/tokens".into(),
        json!({"name":"lost-reply-fixture"}),
    );
    let Err(ClientError::OutcomeUnknown(pending)) = client.call(&issue) else {
        panic!("token issuance did not retain an unknown outcome");
    };
    assert_eq!(server.state.lock().unwrap().tokens_created, 1);
    let key = issue.key.as_deref().unwrap();
    let scope = journal.join(lockyard_cloud_client::credential_fingerprint(&format!(
        "{}\0test-token",
        server.url
    )));
    let write_pending = |operation: &lockyard_cloud_client::PendingWrite| {
        let name = lockyard_cloud_client::credential_fingerprint(&operation.key);
        lockyard_core::fsio::replace(
            &scope.join(format!("{name}.json")),
            &serde_json::to_vec(operation).unwrap(),
            0o600,
        )
        .unwrap();
    };
    let mut pending = *pending;
    pending.first_sent_unix_secs = pending.first_sent_unix_secs.map(|time| time - 120);
    write_pending(&pending);
    let restored = open();
    assert!(restored.pending_operation(key).is_some());
    assert!(matches!(
        restored.call(&issue),
        Err(ClientError::OutcomeUnknown(_))
    ));
    assert_eq!(server.state.lock().unwrap().tokens_created, 1);

    let daemon = start_agent_until(dir.path(), runtime.path(), true);
    // A second journal record added after startup proves the periodic service pass ran.
    let path = "/api/v1/registry/items/D-1/evidence";
    let witness = lockyard_cloud_client::PendingWrite {
        key: lockyard_cloud_client::ulid(),
        path: path.into(),
        request_path: path.into(),
        body: Some(r#"{"evidence":"fixture"}"#.into()),
        ..pending.clone()
    };
    write_pending(&witness);
    let until = Instant::now() + Duration::from_secs(15);
    while !server
        .seen("POST", path)
        .iter()
        .any(|request| request.key.as_deref() == Some(&witness.key))
    {
        assert!(
            Instant::now() < until,
            "daemon did not reconcile the evidence witness"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(server.state.lock().unwrap().tokens_created, 1);
    drop(daemon);

    let out = binary(dir.path(), runtime.path())
        .env_remove("LOCKYARD_AGENT")
        .env("LOCKYARD_TOKEN", "test-token")
        .args(["--json", "doctor", "--repair-pending"])
        .output()
        .unwrap();
    let report = json_of(&out);
    assert_eq!(report["pending_repair"]["outcome_unknown"], 1);
    assert_eq!(report["pending_repair"]["remaining"], 0);
    assert!(
        scope
            .join(format!(
                "{}.json",
                lockyard_cloud_client::credential_fingerprint(key)
            ))
            .is_file()
    );
    assert_eq!(server.state.lock().unwrap().tokens_created, 1);
    assert!(!String::from_utf8_lossy(&out.stdout).contains("new-secret-key"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("new-secret-key"));
}

#[test]
fn survey1118_r12_doctor_repair_respects_revoked_url_trust() {
    use lockyard_cloud_client::{Call, Client, ClientError, Transport};

    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let journal = runtime
        .path()
        .canonicalize()
        .unwrap()
        .join("state/lockyard/pending-writes");
    assert!(
        cli(dir.path(), runtime.path(), &["cloud", "trust", &server.url])
            .status
            .success()
    );
    let client = Client::new(&server.url, "test-token".into())
        .unwrap()
        .with_pending_journal(&journal)
        .unwrap();
    server.state.lock().unwrap().refuse_registry_create = Some((
        500,
        json!({"error":{"code":"unavailable","message":"lost confirmation"}}),
    ));
    let call = Call::write(
        "alice",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title":"pending trust fixture", "client_key":lockyard_cloud_client::ulid()}),
    );
    assert!(matches!(
        client.call(&call),
        Err(ClientError::OutcomeUnknown(_))
    ));
    let scope =
        lockyard_cloud_client::credential_fingerprint(&format!("{}\0test-token", server.url));
    let record = lockyard_cloud_client::credential_fingerprint(call.key.as_deref().unwrap());
    let path = journal.join(scope).join(format!("{record}.json"));
    let before = std::fs::read(&path).unwrap();

    std::fs::remove_file(runtime.path().join("config/lockyard/trusted-servers")).unwrap();
    server.state.lock().unwrap().refuse_registry_create = None;
    let count = server.state.lock().unwrap().seen.len();
    let out = binary(dir.path(), runtime.path())
        .env_remove("LOCKYARD_URL")
        .env("LOCKYARD_TOKEN", "test-token")
        .args(["--json", "doctor", "--repair-pending"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not trusted"));
    assert_eq!(server.state.lock().unwrap().seen.len(), count);
    assert_eq!(std::fs::read(path).unwrap(), before);
}
