// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A small HTTP server for tests: it answers from a script and records what it was asked.

use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

/// One scripted response.
pub struct Reply {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
    delay: std::time::Duration,
}

impl Reply {
    pub fn json(status: u16, body: Value) -> Self {
        Self::text(status, &body.to_string()).header("Content-Type", "application/json")
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_string(),
            headers: Vec::new(),
            delay: std::time::Duration::ZERO,
        }
    }

    pub fn sse(body: &str) -> Self {
        Self::text(200, body).header("Content-Type", "text/event-stream")
    }

    /// Match CoordinationBus.BusEvent: sender first, recipient envelopes with concrete
    /// `to`, then the full metadata unread notification (including for self-mail).
    pub fn mail(first_seq: i64, recipients: &[&str], payload: Value) -> Self {
        let mut payload = payload;
        payload
            .as_object_mut()
            .unwrap()
            .entry("created_at")
            .or_insert_with(|| "2026-11-16T00:00:00Z".into());
        let mut body = String::new();
        let sender = payload["from"].as_str().unwrap();
        let mut seq = first_seq;
        for (session, role) in
            std::iter::once((sender, "sender")).chain(recipients.iter().map(|s| (*s, "recipient")))
        {
            let mut mail = payload.clone();
            mail["role"] = role.into();
            if role == "recipient" {
                mail["to"] = session.into();
            }
            let event = serde_json::json!({"seq":seq,"type":"bus.message","session":session,"payload":mail});
            body.push_str(&format!("id: {seq}\nevent: bus.message\ndata: {event}\n\n"));
            seq += 1;
        }
        if payload["to"] != "*" && payload["address"].is_null() {
            let to = payload["to"].as_str().unwrap().to_owned();
            let mut mail = payload;
            mail["role"] = "recipient".into();
            mail["to"] = to.clone().into();
            mail.as_object_mut().unwrap().remove("body");
            let event =
                serde_json::json!({"seq":seq,"type":"bus.unread","session":to,"payload":mail});
            body.push_str(&format!("id: {seq}\nevent: bus.unread\ndata: {event}\n\n"));
        }
        Self::sse(&body)
    }

    pub fn replaced(by: &str) -> Self {
        Self::sse(&format!(
            "event: replaced\ndata: {}\n\n",
            serde_json::json!({"by":by})
        ))
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn delay(mut self, delay: std::time::Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// One recorded request.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    headers: Vec<(String, String)>,
    pub body: Value,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// How the fake answers after the script runs out.
#[derive(Clone)]
struct ServeMode {
    /// Headers merged into every response (including `/api/v1/protocol` and empty fallback).
    default_headers: Vec<(String, String)>,
    /// When the script is empty, answer with path-shaped empty JSON instead of `{}`.
    routed: bool,
    capabilities: Vec<String>,
    routes: Arc<Mutex<HashMap<String, VecDeque<Reply>>>>,
    discovery: Arc<Mutex<Vec<Seen>>>,
    mailboxes: Arc<Mutex<HashMap<String, MailFixture>>>,
    sse_generation: Arc<AtomicU64>,
    bindings: Arc<Mutex<HashMap<String, String>>>,
    streams: Arc<Mutex<HashMap<u64, FakeStream>>>,
}

struct FakeStream {
    token: String,
    sessions: Vec<String>,
    replaced_by: Option<u64>,
}
struct StreamGuard<'a> {
    streams: &'a Mutex<HashMap<u64, FakeStream>>,
    id: u64,
}
impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        self.streams.lock().unwrap().remove(&self.id);
    }
}

#[derive(Default)]
struct MailFixture {
    unread: BTreeMap<i64, Value>,
    open: BTreeMap<i64, Value>,
}

pub struct FakeServer {
    address: String,
    bindings: Arc<Mutex<HashMap<String, String>>>,
    routes: Arc<Mutex<HashMap<String, VecDeque<Reply>>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    discovery: Arc<Mutex<Vec<Seen>>>,
    mailboxes: Arc<Mutex<HashMap<String, MailFixture>>>,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl FakeServer {
    /// Seed an existing server-side session binding, independently of local daemon state.
    pub fn bind_session(&self, session: &str, token: &str) {
        self.bindings
            .lock()
            .unwrap()
            .insert(session.into(), format!("Bearer {token}"));
    }

    /// Queue a response for a route independently of concurrent upkeep requests.
    pub fn enqueue(&self, route: &str, reply: Reply) {
        if route == "/api/v1/events" {
            ingest_mail(&mut self.mailboxes.lock().unwrap(), &reply.body);
        }
        self.routes
            .lock()
            .unwrap()
            .entry(route.into())
            .or_default()
            .push_back(reply);
    }

    /// Serves `script` in order. Requests past the end get `{}`.
    pub fn start(script: Vec<Reply>) -> Self {
        Self::start_with(script, Vec::new(), false, &[])
    }

    /// Path-shaped empty JSON for agent refresh traffic, with sticky response headers.
    ///
    /// Used when a real [`crate::Client`] backs a daemon: FIFO scripts cannot keep up with
    /// concurrent refresh, and every response must keep announcing capabilities such as
    /// `mail_open_v1`.
    pub fn start_routed(default_headers: Vec<(String, String)>) -> Self {
        Self::start_with(Vec::new(), default_headers, true, &[])
    }

    /// Routed agent fixture with additional capabilities in the discovery response body.
    pub fn start_routed_with_capabilities(capabilities: &[&str]) -> Self {
        Self::start_with(Vec::new(), Vec::new(), true, capabilities)
    }

    pub fn start_routed_with_headers_and_capabilities(
        headers: Vec<(String, String)>,
        capabilities: &[&str],
    ) -> Self {
        Self::start_with(Vec::new(), headers, true, capabilities)
    }

    fn start_with(
        script: Vec<Reply>,
        default_headers: Vec<(String, String)>,
        routed: bool,
        capabilities: &[&str],
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let discovery = Arc::new(Mutex::new(Vec::new()));
        let mailboxes = Arc::new(Mutex::new(HashMap::new()));
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let bindings = Arc::new(Mutex::new(HashMap::new()));
        let mode = Arc::new(ServeMode {
            routes: Arc::clone(&routes),
            discovery: Arc::clone(&discovery),
            mailboxes: Arc::clone(&mailboxes),
            sse_generation: Arc::new(AtomicU64::new(0)),
            bindings: bindings.clone(),
            streams: Arc::new(Mutex::new(HashMap::new())),
            default_headers,
            routed,
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        });
        let (stop, stopped) = mpsc::channel();
        let (ready, started) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            let mut workers: Vec<(TcpStream, thread::JoinHandle<()>)> = Vec::new();
            ready.send(()).unwrap();
            loop {
                if stopped.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Darwin inherits O_NONBLOCK from the listener on accepted sockets.
                        // Request readers run on their own threads and must wait for bytes.
                        stream.set_nonblocking(false).unwrap();
                        // Do not leave stalled request readers behind when a client cancels.
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let (log, script, mode) =
                            (Arc::clone(&log), Arc::clone(&script), Arc::clone(&mode));
                        let control = stream.try_clone().unwrap();
                        let worker = thread::spawn(move || {
                            let mut stream = stream;
                            while answer(&mut stream, &log, &script, &mode) {}
                        });
                        workers.push((control, worker));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopped
                            .recv_timeout(std::time::Duration::from_millis(1))
                            .is_ok()
                        {
                            break;
                        }
                    }
                    // A peer that resets before accept is not a fixture failure.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("fake server accept: {error}"),
                }
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].1.is_finished() {
                        let _ = workers.swap_remove(index).1.join();
                    } else {
                        index += 1;
                    }
                }
            }
            drop(listener);
            // Persistent HTTP connections avoid a fresh handshake and TIME_WAIT socket for
            // every discovery/business request. Wake idle readers before joining them.
            for (stream, _) in &workers {
                let _ = stream.shutdown(Shutdown::Both);
            }
            for (_, worker) in workers {
                let _ = worker.join();
            }
        });
        started.recv().unwrap();
        Self {
            address,
            bindings,
            routes,
            seen,
            discovery,
            mailboxes,
            stop,
            worker: Some(worker),
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn discovery_requests(&self) -> Vec<Seen> {
        self.discovery.lock().unwrap().clone()
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("fake server worker panicked");
            }
        }
    }
}

#[cfg(test)]
#[test]
fn discovery_and_business_requests_reuse_one_connection() {
    let server = FakeServer::start(vec![Reply::json(200, serde_json::json!({"ok": true}))]);
    let client = crate::Client::new(&server.url(), "fixture".into()).unwrap();
    let response =
        crate::Transport::call(&client, &crate::Call::get("me", "/api/v1/bus/tasks".into()))
            .unwrap();
    assert_eq!(response, serde_json::json!({"ok": true}));
    // One owner in FakeServer, one in accept, and one in the persistent request worker.
    assert_eq!(Arc::strong_count(&server.seen), 3);
    assert_eq!(
        server.requests().len(),
        1,
        "discovery stays outside the script"
    );
}

#[cfg(test)]
#[test]
fn dropping_server_closes_listener_and_joins_request_workers() {
    let server = FakeServer::start(vec![Reply::json(200, serde_json::json!({"ok": true}))]);
    let address = server.address.clone();
    let log = Arc::clone(&server.seen);
    let response: Value = ureq::get(&server.url())
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(response, serde_json::json!({"ok": true}));
    drop(server);
    assert_eq!(
        Arc::strong_count(&log),
        1,
        "all server workers must have exited"
    );
    assert!(
        TcpStream::connect(&address).is_err(),
        "listener must be closed"
    );
}

fn routed_body(path: &str) -> String {
    let route = path.split('?').next().unwrap_or(path);
    let body = match route {
        "/api/v1/zones/claims" => r#"{"claims":[]}"#,
        "/api/v1/zones/queue" => r#"{"queue":[]}"#,
        "/api/v1/zones/requests" => r#"{"requests":[]}"#,
        "/api/v1/zones/lost" => r#"{"lost":[]}"#,
        "/api/v1/zones/check" => r#"{"paths":[{"path":"src","status":"free"}]}"#,
        "/api/v1/bus/board" => "[]",
        "/api/v1/bus/tasks" => r#"{"tasks":[]}"#,
        "/api/v1/bus/inbox" => r#"{"messages":[],"skipped":0}"#,
        "/api/v1/bus/sent" => r#"{"messages":[]}"#,
        "/api/v1/registry/items" => r#"{"items":[]}"#,
        "/api/v1/workspace/encryption" => r#"{"required":false}"#,
        path if path.contains("/events") => r#"{"events":[]}"#,
        _ => "{}",
    };
    body.to_string()
}

fn merge_headers(reply: &mut Reply, extra: &[(String, String)]) {
    for (name, value) in extra {
        if !reply
            .headers
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            reply.headers.push((name.clone(), value.clone()));
        }
    }
}

fn answer(
    stream: &mut TcpStream,
    log: &Mutex<Vec<Seen>>,
    script: &Mutex<VecDeque<Reply>>,
    mode: &ServeMode,
) -> bool {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
        }
    };
    let head = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    while bytes.len() < header_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(count) => bytes.extend_from_slice(&chunk[..count]),
        }
    }
    let body = serde_json::from_slice(&bytes[header_end..]).unwrap_or(Value::Null);
    let protocol = headers
        .iter()
        .find(|(name, _)| name == "lockyard-protocol")
        .map(|(_, value)| value.clone());
    let legacy_namespace = headers
        .iter()
        .any(|(name, value)| name == "x-lockyard-repository" && value == "-");
    if mode.capabilities.iter().any(|v| v == "mail_push_v1")
        && !headers.iter().any(|(k, v)| {
            k == "x-lockyard-capabilities" && v.split(',').any(|c| c.trim() == "mail_push_v1")
        })
    {
        log.lock().unwrap().push(Seen {
            method,
            path,
            headers,
            body,
        });
        let _ = stream.write_all(
            b"HTTP/1.1 406 Missing capability\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return false;
    }
    if path == "/api/v1/protocol" {
        mode.discovery.lock().unwrap().push(Seen {
            method: method.clone(),
            path: path.clone(),
            headers: headers.clone(),
            body: body.clone(),
        });
        // Existing tests describe business traffic. EP-10 negotiation is exercised by the
        // dedicated raw HTTP fixtures; upgrade this helper without changing those assertions.
        let selected: u16 = protocol.as_deref().unwrap_or("2").parse().unwrap();
        let capabilities: Vec<&str> = ["revocations_v1", "zone_catalog_v1", "drain_v1"]
            .into_iter()
            .chain(mode.capabilities.iter().map(String::as_str))
            .collect();
        let reply_body = serde_json::json!({"selected_protocol":selected,"min_protocol":1,"max_protocol":2,"capabilities":capabilities}).to_string();
        let mut reply = Reply::text(200, &reply_body)
            .header("Content-Type", "application/json")
            .header("Lockyard-Protocol", &selected.to_string());
        merge_headers(&mut reply, &mode.default_headers);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
            reply.body.len()
        );
        for (name, value) in &reply.headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }
        response.push_str("\r\n");
        response.push_str(&reply.body);
        return stream.write_all(response.as_bytes()).is_ok();
    }
    log.lock().unwrap().push(Seen {
        method,
        path: path.clone(),
        headers: headers.clone(),
        body,
    });
    let sse = headers
        .iter()
        .any(|(k, v)| k == "accept" && v == "text/event-stream");
    if sse
        && (!path.split('?').nth(1).is_some_and(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .any(|(k, v)| k == "sessions" && !v.is_empty() && v.split(',').count() <= 32)
        }))
    {
        let _ = stream.write_all(
            b"HTTP/1.1 406 Missing sessions\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return false;
    }
    let route = path.split('?').next().unwrap_or(&path);
    let token = headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let selected: Vec<String> = path
        .split('?')
        .nth(1)
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .filter(|(k, _)| k == "sessions")
                .flat_map(|(_, v)| v.split(',').map(str::to_owned).collect::<Vec<_>>())
                .collect()
        })
        .unwrap_or_default();
    if sse && mode.routed && mode.capabilities.iter().any(|c| c == "mail_push_v1") {
        let foreign: Vec<_> = {
            let bindings = mode.bindings.lock().unwrap();
            selected
                .iter()
                .filter(|s| bindings.get(*s) != Some(&token))
                .cloned()
                .collect()
        };
        if !foreign.is_empty() {
            let details = serde_json::json!({"sessions":foreign});
            let body = serde_json::json!({"type":"urn:lockyard:problem:forbidden","status":403,
                "code":"forbidden","detail":"Sessions are not bound to this token.","details":details,
                "error":{"code":"forbidden","message":"Sessions are not bound to this token.","details":details}}).to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            return false;
        }
    }
    let routed_reply = {
        let mut routes = mode.routes.lock().unwrap();
        let key = if sse
            && routes
                .get(&format!("{route}#sse"))
                .is_some_and(|q| !q.is_empty())
        {
            format!("{route}#sse")
        } else {
            route.to_string()
        };
        routes.get_mut(&key).and_then(|queue| {
            // Background JSON session polls must never consume an SSE script.
            if !sse
                && queue.front().is_some_and(|r| {
                    r.headers.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("content-type") && v == "text/event-stream"
                    })
                })
            {
                None
            } else {
                queue.pop_front()
            }
        })
    };
    if sse
        && mode.routed
        && script.lock().unwrap().is_empty()
        && routed_reply.as_ref().is_none_or(|r| {
            r.status == 200
                && r.headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("content-type") && v == "text/event-stream"
                })
        })
    {
        let capability = headers
            .iter()
            .find(|(k, _)| k == "x-lockyard-capabilities")
            .map(|(_, v)| v.as_str());
        let sessions = path
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("sessions=")));
        let valid_sessions = sessions.is_some_and(|value| {
            let decoded = url::form_urlencoded::parse(format!("sessions={value}").as_bytes())
                .next()
                .unwrap()
                .1
                .into_owned();
            !decoded.is_empty() && decoded.split(',').count() <= 32
        });
        if !capability.is_some_and(|v| v.split(',').any(|c| c.trim() == "mail_push_v1"))
            || !valid_sessions
        {
            let _ = stream.write_all(b"HTTP/1.1 406 Contract violation\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return false;
        }
        let after = headers
            .iter()
            .find(|(k, _)| k == "last-event-id")
            .and_then(|(_, v)| v.parse::<i64>().ok())
            .unwrap_or(0);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nLockyard-Protocol: {}\r\n",
            protocol.as_deref().unwrap_or("2")
        );
        for (k, v) in &mode.default_headers {
            response.push_str(&format!("{k}: {v}\r\n"));
        }
        response.push_str("\r\n");
        if stream.write_all(response.as_bytes()).is_err() {
            return false;
        }
        let generation = mode.sse_generation.fetch_add(1, Ordering::AcqRel) + 1;
        {
            let mut streams = mode.streams.lock().unwrap();
            for old in streams.values_mut() {
                if old.token == token && old.sessions.iter().all(|s| selected.contains(s)) {
                    old.replaced_by = Some(generation);
                }
            }
            streams.insert(
                generation,
                FakeStream {
                    token: token.clone(),
                    sessions: selected,
                    replaced_by: None,
                },
            );
        }
        let _lease = StreamGuard {
            streams: &mode.streams,
            id: generation,
        };
        let head = routed_reply
            .as_ref()
            .and_then(|reply| {
                reply
                    .body
                    .lines()
                    .filter_map(|line| {
                        line.strip_prefix("id: ")
                            .and_then(|id| id.parse::<i64>().ok())
                    })
                    .max()
            })
            .unwrap_or(after)
            .max(after);
        let has_ready = routed_reply
            .as_ref()
            .is_some_and(|r| r.body.contains("event: ready"));
        if let Some(reply) = routed_reply {
            thread::sleep(reply.delay);
            if !write_chunk(stream, &reply.body) {
                return false;
            }
        }
        if !has_ready {
            let ready = format!("id: {head}\nevent: ready\ndata: {{\"head\":{head}}}\n\n");
            if !write_chunk(stream, &ready) {
                return false;
            }
        }
        loop {
            let replaced = mode
                .streams
                .lock()
                .unwrap()
                .get(&generation)
                .and_then(|s| s.replaced_by);
            if let Some(by) = replaced {
                let _ = write_chunk(stream, &Reply::replaced(&by.to_string()).body);
                let _ = stream.write_all(b"0\r\n\r\n");
                return false;
            }
            let reply = {
                let mut routes = mode.routes.lock().unwrap();
                routes.get_mut(route).and_then(|queue| {
                    // Refusals belong to the next handshake; JSON pages belong to
                    // concurrent fallback/session polls, never to an old SSE reader.
                    if queue.front().is_some_and(|r| {
                        r.status != 200
                            || !r.headers.iter().any(|(k, v)| {
                                k.eq_ignore_ascii_case("content-type") && v == "text/event-stream"
                            })
                    }) {
                        None
                    } else {
                        queue.pop_front()
                    }
                })
            };
            if let Some(reply) = reply {
                thread::sleep(reply.delay);
                if !write_chunk(stream, &reply.body) {
                    return false;
                }
            } else {
                if mode
                    .routes
                    .lock()
                    .unwrap()
                    .get(route)
                    .is_some_and(|q| !q.is_empty())
                {
                    return false;
                }
                if !write_chunk(stream, ": heartbeat\n\n") {
                    return false;
                }
                thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    let mut reply = routed_reply
        .or_else(|| script.lock().unwrap().pop_front())
        .unwrap_or_else(|| {
            if sse {
                return Reply::sse(": heartbeat\n\n").delay(std::time::Duration::from_millis(20));
            }
            let body = if mode.routed && route == "/api/v1/bus/inbox" {
                let mailboxes = mode.mailboxes.lock().unwrap();
                let session = headers
                    .iter()
                    .find(|(k, _)| k == "x-lockyard-session")
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                let messages: Vec<_> = mailboxes
                    .get(session)
                    .map(|mailbox| {
                        if path.contains("open=true") || path.contains("all=true") {
                            mailbox.open.values().cloned().collect()
                        } else {
                            mailbox.unread.values().cloned().collect()
                        }
                    })
                    .unwrap_or_default();
                serde_json::json!({"messages":messages,"skipped":0}).to_string()
            } else if mode.routed {
                routed_body(&path)
            } else {
                "{}".into()
            };
            Reply {
                status: 200,
                body,
                headers: Vec::new(),
                delay: std::time::Duration::ZERO,
            }
        });
    if mode.routed
        && !sse
        && (200..300).contains(&reply.status)
        && let Some((_, session)) = headers.iter().find(|(k, _)| k == "x-lockyard-session")
    {
        mode.bindings
            .lock()
            .unwrap()
            .entry(session.clone())
            .or_insert(token);
    }
    merge_headers(&mut reply, &mode.default_headers);
    std::thread::sleep(reply.delay);
    if let Some(protocol) = protocol
        && !reply
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Lockyard-Protocol"))
    {
        reply.headers.push(("Lockyard-Protocol".into(), protocol));
    }
    if legacy_namespace
        && !reply
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("X-Lockyard-Repository"))
    {
        reply
            .headers
            .push(("X-Lockyard-Repository".into(), "-".into()));
    }
    let mut response = format!(
        "HTTP/1.1 {} Status\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(&reply.body);
    stream.write_all(response.as_bytes()).is_ok()
}

fn write_chunk(stream: &mut TcpStream, body: &str) -> bool {
    write!(stream, "{:x}\r\n{}\r\n", body.len(), body).is_ok()
}

fn ingest_mail(mailboxes: &mut HashMap<String, MailFixture>, wire: &str) {
    for frame in wire.split("\n\n") {
        let data = frame
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .collect::<Vec<_>>()
            .join("\n");
        let Ok(event) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        let Some(session) = event["session"].as_str() else {
            continue;
        };
        let kind = event["type"].as_str().unwrap_or("");
        let payload = &event["payload"];
        let mailbox = mailboxes.entry(session.into()).or_default();
        if kind == "bus.message" {
            if let Some(parent) = payload["reply_to"].as_i64() {
                mailbox.open.remove(&parent);
            }
            if payload["role"] == "sender" {
                continue;
            }
            let Some(id) = payload["id"].as_i64() else {
                continue;
            };
            if payload["thread_id"].as_i64().is_none() {
                continue;
            }
            mailbox.unread.insert(id, payload.clone());
            if payload["urgent"] == true
                || matches!(payload["needs"].as_str(), Some("reply" | "ack"))
                || (payload["kind"] == "ask" && payload["reply_to"].is_null())
            {
                mailbox.open.insert(id, payload.clone());
            }
        } else {
            let ids = match kind {
                "bus.seen" => payload["seen"].as_array().cloned().unwrap_or_default(),
                "bus.handled" => payload["handled"].as_array().cloned().unwrap_or_default(),
                "bus.ack" => vec![payload["id"].clone()],
                _ => Vec::new(),
            };
            for id in ids.iter().filter_map(Value::as_i64) {
                mailbox.unread.remove(&id);
                mailbox.open.remove(&id);
            }
        }
    }
}
