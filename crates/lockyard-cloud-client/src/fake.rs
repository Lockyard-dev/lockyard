// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A small HTTP server for tests: it answers from a script and records what it was asked.

use serde_json::Value;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
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
}

pub struct FakeServer {
    address: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl FakeServer {
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
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let mode = Arc::new(ServeMode {
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
            seen,
            stop,
            worker: Some(worker),
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address)
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
    if path == "/api/v1/protocol" {
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
        headers,
        body,
    });
    let mut reply = script.lock().unwrap().pop_front().unwrap_or_else(|| {
        let body = if mode.routed {
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
