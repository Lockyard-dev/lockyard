// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A small HTTP server for tests: it answers from a script and records what it was asked.

use serde_json::Value;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
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

pub struct FakeServer {
    address: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeServer {
    /// Serves `script` in order. Requests past the end get `{}`.
    pub fn start(script: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let (log, script) = (Arc::clone(&log), Arc::clone(&script));
                thread::spawn(move || answer(stream, &log, &script));
            }
        });
        Self { address, seen }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn answer(mut stream: TcpStream, log: &Mutex<Vec<Seen>>, script: &Mutex<VecDeque<Reply>>) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
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
            Ok(0) | Err(_) => break,
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
        let reply = serde_json::json!({"selected_protocol":selected,"min_protocol":1,"max_protocol":2,"capabilities":["revocations_v1","zone_catalog_v1","drain_v1"]}).to_string();
        let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLockyard-Protocol: {selected}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",reply.len()).as_bytes());
        return;
    }
    log.lock().unwrap().push(Seen {
        method,
        path,
        headers,
        body,
    });
    let mut reply = script.lock().unwrap().pop_front().unwrap_or(Reply {
        status: 200,
        body: "{}".into(),
        headers: Vec::new(),
        delay: std::time::Duration::ZERO,
    });
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
        "HTTP/1.1 {} Status\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(&reply.body);
    let _ = stream.write_all(response.as_bytes());
}
