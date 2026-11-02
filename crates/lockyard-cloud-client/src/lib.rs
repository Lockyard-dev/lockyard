// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Synchronous HTTP transport for Lockyard Cloud protocol v1.

use serde::Serialize;
use serde_json::Value;
use std::fmt;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub enum ClientError {
    Invalid(String),
    Http(u16, String),
    Transport(String),
    Decode(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(text) | Self::Transport(text) | Self::Decode(text) => f.write_str(text),
            Self::Http(code, text) => write!(f, "cloud returned HTTP {code}: {text}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Cloud connection credentials. Tokens are passed by the caller and are never persisted here.
pub struct Client {
    base_url: String,
    token: String,
    workspace: String,
    session: String,
    agent: ureq::Agent,
    poll_agent: ureq::Agent,
}

impl Client {
    pub fn new(base_url: &str, token: String, workspace: &str, session: &str) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/');
        if !(base_url.starts_with("https://") || base_url.starts_with("http://localhost") || base_url.starts_with("http://127.0.0.1")) {
            return Err(ClientError::Invalid("cloud URL must use HTTPS (HTTP is allowed for localhost)".into()));
        }
        if token.is_empty() || workspace.is_empty() || session.is_empty() {
            return Err(ClientError::Invalid("token, workspace and session are required".into()));
        }
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(2)).timeout_read(Duration::from_secs(5)).build();
        let poll_agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(2)).timeout_read(Duration::from_secs(32)).build();
        Ok(Self { base_url: base_url.into(), token, workspace: workspace.into(), session: session.into(), agent, poll_agent })
    }

    pub fn workspace(&self) -> &str { &self.workspace }

    /// Sends a protocol request. All writes require a stable idempotency key.
    pub fn request<T: Serialize>(&self, method: &str, path: &str, body: Option<&T>, idempotency_key: Option<&str>, long_poll: bool) -> Result<Value, ClientError> {
        let write = !matches!(method, "GET" | "HEAD");
        if write && idempotency_key.is_none_or(str::is_empty) {
            return Err(ClientError::Invalid("writes require an Idempotency-Key".into()));
        }
        if !path.starts_with("/") || path.contains("..") {
            return Err(ClientError::Invalid("request path must be an absolute API path".into()));
        }
        let url = format!("{}{}", self.base_url, path);
        let encoded = body.map(serde_json::to_string).transpose().map_err(|error| ClientError::Decode(error.to_string()))?;
        let attempts = if write || idempotency_key.is_some() { 3 } else { 1 };
        let client = if long_poll { &self.poll_agent } else { &self.agent };
        let mut delay = 100;
        for attempt in 0..attempts {
            let mut request = match method {
                "GET" => client.get(&url),
                "POST" => client.post(&url),
                "PUT" => client.put(&url),
                "DELETE" => client.delete(&url),
                _ => return Err(ClientError::Invalid(format!("unsupported HTTP method {method}"))),
            };
            request = request.set("Authorization", &format!("Bearer {}", self.token))
                .set("X-Lockyard-Session", &self.session)
                .set("X-Lockyard-Workspace", &self.workspace)
                .set("User-Agent", concat!("lockyard/", env!("CARGO_PKG_VERSION")));
            if let Some(key) = idempotency_key { request = request.set("Idempotency-Key", key); }
            let result = if let Some(body) = &encoded { request.set("Content-Type", "application/json").send_string(body) } else { request.call() };
            match result {
                Ok(response) => return decode(response),
                Err(ureq::Error::Status(code, response)) => {
                    let message = response.into_string().unwrap_or_default();
                    if matches!(code, 401 | 403 | 404 | 409) || !(code == 429 || code >= 500) || attempt + 1 == attempts {
                        return Err(ClientError::Http(code, message));
                    }
                    if !write && idempotency_key.is_none() { return Err(ClientError::Http(code, message)); }
                }
                Err(error) if attempt + 1 < attempts && (write || idempotency_key.is_some()) => {
                    let _ = error;
                }
                Err(error) => return Err(ClientError::Transport(error.to_string())),
            }
            thread::sleep(Duration::from_millis(delay));
            delay *= 2;
        }
        Err(ClientError::Transport("request retry limit reached".into()))
    }
}

fn decode(response: ureq::Response) -> Result<Value, ClientError> {
    let text = response.into_string().map_err(|error| ClientError::Transport(error.to_string()))?;
    if text.is_empty() { return Ok(Value::Null); }
    serde_json::from_str(&text).map_err(|error| ClientError::Decode(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn sends_workspace_session_user_agent_and_idempotency_key() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let count = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..count]);
                if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") { break; }
            }
            let request = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(request.contains("idempotency-key: key-1"));
            assert!(request.contains("x-lockyard-session: agent-a"));
            assert!(request.contains("x-lockyard-workspace: team"));
            assert!(request.contains("user-agent: lockyard/"));
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
            stream.write_all(response.as_bytes()).unwrap();
        });
        let client = Client::new(&format!("http://{address}"), "secret".into(), "team", "agent-a").unwrap();
        let body = serde_json::json!({"client":"cli"});
        let result = client.request("POST", "/api/v1/presence", Some(&body), Some("key-1"), false).unwrap();
        server.join().unwrap();
        assert_eq!(result["ok"], true);
    }

    #[test]
    fn rejects_writes_without_a_key_and_rejects_authentication_urls() {
        let client = Client::new("http://127.0.0.1:9000", "secret".into(), "team", "agent-a").unwrap();
        let body = serde_json::json!({});
        assert!(matches!(client.request("POST", "/api/v1/bus/messages", Some(&body), None, false), Err(ClientError::Invalid(_))));
        assert!(Client::new("https://example.test", "".into(), "team", "agent-a").is_err());
    }
}
