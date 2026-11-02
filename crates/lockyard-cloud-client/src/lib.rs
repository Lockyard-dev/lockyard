// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client of the Lockyard Cloud protocol: a synchronous HTTP transport and a [`CloudBackend`] on top.
//!
//! [`Transport`] is the seam between the two. Over HTTP it is [`Client`]; the `lockyard agent` process
//! offers the same seam over its socket, and tests replace it with a fake.

mod backend;
#[cfg(test)]
mod fake;

pub use backend::CloudBackend;

use lockyard_core::Error as CoreError;
use lockyard_core::proto::PathCheck;
use lockyard_core::zones::Conflict;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A write is sent at most this many times with one key.
const WRITE_ATTEMPTS: u32 = 3;
/// A retry waits at most this long, whatever `Retry-After` says. A caller with more patience loops.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(5);
/// Longest wait of a long poll, in seconds.
pub const MAX_POLL_WAIT_SECONDS: u64 = 25;

/// The error envelope of the protocol, with the status and `Retry-After` of its response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
    pub retry_after: Option<u64>,
}

impl ApiError {
    /// Reads a failed response. A body that is not the envelope becomes the message.
    pub fn parse(status: u16, body: &str, retry_after: Option<u64>) -> Self {
        let parsed = serde_json::from_str::<Value>(body).ok();
        let envelope = parsed.as_ref().and_then(|value| value.get("error"));
        let text = |key: &str| {
            envelope
                .and_then(|error| error.get(key))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        // A registry 422 from model binding is `{message}` with no envelope around it.
        let bare = parsed
            .as_ref()
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let message = bare.unwrap_or_else(|| text("message"));
        Self {
            status,
            code: text("code"),
            message: if message.is_empty() {
                body.to_string()
            } else {
                message
            },
            details: envelope
                .and_then(|error| error.get("details"))
                .cloned()
                .unwrap_or(Value::Null),
            retry_after,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "HTTP {}", self.status)
        } else {
            f.write_str(&self.message)
        }
    }
}

/// Why a call failed. Crosses the agent socket as JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientError {
    Invalid(String),
    /// 401.
    Unauthorized(ApiError),
    /// 403.
    Denied(ApiError),
    /// 404, also for a record of another workspace.
    NotFound(ApiError),
    /// 409.
    Conflict(ApiError),
    /// 412: the caller's fence is out of date.
    StaleFence(ApiError),
    /// 429.
    RateLimited(ApiError),
    /// 503: coordination writes are frozen.
    Frozen(ApiError),
    /// Any other status.
    Http(ApiError),
    /// The server did not answer.
    Transport(String),
    /// The server answered with something unreadable.
    Decode(String),
}

impl ClientError {
    /// Sorts a failed response by status.
    pub fn from_api(error: ApiError) -> Self {
        match error.status {
            401 => Self::Unauthorized(error),
            403 => Self::Denied(error),
            404 => Self::NotFound(error),
            409 => Self::Conflict(error),
            412 => Self::StaleFence(error),
            429 => Self::RateLimited(error),
            503 => Self::Frozen(error),
            _ => Self::Http(error),
        }
    }

    /// True when the same request may work later, so an outbox entry stays queued.
    pub fn is_outage(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Frozen(_) | Self::RateLimited(_) | Self::Unauthorized(_) => {
                true
            }
            Self::Http(error) => error.status >= 500,
            _ => false,
        }
    }

    /// Seconds the server asked to wait.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Frozen(error) | Self::RateLimited(error) => error.retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(text) | Self::Transport(text) | Self::Decode(text) => f.write_str(text),
            Self::Unauthorized(error)
            | Self::Denied(error)
            | Self::NotFound(error)
            | Self::Conflict(error)
            | Self::StaleFence(error)
            | Self::RateLimited(error)
            | Self::Frozen(error) => error.fmt(f),
            Self::Http(error) => write!(f, "cloud returned HTTP {}: {error}", error.status),
        }
    }
}

impl std::error::Error for ClientError {}

/// Holders named by a 409, if the response lists any.
fn holders(error: &ApiError) -> Vec<Conflict> {
    let Some(list) = error.details.get("conflicts").and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|entry| serde_json::from_value(entry.clone()).ok())
        .collect()
}

impl From<ClientError> for CoreError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Invalid(text) => Self::Invalid(text),
            ClientError::Unauthorized(error) => {
                Self::Denied(format!("the server refused the token: {error}"))
            }
            ClientError::Denied(error) => Self::Denied(error.to_string()),
            ClientError::NotFound(error) => Self::NotFound(error.to_string()),
            ClientError::Conflict(error) => {
                let conflicts = holders(&error);
                if conflicts.is_empty() {
                    Self::Contended(contended_text(&error))
                } else {
                    Self::Conflict(conflicts)
                }
            }
            ClientError::StaleFence(error) => Self::StaleFence(error.to_string()),
            ClientError::Frozen(error) => Self::Frozen(error.to_string()),
            ClientError::RateLimited(error) => Self::Unavailable(format!("rate limited: {error}")),
            ClientError::Http(error) if error.status == 400 || error.status == 422 => {
                Self::Invalid(error.to_string())
            }
            ClientError::Http(error) => Self::Unavailable(error.to_string()),
            ClientError::Transport(text) => Self::Unavailable(text),
            ClientError::Decode(text) => Self::Protocol(text),
        }
    }
}

fn contended_text(error: &ApiError) -> String {
    let mut text = error.to_string();
    if let Some(version) = error.details.get("version") {
        text.push_str(&format!(" (current version {version})"));
    }
    if let Some(first) = error.details.get("priority_of") {
        text.push_str(&format!(" (reserved for {first})"));
    }
    text
}

/// One request of the protocol.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub session: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// Idempotency key. Required on every write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default)]
    pub long_poll: bool,
    /// When set, the whole call is one attempt inside this many milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

impl Call {
    /// A read.
    pub fn get(session: &str, path: String) -> Self {
        Self {
            session: session.into(),
            method: "GET".into(),
            path,
            ..Self::default()
        }
    }

    /// A write under a fresh idempotency key.
    pub fn write(session: &str, method: &str, path: String, body: Value) -> Self {
        Self {
            session: session.into(),
            method: method.into(),
            path,
            body: Some(body),
            key: Some(ulid()),
            ..Self::default()
        }
    }

    /// True when this call changes server state. Only `zones/check` is a POST that reads.
    pub fn is_write(&self) -> bool {
        self.method != "GET"
            && self.method != "HEAD"
            && !self.path.starts_with("/api/v1/zones/check")
    }
}

/// How requests reach the server.
pub trait Transport: Send + Sync {
    fn call(&self, call: &Call) -> Result<Value, ClientError>;

    /// A check answered without a server round trip, when this transport can do that.
    fn fast_check(
        &self,
        _session: &str,
        _paths: &[String],
    ) -> Option<Result<Vec<PathCheck>, ClientError>> {
        None
    }

    /// An unread count answered without a server round trip. `Some(Ok(None))` means unknown.
    fn fast_unread(&self, _session: &str) -> Option<Result<Option<i64>, ClientError>> {
        None
    }
}

impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        (**self).call(call)
    }

    fn fast_check(
        &self,
        session: &str,
        paths: &[String],
    ) -> Option<Result<Vec<PathCheck>, ClientError>> {
        (**self).fast_check(session, paths)
    }

    fn fast_unread(&self, session: &str) -> Option<Result<Option<i64>, ClientError>> {
        (**self).fast_unread(session)
    }
}

/// HTTP transport. The token is passed in by the caller and never stored by this crate.
pub struct Client {
    base_url: String,
    token: String,
    agent: ureq::Agent,
    poll_agent: ureq::Agent,
}

impl Client {
    pub fn new(base_url: &str, token: String) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/');
        if !allowed_url(base_url) {
            return Err(ClientError::Invalid(
                "cloud URL must use HTTPS (HTTP is allowed for localhost)".into(),
            ));
        }
        if token.is_empty() {
            return Err(ClientError::Invalid("a token is required".into()));
        }
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout_read(Duration::from_secs(5))
            .build();
        let poll_agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout_read(Duration::from_secs(MAX_POLL_WAIT_SECONDS + 7))
            .build();
        Ok(Self {
            base_url: base_url.into(),
            token,
            agent,
            poll_agent,
        })
    }

    fn attempt(&self, call: &Call, encoded: Option<&str>) -> Result<Value, Failure> {
        let url = format!("{}{}", self.base_url, call.path);
        let client = if call.long_poll {
            &self.poll_agent
        } else {
            &self.agent
        };
        let mut request = match call.method.as_str() {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "DELETE" => client.delete(&url),
            other => {
                return Err(Failure::Final(ClientError::Invalid(format!(
                    "unsupported HTTP method {other}"
                ))));
            }
        };
        request = request
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("X-Lockyard-Session", &call.session)
            .set(
                "User-Agent",
                concat!("lockyard/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(key) = &call.key {
            request = request.set("Idempotency-Key", key);
        }
        if let Some(limit) = call.deadline_ms {
            request = request.timeout(Duration::from_millis(limit));
        }
        let result = match encoded {
            Some(body) => request
                .set("Content-Type", "application/json")
                .send_string(body),
            None => request.call(),
        };
        match result {
            Ok(response) => decode(response).map_err(Failure::Final),
            Err(ureq::Error::Status(status, response)) => {
                let retry_after = response
                    .header("Retry-After")
                    .and_then(|value| value.parse::<u64>().ok());
                let body = response.into_string().unwrap_or_default();
                let error = ClientError::from_api(ApiError::parse(status, &body, retry_after));
                // A frozen server stays frozen for its whole window: the caller decides what to do.
                let again = status == 429 || (status >= 500 && status != 503);
                Err(if again {
                    Failure::Retry(error)
                } else {
                    Failure::Final(error)
                })
            }
            Err(error) => Err(Failure::Retry(ClientError::Transport(error.to_string()))),
        }
    }
}

enum Failure {
    Retry(ClientError),
    Final(ClientError),
}

impl Transport for Client {
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        if call.is_write() && call.key.as_deref().is_none_or(str::is_empty) {
            return Err(ClientError::Invalid(
                "writes require an Idempotency-Key".into(),
            ));
        }
        if !call.path.starts_with('/') || call.path.contains("..") {
            return Err(ClientError::Invalid(
                "request path must be an absolute API path".into(),
            ));
        }
        let encoded = call.body.as_ref().map(Value::to_string);
        // Only a write has a key that makes a repeat safe, and a deadline leaves no room for one.
        let attempts = if call.is_write() && call.deadline_ms.is_none() {
            WRITE_ATTEMPTS
        } else {
            1
        };
        let mut delay = Duration::from_millis(100);
        for attempt in 1..=attempts {
            match self.attempt(call, encoded.as_deref()) {
                Ok(value) => return Ok(value),
                Err(Failure::Final(error)) => return Err(error),
                Err(Failure::Retry(error)) if attempt == attempts => return Err(error),
                Err(Failure::Retry(error)) => {
                    let asked = error.retry_after().map(Duration::from_secs);
                    thread::sleep(asked.unwrap_or(delay).min(MAX_RETRY_WAIT));
                    delay *= 2;
                }
            }
        }
        Err(ClientError::Transport("request retry limit reached".into()))
    }
}

fn allowed_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or_default();
    matches!(host, "localhost" | "127.0.0.1")
}

/// A short name for a token, so that a client can tell whether the agent process runs under the same one.
/// It identifies, it does not protect: the socket is private to this user already.
pub fn token_id(token: &str) -> String {
    let hash = token.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{hash:016x}")
}

fn decode(response: ureq::Response) -> Result<Value, ClientError> {
    let lines = response
        .content_type()
        .eq_ignore_ascii_case("application/x-ndjson");
    let text = response
        .into_string()
        .map_err(|error| ClientError::Transport(error.to_string()))?;
    if text.is_empty() {
        return Ok(Value::Null);
    }
    if lines {
        // The registry event stream is one JSON record per line.
        return text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<Value>, _>>()
            .map(Value::Array)
            .map_err(|error| ClientError::Decode(error.to_string()));
    }
    serde_json::from_str(&text).map_err(|error| ClientError::Decode(error.to_string()))
}

/// Makes a ULID: 48 bits of milliseconds, then 80 random bits, in Crockford base 32.
pub fn ulid() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let keyed = RandomState::new();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let high = u128::from(keyed.hash_one(count));
    let low = u128::from(keyed.hash_one(!count));
    let random = ((high << 64) | low) & ((1_u128 << 80) - 1);
    let value = (millis << 80) | random;
    (0..26_u32)
        .rev()
        .map(|digit| {
            let index = usize::try_from((value >> (digit * 5)) & 31).unwrap_or(0);
            char::from(ALPHABET[index])
        })
        .collect()
}

/// Percent-encodes one query value or path segment.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeServer, Reply};
    use serde_json::json;

    #[test]
    fn sends_session_user_agent_and_idempotency_key_without_workspace_header() {
        let server = FakeServer::start(vec![Reply::json(200, json!({"ok": true}))]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let mut call = Call::write(
            "agent-a",
            "POST",
            "/api/v1/presence".into(),
            json!({"client": "cli"}),
        );
        call.key = Some("key-1".into());
        assert_eq!(client.call(&call).unwrap()["ok"], true);
        let request = server.requests().remove(0);
        assert_eq!(request.header("idempotency-key"), Some("key-1"));
        assert_eq!(request.header("x-lockyard-session"), Some("agent-a"));
        assert_eq!(request.header("authorization"), Some("Bearer secret"));
        assert_eq!(request.header("x-lockyard-workspace"), None);
        assert!(
            request
                .header("user-agent")
                .unwrap()
                .starts_with("lockyard/")
        );
    }

    #[test]
    fn refuses_a_write_without_a_key_and_a_plain_http_host() {
        let client = Client::new("http://127.0.0.1:9000", "secret".into()).unwrap();
        let mut call = Call::write("a", "POST", "/api/v1/bus/messages".into(), json!({}));
        call.key = None;
        assert!(matches!(client.call(&call), Err(ClientError::Invalid(_))));
        assert!(Client::new("https://example.test", String::new()).is_err());
        assert!(Client::new("http://example.test", "t".into()).is_err());
        assert!(Client::new("http://localhost.example.test", "t".into()).is_err());
        assert!(Client::new("http://localhost:8080/", "t".into()).is_ok());
    }

    #[test]
    fn a_zone_check_is_a_read_and_needs_no_key() {
        let check = Call {
            method: "POST".into(),
            path: "/api/v1/zones/check".into(),
            ..Call::default()
        };
        assert!(!check.is_write());
        assert!(Call::write("a", "POST", "/api/v1/zones/claims".into(), json!({})).is_write());
        assert!(!Call::get("a", "/api/v1/bus/inbox".into()).is_write());
    }

    #[test]
    fn maps_protocol_statuses_to_distinct_errors() {
        type Case = (u16, fn(&ClientError) -> bool);
        let cases: [Case; 7] = [
            (401, |error| matches!(error, ClientError::Unauthorized(_))),
            (403, |error| matches!(error, ClientError::Denied(_))),
            (404, |error| matches!(error, ClientError::NotFound(_))),
            (409, |error| matches!(error, ClientError::Conflict(_))),
            (412, |error| matches!(error, ClientError::StaleFence(_))),
            (503, |error| matches!(error, ClientError::Frozen(_))),
            (400, |error| matches!(error, ClientError::Http(_))),
        ];
        for (status, expected) in cases {
            let body = json!({"error": {"code": "x", "message": "refused", "details": {}}});
            let server = FakeServer::start(vec![Reply::json(status, body)]);
            let client = Client::new(&server.url(), "secret".into()).unwrap();
            let error = client
                .call(&Call::get("a", "/api/v1/bus/inbox".into()))
                .unwrap_err();
            assert!(expected(&error), "{status}: {error:?}");
            assert!(error.to_string().contains("refused"));
        }
    }

    #[test]
    fn the_core_error_keeps_each_mapping() {
        let api = |status, details| ApiError {
            status,
            message: "m".into(),
            details,
            ..ApiError::default()
        };
        let held = json!({"conflicts": [{"path": "src", "session": "a", "claim_id": 4, "note": "n", "expires_at": "t"}]});
        let conflict = CoreError::from(ClientError::Conflict(api(409, held)));
        let CoreError::Conflict(list) = conflict else {
            panic!("expected holders")
        };
        assert_eq!((list[0].agent.as_str(), list[0].claim), ("a", 4));
        let version = CoreError::from(ClientError::Conflict(api(409, json!({"version": 3}))));
        assert!(matches!(&version, CoreError::Contended(text) if text.contains("version 3")));
        let priority = CoreError::from(ClientError::Conflict(api(
            409,
            json!({"priority_of": "first"}),
        )));
        assert!(matches!(&priority, CoreError::Contended(text) if text.contains("first")));
        assert!(matches!(
            CoreError::from(ClientError::StaleFence(api(412, Value::Null))),
            CoreError::StaleFence(_)
        ));
        assert!(matches!(
            CoreError::from(ClientError::Frozen(api(503, Value::Null))),
            CoreError::Frozen(_)
        ));
        assert!(matches!(
            CoreError::from(ClientError::Denied(api(403, Value::Null))),
            CoreError::Denied(_)
        ));
        assert!(matches!(
            CoreError::from(ClientError::NotFound(api(404, Value::Null))),
            CoreError::NotFound(_)
        ));
        assert!(matches!(
            CoreError::from(ClientError::Transport("x".into())),
            CoreError::Unavailable(_)
        ));
    }

    #[test]
    fn a_frozen_write_is_not_retried_and_keeps_retry_after() {
        let server = FakeServer::start(vec![
            Reply::json(503, json!({})).header("Retry-After", "120"),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let call = Call::write("a", "POST", "/api/v1/bus/messages".into(), json!({}));
        let error = client.call(&call).unwrap_err();
        assert_eq!(error.retry_after(), Some(120));
        assert!(error.is_outage());
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_failed_write_is_repeated_under_the_same_key() {
        let server = FakeServer::start(vec![
            Reply::json(500, json!({})),
            Reply::json(200, json!({"id": 1})),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let call = Call::write("a", "POST", "/api/v1/bus/messages".into(), json!({}));
        assert_eq!(client.call(&call).unwrap()["id"], 1);
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].header("idempotency-key"),
            requests[1].header("idempotency-key")
        );
    }

    #[test]
    fn a_call_with_a_deadline_gets_one_attempt() {
        let server = FakeServer::start(vec![
            Reply::json(500, json!({})),
            Reply::json(200, json!({})),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let mut call = Call::write("a", "POST", "/api/v1/bus/messages".into(), json!({}));
        call.deadline_ms = Some(500);
        assert!(client.call(&call).is_err());
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_definite_refusal_is_not_an_outage() {
        let api = |status| ApiError {
            status,
            ..ApiError::default()
        };
        assert!(!ClientError::Conflict(api(409)).is_outage());
        assert!(!ClientError::NotFound(api(404)).is_outage());
        assert!(!ClientError::Http(api(400)).is_outage());
        assert!(ClientError::Http(api(502)).is_outage());
        assert!(ClientError::Transport("down".into()).is_outage());
    }

    #[test]
    fn ulids_are_26_crockford_characters_and_differ() {
        let (first, second) = (ulid(), ulid());
        assert_ne!(first, second);
        assert_eq!(first.len(), 26);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_digit() || (c.is_ascii_uppercase() && !"ILOU".contains(c)))
        );
    }

    #[test]
    fn a_bare_message_from_the_registry_is_read() {
        let error = ApiError::parse(422, r#"{"message":"bad request"}"#, None);
        assert_eq!(error.message, "bad request");
    }

    #[test]
    fn the_registry_stream_reads_one_record_per_line() {
        let body = "{\"seq\":1,\"op\":\"created\"}\n{\"seq\":2,\"op\":\"claimed\"}\n";
        let server = FakeServer::start(vec![
            Reply::text(200, body).header("Content-Type", "application/x-ndjson; charset=utf-8"),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let value = client
            .call(&Call::get("a", "/api/v1/registry/events".into()))
            .unwrap();
        assert_eq!(value[1]["seq"], 2);
    }

    #[test]
    fn a_token_id_is_stable_and_tells_tokens_apart() {
        assert_eq!(token_id("a"), token_id("a"));
        assert_ne!(token_id("a"), token_id("b"));
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode("src/a b"), "src%2Fa%20b");
        assert_eq!(encode("a-b_c.d~"), "a-b_c.d~");
    }
}
