// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client of the Lockyard Cloud protocol: a synchronous HTTP transport and a [`CloudBackend`] on top.
//!
//! [`Transport`] is the seam between the two. Over HTTP it is [`Client`]; the `lockyard agent` process
//! offers the same seam over its socket, and tests replace it with a fake.

mod backend;
mod crypto;
pub mod device;
#[cfg(test)]
mod fake;

pub use backend::CloudBackend;
pub use crypto::{CONTENT_FIELDS, FieldRule, WorkspaceKey, route_matches, transform_fields};

const ENCRYPTION_PATH: &str = "/api/v1/workspace/encryption";

/// Workspace-level content encryption state returned by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEncryption {
    pub encryption: String,
    pub key_id: Option<String>,
    pub workspace_id: String,
}

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
/// Reserve time for the next request after a `Retry-After` pause.
const RETRY_ROUND_TRIP_ESTIMATE: Duration = Duration::from_secs(1);
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
            Self::Transport(_) | Self::Frozen(_) | Self::Unauthorized(_) => true,
            Self::Http(error) => error.status >= 500 || (300..400).contains(&error.status),
            Self::Decode(_) => true,
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
                if error
                    .message
                    .to_ascii_lowercase()
                    .contains("message key was reused")
                {
                    return Self::Invalid(
                        "message key was reused with a different body; use a new message key"
                            .into(),
                    );
                }
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
    /// How long the caller can wait for this call, including retries, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
    /// Per-request timeout for internal transports such as the agent outbox.
    #[serde(skip)]
    pub attempt_timeout_ms: Option<u64>,
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
    workspace: Option<String>,
    content_key: Option<WorkspaceKey>,
    encryption_enabled: bool,
}

impl Client {
    /// A session name for this machine's own service calls, unique per token (D-3178). The server binds a
    /// session name to the first token that uses it, so a name shared by every token on the machine (agent,
    /// lead, owner, a reissued key) made the second one fail with «already bound to another token».
    pub fn service_session(&self, base: &str) -> String {
        format!("{base}-{}", &token_id(&self.token)[..8])
    }

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
            .redirects(0)
            .build();
        let poll_agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout_read(Duration::from_secs(MAX_POLL_WAIT_SECONDS + 7))
            .redirects(0)
            .build();
        Ok(Self {
            base_url: base_url.into(),
            token,
            agent,
            poll_agent,
            workspace: None,
            content_key: None,
            encryption_enabled: false,
        })
    }

    /// Enables local content encryption for a workspace. The key stays in this process.
    pub fn with_content_encryption(
        mut self,
        workspace: &str,
        key: Option<WorkspaceKey>,
        enabled: bool,
    ) -> Self {
        self.workspace = Some(workspace.to_string());
        self.content_key = key;
        self.encryption_enabled = enabled;
        self
    }

    /// Read the server setting once and configure this client. A 404 means the server predates
    /// the setting endpoint, so the client stays in cleartext compatibility mode.
    pub fn configure_content_encryption(self, session: &str) -> Result<Self, ClientError> {
        let response = match self.call(&Call::get(session, ENCRYPTION_PATH.into())) {
            Ok(value) => value,
            Err(ClientError::NotFound(_)) => return Ok(self),
            Err(error) => return Err(error),
        };
        let setting: WorkspaceEncryption = serde_json::from_value(response).map_err(|error| {
            ClientError::Decode(format!("invalid workspace encryption setting: {error}"))
        })?;
        self.apply_content_encryption(setting)
    }

    /// Configure this client from a setting already known, such as the last one the agent saw.
    pub fn apply_content_encryption(
        self,
        setting: WorkspaceEncryption,
    ) -> Result<Self, ClientError> {
        if !matches!(setting.encryption.as_str(), "off" | "required")
            || (setting.encryption == "required" && setting.key_id.is_none())
        {
            return Err(ClientError::Decode(
                "invalid workspace encryption setting values".into(),
            ));
        }
        let key = WorkspaceKey::load_for_workspace(&setting.workspace_id)
            .map_err(ClientError::Invalid)?;
        if setting.encryption == "required"
            && let (Some(key), Some(expected)) = (&key, setting.key_id.as_deref())
        {
            let actual = key.key_id();
            if actual != expected {
                return Err(ClientError::Invalid(format!(
                    "local encryption key id {actual} does not match workspace key id {expected}"
                )));
            }
        }
        Ok(self.with_content_encryption(
            &setting.workspace_id,
            key,
            setting.encryption == "required",
        ))
    }

    /// Fetch the server's setting without enabling transformations, for encryption management.
    pub fn workspace_encryption(&self, session: &str) -> Result<WorkspaceEncryption, ClientError> {
        serde_json::from_value(self.call(&Call::get(session, ENCRYPTION_PATH.into()))?).map_err(
            |error| ClientError::Decode(format!("invalid workspace encryption setting: {error}")),
        )
    }

    /// Update the workspace setting. The server enforces the owner role.
    pub fn set_workspace_encryption(
        &self,
        session: &str,
        encryption: &str,
        key_id: Option<&str>,
    ) -> Result<Value, ClientError> {
        let body = match (encryption, key_id) {
            ("off", None) => serde_json::json!({"encryption":"off"}),
            ("required", Some(key_id)) => {
                serde_json::json!({"encryption":"required","key_id":key_id})
            }
            _ => {
                return Err(ClientError::Invalid(
                    "invalid workspace encryption update".into(),
                ));
            }
        };
        self.call(&Call::write(session, "POST", ENCRYPTION_PATH.into(), body))
    }

    fn attempt(
        &self,
        call: &Call,
        encoded: Option<&str>,
        remaining: Option<Duration>,
    ) -> Result<Value, Failure> {
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
        // A call without an agent name speaks as this token's own CLI session, never as one name shared by
        // every token on the machine (D-3178).
        let session = if call.session == ANONYMOUS_SESSION {
            self.service_session(ANONYMOUS_SESSION)
        } else {
            call.session.clone()
        };
        request = request
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("X-Lockyard-Session", &session)
            .set(
                "User-Agent",
                concat!("lockyard/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(key) = &call.key {
            request = request.set("Idempotency-Key", key);
        }
        // The caller's remaining wait decides whether a retry fits; it never cuts a request short.
        // A short per-request timeout broke TLS handshakes on macOS ("Resource temporarily
        // unavailable"), so only the outbox's own attempt limit bounds a single request.
        let _ = remaining;
        if let Some(limit) = call.attempt_timeout_ms.map(Duration::from_millis) {
            request = request.timeout(limit);
        }
        let result = match encoded {
            Some(body) => request
                .set("Content-Type", "application/json")
                .send_string(body),
            None => request.call(),
        };
        match result {
            // With redirects off a 3xx arrives as a success. It delivered nothing, so a queued write stays queued.
            Ok(response) if (300..400).contains(&response.status()) => {
                Err(Failure::Final(ClientError::Transport(format!(
                    "the server redirected with status {}",
                    response.status()
                ))))
            }
            Ok(response) => decode(response).map_err(Failure::Retry),
            Err(ureq::Error::Status(status, response)) => {
                let retry_after = response
                    .header("Retry-After")
                    .and_then(|value| value.parse::<u64>().ok());
                let body = response.into_string().unwrap_or_default();
                let error = ClientError::from_api(ApiError::parse(status, &body, retry_after));
                // A frozen server stays frozen for its whole window: the caller decides what to do.
                let again = status == 429
                    || (300..400).contains(&status)
                    || (status >= 500 && status != 503);
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
        let mut body = call.body.clone();
        if let (Some(value), Some(workspace)) = (&mut body, self.workspace.as_deref()) {
            transform_fields(
                value,
                &call.method,
                &call.path,
                workspace,
                self.content_key.as_ref(),
                self.encryption_enabled,
            )
            .map_err(ClientError::Invalid)?;
        }
        let encoded = body.as_ref().map(Value::to_string);
        // Only writes have a key that makes repeating safe. A caller deadline controls which
        // rate-limit retries fit; it does not disable them outright.
        // A read may repeat once when the connection itself failed, before anything was sent.
        let attempts = if call.is_write() { WRITE_ATTEMPTS } else { 2 };
        let started = std::time::Instant::now();
        let mut delay = Duration::from_millis(100);
        for attempt in 1..=attempts {
            let remaining = call
                .deadline_ms
                .map(|limit| Duration::from_millis(limit).saturating_sub(started.elapsed()));
            if remaining.is_some_and(|remaining| remaining.is_zero()) {
                return Err(ClientError::Transport("call deadline elapsed".into()));
            }
            match self.attempt(call, encoded.as_deref(), remaining) {
                Ok(mut value) => {
                    if let Some(workspace) = self.workspace.as_deref() {
                        transform_fields(
                            &mut value,
                            &call.method,
                            &call.path,
                            workspace,
                            self.content_key.as_ref(),
                            false,
                        )
                        .map_err(ClientError::Invalid)?;
                    }
                    return Ok(value);
                }
                Err(Failure::Final(error))
                    if call.deadline_ms.is_some()
                        && call.is_write()
                        && matches!(
                            &error,
                            ClientError::Frozen(_) | ClientError::RateLimited(_)
                        )
                        && attempt < attempts =>
                {
                    if !wait_fits_deadline(call.deadline_ms, started, &error, delay) {
                        return Err(error);
                    }
                    let wait = retry_wait(&error, delay);
                    thread::sleep(wait);
                    delay *= 2;
                }
                Err(Failure::Final(error)) => return Err(error),
                Err(Failure::Retry(error)) if attempt == attempts => return Err(error),
                Err(Failure::Retry(error)) => {
                    // Writes repeat under their idempotency key; a read repeats only a failed
                    // connection. With a caller deadline, only a wait that fits is taken.
                    let repeatable = match &error {
                        ClientError::Transport(_) => true,
                        _ => call.is_write(),
                    };
                    if !repeatable
                        || (call.deadline_ms.is_some()
                            && !wait_fits_deadline(call.deadline_ms, started, &error, delay))
                    {
                        return Err(error);
                    }
                    thread::sleep(retry_wait(&error, delay));
                    delay *= 2;
                }
            }
        }
        Err(ClientError::Transport("request retry limit reached".into()))
    }
}

fn retry_wait(error: &ClientError, fallback: Duration) -> Duration {
    error
        .retry_after()
        .map(Duration::from_secs)
        .unwrap_or(fallback)
        .min(MAX_RETRY_WAIT)
}

fn wait_fits_deadline(
    deadline_ms: Option<u64>,
    started: std::time::Instant,
    error: &ClientError,
    fallback: Duration,
) -> bool {
    let Some(deadline_ms) = deadline_ms else {
        return true;
    };
    let remaining = Duration::from_millis(deadline_ms).saturating_sub(started.elapsed());
    retry_wait(error, fallback).saturating_add(RETRY_ROUND_TRIP_ESTIMATE) <= remaining
}

fn allowed_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return false;
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed
            .split_once(']')
            .map(|(host, _)| host)
            .unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    matches!(host, "localhost" | "127.0.0.1")
}

/// The session name the CLI and MCP fall back to when no agent is named.
pub const ANONYMOUS_SESSION: &str = "lockyard-cli";

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
    use std::sync::Mutex;

    static KEY_ENV: Mutex<()> = Mutex::new(());

    struct KeyEnv {
        previous: Option<std::ffi::OsString>,
        path: std::path::PathBuf,
    }
    impl KeyEnv {
        fn new() -> Self {
            let previous = std::env::var_os("XDG_CONFIG_HOME");
            let path = std::env::temp_dir().join(format!("lockyard-test-{}", ulid()));
            unsafe { std::env::set_var("XDG_CONFIG_HOME", &path) };
            Self { previous, path }
        }
    }
    impl Drop for KeyEnv {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                unsafe { std::env::set_var("XDG_CONFIG_HOME", value) };
            } else {
                unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn setting(mode: &str, key_id: Option<&str>) -> Reply {
        Reply::json(
            200,
            json!({"encryption":mode,"key_id":key_id,"workspace_id":"123e4567-e89b-12d3-a456-426614174000"}),
        )
    }

    #[test]
    fn setting_off_leaves_content_clear() {
        let _lock = KEY_ENV.lock().unwrap();
        let _env = KeyEnv::new();
        let server = FakeServer::start(vec![
            setting("off", None),
            Reply::json(200, json!({"body":"plain"})),
        ]);
        let client = Client::new(&server.url(), "secret".into())
            .unwrap()
            .configure_content_encryption("a")
            .unwrap();
        let result = client
            .call(&Call::write(
                "a",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"body":"plain"}),
            ))
            .unwrap();
        assert_eq!(result["body"], "plain");
        assert_eq!(server.requests()[1].body["body"], "plain");
    }

    #[test]
    fn required_setting_encrypts_requests_and_decrypts_replies() {
        let _lock = KEY_ENV.lock().unwrap();
        let _env = KeyEnv::new();
        let (key, _) = WorkspaceKey::generate().unwrap();
        key.store_for_workspace("123e4567-e89b-12d3-a456-426614174000")
            .unwrap();
        let envelope = key
            .encrypt(
                "123e4567-e89b-12d3-a456-426614174000",
                "body",
                "reply clear",
            )
            .unwrap();
        let server = FakeServer::start(vec![
            setting("required", Some(&key.key_id())),
            Reply::json(200, json!({"body":envelope})),
        ]);
        let client = Client::new(&server.url(), "secret".into())
            .unwrap()
            .configure_content_encryption("a")
            .unwrap();
        let result = client
            .call(&Call::write(
                "a",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"body":"send clear"}),
            ))
            .unwrap();
        assert_eq!(result["body"], "reply clear");
        let wire = &server.requests()[1].body["body"];
        assert!(wire.as_str().unwrap().starts_with("lyenc1."));
        assert_eq!(
            key.decrypt(
                "123e4567-e89b-12d3-a456-426614174000",
                "body",
                wire.as_str().unwrap()
            )
            .unwrap(),
            "send clear"
        );
    }

    #[test]
    fn required_setting_without_key_refuses_content_write() {
        let _lock = KEY_ENV.lock().unwrap();
        let _env = KeyEnv::new();
        let server = FakeServer::start(vec![
            setting("required", Some("expected")),
            Reply::json(
                200,
                json!({"messages":[{"body":"lyenc1.unavailable.payload"}]}),
            ),
        ]);
        let client = Client::new(&server.url(), "secret".into())
            .unwrap()
            .configure_content_encryption("a")
            .unwrap();
        let inbox = client
            .call(&Call::get("a", "/api/v1/bus/inbox".into()))
            .unwrap();
        assert_eq!(inbox["messages"][0]["body"], "[locked]");
        let error = client
            .call(&Call::write(
                "a",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"body":"plain"}),
            ))
            .unwrap_err();
        assert!(error.to_string().contains("lockyard cloud key import"));
        // The setting and the inbox were read; the refused write never left the client.
        assert_eq!(server.requests().len(), 2);
    }

    #[test]
    fn required_setting_rejects_a_mismatched_local_key_id() {
        let _lock = KEY_ENV.lock().unwrap();
        let _env = KeyEnv::new();
        let (key, _) = WorkspaceKey::generate().unwrap();
        key.store_for_workspace("123e4567-e89b-12d3-a456-426614174000")
            .unwrap();
        let server = FakeServer::start(vec![setting("required", Some("server-key-id"))]);
        let result = Client::new(&server.url(), "secret".into())
            .unwrap()
            .configure_content_encryption("a");
        let Err(error) = result else {
            panic!("mismatched key id was accepted")
        };
        let message = error.to_string();
        assert!(message.contains(&key.key_id()), "{message}");
        assert!(message.contains("server-key-id"), "{message}");
    }

    #[test]
    fn older_server_without_setting_route_keeps_cleartext_compatibility() {
        let server = FakeServer::start(vec![
            Reply::json(404, json!({"message":"missing"})),
            Reply::json(200, json!({"body":"plain"})),
        ]);
        let client = Client::new(&server.url(), "secret".into())
            .unwrap()
            .configure_content_encryption("a")
            .unwrap();
        let result = client
            .call(&Call::write(
                "a",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"body":"plain"}),
            ))
            .unwrap();
        assert_eq!(result["body"], "plain");
        assert_eq!(server.requests()[1].body["body"], "plain");
    }

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
        assert!(Client::new("http://localhost@127.0.0.1:9000", "t".into()).is_err());
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
    fn a_reused_message_key_gets_mail_specific_guidance() {
        let error = ApiError {
            status: 409,
            message: "Message key was reused with another body.".into(),
            ..ApiError::default()
        };
        let text = CoreError::from(ClientError::Conflict(error)).to_string();
        assert!(text.contains("use a new message key"));
        assert!(!text.contains("zone list"));
        assert!(!text.contains(".."));
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
    fn a_rate_limited_write_keeps_retry_after_and_idempotency_key() {
        let server = FakeServer::start(vec![
            Reply::json(
                429,
                json!({"error": {"code": "limit", "message": "slow down"}}),
            )
            .header("Retry-After", "0"),
            Reply::json(200, json!({"ok": true})),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let call = Call::write(
            "same-session",
            "POST",
            "/api/v1/registry/items".into(),
            json!({}),
        );
        assert_eq!(client.call(&call).unwrap()["ok"], true);
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].header("idempotency-key"),
            requests[1].header("idempotency-key")
        );
        assert_eq!(
            requests[0].header("x-lockyard-session"),
            Some("same-session")
        );
        assert_eq!(
            requests[1].header("x-lockyard-session"),
            Some("same-session")
        );
    }

    #[test]
    fn a_rate_limited_write_retries_when_retry_after_fits_the_callers_budget() {
        let server = FakeServer::start(vec![
            Reply::json(429, json!({})).header("Retry-After", "1"),
            Reply::json(200, json!({"ok": true})),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let mut call = Call::write("s", "POST", "/api/v1/registry/items".into(), json!({}));
        call.deadline_ms = Some(3_000);

        assert_eq!(client.call(&call).unwrap()["ok"], true);
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].header("idempotency-key"),
            requests[1].header("idempotency-key")
        );
    }

    #[test]
    fn a_read_is_not_repeated_after_the_server_answered() {
        let server = FakeServer::start(vec![
            Reply::json(429, json!({})).header("Retry-After", "1"),
            Reply::json(200, json!({"ok": true})),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let mut call = Call::get("s", "/api/v1/zones/claims".into());
        call.deadline_ms = Some(5_000);
        assert!(client.call(&call).is_err());
        // Only a failed connection repeats a read; an answer from the server never does.
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_rate_limited_write_fails_without_retry_when_retry_after_exceeds_the_budget() {
        let server = FakeServer::start(vec![
            Reply::json(
                429,
                json!({"error": {"code": "limit", "message": "slow down"}}),
            )
            .header("Retry-After", "5"),
            Reply::json(200, json!({"ok": true})),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let mut call = Call::write("s", "POST", "/api/v1/registry/items".into(), json!({}));
        call.deadline_ms = Some(3_000);

        assert!(matches!(
            client.call(&call),
            Err(ClientError::RateLimited(_))
        ));
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_rate_limited_event_waiter_receives_retry_after_without_a_write_retry() {
        let server = FakeServer::start(vec![
            Reply::json(
                429,
                json!({"error": {"code": "waiters", "message": "too many waiters"}}),
            )
            .header("Retry-After", "17"),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let mut call = Call::get("worker-session", "/api/v1/events?wait=25".into());
        call.long_poll = true;
        assert_eq!(client.call(&call).unwrap_err().retry_after(), Some(17));
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_403_session_conflict_is_reported_and_token_rotation_keeps_the_session_name() {
        let server = FakeServer::start(vec![
            Reply::json(
                403,
                json!({"error": {"code": "session_owned", "message": "session belongs to another token"}}),
            ),
            Reply::json(200, json!({"ok": true})),
        ]);
        let active = Client::new(&server.url(), "active-token".into()).unwrap();
        let rotated = Client::new(&server.url(), "rotated-token".into()).unwrap();
        let call = Call::write(
            "worker-session",
            "POST",
            "/api/v1/zones/claims".into(),
            json!({}),
        );
        assert!(matches!(active.call(&call), Err(ClientError::Denied(_))));
        assert_eq!(rotated.call(&call).unwrap()["ok"], true);
        let requests = server.requests();
        assert_eq!(
            requests.len(),
            2,
            "403 must not be retried with a renamed session"
        );
        assert!(
            requests
                .iter()
                .all(|request| request.header("x-lockyard-session") == Some("worker-session"))
        );
    }

    #[test]
    fn a_redirect_is_never_followed_and_stays_retryable() {
        let server = FakeServer::start(vec![
            Reply::text(307, "").header("Location", "http://example.test/moved"),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let call = Call::write("a", "POST", "/api/v1/bus/messages".into(), json!({}));
        let error = client.call(&call).unwrap_err();
        assert!(error.is_outage(), "{error:?}");
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
    fn two_tokens_on_one_machine_get_different_service_sessions() {
        // D-3178: one name per machine was bound by the first token and refused every other one.
        let agent = Client::new("https://example.test", "agent-token".into()).unwrap();
        let lead = Client::new("https://example.test", "lead-token".into()).unwrap();
        let again = Client::new("https://example.test", "agent-token".into()).unwrap();
        assert_ne!(
            agent.service_session("lockyard-agent-501"),
            lead.service_session("lockyard-agent-501")
        );
        assert_eq!(
            agent.service_session("lockyard-agent-501"),
            again.service_session("lockyard-agent-501")
        );
        assert!(
            agent
                .service_session("lockyard-cli")
                .starts_with("lockyard-cli-")
        );
        assert!(
            !agent
                .service_session("lockyard-cli")
                .contains("agent-token")
        );
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode("src/a b"), "src%2Fa%20b");
        assert_eq!(encode("a-b_c.d~"), "a-b_c.d~");
    }
}
