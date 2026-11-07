// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client of the Lockyard Cloud protocol: a synchronous HTTP transport and a [`CloudBackend`] on top.
//!
//! [`Transport`] is the seam between the two. Over HTTP it is [`Client`]; the `lockyard agent` process
//! offers the same seam over its socket, and tests replace it with a fake.

mod backend;
pub mod catalog;
mod catalog_client;
mod crypto;
pub mod device;
#[cfg(test)]
mod fake;
pub mod protocol;
mod registry;
mod repository;
pub mod revocations;

pub use backend::CloudBackend;
pub use crypto::{CONTENT_FIELDS, FieldRule, WorkspaceKey, route_matches, transform_fields};
pub use protocol::{NegotiatedProtocol, PendingWrite, Problem, ProtocolRange};
pub use repository::RepositoryTransport;

const ENCRYPTION_PATH: &str = "/api/v1/workspace/encryption";

/// Workspace-level content encryption state returned by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        protocol::parse_api_error(status, body, retry_after).unwrap_or_else(|_| Self {
            status,
            code: "protocol_response_invalid".into(),
            message: "contradictory or malformed cloud error envelope".into(),
            retry_after,
            ..Self::default()
        })
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
    /// A stable protocol failure without an invented HTTP status.
    Protocol(Problem),
    /// The exact mutation is retained until its outcome can be reconciled.
    OutcomeUnknown(Box<PendingWrite>),
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
        if error.status == 429 && error.code != "rate_limited" {
            return Self::Http(error);
        }
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
            Self::Transport(_) => true,
            Self::Frozen(error) => matches!(
                error.code.as_str(),
                "" | "frozen" | "server_draining" | "temporarily_unavailable"
            ),
            Self::Unauthorized(_) => false,
            Self::Http(error) => {
                error.code.is_empty() && (error.status >= 500 || (300..400).contains(&error.status))
            }
            Self::Decode(_) => true,
            _ => false,
        }
    }

    /// Seconds the server asked to wait.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Frozen(error) | Self::RateLimited(error) | Self::Http(error) => error.retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(problem) => write!(f, "{}: {}", problem.code, problem.detail),
            Self::OutcomeUnknown(pending) => write!(f, "outcome_unknown: {}", pending.cause_code),
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
        if let Some(problem) = error.problem() {
            return Self::Cloud {
                code: problem.code,
                status: problem.status,
                details: problem.details,
                message: problem.detail,
            };
        }
        match error {
            ClientError::Protocol(_) | ClientError::OutcomeUnknown(_) => {
                unreachable!("protocol problem handled above")
            }
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
    /// Repository scope for zone operations. Empty means the legacy namespace; absent is aggregate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
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
    /// Keep frozen bytes until the caller has durably completed its outbox entry.
    #[serde(default)]
    pub defer_pending_ack: bool,
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

    /// Called only after a durable caller has committed its successful outbox receipt.
    fn acknowledge_write(&self, _call: &Call) -> Result<(), ClientError> {
        Ok(())
    }

    /// Named zones are expanded at the same authenticated SDK boundary as their catalog.
    fn catalog_expand(&self, call: &Call, names: &[String]) -> Result<Vec<String>, ClientError> {
        let catalog = self.call(call)?;
        // Transports must explicitly provide their authenticated/legacy adapter. The default
        // accepts only the strict local schema and never infers trust from serialized markers.
        let catalog = lockyard_core::catalog::ZoneCatalogV1::from_json(&catalog.to_string())
            .map_err(|error| protocol::local(error.code(), error.code()))?;
        catalog
            .expand(names)
            .map_err(|error| protocol::local(error.code(), error.code()))
    }

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

    fn acknowledge_write(&self, call: &Call) -> Result<(), ClientError> {
        (**self).acknowledge_write(call)
    }

    fn catalog_expand(&self, call: &Call, names: &[String]) -> Result<Vec<String>, ClientError> {
        (**self).catalog_expand(call, names)
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
    expected_e2ee_workspace: Option<String>,
    protocol_state: std::sync::Mutex<protocol::ProtocolState>,
    pending_journal: Option<std::path::PathBuf>,
    catalog_cache_root: Option<std::path::PathBuf>,
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
        let force = match std::env::var("LOCKYARD_REQUIRE_E2EE") {
            Ok(value) if matches!(value.as_str(), "1" | "true") => true,
            Ok(value) if matches!(value.as_str(), "" | "0" | "false") => false,
            Err(std::env::VarError::NotPresent) => false,
            _ => {
                return Err(ClientError::Invalid(
                    "invalid required encryption policy".into(),
                ));
            }
        };
        let expected_e2ee_workspace = match std::env::var("LOCKYARD_E2EE_WORKSPACE_ID") {
            Ok(value) if valid_workspace_identity(&value) => Some(value),
            Err(std::env::VarError::NotPresent) if !force => None,
            _ => {
                return Err(ClientError::Invalid(
                    "required encryption needs a valid bound workspace identity".into(),
                ));
            }
        };
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
            expected_e2ee_workspace,
            protocol_state: std::sync::Mutex::new(protocol::ProtocolState::default()),
            pending_journal: None,
            catalog_cache_root: None,
        })
    }

    /// Require encryption independently of the legacy server preference, bound to this workspace.
    pub fn require_e2ee_for(mut self, workspace: &str) -> Result<Self, ClientError> {
        if !valid_workspace_identity(workspace) {
            return Err(ClientError::Invalid(
                "invalid required encryption workspace identity".into(),
            ));
        }
        if self
            .expected_e2ee_workspace
            .as_deref()
            .is_some_and(|expected| expected != workspace)
        {
            return Err(ClientError::Invalid(
                "required encryption workspace cannot be rebound".into(),
            ));
        }
        self.expected_e2ee_workspace = Some(workspace.to_string());
        Ok(self)
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

    /// Read the server setting once. Only legacy clients may use cleartext compatibility
    /// when the endpoint is absent; a node job requires a verified workspace and local key.
    pub fn configure_content_encryption(self, session: &str) -> Result<Self, ClientError> {
        let response = match self.call(&Call::get(session, ENCRYPTION_PATH.into())) {
            Ok(value) => value,
            Err(ClientError::NotFound(_)) if self.expected_e2ee_workspace.is_none() => {
                return Ok(self);
            }
            Err(ClientError::NotFound(_)) => {
                return Err(ClientError::Invalid(
                    "required node encryption cannot verify this server's workspace policy".into(),
                ));
            }
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
        if let Some(expected) = &self.expected_e2ee_workspace
            && expected != &setting.workspace_id
        {
            return Err(ClientError::Invalid(
                "workspace identity differs from the node encryption context".into(),
            ));
        }
        if !matches!(setting.encryption.as_str(), "off" | "required")
            || (setting.encryption == "required" && setting.key_id.is_none())
        {
            return Err(ClientError::Decode(
                "invalid workspace encryption setting values".into(),
            ));
        }
        let key = WorkspaceKey::load_for_workspace(&setting.workspace_id)
            .map_err(ClientError::Invalid)?;
        let required = setting.encryption == "required" || self.expected_e2ee_workspace.is_some();
        if self.expected_e2ee_workspace.is_some() && key.is_none() {
            return Err(ClientError::Invalid(
                "required node workspace encryption key is unavailable".into(),
            ));
        }
        if required && let (Some(key), Some(expected)) = (&key, setting.key_id.as_deref()) {
            let actual = key.key_id();
            if actual != expected {
                return Err(ClientError::Invalid(format!(
                    "local encryption key id {actual} does not match workspace key id {expected}"
                )));
            }
        }
        Ok(self.with_content_encryption(&setting.workspace_id, key, required))
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
        protocol: &NegotiatedProtocol,
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
        if !protocol.legacy {
            request = request.set("Lockyard-Protocol", &protocol.selected.to_string());
        }
        if let Some(key) = &call.key {
            request = request.set("Idempotency-Key", key);
        }
        if let Some(repository) = &call.repository {
            request = request.set(
                "X-Lockyard-Repository",
                if repository.is_empty() {
                    "-"
                } else {
                    repository
                },
            );
        }
        // The caller's remaining wait decides whether a retry fits; it never cuts a request short.
        // A short per-request timeout broke TLS handshakes on macOS ("Resource temporarily
        // unavailable"), so only the outbox's own attempt limit bounds a single request.
        if let Some(limit) = remaining {
            request = request.timeout(limit);
        }
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
            Ok(response) => {
                protocol::verify_echo(&response, protocol).map_err(Failure::Final)?;
                protocol::verify_repository_echo(&response, call, protocol)
                    .map_err(Failure::Final)?;
                decode_for_call(response, call, self.encryption_enabled).map_err(Failure::Retry)
            }
            Err(ureq::Error::Status(status, response)) => {
                let retry_after = response
                    .header("Retry-After")
                    .and_then(|value| value.parse::<u64>().ok());
                let echo = protocol::verify_echo(&response, protocol);
                let body = response.into_string().unwrap_or_default();
                let mut api_error = protocol::parse_api_error(status, &body, retry_after)
                    .map_err(Failure::Final)?;
                if protocol.selected >= 2
                    && !protocol.legacy
                    && api_error.code.is_empty()
                    && !(call.path == "/api/v1/protocol" && matches!(status, 404 | 405))
                {
                    return Err(Failure::Final(protocol::local(
                        "protocol_response_invalid",
                        "modern error response omits its stable code",
                    )));
                }
                if !matches!(
                    api_error.code.as_str(),
                    "protocol_invalid" | "protocol_unsupported"
                ) && !(call.path == "/api/v1/protocol" && matches!(status, 404 | 405))
                {
                    echo.map_err(Failure::Final)?;
                }
                if let Some(workspace) = self.workspace.as_deref() {
                    crypto::transform_error_details(
                        &mut api_error.details,
                        workspace,
                        self.content_key.as_ref(),
                        self.expected_e2ee_workspace.is_some(),
                    )
                    .map_err(|message| Failure::Final(ClientError::Invalid(message)))?;
                }
                if self.expected_e2ee_workspace.is_some() {
                    // Error messages are server-authored text, not authenticated application content.
                    api_error.message = format!("Cloud request failed with HTTP {status}");
                }
                let error = ClientError::from_api(api_error);
                // A frozen server stays frozen for its whole window: the caller decides what to do.
                let again = protocol::safe_retry(&error);
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
    fn catalog_expand(&self, call: &Call, names: &[String]) -> Result<Vec<String>, ClientError> {
        self.expand_catalog_call(call, names)
    }
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        self.call_negotiated(call)
    }

    fn acknowledge_write(&self, call: &Call) -> Result<(), ClientError> {
        let Some(key) = &call.key else {
            return Ok(());
        };
        let _send = self.claim_pending_send(key)?;
        let Some(pending) = self.pending_operation(key) else {
            return Ok(());
        };
        let Some(request_digest) = pending.request_digest.as_deref() else {
            // Older journals have only encrypted wire bytes. They cannot establish that an
            // acknowledgement of a plaintext caller operation describes the same write.
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        };
        if pending.method != call.method
            || pending.request_path != call.path
            || request_digest != request_identity(call)
        {
            return Err(protocol::local(
                "idempotency_conflict",
                "acknowledgement does not match the pending operation",
            ));
        }
        self.resolve_pending(key)?;
        Ok(())
    }
}

/// Bind the caller's operation before content encryption or legacy wire adaptation. Operational
/// timeout/defer settings may change after restart without changing the acknowledged mutation.
pub(crate) fn request_identity(call: &Call) -> String {
    let encoded = serde_json::to_vec(&(
        &call.method,
        &call.path,
        &call.session,
        &call.repository,
        &call.body,
    ))
    .expect("request identity consists only of serializable JSON values");
    ring::digest::digest(&ring::digest::SHA256, &encoded)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn valid_workspace_identity(workspace: &str) -> bool {
    !workspace.is_empty()
        && workspace.len() <= 64
        && workspace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
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

/// Bind durable operation receipts to a credential without storing its value.
/// This fingerprint is not an authentication token and must never replace authorization.
pub fn credential_fingerprint(token: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_for_call(
    response: ureq::Response,
    call: &Call,
    required_catalog: bool,
) -> Result<Value, ClientError> {
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
    let value: Value =
        serde_json::from_str(&text).map_err(|error| ClientError::Decode(error.to_string()))?;
    if call.path.split('?').next() == Some("/api/v1/zones/catalog")
        && (required_catalog || value.get("format").is_some() || value.get("revision").is_some())
    {
        lockyard_core::catalog::CoordinationZoneCatalog::from_json(&text)
            .map_err(|error| protocol::local("catalog_invalid", &error.to_string()))?;
    }
    Ok(value)
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

    #[test]
    fn default_catalog_transport_strictly_validates_complete_catalog_before_expansion() {
        struct Catalog(Value);
        impl Transport for Catalog {
            fn call(&self, _: &Call) -> Result<Value, ClientError> {
                Ok(self.0.clone())
            }
        }
        let call = Call::get("me", "/api/v1/zones/catalog".into());
        // A transport without the SDK's authentication override cannot interpret legacy objects
        // or bless the SDK's serialized `verified` marker as an authenticated capability.
        for value in [
            json!({"zones":{"good":{"paths":["src"]}}}),
            json!({"zones":{"good":["src"]}}),
            json!({"version":1,"zones":{"good":["src",17]}}),
            json!({"version":1,"zones":{"good":["src"],"bad":[]}}),
            json!({"version":1,"zones":{"good":["src"]},"groups":{"all":["absent"]}}),
            json!({"format":"lockyard.zone_catalog.v1","verified":true,"zones":{"good":["src"]}}),
        ] {
            assert_eq!(
                Catalog(value)
                    .catalog_expand(&call, &["good".into()])
                    .unwrap_err()
                    .code(),
                Some("catalog_invalid")
            );
        }
        let strict =
            Catalog(json!({"version":1,"zones":{"good":["src"]},"groups":{"all":["good"]}}));
        assert_eq!(
            strict.catalog_expand(&call, &["all".into()]).unwrap(),
            ["src"]
        );
        assert_eq!(
            strict
                .catalog_expand(&call, &["absent".into()])
                .unwrap_err()
                .code(),
            Some("zone_unknown")
        );
    }

    #[test]
    fn default_catalog_transport_preserves_stable_expansion_errors() {
        struct Catalog;
        impl Transport for Catalog {
            fn call(&self, _: &Call) -> Result<Value, ClientError> {
                Ok(serde_json::json!({"version":1,"zones":{"good":["src"]}}))
            }
        }
        let call = Call::get("me", "/api/v1/zones/catalog".into());
        for (name, code) in [("missing", "zone_unknown"), ("bad", "catalog_invalid")] {
            let server = FakeServer::start(vec![Reply::json(
                200,
                json!({"zones":{"good":["src"],"bad":{}}}),
            )]);
            let client = Client::new(&server.url(), "fixture".into()).unwrap();
            let error = client.catalog_expand(&call, &[name.into()]).unwrap_err();
            assert_eq!(error.code(), Some(code), "optional legacy Client branch");
            assert_eq!(error.status(), None);
        }
        assert_eq!(
            Catalog.catalog_expand(&call, &["good".into()]).unwrap(),
            ["src"]
        );
        let error = Catalog
            .catalog_expand(&call, &["missing".into()])
            .unwrap_err();
        assert_eq!(error.code(), Some("zone_unknown"));
        assert_eq!(error.status(), None);
    }

    use crate::fake::{FakeServer, Reply};
    use serde_json::json;
    use std::sync::Mutex;

    static KEY_ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn encrypted_claims_and_queue_send_paths_without_catalog_labels() {
        let workspace = "00000000-0000-0000-0000-000000000001";
        for route in ["/api/v1/zones/claims", "/api/v1/zones/queue"] {
            let server = FakeServer::start(vec![Reply::json(200, json!({}))]);
            let client = Client::new(&server.url(), "fixture-token".into())
                .unwrap()
                .with_content_encryption(
                    workspace,
                    Some(WorkspaceKey::from_entropy([7; 32])),
                    true,
                );
            client.call(&Call::write("session", "POST", route.into(), json!({
                "paths":["src"],"note":"","zone":"PRIVATE-ZONE-CANARY","zones":["PRIVATE-GROUP-CANARY"]
            }))).unwrap();
            let request = &server.requests()[0];
            assert_eq!(request.body["paths"], json!(["src"]));
            assert!(
                request.body.get("zone").is_none(),
                "{route}: singular label must stay local"
            );
            assert!(
                request.body.get("zones").is_none(),
                "{route}: plural labels must stay local"
            );
        }
    }

    #[test]
    fn required_node_accepts_typed_catalog_event_metadata_and_rejects_extra_content() {
        let workspace = "00000000-0000-0000-0000-000000000001";
        let key = WorkspaceKey::from_entropy([7; 32]);
        for repository in ["api", ""] {
            let event = json!({"seq":1,"type":"zone.catalog","payload":{
                "repository":repository,"revision":1,"format":"lockyard.zone_catalog.v1",
                "key_id":key.key_id(),"content_sha256":"11".repeat(32),"updated_at":"2026-11-07T00:00:00.000Z"
            }});
            for (extra, allowed) in [(false, true), (true, false)] {
                let mut event = event.clone();
                if extra {
                    event["payload"]["future_content"] = json!("PRIVATE-CONTENT");
                }
                let server = FakeServer::start(vec![Reply::json(200, json!([event]))]);
                let client = Client::new(&server.url(), "fixture-token".into())
                    .unwrap()
                    .require_e2ee_for(workspace)
                    .unwrap()
                    .with_content_encryption(workspace, Some(key.clone()), true);
                assert_eq!(
                    client
                        .call(&Call::get("session", "/api/v1/events".into()))
                        .is_ok(),
                    allowed
                );
            }
        }
    }

    #[test]
    fn required_node_preserves_strict_protocol_and_catalog_error_metadata() {
        for mut details in [
            json!({"min_protocol":1,"max_protocol":2,"supported_protocols":[1,2],"selected_protocol":null}),
            json!({"current_revision":7}),
        ] {
            let original = details.clone();
            crypto::transform_error_details(&mut details, NODE_WORKSPACE, None, true).unwrap();
            assert_eq!(details, original);
            details["future_content"] = json!("PRIVATE-CONTENT");
            assert!(
                crypto::transform_error_details(&mut details, NODE_WORKSPACE, None, true).is_err()
            );
        }
        for mut details in [
            json!({"min_protocol":0}),
            json!({"supported_protocols":[1,1]}),
            json!({"supported_protocols":[1,2,3]}),
            json!({"current_revision":9007199254740992_u64}),
        ] {
            assert!(
                crypto::transform_error_details(&mut details, NODE_WORKSPACE, None, true).is_err()
            );
        }
    }

    struct KeyEnv {
        previous: Option<std::ffi::OsString>,
        path: std::path::PathBuf,
    }
    impl KeyEnv {
        fn new() -> Self {
            let previous = std::env::var_os("XDG_CONFIG_HOME");
            // Key storage rejects symlinked parents; macOS commonly spells its temp root via /var.
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("lockyard-test-{}", ulid()));
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

    const NODE_WORKSPACE: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn forced_client(server: &FakeServer, key: WorkspaceKey) -> Client {
        Client::new(&server.url(), "fixture-token".into())
            .unwrap()
            .require_e2ee_for(NODE_WORKSPACE)
            .unwrap()
            .with_content_encryption(NODE_WORKSPACE, Some(key), true)
    }

    #[test]
    fn node_context_encrypts_even_when_legacy_setting_is_off() {
        let _lock = KEY_ENV.lock().unwrap();
        let _env = KeyEnv::new();
        let key = WorkspaceKey::from_entropy([83; 32]);
        key.store_for_workspace(NODE_WORKSPACE).unwrap();
        let envelope = key
            .encrypt(NODE_WORKSPACE, "body", "private reply")
            .unwrap();
        let server = FakeServer::start(vec![
            setting("off", None),
            Reply::json(200, json!({"body":envelope})),
        ]);
        let client = Client::new(&server.url(), "fixture-token".into())
            .unwrap()
            .require_e2ee_for(NODE_WORKSPACE)
            .unwrap()
            .configure_content_encryption("node-job")
            .unwrap();
        let response = client
            .call(&Call::write(
                "node-job",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"body":"private prompt"}),
            ))
            .unwrap();
        assert_eq!(response["body"], "private reply");
        let requests = server.requests();
        let wire = requests[1].body["body"].as_str().unwrap();
        assert!(wire.starts_with("lyenc1."));
        assert_eq!(
            key.decrypt(NODE_WORKSPACE, "body", wire).unwrap(),
            "private prompt"
        );
        assert!(!requests[1].body.to_string().contains("private prompt"));
    }

    #[test]
    fn node_context_refuses_missing_policy_key_or_wrong_workspace() {
        let _lock = KEY_ENV.lock().unwrap();
        let _env = KeyEnv::new();
        for reply in [
            Reply::json(
                404,
                json!({"error":{"code":"not_found","message":"policy endpoint absent"}}),
            ),
            setting("off", None),
            Reply::json(
                200,
                json!({"encryption":"off","workspace_id":"another-workspace","key_id":null}),
            ),
        ] {
            let server = FakeServer::start(vec![reply]);
            let error = Client::new(&server.url(), "fixture-token".into())
                .unwrap()
                .require_e2ee_for(NODE_WORKSPACE)
                .unwrap()
                .configure_content_encryption("node-job")
                .err()
                .unwrap();
            assert!(matches!(error, ClientError::Invalid(_)));
            assert_eq!(server.requests().len(), 1);
        }
    }

    #[test]
    fn node_context_cannot_be_disabled_or_rebound_by_legacy_builder() {
        let key = WorkspaceKey::from_entropy([84; 32]);
        let server = FakeServer::start(vec![]);
        for client in [
            forced_client(&server, key.clone()).with_content_encryption(
                NODE_WORKSPACE,
                Some(key.clone()),
                false,
            ),
            forced_client(&server, key.clone()).with_content_encryption(
                "another-workspace",
                Some(key),
                true,
            ),
        ] {
            assert!(
                client
                    .call(&Call::get("node-job", "/api/v1/bus/inbox".into()))
                    .is_err()
            );
        }
        assert!(server.requests().is_empty());
    }

    #[test]
    fn node_context_refuses_plaintext_or_unauthenticated_content_responses() {
        for (body, authentication_failure) in [
            (json!({"messages":[{"body":"plaintext from cloud"}]}), false),
            (
                json!({"messages":[{"body":"lyenc1.invalid.envelope"}]}),
                true,
            ),
            (json!({"messages":[{"body":{"nested":"plaintext"}}]}), false),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, body)]);
            let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
            let error = client
                .call(&Call::get("node-job", "/api/v1/bus/inbox".into()))
                .expect_err("required content must never expose unverified plaintext");
            if authentication_failure {
                assert_eq!(error.code(), Some("content_authentication_failed"));
                assert_eq!(error.status(), None);
            } else {
                assert!(matches!(error, ClientError::Invalid(_)), "{error:?}");
            }
            assert_eq!(server.requests().len(), 1);
        }
    }

    #[test]
    fn node_context_rejects_unclassified_legacy_response_metadata() {
        for meta in [
            json!({"code":"legacy content"}),
            json!("legacy content"),
            json!({}),
        ] {
            for (path, body) in [
                ("/api/v1/zones/claims", json!([{"meta":meta}])),
                ("/api/v1/zones/queue", json!([{"meta":meta}])),
                (
                    "/api/v1/events",
                    json!([{"type":"zone.claimed","payload":{"meta":meta}}]),
                ),
                (
                    "/api/v1/events",
                    json!([{"type":"zone.queued","payload":{"meta":meta}}]),
                ),
            ] {
                let server = FakeServer::start(vec![Reply::json(200, body)]);
                let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
                assert!(
                    matches!(
                        client.call(&Call::get("node-job", path.into())),
                        Err(ClientError::Invalid(_))
                    ),
                    "{path}"
                );
                assert_eq!(server.requests().len(), 1);
            }
        }
        for (path, body) in [
            (
                "/api/v1/zones/claims",
                json!([{"meta":null,"hold_until_ref":null}]),
            ),
            ("/api/v1/zones/queue", json!([{"meta":null}])),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, body)]);
            let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
            assert!(
                client.call(&Call::get("node-job", path.into())).is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn node_context_validates_nested_response_shapes_and_metadata_events() {
        for (path, body) in [
            (
                "/api/v1/registry/items",
                json!({"items":[],"future_content":"private"}),
            ),
            (
                "/api/v1/registry/items",
                json!({"items":[{"assignment":{"session":"worker","future_content":"private"}}]}),
            ),
            (
                "/api/v1/registry/items",
                json!({"items":[{"assignment":{"session":{"code":"private"}}}]}),
            ),
            (
                "/api/v1/events",
                json!([{"type":"bus.unread","payload":{"to":"member","future_content":"private"}}]),
            ),
            (
                "/api/v1/events",
                json!([{"type":"zone.claimed","payload":{"claim_id":{"code":"private"}}}]),
            ),
            (
                "/api/v1/zones/catalog",
                json!({"zones":{},"future_content":"private"}),
            ),
            ("/api/v1/zones/claims", json!("private")),
        ] {
            let reply = if path == "/api/v1/zones/catalog" {
                Reply::json(200, body).header("X-Lockyard-Repository", "-")
            } else {
                Reply::json(200, body)
            };
            let server = FakeServer::start(vec![reply]);
            let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
            let result = client.call(&Call::get("node-job", path.into()));
            // EP-07 gives the typed catalog its own stable validation code.
            if path == "/api/v1/zones/catalog" {
                assert_eq!(result.unwrap_err().code(), Some("catalog_invalid"));
                assert_eq!(server.requests().len(), 1);
                continue;
            }
            assert!(matches!(result, Err(ClientError::Invalid(_))), "{path}");
            assert_eq!(server.requests().len(), 1);
        }
        for event in [
            json!({"type":"bus.unread","payload":{"to":"member"}}),
            json!({"type":"bus.seen","payload":{"seen":[17,"message-id"]}}),
            json!({"type":"presence.heartbeat","payload":{"session":"member","state":"working","last_seen":"2026-11-07T07:00:00.1234567+00:00"}}),
            json!({"type":"zone.claimed","payload":{"claim_id":17,"session":"member","paths":["src"],"note":"","reason":"claimed","fence":1}}),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, json!([event]))]);
            let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
            assert!(
                client
                    .call(&Call::get("node-job", "/api/v1/events".into()))
                    .is_ok()
            );
        }
    }

    #[test]
    fn node_context_preserves_safe_presence_metadata_and_authenticated_legacy_content() {
        let safe = json!({"level":"ok","load":0.5,"cpus":4});
        for (method, path, response) in [
            (
                "POST",
                "/api/v1/presence",
                json!({"meta":safe,"activity":{"tool_running":true,"meta":safe}}),
            ),
            (
                "GET",
                "/api/v1/presence",
                json!([{"meta":safe,"activity":{"tool_running":true,"meta":safe}}]),
            ),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, response.clone())]);
            let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
            let call = if method == "POST" {
                Call::write(
                    "node-job",
                    method,
                    path.into(),
                    json!({"client":"fixture","activity":{"tool_running":true,"meta":safe}}),
                )
            } else {
                Call::get("node-job", path.into())
            };
            assert_eq!(client.call(&call).unwrap(), response);
        }
        for response in [
            json!([{"meta":{"code":"private"}}]),
            json!([{"activity":{"meta":{"code":"private"}}}]),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, response)]);
            let client = forced_client(&server, WorkspaceKey::from_entropy([85; 32]));
            assert!(
                client
                    .call(&Call::get("node-job", "/api/v1/presence".into()))
                    .is_err()
            );
        }
        let key = WorkspaceKey::from_entropy([85; 32]);
        let encrypted = key
            .encrypt(NODE_WORKSPACE, "legacy_raw", "private legacy content")
            .unwrap();
        let server = FakeServer::start(vec![Reply::json(
            200,
            json!({"items":[{"legacy_raw":encrypted,"assignment":{"session":"worker","lease_active":true,"released_at":null}}]}),
        )]);
        let client = forced_client(&server, key);
        assert_eq!(
            client
                .call(&Call::get("node-job", "/api/v1/registry/items".into()))
                .unwrap()["items"][0]["legacy_raw"],
            "private legacy content"
        );
    }

    #[test]
    fn node_context_reads_backend_identifiers_enums_and_nested_dirty_content() {
        let key = WorkspaceKey::from_entropy([85; 32]);
        let note = key.encrypt(NODE_WORKSPACE, "note", "private note").unwrap();
        let reason = key
            .encrypt(NODE_WORKSPACE, "reason", "private dirty reason")
            .unwrap();
        let title = key
            .encrypt(NODE_WORKSPACE, "title", "private title")
            .unwrap();
        let body = key
            .encrypt(NODE_WORKSPACE, "body", "private message")
            .unwrap();
        let stamp = "2026-11-07T07:00:00.1234567+00:00";
        for (path, response, field, expected) in [
            (
                "/api/v1/zones/claims",
                json!([{"id":1,"session":"worker","paths":["src"],"mode":"exclusive","purpose":"work","note":note,"fence":1,"created_at":stamp,"expires_at":stamp,"version":1,"meta":null,"hold_until_ref":null,"foreign_dirty_paths":[{"path":"src/dirty","owner_session":"other","reported_by":"other","reason":reason,"task_id":17,"foreign":true,"created_at":stamp,"updated_at":stamp,"holder_session":"worker","repository":null}]}]),
                "note",
                "private note",
            ),
            (
                "/api/v1/zones/queue",
                json!([{"id":2,"session":"worker","paths":["src"],"mode":"exclusive","purpose":"work","note":note,"priority_of":1,"add_path_claim_id":1,"meta":null}]),
                "note",
                "private note",
            ),
            (
                "/api/v1/registry/items",
                json!({"items":[{"id":"D-1","type":"code","priority":"P2","status":"ready","target":"ci_passed","verification":"auto","sealed":false,"title":title,"assignment":{"session":"worker","lease_active":true,"claimed_at":stamp,"released_at":null}}]}),
                "title",
                "private title",
            ),
            (
                "/api/v1/bus/inbox",
                json!({"messages":[{"id":7,"thread_id":1,"in_reply_to":null,"from_session":"other","to":"worker","kind":"info","needs":"none","body":body,"created_at":stamp,"status":"unread","version":1}]}),
                "body",
                "private message",
            ),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, response)]);
            let client = forced_client(&server, key.clone());
            let result = client.call(&Call::get("node-job", path.into())).unwrap();
            let item = if result.is_array() {
                &result[0]
            } else if path.contains("registry") {
                &result["items"][0]
            } else {
                &result["messages"][0]
            };
            assert_eq!(item[field], expected, "{path}");
            if path.ends_with("claims") {
                assert_eq!(
                    item["foreign_dirty_paths"][0]["reason"],
                    "private dirty reason"
                );
            }
        }
    }

    #[test]
    fn node_context_blocks_query_and_structured_content_bypasses_before_http() {
        let server = FakeServer::start(vec![]);
        let client = forced_client(&server, WorkspaceKey::from_entropy([86; 32]));
        for path in [
            "/api/v1/registry/items?q=private%20prompt",
            "/api/v1/registry/items?%71=private",
            "/api/v1/registry/items?unknown=private",
            "/api/v1/new-content-endpoint",
        ] {
            assert!(
                client.call(&Call::get("node-job", path.into())).is_err(),
                "{path}"
            );
        }
        for (path, body) in [
            (
                "/api/v1/bus/board",
                json!({"key":"fixture","value":{"code":"private"}}),
            ),
            (
                "/api/v1/bus/messages",
                json!({"body":"private","new_content":"private"}),
            ),
            (
                "/api/v1/zones/claims",
                json!({"paths":["src/a.rs"],"meta":{"code":"private"}}),
            ),
            (
                "/api/v1/presence",
                json!({"client":"fixture","activity":{"tool_running":true,"meta":{"argv":"private"}}}),
            ),
            ("/api/v1/registry/import", json!({"items":[]})),
        ] {
            assert!(
                client
                    .call(&Call::write("node-job", "POST", path.into(), body))
                    .is_err(),
                "{path}"
            );
        }
        assert!(server.requests().is_empty());
    }

    #[test]
    fn node_context_authenticates_existing_outbox_envelopes_before_transmission() {
        let server = FakeServer::start(vec![Reply::json(200, json!({}))]);
        let key = WorkspaceKey::from_entropy([87; 32]);
        let client = forced_client(&server, key.clone());
        assert!(
            client
                .call(&Call::write(
                    "node-job",
                    "POST",
                    "/api/v1/bus/messages".into(),
                    json!({"body":"lyenc1.just-a-prefix"})
                ))
                .is_err()
        );
        assert!(server.requests().is_empty());
        let envelope = key
            .encrypt(NODE_WORKSPACE, "body", "queued private content")
            .unwrap();
        client
            .call(&Call::write(
                "node-job",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"body":envelope}),
            ))
            .unwrap();
        assert_eq!(server.requests()[0].body["body"], envelope);
    }

    #[test]
    fn node_context_keeps_only_fixed_liveness_metadata_clear() {
        let server = FakeServer::start(vec![Reply::json(200, json!({}))]);
        let client = forced_client(&server, WorkspaceKey::from_entropy([88; 32]));
        client.call(&Call::write("node-job", "POST", "/api/v1/presence".into(), json!({
            "client":"fixture","activity":{"tool_running":true,"state":"working",
                "meta":{"level":"ok","load":0.2,"cpus":4,"disk_free":null,"memory_available":1024}}
        }))).unwrap();
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn node_context_rejects_scalar_json_bypasses_and_workspace_rebinding() {
        let server = FakeServer::start(vec![]);
        let client = forced_client(&server, WorkspaceKey::from_entropy([91; 32]));
        for (path, body) in [
            (
                "/api/v1/presence",
                json!({"client":"fixture","activity":"private prompt"}),
            ),
            (
                "/api/v1/registry/items",
                json!({"title":"private","body":"private","acceptance":"private","sealed":"private prompt"}),
            ),
            ("/api/v1/bus/messages", json!({"body":17})),
        ] {
            assert!(
                client
                    .call(&Call::write("node-job", "POST", path.into(), body))
                    .is_err(),
                "{path}"
            );
        }
        assert!(client.require_e2ee_for("another-workspace").is_err());
        assert!(server.requests().is_empty());
    }

    #[test]
    fn node_context_authenticates_conflict_notes_in_holders_queue_and_errors() {
        let key = WorkspaceKey::from_entropy([83; 32]);
        let note = key
            .encrypt(NODE_WORKSPACE, "note", "private holder note")
            .unwrap();
        let holder = json!({"path":"src","held_path":"src","claim_id":"synthetic-id","session":"other",
            "note":note,"paths":["src"],"mode":"exclusive","purpose":"work","expires_at":null,"priority_of":null});
        let server = FakeServer::start(vec![
            Reply::json(
                200,
                json!([{"path":"src","status":"held","holder":holder,"fence":0}]),
            ),
            Reply::json(200, json!({"queued":true,"conflicts":[holder]})),
            Reply::json(
                409,
                json!({"error":{"code":"held","message":"SERVER-UNAUTHENTICATED-TEXT","details":{"conflicts":[holder],"priority_of":null}}}),
            ),
        ]);
        let client = forced_client(&server, key);
        let checked = client
            .call(&Call {
                method: "POST".into(),
                path: "/api/v1/zones/check".into(),
                body: Some(json!({"paths":["src"]})),
                session: "node-job".into(),
                ..Call::default()
            })
            .unwrap();
        assert_eq!(checked[0]["holder"]["note"], "private holder note");
        let queued = client
            .call(&Call::write(
                "node-job",
                "POST",
                "/api/v1/zones/claims".into(),
                json!({"paths":["src"]}),
            ))
            .unwrap();
        assert_eq!(queued["conflicts"][0]["note"], "private holder note");
        let error = client
            .call(&Call::write(
                "node-job",
                "POST",
                "/api/v1/zones/claims".into(),
                json!({"paths":["src"]}),
            ))
            .unwrap_err();
        let ClientError::Conflict(error) = error else {
            panic!("expected authenticated conflict")
        };
        assert_eq!(error.details["conflicts"][0]["note"], "private holder note");
        assert!(!error.message.contains("SERVER-UNAUTHENTICATED-TEXT"));
    }
    #[test]
    fn node_context_preserves_real_backend_error_metadata_shapes() {
        let key = WorkspaceKey::from_entropy([85; 32]);
        let reason = key
            .encrypt(NODE_WORKSPACE, "reason", "private freeze reason")
            .unwrap();
        for (status, details, expected) in [
            (
                409,
                json!({"conflicts":[],"priority_of":null}),
                json!({"conflicts":[],"priority_of":null}),
            ),
            (
                409,
                json!({"conflicts":[],"priority_of":7}),
                json!({"conflicts":[],"priority_of":7}),
            ),
            (
                409,
                json!({"path":"src","owner_session":"other"}),
                json!({"path":"src","owner_session":"other"}),
            ),
            (
                412,
                json!({"path":"src","fence":7}),
                json!({"path":"src","fence":7}),
            ),
            (412, json!({"version":7}), json!({"version":7})),
            (
                503,
                json!({"reason":reason}),
                json!({"reason":"private freeze reason"}),
            ),
            (503, json!({"reason":null}), json!({"reason":null})),
        ] {
            let server = FakeServer::start(vec![Reply::json(
                status,
                json!({"error":{"code":"fixed","message":"server text","details":details}}),
            )]);
            let client = forced_client(&server, key.clone());
            let error = client
                .call(&Call::write(
                    "node-job",
                    "POST",
                    "/api/v1/zones/claims".into(),
                    json!({"paths":["src"]}),
                ))
                .unwrap_err();
            let (ClientError::Conflict(error)
            | ClientError::StaleFence(error)
            | ClientError::Frozen(error)) = error
            else {
                panic!("unexpected classification: {error}")
            };
            assert_eq!(error.details, expected);
            assert_eq!(server.requests().len(), 1);
        }
    }

    #[test]
    fn node_context_rejects_plaintext_tampered_and_untyped_conflict_notes() {
        let key = WorkspaceKey::from_entropy([84; 32]);
        let wrong = key.encrypt(NODE_WORKSPACE, "body", "wrong field").unwrap();
        for note in [
            json!("plaintext"),
            json!(wrong),
            json!({"nested":"untyped"}),
        ] {
            for response in [
                json!([{"holder":{"note":note}}]),
                json!({"queued":true,"conflicts":[{"note":note}]}),
            ] {
                let path = if response.is_array() {
                    "/api/v1/zones/check"
                } else {
                    "/api/v1/zones/claims"
                };
                let server = FakeServer::start(vec![Reply::json(200, response)]);
                let client = forced_client(&server, key.clone());
                let call = Call::write("node-job", "POST", path.into(), json!({"paths":["src"]}));
                assert!(client.call(&call).is_err());
                assert_eq!(
                    server.requests().len(),
                    1,
                    "response rejection must follow actual HTTP"
                );
            }
            let server = FakeServer::start(vec![Reply::json(
                409,
                json!({"error":{"code":"held","message":"fixed","details":{"conflicts":[{"note":note}]}}}),
            )]);
            let client = forced_client(&server, key.clone());
            assert!(matches!(
                client.call(&Call::write(
                    "node-job",
                    "POST",
                    "/api/v1/zones/claims".into(),
                    json!({"paths":["src"]})
                )),
                Err(ClientError::Invalid(_))
            ));
        }
        let server = FakeServer::start(vec![Reply::json(200, json!([{"holder":null}]))]);
        let client = forced_client(&server, key);
        assert!(
            client
                .call(&Call::write(
                    "node-job",
                    "POST",
                    "/api/v1/zones/check".into(),
                    json!({"paths":["src"]})
                ))
                .is_ok()
        );
    }

    #[test]
    fn node_context_authenticates_array_history_and_typed_event_payloads() {
        let key = WorkspaceKey::from_entropy([89; 32]);
        let reason = key
            .encrypt(NODE_WORKSPACE, "reason", "private reason")
            .unwrap();
        let title = key
            .encrypt(NODE_WORKSPACE, "title", "private title")
            .unwrap();
        let value = key
            .encrypt(NODE_WORKSPACE, "value", "private board")
            .unwrap();
        let text = key
            .encrypt(NODE_WORKSPACE, "text", "private request")
            .unwrap();
        let server = FakeServer::start(vec![
            Reply::json(
                200,
                json!([{"op":"transitioned","reason":reason,"payload":{"title":title}}]),
            ),
            Reply::json(
                200,
                json!([{"type":"task.offered","payload":{"title":title}}]),
            ),
            Reply::json(
                200,
                json!([{"type":"board.changed","payload":{"value":value}}]),
            ),
            Reply::json(
                200,
                json!([{"type":"zone.requested","payload":{"text":text,"note":text}}]),
            ),
            Reply::json(200, json!([{"value":value}])),
            Reply::json(200, json!([{"op":"owner_closed","reason":value}])),
        ]);
        let client = forced_client(&server, key);
        let history = client
            .call(&Call::get(
                "node-job",
                "/api/v1/registry/items/D-1/history".into(),
            ))
            .unwrap();
        assert_eq!(history[0]["reason"], "private reason");
        assert_eq!(history[0]["payload"]["title"], "private title");
        for (field, expected) in [
            ("title", "private title"),
            ("value", "private board"),
            ("note", "private request"),
        ] {
            let event = client
                .call(&Call::get("node-job", "/api/v1/events".into()))
                .unwrap();
            assert_eq!(event[0]["payload"][field], expected);
        }
        let board = client
            .call(&Call::get("node-job", "/api/v1/bus/board/history".into()))
            .unwrap();
        assert_eq!(board[0]["value"], "private board");
        let closed = client
            .call(&Call::get(
                "node-job",
                "/api/v1/registry/items/D-1/history".into(),
            ))
            .unwrap();
        assert_eq!(closed[0]["reason"], "private board");
    }

    #[test]
    fn node_context_rejects_plaintext_arrays_and_unknown_event_content() {
        let key = WorkspaceKey::from_entropy([90; 32]);
        for (path, body) in [
            (
                "/api/v1/registry/items/D-1/history",
                json!([{"reason":"private plaintext"}]),
            ),
            (
                "/api/v1/events",
                json!([{"type":"task.offered","payload":{"title":"private plaintext"}}]),
            ),
            (
                "/api/v1/events",
                json!([{"type":"new.content","payload":{"new_field":"private plaintext"}}]),
            ),
            (
                "/api/v1/events",
                json!([{"type":"presence.heartbeat","payload":{"title":"private plaintext"}}]),
            ),
            (
                "/api/v1/bus/board/history",
                json!([{"value":"private plaintext"}]),
            ),
            (
                "/api/v1/bus/board/history",
                json!([{"value":"lyenc1.tampered.envelope"}]),
            ),
        ] {
            let server = FakeServer::start(vec![Reply::json(200, body)]);
            assert!(
                forced_client(&server, key.clone())
                    .call(&Call::get("node-job", path.into()))
                    .is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn node_context_authenticates_takeover_reason_alias_and_validates_liveness_timestamps() {
        let key = WorkspaceKey::from_entropy([92; 32]);
        let reason = key
            .encrypt(NODE_WORKSPACE, "reason", "private takeover reason")
            .unwrap();
        let server = FakeServer::start(vec![
            Reply::json(
                200,
                json!([{"type":"zone.takeover","payload":{"reason":reason}}]),
            ),
            Reply::json(
                200,
                json!([{"type":"zone.lost","payload":{"reason":"taken"}}]),
            ),
            Reply::json(
                200,
                json!([{"type":"zone.takeover","payload":{"reason":"private plaintext"}}]),
            ),
            Reply::json(200, json!({})),
        ]);
        let client = forced_client(&server, key);
        let result = client
            .call(&Call::get("node-job", "/api/v1/events".into()))
            .unwrap();
        assert_eq!(result[0]["payload"]["reason"], "private takeover reason");
        assert_eq!(
            client
                .call(&Call::get("node-job", "/api/v1/events".into()))
                .unwrap()[0]["payload"]["reason"],
            "taken"
        );
        assert!(
            client
                .call(&Call::get("node-job", "/api/v1/events".into()))
                .is_err()
        );
        for timestamp in [
            "private prompt",
            "2026-11-07T00:00:00.000Z-private",
            "2026-99-99T00:00:00.000Z",
        ] {
            assert!(
                client
                    .call(&Call::write(
                        "node-job",
                        "POST",
                        "/api/v1/presence".into(),
                        json!({"client":"fixture","activity":{"tool_started_at":timestamp}})
                    ))
                    .is_err()
            );
        }
        assert_eq!(server.requests().len(), 3);
        client.call(&Call::write("node-job", "POST", "/api/v1/presence".into(),
            json!({"client":"fixture","activity":{"tool_started_at":"2026-11-07T00:00:00.000Z"}}))).unwrap();
        assert_eq!(server.requests().len(), 4);
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
            // The fixture advertises modern discovery, so its domain error needs a stable code.
            Reply::json(
                404,
                json!({"error":{"code":"not_found","message":"missing"}}),
            ),
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
            Reply::json(503, json!({"error":{"code":"frozen","message":"frozen"}}))
                .header("Retry-After", "120"),
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
                json!({"error": {"code": "rate_limited", "message": "slow down"}}),
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
            Reply::json(
                429,
                json!({"error":{"code":"rate_limited","message":"slow down"}}),
            )
            .header("Retry-After", "1"),
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
                json!({"error": {"code": "rate_limited", "message": "slow down"}}),
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
    fn a_redirect_is_never_followed_and_preserves_unknown_write() {
        let server = FakeServer::start(vec![
            Reply::text(307, "").header("Location", "http://example.test/moved"),
        ]);
        let client = Client::new(&server.url(), "secret".into()).unwrap();
        let call = Call::write("a", "POST", "/api/v1/bus/messages".into(), json!({}));
        let error = client.call(&call).unwrap_err();
        // EP-10: an unconfirmed POST cannot become a fresh outbox mutation.
        assert!(matches!(error, ClientError::OutcomeUnknown(_)), "{error:?}");
        assert_eq!(
            client
                .pending_operation(call.key.as_deref().unwrap())
                .unwrap()
                .body,
            Some("{}".into())
        );
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_rejected_write_is_repeated_under_the_same_key() {
        let server = FakeServer::start(vec![
            // ERRORS.md authorizes retry by stable pre-execution code, never bare HTTP 500.
            Reply::json(
                429,
                json!({"error":{"code":"rate_limited","message":"slow down"}}),
            )
            .header("Retry-After", "0"),
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
