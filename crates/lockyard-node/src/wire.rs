// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Versioned application messages shared by direct and relayed connections.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const PROTOCOL_VERSION: u8 = 2;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
/// Endpoint-enforced first-delivery bound, independent of project content TTL.
pub const REQUEST_DELIVERY_TTL_MS: u64 = (24 * 60 * 60 + 5 * 60) * 1000;
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_LOG_BYTES: u32 = 16 * 1024;
pub const MAX_LOG_BYTES: u32 = 64 * 1024;
/// JSON byte arrays expand up to 4x, then AEAD envelopes add base64 overhead.
/// Keep each network artifact chunk below the complete encrypted frame bound.
pub const MAX_TRANSFER_BYTES: u32 = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    pub id: String,
    pub repository: String,
    pub revision: String,
    pub runner: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub prompt: Option<String>,
    pub timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero_priority")]
    pub priority: i16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workflow_inputs: Vec<crate::workflow::WorkflowInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_runner_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_approval: Option<crate::provenance::SignedDocument>,
}
fn is_zero_priority(value: &i16) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Starting,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    InterruptedUnknown,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    #[serde(default = "legacy_had_runtime_credentials")]
    pub had_runtime_credentials: bool,
    pub spec: JobSpec,
    pub state: JobState,
    pub agent: String,
    pub submitter: String,
    #[serde(default)]
    pub submitter_certificate_sha256: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at_ms: u64,
    #[serde(rename = "updated_at")]
    pub updated_at_ms: u64,
    pub resolved_revision: Option<String>,
    pub worktree: Option<PathBuf>,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub error_code: Option<String>,
    pub log_bytes: u64,
    pub log_truncated: bool,
    #[serde(default)]
    pub log_error: Option<String>,
    #[serde(default)]
    pub patch_bytes: u64,
    #[serde(default)]
    pub patch_truncated: bool,
    #[serde(default)]
    pub patch_error: Option<String>,
    #[serde(default)]
    pub configured_image: Option<String>,
    #[serde(default)]
    pub admission_runner_sha256: Option<String>,
    #[serde(default)]
    pub admission_repository_sha256: Option<String>,
    #[serde(default)]
    pub admitted_image: Option<crate::supply_chain::VerifiedImage>,
    #[serde(default)]
    pub result_manifest: Option<crate::provenance::SignedDocument>,
    #[serde(default)]
    pub provenance_error: Option<String>,
    /// Local bookkeeping for the opt-in metadata outbox, never a result proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_accounted_certificate_sha256: Option<String>,
    #[serde(default)]
    pub retention: Option<crate::retention::RetentionSnapshot>,
}

fn legacy_had_runtime_credentials() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub job_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRequest {
    pub job_id: String,
    pub offset: u64,
    pub limit: u32,
}

pub type PatchRequest = LogRequest;
pub type PatchChunk = LogChunk;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogChunk {
    pub offset: u64,
    pub next_offset: u64,
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    pub eof: bool,
    pub truncated: bool,
}

mod base64_bytes {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    #[serde(rename = "node.ping")]
    NodePing,
    #[serde(rename = "job.submit")]
    JobSubmit,
    #[serde(rename = "job.status")]
    JobStatus,
    #[serde(rename = "job.cancel")]
    JobCancel,
    #[serde(rename = "job.log")]
    JobLog,
    #[serde(rename = "job.patch")]
    JobPatch,
    #[serde(rename = "job.archive")]
    JobArchive,
    #[serde(rename = "job.resolve_unknown")]
    JobResolveUnknown,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodePing => "node.ping",
            Self::JobSubmit => "job.submit",
            Self::JobStatus => "job.status",
            Self::JobCancel => "job.cancel",
            Self::JobLog => "job.log",
            Self::JobPatch => "job.patch",
            Self::JobArchive => "job.archive",
            Self::JobResolveUnknown => "job.resolve_unknown",
        }
    }
    pub fn requires_submit_permission(self) -> bool {
        matches!(
            self,
            Self::JobSubmit | Self::JobCancel | Self::JobResolveUnknown
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcFrame {
    pub v: u8,
    pub kind: FrameKind,
    pub id: String,
    pub source: String,
    pub target: String,
    pub operation: Operation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_certificate_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_certificate_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<crate::retention::ContentRetention>,
    pub payload: String,
}

impl RpcFrame {
    pub fn validate_metadata(&self) -> Result<(), &'static str> {
        if !matches!(self.v, 1 | PROTOCOL_VERSION) {
            return Err("unsupported node protocol version");
        }
        if self.v == 1 && self.operation.requires_submit_permission() {
            return Err("node mutations require protocol version 2");
        }
        if !valid_ulid(&self.id)
            || self
                .in_reply_to
                .as_deref()
                .is_some_and(|id| !valid_ulid(id))
        {
            return Err("RPC IDs must be ULIDs");
        }
        if !valid_name(&self.source) || !valid_name(&self.target) {
            return Err("invalid node identity");
        }
        if matches!(self.kind, FrameKind::Request) != self.in_reply_to.is_none() {
            return Err("response requires in_reply_to; request forbids it");
        }
        match (
            &self.source_certificate_sha256,
            &self.target_certificate_sha256,
        ) {
            (Some(source), Some(target))
                if valid_certificate_pin(source) && valid_certificate_pin(target) => {}
            (None, None) if !self.operation.requires_submit_permission() => (),
            _ => return Err("node mutation requires paired certificate incarnation pins"),
        }
        if let Some(retention) = &self.retention {
            retention
                .validate(
                    crate::retention::id_timestamp_ms(&self.id)
                        .map_err(|_| "invalid request timestamp")?,
                )
                .map_err(|_| "invalid node content retention")?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.validate_metadata()?;
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err("node payload is too large");
        }
        if !valid_ciphertext(&self.payload) {
            return Err("node RPC payloads must be valid end-to-end encryption envelopes");
        }
        if serde_json::to_vec(self)
            .map_err(|_| "cannot encode node frame")?
            .len()
            > MAX_FRAME_BYTES
        {
            return Err("node frame is too large");
        }
        Ok(())
    }

    /// IDs and names exclude delimiters, so this encoding is unambiguous.
    pub fn authenticated_field(&self) -> Result<String, &'static str> {
        self.validate_metadata()?;
        let kind = match self.kind {
            FrameKind::Request => "request",
            FrameKind::Response => "response",
        };
        let mut field = format!(
            "node-rpc-v{}|{}|{}|{}|{}|{}|{}",
            self.v,
            kind,
            self.id,
            self.source,
            self.target,
            self.operation.as_str(),
            self.in_reply_to.as_deref().unwrap_or("")
        );
        if let Some(retention) = &self.retention {
            field.push_str(&format!(
                "|retention:{}:{}",
                retention.content_ttl_seconds, retention.expires_at_ms
            ));
        }
        if let (Some(source), Some(target)) = (
            &self.source_certificate_sha256,
            &self.target_certificate_sha256,
        ) {
            field.push_str(&format!("|certificates:{source}:{target}"));
        }
        Ok(field)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum RelayControl {
    Ack {
        v: u8,
        id: String,
    },
    Error {
        v: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelayMessage {
    Frame(RpcFrame),
    Control(RelayControl),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReply<T> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl<T> RpcReply<T> {
    pub fn success(result: T) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }
    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(RpcError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
pub fn valid_certificate_pin(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Structural validation only; authenticated decryption requires the local workspace key.
pub fn valid_ciphertext(payload: &str) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let Some((key_id, body)) = payload
        .strip_prefix("lyenc1.")
        .and_then(|value| value.split_once('.'))
    else {
        return false;
    };
    key_id.len() == 11
        && URL_SAFE_NO_PAD
            .decode(key_id)
            .is_ok_and(|bytes| bytes.len() == 8)
        && body.len() <= MAX_FRAME_BYTES
        && URL_SAFE_NO_PAD
            .decode(body)
            .is_ok_and(|bytes| bytes.len() >= 28)
}

pub fn valid_ulid(id: &str) -> bool {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    id.len() == 26 && id.as_bytes()[0] <= b'7' && id.bytes().all(|b| ALPHABET.contains(&b))
}

pub fn new_id() -> crate::Result<String> {
    use ring::rand::SecureRandom;
    let mut raw = [0u8; 16];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    raw[..6].copy_from_slice(&now.to_be_bytes()[2..]);
    ring::rand::SystemRandom::new()
        .fill(&mut raw[6..])
        .map_err(|_| "system random source failed")?;
    let mut number = u128::from_be_bytes(raw);
    let mut out = [b'0'; 26];
    for letter in out.iter_mut().rev() {
        *letter = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(number & 31) as usize];
        number >>= 5;
    }
    Ok(String::from_utf8(out.to_vec())?)
}
