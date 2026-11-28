// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! HTTP generation negotiation is independent of RPC frames and package versions.
use crate::{
    ApiError, Call, Cancellation, Client, ClientError, ContentEncryption, Failure,
    WorkspaceEncryption,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DISCOVERY: &str = "/api/v1/protocol";
pub(crate) const CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_STATUS_PROTOCOL_HINT_BYTES: u64 = 16 * 1024;
#[path = "pending_maintenance.rs"]
mod maintenance;
pub use maintenance::PendingRepair;
#[path = "pending_store.rs"]
mod pending_store;
use pending_store::Admission;
pub(crate) use pending_store::PendingJournal;

const MAX_PENDING: usize = 128;
const PENDING_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_PENDING_BYTES: u64 = 16 * 1024 * 1024;

fn registry_create_key(pending: &PendingWrite) -> Option<String> {
    if pending.method != "POST" || pending.request_path != "/api/v1/registry/items" {
        return None;
    }
    let body: Value = serde_json::from_str(pending.body.as_deref()?).ok()?;
    let key = body["client_key"].as_str()?;
    (!key.is_empty() && key.len() <= 256 && key.bytes().all(|byte| byte.is_ascii_graphic()))
        .then(|| key.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRange {
    pub min: u16,
    pub max: u16,
}

impl ProtocolRange {
    fn valid(self) -> bool {
        self.min > 0 && self.min <= self.max && self.max - self.min <= 1
    }

    fn common(self) -> Option<u16> {
        [2, 1]
            .into_iter()
            .find(|version| (self.min..=self.max).contains(version))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedProtocol {
    pub selected: u16,
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub(crate) legacy: bool,
}

impl NegotiatedProtocol {
    fn candidate(selected: u16) -> Self {
        Self {
            selected,
            capabilities: BTreeSet::new(),
            legacy: false,
        }
    }
}

/// Local errors have no HTTP status. Remote errors preserve the actual status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Problem {
    pub status: Option<u16>,
    pub code: String,
    pub detail: String,
    pub details: Value,
}

/// The exact wire operation, retained privately before the first send.
/// Debug and Display intentionally omit its body; private IPC serialization preserves it.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingWrite {
    pub code: String,
    pub cause_code: String,
    pub cause_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    pub protocol: NegotiatedProtocol,
    pub method: String,
    pub path: String,
    pub request_path: String,
    pub body: Option<String>,
    pub key: String,
    pub repository: Option<String>,
    pub session: String,
    pub origin: String,
    pub credential_scope: String,
    /// Original caller identity, before route preparation and randomized encryption.
    #[serde(default)]
    pub request_digest: Option<String>,
    /// First potentially executed attempt. Unknown-outcome replay never refreshes
    /// this receipt clock; a proven pre-execution refusal may start a new window.
    #[serde(default)]
    pub first_sent_unix_secs: Option<u64>,
    /// Server epoch, estimated conservatively at first send from an observed HTTP Date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_sent_server_secs: Option<u64>,
    /// A finite replay window closed. Keep frozen bytes outside the active replay budget.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replay_stopped: bool,
    /// No replay proof is currently available. Recheck against the server on repair.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replay_paused: bool,
    /// Every attempt is proven to have been refused before execution. Reset durably before send.
    #[serde(default)]
    pub pre_execution_rejected: bool,
    /// Binds frozen wire bytes to the encryption policy that produced them.
    #[serde(default)]
    pub encryption_context: Option<String>,
    /// EP-09 freezes this header together with its opaque wire body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_retry_at: Option<u64>,
}

impl std::fmt::Debug for PendingWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingWrite")
            .field("code", &self.code)
            .field("cause_code", &self.cause_code)
            .field("protocol", &self.protocol.selected)
            .field("body", &"[redacted]")
            .finish_non_exhaustive()
    }
}

pub(crate) struct CachedProtocol {
    pub(crate) value: NegotiatedProtocol,
    pub(crate) obtained: Instant,
}

/// A negotiation hint only: no workspace policy, claims, mail, work or assignments are stored.
/// Both clocks must agree that it is younger than CACHE_TTL. Prefer a native boot identity;
/// sandboxed macOS may instead compare the wall-minus-monotonic boot estimate within one second.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusProtocolClock {
    boot: String,
    wall_ms: u64,
    monotonic_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusProtocolHint {
    version: u16,
    origin: String,
    credential_scope: String,
    clock: StatusProtocolClock,
    protocol: NegotiatedProtocol,
}

fn modern_status_protocol(protocol: &NegotiatedProtocol) -> bool {
    protocol.selected == 2
        && !protocol.legacy
        && protocol.capabilities.len() <= 64
        && protocol.capabilities.iter().all(|capability| {
            !capability.is_empty()
                && capability.len() <= 64
                && capability
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
}

fn status_protocol_age(
    observed: &StatusProtocolClock,
    current: &StatusProtocolClock,
) -> Option<Duration> {
    if observed.boot != current.boot {
        return None;
    }
    if observed.boot == "clock-estimate" {
        let previous_boot = observed.wall_ms.checked_sub(observed.monotonic_ms)?;
        let current_boot = current.wall_ms.checked_sub(current.monotonic_ms)?;
        if previous_boot.abs_diff(current_boot) > 1000 {
            return None;
        }
    }
    let wall = current.wall_ms.checked_sub(observed.wall_ms)?;
    let monotonic = current.monotonic_ms.checked_sub(observed.monotonic_ms)?;
    let age = Duration::from_millis(wall.max(monotonic));
    (age < CACHE_TTL).then_some(age)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn status_protocol_clock() -> Option<StatusProtocolClock> {
    let wall_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()?;
    let mut clock = std::mem::MaybeUninit::<libc::timespec>::uninit();
    #[cfg(target_os = "linux")]
    let clock_id = libc::CLOCK_BOOTTIME;
    #[cfg(target_os = "macos")]
    let clock_id = libc::CLOCK_MONOTONIC;
    if unsafe { libc::clock_gettime(clock_id, clock.as_mut_ptr()) } != 0 {
        return None;
    }
    let clock = unsafe { clock.assume_init() };
    let monotonic_ms = u64::try_from(clock.tv_sec)
        .ok()?
        .checked_mul(1000)?
        .checked_add(u64::try_from(clock.tv_nsec).ok()? / 1_000_000)?;
    #[cfg(target_os = "linux")]
    let boot = {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let boot = boot.trim();
        if boot.len() != 36
            || !boot
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return None;
        }
        boot.to_owned()
    };
    #[cfg(target_os = "macos")]
    let boot = {
        let mut boot = std::mem::MaybeUninit::<libc::timeval>::uninit();
        let mut size = std::mem::size_of::<libc::timeval>();
        let available = unsafe {
            libc::sysctlbyname(
                c"kern.boottime".as_ptr(),
                boot.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } == 0
            && size == std::mem::size_of::<libc::timeval>();
        if available {
            let boot = unsafe { boot.assume_init() };
            format!("{}:{}", boot.tv_sec, boot.tv_usec)
        } else {
            // The native boot sysctl can be denied inside a sandbox. This is only a modern
            // version hint: both age clocks and the boot estimate must still agree, and the
            // server must confirm the version on the next live policy/data response. A very
            // short reboot with indistinguishable clocks may reuse this hint, never data.
            "clock-estimate".into()
        }
    };
    Some(StatusProtocolClock {
        boot,
        wall_ms,
        monotonic_ms,
    })
}

// Missing a tested native boot identity disables only this optional optimization.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn status_protocol_clock() -> Option<StatusProtocolClock> {
    None
}

#[derive(Default)]
pub(crate) struct ProtocolState {
    pub(crate) cached: Option<CachedProtocol>,
    pending: BTreeMap<String, PendingWrite>,
    active_writes: BTreeSet<String>,
}

pub(crate) struct MemorySendGuard<'a> {
    state: &'a std::sync::Mutex<ProtocolState>,
    key: String,
}

impl Drop for MemorySendGuard<'_> {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_writes
            .remove(&self.key);
    }
}

pub(crate) fn local(code: &str, message: &str) -> ClientError {
    ClientError::Protocol(Problem {
        status: None,
        code: code.into(),
        detail: message.into(),
        details: Value::Null,
    })
}

pub(crate) fn content_error(message: String) -> ClientError {
    if message.starts_with("catalog_")
        || message == "zone_unknown"
        || message == "content_authentication_failed"
    {
        local(&message, &message)
    } else if message.contains("authentication") {
        local(
            "content_authentication_failed",
            "encrypted content could not be authenticated",
        )
    } else {
        ClientError::Invalid(message)
    }
}

impl ClientError {
    /// Stable code, preserved independently from human-readable text.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Protocol(problem) => Some(&problem.code),
            Self::OutcomeUnknown(pending) => Some(&pending.code),
            Self::JournalBusy => Some("journal_busy"),
            _ => self
                .api_error()
                .map(|error| error.code.as_str())
                .filter(|code| !code.is_empty()),
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Protocol(problem) => problem.status,
            _ => self.api_error().map(|error| error.status),
        }
    }

    pub(super) fn api_error(&self) -> Option<&ApiError> {
        match self {
            Self::Unauthorized(error)
            | Self::Denied(error)
            | Self::NotFound(error)
            | Self::Conflict(error)
            | Self::StaleFence(error)
            | Self::RateLimited(error)
            | Self::Frozen(error)
            | Self::Http(error) => Some(error),
            _ => None,
        }
    }

    pub(crate) fn problem(&self) -> Option<Problem> {
        match self {
            Self::Protocol(problem) => Some(problem.clone()),
            Self::OutcomeUnknown(pending) => {
                let mut details = json!({"cause_code":pending.cause_code,"cause_status":pending.cause_status,"protocol":pending.protocol.selected});
                let detail = if pending.cause_code == "drain_instance_mismatch" {
                    details["idempotency_key"] = json!(pending.key);
                    format!(
                        "Drain outcome unknown. Contact the trusted origin of the original replica, or archive with `lockyard doctor --forget-unknown {} --confirm`.",
                        pending.key
                    )
                } else if maintenance::eligible_for_recovery(pending) {
                    details["idempotency_key"] = json!(pending.key);
                    "mutation outcome requires reconciliation".into()
                } else {
                    maintenance::unreplayed_detail(pending).into()
                };
                Some(Problem {
                    status: None,
                    code: pending.code.clone(),
                    detail,
                    details,
                })
            }
            _ => self
                .api_error()
                .filter(|error| !error.code.is_empty())
                .map(|error| Problem {
                    status: Some(error.status),
                    code: error.code.clone(),
                    detail: if let Some(message) = crate::task_area_error(error) {
                        message
                    } else if error.status == 409 {
                        let conflicts = crate::holders(error);
                        if conflicts.is_empty() {
                            crate::contended_text(error)
                        } else {
                            lockyard_core::Error::Conflict(conflicts).to_string()
                        }
                    } else {
                        error.message.clone()
                    },
                    details: error.details.clone(),
                }),
        }
    }
}

/// Upstream services use numeric `code` and string `status`; these are not Lockyard envelopes.
pub(crate) fn looks_like_lockyard_error(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .is_some_and(|value| {
            value.get("error").is_some()
                || value.get("code").is_some_and(Value::is_string)
                || value
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.starts_with("urn:lockyard:"))
        })
}

/// Both legacy and RFC 9457 envelopes pass through one conflict-checking decoder.
pub(crate) fn parse_api_error(
    status: u16,
    body: &str,
    retry_after: Option<u64>,
) -> Result<ApiError, ClientError> {
    let invalid = || {
        local(
            "protocol_response_invalid",
            "contradictory or malformed cloud error envelope",
        )
    };
    let parsed = serde_json::from_str::<Value>(body);
    if matches!(status, 502..=504) && !looks_like_lockyard_error(body) {
        return Ok(ApiError {
            status,
            code: "unavailable".into(),
            message: format!("сервер Lockyard недоступен или на обслуживании (HTTP {status})"),
            retry_after,
            ..ApiError::default()
        });
    }
    let Ok(_) = parsed else {
        return Ok(ApiError {
            status,
            message: body.into(),
            retry_after,
            ..ApiError::default()
        });
    };
    let value = serde_json::from_str::<UniqueJson>(body)
        .map_err(|_| invalid())?
        .0;
    let legacy = value.get("error");
    if legacy.is_some_and(|value| !value.is_object()) {
        return Err(invalid());
    }
    let modern = value.get("code").is_some() || value.get("type").is_some();
    if let Some(body_status) = value.get("status")
        && body_status.as_u64() != Some(u64::from(status))
    {
        return Err(invalid());
    }
    let text = |node: &Value, key: &str| -> Result<String, ClientError> {
        match node.get(key) {
            Some(Value::String(text)) => Ok(text.clone()),
            None => Ok(String::new()),
            _ => Err(invalid()),
        }
    };
    let (code, message, mut details) = if modern {
        let code = text(&value, "code")?;
        if code.is_empty() || value.get("status").is_none() {
            return Err(invalid());
        }
        let message = text(&value, "detail")?;
        let details = value.get("details").cloned().unwrap_or(Value::Null);
        if let Some(legacy) = legacy {
            if text(legacy, "code")? != code
                || legacy.get("details").cloned().unwrap_or(Value::Null) != details
            {
                return Err(invalid());
            }
            if let Some(legacy_status) = legacy.get("status")
                && legacy_status.as_u64() != Some(u64::from(status))
            {
                return Err(invalid());
            }
        }
        (code, message, details)
    } else if let Some(legacy) = legacy {
        (
            text(legacy, "code")?,
            text(legacy, "message")?,
            legacy.get("details").cloned().unwrap_or(Value::Null),
        )
    } else {
        (String::new(), text(&value, "message")?, Value::Null)
    };
    if !code.is_empty()
        && (code.len() > 128
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
    {
        return Err(invalid());
    }
    if modern
        && value
            .get("type")
            .is_some_and(|kind| kind.as_str() != Some(&format!("urn:lockyard:problem:{code}")))
    {
        return Err(invalid());
    }
    // Pre-negotiation range extensions may be top-level or in details; disagreement is invalid.
    for key in [
        "min_protocol",
        "max_protocol",
        "supported_protocols",
        "selected_protocol",
    ] {
        if let Some(extension) = value.get(key) {
            if details.is_null() {
                details = json!({});
            }
            let object = details.as_object_mut().ok_or_else(invalid)?;
            if object
                .get(key)
                .is_some_and(|existing| existing != extension)
            {
                return Err(invalid());
            }
            object.insert(key.into(), extension.clone());
        }
    }
    Ok(ApiError {
        status,
        code,
        message: if message.is_empty() {
            body.into()
        } else {
            message
        },
        details,
        retry_after,
    })
}

pub(crate) fn verify_echo(
    response: &ureq::Response,
    negotiated: &NegotiatedProtocol,
) -> Result<(), ClientError> {
    if negotiated.legacy {
        return Ok(());
    }
    let headers = response.all("Lockyard-Protocol");
    if headers.len() != 1 || headers[0] != negotiated.selected.to_string() {
        return Err(local(
            "protocol_response_invalid",
            "server did not echo the negotiated HTTP protocol",
        ));
    }
    Ok(())
}

pub(crate) fn verify_repository_echo(
    response: &ureq::Response,
    call: &Call,
    protocol: &NegotiatedProtocol,
) -> Result<(), ClientError> {
    let Some(repository) = &call.repository else {
        return Ok(());
    };
    let expected = if repository.is_empty() {
        "-"
    } else {
        repository.as_str()
    };
    let echoes = response.all("X-Lockyard-Repository");
    if protocol.legacy && repository.is_empty() && echoes.is_empty() {
        // Only safe discovery may enable old unscoped operations on a headerless server.
        return Ok(());
    }
    if echoes.len() != 1 || echoes[0] != expected {
        if call.is_write() {
            return Err(local(
                "protocol_response_invalid",
                "server did not confirm the requested repository namespace",
            ));
        }
        return Err(ClientError::Invalid("this server does not confirm repository namespace support; upgrade the server before using repository-scoped coordination".into()));
    }
    Ok(())
}

pub(crate) fn safe_retry(error: &ClientError) -> bool {
    error
        .api_error()
        .is_some_and(|error| error.status == 429 && error.code == "rate_limited")
}

pub(crate) fn journal_busy(error: &ClientError) -> bool {
    matches!(error, ClientError::JournalBusy)
        || matches!(
            error,
            ClientError::Transport(text) | ClientError::Invalid(text)
                if text.contains("pending journal is busy")
        )
}

fn pre_execution_refusal(error: &ClientError) -> bool {
    error.api_error().is_some_and(|api| {
        (api.status == 429 && matches!(api.code.as_str(), "rate_limited" | "relay_budget_exceeded"))
            || (api.status == 503 && matches!(api.code.as_str(), "frozen" | "server_draining"))
    })
}

fn replay_refusal(error: &ClientError) -> bool {
    pre_execution_refusal(error)
        || (error.status() == Some(400) && error.code() == Some("protocol_unsupported"))
}

impl Client {
    /// Opt into a private, 30-second modern negotiation hint for status-only clients. Live
    /// encryption policy and every response's protocol/repository echo remain mandatory.
    /// A missing, unsafe, stale or unreadable hint is simply a normal discovery cache miss.
    pub fn with_status_protocol_cache(self) -> Self {
        let Some(journal) = self.pending_journal.as_ref() else {
            return self;
        };
        let path = journal.status_cache_path();
        self.use_status_protocol_cache(path)
    }

    /// Locate the same cache for a read-only client without opening the pending database.
    pub fn with_status_protocol_cache_at(self, root: impl AsRef<Path>) -> Self {
        let path = pending_store::status_cache_path(&self, root.as_ref());
        self.use_status_protocol_cache(path)
    }

    fn use_status_protocol_cache(mut self, path: PathBuf) -> Self {
        if status_protocol_clock().is_none() {
            return self;
        }
        if !path
            .parent()
            .is_some_and(Self::private_status_cache_directory)
        {
            return self;
        }
        if let Some(cached) = self.load_status_protocol_hint(&path) {
            self.protocol_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cached = Some(cached);
        }
        self.status_protocol_cache = Some(path);
        self
    }

    fn private_status_cache_directory(directory: &Path) -> bool {
        #[cfg(windows)]
        match std::fs::symlink_metadata(directory) {
            Ok(_) => return lockyard_core::windows::require_private(directory).is_ok(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
        private_directory(directory).is_ok()
    }

    fn load_status_protocol_hint(&self, path: &Path) -> Option<CachedProtocol> {
        use std::io::Read;
        let metadata = std::fs::symlink_metadata(path).ok()?;
        private_file(&metadata).ok()?;
        if metadata.len() > MAX_STATUS_PROTOCOL_HINT_BYTES {
            return None;
        }
        let mut options = StateOpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).ok()?;
        private_file(&file.metadata().ok()?).ok()?;
        let mut bytes = Vec::new();
        file.take(MAX_STATUS_PROTOCOL_HINT_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_STATUS_PROTOCOL_HINT_BYTES {
            return None;
        }
        let hint: StatusProtocolHint =
            serde_json::from_value(strict_json(std::str::from_utf8(&bytes).ok()?).ok()?).ok()?;
        if hint.version != 1
            || hint.origin != self.base_url
            || hint.credential_scope != crate::credential_fingerprint(&self.token)
            || !modern_status_protocol(&hint.protocol)
        {
            return None;
        }
        let age = status_protocol_age(&hint.clock, &status_protocol_clock()?)?;
        Some(CachedProtocol {
            value: hint.protocol,
            obtained: Instant::now().checked_sub(age)?,
        })
    }

    fn save_status_protocol_hint(&self, protocol: &NegotiatedProtocol) {
        let Some(path) = &self.status_protocol_cache else {
            return;
        };
        let Some(clock) = status_protocol_clock() else {
            return;
        };
        if !modern_status_protocol(protocol) {
            return;
        }
        let Some(parent) = path.parent() else {
            return;
        };
        if !Self::private_status_cache_directory(parent) {
            return;
        }
        let hint = StatusProtocolHint {
            version: 1,
            origin: self.base_url.clone(),
            credential_scope: crate::credential_fingerprint(&self.token),
            clock,
            protocol: protocol.clone(),
        };
        if let Ok(bytes) = serde_json::to_vec(&hint) {
            let _ = lockyard_core::fsio::replace(path, &bytes, 0o600);
        }
    }

    fn invalidate_status_protocol_hint(&self) {
        if let Some(path) = &self.status_protocol_cache {
            let _ = std::fs::remove_file(path);
        }
    }

    pub(crate) fn encryption_context(&self) -> String {
        self.encryption_context_for(
            self.workspace.as_deref(),
            self.content_key
                .as_ref()
                .map(crate::WorkspaceKey::key_id)
                .as_deref(),
            self.encryption_enabled,
        )
    }

    fn encryption_context_for(
        &self,
        workspace: Option<&str>,
        key_id: Option<&str>,
        enabled: bool,
    ) -> String {
        crate::credential_fingerprint(
            &serde_json::to_string(&(workspace, key_id, enabled, &self.expected_e2ee_workspace))
                .expect("encryption context is serializable"),
        )
    }

    /// The in-memory transport has no durable admission record shared by callers.
    pub(crate) fn reserve_memory_send(
        &self,
        key: &str,
    ) -> Result<Option<MemorySendGuard<'_>>, ClientError> {
        if self.pending_journal.is_some() {
            return Ok(None);
        }
        if !self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_writes
            .insert(key.to_owned())
        {
            return Err(ClientError::JournalBusy);
        }
        Ok(Some(MemorySendGuard {
            state: &self.protocol_state,
            key: key.to_owned(),
        }))
    }

    pub(super) fn attach_pending_journal(&mut self, directory: &Path) -> Result<(), ClientError> {
        self.pending_journal = Some(PendingJournal::open(self, directory)?);
        Ok(())
    }

    /// Attach the journal and reconcile at startup for a client whose encryption is configured.
    pub fn with_pending_journal(
        mut self,
        directory: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        self.attach_pending_journal(directory.as_ref())?;
        self.reconcile_pending_on_startup()
    }

    /// Loads a private, per-origin and per-credential journal without network I/O.
    pub fn load_pending_journal(
        mut self,
        directory: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        self.attach_pending_journal(directory.as_ref())?;
        Ok(self)
    }

    /// Attest the live workspace policy before replaying frozen writes.
    /// Frontends use this for journals that can be opened under changing workspace policies.
    pub fn with_pending_encryption_policy(mut self) -> Self {
        self.check_pending_encryption_policy = true;
        self
    }

    /// Prepare and attest new wire bodies, and discover the read context for a long-lived client.
    pub fn with_live_write_encryption_policy(mut self) -> Self {
        self.check_live_write_encryption_policy = true;
        self.with_pending_encryption_policy()
    }

    /// Reconcile restored operations after opening the client and configuring encryption.
    pub fn reconcile_pending_on_startup(self) -> Result<Self, ClientError> {
        self.maintain_pending_journal()?;
        Ok(self)
    }

    /// Attach the selected scope and reconcile online within a bounded budget.
    /// Unlike normal startup, this does not run an unreported preliminary sweep.
    pub fn repair_pending_journal(
        mut self,
        directory: impl AsRef<Path>,
    ) -> Result<PendingRepair, ClientError> {
        self.attach_pending_journal(directory.as_ref())?;
        let started = Instant::now();
        let mut total = PendingRepair::default();
        loop {
            let report = self.repair_pending()?;
            let progress = report.applied + report.rejected + report.quarantined != 0
                || report.outcome_unknown > total.outcome_unknown;
            total.applied += report.applied;
            total.rejected += report.rejected;
            total.quarantined += report.quarantined;
            total.remaining = report.remaining;
            total.outcome_unknown = report.outcome_unknown;
            total.state_observed += report.state_observed;
            total.unknown_ids = report.unknown_ids;
            total.drain_instance_mismatch = report.drain_instance_mismatch;
            total.network_required |= report.network_required;
            if total.remaining == 0
                || !progress
                || total.network_required
                || started.elapsed() >= Duration::from_secs(10)
            {
                return Ok(total);
            }
        }
    }

    /// Match only creates of this session/repository with durable client_key deduplication.
    pub fn pending_task_create(
        &self,
        call: &Call,
        explicit_key: bool,
    ) -> Result<Call, ClientError> {
        if call.method != "POST"
            || call.path != "/api/v1/registry/items"
            || !call.body.as_ref().is_some_and(Value::is_object)
        {
            return Err(ClientError::Invalid(
                "expected a registry task create".into(),
            ));
        }
        let mut operations = self.try_pending_operations()?;
        operations.extend(self.unconsumed_settled_operations()?);
        for pending in operations {
            if pending.method != call.method
                || pending.request_path != call.path
                || pending.session != call.session
                || pending.repository != call.repository
                || registry_create_key(&pending).is_none()
            {
                continue;
            }
            let Some(body) = pending
                .body
                .as_deref()
                .and_then(|bytes| serde_json::from_str::<Value>(bytes).ok())
            else {
                continue;
            };
            let mut recovered = call.clone();
            let candidate = recovered.body.as_mut().expect("task create has a body");
            if !explicit_key {
                candidate["client_key"] = body["client_key"].clone();
            }
            if let (Some(current), Some(original)) = (
                candidate.get_mut("evidence").and_then(Value::as_array_mut),
                body.get("evidence").and_then(Value::as_array),
            ) {
                for (current, original) in current.iter_mut().zip(original) {
                    current["observed_at"] = original["observed_at"].clone();
                    if current["kind"] == "commit"
                        && current["value"]
                            .as_str()
                            .is_some_and(crate::commit_names_file)
                        && let Some(current) = current.as_object_mut()
                    {
                        // Match the original digest with the journal's clear metadata,
                        // since Git resolution may change between invocations.
                        match original.get("commit_sha") {
                            Some(sha) => {
                                current.insert("commit_sha".into(), sha.clone());
                            }
                            None => {
                                current.remove("commit_sha");
                            }
                        }
                    }
                }
            }
            // The digest binds caller plaintext before encryption; never compare ciphertext
            // or put encrypted journal bytes back into a new plaintext request.
            if pending.request_digest.as_deref()
                == Some(crate::request_identity(&recovered).as_str())
            {
                recovered.key = Some(pending.key);
                return Ok(recovered);
            }
        }
        Ok(call.clone())
    }

    /// Retrieve exact bytes for receipt reconciliation; do not log this value.
    pub fn pending_operation(&self, key: &str) -> Option<PendingWrite> {
        self.try_pending_operation(key).ok().flatten()
    }

    pub(crate) fn try_pending_operation(
        &self,
        key: &str,
    ) -> Result<Option<PendingWrite>, ClientError> {
        if let Some(journal) = &self.pending_journal {
            return journal.pending(key);
        }
        Ok(self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .get(key)
            .cloned())
    }

    pub fn pending_operations(&self) -> Vec<PendingWrite> {
        self.try_pending_operations().unwrap_or_default()
    }

    pub fn try_pending_operations(&self) -> Result<Vec<PendingWrite>, ClientError> {
        if let Some(journal) = &self.pending_journal {
            return journal.pending_rows();
        }
        Ok(self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .values()
            .cloned()
            .collect())
    }

    pub(crate) fn pending_for_send(&self, key: &str) -> Result<Option<PendingWrite>, ClientError> {
        self.pending_for_send_before(key, None)
    }

    fn pending_for_send_before(
        &self,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<PendingWrite>, ClientError> {
        if let Some(journal) = &self.pending_journal {
            return journal.for_send(key, deadline);
        }
        self.try_pending_operation(key)
    }

    /// Retire an operation only after its receipt or domain state has been verified.
    pub fn resolve_pending(&self, key: &str) -> Result<(), ClientError> {
        if let Some(journal) = &self.pending_journal {
            return journal.complete(key);
        }
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(key);
        Ok(())
    }

    fn finish_pending(&self, pending: &PendingWrite) -> Result<(), ClientError> {
        if let Some(journal) = &self.pending_journal {
            journal
                .complete_verified(pending)
                .map_err(|_| ClientError::OutcomeUnknown(Box::new(pending.clone())))
        } else {
            self.resolve_pending(&pending.key)
        }
    }

    fn discard_unsent(&self, row: &PendingWrite) -> Result<(), ClientError> {
        if let Some(journal) = &self.pending_journal {
            if !journal.discard_unshared(row)? {
                return Err(ClientError::OutcomeUnknown(Box::new(row.clone())));
            }
            return Ok(());
        }
        self.resolve_pending(&row.key)
    }

    pub(crate) fn repair_before_admission(
        &self,
        new_bytes: usize,
        budget: Duration,
    ) -> Result<(), ClientError> {
        let deadline = Instant::now() + budget.min(Duration::from_secs(2));
        if let Some(journal) = &self.pending_journal
            && journal.full(new_bytes, deadline)?
        {
            self.repair_pending_for_capacity(deadline)?;
        }
        Ok(())
    }

    pub(crate) fn admit_pending(
        &self,
        operation: &PendingWrite,
    ) -> Result<Option<PendingWrite>, ClientError> {
        self.admit_pending_before(operation, None)
    }

    fn admit_pending_before(
        &self,
        operation: &PendingWrite,
        deadline: Option<Instant>,
    ) -> Result<Option<PendingWrite>, ClientError> {
        let encoded = serde_json::to_vec(operation).map_err(journal_error)?;
        if encoded.len() > MAX_PENDING_BYTES as usize {
            return Err(journal_error("pending record exceeds budget"));
        }
        if let Some(journal) = &self.pending_journal {
            return match journal.admit(operation, &encoded, deadline)? {
                Admission::Inserted => Ok(None),
                Admission::Existing(existing) => Ok(Some(*existing)),
                Admission::Full => Err(Self::capacity_error()),
            };
        }
        let mut state = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = state.pending.get(&operation.key) {
            return Ok(Some(previous.clone()));
        }
        if maintenance::uses_replay_budget(operation) {
            let mut count = 0;
            let mut bytes = encoded.len();
            for entry in state
                .pending
                .values()
                .filter(|row| maintenance::uses_replay_budget(row))
            {
                count += 1;
                bytes =
                    bytes.saturating_add(serde_json::to_vec(entry).map_err(journal_error)?.len());
            }
            if count >= MAX_PENDING || bytes > MAX_PENDING_BYTES as usize {
                return Err(Self::capacity_error());
            }
        }
        state
            .pending
            .insert(operation.key.clone(), operation.clone());
        Ok(None)
    }

    fn capacity_error() -> ClientError {
        journal_error(
            "pending operation budget exceeded; run `lockyard doctor --repair-pending`; нужна сеть для сверки (network required); no pending operations were discarded",
        )
    }

    #[cfg(test)]
    pub(crate) fn retain_pending(&self, operation: PendingWrite) -> Result<(), ClientError> {
        match self.admit_pending(&operation)? {
            None => Ok(()),
            Some(existing) => Err(ClientError::OutcomeUnknown(Box::new(existing))),
        }
    }

    pub(crate) fn update_pending(
        &self,
        previous: &PendingWrite,
        operation: PendingWrite,
    ) -> Result<bool, ClientError> {
        self.update_pending_before(previous, operation, None)
    }

    fn update_pending_before(
        &self,
        previous: &PendingWrite,
        operation: PendingWrite,
        deadline: Option<Instant>,
    ) -> Result<bool, ClientError> {
        if let Some(journal) = &self.pending_journal {
            return journal.update(previous, &operation, deadline);
        }
        let mut state = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.pending.get(&previous.key) != Some(previous) {
            return Ok(false);
        }
        state.pending.insert(operation.key.clone(), operation);
        Ok(true)
    }

    pub(crate) fn begin_pending_replay(
        &self,
        previous: &PendingWrite,
        row: &PendingWrite,
    ) -> Result<bool, ClientError> {
        self.begin_pending_replay_before(previous, row, None)
    }

    pub(super) fn begin_pending_replay_before(
        &self,
        previous: &PendingWrite,
        row: &PendingWrite,
        deadline: Option<Instant>,
    ) -> Result<bool, ClientError> {
        if let Some(journal) = &self.pending_journal {
            return journal.begin_replay_before(previous, row, deadline);
        }
        self.update_pending(previous, row.clone())
    }

    fn retain_refusal(
        &self,
        mut pending: PendingWrite,
        error: &ClientError,
        deadline: Option<Instant>,
    ) -> Result<Option<PendingWrite>, ClientError> {
        let previous = pending.clone();
        pending.pre_execution_rejected = true;
        pending.cause_code = error.code().unwrap_or("outcome_unknown").to_owned();
        pending.cause_status = error.status();
        Ok(self
            .update_pending_before(&previous, pending.clone(), deadline)?
            .then_some(pending))
    }

    /// Resolve the current generation without performing any write or changing origin.
    pub fn negotiated_protocol(&self, session: &str) -> Result<NegotiatedProtocol, ClientError> {
        self.discover(session, None, None, false)
    }

    pub(crate) fn refresh_protocol(
        &self,
        session: &str,
    ) -> Result<NegotiatedProtocol, ClientError> {
        self.discover(session, None, None, true)
    }

    fn discover(
        &self,
        session: &str,
        remaining: Option<Duration>,
        cancellation: Option<&Cancellation>,
        refresh: bool,
    ) -> Result<NegotiatedProtocol, ClientError> {
        let started = Instant::now();
        let cached = || {
            self.protocol_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cached
                .as_ref()
                .filter(|cached| cached.obtained.elapsed() < CACHE_TTL)
                .map(|cached| cached.value.clone())
        };
        if !refresh && let Some(value) = cached() {
            return Ok(value);
        }
        // Serialize discovery without holding the pending journal state mutex over HTTP.
        // A sibling can still use a fresh cached protocol while a forced refresh is in flight.
        let _discovery = if remaining.is_some() || cancellation.is_some() {
            loop {
                if let Some(cancellation) = cancellation {
                    cancellation.check()?;
                }
                match self.protocol_discovery.try_lock() {
                    Ok(lock) => break lock,
                    Err(std::sync::TryLockError::Poisoned(error)) => break error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        let left = remaining
                            .map(|limit| limit.saturating_sub(started.elapsed()))
                            .unwrap_or(Duration::from_millis(1));
                        if left.is_zero() {
                            return Err(ClientError::Transport(
                                "call deadline elapsed waiting for discovery".into(),
                            ));
                        }
                        std::thread::sleep(left.min(Duration::from_millis(1)));
                    }
                }
            }
        } else {
            self.protocol_discovery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        if !refresh && let Some(value) = cached() {
            return Ok(value);
        }
        let mut call = Call::get(session, DISCOVERY.into());
        call.cancellation = cancellation.cloned();
        let mut selected = 2;
        for attempt in 0..2 {
            let budget = remaining.map(|limit| limit.saturating_sub(started.elapsed()));
            if budget.is_some_and(|limit| limit.is_zero()) {
                return Err(ClientError::Transport(
                    "call deadline elapsed during discovery".into(),
                ));
            }
            let capability = std::sync::atomic::AtomicBool::new(true);
            let auto_area_capability = std::sync::atomic::AtomicBool::new(true);
            let result = self.attempt_observed(
                &call,
                None,
                budget,
                &NegotiatedProtocol::candidate(selected),
                Some(&capability),
                Some(&auto_area_capability),
                true,
            );
            match result {
                Ok(value) => {
                    let mut result = parse_discovery(value, selected)?;
                    if capability.load(std::sync::atomic::Ordering::Relaxed) {
                        result
                            .capabilities
                            .insert(crate::REGISTRY_ASSIGNEE_SESSION.into());
                    }
                    if auto_area_capability.load(std::sync::atomic::Ordering::Relaxed) {
                        result.capabilities.insert(crate::REGISTRY_AUTO_AREA.into());
                    }
                    if self
                        .mail_open_v1_observed
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        result.capabilities.insert(crate::MAIL_OPEN_V1.into());
                    }
                    self.save_status_protocol_hint(&result);
                    self.protocol_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .cached = Some(CachedProtocol {
                        value: result.clone(),
                        obtained: Instant::now(),
                    });
                    return Ok(result);
                }
                Err(Failure::Final(error) | Failure::Retry(error))
                    if error.status() == Some(400)
                        && error.code() == Some("protocol_unsupported") =>
                {
                    let api = error.api_error().expect("remote unsupported");
                    let range = range(&api.details)?;
                    let supported = api
                        .details
                        .get("supported_protocols")
                        .and_then(Value::as_array)
                        .ok_or_else(|| {
                            local(
                                "protocol_response_invalid",
                                "unsupported response omits supported protocols",
                            )
                        })?;
                    let expected: BTreeSet<u16> = (range.min..=range.max).collect();
                    let advertised: Option<BTreeSet<u16>> = supported
                        .iter()
                        .map(|value| value.as_u64().and_then(|number| u16::try_from(number).ok()))
                        .collect();
                    if api.details.get("selected_protocol") != Some(&Value::Null)
                        || advertised.as_ref() != Some(&expected)
                        || supported.len() != expected.len()
                    {
                        return Err(local(
                            "protocol_response_invalid",
                            "unsupported response contradicts its protocol range",
                        ));
                    }
                    let Some(common) = range.common() else {
                        return Err(error);
                    };
                    if attempt > 0 || common >= selected {
                        return Err(error);
                    }
                    selected = common;
                }
                Err(Failure::Final(error) | Failure::Retry(error))
                    if matches!(error.status(), Some(404 | 405)) =>
                {
                    // This preliminary GET is the sole path that permits headerless legacy.
                    let legacy = NegotiatedProtocol {
                        selected: 1,
                        capabilities: BTreeSet::new(),
                        legacy: true,
                    };
                    let mut probe = Call::get(session, crate::ENCRYPTION_PATH.into());
                    probe.cancellation = cancellation.cloned();
                    let budget = remaining.map(|limit| limit.saturating_sub(started.elapsed()));
                    if budget.is_some_and(|limit| limit.is_zero()) {
                        return Err(ClientError::Transport(
                            "call deadline elapsed during discovery".into(),
                        ));
                    }
                    let policy = self
                        .attempt(&probe, None, budget, &legacy)
                        .map_err(failure_error)?;
                    let policy: WorkspaceEncryption =
                        serde_json::from_value(policy).map_err(|_| {
                            local(
                                "protocol_response_invalid",
                                "legacy encryption probe is not a typed workspace policy",
                            )
                        })?;
                    if !matches!(policy.encryption.as_str(), "off" | "required")
                        || !crate::valid_workspace_identity(&policy.workspace_id)
                        || (policy.encryption == "required" && policy.key_id.is_none())
                    {
                        return Err(local(
                            "protocol_response_invalid",
                            "legacy encryption policy values are invalid",
                        ));
                    }
                    self.protocol_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .cached = Some(CachedProtocol {
                        value: legacy.clone(),
                        obtained: Instant::now(),
                    });
                    return Ok(legacy);
                }
                Err(failure) => return Err(failure_error(failure)),
            }
        }
        Err(local(
            "protocol_unsupported",
            "client and server have no common HTTP protocol; upgrade the client or server",
        ))
    }

    fn feature_gate(
        &self,
        call: &Call,
        protocol: &NegotiatedProtocol,
        encryption_enabled: bool,
    ) -> Result<(), ClientError> {
        let route = call.path.split('?').next().unwrap_or(&call.path);
        let required = if route == "/api/v1/zones/catalog"
            && (call.is_write() || encryption_enabled || self.expected_e2ee_workspace.is_some())
        {
            Some(("zone_catalog_v1", 2))
        } else if route == "/api/v1/revocations" || route.starts_with("/api/v1/revocations/") {
            Some(("revocations_v1", 1))
        } else if route == "/api/v1/admin/drain" || route.starts_with("/api/v1/admin/drain/") {
            Some(("drain_v1", 2))
        } else {
            None
        };
        if let Some((capability, minimum)) = required {
            if !protocol.capabilities.contains(capability) {
                return Err(local(
                    "feature_unsupported",
                    &format!("server does not confirm {capability}; upgrade the server"),
                ));
            }
            if protocol.selected < minimum {
                return Err(local(
                    "upgrade_required",
                    "feature requires a newer selected HTTP protocol",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn call_negotiated(&self, call: &Call) -> Result<Value, ClientError> {
        self.call_negotiated_observed(call, None)
    }

    pub(crate) fn cached_registry_assignee_supported(
        &self,
        deadline: Instant,
        cancellation: Option<&Cancellation>,
    ) -> bool {
        // A warm agent's upkeep also takes this mutex for cached reads. Brief contention must
        // not hide already-negotiated support. Wait only inside this status read's deadline,
        // without initiating discovery or waiting unboundedly behind another discovery.
        loop {
            if cancellation.is_some_and(Cancellation::is_cancelled) {
                return false;
            }
            let state = match self.protocol_state.try_lock() {
                Ok(state) => state,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    std::thread::sleep(left.min(Duration::from_millis(1)));
                    continue;
                }
            };
            return state.cached.as_ref().is_some_and(|cached| {
                cached.obtained.elapsed() < CACHE_TTL
                    && cached
                        .value
                        .capabilities
                        .contains(crate::REGISTRY_ASSIGNEE_SESSION)
            });
        }
    }

    /// Fresh negotiated cache or the latest successful `Lockyard-Capabilities` observation.
    /// Never starts discovery; contention waits only until `deadline`.
    pub(crate) fn cached_mail_open_v1(
        &self,
        deadline: Instant,
        cancellation: Option<&Cancellation>,
    ) -> bool {
        if self
            .mail_open_v1_observed
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return true;
        }
        loop {
            if cancellation.is_some_and(Cancellation::is_cancelled) {
                return false;
            }
            let state = match self.protocol_state.try_lock() {
                Ok(state) => state,
                Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return false;
                    }
                    std::thread::sleep(left.min(Duration::from_millis(1)));
                    continue;
                }
            };
            return state.cached.as_ref().is_some_and(|cached| {
                cached.obtained.elapsed() < CACHE_TTL
                    && cached.value.capabilities.contains(crate::MAIL_OPEN_V1)
            });
        }
    }

    pub(crate) fn call_negotiated_observed(
        &self,
        call: &Call,
        registry_capability: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Value, ClientError> {
        let mut resent_after_contention = false;
        let result =
            self.call_negotiated_inner(call, registry_capability, &mut resent_after_contention);
        match result {
            // The key was already used by a same-key sibling whose bytes this call never saw
            // (a fresh encryption differs). The server applied that sibling's write at most once;
            // this caller reconciles by key instead of reading a conflict (LOCAL-0148).
            Err(error) if resent_after_contention && idempotency_key_reused(&error) => {
                Err(reconcile_by_key(
                    call.key.as_deref().expect("validated write key"),
                    "the server refused this key as already used",
                ))
            }
            other => other,
        }
    }

    fn call_negotiated_inner(
        &self,
        call: &Call,
        registry_capability: Option<&std::sync::atomic::AtomicBool>,
        resent_after_contention: &mut bool,
    ) -> Result<Value, ClientError> {
        call.check_cancelled()?;
        if call.is_write() && call.key.as_deref().is_none_or(str::is_empty) {
            return Err(ClientError::Invalid(
                "writes require an Idempotency-Key".into(),
            ));
        }
        // One clock for journal-busy waits, Retry-After pauses, and remaining()/wait_fits_deadline.
        // Without an explicit call deadline the journal wait budget is MAX_RETRY_WAIT (5 s).
        let started = Instant::now();
        let deadline = call
            .deadline_ms
            .and_then(|ms| started.checked_add(Duration::from_millis(ms)));
        let remaining = || {
            call.deadline_ms
                .map(|limit| Duration::from_millis(limit).saturating_sub(started.elapsed()))
        };
        let _send_guard = if call.is_write() {
            let budget = call
                .deadline_ms
                .map(Duration::from_millis)
                .unwrap_or(crate::MAX_RETRY_WAIT);
            let key = call.key.as_deref().expect("validated write key");
            loop {
                call.check_cancelled()?;
                match self.reserve_memory_send(key) {
                    Ok(guard) => break guard,
                    Err(ClientError::JournalBusy) if started.elapsed() < budget => {
                        *resent_after_contention = true;
                        call.wait(
                            budget
                                .saturating_sub(started.elapsed())
                                .min(Duration::from_millis(25)),
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            }
        } else {
            None
        };
        if let Some(value) = self.settled_response(call, &remaining, deadline)? {
            return Ok(value);
        }
        if call.is_write()
            && let Some(pending) =
                self.pending_for_send_before(call.key.as_deref().unwrap(), deadline)?
        {
            return self.replay_pending(call, pending, started);
        }
        let route = call.path.split('?').next().unwrap_or(&call.path);
        if !route.starts_with('/')
            || route.starts_with("//")
            || route.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(ClientError::Invalid(
                "request path must be an absolute API path".into(),
            ));
        }
        if let Some(expected) = &self.expected_e2ee_workspace
            && !(call.method == "GET" && route == crate::ENCRYPTION_PATH)
            && (!self.encryption_enabled
                || self.content_key.is_none()
                || self.workspace.as_deref() != Some(expected.as_str()))
        {
            return Err(ClientError::Invalid(
                "node content request requires a verified encrypted workspace context".into(),
            ));
        }
        if self.expected_e2ee_workspace.is_some() {
            crate::crypto::validate_required_route(&call.method, &call.path)
                .map_err(ClientError::Invalid)?;
        }
        let request_digest = crate::request_identity(call);
        let mut protocol = match self.discover(
            &call.session,
            remaining(),
            call.cancellation.as_ref(),
            false,
        ) {
            Ok(protocol) => protocol,
            Err(error @ ClientError::Transport(_)) => {
                if let Some(cached) = self.catalog_offline_call(call)? {
                    return Ok(cached);
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        // A logical call, including one restored from the daemon's outbox, gets
        // its first wire body under the live policy before it enters the HTTP journal.
        let live_write =
            self.check_live_write_encryption_policy && call.is_write() && call.body.is_some();
        let policy_read = call.method == "GET" && route == crate::ENCRYPTION_PATH;
        let current = (!live_write && !policy_read).then(|| self.current_content_encryption());
        let live = if live_write
            || (self.check_live_write_encryption_policy
                && !policy_read
                && (self.live_encryption_setting().is_none()
                    || matches!(route, "/api/v1/zones/catalog" | "/api/v1/events")
                    || current.as_ref().is_some_and(Result::is_err)))
        {
            match self.live_replay_encryption(
                self,
                remaining()
                    .unwrap_or(crate::MAX_RETRY_WAIT)
                    .min(Duration::from_secs(2)),
                call.cancellation.as_ref(),
            ) {
                Ok(setting) => setting,
                Err(error @ ClientError::Transport(_)) if !call.is_write() => {
                    if let Some(cached) = self.catalog_offline_call(call)? {
                        return Ok(cached);
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        // Snapshot one workspace and key for preparation and response verification.
        let encryption = if policy_read {
            ContentEncryption {
                workspace: None,
                key: None,
                enabled: false,
            }
        } else if let Some(setting) = live {
            // The policy GET may have had to renegotiate before it completed.
            protocol = self.discover(
                &call.session,
                remaining(),
                call.cancellation.as_ref(),
                false,
            )?;
            self.content_encryption_from(setting)?
        } else {
            current.unwrap_or_else(|| self.current_content_encryption())?
        };
        let workspace = encryption.workspace.as_deref();
        let content_key = encryption.key.as_ref();
        let encryption_enabled = encryption.enabled;
        self.feature_gate(call, &protocol, encryption_enabled)?;
        let key_id = content_key.map(crate::WorkspaceKey::key_id);
        let encryption_context = if live_write {
            self.encryption_context_for(workspace, key_id.as_deref(), encryption_enabled)
        } else {
            self.encryption_context()
        };
        // Seal the catalog with the same live workspace and key used to verify its reply.
        let prepared = self.prepare_catalog_call(call, workspace, content_key)?;
        let call = &prepared;
        let mut body = call.body.clone();
        // 579d557 requires mode. Only LC-0019 servers advertising this capability
        // may choose their own default. Freeze the selected wire bytes for retries.
        if call.method == "POST"
            && matches!(route, "/api/v1/zones/claims" | "/api/v1/zones/queue")
            && !protocol.capabilities.contains(crate::SOFT_ZONES_V1)
            && let Some(object) = body.as_mut().and_then(Value::as_object_mut)
            && !object.contains_key("mode")
        {
            object.insert("mode".into(), Value::String("exclusive".into()));
        }
        if (encryption_enabled || self.expected_e2ee_workspace.is_some())
            && call.method == "POST"
            && matches!(
                call.path.split('?').next(),
                Some("/api/v1/zones/claims" | "/api/v1/zones/queue")
            )
            && let Some(object) = body.as_mut().and_then(Value::as_object_mut)
        {
            // Names were expanded locally; only the selected routing paths leave this process.
            object.remove("zone");
            object.remove("zones");
        }
        let session = if call.session == crate::ANONYMOUS_SESSION {
            self.service_session(crate::ANONYMOUS_SESSION)
        } else {
            call.session.clone()
        };
        let mut identity_context = body.clone().unwrap_or_else(|| json!({}));
        identity_context["session"] = json!(session);
        if let (Some(value), Some(workspace)) = (&mut body, workspace) {
            crate::crypto::transform_fields_policy_context(
                value,
                &call.method,
                &call.path,
                workspace,
                content_key,
                encryption_enabled,
                self.expected_e2ee_workspace.is_some(),
                Some(&identity_context),
            )
            .map_err(content_error)?;
        }
        let encoded = body.as_ref().map(Value::to_string);
        let mut replica_changed = false;
        let attempts = if call.is_write() {
            crate::WRITE_ATTEMPTS
        } else {
            2
        };
        let mut delay = Duration::from_millis(100);
        let mut refused_pending: Option<PendingWrite> = None;
        for attempt in 1..=attempts {
            call.check_cancelled()?;
            if remaining().is_some_and(|limit| limit.is_zero()) {
                return Err(ClientError::Transport("call deadline elapsed".into()));
            }
            let wire_call = legacy_wire_call(call, &protocol)?;
            let pending = call.is_write().then(|| PendingWrite {
                code: "outcome_unknown".into(),
                cause_code: "outcome_unknown".into(),
                cause_status: None,
                diagnostic: None,
                protocol: protocol.clone(),
                method: call.method.clone(),
                path: wire_call.path.clone(),
                request_path: call.path.clone(),
                body: encoded.clone(),
                key: call.key.clone().expect("validated write key"),
                repository: call.repository.clone(),
                session: call.session.clone(),
                origin: self.base_url.clone(),
                credential_scope: crate::credential_fingerprint(&self.token),
                request_digest: Some(request_digest.clone()),
                first_sent_unix_secs: refused_pending.as_ref().map_or_else(
                    || {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|time| time.as_secs())
                    },
                    |pending| pending.first_sent_unix_secs,
                ),
                first_sent_server_secs: refused_pending.as_ref().map_or_else(
                    || self.first_send_server_secs(),
                    |row| row.first_sent_server_secs,
                ),
                replay_stopped: false,
                replay_paused: false,
                pre_execution_rejected: false,
                encryption_context: Some(encryption_context.clone()),
                result_expires_at: None,
                result_retry_at: None,
            });
            if let Some(pending) = &pending {
                if let Some(previous) = refused_pending.take() {
                    self.verify_pending_replay_encryption(
                        &previous,
                        remaining(),
                        call.cancellation.as_ref(),
                    )?;
                    if !self.begin_pending_replay_before(&previous, pending, deadline)? {
                        return Err(ClientError::OutcomeUnknown(Box::new(previous)));
                    }
                } else {
                    if maintenance::uses_replay_budget(pending) {
                        self.repair_before_admission(
                            serde_json::to_vec(pending).map_err(journal_error)?.len(),
                            remaining().unwrap_or(crate::MAX_RETRY_WAIT),
                        )?;
                    }
                    call.check_cancelled()?;
                    if remaining().is_some_and(|limit| limit.is_zero()) {
                        return Err(ClientError::Transport("call deadline elapsed".into()));
                    }
                    if let Some(existing) = self.admit_pending_before(pending, deadline)? {
                        if let Some(receipt) = self.settled_response(call, &remaining, deadline)? {
                            return Ok(receipt);
                        }
                        return self.replay_pending(call, existing, started);
                    }
                    if attempt > 1 {
                        self.verify_pending_replay_encryption(
                            pending,
                            remaining(),
                            call.cancellation.as_ref(),
                        )?;
                    }
                }
            }
            let result = match &pending {
                Some(pending) if live_write || attempt > 1 => self.attempt_frozen(
                    self,
                    &wire_call,
                    pending,
                    remaining(),
                    registry_capability,
                    attempt == 1,
                ),
                _ => self.attempt_observed(
                    &wire_call,
                    encoded.as_deref(),
                    remaining(),
                    &protocol,
                    registry_capability,
                    None,
                    attempt == 1,
                ),
            };
            let failure = match result {
                Ok(mut value) => {
                    // Authenticate/decrypt the response before releasing its recovery record.
                    let event_page = call.method == "GET"
                        && call.path.split('?').next() == Some("/api/v1/events");
                    if event_page {
                        self.decode_json_events(&mut value, &encryption)?;
                    }
                    if !event_page
                        && let Some(workspace) = workspace
                        && let Err(message) = crate::crypto::transform_fields_policy(
                            &mut value,
                            &call.method,
                            &call.path,
                            workspace,
                            content_key,
                            false,
                            self.expected_e2ee_workspace.is_some(),
                        )
                    {
                        if let Some(pending) = pending {
                            let cause = if message.starts_with("catalog_") {
                                message.as_str()
                            } else {
                                "content_authentication_failed"
                            };
                            return Err(self.unknown(pending, cause, None));
                        }
                        return Err(content_error(message));
                    }
                    crate::commit_evidence::warn_if_sha_missing(
                        call,
                        encryption_enabled,
                        &mut value,
                    );
                    if let Err(error) = self.finish_catalog_call(
                        call,
                        &mut value,
                        workspace,
                        content_key,
                        encryption_enabled,
                    ) {
                        if let Some(pending) = pending {
                            let cause = error
                                .code()
                                .unwrap_or("catalog_authentication_failed")
                                .to_string();
                            return Err(self.unknown(pending, &cause, None));
                        }
                        return Err(error);
                    }
                    if let Some(pending) = pending
                        && !call.defer_pending_ack
                    {
                        self.finish_pending(&pending)?;
                    }
                    return Ok(value);
                }
                Err(failure) => failure,
            };
            let (error, may_retry) = match failure {
                Failure::BeforeSend(error) => {
                    let pending = pending.expect("policy check belongs to a frozen write");
                    let changed = error.code() == Some(maintenance::ENCRYPTION_MISMATCH);
                    if attempt == 1 {
                        // The policy check stopped this body before its first HTTP send.
                        self.discard_unsent(&pending)?;
                        return Err(if changed {
                            ClientError::Transport(
                                "workspace encryption policy changed before send".into(),
                            )
                        } else {
                            error
                        });
                    }
                    return Err(if changed {
                        self.park_incompatible_pending(&pending, None)?
                    } else {
                        ClientError::OutcomeUnknown(Box::new(pending))
                    });
                }
                Failure::Final(error) => (error, false),
                Failure::Retry(error) => (error, true),
            };
            let replayable = pending
                .as_ref()
                .is_none_or(maintenance::eligible_for_recovery);
            let uncertain = (error.status() == Some(408)
                && (!replayable
                    || (call.method == "POST" && call.path == "/api/v1/registry/items")))
                || matches!(&error, ClientError::Transport(_) | ClientError::Decode(_))
                || matches!(
                    error.code(),
                    Some("protocol_response_invalid" | "content_authentication_failed")
                )
                || (error.code() == Some("catalog_invalid") && error.status() != Some(400));
            if let Some(pending) = pending {
                if uncertain {
                    let cause = error.code().unwrap_or("outcome_unknown").to_string();
                    return Err(self.unknown(pending, &cause, error.status()));
                }
                if error.api_error().is_some_and(|api| {
                    api.status >= 500
                        && !(api.status == 503
                            && matches!(api.code.as_str(), "frozen" | "server_draining"))
                }) {
                    let cause = error.code().unwrap_or("outcome_unknown").to_string();
                    let unknown = self.unknown(pending, &cause, error.status());
                    return Err(
                        if !replayable
                            || call.defer_pending_ack
                            || (call.method == "POST" && call.path == "/api/v1/registry/items")
                        {
                            unknown
                        } else {
                            error
                        },
                    );
                }
                if pre_execution_refusal(&error) {
                    let original = pending.clone();
                    refused_pending = self.retain_refusal(pending, &error, None)?;
                    if refused_pending.is_none() {
                        return Err(ClientError::OutcomeUnknown(Box::new(original)));
                    }
                } else {
                    self.discard_unsent(&pending)?;
                }
            }
            if call.path.contains("&assignee_session=")
                && registry_capability.is_some_and(|capability| {
                    !capability.load(std::sync::atomic::Ordering::Relaxed)
                })
            {
                return Err(error);
            }
            if replayable
                && error.code() == Some("protocol_unsupported")
                && error.status() == Some(400)
                && !replica_changed
            {
                replica_changed = true;
                self.invalidate_status_protocol_hint();
                protocol =
                    self.discover(&call.session, remaining(), call.cancellation.as_ref(), true)?;
                if call.path.contains("&assignee_session=")
                    && let Some(capability) = registry_capability
                    && !protocol
                        .capabilities
                        .contains(crate::REGISTRY_ASSIGNEE_SESSION)
                {
                    capability.store(false, std::sync::atomic::Ordering::Relaxed);
                    return Err(error);
                }
                self.feature_gate(call, &protocol, encryption_enabled)?;
                continue;
            }
            let temporary = error
                .api_error()
                .is_some_and(|error| matches!(error.code.as_str(), "frozen" | "server_draining"));
            let safe = safe_retry(&error) || (call.deadline_ms.is_some() && temporary);
            let retry = attempt < attempts
                && ((call.is_write() && replayable && safe)
                    || (!call.is_write()
                        && may_retry
                        && matches!(error, ClientError::Transport(_))));
            if !retry || !crate::wait_fits_deadline(call.deadline_ms, started, &error, delay) {
                if matches!(error, ClientError::Transport(_))
                    && let Some(cached) = self.catalog_offline_call(call)?
                {
                    return Ok(cached);
                }
                return Err(error);
            }
            // Never shorten Retry-After to the local wait cap.
            if error
                .retry_after()
                .is_some_and(|seconds| Duration::from_secs(seconds) > crate::MAX_RETRY_WAIT)
            {
                return Err(error);
            }
            call.wait(crate::retry_wait(&error, delay))?;
            delay *= 2;
        }
        Err(local(
            "protocol_unsupported",
            "replica protocol changed repeatedly",
        ))
    }

    /// Replay the frozen operation only under a proven server contract and within its
    /// guaranteed retention. The receipt clock stays anchored to the first send.
    fn replay_pending(
        &self,
        call: &Call,
        mut pending: PendingWrite,
        started: Instant,
    ) -> Result<Value, ClientError> {
        let refused = pending.pre_execution_rejected;
        if !maintenance::eligible_for_recovery(&pending)
            || pending.request_digest.as_deref() != Some(crate::request_identity(call).as_str())
            || pending.method != call.method
            || pending.request_path != call.path
            || pending.origin != self.base_url
            || pending.credential_scope != crate::credential_fingerprint(&self.token)
        {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        let mut wire = call.clone();
        wire.method = pending.method.clone();
        wire.path = pending.path.clone();
        wire.session = pending.session.clone();
        wire.repository = pending.repository.clone();
        wire.key = Some(pending.key.clone());
        let remaining = || {
            call.deadline_ms
                .map(|ms| Duration::from_millis(ms).saturating_sub(started.elapsed()))
        };
        if remaining().is_some_and(|limit| limit.is_zero()) {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        if !self.can_replay_pending(&pending, remaining(), call.cancellation.as_ref())? {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        let encryption = self.verify_pending_replay_encryption(
            &pending,
            remaining(),
            call.cancellation.as_ref(),
        )?;
        let live_write = self.check_live_write_encryption_policy;
        if pending.encryption_context.is_none()
            || (!live_write
                && (!self.pending_encryption_context_ready()
                    || pending.encryption_context.as_deref()
                        != Some(self.encryption_context().as_str())))
        {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        let previous = pending.clone();
        if refused {
            pending.pre_execution_rejected = false;
            pending.cause_code = "outcome_unknown".into();
            pending.cause_status = None;
        }
        let deadline = call
            .deadline_ms
            .and_then(|ms| started.checked_add(Duration::from_millis(ms)));
        if !self.begin_pending_replay_before(&previous, &pending, deadline)? {
            if let Some(receipt) = self.settled_response(call, &remaining, deadline)? {
                return Ok(receipt);
            }
            return Err(ClientError::OutcomeUnknown(Box::new(previous)));
        }
        // The SQLite transaction ends before HTTP. Concurrent callers use the
        // same wire bytes, and a completed row is never changed back to pending.
        let replay_started = Instant::now();
        let mut value = match self.reconcile_wire(&wire, &pending, || {
            remaining()
                .unwrap_or_else(|| crate::MAX_RETRY_WAIT.saturating_sub(replay_started.elapsed()))
        }) {
            Ok(value) => value,
            Err(error) => {
                if idempotency_key_reused(&error) {
                    return Err(reconcile_by_key(
                        &pending.key,
                        "the server refused this key as already used",
                    ));
                }
                if error.code() == Some(maintenance::ENCRYPTION_MISMATCH) {
                    return Err(self.park_incompatible_pending(&pending, None)?);
                }
                if error.code() == Some("drain_instance_mismatch") {
                    let result =
                        self.unknown(pending.clone(), "drain_instance_mismatch", error.status());
                    if let Some(updated) = self.pending_operation(&pending.key) {
                        self.park_pending(&updated, false, None)?;
                    }
                    return Err(result);
                }
                if refused && replay_refusal(&error) {
                    return if self
                        .retain_refusal(pending.clone(), &error, None)?
                        .is_some()
                    {
                        Err(error)
                    } else {
                        Err(ClientError::OutcomeUnknown(Box::new(pending)))
                    };
                }
                if self.explicit_expiry(&pending, &error, None)? {
                    return Err(ClientError::OutcomeUnknown(Box::new(pending)));
                }
                if refused
                    && error.api_error().is_some_and(|api| api.status < 500)
                    && !maintenance::outcome_unproven(&error)
                {
                    // The per-attempt failure proves refusal only while this is
                    // still the sole possible execution.
                    return if self
                        .retain_refusal(pending.clone(), &error, None)?
                        .is_some()
                    {
                        Err(error)
                    } else {
                        Err(ClientError::OutcomeUnknown(Box::new(pending)))
                    };
                }
                let cause = error.code().unwrap_or("outcome_unknown").to_owned();
                let diagnostic = (cause == "protocol_response_invalid").then(|| error.to_string());
                return Err(self.record_unknown(pending, &cause, error.status(), diagnostic, None));
            }
        };
        self.decode_pending_response(
            call,
            &pending,
            &mut value,
            live_write.then_some(&encryption),
        )?;
        if !call.defer_pending_ack {
            self.finish_pending(&pending)?;
        }
        // The agent acknowledges only after its outbox completion marker is durable.
        Ok(value)
    }

    fn pending_encryption_context_ready(&self) -> bool {
        self.expected_e2ee_workspace
            .as_deref()
            .is_none_or(|expected| {
                self.encryption_enabled
                    && self.content_key.is_some()
                    && self.workspace.as_deref() == Some(expected)
            })
    }

    fn decode_pending_response(
        &self,
        call: &Call,
        pending: &PendingWrite,
        value: &mut Value,
        encryption: Option<&ContentEncryption>,
    ) -> Result<(), ClientError> {
        // Snapshot-checked updates cannot reinsert completed or retired rows.
        let unknown =
            |cause: &str, status: Option<u16>| self.unknown(pending.clone(), cause, status);
        let (workspace, held, enabled) = match encryption {
            Some(encryption) => (
                encryption.workspace.as_deref(),
                encryption.key.clone(),
                encryption.enabled,
            ),
            None => (
                self.workspace.as_deref(),
                self.resolved_content_key()?,
                self.encryption_enabled,
            ),
        };
        if let Some(workspace) = workspace
            && let Err(message) = crate::crypto::transform_fields_policy(
                value,
                &call.method,
                &call.path,
                workspace,
                held.as_ref(),
                false,
                self.expected_e2ee_workspace.is_some(),
            )
        {
            let cause = if message.starts_with("catalog_") {
                message.as_str()
            } else {
                "content_authentication_failed"
            };
            return Err(unknown(cause, None));
        }
        crate::commit_evidence::warn_if_sha_missing(call, enabled, value);
        if let Err(error) = self.finish_catalog_call(call, value, workspace, held.as_ref(), enabled)
        {
            let cause = error
                .code()
                .unwrap_or("catalog_authentication_failed")
                .to_owned();
            return Err(unknown(&cause, error.status()));
        }
        Ok(())
    }

    pub(crate) fn unknown(
        &self,
        pending: PendingWrite,
        cause: &str,
        status: Option<u16>,
    ) -> ClientError {
        self.record_unknown(pending, cause, status, None, None)
    }

    fn record_unknown(
        &self,
        mut pending: PendingWrite,
        cause: &str,
        status: Option<u16>,
        diagnostic: Option<String>,
        deadline: Option<Instant>,
    ) -> ClientError {
        let previous = pending.clone();
        pending.pre_execution_rejected = false;
        pending.cause_code = cause.into();
        pending.cause_status = status;
        if diagnostic.is_some() {
            pending.diagnostic = diagnostic;
        }
        if !maintenance::uses_replay_budget(&pending)
            || maintenance::ambiguous_refusal_needs_operator(&pending)
        {
            pending.replay_paused = true;
        }
        // A storage failure leaves the already-synced pre-send record intact.
        let _ = self.update_pending_before(&previous, pending.clone(), deadline);
        ClientError::OutcomeUnknown(Box::new(pending))
    }
}

/// The server refused this body because the key already belongs to another request.
/// Coordination answers `conflict` and the registry its own code with the same text.
fn reconcile_by_key(key: &str, reason: &str) -> ClientError {
    ClientError::Protocol(Problem {
        status: None,
        code: "outcome_unknown".into(),
        detail: format!("Reconcile the mutation outcome using Idempotency-Key {key}: {reason}"),
        details: json!({"idempotency_key": key}),
    })
}

fn idempotency_key_reused(error: &ClientError) -> bool {
    const TEXT: &str = "Idempotency-Key was used for another request";
    error.status() == Some(409)
        && (error.code() == Some("idempotency_conflict")
            || error
                .api_error()
                .is_some_and(|api| api.message.contains(TEXT)))
}

fn failure_error(failure: Failure) -> ClientError {
    match failure {
        Failure::BeforeSend(error) | Failure::Final(error) | Failure::Retry(error) => error,
    }
}

fn legacy_wire_call(call: &Call, protocol: &NegotiatedProtocol) -> Result<Call, ClientError> {
    let mut wire = call.clone();
    if protocol.selected == 1
        && let Some(tail) = call.path.strip_prefix("/api/v1/bus/tasks/")
    {
        let end = tail.find(['/', '?']).unwrap_or(tail.len());
        let id = &tail[..end];
        let receipt = lockyard_compat::LegacyCompatibilityV1::task_receipt(
            id,
            lockyard_compat::TaskDomain::Bus,
            lockyard_compat::Source::Sdk,
            1,
        )
        .map_err(|code| {
            local(
                &code,
                "task ID cannot be represented by this protocol-one server",
            )
        })?;
        wire.path = format!("/api/v1/bus/tasks/{}{}", receipt, &tail[end..]);
    }
    Ok(wire)
}

fn range(value: &Value) -> Result<ProtocolRange, ClientError> {
    let invalid = || {
        local(
            "protocol_response_invalid",
            "server advertised an invalid HTTP protocol range",
        )
    };
    let parse = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|number| u16::try_from(number).ok())
            .ok_or_else(invalid)
    };
    let result = ProtocolRange {
        min: parse("min_protocol")?,
        max: parse("max_protocol")?,
    };
    if !result.valid() {
        return Err(invalid());
    }
    Ok(result)
}

fn parse_discovery(value: Value, requested: u16) -> Result<NegotiatedProtocol, ClientError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Discovery {
        selected_protocol: u16,
        min_protocol: u16,
        max_protocol: u16,
        capabilities: Vec<String>,
    }
    let discovery: Discovery = serde_json::from_value(value)
        .map_err(|_| local("protocol_response_invalid", "invalid HTTP discovery schema"))?;
    let range = ProtocolRange {
        min: discovery.min_protocol,
        max: discovery.max_protocol,
    };
    if !range.valid()
        || range.common() != Some(requested)
        || discovery.selected_protocol != requested
    {
        return Err(local(
            "protocol_response_invalid",
            "discovery does not select the highest common requested HTTP protocol",
        ));
    }
    let count = discovery.capabilities.len();
    if count > 64
        || discovery.capabilities.iter().any(|capability| {
            capability.is_empty()
                || capability.len() > 64
                || !capability
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(local("protocol_response_invalid", "invalid capability set"));
    }
    let capabilities: BTreeSet<_> = discovery.capabilities.into_iter().collect();
    if capabilities.len() != count {
        return Err(local("protocol_response_invalid", "duplicate capability"));
    }
    Ok(NegotiatedProtocol {
        selected: requested,
        capabilities,
        legacy: false,
    })
}

pub(crate) fn journal_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Invalid(format!("pending journal unavailable: {error}"))
}

fn journal_decode_error(error: serde_json::Error) -> ClientError {
    journal_error(format!(
        "invalid pending record at line {}, column {}",
        error.line(),
        error.column()
    ))
}

fn journal_path(directory: &Path, key: &str) -> PathBuf {
    directory.join(format!("{}.json", crate::credential_fingerprint(key)))
}

fn read_private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ClientError> {
    private_file(&std::fs::symlink_metadata(path).map_err(journal_error)?)?;
    let mut options = StateOpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(journal_error)?;
    let metadata = file.metadata().map_err(journal_error)?;
    private_file(&metadata)?;
    if metadata.len() > MAX_PENDING_BYTES {
        return Err(journal_error("pending record exceeds budget"));
    }
    serde_json::from_reader(std::io::BufReader::new(file)).map_err(journal_decode_error)
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<(), ClientError> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component);
        match std::fs::symlink_metadata(&ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(journal_error("pending directory contains a symlink"));
            }
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let mode = metadata.permissions().mode();
                    if metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() }
                        || mode & 0o022 != 0 && mode & 0o1000 == 0
                    {
                        return Err(journal_error(
                            "pending directory has an untrusted writable ancestor",
                        ));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(journal_error(error)),
        }
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(journal_error)?;
    let metadata = std::fs::symlink_metadata(path).map_err(journal_error)?;
    if !metadata.is_dir() {
        return Err(journal_error("pending path is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(journal_error("pending directory is not private"));
        }
    }
    Ok(())
}

fn private_file(metadata: &std::fs::Metadata) -> Result<(), ClientError> {
    if !metadata.is_file() || metadata.len() > MAX_PENDING_BYTES {
        return Err(journal_error("invalid pending journal file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(journal_error("pending journal file is not private"));
        }
    }
    Ok(())
}

/// Decode one JSON document without collapsing repeated keys, including nested objects.
pub fn strict_json(raw: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str::<UniqueJson>(raw).map(|value| value.0)
}

/// Error code/range extensions are security-relevant; duplicate object keys are invalid.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Value;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(value))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueJson>()? {
                    values.push(value.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    values.insert(key, map.next_value::<UniqueJson>()?.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(Visitor).map(Self)
    }
}

#[cfg(windows)]
use lockyard_core::windows::OpenOptions as StateOpenOptions;
#[cfg(unix)]
use std::fs::OpenOptions as StateOpenOptions;

#[cfg(windows)]
fn private_directory(path: &Path) -> Result<(), ClientError> {
    lockyard_core::windows::private_dir(path).map_err(journal_error)
}

#[cfg(test)]
pub(super) mod pending_completion_tests {
    use super::*;

    #[test]
    fn task_pending_create_reuses_keys_after_restart_only_for_same_arguments_at_any_age() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let client = Client::new("http://127.0.0.1:1", "fixture".into())
            .unwrap()
            .with_pending_journal(&root)
            .unwrap();
        let original = Call::write(
            "alice",
            "POST",
            "/api/v1/registry/items".into(),
            json!({"client_key":"original-logical-key", "title":"same title", "body":"same body", "paths":["src"], "evidence":[{"kind":"commit", "value":"abcdef0:src/file", "observed_at":"old timestamp"}]}),
        );
        let mut operation = pending(&client, original.key.as_deref().unwrap());
        operation.method = original.method.clone();
        operation.path = original.path.clone();
        operation.request_path = original.path.clone();
        operation.session = original.session.clone();
        operation.body = original.body.as_ref().map(Value::to_string);
        operation.request_digest = Some(crate::request_identity(&original));
        operation.first_sent_unix_secs = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        client.retain_pending(operation.clone()).unwrap();
        drop(client);
        let client = Client::new("http://127.0.0.1:1", "fixture".into())
            .unwrap()
            .with_pending_journal(&root)
            .unwrap();
        let mut repeat = original.clone();
        repeat.key = Some("fresh-http-key".into());
        repeat.body.as_mut().unwrap()["client_key"] = json!("fresh-logical-key");
        repeat.body.as_mut().unwrap()["evidence"][0]["observed_at"] = json!("new timestamp");
        repeat.body.as_mut().unwrap()["evidence"][0]["commit_sha"] =
            json!("abcdef0123456789abcdef0123456789abcdef01");
        assert_eq!(
            client.pending_task_create(&repeat, false).unwrap(),
            original
        );
        assert_eq!(client.pending_task_create(&repeat, true).unwrap(), repeat);
        let mut changed = repeat.clone();
        changed.body.as_mut().unwrap()["body"] = json!("different body");
        assert_eq!(
            client.pending_task_create(&changed, false).unwrap(),
            changed
        );
        changed = repeat.clone();
        changed.session = "bob".into();
        assert_eq!(
            client.pending_task_create(&changed, false).unwrap(),
            changed
        );
        // Simulate encrypted content in the journal: identity is still caller plaintext.
        operation.body = Some(json!({"client_key":"original-logical-key", "title":{"ciphertext":"opaque"}, "evidence":[{"observed_at":"old timestamp"}]}).to_string());
        client
            .pending_journal
            .as_ref()
            .unwrap()
            .seed_pending(&operation);
        assert_eq!(
            client.pending_task_create(&repeat, false).unwrap(),
            original
        );
        operation.first_sent_unix_secs = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(30 * 24 * 60 * 60),
        );
        client
            .pending_journal
            .as_ref()
            .unwrap()
            .seed_pending(&operation);
        assert_eq!(
            client.pending_task_create(&repeat, false).unwrap(),
            original
        );
    }

    pub(super) fn pending(client: &Client, key: &str) -> PendingWrite {
        PendingWrite {
            code: "outcome_unknown".into(),
            cause_code: "outcome_unknown".into(),
            cause_status: None,
            diagnostic: None,
            protocol: NegotiatedProtocol::candidate(2),
            method: "POST".into(),
            path: "/api/v1/presence".into(),
            request_path: "/api/v1/presence".into(),
            body: Some("{}".into()),
            key: key.into(),
            repository: None,
            session: "fixture".into(),
            origin: client.base_url.clone(),
            credential_scope: crate::credential_fingerprint(&client.token),
            request_digest: None,
            first_sent_unix_secs: Some(maintenance::unix_now().unwrap()),
            first_sent_server_secs: Some(maintenance::unix_now().unwrap()),
            replay_stopped: false,
            replay_paused: false,
            pre_execution_rejected: false,
            encryption_context: None,
            result_expires_at: None,
            result_retry_at: None,
        }
    }
}

#[cfg(test)]
mod status_protocol_cache_tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::Transport;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::io::{BufRead, BufReader, Write};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::net::TcpListener;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::sync::{Arc, Mutex};

    #[test]
    fn survey_r5_soft_zones_ping_knowledge_is_fresh_and_never_discovers() {
        use crate::Transport;
        let client = Client::new("http://127.0.0.1:1", "fixture".into()).unwrap();
        assert!(!client.cached_soft_zones_v1());
        let mut protocol = NegotiatedProtocol::candidate(2);
        protocol.capabilities.insert(crate::SOFT_ZONES_V1.into());
        {
            let mut state = client.protocol_state.lock().unwrap();
            state.cached = Some(CachedProtocol {
                value: protocol,
                obtained: Instant::now(),
            });
            assert!(
                !client.cached_soft_zones_v1(),
                "contended Ping must not block"
            );
        }
        assert!(client.cached_soft_zones_v1());
        client
            .protocol_state
            .lock()
            .unwrap()
            .cached
            .as_mut()
            .unwrap()
            .obtained = Instant::now() - CACHE_TTL;
        assert!(
            !client.cached_soft_zones_v1(),
            "expired negotiation is not proof"
        );
    }

    #[test]
    fn status_registry_capability_cache_contention_preserves_support_deadline_and_cancellation() {
        let client = Client::new("http://127.0.0.1:1", "fixture".into()).unwrap();
        let mut protocol = NegotiatedProtocol::candidate(2);
        protocol
            .capabilities
            .insert(crate::REGISTRY_ASSIGNEE_SESSION.into());
        client.protocol_state.lock().unwrap().cached = Some(CachedProtocol {
            value: protocol,
            obtained: Instant::now(),
        });
        let held = client.protocol_state.lock().unwrap();
        std::thread::scope(|scope| {
            let (started, ready) = std::sync::mpsc::channel();
            let client = &client;
            let worker = scope.spawn(move || {
                started.send(()).unwrap();
                client.cached_registry_assignee_supported(
                    Instant::now() + Duration::from_secs(1),
                    None,
                )
            });
            ready.recv().unwrap();
            std::thread::sleep(Duration::from_millis(10));
            drop(held);
            assert!(
                worker.join().unwrap(),
                "brief upkeep contention cannot hide negotiated support"
            );
        });

        let _held = client.protocol_state.lock().unwrap();
        let start = Instant::now();
        assert!(
            !client.cached_registry_assignee_supported(start + Duration::from_millis(20), None)
        );
        assert!(start.elapsed() < Duration::from_millis(150));
        let cancellation = Cancellation::new();
        std::thread::scope(|scope| {
            let (started, ready) = std::sync::mpsc::channel();
            let client = &client;
            let cancellation = &cancellation;
            let worker = scope.spawn(move || {
                started.send(()).unwrap();
                client.cached_registry_assignee_supported(
                    Instant::now() + Duration::from_secs(2),
                    Some(cancellation),
                )
            });
            ready.recv().unwrap();
            std::thread::sleep(Duration::from_millis(10));
            let cancelled = Instant::now();
            cancellation.cancel();
            assert!(!worker.join().unwrap());
            assert!(cancelled.elapsed() < Duration::from_millis(150));
        });
    }

    #[test]
    fn status_protocol_cache_requires_same_boot_and_two_fresh_nonfuture_clocks() {
        let observed = StatusProtocolClock {
            boot: "boot".into(),
            wall_ms: 100_000,
            monotonic_ms: 100_000,
        };
        let mut current = observed.clone();
        current.wall_ms += 100;
        current.monotonic_ms += 200;
        assert_eq!(
            status_protocol_age(&observed, &current),
            Some(Duration::from_millis(200))
        );
        for (boot, wall, monotonic) in [
            ("other", 100_100, 100_100),
            ("boot", 99_999, 100_100),
            ("boot", 100_100, 99_999),
            ("boot", 130_000, 100_100),
            ("boot", 100_100, 130_000),
        ] {
            assert!(
                status_protocol_age(
                    &observed,
                    &StatusProtocolClock {
                        boot: boot.into(),
                        wall_ms: wall,
                        monotonic_ms: monotonic,
                    }
                )
                .is_none()
            );
        }
    }

    #[test]
    fn status_protocol_cache_fallback_boot_estimate_rejects_clock_drift_or_restart() {
        let observed = StatusProtocolClock {
            boot: "clock-estimate".into(),
            wall_ms: 100_000,
            monotonic_ms: 20_000,
        };
        let current = StatusProtocolClock {
            boot: "clock-estimate".into(),
            wall_ms: 100_200,
            monotonic_ms: 20_100,
        };
        assert_eq!(
            status_protocol_age(&observed, &current),
            Some(Duration::from_millis(200))
        );
        let drifted = StatusProtocolClock {
            wall_ms: 102_000,
            ..current.clone()
        };
        assert!(status_protocol_age(&observed, &drifted).is_none());
        let restarted = StatusProtocolClock {
            monotonic_ms: 100,
            ..current
        };
        assert!(status_protocol_age(&observed, &restarted).is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Default)]
    struct HintServerState {
        protocol: u16,
        discoveries: usize,
        policies: usize,
        claims: usize,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn server() -> (String, Arc<Mutex<HintServerState>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(HintServerState {
            protocol: 2,
            ..Default::default()
        }));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let path = first.split_whitespace().nth(1).unwrap_or("");
                let mut selected = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.trim_end().split_once(": ")
                        && name.eq_ignore_ascii_case("Lockyard-Protocol")
                    {
                        selected = value.parse::<u16>().unwrap();
                    }
                }
                let mut state = shared.lock().unwrap();
                if path == DISCOVERY {
                    state.discoveries += 1;
                } else if path == crate::ENCRYPTION_PATH {
                    state.policies += 1;
                } else if path.starts_with("/api/v1/zones/claims") {
                    state.claims += 1;
                }
                let (status, body) = if selected != state.protocol {
                    (
                        400,
                        json!({"error":{"code":"protocol_unsupported","message":"negotiate again", "details": {
                        "min_protocol":state.protocol,"max_protocol":state.protocol,
                        "supported_protocols":[state.protocol],"selected_protocol":null}}}),
                    )
                } else if path == DISCOVERY {
                    (
                        200,
                        json!({"selected_protocol":selected,"min_protocol":selected,
                        "max_protocol":selected,"capabilities":[]}),
                    )
                } else if path == crate::ENCRYPTION_PATH {
                    (
                        200,
                        json!({"encryption":"off","key_id":null,"workspace_id":"workspace"}),
                    )
                } else {
                    (200, json!({"claims":[]}))
                };
                drop(state);
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nLockyard-Protocol: {selected}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (url, state)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn client(url: &str, directory: &Path) -> Client {
        // The pending journal refuses a directory reached through a symlink, and the default
        // temporary directory on macOS is one (`/var` points to `/private/var`).
        let directory = directory.canonicalize().unwrap();
        Client::new(url, "fixture".into())
            .unwrap()
            .with_status_protocol_cache_at(directory)
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn status_protocol_cache_cold_processes_reuse_only_negotiation_not_policy_or_claims() {
        let directory = tempfile::tempdir().unwrap();
        let (url, state) = server();
        for _ in 0..2 {
            let client = client(&url, directory.path())
                .configure_content_encryption("me")
                .unwrap();
            client
                .call(&Call::get("me", "/api/v1/zones/claims?session=me".into()))
                .unwrap();
        }
        let state = state.lock().unwrap();
        assert_eq!(state.discoveries, 1);
        assert_eq!(state.policies, 2, "workspace policy must stay live");
        assert_eq!(
            state.claims, 2,
            "each status still performs its own network claims GET"
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn status_protocol_cache_rejects_other_origin_token_legacy_and_corrupt_records() {
        let directory = tempfile::tempdir().unwrap();
        let (url, _) = server();
        let first = client(&url, directory.path());
        first.negotiated_protocol("me").unwrap();
        let path = first.status_protocol_cache.as_ref().unwrap();
        let record = std::fs::read(path).unwrap();
        let other_token = Client::new(&url, "other".into()).unwrap();
        assert!(other_token.load_status_protocol_hint(path).is_none());
        let other_origin = Client::new("http://127.0.0.1:1", "fixture".into()).unwrap();
        assert!(other_origin.load_status_protocol_hint(path).is_none());
        for update in [
            "legacy",
            "selected",
            "origin",
            "credential_scope",
            "boot",
            "stale",
            "future",
            "corrupt",
        ] {
            let mut hint: Value = serde_json::from_slice(&record).unwrap();
            match update {
                "legacy" => hint["protocol"]["legacy"] = json!(true),
                "selected" => hint["protocol"]["selected"] = json!(1),
                "origin" => hint["origin"] = json!("http://127.0.0.1:1"),
                "credential_scope" => hint["credential_scope"] = json!("other"),
                "boot" => hint["clock"]["boot"] = json!("other"),
                "stale" => {
                    hint["clock"]["monotonic_ms"] = json!(0);
                    hint["clock"]["wall_ms"] = json!(0);
                }
                "future" => hint["clock"]["wall_ms"] = json!(u64::MAX),
                "corrupt" => {}
                _ => unreachable!(),
            }
            let bytes = if update == "corrupt" {
                b"{".to_vec()
            } else {
                serde_json::to_vec(&hint).unwrap()
            };
            lockyard_core::fsio::replace(path, &bytes, 0o600).unwrap();
            assert!(
                first.load_status_protocol_hint(path).is_none(),
                "accepted {update}"
            );
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn status_protocol_cache_stale_or_corrupt_hint_uses_live_discovery() {
        let directory = tempfile::tempdir().unwrap();
        let (url, state) = server();
        let first = client(&url, directory.path());
        first.negotiated_protocol("me").unwrap();
        let path = first.status_protocol_cache.as_ref().unwrap();
        let mut hint: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        hint["clock"]["monotonic_ms"] = json!(0);
        hint["clock"]["wall_ms"] = json!(0);
        lockyard_core::fsio::replace(path, &serde_json::to_vec(&hint).unwrap(), 0o600).unwrap();
        client(&url, directory.path())
            .negotiated_protocol("me")
            .unwrap();
        assert_eq!(state.lock().unwrap().discoveries, 2);
        lockyard_core::fsio::replace(path, b"{", 0o600).unwrap();
        client(&url, directory.path())
            .negotiated_protocol("me")
            .unwrap();
        assert_eq!(state.lock().unwrap().discoveries, 3);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn status_protocol_cache_unsupported_hint_is_invalidated_and_renegotiated() {
        let directory = tempfile::tempdir().unwrap();
        let (url, state) = server();
        let first = client(&url, directory.path());
        first.configure_content_encryption("me").unwrap();
        state.lock().unwrap().protocol = 1;
        let next = client(&url, directory.path());
        let path = next.status_protocol_cache.clone().unwrap();
        let next = next.configure_content_encryption("me").unwrap();
        assert_eq!(next.negotiated_protocol("me").unwrap().selected, 1);
        assert!(
            !path.exists(),
            "a protocol-one result must not preserve a stale modern hint"
        );
        assert_eq!(state.lock().unwrap().discoveries, 3);
    }

    #[test]
    #[cfg(unix)]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn status_protocol_cache_unsafe_file_or_symlink_is_a_cache_miss() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let (url, _) = server();
        let first = client(&url, directory.path());
        first.negotiated_protocol("me").unwrap();
        let path = first.status_protocol_cache.as_ref().unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(first.load_status_protocol_hint(path).is_none());
        let alias = path.with_extension("link");
        symlink(path, &alias).unwrap();
        assert!(first.load_status_protocol_hint(&alias).is_none());
    }
}
