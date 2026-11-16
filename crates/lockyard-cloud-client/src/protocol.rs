// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! HTTP generation negotiation is independent of RPC frames and package versions.
use crate::{ApiError, Call, Cancellation, Client, ClientError, Failure, WorkspaceEncryption};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DISCOVERY: &str = "/api/v1/protocol";
pub(crate) const CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_STATUS_PROTOCOL_HINT_BYTES: u64 = 16 * 1024;
const MAX_PENDING: usize = 128;
const MAX_PENDING_BYTES: u64 = 16 * 1024 * 1024;
// An empty, lazily created directory flags released-journal ownership/cleanup. Its
// absence is a single metadata lookup, not a scan of the ordinary pending journal.
const LONG_POLL_MAINTENANCE: &str = ".long-poll";

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
    /// Unknown-age records are quarantined; replay never refreshes this retention clock.
    #[serde(default)]
    pub first_sent_unix_secs: Option<u64>,
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
    completed_writes: BTreeSet<String>,
}

/// Close alone leaves a Unix flock alive in a descriptor inherited by a concurrent fork,
/// until that child execs. Release ownership explicitly before closing our descriptor.
#[derive(Debug)]
struct PendingFileLock(std::fs::File);

impl Drop for PendingFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // Retry interrupted unlocks; the guard must release ownership before close.
            while unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
        }
        #[cfg(not(unix))]
        let _ = self.0.unlock();
    }
}

pub(crate) struct PendingSendGuard<'a> {
    state: &'a std::sync::Mutex<ProtocolState>,
    key: String,
    /// Directory whose flock serializes journal writes across processes. Held only while
    /// mutating the journal or a short non-poll send — never for the whole long poll.
    journal_dir: Option<&'a Path>,
    journal: Option<PendingFileLock>,
    /// Per-key ownership survives releasing the shared journal during a long poll.
    operation: Option<PendingFileLock>,
}

impl PendingSendGuard<'_> {
    fn lock_operation(path: &Path) -> Result<PendingFileLock, ClientError> {
        let mut options = StateOpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(journal_error)?;
        private_file(&file.metadata().map_err(journal_error)?)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(ClientError::JournalBusy);
            }
        }
        #[cfg(not(unix))]
        file.try_lock().map_err(|_| ClientError::JournalBusy)?;
        Ok(PendingFileLock(file))
    }

    /// All contenders open operation locks while owning the shared journal lock.
    /// Under that lock an unlocked inode can be removed without leaving stale waiters.
    fn clean_operation_locks(directory: &Path) -> Result<bool, ClientError> {
        #[cfg(test)]
        pending_completion_tests::record_maintenance_scan();
        let mut active = false;
        for entry in std::fs::read_dir(directory).map_err(journal_error)? {
            let path = entry.map_err(journal_error)?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("inflight") {
                continue;
            }
            match Self::lock_operation(&path) {
                Ok(lock) => {
                    // The shared journal excludes new openers. Close our probe before
                    // unlinking so Windows does not race an outstanding file handle.
                    drop(lock);
                    std::fs::remove_file(path).map_err(journal_error)?;
                }
                Err(error) if journal_busy(&error) => active = true,
                Err(error) => return Err(error),
            }
        }
        Ok(active)
    }

    /// Drop the cross-process flock so siblings can release / claim / add tasks while this
    /// call waits on the server. The in-process active-write key stays reserved.
    pub(crate) fn release_journal(&mut self) -> Result<(), ClientError> {
        if let Some(directory) = self.journal_dir
            && self.operation.is_none()
        {
            // Create ownership only when actually releasing the journal, while its
            // flock still excludes all openers/cleaners. Short calls need neither file.
            private_directory(&directory.join(LONG_POLL_MAINTENANCE))?;
            self.operation = Some(Self::lock_operation(
                &journal_path(directory, &self.key).with_extension("inflight"),
            )?);
        }
        self.journal = None;
        Ok(())
    }

    fn lock_journal(directory: &Path) -> Result<PendingFileLock, ClientError> {
        private_directory(directory)?;
        let mut options = StateOpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(unix)]
        let lock = options.open(directory).map_err(journal_error)?;
        #[cfg(windows)]
        let lock = StateOpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(directory.join(".journal.lock"))
            .map_err(journal_error)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(ClientError::JournalBusy);
            }
        }
        #[cfg(not(unix))]
        {
            lock.try_lock().map_err(|_| ClientError::JournalBusy)?;
        }
        Ok(PendingFileLock(lock))
    }

    /// Re-take the flock before journal cleanup after a long poll. Retries inside `budget`.
    pub(crate) fn reacquire_journal(
        &mut self,
        budget: Duration,
        wait: impl Fn(Duration) -> Result<(), ClientError>,
    ) -> Result<(), ClientError> {
        let Some(directory) = self.journal_dir else {
            return Ok(());
        };
        if self.journal.is_some() {
            return Ok(());
        }
        let started = Instant::now();
        let mut delay = Duration::from_millis(25);
        loop {
            match Self::lock_journal(directory) {
                Ok(lock) => {
                    self.journal = Some(lock);
                    return Ok(());
                }
                Err(error) if journal_busy(&error) => {
                    let left = budget.saturating_sub(started.elapsed());
                    if left.is_zero() {
                        return Err(error);
                    }
                    let pause = delay.min(left).min(Duration::from_millis(250));
                    wait(pause)?;
                    delay = delay.saturating_mul(2).min(Duration::from_millis(250));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for PendingSendGuard<'_> {
    fn drop(&mut self) {
        let had_operation = self.operation.is_some();
        // Fields otherwise drop in declaration order (journal before operation).
        // Close the operation handle while the shared journal still excludes cleanup
        // in other processes, including on Windows where open handles impede unlink.
        drop(self.operation.take());
        // No process can open this inode while we own the shared journal lock.
        // Without it, leave the inode for clean_operation_locks on the next acquisition.
        if self.journal.is_some()
            && had_operation
            && let Some(directory) = self.journal_dir
        {
            let _ =
                std::fs::remove_file(journal_path(directory, &self.key).with_extension("inflight"));
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_writes
            .remove(&self.key);
        drop(self.journal.take());
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

    fn api_error(&self) -> Option<&ApiError> {
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
            Self::OutcomeUnknown(pending) => Some(Problem {
                status: None,
                code: pending.code.clone(),
                detail: "mutation outcome requires reconciliation".into(),
                details: json!({"cause_code":pending.cause_code,"cause_status":pending.cause_status,"protocol":pending.protocol.selected,"idempotency_key":pending.key}),
            }),
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
    let Ok(_) = serde_json::from_str::<Value>(body) else {
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

impl Client {
    /// Opt into a private, 30-second modern negotiation hint for status-only clients. Live
    /// encryption policy and every response's protocol/repository echo remain mandatory.
    /// A missing, unsafe, stale or unreadable hint is simply a normal discovery cache miss.
    pub fn with_status_protocol_cache(mut self) -> Self {
        let Some(directory) = self.pending_journal.as_ref() else {
            return self;
        };
        if status_protocol_clock().is_none() || private_directory(directory).is_err() {
            return self;
        }
        let path = directory.join("status-protocol.cache");
        if let Some(cached) = self.load_status_protocol_hint(&path) {
            self.protocol_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cached = Some(cached);
        }
        self.status_protocol_cache = Some(path);
        self
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
        if private_directory(parent).is_err() {
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
        crate::credential_fingerprint(
            &serde_json::to_string(&(
                &self.workspace,
                self.content_key.as_ref().map(crate::WorkspaceKey::key_id),
                self.encryption_enabled,
                &self.expected_e2ee_workspace,
            ))
            .expect("encryption context is serializable"),
        )
    }

    /// Exclusive through send, response classification and receipt cleanup, including clients
    /// sharing a journal. Busy callers retry later without issuing a concurrent operation.
    pub(crate) fn claim_pending_send(
        &self,
        key: &str,
    ) -> Result<PendingSendGuard<'_>, ClientError> {
        if !self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_writes
            .insert(key.to_owned())
        {
            return Err(ClientError::JournalBusy);
        }
        let mut guard = PendingSendGuard {
            state: &self.protocol_state,
            key: key.to_owned(),
            journal_dir: self.pending_journal.as_deref(),
            journal: None,
            operation: None,
        };
        if let Some(directory) = &self.pending_journal {
            guard.journal = Some(PendingSendGuard::lock_journal(directory)?);
            if directory
                .join(LONG_POLL_MAINTENANCE)
                .try_exists()
                .map_err(journal_error)?
            {
                let active = PendingSendGuard::clean_operation_locks(directory)?;
                let retry_cleanup = self.retire_completed_pending(directory)?;
                // Only locked inodes remain after cleanup. Do not create a second
                // per-key inode for an ordinary send; the journal protects this check.
                if journal_path(directory, key)
                    .with_extension("inflight")
                    .try_exists()
                    .map_err(journal_error)?
                {
                    return Err(ClientError::JournalBusy);
                }
                if !active && !retry_cleanup {
                    // Completion removal already synced the journal. Removing an empty
                    // hint requires no durability: a stale hint only costs one scan.
                    std::fs::remove_dir(directory.join(LONG_POLL_MAINTENANCE))
                        .map_err(journal_error)?;
                }
            } else {
                // A sibling may already have removed the sidecars and their hint.
                // Retire our verified in-memory completions too, without scanning.
                // This also retries durable cleanup if publishing their marker failed.
                let keys = self
                    .protocol_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .completed_writes
                    .clone();
                self.retire_completed_keys(keys)?;
            }
            // Another client may have sent or completed this operation since we loaded it.
            // Never recreate a stale entry or trust a cached pre-execution refusal.
            let path = journal_path(directory, key);
            if path
                .with_extension("quarantine")
                .try_exists()
                .map_err(journal_error)?
            {
                return Err(local(
                    "outcome_unknown",
                    "signed result is quarantined; original bytes retained",
                ));
            }
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    private_file(&metadata)?;
                    let mut options = StateOpenOptions::new();
                    options.read(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.custom_flags(libc::O_NOFOLLOW);
                    }
                    let file = options.open(path).map_err(journal_error)?;
                    private_file(&file.metadata().map_err(journal_error)?)?;
                    let operation: PendingWrite =
                        serde_json::from_reader(file).map_err(journal_error)?;
                    if operation.key != key
                        || operation.origin != self.base_url
                        || operation.credential_scope != crate::credential_fingerprint(&self.token)
                    {
                        return Err(journal_error("pending operation changed scope"));
                    }
                    self.protocol_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .pending
                        .insert(key.to_owned(), operation);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(pending) = self.pending_operation(key) {
                        return Err(ClientError::OutcomeUnknown(Box::new(pending)));
                    }
                }
                Err(error) => return Err(journal_error(error)),
            }
        }
        Ok(guard)
    }

    /// Enables a private, per-origin and per-credential pending-operation journal.
    /// A restored entry is quarantined until the caller proves its outcome.
    pub fn with_pending_journal(
        mut self,
        directory: impl AsRef<Path>,
    ) -> Result<Self, ClientError> {
        let scope = crate::credential_fingerprint(&format!("{}\0{}", self.base_url, self.token));
        let directory = directory.as_ref().join(scope);
        private_directory(&directory)?;
        let mut pending = BTreeMap::new();
        let mut total = 0_u64;
        let mut maintenance = false;
        for entry in std::fs::read_dir(&directory).map_err(journal_error)? {
            let entry = entry.map_err(journal_error)?;
            // Upgrade old journals during the scan we already need for restoration.
            // Older clients wrote these sidecars directly without the cheap hint.
            if matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("inflight" | "completed")
            ) {
                maintenance = true;
            }
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(journal_error)?;
            private_file(&metadata)?;
            total = total.saturating_add(metadata.len());
            if pending.len() >= MAX_PENDING || total > MAX_PENDING_BYTES {
                return Err(journal_error("pending journal exceeds its budget"));
            }
            let mut options = StateOpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let file = options.open(entry.path()).map_err(journal_error)?;
            private_file(&file.metadata().map_err(journal_error)?)?;
            let operation: PendingWrite = serde_json::from_reader(file).map_err(journal_error)?;
            if operation.origin != self.base_url
                || operation.credential_scope != crate::credential_fingerprint(&self.token)
                || !matches!(operation.protocol.selected, 1 | 2)
                || operation.code != "outcome_unknown"
                || operation.key.is_empty()
                || operation.path.starts_with("//")
                || !operation.path.starts_with('/')
                || !(matches!(operation.method.as_str(), "POST" | "DELETE")
                    || (operation.method == "PUT"
                        && operation.result_expires_at.is_some()
                        && crate::signed_results::is_result_path(&operation.path)))
                || entry.path() != journal_path(&directory, &operation.key)
                || pending.insert(operation.key.clone(), operation).is_some()
            {
                return Err(journal_error(
                    "pending journal operation does not match its origin or credential",
                ));
            }
        }
        let hint = directory.join(LONG_POLL_MAINTENANCE);
        if maintenance && !hint.try_exists().unwrap_or(false) {
            // Even this disposable hint mutates the shared journal. Take its flock
            // briefly for legacy-sidecar restoration, never for the HTTP long poll.
            // Current clients normally publish the hint with their sidecars, so this
            // mostly runs for journals written by older clients. A busy owner never fails the
            // load: the hint stays unpublished and the next open retries it.
            match PendingSendGuard::lock_journal(&directory) {
                Ok(_journal) => private_directory(&hint)?,
                Err(error) if journal_busy(&error) => {}
                Err(error) => return Err(error),
            }
        }
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending = pending;
        self.pending_journal = Some(directory);
        Ok(self)
    }

    /// Match only creates of this session/repository and within the journal replay window.
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ClientError::Invalid(e.to_string()))?
            .as_secs();
        for pending in self.pending_operations() {
            if pending.method != call.method
                || pending.request_path != call.path
                || pending.session != call.session
                || pending.repository != call.repository
                || !pending
                    .first_sent_unix_secs
                    .and_then(|first| now.checked_sub(first))
                    .is_some_and(|age| age < 30 * 24 * 60 * 60 - 60)
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
                candidate["evidence"].as_array_mut(),
                body["evidence"].as_array(),
            ) {
                for (current, original) in current.iter_mut().zip(original) {
                    current["observed_at"] = original["observed_at"].clone();
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
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .get(key)
            .cloned()
    }

    pub fn pending_operations(&self) -> Vec<PendingWrite> {
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .values()
            .cloned()
            .collect()
    }

    /// Retire an EP-09 operation from the active budget without erasing its bytes/key.
    pub fn quarantine_signed_result(&self, key: &str) -> Result<(), ClientError> {
        let _guard = self.claim_pending_send(key)?;
        let pending = self
            .pending_operation(key)
            .ok_or_else(|| local("invalid_request", "pending result missing"))?;
        if pending.method != "PUT" || !crate::signed_results::is_result_path(&pending.path) {
            return Err(local("invalid_request", "not a signed result operation"));
        }
        let directory = self
            .pending_journal
            .as_ref()
            .ok_or_else(|| local("outcome_unknown", "durable quarantine required"))?;
        let path = journal_path(directory, key);
        lockyard_core::fsio::rename(&path, path.with_extension("quarantine"))
            .map_err(journal_error)?;
        lockyard_core::fsio::sync_dir(directory).map_err(journal_error)?;
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(key);
        Ok(())
    }

    /// Forget an operation only after its receipt or domain state has been verified.
    pub fn resolve_pending(&self, key: &str) -> Result<(), ClientError> {
        let resolved = if let Some(directory) = &self.pending_journal {
            match std::fs::remove_file(journal_path(directory, key)) {
                Ok(()) => lockyard_core::fsio::sync_dir(directory).map_err(journal_error),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(journal_error(error)),
            }
        } else {
            Ok(())
        };
        if let Err(error) = resolved {
            if let Some(pending) = self.pending_operation(key) {
                // A cleanup failure cannot turn a possibly-sent write into a preflight refusal.
                // If deletion succeeded but directory sync failed, try restoring its record.
                // Storage failure can still prevent that; memory always retains the exact bytes.
                let cause = pending.cause_code.clone();
                let status = pending.cause_status;
                return Err(self.unknown(pending, &cause, status));
            }
            return Err(error);
        }
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .remove(key);
        if let Some(directory) = &self.pending_journal
            && directory
                .join(LONG_POLL_MAINTENANCE)
                .try_exists()
                .map_err(journal_error)?
        {
            match std::fs::remove_file(journal_path(directory, key).with_extension("completed")) {
                Ok(()) => lockyard_core::fsio::sync_dir(directory).map_err(journal_error)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(journal_error(error)),
            }
        }
        Ok(())
    }

    /// The per-operation lock protects this terminal marker even while another key owns
    /// the shared journal. It never edits the pending record without the shared lock.
    fn complete_pending_later(&self, pending: &PendingWrite) {
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .completed_writes
            .insert(pending.key.clone());
        if let Some(directory) = &self.pending_journal
            && let Ok(bytes) = serde_json::to_string(pending)
        {
            let marker = json!({"key":pending.key,"digest":crate::credential_fingerprint(&bytes)});
            let _ = lockyard_core::fsio::replace(
                &journal_path(directory, &pending.key).with_extension("completed"),
                marker.to_string().as_bytes(),
                0o600,
            );
        }
    }

    /// Called only with the shared journal lock; survives a short-lived CLI exiting.
    fn retire_completed_pending(&self, directory: &Path) -> Result<bool, ClientError> {
        #[cfg(test)]
        pending_completion_tests::record_maintenance_scan();
        let mut retry_cleanup = false;
        let mut keys = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .completed_writes
            .clone();
        for entry in std::fs::read_dir(directory).map_err(journal_error)? {
            let path = entry.map_err(journal_error)?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("completed") {
                continue;
            }
            let validated = (|| {
                let marker: Value = read_private_json(&path)?;
                let key = marker["key"]
                    .as_str()
                    .filter(|key| !key.is_empty())
                    .ok_or_else(|| journal_error("invalid completion marker"))?;
                let marker_digest = marker["digest"]
                    .as_str()
                    .filter(|digest| {
                        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    .ok_or_else(|| journal_error("invalid completion marker digest"))?;
                let pending_path = journal_path(directory, key);
                if path != pending_path.with_extension("completed") {
                    return Err(journal_error("invalid completion marker path"));
                }
                if pending_path.try_exists().map_err(journal_error)? {
                    let pending: PendingWrite = read_private_json(&pending_path)?;
                    let digest = crate::credential_fingerprint(
                        &serde_json::to_string(&pending).map_err(journal_error)?,
                    );
                    if pending.key != key
                        || pending.origin != self.base_url
                        || pending.credential_scope != crate::credential_fingerprint(&self.token)
                        || marker_digest != digest
                    {
                        return Err(journal_error(
                            "completion marker does not match pending operation",
                        ));
                    }
                }
                Ok(key.to_owned())
            })();
            match validated {
                Ok(key) => {
                    keys.insert(key);
                }
                Err(_) => {
                    // A marker is only a cleanup hint. Preserve the pending bytes and
                    // isolate a bad hint instead of blocking every key/process forever.
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos();
                    let quarantine = path.with_extension(format!("completed.bad-{timestamp}"));
                    match lockyard_core::fsio::rename(&path, &quarantine)
                        .and_then(|()| lockyard_core::fsio::sync_dir(directory))
                    {
                        Ok(()) => eprintln!(
                            "warning: quarantined invalid pending completion marker: {}",
                            quarantine.display()
                        ),
                        Err(error) => {
                            retry_cleanup = true;
                            eprintln!(
                                "warning: cannot quarantine invalid pending completion marker {}: {error}",
                                path.display()
                            );
                        }
                    }
                }
            }
        }
        self.retire_completed_keys(keys)?;
        Ok(retry_cleanup)
    }

    fn retire_completed_keys(&self, keys: BTreeSet<String>) -> Result<(), ClientError> {
        for key in keys {
            self.resolve_pending(&key)?;
            self.protocol_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .completed_writes
                .remove(&key);
        }
        Ok(())
    }

    pub(crate) fn retain_pending(&self, operation: PendingWrite) -> Result<(), ClientError> {
        let mut state = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.pending.contains_key(&operation.key) {
            return Err(ClientError::OutcomeUnknown(Box::new(
                state.pending[&operation.key].clone(),
            )));
        }
        let encoded = serde_json::to_vec(&operation).map_err(journal_error)?;
        let current_bytes: usize = state
            .pending
            .values()
            .map(|entry| entry.body.as_ref().map_or(0, String::len))
            .sum();
        if state.pending.len() >= MAX_PENDING
            || current_bytes.saturating_add(encoded.len()) > MAX_PENDING_BYTES as usize
        {
            return Err(journal_error("pending operation budget exceeded"));
        }
        if let Some(directory) = &self.pending_journal {
            private_directory(directory)?;
            use std::io::Write;
            let mut options = StateOpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options
                .open(journal_path(directory, &operation.key))
                .map_err(journal_error)?;
            // An incomplete pre-send journal is deliberately retained and fails closed on load.
            file.write_all(&encoded)
                .and_then(|()| file.sync_all())
                .map_err(journal_error)?;
            lockyard_core::fsio::sync_dir(directory).map_err(journal_error)?;
        }
        state.pending.insert(operation.key.clone(), operation);
        Ok(())
    }

    pub(crate) fn update_pending(
        &self,
        previous: &PendingWrite,
        operation: PendingWrite,
    ) -> Result<(), ClientError> {
        let mut state = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.pending.get(&previous.key) != Some(previous) {
            return Err(journal_error("pending operation changed during retry"));
        }
        if let Some(directory) = &self.pending_journal {
            private_directory(directory)?;
            let bytes = serde_json::to_vec(&operation).map_err(journal_error)?;
            lockyard_core::fsio::replace(&journal_path(directory, &operation.key), &bytes, 0o600)
                .map_err(journal_error)?;
        }
        state.pending.insert(operation.key.clone(), operation);
        Ok(())
    }

    fn retain_refusal(
        &self,
        mut pending: PendingWrite,
        error: &ClientError,
    ) -> Result<PendingWrite, ClientError> {
        let previous = pending.clone();
        pending.pre_execution_rejected = true;
        pending.cause_code = error.code().unwrap_or("outcome_unknown").to_owned();
        pending.cause_status = error.status();
        self.update_pending(&previous, pending.clone())?;
        Ok(pending)
    }

    /// Resolve the current generation without performing any write or changing origin.
    pub fn negotiated_protocol(&self, session: &str) -> Result<NegotiatedProtocol, ClientError> {
        self.discover(session, None, None)
    }

    pub(crate) fn refresh_protocol(
        &self,
        session: &str,
    ) -> Result<NegotiatedProtocol, ClientError> {
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cached = None;
        self.discover(session, None, None)
    }

    fn discover(
        &self,
        session: &str,
        remaining: Option<Duration>,
        cancellation: Option<&Cancellation>,
    ) -> Result<NegotiatedProtocol, ClientError> {
        let started = Instant::now();
        // Discovery is shared by concurrent status workers. Waiting for another thread's
        // discovery is part of this caller's deadline, including a long unrelated request.
        let mut state = if remaining.is_some() || cancellation.is_some() {
            loop {
                if let Some(cancellation) = cancellation {
                    cancellation.check()?;
                }
                match self.protocol_state.try_lock() {
                    Ok(state) => break state,
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
            self.protocol_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        if let Some(cached) = &state.cached
            && cached.obtained.elapsed() < CACHE_TTL
        {
            return Ok(cached.value.clone());
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
                    state.cached = Some(CachedProtocol {
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
                    state.cached = Some(CachedProtocol {
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

    fn feature_gate(&self, call: &Call, protocol: &NegotiatedProtocol) -> Result<(), ClientError> {
        let route = call.path.split('?').next().unwrap_or(&call.path);
        let required = if route == "/api/v1/zones/catalog"
            && (call.is_write()
                || self.encryption_enabled
                || self.expected_e2ee_workspace.is_some())
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
        call.check_cancelled()?;
        if call.is_write() && call.key.as_deref().is_none_or(str::is_empty) {
            return Err(ClientError::Invalid(
                "writes require an Idempotency-Key".into(),
            ));
        }
        // One clock for journal-busy waits, Retry-After pauses, and remaining()/wait_fits_deadline.
        // Without an explicit call deadline the journal wait budget is MAX_RETRY_WAIT (5 s).
        let started = Instant::now();
        let remaining = || {
            call.deadline_ms
                .map(|limit| Duration::from_millis(limit).saturating_sub(started.elapsed()))
        };
        let mut send_guard = if call.is_write() {
            let key = call.key.as_deref().expect("validated write key");
            // The flock is local and pre-send: wait inside the call deadline without starting a
            // second create. Creating calls keep one idempotency key for the whole wait.
            let budget = call
                .deadline_ms
                .map(Duration::from_millis)
                .unwrap_or(crate::MAX_RETRY_WAIT);
            let mut delay = Duration::from_millis(25);
            loop {
                call.check_cancelled()?;
                match self.claim_pending_send(key) {
                    Ok(guard) => break Some(guard),
                    Err(error) if journal_busy(&error) => {
                        let left = budget.saturating_sub(started.elapsed());
                        if left.is_zero() {
                            return Err(error);
                        }
                        let wait = delay.min(left).min(Duration::from_millis(250));
                        call.wait(wait)?;
                        delay = delay.saturating_mul(2).min(Duration::from_millis(250));
                    }
                    Err(error) => return Err(error),
                }
            }
        } else {
            None
        };
        if let Some(key) = &call.key
            && let Some(pending) = self.pending_operation(key)
        {
            return self.replay_pending(call, pending);
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
        // Resolve the content key once so request encryption and response decryption share it.
        let content_key = self.resolved_content_key()?;
        let mut protocol =
            match self.discover(&call.session, remaining(), call.cancellation.as_ref()) {
                Ok(protocol) => protocol,
                Err(error @ ClientError::Transport(_)) => {
                    if let Some(cached) = self.catalog_offline_call(call)? {
                        return Ok(cached);
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
        self.feature_gate(call, &protocol)?;
        let prepared = self.prepare_catalog_call(call)?;
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
        if (self.encryption_enabled || self.expected_e2ee_workspace.is_some())
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
        if let (Some(value), Some(workspace)) = (&mut body, self.workspace.as_deref()) {
            crate::crypto::transform_fields_policy(
                value,
                &call.method,
                &call.path,
                workspace,
                content_key.as_ref(),
                self.encryption_enabled,
                self.expected_e2ee_workspace.is_some(),
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
                pre_execution_rejected: false,
                encryption_context: Some(self.encryption_context()),
                result_expires_at: None,
                result_retry_at: None,
            });
            if let Some(pending) = &pending {
                if let Some(previous) = refused_pending.take() {
                    self.update_pending(&previous, pending.clone())?;
                } else {
                    self.retain_pending(pending.clone())?;
                }
            }
            // zone wait / long poll can sit on the server for tens of seconds; holding the
            // local write journal that whole time deadlocks sibling release / finish_work.
            if call.long_poll
                && let Some(guard) = send_guard.as_mut()
            {
                guard.release_journal()?;
            }
            let failure = match self.attempt_observed(
                &wire_call,
                encoded.as_deref(),
                remaining(),
                &protocol,
                registry_capability,
                None,
            ) {
                Ok(mut value) => {
                    let journal_owned = !call.long_poll
                        || send_guard.as_mut().is_none_or(|guard| {
                            guard
                                .reacquire_journal(
                                    remaining().unwrap_or(crate::MAX_RETRY_WAIT),
                                    |pause| call.wait(pause),
                                )
                                .is_ok()
                        });
                    // Authenticate/decrypt the response before releasing its recovery record.
                    let event_page = call.method == "GET"
                        && call.path.split('?').next() == Some("/api/v1/events");
                    if event_page {
                        self.decode_json_events(&mut value)?;
                    }
                    if !event_page
                        && let Some(workspace) = self.workspace.as_deref()
                        && let Err(message) = crate::crypto::transform_fields_policy(
                            &mut value,
                            &call.method,
                            &call.path,
                            workspace,
                            content_key.as_ref(),
                            false,
                            self.expected_e2ee_workspace.is_some(),
                        )
                    {
                        if let Some(pending) = pending {
                            if !journal_owned {
                                return Err(ClientError::OutcomeUnknown(Box::new(pending)));
                            }
                            let cause = if message.starts_with("catalog_") {
                                message.as_str()
                            } else {
                                "content_authentication_failed"
                            };
                            return Err(self.unknown(pending, cause, None));
                        }
                        return Err(content_error(message));
                    }
                    if let Err(error) = self.finish_catalog_call(call, &mut value) {
                        if let Some(pending) = pending {
                            if !journal_owned {
                                return Err(ClientError::OutcomeUnknown(Box::new(pending)));
                            }
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
                        if !journal_owned {
                            self.complete_pending_later(&pending);
                            return Ok(value);
                        }
                        if let Err(error) = self.resolve_pending(&pending.key) {
                            if call.long_poll {
                                self.complete_pending_later(&pending);
                                return Ok(value);
                            }
                            return Err(error);
                        }
                    }
                    return Ok(value);
                }
                Err(failure) => {
                    if call.long_poll
                        && let Some(guard) = send_guard.as_mut()
                    {
                        let budget = remaining().unwrap_or(crate::MAX_RETRY_WAIT);
                        if guard
                            .reacquire_journal(budget, |pause| call.wait(pause))
                            .is_err()
                        {
                            return Err(ClientError::OutcomeUnknown(Box::new(
                                pending.expect("write pending record"),
                            )));
                        }
                    }
                    failure
                }
            };
            let (error, may_retry) = match failure {
                Failure::Final(error) => (error, false),
                Failure::Retry(error) => (error, true),
            };
            let uncertain = matches!(&error, ClientError::Transport(_) | ClientError::Decode(_))
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
                    return Err(if call.defer_pending_ack {
                        unknown
                    } else {
                        error
                    });
                }
                if pre_execution_refusal(&error) {
                    refused_pending = Some(self.retain_refusal(pending, &error)?);
                } else {
                    self.resolve_pending(&pending.key)?;
                }
            }
            if call.path.contains("&assignee_session=")
                && registry_capability.is_some_and(|capability| {
                    !capability.load(std::sync::atomic::Ordering::Relaxed)
                })
            {
                return Err(error);
            }
            if error.code() == Some("protocol_unsupported")
                && error.status() == Some(400)
                && !replica_changed
            {
                replica_changed = true;
                self.invalidate_status_protocol_hint();
                self.protocol_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cached = None;
                protocol = self.discover(&call.session, remaining(), call.cancellation.as_ref())?;
                if call.path.contains("&assignee_session=")
                    && let Some(capability) = registry_capability
                    && !protocol
                        .capabilities
                        .contains(crate::REGISTRY_ASSIGNEE_SESSION)
                {
                    capability.store(false, std::sync::atomic::Ordering::Relaxed);
                    return Err(error);
                }
                self.feature_gate(call, &protocol)?;
                continue;
            }
            let temporary = error
                .api_error()
                .is_some_and(|error| matches!(error.code.as_str(), "frozen" | "server_draining"));
            let safe = safe_retry(&error) || (call.deadline_ms.is_some() && temporary);
            let retry = attempt < attempts
                && ((call.is_write() && safe)
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

    /// Proven pre-execution refusals reuse the frozen operation. Unknown coordination writes
    /// additionally require a durable caller and the endpoint's guaranteed receipt retention.
    fn replay_pending(&self, call: &Call, mut pending: PendingWrite) -> Result<Value, ClientError> {
        let refused = pending.pre_execution_rejected;
        let route = call.path.split('?').next().unwrap_or(&call.path);
        let parts = route.trim_start_matches('/').split('/').collect::<Vec<_>>();
        let known_ledger = call.method == "POST"
            && matches!(
                parts.as_slice(),
                ["api", "v1", "presence"]
                    | ["api", "v1", "bus", "messages"]
                    | ["api", "v1", "bus", "messages", _, "reply" | "ack"]
                    | ["api", "v1", "bus", "inbox", "seen"]
                    | ["api", "v1", "zones", "dirty"]
                    | ["api", "v1", "zones", "claims", _, "activity"]
            );
        let age = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|now| {
                pending
                    .first_sent_unix_secs
                    .and_then(|first| now.as_secs().checked_sub(first))
            });
        // Leave a clock-skew margin inside the ledger guarantee, never extend it on retry.
        let retained = age.is_some_and(|age| age < 30 * 24 * 60 * 60 - 60);
        // RegistryService.CreateAsync deduplicates by workspace/client_key independently
        // of the HTTP receipt ledger. Replay its exact frozen bytes, never a fresh create.
        let registry_create = call.method == "POST"
            && route == "/api/v1/registry/items"
            && call
                .body
                .as_ref()
                .and_then(|body| body["client_key"].as_str())
                .is_some_and(|key| {
                    !key.is_empty()
                        && key.len() <= 256
                        && key.bytes().all(|byte| byte.is_ascii_graphic())
                        && pending
                            .body
                            .as_deref()
                            .and_then(|body| serde_json::from_str::<Value>(body).ok())
                            .is_some_and(|body| body["client_key"].as_str() == Some(key))
                });
        let context_ready = self
            .expected_e2ee_workspace
            .as_deref()
            .is_none_or(|expected| {
                self.encryption_enabled
                    && self.content_key.is_some()
                    && self.workspace.as_deref() == Some(expected)
            });
        if (!refused && !registry_create && (!call.defer_pending_ack || !known_ledger || !retained))
            || !context_ready
            || pending.encryption_context.as_deref() != Some(self.encryption_context().as_str())
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
        let remaining = call.deadline_ms.map(Duration::from_millis);
        if remaining.is_some_and(|limit| limit.is_zero()) {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        if refused {
            let previous = pending.clone();
            pending.pre_execution_rejected = false;
            pending.cause_code = "outcome_unknown".into();
            pending.cause_status = None;
            // A crash after this point must never restore permission to replay an unknown write.
            self.update_pending(&previous, pending.clone())?;
        }
        // No discovery, route preparation or encryption: those would mutate the operation.
        // A refusal after an originally unknown attempt cannot prove that earlier write failed.
        let mut value =
            match self.attempt(&wire, pending.body.as_deref(), remaining, &pending.protocol) {
                Ok(value) => value,
                Err(failure) => {
                    let error = failure_error(failure);
                    if refused && pre_execution_refusal(&error) {
                        self.retain_refusal(pending, &error)?;
                        return Err(error);
                    }
                    if refused && error.api_error().is_some_and(|api| api.status < 500) {
                        // Retire safe-retry permission, while retaining the original bytes/key.
                        // A later call must reconcile rather than encrypt a new body for this key.
                        return Err(error);
                    }
                    let cause = error.code().unwrap_or("outcome_unknown").to_owned();
                    return Err(self.unknown(pending, &cause, error.status()));
                }
            };
        let held = self.resolved_content_key()?;
        if let Some(workspace) = self.workspace.as_deref()
            && let Err(message) = crate::crypto::transform_fields_policy(
                &mut value,
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
            return Err(self.unknown(pending, cause, None));
        }
        if let Err(error) = self.finish_catalog_call(call, &mut value) {
            let cause = error
                .code()
                .unwrap_or("catalog_authentication_failed")
                .to_owned();
            return Err(self.unknown(pending, &cause, error.status()));
        }
        if !call.defer_pending_ack {
            self.resolve_pending(&pending.key)?;
        }
        // The agent acknowledges only after its outbox completion marker is durable.
        Ok(value)
    }

    pub(crate) fn unknown(
        &self,
        mut pending: PendingWrite,
        cause: &str,
        status: Option<u16>,
    ) -> ClientError {
        pending.pre_execution_rejected = false;
        pending.cause_code = cause.into();
        pending.cause_status = status;
        let mut state = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending.insert(pending.key.clone(), pending.clone());
        if let Some(directory) = &self.pending_journal
            && let Ok(bytes) = serde_json::to_vec(&pending)
        {
            // Failure leaves the already-synced pre-send recovery record intact.
            let _ =
                lockyard_core::fsio::replace(&journal_path(directory, &pending.key), &bytes, 0o600);
        }
        ClientError::OutcomeUnknown(Box::new(pending))
    }
}

fn failure_error(failure: Failure) -> ClientError {
    match failure {
        Failure::Final(error) | Failure::Retry(error) => error,
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

fn journal_error(error: impl std::fmt::Display) -> ClientError {
    ClientError::Invalid(format!("pending journal unavailable: {error}"))
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
    serde_json::from_reader(file).map_err(journal_error)
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
mod pending_completion_tests {
    use super::*;

    std::thread_local! {
        static MAINTENANCE_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    pub(super) fn record_maintenance_scan() {
        MAINTENANCE_SCANS.set(MAINTENANCE_SCANS.get() + 1);
    }

    fn journal_files(directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            // Windows already used this global journal lock in 0.3.12.
            .filter(|path| path.file_name().unwrap() != ".journal.lock")
            .collect()
    }

    #[test]
    fn task_pending_create_reuses_keys_after_restart_only_for_same_arguments_in_window() {
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
            json!({"client_key":"original-logical-key", "title":"same title", "body":"same body", "paths":["src"], "evidence":[{"value":"commit", "observed_at":"old timestamp"}]}),
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
            .protocol_state
            .lock()
            .unwrap()
            .pending
            .insert(operation.key.clone(), operation.clone());
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
            .protocol_state
            .lock()
            .unwrap()
            .pending
            .insert(operation.key.clone(), operation);
        assert_eq!(client.pending_task_create(&repeat, false).unwrap(), repeat);
    }

    #[cfg(unix)]
    #[test]
    fn send_locks_release_while_inherited_descriptors_remain_open() {
        let root = tempfile::tempdir().unwrap();
        let client = Client::new("http://127.0.0.1:1", "fixture".into())
            .unwrap()
            .with_pending_journal(root.path().canonicalize().unwrap())
            .unwrap();
        let mut guard = client.claim_pending_send("short").unwrap();
        // dup and fork share the same open file description. CLOEXEC only closes it at exec,
        // so a concurrently spawned child can retain ownership after the parent closes it.
        let inherited_journal = guard.journal.as_ref().unwrap().0.try_clone().unwrap();
        guard.release_journal().unwrap();
        let inherited_operation = guard.operation.as_ref().unwrap().0.try_clone().unwrap();
        drop(client.claim_pending_send("other").unwrap());
        drop(guard);
        drop(client.claim_pending_send("short").unwrap());
        drop(inherited_operation);
        drop(inherited_journal);
    }

    #[test]
    fn survey_r6_short_sends_do_not_create_long_poll_files() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let client = Client::new("http://127.0.0.1:1", "fixture".into())
            .unwrap()
            .with_pending_journal(&root)
            .unwrap();
        let directory = client.pending_journal.as_ref().unwrap();
        let scans = MAINTENANCE_SCANS.get();
        for _ in 0..3 {
            let guard = client.claim_pending_send("short").unwrap();
            assert!(journal_files(directory).is_empty());
            client.retain_pending(pending(&client, "short")).unwrap();
            let paths = journal_files(directory);
            assert_eq!(paths, vec![journal_path(directory, "short")]);
            client.resolve_pending("short").unwrap();
            drop(guard);
            assert!(journal_files(directory).is_empty());
        }
        assert_eq!(MAINTENANCE_SCANS.get(), scans);
    }

    #[test]
    fn ly0019_legacy_long_poll_hint_creation_and_cleanup_require_journal_lock() {
        for extension in ["inflight", "completed"] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let new_client = || {
                Client::new("http://127.0.0.1:1", "fixture".into())
                    .unwrap()
                    .with_pending_journal(&root)
            };
            let sender = new_client().unwrap();
            let directory = sender.pending_journal.as_ref().unwrap();
            let hint = directory.join(LONG_POLL_MAINTENANCE);
            let sidecar = journal_path(directory, "poll").with_extension(extension);
            let holder = PendingSendGuard::lock_journal(directory).unwrap();
            let record = pending(&sender, "poll");
            sender.retain_pending(record.clone()).unwrap();
            // Model an older journal with sidecars but no maintenance hint.
            if extension == "inflight" {
                drop(PendingSendGuard::lock_operation(&sidecar).unwrap());
            } else {
                sender.complete_pending_later(&record);
            }
            assert!(sidecar.exists());
            assert!(!hint.exists());
            // A busy journal never fails the load; the hint waits for the flock.
            drop(new_client().expect("a busy journal must not fail the load"));
            assert!(!hint.exists(), "{extension}: creation bypassed the flock");
            drop(holder);

            let restored = new_client().unwrap();
            assert!(
                hint.exists(),
                "{extension}: restoration must publish the hint"
            );
            // Restoration releases the flock immediately; another owner can take it.
            let holder = PendingSendGuard::lock_journal(directory).unwrap();
            let error = restored.claim_pending_send("unrelated").err().unwrap();
            assert!(journal_busy(&error), "{extension}: {error}");
            assert!(hint.exists(), "{extension}: removal bypassed the flock");
            assert!(sidecar.exists());
            drop(holder);

            // A published hint means loads skip the flock even while it is busy.
            let holder = PendingSendGuard::lock_journal(directory).unwrap();
            drop(new_client().expect("an existing hint must not need the flock"));
            assert!(hint.exists());
            drop(holder);

            drop(restored.claim_pending_send("unrelated").unwrap());
            assert!(!hint.exists(), "{extension}: cleanup must remove the hint");
            assert!(!sidecar.exists());
            assert_eq!(
                restored.pending_operation("poll").is_some(),
                extension == "inflight"
            );
        }
    }

    #[test]
    fn survey_r6_existing_client_sees_released_ownership_and_durable_completion() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let new_client = || {
            Client::new("http://127.0.0.1:1", "fixture".into())
                .unwrap()
                .with_pending_journal(&root)
                .unwrap()
        };
        let sender = new_client();
        // Created before any hint exists: an in-memory-only flag would miss it.
        let sibling = new_client();
        let directory = sibling.pending_journal.as_ref().unwrap();
        let record = pending(&sender, "poll");
        let mut guard = sender.claim_pending_send("poll").unwrap();
        sender.retain_pending(record.clone()).unwrap();
        guard.release_journal().unwrap();
        assert!(journal_busy(
            &sibling.claim_pending_send("poll").err().unwrap()
        ));
        drop(sibling.claim_pending_send("unrelated").unwrap());
        sender.complete_pending_later(&record);
        let marker = journal_path(directory, "poll").with_extension("completed");
        assert!(marker.exists());
        drop(guard);
        drop(sender);
        drop(sibling.claim_pending_send("unrelated").unwrap());
        assert!(!journal_path(directory, "poll").exists());
        assert!(!marker.exists());
        assert!(!directory.join(LONG_POLL_MAINTENANCE).exists());
        let scans = MAINTENANCE_SCANS.get();
        for _ in 0..3 {
            drop(sibling.claim_pending_send("short").unwrap());
        }
        assert_eq!(MAINTENANCE_SCANS.get(), scans);
    }

    #[test]
    fn survey_r6_sender_retires_local_completion_after_sibling_removes_hint() {
        for marker_persisted in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let new_client = || {
                Client::new("http://127.0.0.1:1", "fixture".into())
                    .unwrap()
                    .with_pending_journal(&root)
                    .unwrap()
            };
            let sender = new_client();
            let sibling = new_client();
            let directory = sender.pending_journal.as_ref().unwrap();
            let record = pending(&sender, "poll");
            let mut guard = sender.claim_pending_send("poll").unwrap();
            sender.retain_pending(record.clone()).unwrap();
            guard.release_journal().unwrap();
            sender.complete_pending_later(&record);
            if !marker_persisted {
                // Model a failed marker publication: the verified success is still
                // known in this client, while other clients cannot retire its JSON.
                std::fs::remove_file(journal_path(directory, "poll").with_extension("completed"))
                    .unwrap();
            }
            drop(guard);
            drop(sibling.claim_pending_send("unrelated").unwrap());
            assert!(!directory.join(LONG_POLL_MAINTENANCE).exists());
            assert_eq!(journal_path(directory, "poll").exists(), !marker_persisted);
            let scans = MAINTENANCE_SCANS.get();
            drop(sender.claim_pending_send("poll").unwrap());
            assert!(sender.pending_operation("poll").is_none());
            assert!(!journal_path(directory, "poll").exists());
            assert_eq!(MAINTENANCE_SCANS.get(), scans);
        }
    }

    fn pending(client: &Client, key: &str) -> PendingWrite {
        PendingWrite {
            code: "outcome_unknown".into(),
            cause_code: "outcome_unknown".into(),
            cause_status: None,
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
            first_sent_unix_secs: None,
            pre_execution_rejected: false,
            encryption_context: None,
            result_expires_at: None,
            result_retry_at: None,
        }
    }

    #[test]
    fn bad_completion_markers_preserve_pending_and_do_not_block_other_keys_or_clients() {
        for fault in [
            "json",
            "key",
            "path",
            "digest",
            "mismatch",
            "changed_record",
        ] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let new_client = || {
                Client::new("http://127.0.0.1:1", "fixture".into())
                    .unwrap()
                    .with_pending_journal(&root)
                    .unwrap()
            };
            let client = new_client();
            let bad = pending(&client, "bad");
            let good = pending(&client, "good");
            client.retain_pending(bad.clone()).unwrap();
            client.retain_pending(good.clone()).unwrap();
            client.complete_pending_later(&bad);
            client.complete_pending_later(&good);
            let directory = client.pending_journal.as_ref().unwrap();
            let path = journal_path(directory, "bad").with_extension("completed");
            let mut marker: Value = read_private_json(&path).unwrap();
            match fault {
                "json" => {}
                "key" => marker["key"] = Value::Null,
                "path" => marker["key"] = json!("another-key"),
                "digest" => marker["digest"] = json!("wrong-digest"),
                "mismatch" => marker["digest"] = json!("a".repeat(64)),
                "changed_record" => {
                    let mut changed = bad.clone();
                    changed.body = Some("{\"new\":true}".into());
                    lockyard_core::fsio::replace(
                        &journal_path(directory, "bad"),
                        &serde_json::to_vec(&changed).unwrap(),
                        0o600,
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            let bytes = if fault == "json" {
                b"broken-json".to_vec()
            } else {
                serde_json::to_vec(&marker).unwrap()
            };
            lockyard_core::fsio::replace(&path, &bytes, 0o600).unwrap();
            let original = std::fs::read(journal_path(directory, "bad")).unwrap();
            // Fresh clients have no in-memory completion hints. The same durable
            // files must permit progress after the original process has exited.
            let next = new_client();
            drop(next.claim_pending_send("unrelated").unwrap());
            assert!(!path.exists(), "{fault}");
            assert_eq!(
                std::fs::read(journal_path(directory, "bad")).unwrap(),
                original
            );
            assert!(!journal_path(directory, "good").exists(), "{fault}");
            let quarantines: Vec<_> = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.to_string_lossy().contains(".completed.bad-"))
                .collect();
            assert_eq!(quarantines.len(), 1, "{fault}");
            assert_eq!(std::fs::read(&quarantines[0]).unwrap(), bytes, "{fault}");
            assert!(!directory.join(LONG_POLL_MAINTENANCE).exists());
            let scans = MAINTENANCE_SCANS.get();
            let restored = new_client();
            drop(restored.claim_pending_send("another-unrelated").unwrap());
            assert_eq!(MAINTENANCE_SCANS.get(), scans);
            assert!(restored.pending_operation("bad").is_some(), "{fault}");
            assert!(restored.pending_operation("good").is_none(), "{fault}");
        }
    }

    #[test]
    fn dropping_send_guard_cleans_operation_lock_and_releases_both_owners() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let client = Client::new("http://127.0.0.1:1", "fixture".into())
            .unwrap()
            .with_pending_journal(root)
            .unwrap();
        let directory = client.pending_journal.as_ref().unwrap();
        let path = journal_path(directory, "key").with_extension("inflight");
        let mut guard = client.claim_pending_send("key").unwrap();
        assert!(journal_busy(
            &PendingSendGuard::lock_journal(directory).unwrap_err()
        ));
        assert!(!path.exists(), "short sends own only the shared journal");
        guard.release_journal().unwrap();
        drop(PendingSendGuard::lock_journal(directory).unwrap());
        assert!(journal_busy(
            &PendingSendGuard::lock_operation(&path).unwrap_err()
        ));
        guard.reacquire_journal(Duration::ZERO, |_| Ok(())).unwrap();
        drop(guard);
        assert!(!path.exists());
        drop(client.claim_pending_send("key").unwrap());
        assert!(!path.exists());

        let mut guard = client.claim_pending_send("key").unwrap();
        guard.release_journal().unwrap();
        drop(guard);
        assert!(
            path.exists(),
            "cleanup without the shared journal is deferred"
        );
        drop(client.claim_pending_send("other-key").unwrap());
        assert!(
            !path.exists(),
            "next owner cleans the closed operation inode"
        );
        assert!(!directory.join(LONG_POLL_MAINTENANCE).exists());
        let scans = MAINTENANCE_SCANS.get();
        drop(client.claim_pending_send("short").unwrap());
        assert_eq!(MAINTENANCE_SCANS.get(), scans);
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
            .with_pending_journal(&directory)
            .unwrap()
            .with_status_protocol_cache()
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
