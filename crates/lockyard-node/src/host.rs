// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Persistent node host and private local control socket.
use crate::{
    Result,
    crypto::PayloadCodec,
    executor::{Caller, Executor, ExecutorConfig},
    quic::{self, DirectClient, DirectServer, PeerPin, PeerPolicy},
    relay::{RelayClient, RelayConfig, RelayEvent, RelaySender},
    wire::{
        self, FrameKind, JobRequest, JobSpec, LogRequest, MAX_FRAME_BYTES, Operation, RelayControl,
        RelayMessage, RpcFrame, RpcReply,
    },
};
#[path = "host_delegation.rs"]
mod delegation_adapter;
#[path = "host_revocations.rs"]
mod revocation_adapter;
#[path = "host_workflow.rs"]
mod workflow_adapter;
use lockyard_cloud_client::WorkspaceKey;
#[cfg(windows)]
use lockyard_core::windows::ipc::{AsyncListener as UnixListener, AsyncStream as UnixStream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, File},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Semaphore, oneshot},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub node_id: String,
    pub workspace: String,
    pub state_dir: PathBuf,
    pub listen: Option<SocketAddr>,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    #[serde(default)]
    pub trust_anchors: Vec<PathBuf>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    pub relay: Option<RelaySettings>,
    #[serde(default)]
    pub revocations: Option<crate::revocations::RevocationConfig>,
    pub executor: Option<ExecutorConfig>,
    /// Explicitly disclose opaque terminal job IDs and states to the configured broker.
    #[serde(default)]
    pub metadata_notifications: bool,
    /// Public signing keys pinned independently of received result envelopes.
    #[serde(default)]
    pub result_trust: BTreeMap<String, crate::provenance::TrustedSigningKey>,
    /// Dispatch-only clients must explicitly configure policy for each project they submit.
    #[serde(default)]
    pub project_retention: BTreeMap<String, crate::retention::RetentionPolicy>,
    pub workflow: Option<crate::workflow::WorkflowPolicy>,
    /// Client-only workload configuration: this socket cannot serve as a daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_socket: Option<PathBuf>,
    #[serde(default = "default_timeout")]
    pub rpc_timeout_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub node_id: String,
    pub address: Option<SocketAddr>,
    pub tls_name: String,
    pub certificate_sha256: String,
    pub certificate: PathBuf,
    #[serde(default)]
    pub allowed_operations: Vec<Operation>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySettings {
    pub url: String,
    pub token_file: PathBuf,
    #[serde(default)]
    pub tls_roots: Vec<PathBuf>,
}
fn default_timeout() -> u64 {
    60
}
impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_private(path, 1024 * 1024)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "invalid node configuration")?;
        let config: Self = toml::from_str(text).map_err(|_| "invalid node configuration")?;
        config.validate()?;
        Ok(config)
    }
    pub fn socket_path(&self) -> PathBuf {
        self.delegation_socket
            .clone()
            .unwrap_or_else(|| self.state_dir.join("control.sock"))
    }
    fn validate(&self) -> Result<()> {
        if let Some(revocations) = &self.revocations {
            revocations.validate()?;
            if revocations.trust.workspace_id != self.workspace {
                return Err("revocation_signer_untrusted".into());
            }
        }
        if self.metadata_notifications && (self.relay.is_none() || self.executor.is_none()) {
            return Err("job metadata notifications require an executor and relay".into());
        }
        if let Some(socket) = &self.delegation_socket
            && (!socket.is_absolute()
                || self.listen.is_some()
                || self.relay.is_some()
                || self.executor.is_some()
                || self.workflow.is_some()
                || !self.peers.is_empty()
                || !self.trust_anchors.is_empty()
                || !self.project_retention.is_empty()
                || self.metadata_notifications)
        {
            return Err("delegation configurations are restricted RPC clients".into());
        }
        if let Some(policy) = &self.workflow {
            policy.validate()?;
        }
        if !wire::valid_name(&self.node_id)
            || !wire::valid_name(&self.workspace)
            || !self.state_dir.is_absolute()
            || !(1..=3600).contains(&self.rpc_timeout_seconds)
        {
            return Err("invalid node configuration".into());
        }
        if !self.certificate.is_absolute()
            || !self.private_key.is_absolute()
            || self.trust_anchors.iter().any(|p| !p.is_absolute())
        {
            return Err("node identity paths must be absolute".into());
        }
        let mut names = HashSet::new();
        let mut pins = HashSet::new();
        for p in &self.peers {
            if !wire::valid_name(&p.node_id)
                || p.node_id == self.node_id
                || p.tls_name.is_empty()
                || !p.certificate.is_absolute()
                || !names.insert(&p.node_id)
                || !pins.insert(p.certificate_sha256.to_ascii_lowercase())
            {
                return Err("invalid peer configuration".into());
            }
            let cert = crate::local_files::read_public(&p.certificate, 64 * 1024)?;
            if PeerPin::certificate(&cert) != PeerPin::from_hex(&p.certificate_sha256)? {
                return Err("peer certificate pin mismatch".into());
            }
        }
        if let Some(executor) = &self.executor
            && (executor.node_id != self.node_id
                || executor.state_dir != self.state_dir.join("executor"))
        {
            return Err("executor identity or state directory mismatch".into());
        }
        if self.result_trust.len() > 4096
            || self
                .result_trust
                .iter()
                .any(|(node, key)| !wire::valid_name(node) || key.validate().is_err())
        {
            return Err("invalid result signing trust configuration".into());
        }
        if self.project_retention.len() > 4096
            || self
                .project_retention
                .iter()
                .any(|(project, policy)| !wire::valid_name(project) || policy.validate().is_err())
        {
            return Err("invalid project content retention configuration".into());
        }
        if self
            .executor
            .as_ref()
            .and_then(|executor| executor.provenance.as_ref())
            .is_some_and(|provenance| provenance.workspace != self.workspace)
        {
            return Err("executor signing workspace mismatch".into());
        }
        if let Some(relay) = &self.relay
            && (!relay.token_file.is_absolute() || relay.tls_roots.iter().any(|p| !p.is_absolute()))
        {
            return Err("relay credential and trust paths must be absolute".into());
        }
        Ok(())
    }
}
impl PeerConfig {
    fn policy(&self) -> PeerPolicy {
        PeerPolicy {
            node_id: self.node_id.clone(),
            certificate_sha256: self.certificate_sha256.clone(),
            allowed_operations: self.allowed_operations.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct NodeStatus {
    #[serde(default)]
    pub build: serde_json::Value,
    #[serde(default)]
    pub revocations_enforced: bool,
    #[serde(default)]
    pub revocations: Option<crate::revocations::RevocationSnapshot>,
    pub node_id: String,
    pub workspace: String,
    pub executor_enabled: bool,
    #[serde(default)]
    pub workflow_enabled: bool,
    #[serde(default)]
    pub workflow_healthy: bool,
    #[serde(default)]
    pub workflow_active_steps: usize,
    pub direct_listen: Option<SocketAddr>,
    pub relay_configured: bool,
    pub relay_outbox_pending: Option<usize>,
    pub relay_undeliverable: Option<usize>,
    /// Invalid encrypted requests rejected by this process since startup.
    pub relay_invalid_requests: u64,
    /// Invalid responses rejected by this process since startup.
    pub relay_invalid_responses: u64,
    /// Authenticated conflicting responses observed since startup.
    pub relay_conflicting_responses: u64,
    #[serde(default)]
    pub retention_cleanup_failed: bool,
    #[serde(default)]
    pub executor_dispatch_failed: bool,
    #[serde(default)]
    pub write_history_remaining: usize,
    #[serde(default)]
    pub job_notifications: Option<JobNotificationStatus>,
}
#[derive(Serialize, Deserialize)]
pub struct JobNotificationStatus {
    pub pending: usize,
    pub dropped: u64,
    pub expired: u64,
    pub capture_failures: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Status,
    Revocations {
        documents: Vec<crate::revocations::SignedDocument>,
    },
    Drain {
        enabled: bool,
    },
    DrainStatus,
    Workflow {
        request: crate::workflow::WorkflowControl,
    },
    Dispatch {
        expected_local_certificate_sha256: String,
        request: crate::incarnation::DispatchControl,
    },
    Rpc {
        target: String,
        operation: Operation,
        payload: Value,
    },
}
#[derive(Serialize, Deserialize)]
struct Cached {
    request_hash: String,
    response: RpcFrame,
    #[serde(default)]
    content_erased: Option<ErasedReply>,
}
#[derive(Serialize, Deserialize)]
struct ErasedReply {
    original_response_id: String,
    original_response_sha256: String,
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    request: RpcFrame,
    response: RpcFrame,
}
#[derive(Serialize, Deserialize)]
struct CompletedReceipt {
    request: RpcFrame,
    response_id: String,
    response_hash: String,
}
#[derive(Serialize, Deserialize)]
struct Expired {
    request: RpcFrame,
    code: String,
}
#[cfg(unix)]
use std::io::Read;

#[cfg(unix)]
use std::io::Write;

const OUTBOX_SLOTS: usize = 128;
const OUTBOX_RECORD_MAX: u64 = (MAX_FRAME_BYTES + 4096) as u64;
#[derive(Serialize, Deserialize)]
struct OutboxEntry {
    request_id: String,
    request_hash: String,
    operation: Operation,
    source: String,
    response: Option<RpcFrame>,
    accepted: bool,
}
#[derive(Serialize, Deserialize)]
struct RequestTombstone {
    request_hash: String,
    operation: Operation,
}
#[derive(Serialize, Deserialize)]
struct Undeliverable {
    request_id: String,
    response_id: String,
    operation: Operation,
    response_hash: String,
    reason: String,
}
#[derive(Serialize, Deserialize)]
struct InvalidResponse {
    request_id: String,
    response_id: String,
    operation: Operation,
    source: String,
    response_hash: String,
    count: u64,
}
struct PendingResponse {
    tx: oneshot::Sender<std::result::Result<RpcFrame, &'static str>>,
}
struct PendingRegistration<'a> {
    pending: &'a std::sync::Mutex<HashMap<String, PendingResponse>>,
    id: String,
}
impl Drop for PendingRegistration<'_> {
    fn drop(&mut self) {
        self.pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.id);
    }
}
#[derive(Default)]
struct CacheBudget {
    // Rebuilt once from durable files at startup. Reservations count before dispatch,
    // so a failed operation may overestimate until the next bounded eviction scan.
    read_responses: usize,
    content_deadlines: BTreeSet<(u64, String, String)>,
    content_by_file: HashMap<(String, String), u64>,
    completed_writes: usize,
}
impl CacheBudget {
    fn load(state: &Path) -> Result<Self> {
        let mut read_responses = 0usize;
        for entry in fs::read_dir(state.join("responses-read"))? {
            if wire::valid_ulid(&entry?.file_name().to_string_lossy()) {
                read_responses += 1;
            }
        }
        let completed_writes = fs::read_dir(state.join("relay-completed-writes"))?
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|entry| wire::valid_ulid(&entry.file_name().to_string_lossy()))
            .count();
        let mut value = Self {
            read_responses,
            content_deadlines: BTreeSet::new(),
            content_by_file: HashMap::new(),
            completed_writes,
        };
        for bucket in [
            "responses-read",
            "responses-write",
            "relay-requests-read",
            "relay-requests-write",
            "relay-inbox-read",
            "relay-inbox-write",
            "relay-outbox",
        ] {
            for entry in fs::read_dir(state.join(bucket))? {
                let entry = entry?;
                let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if !wire::valid_ulid(&id) {
                    continue;
                }
                let bytes = read_private(&entry.path(), (MAX_FRAME_BYTES * 3 + 4096) as u64)?;
                let deadline = if bucket.starts_with("relay-inbox-") {
                    let record: Receipt = serde_json::from_slice(&bytes)?;
                    receipt_deadline(&record)
                } else if bucket == "relay-outbox" {
                    let record: OutboxEntry = serde_json::from_slice(&bytes)?;
                    record.response.as_ref().and_then(frame_deadline)
                } else {
                    let record: Cached = serde_json::from_slice(&bytes)?;
                    if record.content_erased.is_some() {
                        None
                    } else {
                        frame_deadline(&record.response)
                    }
                };
                value.track(bucket, &id, deadline);
            }
        }
        Ok(value)
    }
    fn track(&mut self, bucket: &str, id: &str, deadline: Option<u64>) {
        self.forget(bucket, id);
        if let Some(deadline) = deadline {
            self.content_deadlines
                .insert((deadline, bucket.into(), id.into()));
            self.content_by_file
                .insert((bucket.into(), id.into()), deadline);
        }
    }
    fn forget(&mut self, bucket: &str, id: &str) {
        if let Some(deadline) = self.content_by_file.remove(&(bucket.into(), id.into())) {
            self.content_deadlines
                .remove(&(deadline, bucket.into(), id.into()));
        }
    }
    fn store<T: Serialize>(
        &mut self,
        dir: &Path,
        id: &str,
        value: &T,
        deadline: Option<u64>,
    ) -> Result<()> {
        let bucket = dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid cache bucket")?;
        self.track(bucket, id, deadline);
        let result = store_data(dir, id, &serde_json::to_vec(value)?);
        if result.is_err()
            && fs::symlink_metadata(dir.join(id))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            && deadline.is_some()
        {
            self.forget(bucket, id);
        }
        result
    }
}
fn frame_deadline(frame: &RpcFrame) -> Option<u64> {
    if frame.payload.is_empty() {
        return None;
    }
    frame
        .retention
        .as_ref()
        .map(|value| value.expires_at_ms)
        .or_else(|| {
            ((frame.kind == FrameKind::Response
                && frame.operation != Operation::NodePing
                && frame.source_certificate_sha256.is_none())
                || (frame.kind == FrameKind::Request && frame.operation == Operation::JobSubmit))
                .then_some(0)
        })
}
fn receipt_deadline(receipt: &Receipt) -> Option<u64> {
    match (
        frame_deadline(&receipt.request),
        frame_deadline(&receipt.response),
    ) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        _ => None,
    }
}
struct Host {
    _lock: File,
    config: NodeConfig,
    certificate_sha256: String,
    codec: PayloadCodec,
    executor: Option<Executor>,
    workflow: Option<Arc<crate::workflow::WorkflowController>>,
    direct: Option<DirectClient>,
    revocations: Option<Arc<crate::revocations::RevocationManager>>,
    relay: Option<RelaySender>,
    // Every access is an immediate map operation. A synchronous mutex lets the
    // registration guard clean up even when its async RPC future is cancelled.
    pending: std::sync::Mutex<HashMap<String, PendingResponse>>,
    // Stripe by request ID so independent RPCs can proceed while duplicate IDs serialize.
    request_locks: Vec<Mutex<()>>,
    cache_lock: Mutex<CacheBudget>,
    permits: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    delegation_connections: Arc<Semaphore>,
    relay_slots: Arc<Semaphore>,
    relay_ingress: Arc<Semaphore>,
    relay_inflight: Mutex<HashSet<String>>,
    invalid_requests: AtomicU64,
    invalid_responses: AtomicU64,
    conflicting_responses: AtomicU64,
    retention_cleanup_failed: std::sync::atomic::AtomicBool,
    operator_draining: std::sync::atomic::AtomicBool,
    relay_acks: Arc<Semaphore>,
    // Reserve one permanent correlation slot before each new relay mutation. This
    // guarantees every retained write receipt can be compacted before content expiry.
    write_history: Arc<Semaphore>,
    clock: Mutex<ClockState>,
}
#[cfg(unix)]
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot read private file")?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.mode() & 0o077 != 0
        || m.uid() != unsafe { libc::geteuid() }
        || m.len() > max
    {
        return Err("private file permissions or size invalid".into());
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("private file too large".into());
    }
    Ok(bytes)
}
fn workspace_key_directory() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(lockyard_core::paths::home_dir().ok_or("workspace key unavailable")?)
            .join(".config"),
    };
    Ok(base.join("lockyard/keys"))
}
#[cfg(unix)]
fn validate_workspace_key(workspace: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let keys = workspace_key_directory()?;
    let root = keys
        .parent()
        .ok_or("workspace key unavailable")?
        .to_path_buf();
    for path in [&root, &keys] {
        let metadata = fs::symlink_metadata(path).map_err(|_| "workspace key unavailable")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("workspace key directory must be private".into());
        }
    }
    let bytes = read_private(&keys.join(format!("{workspace}.key")), 32)?;
    if bytes.len() != 32 {
        return Err("invalid workspace key".into());
    }
    Ok(())
}
#[cfg(unix)]
fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.mode() & 0o077 != 0
        || m.uid() != unsafe { libc::geteuid() }
    {
        return Err("node state directory must be private".into());
    }
    Ok(())
}
#[cfg(unix)]
fn lock_state(path: &Path) -> Result<File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.join("host.lock"))?;
    let m = file.metadata()?;
    if !m.is_file() || m.mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() } {
        return Err("node lock must be private".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("node host already running".into());
    }
    Ok(file)
}
#[cfg(unix)]
fn make_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } {
            return Err("unsafe control socket path".into());
        }
        fs::remove_file(path)?;
    }
    let socket = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(socket)
}
fn read_certificates(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    paths
        .iter()
        .map(|p| crate::local_files::read_public(p, 64 * 1024))
        .collect()
}
fn request_hash(frame: &RpcFrame) -> Result<String> {
    let bytes = serde_json::to_vec(frame)?;
    Ok(ring::digest::digest(&ring::digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
const REQUEST_TTL_MS: u64 = wire::REQUEST_DELIVERY_TTL_MS;
fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn ulid_time_ms(id: &str) -> Result<u64> {
    if !wire::valid_ulid(id) {
        return Err("invalid request ID".into());
    }
    let mut result = 0u64;
    for b in id.bytes().take(10) {
        let digit = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
            .iter()
            .position(|c| *c == b)
            .ok_or("invalid request ID")?;
        result = (result << 5) | digit as u64;
    }
    Ok(result)
}
struct ClockState {
    last_wall_ms: u64,
    effective_ms: u64,
    tick: Instant,
}
impl ClockState {
    fn load(dir: &Path) -> Result<Self> {
        let now = wall_ms()?;
        let path = dir.join("clock-floor");
        if path.exists() {
            let bytes = read_private(&path, 32)?;
            let floor: u64 = std::str::from_utf8(&bytes)?
                .parse()
                .map_err(|_| "invalid durable clock")?;
            if now < floor {
                return Err("clock moved backwards; relay replay disabled".into());
            }
        }
        let _ = fs::remove_file(dir.join(".clock-floor.tmp"));
        store_data(dir, "clock-floor", now.to_string().as_bytes())?;
        Ok(Self {
            last_wall_ms: now,
            effective_ms: now,
            tick: Instant::now(),
        })
    }
    fn observe(&mut self, dir: &Path) -> Result<u64> {
        let now = wall_ms()?;
        if now < self.last_wall_ms {
            return Err("clock moved backwards; relay replay disabled".into());
        }
        let elapsed: u64 = self
            .tick
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let effective = now.max(self.effective_ms.saturating_add(elapsed));
        store_data(dir, "clock-floor", effective.to_string().as_bytes())?;
        self.last_wall_ms = now;
        self.effective_ms = effective;
        self.tick = Instant::now();
        Ok(effective)
    }
}
fn is_write(op: Operation) -> bool {
    matches!(
        op,
        Operation::JobSubmit | Operation::JobCancel | Operation::JobResolveUnknown
    )
}
fn bucket_dir(state: &Path, prefix: &str, op: Operation) -> PathBuf {
    state.join(format!(
        "{prefix}-{}",
        if is_write(op) { "write" } else { "read" }
    ))
}
// The broker retains deduplication records for seven days. Read-only responses and
// received routing receipts can be collected after an eight-day margin. Project TTL
// erases write response bodies earlier; compact non-replay evidence remains durable.
fn ensure_capacity(dir: &Path, op: Operation, may_expire: bool) -> Result<()> {
    ensure_capacity_limit(
        dir,
        op,
        may_expire,
        if is_write(op) { 100_000 } else { 10_000 },
    )
}
fn archive_write_receipt(dir: &Path, path: &Path, completed_count: &mut usize) -> Result<()> {
    let id = path
        .file_name()
        .ok_or("invalid response receipt")?
        .to_os_string()
        .into_string()
        .map_err(|_| "invalid response receipt")?;
    if !wire::valid_ulid(&id) {
        return Err("invalid response receipt".into());
    }
    let receipt: Receipt =
        serde_json::from_slice(&read_private(path, (MAX_FRAME_BYTES * 3) as u64)?)?;
    if receipt.request.id != id
        || receipt.request.kind != FrameKind::Request
        || !is_write(receipt.request.operation)
        || receipt.response.kind != FrameKind::Response
        || receipt.response.in_reply_to.as_deref() != Some(&id)
        || receipt.response.source != receipt.request.target
        || receipt.response.target != receipt.request.source
        || receipt.response.operation != receipt.request.operation
    {
        return Err("invalid response receipt".into());
    }
    let state = dir.parent().ok_or("invalid response receipt path")?;
    let completed = state.join("relay-completed-writes");
    let path = completed.join(&id);
    let hash = request_hash(&receipt.response)?;
    if path.exists() {
        let old: CompletedReceipt = serde_json::from_slice(&read_private(&path, 4096)?)?;
        if old.request.id != id
            || old.response_id != receipt.response.id
            || old.response_hash != hash
        {
            return Err("completed receipt conflict".into());
        }
    } else {
        if *completed_count >= 100_000 {
            return Err("completed receipt capacity reached".into());
        }
        let mut request = receipt.request;
        request.payload.clear();
        store_data(
            &completed,
            &id,
            &serde_json::to_vec(&CompletedReceipt {
                request,
                response_id: receipt.response.id,
                response_hash: hash,
            })?,
        )?;
        *completed_count += 1;
    }
    Ok(())
}
fn ensure_capacity_limit(dir: &Path, op: Operation, may_expire: bool, limit: usize) -> Result<()> {
    let entries: Vec<_> = fs::read_dir(dir)?.flatten().collect();
    if entries.len() < limit {
        return Ok(());
    }
    if may_expire {
        let age = Duration::from_secs(8 * 24 * 60 * 60);
        let archive = is_write(op)
            && dir
                .file_name()
                .is_some_and(|name| name == "relay-inbox-write");
        let mut completed_count = if archive {
            fs::read_dir(
                dir.parent()
                    .ok_or("invalid state path")?
                    .join("relay-completed-writes"),
            )?
            .take(100_000)
            .count()
        } else {
            0
        };
        for entry in &entries {
            if entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|elapsed| elapsed >= age)
            {
                if is_write(op)
                    && dir
                        .file_name()
                        .is_some_and(|name| name == "responses-write")
                {
                    continue;
                }
                if archive {
                    archive_write_receipt(dir, &entry.path(), &mut completed_count)?;
                }
                fs::remove_file(entry.path())?;
            }
        }
        lockyard_core::fsio::sync_path(dir)?;
    }
    if fs::read_dir(dir)?.take(limit).count() >= limit {
        return Err("node durable storage capacity reached".into());
    }
    Ok(())
}
// Read-only responses may be recomputed. Retain compact ID/hash tombstones so
// eviction cannot turn a formerly read-only ID into a mutating request.
fn evict_read_responses(dir: &Path, now: u64) -> Result<(usize, Vec<String>)> {
    const CACHE_LIMIT: usize = 10_000;
    const TOMBSTONE_LIMIT: usize = 1_000_000;
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .flatten()
        .filter(|entry| wire::valid_ulid(&entry.file_name().to_string_lossy()))
        .collect();
    if entries.len() < CACHE_LIMIT {
        return Ok((entries.len(), Vec::new()));
    }
    let state = dir.parent().ok_or("invalid response cache path")?;
    let tombstones = state.join("read-tombstones");
    let take = entries
        .len()
        .saturating_sub(CACHE_LIMIT)
        .saturating_add(512)
        .min(entries.len());
    let count = fs::read_dir(&tombstones)?.take(TOMBSTONE_LIMIT).count();
    if count.saturating_add(take) > TOMBSTONE_LIMIT {
        for entry in fs::read_dir(&tombstones)?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ulid_time_ms(&name)
                .is_ok_and(|created| now >= created.saturating_add(REQUEST_TTL_MS))
            {
                let _ = fs::remove_file(entry.path());
            }
        }
        lockyard_core::fsio::sync_path(&tombstones)?;
        if fs::read_dir(&tombstones)?
            .take(TOMBSTONE_LIMIT - take + 1)
            .count()
            + take
            > TOMBSTONE_LIMIT
        {
            return Err("read tombstone capacity reached".into());
        }
    }
    entries.sort_unstable_by_key(|entry| {
        entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(UNIX_EPOCH)
    });
    let remaining = entries.len() - take;
    let mut removed = Vec::with_capacity(take);
    for entry in entries.into_iter().take(take) {
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid response cache")?;
        let cached: Cached =
            serde_json::from_slice(&read_private(&entry.path(), (MAX_FRAME_BYTES * 2) as u64)?)?;
        let path = tombstones.join(&id);
        if path.exists() {
            if read_private(&path, 128)? != cached.request_hash.as_bytes() {
                return Err("read tombstone conflict".into());
            }
        } else {
            store_data(&tombstones, &id, cached.request_hash.as_bytes())?;
        }
        fs::remove_file(entry.path())?;
        removed.push(id);
    }
    lockyard_core::fsio::sync_path(dir)?;
    Ok((remaining, removed))
}
fn erase_cached_content(
    host: &Host,
    budget: &mut CacheBudget,
    dir: &Path,
    id: &str,
    cached: &mut Cached,
) -> Result<()> {
    if cached.content_erased.is_none() {
        let original = ErasedReply {
            original_response_id: cached.response.id.clone(),
            original_response_sha256: request_hash(&cached.response)?,
        };
        let mut response = cached.response.clone();
        response.id = wire::new_id()?;
        response.retention = None;
        response.payload.clear();
        // Legacy unpinned mutations can only remain as metadata: new endpoints reject
        // them before a cache lookup. They must not retain old ciphertext indefinitely.
        if response.operation.requires_submit_permission()
            && (response.v != wire::PROTOCOL_VERSION
                || response.source_certificate_sha256.is_none())
        {
            response.payload.clear();
        } else {
            host.codec.encode(&mut response, &RpcReply::<Value>::failure("response_content_expired",
                "This response's retention window ended; reconcile with a fresh request and the original job ID."))?;
        }
        let candidate = Cached {
            request_hash: cached.request_hash.clone(),
            response,
            content_erased: Some(original),
        };
        budget.store(dir, id, &candidate, None)?;
        *cached = candidate;
    }
    let Some(original) = &cached.content_erased else {
        return Ok(());
    };
    let outbox_dir = host.config.state_dir.join("relay-outbox");
    let path = outbox_dir.join(id);
    if path.exists() {
        let entry: OutboxEntry = serde_json::from_slice(&read_private(&path, OUTBOX_RECORD_MAX)?)?;
        if entry.request_hash != cached.request_hash {
            return Err("retention outbox binding conflict".into());
        }
        if let Some(response) = entry.response.as_ref()
            && response.id == original.original_response_id
            && request_hash(response)? == original.original_response_sha256
        {
            // The original outcome's ID/hash and the non-replay binding are now durable.
            fs::remove_file(path)?;
            lockyard_core::fsio::sync_path(outbox_dir)?;
            budget.forget("relay-outbox", id);
            host.relay_slots.add_permits(1);
        }
    }
    Ok(())
}
#[cfg(test)]
#[cfg(unix)]
fn store_cache(dir: &Path, id: &str, cache: &Cached) -> Result<()> {
    store_data(dir, id, &serde_json::to_vec(cache)?)
}
#[cfg(unix)]
fn store_data(dir: &Path, id: &str, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(id);
    let tmp = dir.join(format!(".{id}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        lockyard_core::fsio::rename(&tmp, path)?;
        lockyard_core::fsio::sync_path(dir)?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        // A temporary body was never published. Preserve any already-renamed final
        // record as uncertain durable evidence, but do not retain a failed private copy.
        match fs::remove_file(&tmp) {
            Ok(()) => {
                lockyard_core::fsio::sync_path(dir)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    result
}
impl Host {
    fn drain_status_value(&self) -> Result<Value> {
        let mut value = match self.executor.as_ref() {
            Some(executor) => serde_json::to_value(executor.drain_status()?)?,
            None => {
                json!({"draining":self.operator_draining.load(Ordering::SeqCst),"queued":0,"running":0,"unknown":0})
            }
        };
        value["workflow_active_steps"] = json!(
            self.workflow
                .as_ref()
                .map(|controller| controller.active_steps())
                .transpose()?
                .unwrap_or(0)
        );
        value["workflow_healthy"] = json!(
            self.workflow
                .as_ref()
                .is_none_or(|controller| controller.is_healthy())
        );
        value["outbound_unresolved"] =
            json!(crate::incarnation::unresolved_dispatches(&self.config)?);
        Ok(value)
    }
    fn status(&self) -> NodeStatus {
        NodeStatus {
            build: lockyard_core::build_info(),
            revocations_enforced: self
                .revocations
                .as_ref()
                .is_some_and(|state| state.config().required),
            revocations: self
                .revocations
                .as_ref()
                .and_then(|state| state.snapshot().ok()),
            node_id: self.config.node_id.clone(),
            workspace: self.config.workspace.clone(),
            executor_enabled: self.executor.is_some(),
            workflow_enabled: self.workflow.is_some(),
            workflow_healthy: self
                .workflow
                .as_ref()
                .is_none_or(|controller| controller.is_healthy()),
            workflow_active_steps: self
                .workflow
                .as_ref()
                .and_then(|controller| controller.active_steps().ok())
                .unwrap_or(0),
            direct_listen: self.config.listen,
            relay_configured: self.relay.is_some(),
            relay_outbox_pending: fs::read_dir(self.config.state_dir.join("relay-outbox"))
                .ok()
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|entry| wire::valid_ulid(&entry.file_name().to_string_lossy()))
                        .count()
                }),
            relay_undeliverable: ["relay-undeliverable-read", "relay-undeliverable-write"]
                .iter()
                .map(|name| {
                    fs::read_dir(self.config.state_dir.join(name))
                        .ok()
                        .map(|entries| {
                            entries
                                .flatten()
                                .filter(|entry| {
                                    wire::valid_ulid(&entry.file_name().to_string_lossy())
                                })
                                .count()
                        })
                })
                .sum::<Option<usize>>(),
            relay_invalid_requests: self.invalid_requests.load(Ordering::Relaxed),
            relay_invalid_responses: self.invalid_responses.load(Ordering::Relaxed),
            relay_conflicting_responses: self.conflicting_responses.load(Ordering::Relaxed),
            retention_cleanup_failed: self.retention_cleanup_failed.load(Ordering::Relaxed),
            executor_dispatch_failed: self
                .executor
                .as_ref()
                .is_some_and(|executor| !executor.dispatch_healthy()),
            write_history_remaining: self.write_history.available_permits(),
            job_notifications: self
                .executor
                .as_ref()
                .and_then(|executor| executor.notification_status())
                .map(
                    |(pending, dropped, expired, capture_failures)| JobNotificationStatus {
                        pending,
                        dropped,
                        expired,
                        capture_failures,
                    },
                ),
        }
    }
    async fn handle(&self, frame: RpcFrame, relay_authenticated: bool) -> Result<RpcFrame> {
        frame.validate()?;
        if frame.kind != FrameKind::Request || frame.target != self.config.node_id {
            return Err("invalid request routing".into());
        }
        if frame
            .target_certificate_sha256
            .as_deref()
            .is_some_and(|pin| pin != self.certificate_sha256)
        {
            return Err("target node incarnation mismatch".into());
        }
        if frame.operation == Operation::JobSubmit && frame.retention.is_none() {
            return Err("project content retention is required".into());
        }
        if frame.operation != Operation::NodePing && frame.target_certificate_sha256.is_none() {
            return Err("job RPC requires node incarnation pins".into());
        }
        if relay_authenticated {
            // The broker binds source to a registered, live workspace credential. The
            // workspace key additionally authenticates the entire encrypted frame.
        } else {
            let peer = self
                .config
                .peers
                .iter()
                .find(|p| p.node_id == frame.source)
                .ok_or("unknown peer")?;
            if !peer.allowed_operations.contains(&frame.operation) {
                return Err("peer operation denied".into());
            }
            if frame
                .source_certificate_sha256
                .as_deref()
                .is_some_and(|pin| pin != peer.certificate_sha256.to_ascii_lowercase())
            {
                return Err("source node incarnation mismatch".into());
            }
        }
        // Reject stale IDs on both transports before any execution. This bounds
        // compact read tombstone retention; wall-clock rollback fails closed.
        let created = ulid_time_ms(&frame.id)?;
        let hash = request_hash(&frame)?;
        let stripe = ring::digest::digest(&ring::digest::SHA256, frame.id.as_bytes()).as_ref()[0]
            as usize
            % self.request_locks.len();
        let _request_guard = self.request_locks[stripe].lock().await;
        let now = self.clock.lock().await.observe(&self.config.state_dir)?;
        if created > now.saturating_add(5 * 60 * 1000)
            || now >= created.saturating_add(REQUEST_TTL_MS)
        {
            return Err("request delivery lifetime exceeded".into());
        }
        let payload: Value = self
            .codec
            .decode(&frame)
            .map_err(|_| "request authentication failed")?;
        if frame
            .retention
            .as_ref()
            .is_some_and(|retention| now >= retention.expires_at_ms)
        {
            return Err("content delivery lifetime exceeded".into());
        }
        let dir = bucket_dir(&self.config.state_dir, "responses", frame.operation);
        // A changed operation must not evade conflict detection by changing buckets.
        for bucket in ["read", "write"] {
            let path = self
                .config
                .state_dir
                .join(format!("responses-{bucket}"))
                .join(&frame.id);
            if path.exists() {
                let mut cached: Cached =
                    serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 2) as u64)?)
                        .map_err(|_| "invalid response cache")?;
                if cached.request_hash != hash {
                    return Err("request identifier conflict".into());
                }
                if cached.content_erased.is_none()
                    && frame_deadline(&cached.response).is_some_and(|deadline| now >= deadline)
                {
                    let mut budget = self.cache_lock.lock().await;
                    erase_cached_content(
                        self,
                        &mut budget,
                        path.parent().ok_or("invalid cache path")?,
                        &frame.id,
                        &mut cached,
                    )?;
                }
                return Ok(cached.response);
            }
        }
        for bucket in ["read", "write"] {
            let path = self
                .config
                .state_dir
                .join(format!("request-tombstones-{bucket}"))
                .join(&frame.id);
            if path.exists() {
                let old: RequestTombstone = serde_json::from_slice(&read_private(&path, 512)?)?;
                if old.request_hash != hash || old.operation != frame.operation {
                    return Err("request identifier conflict".into());
                }
            }
        }
        let tombstone = self
            .config
            .state_dir
            .join("read-tombstones")
            .join(&frame.id);
        if tombstone.exists() && read_private(&tombstone, 128)? != hash.as_bytes() {
            return Err("request identifier conflict".into());
        }
        // At most 128 requests can be in flight, bounding concurrent capacity overshoot.
        {
            let mut budget = self.cache_lock.lock().await;
            if is_write(frame.operation) {
                ensure_capacity(&dir, frame.operation, false)?;
            } else {
                if budget.read_responses >= 10_000 {
                    let (remaining, removed) = evict_read_responses(&dir, now)?;
                    budget.read_responses = remaining;
                    for id in removed {
                        budget.forget("responses-read", &id);
                    }
                }
                budget.read_responses += 1;
            }
        }
        let caller = Caller {
            node_id: frame.source.clone(),
            local_operator: false,
            certificate_sha256: frame.source_certificate_sha256.clone(),
        };
        let mut reply = self
            .dispatch(
                frame.operation,
                payload.clone(),
                caller,
                frame.retention.as_ref().map(|value| value.policy()),
            )
            .await;
        let response_id = wire::new_id()?;
        let retention = match self.reply_retention(
            &response_id,
            frame.operation,
            &payload,
            &reply,
            frame.retention.as_ref(),
        ) {
            Ok(None) if reply.ok && frame.operation != Operation::NodePing => {
                reply = RpcReply::failure(
                    "project_retention_required",
                    "Job content retention is unavailable.",
                );
                None
            }
            Ok(value) => value,
            Err(_) => {
                reply =
                    RpcReply::failure("job_content_expired", "Job content retention has expired.");
                None
            }
        };
        let mut response = RpcFrame {
            v: frame.v,
            kind: FrameKind::Response,
            id: response_id,
            source: self.config.node_id.clone(),
            target: frame.source.clone(),
            operation: frame.operation,
            in_reply_to: Some(frame.id.clone()),
            source_certificate_sha256: frame.target_certificate_sha256.clone(),
            target_certificate_sha256: frame.source_certificate_sha256.clone(),
            retention,
            payload: String::new(),
        };
        self.codec.encode(&mut response, &reply)?;
        let mut budget = self.cache_lock.lock().await;
        budget.store(
            &dir,
            &frame.id,
            &Cached {
                request_hash: hash,
                response: response.clone(),
                content_erased: None,
            },
            frame_deadline(&response),
        )?;
        Ok(response)
    }
    async fn dispatch(
        &self,
        op: Operation,
        payload: Value,
        caller: Caller,
        sender_policy: Option<crate::retention::RetentionPolicy>,
    ) -> RpcReply<Value> {
        if op == Operation::RevocationsApply {
            return self.apply_revocation_payload(payload);
        }
        if op == Operation::NodePing {
            if let Some(resolve) = payload.get("resolve") {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Resolve {
                    repository: String,
                    revision: String,
                    runner: String,
                }
                let request: Resolve = match serde_json::from_value(resolve.clone()) {
                    Ok(request) => request,
                    Err(_) => {
                        return RpcReply::failure(
                            "invalid_revision_request",
                            "Invalid revision request.",
                        );
                    }
                };
                let Some(executor) = self.executor.clone() else {
                    return RpcReply::failure(
                        "executor_disabled",
                        "This node does not execute jobs.",
                    );
                };
                let pin = self.certificate_sha256.clone();
                return match tokio::task::spawn_blocking(move || {
                    executor.workflow_revision(
                        &pin,
                        &request.repository,
                        &request.revision,
                        &request.runner,
                    )
                })
                .await
                {
                    Ok(Ok(revision)) => match serde_json::to_value(revision) {
                        Ok(value) => RpcReply::success(value),
                        Err(_) => RpcReply::failure(
                            "revision_unavailable",
                            "Revision context is unavailable.",
                        ),
                    },
                    _ => RpcReply::failure(
                        "revision_unavailable",
                        "Revision context is unavailable.",
                    ),
                };
            }
            if payload.get("describe").and_then(Value::as_bool) == Some(true) {
                return match self.executor.as_ref() {
                    Some(executor) => match executor.capabilities(&self.certificate_sha256) {
                        Ok(capabilities) => RpcReply::success(
                            json!({"node_id":self.config.node_id,"capabilities":capabilities,"protocol_capabilities":self.revocation_capabilities()}),
                        ),
                        Err(_) => RpcReply::failure(
                            "capabilities_unavailable",
                            "Node capabilities are unavailable.",
                        ),
                    },
                    None => RpcReply::success(
                        json!({"node_id":self.config.node_id,"capabilities":self.revocation_capabilities()}),
                    ),
                };
            }
            return RpcReply::success(
                json!({"node_id":self.config.node_id,"capabilities":self.revocation_capabilities(),"revocations_enforced":self.revocations.as_ref().is_some_and(|state|state.config().required)}),
            );
        }
        let Some(executor) = self.executor.clone() else {
            return RpcReply::failure("executor_disabled", "This node does not execute jobs.");
        };
        if op == Operation::JobStatus
            && let Ok(request) = serde_json::from_value::<JobRequest>(payload.clone())
        {
            let status_executor = executor.clone();
            match tokio::task::spawn_blocking(move || {
                status_executor.expired_metadata(&request.job_id)
            })
            .await
            {
                Ok(Ok(Some(metadata))) => {
                    let mut reply = RpcReply::failure(
                        "job_content_expired",
                        "Job content retention has expired.",
                    );
                    reply.result = Some(metadata);
                    return reply;
                }
                Ok(Ok(None)) => (),
                _ => {
                    return RpcReply::failure(
                        "retention_evidence_unavailable",
                        "Job retention evidence is unavailable.",
                    );
                }
            }
        }
        let result =
            tokio::task::spawn_blocking(move || -> std::result::Result<Value, &'static str> {
                let value = match op {
                    Operation::JobSubmit => {
                        let spec: JobSpec =
                            serde_json::from_value(payload).map_err(|_| "invalid_request")?;
                        let policy = sender_policy.as_ref().ok_or("project_retention_required")?;
                        serde_json::to_value(
                            executor
                                .submit_with_retention(spec, &caller, Some(policy))
                                .map_err(|e| e.0)?,
                        )
                    }
                    Operation::JobStatus | Operation::JobCancel | Operation::JobResolveUnknown => {
                        let request: JobRequest =
                            serde_json::from_value(payload).map_err(|_| "invalid_request")?;
                        let record = match op {
                            Operation::JobStatus => executor.status(&request.job_id),
                            Operation::JobCancel => executor.cancel(&request.job_id, &caller),
                            _ => executor.resolve_unknown(&request.job_id, &caller),
                        }
                        .map_err(|e| e.0)?;
                        serde_json::to_value(record)
                    }
                    Operation::JobLog | Operation::JobPatch | Operation::JobArchive => {
                        let request: LogRequest =
                            serde_json::from_value(payload).map_err(|_| "invalid_request")?;
                        let limit = request.limit.min(wire::MAX_TRANSFER_BYTES) as usize;
                        let chunk = if op == Operation::JobLog {
                            executor.read_log(&request.job_id, request.offset, limit)
                        } else if op == Operation::JobPatch {
                            executor.read_patch(&request.job_id, request.offset, limit)
                        } else {
                            executor.read_archive(&request.job_id, request.offset, limit)
                        }
                        .map_err(|e| e.0)?;
                        serde_json::to_value(chunk)
                    }
                    Operation::NodePing | Operation::RevocationsApply => unreachable!(),
                };
                value.map_err(|_| "response_encoding_failed")
            })
            .await;
        match result {
            Ok(Ok(value)) => RpcReply::success(value),
            Ok(Err(code)) => RpcReply::failure(code, "Node operation failed."),
            Err(_) => RpcReply::failure("executor_failed", "Node operation failed."),
        }
    }
    fn project_policy(&self, payload: &Value) -> Result<crate::retention::RetentionPolicy> {
        let project = payload
            .get("repository")
            .and_then(Value::as_str)
            .ok_or("job repository is required")?;
        let policy = self
            .config
            .project_retention
            .get(project)
            .or_else(|| {
                self.config
                    .executor
                    .as_ref()
                    .and_then(|executor| executor.repositories.get(project))
                    .and_then(|repository| repository.retention.as_ref())
            })
            .ok_or("explicit project content retention is required before submission")?;
        policy.validate()?;
        Ok(policy.clone())
    }
    fn reply_retention(
        &self,
        response_id: &str,
        op: Operation,
        payload: &Value,
        reply: &RpcReply<Value>,
        request: Option<&crate::retention::ContentRetention>,
    ) -> Result<Option<crate::retention::ContentRetention>> {
        if op == Operation::RevocationsApply {
            return Ok(None);
        }
        if op == Operation::NodePing {
            if let Some(resolve) = payload.get("resolve") {
                let receiver = self.project_policy(resolve)?;
                let policy = match request {
                    Some(sender) => receiver.effective(&sender.policy())?,
                    None => {
                        return Err(
                            "revision resolution requires explicit project retention".into()
                        );
                    }
                };
                return Ok(Some(crate::retention::ContentRetention::for_copy(
                    &policy,
                    crate::retention::id_timestamp_ms(response_id)?,
                    None,
                )?));
            }
            return Ok(None);
        }
        let snapshot = reply
            .result
            .as_ref()
            .and_then(|value| value.get("retention"))
            .and_then(|value| {
                serde_json::from_value::<crate::retention::RetentionSnapshot>(value.clone()).ok()
            })
            .or_else(|| {
                payload
                    .get("job_id")
                    .and_then(Value::as_str)
                    .and_then(|id| {
                        self.executor
                            .as_ref()
                            .and_then(|executor| executor.content_retention(id).ok())
                    })
            });
        let (policy, terminal) = if let Some(snapshot) = snapshot {
            (
                crate::retention::RetentionPolicy {
                    content_ttl_seconds: snapshot.content_ttl_seconds,
                },
                snapshot.terminal_expires_at_ms,
            )
        } else if op == Operation::JobSubmit {
            let local = self.project_policy(payload).ok();
            let policy = match (local, request) {
                (Some(local), Some(sender)) => Some(local.effective(&sender.policy())?),
                (Some(local), None) => Some(local),
                (None, Some(sender)) => Some(sender.policy()),
                _ => None,
            };
            let Some(policy) = policy else {
                return Ok(None);
            };
            (policy, None)
        } else if let Some(request) = request {
            (request.policy(), None)
        } else {
            return Ok(None);
        };
        Ok(Some(crate::retention::ContentRetention::for_copy(
            &policy,
            crate::retention::id_timestamp_ms(response_id)?,
            terminal,
        )?))
    }
    async fn rpc(&self, target: &str, op: Operation, payload: Value) -> Result<RpcReply<Value>> {
        self.rpc_bound(
            target,
            op,
            payload,
            None,
            crate::incarnation::DispatchOrigin::Operator,
        )
        .await
    }
    async fn rpc_bound(
        &self,
        target: &str,
        op: Operation,
        payload: Value,
        expected_pin: Option<&str>,
        origin: crate::incarnation::DispatchOrigin,
    ) -> Result<RpcReply<Value>> {
        let reply = self
            .rpc_bound_inner(target, op, payload, expected_pin, origin)
            .await?;
        if matches!(
            op,
            Operation::JobSubmit
                | Operation::JobStatus
                | Operation::JobCancel
                | Operation::JobResolveUnknown
        ) {
            let config = self.config.clone();
            let target = target.to_owned();
            let pin = self.certificate_sha256.clone();
            return tokio::task::spawn_blocking(move || -> Result<RpcReply<Value>> {
                crate::incarnation::note_terminal(&config, &target, &pin, &reply)?;
                Ok(reply)
            })
            .await
            .map_err(|_| "outbound terminal reconciliation failed")?;
        }
        Ok(reply)
    }
    async fn rpc_bound_inner(
        &self,
        target: &str,
        op: Operation,
        payload: Value,
        expected_pin: Option<&str>,
        origin: crate::incarnation::DispatchOrigin,
    ) -> Result<RpcReply<Value>> {
        let sender_policy = if op == Operation::JobSubmit {
            Some(self.project_policy(&payload)?)
        } else if op == Operation::NodePing && payload.get("resolve").is_some() {
            Some(self.project_policy(&payload["resolve"])?)
        } else {
            None
        };
        let local_operator = origin == crate::incarnation::DispatchOrigin::Operator;
        if target == self.config.node_id
            && expected_pin.is_some_and(|pin| pin != self.certificate_sha256)
        {
            return Err("expected local node incarnation has changed".into());
        }
        // Preserve the operator's existing local administration semantics. Internal
        // dispatches below always establish their immutable route and origin first.
        if target == self.config.node_id && local_operator {
            return Ok(self
                .dispatch(
                    op,
                    payload,
                    Caller {
                        node_id: self.config.node_id.clone(),
                        local_operator: true,
                        certificate_sha256: Some(self.certificate_sha256.clone()),
                    },
                    sender_policy,
                )
                .await);
        }
        if !wire::valid_name(target) {
            return Err("invalid target node".into());
        }
        let previously_submitted = if op == Operation::JobSubmit {
            let id = payload
                .get("id")
                .and_then(Value::as_str)
                .ok_or("job ID is required")?;
            crate::incarnation::has_binding(&self.config, id)?
        } else {
            false
        };
        if op == Operation::JobSubmit
            && !previously_submitted
            && self.operator_draining.load(Ordering::SeqCst)
        {
            return Err("node is draining; new dispatches are disabled".into());
        }
        let target_pin = crate::incarnation::target_pin_bound(
            &self.config,
            target,
            op,
            &payload,
            expected_pin,
            &origin,
        )
        .await?;
        if previously_submitted {
            // The sticky spec/target binding was verified above. Reconciliation must
            // not publish a fresh prompt copy or renew the original delivery window.
            let id = payload
                .get("id")
                .and_then(Value::as_str)
                .ok_or("job ID is required")?;
            let status = if target == self.config.node_id {
                Ok(self
                    .dispatch(
                        Operation::JobStatus,
                        json!({"job_id":id}),
                        Caller {
                            node_id: self.config.node_id.clone(),
                            local_operator: false,
                            certificate_sha256: Some(self.certificate_sha256.clone()),
                        },
                        None,
                    )
                    .await)
            } else {
                self.rpc_once(
                    target,
                    Operation::JobStatus,
                    json!({"job_id":id}),
                    None,
                    target_pin.clone(),
                )
                .await
            };
            return match status {
                Ok(reply) if reply.ok => {
                    let same_owner = reply.result.as_ref().is_some_and(|record|
                        record.get("submitter").and_then(Value::as_str) == Some(self.config.node_id.as_str())
                        && record.get("submitter_certificate_sha256").and_then(Value::as_str) == Some(self.certificate_sha256.as_str()));
                    if same_owner { Ok(reply) } else { Ok(RpcReply::failure("submission_incarnation_changed",
                        "The original job belongs to another source incarnation; use read-only reconciliation.")) }
                }
                Ok(reply) if reply.error.as_ref().is_some_and(|error| error.code == "job_content_expired") => Ok(reply),
                _ => Err("submission was already attempted; outcome is uncertain, reconcile the original job ID without renewing its prompt".into()),
            };
        }
        if target == self.config.node_id {
            if op == Operation::JobSubmit {
                let spec: JobSpec = serde_json::from_value(payload)?;
                let policy = sender_policy.ok_or("project retention required")?;
                let executor = self.executor.clone().ok_or("local executor unavailable")?;
                let config = self.config.clone();
                let caller = Caller {
                    node_id: self.config.node_id.clone(),
                    local_operator: false,
                    certificate_sha256: Some(self.certificate_sha256.clone()),
                };
                // The durable local claim and admission share a blocking closure and
                // per-job lock, even if the awaiting RPC future is cancelled.
                let outcome = tokio::task::spawn_blocking(move || {
                    crate::incarnation::local_submit(&config, &spec, || {
                        executor
                            .submit_with_retention(spec.clone(), &caller, Some(&policy))
                            .map_err(|error| error.0)
                    })
                })
                .await
                .map_err(|_| "local admission worker failed")??;
                return Ok(match outcome {
                    Ok(record) => RpcReply::success(serde_json::to_value(record)?),
                    Err(code) => RpcReply::failure(code, "Node operation failed."),
                });
            }
            return Ok(self
                .dispatch(
                    op,
                    payload,
                    Caller {
                        node_id: self.config.node_id.clone(),
                        local_operator: false,
                        certificate_sha256: Some(self.certificate_sha256.clone()),
                    },
                    sender_policy,
                )
                .await);
        }
        self.rpc_once(target, op, payload, sender_policy, target_pin)
            .await
    }
    async fn rpc_once(
        &self,
        target: &str,
        op: Operation,
        payload: Value,
        sender_policy: Option<crate::retention::RetentionPolicy>,
        target_pin: Option<String>,
    ) -> Result<RpcReply<Value>> {
        let peer = self.config.peers.iter().find(|p| p.node_id == target);
        if self.known_revoked_direct_target(
            target_pin
                .as_deref()
                .or_else(|| peer.map(|peer| peer.certificate_sha256.as_str())),
        ) {
            return Ok(RpcReply::failure(
                "revoked",
                "Access to this identity has been revoked.",
            ));
        }
        let payload = self.announce_direct_capabilities(op, payload);
        let mut frame = RpcFrame {
            v: wire::PROTOCOL_VERSION,
            kind: FrameKind::Request,
            id: wire::new_id()?,
            source: self.config.node_id.clone(),
            target: target.into(),
            operation: op,
            in_reply_to: None,
            source_certificate_sha256: target_pin.as_ref().map(|_| self.certificate_sha256.clone()),
            target_certificate_sha256: target_pin,
            retention: None,
            payload: String::new(),
        };
        if let Some(policy) = sender_policy {
            frame.retention = Some(crate::retention::ContentRetention::for_copy(
                &policy,
                crate::retention::id_timestamp_ms(&frame.id)?,
                None,
            )?);
        }
        self.codec.encode(&mut frame, &payload)?;
        if op == Operation::JobSubmit {
            let config = self.config.clone();
            let target = target.to_owned();
            let original = frame.clone();
            let original_payload = payload.clone();
            tokio::task::spawn_blocking(move || {
                crate::incarnation::note_delivery_deadline(
                    &config,
                    &target,
                    &original,
                    &original_payload,
                )
            })
            .await
            .map_err(|_| "original dispatch deadline publication failed")??;
        }
        let timeout = Duration::from_secs(self.config.rpc_timeout_seconds);
        if let (Some(direct), Some(peer)) = (&self.direct, peer)
            && let Some(address) = peer.address
            && let Ok(Ok(connection)) = tokio::time::timeout(
                timeout,
                direct.connect(address, &peer.tls_name, peer.policy()),
            )
            .await
        {
            // Once sent, a failure is uncertain. Relay may retry the exact same encrypted frame.
            match tokio::time::timeout(timeout, self.direct_rpc(&connection, &frame)).await {
                Ok(Ok(reply)) => return Ok(reply),
                Ok(Err(error)) if error.to_string() == "revoked" => {
                    // A peer's authenticated close stops this attempt, without treating its
                    // unsigned reason as a durable local deny-list update.
                    if let Some(state) = &self.revocations {
                        state.wake();
                    }
                    return Ok(RpcReply::failure(
                        "revoked",
                        "Access to this identity has been revoked.",
                    ));
                }
                _ => {}
            }
            if self.known_revoked_direct_target(Some(&peer.certificate_sha256)) {
                return Ok(RpcReply::failure(
                    "revoked",
                    "Access to this identity has been revoked.",
                ));
            }
        }
        // A verified revoke may arrive while connect fails or times out. Recheck on every
        // fallthrough, including failed handshakes, before selecting any relay route.
        if self.known_revoked_direct_target(
            frame
                .target_certificate_sha256
                .as_deref()
                .or_else(|| peer.map(|peer| peer.certificate_sha256.as_str())),
        ) {
            return Ok(RpcReply::failure(
                "revoked",
                "Access to this identity has been revoked.",
            ));
        }
        let relay = self
            .relay
            .as_ref()
            .ok_or("transport failed; execution outcome may be unknown")?;
        let history_slot = if is_write(op) {
            Some(
                self.write_history
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| "write correlation history capacity reached")?,
            )
        } else {
            None
        };
        self.clock.lock().await.observe(&self.config.state_dir)?;
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if pending.len() >= 128 {
                return Err("too many pending requests".into());
            }
            pending.insert(frame.id.clone(), PendingResponse { tx });
        }
        let _registration = PendingRegistration {
            pending: &self.pending,
            id: frame.id.clone(),
        };
        let saved = {
            let mut budget = self.cache_lock.lock().await;
            let dir = bucket_dir(&self.config.state_dir, "relay-requests", frame.operation);
            if ensure_capacity(&dir, frame.operation, false).is_err() {
                Err("relay request capacity reached".into())
            } else {
                budget.store(
                    &dir,
                    &frame.id,
                    &Cached {
                        request_hash: String::new(),
                        response: frame.clone(),
                        content_erased: None,
                    },
                    frame_deadline(&frame),
                )
            }
        };
        if saved.is_err() {
            if bucket_dir(&self.config.state_dir, "relay-requests", frame.operation)
                .join(&frame.id)
                .exists()
                && let Some(slot) = history_slot
            {
                slot.forget();
            }
            return Err("cannot persist relay request".into());
        }
        if let Some(slot) = history_slot {
            slot.forget();
        }
        if relay
            .send(&RelayMessage::Frame(frame.clone()))
            .await
            .is_err()
        {
            return Err("relay write failed; execution outcome may be unknown".into());
        }
        let result = tokio::time::timeout(timeout, rx).await;
        let response = result
            .map_err(|_| "response timeout; execution outcome may be unknown")?
            .map_err(|_| "relay stopped; execution outcome may be unknown")??;
        self.decode_response(&frame, &response)
    }
    fn decode_response(&self, request: &RpcFrame, response: &RpcFrame) -> Result<RpcReply<Value>> {
        if response.kind != FrameKind::Response
            || response.v != request.v
            || response.source != request.target
            || response.target != request.source
            || response.operation != request.operation
            || response.in_reply_to.as_deref() != Some(&request.id)
            || response.source_certificate_sha256 != request.target_certificate_sha256
            || response.target_certificate_sha256 != request.source_certificate_sha256
        {
            return Err("response routing mismatch".into());
        }
        if response
            .retention
            .as_ref()
            .is_some_and(|retention| wall_ms().map_or(true, |now| now >= retention.expires_at_ms))
        {
            return Err("response content retention expired".into());
        }
        let reply: RpcReply<Value> = self
            .codec
            .decode(response)
            .map_err(|_| "response authentication failed")?;
        if !matches!(
            request.operation,
            Operation::NodePing | Operation::RevocationsApply
        ) && reply.ok
            && response.retention.is_none()
        {
            return Err("successful response requires content retention".into());
        }
        Ok(reply)
    }
}

async fn maintain_content_cache(host: &Host) -> Result<()> {
    let now = host.clock.lock().await.observe(&host.config.state_dir)?;
    loop {
        let due = {
            let mut budget = host.cache_lock.lock().await;
            let Some((deadline, bucket, id)) = budget.content_deadlines.first().cloned() else {
                break;
            };
            if deadline > now {
                break;
            }
            budget.forget(&bucket, &id);
            (deadline, bucket, id)
        };
        let (_, bucket, id) = &due;
        let dir = host.config.state_dir.join(bucket);
        let path = dir.join(id);
        let result: Result<()> = async {
            if !path.exists() {
                return Ok(());
            }
            if bucket.starts_with("relay-requests-") {
                let cached: Cached =
                    serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 2) as u64)?)?;
                if frame_deadline(&cached.response).is_some_and(|deadline| now >= deadline) {
                    receive_failure(host, id, "content_expired").await?;
                    if let Some(pending) = host
                        .pending
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .remove(id)
                    {
                        let _ = pending.tx.send(Err("content_expired"));
                    }
                }
                return Ok(());
            }
            let mut budget = host.cache_lock.lock().await;
            if !path.exists() {
                return Ok(());
            }
            if bucket.starts_with("responses-") {
                let mut cached: Cached =
                    serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 2) as u64)?)?;
                if cached.content_erased.is_none()
                    && frame_deadline(&cached.response).is_some_and(|deadline| now >= deadline)
                {
                    erase_cached_content(host, &mut budget, &dir, id, &mut cached)?;
                }
            } else if bucket.starts_with("relay-inbox-") {
                let receipt: Receipt =
                    serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 3) as u64)?)?;
                if receipt_deadline(&receipt).is_some_and(|deadline| now >= deadline) {
                    if is_write(receipt.request.operation) {
                        archive_write_receipt(&dir, &path, &mut budget.completed_writes)?;
                    }
                    fs::remove_file(&path)?;
                    lockyard_core::fsio::sync_path(&dir)?;
                    let pending_dir = bucket_dir(
                        &host.config.state_dir,
                        "relay-requests",
                        receipt.request.operation,
                    );
                    if fs::remove_file(pending_dir.join(id)).is_ok() {
                        lockyard_core::fsio::sync_path(&pending_dir)?;
                        budget.forget(
                            pending_dir
                                .file_name()
                                .and_then(|value| value.to_str())
                                .ok_or("invalid pending directory")?,
                            id,
                        );
                    }
                }
            } else if bucket == "relay-outbox" {
                let entry: OutboxEntry =
                    serde_json::from_slice(&read_private(&path, OUTBOX_RECORD_MAX)?)?;
                if entry
                    .response
                    .as_ref()
                    .and_then(frame_deadline)
                    .is_some_and(|deadline| now >= deadline)
                {
                    let cache_dir =
                        bucket_dir(&host.config.state_dir, "responses", entry.operation);
                    let cache_path = cache_dir.join(id);
                    if cache_path.exists() {
                        let mut cached: Cached = serde_json::from_slice(&read_private(
                            &cache_path,
                            (MAX_FRAME_BYTES * 2) as u64,
                        )?)?;
                        erase_cached_content(host, &mut budget, &cache_dir, id, &mut cached)?;
                    } else if is_write(entry.operation) {
                        return Err(
                            "write response cache unavailable for retention reconciliation".into(),
                        );
                    } else {
                        fs::remove_file(&path)?;
                        lockyard_core::fsio::sync_path(&dir)?;
                        budget.forget("relay-outbox", id);
                        host.relay_slots.add_permits(1);
                    }
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            host.cache_lock.lock().await.track(bucket, id, Some(due.0));
            return Err(error);
        }
        tokio::task::yield_now().await;
    }
    Ok(())
}

async fn read_packet(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>> {
    let mut prefix = [0; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut prefix)).await??;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_BYTES {
        return Err("control message too large".into());
    }
    let mut bytes = vec![0; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut bytes)).await??;
    Ok(bytes)
}
async fn write_packet(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err("control message too large".into());
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(bytes).await?;
        #[cfg(windows)]
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await??;
    Ok(())
}
#[derive(Serialize, Deserialize)]
struct ControlReply {
    value: Option<Value>,
    error: Option<String>,
}
fn local_dispatch_stopped(
    config: &NodeConfig,
    executor: Option<&Executor>,
    id: &str,
) -> Result<()> {
    if !wire::valid_ulid(id) {
        return Err("invalid local dispatch ID".into());
    }
    let executor = executor.ok_or("local dispatch review requires an executor")?;
    let state = executor.status(id);
    match &state {
        Ok(record) if !record.state.is_terminal() => {
            return Err("local execution remains queued, active or unknown".into());
        }
        Err(error) if !matches!(error.0, "job_not_found" | "job_content_expired") => {
            return Err("local execution state unavailable".into());
        }
        _ => (),
    }
    let state_dir = &config
        .executor
        .as_ref()
        .ok_or("local executor configuration unavailable")?
        .state_dir;
    if executor.tombstone(id)?.is_some() {
        let tombstones = state_dir.join("job-tombstones");
        lockyard_core::fsio::sync_path(tombstones.join(id))?;
        lockyard_core::fsio::sync_path(tombstones)?;
        return Ok(());
    }
    let jobs = state_dir.join("jobs");
    let directory = jobs.join(id);
    match state {
        Err(error) if error.0 == "job_not_found" => match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                lockyard_core::fsio::sync_path(jobs)?;
                Ok(())
            }
            _ => Err("local job directory requires durable reconciliation".into()),
        },
        _ => {
            // Executor updates can fail after mutating memory, and a failed
            // admission can publish a Queued record before returning an error.
            // Check what restart would actually recover, not only RAM state.
            let bytes = read_private(&directory.join("record.json"), 8 * 1024 * 1024)?;
            let record: wire::JobRecord =
                serde_json::from_slice(&bytes).map_err(|_| "invalid local job journal")?;
            if record.spec.id != id || !record.state.is_terminal() {
                return Err("durable local job remains queued, active or unknown".into());
            }
            lockyard_core::fsio::sync_path(directory.join("record.json"))?;
            lockyard_core::fsio::sync_path(directory)?;
            Ok(())
        }
    }
}

async fn control_connection(host: Arc<Host>, mut stream: UnixStream) -> Result<()> {
    #[cfg(unix)]
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Err("control peer denied".into());
    }
    let request: Control =
        serde_json::from_slice(&read_packet(&mut stream, Duration::from_secs(30)).await?)
            .map_err(|_| "invalid control request")?;
    let result: Result<Value> = match request {
        Control::Status => Ok(serde_json::to_value(host.status())?),
        Control::Revocations { documents } => host.propagate_revocations(documents).await,
        Control::DrainStatus => host.drain_status_value(),
        Control::Dispatch {
            expected_local_certificate_sha256,
            request,
        } => {
            if expected_local_certificate_sha256 != host.certificate_sha256 {
                return Err(
                    "outbound operator review belongs to another local node incarnation".into(),
                );
            }
            let config = host.config.clone();
            let source_pin = host.certificate_sha256.clone();
            let executor = host.executor.clone();
            tokio::task::spawn_blocking(move || {
                crate::incarnation::dispatch_control_with_local(
                    &config,
                    &source_pin,
                    request,
                    wall_ms()?,
                    Some(&|id| local_dispatch_stopped(&config, executor.as_ref(), id)),
                )
            })
            .await
            .map_err(|_| "outbound operator review failed")?
        }
        Control::Workflow { request } => {
            let controller = host
                .workflow
                .as_ref()
                .ok_or("workflow_controller_disabled")?;
            use crate::workflow::WorkflowControl;
            match request {
                WorkflowControl::Submit { definition } => Ok(serde_json::to_value(
                    controller.submit(definition, wall_ms()?)?,
                )?),
                WorkflowControl::Status { id } => {
                    Ok(serde_json::to_value(controller.status(&id)?)?)
                }
                WorkflowControl::List { offset, limit } => {
                    controller.list_page(offset, limit).map_err(Into::into)
                }
                WorkflowControl::Cancel { id } => {
                    Ok(serde_json::to_value(controller.cancel(&id, wall_ms()?)?)?)
                }
                WorkflowControl::ApprovalRequest { id, step } => Ok(serde_json::to_value(
                    controller.approval_request(&id, &step)?,
                )?),
                WorkflowControl::ApprovalAttach {
                    id,
                    step,
                    definition_sha256,
                    approval,
                } => Ok(serde_json::to_value(controller.approval_attach(
                    &id,
                    &step,
                    &definition_sha256,
                    approval,
                    wall_ms()?,
                )?)?),
                WorkflowControl::Abandon { review } => {
                    if review.expected_local_certificate_sha256 != host.certificate_sha256 {
                        return Err(
                            "workflow abandonment belongs to another local node incarnation".into(),
                        );
                    }
                    let config = host.config.clone();
                    let executor = host.executor.clone();
                    let summary=controller.abandon(review,wall_ms()?,move |summary|Box::pin(async move {
                        tokio::task::spawn_blocking(move ||->crate::workflow::Result<()> {
                            for step in &summary.steps {
                                let (Some(target),Some(pin),Some(spec_hash))=(&step.node_id,&step.certificate_sha256,&step.spec_sha256) else {continue;};
                                if target==&config.node_id {
                                    let executor=executor.as_ref().ok_or(crate::workflow::WorkflowError("workflow_abandon_local_executor_unavailable"))?;
                                    match executor.status(&step.job_id) {
                                        Ok(record) if record.state.is_terminal()=>{},
                                        Err(error) if matches!(error.0,"job_not_found"|"job_content_expired")=>{},
                                        _=>return Err(crate::workflow::WorkflowError("workflow_abandon_requires_stopped_and_reconciled_local_execution")),
                                    }
                                }
                                crate::incarnation::require_abandonable_dispatch(&config,&summary.id,&step.job_id,target,pin,spec_hash)
                                    .map_err(|_|crate::workflow::WorkflowError("workflow_abandon_requires_separate_outbound_completion_or_expired_delivery_review"))?;
                            }
                            Ok(())
                        }).await.map_err(|_|crate::workflow::WorkflowError("workflow_abandon_review_failed"))?
                    })).await?;
                    Ok(serde_json::to_value(summary)?)
                }
            }
        }
        Control::Drain { enabled } => {
            store_data(
                &host.config.state_dir,
                "operator-drain",
                if enabled { b"1" } else { b"0" },
            )?;
            host.operator_draining.store(enabled, Ordering::SeqCst);
            if let Some(controller) = &host.workflow {
                if enabled {
                    controller.begin_drain();
                } else {
                    controller.resume_dispatch();
                }
            }
            if let Some(executor) = host.executor.as_ref() {
                executor.set_draining(
                    enabled,
                    &Caller {
                        node_id: host.config.node_id.clone(),
                        local_operator: true,
                        certificate_sha256: Some(host.certificate_sha256.clone()),
                    },
                )?;
            }
            host.drain_status_value()
        }
        Control::Rpc {
            target,
            operation,
            payload,
        } => host
            .rpc(&target, operation, payload)
            .await
            .and_then(|reply| Ok(serde_json::to_value(reply)?)),
    };
    let response = match result {
        Ok(value) => ControlReply {
            value: Some(value),
            error: None,
        },
        Err(_) => ControlReply {
            value: None,
            error: Some("node RPC failed; execution outcome may be unknown".into()),
        },
    };
    write_packet(&mut stream, &serde_json::to_vec(&response)?).await
}
async fn call_control(path: &Path, request: Control, timeout: Duration) -> Result<Value> {
    let task = async {
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(|_| "node control socket unavailable")?;
        #[cfg(unix)]
        if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
            return Err("control host denied".into());
        }
        write_packet(&mut stream, &serde_json::to_vec(&request)?).await?;
        let response: ControlReply =
            serde_json::from_slice(&read_packet(&mut stream, timeout).await?)
                .map_err(|_| "invalid control response")?;
        match (response.value, response.error) {
            (Some(value), None) => Ok(value),
            _ => Err("node RPC failed; execution outcome may be unknown".into()),
        }
    };
    tokio::time::timeout(timeout, task)
        .await
        .map_err(|_| "control timeout; execution outcome may be unknown")?
}
/// Explicit local operator maintenance. No remote calls are made by a review.
pub async fn local_dispatch(
    config_path: &Path,
    request: crate::incarnation::DispatchControl,
) -> Result<Value> {
    let config = NodeConfig::load(config_path)?;
    if config.delegation_socket.is_some() {
        return Err("workload clients cannot review outbound execution".into());
    }
    let certificate = crate::local_files::read_public(&config.certificate, 64 * 1024)?;
    if certificate.is_empty() || certificate.len() > 64 * 1024 {
        return Err("invalid local certificate".into());
    }
    call_control(
        &config.socket_path(),
        Control::Dispatch {
            expected_local_certificate_sha256: PeerPin::certificate(&certificate).to_hex(),
            request,
        },
        Duration::from_secs(30),
    )
    .await
}
/// Applies signed closure pages through the private daemon control channel.
pub async fn local_revocations(
    config_path: &Path,
    documents: Vec<crate::revocations::SignedDocument>,
) -> Result<Value> {
    let config = NodeConfig::load(config_path)?;
    call_control(
        &config.socket_path(),
        Control::Revocations { documents },
        Duration::from_secs(config.rpc_timeout_seconds),
    )
    .await
}
/// Controls the local persistent DAG controller. Delegation sockets reject this protocol.
pub async fn local_workflow(
    config_path: &Path,
    mut request: crate::workflow::WorkflowControl,
) -> Result<Value> {
    let config = NodeConfig::load(config_path)?;
    if let crate::workflow::WorkflowControl::Abandon { review } = &mut request {
        if config.delegation_socket.is_some() {
            return Err("workload clients cannot abandon workflows".into());
        }
        let certificate = crate::local_files::read_public(&config.certificate, 64 * 1024)?;
        review.expected_local_certificate_sha256 = PeerPin::certificate(&certificate).to_hex();
    }
    call_control(
        &config.socket_path(),
        Control::Workflow { request },
        Duration::from_secs(30),
    )
    .await
}
/// Dispatches through the running node's private socket, reusing its connections.
pub async fn local_rpc(
    config_path: &Path,
    target: &str,
    operation: Operation,
    payload: Value,
) -> Result<RpcReply<Value>> {
    let config = NodeConfig::load(config_path)?;
    let value = call_control(
        &config.socket_path(),
        Control::Rpc {
            target: target.to_string(),
            operation,
            payload,
        },
        Duration::from_secs(
            config
                .rpc_timeout_seconds
                .saturating_mul(3)
                .saturating_add(30),
        ),
    )
    .await?;
    serde_json::from_value(value).map_err(|_| "invalid control response".into())
}
pub async fn drain(config_path: &Path, enabled: Option<bool>) -> Result<Value> {
    let config = NodeConfig::load(config_path)?;
    call_control(
        &config.socket_path(),
        enabled.map_or(Control::DrainStatus, |enabled| Control::Drain { enabled }),
        Duration::from_secs(10),
    )
    .await
}
pub async fn status(config_path: &Path) -> Result<NodeStatus> {
    let config = NodeConfig::load(config_path)?;
    let value = call_control(
        &config.socket_path(),
        Control::Status,
        Duration::from_secs(10),
    )
    .await?;
    serde_json::from_value(value).map_err(|_| "invalid control response".into())
}
async fn direct_connection(host: Arc<Host>, connection: quic::DirectConnection) {
    loop {
        let stream = match connection.accept().await {
            Ok(stream) => stream,
            Err(_) => break,
        };
        let permit = match host.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let host = host.clone();
        let connection = connection.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut stream = stream;
            if let Ok(frame) = stream.recv().await {
                let response = match host.direct_frame_gate(&connection, &frame) {
                    Ok(Some(response)) => Ok(response),
                    Ok(None) => host.handle(frame, false).await,
                    Err(error) => Err(error),
                };
                if let Ok(response) = response {
                    let _ = stream.send(&response).await;
                    let _ = stream.finish();
                }
            }
        });
    }
}
// Reserve one worst-case frame before dispatch; each persisted entry is bounded to
// OUTBOX_RECORD_MAX and slots are recovered only after broker acceptance.
async fn reserve_response(host: &Host, request: &RpcFrame) -> Result<()> {
    let dir = host.config.state_dir.join("relay-outbox");
    let hash = request_hash(request)?;
    loop {
        {
            let _guard = host.cache_lock.lock().await;
            let path = dir.join(&request.id);
            if path.exists() {
                let entry: OutboxEntry =
                    serde_json::from_slice(&read_private(&path, OUTBOX_RECORD_MAX)?)?;
                if entry.request_id != request.id
                    || entry.request_hash != hash
                    || entry.operation != request.operation
                    || entry.source != request.source
                {
                    return Err("request identifier conflict".into());
                }
                return Ok(());
            }
        }
        let permit = host.relay_slots.acquire().await?;
        let _guard = host.cache_lock.lock().await;
        let path = dir.join(&request.id);
        if path.exists() {
            drop(permit);
            continue;
        }
        let entry = OutboxEntry {
            request_id: request.id.clone(),
            request_hash: hash.clone(),
            operation: request.operation,
            source: request.source.clone(),
            response: None,
            accepted: false,
        };
        store_data(&dir, &request.id, &serde_json::to_vec(&entry)?)?;
        permit.forget();
        return Ok(());
    }
}
async fn relay_request(host: Arc<Host>, sender: RelaySender, request: RpcFrame) {
    // Reject invalid envelopes before consuming a bounded durable reservation.
    if host.codec.decode::<Value>(&request).is_err()
        || request.target != host.config.node_id
        || request
            .target_certificate_sha256
            .as_deref()
            .is_some_and(|pin| pin != host.certificate_sha256)
        || (request.operation != Operation::NodePing && request.target_certificate_sha256.is_none())
        || (request.operation == Operation::JobSubmit && request.retention.is_none())
        || request
            .retention
            .as_ref()
            .is_some_and(|retention| wall_ms().map_or(true, |now| now >= retention.expires_at_ms))
    {
        // Broker-authenticated routing has already bound this exact incoming request.
        // Discarding an undecryptable frame cannot dispatch work or affect pending replies.
        host.invalid_requests.fetch_add(1, Ordering::Relaxed);
        if sender
            .send(&RelayMessage::Control(RelayControl::Ack {
                v: 1,
                id: request.id,
            }))
            .await
            .is_err()
        {
            sender.request_reconnect();
        }
        return;
    }
    if reserve_response(&host, &request).await.is_err() {
        sender.request_reconnect();
        return;
    }
    let request_id = request.id.clone();
    let response = match host.handle(request, true).await {
        Ok(response) => response,
        Err(_) => {
            let _ = release_empty_reservation(&host, &request_id).await;
            sender.request_reconnect();
            return;
        }
    };
    {
        let saved = {
            let mut budget = host.cache_lock.lock().await;
            let dir = host.config.state_dir.join("relay-outbox");
            let path = dir.join(&request_id);
            match read_private(&path, OUTBOX_RECORD_MAX)
                .and_then(|bytes| Ok(serde_json::from_slice::<OutboxEntry>(&bytes)?))
            {
                Ok(mut entry)
                    if entry
                        .response
                        .as_ref()
                        .is_none_or(|prior| *prior == response) =>
                {
                    entry.response = Some(response.clone());
                    match serde_json::to_vec(&entry) {
                        Ok(bytes) if bytes.len() as u64 <= OUTBOX_RECORD_MAX => budget
                            .store(&dir, &request_id, &entry, frame_deadline(&response))
                            .is_ok(),
                        _ => false,
                    }
                }
                _ => false,
            }
        };
        if saved {
            let _ = sender.send(&RelayMessage::Frame(response)).await;
        } else {
            let _ = release_empty_reservation(&host, &request_id).await;
            sender.request_reconnect();
        }
    }
}
fn tombstone_reservation(state: &Path, record: &OutboxEntry, now: Option<u64>) -> Result<()> {
    let dir = bucket_dir(state, "request-tombstones", record.operation);
    let path = dir.join(&record.request_id);
    if path.exists() {
        let old: RequestTombstone = serde_json::from_slice(&read_private(&path, 512)?)?;
        if old.request_hash != record.request_hash || old.operation != record.operation {
            return Err("request tombstone conflict".into());
        }
    } else {
        let limit = if is_write(record.operation) {
            100_000
        } else {
            1_000_000
        };
        if fs::read_dir(&dir)?.take(limit).count() >= limit {
            if !is_write(record.operation)
                && let Some(now) = now
            {
                for entry in fs::read_dir(&dir)?.flatten() {
                    let id = entry.file_name();
                    let id = id.to_string_lossy();
                    if ulid_time_ms(&id)
                        .is_ok_and(|created| now >= created.saturating_add(REQUEST_TTL_MS))
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
                lockyard_core::fsio::sync_path(&dir)?;
            }
            if fs::read_dir(&dir)?.take(limit).count() >= limit {
                return Err("request tombstone capacity reached".into());
            }
        }
        store_data(
            &dir,
            &record.request_id,
            &serde_json::to_vec(&RequestTombstone {
                request_hash: record.request_hash.clone(),
                operation: record.operation,
            })?,
        )?;
    }
    Ok(())
}
// If this frame collided with an earlier durable ID, that existing binding is
// sufficient; never overwrite it with a conflicting orphan tombstone.
fn preserve_orphan_binding(state: &Path, record: &OutboxEntry, now: Option<u64>) -> Result<()> {
    for bucket in ["read", "write"] {
        let path = state
            .join(format!("request-tombstones-{bucket}"))
            .join(&record.request_id);
        if path.exists() {
            let old: RequestTombstone = serde_json::from_slice(&read_private(&path, 512)?)?;
            if old.request_hash != record.request_hash || old.operation != record.operation {
                return Ok(());
            }
        }
        let path = state
            .join(format!("responses-{bucket}"))
            .join(&record.request_id);
        if path.exists() {
            let old: Cached =
                serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 2) as u64)?)?;
            if old.request_hash != record.request_hash {
                return Ok(());
            }
        }
    }
    let path = state.join("read-tombstones").join(&record.request_id);
    if path.exists() && read_private(&path, 128)? != record.request_hash.as_bytes() {
        return Ok(());
    }
    tombstone_reservation(state, record, now)
}
async fn release_empty_reservation(host: &Host, id: &str) -> Result<()> {
    let now = host.clock.lock().await.observe(&host.config.state_dir).ok();
    let mut budget = host.cache_lock.lock().await;
    let dir = host.config.state_dir.join("relay-outbox");
    let path = dir.join(id);
    if !path.exists() {
        return Ok(());
    }
    let record: OutboxEntry = serde_json::from_slice(&read_private(&path, OUTBOX_RECORD_MAX)?)?;
    if record.response.is_some() || record.request_id != id {
        return Ok(());
    }
    preserve_orphan_binding(&host.config.state_dir, &record, now)?;
    fs::remove_file(path)?;
    lockyard_core::fsio::sync_path(dir)?;
    budget.forget("relay-outbox", id);
    host.relay_slots.add_permits(1);
    Ok(())
}
// No handler survives a daemon restart. Preserve the request hash before releasing
// an empty reservation; job journal/cache recovery remains the execution authority.
fn recover_empty_reservations(state: &Path, now: u64) -> Result<()> {
    let dir = state.join("relay-outbox");
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid relay outbox")?;
        if !wire::valid_ulid(&id) {
            return Err("invalid relay outbox".into());
        }
        let record: OutboxEntry =
            serde_json::from_slice(&read_private(&entry.path(), OUTBOX_RECORD_MAX)?)?;
        if record.request_id != id {
            return Err("invalid relay outbox".into());
        }
        if record.response.is_none() {
            if record.accepted {
                return Err("invalid relay outbox".into());
            }
            preserve_orphan_binding(state, &record, Some(now))?;
            fs::remove_file(entry.path())?;
        }
    }
    lockyard_core::fsio::sync_path(dir)?;
    Ok(())
}
// Only a broker ACK for the exact response transitions its reservation to accepted.
async fn accept_response(host: &Host, response_id: &str) -> Result<Option<String>> {
    let _guard = host.cache_lock.lock().await;
    let dir = host.config.state_dir.join("relay-outbox");
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid outbox name")?;
        if !wire::valid_ulid(&name) {
            continue;
        }
        let mut record: OutboxEntry =
            serde_json::from_slice(&read_private(&entry.path(), OUTBOX_RECORD_MAX)?)?;
        if record
            .response
            .as_ref()
            .is_some_and(|frame| frame.id == response_id)
        {
            record.accepted = true;
            store_data(&dir, &name, &serde_json::to_vec(&record)?)?;
            return Ok(Some(record.request_id));
        }
    }
    Ok(None)
}
async fn acknowledge_accepted(host: &Host, sender: &RelaySender, request_id: &str) -> Result<()> {
    sender
        .send(&RelayMessage::Control(RelayControl::Ack {
            v: 1,
            id: request_id.to_string(),
        }))
        .await?;
    let mut budget = host.cache_lock.lock().await;
    let dir = host.config.state_dir.join("relay-outbox");
    let path = dir.join(request_id);
    if path.exists() {
        let entry: OutboxEntry = serde_json::from_slice(&read_private(&path, OUTBOX_RECORD_MAX)?)?;
        if entry.accepted && entry.request_id == request_id {
            fs::remove_file(path)?;
            lockyard_core::fsio::sync_path(dir)?;
            budget.forget("relay-outbox", request_id);
            host.relay_slots.add_permits(1);
        }
    }
    Ok(())
}
// A permanently unroutable response remains an unknown delivery outcome. Preserve
// its metadata and, for mutating operations, the exact durable response cache.
async fn retire_outbox_response(
    host: &Host,
    response_id: &str,
    reason: &'static str,
) -> Result<bool> {
    let mut budget = host.cache_lock.lock().await;
    let dir = host.config.state_dir.join("relay-outbox");
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid relay outbox")?;
        if !wire::valid_ulid(&id) {
            continue;
        }
        let record: OutboxEntry =
            serde_json::from_slice(&read_private(&entry.path(), OUTBOX_RECORD_MAX)?)?;
        let Some(response) = record.response.as_ref() else {
            continue;
        };
        if response.id != response_id || record.accepted {
            continue;
        }
        if is_write(record.operation) {
            let path = bucket_dir(&host.config.state_dir, "responses", record.operation).join(&id);
            let cached: Cached =
                serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 2) as u64)?)?;
            if cached.request_hash != record.request_hash || cached.response != *response {
                return Err("durable response cache mismatch".into());
            }
        }
        let outcomes = bucket_dir(
            &host.config.state_dir,
            "relay-undeliverable",
            record.operation,
        );
        let path = outcomes.join(&id);
        let hash = request_hash(response)?;
        if path.exists() {
            let old: Undeliverable = serde_json::from_slice(&read_private(&path, 4096)?)?;
            if old.response_id != response_id || old.response_hash != hash {
                return Err("relay outcome conflict".into());
            }
        } else {
            if fs::read_dir(&outcomes)?.take(100_000).count() >= 100_000 {
                // Read-only results can be recomputed; retain at least the broker's 8-day window.
                if !is_write(record.operation) {
                    for entry in fs::read_dir(&outcomes)?.flatten() {
                        if entry
                            .metadata()
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .is_some_and(|age| age >= Duration::from_secs(8 * 24 * 60 * 60))
                        {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                    lockyard_core::fsio::sync_path(&outcomes)?;
                }
                if fs::read_dir(&outcomes)?.take(100_000).count() >= 100_000 {
                    return Err("relay outcome capacity reached".into());
                }
            }
            store_data(
                &outcomes,
                &id,
                &serde_json::to_vec(&Undeliverable {
                    request_id: id.clone(),
                    response_id: response_id.into(),
                    operation: record.operation,
                    response_hash: hash,
                    reason: reason.into(),
                })?,
            )?;
        }
        fs::remove_file(entry.path())?;
        lockyard_core::fsio::sync_path(dir)?;
        budget.forget("relay-outbox", &id);
        host.relay_slots.add_permits(1);
        return Ok(true);
    }
    Ok(false)
}
async fn replay_cached(host: &Host, sender: &RelaySender) {
    let now = host.clock.lock().await.observe(&host.config.state_dir).ok();
    let Ok(entries) = fs::read_dir(host.config.state_dir.join("relay-outbox")) else {
        return;
    };
    // The number and size of entries are bounded before dispatch. Visit every entry.
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !wire::valid_ulid(&name) {
            continue;
        }
        let Ok(bytes) = read_private(&entry.path(), OUTBOX_RECORD_MAX) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<OutboxEntry>(&bytes) else {
            continue;
        };
        if record.request_id != name {
            continue;
        }
        if record.accepted {
            let _ = acknowledge_accepted(host, sender, &record.request_id).await;
            continue;
        }
        if let (Some(now), Some(response)) = (now, record.response.as_ref())
            && ulid_time_ms(&record.request_id).is_ok_and(|created| {
                now >= created
                    .saturating_add(REQUEST_TTL_MS)
                    .saturating_add(7 * 24 * 60 * 60 * 1000)
            })
        {
            let _ = retire_outbox_response(host, &response.id, "correlation_expired").await;
            continue;
        }
        let Some(response) = record.response else {
            continue;
        };
        if response.source != host.config.node_id
            || response.in_reply_to.as_deref() != Some(&name)
            || response.validate().is_err()
        {
            continue;
        }
        // The same ciphertext and ID are retried even after transient broker rejection.
        if sender.send(&RelayMessage::Frame(response)).await.is_err() {
            break;
        }
    }
}
async fn replay_requests(host: &Host, sender: &RelaySender, transmit: bool) {
    let now = match host.clock.lock().await.observe(&host.config.state_dir) {
        Ok(now) => now,
        Err(_) => return,
    };
    for bucket in ["write", "read"] {
        let Ok(entries) = fs::read_dir(
            host.config
                .state_dir
                .join(format!("relay-requests-{bucket}")),
        ) else {
            continue;
        };
        for entry in entries.flatten().take(100000) {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !wire::valid_ulid(&name) {
                continue;
            }
            let Ok(bytes) = read_private(&entry.path(), (MAX_FRAME_BYTES * 2) as u64) else {
                continue;
            };
            let Ok(cache) = serde_json::from_slice::<Cached>(&bytes) else {
                continue;
            };
            let frame = cache.response;
            if frame.kind != FrameKind::Request
                || frame.id != name
                || frame.source != host.config.node_id
                || frame.validate().is_err()
            {
                continue;
            }
            let mut deadline = match ulid_time_ms(&frame.id) {
                Ok(created) => created.saturating_add(REQUEST_TTL_MS),
                Err(_) => continue,
            };
            if let Some(retention) = &frame.retention {
                deadline = deadline.min(retention.expires_at_ms);
            }
            if now >= deadline {
                if receive_failure(host, &frame.id, "delivery_expired")
                    .await
                    .is_ok()
                    && let Some(p) = host
                        .pending
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .remove(&frame.id)
                {
                    let _ = p.tx.send(Err("delivery_expired"));
                }
                continue;
            }
            if transmit && sender.send(&RelayMessage::Frame(frame)).await.is_err() {
                break;
            }
        }
    }
}
async fn receive_response(host: &Host, frame: &RpcFrame) -> Result<()> {
    let id = frame
        .in_reply_to
        .as_deref()
        .ok_or("response correlation missing")?;
    let mut budget = host.cache_lock.lock().await;
    let request_dir = bucket_dir(&host.config.state_dir, "relay-requests", frame.operation);
    let inbox_dir = bucket_dir(&host.config.state_dir, "relay-inbox", frame.operation);
    let receipt_path = inbox_dir.join(id);
    if receipt_path.exists() {
        let receipt: Receipt =
            serde_json::from_slice(&read_private(&receipt_path, (MAX_FRAME_BYTES * 3) as u64)?)?;
        if receipt.response != *frame || host.decode_response(&receipt.request, frame).is_err() {
            return Err("response correlation mismatch".into());
        }
        if fs::remove_file(request_dir.join(id)).is_ok() {
            lockyard_core::fsio::sync_path(&request_dir)?;
        }
        return Ok(());
    }
    let pending_path = request_dir.join(id);
    let request = if pending_path.exists() {
        let pending: Cached =
            serde_json::from_slice(&read_private(&pending_path, (MAX_FRAME_BYTES * 2) as u64)?)?;
        pending.response
    } else {
        let expired: Expired = serde_json::from_slice(&read_private(
            &bucket_dir(&host.config.state_dir, "relay-expired", frame.operation).join(id),
            (MAX_FRAME_BYTES * 2) as u64,
        )?)?;
        expired.request
    };
    host.decode_response(&request, frame)?;
    ensure_capacity(&inbox_dir, frame.operation, true)?;
    let receipt = Receipt {
        request,
        response: frame.clone(),
    };
    budget.store(&inbox_dir, id, &receipt, receipt_deadline(&receipt))?;
    if fs::remove_file(pending_path).is_ok() {
        budget.forget(
            request_dir
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or("invalid request directory")?,
            id,
        );
        lockyard_core::fsio::sync_path(request_dir)?;
    }
    Ok(())
}
async fn discardable_read_response(host: &Host, frame: &RpcFrame) -> bool {
    if frame.kind != FrameKind::Response
        || is_write(frame.operation)
        || frame.target != host.config.node_id
    {
        return false;
    }
    let Some(id) = frame.in_reply_to.as_ref() else {
        return false;
    };
    if host
        .pending
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .contains_key(id)
    {
        return false;
    }
    if host
        .config
        .state_dir
        .join("relay-requests-write")
        .join(id)
        .exists()
        || host
            .config
            .state_dir
            .join("relay-inbox-write")
            .join(id)
            .exists()
    {
        return false;
    }
    if host
        .config
        .state_dir
        .join("relay-completed-writes")
        .join(id)
        .exists()
    {
        return false;
    }
    let expired_path = host.config.state_dir.join("relay-expired-write").join(id);
    if expired_path.exists() {
        let Ok(bytes) = read_private(&expired_path, (MAX_FRAME_BYTES * 2) as u64) else {
            return false;
        };
        let Ok(expired) = serde_json::from_slice::<Expired>(&bytes) else {
            return false;
        };
        if is_write(expired.request.operation) {
            return false;
        }
    }
    host.codec.decode::<RpcReply<Value>>(frame).is_ok()
}
// A broker-bound peer can send many malformed replies to one request. Only after
// exact routing correlation and durable metadata recording may such a reply be
// discarded; the original request and waiter stay untouched and remain uncertain.
async fn reject_invalid_response(host: &Host, frame: &RpcFrame) -> Result<bool> {
    if frame.kind != FrameKind::Response || frame.target != host.config.node_id {
        return Ok(false);
    }
    let Some(id) = frame.in_reply_to.as_ref() else {
        return Ok(false);
    };
    let has_waiter = host
        .pending
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .contains_key(id);
    let _guard = host.cache_lock.lock().await;
    let pending = bucket_dir(&host.config.state_dir, "relay-requests", frame.operation).join(id);
    let expired = bucket_dir(&host.config.state_dir, "relay-expired", frame.operation).join(id);
    let receipt = bucket_dir(&host.config.state_dir, "relay-inbox", frame.operation).join(id);
    let original = if pending.exists() {
        Some(
            serde_json::from_slice::<Cached>(&read_private(
                &pending,
                (MAX_FRAME_BYTES * 2) as u64,
            )?)?
            .response,
        )
    } else if expired.exists() {
        Some(
            serde_json::from_slice::<Expired>(&read_private(
                &expired,
                (MAX_FRAME_BYTES * 2) as u64,
            )?)?
            .request,
        )
    } else if receipt.exists() {
        Some(
            serde_json::from_slice::<Receipt>(&read_private(
                &receipt,
                (MAX_FRAME_BYTES * 3) as u64,
            )?)?
            .request,
        )
    } else {
        let completed = host
            .config
            .state_dir
            .join("relay-completed-writes")
            .join(id);
        if is_write(frame.operation) && completed.exists() {
            Some(
                serde_json::from_slice::<CompletedReceipt>(&read_private(&completed, 4096)?)?
                    .request,
            )
        } else {
            None
        }
    };
    if let Some(request) = original {
        if request.kind != FrameKind::Request
            || request.id != *id
            || request.source != host.config.node_id
            || request.target != frame.source
            || request.operation != frame.operation
        {
            return Ok(false);
        }
        if host.decode_response(&request, frame).is_ok() {
            return Ok(false);
        }
    } else {
        if host.codec.decode::<RpcReply<Value>>(frame).is_ok() {
            return Ok(false);
        }
        // A completed read may have had its receipt reclaimed. The authenticated
        // broker still binds its routing; never discard against any live/write state.
        if is_write(frame.operation)
            || has_waiter
            || host
                .config
                .state_dir
                .join("relay-requests-write")
                .join(id)
                .exists()
            || host
                .config
                .state_dir
                .join("relay-expired-write")
                .join(id)
                .exists()
            || host
                .config
                .state_dir
                .join("relay-inbox-write")
                .join(id)
                .exists()
        {
            return Ok(false);
        }
    }
    if !store_response_evidence(host, frame, "relay-invalid-responses")? {
        return Ok(false);
    }
    host.invalid_responses.fetch_add(1, Ordering::Relaxed);
    Ok(true)
}
// Called with cache_lock held by the caller.
fn store_response_evidence(host: &Host, frame: &RpcFrame, prefix: &str) -> Result<bool> {
    let dir = bucket_dir(&host.config.state_dir, prefix, frame.operation);
    let id = frame
        .in_reply_to
        .as_ref()
        .ok_or("response correlation missing")?;
    let path = dir.join(id);
    let count = if path.exists() {
        let old: InvalidResponse = serde_json::from_slice(&read_private(&path, 4096)?)?;
        if old.request_id != *id || old.operation != frame.operation || old.source != frame.source {
            return Ok(false);
        }
        old.count.saturating_add(1)
    } else {
        if fs::read_dir(&dir)?.take(100_000).count() >= 100_000 {
            if !is_write(frame.operation) {
                for entry in fs::read_dir(&dir)?.flatten() {
                    if entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age >= Duration::from_secs(8 * 24 * 60 * 60))
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
                lockyard_core::fsio::sync_path(&dir)?;
            }
            if fs::read_dir(&dir)?.take(100_000).count() >= 100_000 {
                return Err("invalid response evidence capacity reached".into());
            }
        }
        1
    };
    store_data(
        &dir,
        id,
        &serde_json::to_vec(&InvalidResponse {
            request_id: id.clone(),
            response_id: frame.id.clone(),
            operation: frame.operation,
            source: frame.source.clone(),
            response_hash: request_hash(frame)?,
            count,
        })?,
    )?;
    Ok(true)
}
// A valid but different second reply must not overwrite the first durable receipt
// or complete any waiter a second time. Record its metadata before ACK/discard.
async fn record_conflicting_response(host: &Host, frame: &RpcFrame) -> Result<bool> {
    if frame.kind != FrameKind::Response
        || !is_write(frame.operation)
        || frame.target != host.config.node_id
        || host.codec.decode::<RpcReply<Value>>(frame).is_err()
    {
        return Ok(false);
    }
    let Some(id) = frame.in_reply_to.as_ref() else {
        return Ok(false);
    };
    let _guard = host.cache_lock.lock().await;
    let path = bucket_dir(&host.config.state_dir, "relay-inbox", frame.operation).join(id);
    let (request, first_id, first_hash) = if path.exists() {
        let receipt: Receipt =
            serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 3) as u64)?)?;
        let hash = request_hash(&receipt.response)?;
        (receipt.request, receipt.response.id, hash)
    } else {
        let path = host
            .config
            .state_dir
            .join("relay-completed-writes")
            .join(id);
        if !path.exists() {
            return Ok(false);
        }
        let completed: CompletedReceipt = serde_json::from_slice(&read_private(&path, 4096)?)?;
        (
            completed.request,
            completed.response_id,
            completed.response_hash,
        )
    };
    if request.id != *id
        || request.kind != FrameKind::Request
        || request.source != host.config.node_id
        || request.target != frame.source
        || request.operation != frame.operation
    {
        return Ok(false);
    }
    if frame.id == first_id && request_hash(frame)? == first_hash {
        return Ok(true);
    }
    if !store_response_evidence(host, frame, "relay-conflicting-responses")? {
        return Ok(false);
    }
    host.conflicting_responses.fetch_add(1, Ordering::Relaxed);
    Ok(true)
}
async fn receive_failure(host: &Host, id: &str, code: &'static str) -> Result<()> {
    let mut budget = host.cache_lock.lock().await;
    for bucket in ["write", "read"] {
        let expired = host
            .config
            .state_dir
            .join(format!("relay-expired-{bucket}"));
        if expired.join(id).exists() {
            for source in ["write", "read"] {
                let dir = host
                    .config
                    .state_dir
                    .join(format!("relay-requests-{source}"));
                if fs::remove_file(dir.join(id)).is_ok() {
                    budget.forget(
                        dir.file_name()
                            .and_then(|value| value.to_str())
                            .ok_or("invalid request directory")?,
                        id,
                    );
                    lockyard_core::fsio::sync_path(dir)?;
                }
            }
            return Ok(());
        }
    }
    for bucket in ["write", "read"] {
        let dir = host
            .config
            .state_dir
            .join(format!("relay-requests-{bucket}"));
        let path = dir.join(id);
        if !path.exists() {
            continue;
        }
        let cache: Cached =
            serde_json::from_slice(&read_private(&path, (MAX_FRAME_BYTES * 2) as u64)?)?;
        if cache.response.id != id
            || cache.response.kind != FrameKind::Request
            || cache.response.source != host.config.node_id
        {
            return Err("invalid expired request".into());
        }
        let expired = bucket_dir(
            &host.config.state_dir,
            "relay-expired",
            cache.response.operation,
        );
        if fs::read_dir(&expired)?.take(100_000).count() >= 100_000 {
            if !is_write(cache.response.operation) {
                for entry in fs::read_dir(&expired)?.flatten() {
                    if entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age >= Duration::from_secs(8 * 24 * 60 * 60))
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
                lockyard_core::fsio::sync_path(&expired)?;
            }
            if fs::read_dir(&expired)?.take(100_000).count() >= 100_000 {
                return Err("relay expiry storage capacity reached".into());
            }
        }
        let mut request = cache.response;
        request.payload.clear();
        store_data(
            &expired,
            id,
            &serde_json::to_vec(&Expired {
                request,
                code: code.into(),
            })?,
        )?;
        fs::remove_file(path)?;
        budget.forget(
            dir.file_name()
                .and_then(|value| value.to_str())
                .ok_or("invalid request directory")?,
            id,
        );
        lockyard_core::fsio::sync_path(dir)?;
        return Ok(());
    }
    Err("unknown expired request".into())
}
async fn relay_loop(host: Arc<Host>, mut client: RelayClient) {
    let sender = client.sender();
    let mut response_replay: Option<tokio::task::JoinHandle<()>> = None;
    let mut request_replay: Option<tokio::task::JoinHandle<()>> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let event = tokio::select! {
            event = client.recv() => match event { Some(event) => event, None => break },
            _ = tick.tick() => {
                if response_replay.as_ref().is_none_or(|task| task.is_finished()) {
                    let host = host.clone(); let sender = sender.clone();
                    response_replay = Some(tokio::spawn(async move { replay_cached(&host,&sender).await; }));
                }
                if request_replay.as_ref().is_none_or(|task| task.is_finished()) {
                    let host = host.clone(); let sender = sender.clone();
                    request_replay = Some(tokio::spawn(async move { replay_requests(&host,&sender,false).await; }));
                }
                continue;
            }
        };
        match event {
            RelayEvent::Connected => {
                if let Some(state) = &host.revocations {
                    state.wake();
                }
                if let Some(task) = response_replay.take() {
                    task.abort();
                }
                if let Some(task) = request_replay.take() {
                    task.abort();
                }
                let replay_host = host.clone();
                let replay_sender = sender.clone();
                response_replay = Some(tokio::spawn(async move {
                    replay_cached(&replay_host, &replay_sender).await;
                }));
                let replay_host = host.clone();
                let replay_sender = sender.clone();
                request_replay = Some(tokio::spawn(async move {
                    replay_requests(&replay_host, &replay_sender, true).await;
                }));
            }
            RelayEvent::Message(RelayMessage::Frame(frame)) if frame.kind == FrameKind::Request => {
                let mut inflight = host.relay_inflight.lock().await;
                if !inflight.contains(&frame.id)
                    && let Ok(permit) = host.relay_ingress.clone().try_acquire_owned()
                {
                    inflight.insert(frame.id.clone());
                    let host = host.clone();
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let id = frame.id.clone();
                        relay_request(host.clone(), sender, frame).await;
                        host.relay_inflight.lock().await.remove(&id);
                    });
                }
            }
            RelayEvent::Message(RelayMessage::Frame(frame))
                if frame.kind == FrameKind::Response =>
            {
                let matched = receive_response(&host, &frame).await.is_ok();
                let discard = !matched && discardable_read_response(&host, &frame).await;
                let reject = !matched
                    && !discard
                    && reject_invalid_response(&host, &frame)
                        .await
                        .unwrap_or(false);
                let conflict = !matched
                    && !discard
                    && !reject
                    && record_conflicting_response(&host, &frame)
                        .await
                        .unwrap_or(false);
                if matched || discard || reject || conflict {
                    if matched {
                        if let Some(id) = frame.in_reply_to.as_ref()
                            && let Some(p) = host
                                .pending
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .remove(id)
                        {
                            let _ = p.tx.send(Ok(frame.clone()));
                        }
                        if !is_write(frame.operation)
                            && let Some(id) = frame.in_reply_to.as_ref()
                        {
                            let mut budget = host.cache_lock.lock().await;
                            if fs::remove_file(
                                host.config.state_dir.join("relay-inbox-read").join(id),
                            )
                            .is_ok()
                            {
                                budget.forget("relay-inbox-read", id);
                            }
                        }
                    }
                    let _ = sender
                        .send(&RelayMessage::Control(RelayControl::Ack {
                            v: 1,
                            id: frame.id,
                        }))
                        .await;
                }
            }
            RelayEvent::Message(RelayMessage::Control(RelayControl::Error {
                id: Some(id),
                code,
                ..
            })) if code == "delivery_expired" || code == "delivery_unauthorized" => {
                let reason = if code == "delivery_expired" {
                    "delivery_expired"
                } else {
                    "delivery_unauthorized"
                };
                let request_recorded = receive_failure(&host, &id, reason).await.is_ok();
                let response_recorded = if request_recorded {
                    false
                } else {
                    retire_outbox_response(&host, &id, reason)
                        .await
                        .unwrap_or(false)
                };
                if request_recorded || response_recorded || wire::valid_ulid(&id) {
                    if request_recorded
                        && let Some(p) = host
                            .pending
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .remove(&id)
                    {
                        let _ = p.tx.send(Err(reason));
                    }
                    // An authenticated broker notice acknowledges only a failed/expired
                    // delivery. An already-erased local record is not an execution result;
                    // ACKing that stale notice cannot complete a waiter or replay work.
                    let _ = sender
                        .send(&RelayMessage::Control(RelayControl::Ack { v: 1, id }))
                        .await;
                }
            }
            RelayEvent::Message(RelayMessage::Control(RelayControl::Error {
                id: Some(id),
                code,
                ..
            })) if code == "response_mismatch" => {
                let _ = retire_outbox_response(&host, &id, "response_mismatch").await;
            }
            RelayEvent::Message(RelayMessage::Control(RelayControl::Ack { v: 1, id })) => {
                if let Ok(Some(request_id)) = accept_response(&host, &id).await
                    && let Ok(permit) = host.relay_acks.clone().try_acquire_owned()
                {
                    let host = host.clone();
                    let sender = sender.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = acknowledge_accepted(&host, &sender, &request_id).await;
                    });
                }
            }
            _ => {}
        }
    }
    if let Some(task) = response_replay {
        task.abort();
    }
    if let Some(task) = request_replay {
        task.abort();
    }
}
fn count_outbox(state_dir: &Path) -> Result<usize> {
    let mut occupied = 0usize;
    for entry in fs::read_dir(state_dir.join("relay-outbox"))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid relay outbox")?;
        if !wire::valid_ulid(&name) {
            return Err("invalid relay outbox".into());
        }
        let record: OutboxEntry =
            serde_json::from_slice(&read_private(&entry.path(), OUTBOX_RECORD_MAX)?)
                .map_err(|_| "invalid relay outbox")?;
        if record.request_id != name
            || !wire::valid_name(&record.source)
            || record.response.as_ref().is_some_and(|f| {
                f.in_reply_to.as_deref() != Some(&name)
                    || f.operation != record.operation
                    || f.target != record.source
                    || f.validate().is_err()
            })
            || (record.accepted && record.response.is_none())
        {
            return Err("invalid relay outbox".into());
        }
        occupied += 1;
        if occupied > OUTBOX_SLOTS {
            return Err("relay outbox capacity exceeded".into());
        }
    }
    Ok(occupied)
}
fn count_write_history(state: &Path) -> Result<usize> {
    let mut ids = HashSet::new();
    for bucket in [
        "relay-requests-write",
        "relay-inbox-write",
        "relay-expired-write",
        "relay-completed-writes",
    ] {
        for entry in fs::read_dir(state.join(bucket))? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if wire::valid_ulid(&id) {
                ids.insert(id);
            }
            if ids.len() > 100_000 {
                return Err("write correlation history capacity exceeded".into());
            }
        }
    }
    Ok(ids.len())
}
/// Runs until the process is stopped. The exclusive state lock also protects replay records.
pub async fn serve(config: NodeConfig) -> Result<()> {
    config.validate()?;
    if config.delegation_socket.is_some() {
        return Err("workload delegation configuration cannot start a node daemon".into());
    }
    private_dir(&config.state_dir)?;
    let lock = lock_state(&config.state_dir)?;
    let _managed_binary_guard = crate::updates::startup_guard(&config)?;
    let mut dirs = vec![
        config.state_dir.join("relay-outbox"),
        config.state_dir.join("relay-expired-read"),
        config.state_dir.join("relay-expired-write"),
        config.state_dir.join("read-tombstones"),
        config.state_dir.join("request-tombstones-read"),
        config.state_dir.join("request-tombstones-write"),
        config.state_dir.join("relay-undeliverable-read"),
        config.state_dir.join("relay-undeliverable-write"),
        config.state_dir.join("relay-invalid-responses-read"),
        config.state_dir.join("relay-invalid-responses-write"),
        config.state_dir.join("relay-conflicting-responses-read"),
        config.state_dir.join("relay-conflicting-responses-write"),
        config.state_dir.join("relay-completed-writes"),
    ];
    for prefix in ["responses", "relay-requests", "relay-inbox"] {
        for bucket in ["read", "write"] {
            dirs.push(config.state_dir.join(format!("{prefix}-{bucket}")));
        }
    }
    for dir in &dirs {
        private_dir(dir)?;
    }
    // Leftover temporary files were never committed. Executor job IDs still deduplicate a retry.
    for dir in &dirs {
        for entry in fs::read_dir(dir)?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') && name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    // Read-only replies can be retried; no caller survives a daemon restart.
    // Discard stale local receipts so previous churn cannot exhaust the next run.
    let read_inbox = config.state_dir.join("relay-inbox-read");
    for entry in fs::read_dir(&read_inbox)?.flatten() {
        if wire::valid_ulid(&entry.file_name().to_string_lossy()) {
            fs::remove_file(entry.path())?;
        }
    }
    lockyard_core::fsio::sync_path(read_inbox)?;
    let clock = ClockState::load(&config.state_dir)?;
    recover_empty_reservations(&config.state_dir, clock.effective_ms)?;
    let occupied = count_outbox(&config.state_dir)?;
    let history = count_write_history(&config.state_dir)?;
    crate::rotation_install::require_no_pending(&config.state_dir)?;
    let workspace_key_path = workspace_key_directory()?.join(format!("{}.key", config.workspace));
    let _workspace_key_guard = crate::rotation_install::guard_workspace_key(&workspace_key_path)?;
    crate::rotation_install::require_global_binding(&config, &workspace_key_path)?;
    validate_workspace_key(&config.workspace)?;
    let key = WorkspaceKey::load_for_workspace(&config.workspace)
        .map_err(|_| "workspace key unavailable")?
        .ok_or("workspace key unavailable")?;
    let delegation = Arc::new(crate::delegation::DeferredDelegation::default());
    let identity = quic::load_identity(&config.certificate, &config.private_key)?;
    let certificate_der = identity
        .certificates
        .first()
        .ok_or("node certificate unavailable")?
        .as_ref()
        .to_vec();
    let certificate_sha256 = PeerPin::certificate(&certificate_der).to_hex();
    let notifications = if config.metadata_notifications {
        Some(Arc::new(std::sync::Mutex::new(
            crate::job_notifications::Outbox::open(&config.state_dir, &certificate_sha256, true)?,
        )))
    } else {
        crate::job_notifications::disable_if_present(&config.state_dir, &certificate_sha256)?;
        None
    };
    let executor = config
        .executor
        .clone()
        .map(|mut executor| {
            executor.node_certificate_sha256 = Some(certificate_sha256.clone());
            let cloud = if config.relay.is_some() {
                Some(crate::cloud::NodeCloudClient::from_config(&config)?)
            } else if config.revocations.is_some() {
                Some(crate::cloud::NodeCloudClient::for_revocations(&config)?)
            } else {
                None
            };
            if let Some(cloud) = cloud {
                executor.signed_results = Some(Arc::new(
                    cloud
                        .revocation_client()?
                        .with_content_encryption(&config.workspace, Some(key.clone()), true)
                        .with_pending_journal(executor.state_dir.join("signed-result-pending"))?,
                ));
            }
            executor
                .protected_identity_files
                .push(config.private_key.clone());
            executor
                .protected_identity_files
                .push(config.state_dir.clone());
            if let Some(relay) = &config.relay {
                executor
                    .protected_identity_files
                    .push(relay.token_file.clone());
            }
            executor
                .protected_identity_files
                .push(workspace_key_directory()?);
            for name in [
                "rotation-authority.json",
                "workspace-rotation-state.json",
                "workspace-rotation.pending.json",
            ] {
                executor
                    .protected_identity_files
                    .push(config.state_dir.join(name));
            }
            Executor::new_with_notifications(
                executor,
                config.workspace.clone(),
                key.clone(),
                delegation.clone(),
                notifications.clone(),
            )
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { Box::new(error) })
        })
        .transpose()?;
    let codec = PayloadCodec::new(config.workspace.clone(), key)?;
    let roots = read_certificates(&config.trust_anchors)?;
    let revocations = config
        .revocations
        .clone()
        .map(|settings| crate::revocations::RevocationManager::open(settings, &config.state_dir))
        .transpose()?;
    // The initial challenge completes before exposing any direct listener/client.
    if let Some(state) = &revocations {
        let _ = revocation_adapter::refresh_once(&config, state).await;
    }
    let direct = if config.peers.iter().any(|p| p.address.is_some()) {
        let bind: SocketAddr = if config
            .peers
            .iter()
            .filter_map(|p| p.address)
            .all(|a| a.is_ipv6())
        {
            "[::]:0".parse()?
        } else {
            "0.0.0.0:0".parse()?
        };
        Some(DirectClient::bind_with_revocations(
            bind,
            config.node_id.clone(),
            quic::Identity {
                certificates: identity.certificates.clone(),
                private_key: identity.private_key.clone_key(),
            },
            roots.clone(),
            revocations.clone(),
        )?)
    } else {
        None
    };
    let server = if let Some(bind) = config.listen {
        Some(DirectServer::bind_with_revocations(
            bind,
            config.node_id.clone(),
            quic::Identity {
                certificates: identity.certificates.clone(),
                private_key: identity.private_key.clone_key(),
            },
            roots,
            config.peers.iter().map(PeerConfig::policy).collect(),
            revocations.clone(),
        )?)
    } else {
        None
    };
    let advertised_endpoint = server
        .as_ref()
        .and_then(|server| server.local_addr().ok())
        .filter(|address| !address.ip().is_unspecified() && address.port() != 0)
        .map(|address| address.to_string());
    let relay = if let Some(settings) = &config.relay {
        let bytes = read_private(&settings.token_file, 16384)?;
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| "invalid relay credential")?
            .trim()
            .to_string();
        let config = RelayConfig::new(&settings.url, config.node_id.clone(), token)?
            .with_trust_anchors(read_certificates(&settings.tls_roots)?)?
            .with_enrollment(certificate_der, advertised_endpoint)?
            .with_enrollment_proof(codec.identity_proof(&config.node_id, &certificate_sha256)?)?;
        Some(RelayClient::spawn(config)?)
    } else {
        None
    };
    let workflow = workflow_adapter::open(&config, &certificate_sha256)?;
    let socket_path = config.socket_path();
    let listener = make_socket(&socket_path)?;
    let sender = relay.as_ref().map(RelayClient::sender);
    let cache_budget = CacheBudget::load(&config.state_dir)?;
    let operator_draining =
        crate::executor::read_drain_flag(&config.state_dir.join("operator-drain"))?;
    let host = Arc::new(Host {
        _lock: lock,
        certificate_sha256,
        config,
        codec,
        executor,
        workflow,
        direct,
        revocations,
        relay: sender,
        pending: std::sync::Mutex::new(HashMap::new()),
        request_locks: (0..64).map(|_| Mutex::new(())).collect(),
        cache_lock: Mutex::new(cache_budget),
        permits: Arc::new(Semaphore::new(128)),
        connections: Arc::new(Semaphore::new(128)),
        delegation_connections: Arc::new(Semaphore::new(64)),
        relay_slots: Arc::new(Semaphore::new(OUTBOX_SLOTS - occupied)),
        // The broker caps a target at 1000 unacknowledged deliveries.
        relay_ingress: Arc::new(Semaphore::new(1024)),
        relay_inflight: Mutex::new(HashSet::new()),
        invalid_requests: AtomicU64::new(0),
        invalid_responses: AtomicU64::new(0),
        conflicting_responses: AtomicU64::new(0),
        retention_cleanup_failed: std::sync::atomic::AtomicBool::new(false),
        operator_draining: std::sync::atomic::AtomicBool::new(operator_draining),
        relay_acks: Arc::new(Semaphore::new(16)),
        write_history: Arc::new(Semaphore::new(100_000 - history)),
        clock: Mutex::new(clock),
    });
    delegation.bind(Arc::new(delegation_adapter::Provider {
        host: Arc::downgrade(&host),
        runtime: tokio::runtime::Handle::current(),
    }))?;
    // Keep the state lock held until all request tasks finish, including after cancellation.
    struct Tasks(Vec<tokio::task::JoinHandle<()>>);
    impl Drop for Tasks {
        fn drop(&mut self) {
            for task in &self.0 {
                task.abort();
            }
        }
    }
    let mut tasks = Tasks(Vec::new());
    if host.revocations.is_some() {
        tasks
            .0
            .push(tokio::spawn(revocation_adapter::monitor(Arc::downgrade(
                &host,
            ))));
    }
    if host.config.metadata_notifications {
        let client = crate::cloud::NodeCloudClient::from_config(&host.config)?;
        let executor = host
            .executor
            .clone()
            .ok_or("job metadata notifications require an executor")?;
        tasks.0.push(tokio::spawn(crate::job_notifications::run(
            notifications.ok_or("job notification outbox unavailable")?,
            host.certificate_sha256.clone(),
            executor,
            client,
        )));
    }
    maintain_content_cache(&host).await?;
    {
        let host = host.clone();
        tasks.0.push(tokio::spawn(async move {
            let mut cursor = 0usize;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if !host.operator_draining.load(Ordering::Acquire) {
                    continue;
                }
                let config = host.config.clone();
                let pending = match tokio::task::spawn_blocking(move || {
                    crate::incarnation::pending_submissions(&config)
                })
                .await
                {
                    Ok(Ok(pending)) => pending,
                    _ => continue,
                };
                if pending.is_empty() {
                    cursor = 0;
                    continue;
                }
                let count = pending.len();
                let selected: Vec<_> = pending
                    .into_iter()
                    .cycle()
                    .skip(cursor % count)
                    .take(count.min(16))
                    .collect();
                cursor = (cursor + selected.len()) % count;
                let mut requests = futures_util::stream::FuturesUnordered::new();
                for pending in selected {
                    let host = host.clone();
                    requests.push(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(5),
                            host.rpc_bound(
                                &pending.target,
                                Operation::JobStatus,
                                json!({"job_id":pending.job_id}),
                                Some(&pending.certificate_sha256),
                                crate::incarnation::DispatchOrigin::Operator,
                            ),
                        )
                        .await;
                    });
                }
                use futures_util::StreamExt;
                while requests.next().await.is_some() {}
            }
        }));
    }
    if let Some(controller) = host.workflow.clone() {
        if operator_draining {
            controller.begin_drain();
        }
        let driver = Arc::new(workflow_adapter::Driver::new(Arc::downgrade(&host)));
        tasks.0.push(tokio::spawn(controller.run(driver)));
    }
    {
        let host = host.clone();
        tasks.0.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let mut failed = false;
                if let Some(executor) = host.executor.clone() {
                    failed |= !matches!(
                        tokio::task::spawn_blocking(move || executor.purge_expired()).await,
                        Ok(Ok(_))
                    );
                }
                if maintain_content_cache(&host).await.is_err() {
                    failed = true;
                }
                host.retention_cleanup_failed
                    .store(failed, Ordering::Relaxed);
                if failed {
                    eprintln!("lockyard node: content retention cleanup is incomplete");
                }
            }
        }));
    }
    if let Some(executor) = host.executor.clone() {
        let reconciliation_executor = executor.clone();
        tasks.0.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let executor = reconciliation_executor.clone();
                let _ = tokio::task::spawn_blocking(move || executor.reconcile_cloud_tombstones())
                    .await;
            }
        }));
        tasks.0.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let executor = executor.clone();
                let _ =
                    tokio::task::spawn_blocking(move || executor.publish_signed_results()).await;
            }
        }));
    }
    if let Some(client) = relay {
        tasks.0.push(tokio::spawn(relay_loop(host.clone(), client)));
    }
    if let Some(server) = server {
        let host = host.clone();
        tasks.0.push(tokio::spawn(async move {
            loop {
                match server.accept().await {
                    Ok(connection) => {
                        let host = host.clone();
                        if let Ok(permit) = host.connections.clone().try_acquire_owned() {
                            tokio::spawn(async move {
                                let _permit = permit;
                                direct_connection(host, connection).await;
                            });
                        }
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        }));
    }
    loop {
        let (stream, _) = listener.accept().await?;
        if let Ok(permit) = host.permits.clone().try_acquire_owned() {
            let host = host.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = control_connection(host, stream).await;
            });
        }
    }
}

#[cfg(windows)]
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    Ok(lockyard_core::windows::read_private(path, max)?)
}

#[cfg(windows)]
fn private_dir(path: &Path) -> Result<()> {
    Ok(lockyard_core::windows::private_dir(path)?)
}

#[cfg(windows)]
fn lock_state(path: &Path) -> Result<File> {
    let file = lockyard_core::windows::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path.join("host.lock"))?;
    file.try_lock().map_err(|_| "node host already running")?;
    Ok(file)
}

#[cfg(windows)]
fn make_socket(path: &Path) -> Result<UnixListener> {
    Ok(UnixListener::bind(path)?)
}

#[cfg(windows)]
fn validate_workspace_key(workspace: &str) -> Result<()> {
    let keys = workspace_key_directory()?;
    lockyard_core::windows::require_private(&keys)?;
    if read_private(&keys.join(format!("{workspace}.key")), 32)?.len() != 32 {
        return Err("invalid workspace key".into());
    }
    Ok(())
}

#[cfg(windows)]
fn store_data(dir: &Path, id: &str, bytes: &[u8]) -> Result<()> {
    Ok(lockyard_core::fsio::replace(&dir.join(id), bytes, 0o600)?)
}

#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn node_diagnostics_exposes_shared_build_identity() {
        let (_root, host) = fixture();
        let status = serde_json::to_value(host.status()).unwrap();
        assert_eq!(status["build"]["semver"], env!("CARGO_PKG_VERSION"));
        let sha = status["build"]["git_sha"].as_str().unwrap();
        assert!(
            sha == "unknown"
                || (sha.len() >= 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
        );
        assert!(
            status["build"]["built_at_unix"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
    }

    impl Host {
        fn seal<T: Serialize>(&self, frame: &mut RpcFrame, payload: &T) -> Result<()> {
            if frame.operation != Operation::NodePing {
                frame.v = wire::PROTOCOL_VERSION;
                let peer = self.config.peers.first().ok_or("test peer missing")?;
                frame.source_certificate_sha256 = Some(if frame.source == self.config.node_id {
                    self.certificate_sha256.clone()
                } else {
                    peer.certificate_sha256.to_ascii_lowercase()
                });
                frame.target_certificate_sha256 = Some(if frame.target == self.config.node_id {
                    self.certificate_sha256.clone()
                } else {
                    peer.certificate_sha256.to_ascii_lowercase()
                });
                if frame.retention.is_none() {
                    frame.retention = Some(crate::retention::ContentRetention::for_copy(
                        &crate::retention::RetentionPolicy {
                            content_ttl_seconds: 3600,
                        },
                        crate::retention::id_timestamp_ms(&frame.id)?,
                        None,
                    )?);
                }
            }
            self.codec.encode(frame, payload)
        }
    }
    use super::*;
    static PORT_5221: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    #[cfg(unix)]
    fn private_config_and_state_fifos_fail_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let root = tempfile::tempdir().unwrap();
        for name in ["node.toml", "workspace.key", "relay-state"] {
            let path = root.path().join(name);
            let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let rejected = if name == "node.toml" {
                    NodeConfig::load(&path).is_err()
                } else {
                    read_private(&path, 1024).is_err()
                };
                let _ = tx.send(rejected);
            });
            assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
        }
    }

    pub(super) fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["peer".into()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let cert_path = dir.path().join("peer.der");
        fs::write(&cert_path, &cert).unwrap();
        let own_certificate = rcgen::generate_simple_self_signed(vec!["worker".into()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        fs::write(dir.path().join("node.der"), &own_certificate).unwrap();
        let state = dir.path().join("state");
        private_dir(&state).unwrap();
        for dir in [
            "responses-read",
            "responses-write",
            "relay-outbox",
            "relay-requests-read",
            "relay-requests-write",
            "relay-inbox-read",
            "relay-inbox-write",
            "relay-expired-read",
            "relay-expired-write",
            "read-tombstones",
            "request-tombstones-read",
            "request-tombstones-write",
            "relay-undeliverable-read",
            "relay-undeliverable-write",
            "relay-invalid-responses-read",
            "relay-invalid-responses-write",
            "relay-conflicting-responses-read",
            "relay-conflicting-responses-write",
            "relay-completed-writes",
        ] {
            private_dir(&state.join(dir)).unwrap();
        }
        let config = NodeConfig {
            node_id: "worker".into(),
            workspace: "workspace".into(),
            state_dir: state,
            listen: None,
            certificate: dir.path().join("node.der"),
            private_key: dir.path().join("key.der"),
            trust_anchors: vec![],
            peers: vec![PeerConfig {
                node_id: "caller".into(),
                address: None,
                tls_name: "peer".into(),
                certificate_sha256: PeerPin::certificate(&cert).to_hex(),
                certificate: cert_path,
                allowed_operations: vec![Operation::NodePing],
            }],
            relay: None,
            executor: None,
            metadata_notifications: false,
            result_trust: BTreeMap::new(),
            project_retention: BTreeMap::new(),
            workflow: None,
            delegation_socket: None,
            revocations: None,
            rpc_timeout_seconds: 60,
        };
        let codec =
            PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32])).unwrap();
        let lock = lock_state(&config.state_dir).unwrap();
        let clock = ClockState::load(&config.state_dir).unwrap();
        let host = Host {
            _lock: lock,
            certificate_sha256: PeerPin::certificate(&own_certificate).to_hex(),
            config,
            codec,
            executor: None,
            workflow: None,
            direct: None,
            revocations: None,
            relay: None,
            pending: std::sync::Mutex::new(HashMap::new()),
            request_locks: (0..64).map(|_| Mutex::new(())).collect(),
            cache_lock: Mutex::new(CacheBudget::default()),
            permits: Arc::new(Semaphore::new(128)),
            connections: Arc::new(Semaphore::new(128)),
            delegation_connections: Arc::new(Semaphore::new(64)),
            relay_slots: Arc::new(Semaphore::new(OUTBOX_SLOTS)),
            relay_ingress: Arc::new(Semaphore::new(1024)),
            relay_inflight: Mutex::new(HashSet::new()),
            invalid_requests: AtomicU64::new(0),
            invalid_responses: AtomicU64::new(0),
            conflicting_responses: AtomicU64::new(0),
            retention_cleanup_failed: std::sync::atomic::AtomicBool::new(false),
            operator_draining: std::sync::atomic::AtomicBool::new(false),
            relay_acks: Arc::new(Semaphore::new(16)),
            write_history: Arc::new(Semaphore::new(100_000)),
            clock: Mutex::new(clock),
        };
        (dir, host)
    }
    fn ping(host: &Host) -> RpcFrame {
        let mut frame = RpcFrame {
            v: 1,
            kind: FrameKind::Request,
            id: wire::new_id().unwrap(),
            source: "caller".into(),
            target: "worker".into(),
            operation: Operation::NodePing,
            in_reply_to: None,
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        host.seal(&mut frame, &json!({})).unwrap();
        frame
    }
    #[tokio::test]
    async fn cancelled_relay_rpc_removes_pending_waiter_while_cache_is_busy() {
        let (_dir, mut host) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = RelayClient::spawn(
            RelayConfig::new(
                &format!("http://{}", listener.local_addr().unwrap()),
                host.config.node_id.clone(),
                "synthetic-relay-token".into(),
            )
            .unwrap(),
        )
        .unwrap();
        host.relay = Some(client.sender());
        let _cache = host.cache_lock.lock().await;
        let mut request =
            Box::pin(host.rpc_once("caller", Operation::NodePing, json!({}), None, None));
        // Poll to the held cache mutex: the real RPC has already registered its
        // waiter, but no durable request exists for expiry/replay to clean up.
        assert!(futures_util::poll!(request.as_mut()).is_pending());
        assert_eq!(
            host.pending
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );
        assert_eq!(
            fs::read_dir(host.config.state_dir.join("relay-requests-read"))
                .unwrap()
                .count(),
            0
        );
        drop(request);
        assert!(
            host.pending
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty(),
            "cancelled RPC must release its transient waiter without a response or expiry notice"
        );
    }
    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn seeded_relay_rpc_cancellation_preserves_replay_and_write_history() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::{
            accept_hdr_async,
            tungstenite::{
                Message,
                handshake::server::{Request, Response},
            },
        };
        let _port = PORT_5221.lock().await;
        tokio::time::timeout(Duration::from_secs(12), async {
            let (_dir, mut host) = fixture();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let relay_url = format!("http://{}", listener.local_addr().unwrap());
            let (observed_tx, mut observed) = tokio::sync::mpsc::channel(16);
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |_request: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "lockyard-node.v1".parse().unwrap(),
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    match message {
                        Message::Text(text) => {
                            let RelayMessage::Frame(frame) =
                                serde_json::from_str(&text).unwrap()
                            else {
                                panic!("unexpected relay control message");
                            };
                            observed_tx.send(frame).await.unwrap();
                        }
                        Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                        _ => {}
                    }
                }
            });
            let client = RelayClient::spawn(
                RelayConfig::new(&relay_url, "worker".into(), "test".into()).unwrap(),
            )
            .unwrap();
            let mut sender = client.sender();
            sender.wait_connected(Duration::from_secs(4)).await.unwrap();
            host.relay = Some(sender);
            let mut seed = 0x6f35_f83d_6072_1281_u64;
            let mut durable_writes = 0usize;
            let mut phases = [0usize; 4];
            for _ in 0..256 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let phase = (seed % 4) as usize;
                phases[phase] += 1;
                let operation = if seed & 8 == 0 {
                    Operation::NodePing
                } else {
                    Operation::JobCancel
                };
                let mut request = Box::pin(host.rpc_once(
                    "caller",
                    operation,
                    json!({"job_id":wire::new_id().unwrap()}),
                    None,
                    Some(host.config.peers[0].certificate_sha256.clone()),
                ));
                match phase {
                    0 => {
                        let _clock = host.clock.lock().await;
                        assert!(futures_util::poll!(request.as_mut()).is_pending());
                        assert!(host.pending.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
                        drop(request);
                    }
                    1 => {
                        let _cache = host.cache_lock.lock().await;
                        assert!(futures_util::poll!(request.as_mut()).is_pending());
                        assert_eq!(host.pending.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
                        drop(request);
                    }
                    _ => {
                        let frame = tokio::select! {
                            frame = observed.recv() => frame.unwrap(),
                            result = &mut request => panic!("RPC completed before response: {result:?}"),
                        };
                        durable_writes += usize::from(is_write(operation));
                        let path = bucket_dir(&host.config.state_dir, "relay-requests", operation)
                            .join(&frame.id);
                        let saved = fs::read(&path).unwrap();
                        if phase == 2 {
                            drop(request);
                            assert_eq!(fs::read(path).unwrap(), saved);
                        } else {
                            let mut response = RpcFrame {
                                v: frame.v,
                                kind: FrameKind::Response,
                                id: wire::new_id().unwrap(),
                                source: frame.target.clone(),
                                target: frame.source.clone(),
                                operation,
                                in_reply_to: Some(frame.id.clone()),
                                source_certificate_sha256: frame.target_certificate_sha256.clone(),
                                target_certificate_sha256: frame.source_certificate_sha256.clone(),
                                retention: None,
                                payload: String::new(),
                            };
                            host.codec
                                .encode(&mut response, &RpcReply::<Value>::failure("fixture", "fixture"))
                                .unwrap();
                            receive_response(&host, &response).await.unwrap();
                            let pending = host.pending.lock().unwrap_or_else(|e| e.into_inner())
                                .remove(&frame.id).unwrap();
                            pending.tx.send(Ok(response)).unwrap();
                            assert!(!request.await.unwrap().ok);
                            assert!(!path.exists());
                            assert!(bucket_dir(&host.config.state_dir, "relay-inbox", operation)
                                .join(&frame.id).exists());
                        }
                    }
                }
                assert!(host.pending.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
                assert_eq!(host.write_history.available_permits(), 100_000 - durable_writes);
            }
            assert!(phases.into_iter().all(|count| count > 0));
            assert_eq!(count_write_history(&host.config.state_dir).unwrap(), durable_writes);
            client.shutdown().await;
            server.abort();
            let _ = server.await;
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn local_scoped_quota_rejection_settles_binding_without_a_job() {
        use crate::executor::regression_tests::{retained_fixture_record, retention_fixture};
        let (_host_root, mut host) = fixture();
        let (root, mut config, empty_executor) = retention_fixture();
        drop(empty_executor);
        let checkout = root.path().join("checkout");
        fs::create_dir(&checkout).unwrap();
        let key_path = root.path().join("result.pk8");
        let signing = crate::provenance::SigningKey::generate(&key_path).unwrap();
        let trusted = signing.trusted_key();
        config.provenance = Some(crate::provenance::ResultSigningConfig {
            workspace: "workspace".into(),
            key_file: key_path,
            public_key: trusted.public_key.clone(),
        });
        config.repositories.insert(
            "repo".into(),
            crate::executor::RepositoryConfig {
                checkout,
                cloud: None,
                retention: Some(crate::retention::RetentionPolicy {
                    content_ttl_seconds: 3600,
                }),
            },
        );
        config.runners.insert("runner".into(),serde_json::from_value(json!({"program":"/bin/false","kind":"command","mcp_program":null,
            "container":{"runtime":"docker","runtime_program":"/bin/false","image":format!("sha256:{}","a".repeat(64)),
                "memory_mb":128,"cpu_millis":1000,"pids_limit":64,"network":"none","supply_chain":{
                    "attestation_file":root.path().join("attestation"),"sbom_file":root.path().join("sbom"),
                    "vulnerability_report_file":root.path().join("vulnerabilities"),"trusted_signers":[trusted],
                    "max_attestation_age_seconds":3600,"max_report_age_seconds":3600,"max_database_age_seconds":3600,
                    "max_critical":0,"max_high":0,"max_medium":0,"max_low":0,"max_unknown":0}}})).unwrap());
        config.limits.max_pending_jobs = 1;
        let executor = Executor::new(config.clone()).unwrap();
        let queued = retained_fixture_record(
            &executor,
            wire::JobState::Queued,
            wall_ms().unwrap() + 60_000,
        );
        host.config.executor = Some(config);
        host.executor = Some(executor.clone());
        let id = wire::new_id().unwrap();
        let spec = json!({"id":id,"repository":"repo","revision":"HEAD","runner":"runner",
            "arguments":[],"prompt":null,"timeout_seconds":null});
        let reply = host
            .rpc_bound(
                "worker",
                Operation::JobSubmit,
                spec,
                None,
                crate::incarnation::DispatchOrigin::Job(wire::new_id().unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(reply.error.unwrap().code, "job_queue_full");
        assert_eq!(executor.status(&id).unwrap_err().0, "job_not_found");
        assert_eq!(
            crate::incarnation::unresolved_dispatches(&host.config).unwrap(),
            0
        );
        assert!(crate::incarnation::offline_dispatch_guard(&host.config).is_ok());
        // A claimed local submission cannot be reviewed away while the actual
        // executor still knows a queued job with that ID.
        crate::incarnation::target_pin_bound(
            &host.config,
            "worker",
            Operation::JobSubmit,
            &serde_json::to_value(&queued.spec).unwrap(),
            None,
            &crate::incarnation::DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(
            crate::incarnation::local_submit::<()>(&host.config, &queued.spec, || Err(
                "executor_failed"
            ))
            .unwrap(),
            Err("executor_failed")
        );
        let listing = crate::incarnation::dispatch_control_with_local(
            &host.config,
            &host.certificate_sha256,
            crate::incarnation::DispatchControl::List {
                offset: 0,
                limit: 100,
            },
            wall_ms().unwrap(),
            None,
        )
        .unwrap();
        let entry = &listing["items"][0];
        let review = crate::incarnation::DispatchControl::Review {
            job_id: queued.spec.id.clone(),
            target: "worker".into(),
            certificate_sha256: host.certificate_sha256.clone(),
            source_certificate_sha256: Some(host.certificate_sha256.clone()),
            binding: entry["binding"].as_str().unwrap().into(),
            confirm_no_active_execution: true,
        };
        assert!(
            crate::incarnation::dispatch_control_with_local(
                &host.config,
                &host.certificate_sha256,
                review,
                wall_ms().unwrap(),
                Some(&|id| local_dispatch_stopped(&host.config, Some(&executor), id))
            )
            .is_err()
        );
        assert_eq!(
            crate::incarnation::unresolved_dispatches(&host.config).unwrap(),
            1
        );
        // A directory published before a failed admission is not visible in
        // executor memory but can contain a Queued journal on restart.
        let orphan = wire::new_id().unwrap();
        let jobs = &host
            .config
            .executor
            .as_ref()
            .unwrap()
            .state_dir
            .join("jobs");
        fs::create_dir(jobs.join(&orphan)).unwrap();
        assert_eq!(executor.status(&orphan).unwrap_err().0, "job_not_found");
        assert!(local_dispatch_stopped(&host.config, Some(&executor), &orphan).is_err());
        // A failed queued cancellation can change memory to terminal before
        // persistence fails, while restart still sees the durable Queued job.
        fs::create_dir(jobs.join(&queued.spec.id).join("record.json.tmp")).unwrap();
        let caller = Caller {
            node_id: "worker".into(),
            local_operator: true,
            certificate_sha256: Some(host.certificate_sha256.clone()),
        };
        assert!(executor.cancel(&queued.spec.id, &caller).is_err());
        assert_eq!(
            executor.status(&queued.spec.id).unwrap().state,
            wire::JobState::Cancelled
        );
        assert!(local_dispatch_stopped(&host.config, Some(&executor), &queued.spec.id).is_err());
    }
    #[tokio::test]
    async fn dispatch_requires_project_policy_before_binding_and_submit_header_before_cache() {
        let (_dir, mut host) = fixture();
        let id = wire::new_id().unwrap();
        assert!(
            host.rpc(
                "caller",
                Operation::JobSubmit,
                json!({"id":id,"repository":"unconfigured"})
            )
            .await
            .is_err()
        );
        assert!(!host.config.state_dir.join("incarnation-bindings").exists());
        host.config.peers[0]
            .allowed_operations
            .push(Operation::JobSubmit);
        let mut request = ping(&host);
        request.operation = Operation::JobSubmit;
        host.seal(&mut request, &json!({"id":id,"repository":"unconfigured"}))
            .unwrap();
        request.retention = None;
        host.codec
            .encode(&mut request, &json!({"id":id,"repository":"unconfigured"}))
            .unwrap();
        assert!(host.handle(request.clone(), false).await.is_err());
        assert!(
            !host
                .config
                .state_dir
                .join("responses-write")
                .join(&request.id)
                .exists()
        );
        assert!(
            !host
                .config
                .state_dir
                .join("request-tombstones-write")
                .join(&request.id)
                .exists()
        );
    }
    #[tokio::test]
    async fn cached_response_requires_authentication_with_the_current_workspace_key() {
        let (_dir, mut host) = fixture();
        let request = ping(&host);
        let first = host.handle(request.clone(), false).await.unwrap();
        assert_eq!(host.handle(request.clone(), false).await.unwrap(), first);
        host.codec =
            PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([98; 32])).unwrap();
        assert!(host.handle(request.clone(), false).await.is_err());
        assert!(
            host.config
                .state_dir
                .join("responses-read")
                .join(&request.id)
                .exists()
        );
    }
    #[tokio::test]
    async fn authenticated_wrong_target_incarnation_is_rejected_before_any_cache_write() {
        let (_dir, host) = fixture();
        let mut request = ping(&host);
        request.v = wire::PROTOCOL_VERSION;
        request.operation = Operation::JobCancel;
        host.seal(&mut request, &json!({"job_id":wire::new_id().unwrap()}))
            .unwrap();
        request.target_certificate_sha256 = Some("b".repeat(64));
        host.codec
            .encode(&mut request, &json!({"job_id":wire::new_id().unwrap()}))
            .unwrap();
        assert!(host.handle(request.clone(), true).await.is_err());
        assert!(
            !host
                .config
                .state_dir
                .join("responses-write")
                .join(&request.id)
                .exists()
        );
        assert!(
            !host
                .config
                .state_dir
                .join("request-tombstones-write")
                .join(&request.id)
                .exists()
        );
    }
    #[tokio::test]
    async fn expired_cached_content_becomes_durable_metadata_without_replaying_dispatch() {
        let (_dir, mut host) = fixture();
        host.config.peers[0]
            .allowed_operations
            .push(Operation::JobLog);
        let mut request = ping(&host);
        request.v = wire::PROTOCOL_VERSION;
        request.operation = Operation::JobLog;
        host.seal(
            &mut request,
            &json!({"job_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}),
        )
        .unwrap();
        let mut response = RpcFrame {
            v: wire::PROTOCOL_VERSION,
            kind: FrameKind::Response,
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            source: "worker".into(),
            target: "caller".into(),
            operation: Operation::JobLog,
            in_reply_to: Some(request.id.clone()),
            source_certificate_sha256: request.target_certificate_sha256.clone(),
            target_certificate_sha256: request.source_certificate_sha256.clone(),
            retention: Some(
                crate::retention::ContentRetention::for_copy(
                    &crate::retention::RetentionPolicy {
                        content_ttl_seconds: 60,
                    },
                    crate::retention::id_timestamp_ms("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap(),
                    None,
                )
                .unwrap(),
            ),
            payload: String::new(),
        };
        host.codec
            .encode(
                &mut response,
                &RpcReply::success(json!({"private":"content-sentinel"})),
            )
            .unwrap();
        let cache = host.config.state_dir.join("responses-read");
        host.cache_lock
            .lock()
            .await
            .store(
                &cache,
                &request.id,
                &Cached {
                    request_hash: request_hash(&request).unwrap(),
                    response: response.clone(),
                    content_erased: None,
                },
                frame_deadline(&response),
            )
            .unwrap();
        maintain_content_cache(&host).await.unwrap();
        let stored: Cached = serde_json::from_slice(
            &read_private(&cache.join(&request.id), (MAX_FRAME_BYTES * 2) as u64).unwrap(),
        )
        .unwrap();
        assert!(stored.content_erased.is_some());
        assert_ne!(stored.response.payload, response.payload);
        let reply: RpcReply<Value> = host.codec.decode(&stored.response).unwrap();
        assert_eq!(reply.error.unwrap().code, "response_content_expired");
        assert_eq!(
            host.handle(request.clone(), false).await.unwrap(),
            stored.response
        );
        assert!(!cache.join(response.id).exists());
    }
    #[tokio::test]
    async fn durable_cache_reuses_exact_ciphertext_and_rejects_conflicts() {
        let (_dir, mut host) = fixture();
        host.config.peers[0]
            .allowed_operations
            .push(Operation::JobSubmit);
        let frame = ping(&host);
        let first = host.handle(frame.clone(), false).await.unwrap();
        let second = host.handle(frame.clone(), false).await.unwrap();
        assert_eq!(first, second);
        let reply: RpcReply<Value> = host.codec.decode(&first).unwrap();
        assert_eq!(reply.result.unwrap()["node_id"], "worker");
        let mut conflict = frame.clone();
        host.seal(&mut conflict, &json!({"changed":true})).unwrap();
        assert!(host.handle(conflict, false).await.is_err());
        let mut crossed = frame.clone();
        crossed.operation = Operation::JobSubmit;
        host.seal(&mut crossed, &json!({})).unwrap();
        assert!(host.handle(crossed, false).await.is_err());
        let mut denied = frame.clone();
        denied.id = wire::new_id().unwrap();
        denied.operation = Operation::JobCancel;
        host.seal(&mut denied, &json!({})).unwrap();
        assert!(host.handle(denied, false).await.is_err());
        let mut tampered = first.clone();
        tampered.source = "attacker".into();
        assert!(host.decode_response(&frame, &tampered).is_err());
        let bytes = fs::read(host.config.state_dir.join("responses-read").join(&frame.id)).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("node_id"));
    }
    #[tokio::test]
    async fn concurrent_duplicate_requests_share_the_exact_response() {
        let (_dir, host) = fixture();
        let host = Arc::new(host);
        let frame = ping(&host);
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let host = host.clone();
            let frame = frame.clone();
            tasks.push(tokio::spawn(async move {
                host.handle(frame, false).await.unwrap()
            }));
        }
        let mut responses = Vec::new();
        for task in tasks {
            responses.push(task.await.unwrap());
        }
        assert!(responses.iter().all(|response| response == &responses[0]));
    }
    #[tokio::test]
    async fn late_response_is_correlated_and_durable_before_ack() {
        let (_dir, host) = fixture();
        let mut request = ping(&host);
        request.source = "worker".into();
        request.target = "caller".into();
        host.seal(&mut request, &json!({})).unwrap();
        let mut response = RpcFrame {
            v: 1,
            kind: FrameKind::Response,
            id: wire::new_id().unwrap(),
            source: "caller".into(),
            target: "worker".into(),
            operation: Operation::NodePing,
            in_reply_to: Some(request.id.clone()),
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        host.seal(
            &mut response,
            &RpcReply::success(json!({"node_id":"caller"})),
        )
        .unwrap();
        store_cache(
            &host.config.state_dir.join("relay-requests-read"),
            &request.id,
            &Cached {
                request_hash: String::new(),
                content_erased: None,
                response: request.clone(),
            },
        )
        .unwrap();
        let mut altered = response.clone();
        altered.operation = Operation::JobCancel;
        assert!(receive_response(&host, &altered).await.is_err());
        assert!(
            host.config
                .state_dir
                .join("relay-requests-read")
                .join(&request.id)
                .exists()
        );
        receive_response(&host, &response).await.unwrap();
        assert!(
            !host
                .config
                .state_dir
                .join("relay-requests-read")
                .join(&request.id)
                .exists()
        );
        assert!(
            host.config
                .state_dir
                .join("relay-inbox-read")
                .join(&request.id)
                .exists()
        );
        receive_response(&host, &response).await.unwrap();
        let mut different = response.clone();
        different.id = wire::new_id().unwrap();
        host.seal(&mut different, &RpcReply::success(json!({})))
            .unwrap();
        assert!(receive_response(&host, &different).await.is_err());
    }
    #[tokio::test]
    async fn delivery_failure_is_recorded_before_request_replay_stops() {
        let (_dir, host) = fixture();
        let mut request = ping(&host);
        request.source = "worker".into();
        request.target = "caller".into();
        host.seal(&mut request, &json!({})).unwrap();
        let dir = host.config.state_dir.join("relay-requests-read");
        store_cache(
            &dir,
            &request.id,
            &Cached {
                request_hash: String::new(),
                content_erased: None,
                response: request.clone(),
            },
        )
        .unwrap();
        receive_failure(&host, &request.id, "delivery_expired")
            .await
            .unwrap();
        assert!(!dir.join(&request.id).exists());
        let saved: Expired = serde_json::from_slice(
            &fs::read(
                host.config
                    .state_dir
                    .join("relay-expired-read")
                    .join(&request.id),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(saved.code, "delivery_expired");
        let mut expected_metadata = request.clone();
        expected_metadata.payload.clear();
        assert_eq!(saved.request, expected_metadata);
        assert!(saved.request.payload.is_empty());
        let mut response = RpcFrame {
            v: 1,
            kind: FrameKind::Response,
            id: wire::new_id().unwrap(),
            source: "caller".into(),
            target: "worker".into(),
            operation: Operation::NodePing,
            in_reply_to: Some(request.id.clone()),
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        host.seal(&mut response, &RpcReply::success(json!({})))
            .unwrap();
        receive_response(&host, &response).await.unwrap();
        assert!(
            host.config
                .state_dir
                .join("relay-inbox-read")
                .join(&request.id)
                .exists()
        );
        receive_failure(&host, &request.id, "delivery_expired")
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn full_outbox_applies_backpressure_before_dispatch() {
        let (_dir, host) = fixture();
        for _ in 0..OUTBOX_SLOTS {
            reserve_response(&host, &ping(&host)).await.unwrap();
        }
        assert_eq!(host.relay_slots.available_permits(), 0);
        assert_eq!(count_outbox(&host.config.state_dir).unwrap(), OUTBOX_SLOTS);
        assert_eq!(
            fs::read_dir(host.config.state_dir.join("relay-outbox"))
                .unwrap()
                .flatten()
                .filter(|e| wire::valid_ulid(&e.file_name().to_string_lossy()))
                .count(),
            OUTBOX_SLOTS
        );
        let extra = ping(&host);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), reserve_response(&host, &extra))
                .await
                .is_err()
        );
        assert_eq!(
            fs::read_dir(host.config.state_dir.join("relay-outbox"))
                .unwrap()
                .flatten()
                .filter(|e| wire::valid_ulid(&e.file_name().to_string_lossy()))
                .count(),
            OUTBOX_SLOTS
        );
    }
    #[tokio::test]
    async fn orphan_reservations_recover_slots_without_losing_conflict_protection() {
        let (_dir, mut host) = fixture();
        host.config.peers[0]
            .allowed_operations
            .push(Operation::JobSubmit);
        let mut requests = Vec::new();
        for _ in 0..OUTBOX_SLOTS {
            let request = ping(&host);
            reserve_response(&host, &request).await.unwrap();
            requests.push(request);
        }
        recover_empty_reservations(&host.config.state_dir, wall_ms().unwrap()).unwrap();
        assert_eq!(count_outbox(&host.config.state_dir).unwrap(), 0);
        assert_eq!(
            fs::read_dir(host.config.state_dir.join("request-tombstones-read"))
                .unwrap()
                .count(),
            OUTBOX_SLOTS
        );
        let mut changed = requests[0].clone();
        changed.operation = Operation::JobSubmit;
        host.seal(&mut changed, &json!({})).unwrap();
        assert!(host.handle(changed, false).await.is_err());
        // An identical redelivery is still allowed and goes through the normal handler.
        assert!(host.handle(requests[0].clone(), false).await.is_ok());
        // A conflicting reuse must not poison restart or permanently consume a slot.
        let mut bad = requests[0].clone();
        bad.operation = Operation::JobSubmit;
        host.seal(&mut bad, &json!({})).unwrap();
        let fresh_host = Arc::new(host);
        // Reconstruct available permits as a restarted host would.
        fresh_host.relay_slots.add_permits(OUTBOX_SLOTS);
        reserve_response(&fresh_host, &bad).await.unwrap();
        assert!(fresh_host.handle(bad.clone(), true).await.is_err());
        release_empty_reservation(&fresh_host, &bad.id)
            .await
            .unwrap();
        assert_eq!(count_outbox(&fresh_host.config.state_dir).unwrap(), 0);
    }
    #[tokio::test]
    async fn terminal_rejection_preserves_write_cache_before_releasing_slot() {
        let (_dir, host) = fixture();
        let mut request = ping(&host);
        request.operation = Operation::JobSubmit;
        host.seal(&mut request, &json!({})).unwrap();
        reserve_response(&host, &request).await.unwrap();
        let response = host.handle(request.clone(), true).await.unwrap();
        let outbox = host.config.state_dir.join("relay-outbox");
        let entry = OutboxEntry {
            request_id: request.id.clone(),
            request_hash: request_hash(&request).unwrap(),
            operation: request.operation,
            source: request.source.clone(),
            response: Some(response.clone()),
            accepted: false,
        };
        store_data(&outbox, &request.id, &serde_json::to_vec(&entry).unwrap()).unwrap();
        let cache = host.config.state_dir.join("responses-write");
        let saved = fs::read(cache.join(&request.id)).unwrap();
        fs::remove_file(cache.join(&request.id)).unwrap();
        assert!(
            retire_outbox_response(&host, &response.id, "response_mismatch")
                .await
                .is_err()
        );
        assert!(outbox.join(&request.id).exists());
        store_data(&cache, &request.id, &saved).unwrap();
        assert!(
            retire_outbox_response(&host, &response.id, "response_mismatch")
                .await
                .unwrap()
        );
        assert!(!outbox.join(&request.id).exists());
        assert_eq!(fs::read(cache.join(&request.id)).unwrap(), saved);
        assert_eq!(host.relay_slots.available_permits(), OUTBOX_SLOTS);
        let outcome: Undeliverable = serde_json::from_slice(
            &fs::read(
                host.config
                    .state_dir
                    .join("relay-undeliverable-write")
                    .join(&request.id),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(outcome.reason, "response_mismatch");
        assert_eq!(host.status().relay_undeliverable, Some(1));
    }
    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn full_outbox_replay_visits_every_persisted_response() {
        let _port = PORT_5221.lock().await;
        use futures_util::StreamExt;
        use tokio_tungstenite::{
            accept_hdr_async,
            tungstenite::{
                Message,
                handshake::server::{Request, Response},
            },
        };
        tokio::time::timeout(Duration::from_secs(12), async {
            let (_dir, host) = fixture();
            let mut ids = HashSet::new();
            for _ in 0..OUTBOX_SLOTS {
                let request = ping(&host);
                reserve_response(&host, &request).await.unwrap();
                let mut response = RpcFrame {
                    v: 1,
                    kind: FrameKind::Response,
                    id: wire::new_id().unwrap(),
                    source: "worker".into(),
                    target: "caller".into(),
                    operation: Operation::NodePing,
                    in_reply_to: Some(request.id.clone()),
                    source_certificate_sha256: None,
                    target_certificate_sha256: None,
                    retention: None,
                    payload: String::new(),
                };
                host.seal(&mut response, &RpcReply::success(json!({})))
                    .unwrap();
                ids.insert(response.id.clone());
                let entry = OutboxEntry {
                    request_id: request.id.clone(),
                    request_hash: request_hash(&request).unwrap(),
                    operation: request.operation,
                    source: request.source.clone(),
                    response: Some(response),
                    accepted: false,
                };
                store_data(
                    &host.config.state_dir.join("relay-outbox"),
                    &request.id,
                    &serde_json::to_vec(&entry).unwrap(),
                )
                .unwrap();
            }
            assert_eq!(count_outbox(&host.config.state_dir).unwrap(), OUTBOX_SLOTS);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:5221")
                .await
                .unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |_request: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "lockyard-node.v1".parse().unwrap(),
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();
                let mut observed = HashSet::new();
                while observed.len() < OUTBOX_SLOTS {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Frame(frame) => {
                                observed.insert(frame.id);
                            }
                            _ => panic!("request ACK before broker acceptance"),
                        }
                    }
                }
                assert_eq!(observed, ids);
            });
            let client = RelayClient::spawn(
                RelayConfig::new("http://127.0.0.1:5221", "worker".into(), "test".into()).unwrap(),
            )
            .unwrap();
            let mut sender = client.sender();
            sender.wait_connected(Duration::from_secs(4)).await.unwrap();
            replay_cached(&host, &sender).await;
            server.await.unwrap();
            client.shutdown().await;
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn restart_replays_accepted_ack_without_resending_or_losing_outcome() {
        let _port = PORT_5221.lock().await;
        use futures_util::StreamExt;
        use tokio_tungstenite::{
            accept_hdr_async,
            tungstenite::{
                Message,
                handshake::server::{Request, Response},
            },
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            let (_dir, host) = fixture();
            let request = ping(&host);
            reserve_response(&host, &request).await.unwrap();
            let response = host.handle(request.clone(), true).await.unwrap();
            let entry = OutboxEntry {
                request_id: request.id.clone(),
                request_hash: request_hash(&request).unwrap(),
                operation: request.operation,
                source: request.source.clone(),
                response: Some(response.clone()),
                accepted: false,
            };
            store_data(
                &host.config.state_dir.join("relay-outbox"),
                &request.id,
                &serde_json::to_vec(&entry).unwrap(),
            )
            .unwrap();
            assert_eq!(
                accept_response(&host, &response.id).await.unwrap(),
                Some(request.id.clone())
            );
            let config = host.config.clone();
            let certificate_sha256 = host.certificate_sha256.clone();
            drop(host);
            let lock = lock_state(&config.state_dir).unwrap();
            let clock = ClockState::load(&config.state_dir).unwrap();
            recover_empty_reservations(&config.state_dir, clock.effective_ms).unwrap();
            let occupied = count_outbox(&config.state_dir).unwrap();
            assert_eq!(occupied, 1);
            let cache_budget = CacheBudget::load(&config.state_dir).unwrap();
            let history = count_write_history(&config.state_dir).unwrap();
            let host = Host {
                _lock: lock,
                certificate_sha256,
                config,
                codec: PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32]))
                    .unwrap(),
                executor: None,
                workflow: None,
                direct: None,
                revocations: None,
                relay: None,
                pending: std::sync::Mutex::new(HashMap::new()),
                request_locks: (0..64).map(|_| Mutex::new(())).collect(),
                cache_lock: Mutex::new(cache_budget),
                permits: Arc::new(Semaphore::new(128)),
                connections: Arc::new(Semaphore::new(128)),
                delegation_connections: Arc::new(Semaphore::new(64)),
                relay_slots: Arc::new(Semaphore::new(OUTBOX_SLOTS - occupied)),
                relay_ingress: Arc::new(Semaphore::new(1024)),
                relay_inflight: Mutex::new(HashSet::new()),
                invalid_requests: AtomicU64::new(0),
                invalid_responses: AtomicU64::new(0),
                conflicting_responses: AtomicU64::new(0),
                retention_cleanup_failed: std::sync::atomic::AtomicBool::new(false),
                operator_draining: std::sync::atomic::AtomicBool::new(false),
                relay_acks: Arc::new(Semaphore::new(16)),
                write_history: Arc::new(Semaphore::new(100_000 - history)),
                clock: Mutex::new(clock),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:5221")
                .await
                .unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |_request: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "lockyard-node.v1".parse().unwrap(),
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();
                loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Control(RelayControl::Ack { id, .. }) => {
                                assert_eq!(id, request.id);
                                break;
                            }
                            _ => panic!("accepted response must not be retransmitted"),
                        }
                    }
                }
            });
            let client = RelayClient::spawn(
                RelayConfig::new("http://127.0.0.1:5221", "worker".into(), "test".into()).unwrap(),
            )
            .unwrap();
            let mut sender = client.sender();
            sender.wait_connected(Duration::from_secs(3)).await.unwrap();
            replay_cached(&host, &sender).await;
            server.await.unwrap();
            assert_eq!(count_outbox(&host.config.state_dir).unwrap(), 0);
            assert_eq!(host.relay_slots.available_permits(), OUTBOX_SLOTS);
            client.shutdown().await;
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn stale_offline_request_expires_and_detected_clock_rollback_blocks_replay() {
        let (_dir, host) = fixture();
        let mut request = ping(&host);
        request.source = "worker".into();
        request.target = "caller".into();
        // The zero timestamp is valid ULID syntax but older than the delivery lifetime.
        request.id.replace_range(..10, "0000000000");
        host.seal(&mut request, &json!({})).unwrap();
        let dir = host.config.state_dir.join("relay-requests-read");
        store_cache(
            &dir,
            &request.id,
            &Cached {
                request_hash: String::new(),
                content_erased: None,
                response: request.clone(),
            },
        )
        .unwrap();
        let client = RelayClient::spawn(
            RelayConfig::new("http://127.0.0.1:0", "worker".into(), "test".into()).unwrap(),
        )
        .unwrap();
        host.clock.lock().await.last_wall_ms = wall_ms().unwrap() + 60_000;
        replay_requests(&host, &client.sender(), true).await;
        assert!(dir.join(&request.id).exists());
        host.clock.lock().await.last_wall_ms = wall_ms().unwrap();
        replay_requests(&host, &client.sender(), true).await;
        assert!(!dir.join(&request.id).exists());
        assert!(
            host.config
                .state_dir
                .join("relay-expired-read")
                .join(&request.id)
                .exists()
        );
        store_data(
            &host.config.state_dir,
            "clock-floor",
            (wall_ms().unwrap() + 60_000).to_string().as_bytes(),
        )
        .unwrap();
        assert!(ClockState::load(&host.config.state_dir).is_err());
        client.shutdown().await;
    }
    #[tokio::test]
    #[allow(clippy::result_large_err, clippy::collapsible_if)]
    async fn relay_retries_rejected_response_without_early_request_ack() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::{
            accept_hdr_async,
            tungstenite::{
                Message,
                handshake::server::{Request, Response},
            },
        };
        tokio::time::timeout(Duration::from_secs(12), async {
            let (_dir, mut host) = fixture();
            host.config.peers.clear();
            let host = Arc::new(host);
            let request = ping(&host);
            assert!(host.handle(request.clone(), false).await.is_err());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:5220")
                .await
                .unwrap();
            let failing_request = ping(&host);
            let wrong_codec =
                PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([8; 32])).unwrap();
            let mut poison = Vec::new();
            for _ in 0..16 {
                let mut frame = ping(&host);
                wrong_codec.encode(&mut frame, &json!({})).unwrap();
                poison.push(frame);
            }
            let blocked_host = host.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |_request: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "lockyard-node.v1".parse().unwrap(),
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();
                let poison_ids: HashSet<_> = poison.iter().map(|frame| frame.id.clone()).collect();
                for frame in poison {
                    socket
                        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
                        .await
                        .unwrap();
                }
                let mut rejected = HashSet::new();
                while rejected.len() < 16 {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Control(RelayControl::Ack { id, .. })
                                if poison_ids.contains(&id) =>
                            {
                                rejected.insert(id);
                            }
                            RelayMessage::Frame(frame)
                                if frame
                                    .in_reply_to
                                    .as_ref()
                                    .is_some_and(|id| poison_ids.contains(id)) =>
                            {
                                panic!("poison request was dispatched")
                            }
                            _ => {}
                        }
                    }
                }
                assert_eq!(blocked_host.invalid_requests.load(Ordering::Relaxed), 16);
                for id in poison_ids {
                    assert!(
                        !blocked_host
                            .config
                            .state_dir
                            .join("responses-read")
                            .join(id)
                            .exists()
                    );
                }
                socket
                    .send(Message::Text(
                        serde_json::to_string(&request).unwrap().into(),
                    ))
                    .await
                    .unwrap();
                let first = loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        if let Ok(RelayMessage::Frame(frame)) = serde_json::from_str(&text) {
                            break frame;
                        }
                    }
                };
                socket
                    .send(Message::Text(
                        serde_json::to_string(&RelayControl::Error {
                            v: 1,
                            id: Some(first.id.clone()),
                            code: "backlog_full".into(),
                            message: "queue full".into(),
                        })
                        .unwrap()
                        .into(),
                    ))
                    .await
                    .unwrap();
                let retry = loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Frame(frame) => break frame,
                            RelayMessage::Control(RelayControl::Ack { id, .. })
                                if id == request.id =>
                            {
                                panic!("request ACK preceded broker acceptance")
                            }
                            _ => {}
                        }
                    }
                };
                assert_eq!(first, retry);
                socket
                    .send(Message::Text(
                        serde_json::to_string(&RelayControl::Ack {
                            v: 1,
                            id: first.id.clone(),
                        })
                        .unwrap()
                        .into(),
                    ))
                    .await
                    .unwrap();
                loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        if let RelayMessage::Control(RelayControl::Ack { id, .. }) =
                            serde_json::from_str(&text).unwrap()
                        {
                            if id == request.id {
                                break;
                            }
                        }
                    }
                }
                // Force durable reservation creation to fail, and verify no work or ACK.
                let blocked_id = failing_request.id.clone();
                fs::write(
                    blocked_host
                        .config
                        .state_dir
                        .join("relay-outbox")
                        .join(format!(".{blocked_id}.tmp")),
                    b"block",
                )
                .unwrap();
                socket
                    .send(Message::Text(
                        serde_json::to_string(&failing_request).unwrap().into(),
                    ))
                    .await
                    .unwrap();
                loop {
                    match socket.next().await {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                                RelayMessage::Frame(frame)
                                    if frame.in_reply_to.as_deref() == Some(&blocked_id) =>
                                {
                                    panic!("dispatched despite failed storage")
                                }
                                RelayMessage::Control(RelayControl::Ack { id, .. })
                                    if id == blocked_id =>
                                {
                                    panic!("acknowledged despite failed storage")
                                }
                                _ => {}
                            }
                        }
                        Some(Ok(Message::Ping(bytes))) => {
                            let _ = socket.send(Message::Pong(bytes)).await;
                        }
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        _ => {}
                    }
                }
                assert!(
                    !blocked_host
                        .config
                        .state_dir
                        .join("responses-read")
                        .join(&blocked_id)
                        .exists()
                );
                fs::remove_file(
                    blocked_host
                        .config
                        .state_dir
                        .join("relay-outbox")
                        .join(format!(".{blocked_id}.tmp")),
                )
                .unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |_request: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "lockyard-node.v1".parse().unwrap(),
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();
                // Re-delivery after reconnect is reauthenticated by the real broker.
                socket
                    .send(Message::Text(
                        serde_json::to_string(&failing_request).unwrap().into(),
                    ))
                    .await
                    .unwrap();
                let recovered = loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Frame(frame)
                                if frame.in_reply_to.as_deref() == Some(&blocked_id) =>
                            {
                                break frame;
                            }
                            RelayMessage::Control(RelayControl::Ack { id, .. })
                                if id == blocked_id =>
                            {
                                panic!("early request ACK after reconnect")
                            }
                            _ => {}
                        }
                    }
                };
                socket
                    .send(Message::Text(
                        serde_json::to_string(&RelayControl::Ack {
                            v: 1,
                            id: recovered.id,
                        })
                        .unwrap()
                        .into(),
                    ))
                    .await
                    .unwrap();
                loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        if let RelayMessage::Control(RelayControl::Ack { id, .. }) =
                            serde_json::from_str(&text).unwrap()
                        {
                            if id == blocked_id {
                                break;
                            }
                        }
                    }
                }
            });
            let client = RelayClient::spawn(
                RelayConfig::new("http://127.0.0.1:5220", "worker".into(), "test".into()).unwrap(),
            )
            .unwrap();
            let task = tokio::spawn(relay_loop(host.clone(), client));
            server.await.unwrap();
            task.abort();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    #[cfg(unix)]
    async fn read_cache_churn_reclaims_space_and_keeps_operation_tombstones() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, mut host) = fixture();
        host.config.peers[0]
            .allowed_operations
            .push(Operation::JobSubmit);
        let original = ping(&host);
        host.handle(original.clone(), false).await.unwrap();
        let dir = host.config.state_dir.join("responses-read");
        let source = dir.join(&original.id);
        for _ in 0..10_000 {
            let id = wire::new_id().unwrap();
            fs::hard_link(&source, dir.join(id)).unwrap();
        }
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        // The fixture arranged files outside the host; rebuild the startup index as
        // a restart would, then exercise the ordinary pressure/replay path.
        *host.cache_lock.lock().await = CacheBudget::load(&host.config.state_dir).unwrap();
        host.handle(ping(&host), false).await.unwrap();
        assert!(fs::read_dir(&dir).unwrap().count() < 10_000);
        let id = fs::read_dir(host.config.state_dir.join("read-tombstones"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name()
            .into_string()
            .unwrap();
        let mut write = ping(&host);
        write.id = id;
        write.operation = Operation::JobSubmit;
        host.seal(&mut write, &json!({})).unwrap();
        assert!(host.handle(write, false).await.is_err());
    }
    #[tokio::test]
    async fn failed_read_reservations_recover_without_stalling_or_weakening_replay() {
        let (_dir, host) = fixture();
        let original = ping(&host);
        let first = host.handle(original.clone(), false).await.unwrap();
        let mut invalid = ping(&host);
        PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([99; 32]))
            .unwrap()
            .encode(&mut invalid, &json!({}))
            .unwrap();
        assert!(host.handle(invalid, false).await.is_err());
        assert_eq!(
            fs::read_dir(host.config.state_dir.join("responses-read"))
                .unwrap()
                .count(),
            1
        );
        // Failed requests may reserve conservatively. A pressure scan reconciles
        // actual durable files; it must not turn that estimate into permanent refusal.
        host.cache_lock.lock().await.read_responses = 10_000;
        host.handle(ping(&host), false).await.unwrap();
        let rebuilt = CacheBudget::load(&host.config.state_dir).unwrap();
        assert_eq!(rebuilt.read_responses, 2);
        *host.cache_lock.lock().await = rebuilt;
        assert_eq!(host.handle(original, false).await.unwrap(), first);
        assert_eq!(
            CacheBudget::load(&host.config.state_dir)
                .unwrap()
                .read_responses,
            2
        );
    }
    #[tokio::test]
    async fn unknown_read_reply_is_discarded_only_after_authentication_and_never_matches_pending_write()
     {
        let (_dir, host) = fixture();
        let mut response = RpcFrame {
            v: 1,
            kind: FrameKind::Response,
            id: wire::new_id().unwrap(),
            source: "caller".into(),
            target: "worker".into(),
            operation: Operation::NodePing,
            in_reply_to: Some(wire::new_id().unwrap()),
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        host.seal(&mut response, &RpcReply::success(json!({})))
            .unwrap();
        assert!(discardable_read_response(&host, &response).await);
        let mut tampered = response.clone();
        tampered.target = "other".into();
        assert!(!discardable_read_response(&host, &tampered).await);
        let mut tampered = response.clone();
        tampered.source = "other".into();
        assert!(!discardable_read_response(&host, &tampered).await);
        let mut tampered = response.clone();
        tampered.operation = Operation::JobSubmit;
        assert!(!discardable_read_response(&host, &tampered).await);
        let (tx, _rx) = oneshot::channel();
        host.pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                response.in_reply_to.clone().unwrap(),
                PendingResponse { tx },
            );
        assert!(!discardable_read_response(&host, &response).await);
    }
    #[tokio::test]
    #[allow(clippy::result_large_err, clippy::collapsible_if)]
    async fn poison_responses_do_not_starve_or_complete_pending_write() {
        let _port = PORT_5221.lock().await;
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::{
            accept_hdr_async,
            tungstenite::{
                Message,
                handshake::server::{Request, Response},
            },
        };
        tokio::time::timeout(Duration::from_secs(12), async {
            let (_dir, host) = fixture();
            let host = Arc::new(host);
            let mut request = ping(&host);
            request.source = "worker".into();
            request.target = "caller".into();
            request.operation = Operation::JobSubmit;
            host.seal(&mut request, &json!({})).unwrap();
            store_cache(
                &host.config.state_dir.join("relay-requests-write"),
                &request.id,
                &Cached {
                    request_hash: String::new(),
                    content_erased: None,
                    response: request.clone(),
                },
            )
            .unwrap();
            let (tx, rx) = oneshot::channel();
            host.pending
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(request.id.clone(), PendingResponse { tx });
            let wrong_codec =
                PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([8; 32])).unwrap();
            let make_response = |id: String| RpcFrame {
                v: wire::PROTOCOL_VERSION,
                kind: FrameKind::Response,
                id,
                source: "caller".into(),
                target: "worker".into(),
                operation: Operation::JobSubmit,
                in_reply_to: Some(request.id.clone()),
                source_certificate_sha256: request.target_certificate_sha256.clone(),
                target_certificate_sha256: request.source_certificate_sha256.clone(),
                retention: request.retention.clone(),
                payload: String::new(),
            };
            let mut poison = Vec::new();
            for _ in 0..16 {
                let mut response = make_response(wire::new_id().unwrap());
                wrong_codec
                    .encode(&mut response, &RpcReply::success(json!({})))
                    .unwrap();
                poison.push(response);
            }
            let mut wrong_source = poison[0].clone();
            wrong_source.source = "other".into();
            wrong_codec
                .encode(&mut wrong_source, &RpcReply::success(json!({})))
                .unwrap();
            assert!(!reject_invalid_response(&host, &wrong_source).await.unwrap());
            let blocked = host
                .config
                .state_dir
                .join("relay-invalid-responses-write")
                .join(format!(".{}.tmp", request.id));
            fs::write(&blocked, b"block").unwrap();
            assert!(reject_invalid_response(&host, &poison[0]).await.is_err());
            assert!(
                host.pending
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .contains_key(&request.id)
            );
            assert!(
                host.config
                    .state_dir
                    .join("relay-requests-write")
                    .join(&request.id)
                    .exists()
            );
            fs::remove_file(blocked).unwrap();
            let mut valid = make_response(wire::new_id().unwrap());
            host.seal(&mut valid, &RpcReply::success(json!({"state":"queued"})))
                .unwrap();
            let mut conflicts = Vec::new();
            for _ in 0..16 {
                let mut frame = make_response(wire::new_id().unwrap());
                host.seal(
                    &mut frame,
                    &RpcReply::success(json!({"state":"conflicting"})),
                )
                .unwrap();
                conflicts.push(frame);
            }
            let unrelated = ping(&host);
            let worker = host.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:5221")
                .await
                .unwrap();
            let server_request = request.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket =
                    accept_hdr_async(stream, |_request: &Request, mut response: Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            "lockyard-node.v1".parse().unwrap(),
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();
                let ids: HashSet<_> = poison.iter().map(|frame| frame.id.clone()).collect();
                for frame in poison {
                    socket
                        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
                        .await
                        .unwrap();
                }
                let mut acknowledged = HashSet::new();
                while acknowledged.len() < 16 {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        if let RelayMessage::Control(RelayControl::Ack { id, .. }) =
                            serde_json::from_str(&text).unwrap()
                        {
                            if ids.contains(&id) {
                                acknowledged.insert(id);
                            }
                        }
                    }
                }
                assert!(
                    worker
                        .pending
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .contains_key(&server_request.id)
                );
                assert!(
                    worker
                        .config
                        .state_dir
                        .join("relay-requests-write")
                        .join(&server_request.id)
                        .exists()
                );
                let record: InvalidResponse = serde_json::from_slice(
                    &fs::read(
                        worker
                            .config
                            .state_dir
                            .join("relay-invalid-responses-write")
                            .join(&server_request.id),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(record.count, 16);
                socket
                    .send(Message::Text(serde_json::to_string(&valid).unwrap().into()))
                    .await
                    .unwrap();
                loop {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        if let RelayMessage::Control(RelayControl::Ack { id, .. }) =
                            serde_json::from_str(&text).unwrap()
                        {
                            if id == valid.id {
                                break;
                            }
                        }
                    }
                }
                let conflict_ids: HashSet<_> =
                    conflicts.iter().map(|frame| frame.id.clone()).collect();
                for frame in conflicts {
                    socket
                        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
                        .await
                        .unwrap();
                }
                socket
                    .send(Message::Text(
                        serde_json::to_string(&unrelated).unwrap().into(),
                    ))
                    .await
                    .unwrap();
                let mut acknowledged_conflicts = HashSet::new();
                let mut unrelated_reply = None;
                while acknowledged_conflicts.len() < 16 || unrelated_reply.is_none() {
                    if let Some(Ok(Message::Text(text))) = socket.next().await {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Control(RelayControl::Ack { id, .. })
                                if conflict_ids.contains(&id) =>
                            {
                                acknowledged_conflicts.insert(id);
                            }
                            RelayMessage::Frame(frame)
                                if frame.in_reply_to.as_deref() == Some(&unrelated.id) =>
                            {
                                unrelated_reply = Some(frame)
                            }
                            _ => {}
                        }
                    }
                }
                let original: Receipt = serde_json::from_slice(
                    &fs::read(
                        worker
                            .config
                            .state_dir
                            .join("relay-inbox-write")
                            .join(&server_request.id),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(original.response, valid);
                let conflicts: InvalidResponse = serde_json::from_slice(
                    &fs::read(
                        worker
                            .config
                            .state_dir
                            .join("relay-conflicting-responses-write")
                            .join(&server_request.id),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(conflicts.count, 16);
                socket
                    .send(Message::Text(
                        serde_json::to_string(&RelayControl::Ack {
                            v: 1,
                            id: unrelated_reply.unwrap().id,
                        })
                        .unwrap()
                        .into(),
                    ))
                    .await
                    .unwrap();
            });
            let client = RelayClient::spawn(
                RelayConfig::new("http://127.0.0.1:5221", "worker".into(), "test".into()).unwrap(),
            )
            .unwrap();
            let task = tokio::spawn(relay_loop(host.clone(), client));
            let received = rx.await.unwrap().unwrap();
            assert_eq!(
                host.decode_response(&request, &received)
                    .unwrap()
                    .result
                    .unwrap()["state"],
                "queued"
            );
            server.await.unwrap();
            task.abort();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn delayed_write_responses_remain_correlated_after_receipt_pressure_gc() {
        let (_dir, host) = fixture();
        let mut request = ping(&host);
        request.source = "worker".into();
        request.target = "caller".into();
        request.operation = Operation::JobSubmit;
        host.seal(&mut request, &json!({"private":"request"}))
            .unwrap();
        store_cache(
            &host.config.state_dir.join("relay-requests-write"),
            &request.id,
            &Cached {
                request_hash: String::new(),
                content_erased: None,
                response: request.clone(),
            },
        )
        .unwrap();
        let mut first = RpcFrame {
            v: 1,
            kind: FrameKind::Response,
            id: wire::new_id().unwrap(),
            source: "caller".into(),
            target: "worker".into(),
            operation: Operation::JobSubmit,
            in_reply_to: Some(request.id.clone()),
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        host.seal(&mut first, &RpcReply::success(json!({"state":"queued"})))
            .unwrap();
        receive_response(&host, &first).await.unwrap();
        let inbox = host.config.state_dir.join("relay-inbox-write");
        let path = inbox.join(&request.id);
        let old = SystemTime::now() - Duration::from_secs(8 * 24 * 60 * 60 + 60);
        File::open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old))
            .unwrap();
        ensure_capacity_limit(&inbox, Operation::JobSubmit, true, 1).unwrap();
        assert!(!path.exists());
        let completed_path = host
            .config
            .state_dir
            .join("relay-completed-writes")
            .join(&request.id);
        let bytes = fs::read(&completed_path).unwrap();
        let completed: CompletedReceipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(completed.response_id, first.id);
        assert_eq!(completed.response_hash, request_hash(&first).unwrap());
        assert!(!String::from_utf8_lossy(&bytes).contains(&request.payload));
        assert!(!String::from_utf8_lossy(&bytes).contains(&first.payload));
        assert!(record_conflicting_response(&host, &first).await.unwrap());
        let mut valid = first.clone();
        valid.id = wire::new_id().unwrap();
        host.seal(&mut valid, &RpcReply::success(json!({"state":"different"})))
            .unwrap();
        assert!(record_conflicting_response(&host, &valid).await.unwrap());
        let mut wrong = first.clone();
        wrong.id = wire::new_id().unwrap();
        PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([8; 32]))
            .unwrap()
            .encode(&mut wrong, &RpcReply::success(json!({})))
            .unwrap();
        assert!(reject_invalid_response(&host, &wrong).await.unwrap());
        let mut wrong_source = wrong.clone();
        wrong_source.source = "other".into();
        assert!(!reject_invalid_response(&host, &wrong_source).await.unwrap());
        let mut wrong_operation = wrong.clone();
        wrong_operation.operation = Operation::JobCancel;
        assert!(
            !reject_invalid_response(&host, &wrong_operation)
                .await
                .unwrap()
        );
        assert!(
            host.pending
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
        assert!(
            !host
                .config
                .state_dir
                .join("relay-requests-write")
                .join(&request.id)
                .exists()
        );
        assert_eq!(fs::read(&completed_path).unwrap(), bytes);
    }
    #[tokio::test]
    async fn direct_revocation_takes_effect_after_server_stop_and_restart() {
        use crate::quic::{DirectClient, DirectServer, Identity};
        tokio::time::timeout(Duration::from_secs(8), async {
            let make_pair = || {
                let pair =
                    rcgen::generate_simple_self_signed(vec!["lockyard-node".into()]).unwrap();
                (pair.cert.der().to_vec(), pair.signing_key.serialize_der())
            };
            let identity = |pair: &(Vec<u8>, Vec<u8>)| {
                Identity::from_der(vec![pair.0.clone()], pair.1.clone()).unwrap()
            };
            let policy = |name: &str, cert: &[u8]| PeerPolicy {
                node_id: name.into(),
                certificate_sha256: PeerPin::certificate(cert).to_hex(),
                allowed_operations: vec![Operation::NodePing],
            };
            let server_pair = make_pair();
            let old_pair = make_pair();
            let other_pair = make_pair();
            let roots = vec![old_pair.0.clone(), other_pair.0.clone()];
            let server = DirectServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                "worker".into(),
                identity(&server_pair),
                roots.clone(),
                vec![policy("caller", &old_pair.0)],
            )
            .unwrap();
            let client = DirectClient::bind(
                "127.0.0.1:0".parse().unwrap(),
                "caller".into(),
                identity(&old_pair),
                vec![server_pair.0.clone()],
            )
            .unwrap();
            let first_address = server.local_addr().unwrap();
            let accepting = tokio::spawn(async move {
                let connection = server.accept().await.unwrap();
                server.close();
                connection
            });
            let connection = client
                .connect(
                    first_address,
                    "lockyard-node",
                    policy("worker", &server_pair.0),
                )
                .await
                .unwrap();
            let accepted = accepting.await.unwrap();
            drop(accepted);
            assert!(connection.rpc(&ping(&fixture().1)).await.is_err());
            let server = DirectServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                "worker".into(),
                identity(&server_pair),
                roots,
                vec![policy("other", &other_pair.0)],
            )
            .unwrap();
            let second_address = server.local_addr().unwrap();
            let accepting = tokio::spawn(async move { server.accept().await.is_err() });
            let fresh = DirectClient::bind(
                "127.0.0.1:0".parse().unwrap(),
                "caller".into(),
                identity(&old_pair),
                vec![server_pair.0.clone()],
            )
            .unwrap();
            if let Ok(connection) = fresh
                .connect(
                    second_address,
                    "lockyard-node",
                    policy("worker", &server_pair.0),
                )
                .await
            {
                assert!(connection.rpc(&ping(&fixture().1)).await.is_err());
            }
            assert!(accepting.await.unwrap());
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn local_socket_authenticates_and_rejects_unsafe_paths() {
        let (dir, host) = fixture();
        let host = Arc::new(host);
        let path = host.config.socket_path();
        let listener = make_socket(&path).unwrap();
        let running = host.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            control_connection(running, stream).await.unwrap();
        });
        let value = call_control(
            &path,
            Control::Rpc {
                target: "worker".into(),
                operation: Operation::NodePing,
                payload: Value::Null,
            },
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let reply: RpcReply<Value> = serde_json::from_value(value).unwrap();
        assert!(reply.ok);
        task.await.unwrap();
        fs::remove_file(&path).unwrap();
        symlink(dir.path().join("victim"), &path).unwrap();
        assert!(make_socket(&path).is_err());
    }
    #[test]
    fn config_is_private_and_peer_pins_are_verified() {
        let (dir, host) = fixture();
        let path = dir.path().join("config.toml");
        fs::write(&path, toml::to_string(&host.config).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(NodeConfig::load(&path).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(NodeConfig::load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&host.config.peers[0].certificate, b"changed").unwrap();
        assert!(NodeConfig::load(&path).is_err());
    }
}

#[cfg(all(test, unix))]
#[path = "host_revocations_tests.rs"]
mod revocation_negotiation_tests;

#[cfg(all(test, unix))]
#[path = "host_revocations_race_tests.rs"]
mod revocation_connect_race_tests;
