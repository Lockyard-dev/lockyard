// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Opt-in container execution with durable job identity and isolated Git metadata.

use crate::provenance::{ArtifactDigest, ResultManifest, ResultSigningConfig, SigningKey};
use crate::retention::{self, JobTombstone, RetentionPolicy, RetentionSnapshot};
use crate::supply_chain::{SupplyChainPolicy, VerifiedImage};
use crate::wire::{JobRecord, JobSpec, JobState, LogChunk};
use lockyard_cloud_client::WorkspaceKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, ExecutorError>;
/// Shared artifact contract: clients must accept this bound and reject incomplete patches.
pub const MAX_PATCH_BYTES: u64 = 128 * 1024 * 1024;

/// Fingerprint configured references and policy, never resolved secret values.
pub fn admission_fingerprint<T: Serialize>(config: &T) -> Result<String> {
    let bytes =
        serde_json::to_vec(config).map_err(|_| ExecutorError("admission_fingerprint_failed"))?;
    Ok(crate::provenance::sha256(&bytes))
}

/// Stable error codes deliberately omit argv, prompts, credentials and child stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorError(pub &'static str);
impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ExecutorError {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorConfig {
    pub node_id: String,
    /// Workspace admission policy; only trusted node configuration can set this.
    #[serde(default)]
    pub external_actions: ExternalActionsPolicy,
    /// Authenticated local TLS incarnation, populated by NodeHost; not user-settable in TOML.
    #[serde(skip)]
    pub node_certificate_sha256: Option<String>,
    pub state_dir: PathBuf,
    pub repositories: BTreeMap<String, RepositoryConfig>,
    pub runners: BTreeMap<String, RunnerProfile>,
    pub provenance: Option<ResultSigningConfig>,
    /// Populated by the trusted node host before journal recovery; never configurable via TOML.
    #[serde(skip)]
    pub protected_identity_files: Vec<PathBuf>,
    #[serde(default)]
    pub limits: ExecutionLimits,
    #[serde(default)]
    pub scheduling: crate::scheduler::NodeScheduling,
}

/// External workloads always require an owner signature. Deny additionally forbids
/// a networked workload from receiving any configured credentials, even when signed.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalActionsPolicy {
    #[default]
    RequireApproval,
    Deny,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    pub checkout: PathBuf,
    pub cloud: Option<CloudConfig>,
    pub retention: Option<crate::retention::RetentionPolicy>,
}

/// Only non-secret endpoint metadata and a reference to an existing private token file.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudConfig {
    pub url: String,
    pub workspace: String,
    pub repository: String,
    pub token_file: Option<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerProfile {
    #[serde(default)]
    pub action: crate::approvals::ManagedAction,
    /// Independently authenticated customer-owner keys; never inferred from workspace membership.
    #[serde(default)]
    pub owner_approval_authorities: Vec<crate::provenance::TrustedSigningKey>,
    pub container: ContainerProfile,
    pub program: PathBuf,
    #[serde(default)]
    pub kind: RunnerKind,
    /// For Codex, the installed Lockyard executable used by the per-invocation MCP server.
    pub mcp_program: Option<PathBuf>,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    /// No ambient secrets are inherited unless this local allowlist names them.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<crate::secrets::SecretBinding>,
    /// Explicit project aliases permitted to use this profile's credentials.
    #[serde(default)]
    pub credential_repositories: Vec<String>,
}

impl RunnerProfile {
    pub fn has_credentials(&self) -> bool {
        !self.secrets.is_empty() || !self.env_passthrough.is_empty()
    }

    pub fn requires_external_approval(&self) -> bool {
        !matches!(self.container.network, ContainerNetwork::None) || self.has_credentials()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerProfile {
    #[serde(default)]
    pub runtime: ContainerRuntime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_rootfs: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_network_program: Option<PathBuf>,
    pub runtime_program: PathBuf,
    pub image: String,
    pub supply_chain: Option<SupplyChainPolicy>,
    #[serde(default = "default_git_program")]
    pub git_program: PathBuf,
    pub memory_mb: u64,
    pub cpu_millis: u32,
    pub pids_limit: u32,
    #[serde(default)]
    pub network: ContainerNetwork,
}
fn default_git_program() -> PathBuf {
    "/usr/bin/git".into()
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerRuntime {
    #[default]
    Native,
    Docker,
    Podman,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerNetwork {
    #[default]
    None,
    Bridge,
}

/// Construct only from authenticated transport identity, never from an RPC payload.
pub struct Caller {
    pub node_id: String,
    pub local_operator: bool,
    pub certificate_sha256: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerKind {
    #[default]
    Command,
    Agent,
    Codex,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub max_concurrency: usize,
    pub max_timeout_seconds: u64,
    pub max_log_bytes: u64,
    #[serde(default = "default_patch_limit")]
    pub max_patch_bytes: u64,
    #[serde(default = "default_pending_limit")]
    pub max_pending_jobs: usize,
}
fn default_pending_limit() -> usize {
    128
}
fn default_patch_limit() -> u64 {
    8 * 1024 * 1024
}
impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_concurrency: 1,
            max_timeout_seconds: 3600,
            max_log_bytes: 8 * 1024 * 1024,
            max_patch_bytes: default_patch_limit(),
            max_pending_jobs: default_pending_limit(),
        }
    }
}

#[derive(Clone)]
pub struct Executor {
    inner: Arc<Inner>,
}
struct WorkspaceKeyContext {
    workspace: String,
    key: WorkspaceKey,
}
struct Inner {
    config: ExecutorConfig,
    key_context: Option<WorkspaceKeyContext>,
    delegation: Option<Arc<dyn crate::delegation::DelegationProvider>>,
    delegation_leases: Mutex<BTreeMap<String, crate::delegation::DelegationLease>>,
    signing_key: Option<SigningKey>,
    notifications: Option<crate::job_notifications::SharedOutbox>,
    notification_capture_failures: std::sync::atomic::AtomicU64,
    jobs: Mutex<BTreeMap<String, Entry>>,
    worker_signal: Arc<WorkerSignal>,
    worker_registry: Mutex<WorkerRegistry>,
    dispatch_failed: AtomicBool,
    retention_lock: Mutex<()>,
    pending_erasures: Mutex<std::collections::BTreeSet<String>>,
    retention_failed: AtomicBool,
    draining: AtomicBool,
    _lock: File,
    _workspace_key_guard: Option<crate::rotation_install::KeyReadGuard>,
    _managed_binary_guard: Option<crate::updates::BinaryReadGuard>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // flock follows the open file description through fork. Releasing the last
            // real Executor owner must revoke that lock even if a helper inherited a
            // CLOEXEC descriptor before exec; jobs retain Inner through their Arc.
            unsafe {
                libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}
#[derive(Default)]
struct WorkerSignal {
    epoch: std::sync::atomic::AtomicU64,
    wait: Mutex<()>,
    changed: Condvar,
}
impl WorkerSignal {
    fn notify(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
    }
}
#[derive(Default)]
struct WorkerRegistry {
    workers: Vec<WorkerHandle>,
    coordinator_running: bool,
}
struct WorkerHandle {
    thread: thread::JoinHandle<()>,
    current: Arc<Mutex<Option<String>>>,
}
struct ClaimedJob {
    id: String,
    cancel: Arc<AtomicBool>,
}
struct WorkerWake(Arc<WorkerSignal>);
impl Drop for WorkerWake {
    fn drop(&mut self) {
        self.0.notify();
    }
}
struct CoordinatorExit {
    executor: Executor,
    finished: bool,
}
impl Drop for CoordinatorExit {
    fn drop(&mut self) {
        if !self.finished {
            self.executor
                .inner
                .dispatch_failed
                .store(true, Ordering::SeqCst);
            self.executor
                .inner
                .worker_registry
                .lock()
                .unwrap_or_else(|value| value.into_inner())
                .coordinator_running = false;
            self.executor.inner.worker_signal.notify();
        }
    }
}

struct Entry {
    record: JobRecord,
    cancel: Arc<AtomicBool>,
    artifacts: Arc<Mutex<()>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainStatus {
    pub draining: bool,
    pub queued: usize,
    pub running: usize,
    pub unknown: usize,
}
fn drain_status(jobs: &BTreeMap<String, Entry>, draining: bool) -> DrainStatus {
    DrainStatus {
        draining,
        queued: jobs
            .values()
            .filter(|entry| entry.record.state == JobState::Queued)
            .count(),
        running: jobs
            .values()
            .filter(|entry| matches!(entry.record.state, JobState::Starting | JobState::Running))
            .count(),
        unknown: jobs
            .values()
            .filter(|entry| entry.record.state == JobState::InterruptedUnknown)
            .count(),
    }
}
pub(crate) fn read_drain_flag(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error(error)),
        Ok(metadata) if metadata.is_file() => (),
        _ => return Err(ExecutorError("invalid_drain_state")),
    }
    let file = private_open_existing(path)?;
    let mut bytes = Vec::new();
    file.take(2).read_to_end(&mut bytes).map_err(io_error)?;
    match bytes.as_slice() {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(ExecutorError("invalid_drain_state")),
    }
}

fn io_error(_: std::io::Error) -> ExecutorError {
    ExecutorError("executor_io")
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
fn terminal(state: &JobState) -> bool {
    !matches!(
        state,
        JobState::Queued | JobState::Starting | JobState::Running
    )
}
fn queue_items(jobs: &BTreeMap<String, Entry>) -> Vec<crate::scheduler::QueueItem<'_>> {
    jobs.values()
        .map(|entry| crate::scheduler::QueueItem {
            id: &entry.record.spec.id,
            submitter: &entry.record.submitter,
            submitter_certificate_sha256: entry.record.submitter_certificate_sha256.as_deref(),
            project: &entry.record.spec.repository,
            enqueued_at_ms: entry.record.created_at_ms,
            priority: entry.record.spec.priority,
            phase: match entry.record.state {
                JobState::Queued => crate::scheduler::QueuePhase::Queued,
                JobState::Starting | JobState::Running => crate::scheduler::QueuePhase::Active,
                JobState::InterruptedUnknown => crate::scheduler::QueuePhase::Unknown,
                _ => crate::scheduler::QueuePhase::Done,
            },
        })
        .collect()
}
pub fn runner_config_digest(profile: &RunnerProfile) -> Result<String> {
    Ok(crate::provenance::sha256(
        &serde_json::to_vec(profile).map_err(|_| ExecutorError("invalid_runner_configuration"))?,
    ))
}
fn valid_id(id: &str) -> bool {
    id.len() == 26
        && id.as_bytes()[0] <= b'7'
        && id
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

/// Drains bytes already buffered after stop, but never waits forever for an
/// inherited writer. A missing EOF is an incomplete artifact, not success.
struct StoppablePipe<R> {
    reader: R,
    stopped: Arc<AtomicBool>,
    stopped_at: Option<Instant>,
}
impl<R: Read> Read for StoppablePipe<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.stopped.load(Ordering::SeqCst) {
                let at = *self.stopped_at.get_or_insert_with(Instant::now);
                if at.elapsed() >= Duration::from_millis(250) {
                    return Err(std::io::Error::other("pipe writer survived stop"));
                }
            }
            match self.reader.read(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if self.stopped.load(Ordering::SeqCst) {
                        return Err(std::io::Error::other("pipe writer survived stop"));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                result => return result,
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectedPath {
    path: String,
    blob: String,
}

const MAX_PATCH_SCAN_ENTRIES: usize = 1024;
struct PatchBudget<'a> {
    deadline: Instant,
    cancel: &'a AtomicBool,
}
impl<'a> PatchBudget<'a> {
    fn new(cancel: &'a AtomicBool) -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(30),
            cancel,
        }
    }
    fn remaining(&self) -> Result<Duration> {
        if self.cancel.load(Ordering::SeqCst) {
            return Err(ExecutorError("patch_collection_cancelled"));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ExecutorError("patch_collection_timeout"))
    }
}

/// One automaton checks all credential byte strings in linear time. Keep at most
/// the longest pattern minus one byte between chunks, so matches spanning reads
/// and writes are still detected. Empty values are intentionally ignored.
struct CredentialMatcher {
    automaton: Option<aho_corasick::AhoCorasick>,
    longest: usize,
}
impl CredentialMatcher {
    fn new(secrets: &[Vec<u8>]) -> Result<Self> {
        let mut patterns: Vec<&[u8]> = secrets
            .iter()
            .filter(|value| !value.is_empty())
            .map(Vec::as_slice)
            .collect();
        patterns.sort_unstable();
        patterns.dedup();
        let longest = patterns.iter().map(|value| value.len()).max().unwrap_or(1);
        let automaton = if patterns.is_empty() {
            None
        } else {
            Some(
                aho_corasick::AhoCorasickBuilder::new()
                    .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                    // The contiguous NFA builder can take quadratic time for long
                    // repeated prefixes; the sparse NFA avoids that construction path.
                    .kind(Some(aho_corasick::AhoCorasickKind::NoncontiguousNFA))
                    .prefilter(false)
                    .build(patterns)
                    .map_err(|_| ExecutorError("credential_matcher_unavailable"))?,
            )
        };
        Ok(Self { automaton, longest })
    }
    fn contains(&self, bytes: &[u8]) -> bool {
        self.automaton
            .as_ref()
            .is_some_and(|matcher| matcher.is_match(bytes))
    }
}

struct Spool<W: Write = File> {
    file: W,
    bytes: u64,
    truncated: bool,
    limit: u64,
    error: Option<&'static str>,
    credential_tail: Vec<u8>,
}
impl<W: Write> Spool<W> {
    fn mark_error(&mut self, code: &'static str) {
        self.error.get_or_insert(code);
        self.truncated = true;
    }
    fn append(&mut self, bytes: &[u8], matcher: &CredentialMatcher) -> std::io::Result<()> {
        if self.error.is_some() {
            self.truncated |= !bytes.is_empty();
            return Err(std::io::Error::other("spool previously failed"));
        }
        let count = bytes
            .len()
            .min(self.limit.saturating_sub(self.bytes) as usize);
        let mut checked = self.credential_tail.clone();
        checked.extend_from_slice(&bytes[..count]);
        if matcher.contains(&checked) {
            self.mark_error("serialized_log_contains_credential");
            return Err(std::io::Error::other("serialized log credential rejected"));
        }
        let mut written = 0;
        while written < count {
            match self.file.write(&bytes[written..count]) {
                Ok(0) => {
                    self.mark_error("spool_write_failed");
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
                }
                Ok(size) => {
                    written += size;
                    self.bytes += size as u64;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.mark_error("spool_write_failed");
                    return Err(error);
                }
            }
        }
        self.truncated |= count < bytes.len();
        let overlap = matcher.longest.saturating_sub(1);
        let keep = checked.len().min(overlap);
        self.credential_tail = checked[checked.len() - keep..].to_vec();
        Ok(())
    }
}

#[cfg(test)]
type WorkerRunHook = Arc<dyn Fn(&Executor, &str, Arc<AtomicBool>) -> Result<()> + Send + Sync>;
#[cfg(test)]
static WORKER_RUN_HOOKS: std::sync::OnceLock<Mutex<BTreeMap<PathBuf, WorkerRunHook>>> =
    std::sync::OnceLock::new();
#[cfg(test)]
static FAIL_WORKER_SPAWN: std::sync::OnceLock<Mutex<std::collections::BTreeSet<PathBuf>>> =
    std::sync::OnceLock::new();
#[cfg(test)]
static FAIL_COORDINATOR_SPAWN: std::sync::OnceLock<Mutex<std::collections::BTreeSet<PathBuf>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
type OpenTestHook = Box<dyn FnOnce() + Send>;
#[cfg(test)]
static OPEN_TEST_HOOKS: std::sync::OnceLock<Mutex<BTreeMap<PathBuf, OpenTestHook>>> =
    std::sync::OnceLock::new();

mod api;
mod execution;
mod queue;
mod retained_content;
mod tombstone_reconciliation;
use tombstone_reconciliation::*;
mod retention_files;
mod startup;
use retention_files::*;
mod credentials;
use credentials::*;
mod runtime;
use runtime::*;
mod injections;
use injections::*;
mod patch;
use patch::*;
mod patch_scan;
use patch_scan::*;
mod storage;
use storage::*;
mod streams;
use streams::*;

#[cfg(target_os = "linux")]
pub(crate) fn native_probe_diagnostic(command: &mut Command) -> std::result::Result<(), String> {
    match runtime_output(command, Duration::from_secs(5), 4096, None) {
        Ok((status, _, _)) if status.success() => Ok(()),
        Ok((_, _, error)) => Err(String::from_utf8_lossy(&error).trim().to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(all(test, unix))]
pub(crate) mod regression_tests;
