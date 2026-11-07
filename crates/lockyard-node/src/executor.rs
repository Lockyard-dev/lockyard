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
use std::fs::{self, File, OpenOptions};
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerProfile {
    pub runtime: ContainerRuntime,
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerRuntime {
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

impl Executor {
    pub fn new(config: ExecutorConfig) -> Result<Self> {
        Self::open(config, None, None, None)
    }

    /// The already-imported key is held in memory, never serialized into node configuration.
    pub fn new_with_workspace_key(
        config: ExecutorConfig,
        workspace: String,
        key: WorkspaceKey,
    ) -> Result<Self> {
        if !crate::wire::valid_name(&workspace) {
            return Err(ExecutorError("invalid_workspace_identity"));
        }
        Self::open(
            config,
            Some(WorkspaceKeyContext { workspace, key }),
            None,
            None,
        )
    }

    pub fn new_with_workspace_key_and_delegation(
        config: ExecutorConfig,
        workspace: String,
        key: WorkspaceKey,
        provider: Arc<dyn crate::delegation::DelegationProvider>,
    ) -> Result<Self> {
        if !crate::wire::valid_name(&workspace) {
            return Err(ExecutorError("invalid_workspace_identity"));
        }
        Self::open(
            config,
            Some(WorkspaceKeyContext { workspace, key }),
            Some(provider),
            None,
        )
    }

    pub(crate) fn new_with_notifications(
        config: ExecutorConfig,
        workspace: String,
        key: WorkspaceKey,
        provider: Arc<dyn crate::delegation::DelegationProvider>,
        notifications: Option<crate::job_notifications::SharedOutbox>,
    ) -> Result<Self> {
        if !crate::wire::valid_name(&workspace) {
            return Err(ExecutorError("invalid_workspace_identity"));
        }
        Self::open(
            config,
            Some(WorkspaceKeyContext { workspace, key }),
            Some(provider),
            notifications,
        )
    }

    fn open(
        config: ExecutorConfig,
        key_context: Option<WorkspaceKeyContext>,
        delegation: Option<Arc<dyn crate::delegation::DelegationProvider>>,
        notifications: Option<crate::job_notifications::SharedOutbox>,
    ) -> Result<Self> {
        if config
            .state_dir
            .file_name()
            .is_some_and(|name| name == "executor")
            && let Some(parent) = config.state_dir.parent()
        {
            crate::rotation_install::require_no_pending(parent)
                .map_err(|error| ExecutorError(error.0))?;
            crate::updates::require_no_pending(parent).map_err(|error| ExecutorError(error.0))?;
        }
        let workspace_key_guard = key_context
            .as_ref()
            .map(|context| {
                let node_state = config
                    .state_dir
                    .parent()
                    .ok_or(ExecutorError("invalid_state_directory"))?;
                crate::rotation_install::guard_executor_workspace_key(
                    node_state,
                    &config.node_id,
                    &context.workspace,
                    &context.key,
                )
                .map_err(|error| ExecutorError(error.0))
            })
            .transpose()?
            .flatten();
        #[cfg(not(unix))]
        return Err(ExecutorError("execution_requires_unix"));
        if config.node_id.is_empty()
            || config.node_id.len() > 64
            || !config
                .node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !config.state_dir.is_absolute()
            || config.limits.max_concurrency == 0
            || config.limits.max_concurrency > 128
            || config.limits.max_timeout_seconds == 0
            || config.limits.max_timeout_seconds > 604800
            || config.limits.max_log_bytes == 0
            || config.limits.max_log_bytes > 1024 * 1024 * 1024
            || config.limits.max_patch_bytes == 0
            || config.limits.max_patch_bytes > MAX_PATCH_BYTES
            || config
                .state_dir
                .to_string_lossy()
                .contains([',', ':', '\n', '\r'])
            || config.limits.max_pending_jobs == 0
            || config.limits.max_pending_jobs > 4096
        {
            return Err(ExecutorError("invalid_executor_limits"));
        }
        config.scheduling.validate().map_err(ExecutorError)?;
        if config.repositories.len() > 1024
            || config.runners.len() > 256
            || config
                .scheduling
                .queue
                .projects
                .keys()
                .any(|project| !config.repositories.contains_key(project))
            || config.scheduling.capacity.is_some_and(|capacity| {
                config.runners.values().any(|runner| {
                    let required = crate::scheduler::Resources {
                        cpu_millis: runner.container.cpu_millis,
                        memory_mb: runner.container.memory_mb,
                    };
                    !required.fits(capacity)
                })
            })
        {
            return Err(ExecutorError("invalid_executor_resource_budget"));
        }
        let signing_key = match &config.provenance {
            Some(provenance) => {
                if key_context
                    .as_ref()
                    .is_some_and(|context| context.workspace != provenance.workspace)
                {
                    return Err(ExecutorError("signing_workspace_mismatch"));
                }
                Some(provenance.load().map_err(|error| ExecutorError(error.0))?)
            }
            None if config.runners.is_empty() => None,
            None => return Err(ExecutorError("result_signing_required")),
        };
        for repo in config.repositories.values() {
            repo.retention
                .as_ref()
                .ok_or(ExecutorError("project_retention_required"))?
                .validate()
                .map_err(|error| ExecutorError(error.0))?;
            if !repo.checkout.is_absolute() {
                return Err(ExecutorError("checkout_must_be_absolute"));
            }
            if let Some(cloud) = &repo.cloud {
                let secure_endpoint = url::Url::parse(&cloud.url).is_ok_and(|url| {
                    url.scheme() == "https"
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.query().is_none()
                        && url.fragment().is_none()
                });
                if cloud.url.is_empty()
                    || !secure_endpoint
                    || cloud.workspace.is_empty()
                    || cloud.repository.is_empty()
                    || [&cloud.url, &cloud.workspace, &cloud.repository]
                        .iter()
                        .any(|v| v.chars().any(char::is_control))
                {
                    return Err(ExecutorError("invalid_cloud_config"));
                }
                if let Some(path) = &cloud.token_file {
                    read_private_token(path)?;
                }
            }
        }
        for runner in config.runners.values() {
            if runner.owner_approval_authorities.len() > 32
                || runner
                    .owner_approval_authorities
                    .iter()
                    .any(|key| key.validate().is_err())
                || runner
                    .owner_approval_authorities
                    .iter()
                    .map(|key| &key.public_key)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != runner.owner_approval_authorities.len()
                || (runner.action.requires_owner()
                    && (runner.owner_approval_authorities.is_empty()
                        || !config
                            .node_certificate_sha256
                            .as_deref()
                            .is_some_and(crate::wire::valid_certificate_pin)))
            {
                return Err(ExecutorError("owner_approval_authority_required"));
            }
            if (!runner.secrets.is_empty() || !runner.env_passthrough.is_empty())
                && (runner.credential_repositories.is_empty()
                    || runner
                        .credential_repositories
                        .iter()
                        .any(|repository| !config.repositories.contains_key(repository))
                    || runner
                        .credential_repositories
                        .iter()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != runner.credential_repositories.len())
            {
                return Err(ExecutorError("credential_profile_project_scope_required"));
            }
            if runner.secrets.len() > 64
                || runner
                    .secrets
                    .iter()
                    .map(|secret| &secret.name)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != runner.secrets.len()
            {
                return Err(ExecutorError("invalid_secret_references"));
            }
            for secret in &runner.secrets {
                secret.validate().map_err(|error| ExecutorError(error.0))?;
            }
            let env_names = runner.env_passthrough.iter().collect::<BTreeSet<_>>();
            if runner.env_passthrough.len() > 64
                || env_names.len() != runner.env_passthrough.len()
                || runner.env_passthrough.iter().any(|name| name.len() > 128)
                || runner
                    .secrets
                    .iter()
                    .filter_map(|secret| secret.environment.as_ref())
                    .any(|name| env_names.contains(name))
            {
                return Err(ExecutorError("invalid_credential_environment"));
            }
            let container = &runner.container;
            if !runner.program.is_absolute()
                || runner.fixed_args.iter().any(|a| a.contains('\0'))
                || runner.env_passthrough.iter().any(|name| {
                    name.is_empty()
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        || name.starts_with("DOCKER_")
                        || name.starts_with("PODMAN_")
                        || name.starts_with("CONTAINER_")
                        || name.starts_with("LOCKYARD_")
                        || name.starts_with("LD_")
                        || name.starts_with("DYLD_")
                        || [
                            "HOME",
                            "PATH",
                            "TMPDIR",
                            "XDG_RUNTIME_DIR",
                            "XDG_CONFIG_HOME",
                            "LOCKYARD_REQUIRE_E2EE",
                            "LOCKYARD_E2EE_WORKSPACE_ID",
                        ]
                        .contains(&name.as_str())
                })
                || runner
                    .mcp_program
                    .as_ref()
                    .is_some_and(|p| !p.is_absolute())
                || !container.runtime_program.is_absolute()
                || !container.git_program.is_absolute()
                || container.image.is_empty()
                || container.image.starts_with('-')
                || container
                    .image
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
                || container.memory_mb < 16
                || container.memory_mb > 1048576
                || container.cpu_millis == 0
                || container.cpu_millis > 128000
                || container.pids_limit == 0
                || container.pids_limit > 65536
            {
                return Err(ExecutorError("invalid_runner_profile"));
            }
            crate::supply_chain::immutable_image_digest(&container.image)
                .map_err(|error| ExecutorError(error.0))?;
            container
                .supply_chain
                .as_ref()
                .ok_or(ExecutorError("supply_chain_policy_required"))?
                .validate()
                .map_err(|error| ExecutorError(error.0))?;
        }
        private_dir(&config.state_dir)?;
        private_dir(&config.state_dir.join("jobs"))?;
        private_dir(&config.state_dir.join("job-tombstones"))?;
        private_dir(&config.state_dir.join("purge-completed"))?;
        private_dir(&config.state_dir.join("expired-content"))?;
        private_dir(&config.state_dir.join("exports"))?;
        if let Some(signing) = &config.provenance {
            let key_path = fs::canonicalize(&signing.key_file).map_err(io_error)?;
            let jobs_path = fs::canonicalize(config.state_dir.join("jobs")).map_err(io_error)?;
            if key_path.starts_with(&jobs_path)
                || config.repositories.values().any(|repository| {
                    fs::canonicalize(&repository.checkout)
                        .is_ok_and(|checkout| key_path.starts_with(checkout))
                })
            {
                return Err(ExecutorError(
                    "signing_key_must_be_outside_execution_mounts",
                ));
            }
        }
        check_execution_identity_paths(&config)?;
        #[cfg(test)]
        if let Some(hooks) = OPEN_TEST_HOOKS.get() {
            let hook = { hooks.lock().unwrap().remove(&config.state_dir) };
            if let Some(hook) = hook {
                hook();
            }
        }
        let lock = private_open(&config.state_dir.join("executor.lock"), false)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(ExecutorError("executor_already_running"));
            }
        }
        // The early checks are advisory. A stopped maintenance process may have
        // committed a pending journal while this constructor waited for this lock.
        let managed_binary_guard = if config
            .state_dir
            .file_name()
            .is_some_and(|name| name == "executor")
        {
            let parent = config
                .state_dir
                .parent()
                .ok_or(ExecutorError("invalid_state_directory"))?;
            crate::rotation_install::require_no_pending(parent)
                .map_err(|error| ExecutorError(error.0))?;
            crate::updates::standalone_startup_guard(
                parent,
                &config.node_id,
                key_context
                    .as_ref()
                    .map(|context| context.workspace.as_str()),
            )
            .map_err(|error| ExecutorError(error.0))?
        } else {
            None
        };
        let identity_path = config.state_dir.join("node-id");
        let mut identity = private_open(&identity_path, false)?;
        let mut identity_text = String::new();
        identity
            .read_to_string(&mut identity_text)
            .map_err(io_error)?;
        if identity_text.is_empty() {
            identity
                .write_all(config.node_id.as_bytes())
                .map_err(io_error)?;
            identity.sync_all().map_err(io_error)?;
            File::open(&config.state_dir)
                .map_err(io_error)?
                .sync_all()
                .map_err(io_error)?;
        } else if identity_text != config.node_id {
            return Err(ExecutorError("state_directory_node_id_conflict"));
        }
        // Caches created by older versions could contain an interrupted final
        // export. Drop only recognized cache files while exclusivity is held.
        crate::archive::clear_executor_cache(&config.state_dir.join("exports"))
            .map_err(|error| ExecutorError(error.0))?;
        let mut jobs = BTreeMap::new();
        for entry in fs::read_dir(config.state_dir.join("jobs")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !valid_id(&id) {
                continue;
            }
            if retention::load_tombstone(&config.state_dir.join("job-tombstones"), &id)
                .map_err(|error| ExecutorError(error.0))?
                .is_some()
            {
                retire_job_directory(&config.state_dir, &id)?;
                continue;
            }
            let path = entry.path().join("record.json");
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    quarantine_prejournal(&config.state_dir, &entry.path(), &id)?;
                    continue;
                }
                Err(error) => return Err(io_error(error)),
            };
            let mut record: JobRecord =
                serde_json::from_slice(&bytes).map_err(|_| ExecutorError("invalid_job_record"))?;
            if record.spec.id != id {
                return Err(ExecutorError("invalid_job_record"));
            }
            if record.retention.is_none() {
                let policy = config
                    .repositories
                    .get(&record.spec.repository)
                    .and_then(|repository| repository.retention.as_ref())
                    .ok_or(ExecutorError("legacy_job_retention_policy_required"))?;
                let mut snapshot = RetentionSnapshot::admit(policy, record.created_at_ms)
                    .map_err(|error| ExecutorError(error.0))?;
                snapshot
                    .note_terminal(record.state, record.updated_at_ms)
                    .map_err(|error| ExecutorError(error.0))?;
                record.retention = Some(snapshot);
                persist(&config.state_dir, &record)?;
            }
            let retention = record
                .retention
                .as_ref()
                .ok_or(ExecutorError("project_retention_required"))?;
            retention
                .validate()
                .map_err(|error| ExecutorError(error.0))?;
            if retention.admitted_at_ms != record.created_at_ms {
                return Err(ExecutorError("invalid_retention_snapshot"));
            }
            if record.state == JobState::Queued
                && (!config.repositories.contains_key(&record.spec.repository)
                    || !config.runners.contains_key(&record.spec.runner)
                    || record.admission_runner_sha256.is_none()
                    || record.admission_repository_sha256.is_none()
                    || !record.resolved_revision.as_ref().is_some_and(|revision| {
                        [40, 64].contains(&revision.len())
                            && revision.bytes().all(|b| b.is_ascii_hexdigit())
                    }))
            {
                record.state = JobState::Failed;
                record.updated_at_ms = now_ms();
                record.error_code = Some("queued_configuration_unavailable".into());
                record.patch_error = Some("job_not_started".into());
                note_terminal_retention(&mut record)?;
                persist(&config.state_dir, &record)?;
            }
            if matches!(record.state, JobState::Starting | JobState::Running) {
                record.state = JobState::InterruptedUnknown;
                record.updated_at_ms = now_ms();
                record.error_code = Some("daemon_interrupted_execution_unknown".into());
                record.patch_error = Some("execution_interrupted".into());
                persist(&config.state_dir, &record)?;
            }
            jobs.insert(
                id,
                Entry {
                    record,
                    cancel: Arc::new(AtomicBool::new(false)),
                    artifacts: Arc::new(Mutex::new(())),
                },
            );
        }
        let mut pending_erasures = std::collections::BTreeSet::new();
        for entry in fs::read_dir(config.state_dir.join("job-tombstones")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let Some(id) = entry
                .file_name()
                .to_str()
                .filter(|id| valid_id(id))
                .map(str::to_owned)
            else {
                continue;
            };
            let tombstone =
                retention::load_tombstone(&config.state_dir.join("job-tombstones"), &id)
                    .map_err(|error| ExecutorError(error.0))?
                    .ok_or(ExecutorError("job_tombstone_missing"))?;
            if retention::load_purge_completion(
                &config.state_dir.join("purge-completed"),
                &tombstone,
            )
            .map_err(|error| ExecutorError(error.0))?
            .is_none()
            {
                pending_erasures.insert(id);
            }
        }
        let queued = jobs
            .values()
            .any(|entry| entry.record.state == JobState::Queued);
        let executor = Self {
            inner: Arc::new(Inner {
                draining: AtomicBool::new(
                    read_drain_flag(&config.state_dir.join("drain-state"))?
                        || read_drain_flag(
                            &config
                                .state_dir
                                .parent()
                                .ok_or(ExecutorError("invalid_state_directory"))?
                                .join("operator-drain"),
                        )?,
                ),
                config,
                key_context,
                delegation,
                delegation_leases: Mutex::new(BTreeMap::new()),
                signing_key,
                notifications,
                notification_capture_failures: std::sync::atomic::AtomicU64::new(0),
                jobs: Mutex::new(jobs),
                worker_signal: Arc::new(WorkerSignal::default()),
                worker_registry: Mutex::new(WorkerRegistry::default()),
                dispatch_failed: AtomicBool::new(false),
                retention_lock: Mutex::new(()),
                pending_erasures: Mutex::new(pending_erasures),
                retention_failed: AtomicBool::new(false),
                _lock: lock,
                _workspace_key_guard: workspace_key_guard,
                _managed_binary_guard: managed_binary_guard,
            }),
        };
        executor.purge_expired()?;
        // Recover only a missing local signature. This never relaunches a completed execution.
        let unsigned: Vec<_> = executor
            .list()?
            .into_iter()
            .filter(|record| {
                record.state.is_terminal()
                    && record.result_manifest.is_none()
                    && record.provenance_error.is_none()
            })
            .map(|record| record.spec.id)
            .collect();
        for id in unsigned {
            executor.finalize_provenance(&id);
        }
        if queued {
            executor.launch_ready()?;
        }
        Ok(executor)
    }

    /// Idempotent for an identical job id/spec. A duplicate never starts another child.
    pub fn submit(&self, spec: JobSpec, caller: &Caller) -> Result<JobRecord> {
        self.submit_with_retention(spec, caller, None)
    }
    pub fn submit_with_retention(
        &self,
        spec: JobSpec,
        caller: &Caller,
        sender_policy: Option<&RetentionPolicy>,
    ) -> Result<JobRecord> {
        if !crate::wire::valid_name(&caller.node_id) {
            return Err(ExecutorError("invalid_caller"));
        }
        if !caller.local_operator
            && !caller
                .certificate_sha256
                .as_deref()
                .is_some_and(crate::wire::valid_certificate_pin)
        {
            return Err(ExecutorError("submitter_incarnation_required"));
        }
        if !valid_id(&spec.id) {
            return Err(ExecutorError("invalid_job_spec"));
        }
        if let Some(old) = self.tombstone(&spec.id)? {
            return Err(ExecutorError(
                if old
                    .matches(
                        &spec,
                        &caller.node_id,
                        caller.certificate_sha256.as_deref(),
                        caller.local_operator,
                    )
                    .map_err(|error| ExecutorError(error.0))?
                {
                    "job_content_expired"
                } else {
                    "job_id_conflict"
                },
            ));
        }
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        // Purge can commit a tombstone between the optimistic check and this lock.
        if let Some(old) = self.tombstone(&spec.id)? {
            return Err(ExecutorError(
                if old
                    .matches(
                        &spec,
                        &caller.node_id,
                        caller.certificate_sha256.as_deref(),
                        caller.local_operator,
                    )
                    .map_err(|error| ExecutorError(error.0))?
                {
                    "job_content_expired"
                } else {
                    "job_id_conflict"
                },
            ));
        }
        if let Some(existing) = jobs.get(&spec.id) {
            if record_content_expired(&existing.record, now_ms())? {
                return Err(ExecutorError("job_content_expired"));
            }
            if !caller.local_operator
                && existing.record.submitter == caller.node_id
                && existing.record.submitter_certificate_sha256.is_none()
            {
                return Err(ExecutorError("legacy_submitter_requires_local_review"));
            }
            return if existing.record.spec == spec
                && existing.record.submitter == caller.node_id
                && (existing.record.submitter_certificate_sha256 == caller.certificate_sha256
                    || (caller.local_operator
                        && existing.record.submitter_certificate_sha256.is_none()))
            {
                Ok(existing.record.clone())
            } else {
                Err(ExecutorError("job_id_conflict"))
            };
        }
        if self.inner.retention_failed.load(Ordering::SeqCst) {
            return Err(ExecutorError("retention_maintenance_required"));
        }
        if self.inner.draining.load(Ordering::SeqCst) {
            return Err(ExecutorError("node_draining"));
        }
        if self.inner.dispatch_failed.load(Ordering::SeqCst) {
            return Err(ExecutorError("executor_dispatch_unavailable"));
        }
        self.validate(&spec)?;
        if jobs
            .values()
            .any(|entry| entry.record.state == JobState::InterruptedUnknown)
        {
            return Err(ExecutorError("unknown_execution_requires_review"));
        }
        crate::scheduler::admit(
            &queue_items(&jobs),
            &caller.node_id,
            caller.certificate_sha256.as_deref(),
            &spec.repository,
            &self.inner.config.scheduling.queue,
            self.inner.config.limits.max_pending_jobs,
        )
        .map_err(ExecutorError)?;
        let repo = &self.inner.config.repositories[&spec.repository];
        let configured_policy = repo
            .retention
            .as_ref()
            .ok_or(ExecutorError("project_retention_required"))?;
        let policy = sender_policy.map_or_else(
            || Ok(configured_policy.clone()),
            |sender| {
                configured_policy
                    .effective(sender)
                    .map_err(|error| ExecutorError(error.0))
            },
        )?;
        let revision = resolve_revision(&repo.checkout, &spec.revision)?;
        self.verify_owner_approval(&spec, &revision)?;
        let id = spec.id.clone();
        private_dir_new(&self.inner.config.state_dir.join("jobs").join(&id))?;
        File::open(self.inner.config.state_dir.join("jobs"))
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
        let configured_image = self.inner.config.runners[&spec.runner]
            .container
            .image
            .clone();
        let admitted_at = now_ms();
        let admission_runner_sha256 = Some(admission_fingerprint(
            &self.inner.config.runners[&spec.runner],
        )?);
        let admission_repository_sha256 = Some(admission_fingerprint(
            &self.inner.config.repositories[&spec.repository],
        )?);
        let record = JobRecord {
            had_runtime_credentials: !self.inner.config.runners[&spec.runner].secrets.is_empty()
                || !self.inner.config.runners[&spec.runner]
                    .env_passthrough
                    .is_empty()
                || repo.cloud.is_some(),
            submitter: caller.node_id.clone(),
            submitter_certificate_sha256: caller.certificate_sha256.clone(),
            agent: format!("node-{}-{}", self.inner.config.node_id, spec.id),
            spec,
            state: JobState::Queued,
            created_at_ms: admitted_at,
            updated_at_ms: admitted_at,
            resolved_revision: Some(revision),
            worktree: None,
            pid: None,
            exit_code: None,
            error_code: None,
            log_bytes: 0,
            log_truncated: false,
            log_error: None,
            patch_bytes: 0,
            patch_truncated: false,
            patch_error: None,
            configured_image: Some(configured_image),
            admission_runner_sha256,
            admission_repository_sha256,
            admitted_image: None,
            result_manifest: None,
            provenance_error: None,
            notification_accounted_certificate_sha256: None,
            retention: Some(
                RetentionSnapshot::admit(&policy, admitted_at)
                    .map_err(|error| ExecutorError(error.0))?,
            ),
        };
        persist(&self.inner.config.state_dir, &record)?;
        let cancel = Arc::new(AtomicBool::new(false));
        jobs.insert(
            id.clone(),
            Entry {
                record: record.clone(),
                cancel: cancel.clone(),
                artifacts: Arc::new(Mutex::new(())),
            },
        );
        drop(jobs);
        self.launch_ready()?;
        Ok(record)
    }

    /// One coordinator exists only while registered workers or eligible work remain.
    /// It counts workers through finalization and actual JoinHandle completion.
    fn launch_ready(&self) -> Result<()> {
        if self.inner.dispatch_failed.load(Ordering::SeqCst) {
            return Err(ExecutorError("executor_dispatch_unavailable"));
        }
        let mut registry = self
            .inner
            .worker_registry
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        self.inner.worker_signal.notify();
        if registry.coordinator_running {
            return Ok(());
        }
        if !self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?
            .values()
            .any(|entry| entry.record.state == JobState::Queued)
        {
            return Ok(());
        }
        registry.coordinator_running = true;
        #[cfg(test)]
        if FAIL_COORDINATOR_SPAWN
            .get()
            .is_some_and(|states| states.lock().unwrap().remove(&self.inner.config.state_dir))
        {
            registry.coordinator_running = false;
            self.inner.dispatch_failed.store(true, Ordering::SeqCst);
            return Err(ExecutorError("job_coordinator_failed"));
        }
        let executor = self.clone();
        if thread::Builder::new()
            .name("lockyard-job-coordinator".into())
            .spawn(move || executor.coordinate_workers())
            .is_err()
        {
            registry.coordinator_running = false;
            self.inner.dispatch_failed.store(true, Ordering::SeqCst);
            return Err(ExecutorError("job_coordinator_failed"));
        }
        Ok(())
    }
    fn claim_ready(&self) -> Result<Option<ClaimedJob>> {
        if self.inner.dispatch_failed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        if self.inner.dispatch_failed.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let id = {
            let items = queue_items(&jobs);
            let resources = jobs
                .values()
                .filter_map(|entry| {
                    self.inner
                        .config
                        .runners
                        .get(&entry.record.spec.runner)
                        .map(|runner| {
                            (
                                entry.record.spec.id.as_str(),
                                crate::scheduler::Resources {
                                    cpu_millis: runner.container.cpu_millis,
                                    memory_mb: runner.container.memory_mb,
                                },
                            )
                        })
                })
                .collect();
            crate::scheduler::next_job(
                &items,
                &self.inner.config.scheduling.queue,
                self.inner.config.limits.max_concurrency,
                self.inner.config.scheduling.capacity,
                &resources,
                now_ms(),
            )
            .map(str::to_owned)
        };
        let Some(id) = id else {
            return Ok(None);
        };
        let entry = jobs.get_mut(&id).ok_or(ExecutorError("job_not_found"))?;
        let mut starting = entry.record.clone();
        starting.state = JobState::Starting;
        starting.updated_at_ms = now_ms();
        // A claim is durable before any thread or process can start. On ambiguous
        // persistence the dispatcher fences, and restart reconciles Starting as Unknown.
        persist(&self.inner.config.state_dir, &starting)?;
        entry.record = starting;
        Ok(Some(ClaimedJob {
            id,
            cancel: entry.cancel.clone(),
        }))
    }
    fn coordinate_workers(&self) {
        let mut exit = CoordinatorExit {
            executor: self.clone(),
            finished: false,
        };
        loop {
            let observed = self.inner.worker_signal.epoch.load(Ordering::SeqCst);
            let mut registry = match self.inner.worker_registry.lock() {
                Ok(value) => value,
                Err(_) => {
                    self.inner.dispatch_failed.store(true, Ordering::SeqCst);
                    return;
                }
            };
            let mut index = 0;
            while index < registry.workers.len() {
                if !registry.workers[index].thread.is_finished() {
                    index += 1;
                    continue;
                }
                let worker = registry.workers.swap_remove(index);
                if worker.thread.join().is_err() {
                    self.inner.dispatch_failed.store(true, Ordering::SeqCst);
                    let id = worker
                        .current
                        .lock()
                        .unwrap_or_else(|value| value.into_inner())
                        .clone();
                    if let Some(id) = id {
                        let _ = self.update(&id, |record| {
                            if matches!(record.state, JobState::Starting | JobState::Running) {
                                record.state = JobState::InterruptedUnknown;
                                record.error_code = Some("job_worker_panicked".into());
                                record.patch_error = Some("execution_interrupted".into());
                            }
                        });
                    }
                }
            }
            while registry.workers.len() < self.inner.config.limits.max_concurrency
                && !self.inner.dispatch_failed.load(Ordering::SeqCst)
            {
                let claimed = match self.claim_ready() {
                    Ok(Some(value)) => value,
                    Ok(None) => break,
                    Err(_) => {
                        self.inner.dispatch_failed.store(true, Ordering::SeqCst);
                        break;
                    }
                };
                let id = claimed.id.clone();
                let current = Arc::new(Mutex::new(Some(id.clone())));
                let tracker = current.clone();
                let executor = self.clone();
                #[cfg(test)]
                let injected = FAIL_WORKER_SPAWN.get().is_some_and(|states| {
                    states.lock().unwrap().remove(&self.inner.config.state_dir)
                });
                #[cfg(not(test))]
                let injected = false;
                let spawn = if injected {
                    Err(std::io::Error::other("synthetic worker spawn failure"))
                } else {
                    thread::Builder::new()
                        .name(format!("lockyard-worker-{id}"))
                        .spawn(move || executor.worker_loop(claimed, tracker))
                };
                match spawn {
                    Ok(thread) => registry.workers.push(WorkerHandle { thread, current }),
                    Err(_) => {
                        self.inner.dispatch_failed.store(true, Ordering::SeqCst);
                        let _ = self.update(&id, |record| {
                            record.state = JobState::Failed;
                            record.error_code = Some("job_thread_failed".into());
                            record.patch_error = Some("job_not_started".into());
                        });
                        self.finalize_provenance(&id);
                        break;
                    }
                }
            }
            if registry.workers.is_empty() {
                registry.coordinator_running = false;
                exit.finished = true;
                return;
            }
            drop(registry);
            let waiting = self
                .inner
                .worker_signal
                .wait
                .lock()
                .unwrap_or_else(|value| value.into_inner());
            if self.inner.worker_signal.epoch.load(Ordering::SeqCst) == observed {
                let _ = self
                    .inner
                    .worker_signal
                    .changed
                    .wait_timeout(waiting, Duration::from_millis(10));
            }
        }
    }
    fn worker_loop(&self, first: ClaimedJob, current: Arc<Mutex<Option<String>>>) {
        let _wake = WorkerWake(self.inner.worker_signal.clone());
        let mut next = Some(first);
        while let Some(job) = next {
            *current.lock().unwrap_or_else(|value| value.into_inner()) = Some(job.id.clone());
            #[cfg(test)]
            let hook = WORKER_RUN_HOOKS.get().and_then(|hooks| {
                hooks
                    .lock()
                    .unwrap()
                    .get(&self.inner.config.state_dir)
                    .cloned()
            });
            #[cfg(test)]
            if let Some(hook) = hook {
                if let Err(error) = hook(self, &job.id, job.cancel.clone()) {
                    let _ = self.update(&job.id, |record| {
                        record.state = JobState::Failed;
                        record.error_code = Some(error.0.into());
                    });
                }
                self.finalize_provenance(&job.id);
            } else {
                self.run(&job.id, job.cancel);
            }
            #[cfg(not(test))]
            self.run(&job.id, job.cancel);
            next = match self.claim_ready() {
                Ok(value) => value,
                Err(_) => {
                    self.inner.dispatch_failed.store(true, Ordering::SeqCst);
                    None
                }
            };
        }
        *current.lock().unwrap_or_else(|value| value.into_inner()) = None;
    }

    pub fn status(&self, id: &str) -> Result<JobRecord> {
        let record = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?
            .get(id)
            .map(|entry| entry.record.clone())
            .ok_or(ExecutorError("job_not_found"));
        match record {
            Ok(record) if record_content_expired(&record, now_ms())? => {
                Err(ExecutorError("job_content_expired"))
            }
            Ok(record) => Ok(record),
            Err(_) if self.tombstone(id)?.is_some() => Err(ExecutorError("job_content_expired")),
            Err(error) => Err(error),
        }
    }
    pub fn list(&self) -> Result<Vec<JobRecord>> {
        let jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let mut records = Vec::new();
        for entry in jobs.values() {
            if !record_content_expired(&entry.record, now_ms())? {
                records.push(entry.record.clone());
            }
        }
        Ok(records)
    }
    /// Recover at most 32 durable records without cloning their application contents.
    pub(crate) fn notification_capture_page(&self, after: Option<&str>) -> Result<Option<String>> {
        use std::ops::Bound::{Excluded, Unbounded};
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let start = after.map_or(Unbounded, Excluded);
        let mut cursor = None;
        for (id, entry) in jobs.range_mut::<str, _>((start, Unbounded)).take(32) {
            cursor = Some(id.clone());
            self.capture_notification_best_effort(&mut entry.record);
        }
        Ok(cursor)
    }
    fn capture_notification(&self, record: &mut JobRecord) -> Result<()> {
        let Some(outbox) = &self.inner.notifications else {
            return Ok(());
        };
        let Some(pin) = self.inner.config.node_certificate_sha256.as_deref() else {
            return Err(ExecutorError("notification_identity_unavailable"));
        };
        if record.notification_accounted_certificate_sha256.as_deref() == Some(pin) {
            return outbox
                .lock()
                .map_err(|_| ExecutorError("notification_outbox_unavailable"))?
                .source_accounted(&record.spec.id, record.state)
                .map_err(|_| ExecutorError("notification_outbox_unavailable"));
        }
        if !record.state.is_terminal() || record.provenance_error.is_some() {
            return Ok(());
        }
        let Some(document) = &record.result_manifest else {
            return Ok(());
        };
        let signer = self
            .inner
            .signing_key
            .as_ref()
            .ok_or(ExecutorError("result_provenance_unavailable"))?;
        let context = self
            .inner
            .key_context
            .as_ref()
            .ok_or(ExecutorError("result_provenance_unavailable"))?;
        let signed = crate::provenance::verify_result_identity(
            document,
            &signer.trusted_key(),
            &self.inner.config.node_id,
            &context.workspace,
            &record.spec.id,
        )
        .map_err(|_| ExecutorError("result_provenance_unavailable"))?;
        if signed.state != record.state || signed.completed_at_ms > now_ms() {
            return Err(ExecutorError("result_provenance_unavailable"));
        }
        outbox
            .lock()
            .map_err(|_| ExecutorError("notification_outbox_unavailable"))?
            .capture(&record.spec.id, signed.state, signed.completed_at_ms)
            .map_err(|_| ExecutorError("notification_outbox_unavailable"))?;
        // The outbox was synced first. A crash before this marker simply rediscovers
        // the same key and cannot execute the job again.
        let mut candidate = record.clone();
        candidate.notification_accounted_certificate_sha256 = Some(pin.to_owned());
        persist(&self.inner.config.state_dir, &candidate)?;
        *record = candidate;
        outbox
            .lock()
            .map_err(|_| ExecutorError("notification_outbox_unavailable"))?
            .source_accounted(&record.spec.id, record.state)
            .map_err(|_| ExecutorError("notification_outbox_unavailable"))
    }
    fn capture_notification_best_effort(&self, record: &mut JobRecord) {
        if self.capture_notification(record).is_err() {
            self.inner
                .notification_capture_failures
                .fetch_add(1, Ordering::Relaxed);
            eprintln!("lockyard node: job notification capture unavailable");
        }
    }
    pub(crate) fn notification_status(&self) -> Option<(usize, u64, u64, u64)> {
        let outbox = self.inner.notifications.as_ref()?.lock().ok()?;
        let (pending, dropped, expired) = outbox.counts();
        Some((
            pending,
            dropped,
            expired,
            self.inner
                .notification_capture_failures
                .load(Ordering::Relaxed),
        ))
    }
    /// Configured resource limits and reservations, not a claim that a runtime passed admission.
    pub fn capabilities(
        &self,
        certificate_sha256: &str,
    ) -> Result<crate::scheduler::NodeCapabilities> {
        use crate::scheduler::{NodeCapabilities, Resources, RunnerCapability};
        let jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let mut reserved = Resources {
            cpu_millis: 0,
            memory_mb: 0,
        };
        let (mut running, mut queued, mut unknown) = (0, 0, 0);
        for entry in jobs.values() {
            match entry.record.state {
                JobState::Queued => queued += 1,
                JobState::Starting | JobState::Running => running += 1,
                JobState::InterruptedUnknown => unknown += 1,
                _ => (),
            }
            if matches!(
                entry.record.state,
                JobState::Starting | JobState::Running | JobState::InterruptedUnknown
            ) && let Some(runner) = self.inner.config.runners.get(&entry.record.spec.runner)
            {
                reserved.cpu_millis = reserved
                    .cpu_millis
                    .saturating_add(runner.container.cpu_millis);
                reserved.memory_mb = reserved
                    .memory_mb
                    .saturating_add(runner.container.memory_mb);
            }
        }
        let runners = self
            .inner
            .config
            .runners
            .iter()
            .map(|(name, runner)| {
                Ok((
                    name.clone(),
                    RunnerCapability {
                        action: runner.action,
                        owner_approval_authorities: runner.owner_approval_authorities.clone(),
                        image_reference: runner.container.image.clone(),
                        resources: Resources {
                            cpu_millis: runner.container.cpu_millis,
                            memory_mb: runner.container.memory_mb,
                        },
                        pids_limit: runner.container.pids_limit,
                        image_digest: crate::supply_chain::immutable_image_digest(
                            &runner.container.image,
                        )
                        .map_err(|error| ExecutorError(error.0))?,
                        configuration_sha256: runner_config_digest(runner)?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        let result = NodeCapabilities {
            version: 1,
            node_id: self.inner.config.node_id.clone(),
            certificate_sha256: certificate_sha256.into(),
            labels: self.inner.config.scheduling.labels.clone(),
            capacity: self.inner.config.scheduling.capacity,
            reserved,
            runners,
            projects: self.inner.config.repositories.keys().cloned().collect(),
            max_concurrency: self.inner.config.limits.max_concurrency,
            max_pending_jobs: self.inner.config.limits.max_pending_jobs,
            running,
            queued,
            unknown,
            draining: self.inner.draining.load(Ordering::SeqCst)
                || self.inner.dispatch_failed.load(Ordering::SeqCst),
        };
        result.validate().map_err(ExecutorError)?;
        if serde_json::to_vec(&result)
            .map_err(|_| ExecutorError("invalid_node_capabilities"))?
            .len()
            > 128 * 1024
        {
            return Err(ExecutorError("node_capabilities_too_large"));
        }
        Ok(result)
    }
    /// Read-only immutable commit resolution for a frozen owner-approval request.
    pub fn workflow_revision(
        &self,
        certificate_sha256: &str,
        repository: &str,
        revision: &str,
        runner: &str,
    ) -> Result<crate::scheduler::RevisionCapability> {
        if !crate::wire::valid_certificate_pin(certificate_sha256)
            || !crate::wire::valid_name(repository)
            || !crate::wire::valid_name(runner)
            || revision.is_empty()
            || revision.len() > 512
            || revision.contains('\0')
        {
            return Err(ExecutorError("invalid_revision_request"));
        }
        let project = self
            .inner
            .config
            .repositories
            .get(repository)
            .ok_or(ExecutorError("repository_not_configured"))?;
        let profile = self
            .inner
            .config
            .runners
            .get(runner)
            .ok_or(ExecutorError("runner_not_configured"))?;
        Ok(crate::scheduler::RevisionCapability {
            node_id: self.inner.config.node_id.clone(),
            certificate_sha256: certificate_sha256.into(),
            repository: repository.into(),
            requested_revision: revision.into(),
            resolved_revision: resolve_revision(&project.checkout, revision)?,
            runner: runner.into(),
            profile: crate::scheduler::RunnerCapability {
                action: profile.action,
                owner_approval_authorities: profile.owner_approval_authorities.clone(),
                image_reference: profile.container.image.clone(),
                image_digest: crate::supply_chain::immutable_image_digest(&profile.container.image)
                    .map_err(|error| ExecutorError(error.0))?,
                configuration_sha256: runner_config_digest(profile)?,
                resources: crate::scheduler::Resources {
                    cpu_millis: profile.container.cpu_millis,
                    memory_mb: profile.container.memory_mb,
                },
                pids_limit: profile.container.pids_limit,
            },
        })
    }
    pub fn cancel(&self, id: &str, caller: &Caller) -> Result<JobRecord> {
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let entry = jobs.get_mut(id).ok_or(ExecutorError("job_not_found"))?;
        if record_content_expired(&entry.record, now_ms())? {
            return Err(ExecutorError("job_content_expired"));
        }
        if !caller.local_operator && entry.record.submitter != caller.node_id {
            return Err(ExecutorError("job_owner_required"));
        }
        if !caller.local_operator && entry.record.submitter_certificate_sha256.is_none() {
            return Err(ExecutorError("legacy_submitter_requires_local_review"));
        }
        if !caller.local_operator
            && (caller.certificate_sha256.is_none()
                || entry.record.submitter_certificate_sha256 != caller.certificate_sha256)
        {
            return Err(ExecutorError("job_owner_required"));
        }
        if entry.record.state == JobState::InterruptedUnknown {
            return Err(ExecutorError("unknown_execution_requires_review"));
        }
        if !terminal(&entry.record.state) {
            entry.cancel.store(true, Ordering::SeqCst);
            if entry.record.state == JobState::Queued {
                entry.record.state = JobState::Cancelled;
                entry.record.patch_error = Some("job_not_started".into());
                entry.record.updated_at_ms = now_ms();
                note_terminal_retention(&mut entry.record)?;
                persist(&self.inner.config.state_dir, &entry.record)?;
            }
            self.inner.worker_signal.notify();
        }
        let record = entry.record.clone();
        let finalize = record.state == JobState::Cancelled;
        drop(jobs);
        if finalize {
            self.finalize_provenance(id);
        }
        self.launch_ready()?;
        if finalize {
            self.status(id)
        } else {
            Ok(record)
        }
    }

    /// Explicit local reconciliation after an operator has checked for surviving processes.
    /// It neither kills an unverified old PID nor executes the job again.
    pub fn resolve_unknown(&self, id: &str, caller: &Caller) -> Result<JobRecord> {
        if !caller.local_operator {
            return Err(ExecutorError("local_operator_required"));
        }
        if self.status(id)?.state == JobState::InterruptedUnknown {
            remove_runtime_key(&self.inner.config.state_dir.join("jobs").join(id))?;
        }
        self.update(id, |record| {
            if record.state == JobState::InterruptedUnknown {
                record.state = JobState::Failed;
                record.error_code = Some("interrupted_execution_reviewed".into());
            }
        })?;
        self.finalize_provenance(id);
        self.launch_ready()?;
        self.status(id)
    }

    pub(crate) fn store_delegation(
        &self,
        id: &str,
        lease: crate::delegation::DelegationLease,
    ) -> Result<()> {
        if !valid_id(id)
            || !matches!(
                self.status(id)?.state,
                JobState::Starting | JobState::Running
            )
        {
            return Err(ExecutorError("delegation_parent_not_active"));
        }
        let mut leases = self
            .inner
            .delegation_leases
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        if leases.contains_key(id) || leases.len() >= self.inner.config.limits.max_concurrency {
            return Err(ExecutorError("delegation_capacity_unavailable"));
        }
        leases.insert(id.into(), lease);
        Ok(())
    }
    pub(crate) fn release_delegation(&self, id: &str) -> Result<()> {
        if !self.status(id)?.state.is_terminal() {
            return Err(ExecutorError("delegation_stop_unconfirmed"));
        }
        let lease = self
            .inner
            .delegation_leases
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?
            .remove(id);
        drop(lease);
        Ok(())
    }

    pub fn read_log(&self, id: &str, offset: u64, max_bytes: usize) -> Result<LogChunk> {
        let artifacts = self.artifact_lock(id)?;
        let _guard = artifacts
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let record = self.status(id)?;
        let path = self
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(id)
            .join("output.log");
        let mut bytes = Vec::new();
        let mut eof = terminal(&record.state);
        match File::open(path) {
            Ok(mut file) => {
                let len = file.metadata().map_err(io_error)?.len();
                if offset > len {
                    return Err(ExecutorError("log_offset_out_of_range"));
                }
                file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
                file.take(max_bytes.min(65536) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(io_error)?;
                eof &= offset + bytes.len() as u64 >= len;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && offset == 0 => {}
            Err(_) => return Err(ExecutorError("log_read_failed")),
        }
        Ok(LogChunk {
            offset,
            next_offset: offset + bytes.len() as u64,
            bytes,
            eof,
            truncated: record.log_truncated,
        })
    }

    pub fn read_patch(&self, id: &str, offset: u64, max_bytes: usize) -> Result<LogChunk> {
        let artifacts = self.artifact_lock(id)?;
        let _guard = artifacts
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let record = self.status(id)?;
        if !terminal(&record.state) {
            return Err(ExecutorError("job_not_finished"));
        }
        if record.patch_error.is_some() {
            return Err(ExecutorError("patch_unavailable"));
        }
        if record.result_manifest.is_none() || record.provenance_error.is_some() {
            return Err(ExecutorError("result_provenance_unavailable"));
        }
        let mut file = private_open_existing(
            &self
                .inner
                .config
                .state_dir
                .join("jobs")
                .join(id)
                .join("result.patch"),
        )?;
        let len = file.metadata().map_err(io_error)?.len();
        if offset > len {
            return Err(ExecutorError("patch_offset_out_of_range"));
        }
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut bytes = Vec::new();
        file.take(max_bytes.min(65536) as u64)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let next_offset = offset + bytes.len() as u64;
        Ok(LogChunk {
            offset,
            next_offset,
            bytes,
            eof: next_offset == len,
            truncated: record.patch_truncated,
        })
    }

    pub fn set_draining(&self, enabled: bool, caller: &Caller) -> Result<DrainStatus> {
        if !caller.local_operator {
            return Err(ExecutorError("local_operator_required"));
        }
        let jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let temporary = self
            .inner
            .config
            .state_dir
            .join(format!(".drain-{}.tmp", lockyard_cloud_client::ulid()));
        let mut file = private_open(&temporary, true)?;
        file.write_all(if enabled { b"1" } else { b"0" })
            .and_then(|()| file.sync_all())
            .map_err(io_error)?;
        fs::rename(&temporary, self.inner.config.state_dir.join("drain-state"))
            .map_err(io_error)?;
        File::open(&self.inner.config.state_dir)
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?;
        self.inner.draining.store(enabled, Ordering::SeqCst);
        Ok(drain_status(&jobs, enabled))
    }
    pub fn dispatch_healthy(&self) -> bool {
        !self.inner.dispatch_failed.load(Ordering::SeqCst)
    }
    pub fn drain_status(&self) -> Result<DrainStatus> {
        let jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        Ok(drain_status(
            &jobs,
            self.inner.draining.load(Ordering::SeqCst),
        ))
    }
    fn artifact_lock(&self, id: &str) -> Result<Arc<Mutex<()>>> {
        self.inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?
            .get(id)
            .map(|entry| entry.artifacts.clone())
            .ok_or(ExecutorError("job_not_found"))
    }
    pub fn tombstone(&self, id: &str) -> Result<Option<JobTombstone>> {
        retention::load_tombstone(&self.inner.config.state_dir.join("job-tombstones"), id)
            .map_err(|error| ExecutorError(error.0))
    }
    fn terminal_receipt(
        &self,
        tombstone: &JobTombstone,
    ) -> Result<crate::provenance::SignedDocument> {
        let signer = self
            .inner
            .signing_key
            .as_ref()
            .ok_or(ExecutorError("terminal_receipt_signing_unavailable"))?;
        let signing = self
            .inner
            .config
            .provenance
            .as_ref()
            .ok_or(ExecutorError("terminal_receipt_signing_unavailable"))?;
        let completed_at_ms = tombstone
            .completed_at_ms
            .filter(|t| *t > 0 && *t <= tombstone.terminal_expires_at_ms)
            .ok_or(ExecutorError("terminal_receipt_legacy_unavailable"))?;
        let receipt = retention::TerminalReceipt {
            version: 1,
            node_id: self.inner.config.node_id.clone(),
            workspace: signing.workspace.clone(),
            job_id: tombstone.job_id.clone(),
            submitter: tombstone.submitter.clone(),
            submitter_certificate_sha256: tombstone.submitter_certificate_sha256.clone(),
            request_sha256: tombstone.spec_sha256.clone(),
            outcome: tombstone.outcome,
            completed_at_ms,
        };
        retention::terminal_receipt(
            &self.inner.config.state_dir.join("job-tombstones"),
            tombstone,
            &receipt,
            signer,
        )
        .map_err(|e| ExecutorError(e.0))
    }
    pub fn expired_metadata(&self, id: &str) -> Result<Option<serde_json::Value>> {
        if let Some(tombstone) = self.tombstone(id)? {
            let completion = retention::load_purge_completion(
                &self.inner.config.state_dir.join("purge-completed"),
                &tombstone,
            )
            .map_err(|error| ExecutorError(error.0))?;
            let (receipt, receipt_error) = match self.terminal_receipt(&tombstone) {
                Ok(receipt) => (Some(receipt), None),
                Err(error) => (None, Some(error.0)),
            };
            return Ok(Some(
                serde_json::json!({"job_id":id,"content_expired":true,"erasure_committed":true,
                "erasure_complete":completion.is_some(),"purge_completion":completion,"tombstone":tombstone,"terminal_receipt":receipt,"terminal_receipt_error":receipt_error}),
            ));
        }
        let jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        match jobs.get(id) {
            Some(entry) if record_content_expired(&entry.record, now_ms())? => {
                Ok(Some(serde_json::json!({"job_id":id,
                "content_expired":true,"state":entry.record.state,"erasure_committed":false,"erasure_complete":false,
                "terminal_expires_at_ms":entry.record.retention.as_ref().and_then(|policy|policy.terminal_expires_at_ms)})))
            }
            _ => Ok(None),
        }
    }
    pub fn content_retention(&self, id: &str) -> Result<RetentionSnapshot> {
        self.status(id)?
            .retention
            .ok_or(ExecutorError("project_retention_required"))
    }
    /// Logical content removal only: this cannot erase copies a workspace member already
    /// downloaded, filesystem snapshots, or physical sectors retained by the storage device.
    pub fn purge_expired(&self) -> Result<usize> {
        self.purge_expired_at(now_ms())
    }
    fn purge_expired_at(&self, now: u64) -> Result<usize> {
        let _maintenance = self
            .inner
            .retention_lock
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let result = (|| {
            let pending = self
                .inner
                .pending_erasures
                .lock()
                .map_err(|_| ExecutorError("executor_poisoned"))?
                .clone();
            for id in pending {
                retire_job_directory(&self.inner.config.state_dir, &id)?;
                self.inner
                    .pending_erasures
                    .lock()
                    .map_err(|_| ExecutorError("executor_poisoned"))?
                    .remove(&id);
            }
            // A prior crash may have committed the tombstone before erasing its directory.
            for entry in fs::read_dir(self.inner.config.state_dir.join("jobs")).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if valid_id(&id) && self.tombstone(&id)?.is_some() {
                    self.inner
                        .jobs
                        .lock()
                        .map_err(|_| ExecutorError("executor_poisoned"))?
                        .remove(&id);
                    retire_job_directory(&self.inner.config.state_dir, &id)?;
                }
            }
            let candidates = {
                let jobs = self
                    .inner
                    .jobs
                    .lock()
                    .map_err(|_| ExecutorError("executor_poisoned"))?;
                let mut candidates = Vec::new();
                for (id, entry) in jobs.iter() {
                    if record_content_expired(&entry.record, now)? {
                        candidates.push((id.clone(), entry.artifacts.clone()));
                    }
                }
                candidates
            };
            let mut purged = 0;
            for (id, artifacts) in candidates {
                // Signing, a log read, or an explicit export may be using this job's files.
                let Ok(_guard) = artifacts.try_lock() else {
                    continue;
                };
                let mut jobs = self
                    .inner
                    .jobs
                    .lock()
                    .map_err(|_| ExecutorError("executor_poisoned"))?;
                let Some(entry) = jobs.get_mut(&id) else {
                    continue;
                };
                if !record_content_expired(&entry.record, now)? {
                    continue;
                }
                self.capture_notification_best_effort(&mut entry.record);
                let snapshot = entry
                    .record
                    .retention
                    .as_ref()
                    .ok_or(ExecutorError("project_retention_required"))?;
                let tombstone = JobTombstone {
                    version: 1,
                    job_id: id.clone(),
                    submitter: entry.record.submitter.clone(),
                    submitter_certificate_sha256: entry.record.submitter_certificate_sha256.clone(),
                    spec_sha256: retention::spec_digest(&entry.record.spec)
                        .map_err(|error| ExecutorError(error.0))?,
                    outcome: entry.record.state,
                    terminal_expires_at_ms: snapshot
                        .terminal_expires_at_ms
                        .ok_or(ExecutorError("invalid_retention_snapshot"))?,
                    purged_at_ms: now,
                    result_manifest: entry.record.result_manifest.clone(),
                    completed_at_ms: Some(entry.record.updated_at_ms),
                };
                retention::store_tombstone(
                    &self.inner.config.state_dir.join("job-tombstones"),
                    &tombstone,
                )
                .map_err(|error| ExecutorError(error.0))?;
                // After this durable commit an ID is never admitted again, even if deletion fails.
                self.inner
                    .pending_erasures
                    .lock()
                    .map_err(|_| ExecutorError("executor_poisoned"))?
                    .insert(id.clone());
                jobs.remove(&id);
                drop(jobs);
                retire_job_directory(&self.inner.config.state_dir, &id)?;
                self.inner
                    .pending_erasures
                    .lock()
                    .map_err(|_| ExecutorError("executor_poisoned"))?
                    .remove(&id);
                // Receipt publication is best effort and never blocks content erasure.
                let _ = self.terminal_receipt(&tombstone);
                purged += 1;
            }
            for entry in fs::read_dir(self.inner.config.state_dir.join("expired-content"))
                .map_err(io_error)?
            {
                let entry = entry.map_err(io_error)?;
                let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if valid_id(&id) && self.tombstone(&id)?.is_some() {
                    fs::remove_dir_all(entry.path()).map_err(io_error)?;
                }
            }
            File::open(self.inner.config.state_dir.join("expired-content"))
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?;
            Ok(purged)
        })();
        self.inner
            .retention_failed
            .store(result.is_err(), Ordering::SeqCst);
        result
    }
    /// The archive is generated only by an explicit RPC/CLI request, never by maintenance.
    pub fn read_archive(&self, id: &str, offset: u64, max_bytes: usize) -> Result<LogChunk> {
        self.finalize_provenance(id);
        let artifacts = self.artifact_lock(id)?;
        let _guard = artifacts
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let record = self.status(id)?;
        if !record.state.is_terminal() {
            return Err(ExecutorError("job_not_finished"));
        }
        if record.result_manifest.is_none() || record.provenance_error.is_some() {
            return Err(ExecutorError("result_provenance_unavailable"));
        }
        let context = self
            .inner
            .key_context
            .as_ref()
            .ok_or(ExecutorError("workspace_key_required_for_export"))?;
        let path = self
            .inner
            .config
            .state_dir
            .join("exports")
            .join(format!("{id}.lyarchive"));
        if !path.exists() {
            if offset != 0 {
                return Err(ExecutorError("archive_restart_required"));
            }
            let job = self.inner.config.state_dir.join("jobs").join(id);
            let scope = if record.had_runtime_credentials {
                crate::archive::ArchiveScope::ResultsOnly
            } else {
                crate::archive::ArchiveScope::FullProject
            };
            let metadata = serde_json::to_vec(&serde_json::json!({"version":1,"job_id":record.spec.id,"scope":scope,
                "state":record.state,"retention":record.retention,"result_manifest":record.result_manifest}))
                .map_err(|_| ExecutorError("archive_metadata_encoding_failed"))?;
            let metadata_path = job.join("export-metadata.json");
            if !metadata_path.exists() {
                let temporary = job.join(".export-metadata.tmp");
                let mut metadata_file = private_open(&temporary, false)?;
                metadata_file
                    .set_len(0)
                    .and_then(|()| metadata_file.write_all(&metadata))
                    .and_then(|()| metadata_file.sync_all())
                    .map_err(io_error)?;
                fs::rename(&temporary, &metadata_path).map_err(io_error)?;
                File::open(&job)
                    .and_then(|directory| directory.sync_all())
                    .map_err(io_error)?;
            }
            let signer = self
                .inner
                .signing_key
                .as_ref()
                .ok_or(ExecutorError("result_provenance_unavailable"))?;
            let signed_result = crate::provenance::verify_result_identity(
                record
                    .result_manifest
                    .as_ref()
                    .ok_or(ExecutorError("result_provenance_unavailable"))?,
                &signer.trusted_key(),
                &self.inner.config.node_id,
                &context.workspace,
                id,
            )
            .map_err(|_| ExecutorError("result_provenance_unavailable"))?;
            let mut paths = if record.had_runtime_credentials {
                vec![
                    "export-metadata.json".into(),
                    "output.log".into(),
                    "result.patch".into(),
                ]
            } else {
                crate::archive::job_export_paths(&job).map_err(|error| ExecutorError(error.0))?
            };
            // A scan/collection failure may leave a private partial file. Export must never
            // become a second path around the log/patch completeness and credential guards.
            paths.retain(|path| match path.as_str() {
                "output.log" => {
                    record.log_error.is_none()
                        && !record.log_truncated
                        && signed_result.artifacts.get(path).is_some_and(|artifact| {
                            !artifact.truncated && artifact.error_code.is_none()
                        })
                }
                "result.patch" => {
                    record.patch_error.is_none()
                        && !record.patch_truncated
                        && signed_result.artifacts.get(path).is_some_and(|artifact| {
                            !artifact.truncated && artifact.error_code.is_none()
                        })
                }
                _ => true,
            });
            crate::archive::export_job_files(
                &job,
                &paths,
                &path,
                &context.workspace,
                &self.inner.config.node_id,
                id,
                scope,
                now_ms(),
                &context.key,
                self.inner
                    .signing_key
                    .as_ref()
                    .ok_or(ExecutorError("result_provenance_unavailable"))?,
                &signed_result.artifacts,
            )
            .map_err(|error| ExecutorError(error.0))?;
        }
        // An export that crossed the deadline must not expose a new content copy.
        if record_content_expired(&record, now_ms())? {
            return Err(ExecutorError("job_content_expired"));
        }
        let mut file = private_open_existing(&path)?;
        let len = file.metadata().map_err(io_error)?.len();
        if len > 1024 * 1024 * 1024 || offset > len {
            return Err(ExecutorError("archive_offset_out_of_range"));
        }
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut bytes = Vec::new();
        file.take(max_bytes.min(65536) as u64)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let next_offset = offset + bytes.len() as u64;
        Ok(LogChunk {
            offset,
            next_offset,
            bytes,
            eof: next_offset == len,
            truncated: false,
        })
    }

    fn verify_owner_approval(&self, spec: &JobSpec, revision: &str) -> Result<()> {
        let runner = &self.inner.config.runners[&spec.runner];
        if !runner.action.requires_owner() && spec.owner_approval.is_none() {
            return Ok(());
        }
        let workspace = &self
            .inner
            .config
            .provenance
            .as_ref()
            .ok_or(ExecutorError("result_signing_required"))?
            .workspace;
        let pin = self
            .inner
            .config
            .node_certificate_sha256
            .as_deref()
            .ok_or(ExecutorError("owner_approval_node_incarnation_required"))?;
        let expected = crate::approvals::ApprovalExpectation {
            workspace,
            node_id: &self.inner.config.node_id,
            node_certificate_sha256: pin,
            spec,
            resolved_revision: revision,
            runner,
        };
        crate::approvals::enforce(&expected, now_ms()).map_err(|error| ExecutorError(error.0))
    }

    fn validate(&self, spec: &JobSpec) -> Result<()> {
        if !valid_id(&spec.id)
            || !crate::scheduler::valid_priority(spec.priority)
            || spec.workflow_inputs.len() > 64
            || crate::workflow::validate_inputs(&spec.workflow_inputs).is_err()
            || serde_json::to_vec(spec)
                .map_err(|_| ExecutorError("invalid_job_spec"))?
                .len()
                > 128 * 1024
            || spec.revision.is_empty()
            || spec.revision.len() > 512
            || spec.revision.contains('\0')
            || spec.arguments.len() > 256
            || spec.arguments.iter().any(|arg| arg.contains('\0'))
            || spec.arguments.iter().map(String::len).sum::<usize>() > 131072
            || spec
                .prompt
                .as_ref()
                .is_some_and(|prompt| prompt.len() > 131072 || prompt.contains('\0'))
        {
            return Err(ExecutorError("invalid_job_spec"));
        }
        if !self
            .inner
            .config
            .repositories
            .contains_key(&spec.repository)
        {
            return Err(ExecutorError("repository_not_configured"));
        }
        if !self.inner.config.runners.contains_key(&spec.runner) {
            return Err(ExecutorError("runner_not_configured"));
        }
        if let Some(expected) = &spec.expected_runner_sha256
            && (!crate::wire::valid_certificate_pin(expected)
                || *expected != runner_config_digest(&self.inner.config.runners[&spec.runner])?)
        {
            return Err(ExecutorError("runner_configuration_changed"));
        }
        let runner = &self.inner.config.runners[&spec.runner];
        if (!runner.secrets.is_empty() || !runner.env_passthrough.is_empty())
            && !runner.credential_repositories.contains(&spec.repository)
        {
            return Err(ExecutorError("credential_profile_project_forbidden"));
        }
        let mut protected = self.inner.config.protected_identity_files.clone();
        protected.push(self.inner.config.state_dir.clone());
        if let Some(signing) = &self.inner.config.provenance {
            protected.push(signing.key_file.clone());
        }
        crate::secrets::check_protected_references(&runner.secrets, &protected)
            .map_err(|error| ExecutorError(error.0))?;
        if let Some(path) = self.inner.config.repositories[&spec.repository]
            .cloud
            .as_ref()
            .and_then(|cloud| cloud.token_file.as_ref())
        {
            crate::secrets::check_private_reference(path, &protected)
                .map_err(|error| ExecutorError(error.0))?;
        }
        if spec.timeout_seconds.is_some_and(|timeout| {
            timeout == 0 || timeout > self.inner.config.limits.max_timeout_seconds
        }) {
            return Err(ExecutorError("invalid_job_timeout"));
        }
        Ok(())
    }

    fn update(&self, id: &str, change: impl FnOnce(&mut JobRecord)) -> Result<JobRecord> {
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let entry = jobs.get_mut(id).ok_or(ExecutorError("job_not_found"))?;
        change(&mut entry.record);
        entry.record.updated_at_ms = now_ms();
        note_terminal_retention(&mut entry.record)?;
        persist(&self.inner.config.state_dir, &entry.record)?;
        self.inner.worker_signal.notify();
        Ok(entry.record.clone())
    }

    fn run(&self, id: &str, cancel: Arc<AtomicBool>) {
        let result = self.run_inner(id, cancel);
        if let Err(error) = result {
            let persisted = self.update(id, |record| {
                if !terminal(&record.state) {
                    record.state = if record.state == JobState::Running {
                        // An I/O error after launch does not establish that the container stopped.
                        JobState::InterruptedUnknown
                    } else {
                        match error.0 {
                            "setup_cancelled" => JobState::Cancelled,
                            "setup_timed_out" => JobState::TimedOut,
                            _ => JobState::Failed,
                        }
                    };
                    record.error_code = Some(error.0.into());
                    record.patch_error = Some("job_setup_incomplete".into());
                    if record.state != JobState::InterruptedUnknown
                        && remove_runtime_key(&self.inner.config.state_dir.join("jobs").join(id))
                            .is_err()
                    {
                        record.error_code = Some("runtime_key_cleanup_failed".into());
                    }
                }
            });
            if persisted.is_err() {
                self.inner.dispatch_failed.store(true, Ordering::SeqCst);
            }
        }
        self.finalize_provenance(id);
    }

    // The durable Starting record is already committed. The jobs mutex makes
    // cancellation and the OS spawn a single ordered launch decision.
    fn commit_launch(
        &self,
        id: &str,
        cancel: &AtomicBool,
        job_dir: &Path,
        command: &mut Command,
    ) -> Result<Option<(std::process::Child, bool)>> {
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?;
        let entry = jobs.get_mut(id).ok_or(ExecutorError("job_not_found"))?;
        if entry.record.state != JobState::Starting {
            return Err(ExecutorError("invalid_launch_state"));
        }
        if cancel.load(Ordering::SeqCst) {
            remove_runtime_key(job_dir)?;
            entry.record.state = JobState::Cancelled;
            entry.record.patch_error = Some("job_not_started".into());
            entry.record.updated_at_ms = now_ms();
            note_terminal_retention(&mut entry.record)?;
            persist(&self.inner.config.state_dir, &entry.record)?;
            self.inner.worker_signal.notify();
            return Ok(None);
        }
        let child = command
            .spawn()
            .map_err(|_| ExecutorError("runner_spawn_failed"))?;
        entry.record.state = JobState::Running;
        entry.record.pid = Some(child.id());
        entry.record.updated_at_ms = now_ms();
        let durable = persist(&self.inner.config.state_dir, &entry.record).is_ok();
        self.inner.worker_signal.notify();
        Ok(Some((child, durable)))
    }

    fn finalize_provenance(&self, id: &str) {
        let Ok(artifacts) = self.artifact_lock(id) else {
            return;
        };
        let Ok(_guard) = artifacts.lock() else {
            return;
        };
        let Ok(record) = self.status(id) else {
            return;
        };
        if record.state.is_terminal() {
            let _ = self.release_delegation(id);
        }
        if !record.state.is_terminal()
            || record.result_manifest.is_some()
            || record.provenance_error.is_some()
        {
            return;
        }
        let result = self.build_manifest(&record);
        let Ok(mut jobs) = self.inner.jobs.lock() else {
            return;
        };
        let Some(entry) = jobs.get_mut(id) else {
            return;
        };
        if entry.record.updated_at_ms != record.updated_at_ms
            || entry.record.state != record.state
            || entry.record.result_manifest.is_some()
            || entry.record.provenance_error.is_some()
        {
            return;
        }
        let mut candidate = entry.record.clone();
        match result {
            Ok(document) => candidate.result_manifest = Some(document),
            Err(error) => candidate.provenance_error = Some(error.0.into()),
        }
        if persist(&self.inner.config.state_dir, &candidate).is_ok() {
            entry.record = candidate;
            self.capture_notification_best_effort(&mut entry.record);
        } else {
            // Never return a successful signed result whose local durable write failed.
            entry.record.provenance_error = Some("result_manifest_persist_failed".into());
        }
    }

    fn build_manifest(
        &self,
        record: &JobRecord,
    ) -> crate::provenance::Result<crate::provenance::SignedDocument> {
        use crate::provenance::{self, ProvenanceError};
        let signer = self
            .inner
            .signing_key
            .as_ref()
            .ok_or(ProvenanceError("result_signing_required"))?;
        let signing = self
            .inner
            .config
            .provenance
            .as_ref()
            .ok_or(ProvenanceError("result_signing_required"))?;
        let image_reference = record
            .configured_image
            .as_ref()
            .ok_or(ProvenanceError("legacy_result_image_unknown"))?;
        let image_digest = crate::supply_chain::immutable_image_digest(image_reference)?;
        if record.pid.is_some() && record.admitted_image.is_none() {
            return Err(ProvenanceError("result_image_admission_missing"));
        }
        if let Some(admission) = &record.admitted_image {
            admission.validate()?;
            if admission.image_reference != *image_reference
                || admission.image_digest != image_digest
            {
                return Err(ProvenanceError("result_image_admission_mismatch"));
            }
        }
        let job_dir = self
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(&record.spec.id);
        let mut artifacts = BTreeMap::new();
        for (name, limit, declared, truncated, error) in [
            (
                "output.log",
                self.inner.config.limits.max_log_bytes,
                record.log_bytes,
                record.log_truncated,
                record.log_error.clone(),
            ),
            (
                "result.patch",
                self.inner.config.limits.max_patch_bytes,
                record.patch_bytes,
                record.patch_truncated,
                record.patch_error.clone(),
            ),
        ] {
            let artifact = match fs::symlink_metadata(job_dir.join(name)) {
                Ok(_) => {
                    let (size, hash) = provenance::hash_file(&job_dir.join(name), limit)?;
                    ArtifactDigest {
                        size_bytes: size,
                        sha256: hash,
                        truncated,
                        error_code: if size != declared {
                            Some("artifact_length_mismatch".into())
                        } else {
                            error
                        },
                    }
                }
                Err(error_io) if error_io.kind() == std::io::ErrorKind::NotFound => {
                    ArtifactDigest {
                        size_bytes: 0,
                        sha256: provenance::sha256(&[]),
                        truncated,
                        error_code: error.or_else(|| Some("artifact_not_retained".into())),
                    }
                }
                Err(_) => return Err(ProvenanceError("result_artifact_unavailable")),
            };
            artifacts.insert(name.into(), artifact);
        }
        let admission = record.admitted_image.as_ref();
        let manifest = ResultManifest {
            version: 1,
            node_id: self.inner.config.node_id.clone(),
            workspace: signing.workspace.clone(),
            job_id: record.spec.id.clone(),
            repository: record.spec.repository.clone(),
            runner: record.spec.runner.clone(),
            request_sha256: provenance::sha256(
                &serde_json::to_vec(&record.spec)
                    .map_err(|_| ProvenanceError("result_request_encoding_failed"))?,
            ),
            resolved_revision: record
                .resolved_revision
                .clone()
                .ok_or(ProvenanceError("result_revision_unknown"))?,
            image_reference: image_reference.clone(),
            image_digest,
            image_config_digest: admission.map(|image| image.image_config_digest.clone()),
            image_attestation_sha256: admission.map(|image| image.attestation_sha256.clone()),
            execution_attempted: record.pid.is_some(),
            completed_at_ms: record.updated_at_ms,
            state: record.state,
            exit_code: record.exit_code,
            error_code: record.error_code.clone(),
            artifacts,
        };
        signer.sign_result(&manifest)
    }

    fn run_inner(&self, id: &str, cancel: Arc<AtomicBool>) -> Result<()> {
        let record = self.status(id)?;
        if record.state != JobState::Starting {
            return Ok(());
        }
        if cancel.load(Ordering::SeqCst) {
            self.update(id, |record| {
                record.state = JobState::Cancelled;
                record.patch_error = Some("job_not_started".into());
            })?;
            return Ok(());
        }
        let spec = &record.spec;
        // Recovery can outlive profile edits. Re-check scope before touching credentials.
        self.validate(spec)?;
        let repo = &self.inner.config.repositories[&spec.repository];
        let runner = &self.inner.config.runners[&spec.runner];
        let job_dir = self.inner.config.state_dir.join("jobs").join(id);
        if record.admission_runner_sha256.as_deref()
            != Some(admission_fingerprint(runner)?.as_str())
            || record.admission_repository_sha256.as_deref()
                != Some(admission_fingerprint(repo)?.as_str())
        {
            return Err(ExecutorError("queued_profile_changed"));
        }
        if record.configured_image.as_deref() != Some(runner.container.image.as_str()) {
            return Err(ExecutorError("queued_image_changed"));
        }
        self.verify_owner_approval(
            spec,
            record
                .resolved_revision
                .as_deref()
                .ok_or(ExecutorError("result_revision_unknown"))?,
        )?;
        check_execution_identity_paths(&self.inner.config)?;
        let worktree = job_dir.join("worktree");
        let private_git = job_dir.join("repository.git");
        private_dir_new(&job_dir.join("runtime-config"))?;
        verify_runtime_limits(&runner.container, &job_dir)?;
        let admitted_image = admit_image(&runner.container, &job_dir)?;
        self.update(id, |record| record.admitted_image = Some(admitted_image))?;
        // Independent objects and refs: the container receives no reference to the source checkout.
        let mut clone = git(&repo.checkout);
        clone
            .args(["clone", "--bare", "--no-hardlinks", "--dissociate", "--"])
            .arg(&repo.checkout)
            .arg(&private_git)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !bounded_status(&mut clone, Duration::from_secs(60), Some(&cancel))?.success() {
            return Err(ExecutorError("private_repository_creation_failed"));
        }
        let mut setup = git(&private_git);
        setup
            .args(["worktree", "add", "--detach"])
            .arg(&worktree)
            .arg(record.resolved_revision.as_ref().unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            setup.process_group(0);
        }
        let mut setup = setup.spawn().map_err(io_error)?;
        let setup_started = Instant::now();
        let setup_timeout = Duration::from_secs(
            spec.timeout_seconds
                .unwrap_or(self.inner.config.limits.max_timeout_seconds),
        );
        let output = loop {
            if cancel.load(Ordering::SeqCst) || setup_started.elapsed() >= setup_timeout {
                terminate_group(setup.id());
                let _ = setup.wait();
                self.update(id, |record| {
                    record.state = if cancel.load(Ordering::SeqCst) {
                        JobState::Cancelled
                    } else {
                        JobState::TimedOut
                    };
                    record.patch_error = Some("job_setup_incomplete".into());
                })?;
                return Ok(());
            }
            if let Some(status) = setup.try_wait().map_err(io_error)? {
                break status;
            }
            thread::sleep(Duration::from_millis(25));
        };
        if !output.success() {
            return Err(ExecutorError("worktree_creation_failed"));
        }
        self.update(id, |record| record.worktree = Some(worktree.clone()))?;
        let injected_paths: Vec<String> = match &repo.cloud {
            Some(cloud) => write_cloud_config(&worktree, cloud)?.into_iter().collect(),
            None => Vec::new(),
        };
        record_injected_paths(&job_dir, &worktree, injected_paths)?;
        if cancel.load(Ordering::SeqCst) {
            self.update(id, |record| {
                record.state = JobState::Cancelled;
                record.patch_error = Some("job_not_started".into());
            })?;
            return Ok(());
        }
        let name = format!("lockyard-{}-{id}", self.inner.config.node_id);
        self.verify_owner_approval(
            spec,
            record
                .resolved_revision
                .as_deref()
                .ok_or(ExecutorError("result_revision_unknown"))?,
        )?;
        let key_bytes = if repo.cloud.is_some() {
            let context = self
                .inner
                .key_context
                .as_ref()
                .ok_or(ExecutorError("workspace_key_unavailable"))?;
            Some(create_runtime_key(&job_dir, context)?)
        } else {
            None
        };
        let mut protected = self.inner.config.protected_identity_files.clone();
        protected.push(self.inner.config.state_dir.clone());
        if let Some(signing) = &self.inner.config.provenance {
            protected.push(signing.key_file.clone());
        }
        let resolved_secrets = crate::secrets::stage_with_budget(
            &job_dir,
            &runner.secrets,
            &protected,
            Instant::now() + Duration::from_secs(30).min(setup_timeout),
            &cancel,
        )
        .map_err(|error| {
            ExecutorError(match error.0 {
                "secret_fetch_cancelled" => "setup_cancelled",
                "secret_fetch_timed_out" => "setup_timed_out",
                code => code,
            })
        })?;
        crate::workflow::stage_context(&job_dir, &spec.workflow_inputs)
            .map_err(|_| ExecutorError("workflow_context_unavailable"))?;
        if let Some(provider) = &self.inner.delegation {
            let lease = provider
                .prepare(id, &job_dir)
                .map_err(|_| ExecutorError("delegation_unavailable"))?;
            self.store_delegation(id, lease)?;
        }
        let mut secrets: Vec<Vec<u8>> = key_bytes.into_iter().collect();
        secrets.extend(
            resolved_secrets
                .iter()
                .map(|secret| secret.bytes().to_vec()),
        );
        let forwarded = runner
            .env_passthrough
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.clone(), value)))
            .collect::<Vec<_>>();
        stage_forwarded_environment(&job_dir, forwarded, &mut secrets)?;
        if let Some(path) = repo
            .cloud
            .as_ref()
            .and_then(|cloud| cloud.token_file.as_ref())
        {
            let token = read_private_token(path)?;
            let value =
                String::from_utf8(token).map_err(|_| ExecutorError("invalid_token_file"))?;
            stage_forwarded_environment(
                &job_dir,
                vec![("LOCKYARD_TOKEN".into(), value.into())],
                &mut secrets,
            )?;
        }
        // Compile once before launching the workload; both output threads share the automaton.
        let log_matcher = Arc::new(CredentialMatcher::new(&secrets)?);
        let mut command = container_command(
            &runner.container,
            &job_dir,
            &worktree,
            &runner.program,
            &name,
            false,
        )?;
        // A node-host invocation must never fall back to legacy plaintext MCP behavior, even when
        // the checkout supplies its own Cloud configuration. Only explicitly scoped jobs get keys.
        if let Some(context) = &self.inner.key_context {
            command
                .env("LOCKYARD_REQUIRE_E2EE", "1")
                .args(["--env", "LOCKYARD_REQUIRE_E2EE"])
                .env("LOCKYARD_E2EE_WORKSPACE_ID", &context.workspace)
                .args(["--env", "LOCKYARD_E2EE_WORKSPACE_ID"]);
        }
        if let Some(cloud) = &repo.cloud {
            command
                .env("LOCKYARD_URL", &cloud.url)
                .args(["--env", "LOCKYARD_URL"]);
        }
        command
            .env("LOCKYARD_AGENT", &record.agent)
            .args(["--env", "LOCKYARD_AGENT"]);
        command
            .arg(&runner.container.image)
            .args(&runner.fixed_args);
        if matches!(runner.kind, RunnerKind::Codex) {
            let program = runner
                .mcp_program
                .as_ref()
                .ok_or(ExecutorError("codex_mcp_program_required"))?;
            let program = program
                .to_str()
                .ok_or(ExecutorError("invalid_mcp_program"))?;
            command.arg("-c").arg(format!(
                "mcp_servers.lockyard.command={}",
                serde_json::to_string(program).unwrap()
            ));
            command.args(["-c", "mcp_servers.lockyard.args=[\"mcp\"]", "-c", "mcp_servers.lockyard.env_vars=[\"LOCKYARD_AGENT\",\"LOCKYARD_URL\",\"LOCKYARD_TOKEN_FILE\",\"LOCKYARD_TOKEN\",\"XDG_CONFIG_HOME\",\"LOCKYARD_REQUIRE_E2EE\",\"LOCKYARD_E2EE_WORKSPACE_ID\",\"LOCKYARD_NODE_CONFIG\",\"LOCKYARD_WORKFLOW_INPUTS_FILE\"]"]);
            command.args(&spec.arguments).arg("--");
        } else {
            command.args(&spec.arguments);
        }
        if let Some(prompt) = &spec.prompt {
            command.arg(prompt);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let file = private_open(&job_dir.join("output.log"), true)?;
        let spool = Arc::new(Mutex::new(Spool {
            file,
            bytes: 0,
            truncated: false,
            limit: self.inner.config.limits.max_log_bytes,
            error: None,
            credential_tail: Vec::new(),
        }));
        // Starting has been fsynced before the OS is asked to launch any job process.
        // The jobs mutex linearizes cancellation with the launch commitment: a
        // cancel accepted while Starting prevents the spawn; once spawn wins,
        // cancel observes Running and is a stop request, not a never-ran claim.
        self.verify_owner_approval(
            spec,
            record
                .resolved_revision
                .as_deref()
                .ok_or(ExecutorError("result_revision_unknown"))?,
        )?;
        let Some((mut child, durable)) = self.commit_launch(id, &cancel, &job_dir, &mut command)?
        else {
            return Ok(());
        };
        let pid = child.id();
        if !durable {
            let _ = stop_container(&runner.container, &job_dir, &name);
            terminate_group(pid);
            let _ = child.wait();
            return Err(ExecutorError("running_state_not_durable"));
        }
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        if set_pipe_nonblocking(&stdout).is_err() || set_pipe_nonblocking(&stderr).is_err() {
            terminate_group(pid);
            let _ = child.wait();
            let _ = stop_container(&runner.container, &job_dir, &name);
            // Running remains durable; the common error path records Unknown.
            return Err(ExecutorError("pipe_nonblocking_failed"));
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let out_spool = spool.clone();
        let out_matcher = log_matcher.clone();
        let out_stopped = stopped.clone();
        let out_pipe_stopped = stopped.clone();
        let out = match thread::Builder::new()
            .name("lockyard-stdout".into())
            .spawn(move || {
                drain_matched(
                    StoppablePipe {
                        reader: stdout,
                        stopped: out_pipe_stopped,
                        stopped_at: None,
                    },
                    out_spool,
                    out_matcher,
                    out_stopped,
                )
            }) {
            Ok(reader) => reader,
            Err(_) => {
                terminate_group(pid);
                let _ = child.wait();
                let _ = stop_container(&runner.container, &job_dir, &name);
                return Err(ExecutorError("log_reader_spawn_failed"));
            }
        };
        let err_spool = spool.clone();
        let err_stopped = stopped.clone();
        let err_matcher = log_matcher;
        let err_pipe_stopped = stopped.clone();
        let err = match thread::Builder::new()
            .name("lockyard-stderr".into())
            .spawn(move || {
                drain_matched(
                    StoppablePipe {
                        reader: stderr,
                        stopped: err_pipe_stopped,
                        stopped_at: None,
                    },
                    err_spool,
                    err_matcher,
                    err_stopped,
                )
            }) {
            Ok(reader) => reader,
            Err(_) => {
                terminate_group(pid);
                let _ = child.wait();
                let _ = stop_container(&runner.container, &job_dir, &name);
                stopped.store(true, Ordering::SeqCst);
                let _ = out.join();
                return Err(ExecutorError("log_reader_spawn_failed"));
            }
        };
        let started = Instant::now();
        let timeout = Duration::from_secs(
            spec.timeout_seconds
                .unwrap_or(self.inner.config.limits.max_timeout_seconds),
        );
        let mut final_state = JobState::Succeeded;
        let status = loop {
            if cancel.load(Ordering::SeqCst) || started.elapsed() >= timeout {
                final_state = if cancel.load(Ordering::SeqCst) {
                    JobState::Cancelled
                } else {
                    JobState::TimedOut
                };
                terminate_group(pid);
                let status = match child.wait() {
                    Ok(status) => status,
                    Err(error) => {
                        let _ = stop_container(&runner.container, &job_dir, &name);
                        stopped.store(true, Ordering::SeqCst);
                        let _ = out.join();
                        let _ = err.join();
                        return Err(io_error(error));
                    }
                };
                if !stop_container(&runner.container, &job_dir, &name) {
                    final_state = JobState::InterruptedUnknown;
                }
                break status;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !stop_container(&runner.container, &job_dir, &name) {
                        final_state = JobState::InterruptedUnknown;
                    }
                    break status;
                }
                Ok(None) => thread::sleep(Duration::from_millis(25)),
                Err(error) => {
                    terminate_group(pid);
                    let _ = child.wait();
                    let _ = stop_container(&runner.container, &job_dir, &name);
                    stopped.store(true, Ordering::SeqCst);
                    let _ = out.join();
                    let _ = err.join();
                    return Err(io_error(error));
                }
            }
        };
        if final_state == JobState::Succeeded && !status.success() {
            final_state = JobState::Failed;
        }
        let key_cleanup_error =
            final_state != JobState::InterruptedUnknown && remove_runtime_key(&job_dir).is_err();
        if key_cleanup_error && final_state == JobState::Succeeded {
            final_state = JobState::Failed;
        }
        stopped.store(true, Ordering::SeqCst);
        let stream_error = join_stream(out).or(join_stream(err));
        let mut spool = spool
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(code) = stream_error {
            spool.mark_error(code);
        }
        if spool.file.sync_all().is_err() {
            spool.mark_error("spool_sync_failed");
        }
        let log_error = spool.error;
        if log_error.is_some() && final_state == JobState::Succeeded {
            final_state = JobState::Failed;
        }
        let patch = if final_state == JobState::InterruptedUnknown {
            Err(ExecutorError("execution_still_unknown"))
        } else {
            collect_patch_bounded(
                &runner.container,
                &job_dir,
                &worktree,
                record.resolved_revision.as_ref().unwrap(),
                &name,
                self.inner.config.limits.max_patch_bytes,
                &secrets,
                &cancel,
            )
        };
        if cancel.load(Ordering::SeqCst) && final_state == JobState::Succeeded {
            final_state = JobState::Cancelled;
        }
        self.update(id, |record| {
            match patch {
                Ok((bytes, truncated)) => {
                    record.patch_bytes = bytes;
                    record.patch_truncated = truncated;
                }
                Err(error) => {
                    record.patch_error = Some(error.0.into());
                    record.patch_truncated = true;
                    if error.0 == "patch_container_stop_unconfirmed" {
                        final_state = JobState::InterruptedUnknown;
                    } else if final_state == JobState::Succeeded {
                        final_state = JobState::Failed;
                        record.error_code = Some("patch_incomplete".into());
                    }
                }
            }
            if final_state == JobState::InterruptedUnknown {
                record.error_code = Some("container_stop_unconfirmed".into());
            } else if log_error.is_some() {
                record.error_code = Some("log_incomplete".into());
            } else if key_cleanup_error {
                record.error_code = Some("runtime_key_cleanup_failed".into());
            }
            record.state = final_state;
            record.exit_code = status.code();
            record_log_integrity(record, spool.bytes, spool.truncated, log_error);
        })?;
        Ok(())
    }
}

fn record_content_expired(record: &JobRecord, now: u64) -> Result<bool> {
    record
        .retention
        .as_ref()
        .ok_or(ExecutorError("project_retention_required"))?
        .expired(record.state, now)
        .map_err(|error| ExecutorError(error.0))
}
fn note_terminal_retention(record: &mut JobRecord) -> Result<()> {
    record
        .retention
        .as_mut()
        .ok_or(ExecutorError("project_retention_required"))?
        .note_terminal(record.state, record.updated_at_ms)
        .map_err(|error| ExecutorError(error.0))
}
fn retire_job_directory(state: &Path, id: &str) -> Result<()> {
    if !valid_id(id) {
        return Err(ExecutorError("invalid_job_id"));
    }
    let job = state.join("jobs").join(id);
    let expired = state.join("expired-content").join(id);
    match fs::symlink_metadata(&job) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ExecutorError("unsafe_expired_job_directory"));
            }
            match fs::symlink_metadata(&expired) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    fs::remove_dir_all(&expired).map_err(io_error)?
                }
                Ok(_) => return Err(ExecutorError("unsafe_expired_job_directory")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(io_error(error)),
            }
            fs::rename(&job, &expired).map_err(io_error)?;
            File::open(state.join("jobs"))
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?;
            File::open(state.join("expired-content"))
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error(error)),
    }
    let export = state.join("exports").join(format!("{id}.lyarchive"));
    match fs::remove_file(export) {
        Ok(()) => File::open(state.join("exports"))
            .and_then(|directory| directory.sync_all())
            .map_err(io_error)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error(error)),
    }
    match fs::symlink_metadata(&expired) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(expired).map_err(io_error)?;
            File::open(state.join("expired-content"))
                .and_then(|directory| directory.sync_all())
                .map_err(io_error)?;
        }
        Ok(_) => return Err(ExecutorError("unsafe_expired_job_directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error(error)),
    }
    let tombstone = retention::load_tombstone(&state.join("job-tombstones"), id)
        .map_err(|error| ExecutorError(error.0))?
        .ok_or(ExecutorError("job_tombstone_required_before_erasure"))?;
    retention::store_purge_completion(&state.join("purge-completed"), &tombstone, now_ms())
        .map_err(|error| ExecutorError(error.0))?;
    Ok(())
}

/// A checkout must never snapshot node/control keys or another executor's state.
fn check_execution_identity_paths(config: &ExecutorConfig) -> Result<()> {
    let mut protected = config.protected_identity_files.clone();
    protected.push(config.state_dir.clone());
    if let Some(signing) = &config.provenance {
        protected.push(signing.key_file.clone());
    }
    for repository in config.repositories.values() {
        let checkout = fs::canonicalize(&repository.checkout)
            .map_err(|_| ExecutorError("checkout_unavailable"))?;
        for path in &protected {
            let path = match fs::canonicalize(path) {
                Ok(path) => path,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(ExecutorError("protected_identity_unavailable")),
            };
            if path.starts_with(&checkout) || checkout.starts_with(&path) {
                return Err(ExecutorError("identity_must_be_outside_execution_mounts"));
            }
        }
    }
    Ok(())
}

/// Forward every explicitly allowed value through a private file, treating all
/// names as credentials. No heuristic based on AUTH/TOKEN/URL naming is safe.
fn stage_forwarded_environment(
    job_dir: &Path,
    values: Vec<(String, std::ffi::OsString)>,
    secrets: &mut Vec<Vec<u8>>,
) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    let mut encoded = Vec::new();
    for (name, value) in values {
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ExecutorError("invalid_credential_environment"));
        }
        let value = value
            .into_string()
            .map_err(|_| ExecutorError("credential_environment_requires_utf8"))?;
        if value.len() > 16384 {
            return Err(ExecutorError("forwarded_credential_too_large"));
        }
        if value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
            return Err(ExecutorError("credential_environment_requires_one_line"));
        }
        encoded.push((name, value.into_bytes()));
    }
    let directory = job_dir.join("runtime-secrets");
    private_dir(&directory)?;
    let mut file = private_open(&directory.join(".environment"), false)?;
    if file.metadata().map_err(io_error)?.len() > 2 * 1024 * 1024 {
        return Err(ExecutorError("credential_environment_too_large"));
    }
    file.seek(SeekFrom::End(0)).map_err(io_error)?;
    for (name, value) in encoded {
        file.write_all(name.as_bytes())
            .and_then(|()| file.write_all(b"="))
            .and_then(|()| file.write_all(&value))
            .and_then(|()| file.write_all(b"\n"))
            .map_err(io_error)?;
        if !value.is_empty() {
            secrets.push(value);
        }
    }
    file.sync_all().map_err(io_error)?;
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    File::open(job_dir)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    Ok(())
}

fn create_runtime_key(job_dir: &Path, context: &WorkspaceKeyContext) -> Result<Vec<u8>> {
    let root = job_dir.join("runtime-key");
    private_dir_new(&root)?;
    private_dir_new(&root.join("lockyard"))?;
    private_dir_new(&root.join("lockyard/keys"))?;
    let path = root
        .join("lockyard/keys")
        .join(format!("{}.key", context.workspace));
    context
        .key
        .copy_to_private(&path)
        .map_err(|_| ExecutorError("runtime_key_copy_failed"))?;
    let mut key = Vec::new();
    private_open_existing(&path)?
        .take(33)
        .read_to_end(&mut key)
        .map_err(io_error)?;
    if key.len() != 32 {
        return Err(ExecutorError("runtime_key_copy_failed"));
    }
    Ok(key)
}
fn remove_runtime_key(job_dir: &Path) -> Result<()> {
    remove_private_runtime_directory(job_dir, "runtime-key")?;
    remove_private_runtime_directory(job_dir, "runtime-secrets")
}

fn remove_private_runtime_directory(job_dir: &Path, name: &str) -> Result<()> {
    let path = job_dir.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(|_| ExecutorError("runtime_key_cleanup_failed"))?;
            File::open(job_dir)
                .map_err(io_error)?
                .sync_all()
                .map_err(io_error)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(ExecutorError("runtime_key_cleanup_failed")),
    }
}

fn record_log_integrity(
    record: &mut JobRecord,
    bytes: u64,
    truncated: bool,
    error: Option<&'static str>,
) {
    record.log_bytes = bytes;
    record.log_truncated = truncated || error.is_some();
    record.log_error = error.map(str::to_owned);
    if error.is_some() && record.state == JobState::Succeeded {
        record.state = JobState::Failed;
        record.error_code = Some("log_incomplete".into());
    }
}

fn quarantine_prejournal(state_dir: &Path, path: &Path, id: &str) -> Result<()> {
    private_dir(path)?;
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_name() != "record.json.tmp" || !entry.file_type().map_err(io_error)?.is_file()
        {
            // Worktree/runtime/output artifacts cannot precede the first durable record.
            return Err(ExecutorError("unclassified_job_directory"));
        }
    }
    let quarantine = state_dir.join("prejournal-quarantine");
    private_dir(&quarantine)?;
    let suffix = crate::wire::new_id().map_err(|_| ExecutorError("quarantine_identity_failed"))?;
    let destination = quarantine.join(format!("{id}-{suffix}"));
    if destination.exists() {
        return Err(ExecutorError("quarantine_collision"));
    }
    fs::rename(path, destination).map_err(io_error)?;
    for parent in [state_dir.to_path_buf(), state_dir.join("jobs"), quarantine] {
        File::open(parent)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
    }
    Ok(())
}

fn runtime_command(profile: &ContainerProfile, job_dir: &Path) -> Command {
    let mut command = Command::new(&profile.runtime_program);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    // Empty per-job client config prevents ambient Docker proxy/credential settings leaking in.
    command.env("DOCKER_CONFIG", job_dir.join("runtime-config"));
    match profile.runtime {
        ContainerRuntime::Docker => {
            command.arg("--host=unix:///var/run/docker.sock");
        }
        ContainerRuntime::Podman => {
            command.arg("--remote=false");
            if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
                command.env("XDG_RUNTIME_DIR", path);
            }
        }
    }
    command.current_dir(job_dir);
    command
}

fn host_container_identity() -> String {
    #[cfg(unix)]
    {
        format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    }
    #[cfg(not(unix))]
    {
        "0:0".into()
    }
}
fn container_identity(job_dir: &Path) -> Result<String> {
    let mut file = private_open_existing(&job_dir.join("runtime-user"))?;
    let mut value = String::new();
    Read::by_ref(&mut file)
        .take(64)
        .read_to_string(&mut value)
        .map_err(io_error)?;
    let Some((uid, gid)) = value.split_once(':') else {
        return Err(ExecutorError("runtime_identity_unavailable"));
    };
    if uid.parse::<u32>().is_err() || gid.parse::<u32>().is_err() {
        return Err(ExecutorError("runtime_identity_unavailable"));
    }
    Ok(value)
}

fn container_command(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    program: &Path,
    name: &str,
    patch: bool,
) -> Result<Command> {
    let identity = container_identity(job_dir)?;
    let mut command = runtime_command(profile, job_dir);
    command
        .args([
            "run",
            "--pull=never",
            "--no-healthcheck",
            "--name",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--ipc=none",
            "--user",
            &identity,
            "--pids-limit",
        ])
        .arg(profile.pids_limit.to_string())
        .arg("--memory")
        .arg(format!("{}m", profile.memory_mb))
        .arg("--memory-swap")
        .arg(format!("{}m", profile.memory_mb))
        .arg("--cpus")
        .arg(format!(
            "{}.{:03}",
            profile.cpu_millis / 1000,
            profile.cpu_millis % 1000
        ))
        .arg("--network")
        .arg(
            if patch || matches!(profile.network, ContainerNetwork::None) {
                "none"
            } else {
                "bridge"
            },
        )
        .args([
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=67108864",
            "--env",
            "HOME=/tmp",
            "--env",
            "TMPDIR=/tmp",
        ])
        .arg("--workdir")
        .arg(worktree)
        .arg("--entrypoint")
        .arg(program);
    for path in [worktree.to_path_buf(), job_dir.join("repository.git")] {
        let path = path
            .to_str()
            .ok_or(ExecutorError("invalid_container_mount"))?;
        if path.contains([',', ':', '\n', '\r']) {
            return Err(ExecutorError("invalid_container_mount"));
        }
        let readonly = if patch && Path::new(path) == worktree {
            ",readonly"
        } else {
            ""
        };
        command
            .arg("--mount")
            .arg(format!("type=bind,src={path},dst={path}{readonly}"));
    }
    if !patch && job_dir.join("runtime-key").exists() {
        let path = job_dir.join("runtime-key");
        private_dir(&path)?;
        let path = path
            .to_str()
            .ok_or(ExecutorError("invalid_container_mount"))?;
        command
            .arg("--mount")
            .arg(format!(
                "type=bind,src={path},dst=/run/lockyard-config,readonly"
            ))
            .args(["--env", "XDG_CONFIG_HOME=/run/lockyard-config"]);
    }
    if !patch && job_dir.join("runtime-secrets").exists() {
        let path = job_dir.join("runtime-secrets");
        private_dir(&path)?;
        let path_text = path
            .to_str()
            .ok_or(ExecutorError("invalid_container_mount"))?;
        if path_text.contains([',', ':', '\n', '\r']) {
            return Err(ExecutorError("invalid_container_mount"));
        }
        command
            .arg("--mount")
            .arg(format!(
                "type=bind,src={path_text},dst=/run/lockyard-secrets,readonly"
            ))
            .args(["--env", "LOCKYARD_SECRETS_DIR=/run/lockyard-secrets"]);
        let environment = path.join(".environment");
        if environment.exists() {
            private_open_existing(&environment)?;
            // Runtime client reads a private file; values never enter its argv or environment.
            command.arg("--env-file").arg(environment);
        }
    }
    for (directory, destination, variable, relative) in [
        (
            "runtime-context",
            "/run/lockyard-context",
            "LOCKYARD_WORKFLOW_INPUTS_FILE",
            "workflow-inputs.json",
        ),
        (
            "runtime-delegation",
            "/run/lockyard-delegation",
            "LOCKYARD_NODE_CONFIG",
            "node.toml",
        ),
    ] {
        if !patch && job_dir.join(directory).exists() {
            let path = job_dir.join(directory);
            private_dir(&path)?;
            let path_text = path
                .to_str()
                .ok_or(ExecutorError("invalid_container_mount"))?;
            if path_text.contains([',', ':', '\n', '\r']) {
                return Err(ExecutorError("invalid_container_mount"));
            }
            command
                .arg("--mount")
                .arg(format!(
                    "type=bind,src={path_text},dst={destination},readonly"
                ))
                .args(["--env", &format!("{variable}={destination}/{relative}")]);
        }
    }
    Ok(command)
}

fn bounded_status(
    command: &mut Command,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(io_error)?;
    let started = Instant::now();
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) || started.elapsed() >= timeout {
            terminate_group(child.id());
            let _ = child.wait();
            return Err(ExecutorError(
                if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
                    "setup_cancelled"
                } else {
                    "setup_timed_out"
                },
            ));
        }
        if let Some(status) = child.try_wait().map_err(io_error)? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn verify_runtime_limits(profile: &ContainerProfile, job_dir: &Path) -> Result<()> {
    let mut command = runtime_command(profile, job_dir);
    match profile.runtime {
        ContainerRuntime::Docker => {
            command.args([
                "info",
                "--format",
                "{{.MemoryLimit}} {{.CPUCfsQuota}} {{.PidsLimit}}",
            ]);
        }
        ContainerRuntime::Podman => {
            command.args(["info", "--format", "{{json .Host.CgroupControllers}}"]);
        }
    }
    let bytes = probe_runtime(&mut command)?;
    let text = String::from_utf8_lossy(&bytes);
    let verified =
        match profile.runtime {
            ContainerRuntime::Docker => text.trim() == "true true true",
            ContainerRuntime::Podman => serde_json::from_str::<Vec<String>>(&text)
                .ok()
                .is_some_and(|controllers| {
                    ["memory", "cpu", "pids"]
                        .iter()
                        .all(|required| controllers.iter().any(|controller| controller == required))
                }),
        };
    if !verified {
        return Err(ExecutorError("container_limits_unavailable"));
    }
    let mut image = runtime_command(profile, job_dir);
    image.args([
        "image",
        "inspect",
        "--format",
        "{{json .Config.Volumes}}",
        &profile.image,
    ]);
    let volumes =
        probe_runtime(&mut image).map_err(|_| ExecutorError("container_image_unavailable"))?;
    let volumes: serde_json::Value = serde_json::from_slice(&volumes)
        .map_err(|_| ExecutorError("container_image_probe_failed"))?;
    if !volumes.is_null()
        && !volumes
            .as_object()
            .is_some_and(|volumes| volumes.is_empty())
    {
        return Err(ExecutorError("container_image_declares_volumes"));
    }
    let mut security = runtime_command(profile, job_dir);
    security.args([
        "info",
        "--format",
        match profile.runtime {
            ContainerRuntime::Docker => "{{json .SecurityOptions}}",
            ContainerRuntime::Podman => "{{.Host.Security.Rootless}}",
        },
    ]);
    let value = probe_runtime(&mut security)?;
    let rootless = match profile.runtime {
        ContainerRuntime::Docker => serde_json::from_slice::<Vec<String>>(&value)
            .map_err(|_| ExecutorError("runtime_identity_unavailable"))?
            .iter()
            .any(|entry| entry == "name=rootless"),
        ContainerRuntime::Podman => serde_json::from_slice::<bool>(&value)
            .map_err(|_| ExecutorError("runtime_identity_unavailable"))?,
    };
    let identity = if rootless {
        "0:0".to_string()
    } else {
        host_container_identity()
    };
    let mut file = private_open(&job_dir.join("runtime-user"), true)?;
    file.write_all(identity.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    Ok(())
}

fn admit_image(profile: &ContainerProfile, job_dir: &Path) -> Result<VerifiedImage> {
    let policy = profile
        .supply_chain
        .as_ref()
        .ok_or(ExecutorError("supply_chain_policy_required"))?;
    let admission = crate::supply_chain::verify_image(policy, &profile.image, now_ms())
        .map_err(|error| ExecutorError(error.0))?;
    let mut inspect = runtime_command(profile, job_dir);
    inspect.args(["image", "inspect", "--format", "{{.Id}}", &profile.image]);
    let bytes = probe_runtime(&mut inspect)
        .map_err(|_| ExecutorError("container_image_identity_unavailable"))?;
    let actual = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|_| ExecutorError("container_image_identity_unavailable"))?;
    let actual = if crate::provenance::valid_sha256(actual) {
        format!("sha256:{actual}")
    } else {
        actual.into()
    };
    if actual != admission.image_config_digest {
        return Err(ExecutorError("container_image_identity_mismatch"));
    }
    Ok(admission)
}

fn probe_runtime(command: &mut Command) -> Result<Vec<u8>> {
    let (status, output, _) = runtime_output(command, Duration::from_secs(5), 4096, None)
        .map_err(|_| ExecutorError("container_runtime_unavailable"))?;
    if !status.success() {
        return Err(ExecutorError("container_runtime_unavailable"));
    }
    Ok(output)
}

fn stop_container(profile: &ContainerProfile, job_dir: &Path, name: &str) -> bool {
    let mut remove = runtime_command(profile, job_dir);
    remove
        .args(["container", "rm", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if bounded_status(&mut remove, Duration::from_secs(5), None)
        .is_ok_and(|status| status.success())
    {
        return true;
    }
    let mut command = runtime_command(profile, job_dir);
    command
        .args(["kill", "--signal", "KILL", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let kill_confirmed = bounded_status(&mut command, Duration::from_secs(5), None)
        .is_ok_and(|status| status.success());
    let mut inspect = runtime_command(profile, job_dir);
    inspect.args(["container", "inspect", "--format", "{{json .State}}", name]);
    let Ok((status, output, error)) =
        runtime_output(&mut inspect, Duration::from_secs(5), 4096, None)
    else {
        return false;
    };
    if status.success() {
        let Ok(state) = serde_json::from_slice::<serde_json::Value>(&output) else {
            return false;
        };
        let stopped = matches!(
            state.get("Status").and_then(serde_json::Value::as_str),
            Some("exited" | "dead")
        ) && state.get("Running").and_then(serde_json::Value::as_bool) == Some(false)
            && state.get("Paused").and_then(serde_json::Value::as_bool) == Some(false)
            && state.get("Restarting").and_then(serde_json::Value::as_bool) == Some(false);
        if stopped {
            let mut remove = runtime_command(profile, job_dir);
            remove
                .args(["container", "rm", name])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = bounded_status(&mut remove, Duration::from_secs(5), None);
        }
        return stopped;
    }
    // Absence alone cannot settle a run/create request still in flight. Only an acknowledged
    // kill followed by the runtime's exact not-found response establishes automatic removal.
    if !kill_confirmed {
        return false;
    }
    let text = String::from_utf8_lossy(&error);
    match profile.runtime {
        ContainerRuntime::Docker => [
            format!("Error: No such container: {name}"),
            format!("Error: No such object: {name}"),
            format!("Error response from daemon: No such container: {name}"),
        ]
        .iter()
        .any(|expected| text.trim() == expected),
        ContainerRuntime::Podman => {
            text.trim()
                == format!(
                    "Error: no container with name or ID \"{name}\" found: no such container"
                )
        }
    }
}

fn runtime_output(
    command: &mut Command,
    timeout: Duration,
    limit: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(io_error)?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let started = Instant::now();
    let mut status = None;
    let outcome = (|| {
        set_pipe_nonblocking(&stdout)?;
        set_pipe_nonblocking(&stderr)?;
        let (mut output, mut error) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if started.elapsed() >= timeout
                || cancel.is_some_and(|flag| flag.load(Ordering::SeqCst))
            {
                return Err(ExecutorError("runtime_output_timeout"));
            }
            if status.is_none() {
                status = child.try_wait().map_err(io_error)?;
            }
            let mut progress = false;
            for (pipe, bytes, eof) in [
                (&mut stdout as &mut dyn Read, &mut output, &mut out_eof),
                (&mut stderr as &mut dyn Read, &mut error, &mut err_eof),
            ] {
                if *eof {
                    continue;
                }
                let mut buffer = [0u8; 8192];
                match pipe.read(&mut buffer) {
                    Ok(0) => {
                        *eof = true;
                        progress = true;
                    }
                    Ok(n) => {
                        if bytes.len().saturating_add(n) as u64 > limit {
                            return Err(ExecutorError("runtime_output_limit"));
                        }
                        bytes.extend_from_slice(&buffer[..n]);
                        progress = true;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(io_error(error)),
                }
            }
            if out_eof
                && err_eof
                && let Some(status) = status
            {
                return Ok((status, output, error));
            }
            if !progress {
                thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    if outcome.is_err() && status.is_none() {
        terminate_group(child.id());
        let _ = child.wait();
    }
    outcome
}

#[cfg(unix)]
fn set_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ExecutorError("pipe_nonblocking_failed"));
    }
    Ok(())
}
#[cfg(not(unix))]
fn set_pipe_nonblocking<T>(_pipe: &T) -> Result<()> {
    Err(ExecutorError("execution_requires_unix"))
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
fn valid_blob_id(oid: &str) -> bool {
    [40, 64].contains(&oid.len()) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn record_injected_paths(job_dir: &Path, worktree: &Path, paths: Vec<String>) -> Result<()> {
    let mut injections = Vec::new();
    for path in paths {
        let output = git(&job_dir.join("repository.git"))
            .args(["hash-object", "--no-filters", "--"])
            .arg(worktree.join(&path))
            .output()
            .map_err(io_error)?;
        let blob = String::from_utf8(output.stdout)
            .map_err(|_| ExecutorError("injection_manifest_failed"))?
            .trim()
            .to_string();
        if !output.status.success() || !valid_blob_id(&blob) {
            return Err(ExecutorError("injection_manifest_failed"));
        }
        injections.push(InjectedPath { path, blob });
    }
    let mut file = private_open(&job_dir.join("injected-paths.json"), true)?;
    file.write_all(
        &serde_json::to_vec(&injections).map_err(|_| ExecutorError("injection_manifest_failed"))?,
    )
    .map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    File::open(job_dir)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)?;
    Ok(())
}
fn load_injected_paths(job_dir: &Path) -> Result<Vec<InjectedPath>> {
    let path = job_dir.join("injected-paths.json");
    let mut file = match private_open_existing(&path) {
        Ok(file) => file,
        Err(_) if !path.exists() => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 4096 {
        return Err(ExecutorError("invalid_injection_manifest"));
    }
    let injections: Vec<InjectedPath> =
        serde_json::from_slice(&bytes).map_err(|_| ExecutorError("invalid_injection_manifest"))?;
    if injections.len() > 1
        || injections
            .iter()
            .any(|item| item.path != ".lockyard/config.toml" || !valid_blob_id(&item.blob))
    {
        return Err(ExecutorError("invalid_injection_manifest"));
    }
    Ok(injections)
}
#[allow(clippy::too_many_arguments)]
fn verify_injected_paths(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    name: &str,
    git_args: &[String],
    injections: &[InjectedPath],
    budget: &PatchBudget<'_>,
) -> Result<()> {
    for injection in injections {
        let run = |suffix: &str, arguments: &[&str]| -> Result<Vec<u8>> {
            let args: Vec<_> = arguments.iter().map(OsString::from).collect();
            patch_git_output(
                profile,
                job_dir,
                worktree,
                &format!("{name}-injection-{suffix}"),
                git_args,
                &args,
                4096,
                budget,
            )
            .map_err(|error| {
                if matches!(
                    error.0,
                    "patch_container_stop_unconfirmed"
                        | "patch_collection_cancelled"
                        | "patch_collection_timeout"
                ) {
                    error
                } else {
                    ExecutorError("patch_injected_file_changed")
                }
            })
        };
        run("stage", &["add", "-f", "--", &injection.path])?;
        let index = run(
            "type",
            &["ls-files", "--stage", "-z", "--", &injection.path],
        )?;
        let expected = format!("100644 {} 0\t{}\0", injection.blob, injection.path);
        if index != expected.as_bytes() {
            return Err(ExecutorError("patch_injected_file_changed"));
        }
        let hash = run(
            "raw",
            &["hash-object", "--no-filters", "--", &injection.path],
        )?;
        if std::str::from_utf8(&hash).ok().map(str::trim) != Some(injection.blob.as_str()) {
            return Err(ExecutorError("patch_injected_file_changed"));
        }
        run(
            "remove",
            &["update-index", "--force-remove", "--", &injection.path],
        )?;
    }
    Ok(())
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

#[cfg(test)]
fn collect_patch(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    revision: &str,
    name: &str,
    limit: u64,
    secrets: &[Vec<u8>],
) -> Result<(u64, bool)> {
    collect_patch_bounded(
        profile,
        job_dir,
        worktree,
        revision,
        name,
        limit,
        secrets,
        &AtomicBool::new(false),
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_patch_bounded(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    revision: &str,
    name: &str,
    limit: u64,
    secrets: &[Vec<u8>],
    cancel: &AtomicBool,
) -> Result<(u64, bool)> {
    let budget = PatchBudget::new(cancel);
    let metadata = job_dir.join("repository.git");
    let index = metadata.join("lockyard-export.index");
    let git_args = [
        format!("--git-dir={}", metadata.display()),
        format!("--work-tree={}", worktree.display()),
    ];
    let injections = load_injected_paths(job_dir)?;
    let mut pathspecs = vec![".".to_string()];
    pathspecs.extend(
        injections
            .iter()
            .map(|injection| format!(":(exclude,literal){}", injection.path)),
    );
    // Git evaluates job-controlled attributes/config only inside a fresh, credential-free container.
    for (suffix, args) in [
        ("read", vec!["read-tree", revision]),
        ("add", vec!["add", "-A", "--"]),
    ] {
        let patch_name = format!("{name}-{suffix}");
        let mut command = container_command(
            profile,
            job_dir,
            worktree,
            &profile.git_program,
            &patch_name,
            true,
        )?;
        command
            .env("GIT_INDEX_FILE", &index)
            .args(["--env", "GIT_INDEX_FILE"])
            .arg(&profile.image)
            .args(&git_args)
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(&args);
        if suffix == "add" {
            command.args(&pathspecs);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match bounded_status(&mut command, budget.remaining()?, Some(budget.cancel)) {
            Ok(status) if status.success() => {
                if !stop_container(profile, job_dir, &patch_name) {
                    return Err(ExecutorError("patch_container_stop_unconfirmed"));
                }
            }
            _ => {
                if !stop_container(profile, job_dir, &patch_name) {
                    return Err(ExecutorError("patch_container_stop_unconfirmed"));
                }
                return Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
                    "patch_collection_cancelled"
                } else {
                    "patch_index_failed"
                }));
            }
        }
    }
    verify_injected_paths(
        profile,
        job_dir,
        worktree,
        name,
        &git_args,
        &injections,
        &budget,
    )?;
    let credential_matcher = Arc::new(CredentialMatcher::new(secrets)?);
    scan_patch_credentials(
        profile,
        job_dir,
        worktree,
        revision,
        name,
        limit,
        &credential_matcher,
        &git_args,
        &pathspecs,
        &budget,
    )?;
    let patch_name = format!("{name}-diff");
    let mut command = container_command(
        profile,
        job_dir,
        worktree,
        &profile.git_program,
        &patch_name,
        true,
    )?;
    command
        .env("GIT_INDEX_FILE", &index)
        .args(["--env", "GIT_INDEX_FILE"])
        .arg(&profile.image)
        .args(&git_args)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            revision,
            "--",
        ])
        .args(&pathspecs)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let timeout = budget.remaining()?;
    let file = private_open(&job_dir.join("result.patch"), true)?;
    let mut child = command.spawn().map_err(io_error)?;
    let output = child.stdout.take().unwrap();
    if set_pipe_nonblocking(&output).is_err() {
        terminate_group(child.id());
        let _ = child.wait();
        if !stop_container(profile, job_dir, &patch_name) {
            return Err(ExecutorError("patch_container_stop_unconfirmed"));
        }
        return Err(ExecutorError("pipe_nonblocking_failed"));
    }
    let spool = Arc::new(Mutex::new(Spool {
        file,
        bytes: 0,
        truncated: false,
        limit,
        error: None,
        credential_tail: Vec::new(),
    }));
    let reader_spool = spool.clone();
    let matcher = Arc::new(CredentialMatcher::new(&[])?);
    let pipe_stopped = Arc::new(AtomicBool::new(false));
    let reader_stopped = pipe_stopped.clone();
    let reader = match thread::Builder::new()
        .name("lockyard-patch-reader".into())
        .spawn(move || {
            // A Git patch is a serialization: rewriting bytes would silently corrupt binary patches.
            drain_matched(
                StoppablePipe {
                    reader: output,
                    stopped: reader_stopped,
                    stopped_at: None,
                },
                reader_spool,
                matcher,
                Arc::new(AtomicBool::new(false)),
            )
        }) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_group(child.id());
            let _ = child.wait();
            if !stop_container(profile, job_dir, &patch_name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            return Err(ExecutorError("patch_reader_spawn_failed"));
        }
    };
    let started = Instant::now();
    let mut stop_confirmed = true;
    let success = loop {
        if started.elapsed() > timeout || budget.cancel.load(Ordering::SeqCst) {
            terminate_group(child.id());
            let _ = child.wait();
            stop_confirmed = stop_container(profile, job_dir, &patch_name);
            break false;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    stop_confirmed = stop_container(profile, job_dir, &patch_name);
                }
                break status.success();
            }
            Ok(None) => {}
            Err(_) => {
                terminate_group(child.id());
                let _ = child.wait();
                stop_confirmed = stop_container(profile, job_dir, &patch_name);
                break false;
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    if success {
        stop_confirmed = stop_container(profile, job_dir, &patch_name);
    }
    pipe_stopped.store(true, Ordering::SeqCst);
    let stream_error = join_stream(reader);
    if !stop_confirmed {
        return Err(ExecutorError("patch_container_stop_unconfirmed"));
    }
    if !success {
        return Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
            "patch_collection_cancelled"
        } else {
            "patch_diff_failed"
        }));
    }
    let spool = spool
        .lock()
        .map_err(|_| ExecutorError("patch_spool_poisoned"))?;
    if stream_error.is_some() || spool.error.is_some() {
        return Err(ExecutorError("patch_stream_incomplete"));
    }
    spool
        .file
        .sync_all()
        .map_err(|_| ExecutorError("patch_spool_sync_failed"))?;
    if !secrets.is_empty() {
        let mut file = spool
            .file
            .try_clone()
            .map_err(|_| ExecutorError("patch_spool_read_failed"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ExecutorError("patch_spool_read_failed"))?;
        scan_credential_stream_matched(file, &credential_matcher, limit)?;
    }
    Ok((spool.bytes, spool.truncated))
}

#[allow(clippy::too_many_arguments)]
fn patch_git_output(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    name: &str,
    git_args: &[String],
    args: &[OsString],
    limit: u64,
    budget: &PatchBudget<'_>,
) -> Result<Vec<u8>> {
    let mut command =
        container_command(profile, job_dir, worktree, &profile.git_program, name, true)?;
    command
        .env(
            "GIT_INDEX_FILE",
            job_dir.join("repository.git/lockyard-export.index"),
        )
        .args(["--env", "GIT_INDEX_FILE"])
        .arg(&profile.image)
        .args(git_args)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args);
    match runtime_output(
        &mut command,
        budget.remaining()?,
        limit,
        Some(budget.cancel),
    ) {
        Ok((status, bytes, _)) if status.success() => {
            if !stop_container(profile, job_dir, name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            Ok(bytes)
        }
        _ => {
            if !stop_container(profile, job_dir, name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
                "patch_collection_cancelled"
            } else {
                "patch_credential_scan_failed"
            }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_patch_credentials(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    revision: &str,
    name: &str,
    limit: u64,
    matcher: &Arc<CredentialMatcher>,
    git_args: &[String],
    pathspecs: &[String],
    budget: &PatchBudget<'_>,
) -> Result<()> {
    if matcher.automaton.is_none() {
        return Ok(());
    }
    let mut args: Vec<OsString> = [
        "diff",
        "--cached",
        "--raw",
        "-z",
        "--no-renames",
        "--no-abbrev",
        revision,
        "--",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.extend(pathspecs.iter().map(OsString::from));
    let raw = patch_git_output(
        profile,
        job_dir,
        worktree,
        &format!("{name}-scan-list"),
        git_args,
        &args,
        limit.min(1024 * 1024),
        budget,
    )?;
    if matcher.contains(&raw) {
        return Err(ExecutorError("patch_contains_forwarded_credential"));
    }
    let mut fields = raw.split(|byte| *byte == 0);
    let mut objects = BTreeSet::new();
    let mut paths = Vec::new();
    while let Some(header) = fields.next() {
        if header.is_empty() {
            break;
        }
        let text = std::str::from_utf8(header)
            .map_err(|_| ExecutorError("patch_credential_scan_failed"))?;
        let columns: Vec<_> = text.split_ascii_whitespace().collect();
        if columns.len() != 5 || !columns[0].starts_with(':') {
            return Err(ExecutorError("patch_credential_scan_failed"));
        }
        for oid in [columns[2], columns[3]] {
            if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ExecutorError("patch_credential_scan_failed"));
            }
            if oid.bytes().any(|byte| byte != b'0') {
                objects.insert(oid.to_string());
            }
        }
        let path = fields
            .next()
            .ok_or(ExecutorError("patch_credential_scan_failed"))?;
        if path.is_empty() {
            return Err(ExecutorError("patch_credential_scan_failed"));
        }
        if columns[3].bytes().any(|byte| byte != b'0') {
            paths.push(path.to_vec());
        }
    }
    if paths.len() + objects.len() > MAX_PATCH_SCAN_ENTRIES {
        return Err(ExecutorError("patch_credential_scan_entries"));
    }
    let mut scanned = raw.len() as u64;
    for (index, oid) in objects.iter().enumerate() {
        let remaining = limit
            .checked_sub(scanned)
            .ok_or(ExecutorError("patch_credential_scan_limit"))?;
        let args = [
            OsString::from("cat-file"),
            OsString::from("blob"),
            OsString::from(oid),
        ];
        scanned += patch_git_scan_blob(
            profile,
            job_dir,
            worktree,
            &format!("{name}-scan-blob-{index}"),
            git_args,
            &args,
            remaining,
            matcher,
            budget,
        )?;
    } // Index clean filters can transform content. Also hash the unfiltered worktree bytes inside
    // the container, then inspect those raw objects. No host path/symlink is ever opened here.
    for (index, path) in paths.into_iter().enumerate() {
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(path)
        };
        #[cfg(not(unix))]
        let path = OsString::from(
            String::from_utf8(path).map_err(|_| ExecutorError("patch_credential_scan_failed"))?,
        );
        let args = [
            OsString::from("hash-object"),
            OsString::from("--no-filters"),
            OsString::from("-w"),
            OsString::from("--"),
            path,
        ];
        let output = patch_git_output(
            profile,
            job_dir,
            worktree,
            &format!("{name}-scan-raw-{index}"),
            git_args,
            &args,
            128,
            budget,
        )?;
        let oid = std::str::from_utf8(&output)
            .map_err(|_| ExecutorError("patch_credential_scan_failed"))?
            .trim();
        if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ExecutorError("patch_credential_scan_failed"));
        }
        if objects.insert(oid.to_string()) {
            let remaining = limit
                .checked_sub(scanned)
                .ok_or(ExecutorError("patch_credential_scan_limit"))?;
            let args = [
                OsString::from("cat-file"),
                OsString::from("blob"),
                OsString::from(oid),
            ];
            scanned += patch_git_scan_blob(
                profile,
                job_dir,
                worktree,
                &format!("{name}-scan-raw-blob-{index}"),
                git_args,
                &args,
                remaining,
                matcher,
                budget,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn patch_git_scan_blob(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    name: &str,
    git_args: &[String],
    args: &[OsString],
    limit: u64,
    matcher: &Arc<CredentialMatcher>,
    budget: &PatchBudget<'_>,
) -> Result<u64> {
    let mut command =
        container_command(profile, job_dir, worktree, &profile.git_program, name, true)?;
    command
        .env(
            "GIT_INDEX_FILE",
            job_dir.join("repository.git/lockyard-export.index"),
        )
        .args(["--env", "GIT_INDEX_FILE"])
        .arg(&profile.image)
        .args(git_args)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let timeout = budget.remaining()?;
    let mut child = command.spawn().map_err(io_error)?;
    let stdout = child.stdout.take().unwrap();
    if set_pipe_nonblocking(&stdout).is_err() {
        terminate_group(child.id());
        let _ = child.wait();
        if !stop_container(profile, job_dir, name) {
            return Err(ExecutorError("patch_container_stop_unconfirmed"));
        }
        return Err(ExecutorError("pipe_nonblocking_failed"));
    }
    let matcher = matcher.clone();
    let pipe_stopped = Arc::new(AtomicBool::new(false));
    let reader_stopped = pipe_stopped.clone();
    let reader = match thread::Builder::new()
        .name("lockyard-patch-scan".into())
        .spawn(move || {
            scan_credential_stream_matched(
                StoppablePipe {
                    reader: stdout,
                    stopped: reader_stopped,
                    stopped_at: None,
                },
                &matcher,
                limit,
            )
        }) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_group(child.id());
            let _ = child.wait();
            if !stop_container(profile, job_dir, name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            return Err(ExecutorError("patch_reader_spawn_failed"));
        }
    };
    let started = Instant::now();
    let mut stop_confirmed = None;
    let success = loop {
        if started.elapsed() >= timeout || budget.cancel.load(Ordering::SeqCst) {
            terminate_group(child.id());
            let _ = child.wait();
            stop_confirmed = Some(stop_container(profile, job_dir, name));
            break false;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                terminate_group(child.id());
                let _ = child.wait();
                stop_confirmed = Some(stop_container(profile, job_dir, name));
                break false;
            }
        }
    };
    let confirmed = stop_confirmed.unwrap_or_else(|| stop_container(profile, job_dir, name));
    pipe_stopped.store(true, Ordering::SeqCst);
    let result = reader.join();
    if !confirmed {
        return Err(ExecutorError("patch_container_stop_unconfirmed"));
    }
    let result = result.map_err(|_| ExecutorError("patch_scan_thread_failed"))?;
    if !success {
        return Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
            "patch_collection_cancelled"
        } else {
            "patch_credential_scan_failed"
        }));
    }
    result
}

#[cfg(test)]
fn scan_credential_stream(reader: impl Read, secrets: &[Vec<u8>], limit: u64) -> Result<u64> {
    scan_credential_stream_matched(reader, &CredentialMatcher::new(secrets)?, limit)
}
fn scan_credential_stream_matched(
    mut reader: impl Read,
    matcher: &CredentialMatcher,
    limit: u64,
) -> Result<u64> {
    let overlap = matcher.longest.saturating_sub(1);
    let mut tail = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    let mut failure = None;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ExecutorError("patch_scan_read_failed")),
        };
        total = total.saturating_add(count as u64);
        if failure.is_none() {
            tail.extend_from_slice(&buffer[..count]);
            if matcher.contains(&tail) {
                failure = Some("patch_contains_forwarded_credential");
            } else if total > limit {
                failure = Some("patch_credential_scan_limit");
            }
            let keep = tail.len().min(overlap);
            tail.drain(..tail.len() - keep);
        }
        // Continue draining after detection/limit failures. Memory stays bounded by overlap+8KiB.
    }
    match failure {
        Some(code) => Err(ExecutorError(code)),
        None => Ok(total),
    }
}

fn git(checkout: &Path) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for name in ["PATH", "HOME", "TMPDIR", "LANG"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(checkout);
    command
}
fn resolve_revision(checkout: &Path, revision: &str) -> Result<String> {
    let mut command = git(checkout);
    command
        .args(["rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{revision}^{{commit}}"))
        .stdin(Stdio::null());
    let (status, output, _) = runtime_output(&mut command, Duration::from_secs(5), 4096, None)
        .map_err(|_| ExecutorError("revision_resolution_unavailable"))?;
    let revision = String::from_utf8(output).map_err(|_| ExecutorError("invalid_revision"))?;
    let revision = revision.trim();
    if !status.success()
        || !(revision.len() == 40 || revision.len() == 64)
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ExecutorError("invalid_revision"));
    }
    Ok(revision.to_string())
}
fn private_dir(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(io_error)?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ExecutorError("state_directory_not_private"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ExecutorError("state_directory_not_private"));
        }
    }
    Ok(())
}
fn private_dir_new(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(io_error)?;
    }
    Ok(())
}
fn private_open(path: &Path, create_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(ExecutorError("state_file_not_private"));
        }
    }
    Ok(file)
}
fn persist(state_dir: &Path, record: &JobRecord) -> Result<()> {
    let dir = state_dir.join("jobs").join(&record.spec.id);
    let path = dir.join("record.json.tmp");
    let mut file = private_open(&path, false)?;
    file.set_len(0).map_err(io_error)?;
    let bytes =
        serde_json::to_vec(record).map_err(|_| ExecutorError("job_record_encoding_failed"))?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(path, dir.join("record.json")).map_err(io_error)?;
    File::open(dir)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)?;
    Ok(())
}
fn read_private_token(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(ExecutorError("token_file_must_be_absolute"));
    }
    let mut file = private_open_existing(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata().map_err(io_error)?.nlink() != 1 {
            return Err(ExecutorError("token_file_has_aliases"));
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 16384 {
        return Err(ExecutorError("invalid_token_file"));
    }
    let trimmed = String::from_utf8(bytes)
        .map_err(|_| ExecutorError("invalid_token_file"))?
        .trim()
        .as_bytes()
        .to_vec();
    if trimmed.is_empty() || trimmed.len() > 16384 {
        return Err(ExecutorError("invalid_token_file"));
    }
    Ok(trimmed)
}
fn private_open_existing(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(io_error)?;
        if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(ExecutorError("token_file_not_private"));
        }
    }
    Ok(file)
}
fn write_cloud_config(worktree: &Path, cloud: &CloudConfig) -> Result<Option<String>> {
    let dir = worktree.join(".lockyard");
    if fs::symlink_metadata(&dir)
        .is_ok_and(|metadata| !metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(ExecutorError("unsafe_worktree_cloud_config"));
    }
    if !dir.exists() {
        private_dir_new(&dir)?;
    }
    let path = dir.join("config.toml");
    if fs::symlink_metadata(&path)
        .is_ok_and(|metadata| !metadata.is_file() || metadata.file_type().is_symlink())
    {
        return Err(ExecutorError("unsafe_worktree_cloud_config"));
    }
    // JSON string escaping is also valid TOML basic-string escaping for these strings.
    let quoted = |value: &str| serde_json::to_string(value).unwrap();
    let content = format!(
        "mode = \"cloud\"\nurl = {}\nworkspace = {}\nrepository = {}\n",
        quoted(&cloud.url),
        quoted(&cloud.workspace),
        quoted(&cloud.repository)
    );
    if path.exists() {
        return if fs::read(&path).map_err(io_error)? == content.as_bytes() {
            Ok(None)
        } else {
            Err(ExecutorError("worktree_cloud_config_conflict"))
        };
    }
    let temp = dir.join("config.toml.node-tmp");
    let mut file = private_open(&temp, true)?;
    file.write_all(content.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(temp, path).map_err(io_error)?;
    Ok(Some(".lockyard/config.toml".into()))
}
fn terminate_group(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
        // A bounded grace period applies to the entire child process group.
        for _ in 0..10 {
            if unsafe { libc::kill(-(pid as i32), 0) } != 0 {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
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
fn drain<W: Write>(
    reader: impl Read,
    spool: Arc<Mutex<Spool<W>>>,
    secrets: Vec<Vec<u8>>,
    stopped: Arc<AtomicBool>,
) -> std::result::Result<(), &'static str> {
    let matcher =
        Arc::new(CredentialMatcher::new(&secrets).map_err(|_| "credential_matcher_unavailable")?);
    drain_matched(reader, spool, matcher, stopped)
}
fn drain_matched<W: Write>(
    mut reader: impl Read,
    spool: Arc<Mutex<Spool<W>>>,
    matcher: Arc<CredentialMatcher>,
    stopped: Arc<AtomicBool>,
) -> std::result::Result<(), &'static str> {
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];
    let mut failure = None;
    loop {
        let count = match reader.read(&mut buf) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stopped.load(Ordering::SeqCst) {
                    0
                } else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                failure = Some("stream_read_failed");
                0
            }
        };
        pending.extend_from_slice(&buf[..count]);
        let mut output = Vec::new();
        let safe = if count == 0 {
            pending.len()
        } else {
            pending
                .len()
                .saturating_sub(matcher.longest.saturating_sub(1))
        };
        let mut pos = 0;
        if let Some(automaton) = &matcher.automaton {
            for found in automaton.find_iter(&pending) {
                if found.start() >= safe {
                    break;
                }
                output.extend_from_slice(&pending[pos..found.start()]);
                output.extend_from_slice(b"[REDACTED]");
                pos = found.end();
            }
        }
        if pos < safe {
            output.extend_from_slice(&pending[pos..safe]);
            pos = safe;
        }
        pending.drain(..pos);
        match spool.lock() {
            Ok(mut spool) => {
                if let Some(code) = failure {
                    spool.mark_error(code);
                }
                if spool.append(&output, &matcher).is_err() {
                    failure.get_or_insert("spool_write_failed");
                }
            }
            Err(poisoned) => {
                poisoned.into_inner().mark_error("spool_lock_poisoned");
                failure.get_or_insert("spool_lock_poisoned");
            }
        }
        // A sink failure never stops draining the process pipe. EOF/read failure still ends it.
        if count == 0 {
            break;
        }
    }
    match failure {
        Some(code) => Err(code),
        None => Ok(()),
    }
}

fn join_stream(
    handle: thread::JoinHandle<std::result::Result<(), &'static str>>,
) -> Option<&'static str> {
    match handle.join() {
        Ok(Ok(())) => None,
        Ok(Err(code)) => Some(code),
        Err(_) => Some("stream_thread_failed"),
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

#[cfg(test)]
pub(crate) mod regression_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn retention_fixture() -> (tempfile::TempDir, ExecutorConfig, Executor) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = ExecutorConfig {
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: None,
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
            node_certificate_sha256: None,
            protected_identity_files: Vec::new(),
        };
        let executor = Executor::new(config.clone()).unwrap();
        (root, config, executor)
    }
    pub(crate) fn retained_fixture_record(
        executor: &Executor,
        state: JobState,
        expiry: u64,
    ) -> JobRecord {
        let current = now_ms();
        let record: JobRecord = serde_json::from_value(serde_json::json!({
            "spec":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo","revision":"HEAD","runner":"runner","arguments":[],"prompt":"private-prompt-sentinel","timeout_seconds":null},
            "state":state,"agent":"derived","submitter":"controller","submitter_certificate_sha256":"a".repeat(64),
            "created_at":current-120_000,"updated_at":current-60_000,
            "retention":{"content_ttl_seconds":60,"admitted_at_ms":current-120_000,"terminal_expires_at_ms":expiry,"purged_at_ms":null},
            "worktree":null,"pid":null,"exit_code":null,"error_code":null,"log_bytes":0,"log_truncated":false
        })).unwrap();
        let job = executor
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(&record.spec.id);
        private_dir_new(&job).unwrap();
        fs::write(job.join("output.log"), b"private-log-sentinel").unwrap();
        fs::write(job.join("result.patch"), b"private-patch-sentinel").unwrap();
        private_dir_new(&job.join("worktree")).unwrap();
        fs::write(job.join("worktree/private.rs"), b"private-code-sentinel").unwrap();
        private_dir_new(&job.join("repository.git")).unwrap();
        fs::write(job.join("repository.git/config"), b"private-git-sentinel").unwrap();
        persist(&executor.inner.config.state_dir, &record).unwrap();
        executor.inner.jobs.lock().unwrap().insert(
            record.spec.id.clone(),
            Entry {
                record: record.clone(),
                cancel: Arc::new(AtomicBool::new(false)),
                artifacts: Arc::new(Mutex::new(())),
            },
        );
        record
    }
    fn synthetic_queue(
        count: usize,
        concurrency: usize,
    ) -> (tempfile::TempDir, Executor, Vec<String>) {
        let (root, _config, mut executor) = retention_fixture();
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .limits
            .max_concurrency = concurrency;
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .limits
            .max_pending_jobs = 4096;
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .scheduling
            .queue
            .max_pending_per_project = 4096;
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .scheduling
            .queue
            .max_pending_per_submitter = 4096;
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .scheduling
            .queue
            .max_running_per_submitter = concurrency;
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .scheduling
            .queue
            .max_running_per_project = concurrency;
        let mut first = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
        first.retention.as_mut().unwrap().terminal_expires_at_ms = None;
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&first.spec.id)
            .unwrap()
            .record = first.clone();
        persist(&executor.inner.config.state_dir, &first).unwrap();
        let mut ids = vec![first.spec.id.clone()];
        for _ in 1..count {
            let mut record = first.clone();
            record.spec.id = crate::wire::new_id().unwrap();
            private_dir_new(
                &executor
                    .inner
                    .config
                    .state_dir
                    .join("jobs")
                    .join(&record.spec.id),
            )
            .unwrap();
            persist(&executor.inner.config.state_dir, &record).unwrap();
            executor.inner.jobs.lock().unwrap().insert(
                record.spec.id.clone(),
                Entry {
                    record: record.clone(),
                    cancel: Arc::new(AtomicBool::new(false)),
                    artifacts: Arc::new(Mutex::new(())),
                },
            );
            ids.push(record.spec.id);
        }
        (root, executor, ids)
    }
    fn install_worker_hook(executor: &Executor, hook: WorkerRunHook) {
        WORKER_RUN_HOOKS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap()
            .insert(executor.inner.config.state_dir.clone(), hook);
    }
    fn wait_queue(mut ready: impl FnMut() -> bool) {
        // This is a deadlock guard, not a throughput target: 1000 durable journal
        // writes may contend with unrelated builds on the same filesystem.
        let deadline = Instant::now() + Duration::from_secs(60);
        while !ready() {
            assert!(
                Instant::now() < deadline,
                "bounded queue fixture did not settle"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
    #[cfg(target_os = "linux")]
    fn process_stat(name: &str) -> u64 {
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|number| number.parse().ok())
            })
            .unwrap()
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn thousand_queued_jobs_use_bounded_workers_through_finalization_and_release_every_owner() {
        // Synthetic callbacks only. No runner/provider/Git/container is invoked.
        let baseline_threads = process_stat("Threads:");
        let baseline_rss = process_stat("VmRSS:");
        let (_root, executor, ids) = synthetic_queue(1000, 4);
        let queued_threads = process_stat("Threads:");
        let queued_rss = process_stat("VmRSS:");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tids = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let worker_tids = tids.clone();
        let callback_gate = gate.clone();
        let callback_started = started.clone();
        let callback_active = active.clone();
        let callback_peak = peak.clone();
        install_worker_hook(
            &executor,
            Arc::new(move |executor, id, _cancel| {
                worker_tids
                    .lock()
                    .unwrap()
                    .insert(unsafe { libc::syscall(libc::SYS_gettid) });
                let count = callback_active.fetch_add(1, Ordering::SeqCst) + 1;
                callback_peak.fetch_max(count, Ordering::SeqCst);
                executor.update(id, |record| {
                    record.state = JobState::Succeeded;
                    record.exit_code = Some(0);
                })?;
                callback_started.fetch_add(1, Ordering::SeqCst);
                // Hold a terminal callback before finalization: admission must still count
                // this physical worker, even though the logical job is already terminal.
                let (lock, changed) = &*callback_gate;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
                callback_active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        executor.launch_ready().unwrap();
        wait_queue(|| started.load(Ordering::SeqCst) == 4);
        thread::sleep(Duration::from_millis(20));
        assert_eq!(
            executor.inner.worker_registry.lock().unwrap().workers.len(),
            4
        );
        assert_eq!(started.load(Ordering::SeqCst), 4);
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        let active_threads = process_stat("Threads:");
        let active_rss = process_stat("VmRSS:");
        assert_eq!(tids.lock().unwrap().len(), 4);
        let exclusive = std::env::var_os("LOCKYARD_QUEUE_MEASURE_EXCLUSIVE").is_some();
        if exclusive {
            assert!(
                active_threads <= queued_threads + 5,
                "four workers plus one coordinator must bound thread growth"
            );
        }
        {
            let (lock, changed) = &*gate;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }
        wait_queue(|| {
            let registry = executor.inner.worker_registry.lock().unwrap();
            !registry.coordinator_running && registry.workers.is_empty()
        });
        assert_eq!(started.load(Ordering::SeqCst), 1000);
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(tids.lock().unwrap().len(), 4);
        assert!(
            executor
                .inner
                .jobs
                .lock()
                .unwrap()
                .values()
                .all(|entry| entry.record.state == JobState::Succeeded)
        );
        let weak = Arc::downgrade(&executor.inner);
        WORKER_RUN_HOOKS
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&executor.inner.config.state_dir);
        drop(executor);
        wait_queue(|| weak.upgrade().is_none());
        println!(
            "QUEUE_MEASUREMENTS {}",
            serde_json::json!({"queued":ids.len(),"configured_workers":4,"synthetic_callbacks":1000,"container_jobs_executed":0,
            "baseline_threads":baseline_threads,"queued_threads":queued_threads,"active_threads":active_threads,"baseline_rss_kib":baseline_rss,"queued_rss_kib":queued_rss,"active_rss_kib":active_rss,
            "peak_callbacks":peak.load(Ordering::SeqCst),"unique_worker_tids":tids.lock().unwrap().len(),"exclusive_measurement":exclusive,"coordinator_exited":true,"last_owner_released":true})
        );
    }
    #[test]
    fn queued_cancel_and_unknown_barrier_do_not_create_idle_workers_and_resolution_kicks_fair_work()
    {
        let (_root, executor, ids) = synthetic_queue(3, 1);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_gate = gate.clone();
        let callbacks = started.clone();
        install_worker_hook(
            &executor,
            Arc::new(move |executor, id, _cancel| {
                callbacks.fetch_add(1, Ordering::SeqCst);
                let (lock, changed) = &*callback_gate;
                let mut open = lock.lock().unwrap();
                while !*open {
                    open = changed.wait(open).unwrap();
                }
                executor.update(id, |record| record.state = JobState::Succeeded)?;
                Ok(())
            }),
        );
        // Unknown blocks all fresh claims without parking three OS threads.
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&ids[0])
            .unwrap()
            .record
            .state = JobState::InterruptedUnknown;
        executor.launch_ready().unwrap();
        wait_queue(|| {
            !executor
                .inner
                .worker_registry
                .lock()
                .unwrap()
                .coordinator_running
        });
        assert_eq!(started.load(Ordering::SeqCst), 0);
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        assert_eq!(
            executor.cancel(&ids[2], &owner).unwrap().state,
            JobState::Cancelled
        );
        let operator = Caller {
            node_id: "worker".into(),
            local_operator: true,
            certificate_sha256: None,
        };
        executor.resolve_unknown(&ids[0], &operator).unwrap();
        wait_queue(|| started.load(Ordering::SeqCst) == 1);
        {
            let (lock, changed) = &*gate;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }
        wait_queue(|| {
            !executor
                .inner
                .worker_registry
                .lock()
                .unwrap()
                .coordinator_running
        });
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(executor.status(&ids[1]).unwrap().state, JobState::Succeeded);
    }
    #[test]
    fn cancellation_after_the_durable_starting_claim_stops_before_profile_or_runtime_access() {
        let (_root, executor, ids) = synthetic_queue(1, 1);
        let claimed = executor.claim_ready().unwrap().unwrap();
        assert_eq!(claimed.id, ids[0]);
        let saved: JobRecord = serde_json::from_slice(
            &fs::read(
                executor
                    .inner
                    .config
                    .state_dir
                    .join("jobs")
                    .join(&ids[0])
                    .join("record.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(saved.state, JobState::Starting);
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        executor.cancel(&ids[0], &owner).unwrap();
        executor.run_inner(&ids[0], claimed.cancel).unwrap();
        let cancelled = executor.status(&ids[0]).unwrap();
        assert_eq!(cancelled.state, JobState::Cancelled);
        assert_eq!(cancelled.patch_error.as_deref(), Some("job_not_started"));
        assert!(cancelled.pid.is_none());
        assert!(
            !executor
                .inner
                .config
                .state_dir
                .join("jobs")
                .join(&ids[0])
                .join("runtime-config")
                .exists()
        );
    }

    #[test]
    fn cancellation_and_launch_have_one_serialized_decision() {
        let (_root, executor, _ids) = synthetic_queue(1, 1);
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        let first = executor.claim_ready().unwrap().unwrap();
        let first_dir = executor.inner.config.state_dir.join("jobs").join(&first.id);
        let marker = first_dir.join("must-not-start");
        private_dir_new(&first_dir.join("runtime-secrets")).unwrap();
        assert_eq!(
            executor.cancel(&first.id, &owner).unwrap().state,
            JobState::Starting
        );
        let mut never = Command::new("/bin/sh");
        never.args(["-c", "touch -- \"$1\"", "test"]).arg(&marker);
        assert!(
            executor
                .commit_launch(&first.id, &first.cancel, &first_dir, &mut never)
                .unwrap()
                .is_none()
        );
        assert!(!marker.exists());
        assert!(!first_dir.join("runtime-secrets").exists());
        assert_eq!(
            executor.status(&first.id).unwrap().state,
            JobState::Cancelled
        );
        let (_root2, executor2, _ids2) = synthetic_queue(1, 1);
        let second = executor2.claim_ready().unwrap().unwrap();
        let second_dir = executor2
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(&second.id);
        let mut process = Command::new("/bin/sleep");
        process.arg("2");
        let (mut child, durable) = executor2
            .commit_launch(&second.id, &second.cancel, &second_dir, &mut process)
            .unwrap()
            .unwrap();
        assert!(durable);
        assert_eq!(
            executor2.cancel(&second.id, &owner).unwrap().state,
            JobState::Running
        );
        assert!(second.cancel.load(Ordering::SeqCst));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn queued_cancellation_immediately_has_a_signed_terminal_result() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signer = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
        let trusted = signer.trusted_key();
        let config = ExecutorConfig {
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: Some(ResultSigningConfig {
                workspace: "workspace".into(),
                key_file: root.path().join("signing.pk8"),
                public_key: trusted.public_key.clone(),
            }),
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
            node_certificate_sha256: Some("a".repeat(64)),
            protected_identity_files: Vec::new(),
        };
        let outbox = Arc::new(Mutex::new(
            crate::job_notifications::Outbox::open(root.path(), &"a".repeat(64), true).unwrap(),
        ));
        let executor = Executor::open(
            config.clone(),
            Some(WorkspaceKeyContext {
                workspace: "workspace".into(),
                key: WorkspaceKey::from_entropy([7; 32]),
            }),
            None,
            Some(outbox.clone()),
        )
        .unwrap();
        let mut record = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
        record.retention.as_mut().unwrap().terminal_expires_at_ms = None;
        record.configured_image = Some(format!("sha256:{}", "a".repeat(64)));
        record.resolved_revision = Some("b".repeat(40));
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&record.spec.id)
            .unwrap()
            .record = record.clone();
        persist(&executor.inner.config.state_dir, &record).unwrap();
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        std::thread::sleep(Duration::from_millis(2));
        let cancelled = executor.cancel(&record.spec.id, &owner).unwrap();
        assert_eq!(cancelled.state, JobState::Cancelled);
        let signed = cancelled
            .result_manifest
            .as_ref()
            .expect("signed without restart or archive request");
        let manifest = crate::provenance::verify_result_identity(
            signed,
            &trusted,
            "worker",
            "workspace",
            &record.spec.id,
        )
        .unwrap();
        assert_eq!(manifest.state, JobState::Cancelled);
        assert!(!manifest.execution_attempted);
        assert_eq!(executor.notification_status().unwrap().0, 1);
        executor.notification_capture_page(None).unwrap();
        assert_eq!(executor.notification_status().unwrap().0, 1);
        let metadata = fs::read_to_string(root.path().join("job-notifications.json")).unwrap();
        assert!(metadata.contains(&record.spec.id));
        assert!(!metadata.contains("manifest"));
        assert!(!metadata.contains("prompt"));
        // Crash after the outbox sync but before the source acknowledgement: recovery
        // sees the existing key and must not append another notification.
        {
            let mut jobs = executor.inner.jobs.lock().unwrap();
            let entry = jobs.get_mut(&record.spec.id).unwrap();
            entry.record.notification_accounted_certificate_sha256 = None;
            persist(&executor.inner.config.state_dir, &entry.record).unwrap();
        }
        drop(executor);
        let executor = Executor::open(
            config.clone(),
            Some(WorkspaceKeyContext {
                workspace: "workspace".into(),
                key: WorkspaceKey::from_entropy([7; 32]),
            }),
            None,
            Some(outbox.clone()),
        )
        .unwrap();
        executor.notification_capture_page(None).unwrap();
        assert_eq!(executor.notification_status().unwrap().0, 1);
        // The per-record acknowledgement survives expiration of the outbox tombstone.
        drop(executor);
        drop(outbox);
        let path = root.path().join("job-notifications.json");
        let mut disk: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        disk["entries"] = serde_json::json!([]);
        fs::write(&path, serde_json::to_vec(&disk).unwrap()).unwrap();
        let outbox = Arc::new(Mutex::new(
            crate::job_notifications::Outbox::open(root.path(), &"a".repeat(64), true).unwrap(),
        ));
        let executor = Executor::open(
            config,
            Some(WorkspaceKeyContext {
                workspace: "workspace".into(),
                key: WorkspaceKey::from_entropy([7; 32]),
            }),
            None,
            Some(outbox),
        )
        .unwrap();
        executor.notification_capture_page(None).unwrap();
        assert_eq!(executor.notification_status().unwrap().0, 0);
        let expiry = cancelled.retention.unwrap().terminal_expires_at_ms.unwrap();
        executor.purge_expired_at(expiry).unwrap();
        assert!(executor.status(&record.spec.id).is_err());
        assert_eq!(executor.notification_status().unwrap().0, 0);
    }

    #[tokio::test]
    #[ignore = "requires an isolated verified-TLS notification fixture"]
    async fn signed_negative_terminal_reaches_cloud_notification_fixture() {
        let workspace = std::env::var("LOCKYARD_E20_WORKSPACE").unwrap();
        let base = std::env::var("LOCKYARD_E20_BASE").unwrap();
        let root_certificate = fs::read(std::env::var("LOCKYARD_E20_ROOT_FILE").unwrap()).unwrap();
        let token = fs::read_to_string(std::env::var("LOCKYARD_E20_TOKEN_FILE").unwrap()).unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signer = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
        let config = ExecutorConfig {
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: Some(ResultSigningConfig {
                workspace: workspace.clone(),
                key_file: root.path().join("signing.pk8"),
                public_key: signer.trusted_key().public_key,
            }),
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
            node_certificate_sha256: Some("a".repeat(64)),
            protected_identity_files: Vec::new(),
        };
        let outbox = Arc::new(Mutex::new(
            crate::job_notifications::Outbox::open(root.path(), &"a".repeat(64), true).unwrap(),
        ));
        let executor = Executor::open(
            config,
            Some(WorkspaceKeyContext {
                workspace,
                key: WorkspaceKey::from_entropy([7; 32]),
            }),
            None,
            Some(outbox.clone()),
        )
        .unwrap();
        let mut record = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
        record.retention.as_mut().unwrap().terminal_expires_at_ms = None;
        record.configured_image = Some(format!("sha256:{}", "a".repeat(64)));
        record.resolved_revision = Some("b".repeat(40));
        record.spec.prompt = Some("PRIVATE_PROMPT_CANARY".into());
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&record.spec.id)
            .unwrap()
            .record = record.clone();
        persist(&executor.inner.config.state_dir, &record).unwrap();
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        tokio::time::sleep(Duration::from_millis(2)).await;
        let terminal = executor.cancel(&record.spec.id, &owner).unwrap();
        assert_eq!(terminal.state, JobState::Cancelled);
        assert!(terminal.result_manifest.is_some());
        assert_eq!(executor.notification_status().unwrap().0, 1);
        let client = crate::cloud::NodeCloudClient::new(
            &base,
            "worker".into(),
            token.trim().into(),
            &[root_certificate],
        )
        .unwrap();
        let worker = tokio::spawn(crate::job_notifications::run(
            outbox,
            "a".repeat(64),
            executor.clone(),
            client,
        ));
        tokio::time::timeout(Duration::from_secs(20), async {
            while executor.notification_status().unwrap().0 != 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the verified TLS fixture did not acknowledge the captured outcome");
        worker.abort();
    }

    #[test]
    fn output_timeout_covers_pipes_inherited_after_parent_exit() {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 2"]);
        // Keep a real detached descendant holding the output pipes after its immediate parent
        // exits. Native syscalls avoid depending on the Linux-only `setsid` command-line utility.
        unsafe {
            command.pre_exec(|| {
                let descendant = libc::fork();
                if descendant < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if descendant > 0 {
                    libc::_exit(0);
                }
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let started = Instant::now();
        assert_eq!(
            runtime_output(&mut command, Duration::from_millis(150), 4096, None)
                .unwrap_err()
                .0,
            "runtime_output_timeout"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn bounded_runtime_output_drains_both_streams_and_enforces_each_limit() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf out; printf err >&2"]);
        let (status, out, err) =
            runtime_output(&mut command, Duration::from_secs(2), 3, None).unwrap();
        assert!(status.success());
        assert_eq!(out, b"out");
        assert_eq!(err, b"err");
        let mut excessive = Command::new("/bin/sh");
        excessive.args(["-c", "printf excessive >&2"]);
        assert_eq!(
            runtime_output(&mut excessive, Duration::from_secs(2), 3, None)
                .unwrap_err()
                .0,
            "runtime_output_limit"
        );
    }

    #[test]
    fn stopped_reader_rejects_a_surviving_pipe_writer() {
        let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
        set_pipe_nonblocking(&reader).unwrap();
        let mut pipe = StoppablePipe {
            reader,
            stopped: Arc::new(AtomicBool::new(true)),
            stopped_at: None,
        };
        let mut output = [0u8; 8];
        let started = Instant::now();
        assert!(pipe.read(&mut output).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn starting_persist_and_worker_spawn_failures_fence_dispatch_before_any_callback() {
        for spawn_failure in [false, true] {
            let (_root, executor, ids) = synthetic_queue(1, 1);
            let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let called = callbacks.clone();
            install_worker_hook(
                &executor,
                Arc::new(move |_, _, _| {
                    called.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
            );
            if spawn_failure {
                FAIL_WORKER_SPAWN
                    .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
                    .lock()
                    .unwrap()
                    .insert(executor.inner.config.state_dir.clone());
            } else {
                fs::create_dir(
                    executor
                        .inner
                        .config
                        .state_dir
                        .join("jobs")
                        .join(&ids[0])
                        .join("record.json.tmp"),
                )
                .unwrap();
            }
            executor.launch_ready().unwrap();
            wait_queue(|| {
                !executor.dispatch_healthy()
                    && !executor
                        .inner
                        .worker_registry
                        .lock()
                        .unwrap()
                        .coordinator_running
            });
            assert_eq!(callbacks.load(Ordering::SeqCst), 0);
            assert!(
                executor
                    .inner
                    .worker_registry
                    .lock()
                    .unwrap()
                    .workers
                    .is_empty()
            );
            assert_eq!(
                executor.status(&ids[0]).unwrap().state,
                if spawn_failure {
                    JobState::Failed
                } else {
                    JobState::Queued
                }
            );
            assert_eq!(
                executor.launch_ready().unwrap_err().0,
                "executor_dispatch_unavailable"
            );
            let existing = executor
                .inner
                .jobs
                .lock()
                .unwrap()
                .get(&ids[0])
                .unwrap()
                .record
                .clone();
            let owner = Caller {
                node_id: "controller".into(),
                local_operator: false,
                certificate_sha256: Some("a".repeat(64)),
            };
            assert_eq!(
                executor.submit(existing.spec, &owner).unwrap().spec.id,
                ids[0]
            );
        }
    }
    #[test]
    fn coordinator_spawn_failure_keeps_the_admitted_job_queued_without_claiming_or_executing() {
        let (_root, executor, ids) = synthetic_queue(1, 1);
        FAIL_COORDINATOR_SPAWN
            .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
            .lock()
            .unwrap()
            .insert(executor.inner.config.state_dir.clone());
        assert_eq!(
            executor.launch_ready().unwrap_err().0,
            "job_coordinator_failed"
        );
        assert!(!executor.dispatch_healthy());
        assert_eq!(executor.status(&ids[0]).unwrap().state, JobState::Queued);
        let registry = executor.inner.worker_registry.lock().unwrap();
        assert!(!registry.coordinator_running);
        assert!(registry.workers.is_empty());
    }
    #[test]
    fn panicked_worker_preserves_unknown_evidence_and_never_launches_the_next_job() {
        let (_root, executor, ids) = synthetic_queue(2, 1);
        let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = callbacks.clone();
        install_worker_hook(
            &executor,
            Arc::new(move |_, _, _| {
                called.fetch_add(1, Ordering::SeqCst);
                panic!("synthetic worker panic before any execution")
            }),
        );
        executor.launch_ready().unwrap();
        wait_queue(|| {
            !executor.dispatch_healthy()
                && !executor
                    .inner
                    .worker_registry
                    .lock()
                    .unwrap()
                    .coordinator_running
        });
        assert_eq!(callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(
            executor.status(&ids[0]).unwrap().state,
            JobState::InterruptedUnknown
        );
        assert_eq!(executor.status(&ids[1]).unwrap().state, JobState::Queued);
    }

    #[test]
    fn pending_maintenance_is_rechecked_after_acquiring_the_executor_lock_before_recovery() {
        use std::os::fd::AsRawFd;
        for rotation in [false, true] {
            let (_root, config, executor) = retention_fixture();
            let record = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
            let journal = config
                .state_dir
                .join("jobs")
                .join(&record.spec.id)
                .join("record.json");
            let before = fs::read(&journal).unwrap();
            drop(executor);
            let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
            let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
            OPEN_TEST_HOOKS
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .unwrap()
                .insert(
                    config.state_dir.clone(),
                    Box::new(move || {
                        reached_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                    }),
                );
            let opening = config.clone();
            let constructor = thread::spawn(move || Executor::new(opening));
            reached_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            let maintenance = private_open(&config.state_dir.join("executor.lock"), false).unwrap();
            assert_eq!(
                unsafe { libc::flock(maintenance.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
            let parent = config.state_dir.parent().unwrap();
            let marker = if rotation {
                parent.join("workspace-rotation.pending.json")
            } else {
                private_dir(&parent.join("managed-updates")).unwrap();
                parent.join("managed-updates/pending.json")
            };
            let mut file = private_open(&marker, true).unwrap();
            file.write_all(b"{}").unwrap();
            file.sync_all().unwrap();
            File::open(marker.parent().unwrap())
                .unwrap()
                .sync_all()
                .unwrap();
            unsafe {
                libc::flock(maintenance.as_raw_fd(), libc::LOCK_UN);
            }
            drop(maintenance);
            resume_tx.send(()).unwrap();
            let error = constructor
                .join()
                .unwrap()
                .err()
                .expect("pending maintenance must block recovery");
            assert_eq!(
                error.0,
                if rotation {
                    "workspace_rotation_recovery_required"
                } else {
                    "managed_update_recovery_required"
                }
            );
            assert_eq!(fs::read(journal).unwrap(), before);
        }
    }
    #[test]
    fn last_executor_owner_releases_state_lock_even_if_a_fork_inherits_its_descriptor() {
        // A helper fork before exec can inherit CLOEXEC descriptors. It must not extend
        // executor authority after the last actual Executor/job owner has been dropped.
        let (_root, config, executor) = retention_fixture();
        assert_eq!(Arc::strong_count(&executor.inner), 1);
        use std::os::fd::IntoRawFd;
        // std creates both pipe ends with close-on-exec on every supported Unix platform;
        // Darwin has no pipe2, but this test still needs descriptors inherited by fork.
        let (reader, writer) = std::io::pipe().unwrap();
        let pipe = [reader.into_raw_fd(), writer.into_raw_fd()];
        for descriptor in pipe {
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
            assert!(flags >= 0);
            assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        }
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                libc::close(pipe[1]);
                let mut byte = 0u8;
                libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        assert!(child > 0);
        unsafe {
            libc::close(pipe[0]);
        }
        struct Child {
            pid: libc::pid_t,
            writer: libc::c_int,
        }
        impl Drop for Child {
            fn drop(&mut self) {
                unsafe {
                    let byte = 1u8;
                    libc::write(self.writer, (&byte as *const u8).cast(), 1);
                    libc::close(self.writer);
                    libc::waitpid(self.pid, std::ptr::null_mut(), 0);
                }
            }
        }
        let child = Child {
            pid: child,
            writer: pipe[1],
        };
        drop(executor);
        let reopened = Executor::new(config);
        drop(child);
        assert!(
            reopened.is_ok(),
            "last executor owner left a state lock behind: {:?}",
            reopened.err()
        );
    }
    #[test]
    fn retention_purges_private_content_only_after_durable_nonreplay_tombstone() {
        let (_root, config, executor) = retention_fixture();
        let current = now_ms();
        let record = retained_fixture_record(&executor, JobState::Succeeded, current - 1);
        fs::write(
            config
                .state_dir
                .join("exports")
                .join(format!("{}.lyarchive", record.spec.id)),
            b"encrypted-copy",
        )
        .unwrap();
        assert_eq!(executor.purge_expired_at(current).unwrap(), 1);
        assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
        assert!(
            !config
                .state_dir
                .join("exports")
                .join(format!("{}.lyarchive", record.spec.id))
                .exists()
        );
        let tombstone = executor.tombstone(&record.spec.id).unwrap().unwrap();
        assert_eq!(
            executor.expired_metadata(&record.spec.id).unwrap().unwrap()["erasure_complete"],
            true
        );
        let minimal = serde_json::to_string(&tombstone).unwrap();
        for content in [
            "private-prompt-sentinel",
            "private-log-sentinel",
            "private-patch-sentinel",
            "private-code-sentinel",
            "private-git-sentinel",
        ] {
            assert!(!minimal.contains(content));
        }
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        assert_eq!(
            executor.submit(record.spec.clone(), &owner).unwrap_err().0,
            "job_content_expired"
        );
        let replacement = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("b".repeat(64)),
        };
        assert_eq!(
            executor
                .submit(record.spec.clone(), &replacement)
                .unwrap_err()
                .0,
            "job_id_conflict"
        );
        let mut changed = record.spec.clone();
        changed.prompt = Some("changed".into());
        assert_eq!(
            executor.submit(changed, &owner).unwrap_err().0,
            "job_id_conflict"
        );
        // Crash boundary: committed tombstone plus an unremoved body must recover by erasing,
        // without interpreting a stale job journal as a fresh runnable job.
        let job = config.state_dir.join("jobs").join(&record.spec.id);
        private_dir_new(&job).unwrap();
        persist(&config.state_dir, &record).unwrap();
        drop(executor);
        let recovered = Executor::new(config.clone()).unwrap();
        assert!(!job.exists());
        assert!(recovered.list().unwrap().is_empty());
        assert_eq!(
            recovered.submit(record.spec, &owner).unwrap_err().0,
            "job_content_expired"
        );
    }
    #[test]
    fn a_reused_source_name_never_inherits_cancel_or_submit_ownership() {
        let (_root, _config, executor) = retention_fixture();
        let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
        let replacement = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("b".repeat(64)),
        };
        assert_eq!(
            executor
                .cancel(&record.spec.id, &replacement)
                .unwrap_err()
                .0,
            "job_owner_required"
        );
        assert_eq!(
            executor
                .submit(record.spec.clone(), &replacement)
                .unwrap_err()
                .0,
            "job_id_conflict"
        );
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&record.spec.id)
            .unwrap()
            .record
            .submitter_certificate_sha256 = None;
        let original = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        assert_eq!(
            executor.cancel(&record.spec.id, &original).unwrap_err().0,
            "legacy_submitter_requires_local_review"
        );
        assert_eq!(
            executor.submit(record.spec, &original).unwrap_err().0,
            "legacy_submitter_requires_local_review"
        );
    }
    #[test]
    fn erasure_failure_retains_commitment_blocks_admission_and_recovers_completion() {
        let (_root, config, executor) = retention_fixture();
        let current = now_ms();
        let record = retained_fixture_record(&executor, JobState::Succeeded, current - 1);
        let export = config
            .state_dir
            .join("exports")
            .join(format!("{}.lyarchive", record.spec.id));
        fs::create_dir(&export).unwrap(); // Deterministic unlink failure on an invalid fixture.
        assert!(executor.purge_expired_at(current).is_err());
        assert!(executor.tombstone(&record.spec.id).unwrap().is_some());
        assert_eq!(
            executor.expired_metadata(&record.spec.id).unwrap().unwrap()["erasure_complete"],
            false
        );
        assert!(
            !config
                .state_dir
                .join("purge-completed")
                .join(&record.spec.id)
                .exists()
        );
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        let mut new_spec = record.spec.clone();
        new_spec.id = crate::wire::new_id().unwrap();
        assert_eq!(
            executor.submit(new_spec, &owner).unwrap_err().0,
            "retention_maintenance_required"
        );
        fs::remove_dir(export).unwrap();
        executor.purge_expired_at(current).unwrap();
        assert_eq!(
            executor.expired_metadata(&record.spec.id).unwrap().unwrap()["erasure_complete"],
            true
        );
        assert!(!executor.inner.retention_failed.load(Ordering::SeqCst));
        assert!(
            !config
                .state_dir
                .join("expired-content")
                .join(&record.spec.id)
                .exists()
        );
    }
    #[test]
    fn retention_never_erases_unknown_execution_or_an_artifact_in_use() {
        let (_root, config, executor) = retention_fixture();
        let current = now_ms();
        let record = retained_fixture_record(&executor, JobState::InterruptedUnknown, current - 1);
        assert_eq!(executor.purge_expired_at(current).unwrap(), 0);
        assert!(
            config
                .state_dir
                .join("jobs")
                .join(&record.spec.id)
                .join("output.log")
                .exists()
        );
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&record.spec.id)
            .unwrap()
            .record
            .state = JobState::Succeeded;
        let artifacts = executor.artifact_lock(&record.spec.id).unwrap();
        let guard = artifacts.lock().unwrap();
        assert_eq!(executor.purge_expired_at(current).unwrap(), 0);
        drop(guard);
        assert_eq!(executor.purge_expired_at(current).unwrap(), 1);
    }
    #[test]
    fn expired_unsigned_terminal_restart_preserves_recoverable_signed_outcome() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("signing.pk8");
        let key = SigningKey::generate(&path).unwrap();
        let config = ExecutorConfig {
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: Some(ResultSigningConfig {
                workspace: "workspace".into(),
                key_file: path,
                public_key: key.trusted_key().public_key,
            }),
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
            node_certificate_sha256: None,
            protected_identity_files: Vec::new(),
        };
        let executor = Executor::new(config.clone()).unwrap();
        let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
        assert!(record.result_manifest.is_none());
        drop(executor);
        let recovered = Executor::new(config.clone()).unwrap();
        assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
        let metadata = recovered
            .expired_metadata(&record.spec.id)
            .unwrap()
            .unwrap();
        assert_eq!(metadata["erasure_complete"], true);
        let signed: crate::provenance::SignedDocument =
            serde_json::from_value(metadata["terminal_receipt"].clone()).unwrap();
        let proof: retention::TerminalReceipt = crate::provenance::verify_document(
            &signed,
            retention::TERMINAL_RECEIPT_DOMAIN,
            &key.trusted_key(),
        )
        .unwrap();
        assert_eq!(proof.outcome, JobState::Succeeded);
        assert_eq!(
            proof.request_sha256,
            retention::spec_digest(&record.spec).unwrap()
        );
        assert!(
            !serde_json::to_string(&proof)
                .unwrap()
                .contains("private-prompt-sentinel")
        );
        assert!(metadata["tombstone"]["result_manifest"].is_null());
        let caller = Caller {
            node_id: record.submitter.clone(),
            local_operator: false,
            certificate_sha256: record.submitter_certificate_sha256.clone(),
        };
        assert_eq!(
            recovered
                .submit(record.spec.clone(), &caller)
                .unwrap_err()
                .0,
            "job_content_expired"
        );
        assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
    }

    #[test]
    fn receipt_signer_failure_does_not_delay_purge_and_retries_from_tombstone() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("signing.pk8");
        let key = SigningKey::generate(&path).unwrap();
        let config = ExecutorConfig {
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: Some(ResultSigningConfig {
                workspace: "workspace".into(),
                key_file: path,
                public_key: key.trusted_key().public_key,
            }),
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
            node_certificate_sha256: None,
            protected_identity_files: Vec::new(),
        };
        let mut executor = Executor::new(config.clone()).unwrap();
        let record = retained_fixture_record(&executor, JobState::Failed, now_ms() - 1);
        Arc::get_mut(&mut executor.inner).unwrap().signing_key = None;
        assert_eq!(executor.purge_expired().unwrap(), 1);
        assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
        let metadata = executor.expired_metadata(&record.spec.id).unwrap().unwrap();
        assert_eq!(metadata["erasure_complete"], true);
        assert!(metadata["terminal_receipt"].is_null());
        assert_eq!(
            metadata["terminal_receipt_error"],
            "terminal_receipt_signing_unavailable"
        );
        drop(executor);
        let recovered = Executor::new(config.clone()).unwrap();
        let metadata = recovered
            .expired_metadata(&record.spec.id)
            .unwrap()
            .unwrap();
        assert!(metadata["terminal_receipt"].is_object());
        assert!(
            config
                .state_dir
                .join("job-tombstones")
                .join(format!("{}.receipt", record.spec.id))
                .exists()
        );
        assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
    }

    #[test]
    fn credential_job_export_is_signed_results_only_and_restores_without_a_runnable_journal() {
        // Synthetic confirmed-terminal journal, not a container execution proof.
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signer = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
        let trusted = signer.trusted_key();
        let config = ExecutorConfig {
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: Some(ResultSigningConfig {
                workspace: "workspace".into(),
                key_file: root.path().join("signing.pk8"),
                public_key: trusted.public_key.clone(),
            }),
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
            node_certificate_sha256: None,
            protected_identity_files: Vec::new(),
        };
        let key = WorkspaceKey::from_entropy([37; 32]);
        let executor =
            Executor::new_with_workspace_key(config, "workspace".into(), key.clone()).unwrap();
        let mut record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
        assert!(record.had_runtime_credentials); // Legacy records conservatively restrict exports.
        record.configured_image = Some(format!("sha256:{}", "a".repeat(64)));
        record.resolved_revision = Some("b".repeat(40));
        record.exit_code = Some(0);
        record.log_error = Some("log_contains_forwarded_credential".into());
        record.patch_error = Some("patch_contains_forwarded_credential".into());
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get_mut(&record.spec.id)
            .unwrap()
            .record = record.clone();
        persist(&executor.inner.config.state_dir, &record).unwrap();
        let archive = root.path().join("export.lyarchive");
        let mut output = private_open(&archive, true).unwrap();
        let mut offset = 0;
        loop {
            let chunk = executor
                .read_archive(&record.spec.id, offset, 65536)
                .unwrap();
            output.write_all(&chunk.bytes).unwrap();
            offset = chunk.next_offset;
            if chunk.eof {
                break;
            }
        }
        output.sync_all().unwrap();
        drop(output);
        let manifest =
            crate::archive::inspect(&archive, "workspace", &key, "worker", &trusted).unwrap();
        assert_eq!(manifest.scope, crate::archive::ArchiveScope::ResultsOnly);
        assert!(manifest.entries.iter().all(|entry| matches!(
            entry.path.as_str(),
            "export-metadata.json" | "output.log" | "result.patch"
        )));
        let restored = root.path().join("offline");
        crate::archive::restore_offline(&archive, &restored, "workspace", &key, "worker", &trusted)
            .unwrap();
        assert!(!restored.join("files/record.json").exists());
        assert!(!restored.join("files/worktree").exists());
        assert!(!restored.join("files/repository.git").exists());
        assert!(!restored.join("files/output.log").exists());
        assert!(!restored.join("files/result.patch").exists());
        assert!(!restored.join("executor").exists());
        let metadata = fs::read_to_string(restored.join("files/export-metadata.json")).unwrap();
        assert!(!metadata.contains("private-prompt-sentinel"));
        assert!(!metadata.contains("private-code-sentinel"));
        assert!(metadata.contains("result_manifest"));
    }
    #[test]
    fn operator_drain_is_durable_and_only_gates_new_job_ids() {
        let (_root, config, executor) = retention_fixture();
        let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        assert_eq!(
            executor.set_draining(true, &owner).unwrap_err().0,
            "local_operator_required"
        );
        let operator = Caller {
            node_id: "worker".into(),
            local_operator: true,
            certificate_sha256: None,
        };
        assert!(executor.set_draining(true, &operator).unwrap().draining);
        assert_eq!(
            executor
                .submit(record.spec.clone(), &owner)
                .unwrap()
                .spec
                .id,
            record.spec.id
        );
        let mut fresh = record.spec.clone();
        fresh.id = crate::wire::new_id().unwrap();
        assert_eq!(
            executor.submit(fresh.clone(), &owner).unwrap_err().0,
            "node_draining"
        );
        drop(executor);
        let recovered = Executor::new(config).unwrap();
        assert!(recovered.drain_status().unwrap().draining);
        assert_eq!(
            recovered.submit(fresh, &owner).unwrap_err().0,
            "node_draining"
        );
        assert!(!recovered.set_draining(false, &operator).unwrap().draining);
    }

    #[test]
    fn signature_persist_failure_never_exposes_a_successful_signed_patch() {
        // A pre-existing terminal journal fixture, not an execution or container proof.
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key_file = root.path().join("result.pk8");
        let key = SigningKey::generate(&key_file).unwrap();
        let signing = ResultSigningConfig {
            workspace: "workspace".into(),
            key_file,
            public_key: key.trusted_key().public_key,
        };
        let config = ExecutorConfig {
            node_certificate_sha256: None,
            protected_identity_files: Vec::new(),
            node_id: "worker".into(),
            state_dir: root.path().join("executor"),
            repositories: BTreeMap::new(),
            runners: BTreeMap::new(),
            provenance: Some(signing),
            limits: ExecutionLimits::default(),
            scheduling: Default::default(),
        };
        let executor = Executor::new(config.clone()).unwrap();
        let current = now_ms();
        let record: JobRecord = serde_json::from_value(serde_json::json!({
            "spec":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo","revision":"HEAD","runner":"runner","arguments":[],"prompt":null,"timeout_seconds":null},
            "state":"succeeded","agent":"derived","submitter":"controller","created_at":current,"updated_at":current,
            "retention":{"content_ttl_seconds":3600,"admitted_at_ms":current,"terminal_expires_at_ms":current+3_600_000,"purged_at_ms":null},
            "resolved_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worktree":null,"pid":null,"exit_code":0,"error_code":null,"log_bytes":0,"log_truncated":false,
            "configured_image":format!("sha256:{}","a".repeat(64))
        })).unwrap();
        let job = config.state_dir.join("jobs").join(&record.spec.id);
        private_dir_new(&job).unwrap();
        fs::write(job.join("output.log"), []).unwrap();
        fs::write(job.join("result.patch"), []).unwrap();
        for name in ["output.log", "result.patch"] {
            fs::set_permissions(job.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        persist(&config.state_dir, &record).unwrap();
        executor.inner.jobs.lock().unwrap().insert(
            record.spec.id.clone(),
            Entry {
                record: record.clone(),
                cancel: Arc::new(AtomicBool::new(false)),
                artifacts: Arc::new(Mutex::new(())),
            },
        );
        fs::create_dir(job.join("record.json.tmp")).unwrap();
        executor.finalize_provenance(&record.spec.id);
        let failed = executor.status(&record.spec.id).unwrap();
        assert!(failed.result_manifest.is_none());
        assert_eq!(
            failed.provenance_error.as_deref(),
            Some("result_manifest_persist_failed")
        );
        assert_eq!(
            executor.read_patch(&record.spec.id, 0, 1024).unwrap_err().0,
            "result_provenance_unavailable"
        );
        drop(executor);
        fs::remove_dir(job.join("record.json.tmp")).unwrap();
        let recovered = Executor::new(config).unwrap();
        let restored = recovered.status(&record.spec.id).unwrap();
        assert!(restored.result_manifest.is_some());
        assert!(restored.provenance_error.is_none());
        assert_eq!(restored.state, JobState::Succeeded);
        assert!(recovered.read_patch(&record.spec.id, 0, 1024).unwrap().eof);
    }

    fn git_ok(path: &Path, args: &[&str]) -> Vec<u8> {
        let output = git(path).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }
    // A protocol fixture for patch-only Git calls on controlled test data, not a container proof.
    fn patch_fixture(root: &Path) -> (ContainerProfile, PathBuf, PathBuf, String) {
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        git_ok(&source, &["init", "-q"]);
        git_ok(&source, &["config", "user.email", "test@example.invalid"]);
        git_ok(&source, &["config", "user.name", "Test"]);
        fs::write(source.join("base"), b"base\n").unwrap();
        fs::create_dir(source.join(".lockyard")).unwrap();
        fs::write(source.join(".lockyard/tracked.rs"), b"// original code\n").unwrap();
        git_ok(&source, &["add", "."]);
        git_ok(&source, &["commit", "-qm", "base"]);
        let revision = String::from_utf8(git_ok(&source, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_string();
        let job = root.join("job");
        private_dir_new(&job).unwrap();
        private_dir_new(&job.join("runtime-config")).unwrap();
        private_open(&job.join("runtime-user"), true)
            .unwrap()
            .write_all(host_container_identity().as_bytes())
            .unwrap();
        let metadata = job.join("repository.git");
        assert!(
            git(&source)
                .args(["clone", "--bare", "--no-hardlinks"])
                .arg(&source)
                .arg(&metadata)
                .output()
                .unwrap()
                .status
                .success()
        );
        let worktree = job.join("worktree");
        assert!(
            git(&metadata)
                .args(["worktree", "add", "--detach"])
                .arg(&worktree)
                .arg(&revision)
                .output()
                .unwrap()
                .status
                .success()
        );
        let runtime = root.join("runtime-fixture");
        fs::write(
            &runtime,
            r#"#!/usr/bin/python3
import os,sys
a=sys.argv[1:]
if 'container' in a and 'rm' in a: sys.exit(0)
if 'run' not in a: sys.exit(2)
os.chdir(a[a.index('--workdir')+1])
os.environ['GIT_CONFIG_GLOBAL']='/dev/null'
os.environ['GIT_CONFIG_NOSYSTEM']='1'
os.execve('/usr/bin/git',['git']+a[a.index('fixture:image')+1:],os.environ)
"#,
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        (
            ContainerProfile {
                runtime: ContainerRuntime::Docker,
                runtime_program: runtime,
                image: "fixture:image".into(),
                supply_chain: None,
                git_program: "/usr/bin/git".into(),
                memory_mb: 128,
                cpu_millis: 1000,
                pids_limit: 64,
                network: ContainerNetwork::None,
            },
            job,
            worktree,
            revision,
        )
    }

    #[test]
    fn legitimate_lockyard_source_is_included_in_patch() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        fs::create_dir_all(worktree.join(".lockyard")).unwrap();
        fs::write(
            worktree.join(".lockyard/library.rs"),
            b"pub fn legitimate() {}\n",
        )
        .unwrap();
        fs::write(
            worktree.join(".lockyard/tracked.rs"),
            b"// changed legitimate code\n",
        )
        .unwrap();
        let cloud = CloudConfig {
            url: "https://example.invalid".into(),
            workspace: "team".into(),
            repository: "repo".into(),
            token_file: None,
        };
        let injected = write_cloud_config(&worktree, &cloud).unwrap().unwrap();
        record_injected_paths(&job, &worktree, vec![injected]).unwrap();
        collect_patch(&profile, &job, &worktree, &revision, "fixture", 4096, &[]).unwrap();
        let patch = fs::read_to_string(job.join("result.patch")).unwrap();
        assert!(
            patch.contains(".lockyard/library.rs"),
            "legitimate project code was dropped"
        );
        assert!(patch.contains(".lockyard/tracked.rs"));
        assert!(!patch.contains(".lockyard/config.toml"));
    }

    #[test]
    fn preexisting_cloud_config_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".lockyard")).unwrap();
        let path = dir.path().join(".lockyard/config.toml");
        fs::write(&path, b"# project-owned content\n").unwrap();
        let cloud = CloudConfig {
            url: "https://example.invalid".into(),
            workspace: "team".into(),
            repository: "repo".into(),
            token_file: None,
        };
        assert!(write_cloud_config(dir.path(), &cloud).is_err());
        assert_eq!(fs::read(path).unwrap(), b"# project-owned content\n");
    }

    #[test]
    fn changed_or_deleted_injected_config_is_an_explicit_incomplete_patch() {
        for deleted in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (profile, job, worktree, revision) = patch_fixture(dir.path());
            let cloud = CloudConfig {
                url: "https://example.invalid".into(),
                workspace: "team".into(),
                repository: "repo".into(),
                token_file: None,
            };
            let injected = write_cloud_config(&worktree, &cloud).unwrap().unwrap();
            record_injected_paths(&job, &worktree, vec![injected]).unwrap();
            let path = worktree.join(".lockyard/config.toml");
            if deleted {
                fs::remove_file(path).unwrap();
            } else {
                fs::write(path, b"# legitimate job edit\n").unwrap();
            }
            assert_eq!(
                collect_patch(&profile, &job, &worktree, &revision, "fixture", 4096, &[])
                    .unwrap_err()
                    .0,
                "patch_injected_file_changed"
            );
        }
    }

    #[test]
    fn clean_filter_cannot_hide_its_mutation_of_injected_config() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        let cloud = CloudConfig {
            url: "https://example.invalid".into(),
            workspace: "team".into(),
            repository: "repo".into(),
            token_file: None,
        };
        let injected = write_cloud_config(&worktree, &cloud).unwrap().unwrap();
        record_injected_paths(&job, &worktree, vec![injected]).unwrap();
        fs::copy(
            worktree.join(".lockyard/config.toml"),
            worktree.join(".lockyard/original.txt"),
        )
        .unwrap();
        fs::write(worktree.join(".lockyard/filter.py"), b"import sys,pathlib\nsys.stdin.buffer.read()\noriginal=pathlib.Path('.lockyard/original.txt').read_bytes()\npathlib.Path('.lockyard/config.toml').write_bytes(b'# filter mutation\\n')\nsys.stdout.buffer.write(original)\n").unwrap();
        fs::write(
            worktree.join(".gitattributes"),
            b".lockyard/config.toml filter=fixture\n",
        )
        .unwrap();
        git_ok(
            &job.join("repository.git"),
            &[
                "config",
                "filter.fixture.clean",
                "/usr/bin/python3 .lockyard/filter.py",
            ],
        );
        assert_eq!(
            collect_patch(&profile, &job, &worktree, &revision, "fixture", 16384, &[])
                .unwrap_err()
                .0,
            "patch_injected_file_changed"
        );
    }

    #[test]
    fn runtime_identity_preserves_private_file_access_without_capabilities() {
        for rootless in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (profile, job, worktree, _) = patch_fixture(dir.path());
            fs::remove_file(job.join("runtime-user")).unwrap();
            fs::write(
                &profile.runtime_program,
                format!(
                    r#"#!/usr/bin/python3
import sys
a=sys.argv[1:]
if 'image' in a: print('null')
elif any('SecurityOptions' in item for item in a): print('{}')
else: print('true true true')
"#,
                    if rootless {
                        "[\"name=rootless\"]"
                    } else {
                        "[]"
                    }
                ),
            )
            .unwrap();
            verify_runtime_limits(&profile, &job).unwrap();
            let command = container_command(
                &profile,
                &job,
                &worktree,
                &profile.git_program,
                "fixture",
                false,
            )
            .unwrap();
            let args: Vec<_> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let identity = if rootless {
                "0:0".into()
            } else {
                host_container_identity()
            };
            assert!(
                args.windows(2)
                    .any(|pair| pair[0] == "--user" && pair[1] == identity)
            );
            assert!(args.iter().any(|arg| arg == "--cap-drop=ALL"));
        }
    }

    #[test]
    fn runtime_workspace_key_copy_is_private_scoped_and_helpers_cannot_mount_it() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, _) = patch_fixture(dir.path());
        let key = WorkspaceKey::from_entropy([73; 32]);
        let context = WorkspaceKeyContext {
            workspace: "actual-workspace-id".into(),
            key,
        };
        assert_eq!(create_runtime_key(&job, &context).unwrap(), vec![73; 32]);
        let key_file = job.join("runtime-key/lockyard/keys/actual-workspace-id.key");
        assert_eq!(
            fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(key_file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let main = container_command(
            &profile,
            &job,
            &worktree,
            &profile.git_program,
            "fixture",
            false,
        )
        .unwrap();
        let main: Vec<_> = main
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            main.iter()
                .any(|arg| arg.ends_with("dst=/run/lockyard-config,readonly"))
        );
        assert!(
            main.iter()
                .any(|arg| arg == "XDG_CONFIG_HOME=/run/lockyard-config")
        );
        assert!(
            !main
                .iter()
                .any(|arg| arg.contains("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"))
        );
        let patch = container_command(
            &profile,
            &job,
            &worktree,
            &profile.git_program,
            "fixture",
            true,
        )
        .unwrap();
        let patch: Vec<_> = patch
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            !patch
                .iter()
                .any(|arg| arg.contains("runtime-key") || arg.contains("XDG_CONFIG_HOME"))
        );
        assert!(
            patch
                .iter()
                .any(|arg| arg.ends_with(&format!("dst={},readonly", worktree.display())))
        );
        remove_runtime_key(&job).unwrap();
        assert!(!key_file.exists());
    }

    #[test]
    fn arbitrary_forwarded_environment_names_are_private_and_redacted() {
        let root = tempfile::tempdir().unwrap();
        let (profile, job, worktree, _) = patch_fixture(root.path());
        let mut secrets = Vec::new();
        stage_forwarded_environment(
            &job,
            vec![
                ("AUTH".into(), "unique-auth-value".into()),
                ("DATABASE_URL".into(), "unique-database-value".into()),
            ],
            &mut secrets,
        )
        .unwrap();
        assert_eq!(
            secrets,
            vec![
                b"unique-auth-value".to_vec(),
                b"unique-database-value".to_vec()
            ]
        );
        let command = container_command(
            &profile,
            &job,
            &worktree,
            &profile.git_program,
            "main",
            false,
        )
        .unwrap();
        assert!(command.get_args().any(|arg| arg == "--env-file"));
        assert!(
            command
                .get_args()
                .all(|arg| !arg.to_string_lossy().contains("unique-"))
        );
        assert!(command.get_envs().all(|(_, value)| {
            !value.is_some_and(|value| value.to_string_lossy().contains("unique-"))
        }));
        let spool = Arc::new(Mutex::new(Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 4096,
            error: None,
            credential_tail: Vec::new(),
        }));
        let raw = b"AUTH unique-auth-value DB unique-database-value";
        drain(
            std::io::Cursor::new(raw),
            spool.clone(),
            secrets.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let spool = spool.lock().unwrap();
        for secret in &secrets {
            assert!(
                !spool
                    .file
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        }
        assert_eq!(
            scan_credential_stream(std::io::Cursor::new(raw), &secrets, 4096)
                .unwrap_err()
                .0,
            "patch_contains_forwarded_credential"
        );
    }
    #[test]
    fn forwarded_environment_rejects_unsupported_values_without_staging_any_prefix() {
        use std::os::unix::ffi::OsStringExt;
        for invalid in [
            std::ffi::OsString::from_vec(vec![255]),
            "bad\nline".into(),
            "bad\rline".into(),
            "bad\0line".into(),
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut secrets = Vec::new();
            assert!(
                stage_forwarded_environment(
                    root.path(),
                    vec![
                        ("AUTH".into(), "valid-first".into()),
                        ("DATABASE_URL".into(), invalid)
                    ],
                    &mut secrets
                )
                .is_err()
            );
            assert!(!root.path().join("runtime-secrets").exists());
            assert!(secrets.is_empty());
        }
    }
    #[test]
    fn serialized_log_guard_rejects_unsafe_marker_and_shared_stream_boundary() {
        for (raw, secrets) in [
            (b"REDACTED".to_vec(), vec![b"REDACTED".to_vec()]),
            (
                b"asecretb".to_vec(),
                vec![b"secret".to_vec(), b"a[REDACTED]b".to_vec()],
            ),
        ] {
            let spool = Arc::new(Mutex::new(Spool {
                file: Vec::new(),
                bytes: 0,
                truncated: false,
                limit: 4096,
                error: None,
                credential_tail: Vec::new(),
            }));
            assert!(
                drain(
                    std::io::Cursor::new(raw),
                    spool.clone(),
                    secrets.clone(),
                    Arc::new(AtomicBool::new(false))
                )
                .is_err()
            );
            let spool = spool.lock().unwrap();
            assert_eq!(spool.error, Some("serialized_log_contains_credential"));
            for secret in secrets {
                assert!(
                    !spool
                        .file
                        .windows(secret.len())
                        .any(|window| window == secret)
                );
            }
        }
        // stdout and stderr append into one shared spool; their joint output must be safe too.
        let secrets = vec![b"abc".to_vec()];
        let mut spool = Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 4096,
            error: None,
            credential_tail: Vec::new(),
        };
        let matcher = CredentialMatcher::new(&secrets).unwrap();
        spool.append(b"ab", &matcher).unwrap();
        assert!(spool.append(b"c", &matcher).is_err());
        assert_eq!(spool.file, b"ab");
        assert_eq!(spool.error, Some("serialized_log_contains_credential"));
    }
    #[test]
    fn overlapping_credentials_redact_longest_match_without_leaving_a_suffix() {
        let spool = Arc::new(Mutex::new(Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 4096,
            error: None,
            credential_tail: Vec::new(),
        }));
        drain(
            std::io::Cursor::new(b"ABCDE"),
            spool.clone(),
            vec![b"ABC".to_vec(), b"ABCDE".to_vec()],
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(spool.lock().unwrap().file, b"[REDACTED]");
    }
    #[test]
    fn overlapping_redaction_handles_arbitrary_read_boundaries() {
        struct Chunked<'a> {
            bytes: &'a [u8],
            chunk: usize,
        }
        impl Read for Chunked<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let count = self.bytes.len().min(self.chunk).min(out.len());
                out[..count].copy_from_slice(&self.bytes[..count]);
                self.bytes = &self.bytes[count..];
                Ok(count)
            }
        }
        let secrets = vec![
            b"abc".to_vec(),
            b"abcde".to_vec(),
            b"bcd".to_vec(),
            b"zab".to_vec(),
        ];
        let input = b"zabcdeabcxzababcde";
        let mut expected = Vec::new();
        let mut pos = 0;
        while pos < input.len() {
            if let Some(pattern) = secrets
                .iter()
                .filter(|pattern| input[pos..].starts_with(pattern))
                .max_by_key(|pattern| pattern.len())
            {
                expected.extend_from_slice(b"[REDACTED]");
                pos += pattern.len();
            } else {
                expected.push(input[pos]);
                pos += 1;
            }
        }
        for chunk in 1..=input.len() {
            let spool = Arc::new(Mutex::new(Spool {
                file: Vec::new(),
                bytes: 0,
                truncated: false,
                limit: 4096,
                error: None,
                credential_tail: Vec::new(),
            }));
            drain(
                Chunked {
                    bytes: input,
                    chunk,
                },
                spool.clone(),
                secrets.clone(),
                Arc::new(AtomicBool::new(false)),
            )
            .unwrap();
            assert_eq!(spool.lock().unwrap().file, expected, "chunk size {chunk}");
        }
    }
    #[test]
    fn long_overlapping_credentials_are_screened_without_quadratic_work() {
        let secrets: Vec<Vec<u8>> = (0..64)
            .map(|index| {
                let mut secret = vec![b'A'; 16384];
                secret[16382] = 64 + index;
                secret[16383] = b'B';
                secret
            })
            .collect();
        let mut data = vec![b'A'; 64 * 1024];
        data.push(b'B');
        let spool = Arc::new(Mutex::new(Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 2 * 1024 * 1024,
            error: None,
            credential_tail: Vec::new(),
        }));
        drain(
            std::io::Cursor::new(&data),
            spool.clone(),
            secrets.clone(),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let output = &spool.lock().unwrap().file;
        assert_eq!(output.len(), 64 * 1024 - 16383 + b"[REDACTED]".len());
        assert!(output.ends_with(b"[REDACTED]"));
        assert_eq!(
            scan_credential_stream(std::io::Cursor::new(&data), &secrets, 2 * 1024 * 1024)
                .unwrap_err()
                .0,
            "patch_contains_forwarded_credential"
        );
    }
    #[test]
    fn oversized_padded_cloud_token_cannot_be_silently_truncated() {
        use std::os::unix::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let token = root.path().join("token");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token)
            .unwrap();
        file.write_all(b"synthetic").unwrap();
        file.write_all(&vec![b' '; 16385]).unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            read_private_token(&token).unwrap_err().0,
            "invalid_token_file"
        );
    }

    #[test]
    fn hardlinked_protected_node_token_cannot_be_forwarded_as_project_cloud_token() {
        use std::os::unix::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let protected = root.path().join("node-relay.token");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&protected)
            .unwrap();
        file.write_all(b"synthetic-private-node-identity").unwrap();
        file.sync_all().unwrap();
        let alias = root.path().join("project-cloud.token");
        fs::hard_link(&protected, &alias).unwrap();
        assert_eq!(
            read_private_token(&alias).unwrap_err().0,
            "token_file_has_aliases"
        );
    }

    #[test]
    fn project_cloud_token_fifo_is_rejected_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt;
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("token.fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_private_token(&fifo).is_err());
        });
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn source_checkout_cannot_include_node_identity_or_other_job_state() {
        let (root, mut config, executor) = retention_fixture();
        drop(executor);
        let checkout = root.path().join("checkout");
        private_dir_new(&checkout).unwrap();
        config.repositories.insert(
            "repo".into(),
            RepositoryConfig {
                checkout: checkout.clone(),
                cloud: None,
                retention: Some(crate::retention::RetentionPolicy {
                    content_ttl_seconds: 60,
                }),
            },
        );
        check_execution_identity_paths(&config).unwrap();
        let identity = checkout.join("node-identity.key");
        fs::write(&identity, [7; 32]).unwrap();
        config.protected_identity_files = vec![identity];
        assert_eq!(
            check_execution_identity_paths(&config).unwrap_err().0,
            "identity_must_be_outside_execution_mounts"
        );
        config.protected_identity_files.clear();
        config.repositories.get_mut("repo").unwrap().checkout = config.state_dir.join("jobs");
        assert_eq!(
            check_execution_identity_paths(&config).unwrap_err().0,
            "identity_must_be_outside_execution_mounts"
        );
    }

    #[test]
    fn workload_credentials_and_context_are_readonly_main_only_and_cleaned() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, _) = patch_fixture(dir.path());
        let secret_file = dir.path().join("customer.secret");
        let mut source = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret_file)
            .unwrap();
        source
            .write_all(b"private-customer-value-sentinel")
            .unwrap();
        source.sync_all().unwrap();
        let refs = vec![crate::secrets::SecretBinding {
            name: "customer_api".into(),
            environment: Some("CUSTOMER_API_TOKEN".into()),
            source: crate::secrets::SecretSource::LocalFile { path: secret_file },
        }];
        let resolved = crate::secrets::stage_with_budget(
            &job,
            &refs,
            &[],
            Instant::now() + Duration::from_secs(2),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(resolved[0].bytes(), b"private-customer-value-sentinel");
        for name in ["runtime-context", "runtime-delegation"] {
            private_dir_new(&job.join(name)).unwrap();
        }
        fs::write(job.join("runtime-context/workflow-inputs.json"), b"{}").unwrap();
        fs::write(
            job.join("runtime-delegation/node.toml"),
            b"private-delegation-config",
        )
        .unwrap();
        let main = container_command(
            &profile,
            &job,
            &worktree,
            &profile.git_program,
            "main",
            false,
        )
        .unwrap();
        let main = main
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for path in [
            "/run/lockyard-secrets",
            "/run/lockyard-context",
            "/run/lockyard-delegation",
        ] {
            assert!(
                main.iter()
                    .any(|arg| arg.ends_with(&format!("dst={path},readonly")))
            );
        }
        assert!(
            main.iter()
                .any(|arg| arg == "LOCKYARD_NODE_CONFIG=/run/lockyard-delegation/node.toml")
        );
        assert!(
            main.iter().any(|arg| arg
                == "LOCKYARD_WORKFLOW_INPUTS_FILE=/run/lockyard-context/workflow-inputs.json")
        );
        assert!(main.windows(2).any(
            |pair| pair[0] == "--env-file" && pair[1].ends_with("runtime-secrets/.environment")
        ));
        assert!(
            main.iter()
                .all(|arg| !arg.contains("private-customer-value-sentinel"))
        );
        assert!(main.iter().all(|arg| !arg.contains("CUSTOMER_API_TOKEN=")));
        assert!(main.iter().all(|arg| !arg.contains("operator.sock")));
        let helper = container_command(
            &profile,
            &job,
            &worktree,
            &profile.git_program,
            "helper",
            true,
        )
        .unwrap();
        assert!(
            helper
                .get_args()
                .all(|arg| !arg.to_string_lossy().contains("runtime-secrets")
                    && !arg.to_string_lossy().contains("runtime-delegation")
                    && !arg.to_string_lossy().contains("runtime-context"))
        );
        remove_runtime_key(&job).unwrap();
        assert!(!job.join("runtime-secrets").exists());
    }

    #[test]
    fn binary_patch_cannot_serialize_a_known_forwarded_credential() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        let token = b"fixture-known-sensitive-token".to_vec();
        let mut bytes = vec![0];
        bytes.extend_from_slice(&token);
        bytes.extend_from_slice(b"\0binary tail");
        fs::write(worktree.join("artifact.bin"), bytes).unwrap();
        assert_eq!(
            collect_patch(
                &profile,
                &job,
                &worktree,
                &revision,
                "fixture",
                4096,
                &[token]
            )
            .unwrap_err()
            .0,
            "patch_contains_forwarded_credential"
        );
    }

    #[test]
    fn benign_binary_patch_with_forwarded_credential_still_applies() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        let bytes = b"\0benign\0binary tail";
        fs::write(worktree.join("artifact.bin"), bytes).unwrap();
        collect_patch(
            &profile,
            &job,
            &worktree,
            &revision,
            "fixture",
            4096,
            &[b"fixture-known-sensitive-token".to_vec()],
        )
        .unwrap();
        let patch = job.join("result.patch");
        fs::remove_file(worktree.join("artifact.bin")).unwrap();
        assert!(
            git(&worktree)
                .arg("apply")
                .arg(&patch)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(fs::read(worktree.join("artifact.bin")).unwrap(), bytes);
    }

    #[test]
    fn serialized_patch_is_refused_instead_of_rewritten_when_syntax_matches_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        fs::write(worktree.join("artifact.bin"), b"\0benign\0binary tail").unwrap();
        // "literal" occurs in Git's binary patch syntax rather than in the source blob.
        assert_eq!(
            collect_patch(
                &profile,
                &job,
                &worktree,
                &revision,
                "fixture",
                4096,
                &[b"literal".to_vec()]
            )
            .unwrap_err()
            .0,
            "patch_contains_forwarded_credential"
        );
        assert!(
            !fs::read_to_string(job.join("result.patch"))
                .unwrap()
                .contains("[REDACTED]")
        );
    }

    #[test]
    fn credential_scan_rejects_secret_paths_and_symlink_targets_before_encoding() {
        for symlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (profile, job, worktree, revision) = patch_fixture(dir.path());
            let token = b"fixture-known-sensitive-token".to_vec();
            if symlink {
                std::os::unix::fs::symlink(
                    std::str::from_utf8(&token).unwrap(),
                    worktree.join("link"),
                )
                .unwrap();
            } else {
                fs::write(
                    worktree.join(std::str::from_utf8(&token).unwrap()),
                    b"benign",
                )
                .unwrap();
            }
            assert_eq!(
                collect_patch(
                    &profile,
                    &job,
                    &worktree,
                    &revision,
                    "fixture",
                    4096,
                    &[token]
                )
                .unwrap_err()
                .0,
                "patch_contains_forwarded_credential"
            );
        }
    }

    #[test]
    fn credential_scan_has_explicit_entry_and_collection_time_bounds() {
        let cancel = AtomicBool::new(false);
        let budget = PatchBudget {
            deadline: Instant::now() - Duration::from_millis(1),
            cancel: &cancel,
        };
        assert_eq!(
            budget.remaining().unwrap_err().0,
            "patch_collection_timeout"
        );
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(
            budget.remaining().unwrap_err().0,
            "patch_collection_cancelled"
        );
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        for index in 0..MAX_PATCH_SCAN_ENTRIES / 2 + 1 {
            fs::write(
                worktree.join(format!("file-{index}")),
                format!("unique content {index}\n"),
            )
            .unwrap();
        }
        assert_eq!(
            collect_patch(
                &profile,
                &job,
                &worktree,
                &revision,
                "fixture",
                1024 * 1024,
                &[b"fixture-known-sensitive-token".to_vec()]
            )
            .unwrap_err()
            .0,
            "patch_credential_scan_entries"
        );
    }

    #[test]
    fn cancellation_interrupts_patch_helpers_and_confirms_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        fs::write(&profile.runtime_program, b"#!/usr/bin/python3\nimport sys,time\na=sys.argv[1:]\nif 'container' in a and 'rm' in a: sys.exit(0)\ntime.sleep(300)\n").unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let started = Instant::now();
        let worker = thread::spawn(move || {
            collect_patch_bounded(
                &profile,
                &job,
                &worktree,
                &revision,
                "fixture",
                4096,
                &[],
                &worker_cancel,
            )
        });
        thread::sleep(Duration::from_millis(100));
        cancel.store(true, Ordering::SeqCst);
        assert_eq!(
            worker.join().unwrap().unwrap_err().0,
            "patch_collection_cancelled"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    struct FailingWriter {
        bytes: Vec<u8>,
        fail_after: usize,
    }
    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() >= self.fail_after {
                return Err(std::io::Error::other("fixture writer failure"));
            }
            let count = bytes.len().min(2).min(self.fail_after - self.bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn sink_failure_preserves_partial_count_and_keeps_draining() {
        struct CountedReader {
            data: std::io::Cursor<Vec<u8>>,
            consumed: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Read for CountedReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.data.read(buffer)?;
                self.consumed.fetch_add(count, Ordering::SeqCst);
                Ok(count)
            }
        }
        let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let spool = Arc::new(Mutex::new(Spool {
            file: FailingWriter {
                bytes: Vec::new(),
                fail_after: 3,
            },
            bytes: 0,
            truncated: false,
            limit: 65536,
            error: None,
            credential_tail: Vec::new(),
        }));
        let data = vec![b'x'; 20000];
        let reader = CountedReader {
            data: std::io::Cursor::new(data.clone()),
            consumed: consumed.clone(),
        };
        assert_eq!(
            drain(
                reader,
                spool.clone(),
                vec![],
                Arc::new(AtomicBool::new(false))
            ),
            Err("spool_write_failed")
        );
        let spool = spool.lock().unwrap();
        assert_eq!(consumed.load(Ordering::SeqCst), data.len());
        assert_eq!(spool.bytes, 3);
        assert_eq!(spool.file.bytes.len(), 3);
        assert!(spool.truncated);
        assert_eq!(spool.error, Some("spool_write_failed"));
        let dir = tempfile::tempdir().unwrap();
        let id = "00000000000000000000000001";
        private_dir(&dir.path().join("jobs")).unwrap();
        private_dir_new(&dir.path().join("jobs").join(id)).unwrap();
        let mut record = JobRecord {
            had_runtime_credentials: true,
            spec: JobSpec {
                id: id.into(),
                repository: "repo".into(),
                revision: "HEAD".into(),
                runner: "fixture".into(),
                arguments: vec![],
                prompt: None,
                timeout_seconds: None,
                priority: 0,
                workflow_inputs: Vec::new(),
                expected_runner_sha256: None,
                owner_approval: None,
            },
            state: JobState::Succeeded,
            agent: "derived".into(),
            submitter: "peer".into(),
            submitter_certificate_sha256: None,
            created_at_ms: 1,
            updated_at_ms: 1,
            resolved_revision: None,
            worktree: None,
            pid: None,
            exit_code: Some(0),
            error_code: None,
            log_bytes: 0,
            log_truncated: false,
            log_error: None,
            patch_bytes: 0,
            patch_truncated: false,
            patch_error: None,
            configured_image: None,
            admission_runner_sha256: None,
            admission_repository_sha256: None,
            admitted_image: None,
            result_manifest: None,
            provenance_error: None,
            notification_accounted_certificate_sha256: None,
            retention: None,
        };
        record_log_integrity(&mut record, spool.bytes, spool.truncated, spool.error);
        persist(dir.path(), &record).unwrap();
        let stored: JobRecord = serde_json::from_slice(
            &fs::read(dir.path().join("jobs").join(id).join("record.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(stored.state, JobState::Failed);
        assert_eq!(stored.log_error.as_deref(), Some("spool_write_failed"));
        assert_eq!(stored.log_bytes, 3);
        assert!(stored.log_truncated);
    }

    #[test]
    fn reader_and_join_failures_are_explicit_incomplete_results() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fixture reader failure"))
            }
        }
        let spool = Arc::new(Mutex::new(Spool {
            file: Vec::new(),
            bytes: 0,
            truncated: false,
            limit: 1024,
            error: None,
            credential_tail: Vec::new(),
        }));
        assert_eq!(
            drain(
                FailingReader,
                spool.clone(),
                vec![],
                Arc::new(AtomicBool::new(false))
            ),
            Err("stream_read_failed")
        );
        assert_eq!(spool.lock().unwrap().error, Some("stream_read_failed"));
        assert_eq!(
            join_stream(thread::spawn(|| panic!("fixture stream panic"))),
            Some("stream_thread_failed")
        );
    }

    #[test]
    fn ambiguous_inspection_error_does_not_confirm_container_stop() {
        let dir = tempfile::tempdir().unwrap();
        private_dir_new(&dir.path().join("runtime-config")).unwrap();
        let runtime = dir.path().join("runtime-fixture");
        fs::write(
            &runtime,
            b"#!/bin/sh\ncase \"$2\" in info) exit 0;; *) exit 1;; esac\n",
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let profile = ContainerProfile {
            runtime: ContainerRuntime::Docker,
            runtime_program: runtime,
            image: "fixture:image".into(),
            supply_chain: None,
            git_program: "/usr/bin/git".into(),
            memory_mb: 128,
            cpu_millis: 1000,
            pids_limit: 64,
            network: ContainerNetwork::None,
        };
        assert!(!stop_container(&profile, dir.path(), "fixture"));
    }
}
