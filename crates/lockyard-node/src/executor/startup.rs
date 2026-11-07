// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

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

    pub(super) fn open(
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
            if matches!(container.runtime, ContainerRuntime::Native) {
                let report = crate::native::capabilities(
                    container.cgroup_root.as_deref(),
                    &container.runtime_program,
                );
                if !report.available {
                    return Err(ExecutorError("container_limits_unavailable"));
                }
                if !container
                    .native_rootfs
                    .as_ref()
                    .is_some_and(|path| path.is_absolute() && path != Path::new("/"))
                {
                    return Err(ExecutorError("native_rootfs_unavailable"));
                }
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
            if let Some(tombstone) =
                retention::load_tombstone(&config.state_dir.join("job-tombstones"), &id)
                    .map_err(|error| ExecutorError(error.0))?
            {
                // Reconcile the old journal before any content can be retired.
                if legacy_erasure_authorized(&config, &tombstone)? {
                    retire_job_directory(&config.state_dir, &id)?;
                }
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
            if !legacy_erasure_authorized(&config, &tombstone)? {
                continue;
            }
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
}
