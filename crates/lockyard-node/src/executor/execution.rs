// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

impl Executor {
    pub(super) fn run(&self, id: &str, cancel: Arc<AtomicBool>) {
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
    pub(super) fn commit_launch(
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

    pub(super) fn finalize_provenance(&self, id: &str) {
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

    pub(super) fn build_manifest(
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

    pub(super) fn run_inner(&self, id: &str, cancel: Arc<AtomicBool>) -> Result<()> {
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
