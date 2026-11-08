// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

impl Executor {
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
    pub(super) fn capture_notification(&self, record: &mut JobRecord) -> Result<()> {
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
    pub(super) fn capture_notification_best_effort(&self, record: &mut JobRecord) {
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
                        external_approval_required: runner.requires_external_approval(),
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
        let repository_cloud_sha256 = self
            .inner
            .config
            .repositories
            .iter()
            .filter_map(|(name, repository)| {
                repository.cloud.as_ref().map(|cloud| {
                    crate::approvals::repository_cloud_sha256(Some(cloud))
                        .map(|digest| (name.clone(), digest.expect("a cloud config has a digest")))
                        .map_err(|error| ExecutorError(error.0))
                })
            })
            .collect::<Result<_>>()?;
        let result = NodeCapabilities {
            repository_cloud_sha256,
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
            repository_cloud_sha256: crate::approvals::repository_cloud_sha256(
                project.cloud.as_ref(),
            )
            .map_err(|error| ExecutorError(error.0))?,
            node_id: self.inner.config.node_id.clone(),
            certificate_sha256: certificate_sha256.into(),
            repository: repository.into(),
            requested_revision: revision.into(),
            resolved_revision: resolve_revision(&project.checkout, revision)?,
            runner: runner.into(),
            profile: crate::scheduler::RunnerCapability {
                external_approval_required: profile.requires_external_approval(),
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
        lockyard_core::fsio::rename(&temporary, self.inner.config.state_dir.join("drain-state"))
            .map_err(io_error)?;
        lockyard_core::fsio::sync_path(&self.inner.config.state_dir).map_err(io_error)?;
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
    pub(super) fn artifact_lock(&self, id: &str) -> Result<Arc<Mutex<()>>> {
        self.inner
            .jobs
            .lock()
            .map_err(|_| ExecutorError("executor_poisoned"))?
            .get(id)
            .map(|entry| entry.artifacts.clone())
            .ok_or(ExecutorError("job_not_found"))
    }

    pub(super) fn verify_owner_approval(&self, spec: &JobSpec, revision: &str) -> Result<()> {
        let runner = &self.inner.config.runners[&spec.runner];
        let repository_cloud = self.inner.config.repositories[&spec.repository]
            .cloud
            .as_ref();
        let has_credentials = runner.has_credentials() || repository_cloud.is_some();
        let networked = !matches!(runner.container.network, ContainerNetwork::None);
        if self.inner.config.external_actions == ExternalActionsPolicy::Deny
            && networked
            && has_credentials
        {
            return Err(ExecutorError("external_actions_denied"));
        }
        let requires_owner = runner.action.requires_owner() || networked || has_credentials;
        if !requires_owner && spec.owner_approval.is_none() {
            return Ok(());
        }
        if requires_owner && spec.owner_approval.is_none() {
            return Err(ExecutorError("owner_approval_required"));
        }
        let workspace = &self
            .inner
            .config
            .provenance
            .as_ref()
            .ok_or(ExecutorError(if runner.action.requires_owner() {
                "result_signing_required"
            } else {
                "owner_approval_required"
            }))?
            .workspace;
        let pin = self
            .inner
            .config
            .node_certificate_sha256
            .as_deref()
            .ok_or(ExecutorError(if runner.action.requires_owner() {
                "owner_approval_node_incarnation_required"
            } else {
                "owner_approval_required"
            }))?;
        let expected = crate::approvals::ApprovalExpectation {
            workspace,
            node_id: &self.inner.config.node_id,
            node_certificate_sha256: pin,
            spec,
            resolved_revision: revision,
            runner,
            repository_cloud,
        };
        crate::approvals::enforce(&expected, now_ms()).map_err(|error| {
            ExecutorError(if runner.action.requires_owner() {
                error.0
            } else {
                "owner_approval_required"
            })
        })
    }

    pub(super) fn validate(&self, spec: &JobSpec) -> Result<()> {
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

    pub(super) fn update(
        &self,
        id: &str,
        change: impl FnOnce(&mut JobRecord),
    ) -> Result<JobRecord> {
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
}
