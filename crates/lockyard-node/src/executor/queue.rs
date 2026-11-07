// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

impl Executor {
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
    pub(super) fn launch_ready(&self) -> Result<()> {
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
    pub(super) fn claim_ready(&self) -> Result<Option<ClaimedJob>> {
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
    pub(super) fn coordinate_workers(&self) {
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
    pub(super) fn worker_loop(&self, first: ClaimedJob, current: Arc<Mutex<Option<String>>>) {
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
}
