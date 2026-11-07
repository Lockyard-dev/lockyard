// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

impl Executor {
    pub fn tombstone(&self, id: &str) -> Result<Option<JobTombstone>> {
        retention::load_tombstone(&self.inner.config.state_dir.join("job-tombstones"), id)
            .map_err(|error| ExecutorError(error.0))
    }
    pub(super) fn terminal_receipt(
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
    pub(super) fn purge_expired_at(&self, now: u64) -> Result<usize> {
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
}
