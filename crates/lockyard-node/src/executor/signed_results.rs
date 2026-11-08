// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;

impl Executor {
    /// Read the saved serialization, never round-trip SignedDocument to produce upload bytes.
    pub(super) fn publish_signed_result(&self, record: &JobRecord) -> Result<()> {
        let Some(client) = &self.inner.config.signed_results else {
            return Ok(());
        };
        if !record.state.is_terminal()
            || record.result_manifest.is_none()
            || record.provenance_error.is_some()
        {
            return Ok(());
        }
        let directory = self
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(&record.spec.id);
        let path = directory.join("signed-result.json");
        if !path.try_exists().map_err(io_error)? {
            return Ok(());
        } // Older journals have no original byte serialization.
        let file = private_open_existing(&path)?;
        let mut bytes = Vec::new();
        file.take(crate::provenance::MAX_SIGNED_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > crate::provenance::MAX_SIGNED_DOCUMENT_BYTES {
            return Err(ExecutorError("result_document_invalid"));
        }
        let document: crate::provenance::SignedDocument =
            serde_json::from_slice(&bytes).map_err(|_| ExecutorError("result_document_invalid"))?;
        if Some(&document) != record.result_manifest.as_ref() {
            return Err(ExecutorError("result_document_invalid"));
        }
        let expires_at_ms = record
            .retention
            .as_ref()
            .and_then(|r| r.terminal_expires_at_ms)
            .ok_or(ExecutorError("invalid_content_deadline"))?;
        let expires_at_ms = lockyard_cloud_client::Client::signed_result_expiry(
            &self.inner.config.node_id,
            &record.spec.id,
            expires_at_ms,
        )
        .map_err(|_| ExecutorError("invalid_content_deadline"))?;
        let receipt = directory.join("signed-result.published");
        let expected_receipt = crate::provenance::sha256(&bytes);
        if receipt.try_exists().map_err(io_error)? {
            let mut saved = String::new();
            private_open_existing(&receipt)?
                .take(128)
                .read_to_string(&mut saved)
                .map_err(io_error)?;
            if saved != expected_receipt {
                return Err(ExecutorError("result_publication_receipt_invalid"));
            }
        } else {
            client
                .put_signed_result(
                    &self.inner.config.node_id,
                    &self.inner.config.node_id,
                    &record.spec.id,
                    &bytes,
                    expires_at_ms,
                )
                .map_err(|_| ExecutorError("result_publication_pending"))?;
            lockyard_core::fsio::replace(&receipt, expected_receipt.as_bytes(), 0o600)
                .map_err(io_error)?;
        }
        client
            .acknowledge_signed_result(
                &self.inner.config.node_id,
                &self.inner.config.node_id,
                &record.spec.id,
                &bytes,
                expires_at_ms,
            )
            .map_err(|_| ExecutorError("result_publication_pending"))
    }
    /// One publication per tick, independent of retention/startup. A round-robin cursor
    /// prevents one unavailable result from starving later jobs and expired pending writes.
    pub(crate) fn publish_signed_results(&self) {
        let Some(client) = &self.inner.config.signed_results else {
            return;
        };
        let Ok(mut cursor) = self.inner.signed_result_cursor.lock() else {
            return;
        };
        let Ok(records) = self.list() else {
            return;
        };
        let mut candidates: BTreeMap<String, Option<JobRecord>> = records
            .into_iter()
            .filter(|r| r.state.is_terminal() && r.result_manifest.is_some())
            .map(|record| (record.spec.id.clone(), Some(record)))
            .collect();
        for pending in client.pending_operations() {
            let parts = pending.path.split('/').collect::<Vec<_>>();
            let ["", "api", "v1", "nodes", node, "jobs", job, "signed-result"] = parts.as_slice()
            else {
                continue;
            };
            if *node == self.inner.config.node_id {
                candidates.entry((*job).into()).or_insert(None);
            }
        }
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        let split =
            candidates.partition_point(|(id, _)| cursor.as_ref().is_some_and(|last| id <= last));
        candidates.rotate_left(split);
        for (id, record) in candidates {
            let pending = client.signed_result_pending(&self.inner.config.node_id, &id);
            if let Some(pending) = &pending {
                if lockyard_cloud_client::Client::result_replay_expired(pending)
                    || lockyard_cloud_client::Client::result_permanently_refused(pending)
                {
                    let _ = client.quarantine_signed_result(&pending.key);
                    *cursor = Some(id);
                    return;
                }
                if !lockyard_cloud_client::Client::result_retry_ready(pending) {
                    continue;
                }
            }
            if let Some(record) = record {
                let directory = self.inner.config.state_dir.join("jobs").join(&id);
                if directory.join("signed-result.published").exists() && pending.is_none() {
                    continue;
                }
                if directory.join("signed-result.suspended").exists()
                    || !directory.join("signed-result.json").exists()
                {
                    continue;
                }
                let Ok(artifacts) = self.artifact_lock(&id) else {
                    continue;
                };
                let Ok(_guard) = artifacts.try_lock() else {
                    continue;
                };
                *cursor = Some(id.clone());
                if let Err(error) = self.publish_signed_result(&record) {
                    let pending = client.signed_result_pending(&self.inner.config.node_id, &id);
                    let code = pending
                        .as_ref()
                        .map(|p| p.cause_code.clone())
                        .unwrap_or_else(|| error.0.into());
                    eprintln!(
                        "lockyard node: result_publication_pending code={} job_id={}",
                        code, id
                    );
                    if let Some(pending) = pending
                        && lockyard_cloud_client::Client::result_permanently_refused(&pending)
                        && lockyard_core::fsio::replace(
                            &directory.join("signed-result.suspended"),
                            code.as_bytes(),
                            0o600,
                        )
                        .is_ok()
                    {
                        let _ = client.quarantine_signed_result(&pending.key);
                    }
                }
            } else if let Some(pending) = pending {
                // Retention has removed the original plaintext. Only frozen bytes can be sent.
                *cursor = Some(id.clone());
                // Keep a content-free commitment to the acknowledged ciphertext beside the
                // tombstone: jobs/<id> was erased. Sync it before releasing the W4 bytes, so
                // a crash between receipt and cleanup causes an exact replay, never proof loss.
                let receipt = self
                    .inner
                    .config
                    .state_dir
                    .join("job-tombstones")
                    .join(format!("{id}.signed-result.published"));
                if let Some(body) = &pending.body
                    && client.replay_signed_result(&pending.key).is_ok()
                    && lockyard_core::fsio::replace(
                        &receipt,
                        crate::provenance::sha256(body.as_bytes()).as_bytes(),
                        0o600,
                    )
                    .is_ok()
                {
                    let _ = client.resolve_pending(&pending.key);
                }
            }
            return;
        }
    }
}
