// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Legacy recovery is a sidecar: the original tombstone and its purge hash stay immutable.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TombstoneReconciliation {
    version: u8,
    job_id: String,
    tombstone_sha256: String,
    pub(super) status: ReconciliationStatus,
    source: Option<ReconciliationSource>,
    pub(super) completed_at_ms: Option<u64>,
    diagnostic_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cloud_error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cloud_error_status: Option<u16>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReconciliationStatus {
    Reconciled,
    NeedsReview,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReconciliationSource {
    SignedResult,
    NodeJournal,
    CloudSignedResult,
}
fn tombstone_hash(tombstone: &JobTombstone) -> Result<String> {
    Ok(crate::provenance::sha256(
        &serde_json::to_vec(tombstone).map_err(|_| ExecutorError("invalid_job_tombstone"))?,
    ))
}
fn read_optional<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
        Ok(_) => (),
    }
    let file = private_open_existing(path)?;
    if file.metadata().map_err(io_error)?.len() > limit {
        return Err(ExecutorError("tombstone_evidence_invalid"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > limit {
        return Err(ExecutorError("tombstone_evidence_invalid"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| ExecutorError("tombstone_evidence_invalid"))
}
fn valid_completion(tombstone: &JobTombstone, completed_at_ms: u64) -> bool {
    completed_at_ms > 0
        && completed_at_ms <= tombstone.terminal_expires_at_ms
        && completed_at_ms <= tombstone.purged_at_ms
        && completed_at_ms <= now_ms()
}
pub(super) fn load_reconciliation(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
) -> Result<Option<TombstoneReconciliation>> {
    let path = config
        .state_dir
        .join("job-tombstones")
        .join(format!("{}.reconciliation", tombstone.job_id));
    let Some(value): Option<TombstoneReconciliation> = read_optional(&path, 4096)? else {
        return Ok(None);
    };
    if value.version != 1
        || value.job_id != tombstone.job_id
        || value.tombstone_sha256 != tombstone_hash(tombstone)?
        || match value.status {
            ReconciliationStatus::Reconciled => {
                value.source.is_none()
                    || value
                        .completed_at_ms
                        .is_none_or(|time| !valid_completion(tombstone, time))
                    || value.diagnostic_code.is_some()
                    || value.cloud_error_code.is_some()
                    || value.cloud_error_status.is_some()
            }
            ReconciliationStatus::NeedsReview => {
                value.source.is_some()
                    || value.completed_at_ms.is_some()
                    || value.diagnostic_code.as_deref() != Some("tombstone_reconciliation_required")
            }
        }
    {
        return Err(ExecutorError("tombstone_reconciliation_invalid"));
    }
    Ok(Some(value))
}
fn signed_completion(config: &ExecutorConfig, tombstone: &JobTombstone) -> Result<Option<u64>> {
    let Some(document) = &tombstone.result_manifest else {
        return Ok(None);
    };
    verified_completion(config, tombstone, document).map(Some)
}
fn verified_completion(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
    document: &crate::provenance::SignedDocument,
) -> Result<u64> {
    let signing = config
        .provenance
        .as_ref()
        .ok_or(ExecutorError("tombstone_evidence_invalid"))?;
    let key = crate::provenance::TrustedSigningKey {
        public_key: signing.public_key.clone(),
    };
    let manifest = crate::provenance::verify_result_identity(
        document,
        &key,
        &config.node_id,
        &signing.workspace,
        &tombstone.job_id,
    )
    .map_err(|_| ExecutorError("tombstone_evidence_invalid"))?;
    if manifest.request_sha256 != tombstone.spec_sha256
        || manifest.state != tombstone.outcome
        || !valid_completion(tombstone, manifest.completed_at_ms)
    {
        return Err(ExecutorError("tombstone_evidence_invalid"));
    }
    Ok(manifest.completed_at_ms)
}
fn cloud_completion(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
) -> std::result::Result<Option<u64>, (String, Option<u16>)> {
    let Some(client) = &config.signed_results else {
        return Ok(None);
    };
    let bytes = client
        .get_signed_result(&config.node_id, &config.node_id, &tombstone.job_id)
        .map_err(|error| {
            (
                error.code().unwrap_or("temporarily_unavailable").to_owned(),
                error.status(),
            )
        })?;
    let document: crate::provenance::SignedDocument = serde_json::from_slice(&bytes)
        .map_err(|_| ("content_authentication_failed".into(), None))?;
    verified_completion(config, tombstone, &document)
        .map(Some)
        .map_err(|error| (error.0.into(), None))
}
fn journal_path_completion(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
    parent: &str,
) -> Result<Option<u64>> {
    let directory = config.state_dir.join(parent).join(&tombstone.job_id);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
        Ok(_) => {
            retention::require_directory(&directory).map_err(|error| ExecutorError(error.0))?
        }
    }
    let Some(record): Option<JobRecord> =
        read_optional(&directory.join("record.json"), 1024 * 1024)?
    else {
        return Ok(None);
    };
    if record.spec.id != tombstone.job_id
        || record.submitter != tombstone.submitter
        || record.submitter_certificate_sha256 != tombstone.submitter_certificate_sha256
        || retention::spec_digest(&record.spec).map_err(|error| ExecutorError(error.0))?
            != tombstone.spec_sha256
        || record.state != tombstone.outcome
        || record.created_at_ms > record.updated_at_ms
        || !valid_completion(tombstone, record.updated_at_ms)
    {
        return Err(ExecutorError("tombstone_evidence_invalid"));
    }
    Ok(Some(record.updated_at_ms))
}
fn journal_completion(config: &ExecutorConfig, tombstone: &JobTombstone) -> Result<Option<u64>> {
    match (
        journal_path_completion(config, tombstone, "jobs"),
        journal_path_completion(config, tombstone, "expired-content"),
    ) {
        (Ok(Some(first)), Ok(Some(second))) if first == second => Ok(Some(first)),
        (Ok(Some(time)), Ok(None)) | (Ok(None), Ok(Some(time))) => Ok(Some(time)),
        (Ok(None), Ok(None)) => Ok(None),
        _ => Err(ExecutorError("tombstone_evidence_invalid")),
    }
}
fn persist_reconciliation(config: &ExecutorConfig, value: &TombstoneReconciliation) -> Result<()> {
    let directory = config.state_dir.join("job-tombstones");
    let temporary = directory.join(format!(
        ".{}-{}.reconciliation.tmp",
        value.job_id,
        lockyard_cloud_client::ulid()
    ));
    let path = directory.join(format!("{}.reconciliation", value.job_id));
    let result = (|| {
        let mut file = private_open(&temporary, true)?;
        file.write_all(
            &serde_json::to_vec(value)
                .map_err(|_| ExecutorError("tombstone_reconciliation_invalid"))?,
        )
        .and_then(|()| file.sync_all())
        .map_err(io_error)?;
        lockyard_core::fsio::rename(&temporary, &path).map_err(io_error)?;
        lockyard_core::fsio::sync_path(&directory).map_err(io_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
pub(super) fn reconcile_legacy_tombstone(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
) -> Result<TombstoneReconciliation> {
    reconcile_with_cloud(config, tombstone, None)
}
type CloudCompletion = std::result::Result<Option<u64>, (String, Option<u16>)>;
fn reconcile_with_cloud(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
    cloud: Option<CloudCompletion>,
) -> Result<TombstoneReconciliation> {
    tombstone
        .validate()
        .map_err(|error| ExecutorError(error.0))?;
    // Metadata reads and maintenance may race in one process. Serialize the evidence commit;
    // a later observer must see its durable success before the journal can be erased.
    let _guard = private_open(
        &config
            .state_dir
            .join("job-tombstones")
            .join(format!("{}.reconciliation.lock", tombstone.job_id)),
        false,
    )?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(_guard.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(ExecutorError("tombstone_reconciliation_unavailable"));
        }
    }
    #[cfg(not(unix))]
    _guard
        .lock()
        .map_err(|_| ExecutorError("tombstone_reconciliation_unavailable"))?;
    let previous = load_reconciliation(config, tombstone)?;
    if let Some(value) = &previous
        && value.status == ReconciliationStatus::Reconciled
    {
        return Ok(value.clone());
    }
    // Both sources are checked before erasing the surviving journal. Conflicts require review.
    let mut cloud_error = previous.as_ref().and_then(|value| {
        value
            .cloud_error_code
            .clone()
            .map(|code| (code, value.cloud_error_status))
    });
    let evidence = match (
        signed_completion(config, tombstone),
        journal_completion(config, tombstone),
    ) {
        (Ok(Some(signed)), Ok(Some(journal))) if signed == journal => {
            Some((signed, ReconciliationSource::SignedResult))
        }
        (Ok(Some(signed)), Ok(None)) => Some((signed, ReconciliationSource::SignedResult)),
        (Ok(None), Ok(Some(journal))) => Some((journal, ReconciliationSource::NodeJournal)),
        (Ok(None), Ok(None)) => match cloud.unwrap_or(Ok(None)) {
            Ok(Some(time)) => Some((time, ReconciliationSource::CloudSignedResult)),
            Ok(None) => None,
            Err(error) => {
                cloud_error = Some(error);
                None
            }
        },
        _ => None,
    };
    if evidence.is_some() {
        cloud_error = None;
    }
    let value = TombstoneReconciliation {
        version: 1,
        job_id: tombstone.job_id.clone(),
        tombstone_sha256: tombstone_hash(tombstone)?,
        status: if evidence.is_some() {
            ReconciliationStatus::Reconciled
        } else {
            ReconciliationStatus::NeedsReview
        },
        source: evidence.map(|(_, source)| source),
        completed_at_ms: evidence.map(|(time, _)| time),
        diagnostic_code: evidence
            .is_none()
            .then(|| "tombstone_reconciliation_required".into()),
        cloud_error_code: cloud_error.as_ref().map(|error| error.0.clone()),
        cloud_error_status: cloud_error.and_then(|error| error.1),
    };
    if previous.as_ref() != Some(&value) {
        persist_reconciliation(config, &value)?;
        if value.status == ReconciliationStatus::NeedsReview {
            // This content-free durable sidecar is the diagnostic event; emit only its code/id.
            eprintln!(
                "lockyard node: tombstone_reconciliation_required job_id={} status=needs_review",
                tombstone.job_id
            );
        }
    }
    Ok(value)
}
pub(super) fn legacy_erasure_authorized(
    config: &ExecutorConfig,
    tombstone: &JobTombstone,
) -> Result<bool> {
    Ok(tombstone.completed_at_ms.is_some()
        || reconcile_legacy_tombstone(config, tombstone)?.status
            == ReconciliationStatus::Reconciled)
}
impl Executor {
    /// Fetch one unresolved legacy result per background tick. Remote I/O happens before
    /// taking the reconciliation lock, so metadata, startup and unrelated erasure stay local.
    pub(crate) fn reconcile_cloud_tombstones(&self) -> Result<()> {
        if self.inner.config.signed_results.is_none() {
            return Ok(());
        }
        let Ok(mut cursor) = self.inner.legacy_result_cursor.try_lock() else {
            return Ok(());
        };
        let mut candidates = BTreeMap::new();
        for entry in
            fs::read_dir(self.inner.config.state_dir.join("job-tombstones")).map_err(io_error)?
        {
            let entry = entry.map_err(io_error)?;
            let Some(id) = entry
                .file_name()
                .to_str()
                .filter(|id| valid_id(id))
                .map(str::to_owned)
            else {
                continue;
            };
            let tombstone = self
                .tombstone(&id)?
                .ok_or(ExecutorError("job_tombstone_missing"))?;
            if tombstone.completed_at_ms.is_none()
                && !load_reconciliation(&self.inner.config, &tombstone)?
                    .is_some_and(|value| value.status == ReconciliationStatus::Reconciled)
            {
                candidates.insert(id, tombstone);
            }
        }
        let next = candidates
            .iter()
            .find(|(id, _)| cursor.as_ref().is_none_or(|last| *id > last))
            .or_else(|| candidates.first_key_value());
        if let Some((id, tombstone)) = next {
            *cursor = Some(id.clone());
            let evidence = cloud_completion(&self.inner.config, tombstone);
            reconcile_with_cloud(&self.inner.config, tombstone, Some(evidence))?;
        }
        Ok(())
    }

    pub(super) fn reconcile_legacy_tombstones(&self) -> Result<()> {
        for entry in
            fs::read_dir(self.inner.config.state_dir.join("job-tombstones")).map_err(io_error)?
        {
            let entry = entry.map_err(io_error)?;
            let Some(id) = entry
                .file_name()
                .to_str()
                .filter(|id| valid_id(id))
                .map(str::to_owned)
            else {
                continue;
            };
            let tombstone = self
                .tombstone(&id)?
                .ok_or(ExecutorError("job_tombstone_missing"))?;
            if tombstone.completed_at_ms.is_none() {
                reconcile_legacy_tombstone(&self.inner.config, &tombstone)?;
            }
        }
        Ok(())
    }
}
