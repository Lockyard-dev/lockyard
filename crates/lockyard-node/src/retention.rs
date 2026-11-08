// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Explicit project content expiry and durable, content-free execution tombstones.
//! Expiry never authorizes replay or removal of an uncertain running execution.
use crate::wire::{JobSpec, JobState};
use ring::digest;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self},
    io::{Read, Write},
    path::Path,
};

pub const MIN_CONTENT_TTL_SECONDS: u64 = 60;
pub const MAX_CONTENT_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const MAX_TOMBSTONE_BYTES: u64 = 128 * 1024;

/// Authenticated routing metadata only. The policy duration and this copy's deadline
/// are distinct from a running job's immutable terminal artifact deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRetention {
    pub content_ttl_seconds: u64,
    pub expires_at_ms: u64,
}
impl ContentRetention {
    pub fn for_copy(
        policy: &RetentionPolicy,
        created_at_ms: u64,
        terminal_expires_at_ms: Option<u64>,
    ) -> Result<Self> {
        policy.validate()?;
        let mut expires_at_ms = created_at_ms
            .checked_add(policy.content_ttl_seconds * 1000)
            .ok_or(RetentionError("retention_clock_overflow"))?;
        if let Some(terminal) = terminal_expires_at_ms {
            expires_at_ms = expires_at_ms.min(terminal);
        }
        let value = Self {
            content_ttl_seconds: policy.content_ttl_seconds,
            expires_at_ms,
        };
        value.validate(created_at_ms)?;
        Ok(value)
    }
    pub fn validate(&self, created_at_ms: u64) -> Result<()> {
        RetentionPolicy {
            content_ttl_seconds: self.content_ttl_seconds,
        }
        .validate()?;
        if self.expires_at_ms <= created_at_ms
            || self.expires_at_ms > 253_402_300_799_999
            || self.expires_at_ms > created_at_ms.saturating_add(self.content_ttl_seconds * 1000)
        {
            return Err(RetentionError("invalid_content_deadline"));
        }
        Ok(())
    }
    pub fn policy(&self) -> RetentionPolicy {
        RetentionPolicy {
            content_ttl_seconds: self.content_ttl_seconds,
        }
    }
}
pub fn id_timestamp_ms(id: &str) -> Result<u64> {
    if !crate::wire::valid_ulid(id) {
        return Err(RetentionError("invalid_request_id"));
    }
    let mut result = 0u64;
    for byte in id.bytes().take(10) {
        let digit = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
            .iter()
            .position(|value| *value == byte)
            .ok_or(RetentionError("invalid_request_id"))?;
        result = (result << 5) | digit as u64;
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionError(pub &'static str);
impl std::fmt::Display for RetentionError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.0)
    }
}
impl std::error::Error for RetentionError {}
pub type Result<T> = std::result::Result<T, RetentionError>;
fn io(_: std::io::Error) -> RetentionError {
    RetentionError("retention_io")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    /// Required in each configured project. There is deliberately no default.
    pub content_ttl_seconds: u64,
}
impl RetentionPolicy {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_CONTENT_TTL_SECONDS..=MAX_CONTENT_TTL_SECONDS).contains(&self.content_ttl_seconds)
        {
            return Err(RetentionError("invalid_project_content_retention"));
        }
        Ok(())
    }
    pub fn effective(&self, sender: &Self) -> Result<Self> {
        self.validate()?;
        sender.validate()?;
        Ok(Self {
            content_ttl_seconds: self.content_ttl_seconds.min(sender.content_ttl_seconds),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSnapshot {
    pub content_ttl_seconds: u64,
    pub admitted_at_ms: u64,
    /// Set once on the first confirmed terminal outcome, never on reads/retries/signing.
    pub terminal_expires_at_ms: Option<u64>,
    pub purged_at_ms: Option<u64>,
}
impl RetentionSnapshot {
    pub fn admit(policy: &RetentionPolicy, admitted_at_ms: u64) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            content_ttl_seconds: policy.content_ttl_seconds,
            admitted_at_ms,
            terminal_expires_at_ms: None,
            purged_at_ms: None,
        })
    }
    pub fn validate(&self) -> Result<()> {
        RetentionPolicy {
            content_ttl_seconds: self.content_ttl_seconds,
        }
        .validate()?;
        if self
            .terminal_expires_at_ms
            .is_some_and(|expiry| expiry < self.admitted_at_ms)
            || self.purged_at_ms.is_some_and(|purged| {
                self.terminal_expires_at_ms
                    .is_none_or(|expiry| purged < expiry)
            })
        {
            return Err(RetentionError("invalid_retention_snapshot"));
        }
        Ok(())
    }
    pub fn note_terminal(&mut self, state: JobState, now_ms: u64) -> Result<()> {
        self.validate()?;
        if now_ms < self.admitted_at_ms {
            return Err(RetentionError("retention_clock_rollback"));
        }
        if state.is_terminal() && self.terminal_expires_at_ms.is_none() {
            self.terminal_expires_at_ms = Some(
                now_ms
                    .checked_add(self.content_ttl_seconds * 1000)
                    .ok_or(RetentionError("retention_clock_overflow"))?,
            );
        }
        Ok(())
    }
    pub fn expired(&self, state: JobState, now_ms: u64) -> Result<bool> {
        self.validate()?;
        if now_ms < self.admitted_at_ms {
            return Err(RetentionError("retention_clock_rollback"));
        }
        Ok(state.is_terminal()
            && self
                .terminal_expires_at_ms
                .is_some_and(|expiry| now_ms >= expiry))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobTombstone {
    pub version: u8,
    pub job_id: String,
    pub submitter: String,
    #[serde(default)]
    pub submitter_certificate_sha256: Option<String>,
    /// The original spec is not retained. This digest detects an ID reused with changed content.
    pub spec_sha256: String,
    pub outcome: JobState,
    pub terminal_expires_at_ms: u64,
    pub purged_at_ms: u64,
    /// Signed hashes/identity only; this document contains no prompt, argv, logs or patch body.
    pub result_manifest: Option<crate::provenance::SignedDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_ms: Option<u64>,
}
impl JobTombstone {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !crate::wire::valid_ulid(&self.job_id)
            || !crate::wire::valid_name(&self.submitter)
            || self
                .submitter_certificate_sha256
                .as_deref()
                .is_some_and(|pin| !crate::wire::valid_certificate_pin(pin))
            || !self.outcome.is_terminal()
            || self.spec_sha256.len() != 64
            || !self
                .spec_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.purged_at_ms < self.terminal_expires_at_ms
        {
            return Err(RetentionError("invalid_job_tombstone"));
        }
        Ok(())
    }
    pub fn matches(
        &self,
        spec: &JobSpec,
        submitter: &str,
        certificate_sha256: Option<&str>,
        local_operator: bool,
    ) -> Result<bool> {
        self.validate()?;
        if !local_operator
            && (certificate_sha256.is_none() || self.submitter_certificate_sha256.is_none())
        {
            return Err(RetentionError("legacy_submitter_requires_local_review"));
        }
        Ok(self.job_id == spec.id
            && self.submitter == submitter
            && (self.submitter_certificate_sha256.as_deref() == certificate_sha256
                || (local_operator && self.submitter_certificate_sha256.is_none()))
            && self.spec_sha256 == spec_digest(spec)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeCompletion {
    pub version: u8,
    pub job_id: String,
    pub tombstone_sha256: String,
    pub completed_at_ms: u64,
}
pub fn load_purge_completion(
    directory: &Path,
    tombstone: &JobTombstone,
) -> Result<Option<PurgeCompletion>> {
    require_directory(directory)?;
    let file = match private_options()
        .read(true)
        .open(directory.join(&tombstone.job_id))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let metadata = file.metadata().map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(RetentionError("invalid_purge_completion"));
        }
    }
    if metadata.len() > 4096 {
        return Err(RetentionError("invalid_purge_completion"));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).map_err(io)?;
    let completion: PurgeCompletion =
        serde_json::from_slice(&bytes).map_err(|_| RetentionError("invalid_purge_completion"))?;
    let digest = hex(digest::digest(
        &digest::SHA256,
        &serde_json::to_vec(tombstone).map_err(|_| RetentionError("invalid_job_tombstone"))?,
    )
    .as_ref());
    if completion.version != 1
        || completion.job_id != tombstone.job_id
        || completion.tombstone_sha256 != digest
        || completion.completed_at_ms < tombstone.purged_at_ms
    {
        return Err(RetentionError("invalid_purge_completion"));
    }
    Ok(Some(completion))
}
pub fn store_purge_completion(
    directory: &Path,
    tombstone: &JobTombstone,
    now_ms: u64,
) -> Result<()> {
    if load_purge_completion(directory, tombstone)?.is_some() {
        return lockyard_core::fsio::sync_path(directory).map_err(io);
    }
    let completion = PurgeCompletion {
        version: 1,
        job_id: tombstone.job_id.clone(),
        completed_at_ms: now_ms.max(tombstone.purged_at_ms),
        tombstone_sha256: hex(digest::digest(
            &digest::SHA256,
            &serde_json::to_vec(tombstone).map_err(|_| RetentionError("invalid_job_tombstone"))?,
        )
        .as_ref()),
    };
    let tmp = directory.join(format!(
        ".{}-{}.tmp",
        tombstone.job_id,
        lockyard_cloud_client::ulid()
    ));
    let result = (|| {
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io)?;
        file.write_all(
            &serde_json::to_vec(&completion)
                .map_err(|_| RetentionError("invalid_purge_completion"))?,
        )
        .map_err(io)?;
        file.sync_all().map_err(io)?;
        match fs::hard_link(&tmp, directory.join(&tombstone.job_id)) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                load_purge_completion(directory, tombstone)?
                    .ok_or(RetentionError("invalid_purge_completion"))?;
            }
            Err(error) => return Err(io(error)),
        }
        fs::remove_file(&tmp).map_err(io)?;
        lockyard_core::fsio::sync_path(directory).map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

/// This receipt states only a terminal outcome, never the availability of results.
pub(crate) const TERMINAL_RECEIPT_DOMAIN: &[u8] = b"lockyard-terminal-receipt-v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalReceipt {
    pub version: u8,
    pub node_id: String,
    pub workspace: String,
    pub job_id: String,
    pub submitter: String,
    pub submitter_certificate_sha256: Option<String>,
    pub request_sha256: String,
    pub outcome: JobState,
    pub completed_at_ms: u64,
}

/// Sidecars do not modify the immutable tombstone committed by purge completion.
pub(crate) fn terminal_receipt(
    directory: &Path,
    tombstone: &JobTombstone,
    expected: &TerminalReceipt,
    signer: &crate::provenance::SigningKey,
) -> Result<crate::provenance::SignedDocument> {
    require_directory(directory)?;
    tombstone.validate()?;
    let path = directory.join(format!("{}.receipt", tombstone.job_id));
    let load = || -> Result<Option<crate::provenance::SignedDocument>> {
        let file = match private_options().read(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let metadata = file.metadata().map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err(RetentionError("invalid_terminal_receipt"));
            }
        }
        if metadata.len() > MAX_TOMBSTONE_BYTES {
            return Err(RetentionError("invalid_terminal_receipt"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_TOMBSTONE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        let doc = serde_json::from_slice(&bytes)
            .map_err(|_| RetentionError("invalid_terminal_receipt"))?;
        let actual: TerminalReceipt = crate::provenance::verify_document(
            &doc,
            TERMINAL_RECEIPT_DOMAIN,
            &signer.trusted_key(),
        )
        .map_err(|_| RetentionError("invalid_terminal_receipt"))?;
        if &actual != expected {
            return Err(RetentionError("invalid_terminal_receipt"));
        }
        Ok(Some(doc))
    };
    if let Some(doc) = load()? {
        lockyard_core::fsio::sync_path(directory).map_err(io)?;
        return Ok(doc);
    }
    let doc = signer
        .sign_document(TERMINAL_RECEIPT_DOMAIN, expected)
        .map_err(|_| RetentionError("terminal_receipt_signing_failed"))?;
    let tmp = directory.join(format!(
        ".{}-{}.receipt.tmp",
        tombstone.job_id,
        lockyard_cloud_client::ulid()
    ));
    let result = (|| {
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io)?;
        file.write_all(
            &serde_json::to_vec(&doc).map_err(|_| RetentionError("invalid_terminal_receipt"))?,
        )
        .and_then(|()| file.sync_all())
        .map_err(io)?;
        match fs::hard_link(&tmp, &path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                load()?.ok_or(RetentionError("invalid_terminal_receipt"))?;
            }
            Err(e) => return Err(io(e)),
        }
        fs::remove_file(&tmp).map_err(io)?;
        lockyard_core::fsio::sync_path(directory).map_err(io)?;
        load()?.ok_or(RetentionError("invalid_terminal_receipt"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

pub fn spec_digest(spec: &JobSpec) -> Result<String> {
    let encoded =
        serde_json::to_vec(spec).map_err(|_| RetentionError("retention_spec_encoding"))?;
    Ok(hex(digest::digest(&digest::SHA256, &encoded).as_ref()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Persist before erasing any job content. Existing tombstones are immutable.
pub fn store_tombstone(directory: &Path, tombstone: &JobTombstone) -> Result<()> {
    require_directory(directory)?;
    tombstone.validate()?;
    let path = directory.join(&tombstone.job_id);
    if let Some(existing) = load_tombstone(directory, &tombstone.job_id)? {
        return if existing == *tombstone {
            lockyard_core::fsio::sync_path(directory).map_err(io)
        } else {
            Err(RetentionError("job_tombstone_conflict"))
        };
    }
    let bytes =
        serde_json::to_vec(tombstone).map_err(|_| RetentionError("invalid_job_tombstone"))?;
    if bytes.len() as u64 > MAX_TOMBSTONE_BYTES {
        return Err(RetentionError("job_tombstone_too_large"));
    }
    let temporary = directory.join(format!(
        ".{}-{}.tmp",
        tombstone.job_id,
        lockyard_cloud_client::ulid()
    ));
    let result = (|| {
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(io)?;
        // A create-only link prevents a second writer from replacing an immutable outcome.
        match fs::hard_link(&temporary, &path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = load_tombstone(directory, &tombstone.job_id)?
                    .ok_or(RetentionError("job_tombstone_unavailable"))?;
                if existing != *tombstone {
                    return Err(RetentionError("job_tombstone_conflict"));
                }
            }
            Err(error) => return Err(io(error)),
        }
        fs::remove_file(&temporary).map_err(io)?;
        lockyard_core::fsio::sync_path(directory).map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub fn load_tombstone(directory: &Path, job_id: &str) -> Result<Option<JobTombstone>> {
    require_directory(directory)?;
    if !crate::wire::valid_ulid(job_id) {
        return Err(RetentionError("invalid_job_id"));
    }
    let file = match private_options().read(true).open(directory.join(job_id)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let metadata = file.metadata().map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(RetentionError("job_tombstone_not_private"));
        }
    }
    if metadata.len() > MAX_TOMBSTONE_BYTES {
        return Err(RetentionError("job_tombstone_too_large"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOMBSTONE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let tombstone: JobTombstone =
        serde_json::from_slice(&bytes).map_err(|_| RetentionError("invalid_job_tombstone"))?;
    tombstone.validate()?;
    if tombstone.job_id != job_id {
        return Err(RetentionError("job_tombstone_identity_conflict"));
    }
    Ok(Some(tombstone))
}
pub(crate) fn require_directory(path: &Path) -> Result<()> {
    #[cfg(windows)]
    lockyard_core::windows::require_private(path).map_err(io)?;
    if !path.is_absolute() {
        return Err(RetentionError("retention_path_must_be_absolute"));
    }
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RetentionError("retention_directory_not_private"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(RetentionError("retention_directory_not_private"));
        }
    }
    Ok(())
}
fn private_options() -> OpenOptions {
    #[cfg(windows)]
    let options = OpenOptions::new();
    #[cfg(unix)]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

#[cfg(windows)]
use lockyard_core::windows::OpenOptions;
#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn fifo_receipt_without_writer_never_blocks_expiry_maintenance() {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signer =
            crate::provenance::SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let tombstone = JobTombstone {
            version: 1,
            job_id: id.into(),
            submitter: "sender".into(),
            submitter_certificate_sha256: Some("a".repeat(64)),
            spec_sha256: "b".repeat(64),
            outcome: JobState::Failed,
            terminal_expires_at_ms: 2000,
            purged_at_ms: 2000,
            result_manifest: None,
            completed_at_ms: Some(1000),
        };
        let receipt = TerminalReceipt {
            version: 1,
            node_id: "worker".into(),
            workspace: "workspace".into(),
            job_id: id.into(),
            submitter: "sender".into(),
            submitter_certificate_sha256: Some("a".repeat(64)),
            request_sha256: "b".repeat(64),
            outcome: JobState::Failed,
            completed_at_ms: 1000,
        };
        let path = root.path().join(format!("{id}.receipt"));
        let fifo = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let directory = root.path().to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ =
                sender.send(terminal_receipt(&directory, &tombstone, &receipt, &signer).is_err());
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("receipt read blocked")
        );
    }
    #[test]
    fn project_policy_is_explicit_and_effective_policy_cannot_extend_retention() {
        assert!(serde_json::from_str::<RetentionPolicy>("{}").is_err());
        for seconds in [0, 59, MAX_CONTENT_TTL_SECONDS + 1] {
            assert!(
                RetentionPolicy {
                    content_ttl_seconds: seconds
                }
                .validate()
                .is_err()
            );
        }
        let executor = RetentionPolicy {
            content_ttl_seconds: 3600,
        };
        assert_eq!(
            executor
                .effective(&RetentionPolicy {
                    content_ttl_seconds: 60
                })
                .unwrap()
                .content_ttl_seconds,
            60
        );
    }
    #[test]
    fn expiry_waits_for_confirmed_terminal_outcome_and_never_moves_on_retry() {
        let mut snapshot = RetentionSnapshot::admit(
            &RetentionPolicy {
                content_ttl_seconds: 60,
            },
            1000,
        )
        .unwrap();
        for state in [
            JobState::Queued,
            JobState::Starting,
            JobState::Running,
            JobState::InterruptedUnknown,
        ] {
            snapshot.note_terminal(state, 2000).unwrap();
            assert!(!snapshot.expired(state, u64::MAX).unwrap());
            assert_eq!(snapshot.terminal_expires_at_ms, None);
        }
        snapshot.note_terminal(JobState::Failed, 3000).unwrap();
        snapshot.note_terminal(JobState::Failed, 9000).unwrap();
        assert_eq!(snapshot.terminal_expires_at_ms, Some(63_000));
        assert!(!snapshot.expired(JobState::Failed, 62_999).unwrap());
        assert!(snapshot.expired(JobState::Failed, 63_000).unwrap());
        assert!(snapshot.expired(JobState::Failed, 999).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn tombstone_survives_content_removal_and_rejects_changed_spec_or_outcome() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let spec = JobSpec {
            id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            repository: "private-repo".into(),
            revision: "HEAD".into(),
            runner: "command".into(),
            arguments: vec!["private-argv".into()],
            prompt: Some("private-prompt".into()),
            timeout_seconds: None,
            priority: 0,
            workflow_inputs: Vec::new(),
            expected_runner_sha256: None,
            owner_approval: None,
        };
        let tombstone = JobTombstone {
            version: 1,
            job_id: spec.id.clone(),
            submitter: "sender".into(),
            submitter_certificate_sha256: None,
            spec_sha256: spec_digest(&spec).unwrap(),
            outcome: JobState::Failed,
            terminal_expires_at_ms: 60_000,
            purged_at_ms: 60_000,
            result_manifest: None,
            completed_at_ms: None,
        };
        store_tombstone(dir.path(), &tombstone).unwrap();
        store_tombstone(dir.path(), &tombstone).unwrap();
        let bytes = fs::read(dir.path().join(&spec.id)).unwrap();
        for private in ["private-prompt", "private-argv", "private-repo"] {
            assert!(!String::from_utf8_lossy(&bytes).contains(private));
        }
        let stored = load_tombstone(dir.path(), &spec.id).unwrap().unwrap();
        assert!(stored.matches(&spec, "sender", None, true).unwrap());
        let mut changed = spec.clone();
        changed.prompt = Some("changed".into());
        assert!(!stored.matches(&changed, "sender", None, true).unwrap());
        assert!(
            !stored
                .matches(&spec, "different-sender", None, true)
                .unwrap()
        );
        let mut conflicting = tombstone;
        conflicting.outcome = JobState::Succeeded;
        assert!(store_tombstone(dir.path(), &conflicting).is_err());
    }
}
