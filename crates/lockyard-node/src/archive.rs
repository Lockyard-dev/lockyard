// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Explicit, streaming encrypted export. Restore only creates a fresh offline review tree.
//! Keys and live daemon configuration are never part of this format.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use lockyard_cloud_client::WorkspaceKey;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8] = b"LOCKYARD-ARCHIVE-1\n";
const ARCHIVE_DOMAIN: &[u8] = b"lockyard-node-archive-manifest-v1\0";
const CHUNK_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_ARCHIVE_FILES: usize = 4096;
pub const MAX_ARCHIVE_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ARCHIVE_CONTENT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveError(pub &'static str);
impl std::fmt::Display for ArchiveError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.0)
    }
}
impl std::error::Error for ArchiveError {}
pub type Result<T> = std::result::Result<T, ArchiveError>;
fn io(_: std::io::Error) -> ArchiveError {
    ArchiveError("archive_io")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveEntry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveScope {
    FullProject,
    ResultsOnly,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub scope: ArchiveScope,
    pub version: u8,
    pub workspace: String,
    pub node_id: String,
    pub job_id: String,
    pub created_at_ms: u64,
    pub entries: Vec<ArchiveEntry>,
}
impl ArchiveManifest {
    fn validate(&self, workspace: &str) -> Result<()> {
        if self.version != 1
            || self.workspace != workspace
            || !crate::wire::valid_name(workspace)
            || !crate::wire::valid_name(&self.node_id)
            || !crate::wire::valid_ulid(&self.job_id)
            || self.entries.len() > MAX_ARCHIVE_FILES
        {
            return Err(ArchiveError("invalid_archive_manifest"));
        }
        let mut total = 0u64;
        let mut previous = None;
        for entry in &self.entries {
            validate_relative_path(&entry.path)?;
            if self.scope == ArchiveScope::ResultsOnly
                && !matches!(
                    entry.path.as_str(),
                    "export-metadata.json" | "output.log" | "result.patch"
                )
            {
                return Err(ArchiveError("invalid_results_only_archive_entry"));
            }
            if previous.is_some_and(|previous: &str| previous >= entry.path.as_str())
                || entry.bytes > MAX_ARCHIVE_FILE_BYTES
                || !valid_hash(&entry.sha256)
            {
                return Err(ArchiveError("invalid_archive_entry"));
            }
            previous = Some(entry.path.as_str());
            total = total
                .checked_add(entry.bytes)
                .ok_or(ArchiveError("archive_budget_exceeded"))?;
            if total > MAX_ARCHIVE_CONTENT_BYTES {
                return Err(ArchiveError("archive_budget_exceeded"));
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAttestation {
    version: u8,
    workspace: String,
    node_id: String,
    job_id: String,
    manifest_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveHeader {
    manifest: ArchiveManifest,
    attestation: crate::provenance::SignedDocument,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveFooter {
    version: u8,
    manifest_sha256: String,
    files: usize,
    total_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReport {
    pub scope: ArchiveScope,
    pub manifest_sha256: String,
    pub files: usize,
    pub total_bytes: u64,
    /// True only when the embedded job result signature and artifact hashes
    /// were checked, in addition to the archive's own integrity.
    pub result_provenance_verified: bool,
}

/// Invalidate the executor's derived export cache on startup, while its exclusive
/// state lock is held. Older versions published directly to the final filename,
/// so even an apparently complete cache file may be a crash-truncated stream.
/// A restarted download must begin at offset zero and regenerate the archive.
pub(crate) fn clear_executor_cache(directory: &Path) -> Result<()> {
    require_directory(directory)?;
    for entry in fs::read_dir(directory).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let final_cache = name
            .strip_suffix(".lyarchive")
            .is_some_and(crate::wire::valid_ulid);
        let temporary = name
            .strip_prefix(".archive-")
            .and_then(|name| name.strip_suffix(".tmp"))
            .and_then(|name| name.split_once('-'))
            .is_some_and(|(job, archive)| {
                crate::wire::valid_ulid(job) && crate::wire::valid_ulid(archive)
            });
        if !final_cache && !temporary {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(io)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ArchiveError("unsafe_archive_cache_entry"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(ArchiveError("unsafe_archive_cache_entry"));
            }
        }
        fs::remove_file(entry.path()).map_err(io)?;
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(io)
}

/// Export only explicitly selected relative regular files. The caller chooses a confirmed
/// terminal job and excludes local credentials; no daemon thread calls this automatically.
#[allow(clippy::too_many_arguments)]
pub fn export_files(
    source: &Path,
    relative_paths: &[String],
    destination: &Path,
    workspace: &str,
    node_id: &str,
    job_id: &str,
    scope: ArchiveScope,
    now_ms: u64,
    key: &WorkspaceKey,
    signer: &crate::provenance::SigningKey,
) -> Result<ArchiveReport> {
    export_files_inner(
        source,
        relative_paths,
        destination,
        workspace,
        node_id,
        job_id,
        scope,
        now_ms,
        key,
        signer,
        None,
    )
}

/// A job archive must agree with the previously signed result, not merely
/// acquire a fresh signature over whatever bytes happen to remain on disk.
#[allow(clippy::too_many_arguments)]
pub(crate) fn export_job_files(
    source: &Path,
    relative_paths: &[String],
    destination: &Path,
    workspace: &str,
    node_id: &str,
    job_id: &str,
    scope: ArchiveScope,
    now_ms: u64,
    key: &WorkspaceKey,
    signer: &crate::provenance::SigningKey,
    expected_artifacts: &std::collections::BTreeMap<String, crate::provenance::ArtifactDigest>,
) -> Result<ArchiveReport> {
    export_files_inner(
        source,
        relative_paths,
        destination,
        workspace,
        node_id,
        job_id,
        scope,
        now_ms,
        key,
        signer,
        Some(expected_artifacts),
    )
}

#[allow(clippy::too_many_arguments)]
fn export_files_inner(
    source: &Path,
    relative_paths: &[String],
    destination: &Path,
    workspace: &str,
    node_id: &str,
    job_id: &str,
    scope: ArchiveScope,
    now_ms: u64,
    key: &WorkspaceKey,
    signer: &crate::provenance::SigningKey,
    expected_artifacts: Option<
        &std::collections::BTreeMap<String, crate::provenance::ArtifactDigest>,
    >,
) -> Result<ArchiveReport> {
    require_directory(source)?;
    let parent = destination
        .parent()
        .ok_or(ArchiveError("invalid_archive_destination"))?;
    require_directory(parent)?;
    if destination.starts_with(source) || !destination.is_absolute() {
        return Err(ArchiveError("archive_destination_must_be_outside_source"));
    }
    if relative_paths.len() > MAX_ARCHIVE_FILES {
        return Err(ArchiveError("archive_budget_exceeded"));
    }
    let mut paths = relative_paths.to_vec();
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ArchiveError("duplicate_archive_path"));
    }
    let mut entries = Vec::new();
    let mut total = 0u64;
    for relative in paths {
        validate_relative_path(&relative)?;
        let file = open_source(source, &relative)?;
        let bytes = file.metadata().map_err(io)?.len();
        if bytes > MAX_ARCHIVE_FILE_BYTES {
            return Err(ArchiveError("archive_budget_exceeded"));
        }
        total = total
            .checked_add(bytes)
            .ok_or(ArchiveError("archive_budget_exceeded"))?;
        if total > MAX_ARCHIVE_CONTENT_BYTES {
            return Err(ArchiveError("archive_budget_exceeded"));
        }
        entries.push(ArchiveEntry {
            path: relative,
            bytes,
            sha256: hash_reader(file, bytes)?,
        });
    }
    let manifest = ArchiveManifest {
        scope,
        version: 1,
        workspace: workspace.into(),
        node_id: node_id.into(),
        job_id: job_id.into(),
        created_at_ms: now_ms,
        entries,
    };
    manifest.validate(workspace)?;
    if let Some(expected_artifacts) = expected_artifacts {
        for entry in &manifest.entries {
            if matches!(entry.path.as_str(), "output.log" | "result.patch") {
                let expected = expected_artifacts
                    .get(&entry.path)
                    .ok_or(ArchiveError("archive_result_artifact_mismatch"))?;
                if expected.truncated
                    || expected.error_code.is_some()
                    || entry.bytes != expected.size_bytes
                    || entry.sha256 != expected.sha256
                {
                    return Err(ArchiveError("archive_result_artifact_mismatch"));
                }
            }
        }
    }
    let encoded =
        serde_json::to_vec(&manifest).map_err(|_| ArchiveError("invalid_archive_manifest"))?;
    if encoded.len() > MAX_MANIFEST_BYTES {
        return Err(ArchiveError("archive_manifest_too_large"));
    }
    let manifest_sha256 = sha256(&encoded);
    let attestation = signer
        .sign_document(
            ARCHIVE_DOMAIN,
            &ArchiveAttestation {
                version: 1,
                workspace: workspace.into(),
                node_id: node_id.into(),
                job_id: job_id.into(),
                manifest_sha256: manifest_sha256.clone(),
            },
        )
        .map_err(|_| ArchiveError("archive_signing_failed"))?;
    let header = serde_json::to_string(&ArchiveHeader {
        manifest: manifest.clone(),
        attestation,
    })
    .map_err(|_| ArchiveError("invalid_archive_manifest"))?;
    let archive_id =
        crate::wire::new_id().map_err(|_| ArchiveError("archive_entropy_unavailable"))?;
    // A daemon crash must never leave an incomplete archive at the cache path.
    // Publish only after the complete encrypted stream and footer are durable.
    // The scoped name lets executor startup remove interrupted export attempts.
    let temporary = parent.join(format!(".archive-{job_id}-{archive_id}.tmp"));
    let mut output = private_options()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io)?;
    let result = (|| {
        output
            .write_all(MAGIC)
            .and_then(|()| output.write_all(archive_id.as_bytes()))
            .map_err(io)?;
        let mut index = 0u64;
        write_record(
            &mut output,
            key,
            workspace,
            &archive_id,
            &mut index,
            &header,
        )?;
        for entry in &manifest.entries {
            let mut input = open_source(source, &entry.path)?;
            let mut digest = digest::Context::new(&digest::SHA256);
            let mut remaining = entry.bytes;
            let mut buffer = vec![0u8; CHUNK_BYTES];
            while remaining > 0 {
                let count = remaining.min(CHUNK_BYTES as u64) as usize;
                input
                    .read_exact(&mut buffer[..count])
                    .map_err(|_| ArchiveError("archive_source_changed"))?;
                digest.update(&buffer[..count]);
                write_record(
                    &mut output,
                    key,
                    workspace,
                    &archive_id,
                    &mut index,
                    &STANDARD.encode(&buffer[..count]),
                )?;
                remaining -= count as u64;
            }
            if input.read(&mut [0]).map_err(io)? != 0
                || hex(digest.finish().as_ref()) != entry.sha256
            {
                return Err(ArchiveError("archive_source_changed"));
            }
        }
        let footer = ArchiveFooter {
            version: 1,
            manifest_sha256: manifest_sha256.clone(),
            files: manifest.entries.len(),
            total_bytes: total,
        };
        write_record(
            &mut output,
            key,
            workspace,
            &archive_id,
            &mut index,
            &serde_json::to_string(&footer).map_err(|_| ArchiveError("invalid_archive_footer"))?,
        )?;
        output.sync_all().map_err(io)?;
        // The destination is create-only, so concurrent exports and existing
        // user files cannot be replaced. The link refers to the synced inode.
        fs::hard_link(&temporary, destination).map_err(io)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io)?;
        fs::remove_file(&temporary).map_err(io)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io)?;
        Ok(ArchiveReport {
            scope,
            manifest_sha256,
            files: manifest.entries.len(),
            total_bytes: total,
            result_provenance_verified: expected_artifacts.is_some(),
        })
    })();
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(&temporary);
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
    }
    result
}

/// Restored content lives under `destination/files`, with no executable permissions.
/// This never writes to an executor state directory or registers/imports a runnable job.
pub fn restore_offline(
    archive: &Path,
    destination: &Path,
    workspace: &str,
    key: &WorkspaceKey,
    expected_node: &str,
    trusted_signer: &crate::provenance::TrustedSigningKey,
) -> Result<ArchiveReport> {
    restore_offline_inner(
        archive,
        destination,
        workspace,
        key,
        expected_node,
        trusted_signer,
        false,
    )
}

/// Restore a job export only if its embedded result provenance is independently
/// signed by the pinned node and agrees with every included result artifact.
pub fn restore_job_offline(
    archive: &Path,
    destination: &Path,
    workspace: &str,
    key: &WorkspaceKey,
    expected_node: &str,
    trusted_signer: &crate::provenance::TrustedSigningKey,
) -> Result<ArchiveReport> {
    restore_offline_inner(
        archive,
        destination,
        workspace,
        key,
        expected_node,
        trusted_signer,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn restore_offline_inner(
    archive: &Path,
    destination: &Path,
    workspace: &str,
    key: &WorkspaceKey,
    expected_node: &str,
    trusted_signer: &crate::provenance::TrustedSigningKey,
    require_job_metadata: bool,
) -> Result<ArchiveReport> {
    // The path-based fallback cannot prevent an ancestor from being swapped
    // during extraction. Only the descriptor-anchored implementation is safe.
    if !cfg!(target_os = "linux") {
        return Err(ArchiveError("archive_restore_platform_unsupported"));
    }
    if !destination.is_absolute() || !crate::wire::valid_name(workspace) {
        return Err(ArchiveError("invalid_archive_destination"));
    }
    let parent = destination
        .parent()
        .ok_or(ArchiveError("invalid_archive_destination"))?;
    require_directory(parent)?;
    // Pin the validated parent for the entire restore. On Linux, all path-based
    // operations below are resolved through this fd even if an ancestor is renamed.
    let parent_file = open_restore_parent(parent)?;
    #[cfg(target_os = "linux")]
    let anchored_destination = {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", parent_file.as_raw_fd())).join(
            destination
                .file_name()
                .ok_or(ArchiveError("invalid_archive_destination"))?,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let anchored_destination = destination.to_path_buf();
    let destination = anchored_destination.as_path();
    let mut input = private_options().read(true).open(archive).map_err(io)?;
    if !input.metadata().map_err(io)?.is_file() {
        return Err(ArchiveError("invalid_archive_file"));
    }
    let mut header = vec![0; MAGIC.len() + 26];
    input
        .read_exact(&mut header)
        .map_err(|_| ArchiveError("invalid_archive_header"))?;
    if &header[..MAGIC.len()] != MAGIC {
        return Err(ArchiveError("invalid_archive_header"));
    }
    let archive_id = std::str::from_utf8(&header[MAGIC.len()..])
        .map_err(|_| ArchiveError("invalid_archive_header"))?;
    if !crate::wire::valid_ulid(archive_id) {
        return Err(ArchiveError("invalid_archive_header"));
    }
    let mut index = 0u64;
    let encoded = read_record(&mut input, key, workspace, archive_id, &mut index)?;
    if encoded.len() > MAX_MANIFEST_BYTES + 4096 {
        return Err(ArchiveError("archive_manifest_too_large"));
    }
    let header: ArchiveHeader =
        serde_json::from_str(&encoded).map_err(|_| ArchiveError("invalid_archive_manifest"))?;
    if serde_json::to_string(&header).map_err(|_| ArchiveError("invalid_archive_manifest"))?
        != encoded
    {
        return Err(ArchiveError("noncanonical_archive_manifest"));
    }
    let manifest = &header.manifest;
    manifest.validate(workspace)?;
    let manifest_encoded =
        serde_json::to_vec(manifest).map_err(|_| ArchiveError("invalid_archive_manifest"))?;
    let manifest_sha256 = sha256(&manifest_encoded);
    let verified: ArchiveAttestation =
        crate::provenance::verify_document(&header.attestation, ARCHIVE_DOMAIN, trusted_signer)
            .map_err(|_| ArchiveError("untrusted_archive_signer"))?;
    if manifest.node_id != expected_node
        || verified
            != (ArchiveAttestation {
                version: 1,
                workspace: workspace.into(),
                node_id: expected_node.into(),
                job_id: manifest.job_id.clone(),
                manifest_sha256: manifest_sha256.clone(),
            })
    {
        return Err(ArchiveError("archive_signature_context_mismatch"));
    }
    if require_job_metadata
        && !manifest
            .entries
            .iter()
            .any(|entry| entry.path == "export-metadata.json")
    {
        return Err(ArchiveError("archive_job_metadata_required"));
    }
    create_private_directory(destination)?;
    let result = (|| {
        let files_root = destination.join("files");
        create_private_directory(&files_root)?;
        let mut total = 0u64;
        let mut result_provenance_verified = false;
        for entry in &manifest.entries {
            let metadata_within_budget =
                entry.path == "export-metadata.json" && entry.bytes <= 128 * 1024;
            if require_job_metadata
                && entry.path == "export-metadata.json"
                && !metadata_within_budget
            {
                return Err(ArchiveError("archive_job_metadata_too_large"));
            }
            let relative = Path::new(&entry.path);
            let mut directory = files_root.clone();
            let components: Vec<_> = relative.components().collect();
            for component in &components[..components.len() - 1] {
                directory.push(component.as_os_str());
                if !directory.exists() {
                    create_private_directory(&directory)?;
                }
                require_directory(&directory)?;
            }
            let mut file = private_options()
                .write(true)
                .create_new(true)
                .open(files_root.join(relative))
                .map_err(io)?;
            let mut digest = digest::Context::new(&digest::SHA256);
            let mut remaining = entry.bytes;
            let mut metadata_bytes = Vec::new();
            while remaining > 0 {
                let text = read_record(&mut input, key, workspace, archive_id, &mut index)?;
                if text.len() > CHUNK_BYTES.div_ceil(3) * 4 {
                    return Err(ArchiveError("invalid_archive_chunk"));
                }
                let bytes = STANDARD
                    .decode(&text)
                    .map_err(|_| ArchiveError("invalid_archive_chunk"))?;
                let expected = remaining.min(CHUNK_BYTES as u64) as usize;
                if bytes.len() != expected || STANDARD.encode(&bytes) != text {
                    return Err(ArchiveError("invalid_archive_chunk"));
                }
                file.write_all(&bytes).map_err(io)?;
                digest.update(&bytes);
                if metadata_within_budget {
                    metadata_bytes.extend_from_slice(&bytes);
                }
                remaining -= bytes.len() as u64;
            }
            if hex(digest.finish().as_ref()) != entry.sha256 {
                return Err(ArchiveError("archive_file_hash_mismatch"));
            }
            if metadata_within_budget {
                result_provenance_verified = verify_job_metadata(
                    &metadata_bytes,
                    manifest,
                    expected_node,
                    trusted_signer,
                    require_job_metadata,
                )?;
            }
            file.sync_all().map_err(io)?;
            File::open(&directory)
                .and_then(|directory| directory.sync_all())
                .map_err(io)?;
            total += entry.bytes;
        }
        let encoded_footer = read_record(&mut input, key, workspace, archive_id, &mut index)?;
        let footer: ArchiveFooter = serde_json::from_str(&encoded_footer)
            .map_err(|_| ArchiveError("invalid_archive_footer"))?;
        let report = ArchiveReport {
            scope: manifest.scope,
            manifest_sha256,
            files: manifest.entries.len(),
            total_bytes: total,
            result_provenance_verified,
        };
        if require_job_metadata && !report.result_provenance_verified {
            return Err(ArchiveError("archive_job_metadata_required"));
        }
        if footer
            != (ArchiveFooter {
                version: 1,
                manifest_sha256: report.manifest_sha256.clone(),
                files: report.files,
                total_bytes: report.total_bytes,
            })
            || input.read(&mut [0]).map_err(io)? != 0
        {
            return Err(ArchiveError("invalid_archive_footer"));
        }
        let mut manifest_file = private_options()
            .write(true)
            .create_new(true)
            .open(destination.join("manifest.json"))
            .map_err(io)?;
        manifest_file
            .write_all(encoded.as_bytes())
            .and_then(|()| manifest_file.sync_all())
            .map_err(io)?;
        let mut notice = private_options()
            .write(true)
            .create_new(true)
            .open(destination.join("RESTORE.txt"))
            .map_err(io)?;
        notice.write_all(b"Offline review copy only. No job was imported, scheduled, executed or applied.\nAll archived paths and hashes were verified with the independently pinned node signing key. This authenticates an offline copy; it does not authorize execution or publication.\n").and_then(|()| notice.sync_all()).map_err(io)?;
        File::open(destination)
            .and_then(|directory| directory.sync_all())
            .map_err(io)?;
        parent_file.sync_all().map_err(io)?;
        verify_restore_parent_identity(parent, &parent_file)?;
        Ok(report)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
        let _ = parent_file.sync_all();
    }
    result
}

/// Authenticate the encrypted archive scope/manifest using independently pinned node trust.
/// Body integrity is checked during restore; this bounded header inspection never executes content.
pub fn inspect(
    archive: &Path,
    workspace: &str,
    key: &WorkspaceKey,
    expected_node: &str,
    trusted_signer: &crate::provenance::TrustedSigningKey,
) -> Result<ArchiveManifest> {
    let mut input = private_options().read(true).open(archive).map_err(io)?;
    inspect_file(&mut input, workspace, key, expected_node, trusted_signer)
}
/// Inspect the same opened file that received a download; never reopen by path.
pub fn inspect_file(
    input: &mut File,
    workspace: &str,
    key: &WorkspaceKey,
    expected_node: &str,
    trusted_signer: &crate::provenance::TrustedSigningKey,
) -> Result<ArchiveManifest> {
    input.seek(SeekFrom::Start(0)).map_err(io)?;
    if !input.metadata().map_err(io)?.is_file() {
        return Err(ArchiveError("invalid_archive_file"));
    }
    let mut prefix = vec![0; MAGIC.len() + 26];
    input
        .read_exact(&mut prefix)
        .map_err(|_| ArchiveError("invalid_archive_header"))?;
    if &prefix[..MAGIC.len()] != MAGIC {
        return Err(ArchiveError("invalid_archive_header"));
    }
    let archive_id = std::str::from_utf8(&prefix[MAGIC.len()..])
        .map_err(|_| ArchiveError("invalid_archive_header"))?;
    if !crate::wire::valid_ulid(archive_id) {
        return Err(ArchiveError("invalid_archive_header"));
    }
    let encoded = read_record(input, key, workspace, archive_id, &mut 0)?;
    if encoded.len() > MAX_MANIFEST_BYTES + 4096 {
        return Err(ArchiveError("archive_manifest_too_large"));
    }
    let header: ArchiveHeader =
        serde_json::from_str(&encoded).map_err(|_| ArchiveError("invalid_archive_manifest"))?;
    if serde_json::to_string(&header).map_err(|_| ArchiveError("invalid_archive_manifest"))?
        != encoded
    {
        return Err(ArchiveError("noncanonical_archive_manifest"));
    }
    header.manifest.validate(workspace)?;
    let manifest_sha256 = sha256(
        &serde_json::to_vec(&header.manifest)
            .map_err(|_| ArchiveError("invalid_archive_manifest"))?,
    );
    let verified: ArchiveAttestation =
        crate::provenance::verify_document(&header.attestation, ARCHIVE_DOMAIN, trusted_signer)
            .map_err(|_| ArchiveError("untrusted_archive_signer"))?;
    if header.manifest.node_id != expected_node
        || verified
            != (ArchiveAttestation {
                version: 1,
                workspace: workspace.into(),
                node_id: expected_node.into(),
                job_id: header.manifest.job_id.clone(),
                manifest_sha256,
            })
    {
        return Err(ArchiveError("archive_signature_context_mismatch"));
    }
    Ok(header.manifest)
}

/// Enumerate a completed job's portable content, excluding all injected runtime credentials.
pub fn job_export_paths(job_directory: &Path) -> Result<Vec<String>> {
    require_directory(job_directory)?;
    let mut paths = Vec::new();
    let mut visited = 0usize;
    for top in [
        "record.json",
        "export-metadata.json",
        "output.log",
        "result.patch",
        "worktree",
        "repository.git",
    ] {
        let path = job_directory.join(top);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.is_file() {
                    paths.push(top.into());
                } else if metadata.is_dir() {
                    scan_tree(job_directory, Path::new(top), 0, &mut paths, &mut visited)?;
                } else {
                    return Err(ArchiveError("archive_links_are_not_supported"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(io(error)),
        }
    }
    paths.sort();
    Ok(paths)
}
fn scan_tree(
    root: &Path,
    relative: &Path,
    depth: usize,
    paths: &mut Vec<String>,
    visited: &mut usize,
) -> Result<()> {
    if depth > 32 || paths.len() > MAX_ARCHIVE_FILES {
        return Err(ArchiveError("archive_budget_exceeded"));
    }
    for entry in fs::read_dir(root.join(relative)).map_err(io)? {
        let entry = entry.map_err(io)?;
        *visited += 1;
        if *visited > MAX_ARCHIVE_FILES * 4 {
            return Err(ArchiveError("archive_budget_exceeded"));
        }
        let path = relative.join(entry.file_name());
        let text = path.to_str().ok_or(ArchiveError("invalid_archive_path"))?;
        validate_relative_path(text)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(io)?;
        if metadata.is_dir() {
            scan_tree(root, &path, depth + 1, paths, visited)?;
        } else if metadata.is_file() {
            paths.push(text.into());
        } else {
            return Err(ArchiveError("archive_links_are_not_supported"));
        }
        if paths.len() > MAX_ARCHIVE_FILES {
            return Err(ArchiveError("archive_budget_exceeded"));
        }
    }
    Ok(())
}
fn write_record(
    output: &mut File,
    key: &WorkspaceKey,
    workspace: &str,
    id: &str,
    index: &mut u64,
    plaintext: &str,
) -> Result<()> {
    let record_key = archive_record_key(key, workspace, id, *index)?;
    let encrypted = record_key
        .encrypt(workspace, &record_field(id, *index), plaintext)
        .map_err(|_| ArchiveError("archive_encryption_failed"))?;
    if encrypted.len() > MAX_RECORD_BYTES {
        return Err(ArchiveError("archive_record_too_large"));
    }
    output
        .write_all(&(encrypted.len() as u32).to_be_bytes())
        .and_then(|()| output.write_all(encrypted.as_bytes()))
        .map_err(io)?;
    *index = index
        .checked_add(1)
        .ok_or(ArchiveError("archive_budget_exceeded"))?;
    Ok(())
}
fn read_record(
    input: &mut File,
    key: &WorkspaceKey,
    workspace: &str,
    id: &str,
    index: &mut u64,
) -> Result<String> {
    let mut size = [0u8; 4];
    input
        .read_exact(&mut size)
        .map_err(|_| ArchiveError("truncated_archive"))?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_RECORD_BYTES {
        return Err(ArchiveError("archive_record_too_large"));
    }
    let mut encrypted = vec![0u8; size];
    input
        .read_exact(&mut encrypted)
        .map_err(|_| ArchiveError("truncated_archive"))?;
    let encrypted =
        std::str::from_utf8(&encrypted).map_err(|_| ArchiveError("invalid_archive_encoding"))?;
    let parts: Vec<_> = encrypted.split('.').collect();
    if parts.len() != 3
        || parts[0] != "lyenc1"
        || !URL_SAFE_NO_PAD
            .decode(parts[1])
            .is_ok_and(|bytes| bytes.len() == 8 && URL_SAFE_NO_PAD.encode(bytes) == parts[1])
        || !URL_SAFE_NO_PAD
            .decode(parts[2])
            .is_ok_and(|bytes| bytes.len() >= 28 && URL_SAFE_NO_PAD.encode(bytes) == parts[2])
    {
        return Err(ArchiveError("invalid_archive_encoding"));
    }
    let record_key = archive_record_key(key, workspace, id, *index)?;
    let plaintext = record_key
        .decrypt(workspace, &record_field(id, *index), encrypted)
        .map_err(|_| ArchiveError("archive_authentication_failed"))?;
    *index = index
        .checked_add(1)
        .ok_or(ArchiveError("archive_budget_exceeded"))?;
    Ok(plaintext)
}
fn archive_record_key(
    key: &WorkspaceKey,
    workspace: &str,
    id: &str,
    index: u64,
) -> Result<WorkspaceKey> {
    let context = serde_json::to_vec(&(workspace, id, index))
        .map_err(|_| ArchiveError("invalid_archive_context"))?;
    key.derive_context(b"lockyard-node-archive-record-v1", &context)
        .map_err(|_| ArchiveError("archive_key_derivation_failed"))
}
fn record_field(id: &str, index: u64) -> String {
    format!("node-archive-v1|{id}|{index}")
}
fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(ArchiveError("invalid_archive_path"));
    }
    Ok(())
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn hash_reader(mut file: File, expected: u64) -> Result<String> {
    let mut digest = digest::Context::new(&digest::SHA256);
    let mut remaining = expected;
    let mut buffer = [0u8; CHUNK_BYTES];
    while remaining > 0 {
        let take = remaining.min(CHUNK_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..take])
            .map_err(|_| ArchiveError("archive_source_changed"))?;
        digest.update(&buffer[..take]);
        remaining -= take as u64;
    }
    if file.read(&mut [0]).map_err(io)? != 0 {
        return Err(ArchiveError("archive_source_changed"));
    }
    Ok(hex(digest.finish().as_ref()))
}
fn sha256(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn require_directory(path: &Path) -> Result<()> {
    crate::retention::require_directory(path)
        .map_err(|_| ArchiveError("archive_directory_not_private"))
}
fn open_restore_parent(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path).map_err(io)?;
        let metadata = file.metadata().map_err(io)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(ArchiveError("archive_directory_not_private"));
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    options.open(path).map_err(io)
}
fn verify_restore_parent_identity(path: &Path, pinned: &File) -> Result<()> {
    let current = open_restore_parent(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let before = pinned.metadata().map_err(io)?;
        let after = current.metadata().map_err(io)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(ArchiveError("archive_restore_parent_changed"));
        }
    }
    #[cfg(not(unix))]
    let _ = (current, pinned);
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobExportMetadata {
    version: u8,
    job_id: String,
    scope: ArchiveScope,
    state: crate::wire::JobState,
    #[serde(rename = "retention")]
    _retention: serde_json::Value,
    result_manifest: crate::provenance::SignedDocument,
}

fn verify_job_metadata(
    bytes: &[u8],
    manifest: &ArchiveManifest,
    expected_node: &str,
    trusted_signer: &crate::provenance::TrustedSigningKey,
    required: bool,
) -> Result<bool> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_)
            if !required
                && !bytes
                    .windows(b"\"result_manifest\"".len())
                    .any(|part| part == b"\"result_manifest\"") =>
        {
            return Ok(false);
        }
        Err(_) => return Err(ArchiveError("invalid_archive_job_metadata")),
    };
    if value.get("result_manifest").is_none() && !required {
        return Ok(false);
    }
    let metadata: JobExportMetadata =
        serde_json::from_slice(bytes).map_err(|_| ArchiveError("invalid_archive_job_metadata"))?;
    if metadata.version != 1
        || metadata.job_id != manifest.job_id
        || metadata.scope != manifest.scope
    {
        return Err(ArchiveError("archive_result_context_mismatch"));
    }
    let result = crate::provenance::verify_result_identity(
        &metadata.result_manifest,
        trusted_signer,
        expected_node,
        &manifest.workspace,
        &manifest.job_id,
    )
    .map_err(|_| ArchiveError("archive_result_provenance_invalid"))?;
    if result.state != metadata.state {
        return Err(ArchiveError("archive_result_context_mismatch"));
    }
    for entry in &manifest.entries {
        if matches!(entry.path.as_str(), "output.log" | "result.patch") {
            let artifact = result
                .artifacts
                .get(&entry.path)
                .ok_or(ArchiveError("archive_result_artifact_mismatch"))?;
            if artifact.truncated
                || artifact.error_code.is_some()
                || artifact.size_bytes != entry.bytes
                || artifact.sha256 != entry.sha256
            {
                return Err(ArchiveError("archive_result_artifact_mismatch"));
            }
        }
    }
    Ok(true)
}
fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path).map_err(io)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path).map_err(io)?;
    }
    File::open(path.parent().ok_or(ArchiveError("invalid_archive_path"))?)
        .and_then(|parent| parent.sync_all())
        .map_err(io)
}
fn open_source(root: &Path, relative: &str) -> Result<File> {
    let mut current = PathBuf::from(root);
    let components: Vec<_> = Path::new(relative).components().collect();
    for component in &components[..components.len() - 1] {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(io)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ArchiveError("archive_links_are_not_supported"));
        }
    }
    let file = private_options()
        .read(true)
        .open(root.join(relative))
        .map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() {
        return Err(ArchiveError("archive_links_are_not_supported"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(ArchiveError("archive_source_not_owned_regular_file"));
        }
    }
    Ok(file)
}
fn private_options() -> OpenOptions {
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

#[cfg(test)]
mod tests {
    use super::*;
    const JOB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    #[cfg(unix)]
    fn private(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn encrypted_roundtrip_restores_only_offline_regular_nonexecutable_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let signer =
            crate::provenance::SigningKey::generate(&dir.path().join("signing.pk8")).unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        private(&source);
        fs::create_dir(source.join("worktree")).unwrap();
        fs::write(source.join("worktree/code.rs"), b"private-code-sentinel").unwrap();
        fs::write(source.join("output.log"), vec![b'x'; CHUNK_BYTES + 19]).unwrap();
        fs::write(source.join("empty"), b"").unwrap();
        let key = WorkspaceKey::from_entropy([41; 32]);
        let archive = dir.path().join("result.lyarchive");
        let report = export_files(
            &source,
            &[
                "worktree/code.rs".into(),
                "output.log".into(),
                "empty".into(),
            ],
            &archive,
            "workspace",
            "worker",
            JOB,
            ArchiveScope::FullProject,
            1000,
            &key,
            &signer,
        )
        .unwrap();
        let wrong_signer =
            crate::provenance::SigningKey::generate(&dir.path().join("wrong.pk8")).unwrap();
        assert!(
            restore_offline(
                &archive,
                &dir.path().join("wrong-signer"),
                "workspace",
                &key,
                "worker",
                &wrong_signer.trusted_key()
            )
            .is_err()
        );
        assert!(
            restore_offline(
                &archive,
                &dir.path().join("wrong-node"),
                "workspace",
                &key,
                "replacement",
                &signer.trusted_key()
            )
            .is_err()
        );
        assert!(!dir.path().join("wrong-signer").exists());
        let encrypted = fs::read(&archive).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("private-code-sentinel"));
        assert!(!String::from_utf8_lossy(&encrypted).contains("worktree/code.rs"));
        let target = dir.path().join("offline");
        assert_eq!(
            restore_offline(
                &archive,
                &target,
                "workspace",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .unwrap(),
            report
        );
        assert_eq!(
            fs::read(target.join("files/worktree/code.rs")).unwrap(),
            b"private-code-sentinel"
        );
        assert_eq!(
            fs::read(target.join("files/output.log")).unwrap().len(),
            CHUNK_BYTES + 19
        );
        assert_eq!(
            fs::metadata(target.join("files/worktree/code.rs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(target.join("RESTORE.txt").exists());
        assert!(!target.join("executor").exists());
        assert!(
            restore_offline(
                &archive,
                &target,
                "workspace",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .is_err()
        );
    }
    #[test]
    #[cfg(unix)]
    fn archive_authenticates_workspace_key_record_order_completion_and_file_bytes() {
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let signer =
            crate::provenance::SigningKey::generate(&dir.path().join("signing.pk8")).unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        private(&source);
        fs::write(source.join("data"), b"private").unwrap();
        let key = WorkspaceKey::from_entropy([42; 32]);
        let archive = dir.path().join("archive");
        export_files(
            &source,
            &["data".into()],
            &archive,
            "workspace",
            "worker",
            JOB,
            ArchiveScope::FullProject,
            1000,
            &key,
            &signer,
        )
        .unwrap();
        assert!(
            restore_offline(
                &archive,
                &dir.path().join("wrong-key"),
                "workspace",
                &WorkspaceKey::from_entropy([43; 32]),
                "worker",
                &signer.trusted_key()
            )
            .is_err()
        );
        assert!(
            restore_offline(
                &archive,
                &dir.path().join("wrong-workspace"),
                "different",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .is_err()
        );
        let bytes = fs::read(&archive).unwrap();
        for (name, mutated) in [
            ("truncated", bytes[..bytes.len() - 1].to_vec()),
            ("appended", [bytes.as_slice(), &[0u8]].concat()),
            ("changed", {
                let mut bytes = bytes.clone();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                bytes
            }),
        ] {
            let damaged = dir.path().join(name);
            fs::write(&damaged, mutated).unwrap();
            let target = dir.path().join(format!("restore-{name}"));
            assert!(
                restore_offline(
                    &damaged,
                    &target,
                    "workspace",
                    &key,
                    "worker",
                    &signer.trusted_key()
                )
                .is_err()
            );
            assert!(!target.exists());
        }
    }
    #[test]
    #[cfg(unix)]
    fn export_refuses_paths_links_duplicates_and_existing_destination() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let signer =
            crate::provenance::SigningKey::generate(&dir.path().join("signing.pk8")).unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        private(&source);
        fs::write(source.join("data"), b"private").unwrap();
        fs::write(source.join("runtime-key"), b"workspace-key-must-not-export").unwrap();
        fs::create_dir(source.join("runtime-secrets")).unwrap();
        fs::write(
            source.join("runtime-secrets/secret"),
            b"secret-must-not-export",
        )
        .unwrap();
        fs::write(source.join("record.json"), b"record").unwrap();
        assert_eq!(
            job_export_paths(&source).unwrap(),
            vec!["record.json".to_owned()]
        );
        symlink(dir.path(), source.join("link")).unwrap();
        fs::write(source.join("linked"), b"linked").unwrap();
        fs::hard_link(source.join("linked"), source.join("hardlink")).unwrap();
        let fifo =
            std::ffi::CString::new(source.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let sparse = private_options()
            .write(true)
            .create_new(true)
            .open(source.join("oversized"))
            .unwrap();
        sparse.set_len(MAX_ARCHIVE_FILE_BYTES + 1).unwrap();
        let key = WorkspaceKey::from_entropy([44; 32]);
        for paths in [
            vec!["../outside".into()],
            vec!["/absolute".into()],
            vec!["a\\b".into()],
            vec!["link/outside".into()],
            vec!["hardlink".into()],
            vec!["fifo".into()],
            vec!["oversized".into()],
            vec!["data".into(); MAX_ARCHIVE_FILES + 1],
            vec!["data".into(), "data".into()],
        ] {
            assert!(
                export_files(
                    &source,
                    &paths,
                    &dir.path().join("output"),
                    "workspace",
                    "worker",
                    JOB,
                    ArchiveScope::FullProject,
                    1000,
                    &key,
                    &signer
                )
                .is_err()
            );
        }
        let archive = dir.path().join("archive");
        fs::write(&archive, b"keep-existing").unwrap();
        assert!(
            export_files(
                &source,
                &["data".into()],
                &archive,
                "workspace",
                "worker",
                JOB,
                ArchiveScope::FullProject,
                1000,
                &key,
                &signer
            )
            .is_err()
        );
        assert_eq!(fs::read(&archive).unwrap(), b"keep-existing");
        assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".archive-")
        }));
    }

    #[test]
    #[cfg(unix)]
    fn startup_clears_only_scoped_cache_and_rejects_unsafe_entries() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let final_path = dir.path().join(format!("{JOB}.lyarchive"));
        let temporary = dir.path().join(format!(".archive-{JOB}-{JOB}.tmp"));
        let unrelated = dir.path().join("other.lyarchive");
        let target = dir.path().join("target");
        for path in [&final_path, &temporary, &unrelated, &target] {
            fs::write(path, b"preserve-or-remove").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let unsafe_path = dir.path().join("00000000000000000000000001.lyarchive");
        symlink(&target, &unsafe_path).unwrap();
        assert_eq!(
            clear_executor_cache(dir.path()).unwrap_err().0,
            "unsafe_archive_cache_entry"
        );
        assert!(target.exists());
        fs::remove_file(&unsafe_path).unwrap();
        clear_executor_cache(dir.path()).unwrap();
        assert!(!final_path.exists());
        assert!(!temporary.exists());
        assert!(unrelated.exists());
        assert!(target.exists());
    }

    #[test]
    #[cfg(unix)]
    fn job_export_refuses_artifact_changed_after_result_was_signed() {
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let signer =
            crate::provenance::SigningKey::generate(&dir.path().join("signing.pk8")).unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        private(&source);
        let artifact = source.join("output.log");
        let expected_bytes = b"expected";
        let expected = std::collections::BTreeMap::from([(
            "output.log".to_owned(),
            crate::provenance::ArtifactDigest {
                size_bytes: expected_bytes.len() as u64,
                sha256: crate::provenance::sha256(expected_bytes),
                truncated: false,
                error_code: None,
            },
        )]);
        let archive = dir.path().join("archive");
        let key = WorkspaceKey::from_entropy([42; 32]);
        fs::write(&artifact, b"tampered").unwrap(); // Same size, different signed digest.
        assert_eq!(
            export_job_files(
                &source,
                &["output.log".into()],
                &archive,
                "workspace",
                "worker",
                JOB,
                ArchiveScope::ResultsOnly,
                1000,
                &key,
                &signer,
                &expected
            )
            .unwrap_err()
            .0,
            "archive_result_artifact_mismatch"
        );
        assert!(!archive.exists());
        assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".archive-")
        }));
        fs::write(&artifact, expected_bytes).unwrap();
        export_job_files(
            &source,
            &["output.log".into()],
            &archive,
            "workspace",
            "worker",
            JOB,
            ArchiveScope::ResultsOnly,
            1000,
            &key,
            &signer,
            &expected,
        )
        .unwrap();
        let restored = dir.path().join("restored");
        restore_offline(
            &archive,
            &restored,
            "workspace",
            &key,
            "worker",
            &signer.trusted_key(),
        )
        .unwrap();
        assert_eq!(
            fs::read(restored.join("files/output.log")).unwrap(),
            expected_bytes
        );
    }

    #[test]
    #[cfg(unix)]
    fn strict_job_restore_checks_nested_result_and_rejects_incomplete_artifacts() {
        use crate::provenance::{ArtifactDigest, ResultManifest};
        use crate::wire::JobState;
        use std::collections::BTreeMap;
        let dir = tempfile::tempdir().unwrap();
        private(dir.path());
        let signer =
            crate::provenance::SigningKey::generate(&dir.path().join("signing.pk8")).unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        private(&source);
        let key = WorkspaceKey::from_entropy([43; 32]);
        let original = b"original";
        fs::write(source.join("output.log"), original).unwrap();
        let result = ResultManifest {
            version: 1,
            node_id: "worker".into(),
            workspace: "workspace".into(),
            job_id: JOB.into(),
            repository: "repo".into(),
            runner: "runner".into(),
            request_sha256: "a".repeat(64),
            resolved_revision: "b".repeat(40),
            image_reference: format!("sha256:{}", "c".repeat(64)),
            image_digest: format!("sha256:{}", "c".repeat(64)),
            image_config_digest: None,
            image_attestation_sha256: None,
            execution_attempted: false,
            completed_at_ms: 1234,
            state: JobState::Succeeded,
            exit_code: Some(0),
            error_code: None,
            artifacts: BTreeMap::from([(
                "output.log".into(),
                ArtifactDigest {
                    size_bytes: original.len() as u64,
                    sha256: crate::provenance::sha256(original),
                    truncated: false,
                    error_code: None,
                },
            )]),
        };
        let paths = vec!["export-metadata.json".into(), "output.log".into()];
        for case in [
            "valid",
            "valid_full",
            "digest",
            "digest_full",
            "truncated",
            "rejected",
            "wrong_job",
            "wrong_signer",
            "malformed",
        ] {
            let mut current = result.clone();
            if case == "truncated" {
                current.artifacts.get_mut("output.log").unwrap().truncated = true;
            }
            if case == "rejected" {
                current.artifacts.get_mut("output.log").unwrap().error_code =
                    Some("log_contains_forwarded_credential".into());
            }
            if case == "wrong_job" {
                current.job_id = "00000000000000000000000001".into();
            }
            let other = if case == "wrong_signer" {
                Some(
                    crate::provenance::SigningKey::generate(&dir.path().join("other.pk8")).unwrap(),
                )
            } else {
                None
            };
            let signed = other
                .as_ref()
                .unwrap_or(&signer)
                .sign_result(&current)
                .unwrap();
            let scope = if case.ends_with("_full") {
                ArchiveScope::FullProject
            } else {
                ArchiveScope::ResultsOnly
            };
            let metadata = serde_json::json!({"version":1,"job_id":JOB,"scope":scope,
                "state":"succeeded","retention":null,"result_manifest":signed});
            fs::write(
                source.join("export-metadata.json"),
                if case == "malformed" {
                    b"{\"result_manifest\":".to_vec()
                } else {
                    serde_json::to_vec(&metadata).unwrap()
                },
            )
            .unwrap();
            fs::write(
                source.join("output.log"),
                if case.starts_with("digest") {
                    b"tampered"
                } else {
                    original
                },
            )
            .unwrap();
            let archive = dir.path().join(format!("archive-{case}"));
            // Generic export simulates older nodes that signed the altered archive bytes.
            export_files(
                &source,
                &paths,
                &archive,
                "workspace",
                "worker",
                JOB,
                scope,
                1000,
                &key,
                &signer,
            )
            .unwrap();
            let restored = dir.path().join(format!("restore-{case}"));
            let outcome = restore_job_offline(
                &archive,
                &restored,
                "workspace",
                &key,
                "worker",
                &signer.trusted_key(),
            );
            if case.starts_with("valid") {
                assert!(outcome.unwrap().result_provenance_verified);
                assert_eq!(
                    fs::read(restored.join("files/output.log")).unwrap(),
                    original
                );
            } else {
                assert!(outcome.is_err(), "accepted {case}");
                assert!(!restored.exists(), "partial restore remains for {case}");
            }
        }
        // Generic archives without job metadata remain usable by the library,
        // but do not claim result provenance and are rejected by job restore.
        let generic = dir.path().join("generic");
        export_files(
            &source,
            &["output.log".into()],
            &generic,
            "workspace",
            "worker",
            JOB,
            ArchiveScope::ResultsOnly,
            1000,
            &key,
            &signer,
        )
        .unwrap();
        let generic_out = dir.path().join("generic-out");
        assert!(
            !restore_offline(
                &generic,
                &generic_out,
                "workspace",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .unwrap()
            .result_provenance_verified
        );
        assert!(
            restore_job_offline(
                &generic,
                &dir.path().join("strict-out"),
                "workspace",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .is_err()
        );
        // Generic archives may contain arbitrary large files at this name. No
        // result provenance claim is made unless metadata fits the job bound.
        fs::write(
            source.join("export-metadata.json"),
            vec![b'x'; 128 * 1024 + 1],
        )
        .unwrap();
        let large_generic = dir.path().join("large-generic");
        export_files(
            &source,
            &["export-metadata.json".into()],
            &large_generic,
            "workspace",
            "worker",
            JOB,
            ArchiveScope::FullProject,
            1000,
            &key,
            &signer,
        )
        .unwrap();
        let large_out = dir.path().join("large-generic-out");
        assert!(
            !restore_offline(
                &large_generic,
                &large_out,
                "workspace",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .unwrap()
            .result_provenance_verified
        );
        assert!(
            restore_job_offline(
                &large_generic,
                &dir.path().join("large-strict-out"),
                "workspace",
                &key,
                "worker",
                &signer.trusted_key()
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn restore_parent_descriptor_survives_ancestor_rename() {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{PermissionsExt, symlink},
        };
        let root = tempfile::tempdir().unwrap();
        private(root.path());
        let parent = root.path().join("parent");
        let moved = root.path().join("moved");
        let victim = root.path().join("victim");
        fs::create_dir(&parent).unwrap();
        private(&parent);
        fs::create_dir(&victim).unwrap();
        private(&victim);
        let fd = open_restore_parent(&parent).unwrap();
        fs::rename(&parent, &moved).unwrap();
        symlink(&victim, &parent).unwrap();
        let anchored = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())).join("restored");
        create_private_directory(&anchored).unwrap();
        assert!(moved.join("restored").is_dir());
        assert!(!victim.join("restored").exists());
        assert!(verify_restore_parent_identity(&parent, &fd).is_err());
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_restore_parent(&victim).is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn restore_apis_fail_closed_without_descriptor_anchored_traversal() {
        let key = WorkspaceKey::from_entropy([9; 32]);
        let signer = crate::provenance::TrustedSigningKey {
            public_key: String::new(),
        };
        let path = Path::new("not-an-absolute-path");
        for result in [
            restore_offline(path, path, "workspace", &key, "worker", &signer),
            restore_job_offline(path, path, "workspace", &key, "worker", &signer),
        ] {
            assert_eq!(
                result.unwrap_err().0,
                "archive_restore_platform_unsupported"
            );
        }
    }
}
