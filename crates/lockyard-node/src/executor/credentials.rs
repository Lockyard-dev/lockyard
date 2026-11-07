// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// A checkout must never snapshot node/control keys or another executor's state.
pub(super) fn check_execution_identity_paths(config: &ExecutorConfig) -> Result<()> {
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
pub(super) fn stage_forwarded_environment(
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

pub(super) fn create_runtime_key(job_dir: &Path, context: &WorkspaceKeyContext) -> Result<Vec<u8>> {
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
pub(super) fn remove_runtime_key(job_dir: &Path) -> Result<()> {
    remove_private_runtime_directory(job_dir, "runtime-key")?;
    remove_private_runtime_directory(job_dir, "runtime-secrets")
}

pub(super) fn remove_private_runtime_directory(job_dir: &Path, name: &str) -> Result<()> {
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

pub(super) fn record_log_integrity(
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

pub(super) fn quarantine_prejournal(state_dir: &Path, path: &Path, id: &str) -> Result<()> {
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
