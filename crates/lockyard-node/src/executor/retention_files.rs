// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn record_content_expired(record: &JobRecord, now: u64) -> Result<bool> {
    record
        .retention
        .as_ref()
        .ok_or(ExecutorError("project_retention_required"))?
        .expired(record.state, now)
        .map_err(|error| ExecutorError(error.0))
}
pub(super) fn note_terminal_retention(record: &mut JobRecord) -> Result<()> {
    record
        .retention
        .as_mut()
        .ok_or(ExecutorError("project_retention_required"))?
        .note_terminal(record.state, record.updated_at_ms)
        .map_err(|error| ExecutorError(error.0))
}
pub(super) fn retire_job_directory(state: &Path, id: &str) -> Result<()> {
    if !valid_id(id) {
        return Err(ExecutorError("invalid_job_id"));
    }
    let job = state.join("jobs").join(id);
    let expired = state.join("expired-content").join(id);
    match fs::symlink_metadata(&job) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(ExecutorError("unsafe_expired_job_directory"));
            }
            match fs::symlink_metadata(&expired) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    fs::remove_dir_all(&expired).map_err(io_error)?
                }
                Ok(_) => return Err(ExecutorError("unsafe_expired_job_directory")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(io_error(error)),
            }
            lockyard_core::fsio::rename(&job, &expired).map_err(io_error)?;
            lockyard_core::fsio::sync_path(state.join("jobs")).map_err(io_error)?;
            lockyard_core::fsio::sync_path(state.join("expired-content")).map_err(io_error)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error(error)),
    }
    let export = state.join("exports").join(format!("{id}.lyarchive"));
    match fs::remove_file(export) {
        Ok(()) => lockyard_core::fsio::sync_path(state.join("exports")).map_err(io_error)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error(error)),
    }
    match fs::symlink_metadata(&expired) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(expired).map_err(io_error)?;
            lockyard_core::fsio::sync_path(state.join("expired-content")).map_err(io_error)?;
        }
        Ok(_) => return Err(ExecutorError("unsafe_expired_job_directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io_error(error)),
    }
    let tombstone = retention::load_tombstone(&state.join("job-tombstones"), id)
        .map_err(|error| ExecutorError(error.0))?
        .ok_or(ExecutorError("job_tombstone_required_before_erasure"))?;
    retention::store_purge_completion(&state.join("purge-completed"), &tombstone, now_ms())
        .map_err(|error| ExecutorError(error.0))?;
    Ok(())
}
