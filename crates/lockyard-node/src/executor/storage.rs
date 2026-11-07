// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn git(checkout: &Path) -> Command {
    let mut command = Command::new("git");
    command.env_clear();
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for name in ["PATH", "HOME", "TMPDIR", "LANG"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(checkout);
    command
}
pub(super) fn resolve_revision(checkout: &Path, revision: &str) -> Result<String> {
    let mut command = git(checkout);
    command
        .args(["rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{revision}^{{commit}}"))
        .stdin(Stdio::null());
    let (status, output, _) = runtime_output(&mut command, Duration::from_secs(5), 4096, None)
        .map_err(|_| ExecutorError("revision_resolution_unavailable"))?;
    let revision = String::from_utf8(output).map_err(|_| ExecutorError("invalid_revision"))?;
    let revision = revision.trim();
    if !status.success()
        || !(revision.len() == 40 || revision.len() == 64)
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ExecutorError("invalid_revision"));
    }
    Ok(revision.to_string())
}
pub(super) fn private_dir(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(io_error)?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ExecutorError("state_directory_not_private"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ExecutorError("state_directory_not_private"));
        }
    }
    Ok(())
}
pub(super) fn private_dir_new(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(io_error)?;
    }
    Ok(())
}
pub(super) fn private_open(path: &Path, create_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(ExecutorError("state_file_not_private"));
        }
    }
    Ok(file)
}
pub(super) fn persist(state_dir: &Path, record: &JobRecord) -> Result<()> {
    let dir = state_dir.join("jobs").join(&record.spec.id);
    let path = dir.join("record.json.tmp");
    let mut file = private_open(&path, false)?;
    file.set_len(0).map_err(io_error)?;
    let bytes =
        serde_json::to_vec(record).map_err(|_| ExecutorError("job_record_encoding_failed"))?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(path, dir.join("record.json")).map_err(io_error)?;
    File::open(dir)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)?;
    Ok(())
}
pub(super) fn read_private_token(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(ExecutorError("token_file_must_be_absolute"));
    }
    let mut file = private_open_existing(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata().map_err(io_error)?.nlink() != 1 {
            return Err(ExecutorError("token_file_has_aliases"));
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 16384 {
        return Err(ExecutorError("invalid_token_file"));
    }
    let trimmed = String::from_utf8(bytes)
        .map_err(|_| ExecutorError("invalid_token_file"))?
        .trim()
        .as_bytes()
        .to_vec();
    if trimmed.is_empty() || trimmed.len() > 16384 {
        return Err(ExecutorError("invalid_token_file"));
    }
    Ok(trimmed)
}
pub(super) fn private_open_existing(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(io_error)?;
        if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err(ExecutorError("token_file_not_private"));
        }
    }
    Ok(file)
}
pub(super) fn write_cloud_config(worktree: &Path, cloud: &CloudConfig) -> Result<Option<String>> {
    let dir = worktree.join(".lockyard");
    if fs::symlink_metadata(&dir)
        .is_ok_and(|metadata| !metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(ExecutorError("unsafe_worktree_cloud_config"));
    }
    if !dir.exists() {
        private_dir_new(&dir)?;
    }
    let path = dir.join("config.toml");
    if fs::symlink_metadata(&path)
        .is_ok_and(|metadata| !metadata.is_file() || metadata.file_type().is_symlink())
    {
        return Err(ExecutorError("unsafe_worktree_cloud_config"));
    }
    // JSON string escaping is also valid TOML basic-string escaping for these strings.
    let quoted = |value: &str| serde_json::to_string(value).unwrap();
    let content = format!(
        "mode = \"cloud\"\nurl = {}\nworkspace = {}\nrepository = {}\n",
        quoted(&cloud.url),
        quoted(&cloud.workspace),
        quoted(&cloud.repository)
    );
    if path.exists() {
        return if fs::read(&path).map_err(io_error)? == content.as_bytes() {
            Ok(None)
        } else {
            Err(ExecutorError("worktree_cloud_config_conflict"))
        };
    }
    let temp = dir.join("config.toml.node-tmp");
    let mut file = private_open(&temp, true)?;
    file.write_all(content.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(temp, path).map_err(io_error)?;
    Ok(Some(".lockyard/config.toml".into()))
}
