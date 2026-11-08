// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Native Linux execution. Missing kernel enforcement is never a host-execution fallback.
#[cfg(target_os = "linux")]
use crate::executor::ContainerNetwork;
use crate::executor::{ContainerProfile, ExecutorError, Result};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{fs, path::Path, process::Command};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug, Serialize, Deserialize)]
pub struct Capabilities {
    pub available: bool,
    pub reasons: Vec<String>,
    pub remedies: Vec<String>,
}
pub fn capabilities(root: Option<&Path>, helper: &Path) -> Capabilities {
    #[cfg(target_os = "linux")]
    {
        linux::capabilities(root, helper)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, helper);
        Capabilities { available: false, reasons: vec!["native execution requires Linux cgroups v2 and namespaces".into()], remedies: vec!["Run the node on Linux with an explicitly delegated cgroup subtree; macOS cannot enforce these limits".into()] }
    }
}

/// Canonical, content-based identity of the provisioned native rootfs. Symlinks are hashed,
/// never followed. No sockets, devices or additional mount points belong in an image.
pub fn rootfs_digest(root: &Path) -> Result<String> {
    use ring::digest::{Context, SHA256};
    use std::io::Read;
    let root = fs::canonicalize(root).map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
    if root == Path::new("/") {
        return Err(ExecutorError("native_rootfs_must_be_private"));
    }
    #[cfg(target_os = "linux")]
    linux::check_rootfs_mounts(&root)?;
    let mut digest = Context::new(&SHA256);
    let mut entries = vec![root.clone()];
    let mut count = 0usize;
    let mut size = 0u64;
    while let Some(path) = entries.pop() {
        count += 1;
        if count > 1_000_000 {
            return Err(ExecutorError("native_rootfs_too_large"));
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0 && !metadata.is_symlink() {
                return Err(ExecutorError("native_rootfs_writable"));
            }
            digest.update(&(metadata.mode() & 0o7777).to_le_bytes());
        }
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
        #[cfg(unix)]
        let name = {
            use std::os::unix::ffi::OsStrExt;
            relative.as_os_str().as_bytes()
        };
        #[cfg(not(unix))]
        let name = relative
            .to_str()
            .ok_or(ExecutorError("native_rootfs_unavailable"))?
            .as_bytes();
        digest.update(&(name.len() as u64).to_le_bytes());
        digest.update(name);
        if metadata.is_symlink() {
            digest.update(b"L");
            let target =
                fs::read_link(&path).map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
            #[cfg(unix)]
            let bytes = {
                use std::os::unix::ffi::OsStrExt;
                target.as_os_str().as_bytes()
            };
            #[cfg(not(unix))]
            let bytes = target
                .to_str()
                .ok_or(ExecutorError("native_rootfs_unavailable"))?
                .as_bytes();
            digest.update(&(bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
        } else if metadata.is_dir() {
            digest.update(b"D");
            let mut children = fs::read_dir(&path)
                .map_err(|_| ExecutorError("native_rootfs_unavailable"))?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
            children.sort();
            entries.extend(children.into_iter().rev());
        } else if metadata.is_file() {
            digest.update(b"F");
            digest.update(&metadata.len().to_le_bytes());
            size = size.saturating_add(metadata.len());
            if size > 32 * 1024 * 1024 * 1024 {
                return Err(ExecutorError("native_rootfs_too_large"));
            }
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let mut file = options
                .open(&path)
                .map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let opened = file
                    .metadata()
                    .map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
                if opened.ino() != metadata.ino()
                    || opened.dev() != metadata.dev()
                    || opened.len() != metadata.len()
                {
                    return Err(ExecutorError("native_rootfs_changed"));
                }
            }
            let mut buffer = [0u8; 65536];
            loop {
                let n = file
                    .read(&mut buffer)
                    .map_err(|_| ExecutorError("native_rootfs_unavailable"))?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
        } else {
            return Err(ExecutorError("native_rootfs_special_file"));
        }
    }
    #[cfg(target_os = "linux")]
    linux::check_rootfs_mounts(&root)?;
    Ok(format!(
        "sha256:{}",
        digest
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

#[cfg(target_os = "linux")]
#[derive(Serialize, Deserialize)]
pub(crate) struct Sandbox {
    rootfs: PathBuf,
    cgroup: PathBuf,
    job_dir: PathBuf,
    worktree: PathBuf,
    program: PathBuf,
    image: String,
    patch: bool,
    network: ContainerNetwork,
    network_program: Option<PathBuf>,
    memory_mb: u64,
    cpu_millis: u32,
    pids_limit: u32,
}
pub(crate) fn command(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    program: &Path,
    name: &str,
    patch: bool,
) -> Result<Command> {
    #[cfg(target_os = "linux")]
    {
        linux::command(profile, job_dir, worktree, program, name, patch)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, job_dir, worktree, program, name, patch);
        Err(ExecutorError("container_limits_unavailable"))
    }
}
pub(crate) fn stop(profile: &ContainerProfile, job_dir: &Path, name: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::stop(profile, job_dir, name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, job_dir, name);
        false
    }
}
pub(crate) fn limit_error(job_dir: &Path, name: &str) -> Option<&'static str> {
    let receipt = cleanup_receipt(job_dir, name, None)?;
    let events = receipt.events;
    if events.get("oom_kill").copied().unwrap_or(0) > 0
        || events.get("oom").copied().unwrap_or(0) > 0
    {
        Some("limit_exceeded:memory")
    } else if events.get("pids_max").copied().unwrap_or(0) > 0 {
        Some("limit_exceeded:pids")
    } else {
        None
    }
}
fn cleanup_receipt(
    job_dir: &Path,
    name: &str,
    expected_group: Option<&Path>,
) -> Option<CleanupReceipt> {
    let bytes = crate::provenance::read_bounded(
        &job_dir.join(format!("native-events-{}.json", identity(name))),
        4096,
    )
    .ok()?;
    let receipt: CleanupReceipt = serde_json::from_slice(&bytes).ok()?;
    if receipt.version != 1
        || receipt.identity != identity(name)
        || !receipt.stopped
        || !receipt.cgroup.is_absolute()
        || expected_group.is_some_and(|group| group != receipt.cgroup)
    {
        return None;
    }
    Some(receipt)
}
pub(crate) fn identity(name: &str) -> String {
    crate::provenance::sha256(name.as_bytes())[..32].into()
}

/// Entry point of the fresh helper process. The daemon never calls unshare/pre_exec closures.
pub fn sandbox_main() -> i32 {
    #[cfg(target_os = "linux")]
    {
        match linux::entry() {
            Ok(code) => code,
            Err(error) => {
                eprintln!("{error}");
                125
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("container_limits_unavailable: Linux is required");
        125
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupReceipt {
    version: u8,
    identity: String,
    cgroup: std::path::PathBuf,
    stopped: bool,
    events: std::collections::BTreeMap<String, u64>,
}

#[cfg(test)]
mod regression_tests;
