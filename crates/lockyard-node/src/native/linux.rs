// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    io::Write,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    time::{Duration, Instant},
};

mod filesystem;
mod network;
mod sandbox;
mod seccomp;

pub(super) fn entry() -> Result<i32> {
    sandbox::entry()
}
fn unavailable() -> ExecutorError {
    ExecutorError("container_limits_unavailable")
}
fn child_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("lockyard-{}", identity(name)))
}
pub(super) fn check_rootfs_mounts(root: &Path) -> Result<()> {
    let mounts = fs::read("/proc/self/mountinfo")
        .map_err(|_| ExecutorError("native_rootfs_mounts_unavailable"))?;
    for line in mounts.split(|byte| *byte == b'\n') {
        let Some(field) = line.split(|byte| *byte == b' ').nth(4) else {
            continue;
        };
        let mut decoded = Vec::new();
        let mut index = 0;
        while index < field.len() {
            if field[index] == b'\\'
                && index + 3 < field.len()
                && field[index + 1..index + 4]
                    .iter()
                    .all(|byte| (b'0'..=b'7').contains(byte))
            {
                let byte = (field[index + 1] - b'0') * 64
                    + (field[index + 2] - b'0') * 8
                    + field[index + 3]
                    - b'0';
                decoded.push(byte);
                index += 4;
            } else {
                decoded.push(field[index]);
                index += 1;
            }
        }
        let mount = Path::new(std::ffi::OsStr::from_bytes(&decoded));
        if mount != root && mount.starts_with(root) {
            return Err(ExecutorError("native_rootfs_nested_mount"));
        }
    }
    Ok(())
}
fn checked_root(root: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(root).map_err(|_| unavailable())?;
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 || stat.f_type != 0x63677270 {
        return Err(unavailable());
    }
    let controllers =
        fs::read_to_string(root.join("cgroup.controllers")).map_err(|_| unavailable())?;
    if !["memory", "cpu", "pids"]
        .iter()
        .all(|c| controllers.split_whitespace().any(|v| v == *c))
    {
        return Err(unavailable());
    }
    fs::write(root.join("cgroup.subtree_control"), "+memory +cpu +pids")
        .map_err(|_| unavailable())?;
    Ok(root)
}
fn configure(path: &Path, memory_mb: u64, cpu_millis: u32, pids: u32) -> Result<()> {
    for (file, value) in [
        ("memory.max", (memory_mb * 1024 * 1024).to_string()),
        ("memory.swap.max", "0".into()),
        ("cpu.max", {
            let period = if cpu_millis < 10 {
                1_000_000u64
            } else {
                100_000
            };
            format!("{} {period}", u64::from(cpu_millis) * period / 1000)
        }),
        ("pids.max", pids.to_string()),
        ("memory.oom.group", "1".into()),
    ] {
        fs::write(path.join(file), &value).map_err(|_| unavailable())?;
        if fs::read_to_string(path.join(file))
            .map_err(|_| unavailable())?
            .trim()
            != value
        {
            return Err(unavailable());
        }
    }
    if !path.join("cgroup.kill").exists() {
        return Err(unavailable());
    }
    Ok(())
}
pub(super) fn capabilities(root: Option<&Path>, helper: &Path) -> Capabilities {
    static NEXT_PROBE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut reasons = Vec::new();
    let mut probe_group = None;
    match root {
        None => reasons
            .push("cgroup_root is unset: configure a delegated empty cgroup v2 subtree".into()),
        Some(root) => {
            let checked = (|| -> std::result::Result<PathBuf, String> {
                let root =
                    fs::canonicalize(root).map_err(|error| format!("cgroup_root: {error}"))?;
                let path = CString::new(root.as_os_str().as_bytes())
                    .map_err(|_| "invalid cgroup_root".to_owned())?;
                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
                    return Err(format!(
                        "cgroup_root statfs: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                if stat.f_type != 0x63677270 {
                    return Err("cgroup_root is not on cgroup2fs".into());
                }
                let controllers = fs::read_to_string(root.join("cgroup.controllers"))
                    .map_err(|error| format!("cgroup.controllers: {error}"))?;
                let missing: Vec<_> = ["cpu", "memory", "pids"]
                    .into_iter()
                    .filter(|name| !controllers.split_whitespace().any(|value| value == *name))
                    .collect();
                if !missing.is_empty() {
                    return Err(format!("controllers not delegated: {}", missing.join(", ")));
                }
                fs::write(root.join("cgroup.subtree_control"),"+cpu +memory +pids").map_err(|error| format!("cgroup.subtree_control: {error}; move the daemon into a manager leaf before enabling domain controllers"))?;
                Ok(root)
            })();
            match checked {
                Err(reason) => reasons.push(reason),
                Ok(root) => {
                    let probe = root.join(format!(
                        "lockyard-probe-{}-{}",
                        std::process::id(),
                        NEXT_PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    ));
                    match fs::create_dir(&probe) {
                        Err(error) => reasons.push(format!("create delegated child: {error}")),
                        Ok(()) => {
                            if let Err(error) = configure(&probe, 64, 1000, 16) {
                                reasons.push(format!("cannot enforce child memory.max/memory.swap.max/cpu.max/pids.max/cgroup.kill: {error}"));
                            }
                            probe_group = Some(probe);
                        }
                    }
                }
            }
        }
    }
    let mut probe = Command::new(helper);
    if helper
        .file_name()
        .is_none_or(|name| name != "lockyard-sandbox")
    {
        probe.arg("__native-sandbox");
    }
    probe.arg("--probe");
    if let Some(group) = &probe_group {
        probe.arg(group);
    }
    probe.env_clear();
    if let Err(error) = crate::executor::native_probe_diagnostic(&mut probe) {
        reasons.push(format!("isolation probe: {error}"));
        if fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|value| value.trim() == "1")
        {
            reasons.push("kernel.apparmor_restrict_unprivileged_userns=1: install the AppArmor profile for the actual helper executable".into());
        }
    }
    if let Some(group) = probe_group {
        let _ = fs::write(group.join("cgroup.kill"), "1");
        if let Err(error) = fs::remove_dir(group) {
            reasons.push(format!("probe cgroup cleanup: {error}"));
        }
    }
    Capabilities {available:reasons.is_empty(), reasons, remedies:vec!["Use systemd-run --user --scope -p Delegate=yes; move the daemon to a manager leaf and configure a sibling empty delegated jobs subtree".into(),"Enable unprivileged user namespaces and install the exact AppArmor attachment with lockyard node install --apparmor --sandbox-binary <helper>".into()]}
}
pub(super) fn command(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    program: &Path,
    name: &str,
    patch: bool,
) -> Result<Command> {
    if !patch
        && matches!(profile.network, ContainerNetwork::Bridge)
        && !profile
            .native_network_program
            .as_ref()
            .is_some_and(|p| p.is_absolute() && p.is_file())
    {
        return Err(ExecutorError("native_network_unavailable"));
    }
    let root = checked_root(profile.cgroup_root.as_deref().ok_or_else(unavailable)?)?;
    let group = child_path(&root, name);
    let sandbox = Sandbox {
        rootfs: fs::canonicalize(
            profile
                .native_rootfs
                .as_deref()
                .ok_or(ExecutorError("native_rootfs_unavailable"))?,
        )
        .map_err(|_| ExecutorError("native_rootfs_unavailable"))?,
        cgroup: group,
        job_dir: fs::canonicalize(job_dir).map_err(|_| unavailable())?,
        worktree: fs::canonicalize(worktree).map_err(|_| unavailable())?,
        program: program.into(),
        image: profile.image.clone(),
        patch,
        network: if patch {
            ContainerNetwork::None
        } else {
            profile.network.clone()
        },
        network_program: profile.native_network_program.clone(),
        memory_mb: profile.memory_mb,
        cpu_millis: profile.cpu_millis,
        pids_limit: profile.pids_limit,
    };
    let manifest = job_dir.join(format!("native-sandbox-{}.json", identity(name)));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&manifest)
        .map_err(|_| unavailable())?;
    file.write_all(&serde_json::to_vec(&sandbox).map_err(|_| unavailable())?)
        .and_then(|()| file.sync_all())
        .map_err(|_| unavailable())?;
    let previous_receipt = job_dir.join(format!("native-events-{}.json", identity(name)));
    match fs::remove_file(previous_receipt) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(unavailable()),
    }
    fs::File::open(job_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable())?;
    let mut command = Command::new(&profile.runtime_program);
    if profile
        .runtime_program
        .file_name()
        .is_none_or(|name| name != "lockyard-sandbox")
    {
        command.arg("__native-sandbox");
    }
    command
        .arg("--manifest")
        .arg(manifest)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin");
    Ok(command)
}
fn events(group: &Path) -> Result<BTreeMap<String, u64>> {
    let mut result = BTreeMap::new();
    for (file, prefix) in [("memory.events", ""), ("pids.events", "pids_")] {
        let text = fs::read_to_string(group.join(file)).map_err(|_| unavailable())?;
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                result.insert(
                    format!("{prefix}{key}"),
                    value.parse().map_err(|_| unavailable())?,
                );
            }
        }
    }
    Ok(result)
}
pub(super) fn stop(profile: &ContainerProfile, job_dir: &Path, name: &str) -> bool {
    let Some(root) = &profile.cgroup_root else {
        return false;
    };
    let Ok(root) = checked_root(root) else {
        return false;
    };
    let group = child_path(&root, name);
    let output = job_dir.join(format!("native-events-{}.json", identity(name)));
    if !group.exists() {
        return cleanup_receipt(job_dir, name, Some(&group)).is_some();
    }
    if fs::write(group.join("cgroup.kill"), "1").is_err() {
        return false;
    }
    let started = Instant::now();
    while !fs::read_to_string(group.join("cgroup.events"))
        .is_ok_and(|v| v.lines().any(|line| line == "populated 0"))
    {
        if started.elapsed() > Duration::from_secs(5) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let Ok(events) = events(&group) else {
        return false;
    };
    let Ok(mut file) = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)
    else {
        return false;
    };
    let receipt = CleanupReceipt {
        version: 1,
        identity: identity(name),
        cgroup: group.clone(),
        stopped: true,
        events,
    };
    if serde_json::to_writer(&mut file, &receipt).is_err()
        || file.sync_all().is_err()
        || fs::File::open(job_dir)
            .and_then(|directory| directory.sync_all())
            .is_err()
    {
        return false;
    }
    let removed = fs::remove_dir(group).is_ok();
    if let Ok(entries) = fs::read_dir(job_dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("native-root-")
            {
                let _ = fs::remove_dir(entry.path());
            }
        }
    }
    removed
}
