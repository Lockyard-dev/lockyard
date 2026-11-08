// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::sandbox::syscall;
use super::*;
pub(super) fn mount(
    source: Option<&Path>,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let source = source
        .map(|p| CString::new(p.as_os_str().as_bytes()))
        .transpose()
        .map_err(|_| unavailable())?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    let kind = kind
        .map(CString::new)
        .transpose()
        .map_err(|_| unavailable())?;
    let data = data
        .map(CString::new)
        .transpose()
        .map_err(|_| unavailable())?;
    syscall(unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    })
}
fn inherited_mount_flags(source: &Path) -> Result<libc::c_ulong> {
    // Linux statvfs ABI; libc does not expose ST_RELATIME on musl targets.
    const ST_RELATIME: libc::c_ulong = 4096;
    let path = CString::new(source.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    syscall(unsafe { libc::statvfs(path.as_ptr(), &mut stat) })
        .map_err(|_| ExecutorError("native_mount_flags_unavailable"))?;
    let mut flags = 0;
    // These flags become locked when inherited into a less privileged mount namespace.
    // A bind remount must preserve them, even when its requested policy is less restrictive.
    for (status, mount) in [
        (libc::ST_RDONLY, libc::MS_RDONLY),
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (ST_RELATIME, libc::MS_RELATIME),
    ] {
        if stat.f_flag & status != 0 {
            flags |= mount;
        }
    }
    Ok(flags)
}
pub(super) fn bind(source: &Path, target: &Path, readonly: bool) -> Result<()> {
    if source.is_dir() {
        fs::create_dir_all(target).map_err(|_| unavailable())?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|_| unavailable())?;
        }
        fs::File::create(target).map_err(|_| unavailable())?;
    }
    // Non-recursive bind deliberately excludes any nested host mounts.
    mount(Some(source), target, None, libc::MS_BIND, None)
        .map_err(|_| ExecutorError("native_bind_mount_unavailable"))?;
    mount(
        None,
        target,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | inherited_mount_flags(source)?
            | if readonly { libc::MS_RDONLY } else { 0 },
        None,
    )
    .map_err(|_| ExecutorError("native_bind_remount_unavailable"))
}
pub(super) fn bind_device(source: &Path, target: &Path) -> Result<()> {
    fs::File::create(target).map_err(|_| unavailable())?;
    mount(Some(source), target, None, libc::MS_BIND, None)
        .map_err(|_| ExecutorError("native_device_bind_unavailable"))?;
    mount(
        None,
        target,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_NOSUID
            | libc::MS_NOEXEC
            | inherited_mount_flags(source)?,
        None,
    )
    .map_err(|_| ExecutorError("native_device_remount_unavailable"))
}
pub(super) fn setup_root(sandbox: &Sandbox) -> Result<()> {
    let root = sandbox
        .job_dir
        .join(format!("native-root-{}", std::process::id()));
    fs::create_dir(&root).map_err(|_| unavailable())?;
    mount(
        None,
        &root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=67108864,mode=0755"),
    )?;
    for name in ["usr", "bin", "sbin", "lib", "lib64", "etc", "opt"] {
        let source = sandbox.rootfs.join(name);
        let Ok(metadata) = fs::symlink_metadata(&source) else {
            continue;
        };
        let target = root.join(name);
        if metadata.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(source).map_err(|_| unavailable())?, target)
                .map_err(|_| unavailable())?;
        } else {
            bind(&source, &target, true)?;
        }
    }
    for name in ["tmp", "dev", "proc", "run"] {
        fs::create_dir_all(root.join(name)).map_err(|_| unavailable())?;
    }
    if matches!(sandbox.network, ContainerNetwork::Bridge) {
        let resolver = sandbox.rootfs.join("etc/resolv.conf");
        if !fs::symlink_metadata(&resolver).is_ok_and(|m| m.is_file())
            || fs::canonicalize(&resolver).map_err(|_| unavailable())? != resolver
        {
            return Err(ExecutorError("native_resolver_must_be_regular"));
        }
        let source = root.join("tmp/lockyard-resolv.conf");
        fs::write(&source, "nameserver 10.0.2.3\n").map_err(|_| unavailable())?;
        mount(
            Some(&source),
            &root.join("etc/resolv.conf"),
            None,
            libc::MS_BIND,
            None,
        )?;
        mount(
            None,
            &root.join("etc/resolv.conf"),
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
    }
    // A private /dev contains only the explicitly allowed devices, never the host device tree.
    for name in ["null", "zero", "random", "urandom"] {
        let target = root.join("dev").join(name);
        bind_device(&Path::new("/dev").join(name), &target)?;
    }
    std::os::unix::fs::symlink("/proc/self/fd", root.join("dev/fd")).map_err(|_| unavailable())?;
    for (source, readonly) in [
        (&sandbox.worktree, sandbox.patch),
        (&sandbox.job_dir.join("repository.git"), false),
    ] {
        let target = root.join(source.strip_prefix("/").map_err(|_| unavailable())?);
        if [
            "usr", "bin", "sbin", "lib", "lib64", "etc", "opt", "dev", "proc",
        ]
        .iter()
        .any(|p| source.starts_with(Path::new("/").join(p)))
        {
            return Err(ExecutorError("invalid_native_mount"));
        }
        bind(source, &target, readonly)?;
    }
    if !sandbox.patch {
        for (directory, destination) in [
            ("runtime-key", "lockyard-config"),
            ("runtime-secrets", "lockyard-secrets"),
            ("runtime-context", "lockyard-context"),
            ("runtime-delegation", "lockyard-delegation"),
        ] {
            let source = sandbox.job_dir.join(directory);
            if source.exists() {
                bind(&source, &root.join("run").join(destination), true)?;
            }
        }
    }
    // PID namespace was entered by the child fork; this proc cannot expose host processes.
    mount(
        None,
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    let croot = CString::new(root.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    syscall(unsafe { libc::chroot(croot.as_ptr()) })?;
    std::env::set_current_dir(&sandbox.worktree).map_err(|_| unavailable())?;
    Ok(())
}

// The supervisor remains outside the new network namespace. Only its trusted slirp
// child has host networking; the workload waits for explicit network initialization.
