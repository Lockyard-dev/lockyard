// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::filesystem::{bind, bind_device, mount, setup_root};
use super::network::bridge_start;
use super::seccomp::install as seccomp;
use super::*;
use std::{ffi::OsString, os::unix::process::CommandExt};
pub(super) fn syscall(result: libc::c_int) -> Result<()> {
    if result < 0 {
        Err(ExecutorError("native_namespace_setup_failed"))
    } else {
        Ok(())
    }
}
pub(super) fn namespaces() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    syscall(unsafe { libc::unshare(libc::CLONE_NEWUSER) })
        .map_err(|_| ExecutorError("native_user_namespace_unavailable"))?;
    fs::write("/proc/self/setgroups", "deny").map_err(|_| unavailable())?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).map_err(|_| unavailable())?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).map_err(|_| unavailable())?;
    for (flag, code) in [
        (libc::CLONE_NEWNS, "native_mount_namespace_unavailable"),
        (libc::CLONE_NEWPID, "native_pid_namespace_unavailable"),
        (libc::CLONE_NEWNET, "native_net_namespace_unavailable"),
        (libc::CLONE_NEWIPC, "native_ipc_namespace_unavailable"),
        (libc::CLONE_NEWUTS, "native_uts_namespace_unavailable"),
    ] {
        syscall(unsafe { libc::unshare(flag) }).map_err(|_| ExecutorError(code))?;
    }
    mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )
}
pub(super) fn entry() -> Result<i32> {
    let mut arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|name| name == "__native-sandbox")
    {
        arguments.remove(0);
    }
    let mut args = arguments.clone().into_iter();
    if args.next().as_deref() == Some(std::ffi::OsStr::new("--probe")) {
        if let Some(group) = args.next() {
            fs::write(
                Path::new(&group).join("cgroup.procs"),
                std::process::id().to_string(),
            )
            .map_err(|_| ExecutorError("native_cgroup_migration_denied"))?;
        }
        return probe_isolation();
    }
    let mut args = arguments.into_iter();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--manifest")) {
        return Err(ExecutorError("invalid_native_invocation"));
    }
    let manifest = PathBuf::from(
        args.next()
            .ok_or(ExecutorError("invalid_native_invocation"))?,
    );
    let sandbox: Sandbox = serde_json::from_slice(
        &crate::provenance::read_bounded(&manifest, 65536).map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?;
    let mut env = BTreeMap::<OsString, OsString>::new();
    loop {
        let name = args
            .next()
            .ok_or(ExecutorError("invalid_native_invocation"))?;
        if name == "--env" {
            let key = args
                .next()
                .ok_or(ExecutorError("invalid_native_invocation"))?;
            if let Some(value) = std::env::var_os(&key) {
                env.insert(key, value);
            }
        } else if name == sandbox.image.as_str() {
            break;
        } else {
            return Err(ExecutorError("invalid_native_invocation"));
        }
    }
    if !sandbox.patch {
        let environment = sandbox.job_dir.join("runtime-secrets/.environment");
        if environment.exists() {
            let text = String::from_utf8(
                crate::provenance::read_bounded(&environment, 1024 * 1024)
                    .map_err(|_| unavailable())?,
            )
            .map_err(|_| unavailable())?;
            for line in text.lines() {
                let (key, value) = line
                    .split_once('=')
                    .ok_or(ExecutorError("invalid_credential_environment"))?;
                env.insert(key.into(), value.into());
            }
        }
        for (directory, key, value) in [
            ("runtime-key", "XDG_CONFIG_HOME", "/run/lockyard-config"),
            (
                "runtime-secrets",
                "LOCKYARD_SECRETS_DIR",
                "/run/lockyard-secrets",
            ),
            (
                "runtime-context",
                "LOCKYARD_WORKFLOW_INPUTS_FILE",
                "/run/lockyard-context/workflow-inputs.json",
            ),
            (
                "runtime-delegation",
                "LOCKYARD_NODE_CONFIG",
                "/run/lockyard-delegation/node.toml",
            ),
        ] {
            if sandbox.job_dir.join(directory).exists() {
                env.insert(key.into(), value.into());
            }
        }
    }
    // No job code can run before it is inside its enforced cgroup.
    checked_root(sandbox.cgroup.parent().ok_or_else(unavailable)?)?;
    fs::create_dir(&sandbox.cgroup).map_err(|_| unavailable())?;
    configure(
        &sandbox.cgroup,
        sandbox.memory_mb,
        sandbox.cpu_millis,
        sandbox.pids_limit,
    )?;
    fs::write(
        sandbox.cgroup.join("cgroup.procs"),
        std::process::id().to_string(),
    )
    .map_err(|_| unavailable())?;
    if matches!(sandbox.network, ContainerNetwork::Bridge) {
        if let Some(code) = bridge_start(&sandbox)? {
            return Ok(code);
        }
    } else {
        namespaces()?;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(unavailable());
    }
    if pid > 0 {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                return Ok(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(unavailable());
            }
        }
    }
    // This is the new namespace's PID 1. Its workload child may create descendants;
    // PID1 exits only after the main process has a result, which kills the namespace.
    setup_root(&sandbox)?;
    syscall(unsafe { libc::sethostname(c"lockyard".as_ptr().cast(), 8) })?;
    harden()?;
    let mut command = Command::new(&sandbox.program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/tmp")
        .env("TMPDIR", "/tmp")
        .envs(env);
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(unavailable());
    }
    if child == 0 {
        let error = command.exec();
        eprintln!("native_exec_failed: {}", error.kind());
        unsafe { libc::_exit(126) };
    }
    loop {
        let mut status = 0;
        let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
        if reaped == child {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
        }
        if reaped < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(unavailable());
        }
    }
}

fn harden() -> Result<()> {
    // Closing inherited host FDs is essential after chroot. stdio are the sole exception.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) } < 0 {
        return Err(ExecutorError("native_close_range_unavailable"));
    }
    for cap in 0..=40 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) } < 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
        {
            return Err(ExecutorError("native_capability_drop_unavailable"));
        }
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe { libc::syscall(libc::SYS_capset, &header, &data) } < 0 {
        return Err(ExecutorError("native_capability_drop_unavailable"));
    }
    seccomp()?;
    Ok(())
}

fn probe_isolation() -> Result<i32> {
    namespaces()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ExecutorError("native_pid_namespace_unavailable"));
    }
    if pid > 0 {
        let mut status = 0;
        loop {
            let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
            if reaped == pid {
                break;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(unavailable());
            }
        }
        let _ = fs::remove_dir(format!("/tmp/lockyard-capability-probe-{pid}"));
        return Ok(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            125
        });
    }
    syscall(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    // getpid is namespace-local (1); /proc/self reports the host PID until fresh proc is mounted.
    let host_pid = fs::read_link("/proc/self").map_err(|_| unavailable())?;
    let root = PathBuf::from(format!(
        "/tmp/lockyard-capability-probe-{}",
        host_pid.display()
    ));
    fs::create_dir(&root).map_err(|_| ExecutorError("native_probe_directory_unavailable"))?;
    mount(
        None,
        &root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=1048576,mode=0700"),
    )
    .map_err(|_| ExecutorError("native_tmpfs_unavailable"))?;
    // Exercise the same bind/remount policy as setup_root. A tmpfs/proc-only probe
    // misses host mount flags locked by the new user namespace (notably /dev noexec).
    bind(Path::new("/usr"), &root.join("image"), true)?;
    bind(
        &std::env::current_dir().map_err(|_| unavailable())?,
        &root.join("work"),
        false,
    )?;
    fs::create_dir(root.join("dev")).map_err(|_| unavailable())?;
    for name in ["null", "zero", "random", "urandom"] {
        bind_device(&Path::new("/dev").join(name), &root.join("dev").join(name))?;
    }
    fs::create_dir(root.join("proc")).map_err(|_| unavailable())?;
    mount(
        None,
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
    .map_err(|_| ExecutorError("native_procfs_unavailable"))?;
    let root = CString::new(root.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    syscall(unsafe { libc::chroot(root.as_ptr()) })
        .map_err(|_| ExecutorError("native_chroot_unavailable"))?;
    std::env::set_current_dir("/").map_err(|_| unavailable())?;
    harden()?;
    Ok(0)
}
