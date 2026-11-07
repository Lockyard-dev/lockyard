// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn runtime_command(profile: &ContainerProfile, job_dir: &Path) -> Command {
    let mut command = Command::new(&profile.runtime_program);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    // Empty per-job client config prevents ambient Docker proxy/credential settings leaking in.
    command.env("DOCKER_CONFIG", job_dir.join("runtime-config"));
    match profile.runtime {
        ContainerRuntime::Native => {}
        ContainerRuntime::Docker => {
            command.arg("--host=unix:///var/run/docker.sock");
        }
        ContainerRuntime::Podman => {
            command.arg("--remote=false");
            if let Some(path) = std::env::var_os("XDG_RUNTIME_DIR") {
                command.env("XDG_RUNTIME_DIR", path);
            }
        }
    }
    command.current_dir(job_dir);
    command
}

pub(super) fn host_container_identity() -> String {
    #[cfg(unix)]
    {
        format!("{}:{}", unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })
    }
    #[cfg(not(unix))]
    {
        "0:0".into()
    }
}
pub(super) fn container_identity(job_dir: &Path) -> Result<String> {
    let mut file = private_open_existing(&job_dir.join("runtime-user"))?;
    let mut value = String::new();
    Read::by_ref(&mut file)
        .take(64)
        .read_to_string(&mut value)
        .map_err(io_error)?;
    let Some((uid, gid)) = value.split_once(':') else {
        return Err(ExecutorError("runtime_identity_unavailable"));
    };
    if uid.parse::<u32>().is_err() || gid.parse::<u32>().is_err() {
        return Err(ExecutorError("runtime_identity_unavailable"));
    }
    Ok(value)
}

pub(super) fn container_command(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    program: &Path,
    name: &str,
    patch: bool,
) -> Result<Command> {
    if matches!(profile.runtime, ContainerRuntime::Native) {
        return crate::native::command(profile, job_dir, worktree, program, name, patch);
    }
    let identity = container_identity(job_dir)?;
    let mut command = runtime_command(profile, job_dir);
    command
        .args([
            "run",
            "--pull=never",
            "--no-healthcheck",
            "--name",
            name,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--ipc=none",
            "--user",
            &identity,
            "--pids-limit",
        ])
        .arg(profile.pids_limit.to_string())
        .arg("--memory")
        .arg(format!("{}m", profile.memory_mb))
        .arg("--memory-swap")
        .arg(format!("{}m", profile.memory_mb))
        .arg("--cpus")
        .arg(format!(
            "{}.{:03}",
            profile.cpu_millis / 1000,
            profile.cpu_millis % 1000
        ))
        .arg("--network")
        .arg(
            if patch || matches!(profile.network, ContainerNetwork::None) {
                "none"
            } else {
                "bridge"
            },
        )
        .args([
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=67108864",
            "--env",
            "HOME=/tmp",
            "--env",
            "TMPDIR=/tmp",
        ])
        .arg("--workdir")
        .arg(worktree)
        .arg("--entrypoint")
        .arg(program);
    for path in [worktree.to_path_buf(), job_dir.join("repository.git")] {
        let path = path
            .to_str()
            .ok_or(ExecutorError("invalid_container_mount"))?;
        if path.contains([',', ':', '\n', '\r']) {
            return Err(ExecutorError("invalid_container_mount"));
        }
        let readonly = if patch && Path::new(path) == worktree {
            ",readonly"
        } else {
            ""
        };
        command
            .arg("--mount")
            .arg(format!("type=bind,src={path},dst={path}{readonly}"));
    }
    if !patch && job_dir.join("runtime-key").exists() {
        let path = job_dir.join("runtime-key");
        private_dir(&path)?;
        let path = path
            .to_str()
            .ok_or(ExecutorError("invalid_container_mount"))?;
        command
            .arg("--mount")
            .arg(format!(
                "type=bind,src={path},dst=/run/lockyard-config,readonly"
            ))
            .args(["--env", "XDG_CONFIG_HOME=/run/lockyard-config"]);
    }
    if !patch && job_dir.join("runtime-secrets").exists() {
        let path = job_dir.join("runtime-secrets");
        private_dir(&path)?;
        let path_text = path
            .to_str()
            .ok_or(ExecutorError("invalid_container_mount"))?;
        if path_text.contains([',', ':', '\n', '\r']) {
            return Err(ExecutorError("invalid_container_mount"));
        }
        command
            .arg("--mount")
            .arg(format!(
                "type=bind,src={path_text},dst=/run/lockyard-secrets,readonly"
            ))
            .args(["--env", "LOCKYARD_SECRETS_DIR=/run/lockyard-secrets"]);
        let environment = path.join(".environment");
        if environment.exists() {
            private_open_existing(&environment)?;
            // Runtime client reads a private file; values never enter its argv or environment.
            command.arg("--env-file").arg(environment);
        }
    }
    for (directory, destination, variable, relative) in [
        (
            "runtime-context",
            "/run/lockyard-context",
            "LOCKYARD_WORKFLOW_INPUTS_FILE",
            "workflow-inputs.json",
        ),
        (
            "runtime-delegation",
            "/run/lockyard-delegation",
            "LOCKYARD_NODE_CONFIG",
            "node.toml",
        ),
    ] {
        if !patch && job_dir.join(directory).exists() {
            let path = job_dir.join(directory);
            private_dir(&path)?;
            let path_text = path
                .to_str()
                .ok_or(ExecutorError("invalid_container_mount"))?;
            if path_text.contains([',', ':', '\n', '\r']) {
                return Err(ExecutorError("invalid_container_mount"));
            }
            command
                .arg("--mount")
                .arg(format!(
                    "type=bind,src={path_text},dst={destination},readonly"
                ))
                .args(["--env", &format!("{variable}={destination}/{relative}")]);
        }
    }
    Ok(command)
}

pub(super) fn bounded_status(
    command: &mut Command,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(io_error)?;
    let started = Instant::now();
    loop {
        if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) || started.elapsed() >= timeout {
            terminate_group(child.id());
            let _ = child.wait();
            return Err(ExecutorError(
                if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
                    "setup_cancelled"
                } else {
                    "setup_timed_out"
                },
            ));
        }
        if let Some(status) = child.try_wait().map_err(io_error)? {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn verify_runtime_limits(profile: &ContainerProfile, job_dir: &Path) -> Result<()> {
    if matches!(profile.runtime, ContainerRuntime::Native) {
        let capabilities =
            crate::native::capabilities(profile.cgroup_root.as_deref(), &profile.runtime_program);
        return if capabilities.available {
            Ok(())
        } else {
            Err(ExecutorError("container_limits_unavailable"))
        };
    }
    let mut command = runtime_command(profile, job_dir);
    match profile.runtime {
        ContainerRuntime::Native => unreachable!(),
        ContainerRuntime::Docker => {
            command.args([
                "info",
                "--format",
                "{{.MemoryLimit}} {{.CPUCfsQuota}} {{.PidsLimit}}",
            ]);
        }
        ContainerRuntime::Podman => {
            command.args(["info", "--format", "{{json .Host.CgroupControllers}}"]);
        }
    }
    let bytes = probe_runtime(&mut command)?;
    let text = String::from_utf8_lossy(&bytes);
    let verified =
        match profile.runtime {
            ContainerRuntime::Native => unreachable!(),
            ContainerRuntime::Docker => text.trim() == "true true true",
            ContainerRuntime::Podman => serde_json::from_str::<Vec<String>>(&text)
                .ok()
                .is_some_and(|controllers| {
                    ["memory", "cpu", "pids"]
                        .iter()
                        .all(|required| controllers.iter().any(|controller| controller == required))
                }),
        };
    if !verified {
        return Err(ExecutorError("container_limits_unavailable"));
    }
    let mut image = runtime_command(profile, job_dir);
    image.args([
        "image",
        "inspect",
        "--format",
        "{{json .Config.Volumes}}",
        &profile.image,
    ]);
    let volumes =
        probe_runtime(&mut image).map_err(|_| ExecutorError("container_image_unavailable"))?;
    let volumes: serde_json::Value = serde_json::from_slice(&volumes)
        .map_err(|_| ExecutorError("container_image_probe_failed"))?;
    if !volumes.is_null()
        && !volumes
            .as_object()
            .is_some_and(|volumes| volumes.is_empty())
    {
        return Err(ExecutorError("container_image_declares_volumes"));
    }
    let mut security = runtime_command(profile, job_dir);
    security.args([
        "info",
        "--format",
        match profile.runtime {
            ContainerRuntime::Native => unreachable!(),
            ContainerRuntime::Docker => "{{json .SecurityOptions}}",
            ContainerRuntime::Podman => "{{.Host.Security.Rootless}}",
        },
    ]);
    let value = probe_runtime(&mut security)?;
    let rootless = match profile.runtime {
        ContainerRuntime::Native => unreachable!(),
        ContainerRuntime::Docker => serde_json::from_slice::<Vec<String>>(&value)
            .map_err(|_| ExecutorError("runtime_identity_unavailable"))?
            .iter()
            .any(|entry| entry == "name=rootless"),
        ContainerRuntime::Podman => serde_json::from_slice::<bool>(&value)
            .map_err(|_| ExecutorError("runtime_identity_unavailable"))?,
    };
    let identity = if rootless {
        "0:0".to_string()
    } else {
        host_container_identity()
    };
    let mut file = private_open(&job_dir.join("runtime-user"), true)?;
    file.write_all(identity.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    Ok(())
}

pub(super) fn admit_image(profile: &ContainerProfile, job_dir: &Path) -> Result<VerifiedImage> {
    let policy = profile
        .supply_chain
        .as_ref()
        .ok_or(ExecutorError("supply_chain_policy_required"))?;
    let admission = crate::supply_chain::verify_image(policy, &profile.image, now_ms())
        .map_err(|error| ExecutorError(error.0))?;
    if matches!(profile.runtime, ContainerRuntime::Native) {
        let rootfs = profile
            .native_rootfs
            .as_deref()
            .ok_or(ExecutorError("native_rootfs_unavailable"))?;
        let actual = crate::native::rootfs_digest(rootfs)?;
        if actual != admission.image_config_digest || actual != admission.image_digest {
            return Err(ExecutorError("native_rootfs_identity_mismatch"));
        }
        return Ok(admission);
    }
    let mut inspect = runtime_command(profile, job_dir);
    inspect.args(["image", "inspect", "--format", "{{.Id}}", &profile.image]);
    let bytes = probe_runtime(&mut inspect)
        .map_err(|_| ExecutorError("container_image_identity_unavailable"))?;
    let actual = std::str::from_utf8(&bytes)
        .map(str::trim)
        .map_err(|_| ExecutorError("container_image_identity_unavailable"))?;
    let actual = if crate::provenance::valid_sha256(actual) {
        format!("sha256:{actual}")
    } else {
        actual.into()
    };
    if actual != admission.image_config_digest {
        return Err(ExecutorError("container_image_identity_mismatch"));
    }
    Ok(admission)
}

pub(super) fn probe_runtime(command: &mut Command) -> Result<Vec<u8>> {
    let (status, output, _) = runtime_output(command, Duration::from_secs(5), 4096, None)
        .map_err(|_| ExecutorError("container_runtime_unavailable"))?;
    if !status.success() {
        return Err(ExecutorError("container_runtime_unavailable"));
    }
    Ok(output)
}

pub(super) fn stop_container(profile: &ContainerProfile, job_dir: &Path, name: &str) -> bool {
    if matches!(profile.runtime, ContainerRuntime::Native) {
        return crate::native::stop(profile, job_dir, name);
    }
    let mut remove = runtime_command(profile, job_dir);
    remove
        .args(["container", "rm", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if bounded_status(&mut remove, Duration::from_secs(5), None)
        .is_ok_and(|status| status.success())
    {
        return true;
    }
    let mut command = runtime_command(profile, job_dir);
    command
        .args(["kill", "--signal", "KILL", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let kill_confirmed = bounded_status(&mut command, Duration::from_secs(5), None)
        .is_ok_and(|status| status.success());
    let mut inspect = runtime_command(profile, job_dir);
    inspect.args(["container", "inspect", "--format", "{{json .State}}", name]);
    let Ok((status, output, error)) =
        runtime_output(&mut inspect, Duration::from_secs(5), 4096, None)
    else {
        return false;
    };
    if status.success() {
        let Ok(state) = serde_json::from_slice::<serde_json::Value>(&output) else {
            return false;
        };
        let stopped = matches!(
            state.get("Status").and_then(serde_json::Value::as_str),
            Some("exited" | "dead")
        ) && state.get("Running").and_then(serde_json::Value::as_bool) == Some(false)
            && state.get("Paused").and_then(serde_json::Value::as_bool) == Some(false)
            && state.get("Restarting").and_then(serde_json::Value::as_bool) == Some(false);
        if stopped {
            let mut remove = runtime_command(profile, job_dir);
            remove
                .args(["container", "rm", name])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = bounded_status(&mut remove, Duration::from_secs(5), None);
        }
        return stopped;
    }
    // Absence alone cannot settle a run/create request still in flight. Only an acknowledged
    // kill followed by the runtime's exact not-found response establishes automatic removal.
    if !kill_confirmed {
        return false;
    }
    let text = String::from_utf8_lossy(&error);
    match profile.runtime {
        ContainerRuntime::Native => unreachable!(),
        ContainerRuntime::Docker => [
            format!("Error: No such container: {name}"),
            format!("Error: No such object: {name}"),
            format!("Error response from daemon: No such container: {name}"),
        ]
        .iter()
        .any(|expected| text.trim() == expected),
        ContainerRuntime::Podman => {
            text.trim()
                == format!(
                    "Error: no container with name or ID \"{name}\" found: no such container"
                )
        }
    }
}

pub(super) fn runtime_output(
    command: &mut Command,
    timeout: Duration,
    limit: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(io_error)?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let started = Instant::now();
    let mut status = None;
    let outcome = (|| {
        set_pipe_nonblocking(&stdout)?;
        set_pipe_nonblocking(&stderr)?;
        let (mut output, mut error) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if started.elapsed() >= timeout
                || cancel.is_some_and(|flag| flag.load(Ordering::SeqCst))
            {
                return Err(ExecutorError("runtime_output_timeout"));
            }
            if status.is_none() {
                status = child.try_wait().map_err(io_error)?;
            }
            let mut progress = false;
            for (pipe, bytes, eof) in [
                (&mut stdout as &mut dyn Read, &mut output, &mut out_eof),
                (&mut stderr as &mut dyn Read, &mut error, &mut err_eof),
            ] {
                if *eof {
                    continue;
                }
                let mut buffer = [0u8; 8192];
                match pipe.read(&mut buffer) {
                    Ok(0) => {
                        *eof = true;
                        progress = true;
                    }
                    Ok(n) => {
                        if bytes.len().saturating_add(n) as u64 > limit {
                            return Err(ExecutorError("runtime_output_limit"));
                        }
                        bytes.extend_from_slice(&buffer[..n]);
                        progress = true;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(io_error(error)),
                }
            }
            if out_eof
                && err_eof
                && let Some(status) = status
            {
                return Ok((status, output, error));
            }
            if !progress {
                thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    if outcome.is_err() && status.is_none() {
        terminate_group(child.id());
        let _ = child.wait();
    }
    outcome
}

#[cfg(unix)]
pub(super) fn set_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ExecutorError("pipe_nonblocking_failed"));
    }
    Ok(())
}
#[cfg(not(unix))]
pub(super) fn set_pipe_nonblocking<T>(_pipe: &T) -> Result<()> {
    Err(ExecutorError("execution_requires_unix"))
}

pub(super) fn terminate_group(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(-(pid as i32), libc::SIGTERM);
        }
        // A bounded grace period applies to the entire child process group.
        for _ in 0..10 {
            if unsafe { libc::kill(-(pid as i32), 0) } != 0 {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}
