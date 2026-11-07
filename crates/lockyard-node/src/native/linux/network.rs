// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::sandbox::{namespaces, syscall};
use super::*;
use std::process::Stdio;
pub(super) fn bridge_start(sandbox: &Sandbox) -> Result<Option<i32>> {
    use std::{
        io::Read,
        os::{fd::AsRawFd, unix::net::UnixStream},
    };
    let provider = sandbox
        .network_program
        .as_deref()
        .ok_or(ExecutorError("native_network_unavailable"))?;
    let (mut parent, mut worker) = UnixStream::pair().map_err(|_| unavailable())?;
    parent
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| unavailable())?;
    worker
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| unavailable())?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(unavailable());
    }
    if pid == 0 {
        drop(parent);
        namespaces()?;
        worker.write_all(b"N").map_err(|_| unavailable())?;
        let mut ready = [0];
        worker.read_exact(&mut ready).map_err(|_| unavailable())?;
        if ready != *b"G" {
            return Err(ExecutorError("native_network_unavailable"));
        }
        return Ok(None);
    }
    drop(worker);
    let mut ready = [0];
    if parent.read_exact(&mut ready).is_err() || ready != *b"N" {
        return Err(ExecutorError("native_network_unavailable"));
    }
    let (mut ready_reader, ready_writer) = UnixStream::pair().map_err(|_| unavailable())?;
    ready_reader
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| unavailable())?;
    syscall(unsafe { libc::fcntl(ready_writer.as_raw_fd(), libc::F_SETFD, 0) })?;
    let mut slirp = Command::new(provider)
        .args([
            "--configure",
            "--disable-host-loopback",
            "--enable-sandbox",
            "--enable-seccomp",
            // slirp's sandbox parent derives its user namespace from the target PID.
            // Path mode leaves that PID unset even when --userns-path is supplied,
            // so an unprivileged parent cannot become namespace-root for sandboxing.
            "--netns-type=pid",
        ])
        .arg(format!("--ready-fd={}", ready_writer.as_raw_fd()))
        .arg(pid.to_string())
        .arg("tap0")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ExecutorError("native_network_unavailable"))?;
    drop(ready_writer);
    let result = (|| {
        ready_reader
            .read_exact(&mut ready)
            .map_err(|_| ExecutorError("native_network_unavailable"))?;
        if ready != *b"1" {
            return Err(ExecutorError("native_network_unavailable"));
        }
        parent.write_all(b"G").map_err(|_| unavailable())?;
        loop {
            let mut status = 0;
            let reaped = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if reaped == pid {
                return Ok(Some(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                }));
            }
            if reaped < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return Err(unavailable());
            }
            if slirp.try_wait().map_err(|_| unavailable())?.is_some() {
                return Err(ExecutorError("native_network_unavailable"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    let _ = slirp.kill();
    let _ = slirp.wait();
    if result.is_err() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
    }
    result
}
