// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[cfg(test)]
pub(super) fn collect_patch(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    revision: &str,
    name: &str,
    limit: u64,
    secrets: &[Vec<u8>],
) -> Result<(u64, bool)> {
    collect_patch_bounded(
        profile,
        job_dir,
        worktree,
        revision,
        name,
        limit,
        secrets,
        &AtomicBool::new(false),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn collect_patch_bounded(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    revision: &str,
    name: &str,
    limit: u64,
    secrets: &[Vec<u8>],
    cancel: &AtomicBool,
) -> Result<(u64, bool)> {
    let budget = PatchBudget::new(cancel);
    let metadata = job_dir.join("repository.git");
    let index = metadata.join("lockyard-export.index");
    let git_args = [
        format!("--git-dir={}", metadata.display()),
        format!("--work-tree={}", worktree.display()),
    ];
    let injections = load_injected_paths(job_dir)?;
    let mut pathspecs = vec![".".to_string()];
    pathspecs.extend(
        injections
            .iter()
            .map(|injection| format!(":(exclude,literal){}", injection.path)),
    );
    // Git evaluates job-controlled attributes/config only inside a fresh, credential-free container.
    for (suffix, args) in [
        ("read", vec!["read-tree", revision]),
        ("add", vec!["add", "-A", "--"]),
    ] {
        let patch_name = format!("{name}-{suffix}");
        let mut command = container_command(
            profile,
            job_dir,
            worktree,
            &profile.git_program,
            &patch_name,
            true,
        )?;
        command
            .env("GIT_INDEX_FILE", &index)
            .args(["--env", "GIT_INDEX_FILE"])
            .arg(&profile.image)
            .args(&git_args)
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(&args);
        if suffix == "add" {
            command.args(&pathspecs);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match bounded_status(&mut command, budget.remaining()?, Some(budget.cancel)) {
            Ok(status) if status.success() => {
                if !stop_container(profile, job_dir, &patch_name) {
                    return Err(ExecutorError("patch_container_stop_unconfirmed"));
                }
            }
            _ => {
                if !stop_container(profile, job_dir, &patch_name) {
                    return Err(ExecutorError("patch_container_stop_unconfirmed"));
                }
                return Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
                    "patch_collection_cancelled"
                } else {
                    "patch_index_failed"
                }));
            }
        }
    }
    verify_injected_paths(
        profile,
        job_dir,
        worktree,
        name,
        &git_args,
        &injections,
        &budget,
    )?;
    let credential_matcher = Arc::new(CredentialMatcher::new(secrets)?);
    scan_patch_credentials(
        profile,
        job_dir,
        worktree,
        revision,
        name,
        limit,
        &credential_matcher,
        &git_args,
        &pathspecs,
        &budget,
    )?;
    let patch_name = format!("{name}-diff");
    let mut command = container_command(
        profile,
        job_dir,
        worktree,
        &profile.git_program,
        &patch_name,
        true,
    )?;
    command
        .env("GIT_INDEX_FILE", &index)
        .args(["--env", "GIT_INDEX_FILE"])
        .arg(&profile.image)
        .args(&git_args)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            revision,
            "--",
        ])
        .args(&pathspecs)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let timeout = budget.remaining()?;
    let file = private_open(&job_dir.join("result.patch"), true)?;
    let mut child = command.spawn().map_err(io_error)?;
    let output = child.stdout.take().unwrap();
    if set_pipe_nonblocking(&output).is_err() {
        terminate_group(child.id());
        let _ = child.wait();
        if !stop_container(profile, job_dir, &patch_name) {
            return Err(ExecutorError("patch_container_stop_unconfirmed"));
        }
        return Err(ExecutorError("pipe_nonblocking_failed"));
    }
    let spool = Arc::new(Mutex::new(Spool {
        file,
        bytes: 0,
        truncated: false,
        limit,
        error: None,
        credential_tail: Vec::new(),
    }));
    let reader_spool = spool.clone();
    let matcher = Arc::new(CredentialMatcher::new(&[])?);
    let pipe_stopped = Arc::new(AtomicBool::new(false));
    let reader_stopped = pipe_stopped.clone();
    let reader = match thread::Builder::new()
        .name("lockyard-patch-reader".into())
        .spawn(move || {
            // A Git patch is a serialization: rewriting bytes would silently corrupt binary patches.
            drain_matched(
                StoppablePipe {
                    reader: output,
                    stopped: reader_stopped,
                    stopped_at: None,
                },
                reader_spool,
                matcher,
                Arc::new(AtomicBool::new(false)),
            )
        }) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_group(child.id());
            let _ = child.wait();
            if !stop_container(profile, job_dir, &patch_name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            return Err(ExecutorError("patch_reader_spawn_failed"));
        }
    };
    let started = Instant::now();
    let mut stop_confirmed = true;
    let success = loop {
        if started.elapsed() > timeout || budget.cancel.load(Ordering::SeqCst) {
            terminate_group(child.id());
            let _ = child.wait();
            stop_confirmed = stop_container(profile, job_dir, &patch_name);
            break false;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    stop_confirmed = stop_container(profile, job_dir, &patch_name);
                }
                break status.success();
            }
            Ok(None) => {}
            Err(_) => {
                terminate_group(child.id());
                let _ = child.wait();
                stop_confirmed = stop_container(profile, job_dir, &patch_name);
                break false;
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    if success {
        stop_confirmed = stop_container(profile, job_dir, &patch_name);
    }
    pipe_stopped.store(true, Ordering::SeqCst);
    let stream_error = join_stream(reader);
    if !stop_confirmed {
        return Err(ExecutorError("patch_container_stop_unconfirmed"));
    }
    if !success {
        return Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
            "patch_collection_cancelled"
        } else {
            "patch_diff_failed"
        }));
    }
    let spool = spool
        .lock()
        .map_err(|_| ExecutorError("patch_spool_poisoned"))?;
    if stream_error.is_some() || spool.error.is_some() {
        return Err(ExecutorError("patch_stream_incomplete"));
    }
    spool
        .file
        .sync_all()
        .map_err(|_| ExecutorError("patch_spool_sync_failed"))?;
    if !secrets.is_empty() {
        let mut file = spool
            .file
            .try_clone()
            .map_err(|_| ExecutorError("patch_spool_read_failed"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ExecutorError("patch_spool_read_failed"))?;
        scan_credential_stream_matched(file, &credential_matcher, limit)?;
    }
    Ok((spool.bytes, spool.truncated))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn patch_git_output(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    name: &str,
    git_args: &[String],
    args: &[OsString],
    limit: u64,
    budget: &PatchBudget<'_>,
) -> Result<Vec<u8>> {
    let mut command =
        container_command(profile, job_dir, worktree, &profile.git_program, name, true)?;
    command
        .env(
            "GIT_INDEX_FILE",
            job_dir.join("repository.git/lockyard-export.index"),
        )
        .args(["--env", "GIT_INDEX_FILE"])
        .arg(&profile.image)
        .args(git_args)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(args);
    match runtime_output(
        &mut command,
        budget.remaining()?,
        limit,
        Some(budget.cancel),
    ) {
        Ok((status, bytes, _)) if status.success() => {
            if !stop_container(profile, job_dir, name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            Ok(bytes)
        }
        _ => {
            if !stop_container(profile, job_dir, name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
                "patch_collection_cancelled"
            } else {
                "patch_credential_scan_failed"
            }))
        }
    }
}
