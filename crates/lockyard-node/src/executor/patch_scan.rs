// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_patch_credentials(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    revision: &str,
    name: &str,
    limit: u64,
    matcher: &Arc<CredentialMatcher>,
    git_args: &[String],
    pathspecs: &[String],
    budget: &PatchBudget<'_>,
) -> Result<()> {
    if matcher.automaton.is_none() {
        return Ok(());
    }
    let mut args: Vec<OsString> = [
        "diff",
        "--cached",
        "--raw",
        "-z",
        "--no-renames",
        "--no-abbrev",
        revision,
        "--",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.extend(pathspecs.iter().map(OsString::from));
    let raw = patch_git_output(
        profile,
        job_dir,
        worktree,
        &format!("{name}-scan-list"),
        git_args,
        &args,
        limit.min(1024 * 1024),
        budget,
    )?;
    if matcher.contains(&raw) {
        return Err(ExecutorError("patch_contains_forwarded_credential"));
    }
    let mut fields = raw.split(|byte| *byte == 0);
    let mut objects = BTreeSet::new();
    let mut paths = Vec::new();
    while let Some(header) = fields.next() {
        if header.is_empty() {
            break;
        }
        let text = std::str::from_utf8(header)
            .map_err(|_| ExecutorError("patch_credential_scan_failed"))?;
        let columns: Vec<_> = text.split_ascii_whitespace().collect();
        if columns.len() != 5 || !columns[0].starts_with(':') {
            return Err(ExecutorError("patch_credential_scan_failed"));
        }
        for oid in [columns[2], columns[3]] {
            if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(ExecutorError("patch_credential_scan_failed"));
            }
            if oid.bytes().any(|byte| byte != b'0') {
                objects.insert(oid.to_string());
            }
        }
        let path = fields
            .next()
            .ok_or(ExecutorError("patch_credential_scan_failed"))?;
        if path.is_empty() {
            return Err(ExecutorError("patch_credential_scan_failed"));
        }
        if columns[3].bytes().any(|byte| byte != b'0') {
            paths.push(path.to_vec());
        }
    }
    if paths.len() + objects.len() > MAX_PATCH_SCAN_ENTRIES {
        return Err(ExecutorError("patch_credential_scan_entries"));
    }
    let mut scanned = raw.len() as u64;
    for (index, oid) in objects.iter().enumerate() {
        let remaining = limit
            .checked_sub(scanned)
            .ok_or(ExecutorError("patch_credential_scan_limit"))?;
        let args = [
            OsString::from("cat-file"),
            OsString::from("blob"),
            OsString::from(oid),
        ];
        scanned += patch_git_scan_blob(
            profile,
            job_dir,
            worktree,
            &format!("{name}-scan-blob-{index}"),
            git_args,
            &args,
            remaining,
            matcher,
            budget,
        )?;
    } // Index clean filters can transform content. Also hash the unfiltered worktree bytes inside
    // the container, then inspect those raw objects. No host path/symlink is ever opened here.
    for (index, path) in paths.into_iter().enumerate() {
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(path)
        };
        #[cfg(not(unix))]
        let path = OsString::from(
            String::from_utf8(path).map_err(|_| ExecutorError("patch_credential_scan_failed"))?,
        );
        let args = [
            OsString::from("hash-object"),
            OsString::from("--no-filters"),
            OsString::from("-w"),
            OsString::from("--"),
            path,
        ];
        let output = patch_git_output(
            profile,
            job_dir,
            worktree,
            &format!("{name}-scan-raw-{index}"),
            git_args,
            &args,
            128,
            budget,
        )?;
        let oid = std::str::from_utf8(&output)
            .map_err(|_| ExecutorError("patch_credential_scan_failed"))?
            .trim();
        if ![40, 64].contains(&oid.len()) || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ExecutorError("patch_credential_scan_failed"));
        }
        if objects.insert(oid.to_string()) {
            let remaining = limit
                .checked_sub(scanned)
                .ok_or(ExecutorError("patch_credential_scan_limit"))?;
            let args = [
                OsString::from("cat-file"),
                OsString::from("blob"),
                OsString::from(oid),
            ];
            scanned += patch_git_scan_blob(
                profile,
                job_dir,
                worktree,
                &format!("{name}-scan-raw-blob-{index}"),
                git_args,
                &args,
                remaining,
                matcher,
                budget,
            )?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn patch_git_scan_blob(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    name: &str,
    git_args: &[String],
    args: &[OsString],
    limit: u64,
    matcher: &Arc<CredentialMatcher>,
    budget: &PatchBudget<'_>,
) -> Result<u64> {
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
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let timeout = budget.remaining()?;
    let mut child = command.spawn().map_err(io_error)?;
    let stdout = child.stdout.take().unwrap();
    if set_pipe_nonblocking(&stdout).is_err() {
        terminate_group(child.id());
        let _ = child.wait();
        if !stop_container(profile, job_dir, name) {
            return Err(ExecutorError("patch_container_stop_unconfirmed"));
        }
        return Err(ExecutorError("pipe_nonblocking_failed"));
    }
    let matcher = matcher.clone();
    let pipe_stopped = Arc::new(AtomicBool::new(false));
    let reader_stopped = pipe_stopped.clone();
    let reader = match thread::Builder::new()
        .name("lockyard-patch-scan".into())
        .spawn(move || {
            scan_credential_stream_matched(
                StoppablePipe {
                    reader: stdout,
                    stopped: reader_stopped,
                    stopped_at: None,
                },
                &matcher,
                limit,
            )
        }) {
        Ok(reader) => reader,
        Err(_) => {
            terminate_group(child.id());
            let _ = child.wait();
            if !stop_container(profile, job_dir, name) {
                return Err(ExecutorError("patch_container_stop_unconfirmed"));
            }
            return Err(ExecutorError("patch_reader_spawn_failed"));
        }
    };
    let started = Instant::now();
    let mut stop_confirmed = None;
    let success = loop {
        if started.elapsed() >= timeout || budget.cancel.load(Ordering::SeqCst) {
            terminate_group(child.id());
            let _ = child.wait();
            stop_confirmed = Some(stop_container(profile, job_dir, name));
            break false;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                terminate_group(child.id());
                let _ = child.wait();
                stop_confirmed = Some(stop_container(profile, job_dir, name));
                break false;
            }
        }
    };
    let confirmed = stop_confirmed.unwrap_or_else(|| stop_container(profile, job_dir, name));
    pipe_stopped.store(true, Ordering::SeqCst);
    let result = reader.join();
    if !confirmed {
        return Err(ExecutorError("patch_container_stop_unconfirmed"));
    }
    let result = result.map_err(|_| ExecutorError("patch_scan_thread_failed"))?;
    if !success {
        return Err(ExecutorError(if budget.cancel.load(Ordering::SeqCst) {
            "patch_collection_cancelled"
        } else {
            "patch_credential_scan_failed"
        }));
    }
    result
}

#[cfg(test)]
pub(super) fn scan_credential_stream(
    reader: impl Read,
    secrets: &[Vec<u8>],
    limit: u64,
) -> Result<u64> {
    scan_credential_stream_matched(reader, &CredentialMatcher::new(secrets)?, limit)
}
pub(super) fn scan_credential_stream_matched(
    mut reader: impl Read,
    matcher: &CredentialMatcher,
    limit: u64,
) -> Result<u64> {
    let overlap = matcher.longest.saturating_sub(1);
    let mut tail = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    let mut failure = None;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ExecutorError("patch_scan_read_failed")),
        };
        total = total.saturating_add(count as u64);
        if failure.is_none() {
            tail.extend_from_slice(&buffer[..count]);
            if matcher.contains(&tail) {
                failure = Some("patch_contains_forwarded_credential");
            } else if total > limit {
                failure = Some("patch_credential_scan_limit");
            }
            let keep = tail.len().min(overlap);
            tail.drain(..tail.len() - keep);
        }
        // Continue draining after detection/limit failures. Memory stays bounded by overlap+8KiB.
    }
    match failure {
        Some(code) => Err(ExecutorError(code)),
        None => Ok(total),
    }
}
