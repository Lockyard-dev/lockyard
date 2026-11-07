// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn output_timeout_covers_pipes_inherited_after_parent_exit() {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 2"]);
    // Keep a real detached descendant holding the output pipes after its immediate parent
    // exits. Native syscalls avoid depending on the Linux-only `setsid` command-line utility.
    unsafe {
        command.pre_exec(|| {
            let descendant = libc::fork();
            if descendant < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if descendant > 0 {
                libc::_exit(0);
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let started = Instant::now();
    assert_eq!(
        runtime_output(&mut command, Duration::from_millis(150), 4096, None)
            .unwrap_err()
            .0,
        "runtime_output_timeout"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn bounded_runtime_output_drains_both_streams_and_enforces_each_limit() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf out; printf err >&2"]);
    let (status, out, err) = runtime_output(&mut command, Duration::from_secs(2), 3, None).unwrap();
    assert!(status.success());
    assert_eq!(out, b"out");
    assert_eq!(err, b"err");
    let mut excessive = Command::new("/bin/sh");
    excessive.args(["-c", "printf excessive >&2"]);
    assert_eq!(
        runtime_output(&mut excessive, Duration::from_secs(2), 3, None)
            .unwrap_err()
            .0,
        "runtime_output_limit"
    );
}

#[test]
fn stopped_reader_rejects_a_surviving_pipe_writer() {
    let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
    set_pipe_nonblocking(&reader).unwrap();
    let mut pipe = StoppablePipe {
        reader,
        stopped: Arc::new(AtomicBool::new(true)),
        stopped_at: None,
    };
    let mut output = [0u8; 8];
    let started = Instant::now();
    assert!(pipe.read(&mut output).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn sink_failure_preserves_partial_count_and_keeps_draining() {
    struct CountedReader {
        data: std::io::Cursor<Vec<u8>>,
        consumed: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Read for CountedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.data.read(buffer)?;
            self.consumed.fetch_add(count, Ordering::SeqCst);
            Ok(count)
        }
    }
    let consumed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let spool = Arc::new(Mutex::new(Spool {
        file: FailingWriter {
            bytes: Vec::new(),
            fail_after: 3,
        },
        bytes: 0,
        truncated: false,
        limit: 65536,
        error: None,
        credential_tail: Vec::new(),
    }));
    let data = vec![b'x'; 20000];
    let reader = CountedReader {
        data: std::io::Cursor::new(data.clone()),
        consumed: consumed.clone(),
    };
    assert_eq!(
        drain(
            reader,
            spool.clone(),
            vec![],
            Arc::new(AtomicBool::new(false))
        ),
        Err("spool_write_failed")
    );
    let spool = spool.lock().unwrap();
    assert_eq!(consumed.load(Ordering::SeqCst), data.len());
    assert_eq!(spool.bytes, 3);
    assert_eq!(spool.file.bytes.len(), 3);
    assert!(spool.truncated);
    assert_eq!(spool.error, Some("spool_write_failed"));
    let dir = tempfile::tempdir().unwrap();
    let id = "00000000000000000000000001";
    private_dir(&dir.path().join("jobs")).unwrap();
    private_dir_new(&dir.path().join("jobs").join(id)).unwrap();
    let mut record = JobRecord {
        had_runtime_credentials: true,
        spec: JobSpec {
            id: id.into(),
            repository: "repo".into(),
            revision: "HEAD".into(),
            runner: "fixture".into(),
            arguments: vec![],
            prompt: None,
            timeout_seconds: None,
            priority: 0,
            workflow_inputs: Vec::new(),
            expected_runner_sha256: None,
            owner_approval: None,
        },
        state: JobState::Succeeded,
        agent: "derived".into(),
        submitter: "peer".into(),
        submitter_certificate_sha256: None,
        created_at_ms: 1,
        updated_at_ms: 1,
        resolved_revision: None,
        worktree: None,
        pid: None,
        exit_code: Some(0),
        error_code: None,
        log_bytes: 0,
        log_truncated: false,
        log_error: None,
        patch_bytes: 0,
        patch_truncated: false,
        patch_error: None,
        configured_image: None,
        admission_runner_sha256: None,
        admission_repository_sha256: None,
        admitted_image: None,
        result_manifest: None,
        provenance_error: None,
        notification_accounted_certificate_sha256: None,
        retention: None,
    };
    record_log_integrity(&mut record, spool.bytes, spool.truncated, spool.error);
    persist(dir.path(), &record).unwrap();
    let stored: JobRecord = serde_json::from_slice(
        &fs::read(dir.path().join("jobs").join(id).join("record.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(stored.state, JobState::Failed);
    assert_eq!(stored.log_error.as_deref(), Some("spool_write_failed"));
    assert_eq!(stored.log_bytes, 3);
    assert!(stored.log_truncated);
}

#[test]
fn reader_and_join_failures_are_explicit_incomplete_results() {
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fixture reader failure"))
        }
    }
    let spool = Arc::new(Mutex::new(Spool {
        file: Vec::new(),
        bytes: 0,
        truncated: false,
        limit: 1024,
        error: None,
        credential_tail: Vec::new(),
    }));
    assert_eq!(
        drain(
            FailingReader,
            spool.clone(),
            vec![],
            Arc::new(AtomicBool::new(false))
        ),
        Err("stream_read_failed")
    );
    assert_eq!(spool.lock().unwrap().error, Some("stream_read_failed"));
    assert_eq!(
        join_stream(thread::spawn(|| panic!("fixture stream panic"))),
        Some("stream_thread_failed")
    );
}

#[test]
fn ambiguous_inspection_error_does_not_confirm_container_stop() {
    let dir = tempfile::tempdir().unwrap();
    private_dir_new(&dir.path().join("runtime-config")).unwrap();
    let runtime = dir.path().join("runtime-fixture");
    fs::write(
        &runtime,
        b"#!/bin/sh\ncase \"$2\" in info) exit 0;; *) exit 1;; esac\n",
    )
    .unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let profile = ContainerProfile {
        runtime: ContainerRuntime::Docker,
        cgroup_root: None,
        native_rootfs: None,
        native_network_program: None,
        runtime_program: runtime,
        image: "fixture:image".into(),
        supply_chain: None,
        git_program: "/usr/bin/git".into(),
        memory_mb: 128,
        cpu_millis: 1000,
        pids_limit: 64,
        network: ContainerNetwork::None,
    };
    assert!(!stop_container(&profile, dir.path(), "fixture"));
}
