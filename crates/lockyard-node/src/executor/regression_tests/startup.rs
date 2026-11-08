// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn last_public_owner_joins_terminal_workers_before_immediate_restart() {
    // Terminal visibility does not mean the worker has completed its finalization.
    // Keep that phase parked so the old detached-owner race is deterministic.
    let (_root, executor, ids) = synthetic_queue(1, 1);
    let config = executor.inner.config.clone();
    let (terminal_tx, terminal_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    install_worker_hook(
        &executor,
        Arc::new(move |executor, id, _cancel| {
            executor.update(id, |record| record.state = JobState::Succeeded)?;
            terminal_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            Ok(())
        }),
    );
    executor.launch_ready().unwrap();
    terminal_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(executor.status(&ids[0]).unwrap().state, JobState::Succeeded);
    let (dropping_tx, dropping_rx) = std::sync::mpsc::sync_channel(1);
    let (restarted_tx, restarted_rx) = std::sync::mpsc::sync_channel(1);
    let dropping = thread::spawn(move || {
        dropping_tx.send(()).unwrap();
        drop(executor);
        assert!(restarted_tx.send(Executor::new(config)).is_ok());
    });
    dropping_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let premature = restarted_rx.recv_timeout(Duration::from_millis(100));
    // Always release the fixture, including when the old implementation returns early.
    release_tx.send(()).unwrap();
    dropping.join().unwrap();
    assert!(
        matches!(premature, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
        "dropping the last public owner returned before its terminal worker exited"
    );
    let restarted = restarted_rx.recv().unwrap();
    assert!(
        restarted.is_ok(),
        "immediate restart failed: {:?}",
        restarted.err()
    );
}

#[test]
fn public_clones_keep_active_work_detached_and_state_locked() {
    let (_root, executor, ids) = synthetic_queue(1, 1);
    let config = executor.inner.config.clone();
    let state_dir = config.state_dir.clone();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    install_worker_hook(
        &executor,
        Arc::new(move |executor, id, _cancel| {
            started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            executor.update(id, |record| record.state = JobState::Succeeded)?;
            Ok(())
        }),
    );
    let other = executor.clone();
    executor.launch_ready().unwrap();
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    drop(executor);
    assert_eq!(other.status(&ids[0]).unwrap().state, JobState::Starting);
    drop(other);
    // Active execution still owns the journal after all caller handles are gone.
    assert!(
        matches!(Executor::new(config.clone()), Err(error) if error.0 == "executor_already_running")
    );
    release_tx.send(()).unwrap();
    // This case deliberately detached active work. Observe its actual lock release,
    // rather than an Arc strong count which reaches zero before Inner::drop runs.
    use std::os::fd::AsRawFd;
    let lock = File::open(config.state_dir.join("executor.lock")).unwrap();
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
    drop(lock);
    WORKER_RUN_HOOKS
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .remove(&state_dir);
    assert!(Executor::new(config).is_ok());
}

#[test]
fn terminal_worker_panic_does_not_panic_in_drop_or_leave_the_state_locked() {
    let (_root, executor, ids) = synthetic_queue(1, 1);
    let config = executor.inner.config.clone();
    install_worker_hook(
        &executor,
        Arc::new(move |executor, id, _cancel| {
            executor.update(id, |record| record.state = JobState::Succeeded)?;
            panic!("synthetic terminal worker panic");
        }),
    );
    executor.launch_ready().unwrap();
    wait_queue(|| executor.status(&ids[0]).unwrap().state.is_terminal());
    drop(executor);
    assert!(Executor::new(config).is_ok());
}

#[test]
fn pending_maintenance_is_rechecked_after_acquiring_the_executor_lock_before_recovery() {
    use std::os::fd::AsRawFd;
    for rotation in [false, true] {
        let (_root, config, executor) = retention_fixture();
        let record = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
        let journal = config
            .state_dir
            .join("jobs")
            .join(&record.spec.id)
            .join("record.json");
        let before = fs::read(&journal).unwrap();
        drop(executor);
        let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(1);
        OPEN_TEST_HOOKS
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap()
            .insert(
                config.state_dir.clone(),
                Box::new(move || {
                    reached_tx.send(()).unwrap();
                    resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }),
            );
        let opening = config.clone();
        let constructor = thread::spawn(move || Executor::new(opening));
        reached_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let maintenance = private_open(&config.state_dir.join("executor.lock"), false).unwrap();
        assert_eq!(
            unsafe { libc::flock(maintenance.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let parent = config.state_dir.parent().unwrap();
        let marker = if rotation {
            parent.join("workspace-rotation.pending.json")
        } else {
            private_dir(&parent.join("managed-updates")).unwrap();
            parent.join("managed-updates/pending.json")
        };
        let mut file = private_open(&marker, true).unwrap();
        file.write_all(b"{}").unwrap();
        file.sync_all().unwrap();
        File::open(marker.parent().unwrap())
            .unwrap()
            .sync_all()
            .unwrap();
        unsafe {
            libc::flock(maintenance.as_raw_fd(), libc::LOCK_UN);
        }
        drop(maintenance);
        resume_tx.send(()).unwrap();
        let error = constructor
            .join()
            .unwrap()
            .err()
            .expect("pending maintenance must block recovery");
        assert_eq!(
            error.0,
            if rotation {
                "workspace_rotation_recovery_required"
            } else {
                "managed_update_recovery_required"
            }
        );
        assert_eq!(fs::read(journal).unwrap(), before);
    }
}
#[test]
fn last_executor_owner_releases_state_lock_even_if_a_fork_inherits_its_descriptor() {
    // A helper fork before exec can inherit CLOEXEC descriptors. It must not extend
    // executor authority after the last actual Executor/job owner has been dropped.
    let (_root, config, executor) = retention_fixture();
    assert_eq!(Arc::strong_count(&executor.inner), 1);
    use std::os::fd::IntoRawFd;
    // std creates both pipe ends with close-on-exec on every supported Unix platform;
    // Darwin has no pipe2, but this test still needs descriptors inherited by fork.
    let (reader, writer) = std::io::pipe().unwrap();
    let pipe = [reader.into_raw_fd(), writer.into_raw_fd()];
    for descriptor in pipe {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }
    let child = unsafe { libc::fork() };
    if child == 0 {
        unsafe {
            libc::close(pipe[1]);
            let mut byte = 0u8;
            libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    assert!(child > 0);
    unsafe {
        libc::close(pipe[0]);
    }
    struct Child {
        pid: libc::pid_t,
        writer: libc::c_int,
    }
    impl Drop for Child {
        fn drop(&mut self) {
            unsafe {
                let byte = 1u8;
                libc::write(self.writer, (&byte as *const u8).cast(), 1);
                libc::close(self.writer);
                libc::waitpid(self.pid, std::ptr::null_mut(), 0);
            }
        }
    }
    let child = Child {
        pid: child,
        writer: pipe[1],
    };
    drop(executor);
    let reopened = Executor::new(config);
    drop(child);
    assert!(
        reopened.is_ok(),
        "last executor owner left a state lock behind: {:?}",
        reopened.err()
    );
}
