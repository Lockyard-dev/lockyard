// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

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
