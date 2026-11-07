// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
#[cfg(target_os = "linux")]
fn thousand_queued_jobs_use_bounded_workers_through_finalization_and_release_every_owner() {
    // Synthetic callbacks only. No runner/provider/Git/container is invoked.
    let baseline_threads = process_stat("Threads:");
    let baseline_rss = process_stat("VmRSS:");
    let (_root, executor, ids) = synthetic_queue(1000, 4);
    let queued_threads = process_stat("Threads:");
    let queued_rss = process_stat("VmRSS:");
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tids = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
    let worker_tids = tids.clone();
    let callback_gate = gate.clone();
    let callback_started = started.clone();
    let callback_active = active.clone();
    let callback_peak = peak.clone();
    install_worker_hook(
        &executor,
        Arc::new(move |executor, id, _cancel| {
            worker_tids
                .lock()
                .unwrap()
                .insert(unsafe { libc::syscall(libc::SYS_gettid) });
            let count = callback_active.fetch_add(1, Ordering::SeqCst) + 1;
            callback_peak.fetch_max(count, Ordering::SeqCst);
            executor.update(id, |record| {
                record.state = JobState::Succeeded;
                record.exit_code = Some(0);
            })?;
            callback_started.fetch_add(1, Ordering::SeqCst);
            // Hold a terminal callback before finalization: admission must still count
            // this physical worker, even though the logical job is already terminal.
            let (lock, changed) = &*callback_gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = changed.wait(released).unwrap();
            }
            callback_active.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }),
    );
    executor.launch_ready().unwrap();
    wait_queue(|| started.load(Ordering::SeqCst) == 4);
    thread::sleep(Duration::from_millis(20));
    assert_eq!(
        executor.inner.worker_registry.lock().unwrap().workers.len(),
        4
    );
    assert_eq!(started.load(Ordering::SeqCst), 4);
    assert_eq!(peak.load(Ordering::SeqCst), 4);
    let active_threads = process_stat("Threads:");
    let active_rss = process_stat("VmRSS:");
    assert_eq!(tids.lock().unwrap().len(), 4);
    let exclusive = std::env::var_os("LOCKYARD_QUEUE_MEASURE_EXCLUSIVE").is_some();
    if exclusive {
        assert!(
            active_threads <= queued_threads + 5,
            "four workers plus one coordinator must bound thread growth"
        );
    }
    {
        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_all();
    }
    wait_queue(|| {
        let registry = executor.inner.worker_registry.lock().unwrap();
        !registry.coordinator_running && registry.workers.is_empty()
    });
    assert_eq!(started.load(Ordering::SeqCst), 1000);
    assert_eq!(peak.load(Ordering::SeqCst), 4);
    assert_eq!(tids.lock().unwrap().len(), 4);
    assert!(
        executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .all(|entry| entry.record.state == JobState::Succeeded)
    );
    let weak = Arc::downgrade(&executor.inner);
    WORKER_RUN_HOOKS
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .remove(&executor.inner.config.state_dir);
    drop(executor);
    wait_queue(|| weak.upgrade().is_none());
    println!(
        "QUEUE_MEASUREMENTS {}",
        serde_json::json!({"queued":ids.len(),"configured_workers":4,"synthetic_callbacks":1000,"container_jobs_executed":0,
            "baseline_threads":baseline_threads,"queued_threads":queued_threads,"active_threads":active_threads,"baseline_rss_kib":baseline_rss,"queued_rss_kib":queued_rss,"active_rss_kib":active_rss,
            "peak_callbacks":peak.load(Ordering::SeqCst),"unique_worker_tids":tids.lock().unwrap().len(),"exclusive_measurement":exclusive,"coordinator_exited":true,"last_owner_released":true})
    );
}
#[test]
fn queued_cancel_and_unknown_barrier_do_not_create_idle_workers_and_resolution_kicks_fair_work() {
    let (_root, executor, ids) = synthetic_queue(3, 1);
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback_gate = gate.clone();
    let callbacks = started.clone();
    install_worker_hook(
        &executor,
        Arc::new(move |executor, id, _cancel| {
            callbacks.fetch_add(1, Ordering::SeqCst);
            let (lock, changed) = &*callback_gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = changed.wait(open).unwrap();
            }
            executor.update(id, |record| record.state = JobState::Succeeded)?;
            Ok(())
        }),
    );
    // Unknown blocks all fresh claims without parking three OS threads.
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&ids[0])
        .unwrap()
        .record
        .state = JobState::InterruptedUnknown;
    executor.launch_ready().unwrap();
    wait_queue(|| {
        !executor
            .inner
            .worker_registry
            .lock()
            .unwrap()
            .coordinator_running
    });
    assert_eq!(started.load(Ordering::SeqCst), 0);
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    assert_eq!(
        executor.cancel(&ids[2], &owner).unwrap().state,
        JobState::Cancelled
    );
    let operator = Caller {
        node_id: "worker".into(),
        local_operator: true,
        certificate_sha256: None,
    };
    executor.resolve_unknown(&ids[0], &operator).unwrap();
    wait_queue(|| started.load(Ordering::SeqCst) == 1);
    {
        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_all();
    }
    wait_queue(|| {
        !executor
            .inner
            .worker_registry
            .lock()
            .unwrap()
            .coordinator_running
    });
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert_eq!(executor.status(&ids[1]).unwrap().state, JobState::Succeeded);
}
#[test]
fn cancellation_after_the_durable_starting_claim_stops_before_profile_or_runtime_access() {
    let (_root, executor, ids) = synthetic_queue(1, 1);
    let claimed = executor.claim_ready().unwrap().unwrap();
    assert_eq!(claimed.id, ids[0]);
    let saved: JobRecord = serde_json::from_slice(
        &fs::read(
            executor
                .inner
                .config
                .state_dir
                .join("jobs")
                .join(&ids[0])
                .join("record.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(saved.state, JobState::Starting);
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    executor.cancel(&ids[0], &owner).unwrap();
    executor.run_inner(&ids[0], claimed.cancel).unwrap();
    let cancelled = executor.status(&ids[0]).unwrap();
    assert_eq!(cancelled.state, JobState::Cancelled);
    assert_eq!(cancelled.patch_error.as_deref(), Some("job_not_started"));
    assert!(cancelled.pid.is_none());
    assert!(
        !executor
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(&ids[0])
            .join("runtime-config")
            .exists()
    );
}

#[test]
fn cancellation_and_launch_have_one_serialized_decision() {
    let (_root, executor, _ids) = synthetic_queue(1, 1);
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    let first = executor.claim_ready().unwrap().unwrap();
    let first_dir = executor.inner.config.state_dir.join("jobs").join(&first.id);
    let marker = first_dir.join("must-not-start");
    private_dir_new(&first_dir.join("runtime-secrets")).unwrap();
    assert_eq!(
        executor.cancel(&first.id, &owner).unwrap().state,
        JobState::Starting
    );
    let mut never = Command::new("/bin/sh");
    never.args(["-c", "touch -- \"$1\"", "test"]).arg(&marker);
    assert!(
        executor
            .commit_launch(&first.id, &first.cancel, &first_dir, &mut never)
            .unwrap()
            .is_none()
    );
    assert!(!marker.exists());
    assert!(!first_dir.join("runtime-secrets").exists());
    assert_eq!(
        executor.status(&first.id).unwrap().state,
        JobState::Cancelled
    );
    let (_root2, executor2, _ids2) = synthetic_queue(1, 1);
    let second = executor2.claim_ready().unwrap().unwrap();
    let second_dir = executor2
        .inner
        .config
        .state_dir
        .join("jobs")
        .join(&second.id);
    let mut process = Command::new("/bin/sleep");
    process.arg("2");
    let (mut child, durable) = executor2
        .commit_launch(&second.id, &second.cancel, &second_dir, &mut process)
        .unwrap()
        .unwrap();
    assert!(durable);
    assert_eq!(
        executor2.cancel(&second.id, &owner).unwrap().state,
        JobState::Running
    );
    assert!(second.cancel.load(Ordering::SeqCst));
    child.kill().unwrap();
    child.wait().unwrap();
}
