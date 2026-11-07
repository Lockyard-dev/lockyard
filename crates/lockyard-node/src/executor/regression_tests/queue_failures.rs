// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn starting_persist_and_worker_spawn_failures_fence_dispatch_before_any_callback() {
    for spawn_failure in [false, true] {
        let (_root, executor, ids) = synthetic_queue(1, 1);
        let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = callbacks.clone();
        install_worker_hook(
            &executor,
            Arc::new(move |_, _, _| {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );
        if spawn_failure {
            FAIL_WORKER_SPAWN
                .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
                .lock()
                .unwrap()
                .insert(executor.inner.config.state_dir.clone());
        } else {
            fs::create_dir(
                executor
                    .inner
                    .config
                    .state_dir
                    .join("jobs")
                    .join(&ids[0])
                    .join("record.json.tmp"),
            )
            .unwrap();
        }
        executor.launch_ready().unwrap();
        wait_queue(|| {
            !executor.dispatch_healthy()
                && !executor
                    .inner
                    .worker_registry
                    .lock()
                    .unwrap()
                    .coordinator_running
        });
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        assert!(
            executor
                .inner
                .worker_registry
                .lock()
                .unwrap()
                .workers
                .is_empty()
        );
        assert_eq!(
            executor.status(&ids[0]).unwrap().state,
            if spawn_failure {
                JobState::Failed
            } else {
                JobState::Queued
            }
        );
        assert_eq!(
            executor.launch_ready().unwrap_err().0,
            "executor_dispatch_unavailable"
        );
        let existing = executor
            .inner
            .jobs
            .lock()
            .unwrap()
            .get(&ids[0])
            .unwrap()
            .record
            .clone();
        let owner = Caller {
            node_id: "controller".into(),
            local_operator: false,
            certificate_sha256: Some("a".repeat(64)),
        };
        assert_eq!(
            executor.submit(existing.spec, &owner).unwrap().spec.id,
            ids[0]
        );
    }
}
#[test]
fn coordinator_spawn_failure_keeps_the_admitted_job_queued_without_claiming_or_executing() {
    let (_root, executor, ids) = synthetic_queue(1, 1);
    FAIL_COORDINATOR_SPAWN
        .get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
        .lock()
        .unwrap()
        .insert(executor.inner.config.state_dir.clone());
    assert_eq!(
        executor.launch_ready().unwrap_err().0,
        "job_coordinator_failed"
    );
    assert!(!executor.dispatch_healthy());
    assert_eq!(executor.status(&ids[0]).unwrap().state, JobState::Queued);
    let registry = executor.inner.worker_registry.lock().unwrap();
    assert!(!registry.coordinator_running);
    assert!(registry.workers.is_empty());
}
#[test]
fn panicked_worker_preserves_unknown_evidence_and_never_launches_the_next_job() {
    let (_root, executor, ids) = synthetic_queue(2, 1);
    let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let called = callbacks.clone();
    install_worker_hook(
        &executor,
        Arc::new(move |_, _, _| {
            called.fetch_add(1, Ordering::SeqCst);
            panic!("synthetic worker panic before any execution")
        }),
    );
    executor.launch_ready().unwrap();
    wait_queue(|| {
        !executor.dispatch_healthy()
            && !executor
                .inner
                .worker_registry
                .lock()
                .unwrap()
                .coordinator_running
    });
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    assert_eq!(
        executor.status(&ids[0]).unwrap().state,
        JobState::InterruptedUnknown
    );
    assert_eq!(executor.status(&ids[1]).unwrap().state, JobState::Queued);
}
