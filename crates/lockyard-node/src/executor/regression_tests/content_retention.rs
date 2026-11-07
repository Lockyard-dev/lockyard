// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn retention_purges_private_content_only_after_durable_nonreplay_tombstone() {
    let (_root, config, executor) = retention_fixture();
    let current = now_ms();
    let record = retained_fixture_record(&executor, JobState::Succeeded, current - 1);
    fs::write(
        config
            .state_dir
            .join("exports")
            .join(format!("{}.lyarchive", record.spec.id)),
        b"encrypted-copy",
    )
    .unwrap();
    assert_eq!(executor.purge_expired_at(current).unwrap(), 1);
    assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
    assert!(
        !config
            .state_dir
            .join("exports")
            .join(format!("{}.lyarchive", record.spec.id))
            .exists()
    );
    let tombstone = executor.tombstone(&record.spec.id).unwrap().unwrap();
    assert_eq!(
        executor.expired_metadata(&record.spec.id).unwrap().unwrap()["erasure_complete"],
        true
    );
    let minimal = serde_json::to_string(&tombstone).unwrap();
    for content in [
        "private-prompt-sentinel",
        "private-log-sentinel",
        "private-patch-sentinel",
        "private-code-sentinel",
        "private-git-sentinel",
    ] {
        assert!(!minimal.contains(content));
    }
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    assert_eq!(
        executor.submit(record.spec.clone(), &owner).unwrap_err().0,
        "job_content_expired"
    );
    let replacement = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("b".repeat(64)),
    };
    assert_eq!(
        executor
            .submit(record.spec.clone(), &replacement)
            .unwrap_err()
            .0,
        "job_id_conflict"
    );
    let mut changed = record.spec.clone();
    changed.prompt = Some("changed".into());
    assert_eq!(
        executor.submit(changed, &owner).unwrap_err().0,
        "job_id_conflict"
    );
    // Crash boundary: committed tombstone plus an unremoved body must recover by erasing,
    // without interpreting a stale job journal as a fresh runnable job.
    let job = config.state_dir.join("jobs").join(&record.spec.id);
    private_dir_new(&job).unwrap();
    persist(&config.state_dir, &record).unwrap();
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    assert!(!job.exists());
    assert!(recovered.list().unwrap().is_empty());
    assert_eq!(
        recovered.submit(record.spec, &owner).unwrap_err().0,
        "job_content_expired"
    );
}
#[test]
fn a_reused_source_name_never_inherits_cancel_or_submit_ownership() {
    let (_root, _config, executor) = retention_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
    let replacement = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("b".repeat(64)),
    };
    assert_eq!(
        executor
            .cancel(&record.spec.id, &replacement)
            .unwrap_err()
            .0,
        "job_owner_required"
    );
    assert_eq!(
        executor
            .submit(record.spec.clone(), &replacement)
            .unwrap_err()
            .0,
        "job_id_conflict"
    );
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&record.spec.id)
        .unwrap()
        .record
        .submitter_certificate_sha256 = None;
    let original = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    assert_eq!(
        executor.cancel(&record.spec.id, &original).unwrap_err().0,
        "legacy_submitter_requires_local_review"
    );
    assert_eq!(
        executor.submit(record.spec, &original).unwrap_err().0,
        "legacy_submitter_requires_local_review"
    );
}
#[test]
fn erasure_failure_retains_commitment_blocks_admission_and_recovers_completion() {
    let (_root, config, executor) = retention_fixture();
    let current = now_ms();
    let record = retained_fixture_record(&executor, JobState::Succeeded, current - 1);
    let export = config
        .state_dir
        .join("exports")
        .join(format!("{}.lyarchive", record.spec.id));
    fs::create_dir(&export).unwrap(); // Deterministic unlink failure on an invalid fixture.
    assert!(executor.purge_expired_at(current).is_err());
    assert!(executor.tombstone(&record.spec.id).unwrap().is_some());
    assert_eq!(
        executor.expired_metadata(&record.spec.id).unwrap().unwrap()["erasure_complete"],
        false
    );
    assert!(
        !config
            .state_dir
            .join("purge-completed")
            .join(&record.spec.id)
            .exists()
    );
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    let mut new_spec = record.spec.clone();
    new_spec.id = crate::wire::new_id().unwrap();
    assert_eq!(
        executor.submit(new_spec, &owner).unwrap_err().0,
        "retention_maintenance_required"
    );
    fs::remove_dir(export).unwrap();
    executor.purge_expired_at(current).unwrap();
    assert_eq!(
        executor.expired_metadata(&record.spec.id).unwrap().unwrap()["erasure_complete"],
        true
    );
    assert!(!executor.inner.retention_failed.load(Ordering::SeqCst));
    assert!(
        !config
            .state_dir
            .join("expired-content")
            .join(&record.spec.id)
            .exists()
    );
}
#[test]
fn retention_never_erases_unknown_execution_or_an_artifact_in_use() {
    let (_root, config, executor) = retention_fixture();
    let current = now_ms();
    let record = retained_fixture_record(&executor, JobState::InterruptedUnknown, current - 1);
    assert_eq!(executor.purge_expired_at(current).unwrap(), 0);
    assert!(
        config
            .state_dir
            .join("jobs")
            .join(&record.spec.id)
            .join("output.log")
            .exists()
    );
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&record.spec.id)
        .unwrap()
        .record
        .state = JobState::Succeeded;
    let artifacts = executor.artifact_lock(&record.spec.id).unwrap();
    let guard = artifacts.lock().unwrap();
    assert_eq!(executor.purge_expired_at(current).unwrap(), 0);
    drop(guard);
    assert_eq!(executor.purge_expired_at(current).unwrap(), 1);
}
#[test]
fn expired_unsigned_terminal_restart_preserves_recoverable_signed_outcome() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("signing.pk8");
    let key = SigningKey::generate(&path).unwrap();
    let config = ExecutorConfig {
        node_id: "worker".into(),
        state_dir: root.path().join("executor"),
        repositories: BTreeMap::new(),
        runners: BTreeMap::new(),
        provenance: Some(ResultSigningConfig {
            workspace: "workspace".into(),
            key_file: path,
            public_key: key.trusted_key().public_key,
        }),
        limits: ExecutionLimits::default(),
        scheduling: Default::default(),
        node_certificate_sha256: None,
        protected_identity_files: Vec::new(),
    };
    let executor = Executor::new(config.clone()).unwrap();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
    assert!(record.result_manifest.is_none());
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
    let metadata = recovered
        .expired_metadata(&record.spec.id)
        .unwrap()
        .unwrap();
    assert_eq!(metadata["erasure_complete"], true);
    let signed: crate::provenance::SignedDocument =
        serde_json::from_value(metadata["terminal_receipt"].clone()).unwrap();
    let proof: retention::TerminalReceipt = crate::provenance::verify_document(
        &signed,
        retention::TERMINAL_RECEIPT_DOMAIN,
        &key.trusted_key(),
    )
    .unwrap();
    assert_eq!(proof.outcome, JobState::Succeeded);
    assert_eq!(
        proof.request_sha256,
        retention::spec_digest(&record.spec).unwrap()
    );
    assert!(
        !serde_json::to_string(&proof)
            .unwrap()
            .contains("private-prompt-sentinel")
    );
    assert!(metadata["tombstone"]["result_manifest"].is_null());
    let caller = Caller {
        node_id: record.submitter.clone(),
        local_operator: false,
        certificate_sha256: record.submitter_certificate_sha256.clone(),
    };
    assert_eq!(
        recovered
            .submit(record.spec.clone(), &caller)
            .unwrap_err()
            .0,
        "job_content_expired"
    );
    assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
}

#[test]
fn receipt_signer_failure_does_not_delay_purge_and_retries_from_tombstone() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("signing.pk8");
    let key = SigningKey::generate(&path).unwrap();
    let config = ExecutorConfig {
        node_id: "worker".into(),
        state_dir: root.path().join("executor"),
        repositories: BTreeMap::new(),
        runners: BTreeMap::new(),
        provenance: Some(ResultSigningConfig {
            workspace: "workspace".into(),
            key_file: path,
            public_key: key.trusted_key().public_key,
        }),
        limits: ExecutionLimits::default(),
        scheduling: Default::default(),
        node_certificate_sha256: None,
        protected_identity_files: Vec::new(),
    };
    let mut executor = Executor::new(config.clone()).unwrap();
    let record = retained_fixture_record(&executor, JobState::Failed, now_ms() - 1);
    Arc::get_mut(&mut executor.inner).unwrap().signing_key = None;
    assert_eq!(executor.purge_expired().unwrap(), 1);
    assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
    let metadata = executor.expired_metadata(&record.spec.id).unwrap().unwrap();
    assert_eq!(metadata["erasure_complete"], true);
    assert!(metadata["terminal_receipt"].is_null());
    assert_eq!(
        metadata["terminal_receipt_error"],
        "terminal_receipt_signing_unavailable"
    );
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    let metadata = recovered
        .expired_metadata(&record.spec.id)
        .unwrap()
        .unwrap();
    assert!(metadata["terminal_receipt"].is_object());
    assert!(
        config
            .state_dir
            .join("job-tombstones")
            .join(format!("{}.receipt", record.spec.id))
            .exists()
    );
    assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
}

#[test]
fn credential_job_export_is_signed_results_only_and_restores_without_a_runnable_journal() {
    // Synthetic confirmed-terminal journal, not a container execution proof.
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
    let trusted = signer.trusted_key();
    let config = ExecutorConfig {
        node_id: "worker".into(),
        state_dir: root.path().join("executor"),
        repositories: BTreeMap::new(),
        runners: BTreeMap::new(),
        provenance: Some(ResultSigningConfig {
            workspace: "workspace".into(),
            key_file: root.path().join("signing.pk8"),
            public_key: trusted.public_key.clone(),
        }),
        limits: ExecutionLimits::default(),
        scheduling: Default::default(),
        node_certificate_sha256: None,
        protected_identity_files: Vec::new(),
    };
    let key = WorkspaceKey::from_entropy([37; 32]);
    let executor =
        Executor::new_with_workspace_key(config, "workspace".into(), key.clone()).unwrap();
    let mut record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
    assert!(record.had_runtime_credentials); // Legacy records conservatively restrict exports.
    record.configured_image = Some(format!("sha256:{}", "a".repeat(64)));
    record.resolved_revision = Some("b".repeat(40));
    record.exit_code = Some(0);
    record.log_error = Some("log_contains_forwarded_credential".into());
    record.patch_error = Some("patch_contains_forwarded_credential".into());
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&record.spec.id)
        .unwrap()
        .record = record.clone();
    persist(&executor.inner.config.state_dir, &record).unwrap();
    let archive = root.path().join("export.lyarchive");
    let mut output = private_open(&archive, true).unwrap();
    let mut offset = 0;
    loop {
        let chunk = executor
            .read_archive(&record.spec.id, offset, 65536)
            .unwrap();
        output.write_all(&chunk.bytes).unwrap();
        offset = chunk.next_offset;
        if chunk.eof {
            break;
        }
    }
    output.sync_all().unwrap();
    drop(output);
    let manifest =
        crate::archive::inspect(&archive, "workspace", &key, "worker", &trusted).unwrap();
    assert_eq!(manifest.scope, crate::archive::ArchiveScope::ResultsOnly);
    assert!(manifest.entries.iter().all(|entry| matches!(
        entry.path.as_str(),
        "export-metadata.json" | "output.log" | "result.patch"
    )));
    let restored = root.path().join("offline");
    crate::archive::restore_offline(&archive, &restored, "workspace", &key, "worker", &trusted)
        .unwrap();
    assert!(!restored.join("files/record.json").exists());
    assert!(!restored.join("files/worktree").exists());
    assert!(!restored.join("files/repository.git").exists());
    assert!(!restored.join("files/output.log").exists());
    assert!(!restored.join("files/result.patch").exists());
    assert!(!restored.join("executor").exists());
    let metadata = fs::read_to_string(restored.join("files/export-metadata.json")).unwrap();
    assert!(!metadata.contains("private-prompt-sentinel"));
    assert!(!metadata.contains("private-code-sentinel"));
    assert!(metadata.contains("result_manifest"));
}
#[test]
fn operator_drain_is_durable_and_only_gates_new_job_ids() {
    let (_root, config, executor) = retention_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    assert_eq!(
        executor.set_draining(true, &owner).unwrap_err().0,
        "local_operator_required"
    );
    let operator = Caller {
        node_id: "worker".into(),
        local_operator: true,
        certificate_sha256: None,
    };
    assert!(executor.set_draining(true, &operator).unwrap().draining);
    assert_eq!(
        executor
            .submit(record.spec.clone(), &owner)
            .unwrap()
            .spec
            .id,
        record.spec.id
    );
    let mut fresh = record.spec.clone();
    fresh.id = crate::wire::new_id().unwrap();
    assert_eq!(
        executor.submit(fresh.clone(), &owner).unwrap_err().0,
        "node_draining"
    );
    drop(executor);
    let recovered = Executor::new(config).unwrap();
    assert!(recovered.drain_status().unwrap().draining);
    assert_eq!(
        recovered.submit(fresh, &owner).unwrap_err().0,
        "node_draining"
    );
    assert!(!recovered.set_draining(false, &operator).unwrap().draining);
}
