// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn queued_cancellation_immediately_has_a_signed_terminal_result() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
    let trusted = signer.trusted_key();
    let config = ExecutorConfig {
        external_actions: Default::default(),
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
        node_certificate_sha256: Some("a".repeat(64)),
        protected_identity_files: Vec::new(),
        signed_results: None,
    };
    let outbox = Arc::new(Mutex::new(
        crate::job_notifications::Outbox::open(root.path(), &"a".repeat(64), true).unwrap(),
    ));
    let executor = Executor::open(
        config.clone(),
        Some(WorkspaceKeyContext {
            workspace: "workspace".into(),
            key: WorkspaceKey::from_entropy([7; 32]),
        }),
        None,
        Some(outbox.clone()),
    )
    .unwrap();
    let mut record = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
    record.retention.as_mut().unwrap().terminal_expires_at_ms = None;
    record.configured_image = Some(format!("sha256:{}", "a".repeat(64)));
    record.resolved_revision = Some("b".repeat(40));
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&record.spec.id)
        .unwrap()
        .record = record.clone();
    persist(&executor.inner.config.state_dir, &record).unwrap();
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    std::thread::sleep(Duration::from_millis(2));
    let cancelled = executor.cancel(&record.spec.id, &owner).unwrap();
    assert_eq!(cancelled.state, JobState::Cancelled);
    let signed = cancelled
        .result_manifest
        .as_ref()
        .expect("signed without restart or archive request");
    let original = fs::read(
        config
            .state_dir
            .join("jobs")
            .join(&record.spec.id)
            .join("signed-result.json"),
    )
    .unwrap();
    assert_eq!(
        &serde_json::from_slice::<crate::provenance::SignedDocument>(&original).unwrap(),
        signed
    );
    let manifest = crate::provenance::verify_result_identity(
        signed,
        &trusted,
        "worker",
        "workspace",
        &record.spec.id,
    )
    .unwrap();
    assert_eq!(manifest.state, JobState::Cancelled);
    assert!(!manifest.execution_attempted);
    assert_eq!(executor.notification_status().unwrap().0, 1);
    executor.notification_capture_page(None).unwrap();
    assert_eq!(executor.notification_status().unwrap().0, 1);
    let metadata = fs::read_to_string(root.path().join("job-notifications.json")).unwrap();
    assert!(metadata.contains(&record.spec.id));
    assert!(!metadata.contains("manifest"));
    assert!(!metadata.contains("prompt"));
    // Crash after the outbox sync but before the source acknowledgement: recovery
    // sees the existing key and must not append another notification.
    {
        let mut jobs = executor.inner.jobs.lock().unwrap();
        let entry = jobs.get_mut(&record.spec.id).unwrap();
        entry.record.notification_accounted_certificate_sha256 = None;
        persist(&executor.inner.config.state_dir, &entry.record).unwrap();
    }
    drop(executor);
    let executor = Executor::open(
        config.clone(),
        Some(WorkspaceKeyContext {
            workspace: "workspace".into(),
            key: WorkspaceKey::from_entropy([7; 32]),
        }),
        None,
        Some(outbox.clone()),
    )
    .unwrap();
    executor.notification_capture_page(None).unwrap();
    assert_eq!(executor.notification_status().unwrap().0, 1);
    // The per-record acknowledgement survives expiration of the outbox tombstone.
    drop(executor);
    drop(outbox);
    let path = root.path().join("job-notifications.json");
    let mut disk: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    disk["entries"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec(&disk).unwrap()).unwrap();
    let outbox = Arc::new(Mutex::new(
        crate::job_notifications::Outbox::open(root.path(), &"a".repeat(64), true).unwrap(),
    ));
    let executor = Executor::open(
        config,
        Some(WorkspaceKeyContext {
            workspace: "workspace".into(),
            key: WorkspaceKey::from_entropy([7; 32]),
        }),
        None,
        Some(outbox),
    )
    .unwrap();
    executor.notification_capture_page(None).unwrap();
    assert_eq!(executor.notification_status().unwrap().0, 0);
    let expiry = cancelled.retention.unwrap().terminal_expires_at_ms.unwrap();
    executor.purge_expired_at(expiry).unwrap();
    assert!(executor.status(&record.spec.id).is_err());
    assert_eq!(executor.notification_status().unwrap().0, 0);
}

#[tokio::test]
#[ignore = "requires an isolated verified-TLS notification fixture"]
async fn signed_negative_terminal_reaches_cloud_notification_fixture() {
    let workspace = std::env::var("LOCKYARD_E20_WORKSPACE").unwrap();
    let base = std::env::var("LOCKYARD_E20_BASE").unwrap();
    let root_certificate = fs::read(std::env::var("LOCKYARD_E20_ROOT_FILE").unwrap()).unwrap();
    let token = fs::read_to_string(std::env::var("LOCKYARD_E20_TOKEN_FILE").unwrap()).unwrap();
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let signer = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
    let config = ExecutorConfig {
        external_actions: Default::default(),
        node_id: "worker".into(),
        state_dir: root.path().join("executor"),
        repositories: BTreeMap::new(),
        runners: BTreeMap::new(),
        provenance: Some(ResultSigningConfig {
            workspace: workspace.clone(),
            key_file: root.path().join("signing.pk8"),
            public_key: signer.trusted_key().public_key,
        }),
        limits: ExecutionLimits::default(),
        scheduling: Default::default(),
        node_certificate_sha256: Some("a".repeat(64)),
        protected_identity_files: Vec::new(),
        signed_results: None,
    };
    let outbox = Arc::new(Mutex::new(
        crate::job_notifications::Outbox::open(root.path(), &"a".repeat(64), true).unwrap(),
    ));
    let executor = Executor::open(
        config,
        Some(WorkspaceKeyContext {
            workspace,
            key: WorkspaceKey::from_entropy([7; 32]),
        }),
        None,
        Some(outbox.clone()),
    )
    .unwrap();
    let mut record = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
    record.retention.as_mut().unwrap().terminal_expires_at_ms = None;
    record.configured_image = Some(format!("sha256:{}", "a".repeat(64)));
    record.resolved_revision = Some("b".repeat(40));
    record.spec.prompt = Some("PRIVATE_PROMPT_CANARY".into());
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&record.spec.id)
        .unwrap()
        .record = record.clone();
    persist(&executor.inner.config.state_dir, &record).unwrap();
    let owner = Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    tokio::time::sleep(Duration::from_millis(2)).await;
    let terminal = executor.cancel(&record.spec.id, &owner).unwrap();
    assert_eq!(terminal.state, JobState::Cancelled);
    assert!(terminal.result_manifest.is_some());
    assert_eq!(executor.notification_status().unwrap().0, 1);
    let client = crate::cloud::NodeCloudClient::new(
        &base,
        "worker".into(),
        token.trim().into(),
        &[root_certificate],
    )
    .unwrap();
    let worker = tokio::spawn(crate::job_notifications::run(
        outbox,
        "a".repeat(64),
        executor.clone(),
        client,
    ));
    tokio::time::timeout(Duration::from_secs(20), async {
        while executor.notification_status().unwrap().0 != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the verified TLS fixture did not acknowledge the captured outcome");
    worker.abort();
}

#[test]
fn signature_persist_failure_never_exposes_a_successful_signed_patch() {
    // A pre-existing terminal journal fixture, not an execution or container proof.
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let key_file = root.path().join("result.pk8");
    let key = SigningKey::generate(&key_file).unwrap();
    let signing = ResultSigningConfig {
        workspace: "workspace".into(),
        key_file,
        public_key: key.trusted_key().public_key,
    };
    let config = ExecutorConfig {
        external_actions: Default::default(),
        node_certificate_sha256: None,
        protected_identity_files: Vec::new(),
        signed_results: None,
        node_id: "worker".into(),
        state_dir: root.path().join("executor"),
        repositories: BTreeMap::new(),
        runners: BTreeMap::new(),
        provenance: Some(signing),
        limits: ExecutionLimits::default(),
        scheduling: Default::default(),
    };
    let executor = Executor::new(config.clone()).unwrap();
    let current = now_ms();
    let record: JobRecord = serde_json::from_value(serde_json::json!({
            "spec":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo","revision":"HEAD","runner":"runner","arguments":[],"prompt":null,"timeout_seconds":null},
            "state":"succeeded","agent":"derived","submitter":"controller","created_at":current,"updated_at":current,
            "retention":{"content_ttl_seconds":3600,"admitted_at_ms":current,"terminal_expires_at_ms":current+3_600_000,"purged_at_ms":null},
            "resolved_revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","worktree":null,"pid":null,"exit_code":0,"error_code":null,"log_bytes":0,"log_truncated":false,
            "configured_image":format!("sha256:{}","a".repeat(64))
        })).unwrap();
    let job = config.state_dir.join("jobs").join(&record.spec.id);
    private_dir_new(&job).unwrap();
    fs::write(job.join("output.log"), []).unwrap();
    fs::write(job.join("result.patch"), []).unwrap();
    for name in ["output.log", "result.patch"] {
        fs::set_permissions(job.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    persist(&config.state_dir, &record).unwrap();
    executor.inner.jobs.lock().unwrap().insert(
        record.spec.id.clone(),
        Entry {
            record: record.clone(),
            cancel: Arc::new(AtomicBool::new(false)),
            artifacts: Arc::new(Mutex::new(())),
        },
    );
    fs::create_dir(job.join("record.json.tmp")).unwrap();
    executor.finalize_provenance(&record.spec.id);
    let failed = executor.status(&record.spec.id).unwrap();
    assert!(failed.result_manifest.is_none());
    assert_eq!(
        failed.provenance_error.as_deref(),
        Some("result_manifest_persist_failed")
    );
    assert_eq!(
        executor.read_patch(&record.spec.id, 0, 1024).unwrap_err().0,
        "result_provenance_unavailable"
    );
    drop(executor);
    fs::remove_dir(job.join("record.json.tmp")).unwrap();
    let recovered = Executor::new(config).unwrap();
    let restored = recovered.status(&record.spec.id).unwrap();
    assert!(restored.result_manifest.is_some());
    assert!(restored.provenance_error.is_none());
    assert_eq!(restored.state, JobState::Succeeded);
    assert!(recovered.read_patch(&record.spec.id, 0, 1024).unwrap().eof);
}
