// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

fn legacy_fixture() -> (tempfile::TempDir, ExecutorConfig, Executor, SigningKey) {
    let (root, mut config, executor) = retention_fixture();
    drop(executor);
    let key_path = root.path().join("signing.pk8");
    let signer = SigningKey::generate(&key_path).unwrap();
    config.provenance = Some(ResultSigningConfig {
        workspace: "workspace".into(),
        key_file: key_path,
        public_key: signer.trusted_key().public_key,
    });
    let executor = Executor::new(config.clone()).unwrap();
    (root, config, executor, signer)
}
fn legacy_tombstone(record: &JobRecord) -> JobTombstone {
    JobTombstone {
        version: 1,
        job_id: record.spec.id.clone(),
        submitter: record.submitter.clone(),
        submitter_certificate_sha256: record.submitter_certificate_sha256.clone(),
        spec_sha256: retention::spec_digest(&record.spec).unwrap(),
        outcome: record.state,
        terminal_expires_at_ms: record
            .retention
            .as_ref()
            .unwrap()
            .terminal_expires_at_ms
            .unwrap(),
        purged_at_ms: now_ms(),
        result_manifest: None,
        completed_at_ms: None,
    }
}
fn store_legacy(config: &ExecutorConfig, tombstone: &JobTombstone) -> Vec<u8> {
    let directory = config.state_dir.join("job-tombstones");
    retention::store_tombstone(&directory, tombstone).unwrap();
    fs::read(directory.join(&tombstone.job_id)).unwrap()
}
fn assert_legacy_unchanged(config: &ExecutorConfig, tombstone: &JobTombstone, before: &[u8]) {
    assert_eq!(
        fs::read(
            config
                .state_dir
                .join("job-tombstones")
                .join(&tombstone.job_id)
        )
        .unwrap(),
        before
    );
}
fn signed_legacy_result(
    signer: &SigningKey,
    record: &JobRecord,
) -> crate::provenance::SignedDocument {
    signer
        .sign_result(&ResultManifest {
            version: 1,
            node_id: "worker".into(),
            workspace: "workspace".into(),
            job_id: record.spec.id.clone(),
            repository: record.spec.repository.clone(),
            runner: record.spec.runner.clone(),
            request_sha256: retention::spec_digest(&record.spec).unwrap(),
            resolved_revision: "b".repeat(40),
            image_reference: format!("image@sha256:{}", "a".repeat(64)),
            image_digest: format!("sha256:{}", "a".repeat(64)),
            image_config_digest: None,
            image_attestation_sha256: None,
            execution_attempted: false,
            completed_at_ms: record.updated_at_ms,
            state: record.state,
            exit_code: Some(0),
            error_code: None,
            artifacts: BTreeMap::new(),
        })
        .unwrap()
}

#[test]
fn legacy_tombstone_reconciles_verified_signed_result_without_rewriting_purge_proof() {
    let (_root, config, executor, signer) = legacy_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
    let mut tombstone = legacy_tombstone(&record);
    tombstone.result_manifest = Some(signed_legacy_result(&signer, &record));
    let before = store_legacy(&config, &tombstone);
    // The signed manifest remains after the old release has already removed its journal.
    fs::remove_dir_all(config.state_dir.join("jobs").join(&record.spec.id)).unwrap();
    retention::store_purge_completion(
        &config.state_dir.join("purge-completed"),
        &tombstone,
        now_ms(),
    )
    .unwrap();
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    let metadata = recovered
        .expired_metadata(&record.spec.id)
        .unwrap()
        .unwrap();
    assert_eq!(metadata["reconciliation"]["status"], "reconciled");
    assert_eq!(metadata["reconciliation"]["source"], "signed_result");
    assert_eq!(
        metadata["reconciliation"]["completed_at_ms"],
        record.updated_at_ms
    );
    assert_eq!(metadata["erasure_complete"], true);
    assert!(metadata["terminal_receipt"].is_object());
    assert_legacy_unchanged(&config, &tombstone, &before);
    assert!(
        retention::load_purge_completion(&config.state_dir.join("purge-completed"), &tombstone)
            .unwrap()
            .is_some()
    );
}

#[test]
fn legacy_tombstone_reconciles_node_journal_before_erasing_it() {
    let (_root, config, executor, _signer) = legacy_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
    let tombstone = legacy_tombstone(&record);
    let before = store_legacy(&config, &tombstone);
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    let metadata = recovered
        .expired_metadata(&record.spec.id)
        .unwrap()
        .unwrap();
    assert_eq!(metadata["reconciliation"]["status"], "reconciled");
    assert_eq!(metadata["reconciliation"]["source"], "node_journal");
    assert_eq!(
        metadata["reconciliation"]["completed_at_ms"],
        record.updated_at_ms
    );
    assert!(metadata["terminal_receipt"].is_object());
    assert!(!config.state_dir.join("jobs").join(&record.spec.id).exists());
    assert_legacy_unchanged(&config, &tombstone, &before);
}

#[test]
fn legacy_tombstone_without_evidence_needs_review_and_preserves_remaining_content() {
    let (_root, config, executor, _signer) = legacy_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
    let tombstone = legacy_tombstone(&record);
    let before = store_legacy(&config, &tombstone);
    let job = config.state_dir.join("jobs").join(&record.spec.id);
    fs::remove_file(job.join("record.json")).unwrap();
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    let metadata = recovered
        .expired_metadata(&record.spec.id)
        .unwrap()
        .unwrap();
    assert_eq!(metadata["status"], "needs_review");
    assert_eq!(metadata["reconciliation"]["status"], "needs_review");
    assert_eq!(
        metadata["reconciliation"]["diagnostic_code"],
        "tombstone_reconciliation_required"
    );
    assert!(metadata["terminal_receipt"].is_null());
    assert_eq!(metadata["erasure_complete"], false);
    assert_eq!(
        fs::read(job.join("output.log")).unwrap(),
        b"private-log-sentinel"
    );
    assert_legacy_unchanged(&config, &tombstone, &before);
    let sidecar = config
        .state_dir
        .join("job-tombstones")
        .join(format!("{}.reconciliation", record.spec.id));
    let diagnostic = fs::read(&sidecar).unwrap();
    assert!(!String::from_utf8_lossy(&diagnostic).contains("private-prompt-sentinel"));
    assert!(recovered.list().unwrap().is_empty());
    recovered.purge_expired().unwrap();
    assert!(job.exists());
    drop(recovered);
    let reopened = Executor::new(config.clone()).unwrap();
    assert_eq!(fs::read(sidecar).unwrap(), diagnostic);
    assert_eq!(
        reopened.expired_metadata(&record.spec.id).unwrap().unwrap()["status"],
        "needs_review"
    );
    assert!(job.exists());
}

#[test]
fn legacy_tombstone_rejects_wrong_request_signed_evidence_and_conflicting_journal() {
    let (_root, config, executor, signer) = legacy_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
    let mut other = record.clone();
    other.spec.prompt = Some("a different signed request".into());
    let mut tombstone = legacy_tombstone(&record);
    tombstone.result_manifest = Some(signed_legacy_result(&signer, &other));
    let before = store_legacy(&config, &tombstone);
    drop(executor);
    let recovered = Executor::new(config.clone()).unwrap();
    let metadata = recovered
        .expired_metadata(&record.spec.id)
        .unwrap()
        .unwrap();
    assert_eq!(metadata["status"], "needs_review");
    assert!(metadata["terminal_receipt"].is_null());
    assert!(config.state_dir.join("jobs").join(&record.spec.id).exists());
    assert_legacy_unchanged(&config, &tombstone, &before);
}

type CloudFixture = (String, std::thread::JoinHandle<()>, Arc<Mutex<Vec<String>>>);
fn cloud_fixture(body: Vec<u8>, status: u16, code: &str) -> CloudFixture {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let code = code.to_owned();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            if headers.starts_with("GET /stop ") {
                return;
            }
            assert!(
                headers
                    .to_lowercase()
                    .contains("authorization: bearer fixture\r\n")
            );
            if !headers.starts_with("GET /api/v1/protocol ") {
                observed
                    .lock()
                    .unwrap()
                    .push(headers.lines().next().unwrap().to_owned());
            }
            let (status, content_type, body, extra) = if headers
                .starts_with("GET /api/v1/protocol ")
            {
                (200, "application/json", serde_json::json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":["signed_results_v1"]}).to_string().into_bytes(), String::new())
            } else if status == 200 {
                assert!(headers.contains("/signed-result "));
                (
                    200,
                    "application/octet-stream",
                    body.clone(),
                    format!(
                        "Lockyard-Result-Expires-At: {}\r\n",
                        lockyard_core::proto::rfc3339((now_ms() + 60_000) as i64)
                    ),
                )
            } else {
                (status,"application/problem+json",serde_json::json!({"type":format!("urn:lockyard:problem:{code}"),"status":status,"code":code,"detail":"refused","details":null}).to_string().into_bytes(),String::new())
            };
            write!(stream,"HTTP/1.1 {status} Reply\r\nLockyard-Protocol: 2\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (url, handle, requests)
}

#[test]
fn legacy_tombstone_cloud_result_is_verified_before_reconciliation() {
    const WORKSPACE: &str = "00000000-0000-4000-8000-000000000001";
    for variant in [
        "valid",
        "missing",
        "credential_revoked",
        "revoked",
        "foreign_workspace",
        "tampered",
        "wrong_signature",
        "wrong_job",
        "wrong_node",
        "wrong_workspace",
        "wrong_spec",
        "wrong_outcome",
        "wrong_time",
    ] {
        let (_root, mut config, executor, signer) = legacy_fixture();
        let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
        let tombstone = legacy_tombstone(&record);
        let before = store_legacy(&config, &tombstone);
        let job = config.state_dir.join("jobs").join(&record.spec.id);
        fs::remove_file(job.join("record.json")).unwrap();
        drop(executor);
        config.provenance.as_mut().unwrap().workspace = WORKSPACE.into();
        let old = signed_legacy_result(&signer, &record);
        let mut manifest = crate::provenance::verify_result_identity(
            &old,
            &signer.trusted_key(),
            "worker",
            "workspace",
            &record.spec.id,
        )
        .unwrap();
        manifest.workspace = WORKSPACE.into();
        match variant {
            "wrong_job" => manifest.job_id = lockyard_cloud_client::ulid(),
            "wrong_node" => manifest.node_id = "other".into(),
            "wrong_workspace" => manifest.workspace = "other".into(),
            "wrong_spec" => manifest.request_sha256 = "c".repeat(64),
            "wrong_outcome" => manifest.state = JobState::Failed,
            "wrong_time" => manifest.completed_at_ms = now_ms() + 60_000,
            _ => (),
        }
        let mut document = signer.sign_result(&manifest).unwrap();
        if variant == "wrong_signature" {
            document.signature = "A".repeat(document.signature.len());
        }
        let key = WorkspaceKey::from_entropy([39; 32]);
        let mut envelope = key
            .encrypt(
                WORKSPACE,
                &format!("node-result/worker/{}", record.spec.id),
                &serde_json::to_string(&document).unwrap(),
            )
            .unwrap()
            .into_bytes();
        if variant == "tampered" {
            let i = envelope.len() - 4;
            envelope[i] = if envelope[i] == b'A' { b'B' } else { b'A' };
        }
        let (status, code) = match variant {
            "missing" | "foreign_workspace" => (404, "task_not_found"),
            "credential_revoked" => (401, "credential_revoked"),
            "revoked" => (403, "revoked"),
            _ => (200, ""),
        };
        let (url, server, requests) = cloud_fixture(envelope, status, code);
        let client = lockyard_cloud_client::Client::new(&url, "fixture".into())
            .unwrap()
            .with_content_encryption(WORKSPACE, Some(key), true);
        config.signed_results = Some(Arc::new(client));
        let recovered = Executor::new(config.clone()).unwrap();
        assert!(requests.lock().unwrap().is_empty());
        // Starting, reading metadata and ordinary erasure must perform no remote I/O.
        // Only the paced reconciliation worker may contact the cloud.
        assert_eq!(
            recovered
                .expired_metadata(&record.spec.id)
                .unwrap()
                .unwrap()["status"],
            "needs_review",
            "startup must leave cloud evidence to the background worker"
        );
        recovered.reconcile_cloud_tombstones().unwrap();
        recovered.purge_expired().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 1);
        let metadata = recovered
            .expired_metadata(&record.spec.id)
            .unwrap()
            .unwrap();
        if variant == "valid" {
            assert_eq!(metadata["status"], "content_expired", "{variant}");
            assert_eq!(metadata["reconciliation"]["source"], "cloud_signed_result");
            assert!(metadata["terminal_receipt"].is_object());
            assert!(!job.exists());
        } else {
            assert_eq!(metadata["status"], "needs_review", "{variant}");
            assert_eq!(
                metadata["reconciliation"]["diagnostic_code"],
                "tombstone_reconciliation_required"
            );
            assert!(
                metadata["reconciliation"]["cloud_error_code"].is_string(),
                "{variant}"
            );
            assert!(metadata["terminal_receipt"].is_null());
            assert_eq!(
                fs::read(job.join("output.log")).unwrap(),
                b"private-log-sentinel"
            );
            recovered.purge_expired().unwrap();
            assert!(job.exists());
        }
        assert_legacy_unchanged(&config, &tombstone, &before);
        let _ = ureq::get(&format!("{url}/stop")).call();
        server.join().unwrap();
    }
}

#[test]
fn cloud_reconciliation_is_one_per_tick_and_local_reads_preserve_diagnostics() {
    let (_root, mut config, executor, _) = legacy_fixture();
    let record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() - 1);
    fs::remove_file(
        config
            .state_dir
            .join("jobs")
            .join(&record.spec.id)
            .join("record.json"),
    )
    .unwrap();
    let first = legacy_tombstone(&record);
    store_legacy(&config, &first);
    for _ in 0..2 {
        let mut other = first.clone();
        other.job_id = lockyard_cloud_client::ulid();
        store_legacy(&config, &other);
    }
    drop(executor);
    let (url, server, requests) = cloud_fixture(Vec::new(), 404, "task_not_found");
    config.signed_results = Some(Arc::new(
        lockyard_cloud_client::Client::new(&url, "fixture".into())
            .unwrap()
            .with_content_encryption(
                "00000000-0000-4000-8000-000000000001",
                Some(WorkspaceKey::from_entropy([39; 32])),
                true,
            ),
    ));
    let executor = Executor::new(config).unwrap();
    executor.purge_expired().unwrap();
    executor.expired_metadata(&record.spec.id).unwrap();
    assert!(requests.lock().unwrap().is_empty());
    for count in 1..=3 {
        executor.reconcile_cloud_tombstones().unwrap();
        assert_eq!(requests.lock().unwrap().len(), count);
    }
    let requests = requests.lock().unwrap();
    assert_eq!(requests.iter().collect::<BTreeSet<_>>().len(), 3);
    drop(requests);
    let metadata = executor.expired_metadata(&record.spec.id).unwrap().unwrap();
    assert_eq!(
        metadata["reconciliation"]["cloud_error_code"],
        "task_not_found"
    );
    executor.purge_expired().unwrap();
    assert_eq!(
        executor.expired_metadata(&record.spec.id).unwrap().unwrap()["reconciliation"],
        metadata["reconciliation"]
    );
    let _ = ureq::get(&format!("{url}/stop")).call();
    server.join().unwrap();
}

#[test]
fn completed_result_publication_uses_saved_bytes_and_durable_receipt() {
    let (root, _config, mut executor, signer) = legacy_fixture();
    let mut record = retained_fixture_record(&executor, JobState::Succeeded, now_ms() + 60_000);
    let old_id = record.spec.id.clone();
    record.spec.id = lockyard_cloud_client::ulid();
    // Maximum supported retention ends after the cloud's ULID-based year window.
    std::thread::sleep(Duration::from_millis(2));
    record.updated_at_ms = now_ms();
    let retention = record.retention.as_mut().unwrap();
    retention.content_ttl_seconds = 365 * 24 * 60 * 60;
    retention.terminal_expires_at_ms = Some(record.updated_at_ms + 365 * 24 * 60 * 60 * 1000);
    let state = executor.inner.config.state_dir.clone();
    fs::rename(
        state.join("jobs").join(&old_id),
        state.join("jobs").join(&record.spec.id),
    )
    .unwrap();
    {
        let mut jobs = executor.inner.jobs.lock().unwrap();
        let mut entry = jobs.remove(&old_id).unwrap();
        record.result_manifest = Some(signed_legacy_result(&signer, &record));
        entry.record = record.clone();
        jobs.insert(record.spec.id.clone(), entry);
    }
    let raw = format!(
        " {}\n",
        serde_json::to_string(record.result_manifest.as_ref().unwrap()).unwrap()
    )
    .into_bytes();
    let job_dir = state.join("jobs").join(&record.spec.id);
    lockyard_core::fsio::replace(&job_dir.join("signed-result.json"), &raw, 0o600).unwrap();
    persist(&state, &record).unwrap();
    let key = WorkspaceKey::from_entropy([49; 32]);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let expected = raw.clone();
    let job_id = record.spec.id.clone();
    let decrypt_key = key.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let quota = Arc::new(AtomicBool::new(true));
    let server_quota = quota.clone();
    let server = std::thread::spawn(move || {
        let mut frozen_wire = None;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                if stream.read_exact(&mut b).is_err() {
                    return;
                }
                headers.push(b[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            if headers.starts_with("GET /stop ") {
                return;
            }
            if headers.starts_with("GET /api/v1/protocol ") {
                let body = serde_json::json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":["signed_results_v1"]}).to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nLockyard-Protocol: 2\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            } else {
                assert!(headers.starts_with("PUT /api/v1/nodes/worker/jobs/"));
                let length = headers
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .unwrap()
                    .1
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let raw = decrypt_key
                    .decrypt(
                        "00000000-0000-4000-8000-000000000001",
                        &format!("node-result/worker/{job_id}"),
                        std::str::from_utf8(&body).unwrap(),
                    )
                    .unwrap();
                assert_eq!(raw.as_bytes(), expected);
                let expiry = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("Lockyard-Result-Expires-At"))
                    .unwrap()
                    .1
                    .trim()
                    .to_owned();
                let wire = (body, expiry);
                if let Some(original) = &frozen_wire {
                    assert_eq!(original, &wire);
                } else {
                    frozen_wire = Some(wire);
                }
                if server_quota.load(Ordering::SeqCst) {
                    let problem = serde_json::json!({"type":"urn:lockyard:problem:relay_budget_exceeded",
                        "status":429,"code":"relay_budget_exceeded","detail":"quota","details":null}).to_string();
                    write!(stream, "HTTP/1.1 429 Refused\r\nLockyard-Protocol: 2\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{problem}", problem.len()).unwrap();
                    tx.send(false).unwrap();
                    continue;
                }
                stream.write_all(b"HTTP/1.1 204 No Content\r\nLockyard-Protocol: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                tx.send(true).unwrap();
            }
        }
    });
    let client = Arc::new(
        lockyard_cloud_client::Client::new(&url, "fixture".into())
            .unwrap()
            .with_content_encryption("00000000-0000-4000-8000-000000000001", Some(key), true)
            .with_pending_journal(root.path().canonicalize().unwrap().join("pending"))
            .unwrap(),
    );
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .signed_results = Some(client.clone());
    // A permanently invalid first job must not starve publication of the next result.
    let mut bad = record.clone();
    bad.spec.id = "00000000000000000000000000".into();
    let bad_dir = state.join("jobs").join(&bad.spec.id);
    private_dir_new(&bad_dir).unwrap();
    lockyard_core::fsio::replace(&bad_dir.join("signed-result.json"), b"invalid", 0o600).unwrap();
    executor.inner.jobs.lock().unwrap().insert(
        bad.spec.id.clone(),
        Entry {
            record: bad,
            cancel: Arc::new(AtomicBool::new(false)),
            artifacts: Arc::new(Mutex::new(())),
        },
    );
    executor.publish_signed_results();
    assert!(rx.try_recv().is_err());
    executor.publish_signed_results();
    assert!(
        !rx.recv_timeout(Duration::from_secs(2))
            .expect("missing quota refusal")
    );
    let pending = client
        .pending_operations()
        .pop()
        .expect("quota must retain addressable bytes");
    assert!(!job_dir.join("signed-result.suspended").exists());
    for _ in 0..3 {
        executor.publish_signed_results();
    }
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(client.pending_operations()[0].body, pending.body);
    quota.store(false, Ordering::SeqCst);
    client.resume_signed_result(&pending.key).unwrap();
    for _ in 0..2 {
        executor.publish_signed_results();
    }
    assert!(
        rx.recv_timeout(Duration::from_secs(2))
            .expect("completed result was not published")
    );
    assert!(job_dir.join("signed-result.published").exists());
    assert!(client.pending_operations().is_empty());
    executor.publish_signed_results();
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(fs::read(job_dir.join("signed-result.json")).unwrap(), raw);
    let _ = ureq::get(&format!("{url}/stop")).call();
    server.join().unwrap();
}

#[test]
fn expired_result_replay_persists_receipt_before_ack_and_survives_crash() {
    let (root, mut config, mut executor, signer) = legacy_fixture();
    let expiry = now_ms() + 60_000;
    let mut record = retained_fixture_record(&executor, JobState::Succeeded, expiry);
    let old_id = record.spec.id.clone();
    record.spec.id = lockyard_cloud_client::ulid();
    record.result_manifest = Some(signed_legacy_result(&signer, &record));
    let job_dir = config.state_dir.join("jobs").join(&record.spec.id);
    fs::rename(config.state_dir.join("jobs").join(&old_id), &job_dir).unwrap();
    {
        let mut jobs = executor.inner.jobs.lock().unwrap();
        let mut entry = jobs.remove(&old_id).unwrap();
        entry.record = record.clone();
        jobs.insert(record.spec.id.clone(), entry);
    }
    let raw = format!(
        " {}\n",
        serde_json::to_string(record.result_manifest.as_ref().unwrap()).unwrap()
    )
    .into_bytes();
    lockyard_core::fsio::replace(&job_dir.join("signed-result.json"), &raw, 0o600).unwrap();
    persist(&config.state_dir, &record).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (sent, received) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let mut frozen = None;
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            if headers.starts_with("GET /stop ") {
                return;
            }
            if headers.starts_with("GET /api/v1/protocol ") {
                let body = serde_json::json!({"selected_protocol":2,"min_protocol":1,
                    "max_protocol":2,"capabilities":["signed_results_v1"]})
                .to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nLockyard-Protocol: 2\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                continue;
            }
            assert!(headers.starts_with("PUT /api/v1/nodes/worker/jobs/"));
            let header = |name: &str| {
                headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.trim().to_owned())
                    .unwrap()
            };
            let mut body = vec![0; header("content-length").parse().unwrap()];
            stream.read_exact(&mut body).unwrap();
            let wire = (
                headers.lines().next().unwrap().to_owned(),
                header("X-Lockyard-Session"),
                header("Lockyard-Result-Expires-At"),
                body,
            );
            if let Some(original) = &frozen {
                assert_eq!(original, &wire, "restart must replay the frozen operation");
            } else {
                frozen = Some(wire);
            }
            stream.write_all(b"HTTP/1.1 204 No Content\r\nLockyard-Protocol: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            sent.send(()).unwrap();
        }
    });
    let journal = root.path().canonicalize().unwrap().join("pending");
    let key = WorkspaceKey::from_entropy([51; 32]);
    let make_client = || {
        Arc::new(
            lockyard_cloud_client::Client::new(&url, "fixture".into())
                .unwrap()
                .with_content_encryption(
                    "00000000-0000-4000-8000-000000000001",
                    Some(key.clone()),
                    true,
                )
                .with_pending_journal(journal.clone())
                .unwrap(),
        )
    };
    let client = make_client();
    client
        .put_signed_result("worker", "worker", &record.spec.id, &raw, expiry)
        .unwrap();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    let pending = client.pending_operations().pop().unwrap();
    let scoped_journal = fs::read_dir(&journal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    let journal_path = fs::read_dir(&scoped_journal)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let saved_pending = fs::read(&journal_path).unwrap();
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .signed_results = Some(client.clone());
    assert_eq!(executor.purge_expired_at(expiry).unwrap(), 1);
    assert!(!job_dir.exists());
    let receipt = config
        .state_dir
        .join("job-tombstones")
        .join(format!("{}.signed-result.published", record.spec.id));
    fs::create_dir(&receipt).unwrap(); // Deterministic receipt publication failure.
    executor.publish_signed_results();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        client.pending_operations(),
        vec![pending.clone()],
        "a 204 without a durable local receipt must retain W4 bytes"
    );
    assert_eq!(fs::read(&journal_path).unwrap(), saved_pending);

    drop(executor);
    drop(client);
    let client = make_client();
    assert_eq!(client.pending_operations(), vec![pending.clone()]);
    config.signed_results = Some(client.clone());
    let executor = Executor::new(config.clone()).unwrap();
    fs::remove_dir(&receipt).unwrap();
    executor.publish_signed_results();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(client.pending_operations().is_empty());
    let saved_receipt =
        fs::read(&receipt).expect("replay must leave a durable publication receipt");
    assert_eq!(
        saved_receipt,
        crate::provenance::sha256(pending.body.as_ref().unwrap().as_bytes()).as_bytes(),
        "the content-free receipt must commit to the exact frozen ciphertext"
    );
    assert!(
        !job_dir.exists(),
        "publication must not resurrect expired content"
    );

    // Restore exactly the durable state at a crash between receipt publication and W4 cleanup.
    lockyard_core::fsio::replace(&journal_path, &saved_pending, 0o600).unwrap();
    drop(executor);
    config.signed_results = None;
    drop(client);
    let client = make_client();
    assert_eq!(client.pending_operations(), vec![pending]);
    config.signed_results = Some(client.clone());
    let executor = Executor::new(config).unwrap();
    assert_eq!(fs::read(&receipt).unwrap(), saved_receipt);
    executor.publish_signed_results();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(client.pending_operations().is_empty());
    assert!(!journal_path.exists());
    executor.purge_expired().unwrap();
    assert_eq!(fs::read(&receipt).unwrap(), saved_receipt);
    assert!(!job_dir.exists());
    let _ = ureq::get(&format!("{url}/stop")).call();
    server.join().unwrap();
}
