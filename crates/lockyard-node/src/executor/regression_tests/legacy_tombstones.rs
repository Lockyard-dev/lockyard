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
