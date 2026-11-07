// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#![cfg(unix)]
//! Actual CLI with a local control protocol fixture; this does not execute a container.
use lockyard_node::{
    provenance::{self, ArtifactDigest, ResultManifest, SigningKey},
    wire::{JobRecord, JobSpec, JobState, LogChunk},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env_remove("LOCKYARD_NODE_CONFIG");
    command
}
fn fixture(root: &Path, patch: &[u8]) -> (SigningKey, JobRecord) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let key = SigningKey::generate(&root.join("signing.pk8")).unwrap();
    let spec = JobSpec {
        id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        repository: "repo".into(),
        revision: "HEAD".into(),
        runner: "runner".into(),
        arguments: vec![],
        prompt: None,
        timeout_seconds: None,
        priority: 0,
        workflow_inputs: Vec::new(),
        expected_runner_sha256: None,
        owner_approval: None,
    };
    let image = format!("sha256:{}", "a".repeat(64));
    let manifest = ResultManifest {
        version: 1,
        node_id: "worker".into(),
        workspace: "workspace".into(),
        job_id: spec.id.clone(),
        repository: "repo".into(),
        runner: "runner".into(),
        request_sha256: provenance::sha256(&serde_json::to_vec(&spec).unwrap()),
        resolved_revision: "b".repeat(40),
        image_reference: image.clone(),
        image_digest: image.clone(),
        image_config_digest: Some(image.clone()),
        image_attestation_sha256: Some("c".repeat(64)),
        execution_attempted: true,
        completed_at_ms: 1234,
        state: JobState::Succeeded,
        exit_code: Some(0),
        error_code: None,
        artifacts: BTreeMap::from([(
            "result.patch".into(),
            ArtifactDigest {
                size_bytes: patch.len() as u64,
                sha256: provenance::sha256(patch),
                truncated: false,
                error_code: None,
            },
        )]),
    };
    let record = JobRecord {
        had_runtime_credentials: true,
        spec,
        state: JobState::Succeeded,
        agent: "derived".into(),
        submitter: "controller".into(),
        submitter_certificate_sha256: None,
        created_at_ms: 1000,
        updated_at_ms: 1234,
        resolved_revision: Some("b".repeat(40)),
        worktree: None,
        pid: Some(42),
        exit_code: Some(0),
        error_code: None,
        log_bytes: 0,
        log_truncated: false,
        log_error: None,
        patch_bytes: patch.len() as u64,
        patch_truncated: false,
        patch_error: None,
        configured_image: Some(image),
        admission_runner_sha256: None,
        admission_repository_sha256: None,
        admitted_image: None,
        result_manifest: Some(key.sign_result(&manifest).unwrap()),
        provenance_error: None,
        notification_accounted_certificate_sha256: None,
        retention: None,
    };
    (key, record)
}
fn config(root: &Path, key: &SigningKey, pin: bool) -> std::path::PathBuf {
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let trust = if pin {
        BTreeMap::from([("worker", key.trusted_key())])
    } else {
        BTreeMap::new()
    };
    let value = json!({"node_id":"controller","workspace":"workspace","state_dir":state,"certificate":root.join("unused-cert.der"),"private_key":root.join("unused-key.der"),"trust_anchors":[],"peers":[],"rpc_timeout_seconds":1,"result_trust":trust});
    let path = root.join("node.toml");
    fs::write(&path, toml::to_string(&value).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}
fn control(root: &Path, replies: Vec<Value>) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(root.join("state/control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => {
                        panic!("control fixture did not receive expected request: {error}")
                    }
                }
            };
            // Darwin inherits the listener's O_NONBLOCK flag on accepted sockets.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut bytes).unwrap();
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request["command"], "rpc");
            let response = serde_json::to_vec(&json!({"value":reply,"error":null})).unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        }
    })
}
#[test]
fn patch_download_requires_pinned_signature_and_verifies_bytes_before_exposing_destination() {
    let patch = b"fixture patch bytes\n";
    for scenario in ["missing_pin", "bad_signature", "bad_bytes", "valid"] {
        let root = tempfile::tempdir().unwrap();
        let (key, mut record) = fixture(root.path(), patch);
        let configuration = config(root.path(), &key, scenario != "missing_pin");
        if scenario == "bad_signature" {
            record.result_manifest.as_mut().unwrap().signature = "A".repeat(88);
        }
        let replies = if scenario == "missing_pin" {
            vec![]
        } else {
            let mut values = vec![json!({"ok":true,"result":record})];
            if scenario != "bad_signature" {
                let bytes = if scenario == "bad_bytes" {
                    b"tampered bytes\n".to_vec()
                } else {
                    patch.to_vec()
                };
                let chunk = LogChunk {
                    offset: 0,
                    next_offset: bytes.len() as u64,
                    bytes,
                    eof: true,
                    truncated: false,
                };
                values.push(json!({"ok":true,"result":chunk}));
            }
            values
        };
        let server = if replies.is_empty() {
            None
        } else {
            Some(control(root.path(), replies))
        };
        let destination = root.path().join("download.patch");
        let result = command(root.path())
            .args([
                "--json",
                "job",
                "patch",
                "worker",
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "--output",
                destination.to_str().unwrap(),
                "--config",
                configuration.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        if let Some(server) = server {
            server.join().unwrap();
        }
        assert_eq!(
            result.status.success(),
            scenario == "valid",
            "{scenario}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(destination.exists(), scenario == "valid", "{scenario}");
        if scenario == "valid" {
            assert_eq!(fs::read(&destination).unwrap(), patch);
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".lockyard-patch-")
        }));
    }
}
#[test]
fn saved_manifest_cli_checks_explicit_revision_image_and_artifact() {
    let root = tempfile::tempdir().unwrap();
    let patch = b"signed fixture\n";
    let (key, record) = fixture(root.path(), patch);
    let manifest = root.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(record.result_manifest.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    let artifact = root.path().join("result.patch");
    fs::write(&artifact, patch).unwrap();
    let public_key = key.trusted_key().public_key;
    let invoke = |revision: &str| {
        command(root.path())
            .args([
                "--json",
                "job",
                "verify-manifest",
                "--manifest",
                manifest.to_str().unwrap(),
                "--public-key",
                &public_key,
                "--node",
                "worker",
                "--workspace",
                "workspace",
                "--job",
                &record.spec.id,
                "--revision",
                revision,
                "--image-digest",
                record.configured_image.as_ref().unwrap(),
                "--patch",
                artifact.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    assert!(invoke(&"b".repeat(40)).status.success());
    assert!(!invoke(&"f".repeat(40)).status.success());
    let mut payload = provenance::verify_result_identity(
        record.result_manifest.as_ref().unwrap(),
        &key.trusted_key(),
        "worker",
        "workspace",
        &record.spec.id,
    )
    .unwrap();
    for (truncated, error_code) in [
        (true, None),
        (false, Some("patch_collection_failed".to_string())),
    ] {
        let descriptor = payload.artifacts.get_mut("result.patch").unwrap();
        descriptor.truncated = truncated;
        descriptor.error_code = error_code;
        let signed = key.sign_result(&payload).unwrap();
        fs::write(&manifest, serde_json::to_vec(&signed).unwrap()).unwrap();
        assert!(!invoke(&"b".repeat(40)).status.success());
    }
    fs::write(
        &manifest,
        serde_json::to_vec(record.result_manifest.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    fs::write(&artifact, b"tampered").unwrap();
    assert!(!invoke(&"b".repeat(40)).status.success());
}

#[test]
fn signed_large_binary_patch_download_progresses_in_frame_safe_chunks() {
    let root = tempfile::tempdir().unwrap();
    let patch = vec![255; 150_000];
    let (key, record) = fixture(root.path(), &patch);
    let configuration = config(root.path(), &key, true);
    let mut replies = vec![json!({"ok":true,"result":record})];
    let mut offset = 0;
    for bytes in patch.chunks(lockyard_node::wire::MAX_TRANSFER_BYTES as usize) {
        let next = offset + bytes.len();
        replies.push(json!({"ok":true,"result":LogChunk {offset:offset as u64,next_offset:next as u64,bytes:bytes.to_vec(),eof:next==patch.len(),truncated:false}}));
        offset = next;
    }
    let server = control(root.path(), replies);
    let destination = root.path().join("large.patch");
    let output = command(root.path())
        .args([
            "--json",
            "job",
            "patch",
            "worker",
            &record.spec.id,
            "--config",
            configuration.to_str().unwrap(),
            "--output",
            destination.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().unwrap();
    assert_eq!(fs::read(destination).unwrap(), patch);
}
