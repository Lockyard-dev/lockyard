// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#![cfg(unix)]
//! Actual offline CLI process tests. No broker, network send or workload execution occurs.
use lockyard_node::{
    approvals::{self, ApprovalExpectation, OwnerApproval},
    executor::RunnerProfile,
    provenance::{self, SigningKey},
    wire::JobSpec,
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn cli(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env_remove("LOCKYARD_NODE_CONFIG");
    command.arg("--json");
    command
}
fn checked(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn profile(key: Value) -> Value {
    json!({"action":"deploy","owner_approval_authorities":[{"public_key":key}],
        "container":{"runtime":"docker","runtime_program":"/usr/bin/docker","image":format!("sha256:{}","a".repeat(64)),
            "git_program":"/usr/bin/git","memory_mb":128,"cpu_millis":1000,"pids_limit":64,"network":"bridge"},
        "program":"/usr/bin/deploy","fixed_args":[],"env_passthrough":[]})
}
fn request() -> Value {
    json!({"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo","revision":"HEAD","runner":"deploy","arguments":["reviewed-target"],"prompt":null,"timeout_seconds":30})
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn context(command: &mut Command, request: &Path, runner: &Path) {
    command
        .arg("--request")
        .arg(request)
        .arg("--runner-config")
        .arg(runner)
        .args([
            "--workspace",
            "workspace",
            "--node",
            "worker",
            "--certificate-sha256",
            &"b".repeat(64),
            "--revision",
            &"c".repeat(40),
        ]);
}
fn prepare(root: &Path, request: &Path, runner: &Path, output: &Path) -> Value {
    let mut command = cli(root);
    command.args(["node", "approval", "prepare"]);
    context(&mut command, request, runner);
    command
        .args([
            "--not-before-ms",
            &(now() - 1000).to_string(),
            "--expires-at-ms",
            &(now() + 60_000).to_string(),
        ])
        .arg("--output")
        .arg(output);
    checked(command.output().unwrap())
}

#[test]
fn offline_cli_prepares_signs_verifies_and_attaches_exact_request() {
    let root = tempfile::tempdir().unwrap();
    let generated = checked(
        cli(root.path())
            .args(["node", "approval", "key", "--name", "owner"])
            .output()
            .unwrap(),
    );
    let key = PathBuf::from(generated["key_file"].as_str().unwrap());
    assert!(key.starts_with(root.path().join("config/lockyard/keys/owner-approvals")));
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let request_file = root.path().join("request.json");
    let runner_file = root.path().join("runner.json");
    write(&request_file, &request());
    write(&runner_file, &profile(generated["public_key"].clone()));
    let claim_file = root.path().join("claim.json");
    let signed_file = root.path().join("approval.json");
    prepare(root.path(), &request_file, &runner_file, &claim_file);
    checked(
        cli(root.path())
            .args(["node", "approval", "sign"])
            .arg("--input")
            .arg(&claim_file)
            .arg("--request")
            .arg(&request_file)
            .arg("--runner-config")
            .arg(&runner_file)
            .arg("--key-file")
            .arg(&key)
            .arg("--output")
            .arg(&signed_file)
            .output()
            .unwrap(),
    );
    let attached = root.path().join("authorized-request.json");
    let mut command = cli(root.path());
    command.args(["node", "approval", "verify"]);
    context(&mut command, &request_file, &runner_file);
    command
        .arg("--approval")
        .arg(&signed_file)
        .arg("--public-key")
        .arg(generated["public_key"].as_str().unwrap())
        .arg("--output-request")
        .arg(&attached);
    let verified = checked(command.output().unwrap());
    assert_eq!(verified["verified"], true);
    let spec: JobSpec = serde_json::from_slice(&fs::read(&attached).unwrap()).unwrap();
    assert!(spec.owner_approval.is_some());
    let runner: RunnerProfile = serde_json::from_slice(&fs::read(&runner_file).unwrap()).unwrap();
    let expected = ApprovalExpectation {
        workspace: "workspace",
        node_id: "worker",
        node_certificate_sha256: &"b".repeat(64),
        spec: &spec,
        resolved_revision: &"c".repeat(40),
        runner: &runner,
    };
    approvals::enforce(&expected, now()).unwrap();
    // Modified arguments cannot be signed using the old owner-reviewed claim.
    let mut altered = request();
    altered["arguments"] = json!(["unreviewed-target"]);
    write(&request_file, &altered);
    assert!(
        !cli(root.path())
            .args(["node", "approval", "sign"])
            .arg("--input")
            .arg(&claim_file)
            .arg("--request")
            .arg(&request_file)
            .arg("--runner-config")
            .arg(&runner_file)
            .arg("--key-file")
            .arg(&key)
            .arg("--output")
            .arg(root.path().join("wrong.json"))
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn cli_rejects_unprotected_owner_keys_symlinked_inputs_and_duplicate_key_creation() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let generated = checked(
        cli(root.path())
            .args(["node", "approval", "key", "--name", "owner"])
            .output()
            .unwrap(),
    );
    assert!(
        !cli(root.path())
            .args(["node", "approval", "key", "--name", "owner"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let request_file = root.path().join("request.json");
    let runner_file = root.path().join("runner.json");
    write(&request_file, &request());
    write(&runner_file, &profile(generated["public_key"].clone()));
    let claim_file = root.path().join("claim.json");
    prepare(root.path(), &request_file, &runner_file, &claim_file);
    let copied = root.path().join("unsafe-copy.pk8");
    fs::copy(generated["key_file"].as_str().unwrap(), &copied).unwrap();
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(SigningKey::load(&copied).is_ok()); // A valid key still fails the owner-custody location gate.
    assert!(
        !cli(root.path())
            .args(["node", "approval", "sign"])
            .arg("--input")
            .arg(&claim_file)
            .arg("--request")
            .arg(&request_file)
            .arg("--runner-config")
            .arg(&runner_file)
            .arg("--key-file")
            .arg(&copied)
            .arg("--output")
            .arg(root.path().join("wrong.json"))
            .output()
            .unwrap()
            .status
            .success()
    );
    let link = root.path().join("linked-request.json");
    std::os::unix::fs::symlink(&request_file, &link).unwrap();
    let mut command = cli(root.path());
    command.args(["node", "approval", "prepare"]);
    context(&mut command, &link, &runner_file);
    command
        .args([
            "--not-before-ms",
            &(now() - 1000).to_string(),
            "--expires-at-ms",
            &(now() + 60_000).to_string(),
        ])
        .arg("--output")
        .arg(root.path().join("wrong-claim.json"));
    assert!(!command.output().unwrap().status.success());
}

#[test]
fn cli_verification_rejects_context_and_authority_substitution_without_writing_request() {
    let root = tempfile::tempdir().unwrap();
    let generated = checked(
        cli(root.path())
            .args(["node", "approval", "key", "--name", "owner"])
            .output()
            .unwrap(),
    );
    let request_file = root.path().join("request.json");
    let runner_file = root.path().join("runner.json");
    write(&request_file, &request());
    write(&runner_file, &profile(generated["public_key"].clone()));
    let claim_file = root.path().join("claim.json");
    prepare(root.path(), &request_file, &runner_file, &claim_file);
    let claim = OwnerApproval::load(&claim_file).unwrap();
    let key = SigningKey::load(Path::new(generated["key_file"].as_str().unwrap())).unwrap();
    let signed_file = root.path().join("approval.json");
    write(&signed_file, &claim.sign(&key).unwrap());
    assert!(provenance::load_document(&signed_file).is_ok());
    let destination = root.path().join("should-not-exist.json");
    for scenario in ["request", "authority"] {
        let mut altered = request();
        if scenario == "request" {
            altered["id"] = json!("01ARZ3NDEKTSV4RRFFQ69G5FAW");
        }
        write(&request_file, &altered);
        let mut command = cli(root.path());
        command.args(["node", "approval", "verify"]);
        context(&mut command, &request_file, &runner_file);
        command
            .arg("--approval")
            .arg(&signed_file)
            .arg("--public-key")
            .arg(if scenario == "authority" {
                "d".repeat(64)
            } else {
                generated["public_key"].as_str().unwrap().to_owned()
            })
            .arg("--output-request")
            .arg(&destination);
        assert!(!command.output().unwrap().status.success());
        assert!(!destination.exists());
    }
}

#[test]
fn owner_key_custody_rejects_git_ancestor_and_redirected_xdg_before_key_creation() {
    use std::os::unix::fs::symlink;
    for redirected in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let checkout = root.path().join("checkout");
        fs::create_dir(&checkout).unwrap();
        assert!(
            Command::new("git")
                .arg("init")
                .arg("-q")
                .arg(&checkout)
                .status()
                .unwrap()
                .success()
        );
        fs::create_dir(checkout.join("config")).unwrap();
        let selected = if redirected {
            let alias = root.path().join("config-alias");
            symlink(checkout.join("config"), &alias).unwrap();
            alias
        } else {
            checkout.join("config")
        };
        let output = cli(root.path())
            .env("XDG_CONFIG_HOME", &selected)
            .args(["node", "approval", "key", "--name", "owner"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            !checkout
                .join("config/lockyard/keys/owner-approvals/owner.pk8")
                .exists()
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("outside Git"));
    }
}
#[test]
fn owner_key_custody_detects_repository_created_after_key_generation() {
    let root = tempfile::tempdir().unwrap();
    let generated = checked(
        cli(root.path())
            .args(["node", "approval", "key", "--name", "owner"])
            .output()
            .unwrap(),
    );
    let key = PathBuf::from(generated["key_file"].as_str().unwrap());
    let request_file = root.path().join("request.json");
    let runner_file = root.path().join("runner.json");
    write(&request_file, &request());
    write(&runner_file, &profile(generated["public_key"].clone()));
    let claim_file = root.path().join("claim.json");
    prepare(root.path(), &request_file, &runner_file, &claim_file);
    assert!(
        Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(root.path())
            .status()
            .unwrap()
            .success()
    );
    let output_path = root.path().join("approval.json");
    let output = cli(root.path())
        .args(["node", "approval", "sign"])
        .arg("--input")
        .arg(&claim_file)
        .arg("--request")
        .arg(&request_file)
        .arg("--runner-config")
        .arg(&runner_file)
        .arg("--key-file")
        .arg(&key)
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!output_path.exists());
    assert!(key.exists());
}
