// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Real CLI + two daemon processes + pinned encrypted QUIC. Execution is deliberately
//! rejected by /bin/false before any container starts; this is a negative runtime proof.
#![cfg(unix)]
use lockyard_node::{
    host::{NodeConfig, PeerConfig},
    provenance::{self, SigningKey},
    wire::{self, Operation},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    net::UdpSocket,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_CONFIG_HOME", root.join("config"));
    command
}
fn cli(root: &Path, args: &[&str]) -> Value {
    let output = command(root).arg("--json").args(args).output().unwrap();
    assert!(
        output.status.success(),
        "CLI failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn init(root: &Path, node: &str) -> (PathBuf, NodeConfig) {
    fs::create_dir(root).unwrap();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let keys = root.join("config/lockyard/keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    private_write(&keys.join("workflow-fixture.key"), &[91; 32]);
    let path = root.join("node.toml");
    let state = root.join("state");
    cli(
        root,
        &[
            "node",
            "init",
            "--config",
            path.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--node-id",
            node,
            "--workspace",
            "workflow-fixture",
            "--tls-name",
            &format!("{node}.example"),
        ],
    );
    let config = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    (path, config)
}
fn save(path: &Path, config: &NodeConfig) {
    private_write(path, toml::to_string(config).unwrap().as_bytes());
}
struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn serve(root: &Path, config: &Path) -> Service {
    let child = command(root)
        .args(["node", "serve", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut service = Service(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = command(root)
            .args([
                "--json",
                "node",
                "status",
                "--config",
                config.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        if output.status.success() {
            return service;
        }
        assert!(
            service.0.try_wait().unwrap().is_none(),
            "fixture daemon stopped before readiness"
        );
        assert!(Instant::now() < deadline, "fixture daemon was not ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn mcp(root: &Path, name: &str, arguments: Value) -> Value {
    let mut child = command(root)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(),"{}",json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}})).unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}
#[test]
fn distributed_dag_real_cli_encrypted_quic_signed_negative_runtime_and_restart() {
    let root = tempfile::tempdir().unwrap();
    let controller_root = root.path().join("controller");
    let worker_root = root.path().join("worker");
    let (controller_path, mut controller) = init(&controller_root, "controller");
    let (worker_path, mut worker) = init(&worker_root, "worker");
    let worker_pin =
        lockyard_node::quic::PeerPin::certificate(&fs::read(&worker.certificate).unwrap()).to_hex();
    let controller_pin =
        lockyard_node::quic::PeerPin::certificate(&fs::read(&controller.certificate).unwrap())
            .to_hex();
    let address = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    worker.listen = Some(address);
    worker.trust_anchors = vec![controller.certificate.clone()];
    worker.peers = vec![PeerConfig {
        node_id: "controller".into(),
        address: None,
        tls_name: "controller.example".into(),
        certificate_sha256: controller_pin,
        certificate: controller.certificate.clone(),
        allowed_operations: vec![
            Operation::NodePing,
            Operation::JobSubmit,
            Operation::JobStatus,
            Operation::JobCancel,
        ],
    }];
    controller.peers = vec![PeerConfig {
        node_id: "worker".into(),
        address: Some(address),
        tls_name: "worker.example".into(),
        certificate_sha256: worker_pin.clone(),
        certificate: worker.certificate.clone(),
        allowed_operations: vec![Operation::NodePing],
    }];
    controller.trust_anchors = vec![worker.certificate.clone()];
    let checkout = worker_root.join("checkout");
    fs::create_dir(&checkout).unwrap();
    git(&checkout, &["init", "-q"]);
    git(
        &checkout,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&checkout, &["config", "user.name", "Fixture"]);
    fs::write(checkout.join("base.txt"), b"original checkout\n").unwrap();
    git(&checkout, &["add", "base.txt"]);
    git(&checkout, &["commit", "-qm", "fixture"]);
    let signing = SigningKey::generate(&worker_root.join("result.pk8")).unwrap();
    let trusted = signing.trusted_key();
    let state = worker.state_dir.join("executor");
    // Missing attestation files and an unavailable runtime are deliberate. No
    // synthetic resource-capable runtime or requested workload is executed.
    worker.executor=Some(serde_json::from_value(json!({"node_id":"worker","state_dir":state,
        "repositories":{"repo":{"checkout":checkout,"cloud":null,"retention":{"content_ttl_seconds":3600}}},
        "provenance":{"workspace":"workflow-fixture","key_file":worker_root.join("result.pk8"),"public_key":trusted.public_key},
        "runners":{"build":{"program":"/bin/false","kind":"command","mcp_program":null,"fixed_args":[],"env_passthrough":[],
            "container":{"runtime":"docker","runtime_program":"/bin/false","image":format!("sha256:{}","a".repeat(64)),
                "memory_mb":128,"cpu_millis":1000,"pids_limit":64,"network":"none","supply_chain":{
                    "attestation_file":worker_root.join("unused-attestation.json"),"sbom_file":worker_root.join("unused-sbom.json"),
                    "vulnerability_report_file":worker_root.join("unused-report.json"),"trusted_signers":[trusted],
                    "max_attestation_age_seconds":3600,"max_report_age_seconds":3600,"max_database_age_seconds":3600,
                    "max_critical":0,"max_high":0,"max_medium":0,"max_low":0,"max_unknown":0}}}},
        "limits":{"max_concurrency":1,"max_timeout_seconds":30,"max_log_bytes":4096,"max_patch_bytes":4096,"max_pending_jobs":16},
        "scheduling":{"labels":{"os":"linux"},"capacity":{"cpu_millis":2000,"memory_mb":2048}}})).unwrap());
    let owner_directory = controller_root.join("config/lockyard/keys/owner-approvals");
    fs::create_dir(&owner_directory).unwrap();
    fs::set_permissions(&owner_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let owner_path = owner_directory.join("release-owner.pk8");
    let owner = SigningKey::generate(&owner_path).unwrap();
    let mut deploy = worker.executor.as_ref().unwrap().runners["build"].clone();
    deploy.action = lockyard_node::approvals::ManagedAction::Deploy;
    deploy.owner_approval_authorities = vec![owner.trusted_key()];
    let reviewed_profile = controller_root.join("reviewed-deploy-profile.json");
    private_write(
        &reviewed_profile,
        &serde_json::to_vec_pretty(&deploy).unwrap(),
    );
    worker
        .executor
        .as_mut()
        .unwrap()
        .runners
        .insert("deploy".into(), deploy);
    controller
        .result_trust
        .insert("worker".into(), signing.trusted_key());
    controller.project_retention.insert(
        "repo".into(),
        lockyard_node::retention::RetentionPolicy {
            content_ttl_seconds: 3600,
        },
    );
    controller.workflow = Some(lockyard_node::workflow::WorkflowPolicy {
        poll_interval_ms: 250,
        ..Default::default()
    });
    save(&worker_path, &worker);
    save(&controller_path, &controller);
    let _worker_service = serve(&worker_root, &worker_path);
    let controller_service = serve(&controller_root, &controller_path);
    let caps = cli(
        &controller_root,
        &[
            "node",
            "describe",
            "worker",
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    assert_eq!(
        caps["result"]["capabilities"]["certificate_sha256"],
        worker_pin
    );
    assert_eq!(caps["result"]["capabilities"]["labels"]["os"], "linux");
    let flow = wire::new_id().unwrap();
    let definition_path = controller_root.join("flow.json");
    let job = json!({"repository":"repo","revision":"HEAD","runner":"build","arguments":[],"prompt":"PRIVATE-DAG-PROMPT-FIXTURE","timeout_seconds":30});
    let definition = json!({"version":1,"id":flow,"max_parallel":2,"steps":[
        {"key":"a","needs":[],"placement":{"labels":{"os":"linux"}},"job":job},
        {"key":"b","needs":[],"placement":{"node":"worker"},"job":job},
        {"key":"c","needs":["a","b"],"placement":{},"job":job}]});
    private_write(&definition_path, &serde_json::to_vec(&definition).unwrap());
    cli(
        &controller_root,
        &[
            "node",
            "workflow",
            "submit",
            "--file",
            definition_path.to_str().unwrap(),
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let summary = loop {
        let summary = cli(
            &controller_root,
            &[
                "node",
                "workflow",
                "status",
                &flow,
                "--config",
                controller_path.to_str().unwrap(),
            ],
        );
        if summary["state"] == "failed" {
            break summary;
        }
        assert!(Instant::now() < deadline, "DAG did not settle: {summary}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let steps = summary["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0]["state"], "failed");
    assert_eq!(steps[1]["state"], "failed");
    assert_eq!(steps[2]["state"], "skipped");
    assert!(
        !serde_json::to_string(&summary)
            .unwrap()
            .contains("PRIVATE-DAG")
    );
    for key in ["a", "b"] {
        let id = lockyard_node::workflow::step_job_id(&flow, key).unwrap();
        let record = cli(
            &controller_root,
            &[
                "job",
                "status",
                "worker",
                &id,
                "--config",
                controller_path.to_str().unwrap(),
            ],
        );
        assert_eq!(
            record["result"]["error_code"],
            "container_runtime_unavailable"
        );
        assert_eq!(record["result"]["pid"], Value::Null);
        let signed = serde_json::from_value(record["result"]["result_manifest"].clone()).unwrap();
        let manifest = provenance::verify_result_identity(
            &signed,
            &signing.trusted_key(),
            "worker",
            "workflow-fixture",
            &id,
        )
        .unwrap();
        assert!(!manifest.execution_attempted);
        assert_eq!(manifest.state, wire::JobState::Failed);
    }
    assert_eq!(
        fs::read(checkout.join("base.txt")).unwrap(),
        b"original checkout\n"
    );
    assert_eq!(
        fs::read_dir(worker.state_dir.join("executor/jobs"))
            .unwrap()
            .count(),
        2
    );
    let mcp_summary = mcp(
        &controller_root,
        "flow_status",
        json!({"config":controller_path,"id":flow}),
    );
    assert_eq!(mcp_summary, summary);

    // The real daemon materializes an external action without sending it. An
    // independent owner reviews its exact profile/destination and signs locally.
    let release = wire::new_id().unwrap();
    let release_definition = controller_root.join("release.json");
    private_write(&release_definition,&serde_json::to_vec(&json!({"version":1,"id":release,"max_parallel":1,"steps":[{
        "key":"release","needs":[],"placement":{"node":"worker"},"job":{"repository":"repo","revision":"HEAD","runner":"deploy",
            "arguments":[],"prompt":"PRIVATE-DEPLOY-PROMPT-FIXTURE","timeout_seconds":30}}]})).unwrap());
    cli(
        &controller_root,
        &[
            "node",
            "workflow",
            "submit",
            "--file",
            release_definition.to_str().unwrap(),
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let waiting = loop {
        let status = cli(
            &controller_root,
            &[
                "node",
                "workflow",
                "status",
                &release,
                "--config",
                controller_path.to_str().unwrap(),
            ],
        );
        if status["state"] == "awaiting_owner" {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "external action did not await owner: {status}"
        );
        std::thread::sleep(Duration::from_millis(30));
    };
    assert_eq!(
        fs::read_dir(worker.state_dir.join("executor/jobs"))
            .unwrap()
            .count(),
        2
    );
    let owner_request = controller_root.join("owner-request.json");
    cli(
        &controller_root,
        &[
            "node",
            "workflow",
            "approval-request",
            &release,
            "release",
            "--output",
            owner_request.to_str().unwrap(),
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    let materialized: lockyard_node::approvals::MaterializedApproval =
        serde_json::from_slice(&fs::read(&owner_request).unwrap()).unwrap();
    assert_eq!(materialized.spec.revision, materialized.resolved_revision);
    assert!(materialized.spec.owner_approval.is_none());
    assert!(
        !fs::read_to_string(&owner_request)
            .unwrap()
            .contains("runtime_program")
    );
    let mcp_request = mcp(
        &controller_root,
        "flow_approval_request",
        json!({"config":controller_path,"id":release,"step":"release"}),
    );
    assert_eq!(mcp_request, serde_json::to_value(&materialized).unwrap());
    let signed_approval = controller_root.join("owner-approval.json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let exposed_owner_key = controller_root.join("private-checkout-owner.pk8");
    private_write(&exposed_owner_key, &fs::read(&owner_path).unwrap());
    let rejected_output = controller_root.join("must-not-sign.json");
    let rejected = command(&controller_root)
        .args([
            "--json",
            "node",
            "approval",
            "sign-materialized",
            "--workspace",
            "workflow-fixture",
            "--node",
            "worker",
            "--certificate-sha256",
            &worker_pin,
            "--input",
            owner_request.to_str().unwrap(),
            "--runner-config",
            reviewed_profile.to_str().unwrap(),
            "--key-file",
            exposed_owner_key.to_str().unwrap(),
            "--not-before-ms",
            &(now - 1).to_string(),
            "--expires-at-ms",
            &(now + 60_000).to_string(),
            "--output",
            rejected_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(!rejected_output.exists());
    cli(
        &controller_root,
        &[
            "node",
            "approval",
            "sign-materialized",
            "--workspace",
            "workflow-fixture",
            "--node",
            "worker",
            "--certificate-sha256",
            &worker_pin,
            "--input",
            owner_request.to_str().unwrap(),
            "--runner-config",
            reviewed_profile.to_str().unwrap(),
            "--key-file",
            owner_path.to_str().unwrap(),
            "--not-before-ms",
            &(now - 1).to_string(),
            "--expires-at-ms",
            &(now + 60_000).to_string(),
            "--output",
            signed_approval.to_str().unwrap(),
        ],
    );
    cli(
        &controller_root,
        &[
            "node",
            "workflow",
            "approval-attach",
            &release,
            "release",
            "--definition-sha256",
            waiting["definition_sha256"].as_str().unwrap(),
            "--approval",
            signed_approval.to_str().unwrap(),
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let released = loop {
        let status = cli(
            &controller_root,
            &[
                "node",
                "workflow",
                "status",
                &release,
                "--config",
                controller_path.to_str().unwrap(),
            ],
        );
        if status["state"] == "failed" {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "approved external action did not settle at the runtime gate: {status}"
        );
        std::thread::sleep(Duration::from_millis(30));
    };
    assert_eq!(released["definition_sha256"], waiting["definition_sha256"]);
    let release_job = lockyard_node::workflow::step_job_id(&release, "release").unwrap();
    let record = cli(
        &controller_root,
        &[
            "job",
            "status",
            "worker",
            &release_job,
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    assert_eq!(
        record["result"]["error_code"],
        "container_runtime_unavailable"
    );
    assert_eq!(record["result"]["pid"], Value::Null);
    let duplicate = mcp(
        &controller_root,
        "flow_approval_attach",
        json!({"config":controller_path,"id":release,"step":"release",
        "definition_sha256":waiting["definition_sha256"],"approval":serde_json::from_slice::<Value>(&fs::read(&signed_approval).unwrap()).unwrap()}),
    );
    assert_eq!(duplicate, released);
    let index = mcp(
        &controller_root,
        "flow_list",
        json!({"config":controller_path,"offset":0,"limit":100}),
    );
    assert_eq!(index["total"], 2);
    assert_eq!(index["items"].as_array().unwrap().len(), 2);
    assert!(
        index["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|flow| flow["steps"].is_number())
    );
    assert!(!index.to_string().contains("PRIVATE-"));
    assert_eq!(
        fs::read_dir(worker.state_dir.join("executor/jobs"))
            .unwrap()
            .count(),
        3
    );
    let pending = cli(
        &controller_root,
        &[
            "node",
            "dispatch",
            "pending",
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    assert_eq!(pending["total"], 0);
    drop(controller_service);
    let _restarted = serve(&controller_root, &controller_path);
    let restored = cli(
        &controller_root,
        &[
            "node",
            "workflow",
            "submit",
            "--file",
            definition_path.to_str().unwrap(),
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    assert_eq!(restored, summary);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        fs::read_dir(worker.state_dir.join("executor/jobs"))
            .unwrap()
            .count(),
        3
    );
    let drain = cli(
        &controller_root,
        &[
            "node",
            "drain",
            "--config",
            controller_path.to_str().unwrap(),
        ],
    );
    assert_eq!(drain["workflow_active_steps"], 0);
    assert_eq!(drain["outbound_unresolved"], 0);
}
