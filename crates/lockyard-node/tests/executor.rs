// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#![cfg(unix)]

use lockyard_cloud_client::WorkspaceKey;
use lockyard_node::executor::{
    Caller, CloudConfig, ContainerNetwork, ContainerProfile, ContainerRuntime, ExecutionLimits,
    Executor, ExecutorConfig, RepositoryConfig, RunnerKind, RunnerProfile,
};
use lockyard_node::provenance::{self, ResultSigningConfig, SigningKey};
use lockyard_node::supply_chain::{
    BlobDescriptor, ImageAttestation, SbomFormat, SupplyChainPolicy, VulnerabilityReport,
};
use lockyard_node::wire::{JobRecord, JobSpec, JobState};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn runtime_program() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("LOCKYARD_NODE_EXECUTOR_RUNTIME") {
        return path.into();
    }
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let program = directory.join("docker");
            if program.is_absolute() && program.is_file() {
                return program;
            }
        }
    }
    "/usr/bin/docker".into()
}
fn caller() -> Caller {
    Caller {
        node_id: "controller".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    }
}
fn operator() -> Caller {
    Caller {
        node_id: "operator".into(),
        local_operator: true,
        certificate_sha256: None,
    }
}
fn native_live_selected() -> bool {
    cfg!(target_os = "linux")
        && std::env::var_os("LOCKYARD_NATIVE_CGROUP_ROOT").is_some()
        && std::env::var_os("LOCKYARD_NATIVE_ROOTFS").is_some()
}
fn enabled() -> bool {
    native_live_selected() || std::env::var_os("LOCKYARD_NODE_EXECUTOR_IMAGE").is_some()
}
fn live_fixture(path: &Path) -> ExecutorConfig {
    #[cfg(target_os = "linux")]
    if native_live_selected() {
        let mut config = native_cases::configured_fixture(path)
            .expect("native legacy acceptance requires working delegated cgroups, namespaces and signed rootfs");
        // Preserve every existing literal agent/name assertion in the legacy acceptance cases.
        config.node_id = "fixture-node".into();
        return config;
    }
    fixture(path)
}
#[cfg(target_os = "linux")]
fn live_native_cgroup(name: &str) -> std::path::PathBuf {
    let root = std::path::PathBuf::from(std::env::var_os("LOCKYARD_NATIVE_CGROUP_ROOT").unwrap());
    root.join(format!(
        "lockyard-{}",
        &provenance::sha256(name.as_bytes())[..32]
    ))
}

// Synthetic attester data is explicit test trust, not a claim that an upstream scanner ran.
fn security_fixture(path: &Path) -> (String, ResultSigningConfig, SupplyChainPolicy) {
    let private = path.join("signing");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let key_path = private.join("result.pk8");
    let key = SigningKey::generate(&key_path).unwrap();
    let signer = ResultSigningConfig {
        workspace: "actual-workspace-id".into(),
        key_file: key_path,
        public_key: key.trusted_key().public_key,
    };
    let attester = SigningKey::generate(&private.join("attester.pk8")).unwrap();
    let image = std::env::var("LOCKYARD_NODE_EXECUTOR_IMAGE")
        .unwrap_or_else(|_| format!("sha256:{}", "a".repeat(64)));
    let image = if lockyard_node::supply_chain::immutable_image_digest(&image).is_ok() {
        image
    } else {
        let output = Command::new(runtime_program())
            .args([
                "--host=unix:///var/run/docker.sock",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                &image,
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().into()
    };
    let digest = lockyard_node::supply_chain::immutable_image_digest(&image).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let report = VulnerabilityReport {
        version: 1,
        image_digest: digest.clone(),
        generated_at_ms: now,
        database_updated_at_ms: now,
        scanner_name: "synthetic-fixture-no-upstream-scan".into(),
        scanner_version: "1".into(),
        findings: vec![],
    };
    let report_bytes = serde_json::to_vec(&report).unwrap();
    let sbom = br#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}"#;
    let policy = SupplyChainPolicy {
        attestation_file: private.join("attestation.json"),
        sbom_file: private.join("sbom.json"),
        vulnerability_report_file: private.join("report.json"),
        trusted_signers: vec![attester.trusted_key()],
        max_attestation_age_seconds: 3600,
        max_report_age_seconds: 3600,
        max_database_age_seconds: 3600,
        max_critical: 0,
        max_high: 0,
        max_medium: 0,
        max_low: 0,
        max_unknown: 0,
        denied_vulnerability_ids: vec![],
    };
    fs::write(&policy.sbom_file, sbom).unwrap();
    fs::write(&policy.vulnerability_report_file, &report_bytes).unwrap();
    let attestation = ImageAttestation {
        version: 1,
        image_reference: image.clone(),
        image_digest: digest.clone(),
        image_config_digest: digest,
        issued_at_ms: now,
        expires_at_ms: now + 3_600_000,
        sbom_format: SbomFormat::CycloneDxJson,
        sbom: BlobDescriptor {
            sha256: provenance::sha256(sbom),
            size_bytes: sbom.len() as u64,
        },
        vulnerability_report: BlobDescriptor {
            sha256: provenance::sha256(&report_bytes),
            size_bytes: report_bytes.len() as u64,
        },
    };
    fs::write(
        &policy.attestation_file,
        serde_json::to_vec(&attestation.sign(&attester).unwrap()).unwrap(),
    )
    .unwrap();
    (image, signer, policy)
}
fn fixture(path: &Path) -> ExecutorConfig {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    let checkout = path.join("checkout");
    fs::create_dir(&checkout).unwrap();
    git(&checkout, &["init", "-q"]);
    git(
        &checkout,
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(&checkout, &["config", "user.name", "Fixture"]);
    fs::write(checkout.join("base.txt"), "base\n").unwrap();
    git(&checkout, &["add", "base.txt"]);
    git(&checkout, &["commit", "-qm", "base"]);
    let (image, provenance, supply_chain) = security_fixture(path);
    ExecutorConfig {
        external_actions: Default::default(),
        node_certificate_sha256: None,
        protected_identity_files: Vec::new(),
        scheduling: Default::default(),
        node_id: "fixture-node".into(),
        state_dir: path.join("state"),
        provenance: Some(provenance),
        repositories: BTreeMap::from([(
            "repo".into(),
            RepositoryConfig {
                checkout,
                cloud: None,
                retention: Some(lockyard_node::retention::RetentionPolicy {
                    content_ttl_seconds: 3600,
                }),
            },
        )]),
        runners: BTreeMap::from([(
            "python".into(),
            RunnerProfile {
                action: Default::default(),
                owner_approval_authorities: Vec::new(),
                container: ContainerProfile {
                    runtime: ContainerRuntime::Docker,
                    cgroup_root: None,
                    native_rootfs: None,
                    native_network_program: None,
                    runtime_program: runtime_program(),
                    image,
                    supply_chain: Some(supply_chain),
                    git_program: "/usr/bin/git".into(),
                    memory_mb: 128,
                    cpu_millis: 1000,
                    pids_limit: 64,
                    network: ContainerNetwork::None,
                },
                program: "/usr/bin/python3".into(),
                kind: RunnerKind::Command,
                mcp_program: None,
                fixed_args: vec!["-c".into()],
                env_passthrough: vec![],
                secrets: vec![],
                credential_repositories: vec![],
            },
        )]),
        limits: ExecutionLimits {
            max_concurrency: 1,
            max_timeout_seconds: 10,
            max_log_bytes: 4096,
            max_patch_bytes: 4096,
            max_pending_jobs: 16,
        },
    }
}
fn spec(n: u8, code: &str) -> JobSpec {
    JobSpec {
        id: format!("000000000000000000000000{n:02}"),
        repository: "repo".into(),
        revision: "HEAD".into(),
        runner: "python".into(),
        arguments: vec![code.into()],
        prompt: None,
        timeout_seconds: None,
        priority: 0,
        workflow_inputs: Vec::new(),
        expected_runner_sha256: None,
        owner_approval: None,
    }
}
// Runtime fixtures with injected credentials still exercise their original lifecycle/isolation
// behavior after EP06: authorize the exact configured scope instead of weakening that scope.
fn approve_external_fixture(root: &Path, config: &mut ExecutorConfig, request: &mut JobSpec) {
    use lockyard_node::approvals::{self, ApprovalExpectation};
    let owner = SigningKey::generate(&root.join("signing/owner.pk8")).unwrap();
    config.node_certificate_sha256 = Some("b".repeat(64));
    config
        .runners
        .get_mut(&request.runner)
        .unwrap()
        .owner_approval_authorities = vec![owner.trusted_key()];
    let repository = &config.repositories[&request.repository];
    let revision = git(&repository.checkout, &["rev-parse", &request.revision]);
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    request.owner_approval = Some(
        approvals::prepare(
            &ApprovalExpectation {
                workspace: &config.provenance.as_ref().unwrap().workspace,
                node_id: &config.node_id,
                node_certificate_sha256: config.node_certificate_sha256.as_deref().unwrap(),
                spec: request,
                resolved_revision: &revision,
                runner: &config.runners[&request.runner],
                repository_cloud: repository.cloud.as_ref(),
            },
            current - 1000,
            current + 60_000,
        )
        .unwrap()
        .sign(&owner)
        .unwrap(),
    );
}

fn wait(executor: &Executor, id: &str, predicate: impl Fn(&JobRecord) -> bool) -> JobRecord {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let record = executor.status(id).unwrap();
        if predicate(&record) {
            return record;
        }
        assert!(
            Instant::now() < deadline,
            "job did not reach expected state: {record:?}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
fn finished(executor: &Executor, id: &str) -> JobRecord {
    wait(executor, id, |record| {
        record.state.is_terminal()
            && (record.result_manifest.is_some() || record.provenance_error.is_some())
    })
}

#[test]
#[ignore = "requires a resource-capable Docker daemon and LOCKYARD_NODE_EXECUTOR_IMAGE"]
fn literal_arguments_deduplicate_and_preserve_dirty_checkout() {
    assert!(
        enabled(),
        "set LOCKYARD_NODE_EXECUTOR_IMAGE to the preinstalled fixture image"
    );
    let dir = tempfile::tempdir().unwrap();
    let config = live_fixture(dir.path());
    let checkout = config.repositories["repo"].checkout.clone();
    fs::write(checkout.join("base.txt"), "dirty\n").unwrap();
    let executor = Executor::new(config).unwrap();
    let mut request = spec(
        1,
        "import pathlib,sys,os; p=pathlib.Path('executions'); p.write_text(str(int(p.read_text())+1) if p.exists() else '1'); print(pathlib.Path('base.txt').read_text().strip()); print(sys.argv[1]); print(os.environ['LOCKYARD_AGENT'])",
    );
    request
        .arguments
        .push("$(touch SHOULD_NOT_EXIST); 'literal'".into());
    let accepted = executor.submit(request.clone(), &caller()).unwrap();
    assert_eq!(
        executor.submit(request.clone(), &caller()).unwrap().spec.id,
        accepted.spec.id
    );
    let completed = finished(&executor, &request.id);
    assert_eq!(completed.state, JobState::Succeeded);
    let worktree = completed.worktree.unwrap();
    assert_eq!(
        fs::read_to_string(worktree.join("executions")).unwrap(),
        "1"
    );
    assert!(!worktree.join("SHOULD_NOT_EXIST").exists());
    let log = executor.read_log(&request.id, 0, 65536).unwrap();
    let log = String::from_utf8(log.bytes).unwrap();
    assert!(log.contains("base\n$(touch SHOULD_NOT_EXIST); 'literal'\nnode-fixture-node-"));
    assert_eq!(
        fs::read_to_string(checkout.join("base.txt")).unwrap(),
        "dirty\n"
    );
    assert_eq!(git(&checkout, &["status", "--porcelain"]), "M base.txt");
    request.arguments.push("changed".into());
    assert_eq!(
        executor.submit(request, &caller()).unwrap_err().0,
        "job_id_conflict"
    );
}

#[test]
#[ignore = "requires a resource-capable Docker daemon and LOCKYARD_NODE_EXECUTOR_IMAGE"]
fn queued_revision_is_pinned_and_concurrency_is_bounded() {
    assert!(
        enabled(),
        "set LOCKYARD_NODE_EXECUTOR_IMAGE to the preinstalled fixture image"
    );
    let dir = tempfile::tempdir().unwrap();
    let config = live_fixture(dir.path());
    let checkout = config.repositories["repo"].checkout.clone();
    let old_revision = git(&checkout, &["rev-parse", "HEAD"]);
    let executor = Executor::new(config).unwrap();
    let first = spec(2, "import time; time.sleep(0.4)");
    executor.submit(first.clone(), &caller()).unwrap();
    wait(&executor, &first.id, |record| {
        record.state == JobState::Running
    });
    let second = spec(
        3,
        "from pathlib import Path; print(Path('base.txt').read_text())",
    );
    let queued = executor.submit(second.clone(), &caller()).unwrap();
    assert_eq!(queued.state, JobState::Queued);
    assert_eq!(
        queued.resolved_revision.as_deref(),
        Some(old_revision.as_str())
    );
    assert_eq!(executor.status(&second.id).unwrap().state, JobState::Queued);
    fs::write(checkout.join("base.txt"), "new commit\n").unwrap();
    git(&checkout, &["commit", "-qam", "new"]);
    assert_eq!(finished(&executor, &first.id).state, JobState::Succeeded);
    assert_eq!(finished(&executor, &second.id).state, JobState::Succeeded);
    assert_eq!(
        executor.read_log(&second.id, 0, 100).unwrap().bytes,
        b"base\n\n"
    );
}

#[test]
#[ignore = "requires a resource-capable Docker daemon and LOCKYARD_NODE_EXECUTOR_IMAGE"]
fn output_is_capped_and_timeout_and_cancel_stop_child_groups() {
    assert!(
        enabled(),
        "set LOCKYARD_NODE_EXECUTOR_IMAGE to the preinstalled fixture image"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut config = live_fixture(dir.path());
    config.limits.max_log_bytes = 257;
    let executor = Executor::new(config).unwrap();
    let output = spec(
        4,
        "import sys; sys.stdout.write('x'*300000); sys.stderr.write('y'*300000)",
    );
    executor.submit(output.clone(), &caller()).unwrap();
    let complete = finished(&executor, &output.id);
    assert_eq!(complete.state, JobState::Succeeded);
    assert_eq!(complete.log_bytes, 257);
    assert!(complete.log_truncated);
    let log = executor.read_log(&output.id, 0, usize::MAX).unwrap();
    assert_eq!(log.bytes.len(), 257);
    assert!(log.eof && log.truncated);
    let mut timeout = spec(5, "import time; time.sleep(300)");
    timeout.timeout_seconds = Some(1);
    executor.submit(timeout.clone(), &caller()).unwrap();
    assert_eq!(finished(&executor, &timeout.id).state, JobState::TimedOut);
    let cancel = spec(
        6,
        "import subprocess,time; p=subprocess.Popen(['sleep','300']); print(p.pid,flush=True); time.sleep(300)",
    );
    executor.submit(cancel.clone(), &caller()).unwrap();
    wait(&executor, &cancel.id, |record| {
        record.state == JobState::Running
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let child_pid: i32 = loop {
        let bytes = executor.read_log(&cancel.id, 0, 100).unwrap().bytes;
        if let Ok(pid) = String::from_utf8_lossy(&bytes).trim().parse() {
            break pid;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    };
    executor.cancel(&cancel.id, &caller()).unwrap();
    assert_eq!(finished(&executor, &cancel.id).state, JobState::Cancelled);
    assert!(child_pid > 0);
    // The runtime removes the container after killing all processes in its process namespace.
    let name = format!("lockyard-fixture-node-{}", cancel.id);
    #[cfg(target_os = "linux")]
    if native_live_selected() {
        assert!(
            !live_native_cgroup(&name).exists(),
            "cancelled cgroup still exists"
        );
    }
    if !native_live_selected() {
        assert!(
            !Command::new(runtime_program())
                .args([
                    "--host=unix:///var/run/docker.sock",
                    "container",
                    "inspect",
                    &name
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
}

#[test]
#[ignore = "requires a resource-capable Docker daemon and LOCKYARD_NODE_EXECUTOR_IMAGE"]
fn live_container_enforces_resource_limits_and_private_mount_policy() {
    #[cfg(target_os = "linux")]
    if native_live_selected() {
        live_native_resource_policy();
        return;
    }
    assert!(
        enabled(),
        "set LOCKYARD_NODE_EXECUTOR_IMAGE to the fixture image"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut config = live_fixture(dir.path());
    let profile = &mut config.runners.get_mut("python").unwrap().container;
    profile.memory_mb = 64;
    profile.cpu_millis = 500;
    profile.pids_limit = 16;
    let state = config.state_dir.clone();
    let checkout = config.repositories["repo"].checkout.clone();
    let executor = Executor::new(config).unwrap();
    let inspect_job = spec(
        21,
        r#"import json,pathlib,time
root=pathlib.Path('/sys/fs/cgroup')
if (root/'cgroup.controllers').exists():
    memory=int((root/'memory.max').read_text())
    quota,period=map(int,(root/'cpu.max').read_text().split())
    pids=int((root/'pids.max').read_text())
else:
    memory=int((root/'memory/memory.limit_in_bytes').read_text())
    quota=int((root/'cpu/cpu.cfs_quota_us').read_text())
    period=int((root/'cpu/cpu.cfs_period_us').read_text())
    pids=int((root/'pids/pids.max').read_text())
print(json.dumps({'memory':memory,'quota':quota,'period':period,'pids':pids}),flush=True)
time.sleep(300)
"#,
    );
    executor.submit(inspect_job.clone(), &caller()).unwrap();
    wait(&executor, &inspect_job.id, |record| {
        record.state == JobState::Running
    });
    let name = format!("lockyard-fixture-node-{}", inspect_job.id);
    let deadline = Instant::now() + Duration::from_secs(4);
    let inspected = loop {
        let output = Command::new(runtime_program())
            .args([
                "--host=unix:///var/run/docker.sock",
                "container",
                "inspect",
                &name,
            ])
            .output()
            .unwrap();
        if output.status.success() {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if value[0]["State"]["Running"] == true {
                break value[0].clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "container never became inspectable"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let actual = &inspected["HostConfig"];
    assert_eq!(actual["Memory"], 64 * 1024 * 1024);
    assert_eq!(actual["MemorySwap"], 64 * 1024 * 1024);
    assert_eq!(actual["NanoCpus"], 500_000_000);
    assert_eq!(actual["PidsLimit"], 16);
    assert_eq!(actual["ReadonlyRootfs"], true);
    assert_eq!(actual["NetworkMode"], "none");
    assert_eq!(actual["IpcMode"], "none");
    assert!(
        actual["CapDrop"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "ALL")
    );
    assert!(
        actual["SecurityOpt"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "no-new-privileges:true")
    );
    let mounts = inspected["Mounts"].as_array().unwrap();
    let binds: Vec<_> = mounts
        .iter()
        .filter(|mount| mount["Type"] == "bind")
        .collect();
    assert_eq!(binds.len(), 2);
    assert!(mounts.iter().all(|mount| mount["Type"] == "bind"
        || (mount["Type"] == "tmpfs" && mount["Destination"] == "/tmp")));
    let job_dir = state.join("jobs").join(&inspect_job.id);
    for path in [job_dir.join("worktree"), job_dir.join("repository.git")] {
        assert!(binds.iter().any(|mount| mount["Type"] == "bind"
            && mount["Source"].as_str() == path.to_str()
            && mount["Destination"].as_str() == path.to_str()
            && mount["RW"] == true));
    }
    assert!(binds.iter().all(|mount| {
        !mount["Source"]
            .as_str()
            .unwrap()
            .starts_with(checkout.to_str().unwrap())
    }));
    let limits = loop {
        let log = executor.read_log(&inspect_job.id, 0, 4096).unwrap();
        if let Some(value) = String::from_utf8_lossy(&log.bytes)
            .lines()
            .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "effective cgroup limits were not reported"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(limits["memory"], 64 * 1024 * 1024);
    assert_eq!(limits["pids"], 16);
    assert_eq!(
        limits["quota"].as_i64().unwrap() * 2,
        limits["period"].as_i64().unwrap()
    );
    executor.cancel(&inspect_job.id, &caller()).unwrap();
    assert_eq!(
        finished(&executor, &inspect_job.id).state,
        JobState::Cancelled
    );

    // Both adversarial attempts are bounded even if a broken runtime ignores configured limits.
    let pids = spec(
        22,
        r#"import errno,subprocess
children=[]
limited=False
try:
    for _ in range(32):
        try: children.append(subprocess.Popen(['/bin/sleep','30']))
        except OSError as error:
            if error.errno != errno.EAGAIN: raise
            limited=True
            break
finally:
    for child in children: child.terminate()
    for child in children: child.wait()
assert limited, 'runtime did not enforce the configured PID bound'
assert len(children)<16
print('pid-limit-enforced',flush=True)
"#,
    );
    executor.submit(pids.clone(), &caller()).unwrap();
    assert_eq!(finished(&executor, &pids.id).state, JobState::Succeeded);
    assert!(
        String::from_utf8_lossy(&executor.read_log(&pids.id, 0, 4096).unwrap().bytes)
            .contains("pid-limit-enforced")
    );

    let memory = spec(
        23,
        r#"chunks=[]
for _ in range(32):
    chunk=bytearray(8*1024*1024)
    for offset in range(0,len(chunk),4096): chunk[offset]=1
    chunks.append(chunk)
raise RuntimeError('runtime did not enforce the configured memory bound')
"#,
    );
    executor.submit(memory.clone(), &caller()).unwrap();
    let completed = finished(&executor, &memory.id);
    assert_eq!(completed.state, JobState::Failed);
    assert_eq!(
        completed.exit_code,
        Some(137),
        "expected kernel memory-limit termination"
    );
    assert!(completed.patch_error.is_none());
}

#[test]
#[ignore = "requires a resource-capable Docker daemon and LOCKYARD_NODE_EXECUTOR_IMAGE"]
fn codex_profile_injects_mcp_without_user_config_mutation_and_redacts_token() {
    assert!(
        enabled(),
        "set LOCKYARD_NODE_EXECUTOR_IMAGE to the preinstalled fixture image"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut config = live_fixture(dir.path());
    let code = "import sys,os,pathlib,json; print(json.dumps(sys.argv[1:])); print(os.environ['LOCKYARD_AGENT']); print(os.environ['LOCKYARD_URL']); print(os.environ['LOCKYARD_TOKEN']); print(pathlib.Path('.lockyard/config.toml').read_text())";
    let token = dir.path().join("token");
    fs::write(&token, "fixture-sensitive-token\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    config.repositories.get_mut("repo").unwrap().cloud = Some(CloudConfig {
        url: "https://cloud.example.invalid".into(),
        workspace: "team".into(),
        repository: "repo-id".into(),
        token_file: Some(token),
    });
    let runner = config.runners.get_mut("python").unwrap();
    runner.kind = RunnerKind::Codex;
    runner.mcp_program = Some("/configured/lockyard".into());
    runner.fixed_args = vec!["-c".into(), code.into()];
    let mut request = spec(7, "");
    request.arguments.clear();
    request.prompt = Some("--literal-prompt".into());
    approve_external_fixture(dir.path(), &mut config, &mut request);
    let executor = Executor::new_with_workspace_key(
        config,
        "actual-workspace-id".into(),
        WorkspaceKey::from_entropy([77; 32]),
    )
    .unwrap();
    executor.submit(request.clone(), &caller()).unwrap();
    assert_eq!(finished(&executor, &request.id).state, JobState::Succeeded);
    let log = String::from_utf8(executor.read_log(&request.id, 0, 65536).unwrap().bytes).unwrap();
    assert!(log.contains("mcp_servers.lockyard.command"));
    assert!(log.contains("LOCKYARD_TOKEN_FILE") && log.contains("LOCKYARD_TOKEN"));
    assert!(log.contains("--literal-prompt"));
    assert!(log.contains("[REDACTED]"));
    assert!(!log.contains("fixture-sensitive-token"));
    assert!(log.contains("mode = \"cloud\""));
}

#[test]
fn crash_worker_helper() {
    let Some(path) = std::env::var_os("LOCKYARD_EXECUTOR_CRASH_FIXTURE") else {
        return;
    };
    let config: ExecutorConfig = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let executor = Executor::new(config).unwrap();
    executor
        .submit(spec(8, "import time; time.sleep(300)"), &caller())
        .unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore = "requires a resource-capable Docker daemon and LOCKYARD_NODE_EXECUTOR_IMAGE"]
fn actual_daemon_crash_marks_unknown_and_never_reexecutes() {
    assert!(
        enabled(),
        "set LOCKYARD_NODE_EXECUTOR_IMAGE to the preinstalled fixture image"
    );
    let dir = tempfile::tempdir().unwrap();
    let config = live_fixture(dir.path());
    let config_path = dir.path().join("fixture.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut daemon = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_worker_helper", "--nocapture"])
        .env("LOCKYARD_EXECUTOR_CRASH_FIXTURE", &config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let journal = config
        .state_dir
        .join("jobs")
        .join(spec(8, "").id)
        .join("record.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let running = loop {
        if let Ok(bytes) = fs::read(&journal)
            && let Ok(record) = serde_json::from_slice::<JobRecord>(&bytes)
            && record.state == JobState::Running
        {
            break record;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    };
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let executor = Executor::new(config).unwrap();
    let recovered = executor.status(&running.spec.id).unwrap();
    assert_eq!(recovered.state, JobState::InterruptedUnknown);
    assert_eq!(recovered.pid, running.pid);
    assert_eq!(
        executor
            .submit(running.spec.clone(), &caller())
            .unwrap()
            .state,
        JobState::InterruptedUnknown
    );
    assert_eq!(
        executor
            .submit(spec(9, "print('fresh')"), &caller())
            .unwrap_err()
            .0,
        "unknown_execution_requires_review"
    );
    // Operator review identifies the container by its deterministic name, never an old PID.
    let name = format!("lockyard-fixture-node-{}", running.spec.id);
    #[cfg(target_os = "linux")]
    if native_live_selected() {
        let group = live_native_cgroup(&name);
        fs::write(group.join("cgroup.kill"), "1").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fs::read_to_string(group.join("cgroup.events"))
            .unwrap()
            .lines()
            .any(|line| line == "populated 0")
        {
            assert!(
                Instant::now() < deadline,
                "native orphan cgroup never stopped"
            );
            thread::sleep(Duration::from_millis(20));
        }
        fs::remove_dir(group).unwrap();
    }
    if !native_live_selected() {
        let _ = Command::new(runtime_program())
            .args(["--host=unix:///var/run/docker.sock", "kill", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    executor
        .resolve_unknown(&running.spec.id, &operator())
        .unwrap();
    let fresh = spec(9, "print('fresh')");
    executor.submit(fresh.clone(), &caller()).unwrap();
    assert_eq!(finished(&executor, &fresh.id).state, JobState::Succeeded);
}

#[test]
fn exclusive_state_lock_and_unknown_profiles_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(dir.path());
    let executor = Executor::new(config.clone()).unwrap();
    assert!(matches!(Executor::new(config), Err(error) if error.0 == "executor_already_running"));
    let mut request = spec(10, "print('no')");
    request.runner = "not-opted-in".into();
    assert_eq!(
        executor.submit(request, &caller()).unwrap_err().0,
        "runner_not_configured"
    );
}

#[test]
fn runtime_key_location_cannot_be_overridden_by_profile_passthrough() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(dir.path());
    for name in [
        "XDG_CONFIG_HOME",
        "LOCKYARD_REQUIRE_E2EE",
        "LOCKYARD_E2EE_WORKSPACE_ID",
        "LOCKYARD_TOKEN",
        "LOCKYARD_TOKEN_FILE",
        "LD_PRELOAD",
    ] {
        let mut config = config.clone();
        config.runners.get_mut("python").unwrap().env_passthrough = vec![name.into()];
        config
            .runners
            .get_mut("python")
            .unwrap()
            .credential_repositories = vec!["repo".into()];
        assert!(matches!(Executor::new(config), Err(error) if error.0 == "invalid_runner_profile"));
    }
}

#[test]
fn authenticated_owner_and_local_operator_controls_survive_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(dir.path());
    // Starting records can exist after a real crash before the runtime CLI had a PID.
    let request = spec(11, "print('never replay')");
    let job_dir = config.state_dir.join("jobs").join(&request.id);
    fs::create_dir_all(&job_dir).unwrap();
    for path in [&config.state_dir, &config.state_dir.join("jobs"), &job_dir] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let record = JobRecord {
        had_runtime_credentials: true,
        spec: request.clone(),
        submitter: "controller".into(),
        submitter_certificate_sha256: Some("a".repeat(64)),
        agent: "derived".into(),
        state: JobState::Starting,
        created_at_ms: 1,
        updated_at_ms: 1,
        resolved_revision: Some(git(
            &config.repositories["repo"].checkout,
            &["rev-parse", "HEAD"],
        )),
        worktree: None,
        pid: None,
        exit_code: None,
        error_code: None,
        log_bytes: 0,
        log_truncated: false,
        log_error: None,
        patch_bytes: 0,
        patch_truncated: false,
        patch_error: None,
        configured_image: None,
        admission_runner_sha256: None,
        admission_repository_sha256: None,
        admitted_image: None,
        result_manifest: None,
        provenance_error: None,
        notification_accounted_certificate_sha256: None,
        retention: None,
    };
    fs::write(
        job_dir.join("record.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let executor = Executor::new(config).unwrap();
    assert_eq!(
        executor.status(&request.id).unwrap().state,
        JobState::InterruptedUnknown
    );
    let other = Caller {
        node_id: "another-node".into(),
        local_operator: false,
        certificate_sha256: Some("a".repeat(64)),
    };
    assert_eq!(
        executor.cancel(&request.id, &other).unwrap_err().0,
        "job_owner_required"
    );
    assert_eq!(
        executor
            .resolve_unknown(&request.id, &caller())
            .unwrap_err()
            .0,
        "local_operator_required"
    );
    assert_eq!(
        executor.submit(request.clone(), &other).unwrap_err().0,
        "job_id_conflict"
    );
    assert_eq!(
        executor.submit(request.clone(), &caller()).unwrap().state,
        JobState::InterruptedUnknown
    );
    assert_eq!(
        executor
            .resolve_unknown(&request.id, &operator())
            .unwrap()
            .state,
        JobState::Failed
    );
    assert!(!job_dir.join("worktree").exists());
}

#[test]
fn recovered_queued_job_uses_bounded_dispatch_and_still_refuses_an_unavailable_runtime() {
    // A synthetic already-admitted queue journal. This is a negative runtime proof,
    // not successful container execution or a bypass of resource enforcement.
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .runtime_program = dir.path().join("runtime-does-not-exist");
    let marker = dir.path().join("RECOVERY_MUST_NOT_EXECUTE_ON_HOST");
    let request = spec(
        28,
        &format!("open({:?},'w').write('unsafe')", marker.to_string_lossy()),
    );
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let job = config.state_dir.join("jobs").join(&request.id);
    fs::create_dir_all(&job).unwrap();
    for path in [&config.state_dir, &config.state_dir.join("jobs"), &job] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let record = serde_json::json!({"spec":request,"state":"queued","agent":"synthetic-recovered","submitter":"controller","submitter_certificate_sha256":"a".repeat(64),
        "had_runtime_credentials":false,"created_at":current,"updated_at":current,"resolved_revision":git(&config.repositories["repo"].checkout,&["rev-parse","HEAD"]),
        "worktree":null,"pid":null,"exit_code":null,"error_code":null,"log_bytes":0,"log_truncated":false,
        "configured_image":config.runners["python"].container.image,
        "admission_runner_sha256":lockyard_node::executor::admission_fingerprint(&config.runners["python"]).unwrap(),
        "admission_repository_sha256":lockyard_node::executor::admission_fingerprint(&config.repositories["repo"]).unwrap(),
        "retention":{"content_ttl_seconds":3600,"admitted_at_ms":current,"terminal_expires_at_ms":null,"purged_at_ms":null}});
    fs::write(
        job.join("record.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    fs::set_permissions(job.join("record.json"), fs::Permissions::from_mode(0o600)).unwrap();
    let executor = Executor::new(config).unwrap();
    let completed = finished(&executor, &request.id);
    assert_eq!(completed.state, JobState::Failed);
    assert_eq!(
        completed.error_code.as_deref(),
        Some("container_runtime_unavailable")
    );
    assert!(!marker.exists());
    assert!(!job.join("worktree").exists());
    assert!(completed.pid.is_none());
}

#[test]
fn unavailable_container_runtime_never_falls_back_to_host_execution() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .runtime_program = dir.path().join("runtime-does-not-exist");
    let marker = dir.path().join("HOST_EXECUTION_WOULD_BE_A_BUG");
    let request = spec(
        12,
        &format!("open({:?}, 'w').write('unsafe')", marker.to_string_lossy()),
    );
    let executor = Executor::new(config).unwrap();
    executor.submit(request.clone(), &caller()).unwrap();
    let record = finished(&executor, &request.id);
    assert_eq!(record.state, JobState::Failed);
    assert_eq!(
        record.error_code.as_deref(),
        Some("container_runtime_unavailable")
    );
    assert!(!marker.exists());
}

#[test]
fn managed_external_profiles_require_owner_before_journal_clone_or_runtime() {
    use lockyard_node::approvals::{self, ApprovalExpectation, ManagedAction};
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    let owner = SigningKey::generate(&dir.path().join("signing/owner.pk8")).unwrap();
    config.node_certificate_sha256 = Some("b".repeat(64));
    let runner = config.runners.get_mut("python").unwrap();
    runner.action = ManagedAction::Deploy;
    runner.owner_approval_authorities = vec![owner.trusted_key()];
    runner.container.runtime_program = dir.path().join("runtime-does-not-exist");
    let mut request = spec(20, "print('must never execute')");
    let revision = git(
        &config.repositories["repo"].checkout,
        &["rev-parse", "HEAD"],
    );
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let claim = approvals::prepare(
        &ApprovalExpectation {
            workspace: "actual-workspace-id",
            node_id: &config.node_id,
            node_certificate_sha256: config.node_certificate_sha256.as_deref().unwrap(),
            spec: &request,
            resolved_revision: &revision,
            runner: &config.runners["python"],
            repository_cloud: None,
        },
        current - 1000,
        current + 60_000,
    )
    .unwrap();
    let executor = Executor::new(config.clone()).unwrap();
    assert_eq!(
        executor.submit(request.clone(), &caller()).unwrap_err().0,
        "owner_approval_required"
    );
    request.owner_approval = Some(claim.sign(&owner).unwrap());
    for scenario in ["request", "node", "window"] {
        let mut wrong = request.clone();
        if scenario == "request" {
            wrong.arguments.push("changed".into());
        } else {
            let mut claim = claim.clone();
            if scenario == "node" {
                claim.node_certificate_sha256 = "d".repeat(64);
            } else {
                claim.not_before_ms = current - 2000;
                claim.expires_at_ms = current - 1000;
            }
            wrong.owner_approval = Some(claim.sign(&owner).unwrap());
        }
        assert!(executor.submit(wrong, &caller()).is_err());
    }
    assert!(
        fs::read_dir(config.state_dir.join("jobs"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(!config.state_dir.join("jobs").join(&request.id).exists());
}

#[test]
fn owner_approval_is_one_use_with_durable_idempotent_retries_and_no_reexecution() {
    // Negative runtime admission proves journal behavior; this does not claim a successful
    // external action or resource-enforced container execution.
    use lockyard_node::approvals::{self, ApprovalExpectation, ManagedAction};
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    let owner = SigningKey::generate(&dir.path().join("signing/owner.pk8")).unwrap();
    config.node_certificate_sha256 = Some("b".repeat(64));
    let runner = config.runners.get_mut("python").unwrap();
    runner.action = ManagedAction::Deploy;
    runner.owner_approval_authorities = vec![owner.trusted_key()];
    runner.container.runtime_program = dir.path().join("runtime-does-not-exist");
    let mut request = spec(21, "print('not executed')");
    let revision = git(
        &config.repositories["repo"].checkout,
        &["rev-parse", "HEAD"],
    );
    let current = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expires = current + 1000;
    let claim = approvals::prepare(
        &ApprovalExpectation {
            workspace: "actual-workspace-id",
            node_id: &config.node_id,
            node_certificate_sha256: config.node_certificate_sha256.as_deref().unwrap(),
            spec: &request,
            resolved_revision: &revision,
            runner: &config.runners["python"],
            repository_cloud: None,
        },
        current - 1000,
        expires,
    )
    .unwrap();
    request.owner_approval = Some(claim.sign(&owner).unwrap());
    let executor = Executor::new(config.clone()).unwrap();
    executor.submit(request.clone(), &caller()).unwrap();
    let completed = finished(&executor, &request.id);
    assert_eq!(completed.state, JobState::Failed);
    assert_eq!(
        completed.error_code.as_deref(),
        Some("container_runtime_unavailable")
    );
    assert!(completed.worktree.is_none());
    let mut different = request.clone();
    different.id = spec(22, "").id;
    assert_eq!(
        executor.submit(different, &caller()).unwrap_err().0,
        "owner_approval_context_mismatch"
    );
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        < expires as u128
    {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        executor.submit(request.clone(), &caller()).unwrap(),
        completed
    );
    drop(executor);
    let restarted = Executor::new(config).unwrap();
    assert_eq!(
        restarted.submit(request.clone(), &caller()).unwrap(),
        completed
    );
    let mut changed = request;
    changed.arguments.push("changed".into());
    assert_eq!(
        restarted.submit(changed, &caller()).unwrap_err().0,
        "job_id_conflict"
    );
}

#[test]
fn pre_journal_crash_directory_is_quarantined_and_job_id_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .runtime_program = dir.path().join("missing-runtime");
    let request = spec(15, "print('retry')");
    let orphan = config.state_dir.join("jobs").join(&request.id);
    fs::create_dir_all(&orphan).unwrap();
    for path in [&config.state_dir, &config.state_dir.join("jobs"), &orphan] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Simulate termination after mkdir and a torn first journal write, before atomic rename.
    fs::write(orphan.join("record.json.tmp"), b"{\"state\":").unwrap();
    let executor =
        Executor::new(config.clone()).expect("pre-journal directory is safe to quarantine");
    assert!(!orphan.exists());
    executor.submit(request.clone(), &caller()).unwrap();
    assert_eq!(finished(&executor, &request.id).state, JobState::Failed);
    drop(executor);
    assert!(Executor::new(config).is_ok());
}

#[test]
fn corrupt_committed_journal_is_never_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let config = fixture(dir.path());
    let job = config.state_dir.join("jobs").join(spec(16, "").id);
    fs::create_dir_all(&job).unwrap();
    for path in [&config.state_dir, &config.state_dir.join("jobs"), &job] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(job.join("record.json"), b"{torn").unwrap();
    assert!(matches!(Executor::new(config), Err(error) if error.0 == "invalid_job_record"));
}

#[test]
fn configured_patch_limit_matches_the_download_contract() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    config.limits.max_patch_bytes = 128 * 1024 * 1024 + 1;
    assert!(matches!(Executor::new(config), Err(error) if error.0 == "invalid_executor_limits"));
}

#[test]
fn ambiguous_stop_of_main_or_patch_helper_blocks_new_jobs() {
    for patch_helper in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fixture(dir.path());
        let runtime = dir.path().join("uncertain-runtime-fixture");
        let code = format!(
            r#"#!/usr/bin/python3
import sys,time
a=sys.argv[1:]
patch_helper={patch_helper}
if 'info' in a: print('[]' if any('SecurityOptions' in item for item in a) else 'true true true')
elif 'image' in a and 'inspect' in a: print(a[-1] if '{{{{.Id}}}}' in a else 'null')
elif 'container' in a and 'rm' in a:
    sys.exit(0 if patch_helper and not a[-1].endswith('-read') else 1)
elif 'run' in a:
    if patch_helper: sys.exit(1 if a[a.index('--entrypoint')+1]=='/usr/bin/git' else 0)
    time.sleep(300)
else: sys.exit(1)
"#,
            patch_helper = if patch_helper { "True" } else { "False" }
        );
        fs::write(&runtime, code).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        config
            .runners
            .get_mut("python")
            .unwrap()
            .container
            .runtime_program = runtime;
        let state = config.state_dir.clone();
        if !patch_helper {
            config.repositories.get_mut("repo").unwrap().cloud = Some(CloudConfig {
                url: "https://example.invalid".into(),
                workspace: "workspace-label".into(),
                repository: "repo".into(),
                token_file: None,
            });
        }
        let mut request = spec(17, "not executed by fixture");
        request.timeout_seconds = Some(1);
        if !patch_helper {
            approve_external_fixture(dir.path(), &mut config, &mut request);
        }
        let executor = Executor::new_with_workspace_key(
            config,
            "actual-workspace-id".into(),
            WorkspaceKey::from_entropy([77; 32]),
        )
        .unwrap();
        executor.submit(request.clone(), &caller()).unwrap();
        let record = wait(&executor, &request.id, |record| {
            record.state == JobState::InterruptedUnknown
        });
        assert_eq!(
            record.error_code.as_deref(),
            Some("container_stop_unconfirmed")
        );
        if patch_helper {
            assert_eq!(
                record.patch_error.as_deref(),
                Some("patch_container_stop_unconfirmed")
            );
        }
        assert_eq!(
            executor.submit(spec(18, "new"), &caller()).unwrap_err().0,
            "unknown_execution_requires_review"
        );
        if !patch_helper {
            let key = state
                .join("jobs")
                .join(&request.id)
                .join("runtime-key/lockyard/keys/actual-workspace-id.key");
            assert_eq!(fs::read(&key).unwrap(), vec![77; 32]);
            assert!(!key.with_file_name("workspace-label.key").exists());
            assert_eq!(
                executor
                    .resolve_unknown(&request.id, &caller())
                    .unwrap_err()
                    .0,
                "local_operator_required"
            );
            assert!(key.exists());
            // This fixture launched only a mocked runtime CLI; its process group has been reaped.
            executor.resolve_unknown(&request.id, &operator()).unwrap();
            assert!(!key.exists());
        }
    }
}

#[test]
fn settled_nonzero_command_is_failed_and_does_not_block_new_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    let runtime = dir.path().join("settled-runtime-fixture");
    fs::write(
        &runtime,
        r#"#!/usr/bin/python3
import sys,os
a=sys.argv[1:]
if 'info' in a: print('[]' if any('SecurityOptions' in item for item in a) else 'true true true')
elif 'image' in a and 'inspect' in a: print(a[-1] if '{{.Id}}' in a else 'null')
elif 'container' in a and 'rm' in a: sys.exit(0)
elif 'run' in a:
    if a[a.index('--entrypoint')+1] != '/usr/bin/git':
        assert os.environ.get('LOCKYARD_REQUIRE_E2EE') == '1'
        assert os.environ.get('LOCKYARD_E2EE_WORKSPACE_ID') == 'actual-workspace-id'
        assert not any('runtime-key' in item for item in a)
        sys.exit(7)
    assert 'LOCKYARD_REQUIRE_E2EE' not in os.environ
    os.chdir(a[a.index('--workdir')+1])
    os.environ['GIT_CONFIG_GLOBAL']='/dev/null'
    os.environ['GIT_CONFIG_NOSYSTEM']='1'
    os.execve('/usr/bin/git',['git']+a[next(i for i,value in enumerate(a) if value.startswith('sha256:') or '@sha256:' in value)+1:],os.environ)
else: sys.exit(1)
"#,
    )
    .unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .runtime_program = runtime;
    let executor = Executor::new_with_workspace_key(
        config,
        "actual-workspace-id".into(),
        WorkspaceKey::from_entropy([77; 32]),
    )
    .unwrap();
    let request = spec(19, "not executed by fixture");
    executor.submit(request.clone(), &caller()).unwrap();
    let record = finished(&executor, &request.id);
    assert_eq!(record.state, JobState::Failed);
    assert_eq!(record.exit_code, Some(7));
    assert!(record.patch_error.is_none());
    let next = spec(20, "new");
    executor.submit(next.clone(), &caller()).unwrap();
    assert_eq!(finished(&executor, &next.id).state, JobState::Failed);
}

#[test]
fn container_runtime_receives_fixed_isolation_flags_and_only_private_mounts() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    let runtime = dir.path().join("runtime-fixture");
    // This fixture observes runtime argv. It never executes the requested job program.
    fs::write(
        &runtime,
        r#"#!/usr/bin/python3
import json,sys,os,time,pathlib
args=sys.argv[1:]
for option,value in zip(args,args[1:]):
    if option == '--env' and '=' in value:
        name,value=value.split('=',1)
        os.environ[name]=value
if 'info' in args:
    print('[]' if any('SecurityOptions' in item for item in args) else 'true true true')
elif 'image' in args and 'inspect' in args:
    print(args[-1] if '{{.Id}}' in args else 'null')
elif 'run' in args:
    if args[args.index('--entrypoint')+1] == '/usr/bin/git':
        assert not any(name in os.environ for name in ['LOCKYARD_TOKEN','XDG_CONFIG_HOME','LOCKYARD_REQUIRE_E2EE','LOCKYARD_E2EE_WORKSPACE_ID'])
        os.chdir(args[args.index('--workdir')+1])
        os.environ['GIT_CONFIG_GLOBAL']='/dev/null'
        os.environ['GIT_CONFIG_NOSYSTEM']='1'
        os.execve('/usr/bin/git',['git']+args[next(i for i,value in enumerate(args) if value.startswith('sha256:') or '@sha256:' in value)+1:],os.environ)
    print(json.dumps(args))
    print('scoped_context:'+json.dumps({name:os.environ.get(name) for name in ['XDG_CONFIG_HOME','LOCKYARD_REQUIRE_E2EE','LOCKYARD_E2EE_WORKSPACE_ID']}))
    if '--env-file' in args:
        assert 'LOCKYARD_TOKEN' not in os.environ
        envfile=args[args.index('--env-file')+1]
        values=dict(line.split('=',1) for line in pathlib.Path(envfile).read_text().splitlines())
        token=values['LOCKYARD_TOKEN']
        for part in [token[:7],token[7:]]:
            print(part,end='',flush=True)
            time.sleep(0.04)
        print()
"#,
    )
    .unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .runtime_program = runtime;
    config.runners.get_mut("python").unwrap().kind = RunnerKind::Codex;
    config.runners.get_mut("python").unwrap().mcp_program = Some("/configured/lockyard".into());
    let token = dir.path().join("token");
    fs::write(&token, "fixture-sensitive-token").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    config.repositories.get_mut("repo").unwrap().cloud = Some(CloudConfig {
        url: "https://cloud.example.invalid".into(),
        workspace: "team".into(),
        repository: "repo".into(),
        token_file: Some(token),
    });
    let source = config.repositories["repo"].checkout.clone();
    let source_head = git(&source, &["rev-parse", "HEAD"]);
    fs::write(source.join("base.txt"), "dirty checkout\n").unwrap();
    let state = config.state_dir.clone();
    let mut request = spec(13, "literal; $(never interpreted)");
    approve_external_fixture(dir.path(), &mut config, &mut request);
    let executor = Executor::new_with_workspace_key(
        config,
        "actual-workspace-id".into(),
        WorkspaceKey::from_entropy([77; 32]),
    )
    .unwrap();
    executor.submit(request.clone(), &caller()).unwrap();
    let record = finished(&executor, &request.id);
    assert_eq!(record.state, JobState::Succeeded);
    assert!(
        !state
            .join("jobs")
            .join(&request.id)
            .join("runtime-key")
            .exists()
    );
    assert_eq!(
        fs::read_to_string(record.worktree.as_ref().unwrap().join("base.txt")).unwrap(),
        "base\n"
    );
    assert_eq!(
        fs::read_to_string(source.join("base.txt")).unwrap(),
        "dirty checkout\n"
    );
    assert_eq!(git(&source, &["rev-parse", "HEAD"]), source_head);
    assert!(!source.join(".git/worktrees").exists());
    let private_git = state.join("jobs").join(&request.id).join("repository.git");
    assert!(!private_git.join("objects/info/alternates").exists());
    use std::os::unix::fs::MetadataExt;
    let object = Path::new("objects")
        .join(&source_head[..2])
        .join(&source_head[2..]);
    assert_ne!(
        fs::metadata(source.join(".git").join(&object))
            .unwrap()
            .ino(),
        fs::metadata(private_git.join(object)).unwrap().ino()
    );
    let output =
        String::from_utf8(executor.read_log(&request.id, 0, 65536).unwrap().bytes).unwrap();
    let args: Vec<String> = serde_json::from_str(output.lines().next().unwrap()).unwrap();
    let context = output
        .lines()
        .find_map(|line| line.strip_prefix("scoped_context:"))
        .unwrap();
    let context: serde_json::Value = serde_json::from_str(context).unwrap();
    assert_eq!(context["XDG_CONFIG_HOME"], "/run/lockyard-config");
    assert_eq!(context["LOCKYARD_REQUIRE_E2EE"], "1");
    assert_eq!(context["LOCKYARD_E2EE_WORKSPACE_ID"], "actual-workspace-id");
    for name in ["LOCKYARD_REQUIRE_E2EE", "LOCKYARD_E2EE_WORKSPACE_ID"] {
        assert!(args.windows(2).any(|pair| pair == ["--env", name]));
    }
    let forwarded = args
        .iter()
        .find(|arg| arg.starts_with("mcp_servers.lockyard.env_vars="))
        .unwrap();
    for name in [
        "XDG_CONFIG_HOME",
        "LOCKYARD_REQUIRE_E2EE",
        "LOCKYARD_E2EE_WORKSPACE_ID",
    ] {
        assert!(forwarded.contains(&format!("\"{name}\"")));
    }
    for flag in [
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--ipc=none",
        "--pull=never",
        "--pids-limit",
        "--memory",
        "--memory-swap",
        "--cpus",
        "--tmpfs",
    ] {
        assert!(args.iter().any(|arg| arg == flag), "missing {flag}");
    }
    let mounts: Vec<_> = args
        .windows(2)
        .filter(|pair| pair[0] == "--mount")
        .map(|pair| pair[1].as_str())
        .collect();
    assert_eq!(mounts.len(), 4);
    assert!(
        mounts
            .iter()
            .any(|mount| mount.ends_with("dst=/run/lockyard-secrets,readonly"))
    );
    assert!(args.iter().any(|arg| arg == "--env-file"));
    assert!(
        mounts
            .iter()
            .any(|mount| mount.ends_with("dst=/run/lockyard-config,readonly"))
    );
    assert!(
        mounts
            .iter()
            .all(|mount| mount.contains(state.to_str().unwrap()))
    );
    assert!(
        mounts.iter().all(
            |mount| !mount.contains(source.to_str().unwrap()) && !mount.contains("docker.sock")
        )
    );
    assert!(
        args.iter()
            .any(|arg| arg == "literal; $(never interpreted)")
    );
    assert!(
        !args
            .iter()
            .any(|arg| arg.contains("fixture-sensitive-token"))
    );
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("fixture-sensitive-token"));
    let patch =
        String::from_utf8(executor.read_patch(&request.id, 0, 65536).unwrap().bytes).unwrap();
    assert!(!patch.contains("fixture-sensitive-token"));
    assert!(!patch.contains("LOCKYARD_TOKEN"));
}

#[test]
#[ignore = "requires the local Docker socket; requires fixture image when resource controls exist"]
fn runtime_resource_capability_report_is_respected() {
    #[cfg(target_os = "linux")]
    if native_live_selected() {
        let root =
            std::path::PathBuf::from(std::env::var_os("LOCKYARD_NATIVE_CGROUP_ROOT").unwrap());
        let report =
            lockyard_node::native::capabilities(Some(&root), &native_cases::sandbox_program());
        assert!(
            report.available,
            "native limits unavailable: {:?}",
            report.reasons
        );
        let dir = tempfile::tempdir().unwrap();
        let executor = Executor::new(live_fixture(dir.path())).unwrap();
        let request = spec(14, "print('native enforced')");
        executor.submit(request.clone(), &caller()).unwrap();
        let record = finished(&executor, &request.id);
        assert_eq!(record.state, JobState::Succeeded, "{record:?}");
        assert!(record.result_manifest.is_some());
        return;
    }
    let output = Command::new(runtime_program())
        .args([
            "--host=unix:///var/run/docker.sock",
            "info",
            "--format",
            "{{.MemoryLimit}} {{.CPUCfsQuota}} {{.PidsLimit}}",
        ])
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .output()
        .unwrap();
    assert!(output.status.success());
    let controls = String::from_utf8(output.stdout).unwrap();
    let supported = controls.trim() == "true true true";
    if supported {
        assert!(
            enabled(),
            "resource-capable runtime requires LOCKYARD_NODE_EXECUTOR_IMAGE"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let config = live_fixture(dir.path());
    let executor = Executor::new(config).unwrap();
    let request = spec(14, "print('container only')");
    executor.submit(request.clone(), &caller()).unwrap();
    let record = finished(&executor, &request.id);
    if supported {
        assert_eq!(record.state, JobState::Succeeded);
    } else {
        assert_eq!(record.state, JobState::Failed);
        assert_eq!(
            record.error_code.as_deref(),
            Some("container_limits_unavailable")
        );
        assert!(record.worktree.is_none() && record.pid.is_none());
    }
}

#[test]
fn execution_profiles_require_signing_identity_immutable_image_and_supply_chain_policy() {
    let dir = tempfile::tempdir().unwrap();
    let original = fixture(dir.path());
    let mut config = original.clone();
    config.provenance = None;
    assert!(matches!(Executor::new(config),Err(error) if error.0=="result_signing_required"));
    let mut config = original.clone();
    config.provenance.as_mut().unwrap().public_key = "a".repeat(64);
    assert!(matches!(Executor::new(config),Err(error) if error.0=="signing_public_key_mismatch"));
    let mut config = original.clone();
    config.runners.get_mut("python").unwrap().container.image = "runner:latest".into();
    assert!(
        matches!(Executor::new(config),Err(error) if error.0=="image_reference_must_be_immutable")
    );
    let mut config = original;
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .supply_chain = None;
    assert!(matches!(Executor::new(config),Err(error) if error.0=="supply_chain_policy_required"));
}

#[test]
fn image_attestation_and_runtime_identity_fail_before_any_execution_and_return_signed_failure() {
    for corrupt_sbom in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = fixture(dir.path());
        let runtime = dir.path().join("negative-image-runtime");
        fs::write(
            &runtime,
            r#"#!/usr/bin/python3
import sys,pathlib
a=sys.argv[1:]
if 'info' in a: print('[]' if any('SecurityOptions' in x for x in a) else 'true true true')
elif 'image' in a: print('sha256:'+'f'*64 if '{{.Id}}' in a else 'null')
else:
    pathlib.Path('UNEXPECTED_EXECUTION').write_text('bad')
    sys.exit(1)
"#,
        )
        .unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        config
            .runners
            .get_mut("python")
            .unwrap()
            .container
            .runtime_program = runtime;
        if corrupt_sbom {
            fs::write(
                &config.runners["python"]
                    .container
                    .supply_chain
                    .as_ref()
                    .unwrap()
                    .sbom_file,
                b"tampered",
            )
            .unwrap();
        }
        let signing = config.provenance.clone().unwrap();
        let state = config.state_dir.clone();
        let executor = Executor::new(config).unwrap();
        let mut request = spec(30, "never executed");
        request.prompt = Some("PRIVATE_PROMPT_SENTINEL".into());
        executor.submit(request.clone(), &caller()).unwrap();
        let record = finished(&executor, &request.id);
        assert_eq!(record.state, JobState::Failed);
        assert_eq!(
            record.error_code.as_deref(),
            Some(if corrupt_sbom {
                "image_evidence_digest_mismatch"
            } else {
                "container_image_identity_mismatch"
            })
        );
        assert!(record.pid.is_none());
        assert!(record.worktree.is_none());
        let job = state.join("jobs").join(&request.id);
        assert!(!job.join("UNEXPECTED_EXECUTION").exists());
        assert!(!job.join("repository.git").exists());
        let document = record
            .result_manifest
            .as_ref()
            .expect("a confirmed pre-execution failure is still signed");
        let verified = provenance::verify_result_identity(
            document,
            &lockyard_node::provenance::TrustedSigningKey {
                public_key: signing.public_key,
            },
            "fixture-node",
            &signing.workspace,
            &request.id,
        )
        .unwrap();
        assert!(!verified.execution_attempted);
        assert_eq!(
            verified.request_sha256,
            provenance::sha256(&serde_json::to_vec(&request).unwrap())
        );
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&document.payload)
            .unwrap();
        assert!(
            !String::from_utf8(payload)
                .unwrap()
                .contains("PRIVATE_PROMPT_SENTINEL")
        );
    }
}

#[test]
fn completed_job_recovers_missing_signature_without_reexecuting_or_changing_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture(dir.path());
    config
        .runners
        .get_mut("python")
        .unwrap()
        .container
        .runtime_program = "/usr/bin/false".into();
    let executor = Executor::new(config.clone()).unwrap();
    let request = spec(31, "never execute");
    executor.submit(request.clone(), &caller()).unwrap();
    let completed = finished(&executor, &request.id);
    assert!(completed.result_manifest.is_some());
    assert!(completed.pid.is_none());
    let mut missing = completed.clone();
    missing.result_manifest = None;
    let path = config
        .state_dir
        .join("jobs")
        .join(&request.id)
        .join("record.json");
    fs::write(&path, serde_json::to_vec(&missing).unwrap()).unwrap();
    drop(executor);
    let deadline = Instant::now() + Duration::from_secs(5);
    let recovered = loop {
        match Executor::new(config.clone()) {
            Ok(executor) => break executor,
            Err(error) if error.0 == "executor_already_running" && Instant::now() < deadline => {
                thread::yield_now()
            }
            Err(error) => panic!("unexpected recovery error: {error}"),
        }
    };
    let result = recovered.status(&request.id).unwrap();
    assert_eq!(result.state, completed.state);
    assert_eq!(result.updated_at_ms, completed.updated_at_ms);
    assert_eq!(result.exit_code, completed.exit_code);
    assert_eq!(result.error_code, completed.error_code);
    assert_eq!(result.result_manifest, completed.result_manifest);
    assert!(result.pid.is_none());
}

#[path = "executor/native_cases.rs"]
mod native_cases;

#[cfg(target_os = "linux")]
fn live_native_resource_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = live_fixture(dir.path());
    let profile = &mut config.runners.get_mut("python").unwrap().container;
    profile.memory_mb = 64;
    profile.cpu_millis = 500;
    profile.pids_limit = 16;
    let checkout = config.repositories["repo"].checkout.clone();
    let executor = Executor::new(config).unwrap();
    let code = format!(
        "import pathlib,time; assert not pathlib.Path({}).exists(); print('limits-ready',flush=True)\nwhile True: pass",
        serde_json::to_string(&checkout.to_string_lossy()).unwrap()
    );
    let inspect = spec(21, &code);
    executor.submit(inspect.clone(), &caller()).unwrap();
    wait(&executor, &inspect.id, |record| {
        record.state == JobState::Running
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !String::from_utf8_lossy(&executor.read_log(&inspect.id, 0, 4096).unwrap().bytes)
        .contains("limits-ready")
    {
        assert!(
            Instant::now() < deadline,
            "native resource inspector never started"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let group = live_native_cgroup(&format!("lockyard-fixture-node-{}", inspect.id));
    assert_eq!(
        fs::read_to_string(group.join("memory.max")).unwrap().trim(),
        (64 * 1024 * 1024).to_string()
    );
    assert_eq!(
        fs::read_to_string(group.join("memory.swap.max"))
            .unwrap()
            .trim(),
        "0"
    );
    assert_eq!(
        fs::read_to_string(group.join("pids.max")).unwrap().trim(),
        "16"
    );
    let quota = fs::read_to_string(group.join("cpu.max")).unwrap();
    let quota = quota
        .split_whitespace()
        .map(|value| value.parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(quota[0] * 2, quota[1]);
    let throttled = |group: &Path| -> u64 {
        fs::read_to_string(group.join("cpu.stat"))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("nr_throttled "))
            .unwrap()
            .parse()
            .unwrap()
    };
    let before = throttled(&group);
    let deadline = Instant::now() + Duration::from_secs(3);
    while throttled(&group) <= before {
        assert!(
            Instant::now() < deadline,
            "CPU quota did not throttle actual workload"
        );
        thread::sleep(Duration::from_millis(30));
    }
    executor.cancel(&inspect.id, &caller()).unwrap();
    assert_eq!(finished(&executor, &inspect.id).state, JobState::Cancelled);
    assert!(!group.exists());
    let pids = spec(
        22,
        r#"import errno,subprocess
children=[]
limited=False
try:
 for _ in range(32):
  try: children.append(subprocess.Popen(['/bin/sleep','30']))
  except OSError as error:
   if error.errno != errno.EAGAIN: raise
   limited=True
   break
finally:
 for child in children: child.terminate()
 for child in children: child.wait()
assert limited
assert len(children)<16
print('pid-limit-enforced',flush=True)
"#,
    );
    executor.submit(pids.clone(), &caller()).unwrap();
    let result = finished(&executor, &pids.id);
    assert_eq!(result.state, JobState::Failed, "{result:?}");
    assert_eq!(result.error_code.as_deref(), Some("limit_exceeded:pids"));
    assert!(result.result_manifest.is_some());
    assert!(
        String::from_utf8_lossy(&executor.read_log(&pids.id, 0, 4096).unwrap().bytes)
            .contains("pid-limit-enforced")
    );
    let memory = spec(
        23,
        r#"chunks=[]
for _ in range(32):
 chunk=bytearray(8*1024*1024)
 for offset in range(0,len(chunk),4096): chunk[offset]=1
 chunks.append(chunk)
raise RuntimeError('runtime did not enforce the configured memory bound')
"#,
    );
    executor.submit(memory.clone(), &caller()).unwrap();
    let result = finished(&executor, &memory.id);
    assert_eq!(result.state, JobState::Failed, "{result:?}");
    assert_eq!(result.error_code.as_deref(), Some("limit_exceeded:memory"));
    assert!(result.result_manifest.is_some());
    assert!(result.patch_error.is_none(), "{result:?}");
}
