// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Linux acceptance: no Docker daemon/image and no ignored success cases.
use super::*;

#[test]
fn native_limit_codes_preserve_signed_result_contract() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let key = SigningKey::generate(&dir.path().join("result.pk8")).unwrap();
    for error in ["limit_exceeded:memory", "limit_exceeded:pids"] {
        let manifest: provenance::ResultManifest = serde_json::from_value(serde_json::json!({
            "version":1,"node_id":"worker","workspace":"workspace",
            "job_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo","runner":"native",
            "request_sha256":"b".repeat(64),"resolved_revision":"c".repeat(40),
            "image_reference":format!("native-rootfs@sha256:{}","a".repeat(64)),
            "image_digest":format!("sha256:{}","a".repeat(64)),
            "image_config_digest":format!("sha256:{}","a".repeat(64)),
            "image_attestation_sha256":"d".repeat(64),"execution_attempted":true,
            "completed_at_ms":1,"state":"failed","exit_code":137,"error_code":error,"artifacts":{}
        }))
        .unwrap();
        manifest.validate().unwrap();
        key.sign_result(&manifest).unwrap();
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn native_capability_detection_refuses_non_linux() {
    let report = lockyard_node::native::capabilities(None, Path::new("/missing/sandbox"));
    assert!(!report.available);
    assert!(report.reasons.iter().any(|reason| reason.contains("Linux")));
}

#[cfg(target_os = "linux")]
pub(super) fn sandbox_program() -> std::path::PathBuf {
    std::env::var_os("LOCKYARD_NATIVE_SANDBOX_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_lockyard-sandbox").into())
}

#[cfg(target_os = "linux")]
pub(super) fn configured_fixture(path: &Path) -> Option<ExecutorConfig> {
    let resources = linux::resources()?;
    Some(linux::config(path, &resources))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use futures_util::future::BoxFuture;
    use lockyard_node::scheduler::{NodeCapabilities, Placement};
    use lockyard_node::wire::{Operation, RpcReply};
    use lockyard_node::workflow::{
        JobTemplate, WorkflowController, WorkflowDefinition, WorkflowDriver, WorkflowError,
        WorkflowPolicy, WorkflowState, WorkflowStep,
    };
    use serde_json::Value;
    use std::path::PathBuf;
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    };

    #[derive(Clone)]
    pub(super) struct Resources {
        cgroup: PathBuf,
        rootfs: PathBuf,
        digest: String,
    }

    fn required() -> bool {
        std::env::var("LOCKYARD_REQUIRE_NATIVE_TESTS").as_deref() == Ok("1")
    }

    pub(super) fn resources() -> Option<Resources> {
        static RESOURCES: OnceLock<std::result::Result<Resources, String>> = OnceLock::new();
        let result = RESOURCES.get_or_init(|| {
            let cgroup = std::env::var_os("LOCKYARD_NATIVE_CGROUP_ROOT")
                .map(PathBuf::from)
                .ok_or_else(|| "set LOCKYARD_NATIVE_CGROUP_ROOT to an empty delegated cgroup v2 subtree".to_string())?;
            let rootfs = std::env::var_os("LOCKYARD_NATIVE_ROOTFS")
                .map(PathBuf::from)
                .ok_or_else(|| "set LOCKYARD_NATIVE_ROOTFS to a provisioned rootfs containing /usr/bin/python3 and /usr/bin/git".to_string())?;
            let helper = super::sandbox_program();
            let report = lockyard_node::native::capabilities(Some(&cgroup), &helper);
            if !report.available {
                return Err(format!("{}; {}", report.reasons.join("; "), report.remedies.join("; ")));
            }
            for binary in ["usr/bin/python3", "usr/bin/git"] {
                if fs::symlink_metadata(rootfs.join(binary)).is_err() {
                    return Err(format!("native rootfs is missing {binary}"));
                }
            }
            let digest = lockyard_node::native::rootfs_digest(&rootfs)
                .map_err(|error| error.to_string())?;
            Ok(Resources { cgroup, rootfs, digest })
        });
        match result {
            Ok(resources) => Some(resources.clone()),
            Err(reason) => {
                assert!(
                    !required(),
                    "native Linux acceptance required but unavailable: {reason}"
                );
                eprintln!(
                    "SKIP native Linux acceptance: {reason}; LOCKYARD_REQUIRE_NATIVE_TESTS=1 makes missing prerequisites fail"
                );
                None
            }
        }
    }

    // Synthetic scanner/attester trust is explicit fixture data, never an upstream scan claim.
    pub(super) fn config(path: &Path, resources: &Resources) -> ExecutorConfig {
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
        let private = path.join("signing");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let key_file = private.join("result.pk8");
        let signer = SigningKey::generate(&key_file).unwrap();
        let attester = SigningKey::generate(&private.join("attester.pk8")).unwrap();
        let now = now_ms();
        let image = format!("native-rootfs@{}", resources.digest);
        let report = VulnerabilityReport {
            version: 1,
            image_digest: resources.digest.clone(),
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
        let statement = ImageAttestation {
            version: 1,
            image_reference: image.clone(),
            image_digest: resources.digest.clone(),
            image_config_digest: resources.digest.clone(),
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
            serde_json::to_vec(&statement.sign(&attester).unwrap()).unwrap(),
        )
        .unwrap();
        ExecutorConfig {
            external_actions: Default::default(),
            node_certificate_sha256: None,
            protected_identity_files: vec![],
            scheduling: Default::default(),
            node_id: "native-fixture".into(),
            state_dir: path.join("state"),
            provenance: Some(ResultSigningConfig {
                workspace: "actual-workspace-id".into(),
                key_file,
                public_key: signer.trusted_key().public_key,
            }),
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
                    owner_approval_authorities: vec![],
                    container: ContainerProfile {
                        runtime: ContainerRuntime::Native,
                        runtime_program: super::sandbox_program(),
                        cgroup_root: Some(resources.cgroup.clone()),
                        native_rootfs: Some(resources.rootfs.clone()),
                        native_network_program: None,
                        image,
                        supply_chain: Some(policy),
                        git_program: "/usr/bin/git".into(),
                        memory_mb: 128,
                        cpu_millis: 500,
                        pids_limit: 32,
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
                max_timeout_seconds: 20,
                max_log_bytes: 65_536,
                max_patch_bytes: 65_536,
                max_pending_jobs: 16,
            },
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn assert_signed(record: &JobRecord) {
        assert!(
            record.result_manifest.is_some(),
            "missing signed result: {record:?}"
        );
        assert!(record.provenance_error.is_none(), "{record:?}");
    }

    #[test]
    fn native_real_command_is_private_and_patch_downloads() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &resources);
        let checkout = config.repositories["repo"].checkout.clone();
        fs::write(checkout.join("base.txt"), "dirty-source\n").unwrap();
        let executor = Executor::new(config).unwrap();
        let mut request = spec(
            40,
            "import pathlib,sys; assert pathlib.Path('base.txt').read_text()=='base\\n'; pathlib.Path('result.txt').write_text('isolated-value\\n'); print(sys.argv[1])",
        );
        request
            .arguments
            .push("$(touch FORBIDDEN); 'literal'".into());
        executor.submit(request.clone(), &caller()).unwrap();
        let result = finished(&executor, &request.id);
        assert_eq!(result.state, JobState::Succeeded, "{result:?}");
        assert_signed(&result);
        assert_eq!(
            fs::read_to_string(checkout.join("base.txt")).unwrap(),
            "dirty-source\n"
        );
        assert!(!checkout.join("result.txt").exists());
        assert!(!result.worktree.as_ref().unwrap().join("FORBIDDEN").exists());
        let log = executor.read_log(&request.id, 0, 65_536).unwrap();
        assert!(String::from_utf8_lossy(&log.bytes).contains("$(touch FORBIDDEN); 'literal'"));
        let patch = executor.read_patch(&request.id, 0, 65_536).unwrap();
        assert!(patch.eof && !patch.truncated);
        let text = String::from_utf8(patch.bytes).unwrap();
        assert!(
            text.contains("result.txt") && text.contains("+isolated-value"),
            "{text}"
        );
    }

    #[test]
    fn native_real_agent_process_preserves_literal_prompt() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path(), &resources);
        config.runners.get_mut("python").unwrap().kind = RunnerKind::Agent;
        let executor = Executor::new(config).unwrap();
        let mut request = spec(
            41,
            "import os,sys,pathlib; assert sys.argv[1]=='--literal agent prompt'; pathlib.Path('agent-result').write_text('agent executed\\n'); print('agent:'+os.environ['LOCKYARD_AGENT'])",
        );
        request.prompt = Some("--literal agent prompt".into());
        executor.submit(request.clone(), &caller()).unwrap();
        let result = finished(&executor, &request.id);
        assert_eq!(result.state, JobState::Succeeded, "{result:?}");
        assert_signed(&result);
        assert!(
            String::from_utf8_lossy(&executor.read_log(&request.id, 0, 4096).unwrap().bytes)
                .contains("agent:node-native-fixture-")
        );
        assert!(
            String::from_utf8_lossy(&executor.read_patch(&request.id, 0, 65_536).unwrap().bytes)
                .contains("+agent executed")
        );
    }

    #[test]
    fn native_kernel_isolation_is_effective_inside_workload() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let executor = Executor::new(config(dir.path(), &resources)).unwrap();
        let request = spec(
            45,
            r#"import ctypes,errno,json,os,pathlib,socket
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert status['NoNewPrivs'].strip()=='1'
assert status['Seccomp'].strip()=='2'
assert int(status['CapEff'].strip(),16)==0
libc=ctypes.CDLL(None,use_errno=True)
assert libc.unshare(0x10000000)==-1
assert ctypes.get_errno()==errno.EPERM
try:
 socket.create_connection(('192.0.2.1',9),0.2)
 raise AssertionError('network namespace allowed external connection')
except OSError: pass
print(json.dumps({name:os.readlink('/proc/self/ns/'+name) for name in ['user','mnt','pid','net','ipc','uts']}),flush=True)
"#,
        );
        executor.submit(request.clone(), &caller()).unwrap();
        let result = finished(&executor, &request.id);
        assert_eq!(result.state, JobState::Succeeded, "{result:?}");
        assert_signed(&result);
        let log = executor.read_log(&request.id, 0, 65_536).unwrap();
        let observed: Value = serde_json::from_slice(&log.bytes).unwrap();
        for name in ["user", "mnt", "pid", "net", "ipc", "uts"] {
            let host = fs::read_link(Path::new("/proc/self/ns").join(name)).unwrap();
            assert_ne!(
                observed[name].as_str().unwrap(),
                host.to_str().unwrap(),
                "shared {name} namespace"
            );
        }
    }

    #[test]
    fn native_memory_limit_returns_signed_memory_failure() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path(), &resources);
        config
            .runners
            .get_mut("python")
            .unwrap()
            .container
            .memory_mb = 64;
        let executor = Executor::new(config).unwrap();
        let request = spec(
            42,
            "chunks=[]\nfor _ in range(32):\n c=bytearray(8*1024*1024)\n for i in range(0,len(c),4096): c[i]=1\n chunks.append(c)\nraise RuntimeError('memory limit missing')",
        );
        executor.submit(request.clone(), &caller()).unwrap();
        let result = finished(&executor, &request.id);
        assert_eq!(result.state, JobState::Failed, "{result:?}");
        assert_eq!(result.error_code.as_deref(), Some("limit_exceeded:memory"));
        assert_signed(&result);
    }

    #[test]
    fn native_bounded_fork_bomb_returns_signed_pids_failure() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path(), &resources);
        config
            .runners
            .get_mut("python")
            .unwrap()
            .container
            .pids_limit = 16;
        let executor = Executor::new(config).unwrap();
        let request = spec(
            43,
            "import errno,subprocess\nchildren=[]\nlimited=False\ntry:\n for _ in range(48):\n  try: children.append(subprocess.Popen(['/bin/sleep','10']))\n  except OSError as e:\n   assert e.errno==errno.EAGAIN\n   limited=True\n   break\nfinally:\n for child in children: child.terminate()\n for child in children: child.wait()\nassert limited\nassert len(children)<16\nprint('pids-bound-enforced',flush=True)",
        );
        executor.submit(request.clone(), &caller()).unwrap();
        let result = finished(&executor, &request.id);
        assert_eq!(result.state, JobState::Failed, "{result:?}");
        assert_eq!(result.error_code.as_deref(), Some("limit_exceeded:pids"));
        assert!(
            String::from_utf8_lossy(&executor.read_log(&request.id, 0, 4096).unwrap().bytes)
                .contains("pids-bound-enforced")
        );
        assert_signed(&result);
    }

    #[test]
    fn native_cancel_kills_detached_descendants_and_removes_cgroup() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &resources);
        let executor = Executor::new(config).unwrap();
        let request = spec(
            44,
            "import subprocess,time; subprocess.Popen(['/bin/sleep','300'],start_new_session=True); print('descendant-started',flush=True); time.sleep(300)",
        );
        executor.submit(request.clone(), &caller()).unwrap();
        wait(&executor, &request.id, |record| {
            record.state == JobState::Running
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !String::from_utf8_lossy(&executor.read_log(&request.id, 0, 4096).unwrap().bytes)
            .contains("descendant-started")
        {
            assert!(Instant::now() < deadline, "native descendant never started");
            thread::sleep(Duration::from_millis(20));
        }
        executor.cancel(&request.id, &caller()).unwrap();
        let result = finished(&executor, &request.id);
        assert_eq!(result.state, JobState::Cancelled, "{result:?}");
        let name = format!("lockyard-native-fixture-{}", request.id);
        let identity = &provenance::sha256(name.as_bytes())[..32];
        assert!(
            !resources
                .cgroup
                .join(format!("lockyard-{identity}"))
                .exists()
        );
        assert_signed(&result);
    }

    struct NativeDriver {
        executor: Executor,
        offline: AtomicBool,
    }
    impl WorkflowDriver for NativeDriver {
        fn describe_nodes(
            &self,
        ) -> BoxFuture<'_, lockyard_node::workflow::Result<Vec<NodeCapabilities>>> {
            Box::pin(async move {
                if self.offline.load(Ordering::SeqCst) {
                    return Err(WorkflowError("fixture_broker_unavailable"));
                }
                Ok(vec![
                    self.executor
                        .capabilities(&"a".repeat(64))
                        .map_err(|error| WorkflowError(error.0))?,
                ])
            })
        }
        fn rpc<'a>(
            &'a self,
            _flow: &'a str,
            node: &'a str,
            pin: &'a str,
            operation: Operation,
            payload: Value,
        ) -> BoxFuture<'a, lockyard_node::workflow::Result<RpcReply<Value>>> {
            Box::pin(async move {
                if self.offline.load(Ordering::SeqCst) {
                    return Err(WorkflowError("fixture_broker_unavailable"));
                }
                assert_eq!(node, "native-fixture");
                assert_eq!(pin, "a".repeat(64));
                let result = match operation {
                    Operation::NodePing => {
                        let resolve = &payload["resolve"];
                        serde_json::to_value(
                            self.executor
                                .workflow_revision(
                                    pin,
                                    resolve["repository"].as_str().unwrap(),
                                    resolve["revision"].as_str().unwrap(),
                                    resolve["runner"].as_str().unwrap(),
                                )
                                .map_err(|error| WorkflowError(error.0))?,
                        )
                        .unwrap()
                    }
                    Operation::JobSubmit => {
                        let request = serde_json::from_value(payload).unwrap();
                        serde_json::to_value(
                            self.executor
                                .submit(request, &caller())
                                .map_err(|error| WorkflowError(error.0))?,
                        )
                        .unwrap()
                    }
                    Operation::JobStatus => serde_json::to_value(
                        self.executor
                            .status(payload["job_id"].as_str().unwrap())
                            .map_err(|error| WorkflowError(error.0))?,
                    )
                    .unwrap(),
                    Operation::JobCancel => serde_json::to_value(
                        self.executor
                            .cancel(payload["job_id"].as_str().unwrap(), &caller())
                            .map_err(|error| WorkflowError(error.0))?,
                    )
                    .unwrap(),
                    _ => return Err(WorkflowError("unexpected_native_fixture_operation")),
                };
                Ok(RpcReply::success(result))
            })
        }
    }

    fn controller(path: &Path, config: &ExecutorConfig) -> WorkflowController {
        let signing = config.provenance.as_ref().unwrap();
        let key = SigningKey::load(&signing.key_file).unwrap();
        WorkflowController::open(
            path,
            WorkflowPolicy::default(),
            signing.workspace.clone(),
            "controller".into(),
            "a".repeat(64),
            BTreeMap::from([("native-fixture".into(), key.trusted_key())]),
            BTreeMap::from([(
                "repo".into(),
                lockyard_node::retention::RetentionPolicy {
                    content_ttl_seconds: 3600,
                },
            )]),
            now_ms(),
        )
        .unwrap()
    }

    fn step(key: &str, needs: &[&str], code: &str) -> WorkflowStep {
        WorkflowStep {
            key: key.into(),
            needs: needs.iter().map(|value| (*value).into()).collect(),
            // This fixture targets its one known node. Automatic placement requires an
            // independently declared node capacity, which this fixture does not invent.
            placement: Placement {
                node: Some("native-fixture".into()),
                ..Default::default()
            },
            job: JobTemplate {
                repository: "repo".into(),
                revision: "HEAD".into(),
                runner: "python".into(),
                arguments: vec![code.into()],
                prompt: None,
                timeout_seconds: Some(20),
                priority: 0,
            },
            require_complete_patch: true,
        }
    }

    async fn until_done(controller: &WorkflowController, driver: &NativeDriver, id: &str) {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            controller.tick(driver, now_ms()).await.unwrap();
            let state = controller.status(id).unwrap();
            if state.state == WorkflowState::Succeeded {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "native workflow failed to reconcile: {state:?}"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }

    #[tokio::test]
    async fn native_two_step_dag_reads_authenticated_predecessor_result_reference() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &resources);
        let controller = controller(dir.path(), &config);
        let driver = NativeDriver {
            executor: Executor::new(config).unwrap(),
            offline: AtomicBool::new(false),
        };
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        controller.submit(WorkflowDefinition { version: 1, id: id.into(), max_parallel: 1, steps: vec![
            step("produce", &[], "print('produced-value=42')"),
            step("consume", &["produce"], "import json,os,pathlib,hashlib; x=json.loads(pathlib.Path(os.environ['LOCKYARD_WORKFLOW_INPUTS_FILE']).read_text())['inputs']; assert len(x)==1; assert x[0]['step']=='produce'; assert x[0]['artifacts']['output.log']['sha256']==hashlib.sha256(b'produced-value=42\\n').hexdigest(); print('verified-predecessor-result')"),
        ] }, now_ms()).unwrap();
        until_done(&controller, &driver, id).await;
        let final_state = controller.status(id).unwrap();
        for step in &final_state.steps {
            assert_signed(&driver.executor.status(&step.job_id).unwrap());
        }
        let consumer = final_state
            .steps
            .iter()
            .find(|step| step.key == "consume")
            .unwrap();
        assert!(
            String::from_utf8_lossy(
                &driver
                    .executor
                    .read_log(&consumer.job_id, 0, 4096)
                    .unwrap()
                    .bytes
            )
            .contains("verified-predecessor-result")
        );
    }

    #[tokio::test]
    async fn native_result_reconciles_after_broker_adapter_outage() {
        let Some(resources) = resources() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path(), &resources);
        let controller = controller(dir.path(), &config);
        let driver = NativeDriver {
            executor: Executor::new(config).unwrap(),
            offline: AtomicBool::new(false),
        };
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
        controller.submit(WorkflowDefinition { version: 1, id: id.into(), max_parallel: 1, steps: vec![step("during-outage", &[], "import time,pathlib; print('started',flush=True); time.sleep(1); pathlib.Path('once').write_text('completed once\\n'); print('completed-during-outage')")] }, now_ms()).unwrap();
        controller.tick(&driver, now_ms()).await.unwrap();
        let scheduled = controller.status(id).unwrap();
        let scheduled_step = &scheduled.steps[0];
        assert!(
            scheduled_step.dispatch_committed
                && scheduled_step.node_id.as_deref() == Some("native-fixture")
                && scheduled_step.last_error.is_none(),
            "native workflow did not dispatch before broker outage: {scheduled:?}"
        );
        let job_id = scheduled_step.job_id.clone();
        wait(&driver.executor, &job_id, |record| {
            record.state == JobState::Running
        });
        driver.offline.store(true, Ordering::SeqCst);
        let _ = controller.tick(&driver, now_ms()).await;
        let actual = finished(&driver.executor, &job_id);
        assert_eq!(actual.state, JobState::Succeeded, "{actual:?}");
        assert_signed(&actual);
        assert_ne!(
            controller.status(id).unwrap().state,
            WorkflowState::Succeeded
        );
        driver.offline.store(false, Ordering::SeqCst);
        until_done(&controller, &driver, id).await;
        let recovered = driver.executor.status(&job_id).unwrap();
        assert_eq!(recovered.pid, actual.pid);
        assert_eq!(recovered.result_manifest, actual.result_manifest);
        assert_eq!(
            fs::read_to_string(recovered.worktree.unwrap().join("once")).unwrap(),
            "completed once\n"
        );
    }
    #[test]
    fn native_bridge_requires_owner_and_fetches_real_http_in_private_network_namespace() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, UdpSocket},
            sync::Arc,
        };
        let Some(resources) = resources() else {
            return;
        };
        let provider = Path::new("/usr/bin/slirp4netns");
        if !provider.is_file() {
            assert!(
                !required(),
                "native bridge acceptance required but /usr/bin/slirp4netns is missing"
            );
            eprintln!(
                "SKIP native bridge acceptance: install /usr/bin/slirp4netns; LOCKYARD_REQUIRE_NATIVE_TESTS=1 makes this fail"
            );
            return;
        }
        // UDP connect selects a route and local address without sending a datagram.
        let route = UdpSocket::bind("0.0.0.0:0").unwrap();
        route.connect("192.0.2.1:9").unwrap();
        let address = route.local_addr().unwrap().ip();
        assert!(!address.is_loopback() && !address.is_unspecified());
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = format!("native-bridge-{}", lockyard_node::wire::new_id().unwrap());
        let expected = token.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = stop.clone();
        let worker = thread::spawn(move || -> std::result::Result<(), String> {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if stop_server.load(Ordering::SeqCst) {
                    return Err("native HTTP fixture cancelled".into());
                }
                if Instant::now() >= deadline {
                    return Err("native HTTP fixture timed out before a request".into());
                }
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .map_err(|error| error.to_string())?;
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream
                        .read_exact(&mut byte)
                        .map_err(|error| error.to_string())?;
                    headers.push(byte[0]);
                    if headers.len() > 8192 {
                        return Err("native HTTP fixture header limit".into());
                    }
                }
                let headers = String::from_utf8(headers).map_err(|error| error.to_string())?;
                if !headers.starts_with("GET /native-bridge-proof HTTP/1.1\r\n")
                    || !headers.to_ascii_lowercase().contains(&format!(
                        "x-native-proof: {}\r\n",
                        expected.to_ascii_lowercase()
                    ))
                {
                    return Err("native HTTP fixture received an unbound request".into());
                }
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                    expected.len()
                );
                stream
                    .write_all(headers.as_bytes())
                    .map_err(|error| error.to_string())?;
                stream
                    .write_all(expected.as_bytes())
                    .map_err(|error| error.to_string())?;
                return Ok(());
            }
        });
        struct Server {
            stop: Arc<AtomicBool>,
            worker: Option<thread::JoinHandle<std::result::Result<(), String>>>,
        }
        impl Drop for Server {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::SeqCst);
                if let Some(worker) = self.worker.take() {
                    let _ = worker.join();
                }
            }
        }
        let mut server = Server {
            stop,
            worker: Some(worker),
        };
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(dir.path(), &resources);
        let runner = config.runners.get_mut("python").unwrap();
        runner.container.network = ContainerNetwork::Bridge;
        runner.container.native_network_program = Some(provider.into());
        let url = format!("http://{address}:{port}/native-bridge-proof");
        let code = format!(
            "import json,os,urllib.request\nr=urllib.request.Request({},headers={{'X-Native-Proof':{}}})\nwith urllib.request.urlopen(r,timeout=5) as response: body=response.read(4096).decode('ascii')\nassert body=={}\nprint(json.dumps({{'netns':os.readlink('/proc/self/ns/net'),'body':body}}))",
            serde_json::to_string(&url).unwrap(),
            serde_json::to_string(&token).unwrap(),
            serde_json::to_string(&token).unwrap(),
        );
        let mut request = spec(47, &code);
        approve_external_fixture(dir.path(), &mut config, &mut request);
        let executor = Executor::new(config).unwrap();
        let mut unsigned = request.clone();
        unsigned.owner_approval = None;
        assert_eq!(
            executor.submit(unsigned, &caller()).unwrap_err().0,
            "owner_approval_required"
        );
        executor.submit(request.clone(), &caller()).unwrap();
        let result = finished(&executor, &request.id);
        let log = executor.read_log(&request.id, 0, 65_536).unwrap();
        assert_eq!(
            result.state,
            JobState::Succeeded,
            "{result:?}; sandbox output: {}",
            String::from_utf8_lossy(&log.bytes)
        );
        assert_signed(&result);
        server.worker.take().unwrap().join().unwrap().unwrap();
        let observed: Value = serde_json::from_slice(&log.bytes).unwrap();
        assert_eq!(observed["body"], token);
        assert_ne!(
            observed["netns"].as_str().unwrap(),
            fs::read_link("/proc/self/ns/net")
                .unwrap()
                .to_str()
                .unwrap()
        );
        let name = format!("lockyard-native-fixture-{}", request.id);
        let group = resources.cgroup.join(format!(
            "lockyard-{}",
            &provenance::sha256(name.as_bytes())[..32]
        ));
        assert!(
            !group.exists(),
            "native bridge workload or proxy still owns a cgroup"
        );
    }

    mod broker;
}
