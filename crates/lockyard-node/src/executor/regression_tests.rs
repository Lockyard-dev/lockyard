// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use std::os::unix::fs::PermissionsExt;

pub(crate) fn retention_fixture() -> (tempfile::TempDir, ExecutorConfig, Executor) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = ExecutorConfig {
        external_actions: Default::default(),
        node_id: "worker".into(),
        state_dir: root.path().join("executor"),
        repositories: BTreeMap::new(),
        runners: BTreeMap::new(),
        provenance: None,
        limits: ExecutionLimits::default(),
        scheduling: Default::default(),
        node_certificate_sha256: None,
        protected_identity_files: Vec::new(),
    };
    let executor = Executor::new(config.clone()).unwrap();
    (root, config, executor)
}
pub(crate) fn retained_fixture_record(
    executor: &Executor,
    state: JobState,
    expiry: u64,
) -> JobRecord {
    let current = now_ms();
    let record: JobRecord = serde_json::from_value(serde_json::json!({
            "spec":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo","revision":"HEAD","runner":"runner","arguments":[],"prompt":"private-prompt-sentinel","timeout_seconds":null},
            "state":state,"agent":"derived","submitter":"controller","submitter_certificate_sha256":"a".repeat(64),
            "created_at":current-120_000,"updated_at":current-60_000,
            "retention":{"content_ttl_seconds":60,"admitted_at_ms":current-120_000,"terminal_expires_at_ms":expiry,"purged_at_ms":null},
            "worktree":null,"pid":null,"exit_code":null,"error_code":null,"log_bytes":0,"log_truncated":false
        })).unwrap();
    let job = executor
        .inner
        .config
        .state_dir
        .join("jobs")
        .join(&record.spec.id);
    private_dir_new(&job).unwrap();
    fs::write(job.join("output.log"), b"private-log-sentinel").unwrap();
    fs::write(job.join("result.patch"), b"private-patch-sentinel").unwrap();
    private_dir_new(&job.join("worktree")).unwrap();
    fs::write(job.join("worktree/private.rs"), b"private-code-sentinel").unwrap();
    private_dir_new(&job.join("repository.git")).unwrap();
    fs::write(job.join("repository.git/config"), b"private-git-sentinel").unwrap();
    persist(&executor.inner.config.state_dir, &record).unwrap();
    executor.inner.jobs.lock().unwrap().insert(
        record.spec.id.clone(),
        Entry {
            record: record.clone(),
            cancel: Arc::new(AtomicBool::new(false)),
            artifacts: Arc::new(Mutex::new(())),
        },
    );
    record
}
fn synthetic_queue(count: usize, concurrency: usize) -> (tempfile::TempDir, Executor, Vec<String>) {
    let (root, _config, mut executor) = retention_fixture();
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .limits
        .max_concurrency = concurrency;
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .limits
        .max_pending_jobs = 4096;
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .scheduling
        .queue
        .max_pending_per_project = 4096;
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .scheduling
        .queue
        .max_pending_per_submitter = 4096;
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .scheduling
        .queue
        .max_running_per_submitter = concurrency;
    Arc::get_mut(&mut executor.inner)
        .unwrap()
        .config
        .scheduling
        .queue
        .max_running_per_project = concurrency;
    let mut first = retained_fixture_record(&executor, JobState::Queued, now_ms() + 60_000);
    first.retention.as_mut().unwrap().terminal_expires_at_ms = None;
    executor
        .inner
        .jobs
        .lock()
        .unwrap()
        .get_mut(&first.spec.id)
        .unwrap()
        .record = first.clone();
    persist(&executor.inner.config.state_dir, &first).unwrap();
    let mut ids = vec![first.spec.id.clone()];
    for _ in 1..count {
        let mut record = first.clone();
        record.spec.id = crate::wire::new_id().unwrap();
        private_dir_new(
            &executor
                .inner
                .config
                .state_dir
                .join("jobs")
                .join(&record.spec.id),
        )
        .unwrap();
        persist(&executor.inner.config.state_dir, &record).unwrap();
        executor.inner.jobs.lock().unwrap().insert(
            record.spec.id.clone(),
            Entry {
                record: record.clone(),
                cancel: Arc::new(AtomicBool::new(false)),
                artifacts: Arc::new(Mutex::new(())),
            },
        );
        ids.push(record.spec.id);
    }
    (root, executor, ids)
}
fn install_worker_hook(executor: &Executor, hook: WorkerRunHook) {
    WORKER_RUN_HOOKS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap()
        .insert(executor.inner.config.state_dir.clone(), hook);
}
fn wait_queue(mut ready: impl FnMut() -> bool) {
    // This is a deadlock guard, not a throughput target: 1000 durable journal
    // writes may contend with unrelated builds on the same filesystem.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "bounded queue fixture did not settle"
        );
        thread::sleep(Duration::from_millis(2));
    }
}
#[cfg(target_os = "linux")]
fn process_stat(name: &str) -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|number| number.parse().ok())
        })
        .unwrap()
}

fn git_ok(path: &Path, args: &[&str]) -> Vec<u8> {
    let output = git(path).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
// A protocol fixture for patch-only Git calls on controlled test data, not a container proof.
fn patch_fixture(root: &Path) -> (ContainerProfile, PathBuf, PathBuf, String) {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    git_ok(&source, &["init", "-q"]);
    git_ok(&source, &["config", "user.email", "test@example.invalid"]);
    git_ok(&source, &["config", "user.name", "Test"]);
    fs::write(source.join("base"), b"base\n").unwrap();
    fs::create_dir(source.join(".lockyard")).unwrap();
    fs::write(source.join(".lockyard/tracked.rs"), b"// original code\n").unwrap();
    git_ok(&source, &["add", "."]);
    git_ok(&source, &["commit", "-qm", "base"]);
    let revision = String::from_utf8(git_ok(&source, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_string();
    let job = root.join("job");
    private_dir_new(&job).unwrap();
    private_dir_new(&job.join("runtime-config")).unwrap();
    private_open(&job.join("runtime-user"), true)
        .unwrap()
        .write_all(host_container_identity().as_bytes())
        .unwrap();
    let metadata = job.join("repository.git");
    assert!(
        git(&source)
            .args(["clone", "--bare", "--no-hardlinks"])
            .arg(&source)
            .arg(&metadata)
            .output()
            .unwrap()
            .status
            .success()
    );
    let worktree = job.join("worktree");
    assert!(
        git(&metadata)
            .args(["worktree", "add", "--detach"])
            .arg(&worktree)
            .arg(&revision)
            .output()
            .unwrap()
            .status
            .success()
    );
    let runtime = root.join("runtime-fixture");
    fs::write(
        &runtime,
        r#"#!/usr/bin/python3
import os,sys
a=sys.argv[1:]
if 'container' in a and 'rm' in a: sys.exit(0)
if 'run' not in a: sys.exit(2)
os.chdir(a[a.index('--workdir')+1])
os.environ['GIT_CONFIG_GLOBAL']='/dev/null'
os.environ['GIT_CONFIG_NOSYSTEM']='1'
os.execve('/usr/bin/git',['git']+a[a.index('fixture:image')+1:],os.environ)
"#,
    )
    .unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    (
        ContainerProfile {
            runtime: ContainerRuntime::Docker,
            runtime_program: runtime,
            image: "fixture:image".into(),
            supply_chain: None,
            git_program: "/usr/bin/git".into(),
            memory_mb: 128,
            cpu_millis: 1000,
            pids_limit: 64,
            network: ContainerNetwork::None,
        },
        job,
        worktree,
        revision,
    )
}

mod content_retention;
mod credentials;
mod external_actions;
mod patch;
mod provenance;
mod queue;
mod queue_failures;
mod redaction;
mod runtime_output;
mod startup;

struct FailingWriter {
    bytes: Vec<u8>,
    fail_after: usize,
}
impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() >= self.fail_after {
            return Err(std::io::Error::other("fixture writer failure"));
        }
        let count = bytes.len().min(2).min(self.fail_after - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
