// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Explicit, resumable coordination steps. Receipts are evidence of individual steps, not a
//! transaction or a rollback. An uncertain write is never automatically repeated.

use lockyard_core::proto::{ClaimRequest, SendRequest, WorkAction, WorkStep};
use lockyard_core::{Backend, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_PLAN_BYTES: usize = 65536;
const MAX_RECEIPT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    steps: Vec<Step>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    TaskClaim {
        id: i64,
        #[serde(default = "default_ttl")]
        ttl: i64,
    },
    ZoneClaim {
        paths: Vec<String>,
        #[serde(default)]
        note: String,
        #[serde(default = "default_ttl")]
        ttl: i64,
    },
    WorkHandoff {
        id: i64,
        to: String,
        report: String,
        #[serde(default)]
        commits: Vec<String>,
        if_version: i64,
    },
    MessageSend {
        to: String,
        body: String,
    },
}

fn default_ttl() -> i64 {
    30
}

impl Step {
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::TaskClaim { id, ttl } => *id > 0 && (1..=240).contains(ttl),
            Self::ZoneClaim { paths, ttl, .. } => {
                !paths.is_empty()
                    && paths.len() <= 100
                    && paths.iter().all(|p| !p.is_empty())
                    && (1..=240).contains(ttl)
            }
            Self::WorkHandoff {
                id,
                to,
                report,
                if_version,
                commits,
            } => {
                *id > 0
                    && !to.trim().is_empty()
                    && !report.trim().is_empty()
                    && *if_version >= 0
                    && commits.len() <= 100
            }
            Self::MessageSend { to, body } => !to.trim().is_empty() && !body.trim().is_empty(),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Invalid("invalid workflow step fields".into()))
        }
    }

    fn execute(&self, backend: &mut dyn Backend, agent: &str, now: i64) -> Result<Value> {
        fn encode(value: impl serde::Serialize) -> Result<Value> {
            serde_json::to_value(value).map_err(|e| Error::Protocol(e.to_string()))
        }
        match self {
            Self::TaskClaim { id, ttl } => {
                let result = backend.claim_task_receipt(agent, *id, *ttl, now)?;
                if backend.is_cloud()
                    && (result["id"] != *id
                        || result["raw_status"] != "active"
                        || result["registry_assignment_source"] != "claim_response"
                        || !assignment_identity(&result["registry_assignment"], agent))
                {
                    // The write already happened. Missing or unrelated evidence cannot establish
                    // its outcome, and must never turn into an automatically retryable failure.
                    return Err(Error::Protocol(
                        "Task claim response lacks the workflow agent's authoritative assignment; reconcile before retrying.".into(),
                    ));
                }
                Ok(result)
            }
            Self::ZoneClaim { paths, note, ttl } => encode(backend.claim(
                agent,
                &ClaimRequest {
                    paths: paths.clone(),
                    note: note.clone(),
                    ttl_minutes: *ttl,
                    ..Default::default()
                },
                now,
            )?),
            Self::WorkHandoff {
                id,
                to,
                report,
                commits,
                if_version,
            } => encode(backend.work_step(
                agent,
                *id,
                WorkAction::Handoff,
                &WorkStep {
                    to: Some(to.clone()),
                    report: Some(report.clone()),
                    commits: commits.clone(),
                    version: Some(*if_version),
                    ..Default::default()
                },
            )?),
            Self::MessageSend { to, body } => encode(backend.send(
                agent,
                &SendRequest {
                    to: to.clone(),
                    body: body.clone(),
                    ..Default::default()
                },
                now,
            )?),
        }
    }
}

fn assignment_identity(assignment: &Value, agent: &str) -> bool {
    assignment["executor"]
        .as_str()
        .is_some_and(|executor| !executor.trim().is_empty())
        && assignment["session"] == agent
        && assignment["claimed_at"]
            .as_str()
            .is_some_and(|epoch| !epoch.trim().is_empty())
}

/// Execute explicitly supplied steps, preserving completed and uncertain outcomes across retries.
pub fn run(
    cwd: &Path,
    backend: &mut dyn Backend,
    agent: &str,
    now: i64,
    operation_id: &str,
    plan: &Value,
) -> Result<Value> {
    if agent.trim().is_empty() {
        return Err(Error::Invalid("workflow needs an agent name".into()));
    }
    if serde_json::to_vec(plan).map_or(true, |p| p.len() > MAX_PLAN_BYTES) {
        return Err(Error::Invalid("workflow plan exceeds 65536 bytes".into()));
    }
    let mut parsed: Plan = serde_json::from_value(plan.clone())
        .map_err(|e| Error::Invalid(format!("invalid workflow plan: {e}")))?;
    if parsed.steps.is_empty() || parsed.steps.len() > 32 {
        return Err(Error::Invalid("workflow needs 1..32 steps".into()));
    }
    for step in &parsed.steps {
        step.validate()?;
    }
    let root = cwd.canonicalize()?;
    for step in &mut parsed.steps {
        if let Step::ZoneClaim { paths, .. } = step {
            for path in paths {
                *path = lockyard_core::ZonePath::resolve(&root, &root, path)?
                    .ok_or_else(|| {
                        Error::Invalid("workflow zone path is outside the project".into())
                    })?
                    .as_str()
                    .to_owned();
            }
        }
    }
    let dir = directory(&root, operation_id, true)?;
    let receipt_path = dir.join(format!("{operation_id}.json"));
    let lock_path = dir.join(format!("{operation_id}.lock"));
    let config = lockyard_core::config::Config::load(&root)?;
    let credential = if backend.is_cloud() {
        Some(lockyard_cloud_client::credential_fingerprint(
            &lockyard_core::config::Config::token()?,
        ))
    } else {
        None
    };
    let identity = json!({"cwd":root,"agent":agent,"cloud":backend.is_cloud(),"url":config.url,"workspace":config.workspace,"repository":config.repository,"credential_fingerprint":credential,"plan":plan,"resolved_plan":parsed});
    let mut lock = match private_new(&lock_path) {
        Ok(file) => Lock {
            path: lock_path.clone(),
            _file: file,
        },
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut receipt = read_receipt(&receipt_path)?;
            verify(&receipt, &identity)?;
            uncertain(&mut receipt);
            receipt["ok"] = json!(false);
            receipt["locked"] = json!(true);
            receipt["warning"] = json!(
                "Another runner or a retained crash lock exists. Inspect the owner before removing its lock; unknown writes need reconciliation."
            );
            return Ok(receipt);
        }
        Err(error) => return Err(error.into()),
    };
    writeln!(lock._file, "pid={} started_at={now}", std::process::id())?;
    lock._file.sync_all()?;
    let mut receipt = match read_receipt(&receipt_path) {
        Ok(mut stored) => {
            verify(&stored, &identity)?;
            if uncertain(&mut stored) {
                save(&dir, &receipt_path, &stored)?;
            }
            stored
        }
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            let steps:Vec<Value>=parsed.steps.iter().enumerate().map(|(i,_)|json!({"index":i,"status":"not_started","idempotency_key":lockyard_cloud_client::ulid()})).collect();
            let stored = json!({"operation_id":operation_id,"identity":identity,"created_at":now,"updated_at":now,"ok":false,"atomic":false,"steps":steps});
            save(&dir, &receipt_path, &stored)?;
            stored
        }
        Err(error) => return Err(error),
    };
    let has_pending = receipt["steps"]
        .as_array()
        .is_some_and(|steps| steps.iter().any(|step| step["status"] != "completed"));
    if has_pending {
        if let Some(problem) =
            stale_completed_ownership(backend, agent, now, &parsed.steps, &receipt)
        {
            receipt["ok"] = json!(false);
            receipt["needs_reconciliation"] = problem;
            receipt["updated_at"] = json!(now);
            save(&dir, &receipt_path, &receipt)?;
            return Ok(receipt);
        }
        if let Some(object) = receipt.as_object_mut() {
            object.remove("needs_reconciliation");
        }
    }
    for (i, step) in parsed.steps.iter().enumerate() {
        let status = receipt["steps"][i]["status"].as_str().unwrap_or("unknown");
        if status == "completed" {
            continue;
        }
        if status == "unknown" {
            receipt["ok"] = json!(false);
            return Ok(receipt);
        }
        if status != "not_started" && status != "failed" {
            return Err(Error::Invalid("invalid workflow receipt status".into()));
        }
        let key = receipt["steps"][i]["idempotency_key"]
            .as_str()
            .ok_or_else(|| Error::Invalid("workflow receipt lacks idempotency key".into()))?
            .to_owned();
        if key.len() != 26 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::Invalid("invalid workflow idempotency key".into()));
        }
        receipt["steps"][i]["status"] = json!("in_flight");
        receipt["updated_at"] = json!(now);
        save(&dir, &receipt_path, &receipt)?;
        backend.set_write_idempotency_key(Some(key));
        let result = step.execute(backend, agent, now);
        backend.set_write_idempotency_key(None);
        match result {
            Ok(value) => {
                receipt["steps"][i]["status"] = json!("completed");
                receipt["steps"][i]["result"] = value;
                if let Some(entry) = receipt["steps"][i].as_object_mut() {
                    entry.remove("error");
                }
            }
            Err(error) => {
                let certain = matches!(
                    error,
                    Error::Invalid(_)
                        | Error::Denied(_)
                        | Error::Conflict(_)
                        | Error::Contended(_)
                        | Error::NotFound(_)
                        | Error::NeedsCloud(_)
                        | Error::NeedsLocal(_)
                        | Error::Frozen(_)
                        | Error::StaleFence(_)
                );
                receipt["steps"][i]["status"] = json!(if certain { "failed" } else { "unknown" });
                receipt["steps"][i]["error"] =
                    json!({"kind":error.kind(),"message":error.to_string()});
                receipt["ok"] = json!(false);
                save(&dir, &receipt_path, &receipt)?;
                return Ok(receipt);
            }
        }
        save(&dir, &receipt_path, &receipt)?;
    }
    receipt["ok"] = json!(true);
    save(&dir, &receipt_path, &receipt)?;
    drop(lock);
    Ok(receipt)
}

/// Completed effects are historical; before executing more steps, leases must still be held.
/// Cloud assignments retain their original identity and epoch; local tasks require current
/// ownership by this agent. Do not renew or reacquire anything automatically.
fn stale_completed_ownership(
    backend: &dyn Backend,
    agent: &str,
    now: i64,
    steps: &[Step],
    receipt: &Value,
) -> Option<Value> {
    for (index, step) in steps.iter().enumerate() {
        if receipt["steps"][index]["status"] != "completed" {
            continue;
        }
        let saved = &receipt["steps"][index]["result"];
        let result: Result<bool> = match step {
            Step::TaskClaim { id, .. } if backend.is_cloud() => match backend.registry_item(*id) {
                Ok(item) => {
                    let current = &item["assignment"];
                    let previous = &saved["registry_assignment"];
                    if !current["lease_active"].is_boolean()
                        || saved["registry_assignment_source"] != "claim_response"
                        || !assignment_identity(previous, agent)
                    {
                        return Some(
                            json!({"step_index":index,"kind":"current_ownership_unverified","reason":"The server or saved receipt lacks an authoritative claim response and assignment lease check for this agent; reconcile this task before continuing."}),
                        );
                    }
                    Ok(item["status"] == "active"
                        && current["lease_active"] == true
                        && current["executor"] == previous["executor"]
                        && current["session"] == previous["session"]
                        && current["claimed_at"] == previous["claimed_at"])
                }
                Err(error) => Err(error),
            },
            Step::TaskClaim { id, .. } => backend.task(*id).map(|task| {
                task.status == lockyard_core::tasks::Status::Claimed
                    && task.assignee.as_deref() == Some(agent)
                    && task.lease_until.is_some_and(|until| until > now)
            }),
            Step::ZoneClaim { .. } => backend
                .claims(
                    &lockyard_core::proto::ClaimQuery {
                        session: Some(agent.into()),
                        path: None,
                    },
                    now,
                )
                .map(|claims| {
                    claims.iter().any(|claim| {
                        claim.session == agent
                            && json!(claim.id) == saved["id"]
                            && json!(claim.fence) == saved["fence"]
                            && json!(claim.paths) == saved["paths"]
                    })
                }),
            _ => continue,
        };
        match result {
            Ok(true) => {}
            Ok(false) => {
                return Some(
                    json!({"step_index":index,"kind":"ownership_changed","reason":"A previously completed claim is no longer the same active ownership. Completed steps were not repeated; reconcile before further writes."}),
                );
            }
            Err(error) => {
                return Some(
                    json!({"step_index":index,"kind":"current_ownership_unverified","reason":"Current ownership could not be read; no further writes were attempted.","read_error":error.kind()}),
                );
            }
        }
    }
    None
}

/// Read a receipt without retrying any step or repairing a retained lock.
pub fn inspect(cwd: &Path, operation_id: &str) -> Result<Value> {
    let dir = directory(&cwd.canonicalize()?, operation_id, false)?;
    let mut receipt = read_receipt(&dir.join(format!("{operation_id}.json")))?;
    uncertain(&mut receipt);
    receipt["locked"] = json!(dir.join(format!("{operation_id}.lock")).exists());
    Ok(receipt)
}

fn verify(receipt: &Value, identity: &Value) -> Result<()> {
    if receipt.get("identity") != Some(identity) {
        return Err(Error::Invalid(
            "workflow operation belongs to a different agent, project, backend or plan".into(),
        ));
    }
    let expected = identity["plan"]["steps"].as_array().map_or(0, Vec::len);
    if receipt["steps"].as_array().map_or(0, Vec::len) != expected {
        return Err(Error::Invalid("invalid workflow receipt step count".into()));
    }
    Ok(())
}

fn uncertain(receipt: &mut Value) -> bool {
    let mut changed = false;
    if let Some(steps) = receipt["steps"].as_array_mut() {
        for step in steps {
            if step["status"] == "in_flight" {
                step["status"] = json!("unknown");
                step["error"] = json!({"kind":"interrupted","message":"The process stopped before confirming this write; reconcile before continuing."});
                changed = true;
            }
        }
    }
    if changed {
        receipt["ok"] = json!(false);
    }
    changed
}

fn directory(root: &Path, operation_id: &str, create: bool) -> Result<PathBuf> {
    if operation_id.is_empty()
        || operation_id.len() > 64
        || !operation_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Invalid(
            "operation id must contain 1..64 ASCII letters, digits, '-' or '_'".into(),
        ));
    }
    let local = root.join(".lockyard");
    ensure_directory(&local, false)?;
    let dir = local.join("workflows");
    ensure_directory(&dir, create)?;
    Ok(dir)
}

fn ensure_directory(path: &Path, create: bool) -> Result<()> {
    if create {
        match fs::create_dir(path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::Invalid(
            "workflow state directory must be a real directory".into(),
        ));
    }
    Ok(())
}

fn private_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn read_receipt(path: &Path) -> Result<Value> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Invalid(
            "workflow receipt must be a regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(Error::Invalid("workflow receipt is too large".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::Invalid("invalid workflow receipt JSON".into()))
}

fn save(dir: &Path, path: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| Error::Protocol(e.to_string()))?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(Error::Invalid("workflow receipt is too large".into()));
    }
    let temporary = dir.join(format!(".{}.tmp", lockyard_cloud_client::ulid()));
    let result = (|| -> Result<()> {
        let mut file = private_new(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

struct Lock {
    path: PathBuf,
    _file: File,
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockyard_cloud_client::{Call, ClientError, CloudBackend, Transport};
    use lockyard_core::proto::ReleaseRequest;
    use lockyard_core::{Store, tasks::TaskSpec};

    struct AssignmentLease {
        active: Option<bool>,
        claimed_at: &'static str,
    }
    impl Transport for AssignmentLease {
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            assert_eq!(call.method, "GET");
            assert_eq!(call.path, "/api/v1/registry/items/D-1");
            Ok(
                json!({"id":"D-1","status":"active","assignment":{"executor":"token:owner:me","session":"me","claimed_at":self.claimed_at,"lease_active":self.active}}),
            )
        }
    }

    #[test]
    fn cloud_resume_requires_server_active_lease_and_the_original_assignment_epoch() {
        let epoch = "2026-11-06T12:00:00Z";
        let steps = vec![
            Step::TaskClaim { id: 1, ttl: 30 },
            Step::MessageSend {
                to: "other".into(),
                body: "continue".into(),
            },
        ];
        let receipt = json!({"steps":[{"status":"completed","result":{"registry_assignment_source":"claim_response","registry_assignment":{"executor":"token:owner:me","session":"me","claimed_at":epoch}}},{"status":"failed"}]});
        let active = CloudBackend::new(
            AssignmentLease {
                active: Some(true),
                claimed_at: epoch,
            },
            "me",
        );
        assert!(stale_completed_ownership(&active, "me", 1, &steps, &receipt).is_none());
        let expired = CloudBackend::new(
            AssignmentLease {
                active: Some(false),
                claimed_at: epoch,
            },
            "me",
        );
        assert_eq!(
            stale_completed_ownership(&expired, "me", 1, &steps, &receipt).unwrap()["kind"],
            "ownership_changed"
        );
        let unsupported = CloudBackend::new(
            AssignmentLease {
                active: None,
                claimed_at: epoch,
            },
            "me",
        );
        assert_eq!(
            stale_completed_ownership(&unsupported, "me", 1, &steps, &receipt).unwrap()["kind"],
            "current_ownership_unverified"
        );
        let reassigned = CloudBackend::new(
            AssignmentLease {
                active: Some(true),
                claimed_at: "2026-11-06T13:00:00Z",
            },
            "me",
        );
        assert_eq!(
            stale_completed_ownership(&reassigned, "me", 1, &steps, &receipt).unwrap()["kind"],
            "ownership_changed"
        );
    }

    #[test]
    fn resumes_after_conflict_without_repeating_completed_step() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();
        Backend::add_task(
            &mut store,
            "me",
            &TaskSpec {
                title: "work".into(),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
        Backend::claim(
            &mut store,
            "other",
            &ClaimRequest {
                paths: vec!["src".into()],
                ttl_minutes: 30,
                ..Default::default()
            },
            1000,
        )
        .unwrap();
        let plan = json!({"steps":[{"kind":"task_claim","id":1,"ttl":30},{"kind":"zone_claim","paths":["src"],"ttl":30}]});
        let first = run(dir.path(), &mut store, "me", 1001, "work-1", &plan).unwrap();
        assert_eq!(first["steps"][0]["status"], "completed");
        assert_eq!(first["steps"][1]["status"], "failed");
        assert_eq!(first["ok"], false);
        Backend::release(&mut store, "other", None, &ReleaseRequest::default(), 1002).unwrap();
        let again = run(dir.path(), &mut store, "me", 1003, "work-1", &plan).unwrap();
        assert_eq!(again["ok"], true);
        assert_eq!(again["steps"][0], first["steps"][0]);
        assert_eq!(
            run(dir.path(), &mut store, "me", 1004, "work-1", &plan).unwrap(),
            again
        );
        assert!(run(dir.path(), &mut store, "other", 1005, "work-1", &plan).is_err());
        let changed = json!({"steps":[{"kind":"task_claim","id":1,"ttl":60}]});
        assert!(run(dir.path(), &mut store, "me", 1005, "work-1", &changed).is_err());
    }

    #[test]
    fn interrupted_write_is_unknown_and_never_automatically_retried() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();
        Backend::add_task(
            &mut store,
            "me",
            &TaskSpec {
                title: "work".into(),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
        let plan = json!({"steps":[{"kind":"task_claim","id":1}]});
        let mut receipt = run(dir.path(), &mut store, "me", 1001, "interrupted", &plan).unwrap();
        receipt["steps"][0]["status"] = json!("in_flight");
        receipt["ok"] = json!(false);
        let root = dir.path().canonicalize().unwrap();
        let path = directory(&root, "interrupted", false).unwrap();
        save(&path, &path.join("interrupted.json"), &receipt).unwrap();
        assert_eq!(
            inspect(dir.path(), "interrupted").unwrap()["steps"][0]["status"],
            "unknown"
        );
        let again = run(dir.path(), &mut store, "me", 1002, "interrupted", &plan).unwrap();
        assert_eq!(again["steps"][0]["status"], "unknown");
        assert_eq!(again["ok"], false);
    }

    #[test]
    fn expired_completed_claim_blocks_later_writes_without_reacquiring_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();
        Backend::add_task(
            &mut store,
            "me",
            &TaskSpec {
                title: "work".into(),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
        Backend::claim(
            &mut store,
            "other",
            &ClaimRequest {
                paths: vec!["src".into()],
                ttl_minutes: 240,
                ..Default::default()
            },
            1000,
        )
        .unwrap();
        let plan = json!({"steps":[{"kind":"task_claim","id":1,"ttl":1},{"kind":"zone_claim","paths":["src"]}]});
        let first = run(dir.path(), &mut store, "me", 1001, "expired-claim", &plan).unwrap();
        assert_eq!(first["steps"][0]["status"], "completed");
        assert_eq!(first["steps"][1]["status"], "failed");
        Backend::release(&mut store, "other", None, &ReleaseRequest::default(), 62001).unwrap();
        let again = run(dir.path(), &mut store, "me", 62002, "expired-claim", &plan).unwrap();
        assert_eq!(again["ok"], false);
        assert_eq!(again["needs_reconciliation"]["kind"], "ownership_changed");
        assert_eq!(again["steps"][0], first["steps"][0]);
        assert!(
            Backend::claims(&store, &Default::default(), 62002)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn validates_all_steps_before_any_side_effect_and_rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();
        let plan = json!({"steps":[{"kind":"zone_claim","paths":["src"]},{"kind":"execute_shell","command":"false"}]});
        assert!(run(dir.path(), &mut store, "me", 1000, "invalid", &plan).is_err());
        assert!(
            Backend::claims(&store, &Default::default(), 1000)
                .unwrap()
                .is_empty()
        );
        let valid = json!({"steps":[{"kind":"zone_claim","paths":["src"]}]});
        assert!(run(dir.path(), &mut store, "me", 1000, "../outside", &valid).is_err());
    }

    #[test]
    fn zone_paths_use_project_canonical_form_and_outside_paths_fail_before_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::init(dir.path()).unwrap();
        let outside = json!({"steps":[{"kind":"zone_claim","paths":["safe"]},{"kind":"zone_claim","paths":["../outside"]}]});
        assert!(run(dir.path(), &mut store, "me", 1000, "outside-path", &outside).is_err());
        assert!(
            Backend::claims(&store, &Default::default(), 1000)
                .unwrap()
                .is_empty()
        );
        let plan = json!({"steps":[{"kind":"zone_claim","paths":["src/../owned"]}]});
        let receipt = run(dir.path(), &mut store, "me", 1000, "normalized-path", &plan).unwrap();
        assert_eq!(receipt["ok"], true);
        assert_eq!(receipt["steps"][0]["result"]["paths"], json!(["owned"]));
        let conflict = Backend::claim(
            &mut store,
            "other",
            &ClaimRequest {
                paths: vec!["owned/file.rs".into()],
                ttl_minutes: 30,
                ..Default::default()
            },
            1001,
        );
        assert!(matches!(conflict, Err(Error::Conflict(_))));
    }
}
