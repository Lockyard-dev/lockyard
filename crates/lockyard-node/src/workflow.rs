// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Private durable DAG controller. An uncertain step is only queried at its pinned incarnation.
use crate::{
    provenance::{self, ResultManifest, SignedDocument, TrustedSigningKey},
    retention::RetentionPolicy,
    scheduler::{self, NodeCapabilities, Placement},
    wire::{self, JobRecord, JobSpec, JobState, Operation, RpcReply},
};
use futures_util::{
    future::BoxFuture,
    stream::{FuturesUnordered, StreamExt},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const MAX_DEFINITION_BYTES: usize = 128 * 1024;
const MAX_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOMBSTONES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowError(pub &'static str);
impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for WorkflowError {}
pub type Result<T> = std::result::Result<T, WorkflowError>;
fn io(_: std::io::Error) -> WorkflowError {
    WorkflowError("workflow_storage_unavailable")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkflowPolicy {
    pub max_workflows: usize,
    pub max_steps: usize,
    pub max_parallel_per_workflow: usize,
    pub max_active_steps: usize,
    pub poll_interval_ms: u64,
}
impl Default for WorkflowPolicy {
    fn default() -> Self {
        Self {
            max_workflows: 128,
            max_steps: 128,
            max_parallel_per_workflow: 16,
            max_active_steps: 32,
            poll_interval_ms: 1000,
        }
    }
}
impl WorkflowPolicy {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1024).contains(&self.max_workflows)
            || !(1..=128).contains(&self.max_steps)
            || !(1..=128).contains(&self.max_parallel_per_workflow)
            || !(1..=128).contains(&self.max_active_steps)
            || !(250..=60_000).contains(&self.poll_interval_ms)
        {
            return Err(WorkflowError("invalid_workflow_policy"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobTemplate {
    pub repository: String,
    pub revision: String,
    pub runner: String,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub prompt: Option<String>,
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub priority: i16,
}
impl JobTemplate {
    fn validate(&self) -> Result<()> {
        if !wire::valid_name(&self.repository)
            || !wire::valid_name(&self.runner)
            || self.revision.is_empty()
            || self.revision.len() > 512
            || self.revision.contains('\0')
            || self.arguments.len() > 256
            || self
                .arguments
                .iter()
                .any(|argument| argument.contains('\0'))
            || self.arguments.iter().map(String::len).sum::<usize>() > 65_536
            || self
                .prompt
                .as_ref()
                .is_some_and(|prompt| prompt.len() > 65_536 || prompt.contains('\0'))
            || self.timeout_seconds == Some(0)
            || !scheduler::valid_priority(self.priority)
        {
            return Err(WorkflowError("invalid_workflow_job"));
        }
        Ok(())
    }
    fn spec(&self, id: String) -> Result<JobSpec> {
        let mut value = json!({"id":id,"repository":self.repository,"revision":self.revision,"runner":self.runner,
            "arguments":self.arguments,"prompt":self.prompt,"timeout_seconds":self.timeout_seconds});
        if self.priority != 0 {
            value["priority"] = json!(self.priority);
        }
        serde_json::from_value(value).map_err(|_| WorkflowError("invalid_workflow_job"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStep {
    pub key: String,
    #[serde(default)]
    pub needs: Vec<String>,
    #[serde(default)]
    pub placement: Placement,
    pub job: JobTemplate,
    #[serde(default = "default_true")]
    pub require_complete_patch: bool,
}
fn default_true() -> bool {
    true
}

/// References only: bytes are fetched explicitly with the normal verified artifact API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowInput {
    pub step: String,
    pub node_id: String,
    pub certificate_sha256: String,
    pub job_id: String,
    pub manifest_sha256: String,
    pub resolved_revision: String,
    pub image_digest: String,
    pub artifacts: BTreeMap<String, provenance::ArtifactDigest>,
}
impl WorkflowInput {
    pub fn validate(&self) -> Result<()> {
        if !wire::valid_name(&self.step)
            || !wire::valid_name(&self.node_id)
            || !wire::valid_ulid(&self.job_id)
            || !valid_hash(&self.certificate_sha256)
            || !valid_hash(&self.manifest_sha256)
            || !valid_image_digest(&self.image_digest)
            || !matches!(self.resolved_revision.len(), 40 | 64)
            || !self
                .resolved_revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.artifacts.len() > 2
            || self.artifacts.iter().any(|(name, artifact)| {
                !matches!(name.as_str(), "result.patch" | "output.log")
                    || !valid_hash(&artifact.sha256)
                    || artifact.size_bytes > 1024 * 1024 * 1024
                    || artifact.error_code.as_ref().is_some_and(|value| {
                        value.len() > 64
                            || !value
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    })
            })
        {
            return Err(WorkflowError("invalid_workflow_input_reference"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinition {
    pub version: u8,
    pub id: String,
    pub max_parallel: usize,
    pub steps: Vec<WorkflowStep>,
}
impl WorkflowDefinition {
    pub fn validate(&self, policy: &WorkflowPolicy) -> Result<()> {
        policy.validate()?;
        if self.version != 1
            || !wire::valid_ulid(&self.id)
            || self.steps.is_empty()
            || self.steps.len() > policy.max_steps
            || self.max_parallel == 0
            || self.max_parallel > policy.max_parallel_per_workflow
            || serde_json::to_vec(self)
                .map_err(|_| WorkflowError("invalid_workflow_definition"))?
                .len()
                > MAX_DEFINITION_BYTES
        {
            return Err(WorkflowError("invalid_workflow_definition"));
        }
        let keys: BTreeSet<_> = self.steps.iter().map(|step| step.key.as_str()).collect();
        if keys.len() != self.steps.len() {
            return Err(WorkflowError("duplicate_workflow_step"));
        }
        for step in &self.steps {
            if !wire::valid_name(&step.key)
                || step.needs.len() > policy.max_steps
                || step
                    .needs
                    .iter()
                    .any(|key| key == &step.key || !keys.contains(key.as_str()))
                || step.needs.iter().collect::<BTreeSet<_>>().len() != step.needs.len()
            {
                return Err(WorkflowError("invalid_workflow_dependency"));
            }
            step.placement.validate().map_err(WorkflowError)?;
            step.job.validate()?;
        }
        let mut complete = BTreeSet::new();
        loop {
            let before = complete.len();
            for step in &self.steps {
                if step.needs.iter().all(|need| complete.contains(need)) {
                    complete.insert(step.key.clone());
                }
            }
            if complete.len() == self.steps.len() {
                return Ok(());
            }
            if before == complete.len() {
                return Err(WorkflowError("cyclic_workflow_dependencies"));
            }
        }
    }
    pub fn hash(&self) -> Result<String> {
        Ok(provenance::sha256(&serde_json::to_vec(self).map_err(
            |_| WorkflowError("invalid_workflow_definition"),
        )?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pending,
    PreparingOwner,
    AwaitingOwner,
    ReadyToDispatch,
    Dispatching,
    Running,
    Uncertain,
    Blocked,
    Succeeded,
    Failed,
    Cancelled,
    Skipped,
}
impl StepState {
    fn active(self) -> bool {
        matches!(
            self,
            Self::Dispatching | Self::Running | Self::Uncertain | Self::Blocked
        )
    }
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Skipped
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerGate {
    #[serde(default)]
    pub external_spec: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_cloud_sha256: Option<String>,
    pub action: crate::approvals::ManagedAction,
    pub authorities: Vec<TrustedSigningKey>,
    pub image_reference: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementCheckpoint {
    pub node_id: String,
    pub certificate_sha256: String,
    pub result_key: TrustedSigningKey,
    pub image_digest: String,
    pub runner_configuration_sha256: String,
    pub spec: JobSpec,
    pub spec_sha256: String,
    pub resolved_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_gate: Option<OwnerGate>,
    #[serde(default = "default_true")]
    pub dispatch_committed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRecord {
    pub state: StepState,
    pub checkpoint: Option<PlacementCheckpoint>,
    pub result: Option<SignedDocument>,
    pub last_error: Option<String>,
    pub next_poll_ms: u64,
    pub poll_backoff_ms: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowState {
    Pending,
    AwaitingOwner,
    Running,
    Uncertain,
    Paused,
    Succeeded,
    Failed,
    Cancelled,
}
impl WorkflowState {
    fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowAbandonment {
    reviewed_at_ms: u64,
    review_sha256: String,
    reviewing_controller_certificate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowRecord {
    version: u8,
    workspace: String,
    controller_node: String,
    controller_certificate_sha256: String,
    definition: WorkflowDefinition,
    definition_sha256: String,
    steps: BTreeMap<String, StepRecord>,
    created_at_ms: u64,
    updated_at_ms: u64,
    content_ttl_seconds: u64,
    terminal_expires_at_ms: Option<u64>,
    cancel_requested: bool,
    paused_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    abandonment: Option<WorkflowAbandonment>,
}
impl WorkflowRecord {
    fn state(&self) -> WorkflowState {
        if self.paused_reason.is_some() {
            return WorkflowState::Paused;
        }
        if self.steps.values().all(|step| step.state.terminal()) {
            if self
                .steps
                .values()
                .any(|step| step.state == StepState::Failed || step.state == StepState::Skipped)
            {
                WorkflowState::Failed
            } else if self
                .steps
                .values()
                .any(|step| step.state == StepState::Cancelled)
            {
                WorkflowState::Cancelled
            } else {
                WorkflowState::Succeeded
            }
        } else if self
            .steps
            .values()
            .any(|step| matches!(step.state, StepState::Uncertain | StepState::Blocked))
        {
            WorkflowState::Uncertain
        } else if self.steps.values().any(|step| step.state.active()) {
            WorkflowState::Running
        } else if self.steps.values().any(|step| {
            matches!(
                step.state,
                StepState::AwaitingOwner | StepState::ReadyToDispatch
            )
        }) {
            WorkflowState::AwaitingOwner
        } else {
            WorkflowState::Pending
        }
    }
    fn validate(&self, policy: &WorkflowPolicy) -> Result<()> {
        self.definition.validate(policy)?;
        RetentionPolicy {
            content_ttl_seconds: self.content_ttl_seconds,
        }
        .validate()
        .map_err(|_| WorkflowError("invalid_workflow_retention"))?;
        if self.version != 1
            || !wire::valid_name(&self.workspace)
            || !wire::valid_name(&self.controller_node)
            || !valid_hash(&self.controller_certificate_sha256)
            || self.definition.hash()? != self.definition_sha256
            || self.created_at_ms > self.updated_at_ms
            || self.steps.len() != self.definition.steps.len()
            || (self.state().terminal() && self.terminal_expires_at_ms.is_none())
            || self.abandonment.as_ref().is_some_and(|review| {
                !self.state().terminal()
                    || !self.cancel_requested
                    || review.reviewed_at_ms != self.updated_at_ms
                    || !valid_hash(&review.review_sha256)
                    || !valid_hash(&review.reviewing_controller_certificate_sha256)
            })
            || self.terminal_expires_at_ms.is_some_and(|deadline| {
                !self.state().terminal()
                    || self
                        .updated_at_ms
                        .checked_add(self.content_ttl_seconds * 1000)
                        != Some(deadline)
            })
        {
            return Err(WorkflowError("invalid_workflow_journal"));
        }
        for definition in &self.definition.steps {
            let step = self
                .steps
                .get(&definition.key)
                .ok_or(WorkflowError("invalid_workflow_journal"))?;
            if matches!(
                step.state,
                StepState::Dispatching
                    | StepState::Running
                    | StepState::Uncertain
                    | StepState::PreparingOwner
                    | StepState::AwaitingOwner
                    | StepState::ReadyToDispatch
            ) && step.checkpoint.is_none()
                || step.state == StepState::Succeeded
                    && (step.result.is_none() || step.checkpoint.is_none())
            {
                return Err(WorkflowError("invalid_workflow_checkpoint"));
            }
            if let Some(checkpoint) = &step.checkpoint {
                let spec = step_spec(self, definition)?;
                if checkpoint.owner_gate.as_ref().is_some_and(|gate| {
                    (!gate.action.requires_owner()
                        && !gate.external_spec
                        && gate.repository_cloud_sha256.is_none())
                        || gate
                            .repository_cloud_sha256
                            .as_ref()
                            .is_some_and(|digest| !valid_hash(digest))
                        || gate.authorities.is_empty()
                        || gate.authorities.len() > 32
                        || gate.authorities.iter().any(|key| key.validate().is_err())
                        || crate::supply_chain::immutable_image_digest(&gate.image_reference)
                            .ok()
                            .as_deref()
                            != Some(checkpoint.image_digest.as_str())
                }) || matches!(
                    step.state,
                    StepState::PreparingOwner
                        | StepState::AwaitingOwner
                        | StepState::ReadyToDispatch
                ) && (checkpoint.owner_gate.is_none() || checkpoint.dispatch_committed)
                    || matches!(
                        step.state,
                        StepState::AwaitingOwner | StepState::ReadyToDispatch
                    ) && checkpoint.resolved_revision.is_none()
                    || step.state == StepState::ReadyToDispatch
                        && checkpoint.spec.owner_approval.is_none()
                    || matches!(
                        step.state,
                        StepState::Dispatching
                            | StepState::Running
                            | StepState::Uncertain
                            | StepState::Succeeded
                    ) && !checkpoint.dispatch_committed
                    || checkpoint.owner_gate.is_none() && checkpoint.spec.owner_approval.is_some()
                    || checkpoint.owner_gate.is_none() && !checkpoint.dispatch_committed
                    || checkpoint.owner_gate.is_some()
                        && checkpoint.dispatch_committed
                        && checkpoint.spec.owner_approval.is_none()
                    || checkpoint.spec != spec
                    || checkpoint.spec_sha256 != spec_hash(&spec)?
                    || !wire::valid_name(&checkpoint.node_id)
                    || !valid_hash(&checkpoint.certificate_sha256)
                    || checkpoint.result_key.validate().is_err()
                    || !valid_image_digest(&checkpoint.image_digest)
                    || !valid_hash(&checkpoint.runner_configuration_sha256)
                {
                    return Err(WorkflowError("invalid_workflow_checkpoint"));
                }
                if checkpoint.owner_gate.is_some()
                    && let Some(approval) = &checkpoint.spec.owner_approval
                {
                    owner_bundle(self, checkpoint)?
                        .verify_context(approval)
                        .map_err(|_| WorkflowError("invalid_workflow_owner_decision"))?;
                }
                if step.state.terminal() {
                    if step.result.is_none()
                        && ((step.state == StepState::Failed && self.abandonment.is_some())
                            || (!checkpoint.dispatch_committed
                                && matches!(
                                    step.state,
                                    StepState::Cancelled | StepState::Failed | StepState::Skipped
                                )))
                    {
                        continue;
                    }
                    let signed = step
                        .result
                        .as_ref()
                        .ok_or(WorkflowError("workflow_checkpoint_result_missing"))?;
                    let manifest = provenance::verify_result_identity(
                        signed,
                        &checkpoint.result_key,
                        &checkpoint.node_id,
                        &self.workspace,
                        &checkpoint.spec.id,
                    )
                    .map_err(|_| WorkflowError("workflow_checkpoint_signature_invalid"))?;
                    if manifest.request_sha256 != checkpoint.spec_sha256
                        || manifest.image_digest != checkpoint.image_digest
                        || Some(&manifest.resolved_revision)
                            != checkpoint.resolved_revision.as_ref()
                        || (step.state == StepState::Succeeded)
                            != (manifest.state == JobState::Succeeded)
                        || (step.state == StepState::Cancelled)
                            != (manifest.state == JobState::Cancelled)
                    {
                        return Err(WorkflowError("workflow_checkpoint_result_mismatch"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Local operator control only; workload delegation sockets reject these operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowControl {
    Submit {
        definition: WorkflowDefinition,
    },
    Status {
        id: String,
    },
    List {
        offset: usize,
        limit: usize,
    },
    Cancel {
        id: String,
    },
    Abandon {
        review: WorkflowAbandonRequest,
    },
    ApprovalRequest {
        id: String,
        step: String,
    },
    ApprovalAttach {
        id: String,
        step: String,
        definition_sha256: String,
        approval: SignedDocument,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowAbandonRequest {
    pub id: String,
    pub definition_sha256: String,
    pub controller_certificate_sha256: String,
    pub expected_local_certificate_sha256: String,
    pub confirm_no_active_execution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSummary {
    pub key: String,
    pub state: StepState,
    pub job_id: String,
    pub node_id: Option<String>,
    pub certificate_sha256: Option<String>,
    pub spec_sha256: Option<String>,
    pub dispatch_committed: bool,
    pub resolved_revision: Option<String>,
    pub image_digest: Option<String>,
    pub last_error: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSummary {
    pub id: String,
    pub definition_sha256: String,
    pub controller_certificate_sha256: String,
    pub abandoned: bool,
    pub state: WorkflowState,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub cancel_requested: bool,
    pub paused_reason: Option<String>,
    pub terminal_expires_at_ms: Option<u64>,
    pub steps: Vec<StepSummary>,
}
fn summary(record: &WorkflowRecord) -> Result<WorkflowSummary> {
    Ok(WorkflowSummary {
        id: record.definition.id.clone(),
        definition_sha256: record.definition_sha256.clone(),
        controller_certificate_sha256: record.controller_certificate_sha256.clone(),
        abandoned: record.abandonment.is_some(),
        state: record.state(),
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
        cancel_requested: record.cancel_requested,
        paused_reason: record.paused_reason.clone(),
        terminal_expires_at_ms: record.terminal_expires_at_ms,
        steps: record
            .steps
            .iter()
            .map(|(key, step)| {
                Ok(StepSummary {
                    key: key.clone(),
                    state: step.state,
                    job_id: step_job_id(&record.definition.id, key)?,
                    node_id: step.checkpoint.as_ref().map(|p| p.node_id.clone()),
                    certificate_sha256: step
                        .checkpoint
                        .as_ref()
                        .map(|p| p.certificate_sha256.clone()),
                    spec_sha256: step.checkpoint.as_ref().map(|p| p.spec_sha256.clone()),
                    dispatch_committed: step
                        .checkpoint
                        .as_ref()
                        .is_some_and(|p| p.dispatch_committed),
                    resolved_revision: step
                        .checkpoint
                        .as_ref()
                        .and_then(|p| p.resolved_revision.clone()),
                    image_digest: step.checkpoint.as_ref().map(|p| p.image_digest.clone()),
                    last_error: step.last_error.clone(),
                })
            })
            .collect::<Result<_>>()?,
    })
}

/// The host adapter uses authenticated, E2EE transport and rejects a changed certificate.
pub trait WorkflowDriver: Send + Sync {
    fn describe_nodes(&self) -> BoxFuture<'_, Result<Vec<NodeCapabilities>>>;
    fn rpc<'a>(
        &'a self,
        flow: &'a str,
        node: &'a str,
        certificate_sha256: &'a str,
        operation: Operation,
        payload: Value,
    ) -> BoxFuture<'a, Result<RpcReply<Value>>>;
}

pub struct WorkflowController {
    _lock: File,
    directory: PathBuf,
    policy: WorkflowPolicy,
    workspace: String,
    node_id: String,
    certificate_sha256: String,
    trust: BTreeMap<String, TrustedSigningKey>,
    retention: BTreeMap<String, RetentionPolicy>,
    records: Mutex<BTreeMap<String, WorkflowRecord>>,
    ticking: tokio::sync::Mutex<()>,
    storage_failed: AtomicBool,
    draining: AtomicBool,
    dispatch_cursor: Mutex<Option<String>>,
    materialization_cursor: AtomicUsize,
}
impl WorkflowController {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        state_dir: &Path,
        policy: WorkflowPolicy,
        workspace: String,
        node_id: String,
        certificate_sha256: String,
        trust: BTreeMap<String, TrustedSigningKey>,
        retention: BTreeMap<String, RetentionPolicy>,
        now_ms: u64,
    ) -> Result<Self> {
        policy.validate()?;
        if !wire::valid_name(&workspace)
            || !wire::valid_name(&node_id)
            || !valid_hash(&certificate_sha256)
            || trust.len() > 4096
            || trust
                .iter()
                .any(|(node, key)| !wire::valid_name(node) || key.validate().is_err())
            || retention
                .iter()
                .any(|(project, policy)| !wire::valid_name(project) || policy.validate().is_err())
        {
            return Err(WorkflowError("invalid_workflow_controller_context"));
        }
        let directory = state_dir.join("workflows");
        private_dir(&directory)?;
        private_dir(&directory.join("retired"))?;
        let lock = lock_controller(&directory)?;
        let mut records = BTreeMap::new();
        for entry in fs::read_dir(&directory).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| WorkflowError("invalid_workflow_storage"))?;
            if name == "retired" || name == ".lock" {
                continue;
            }
            if name.starts_with('.') && name.ends_with(".tmp") {
                fs::remove_file(entry.path()).map_err(io)?;
                continue;
            }
            if !wire::valid_ulid(&name) || records.len() >= policy.max_workflows {
                return Err(WorkflowError("invalid_workflow_storage"));
            }
            let mut record: WorkflowRecord =
                serde_json::from_slice(&read_private(&entry.path(), MAX_JOURNAL_BYTES)?)
                    .map_err(|_| WorkflowError("invalid_workflow_journal"))?;
            record.validate(&policy)?;
            if record.definition.id != name
                || record.workspace != workspace
                || record.controller_node != node_id
                || now_ms < record.updated_at_ms
            {
                return Err(WorkflowError("workflow_identity_or_clock_mismatch"));
            }
            if record.controller_certificate_sha256 != certificate_sha256
                && !record.state().terminal()
            {
                record.paused_reason = Some("controller_identity_changed".into());
            }
            for step in record.steps.values_mut() {
                if step.state == StepState::Dispatching {
                    step.state = StepState::Uncertain;
                    step.last_error = Some("controller_restarted_during_dispatch".into());
                }
            }
            records.insert(name, record);
        }
        let controller = Self {
            _lock: lock,
            directory,
            policy,
            workspace,
            node_id,
            certificate_sha256,
            trust,
            retention,
            records: Mutex::new(records),
            ticking: tokio::sync::Mutex::new(()),
            storage_failed: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            dispatch_cursor: Mutex::new(None),
            materialization_cursor: AtomicUsize::new(0),
        };
        {
            let records = controller
                .records
                .lock()
                .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
            for record in records.values() {
                controller.persist(record)?;
            }
        }
        controller.prune(now_ms)?;
        Ok(controller)
    }
    pub fn submit(&self, definition: WorkflowDefinition, now_ms: u64) -> Result<WorkflowSummary> {
        self.healthy()?;
        definition.validate(&self.policy)?;
        let hash = definition.hash()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        if let Some(record) = records.get(&definition.id) {
            if record.definition_sha256 != hash {
                return Err(WorkflowError("workflow_identifier_conflict"));
            }
            return summary(record);
        }
        if self.draining.load(Ordering::Acquire) {
            return Err(WorkflowError("workflow_controller_draining"));
        }
        let retired = self.directory.join("retired").join(&definition.id);
        if retired.exists() {
            return Err(WorkflowError("workflow_content_expired"));
        }
        if records.len() >= self.policy.max_workflows
            || fs::read_dir(self.directory.join("retired"))
                .map_err(io)?
                .take(MAX_TOMBSTONES)
                .count()
                >= MAX_TOMBSTONES
        {
            return Err(WorkflowError("workflow_capacity_reached"));
        }
        let mut ttl = u64::MAX;
        for step in &definition.steps {
            let policy = self
                .retention
                .get(&step.job.repository)
                .ok_or(WorkflowError("project_retention_required"))?;
            policy
                .validate()
                .map_err(|_| WorkflowError("invalid_workflow_retention"))?;
            ttl = ttl.min(policy.content_ttl_seconds);
        }
        let record = WorkflowRecord {
            version: 1,
            workspace: self.workspace.clone(),
            controller_node: self.node_id.clone(),
            controller_certificate_sha256: self.certificate_sha256.clone(),
            steps: definition
                .steps
                .iter()
                .map(|step| {
                    (
                        step.key.clone(),
                        StepRecord {
                            state: StepState::Pending,
                            checkpoint: None,
                            result: None,
                            last_error: None,
                            next_poll_ms: now_ms,
                            poll_backoff_ms: self.policy.poll_interval_ms,
                        },
                    )
                })
                .collect(),
            definition,
            definition_sha256: hash,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            content_ttl_seconds: ttl,
            terminal_expires_at_ms: None,
            cancel_requested: false,
            paused_reason: None,
            abandonment: None,
        };
        self.persist(&record)?;
        let result = summary(&record)?;
        records.insert(record.definition.id.clone(), record);
        Ok(result)
    }
    pub fn status(&self, id: &str) -> Result<WorkflowSummary> {
        if !wire::valid_ulid(id) {
            return Err(WorkflowError("invalid_workflow_id"));
        }
        let records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let record = records.get(id).ok_or(WorkflowError(
            if self.directory.join("retired").join(id).exists() {
                "workflow_content_expired"
            } else {
                "workflow_not_found"
            },
        ))?;
        summary(record)
    }
    pub fn list_page(&self, offset: usize, limit: usize) -> Result<Value> {
        if !(1..=100).contains(&limit) {
            return Err(WorkflowError("workflow_list_limit_must_be_1_to_100"));
        }
        let records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        if offset > records.len() {
            return Err(WorkflowError("workflow_list_offset_exceeds_count"));
        }
        let items:Vec<_>=records.values().skip(offset).take(limit).map(|record|json!({
            "id":record.definition.id,"definition_sha256":record.definition_sha256,"state":record.state(),
            "created_at_ms":record.created_at_ms,"updated_at_ms":record.updated_at_ms,"cancel_requested":record.cancel_requested,
            "paused_reason":record.paused_reason,"abandoned":record.abandonment.is_some(),"steps":record.steps.len(),
            "active_steps":record.steps.values().filter(|step|step.state.active()&&step.checkpoint.is_some()).count(),
            "awaiting_owner":record.steps.values().filter(|step|step.state==StepState::AwaitingOwner).count(),
            "terminal_expires_at_ms":record.terminal_expires_at_ms})).collect();
        let next = offset + items.len();
        Ok(
            json!({"total":records.len(),"offset":offset,"items":items,"next_offset":(next<records.len()).then_some(next)}),
        )
    }
    pub fn list(&self) -> Result<Vec<WorkflowSummary>> {
        let records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        records.values().map(summary).collect()
    }
    pub fn cancel(&self, id: &str, now_ms: u64) -> Result<WorkflowSummary> {
        self.healthy()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let original = records.get(id).ok_or(WorkflowError("workflow_not_found"))?;
        let mut record = original.clone();
        if record.state().terminal() {
            return summary(&record);
        }
        if now_ms < record.updated_at_ms {
            return Err(WorkflowError("workflow_clock_rollback"));
        }
        record.cancel_requested = true;
        for step in record.steps.values_mut() {
            if step.state == StepState::Pending
                || step
                    .checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| !checkpoint.dispatch_committed)
                || step.state == StepState::Blocked && step.checkpoint.is_none()
            {
                step.state = StepState::Cancelled;
            }
        }
        finish(&mut record, now_ms)?;
        self.persist(&record)?;
        let result = summary(&record)?;
        records.insert(id.into(), record);
        Ok(result)
    }
    pub fn approval_request(
        &self,
        id: &str,
        key: &str,
    ) -> Result<crate::approvals::MaterializedApproval> {
        let records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let record = records.get(id).ok_or(WorkflowError("workflow_not_found"))?;
        let step = record
            .steps
            .get(key)
            .ok_or(WorkflowError("workflow_step_not_found"))?;
        if !matches!(
            step.state,
            StepState::AwaitingOwner | StepState::ReadyToDispatch
        ) {
            return Err(WorkflowError(
                "workflow_owner_request_not_materialized_or_already_dispatched",
            ));
        }
        owner_bundle(
            record,
            step.checkpoint
                .as_ref()
                .ok_or(WorkflowError("workflow_checkpoint_missing"))?,
        )
    }
    pub fn approval_attach(
        &self,
        id: &str,
        key: &str,
        definition_sha256: &str,
        approval: SignedDocument,
        now_ms: u64,
    ) -> Result<WorkflowSummary> {
        self.healthy()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let original = records.get(id).ok_or(WorkflowError("workflow_not_found"))?;
        if original.definition_sha256 != definition_sha256 {
            return Err(WorkflowError("workflow_identifier_conflict"));
        }
        let mut record = original.clone();
        let original_step = record
            .steps
            .get(key)
            .ok_or(WorkflowError("workflow_step_not_found"))?;
        if original_step
            .checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.spec.owner_approval.as_ref())
            == Some(&approval)
        {
            return summary(&record);
        }
        if record.cancel_requested
            || record.paused_reason.is_some()
            || original_step.state != StepState::AwaitingOwner
        {
            return Err(WorkflowError("workflow_owner_approval_not_waiting"));
        }
        let checkpoint = original_step
            .checkpoint
            .as_ref()
            .ok_or(WorkflowError("workflow_checkpoint_missing"))?;
        if checkpoint.dispatch_committed {
            return Err(WorkflowError("workflow_owner_approval_already_consumed"));
        }
        owner_bundle(&record, checkpoint)?
            .verify(&approval, now_ms)
            .map_err(|error| WorkflowError(error.0))?;
        let step = record.steps.get_mut(key).unwrap();
        let checkpoint = step.checkpoint.as_mut().unwrap();
        checkpoint.spec.owner_approval = Some(approval);
        checkpoint.spec_sha256 = spec_hash(&checkpoint.spec)?;
        if serde_json::to_vec(&checkpoint.spec)
            .map_err(|_| WorkflowError("invalid_workflow_job"))?
            .len()
            > MAX_DEFINITION_BYTES
        {
            return Err(WorkflowError("approved_workflow_job_too_large"));
        }
        step.state = StepState::ReadyToDispatch;
        step.last_error = None;
        finish(&mut record, now_ms)?;
        self.persist(&record)?;
        let result = summary(&record)?;
        records.insert(id.into(), record);
        Ok(result)
    }

    /// Local maintenance only. The Host checks local processes and each original
    /// outbound receipt while this round barrier prevents any new workflow sends.
    pub(crate) async fn abandon<F>(
        &self,
        review: WorkflowAbandonRequest,
        now_ms: u64,
        check: F,
    ) -> Result<WorkflowSummary>
    where
        F: FnOnce(WorkflowSummary) -> BoxFuture<'static, Result<()>>,
    {
        let started = std::time::Instant::now();
        let _round = self.ticking.lock().await;
        self.healthy()?;
        if !self.draining.load(Ordering::Acquire) {
            return Err(WorkflowError("workflow_abandon_requires_drain"));
        }
        if !review.confirm_no_active_execution
            || !wire::valid_ulid(&review.id)
            || !valid_hash(&review.definition_sha256)
            || !valid_hash(&review.controller_certificate_sha256)
            || !valid_hash(&review.expected_local_certificate_sha256)
        {
            return Err(WorkflowError(
                "workflow_abandon_requires_exact_identity_and_stopped_execution_confirmation",
            ));
        }
        let current = self.status(&review.id)?;
        if current.definition_sha256 != review.definition_sha256
            || current.controller_certificate_sha256 != review.controller_certificate_sha256
            || review.expected_local_certificate_sha256 != self.certificate_sha256
        {
            return Err(WorkflowError("workflow_abandon_identity_mismatch"));
        }
        if current.state.terminal() {
            return Ok(current);
        }
        check(current).await?;
        let now_ms = now_ms
            .saturating_add(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64)
            .saturating_add(1);
        if !self.draining.load(Ordering::Acquire) {
            return Err(WorkflowError("workflow_abandon_requires_drain"));
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let original = records
            .get(&review.id)
            .ok_or(WorkflowError("workflow_not_found"))?;
        let mut record = original.clone();
        if record.state().terminal() {
            return summary(&record);
        }
        if now_ms < record.updated_at_ms {
            return Err(WorkflowError("workflow_clock_rollback"));
        }
        let review_bytes=serde_json::to_vec(&json!({"domain":"lockyard-workflow-abandon-v1","review":&review,"reviewed_at_ms":now_ms}))
            .map_err(|_|WorkflowError("invalid_workflow_abandon_review"))?;
        for step in record.steps.values_mut() {
            if step.state.terminal() {
                continue;
            }
            step.state = if step.checkpoint.is_some() {
                StepState::Failed
            } else {
                StepState::Skipped
            };
            step.last_error = Some("operator_abandoned_after_independent_stop_review".into());
        }
        record.cancel_requested = true;
        record.paused_reason = None;
        record.abandonment = Some(WorkflowAbandonment {
            reviewed_at_ms: now_ms,
            review_sha256: provenance::sha256(&review_bytes),
            reviewing_controller_certificate_sha256: review.expected_local_certificate_sha256,
        });
        finish(&mut record, now_ms)?;
        self.persist(&record)?;
        let result = summary(&record)?;
        records.insert(record.definition.id.clone(), record);
        Ok(result)
    }

    fn persist(&self, record: &WorkflowRecord) -> Result<()> {
        record.validate(&self.policy)?;
        let bytes =
            serde_json::to_vec(record).map_err(|_| WorkflowError("invalid_workflow_journal"))?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(WorkflowError("workflow_journal_too_large"));
        }
        let result = atomic_write(&self.directory, &record.definition.id, &bytes);
        if result.is_err() {
            self.storage_failed.store(true, Ordering::SeqCst);
        }
        result
    }
    fn healthy(&self) -> Result<()> {
        if self.storage_failed.load(Ordering::SeqCst) {
            Err(WorkflowError("workflow_storage_failed_restart_required"))
        } else {
            Ok(())
        }
    }
    pub fn is_healthy(&self) -> bool {
        !self.storage_failed.load(Ordering::SeqCst)
    }
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }
    pub fn resume_dispatch(&self) {
        self.draining.store(false, Ordering::Release);
    }
    pub fn active_steps(&self) -> Result<usize> {
        let records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        Ok(records
            .values()
            .flat_map(|record| record.steps.values())
            .filter(|step| step.state.active() && step.checkpoint.is_some())
            .count())
    }
    pub fn prune(&self, now_ms: u64) -> Result<()> {
        let result = self.prune_inner(now_ms);
        if result.is_err() {
            self.storage_failed.store(true, Ordering::SeqCst);
        }
        result
    }
    fn prune_inner(&self, now_ms: u64) -> Result<()> {
        self.healthy()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let expired: Vec<_> = records
            .iter()
            .filter(|(_, record)| {
                record.state().terminal()
                    && record
                        .terminal_expires_at_ms
                        .is_some_and(|deadline| now_ms >= deadline)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            let record = &records[&id];
            let tombstone = json!({"version":1,"id":id,"definition_sha256":record.definition_sha256,"state":record.state(),"expired_at_ms":record.terminal_expires_at_ms,
                "abandoned":record.abandonment.is_some(),"abandon_review_sha256":record.abandonment.as_ref().map(|review|&review.review_sha256)});
            let retired = self.directory.join("retired");
            if fs::read_dir(&retired)
                .map_err(io)?
                .take(MAX_TOMBSTONES)
                .count()
                >= MAX_TOMBSTONES
            {
                return Err(WorkflowError("workflow_tombstone_capacity_reached"));
            }
            atomic_write(
                &retired,
                &id,
                &serde_json::to_vec(&tombstone)
                    .map_err(|_| WorkflowError("invalid_workflow_tombstone"))?,
            )?;
            fs::remove_file(self.directory.join(&id)).map_err(io)?;
            lockyard_core::fsio::sync_path(&self.directory).map_err(io)?;
            records.remove(&id);
        }
        Ok(())
    }

    /// One bounded reconciliation round. Startup converts incomplete dispatch to read-only
    /// uncertainty; no code path automatically submits it again or selects another node.
    pub async fn tick(&self, driver: &dyn WorkflowDriver, now_ms: u64) -> Result<()> {
        let _round = self.ticking.lock().await;
        let started = std::time::Instant::now();
        self.healthy()?;
        self.prune(now_ms)?;
        let actions = {
            let records = self
                .records
                .lock()
                .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
            let mut actions = Vec::new();
            for (id, record) in records.iter() {
                if record.paused_reason.is_some() || record.state().terminal() {
                    continue;
                }
                if now_ms < record.updated_at_ms {
                    return Err(WorkflowError("workflow_clock_rollback"));
                }
                for (key, step) in &record.steps {
                    if !step.state.active() || step.next_poll_ms > now_ms {
                        continue;
                    }
                    if let Some(checkpoint) = &step.checkpoint {
                        actions.push(Action {
                            flow: id.clone(),
                            step: key.clone(),
                            checkpoint: checkpoint.clone(),
                            kind: if record.cancel_requested {
                                ActionKind::Cancel
                            } else {
                                ActionKind::Status
                            },
                        });
                    }
                }
            }
            let preparations: Vec<_> = records
                .iter()
                .filter(|(_, record)| {
                    record.paused_reason.is_none()
                        && !record.cancel_requested
                        && !record.state().terminal()
                })
                .flat_map(|(id, record)| {
                    record
                        .steps
                        .iter()
                        .filter(move |(_, step)| {
                            step.state == StepState::PreparingOwner && step.next_poll_ms <= now_ms
                        })
                        .map(move |(key, step)| (id, key, step))
                })
                .collect();
            if !preparations.is_empty() {
                let count = preparations.len();
                let limit = count.min(self.policy.max_active_steps);
                let start = self
                    .materialization_cursor
                    .fetch_add(limit, Ordering::Relaxed)
                    % count;
                for (id, key, step) in preparations.iter().cycle().skip(start).take(limit) {
                    if let Some(checkpoint) = &step.checkpoint {
                        actions.push(Action {
                            flow: (*id).clone(),
                            step: (*key).clone(),
                            checkpoint: checkpoint.clone(),
                            kind: ActionKind::Materialize,
                        });
                    }
                }
            }
            actions
        };
        self.perform(driver, actions, now_ms).await?;
        self.healthy()?;
        let (has_pending, needs_placement) = {
            let records = self
                .records
                .lock()
                .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
            let active = records
                .values()
                .flat_map(|record| record.steps.values())
                .filter(|step| step.state.active() && step.checkpoint.is_some())
                .count();
            let has_pending = records.values().any(|record| {
                record.paused_reason.is_none()
                    && !record.cancel_requested
                    && record.steps.values().any(|step| {
                        matches!(step.state, StepState::Pending | StepState::ReadyToDispatch)
                    })
            });
            let ready = active < self.policy.max_active_steps
                && records.values().any(|record| {
                    record.paused_reason.is_none()
                        && !record.cancel_requested
                        && record
                            .steps
                            .values()
                            .filter(|step| step.state.active() && step.checkpoint.is_some())
                            .count()
                            < record.definition.max_parallel
                        && record.definition.steps.iter().any(|definition| {
                            record.steps[&definition.key].state == StepState::Pending
                                && definition
                                    .needs
                                    .iter()
                                    .all(|need| record.steps[need].state == StepState::Succeeded)
                        })
                });
            (has_pending, ready)
        };
        if !has_pending {
            return Ok(());
        }
        let nodes = if needs_placement {
            driver.describe_nodes().await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let now_ms =
            now_ms.saturating_add(started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        let actions = self.prepare_submissions(&nodes, now_ms)?;
        self.perform(driver, actions, now_ms).await
    }

    pub async fn run(self: Arc<Self>, driver: Arc<dyn WorkflowDriver>) {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
                .unwrap_or(0);
            let _ = self.tick(driver.as_ref(), now).await;
            tokio::time::sleep(std::time::Duration::from_millis(
                self.policy.poll_interval_ms,
            ))
            .await;
        }
    }

    fn prepare_submissions(&self, nodes: &[NodeCapabilities], now_ms: u64) -> Result<Vec<Action>> {
        self.healthy()?;
        if self.draining.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let mut global = records
            .values()
            .flat_map(|record| record.steps.values())
            .filter(|step| step.state.active() && step.checkpoint.is_some())
            .count();
        let mut actions = Vec::new();
        let mut nodes: Vec<_> = nodes
            .iter()
            .filter(|node| self.trust.contains_key(&node.node_id))
            .cloned()
            .collect();
        // Round-robin one ready step per workflow per pass, ordered by workflow admission.
        let mut order: Vec<_> = records
            .iter()
            .map(|(id, record)| (record.created_at_ms, id.clone()))
            .collect();
        order.sort_unstable();
        let mut cursor = self
            .dispatch_cursor
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        if let Some(previous) = cursor.as_ref()
            && let Some(index) = order.iter().position(|(_, id)| id == previous)
        {
            let count = order.len();
            order.rotate_left((index + 1) % count);
        }
        loop {
            let mut progressed = false;
            for (_, id) in &order {
                let original = &records[id];
                if original.paused_reason.is_some()
                    || original.cancel_requested
                    || original.state().terminal()
                {
                    continue;
                }
                if now_ms < original.updated_at_ms {
                    return Err(WorkflowError("workflow_clock_rollback"));
                }
                let mut record = original.clone();
                let active = record
                    .steps
                    .values()
                    .filter(|step| step.state.active() && step.checkpoint.is_some())
                    .count();
                let mut changed = false;
                let mut chosen = None;
                for definition in &record.definition.steps {
                    if record.steps[&definition.key].state == StepState::ReadyToDispatch {
                        if active >= record.definition.max_parallel
                            || global >= self.policy.max_active_steps
                        {
                            break;
                        }
                        let checkpoint = record.steps[&definition.key].checkpoint.as_ref().unwrap();
                        if self.trust.get(&checkpoint.node_id) != Some(&checkpoint.result_key) {
                            record.paused_reason = Some("result_signing_trust_changed".into());
                            changed = true;
                            break;
                        }
                        let verified = owner_bundle(&record, checkpoint).and_then(|bundle| {
                            bundle
                                .verify(checkpoint.spec.owner_approval.as_ref().unwrap(), now_ms)
                                .map_err(|error| WorkflowError(error.0))
                        });
                        let step = record.steps.get_mut(&definition.key).unwrap();
                        if let Err(error) = verified {
                            step.state = StepState::AwaitingOwner;
                            step.last_error = Some(error.0.into());
                            changed = true;
                            continue;
                        }
                        let checkpoint = step.checkpoint.as_mut().unwrap();
                        checkpoint.dispatch_committed = true;
                        step.state = StepState::Dispatching;
                        step.next_poll_ms = now_ms;
                        step.last_error = None;
                        chosen = Some(Action {
                            flow: id.clone(),
                            step: definition.key.clone(),
                            checkpoint: checkpoint.clone(),
                            kind: ActionKind::Submit,
                        });
                        changed = true;
                        break;
                    }
                    if record.steps[&definition.key].state != StepState::Pending {
                        continue;
                    }
                    if definition.needs.iter().any(|need| {
                        matches!(
                            record.steps[need].state,
                            StepState::Failed | StepState::Cancelled | StepState::Skipped
                        )
                    }) {
                        let step = record.steps.get_mut(&definition.key).unwrap();
                        step.state = StepState::Skipped;
                        step.last_error = Some("predecessor_did_not_succeed".into());
                        changed = true;
                        continue;
                    }
                    if !definition
                        .needs
                        .iter()
                        .all(|need| record.steps[need].state == StepState::Succeeded)
                    {
                        continue;
                    }
                    if active >= record.definition.max_parallel
                        || global >= self.policy.max_active_steps
                    {
                        break;
                    }
                    let inputs = match input_context(&record, definition) {
                        Ok(inputs) => inputs,
                        Err(error) => {
                            let step = record.steps.get_mut(&definition.key).unwrap();
                            step.state = StepState::Blocked;
                            step.last_error = Some(error.0.into());
                            changed = true;
                            continue;
                        }
                    };
                    if definition.needs.iter().any(|need| {
                        record.steps[need]
                            .checkpoint
                            .as_ref()
                            .is_none_or(|checkpoint| {
                                self.trust.get(&checkpoint.node_id) != Some(&checkpoint.result_key)
                            })
                    }) {
                        record.paused_reason = Some("predecessor_signing_trust_changed".into());
                        changed = true;
                        break;
                    }
                    let node = match scheduler::select_node(
                        &nodes,
                        &definition.placement,
                        &definition.job.repository,
                        &definition.job.runner,
                    ) {
                        Ok(node) => node,
                        Err(_) => {
                            let step = record.steps.get_mut(&definition.key).unwrap();
                            if step.last_error.as_deref() != Some("no_compatible_node") {
                                step.last_error = Some("no_compatible_node".into());
                                changed = true;
                            }
                            continue;
                        }
                    };
                    let Some(result_key) = self.trust.get(&node.node_id) else {
                        continue;
                    };
                    let mut spec = definition
                        .job
                        .spec(step_job_id(&record.definition.id, &definition.key)?)?;
                    if !inputs.is_empty() {
                        let mut value = serde_json::to_value(&spec)
                            .map_err(|_| WorkflowError("invalid_workflow_job"))?;
                        value["workflow_inputs"] = serde_json::to_value(inputs)
                            .map_err(|_| WorkflowError("invalid_workflow_inputs"))?;
                        spec = serde_json::from_value(value)
                            .map_err(|_| WorkflowError("workflow_inputs_unsupported"))?;
                    }
                    let mut value = serde_json::to_value(&spec)
                        .map_err(|_| WorkflowError("invalid_workflow_job"))?;
                    value["expected_runner_sha256"] =
                        json!(node.runners[&definition.job.runner].configuration_sha256);
                    spec = serde_json::from_value(value)
                        .map_err(|_| WorkflowError("runner_configuration_binding_unsupported"))?;
                    if serde_json::to_vec(&spec)
                        .map_err(|_| WorkflowError("invalid_workflow_job"))?
                        .len()
                        > MAX_DEFINITION_BYTES
                    {
                        let step = record.steps.get_mut(&definition.key).unwrap();
                        step.state = StepState::Failed;
                        step.last_error = Some("workflow_inputs_too_large".into());
                        changed = true;
                        continue;
                    }
                    let checkpoint = PlacementCheckpoint {
                        node_id: node.node_id.clone(),
                        certificate_sha256: node.certificate_sha256.clone(),
                        result_key: result_key.clone(),
                        image_digest: node.runners[&definition.job.runner].image_digest.clone(),
                        runner_configuration_sha256: node.runners[&definition.job.runner]
                            .configuration_sha256
                            .clone(),
                        spec_sha256: spec_hash(&spec)?,
                        spec,
                        resolved_revision: None,
                        owner_gate: node
                            .requires_owner_approval(
                                &definition.job.repository,
                                &definition.job.runner,
                            )
                            .then(|| OwnerGate {
                                external_spec: node.runners[&definition.job.runner]
                                    .external_approval_required,
                                repository_cloud_sha256: node
                                    .repository_cloud_sha256
                                    .get(&definition.job.repository)
                                    .cloned(),
                                action: node.runners[&definition.job.runner].action,
                                authorities: node.runners[&definition.job.runner]
                                    .owner_approval_authorities
                                    .clone(),
                                image_reference: node.runners[&definition.job.runner]
                                    .image_reference
                                    .clone(),
                            }),
                        dispatch_committed: !node.requires_owner_approval(
                            &definition.job.repository,
                            &definition.job.runner,
                        ),
                    };
                    let step = record.steps.get_mut(&definition.key).unwrap();
                    step.state = if checkpoint.owner_gate.is_some() {
                        StepState::PreparingOwner
                    } else {
                        StepState::Dispatching
                    };
                    step.checkpoint = Some(checkpoint.clone());
                    step.last_error = None;
                    step.next_poll_ms = now_ms;
                    changed = true;
                    chosen = Some(Action {
                        flow: id.clone(),
                        step: definition.key.clone(),
                        kind: if checkpoint.owner_gate.is_some() {
                            ActionKind::Materialize
                        } else {
                            ActionKind::Submit
                        },
                        checkpoint,
                    });
                    break;
                }
                if changed {
                    finish(&mut record, now_ms)?;
                    self.persist(&record)?;
                    records.insert(id.clone(), record);
                    progressed = true;
                }
                if let Some(action) = chosen {
                    // Include durable placements made in this batch in subsequent load
                    // choices, before any network replies can update discovery.
                    if let Some(node) = nodes
                        .iter_mut()
                        .find(|node| node.node_id == action.checkpoint.node_id)
                    {
                        node.queued = node.queued.saturating_add(1);
                    }
                    actions.push(action);
                    global += 1;
                    *cursor = Some(id.clone());
                    progressed = true;
                }
            }
            if !progressed || global >= self.policy.max_active_steps {
                break;
            }
        }
        Ok(actions)
    }

    async fn perform(
        &self,
        driver: &dyn WorkflowDriver,
        actions: Vec<Action>,
        now_ms: u64,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let mut pending = FuturesUnordered::new();
        for action in actions {
            pending.push(async move {
                let operation = match action.kind {
                    ActionKind::Submit => Operation::JobSubmit,
                    ActionKind::Materialize => Operation::NodePing,
                    ActionKind::Status => Operation::JobStatus,
                    ActionKind::Cancel => Operation::JobCancel,
                };
                let payload = match action.kind {
                    ActionKind::Submit => serde_json::to_value(&action.checkpoint.spec)
                        .map_err(|_| WorkflowError("invalid_workflow_job")),
                    ActionKind::Materialize=>Ok(json!({"resolve":{"repository":action.checkpoint.spec.repository,
                        "revision":action.checkpoint.spec.revision,"runner":action.checkpoint.spec.runner}})),
                    _ => Ok(json!({"job_id":action.checkpoint.spec.id})),
                };
                let result = match payload {
                    Ok(payload) => {
                        driver
                            .rpc(
                                &action.flow,
                                &action.checkpoint.node_id,
                                &action.checkpoint.certificate_sha256,
                                operation,
                                payload,
                            )
                            .await
                    }
                    Err(error) => Err(error),
                };
                (
                    action,
                    result,
                    now_ms.saturating_add(
                        started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
                    ),
                )
            });
        }
        while let Some((action, result, observed_at_ms)) = pending.next().await {
            self.observe(action, result, observed_at_ms)?;
        }
        Ok(())
    }

    fn observe(&self, action: Action, result: Result<RpcReply<Value>>, now_ms: u64) -> Result<()> {
        if matches!(action.kind, ActionKind::Materialize) {
            return self.observe_materialization(action, result, now_ms);
        }
        self.healthy()?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let mut record = records
            .get(&action.flow)
            .ok_or(WorkflowError("workflow_not_found"))?
            .clone();
        // A concurrent explicit cancellation can advance the same journal while RPC is in flight.
        let now_ms = now_ms.max(record.updated_at_ms);
        let old = record
            .steps
            .get(&action.step)
            .ok_or(WorkflowError("workflow_step_not_found"))?
            .clone();
        if old.checkpoint.as_ref() != Some(&action.checkpoint) || !old.state.active() {
            return Ok(());
        }
        let step = record.steps.get_mut(&action.step).unwrap();
        let observed = result
            .and_then(|reply| {
                if reply.ok {
                    reply
                        .result
                        .ok_or(WorkflowError("invalid_workflow_job_response"))
                } else {
                    Err(WorkflowError("remote_job_rejected_or_unknown"))
                }
            })
            .and_then(|value| {
                serde_json::from_value::<JobRecord>(value)
                    .map_err(|_| WorkflowError("invalid_workflow_job_response"))
            });
        match observed {
            Err(error) => {
                if matches!(action.kind, ActionKind::Submit) {
                    step.state = StepState::Uncertain;
                }
                step.last_error = Some(error.0.into());
                step.poll_backoff_ms = step.poll_backoff_ms.saturating_mul(2).min(30_000);
            }
            Ok(job) => {
                if job.spec != action.checkpoint.spec
                    || job.submitter != record.controller_node
                    || job
                        .submitter_certificate_sha256
                        .as_ref()
                        .is_some_and(|pin| pin != &record.controller_certificate_sha256)
                    || (action.checkpoint.node_id != record.controller_node
                        && job.submitter_certificate_sha256.is_none())
                    || spec_hash(&job.spec)? != action.checkpoint.spec_sha256
                    || job.resolved_revision.is_none()
                    || action
                        .checkpoint
                        .resolved_revision
                        .as_ref()
                        .is_some_and(|revision| Some(revision) != job.resolved_revision.as_ref())
                {
                    step.state = StepState::Blocked;
                    step.last_error = Some("result_request_context_mismatch".into());
                    step.poll_backoff_ms = 30_000;
                } else {
                    step.checkpoint.as_mut().unwrap().resolved_revision =
                        job.resolved_revision.clone();
                    if job.state == JobState::InterruptedUnknown {
                        step.state = StepState::Uncertain;
                        step.last_error = Some("execution_outcome_unknown".into());
                        step.poll_backoff_ms = 30_000;
                    } else if job.state.is_terminal() {
                        if let Some(signed) = job.result_manifest.as_ref() {
                            let checkpoint = step.checkpoint.as_ref().unwrap();
                            let verified = self.verify_result(checkpoint, &job, signed);
                            match verified {
                                Ok(manifest) => {
                                    step.state = match manifest.state {
                                        JobState::Succeeded => StepState::Succeeded,
                                        JobState::Cancelled => StepState::Cancelled,
                                        _ => StepState::Failed,
                                    };
                                    step.result = Some(signed.clone());
                                    step.last_error = None;
                                }
                                Err(error) => {
                                    step.state = StepState::Blocked;
                                    step.last_error = Some(error.0.into());
                                    step.poll_backoff_ms = 30_000;
                                }
                            }
                        } else {
                            step.state = StepState::Running;
                            step.last_error = Some(
                                if job.provenance_error.is_some() {
                                    "result_signing_failed"
                                } else {
                                    "result_signature_pending"
                                }
                                .into(),
                            );
                        }
                    } else {
                        step.state = StepState::Running;
                        step.last_error = None;
                        step.poll_backoff_ms = self.policy.poll_interval_ms;
                    }
                }
            }
        }
        step.next_poll_ms = now_ms.saturating_add(step.poll_backoff_ms);
        let changed = old.state != step.state
            || old.checkpoint != step.checkpoint
            || old.result != step.result
            || old.last_error != step.last_error;
        if changed {
            finish(&mut record, now_ms)?;
            self.persist(&record)?;
        }
        records.insert(action.flow, record);
        Ok(())
    }
    fn observe_materialization(
        &self,
        action: Action,
        result: Result<RpcReply<Value>>,
        now_ms: u64,
    ) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowError("workflow_state_unavailable"))?;
        let original = records
            .get(&action.flow)
            .ok_or(WorkflowError("workflow_not_found"))?;
        let mut record = original.clone();
        let now_ms = now_ms.max(record.updated_at_ms);
        let step = record
            .steps
            .get_mut(&action.step)
            .ok_or(WorkflowError("workflow_step_not_found"))?;
        if step.state != StepState::PreparingOwner
            || step.checkpoint.as_ref() != Some(&action.checkpoint)
        {
            return Ok(());
        }
        let observed = result
            .and_then(|reply| {
                if reply.ok {
                    reply
                        .result
                        .ok_or(WorkflowError("workflow_revision_unavailable"))
                } else {
                    Err(WorkflowError("workflow_revision_unavailable"))
                }
            })
            .and_then(|value| {
                serde_json::from_value::<crate::scheduler::RevisionCapability>(value)
                    .map_err(|_| WorkflowError("invalid_workflow_revision_response"))
            });
        match observed {
            Ok(revision) => {
                let gate = action
                    .checkpoint
                    .owner_gate
                    .as_ref()
                    .ok_or(WorkflowError("workflow_owner_gate_missing"))?;
                if revision.node_id != action.checkpoint.node_id
                    || revision.certificate_sha256 != action.checkpoint.certificate_sha256
                    || revision.repository != action.checkpoint.spec.repository
                    || revision.runner != action.checkpoint.spec.runner
                    || revision.requested_revision != action.checkpoint.spec.revision
                    || revision.profile.configuration_sha256
                        != action.checkpoint.runner_configuration_sha256
                    || revision.profile.image_digest != action.checkpoint.image_digest
                    || revision.profile.image_reference != gate.image_reference
                    || revision.profile.action != gate.action
                    || revision.profile.external_approval_required != gate.external_spec
                    || revision.repository_cloud_sha256 != gate.repository_cloud_sha256
                    || revision.profile.owner_approval_authorities != gate.authorities
                    || ![40, 64].contains(&revision.resolved_revision.len())
                    || !revision
                        .resolved_revision
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    step.state = StepState::Blocked;
                    step.last_error = Some("workflow_revision_or_profile_context_changed".into());
                } else {
                    let checkpoint = step.checkpoint.as_mut().unwrap();
                    checkpoint.resolved_revision = Some(revision.resolved_revision.clone());
                    checkpoint.spec.revision = revision.resolved_revision;
                    checkpoint.spec_sha256 = spec_hash(&checkpoint.spec)?;
                    step.state = StepState::AwaitingOwner;
                    step.last_error = Some("owner_approval_required".into());
                }
            }
            Err(error) => {
                step.last_error = Some(error.0.into());
                step.poll_backoff_ms = step.poll_backoff_ms.saturating_mul(2).min(30_000);
            }
        }
        step.next_poll_ms = now_ms.saturating_add(step.poll_backoff_ms);
        finish(&mut record, now_ms)?;
        self.persist(&record)?;
        records.insert(action.flow, record);
        Ok(())
    }

    fn verify_result(
        &self,
        checkpoint: &PlacementCheckpoint,
        job: &JobRecord,
        signed: &SignedDocument,
    ) -> Result<ResultManifest> {
        if self.trust.get(&checkpoint.node_id) != Some(&checkpoint.result_key)
            || job.provenance_error.is_some()
        {
            return Err(WorkflowError("result_signing_trust_unavailable"));
        }
        let manifest = provenance::verify_result_identity(
            signed,
            &checkpoint.result_key,
            &checkpoint.node_id,
            &self.workspace,
            &checkpoint.spec.id,
        )
        .map_err(|_| WorkflowError("result_signature_invalid"))?;
        if manifest.request_sha256 != checkpoint.spec_sha256
            || manifest.repository != checkpoint.spec.repository
            || manifest.runner != checkpoint.spec.runner
            || manifest.image_digest != checkpoint.image_digest
            || Some(&manifest.resolved_revision) != checkpoint.resolved_revision.as_ref()
            || manifest.state != job.state
            || manifest.exit_code != job.exit_code
            || manifest.error_code != job.error_code
        {
            return Err(WorkflowError("signed_result_context_mismatch"));
        }
        Ok(manifest)
    }
}

#[derive(Clone, Copy)]
enum ActionKind {
    Submit,
    Materialize,
    Status,
    Cancel,
}
struct Action {
    flow: String,
    step: String,
    checkpoint: PlacementCheckpoint,
    kind: ActionKind,
}

fn input_context(record: &WorkflowRecord, definition: &WorkflowStep) -> Result<Vec<WorkflowInput>> {
    let mut inputs = Vec::new();
    for need in &definition.needs {
        let step = &record.steps[need];
        let checkpoint = step
            .checkpoint
            .as_ref()
            .ok_or(WorkflowError("predecessor_checkpoint_missing"))?;
        let signed = step
            .result
            .as_ref()
            .ok_or(WorkflowError("predecessor_result_missing"))?;
        let manifest = provenance::verify_result_identity(
            signed,
            &checkpoint.result_key,
            &checkpoint.node_id,
            &record.workspace,
            &checkpoint.spec.id,
        )
        .map_err(|_| WorkflowError("predecessor_signature_invalid"))?;
        if step.state != StepState::Succeeded
            || manifest.state != JobState::Succeeded
            || manifest.request_sha256 != checkpoint.spec_sha256
            || manifest.image_digest != checkpoint.image_digest
            || Some(&manifest.resolved_revision) != checkpoint.resolved_revision.as_ref()
        {
            return Err(WorkflowError("predecessor_context_invalid"));
        }
        if definition.require_complete_patch
            && manifest
                .artifacts
                .get("result.patch")
                .is_none_or(|patch| patch.truncated || patch.error_code.is_some())
        {
            return Err(WorkflowError("predecessor_patch_incomplete"));
        }
        inputs.push(WorkflowInput {
            step: need.clone(),
            node_id: checkpoint.node_id.clone(),
            certificate_sha256: checkpoint.certificate_sha256.clone(),
            job_id: checkpoint.spec.id.clone(),
            manifest_sha256: provenance::sha256(
                &serde_json::to_vec(signed)
                    .map_err(|_| WorkflowError("invalid_predecessor_result"))?,
            ),
            resolved_revision: manifest.resolved_revision,
            image_digest: manifest.image_digest,
            artifacts: manifest.artifacts,
        });
    }
    Ok(inputs)
}
fn owner_bundle(
    record: &WorkflowRecord,
    checkpoint: &PlacementCheckpoint,
) -> Result<crate::approvals::MaterializedApproval> {
    let gate = checkpoint
        .owner_gate
        .as_ref()
        .ok_or(WorkflowError("workflow_owner_approval_not_required"))?;
    let revision = checkpoint
        .resolved_revision
        .as_ref()
        .ok_or(WorkflowError("workflow_owner_request_not_materialized"))?;
    let mut spec = checkpoint.spec.clone();
    spec.owner_approval = None;
    Ok(crate::approvals::MaterializedApproval {
        external_spec: gate.external_spec,
        workspace: record.workspace.clone(),
        node_id: checkpoint.node_id.clone(),
        node_certificate_sha256: checkpoint.certificate_sha256.clone(),
        spec,
        resolved_revision: revision.clone(),
        runner_configuration_sha256: checkpoint.runner_configuration_sha256.clone(),
        repository_cloud_sha256: gate.repository_cloud_sha256.clone(),
        image_reference: gate.image_reference.clone(),
        image_digest: checkpoint.image_digest.clone(),
        action: gate.action,
        owner_approval_authorities: gate.authorities.clone(),
    })
}

fn step_spec(record: &WorkflowRecord, definition: &WorkflowStep) -> Result<JobSpec> {
    let spec = definition
        .job
        .spec(step_job_id(&record.definition.id, &definition.key)?)?;
    let inputs = input_context(record, definition)?;
    let mut value =
        serde_json::to_value(spec).map_err(|_| WorkflowError("invalid_workflow_job"))?;
    if !inputs.is_empty() {
        value["workflow_inputs"] =
            serde_json::to_value(inputs).map_err(|_| WorkflowError("invalid_workflow_inputs"))?;
    }
    if let Some(checkpoint) = record
        .steps
        .get(&definition.key)
        .and_then(|step| step.checkpoint.as_ref())
    {
        value["expected_runner_sha256"] = json!(checkpoint.runner_configuration_sha256);
        if checkpoint.owner_gate.is_some() {
            if let Some(revision) = &checkpoint.resolved_revision {
                value["revision"] = json!(revision);
            }
            if let Some(approval) = &checkpoint.spec.owner_approval {
                value["owner_approval"] = json!(approval);
            }
        }
    }
    serde_json::from_value(value).map_err(|_| WorkflowError("workflow_inputs_unsupported"))
}

/// Offline rotation boundary. The caller must also hold the node host lock, and
/// retain this lock through installation. This never opens an executor or launches work.
pub fn offline_rotation_guard(
    state_dir: &Path,
    policy: &WorkflowPolicy,
    workspace: &str,
    node_id: &str,
) -> Result<File> {
    policy.validate()?;
    if !wire::valid_name(workspace) || !wire::valid_name(node_id) {
        return Err(WorkflowError("invalid_workflow_rotation_context"));
    }
    let directory = state_dir.join("workflows");
    private_dir(&directory)?;
    private_dir(&directory.join("retired"))?;
    let lock = lock_controller(&directory)?;
    let mut count = 0usize;
    for entry in fs::read_dir(&directory).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| WorkflowError("invalid_workflow_storage"))?;
        if name == "retired" || name == ".lock" {
            continue;
        }
        // Interrupted writes are conservative blockers during an offline key change;
        // normal controller recovery can inspect/remove them before another attempt.
        count = count
            .checked_add(1)
            .ok_or(WorkflowError("invalid_workflow_storage"))?;
        if !wire::valid_ulid(&name) || count > policy.max_workflows {
            return Err(WorkflowError("invalid_workflow_storage"));
        }
        let record: WorkflowRecord =
            serde_json::from_slice(&read_private(&entry.path(), MAX_JOURNAL_BYTES)?)
                .map_err(|_| WorkflowError("invalid_workflow_journal"))?;
        record.validate(policy)?;
        if record.definition.id != name
            || record.workspace != workspace
            || record.controller_node != node_id
        {
            return Err(WorkflowError("workflow_rotation_identity_mismatch"));
        }
        if !record.state().terminal() {
            return Err(WorkflowError(
                "workflow_rotation_requires_terminal_workflows",
            ));
        }
    }
    Ok(lock)
}

#[cfg(unix)]
fn lock_controller(directory: &Path) -> Result<File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(".lock"))
        .map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err(WorkflowError("workflow_lock_not_private"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(WorkflowError("workflow_controller_already_running"));
    }
    Ok(file)
}

fn finish(record: &mut WorkflowRecord, now_ms: u64) -> Result<()> {
    if now_ms < record.updated_at_ms {
        return Err(WorkflowError("workflow_clock_rollback"));
    }
    record.updated_at_ms = now_ms;
    if record.state().terminal() && record.terminal_expires_at_ms.is_none() {
        record.terminal_expires_at_ms = Some(
            now_ms
                .checked_add(record.content_ttl_seconds * 1000)
                .ok_or(WorkflowError("workflow_clock_overflow"))?,
        );
    }
    Ok(())
}
fn spec_hash(spec: &JobSpec) -> Result<String> {
    Ok(provenance::sha256(
        &serde_json::to_vec(spec).map_err(|_| WorkflowError("invalid_workflow_job"))?,
    ))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_image_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hash)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowContext {
    version: u8,
    inputs: Vec<WorkflowInput>,
}
/// Fixed read-only context file. Contains authenticated artifact references, never keys or code bytes.
#[cfg(unix)]
pub fn stage_context(job_dir: &Path, inputs: &[WorkflowInput]) -> Result<Option<PathBuf>> {
    use std::os::unix::fs::OpenOptionsExt;
    if inputs.is_empty() {
        return Ok(None);
    }
    validate_inputs(inputs)?;
    let bytes = serde_json::to_vec(&WorkflowContext {
        version: 1,
        inputs: inputs.to_vec(),
    })
    .map_err(|_| WorkflowError("invalid_workflow_inputs"))?;
    if bytes.len() > MAX_DEFINITION_BYTES {
        return Err(WorkflowError("workflow_inputs_too_large"));
    }
    let directory = job_dir.join("runtime-context");
    private_dir(&directory)?;
    let destination = directory.join("workflow-inputs.json");
    if destination.exists() {
        if read_private(&destination, MAX_DEFINITION_BYTES as u64)? != bytes {
            return Err(WorkflowError("workflow_input_context_conflict"));
        }
        lockyard_core::fsio::sync_path(&directory).map_err(io)?;
        return Ok(Some(destination));
    }
    let temporary = directory.join(format!(
        ".{}.tmp",
        wire::new_id().map_err(|_| WorkflowError("workflow_entropy_unavailable"))?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(io)?;
    let result = (|| {
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(io)?;
        fs::hard_link(&temporary, &destination).map_err(io)?;
        lockyard_core::fsio::sync_path(&directory).map_err(io)
    })();
    let _ = fs::remove_file(&temporary);
    let _ = lockyard_core::fsio::sync_path(&directory);
    result?;
    Ok(Some(destination))
}
pub fn read_context(path: &Path) -> Result<Vec<WorkflowInput>> {
    let context: WorkflowContext =
        serde_json::from_slice(&read_private(path, MAX_DEFINITION_BYTES as u64)?)
            .map_err(|_| WorkflowError("invalid_workflow_context"))?;
    if context.version != 1 {
        return Err(WorkflowError("unsupported_workflow_context"));
    }
    validate_inputs(&context.inputs)?;
    Ok(context.inputs)
}
pub fn validate_inputs(inputs: &[WorkflowInput]) -> Result<()> {
    if inputs.len() > 64
        || inputs
            .iter()
            .map(|input| &input.step)
            .collect::<BTreeSet<_>>()
            .len()
            != inputs.len()
    {
        return Err(WorkflowError("invalid_workflow_input_references"));
    }
    for input in inputs {
        input.validate()?;
    }
    Ok(())
}
pub fn step_job_id(flow: &str, step: &str) -> Result<String> {
    if !wire::valid_ulid(flow) || !wire::valid_name(step) {
        return Err(WorkflowError("invalid_workflow_step_identity"));
    }
    let hash = ring::digest::digest(
        &ring::digest::SHA256,
        format!("lockyard-workflow-step-v1|{flow}|{step}").as_bytes(),
    );
    let bytes = &hash.as_ref()[..10];
    let mut suffix = String::new();
    for index in 0..16 {
        let mut digit = 0usize;
        for bit in 0..5 {
            let offset = index * 5 + bit;
            digit = (digit << 1) | usize::from((bytes[offset / 8] >> (7 - offset % 8)) & 1);
        }
        suffix.push(b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[digit] as char);
    }
    Ok(format!("{}{suffix}", &flow[..10]))
}

#[cfg(unix)]
fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(io(error)),
    }
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(WorkflowError("workflow_directory_not_private"));
    }
    // Re-establish parent durability even if a previous creator died after mkdir.
    lockyard_core::fsio::sync_path(
        path.parent()
            .ok_or(WorkflowError("invalid_workflow_storage"))?,
    )
    .map_err(io)?;
    Ok(())
}
#[cfg(unix)]
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > max
    {
        return Err(WorkflowError("workflow_file_not_private"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() as u64 > max {
        return Err(WorkflowError("workflow_file_too_large"));
    }
    Ok(bytes)
}
#[cfg(unix)]
fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if !wire::valid_ulid(name) {
        return Err(WorkflowError("invalid_workflow_id"));
    }
    let temporary = directory.join(format!(
        ".{name}-{}.tmp",
        wire::new_id().map_err(|_| WorkflowError("workflow_entropy_unavailable"))?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(io)?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(io)?;
        lockyard_core::fsio::rename(&temporary, directory.join(name)).map_err(io)?;
        lockyard_core::fsio::sync_path(directory).map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(windows)]
fn private_dir(path: &Path) -> Result<()> {
    lockyard_core::windows::private_dir(path).map_err(io)
}

#[cfg(windows)]
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    lockyard_core::windows::read_private(path, max).map_err(io)
}

#[cfg(windows)]
fn lock_controller(directory: &Path) -> Result<File> {
    let file = lockyard_core::windows::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(directory.join(".lock"))
        .map_err(io)?;
    file.try_lock()
        .map_err(|_| WorkflowError("workflow_controller_already_running"))?;
    Ok(file)
}

#[cfg(windows)]
fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    if !wire::valid_ulid(name) {
        return Err(WorkflowError("invalid_workflow_id"));
    }
    lockyard_core::fsio::replace(&directory.join(name), bytes, 0o600).map_err(io)
}

#[cfg(windows)]
pub fn stage_context(job_dir: &Path, inputs: &[WorkflowInput]) -> Result<Option<PathBuf>> {
    if inputs.is_empty() {
        return Ok(None);
    }
    validate_inputs(inputs)?;
    let bytes = serde_json::to_vec(&WorkflowContext {
        version: 1,
        inputs: inputs.to_vec(),
    })
    .map_err(|_| WorkflowError("invalid_workflow_inputs"))?;
    if bytes.len() > MAX_DEFINITION_BYTES {
        return Err(WorkflowError("workflow_inputs_too_large"));
    }
    let directory = job_dir.join("runtime-context");
    private_dir(&directory)?;
    let destination = directory.join("workflow-inputs.json");
    if destination.exists() {
        if read_private(&destination, MAX_DEFINITION_BYTES as u64)? != bytes {
            return Err(WorkflowError("workflow_input_context_conflict"));
        }
        lockyard_core::fsio::sync_path(&directory).map_err(io)?;
        return Ok(Some(destination));
    }
    let temporary = directory.join(format!(
        ".{}.tmp",
        wire::new_id().map_err(|_| WorkflowError("workflow_entropy_unavailable"))?
    ));
    let mut file = lockyard_core::windows::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(io)?;
    let result = (|| {
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(io)?;
        lockyard_core::windows::rename_create_only(&temporary, &destination).map_err(io)?;
        lockyard_core::fsio::sync_path(&directory).map_err(io)
    })();
    let _ = fs::remove_file(&temporary);
    let _ = lockyard_core::fsio::sync_path(&directory);
    result?;
    Ok(Some(destination))
}

#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(unix)]
use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        provenance::{ArtifactDigest, SigningKey},
        scheduler::{Resources, RunnerCapability},
    };
    const FLOW: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    fn template() -> JobTemplate {
        JobTemplate {
            repository: "repo".into(),
            revision: "HEAD".into(),
            runner: "build".into(),
            arguments: vec![],
            prompt: Some("private prompt fixture".into()),
            timeout_seconds: Some(30),
            priority: 0,
        }
    }
    fn definition() -> WorkflowDefinition {
        WorkflowDefinition {
            version: 1,
            id: FLOW.into(),
            max_parallel: 2,
            steps: vec![
                WorkflowStep {
                    key: "a".into(),
                    needs: vec![],
                    placement: Placement::default(),
                    job: template(),
                    require_complete_patch: true,
                },
                WorkflowStep {
                    key: "b".into(),
                    needs: vec![],
                    placement: Placement::default(),
                    job: template(),
                    require_complete_patch: true,
                },
                WorkflowStep {
                    key: "c".into(),
                    needs: vec!["a".into(), "b".into()],
                    placement: Placement::default(),
                    job: template(),
                    require_complete_patch: true,
                },
            ],
        }
    }
    fn capability() -> NodeCapabilities {
        NodeCapabilities {
            repository_cloud_sha256: BTreeMap::new(),
            version: 1,
            node_id: "worker".into(),
            certificate_sha256: "a".repeat(64),
            labels: BTreeMap::new(),
            capacity: Some(Resources {
                cpu_millis: 4000,
                memory_mb: 8192,
            }),
            reserved: Resources {
                cpu_millis: 0,
                memory_mb: 0,
            },
            runners: BTreeMap::from([(
                "build".into(),
                RunnerCapability {
                    external_approval_required: false,
                    action: Default::default(),
                    owner_approval_authorities: vec![],
                    image_reference: format!("sha256:{}", "b".repeat(64)),
                    resources: Resources {
                        cpu_millis: 1000,
                        memory_mb: 1024,
                    },
                    pids_limit: 64,
                    image_digest: format!("sha256:{}", "b".repeat(64)),
                    configuration_sha256: "f".repeat(64),
                },
            )]),
            projects: vec!["repo".into()],
            max_concurrency: 4,
            max_pending_jobs: 128,
            running: 0,
            queued: 0,
            unknown: 0,
            draining: false,
        }
    }
    struct FixtureDriver {
        root: PathBuf,
        key: SigningKey,
        nodes: Mutex<Vec<NodeCapabilities>>,
        jobs: Mutex<BTreeMap<String, JobRecord>>,
        calls: Mutex<Vec<(Operation, String, String)>>,
        lose_submit_reply: AtomicBool,
        complete: AtomicBool,
        bad_context: AtomicBool,
        expired_receipt: AtomicBool,
    }
    impl FixtureDriver {
        fn new(root: &Path) -> Self {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            #[cfg(unix)]
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
            #[cfg(windows)]
            lockyard_core::windows::secure_owned(root).unwrap();
            Self {
                root: root.into(),
                key: SigningKey::generate(&root.join("signing.pk8")).unwrap(),
                nodes: Mutex::new(vec![capability()]),
                jobs: Mutex::new(BTreeMap::new()),
                calls: Mutex::new(vec![]),
                lose_submit_reply: AtomicBool::new(false),
                complete: AtomicBool::new(false),
                bad_context: AtomicBool::new(false),
                expired_receipt: AtomicBool::new(false),
            }
        }
        fn record(&self, spec: JobSpec) -> JobRecord {
            serde_json::from_value(json!({"spec":spec,"state":"running","agent":"fixture","submitter":"controller","submitter_certificate_sha256":"c".repeat(64),"created_at":1000,"updated_at":1001,"resolved_revision":"d".repeat(40),"worktree":null,"pid":42,"exit_code":null,"error_code":null,"log_bytes":0,"log_truncated":false})).unwrap()
        }
        fn sign(&self, job: &mut JobRecord) {
            job.state = JobState::Succeeded;
            job.exit_code = Some(0);
            job.updated_at_ms = 2000;
            let mut manifest:ResultManifest=serde_json::from_value(json!({"version":1,"node_id":"worker","workspace":"workspace","job_id":job.spec.id,"repository":"repo","runner":job.spec.runner,
                "request_sha256":spec_hash(&job.spec).unwrap(),"resolved_revision":"d".repeat(40),"image_reference":format!("sha256:{}","b".repeat(64)),"image_digest":format!("sha256:{}","b".repeat(64)),
                "image_config_digest":format!("sha256:{}","b".repeat(64)),"image_attestation_sha256":"e".repeat(64),"execution_attempted":true,"completed_at_ms":2000,"state":"succeeded","exit_code":0,"error_code":null,
                "artifacts":{"result.patch":{"size_bytes":0,"sha256":provenance::sha256(&[]),"truncated":false,"error_code":null}}})).unwrap();
            if self.bad_context.load(Ordering::SeqCst) {
                manifest.request_sha256 = "f".repeat(64);
            }
            job.result_manifest = Some(self.key.sign_result(&manifest).unwrap());
        }
    }
    impl WorkflowDriver for FixtureDriver {
        fn describe_nodes(&self) -> BoxFuture<'_, Result<Vec<NodeCapabilities>>> {
            Box::pin(async { Ok(self.nodes.lock().unwrap().clone()) })
        }
        fn rpc<'a>(
            &'a self,
            _flow: &'a str,
            node: &'a str,
            pin: &'a str,
            operation: Operation,
            payload: Value,
        ) -> BoxFuture<'a, Result<RpcReply<Value>>> {
            Box::pin(async move {
                if operation == Operation::NodePing {
                    let resolve = &payload["resolve"];
                    let nodes = self.nodes.lock().unwrap();
                    let capability = &nodes[0];
                    let runner = resolve["runner"].as_str().unwrap();
                    return Ok(RpcReply::success(
                        serde_json::to_value(crate::scheduler::RevisionCapability {
                            repository_cloud_sha256: capability
                                .repository_cloud_sha256
                                .get(resolve["repository"].as_str().unwrap())
                                .cloned(),
                            node_id: capability.node_id.clone(),
                            certificate_sha256: capability.certificate_sha256.clone(),
                            repository: resolve["repository"].as_str().unwrap().into(),
                            requested_revision: resolve["revision"].as_str().unwrap().into(),
                            resolved_revision: "d".repeat(40),
                            runner: runner.into(),
                            profile: capability.runners[runner].clone(),
                        })
                        .unwrap(),
                    ));
                }
                let id = if operation == Operation::JobSubmit {
                    payload["id"].as_str().unwrap()
                } else {
                    payload["job_id"].as_str().unwrap()
                }
                .to_owned();
                self.calls
                    .lock()
                    .unwrap()
                    .push((operation, id.clone(), pin.to_string()));
                if self
                    .nodes
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|n| n.node_id != node || n.certificate_sha256 != pin)
                {
                    return Err(WorkflowError("node_incarnation_changed"));
                }
                if operation == Operation::JobSubmit {
                    // Observable precondition: complete chosen target/spec is durable BEFORE side effect.
                    let saved: WorkflowRecord = serde_json::from_slice(
                        &read_private(&self.root.join("workflows").join(FLOW), MAX_JOURNAL_BYTES)
                            .unwrap(),
                    )
                    .unwrap();
                    let checkpoint = saved
                        .steps
                        .values()
                        .find(|step| step.checkpoint.as_ref().is_some_and(|cp| cp.spec.id == id))
                        .unwrap();
                    assert_eq!(checkpoint.state, StepState::Dispatching);
                    assert_eq!(
                        checkpoint.checkpoint.as_ref().unwrap().certificate_sha256,
                        pin
                    );
                    let spec: JobSpec = serde_json::from_value(payload).unwrap();
                    let record = self.record(spec);
                    self.jobs
                        .lock()
                        .unwrap()
                        .entry(id.clone())
                        .or_insert(record);
                    if self.lose_submit_reply.load(Ordering::SeqCst) {
                        return Err(WorkflowError("synthetic_reply_lost"));
                    }
                }
                let mut jobs = self.jobs.lock().unwrap();
                let Some(job) = jobs.get_mut(&id) else {
                    return Ok(RpcReply::failure("job_not_found", "fixture"));
                };
                if operation == Operation::JobStatus && self.expired_receipt.load(Ordering::SeqCst)
                {
                    let receipt = crate::retention::TerminalReceipt {
                        version: 1,
                        node_id: "worker".into(),
                        workspace: "workspace".into(),
                        job_id: id.clone(),
                        submitter: "controller".into(),
                        submitter_certificate_sha256: Some("c".repeat(64)),
                        request_sha256: spec_hash(&job.spec).unwrap(),
                        outcome: JobState::Succeeded,
                        completed_at_ms: 2000,
                    };
                    let signed = self
                        .key
                        .sign_document(crate::retention::TERMINAL_RECEIPT_DOMAIN, &receipt)
                        .unwrap();
                    let mut reply = RpcReply::failure("job_content_expired", "expired");
                    reply.result = Some(
                        json!({"job_id":id,"content_expired":true,"erasure_committed":true,"terminal_receipt":signed}),
                    );
                    return Ok(reply);
                }
                if self.complete.load(Ordering::SeqCst) {
                    self.sign(job);
                }
                Ok(RpcReply::success(serde_json::to_value(job).unwrap()))
            })
        }
    }
    fn open(root: &Path, driver: &FixtureDriver, now: u64) -> WorkflowController {
        WorkflowController::open(
            root,
            WorkflowPolicy::default(),
            "workspace".into(),
            "controller".into(),
            "c".repeat(64),
            BTreeMap::from([("worker".into(), driver.key.trusted_key())]),
            BTreeMap::from([(
                "repo".into(),
                RetentionPolicy {
                    content_ttl_seconds: 60,
                },
            )]),
            now,
        )
        .unwrap()
    }
    #[test]
    fn graph_validation_rejects_cycles_duplicates_and_changed_definition_ids() {
        let mut graph = definition();
        graph.validate(&WorkflowPolicy::default()).unwrap();
        assert_ne!(
            step_job_id(FLOW, "a").unwrap(),
            step_job_id(FLOW, "b").unwrap()
        );
        assert!(wire::valid_ulid(&step_job_id(FLOW, "a").unwrap()));
        graph.steps[0].needs = vec!["c".into()];
        assert!(graph.validate(&WorkflowPolicy::default()).is_err());
        graph = definition();
        graph.steps[2].needs = vec!["a".into(), "a".into()];
        assert!(graph.validate(&WorkflowPolicy::default()).is_err());
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        assert_eq!(controller.submit(definition(), 1001).unwrap().id, FLOW);
        let mut changed = definition();
        changed.steps[0].job.prompt = Some("different private prompt".into());
        assert_eq!(
            controller.submit(changed, 1001),
            Err(WorkflowError("workflow_identifier_conflict"))
        );
        assert!(
            !serde_json::to_string(&controller.status(FLOW).unwrap())
                .unwrap()
                .contains("private prompt")
        );
    }
    #[tokio::test]
    async fn dag_parallel_roots_commit_before_send_and_only_verified_results_release_child() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            2
        );
        assert_eq!(
            controller
                .status(FLOW)
                .unwrap()
                .steps
                .iter()
                .find(|s| s.key == "c")
                .unwrap()
                .state,
            StepState::Pending
        );
        driver.complete.store(true, Ordering::SeqCst);
        controller.tick(&driver, 3000).await.unwrap();
        {
            let jobs = driver.jobs.lock().unwrap();
            let child = &jobs[&step_job_id(FLOW, "c").unwrap()];
            let value = serde_json::to_value(&child.spec).unwrap();
            assert_eq!(value["workflow_inputs"].as_array().unwrap().len(), 2);
            assert!(
                !value["workflow_inputs"]
                    .to_string()
                    .contains("private prompt")
            );
        }
        controller.tick(&driver, 5000).await.unwrap();
        assert_eq!(
            controller.status(FLOW).unwrap().state,
            WorkflowState::Succeeded
        );
    }
    #[tokio::test]
    async fn expired_signed_terminal_receipt_never_releases_workflow_dependencies_or_resubmits() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        driver.expired_receipt.store(true, Ordering::SeqCst);
        controller.tick(&driver, 3000).await.unwrap();
        controller.tick(&driver, 10_000).await.unwrap();
        let status = controller.status(FLOW).unwrap();
        assert!(
            status
                .steps
                .iter()
                .filter(|s| s.key == "a" || s.key == "b")
                .all(|s| s.state != StepState::Succeeded)
        );
        assert_eq!(
            status.steps.iter().find(|s| s.key == "c").unwrap().state,
            StepState::Pending
        );
        let calls = driver.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            2
        );
        assert!(!calls.iter().any(
            |(op, id, _)| *op == Operation::JobSubmit && *id == step_job_id(FLOW, "c").unwrap()
        ));
    }
    #[tokio::test]
    async fn lost_submit_reply_and_restart_query_same_pinned_job_without_reexecution_or_replacement()
     {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        driver.lose_submit_reply.store(true, Ordering::SeqCst);
        let controller = open(root.path(), &driver, 1000);
        let mut graph = definition();
        graph.steps.truncate(1);
        controller.submit(graph, 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        assert_eq!(
            controller.status(FLOW).unwrap().state,
            WorkflowState::Uncertain
        );
        drop(controller);
        driver.nodes.lock().unwrap()[0].certificate_sha256 = "f".repeat(64);
        let controller = open(root.path(), &driver, 3000);
        controller.tick(&driver, 30_000).await.unwrap();
        let calls = driver.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            1
        );
        assert!(calls.iter().all(|(_, _, pin)| pin == &"a".repeat(64)));
        assert_eq!(
            controller.status(FLOW).unwrap().state,
            WorkflowState::Uncertain
        );
    }
    #[tokio::test]
    async fn crash_in_pre_send_gap_is_conservative_and_does_not_turn_not_found_into_a_new_submit() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        let mut graph = definition();
        graph.steps.truncate(1);
        controller.submit(graph, 1000).unwrap();
        assert_eq!(
            controller
                .prepare_submissions(&[capability()], 1000)
                .unwrap()
                .len(),
            1
        );
        drop(controller);
        let controller = open(root.path(), &driver, 2000);
        controller.tick(&driver, 3000).await.unwrap();
        assert!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|(op, _, _)| *op == Operation::JobStatus)
        );
        assert_eq!(
            controller.status(FLOW).unwrap().state,
            WorkflowState::Uncertain
        );
    }
    #[tokio::test]
    async fn signed_but_wrong_request_context_blocks_dependents() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        driver.complete.store(true, Ordering::SeqCst);
        driver.bad_context.store(true, Ordering::SeqCst);
        controller.tick(&driver, 3000).await.unwrap();
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            2
        );
        assert_eq!(
            controller
                .status(FLOW)
                .unwrap()
                .steps
                .iter()
                .find(|s| s.key == "c")
                .unwrap()
                .state,
            StepState::Pending
        );
        assert_eq!(
            controller.status(FLOW).unwrap().state,
            WorkflowState::Uncertain
        );
    }
    #[test]
    fn explicit_cancel_prunes_content_with_tombstone_and_never_revives_same_workflow() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        assert_eq!(
            controller.cancel(FLOW, 2000).unwrap().state,
            WorkflowState::Cancelled
        );
        controller.prune(62_000).unwrap();
        assert_eq!(
            controller.status(FLOW),
            Err(WorkflowError("workflow_content_expired"))
        );
        assert_eq!(
            controller.submit(definition(), 62_000),
            Err(WorkflowError("workflow_content_expired"))
        );
        let tombstone =
            fs::read_to_string(root.path().join("workflows/retired").join(FLOW)).unwrap();
        assert!(!tombstone.contains("private prompt"));
    }
    #[test]
    fn storage_failure_stops_later_dispatch_and_controller_identity_change_pauses() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        drop(controller);
        let other = WorkflowController::open(
            root.path(),
            WorkflowPolicy::default(),
            "workspace".into(),
            "controller".into(),
            "e".repeat(64),
            BTreeMap::from([("worker".into(), driver.key.trusted_key())]),
            BTreeMap::from([(
                "repo".into(),
                RetentionPolicy {
                    content_ttl_seconds: 60,
                },
            )]),
            2000,
        )
        .unwrap();
        assert_eq!(other.status(FLOW).unwrap().state, WorkflowState::Paused);
        let invalid_path = root.path().join("workflows").join(FLOW);
        fs::remove_file(&invalid_path).unwrap();
        fs::create_dir(&invalid_path).unwrap();
        assert!(other.cancel(FLOW, 3000).is_err());
        assert!(other.healthy().is_err());
    }
    #[test]
    fn required_patch_completeness_is_enforced_for_result_references() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        let actions = controller
            .prepare_submissions(&[capability()], 1000)
            .unwrap();
        let mut records = controller.records.lock().unwrap();
        let record = records.get_mut(FLOW).unwrap();
        for action in actions {
            let mut job = driver.record(action.checkpoint.spec);
            driver.sign(&mut job);
            let checkpoint = record.steps.get_mut(&action.step).unwrap();
            checkpoint.checkpoint.as_mut().unwrap().resolved_revision =
                job.resolved_revision.clone();
            let mut manifest = provenance::verify_result_identity(
                job.result_manifest.as_ref().unwrap(),
                &driver.key.trusted_key(),
                "worker",
                "workspace",
                &job.spec.id,
            )
            .unwrap();
            manifest.artifacts.insert(
                "result.patch".into(),
                ArtifactDigest {
                    size_bytes: 0,
                    sha256: provenance::sha256(&[]),
                    truncated: true,
                    error_code: None,
                },
            );
            checkpoint.result = Some(driver.key.sign_result(&manifest).unwrap());
            checkpoint.state = StepState::Succeeded;
        }
        assert_eq!(
            input_context(record, &record.definition.steps[2]),
            Err(WorkflowError("predecessor_patch_incomplete"))
        );
    }
    #[test]
    fn offline_rotation_rejects_incomplete_workflows_and_holds_exact_controller_lock() {
        let temp = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(temp.path());
        let controller = open(temp.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        assert!(
            offline_rotation_guard(
                temp.path(),
                &WorkflowPolicy::default(),
                "workspace",
                "controller"
            )
            .is_err()
        );
        drop(controller);
        assert_eq!(
            offline_rotation_guard(
                temp.path(),
                &WorkflowPolicy::default(),
                "workspace",
                "controller"
            )
            .unwrap_err()
            .0,
            "workflow_rotation_requires_terminal_workflows"
        );
        let controller = open(temp.path(), &driver, 1001);
        controller.cancel(FLOW, 1001).unwrap();
        drop(controller);
        assert!(
            offline_rotation_guard(
                temp.path(),
                &WorkflowPolicy::default(),
                "another",
                "controller"
            )
            .is_err()
        );
        let guard = offline_rotation_guard(
            temp.path(),
            &WorkflowPolicy::default(),
            "workspace",
            "controller",
        )
        .unwrap();
        assert!(
            WorkflowController::open(
                temp.path(),
                WorkflowPolicy::default(),
                "workspace".into(),
                "controller".into(),
                "c".repeat(64),
                BTreeMap::new(),
                BTreeMap::new(),
                1002
            )
            .is_err()
        );
        drop(guard);
        offline_rotation_guard(
            temp.path(),
            &WorkflowPolicy::default(),
            "workspace",
            "controller",
        )
        .unwrap();
    }

    #[test]
    fn exact_workflow_submit_retry_during_drain_reconciles_without_admitting_new_work() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        let original = controller.submit(definition(), 1000).unwrap();
        controller.begin_drain();
        assert_eq!(controller.submit(definition(), 1001).unwrap(), original);
        let mut changed = definition();
        changed.steps[0].job.prompt = Some("changed".into());
        assert_eq!(
            controller.submit(changed, 1001).unwrap_err().0,
            "workflow_identifier_conflict"
        );
        let mut new = definition();
        new.id = wire::new_id().unwrap();
        assert_eq!(
            controller.submit(new, 1001).unwrap_err().0,
            "workflow_controller_draining"
        );
    }

    fn abandon_request(summary: &WorkflowSummary) -> WorkflowAbandonRequest {
        WorkflowAbandonRequest {
            id: summary.id.clone(),
            definition_sha256: summary.definition_sha256.clone(),
            controller_certificate_sha256: summary.controller_certificate_sha256.clone(),
            expected_local_certificate_sha256: "c".repeat(64),
            confirm_no_active_execution: true,
        }
    }
    #[tokio::test]
    async fn explicit_unknown_abandon_requires_drain_exact_identity_and_stop_proof_and_never_releases_dependencies()
     {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        driver.lose_submit_reply.store(true, Ordering::SeqCst);
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        // tick() adds real elapsed discovery time to its logical clock; later steps stay
        // 100 s ahead so a slow host cannot make them look like a clock rollback.
        controller.cancel(FLOW, 101_100).unwrap();
        let mut other = definition();
        other.id = wire::new_id().unwrap();
        controller.submit(other.clone(), 101_100).unwrap();
        let other_before = controller.status(&other.id).unwrap();
        let before = controller.status(FLOW).unwrap();
        assert_eq!(
            controller
                .abandon(abandon_request(&before), 101_200, |_| Box::pin(async {
                    Ok(())
                }))
                .await
                .unwrap_err()
                .0,
            "workflow_abandon_requires_drain"
        );
        controller.begin_drain();
        let mut wrong = abandon_request(&before);
        wrong.definition_sha256 = "f".repeat(64);
        assert_eq!(
            controller
                .abandon(wrong, 101_200, |_| Box::pin(async { Ok(()) }))
                .await
                .unwrap_err()
                .0,
            "workflow_abandon_identity_mismatch"
        );
        let mut wrong = abandon_request(&before);
        wrong.expected_local_certificate_sha256 = "d".repeat(64);
        assert_eq!(
            controller
                .abandon(wrong, 101_200, |_| Box::pin(async { Ok(()) }))
                .await
                .unwrap_err()
                .0,
            "workflow_abandon_identity_mismatch"
        );
        assert_eq!(
            controller
                .abandon(abandon_request(&before), 101_200, |_| Box::pin(async {
                    Err(WorkflowError("synthetic_local_or_outbound_still_active"))
                }))
                .await
                .unwrap_err()
                .0,
            "synthetic_local_or_outbound_still_active"
        );
        assert_eq!(controller.status(FLOW).unwrap(), before);
        let after = controller
            .abandon(abandon_request(&before), 101_200, |_| {
                Box::pin(async { Ok(()) })
            })
            .await
            .unwrap();
        assert!(after.abandoned);
        assert_eq!(after.state, WorkflowState::Failed);
        assert!(
            after
                .steps
                .iter()
                .all(|step| step.state != StepState::Succeeded)
        );
        assert_eq!(controller.status(&other.id).unwrap(), other_before);
        let submits = driver
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(op, _, _)| *op == Operation::JobSubmit)
            .count();
        controller.tick(&driver, 102_000).await.unwrap();
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            submits
        );
        controller.cancel(&other.id, 102_000).unwrap();
        drop(controller);
        let restored = open(root.path(), &driver, 103_000);
        assert!(restored.status(FLOW).unwrap().abandoned);
        offline_rotation_guard(
            root.path(),
            &WorkflowPolicy::default(),
            "workspace",
            "controller",
        )
        .unwrap_err();
        drop(restored);
        offline_rotation_guard(
            root.path(),
            &WorkflowPolicy::default(),
            "workspace",
            "controller",
        )
        .unwrap();
    }
    #[tokio::test]
    async fn abandoning_an_already_cancelled_workflow_is_idempotent_and_never_converts_it_to_success()
     {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let controller = open(root.path(), &driver, 1000);
        controller.submit(definition(), 1000).unwrap();
        let cancelled = controller.cancel(FLOW, 1001).unwrap();
        controller.begin_drain();
        let unchanged = controller
            .abandon(abandon_request(&cancelled), 1002, |_| {
                Box::pin(async {
                    panic!("no execution review needed for an already terminal workflow")
                })
            })
            .await
            .unwrap();
        assert_eq!(unchanged, cancelled);
        assert_eq!(unchanged.state, WorkflowState::Cancelled);
        assert!(!unchanged.abandoned);
    }

    fn owner_flow(driver: &FixtureDriver, owner: &SigningKey) -> WorkflowDefinition {
        let mut nodes = driver.nodes.lock().unwrap();
        let mut deploy = nodes[0].runners["build"].clone();
        deploy.action = crate::approvals::ManagedAction::Deploy;
        deploy.owner_approval_authorities = vec![owner.trusted_key()];
        deploy.configuration_sha256 = "e".repeat(64);
        nodes[0].runners.insert("deploy".into(), deploy);
        let mut graph = definition();
        graph.steps[2].job.runner = "deploy".into();
        graph
    }
    fn after_workflow_update(controller: &WorkflowController, delay_ms: u64) -> u64 {
        // RPC observations include real elapsed time. Continue the test's logical clock from
        // the persisted observation so slow durable writes cannot manufacture a clock rollback.
        controller
            .status(FLOW)
            .unwrap()
            .updated_at_ms
            .checked_add(delay_ms)
            .unwrap()
    }
    #[tokio::test]
    async fn predecessor_results_materialize_owner_request_without_submit_then_exact_approval_executes_once()
     {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let owner = SigningKey::generate(&root.path().join("owner.pk8")).unwrap();
        let graph = owner_flow(&driver, &owner);
        let controller = open(root.path(), &driver, 1000);
        let admitted = controller.submit(graph, 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        driver.complete.store(true, Ordering::SeqCst);
        let results_at = after_workflow_update(&controller, 2000);
        controller.tick(&driver, results_at).await.unwrap();
        let owner_at = after_workflow_update(&controller, 0);
        let waiting = controller.status(FLOW).unwrap();
        assert_eq!(waiting.state, WorkflowState::AwaitingOwner);
        assert_eq!(waiting.steps[2].state, StepState::AwaitingOwner);
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            2
        );
        let bundle = controller.approval_request(FLOW, "c").unwrap();
        assert_eq!(bundle.spec.revision, "d".repeat(40));
        assert_eq!(bundle.spec.workflow_inputs.len(), 2);
        assert!(bundle.spec.owner_approval.is_none());
        assert_eq!(bundle.action, crate::approvals::ManagedAction::Deploy);
        drop(controller);
        let controller = open(root.path(), &driver, owner_at + 100);
        assert_eq!(controller.approval_request(FLOW, "c").unwrap(), bundle);
        let mut tampered = bundle.clone();
        tampered.spec.prompt = Some("changed".into());
        let bad = tampered
            .prepare(1, owner_at + 27_000)
            .unwrap()
            .sign(&owner)
            .unwrap();
        assert!(
            controller
                .approval_attach(FLOW, "c", &admitted.definition_sha256, bad, owner_at + 200)
                .is_err()
        );
        let approval = bundle
            .prepare(1, owner_at + 500)
            .unwrap()
            .sign(&owner)
            .unwrap();
        controller
            .approval_attach(
                FLOW,
                "c",
                &admitted.definition_sha256,
                approval.clone(),
                owner_at + 200,
            )
            .unwrap();
        // A token that expires before first dispatch is not consumed by a failing unsigned submit.
        controller.tick(&driver, owner_at + 1000).await.unwrap();
        assert_eq!(
            controller.status(FLOW).unwrap().steps[2].state,
            StepState::AwaitingOwner
        );
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            2
        );
        let expired_at = after_workflow_update(&controller, 0);
        let approval = bundle
            .prepare(expired_at, expired_at + 26_000)
            .unwrap()
            .sign(&owner)
            .unwrap();
        controller
            .approval_attach(
                FLOW,
                "c",
                &admitted.definition_sha256,
                approval.clone(),
                expired_at + 100,
            )
            .unwrap();
        controller.tick(&driver, expired_at + 1000).await.unwrap();
        let completed = controller.status(FLOW).unwrap();
        assert_eq!(completed.state, WorkflowState::Succeeded);
        assert_eq!(completed.definition_sha256, admitted.definition_sha256);
        let completed_at = after_workflow_update(&controller, 0);
        controller
            .approval_attach(
                FLOW,
                "c",
                &admitted.definition_sha256,
                approval,
                completed_at + 100,
            )
            .unwrap();
        controller.tick(&driver, completed_at + 1000).await.unwrap();
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            3
        );
        let child = &driver.jobs.lock().unwrap()[&step_job_id(FLOW, "c").unwrap()];
        assert_eq!(child.spec.revision, bundle.resolved_revision);
        assert_eq!(child.spec.workflow_inputs, bundle.spec.workflow_inputs);
    }
    #[tokio::test]
    async fn cancelling_awaiting_owner_is_locally_terminal_and_cannot_be_approved_or_replayed_after_restart()
     {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let owner = SigningKey::generate(&root.path().join("owner.pk8")).unwrap();
        let graph = owner_flow(&driver, &owner);
        let controller = open(root.path(), &driver, 1000);
        let admitted = controller.submit(graph, 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        driver.complete.store(true, Ordering::SeqCst);
        let results_at = after_workflow_update(&controller, 2000);
        controller.tick(&driver, results_at).await.unwrap();
        let owner_at = after_workflow_update(&controller, 0);
        let bundle = controller.approval_request(FLOW, "c").unwrap();
        let approval = bundle
            .prepare(1, owner_at + 27_000)
            .unwrap()
            .sign(&owner)
            .unwrap();
        let cancelled = controller.cancel(FLOW, owner_at + 100).unwrap();
        assert_eq!(cancelled.state, WorkflowState::Cancelled);
        assert!(
            controller
                .approval_attach(
                    FLOW,
                    "c",
                    &admitted.definition_sha256,
                    approval,
                    owner_at + 200
                )
                .is_err()
        );
        drop(controller);
        let restored = open(root.path(), &driver, owner_at + 1000);
        restored.tick(&driver, owner_at + 1000).await.unwrap();
        assert_eq!(
            restored.status(FLOW).unwrap().state,
            WorkflowState::Cancelled
        );
        assert_eq!(
            driver
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(op, _, _)| *op == Operation::JobSubmit)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn cancel_after_durable_dispatch_commit_reports_in_flight_and_preserves_actual_success() {
        let root = tempfile::tempdir().unwrap();
        let driver = FixtureDriver::new(root.path());
        let owner = SigningKey::generate(&root.path().join("owner.pk8")).unwrap();
        let graph = owner_flow(&driver, &owner);
        let controller = open(root.path(), &driver, 1000);
        let admitted = controller.submit(graph, 1000).unwrap();
        controller.tick(&driver, 1000).await.unwrap();
        driver.complete.store(true, Ordering::SeqCst);
        let results_at = after_workflow_update(&controller, 2000);
        controller.tick(&driver, results_at).await.unwrap();
        let owner_at = after_workflow_update(&controller, 0);
        let bundle = controller.approval_request(FLOW, "c").unwrap();
        let approval = bundle
            .prepare(1, owner_at + 27_000)
            .unwrap()
            .sign(&owner)
            .unwrap();
        controller
            .approval_attach(
                FLOW,
                "c",
                &admitted.definition_sha256,
                approval,
                owner_at + 100,
            )
            .unwrap();
        let actions = controller.prepare_submissions(&[], owner_at + 200).unwrap();
        assert_eq!(actions.len(), 1);
        // Force the precise pre-send gap: no driver RPC has yet been polled.
        let cancelled = controller.cancel(FLOW, owner_at + 201).unwrap();
        assert_eq!(cancelled.state, WorkflowState::Running);
        assert!(cancelled.cancel_requested);
        assert!(cancelled.steps[2].dispatch_committed);
        controller
            .perform(&driver, actions, owner_at + 202)
            .await
            .unwrap();
        let actual = controller.status(FLOW).unwrap();
        assert!(actual.cancel_requested);
        assert_eq!(actual.steps[2].state, StepState::Succeeded);
        assert_eq!(actual.state, WorkflowState::Succeeded);
    }
    #[tokio::test]
    async fn ep06_external_compute_workflow_waits_for_exact_owner_approval_across_restart() {
        for cloud_credentials in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let driver = FixtureDriver::new(root.path());
            let owner = SigningKey::generate(&root.path().join("owner.pk8")).unwrap();
            let mut node = serde_json::to_value(capability()).unwrap();
            node["runners"]["build"]["owner_approval_authorities"] = json!([owner.trusted_key()]);
            node["runners"]["build"]["external_approval_required"] = json!(!cloud_credentials);
            if cloud_credentials {
                node["repository_cloud_sha256"] = json!({"repo":"e".repeat(64)});
            }
            *driver.nodes.lock().unwrap() = vec![serde_json::from_value(node).unwrap()];
            let mut graph = definition();
            graph.steps.truncate(1);
            let controller = open(root.path(), &driver, 1000);
            let submitted = controller.submit(graph, 1000).unwrap();
            controller.tick(&driver, 1000).await.unwrap();
            assert_eq!(
                controller.status(FLOW).unwrap().steps[0].state,
                StepState::AwaitingOwner
            );
            assert!(driver.calls.lock().unwrap().is_empty());
            let bundle = controller.approval_request(FLOW, "a").unwrap();
            assert_eq!(bundle.action, crate::approvals::ManagedAction::Compute);
            let encoded = serde_json::to_value(&bundle).unwrap();
            assert_eq!(
                encoded["repository_cloud_sha256"],
                if cloud_credentials {
                    json!("e".repeat(64))
                } else {
                    Value::Null
                }
            );
            let after = after_workflow_update(&controller, 100);
            drop(controller);
            let controller = open(root.path(), &driver, after);
            assert_eq!(controller.approval_request(FLOW, "a").unwrap(), bundle);
            let approval = bundle
                .prepare(1, after + 60_000)
                .unwrap()
                .sign(&owner)
                .unwrap();
            controller
                .approval_attach(FLOW, "a", &submitted.definition_sha256, approval, after)
                .unwrap();
            controller.tick(&driver, after + 100).await.unwrap();
            assert_eq!(
                driver
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(op, _, _)| *op == Operation::JobSubmit)
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn ep06_unapprovable_external_compute_does_not_block_other_workflow_steps() {
        for repository_credentials in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let driver = FixtureDriver::new(root.path());
            {
                let mut nodes = driver.nodes.lock().unwrap();
                let mut external = serde_json::to_value(nodes[0].runners["build"].clone()).unwrap();
                external["external_approval_required"] = json!(!repository_credentials);
                nodes[0]
                    .runners
                    .insert("external".into(), serde_json::from_value(external).unwrap());
                nodes[0].projects.push("offline".into());
                if repository_credentials {
                    let mut encoded = serde_json::to_value(&nodes[0]).unwrap();
                    encoded["repository_cloud_sha256"] = json!({"repo":"e".repeat(64)});
                    nodes[0] = serde_json::from_value(encoded).unwrap();
                }
            }
            let mut graph = definition();
            graph.steps.truncate(2);
            graph.steps[0].job.runner = "external".into();
            graph.steps[1].job.repository = "offline".into();
            let mut controller = open(root.path(), &driver, 1000);
            controller.retention.insert(
                "offline".into(),
                RetentionPolicy {
                    content_ttl_seconds: 60,
                },
            );
            controller.submit(graph, 1000).unwrap();
            controller.tick(&driver, 1000).await.unwrap();
            let state = controller.status(FLOW).unwrap();
            assert_eq!(state.steps[0].state, StepState::Pending);
            assert_eq!(
                state.steps[0].last_error.as_deref(),
                Some("no_compatible_node")
            );
            assert_eq!(state.steps[1].state, StepState::Running);
            assert_eq!(
                driver
                    .calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(op, _, _)| *op == Operation::JobSubmit)
                    .count(),
                1
            );
        }
    }
}
