// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Endpoint-verifiable incarnations and immutable local submission destinations.
//! Discovery proofs authenticate workspace group membership, not unique member ownership.
use crate::{
    Result,
    cloud::NodeCloudClient,
    host::NodeConfig,
    quic::PeerPin,
    wire::{self, Operation},
};
use lockyard_cloud_client::WorkspaceKey;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

#[cfg(unix)]
use std::io::Read;

const PROOF_DOMAIN: &str = "node-identity-v1";
const MAX_BINDINGS: usize = 100_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityProof {
    workspace: String,
    node_id: String,
    certificate_sha256: String,
}

pub(crate) fn seal_identity(
    workspace: &str,
    node_id: &str,
    certificate_sha256: &str,
    key: &WorkspaceKey,
) -> Result<String> {
    if !wire::valid_name(node_id) || !valid_pin(certificate_sha256) {
        return Err("invalid node identity proof metadata".into());
    }
    let identity = IdentityProof {
        workspace: workspace.into(),
        node_id: node_id.into(),
        certificate_sha256: certificate_sha256.into(),
    };
    Ok(key.encrypt(workspace, PROOF_DOMAIN, &serde_json::to_string(&identity)?)?)
}

pub(crate) fn verify_identity(
    workspace: &str,
    node_id: &str,
    certificate_sha256: &str,
    proof: &str,
    key: &WorkspaceKey,
) -> Result<()> {
    if proof.len() > 8192 || !valid_pin(certificate_sha256) {
        return Err("invalid authenticated node identity".into());
    }
    let plaintext = key
        .decrypt(workspace, PROOF_DOMAIN, proof)
        .map_err(|_| "node directory identity proof failed authentication")?;
    let identity: IdentityProof =
        serde_json::from_str(&plaintext).map_err(|_| "invalid authenticated node identity")?;
    if identity.workspace != workspace
        || identity.node_id != node_id
        || identity.certificate_sha256 != certificate_sha256
    {
        return Err("node directory identity proof differs from advertised identity".into());
    }
    Ok(())
}

fn valid_pin(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn normalize(pin: &str) -> Result<String> {
    Ok(PeerPin::from_hex(pin)?.to_hex())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    job_id: String,
    target: String,
    certificate_sha256: String,
}
/// A local authority scope. It is never deserialized from an operator RPC request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum DispatchOrigin {
    #[default]
    Operator,
    Workflow(String),
    Job(String),
}
impl DispatchOrigin {
    fn is_operator(&self) -> bool {
        matches!(self, Self::Operator)
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Operator => Ok(()),
            Self::Workflow(id) | Self::Job(id) if wire::valid_ulid(id) => Ok(()),
            _ => Err("invalid local dispatch authority".into()),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    job_id: String,
    target: String,
    certificate_sha256: String,
    spec_fingerprint: String,
    #[serde(default, skip_serializing_if = "DispatchOrigin::is_operator")]
    origin: DispatchOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_certificate_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spec_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<Completion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_frame_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_deadline_ms: Option<u64>,
    /// Missing means a legacy binding: absence of a frame proves nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_state: Option<DeliveryState>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeliveryState {
    PreparedV1,
    RemoteClaimedV1,
    LocalClaimedV1,
    LocalReviewedV1,
    NeverSentV1,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Completion {
    Signed {
        state: crate::wire::JobState,
        completed_at_ms: u64,
        signed_result_sha256: String,
    },
    OperatorReviewed {
        reviewed_at_ms: u64,
        review_sha256: String,
        reviewing_source_certificate_sha256: String,
    },
    LocalRejected {
        rejected_at_ms: u64,
        reason: String,
    },
}
impl Completion {
    fn valid(&self) -> bool {
        match self {
            Self::Signed {
                state,
                completed_at_ms,
                signed_result_sha256,
            } => state.is_terminal() && *completed_at_ms != 0 && valid_pin(signed_result_sha256),
            Self::OperatorReviewed {
                reviewed_at_ms,
                review_sha256,
                reviewing_source_certificate_sha256,
            } => {
                *reviewed_at_ms != 0
                    && valid_pin(review_sha256)
                    && valid_pin(reviewing_source_certificate_sha256)
            }
            Self::LocalRejected {
                rejected_at_ms,
                reason,
            } => *rejected_at_ms != 0 && local_rejection_is_definitive(reason),
        }
    }
}

/// Local operator maintenance controls; workload bridges reject this protocol.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchControl {
    List {
        offset: usize,
        limit: usize,
    },
    Review {
        job_id: String,
        target: String,
        certificate_sha256: String,
        source_certificate_sha256: Option<String>,
        binding: String,
        confirm_no_active_execution: bool,
    },
}
#[derive(Serialize)]
struct DispatchSummary {
    job_id: String,
    target: String,
    certificate_sha256: String,
    source_certificate_sha256: Option<String>,
    binding: String,
    spec_sha256: Option<String>,
    delivery_state: Option<DeliveryState>,
    manual_review_after_ms: Option<u64>,
}

#[cfg(unix)]
fn private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut metadata = file.metadata()?;
    if metadata.nlink() == 2 {
        // Recover only our exact protected publication alias. A creator can die
        // after linking the immutable destination but before unlinking its temp.
        let parent = path.parent().ok_or("invalid incarnation file path")?;
        let mut orphan = None;
        let mut count = 0usize;
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            count += 1;
            if count > MAX_BINDINGS + 32 {
                return Err("incarnation recovery directory exceeds limit".into());
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name
                .strip_prefix(".incarnation-")
                .and_then(|name| name.strip_suffix(".partial"))
            else {
                continue;
            };
            if !wire::valid_ulid(id) || entry.path() == path {
                continue;
            }
            let candidate = match fs::symlink_metadata(entry.path()) {
                Ok(candidate) => candidate,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if candidate.is_file()
                && !candidate.file_type().is_symlink()
                && candidate.uid() == metadata.uid()
                && candidate.mode() & 0o077 == 0
                && candidate.dev() == metadata.dev()
                && candidate.ino() == metadata.ino()
            {
                let duplicate = orphan.replace(entry.path()).is_some();
                if duplicate {
                    return Err("ambiguous incarnation publication aliases".into());
                }
            }
        }
        if let Some(orphan) = orphan {
            match fs::remove_file(orphan) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            lockyard_core::fsio::sync_path(parent)?;
        }
        metadata = file.metadata()?;
    }
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err("invalid private node incarnation binding".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("node incarnation binding exceeds limit".into());
    }
    Ok(bytes)
}
#[cfg(unix)]
fn directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.exists() {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("node incarnation directory must be private and owned".into());
    }
    // A creator may have died after mkdir. Sync every parent in the short private
    // chain before any route below it is treated as durable and sent remotely.
    lockyard_core::fsio::sync_path(path.parent().ok_or("invalid incarnation directory")?)?;
    Ok(())
}
#[cfg(unix)]
fn publish(path: &Path, bytes: &[u8]) -> Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().ok_or("invalid incarnation path")?;
    let temporary = parent.join(format!(".incarnation-{}.partial", wire::new_id()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let linked = match fs::hard_link(&temporary, path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    };
    // Every contender establishes durability, including a creator killed after linking.
    lockyard_core::fsio::sync_path(parent)?;
    match fs::remove_file(temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    lockyard_core::fsio::sync_path(parent)?;
    linked.map_err(Into::into)
}
fn fingerprint_key(root: &Path) -> Result<Vec<u8>> {
    let path = root.join("fingerprint.key");
    if !path.exists() {
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| "incarnation fingerprint entropy unavailable")?;
        publish(&path, &bytes)?;
    }
    let bytes = private(&path, 32)?;
    if bytes.len() != 32 {
        return Err("invalid incarnation fingerprint key".into());
    }
    lockyard_core::fsio::sync_path(root)?;
    Ok(bytes)
}
fn counter(routes: &Path) -> Result<Arc<AtomicUsize>> {
    static COUNTS: OnceLock<Mutex<HashMap<PathBuf, Arc<AtomicUsize>>>> = OnceLock::new();
    let mut counters = COUNTS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "incarnation capacity accounting unavailable")?;
    if let Some(counter) = counters.get(routes) {
        return Ok(counter.clone());
    }
    let count = fs::read_dir(routes)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_str().is_some_and(wire::valid_ulid))
        .take(MAX_BINDINGS + 1)
        .count();
    let counter = Arc::new(AtomicUsize::new(count));
    counters.insert(routes.into(), counter.clone());
    Ok(counter)
}
fn reserve(counter: &AtomicUsize) -> Result<()> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if current >= MAX_BINDINGS {
            return Err("node incarnation binding capacity reached".into());
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}
fn load_route(path: &Path, job_id: &str, target: &str) -> Result<Option<Route>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let route: Route = serde_json::from_slice(&private(path, 2048)?)
        .map_err(|_| "invalid durable job incarnation binding")?;
    if route.job_id != job_id || route.target != target || !valid_pin(&route.certificate_sha256) {
        return Err("job ID is already bound to another node identity".into());
    }
    Ok(Some(route))
}
fn roots(config: &NodeConfig) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let root = config.state_dir.join("incarnation-bindings");
    directory(&root)?;
    let routes = root.join("routes");
    directory(&routes)?;
    let submissions = root.join("submissions");
    directory(&submissions)?;
    Ok((root, routes, submissions))
}

pub(crate) async fn authenticated_pin(config: &NodeConfig, target: &str) -> Result<String> {
    if target == config.node_id {
        let certificate = fs::read(&config.certificate)?;
        if certificate.is_empty() || certificate.len() > 64 * 1024 {
            return Err("invalid local certificate".into());
        }
        return Ok(PeerPin::certificate(&certificate).to_hex());
    }
    if let Some(peer) = config.peers.iter().find(|peer| peer.node_id == target) {
        return normalize(&peer.certificate_sha256);
    }
    let client = NodeCloudClient::from_config(config)?;
    let entries = client.directory().await?;
    let mut matching = entries.iter().filter(|entry| entry.node_id == target);
    let entry = matching
        .next()
        .ok_or("target node is unavailable in the authenticated workspace directory")?;
    if matching.next().is_some() {
        return Err("ambiguous node directory identity".into());
    }
    if entry.controller_only || entry.node_id.starts_with("web_") {
        return Err("browser controllers do not execute node RPC requests".into());
    }
    let proof=entry.identity_proof.as_deref().ok_or("relay job mutations require an authenticated node identity proof or an independent local peer pin")?;
    let key = WorkspaceKey::load_for_workspace(&config.workspace)?
        .ok_or("workspace key unavailable for node identity authentication")?;
    verify_identity(
        &config.workspace,
        target,
        &entry.certificate_sha256,
        proof,
        &key,
    )?;
    Ok(entry.certificate_sha256.clone())
}

/// A published route means an earlier send may have occurred. Its absence is the only
/// automatic first-admission path; corrupt or ambiguous local state fails closed.
pub fn has_binding(config: &NodeConfig, job_id: &str) -> Result<bool> {
    if !wire::valid_ulid(job_id) {
        return Err("invalid stable job ID".into());
    }
    let (root, routes, _) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    let _job_guard = job_lock(&root, job_id)?;
    let path = routes.join(job_id);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }
    let route: Route = serde_json::from_slice(&private(&path, 2048)?)
        .map_err(|_| "invalid durable job incarnation binding")?;
    if route.job_id != job_id
        || !wire::valid_name(&route.target)
        || !valid_pin(&route.certificate_sha256)
    {
        return Err("invalid durable job incarnation binding".into());
    }
    lockyard_core::fsio::sync_path(routes)?;
    Ok(true)
}

/// Frozen routes are authoritative after first mutation. A retry never binds a job to a
/// replacement certificate, even if a current directory entry uses the same logical name.
pub async fn target_pin(
    config: &NodeConfig,
    target: &str,
    operation: Operation,
    payload: &Value,
) -> Result<Option<String>> {
    target_pin_bound(
        config,
        target,
        operation,
        payload,
        None,
        &DispatchOrigin::Operator,
    )
    .await
}

/// Bind an immutable workflow/job dispatch before a possible send. An expected
/// incarnation is checked before any route or specification binding is published.
pub(crate) async fn target_pin_bound(
    config: &NodeConfig,
    target: &str,
    operation: Operation,
    payload: &Value,
    expected_pin: Option<&str>,
    origin: &DispatchOrigin,
) -> Result<Option<String>> {
    origin.validate()?;
    if let Some(expected) = expected_pin
        && !valid_pin(expected)
    {
        return Err("invalid expected node incarnation".into());
    }
    if operation == Operation::NodePing {
        // Describe is read-only: verify discovery without reserving a job route.
        return match expected_pin {
            Some(expected) => {
                let actual = authenticated_pin(config, target).await?;
                if actual != expected {
                    return Err(
                        "expected node incarnation differs from authenticated discovery".into(),
                    );
                }
                Ok(Some(actual))
            }
            None => Ok(None),
        };
    }
    if !wire::valid_name(target) {
        return Err("invalid target node identity".into());
    }
    let job_id = if operation == Operation::JobSubmit {
        payload.get("id")
    } else {
        payload.get("job_id")
    }
    .and_then(Value::as_str)
    .filter(|id| wire::valid_ulid(id))
    .ok_or("job operation requires a stable job ID")?
    .to_owned();
    let lookup_config = config.clone();
    let lookup_target = target.to_owned();
    let id = job_id.clone();
    let prior = tokio::task::spawn_blocking(move || -> Result<Option<Route>> {
        let (root, routes, _) = roots(&lookup_config)?;
        let _guard = dispatch_lock(&root, false)?;
        let _job_guard = job_lock(&root, &id)?;
        load_route(&routes.join(&id), &id, &lookup_target)
    })
    .await
    .map_err(|_| "job incarnation lookup failed")??;
    let chosen = match prior {
        Some(route) => {
            if let Some(peer) = config.peers.iter().find(|peer| peer.node_id == target)
                && normalize(&peer.certificate_sha256)? != route.certificate_sha256
            {
                return Err("job ID remains bound to the previous node incarnation; reconcile it before creating new work".into());
            }
            route.certificate_sha256
        }
        None => authenticated_pin(config, target).await?,
    };
    if expected_pin.is_some_and(|expected| expected != chosen) {
        return Err("expected node incarnation differs from immutable destination".into());
    }
    if !matches!(
        operation,
        Operation::JobSubmit | Operation::JobCancel | Operation::JobResolveUnknown
    ) {
        if let DispatchOrigin::Workflow(_) = origin {
            let config = config.clone();
            let target = target.to_owned();
            let id = job_id.clone();
            let pin = chosen.clone();
            let origin = origin.clone();
            tokio::task::spawn_blocking(move || {
                require_workflow_origin(&config, &target, &id, &pin, &origin)
            })
            .await
            .map_err(|_| "workflow origin lookup failed")??;
        }
        return Ok(Some(chosen));
    }
    let config = config.clone();
    let target = target.to_owned();
    let payload = payload.clone();
    let origin = origin.clone();
    let chosen = tokio::task::spawn_blocking(move || -> Result<String> {
        let (root, routes, submissions) = roots(&config)?;
        let _guard = dispatch_lock(&root, false)?;
        let _job_guard = job_lock(&root, &job_id)?;
        // A delegated job may cancel only children created by that same local
        // scope. Never adopt an operator/workflow job merely by knowing its ID.
        if !origin.is_operator() && operation != Operation::JobSubmit {
            if operation != Operation::JobCancel {
                return Err("scoped dispatch cannot resolve unknown execution".into());
            }
            let existing: Submission =
                serde_json::from_slice(&private(&submissions.join(&job_id), 4096)?)
                    .map_err(|_| "invalid scoped submission binding")?;
            if existing.job_id != job_id
                || existing.target != target
                || existing.certificate_sha256 != chosen
                || existing.origin != origin
            {
                return Err("job cancellation is outside this dispatch authority".into());
            }
        }
        let route_path = routes.join(&job_id);
        if load_route(&route_path, &job_id, &target)?.is_none() {
            let count = counter(&routes)?;
            reserve(&count)?;
            let route = Route {
                job_id: job_id.clone(),
                target: target.clone(),
                certificate_sha256: chosen.clone(),
            };
            match publish(&route_path, &serde_json::to_vec(&route)?) {
                Ok(true) => {}
                Ok(false) => {
                    count.fetch_sub(1, Ordering::AcqRel);
                }
                Err(error) => {
                    // Publication can fail AFTER linking a complete route (for example
                    // a directory fsync failure). Never undercount that retained binding.
                    if fs::symlink_metadata(&route_path).is_err() {
                        count.fetch_sub(1, Ordering::AcqRel);
                    }
                    return Err(error);
                }
            }
        }
        let route = load_route(&route_path, &job_id, &target)?
            .ok_or("durable job incarnation binding disappeared")?;
        if route.certificate_sha256 != chosen {
            return Err("job ID was concurrently bound to a different node incarnation".into());
        }
        if operation == Operation::JobSubmit {
            let key = fingerprint_key(&root)?;
            // Preserve fingerprints for already recorded operator submissions.
            let bytes = if origin.is_operator() {
                serde_json::to_vec(&(&target, &route.certificate_sha256, &payload))?
            } else {
                serde_json::to_vec(&(&origin, &target, &route.certificate_sha256, &payload))?
            };
            let fingerprint =
                hex(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &bytes).as_ref());
            let expected = Submission {
                job_id: job_id.clone(),
                target: target.clone(),
                certificate_sha256: chosen.clone(),
                spec_fingerprint: fingerprint,
                origin: origin.clone(),
                source_certificate_sha256: fs::read(&config.certificate)
                    .ok()
                    .map(|certificate| PeerPin::certificate(&certificate).to_hex()),
                spec_sha256: serde_json::from_value::<crate::wire::JobSpec>(payload.clone())
                    .ok()
                    .and_then(|spec| serde_json::to_vec(&spec).ok())
                    .map(|bytes| crate::provenance::sha256(&bytes)),
                completion: None,
                delivery_frame_id: None,
                delivery_deadline_ms: None,
                delivery_state: Some(DeliveryState::PreparedV1),
            };
            let path = submissions.join(&job_id);
            publish(&path, &serde_json::to_vec(&expected)?)?;
            let existing: Submission = serde_json::from_slice(&private(&path, 8192)?)
                .map_err(|_| "invalid durable job specification binding")?;
            if existing.job_id != job_id
                || existing.target != target
                || existing.certificate_sha256 != chosen
                || existing.spec_fingerprint != expected.spec_fingerprint
                || existing.origin != origin
            {
                return Err(
                    "job ID cannot be retried with a changed specification or incarnation".into(),
                );
            }
            lockyard_core::fsio::sync_path(&submissions)?;
        }
        lockyard_core::fsio::sync_path(&routes)?;
        Ok(chosen)
    })
    .await
    .map_err(|_| "job incarnation publication failed")??;
    Ok(Some(chosen))
}

fn load_submission(path: &Path) -> Result<Submission> {
    let value: Submission = serde_json::from_slice(&private(path, 8192)?)
        .map_err(|_| "invalid outbound submission journal")?;
    value.origin.validate()?;
    if !wire::valid_ulid(&value.job_id)
        || !wire::valid_name(&value.target)
        || !valid_pin(&value.certificate_sha256)
        || !valid_pin(&value.spec_fingerprint)
        || value
            .source_certificate_sha256
            .as_ref()
            .is_some_and(|pin| !valid_pin(pin))
        || value
            .spec_sha256
            .as_ref()
            .is_some_and(|hash| !valid_pin(hash))
        || value.delivery_frame_id.is_some() != value.delivery_deadline_ms.is_some()
        || value
            .delivery_frame_id
            .as_ref()
            .is_some_and(|id| !wire::valid_ulid(id))
        || value
            .delivery_deadline_ms
            .zip(value.delivery_frame_id.as_ref())
            .is_some_and(|(deadline, id)| {
                crate::retention::id_timestamp_ms(id).map_or(true, |created| {
                    deadline <= created
                        || deadline > created.saturating_add(wire::REQUEST_DELIVERY_TTL_MS)
                })
            })
        || value
            .completion
            .as_ref()
            .is_some_and(|completion| !completion.valid())
        || match value.delivery_state {
            Some(
                DeliveryState::PreparedV1
                | DeliveryState::LocalClaimedV1
                | DeliveryState::LocalReviewedV1
                | DeliveryState::NeverSentV1,
            ) => value.delivery_frame_id.is_some(),
            Some(DeliveryState::RemoteClaimedV1) => value.delivery_frame_id.is_none(),
            None => false,
        }
        || matches!(&value.completion,Some(Completion::OperatorReviewed {reviewed_at_ms,..})
            if !matches!(value.delivery_state,Some(DeliveryState::NeverSentV1 | DeliveryState::LocalReviewedV1))
                && value.delivery_deadline_ms.is_none_or(|deadline|*reviewed_at_ms<deadline.saturating_add(wire::MAX_CLOCK_SKEW_MS)))
        || (matches!(
            value.delivery_state,
            Some(DeliveryState::NeverSentV1 | DeliveryState::LocalReviewedV1)
        ) && !matches!(&value.completion, Some(Completion::OperatorReviewed { .. })))
        || matches!(&value.completion, Some(Completion::LocalRejected { .. }))
            && value.delivery_state != Some(DeliveryState::LocalClaimedV1)
    {
        return Err("invalid outbound submission journal".into());
    }
    Ok(value)
}
#[cfg(unix)]
fn replace_submission(directory: &Path, submission: &Submission) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = directory.join(format!(".incarnation-{}.partial", wire::new_id()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(submission)?)?;
    file.sync_all()?;
    drop(file);
    lockyard_core::fsio::rename(&temporary, directory.join(&submission.job_id))?;
    lockyard_core::fsio::sync_path(directory)?;
    Ok(())
}

fn require_workflow_origin(
    config: &NodeConfig,
    target: &str,
    job_id: &str,
    pin: &str,
    origin: &DispatchOrigin,
) -> Result<()> {
    let (root, _, submissions) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    let _job_guard = job_lock(&root, job_id)?;
    let value = load_submission(&submissions.join(job_id))?;
    if value.job_id != job_id
        || value.target != target
        || value.certificate_sha256 != pin
        || &value.origin != origin
    {
        return Err("workflow cannot adopt a job owned by another local dispatch authority".into());
    }
    Ok(())
}

/// Abandon cannot silently settle an accepted outbound dispatch. Each matching
/// workflow-owned binding requires its independent signed/reviewed maintenance receipt.
pub(crate) fn require_abandonable_dispatch(
    config: &NodeConfig,
    flow: &str,
    job_id: &str,
    target: &str,
    pin: &str,
    spec_sha256: &str,
) -> Result<()> {
    let (root, _, submissions) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    let _job_guard = job_lock(&root, job_id)?;
    let path = submissions.join(job_id);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let value = load_submission(&path)?;
    // A conflicting origin prevented this workflow's admission in the first place.
    // Its own pending-work fence remains untouched and is checked separately.
    if value.origin != DispatchOrigin::Workflow(flow.into()) {
        return Ok(());
    }
    if value.job_id != job_id
        || value.target != target
        || value.certificate_sha256 != pin
        || value.spec_sha256.as_deref() != Some(spec_sha256)
    {
        return Err("workflow abandonment differs from immutable dispatch binding".into());
    }
    if value.completion.is_none() {
        return Err(
            "workflow abandonment requires separate outbound completion or expired-delivery review"
                .into(),
        );
    }
    Ok(())
}

/// Minimal unresolved destinations for read-only reconciliation while draining.
#[derive(Clone)]
pub(crate) struct PendingSubmission {
    pub job_id: String,
    pub target: String,
    pub certificate_sha256: String,
}
pub(crate) fn pending_submissions(config: &NodeConfig) -> Result<Vec<PendingSubmission>> {
    let (root, routes, submissions) = roots(config)?;
    let mut pending = Vec::new();
    let mut count = 0usize;
    for entry in fs::read_dir(&submissions)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid outbound submission name")?;
        // No committed send follows an unlinked temporary. Check its privacy/size,
        // then leave it for explicit recovery rather than interpreting its contents.
        if name
            .strip_prefix(".incarnation-")
            .and_then(|name| name.strip_suffix(".partial"))
            .is_some_and(wire::valid_ulid)
        {
            #[cfg(unix)]
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::symlink_metadata(entry.path())?;
            #[cfg(windows)]
            {
                lockyard_core::windows::require_private(&entry.path())?;
                if !metadata.is_file() || metadata.len() > 8192 {
                    return Err("invalid outbound temporary publication".into());
                }
            }
            #[cfg(unix)]
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.len() > 8192
                || metadata.nlink() > 2
            {
                return Err("invalid outbound temporary publication".into());
            }
            continue;
        }
        count = count.checked_add(1).ok_or("outbound journal overflow")?;
        if count > MAX_BINDINGS || !wire::valid_ulid(&name) {
            return Err("invalid outbound submission journal".into());
        }
        let _job_guard = job_lock(&root, &name)?;
        let value = load_submission(&entry.path())?;
        if value.job_id != name {
            return Err("outbound submission ID differs from filename".into());
        }
        let route = load_route(&routes.join(&name), &name, &value.target)?
            .ok_or("outbound submission route missing")?;
        if route.certificate_sha256 != value.certificate_sha256 {
            return Err("outbound submission incarnation differs from route".into());
        }
        if value.completion.is_none() {
            pending.push(PendingSubmission {
                job_id: value.job_id,
                target: value.target,
                certificate_sha256: value.certificate_sha256,
            });
        }
    }
    Ok(pending)
}
pub fn unresolved_dispatches(config: &NodeConfig) -> Result<usize> {
    Ok(pending_submissions(config)?.len())
}

/// Offline installers retain this lock in addition to the exclusive Host lock.
/// Every accepted outbound submit must have an authenticated signed terminal receipt.
#[cfg(unix)]
fn job_lock(root: &Path, job_id: &str) -> Result<File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    if !wire::valid_ulid(job_id) {
        return Err("invalid stable outbound job ID".into());
    }
    let lock_dir = root.join("locks");
    directory(&lock_dir)?;
    let stripe = ring::digest::digest(&ring::digest::SHA256, job_id.as_bytes()).as_ref()[0] % 64;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_dir.join(format!("{stripe:02}")))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err("invalid outbound job lock".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err("outbound job lock unavailable".into());
    }
    Ok(file)
}

#[cfg(unix)]
fn dispatch_lock(root: &Path, exclusive: bool) -> Result<File> {
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
        .open(root.join(".offline-lock"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
    {
        return Err("invalid outbound dispatch lock".into());
    }
    if unsafe {
        libc::flock(
            file.as_raw_fd(),
            (if exclusive {
                libc::LOCK_EX
            } else {
                libc::LOCK_SH
            }) | libc::LOCK_NB,
        )
    } != 0
    {
        return Err("outbound dispatch reconciliation is active".into());
    }
    lockyard_core::fsio::sync_path(root)?;
    Ok(file)
}
pub fn offline_dispatch_guard(config: &NodeConfig) -> Result<File> {
    let (root, _, _) = roots(config)?;
    let file = dispatch_lock(&root, true)?;
    if unresolved_dispatches(config)? != 0 {
        return Err("outbound_dispatch_requires_terminal_reconciliation".into());
    }
    Ok(file)
}

/// Called only after Host authenticated the response's endpoint incarnation. An
/// unsigned response, not_found, rejection or unknown execution never retires a route.
pub(crate) fn note_terminal(
    config: &NodeConfig,
    target: &str,
    source_pin: &str,
    reply: &crate::wire::RpcReply<Value>,
) -> Result<()> {
    if !reply.ok {
        return note_expired_terminal(config, target, source_pin, reply);
    }
    let Some(value) = reply.result.as_ref() else {
        return Ok(());
    };
    let Ok(job) = serde_json::from_value::<crate::wire::JobRecord>(value.clone()) else {
        return Ok(());
    };
    if !job.state.is_terminal() {
        return Ok(());
    }
    let Some(signed) = job.result_manifest.as_ref() else {
        return Ok(());
    };
    let (root, routes, submissions) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    let _job_guard = job_lock(&root, &job.spec.id)?;
    let path = submissions.join(&job.spec.id);
    if !path.try_exists()? {
        return Ok(());
    }
    let mut submission = load_submission(&path)?;
    if submission.completion.is_some() {
        return Ok(());
    }
    let route = load_route(&routes.join(&job.spec.id), &job.spec.id, target)?
        .ok_or("outbound completion route missing")?;
    if submission.target != target
        || submission.certificate_sha256 != route.certificate_sha256
        || job.submitter != config.node_id
        || job.submitter_certificate_sha256.as_deref()
            != Some(
                submission
                    .source_certificate_sha256
                    .as_deref()
                    .unwrap_or(source_pin),
            )
        || job.provenance_error.is_some()
    {
        return Err("outbound completion differs from accepted source or destination".into());
    }
    let spec_bytes = serde_json::to_vec(&job.spec)?;
    let spec_hash = crate::provenance::sha256(&spec_bytes);
    if let Some(expected) = &submission.spec_sha256 {
        if expected != &spec_hash {
            return Err("outbound completion specification changed".into());
        }
    } else {
        // Legacy operator records retain their original exact-payload HMAC format.
        let payload = serde_json::to_value(&job.spec)?;
        let bytes = if submission.origin.is_operator() {
            serde_json::to_vec(&(target, &route.certificate_sha256, &payload))?
        } else {
            serde_json::to_vec(&(
                &submission.origin,
                target,
                &route.certificate_sha256,
                &payload,
            ))?
        };
        let fingerprint = hex(hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &fingerprint_key(&root)?),
            &bytes,
        )
        .as_ref());
        if fingerprint != submission.spec_fingerprint {
            return Err("legacy outbound completion specification differs".into());
        }
    }
    let local = config
        .executor
        .as_ref()
        .and_then(|executor| executor.provenance.as_ref())
        .filter(|_| target == config.node_id)
        .map(|signing| crate::provenance::TrustedSigningKey {
            public_key: signing.public_key.clone(),
        });
    let key = match (config.result_trust.get(target), local.as_ref()) {
        (Some(pinned), Some(local)) if pinned != local => {
            return Err("outbound completion signing trust conflicts".into());
        }
        (Some(pinned), _) => pinned,
        (_, Some(local)) => local,
        _ => return Err("outbound completion requires independent result signing trust".into()),
    };
    let manifest = crate::provenance::verify_result_identity(
        signed,
        key,
        target,
        &config.workspace,
        &job.spec.id,
    )?;
    if manifest.request_sha256 != spec_hash
        || manifest.repository != job.spec.repository
        || manifest.runner != job.spec.runner
        || manifest.state != job.state
        || manifest.exit_code != job.exit_code
        || manifest.error_code != job.error_code
        || Some(&manifest.resolved_revision) != job.resolved_revision.as_ref()
    {
        return Err("outbound signed completion context differs".into());
    }
    submission.completion = Some(Completion::Signed {
        state: manifest.state,
        completed_at_ms: manifest.completed_at_ms,
        signed_result_sha256: crate::provenance::sha256(&serde_json::to_vec(signed)?),
    });
    replace_submission(&submissions, &submission)
}

// A receipt settles only the dispatch/maintenance fence. The error response stays
// an error, so workflow execution cannot consume expired outputs as success.
fn note_expired_terminal(
    config: &NodeConfig,
    target: &str,
    _source_pin: &str,
    reply: &crate::wire::RpcReply<Value>,
) -> Result<()> {
    if !reply
        .error
        .as_ref()
        .is_some_and(|e| e.code == "job_content_expired")
    {
        return Ok(());
    }
    let Some(value) = reply.result.as_ref() else {
        return Ok(());
    };
    if value.get("content_expired").and_then(Value::as_bool) != Some(true)
        || value.get("erasure_committed").and_then(Value::as_bool) != Some(true)
    {
        return Ok(());
    }
    let Some(raw) = value.get("tombstone") else {
        return Ok(());
    };
    let tombstone: crate::retention::JobTombstone = serde_json::from_value(raw.clone())?;
    tombstone.validate()?;
    if value.get("job_id").and_then(Value::as_str) != Some(&tombstone.job_id) {
        return Err("expired completion identity differs".into());
    }
    let (root, routes, submissions) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    let _job_guard = job_lock(&root, &tombstone.job_id)?;
    let path = submissions.join(&tombstone.job_id);
    if !path.try_exists()? {
        return Ok(());
    }
    let mut submission = load_submission(&path)?;
    if submission.completion.is_some() {
        return Ok(());
    }
    let route = load_route(&routes.join(&tombstone.job_id), &tombstone.job_id, target)?
        .ok_or("outbound completion route missing")?;
    if submission.target != target
        || submission.certificate_sha256 != route.certificate_sha256
        || tombstone.submitter != config.node_id
        || submission.source_certificate_sha256.is_none()
        || tombstone.submitter_certificate_sha256 != submission.source_certificate_sha256
        || submission.spec_sha256.as_deref() != Some(&tombstone.spec_sha256)
    {
        return Err("expired completion differs from accepted dispatch".into());
    }
    let local = config
        .executor
        .as_ref()
        .and_then(|e| e.provenance.as_ref())
        .filter(|_| target == config.node_id)
        .map(|s| crate::provenance::TrustedSigningKey {
            public_key: s.public_key.clone(),
        });
    let key = match (config.result_trust.get(target), local.as_ref()) {
        (Some(pinned), Some(local)) if pinned != local => {
            return Err("outbound completion signing trust conflicts".into());
        }
        (Some(pinned), _) => pinned,
        (_, Some(local)) => local,
        _ => return Err("outbound completion requires independent result signing trust".into()),
    };
    let (signed, state, completed_at_ms) = if let Some(raw) =
        value.get("terminal_receipt").filter(|v| !v.is_null())
    {
        let signed: crate::provenance::SignedDocument = serde_json::from_value(raw.clone())?;
        let proof: crate::retention::TerminalReceipt = crate::provenance::verify_document(
            &signed,
            crate::retention::TERMINAL_RECEIPT_DOMAIN,
            key,
        )?;
        if proof.version != 1
            || proof.node_id != target
            || proof.workspace != config.workspace
            || proof.job_id != tombstone.job_id
            || proof.submitter != tombstone.submitter
            || proof.submitter_certificate_sha256 != tombstone.submitter_certificate_sha256
            || proof.request_sha256 != tombstone.spec_sha256
            || proof.outcome != tombstone.outcome
            || Some(proof.completed_at_ms) != tombstone.completed_at_ms
            || proof.completed_at_ms == 0
        {
            return Err("expired terminal receipt context differs".into());
        }
        (signed, proof.outcome, proof.completed_at_ms)
    } else if let Some(signed) = tombstone.result_manifest.as_ref() {
        let manifest = crate::provenance::verify_result_identity(
            signed,
            key,
            target,
            &config.workspace,
            &tombstone.job_id,
        )?;
        if manifest.request_sha256 != tombstone.spec_sha256 || manifest.state != tombstone.outcome {
            return Err("expired signed result context differs".into());
        }
        (signed.clone(), manifest.state, manifest.completed_at_ms)
    } else {
        return Ok(());
    };
    submission.completion = Some(Completion::Signed {
        state,
        completed_at_ms,
        signed_result_sha256: crate::provenance::sha256(&serde_json::to_vec(&signed)?),
    });
    replace_submission(&submissions, &submission)
}

/// Claim the sole original encrypted submit frame before any direct or relay send.
/// A concurrent submit can reconcile this job ID, but cannot renew its admission window.
pub(crate) fn note_delivery_deadline(
    config: &NodeConfig,
    target: &str,
    frame: &crate::wire::RpcFrame,
    payload: &Value,
) -> Result<()> {
    frame.validate()?;
    if frame.kind != crate::wire::FrameKind::Request
        || frame.operation != Operation::JobSubmit
        || frame.source != config.node_id
        || frame.target != target
    {
        return Err("invalid original outbound admission frame".into());
    }
    let created = crate::retention::id_timestamp_ms(&frame.id)?;
    let deadline = frame
        .retention
        .as_ref()
        .ok_or("outbound submit requires explicit content TTL")?
        .expires_at_ms
        .min(created.saturating_add(wire::REQUEST_DELIVERY_TTL_MS));
    let (root, _, submissions) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    // Trusted Host just encrypted this exact payload into frame. The binding is
    // indexed by canonical JobSpec ID; no plaintext is persisted here.
    let spec: crate::wire::JobSpec = serde_json::from_value(payload.clone())?;
    let _job_guard = job_lock(&root, &spec.id)?;
    let mut value = load_submission(&submissions.join(&spec.id))?;
    if value.target != target
        || Some(&value.certificate_sha256) != frame.target_certificate_sha256.as_ref()
        || value.source_certificate_sha256.as_ref() != frame.source_certificate_sha256.as_ref()
        || value.spec_sha256.as_deref()
            != Some(crate::provenance::sha256(&serde_json::to_vec(&spec)?).as_str())
    {
        return Err("original outbound admission frame differs from immutable source, target or specification".into());
    }
    match (&value.delivery_frame_id,value.delivery_deadline_ms) {
        (Some(id),Some(original)) if id==&frame.id&&original==deadline=>return Ok(()),
        (None,None)=>{},
        _=>return Err("outbound job already owns a different original admission frame; reconcile the same job ID".into()),
    }
    if value.completion.is_some() || value.delivery_state != Some(DeliveryState::PreparedV1) {
        return Err(
            "outbound job was already settled; original submission cannot be renewed".into(),
        );
    }
    value.delivery_frame_id = Some(frame.id.clone());
    value.delivery_deadline_ms = Some(deadline);
    value.delivery_state = Some(DeliveryState::RemoteClaimedV1);
    replace_submission(&submissions, &value)
}

// These executor errors are returned while holding the executor job mutex and
// strictly before a new job directory, journal, or execution is created.
fn local_rejection_is_definitive(reason: &str) -> bool {
    matches!(
        reason,
        "job_queue_full" | "submitter_queue_full" | "project_queue_full"
    )
}

/// Serialize local admission with the no-send review on the same job lock.
/// This function and `perform` run together inside one spawn_blocking closure:
/// cancelling the async caller cannot detach an admission from its fence.
pub(crate) fn local_submit<T>(
    config: &NodeConfig,
    spec: &crate::wire::JobSpec,
    perform: impl FnOnce() -> std::result::Result<T, &'static str>,
) -> Result<std::result::Result<T, &'static str>> {
    let (root, _, submissions) = roots(config)?;
    let _guard = dispatch_lock(&root, false)?;
    let _job_guard = job_lock(&root, &spec.id)?;
    let mut value = load_submission(&submissions.join(&spec.id))?;
    let source = PeerPin::certificate(&fs::read(&config.certificate)?).to_hex();
    if value.job_id != spec.id
        || value.target != config.node_id
        || value.certificate_sha256 != source
        || value.source_certificate_sha256.as_deref() != Some(source.as_str())
        || value.spec_sha256.as_deref()
            != Some(crate::provenance::sha256(&serde_json::to_vec(spec)?).as_str())
        || value.delivery_state != Some(DeliveryState::PreparedV1)
        || value.completion.is_some()
    {
        return Err("local dispatch is not an unclaimed exact submission".into());
    }
    value.delivery_state = Some(DeliveryState::LocalClaimedV1);
    replace_submission(&submissions, &value)?;
    let outcome = perform();
    if let Err(reason) = &outcome
        && local_rejection_is_definitive(reason)
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        value.completion = Some(Completion::LocalRejected {
            rejected_at_ms: now,
            reason: (*reason).into(),
        });
        replace_submission(&submissions, &value)?;
    }
    Ok(outcome)
}

/// Review attests only that an operator independently checked/stopped the old
/// execution. It clears a maintenance fence; it creates no signed job success,
/// unlocks no DAG dependency, and sends no remote RPC or retry.
#[cfg(test)]
pub(crate) fn dispatch_control(
    config: &NodeConfig,
    reviewing_source_pin: &str,
    request: DispatchControl,
    now_ms: u64,
) -> Result<Value> {
    dispatch_control_with_local(config, reviewing_source_pin, request, now_ms, None)
}

/// The optional local check runs while holding the job lock used throughout
/// local admission; it must reject queued, running, or uncertain local jobs.
type LocalCheck<'a> = dyn Fn(&str) -> Result<()> + 'a;
pub(crate) fn dispatch_control_with_local(
    config: &NodeConfig,
    reviewing_source_pin: &str,
    request: DispatchControl,
    now_ms: u64,
    local_check: Option<&LocalCheck<'_>>,
) -> Result<Value> {
    if !valid_pin(reviewing_source_pin) || now_ms == 0 {
        return Err("invalid outbound review context".into());
    }
    match request {
        DispatchControl::List { offset, limit } => {
            if !(1..=100).contains(&limit) {
                return Err("dispatch list limit must be 1..100".into());
            }
            let pending = pending_submissions(config)?;
            let total = pending.len();
            if offset > total {
                return Err("dispatch list offset exceeds pending count".into());
            }
            let (_, _, submissions) = roots(config)?;
            let mut items = Vec::new();
            for pending in pending.into_iter().skip(offset).take(limit) {
                let value = load_submission(&submissions.join(&pending.job_id))?;
                items.push(DispatchSummary {
                    job_id: value.job_id,
                    target: value.target,
                    certificate_sha256: value.certificate_sha256,
                    source_certificate_sha256: value.source_certificate_sha256,
                    binding: value.spec_fingerprint,
                    spec_sha256: value.spec_sha256,
                    delivery_state: value.delivery_state,
                    manual_review_after_ms: value
                        .delivery_deadline_ms
                        .map(|deadline| deadline.saturating_add(wire::MAX_CLOCK_SKEW_MS)),
                });
            }
            let next = offset + items.len();
            Ok(
                serde_json::json!({"total":total,"offset":offset,"items":items,"next_offset":(next<total).then_some(next)}),
            )
        }
        DispatchControl::Review {
            job_id,
            target,
            certificate_sha256,
            source_certificate_sha256,
            binding,
            confirm_no_active_execution,
        } => {
            if !confirm_no_active_execution
                || !wire::valid_ulid(&job_id)
                || !wire::valid_name(&target)
                || !valid_pin(&certificate_sha256)
                || !valid_pin(&binding)
                || source_certificate_sha256
                    .as_ref()
                    .is_some_and(|pin| !valid_pin(pin))
            {
                return Err("dispatch review requires exact binding and confirmation of independently stopped execution".into());
            }
            let (root, routes, submissions) = roots(config)?;
            let _guard = dispatch_lock(&root, false)?;
            let _job_guard = job_lock(&root, &job_id)?;
            let mut value = load_submission(&submissions.join(&job_id))?;
            let route = load_route(&routes.join(&job_id), &job_id, &target)?
                .ok_or("dispatch review route missing")?;
            if value.job_id != job_id
                || value.target != target
                || value.certificate_sha256 != certificate_sha256
                || route.certificate_sha256 != certificate_sha256
                || value.source_certificate_sha256 != source_certificate_sha256
                || value.spec_fingerprint != binding
            {
                return Err("dispatch review differs from immutable source, target or specification binding".into());
            }
            if value.completion.is_none() {
                if value.delivery_state == Some(DeliveryState::PreparedV1) {
                    // Under the same lock as either first-delivery claim: after this
                    // durable transition, no local or remote first delivery can start.
                    value.delivery_state = Some(DeliveryState::NeverSentV1);
                } else if value.delivery_state == Some(DeliveryState::LocalClaimedV1)
                    && value.target == config.node_id
                {
                    local_check
                        .ok_or("local admission review requires a stopped executor check")?(
                        &job_id,
                    )?;
                    value.delivery_state = Some(DeliveryState::LocalReviewedV1);
                } else {
                    let deadline=value.delivery_deadline_ms.ok_or("outbound delivery deadline is unknown; a signed remote terminal receipt is required")?;
                    if now_ms < deadline.saturating_add(wire::MAX_CLOCK_SKEW_MS) {
                        return Err("original pending admission window has not expired including clock skew".into());
                    }
                }
                let review = serde_json::json!({"domain":"lockyard-outbound-review-v1","job_id":job_id,"target":target,
                    "certificate_sha256":certificate_sha256,"source_certificate_sha256":source_certificate_sha256,
                    "binding":binding,"reviewing_source_certificate_sha256":reviewing_source_pin,"reviewed_at_ms":now_ms});
                value.completion = Some(Completion::OperatorReviewed {
                    reviewed_at_ms: now_ms,
                    review_sha256: crate::provenance::sha256(&serde_json::to_vec(&review)?),
                    reviewing_source_certificate_sha256: reviewing_source_pin.into(),
                });
                replace_submission(&submissions, &value)?;
            }
            Ok(
                serde_json::json!({"job_id":job_id,"maintenance_fence_cleared":true,
                "job_outcome_verified":matches!(value.completion,Some(Completion::Signed {..})),
                "execution_retried":false,"dependencies_released":false}),
            )
        }
    }
}

#[cfg(windows)]
fn private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    Ok(lockyard_core::windows::read_private(path, limit)?)
}

#[cfg(windows)]
fn directory(path: &Path) -> Result<()> {
    Ok(lockyard_core::windows::private_dir(path)?)
}

#[cfg(windows)]
fn publish(path: &Path, bytes: &[u8]) -> Result<bool> {
    let parent = path.parent().ok_or("invalid incarnation path")?;
    lockyard_core::windows::require_private(parent)?;
    let temporary = parent.join(format!(".incarnation-{}.partial", wire::new_id()?));
    let mut file = lockyard_core::windows::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let result = match lockyard_core::windows::rename_create_only(&temporary, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e.into()),
    };
    let _ = fs::remove_file(temporary);
    result
}

#[cfg(windows)]
fn replace_submission(directory: &Path, submission: &Submission) -> Result<()> {
    Ok(lockyard_core::fsio::replace(
        &directory.join(&submission.job_id),
        &serde_json::to_vec(submission)?,
        0o600,
    )?)
}

#[cfg(windows)]
fn job_lock(root: &Path, job_id: &str) -> Result<File> {
    if !wire::valid_ulid(job_id) {
        return Err("invalid stable outbound job ID".into());
    }
    let dir = root.join("locks");
    directory(&dir)?;
    let stripe = ring::digest::digest(&ring::digest::SHA256, job_id.as_bytes()).as_ref()[0] % 64;
    let file = lockyard_core::windows::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(dir.join(format!("{stripe:02}")))?;
    file.lock()?;
    Ok(file)
}

#[cfg(windows)]
fn dispatch_lock(root: &Path, exclusive: bool) -> Result<File> {
    let file = lockyard_core::windows::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(root.join(".offline-lock"))?;
    if exclusive {
        file.try_lock()
            .map_err(|_| "outbound dispatch reconciliation is active")?;
    } else {
        file.try_lock_shared()
            .map_err(|_| "outbound dispatch reconciliation is active")?;
    }
    Ok(file)
}

#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn encrypted_identity_proof_rejects_cloud_field_substitution_and_wrong_workspace_key() {
        let key = WorkspaceKey::from_entropy([61; 32]);
        let pin = "a".repeat(64);
        let proof = seal_identity("workspace", "worker", &pin, &key).unwrap();
        verify_identity("workspace", "worker", &pin, &proof, &key).unwrap();
        assert!(verify_identity("workspace", "other", &pin, &proof, &key).is_err());
        assert!(verify_identity("workspace", "worker", &"b".repeat(64), &proof, &key).is_err());
        assert!(verify_identity("another", "worker", &pin, &proof, &key).is_err());
        assert!(
            verify_identity(
                "workspace",
                "worker",
                &pin,
                &proof,
                &WorkspaceKey::from_entropy([62; 32])
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn submitted_job_cannot_rebind_to_replacement_or_changed_spec_after_retry() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().to_owned();
        let mut config:NodeConfig=serde_json::from_value(json!({"node_id":"caller","workspace":"workspace","state_dir":state,
            "certificate":state.join("cert"),"private_key":state.join("key"),"peers":[{"node_id":"worker","address":null,"tls_name":"worker.example","certificate_sha256":"a".repeat(64),"certificate":state.join("peer"),"allowed_operations":[]}]})).unwrap();
        let id = wire::new_id().unwrap();
        let spec = json!({"id":id,"repository":"repo","revision":"HEAD","runner":"fixture","arguments":[],"prompt":"PRIVATE-SPEC","timeout_seconds":null});
        assert_eq!(
            target_pin(&config, "worker", Operation::JobSubmit, &spec)
                .await
                .unwrap(),
            Some("a".repeat(64))
        );
        target_pin(&config, "worker", Operation::JobSubmit, &spec)
            .await
            .unwrap();
        let mut changed = spec.clone();
        changed["prompt"] = json!("changed");
        assert!(
            target_pin(&config, "worker", Operation::JobSubmit, &changed)
                .await
                .is_err()
        );
        config.peers[0].certificate_sha256 = "b".repeat(64);
        assert!(
            target_pin(&config, "worker", Operation::JobSubmit, &spec)
                .await
                .is_err()
        );
        let saved = fs::read(state.join("incarnation-bindings/submissions").join(id)).unwrap();
        assert!(
            !saved
                .windows(b"PRIVATE-SPEC".len())
                .any(|window| window == b"PRIVATE-SPEC")
        );
    }
    fn config(state: &Path) -> NodeConfig {
        serde_json::from_value(json!({"node_id":"caller","workspace":"workspace","state_dir":state,
            "certificate":state.join("cert"),"private_key":state.join("key"),
            "peers":[{"node_id":"worker","address":null,"tls_name":"worker.example",
            "certificate_sha256":"a".repeat(64),"certificate":state.join("peer"),"allowed_operations":[]}]})).unwrap()
    }
    #[tokio::test]
    async fn expected_incarnation_is_verified_before_any_mutating_binding() {
        let temp = tempfile::tempdir().unwrap();
        let config = config(temp.path());
        let id = wire::new_id().unwrap();
        let spec = json!({"id":id,"repository":"repo"});
        let origin = DispatchOrigin::Workflow(wire::new_id().unwrap());
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobSubmit,
                &spec,
                Some(&"b".repeat(64)),
                &origin
            )
            .await
            .is_err()
        );
        assert!(!has_binding(&config, &id).unwrap());
        target_pin_bound(
            &config,
            "worker",
            Operation::NodePing,
            &json!({"describe":true}),
            Some(&"a".repeat(64)),
            &origin,
        )
        .await
        .unwrap();
        assert!(!has_binding(&config, &id).unwrap());
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &spec,
            Some(&"a".repeat(64)),
            &origin,
        )
        .await
        .unwrap();
        assert!(has_binding(&config, &id).unwrap());
    }
    #[tokio::test]
    async fn scoped_jobs_cannot_adopt_or_cancel_other_origins() {
        let temp = tempfile::tempdir().unwrap();
        let config = config(temp.path());
        let id = wire::new_id().unwrap();
        let spec = json!({"id":id,"repository":"repo"});
        target_pin(&config, "worker", Operation::JobSubmit, &spec)
            .await
            .unwrap();
        let origin = DispatchOrigin::Job(wire::new_id().unwrap());
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobSubmit,
                &spec,
                None,
                &origin
            )
            .await
            .is_err()
        );
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobCancel,
                &json!({"job_id":id}),
                None,
                &origin
            )
            .await
            .is_err()
        );
        let child = wire::new_id().unwrap();
        let spec = json!({"id":child,"repository":"repo"});
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &spec,
            None,
            &origin,
        )
        .await
        .unwrap();
        target_pin_bound(
            &config,
            "worker",
            Operation::JobCancel,
            &json!({"job_id":child}),
            None,
            &origin,
        )
        .await
        .unwrap();
        let other = DispatchOrigin::Job(wire::new_id().unwrap());
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobCancel,
                &json!({"job_id":child}),
                None,
                &other
            )
            .await
            .is_err()
        );
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobResolveUnknown,
                &json!({"job_id":child}),
                None,
                &origin
            )
            .await
            .is_err()
        );
    }

    #[test]
    #[cfg(unix)]
    fn publication_crash_alias_is_recovered_but_arbitrary_hardlink_is_rejected() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let root = tempfile::tempdir().unwrap();
        let alias = root
            .path()
            .join(format!(".incarnation-{}.partial", wire::new_id().unwrap()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&alias)
            .unwrap();
        file.write_all(b"immutable fixture").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let final_path = root.path().join(wire::new_id().unwrap());
        fs::hard_link(&alias, &final_path).unwrap();
        File::open(root.path()).unwrap().sync_all().unwrap();
        assert_eq!(fs::metadata(&final_path).unwrap().nlink(), 2);
        assert_eq!(private(&final_path, 128).unwrap(), b"immutable fixture");
        assert!(!alias.exists());
        assert_eq!(fs::metadata(&final_path).unwrap().nlink(), 1);
        let arbitrary = root.path().join("arbitrary-alias");
        fs::hard_link(&final_path, &arbitrary).unwrap();
        assert!(private(&final_path, 128).is_err());
        assert!(arbitrary.exists());
    }
    #[cfg(unix)]
    fn signed_terminal(
        config: &mut NodeConfig,
        spec: &crate::wire::JobSpec,
        source_pin: &str,
        key: &crate::provenance::SigningKey,
    ) -> crate::wire::JobRecord {
        config
            .result_trust
            .insert("worker".into(), key.trusted_key());
        let mut record:crate::wire::JobRecord=serde_json::from_value(json!({"spec":spec,"state":"succeeded","agent":"fixture",
            "submitter":"caller","submitter_certificate_sha256":source_pin,"created_at":1000,"updated_at":2000,
            "resolved_revision":"d".repeat(40),"worktree":null,"pid":null,"exit_code":0,"error_code":null,"log_bytes":0,"log_truncated":false})).unwrap();
        let manifest:crate::provenance::ResultManifest=serde_json::from_value(json!({"version":1,"node_id":"worker","workspace":"workspace",
            "job_id":spec.id,"repository":"repo","runner":"fixture","request_sha256":crate::provenance::sha256(&serde_json::to_vec(spec).unwrap()),
            "resolved_revision":"d".repeat(40),"image_reference":format!("sha256:{}","a".repeat(64)),"image_digest":format!("sha256:{}","a".repeat(64)),
            "image_config_digest":null,"image_attestation_sha256":null,"execution_attempted":false,"completed_at_ms":2000,
            "state":"succeeded","exit_code":0,"error_code":null,"artifacts":{}})).unwrap();
        record.result_manifest = Some(key.sign_result(&manifest).unwrap());
        record
    }
    #[tokio::test]
    #[cfg(unix)]
    async fn expired_receipt_settles_only_exact_signed_dispatch_and_legacy_manifest() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let source_pin = PeerPin::certificate(b"synthetic-public-certificate-only").to_hex();
        let key = crate::provenance::SigningKey::generate(&root.path().join("signer.pk8")).unwrap();
        config
            .result_trust
            .insert("worker".into(), key.trusted_key());
        let spec: crate::wire::JobSpec = serde_json::from_value(json!({"id":wire::new_id().unwrap(),"repository":"repo","revision":"HEAD", "runner":"fixture","arguments":[],"prompt":"private fixture","timeout_seconds":null})).unwrap();
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &serde_json::to_value(&spec).unwrap(),
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        let hash = crate::retention::spec_digest(&spec).unwrap();
        let tombstone = crate::retention::JobTombstone {
            version: 1,
            job_id: spec.id.clone(),
            submitter: config.node_id.clone(),
            submitter_certificate_sha256: Some(source_pin.clone()),
            spec_sha256: hash.clone(),
            outcome: crate::wire::JobState::Succeeded,
            terminal_expires_at_ms: 3000,
            purged_at_ms: 3000,
            result_manifest: None,
            completed_at_ms: Some(2000),
        };
        let receipt = crate::retention::TerminalReceipt {
            version: 1,
            node_id: "worker".into(),
            workspace: config.workspace.clone(),
            job_id: spec.id.clone(),
            submitter: config.node_id.clone(),
            submitter_certificate_sha256: Some(source_pin.clone()),
            request_sha256: hash,
            outcome: crate::wire::JobState::Succeeded,
            completed_at_ms: 2000,
        };
        let reply_for = |t: &crate::retention::JobTombstone,
                         r: &crate::retention::TerminalReceipt,
                         k: &crate::provenance::SigningKey| {
            let mut reply = crate::wire::RpcReply::failure("job_content_expired", "expired");
            reply.result = Some(
                json!({"job_id":t.job_id,"content_expired":true,"erasure_committed":true,"tombstone":t,
                "terminal_receipt":k.sign_document(crate::retention::TERMINAL_RECEIPT_DOMAIN,r).unwrap()}),
            );
            reply
        };
        for field in 0..6 {
            let mut bad = receipt.clone();
            match field {
                0 => bad.workspace = "other".into(),
                1 => bad.node_id = "other".into(),
                2 => bad.job_id = wire::new_id().unwrap(),
                3 => bad.submitter = "other".into(),
                4 => bad.submitter_certificate_sha256 = Some("b".repeat(64)),
                _ => bad.request_sha256 = "c".repeat(64),
            }
            assert!(
                note_terminal(
                    &config,
                    "worker",
                    &source_pin,
                    &reply_for(&tombstone, &bad, &key)
                )
                .is_err()
            );
            assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        }
        for field in 0..3 {
            let mut bad = tombstone.clone();
            match field {
                0 => bad.submitter = "other".into(),
                1 => bad.submitter_certificate_sha256 = Some("b".repeat(64)),
                _ => bad.spec_sha256 = "c".repeat(64),
            }
            assert!(
                note_terminal(
                    &config,
                    "worker",
                    &source_pin,
                    &reply_for(&bad, &receipt, &key)
                )
                .is_err()
            );
            assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        }
        let mut unsigned = crate::wire::RpcReply::failure("job_content_expired", "expired");
        unsigned.result = Some(
            json!({"job_id":spec.id,"content_expired":true,"erasure_committed":true,"tombstone":tombstone}),
        );
        note_terminal(&config, "worker", &source_pin, &unsigned).unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        let mut bad = receipt.clone();
        bad.outcome = crate::wire::JobState::Failed;
        assert!(
            note_terminal(
                &config,
                "worker",
                &source_pin,
                &reply_for(&tombstone, &bad, &key)
            )
            .is_err()
        );
        let other =
            crate::provenance::SigningKey::generate(&root.path().join("other.pk8")).unwrap();
        assert!(
            note_terminal(
                &config,
                "worker",
                &source_pin,
                &reply_for(&tombstone, &receipt, &other)
            )
            .is_err()
        );
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        let reply = reply_for(&tombstone, &receipt, &key);
        assert!(!reply.ok);
        note_terminal(&config, "worker", &source_pin, &reply).unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);

        // An older signed result remains usable as terminal evidence, without output access.
        let mut next = spec.clone();
        next.id = wire::new_id().unwrap();
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &serde_json::to_value(&next).unwrap(),
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        let record = signed_terminal(&mut config, &next, &source_pin, &key);
        let legacy = crate::retention::JobTombstone {
            job_id: next.id.clone(),
            spec_sha256: crate::retention::spec_digest(&next).unwrap(),
            result_manifest: record.result_manifest,
            completed_at_ms: None,
            ..tombstone
        };
        let mut reply = crate::wire::RpcReply::failure("job_content_expired", "expired");
        reply.result = Some(
            json!({"job_id":next.id,"content_expired":true,"erasure_committed":true,"tombstone":legacy}),
        );
        note_terminal(&config, "worker", &source_pin, &reply).unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn outbound_maintenance_fence_requires_exact_pinned_signed_terminal_result() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let source_pin = PeerPin::certificate(b"synthetic-public-certificate-only").to_hex();
        let key = crate::provenance::SigningKey::generate(&root.path().join("signer.pk8")).unwrap();
        let spec: crate::wire::JobSpec = serde_json::from_value(
            json!({"id":wire::new_id().unwrap(),"repository":"repo","revision":"HEAD",
            "runner":"fixture","arguments":[],"prompt":"private fixture","timeout_seconds":null}),
        )
        .unwrap();
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &serde_json::to_value(&spec).unwrap(),
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        assert!(offline_dispatch_guard(&config).is_err());
        let record = signed_terminal(&mut config, &spec, &source_pin, &key);
        let mut unsigned = record.clone();
        unsigned.result_manifest = None;
        note_terminal(
            &config,
            "worker",
            &source_pin,
            &crate::wire::RpcReply::success(serde_json::to_value(unsigned).unwrap()),
        )
        .unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        let mut changed = record.clone();
        changed.spec.prompt = Some("changed".into());
        assert!(
            note_terminal(
                &config,
                "worker",
                &source_pin,
                &crate::wire::RpcReply::success(serde_json::to_value(changed).unwrap())
            )
            .is_err()
        );
        let mut unknown = record.clone();
        unknown.state = crate::wire::JobState::InterruptedUnknown;
        note_terminal(
            &config,
            "worker",
            &source_pin,
            &crate::wire::RpcReply::success(serde_json::to_value(unknown).unwrap()),
        )
        .unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        note_terminal(
            &config,
            "worker",
            &source_pin,
            &crate::wire::RpcReply::success(serde_json::to_value(record).unwrap()),
        )
        .unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);
        let guard = offline_dispatch_guard(&config).unwrap();
        let mut next = spec.clone();
        next.id = wire::new_id().unwrap();
        assert!(
            target_pin(
                &config,
                "worker",
                Operation::JobSubmit,
                &serde_json::to_value(next).unwrap()
            )
            .await
            .is_err()
        );
        drop(guard);
    }
    fn original_frame(config: &NodeConfig, payload: &Value) -> crate::wire::RpcFrame {
        let id = wire::new_id().unwrap();
        let created = crate::retention::id_timestamp_ms(&id).unwrap();
        let mut frame = crate::wire::RpcFrame {
            v: wire::PROTOCOL_VERSION,
            kind: crate::wire::FrameKind::Request,
            id,
            source: config.node_id.clone(),
            target: "worker".into(),
            operation: Operation::JobSubmit,
            in_reply_to: None,
            source_certificate_sha256: Some(
                PeerPin::certificate(&fs::read(&config.certificate).unwrap()).to_hex(),
            ),
            target_certificate_sha256: Some("a".repeat(64)),
            retention: Some(
                crate::retention::ContentRetention::for_copy(
                    &crate::retention::RetentionPolicy {
                        content_ttl_seconds: 60,
                    },
                    created,
                    None,
                )
                .unwrap(),
            ),
            payload: String::new(),
        };
        crate::crypto::PayloadCodec::new(
            config.workspace.clone(),
            WorkspaceKey::from_entropy([77; 32]),
        )
        .unwrap()
        .encode(&mut frame, payload)
        .unwrap();
        frame
    }
    #[tokio::test]
    async fn explicit_operator_review_clears_only_exact_maintenance_binding_after_admission_expiry_without_job_success()
     {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let source_pin = PeerPin::certificate(b"synthetic-public-certificate-only").to_hex();
        let spec = json!({"id":wire::new_id().unwrap(),"repository":"repo","revision":"HEAD","runner":"fixture",
            "arguments":[],"prompt":null,"timeout_seconds":null});
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &spec,
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        let listing = dispatch_control(
            &config,
            &"c".repeat(64),
            DispatchControl::List {
                offset: 0,
                limit: 100,
            },
            1000,
        )
        .unwrap();
        let item = &listing["items"][0];
        let request = |binding: String, confirm| DispatchControl::Review {
            job_id: item["job_id"].as_str().unwrap().into(),
            target: "worker".into(),
            certificate_sha256: "a".repeat(64),
            source_certificate_sha256: Some(source_pin.clone()),
            binding,
            confirm_no_active_execution: confirm,
        };
        let frame = original_frame(&config, &spec);
        note_delivery_deadline(&config, "worker", &frame, &spec).unwrap();
        let allowed = frame.retention.as_ref().unwrap().expires_at_ms + wire::MAX_CLOCK_SKEW_MS;
        assert!(
            dispatch_control(
                &config,
                &"c".repeat(64),
                request("d".repeat(64), true),
                allowed
            )
            .is_err()
        );
        assert!(
            dispatch_control(
                &config,
                &"c".repeat(64),
                request(item["binding"].as_str().unwrap().into(), false),
                allowed
            )
            .is_err()
        );
        assert!(
            dispatch_control(
                &config,
                &"c".repeat(64),
                request(item["binding"].as_str().unwrap().into(), true),
                allowed - 1
            )
            .is_err()
        );
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        let result = dispatch_control(
            &config,
            &"c".repeat(64),
            request(item["binding"].as_str().unwrap().into(), true),
            allowed,
        )
        .unwrap();
        assert_eq!(result["maintenance_fence_cleared"], true);
        assert_eq!(result["job_outcome_verified"], false);
        assert_eq!(result["dependencies_released"], false);
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);
        let receipt: Submission = load_submission(
            &root
                .path()
                .join("incarnation-bindings/submissions")
                .join(item["job_id"].as_str().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            receipt.completion,
            Some(Completion::OperatorReviewed { .. })
        ));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_first_submits_claim_one_original_frame_and_cannot_renew_delivery() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let spec = json!({"id":wire::new_id().unwrap(),"repository":"repo","revision":"HEAD","runner":"fixture",
            "arguments":[],"prompt":null,"timeout_seconds":null});
        target_pin(&config, "worker", Operation::JobSubmit, &spec)
            .await
            .unwrap();
        let a = original_frame(&config, &spec);
        let b = original_frame(&config, &spec);
        let call = |frame: crate::wire::RpcFrame| {
            let config = config.clone();
            let spec = spec.clone();
            tokio::task::spawn_blocking(move || {
                note_delivery_deadline(&config, "worker", &frame, &spec)
            })
        };
        let (a_result, b_result) = tokio::join!(call(a.clone()), call(b.clone()));
        assert_eq!(
            usize::from(a_result.unwrap().is_ok()) + usize::from(b_result.unwrap().is_ok()),
            1
        );
        let value = load_submission(
            &root
                .path()
                .join("incarnation-bindings/submissions")
                .join(spec["id"].as_str().unwrap()),
        )
        .unwrap();
        let original = if value.delivery_frame_id.as_ref() == Some(&a.id) {
            a
        } else {
            b
        };
        note_delivery_deadline(&config, "worker", &original, &spec).unwrap();
        let mut renewed = original.clone();
        renewed.retention.as_mut().unwrap().expires_at_ms += 1000;
        renewed.retention.as_mut().unwrap().content_ttl_seconds += 1;
        assert!(note_delivery_deadline(&config, "worker", &renewed, &spec).is_err());
        let preserved = load_submission(
            &root
                .path()
                .join("incarnation-bindings/submissions")
                .join(spec["id"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(preserved.delivery_deadline_ms, value.delivery_deadline_ms);
    }

    #[tokio::test]
    async fn prepared_no_send_review_fences_late_claim_and_legacy_remains_closed() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let source_pin = PeerPin::certificate(b"synthetic-public-certificate-only").to_hex();
        let spec = json!({"id":wire::new_id().unwrap(),"repository":"repo","revision":"HEAD","runner":"fixture",
            "arguments":[],"prompt":null,"timeout_seconds":null});
        target_pin(&config, "worker", Operation::JobSubmit, &spec)
            .await
            .unwrap();
        let path = root
            .path()
            .join("incarnation-bindings/submissions")
            .join(spec["id"].as_str().unwrap());
        let mut entry = load_submission(&path).unwrap();
        let request = || DispatchControl::Review {
            job_id: entry.job_id.clone(),
            target: entry.target.clone(),
            certificate_sha256: entry.certificate_sha256.clone(),
            source_certificate_sha256: Some(source_pin.clone()),
            binding: entry.spec_fingerprint.clone(),
            confirm_no_active_execution: true,
        };
        // Old records lacking the state cannot establish that no frame was sent.
        entry.delivery_state = None;
        replace_submission(path.parent().unwrap(), &entry).unwrap();
        assert!(dispatch_control(&config, &source_pin, request(), u64::MAX).is_err());
        entry.delivery_state = Some(DeliveryState::PreparedV1);
        replace_submission(path.parent().unwrap(), &entry).unwrap();
        dispatch_control(&config, &source_pin, request(), 1000).unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);
        assert!(
            note_delivery_deadline(&config, "worker", &original_frame(&config, &spec), &spec)
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prepared_review_and_first_frame_have_exactly_one_winner() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let pin = PeerPin::certificate(b"synthetic-public-certificate-only").to_hex();
        let spec = json!({"id":wire::new_id().unwrap(),"repository":"repo","revision":"HEAD","runner":"fixture",
            "arguments":[],"prompt":null,"timeout_seconds":null});
        target_pin(&config, "worker", Operation::JobSubmit, &spec)
            .await
            .unwrap();
        let entry = load_submission(
            &root
                .path()
                .join("incarnation-bindings/submissions")
                .join(spec["id"].as_str().unwrap()),
        )
        .unwrap();
        let review = DispatchControl::Review {
            job_id: entry.job_id,
            target: entry.target,
            certificate_sha256: entry.certificate_sha256,
            source_certificate_sha256: Some(pin.clone()),
            binding: entry.spec_fingerprint,
            confirm_no_active_execution: true,
        };
        let frame = original_frame(&config, &spec);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let review_barrier = barrier.clone();
        let review_config = config.clone();
        let review = tokio::task::spawn_blocking(move || {
            review_barrier.wait();
            dispatch_control(&review_config, &pin, review, 1)
        });
        let claim_config = config.clone();
        let claim = tokio::task::spawn_blocking(move || {
            barrier.wait();
            note_delivery_deadline(&claim_config, "worker", &frame, &spec)
        });
        let (review, claim) = tokio::join!(review, claim);
        assert_ne!(review.unwrap().is_ok(), claim.unwrap().is_ok());
    }

    #[tokio::test]
    async fn local_quota_rejection_is_durable_and_cannot_reopen_admission() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let spec: crate::wire::JobSpec = serde_json::from_value(json!({"id":wire::new_id().unwrap(),
            "repository":"repo","revision":"HEAD","runner":"fixture","arguments":[],"prompt":null,"timeout_seconds":null})).unwrap();
        target_pin_bound(
            &config,
            &config.node_id,
            Operation::JobSubmit,
            &serde_json::to_value(&spec).unwrap(),
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        let outcome = local_submit::<()>(&config, &spec, || Err("project_queue_full")).unwrap();
        assert_eq!(outcome, Err("project_queue_full"));
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);
        assert!(offline_dispatch_guard(&config).is_ok());
        assert!(local_submit(&config, &spec, || Ok(())).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_admission_outlives_cancelled_waiter_and_review_cannot_overtake_it() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        fs::write(&config.certificate, b"synthetic-public-certificate-only").unwrap();
        let pin = PeerPin::certificate(b"synthetic-public-certificate-only").to_hex();
        let spec: crate::wire::JobSpec = serde_json::from_value(json!({"id":wire::new_id().unwrap(),
            "repository":"repo","revision":"HEAD","runner":"fixture","arguments":[],"prompt":null,"timeout_seconds":null})).unwrap();
        target_pin_bound(
            &config,
            &config.node_id,
            Operation::JobSubmit,
            &serde_json::to_value(&spec).unwrap(),
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        let entry = load_submission(
            &root
                .path()
                .join("incarnation-bindings/submissions")
                .join(&spec.id),
        )
        .unwrap();
        let review = DispatchControl::Review {
            job_id: spec.id.clone(),
            target: config.node_id.clone(),
            certificate_sha256: pin.clone(),
            source_certificate_sha256: Some(pin.clone()),
            binding: entry.spec_fingerprint,
            confirm_no_active_execution: true,
        };
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let local_config = config.clone();
        let spec_after = spec.clone();
        let waiter = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                local_submit::<()>(&local_config, &spec, || {
                    started_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    Err("executor_failed")
                })
            })
            .await
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        // Aborting a waiter does not stop spawn_blocking; the held journal lock
        // must continue to exclude review until admission itself has finished.
        waiter.abort();
        let review_config = config.clone();
        let reviewing_pin = pin.clone();
        let reviewing_request = review.clone();
        let mut reviewing = tokio::task::spawn_blocking(move || {
            dispatch_control_with_local(
                &review_config,
                &reviewing_pin,
                reviewing_request,
                u64::MAX,
                Some(&|_| Err("local execution remains queued".into())),
            )
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut reviewing)
                .await
                .is_err()
        );
        release_tx.send(()).unwrap();
        assert!(reviewing.await.unwrap().is_err());
        assert_eq!(unresolved_dispatches(&config).unwrap(), 1);
        // After admission has returned, only a successful executor check may
        // settle this claim, and the fenced job can never be submitted again.
        dispatch_control_with_local(&config, &pin, review, 1, Some(&|_| Ok(()))).unwrap();
        assert_eq!(unresolved_dispatches(&config).unwrap(), 0);
        assert!(local_submit(&config, &spec_after, || Ok(())).is_err());
    }

    #[tokio::test]
    async fn workflow_status_cannot_adopt_an_operator_or_other_flow_job_with_identical_spec() {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path());
        let spec = json!({"id":wire::new_id().unwrap(),"repository":"repo"});
        target_pin(&config, "worker", Operation::JobSubmit, &spec)
            .await
            .unwrap();
        let read = json!({"job_id":spec["id"]});
        let origin = DispatchOrigin::Workflow(wire::new_id().unwrap());
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobStatus,
                &read,
                None,
                &origin
            )
            .await
            .is_err()
        );
        // Ordinary delegated workspace reads remain readable; only adoption by a DAG is restricted.
        target_pin_bound(
            &config,
            "worker",
            Operation::JobStatus,
            &read,
            None,
            &DispatchOrigin::Job(wire::new_id().unwrap()),
        )
        .await
        .unwrap();
        let owned = json!({"id":wire::new_id().unwrap(),"repository":"repo"});
        target_pin_bound(
            &config,
            "worker",
            Operation::JobSubmit,
            &owned,
            None,
            &origin,
        )
        .await
        .unwrap();
        target_pin_bound(
            &config,
            "worker",
            Operation::JobStatus,
            &json!({"job_id":owned["id"]}),
            None,
            &origin,
        )
        .await
        .unwrap();
        assert!(
            target_pin_bound(
                &config,
                "worker",
                Operation::JobStatus,
                &json!({"job_id":owned["id"]}),
                None,
                &DispatchOrigin::Workflow(wire::new_id().unwrap())
            )
            .await
            .is_err()
        );
    }
}
