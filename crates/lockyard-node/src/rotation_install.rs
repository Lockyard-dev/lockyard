// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Offline, forward-only workspace-key installation. Cryptographic authorization is verified by
//! `rotation` before calling this module. A pending journal prevents daemon startup after a crash.
use crate::{
    host::NodeConfig,
    provenance::sha256,
    wire::{self, JobRecord},
};
use lockyard_cloud_client::WorkspaceKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const PENDING: &str = "workspace-rotation.pending.json";
const INSTALLED: &str = "workspace-rotation-state.json";
const MAX_JOURNAL: u64 = 8 * 1024 * 1024;
const MAX_CONFIG: u64 = 1024 * 1024;
const MAX_RECORD: u64 = 4 * 1024 * 1024;
const MAX_JOBS: usize = 100_000;
type Result<T> = std::result::Result<T, InstallError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallError(pub &'static str);
impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for InstallError {}
fn io(_: std::io::Error) -> InstallError {
    InstallError("rotation_install_io")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryPolicy {
    RetainPrivateHistory,
    Discard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedPeer {
    pub node_id: String,
    pub certificate_sha256: String,
}

/// Contains only public plan metadata and opaque capsules. It never contains key entropy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallMetadata {
    pub workspace: String,
    pub node_id: String,
    pub epoch: u64,
    pub old_key_id: String,
    pub new_key_id: String,
    pub plan_sha256: String,
    pub history_policy: HistoryPolicy,
    pub approved_peers: Vec<ApprovedPeer>,
    /// Exact signed bundle, retained so the public recovery command can reverify the authority pin.
    pub signed_plan_json: String,
}
impl InstallMetadata {
    fn validate(&self) -> Result<()> {
        if !wire::valid_name(&self.workspace)
            || !wire::valid_name(&self.node_id)
            || self.epoch == 0
            || !valid_key_id(&self.old_key_id)
            || !valid_key_id(&self.new_key_id)
            || self.old_key_id == self.new_key_id
            || !valid_digest(&self.plan_sha256)
            || self.approved_peers.is_empty()
            || self.approved_peers.len() > 512
            || self.signed_plan_json.is_empty()
            || self.signed_plan_json.len() > 4 * 1024 * 1024
        {
            return Err(InstallError("invalid_rotation_install_metadata"));
        }
        let mut previous: Option<&str> = None;
        let mut pins = BTreeSet::new();
        for peer in &self.approved_peers {
            if !wire::valid_name(&peer.node_id)
                || !valid_digest(&peer.certificate_sha256)
                || previous.is_some_and(|p| p >= peer.node_id.as_str())
                || !pins.insert(&peer.certificate_sha256)
            {
                return Err(InstallError("invalid_rotation_approved_roster"));
            }
            previous = Some(&peer.node_id);
        }
        if !self
            .approved_peers
            .iter()
            .any(|peer| peer.node_id == self.node_id)
        {
            return Err(InstallError("rotation_recipient_excluded"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledState {
    pub version: u8,
    pub workspace: String,
    pub node_id: String,
    pub epoch: u64,
    pub previous_key_id: String,
    pub current_key_id: String,
    pub plan_sha256: String,
    pub history_policy: HistoryPolicy,
    pub approved_peers: Vec<ApprovedPeer>,
    pub direct_peer_count: usize,
    pub direct_certificates_reconciled: bool,
}
impl InstalledState {
    fn from_metadata(metadata: &InstallMetadata, direct_peer_count: usize) -> Self {
        Self {
            version: 1,
            workspace: metadata.workspace.clone(),
            node_id: metadata.node_id.clone(),
            epoch: metadata.epoch,
            previous_key_id: metadata.old_key_id.clone(),
            current_key_id: metadata.new_key_id.clone(),
            plan_sha256: metadata.plan_sha256.clone(),
            history_policy: metadata.history_policy,
            approved_peers: metadata.approved_peers.clone(),
            direct_peer_count,
            direct_certificates_reconciled: true,
        }
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !wire::valid_name(&self.workspace)
            || !wire::valid_name(&self.node_id)
            || self.epoch == 0
            || !valid_key_id(&self.previous_key_id)
            || !valid_key_id(&self.current_key_id)
            || self.previous_key_id == self.current_key_id
            || !valid_digest(&self.plan_sha256)
            || self.approved_peers.len() > 512
            || self.direct_peer_count >= self.approved_peers.len()
            || !self.direct_certificates_reconciled
        {
            return Err(InstallError("invalid_installed_rotation_state"));
        }
        let mut nodes = BTreeSet::new();
        let mut pins = BTreeSet::new();
        for peer in &self.approved_peers {
            if !wire::valid_name(&peer.node_id)
                || !valid_digest(&peer.certificate_sha256)
                || !nodes.insert(&peer.node_id)
                || !pins.insert(&peer.certificate_sha256)
            {
                return Err(InstallError("invalid_installed_rotation_state"));
            }
        }
        if !nodes.contains(&self.node_id) {
            return Err(InstallError("invalid_installed_rotation_state"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    metadata: InstallMetadata,
    config_path: PathBuf,
    key_path: PathBuf,
    old_key_sha256: String,
    new_key_sha256: String,
    old_config_sha256: String,
    new_config_sha256: String,
    direct_peer_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalState {
    version: u8,
    workspace: String,
    epoch: u64,
    previous_key_id: String,
    previous_key_sha256: String,
    current_key_id: String,
    current_key_sha256: String,
    plan_sha256: String,
    history_policy: HistoryPolicy,
    approved_peers: Vec<ApprovedPeer>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalPending {
    version: u8,
    state_dir: PathBuf,
    workspace: String,
    epoch: u64,
    plan_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    journal: Option<Box<Journal>>,
}
/// Retain for the entire host lifetime. Every host sharing a workspace key must hold this lock.
pub struct KeyReadGuard {
    _file: File,
}

#[cfg(unix)]
pub fn guard_workspace_key(key_path: &Path) -> Result<KeyReadGuard> {
    require_parent(key_path)?;
    let file = open_lock(&key_path.with_extension("rotation.lock"))?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(InstallError("workspace_rotation_installing"));
    }
    Ok(KeyReadGuard { _file: file })
}

/// Call while holding `KeyReadGuard`, before loading the key or constructing any executor.
/// Shared key files can serve several local node states; each state must apply the signed plan.
pub fn require_global_binding(config: &NodeConfig, key_path: &Path) -> Result<()> {
    require_no_pending(&config.state_dir)?;
    require_no_global_pending(key_path)?;
    let Some(global) = read_global(key_path)? else {
        if read_installed(&config.state_dir)?.is_some() {
            return Err(InstallError("rotation_global_state_missing"));
        }
        return Ok(());
    };
    let key = read_current_key(key_path)?;
    let local = read_installed(&config.state_dir)?
        .ok_or(InstallError("rotation_local_state_update_required"))?;
    if global.workspace != config.workspace
        || local.workspace != config.workspace
        || local.node_id != config.node_id
        || local.epoch != global.epoch
        || local.plan_sha256 != global.plan_sha256
        || local.current_key_id != global.current_key_id
        || local.approved_peers != global.approved_peers
        || sha256(key.as_ref()) != global.current_key_sha256
        || WorkspaceKey::from_entropy(*key).key_id() != global.current_key_id
    {
        return Err(InstallError("rotation_local_state_update_required"));
    }
    validate_direct_trust(config, &global.approved_peers, local.direct_peer_count)
}

/// Standalone executors do not accept direct TLS peers. Bind their supplied key context to the
/// installed node/workspace epoch and retain a shared key lock when a persisted workspace exists.
/// An in-memory-only executor without persisted workspace state remains usable for local fixtures.
pub fn guard_executor_workspace_key(
    node_state_dir: &Path,
    node_id: &str,
    workspace: &str,
    key: &WorkspaceKey,
) -> Result<Option<KeyReadGuard>> {
    require_no_pending(node_state_dir)?;
    let key_path = WorkspaceKey::storage_path(workspace)
        .map_err(|_| InstallError("rotation_invalid_workspace_key_path"))?;
    guard_executor_workspace_key_at(node_state_dir, node_id, workspace, &key_path, key)
}
fn guard_executor_workspace_key_at(
    node_state_dir: &Path,
    node_id: &str,
    workspace: &str,
    key_path: &Path,
    key: &WorkspaceKey,
) -> Result<Option<KeyReadGuard>> {
    require_no_pending(node_state_dir)?;
    let local = read_installed(node_state_dir)?;
    let key_parent = key_path
        .parent()
        .ok_or(InstallError("rotation_invalid_path"))?;
    if missing(key_parent)? {
        if local.is_some() {
            return Err(InstallError("rotation_global_state_missing"));
        }
        return Ok(None);
    }
    let guard = guard_workspace_key(key_path)?;
    require_no_global_pending(key_path)?;
    let Some(global) = read_global(key_path)? else {
        if local.is_some() {
            return Err(InstallError("rotation_global_state_missing"));
        }
        return Ok(Some(guard));
    };
    let local = local.ok_or(InstallError("rotation_local_state_update_required"))?;
    let current = read_current_key(key_path)?;
    if global.workspace != workspace
        || local.workspace != workspace
        || local.node_id != node_id
        || local.epoch != global.epoch
        || local.plan_sha256 != global.plan_sha256
        || local.approved_peers != global.approved_peers
        || local.current_key_id != global.current_key_id
        || key.key_id() != global.current_key_id
        || sha256(current.as_ref()) != global.current_key_sha256
        || !global
            .approved_peers
            .iter()
            .any(|peer| peer.node_id == node_id)
    {
        return Err(InstallError("rotation_executor_state_update_required"));
    }
    Ok(Some(guard))
}

/// Call under the host state lock and before reading a workspace key or opening the Executor.
/// Any marker, including malformed or unsafe markers, blocks startup until explicit recovery.
pub fn require_no_pending(state_dir: &Path) -> Result<()> {
    match fs::symlink_metadata(state_dir.join(PENDING)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InstallError("rotation_pending_state_unavailable")),
        Ok(_) => Err(InstallError("workspace_rotation_recovery_required")),
    }
}

pub fn read_installed(state_dir: &Path) -> Result<Option<InstalledState>> {
    require_directory(state_dir)?;
    let path = state_dir.join(INSTALLED);
    if missing(&path)? {
        return Ok(None);
    }
    let state: InstalledState = serde_json::from_slice(&read_private(&path, MAX_CONFIG)?)
        .map_err(|_| InstallError("invalid_installed_rotation_state"))?;
    state.validate()?;
    Ok(Some(state))
}

pub(crate) fn pending_metadata(state_dir: &Path) -> Result<Option<InstallMetadata>> {
    require_directory(state_dir)?;
    if missing(&state_dir.join(PENDING))? {
        return Ok(None);
    }
    let journal = read_journal(state_dir)?;
    Ok(Some(journal.metadata))
}

/// Caller must verify the signed authority, recipient capsule and current binding first.
/// All local daemons sharing this workspace key must be stopped before invoking installation.
pub(crate) fn install_verified(
    config_path: &Path,
    key_path: &Path,
    new_entropy: &[u8; 32],
    metadata: &InstallMetadata,
) -> Result<InstalledState> {
    metadata.validate()?;
    let (mut config, original_config) = load_config(config_path)?;
    check_config_binding(&config, metadata)?;
    let _locks = acquire_locks(&config, key_path)?;
    require_no_pending(&config.state_dir)?;
    require_no_global_pending(key_path)?;
    require_drained(&config)?;
    inspect_jobs(&config)?;
    let previous = read_installed(&config.state_dir)?;
    let global = read_global(key_path)?;
    if previous.is_some() && global.is_none() {
        return Err(InstallError("rotation_global_state_missing"));
    }
    let old_entropy = read_current_key(key_path)?;
    let old_key_id = WorkspaceKey::from_entropy(*old_entropy).key_id();
    let new_key_id = WorkspaceKey::from_entropy(*new_entropy).key_id();
    if new_key_id != metadata.new_key_id {
        return Err(InstallError("rotation_new_key_mismatch"));
    }
    if let Some(state) = &previous {
        if state.workspace != metadata.workspace || state.node_id != metadata.node_id {
            return Err(InstallError("rotation_state_identity_mismatch"));
        }
        if state.epoch == metadata.epoch
            && state.plan_sha256 == metadata.plan_sha256
            && state.current_key_id == new_key_id
            && old_entropy.as_ref() == new_entropy
        {
            require_global_binding(&config, key_path)?;
            return Ok(state.clone());
        }
    }
    let expected_epoch = previous.map_or(Some(1), |state| state.epoch.checked_add(1));
    if expected_epoch != Some(metadata.epoch) {
        return Err(InstallError("rotation_epoch_conflict"));
    }
    let shared_already_installed = global
        .as_ref()
        .is_some_and(|global| global_matches(global, metadata, &sha256(new_entropy)));
    if !shared_already_installed && old_key_id != metadata.old_key_id {
        return Err(InstallError("rotation_old_key_mismatch"));
    }
    if shared_already_installed && old_entropy.as_ref() != new_entropy {
        return Err(InstallError("rotation_shared_key_conflict"));
    }
    if let Some(global) = &global
        && !shared_already_installed
        && (global.epoch.checked_add(1) != Some(metadata.epoch)
            || global.workspace != metadata.workspace
            || global.current_key_id != old_key_id
            || global.current_key_sha256 != sha256(old_entropy.as_ref()))
    {
        return Err(InstallError("rotation_global_epoch_conflict"));
    }
    reconcile_direct_trust(&mut config, metadata)?;
    let replacement_config = toml::to_string(&config)
        .map_err(|_| InstallError("rotation_config_encoding_failed"))?
        .into_bytes();
    if replacement_config.len() as u64 > MAX_CONFIG {
        return Err(InstallError("rotation_config_too_large"));
    }
    let journal = Journal {
        version: 1,
        metadata: metadata.clone(),
        config_path: config_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        old_key_sha256: if shared_already_installed {
            global
                .as_ref()
                .ok_or(InstallError("rotation_global_state_missing"))?
                .previous_key_sha256
                .clone()
        } else {
            sha256(old_entropy.as_ref())
        },
        new_key_sha256: sha256(new_entropy),
        old_config_sha256: sha256(&original_config),
        new_config_sha256: sha256(&replacement_config),
        direct_peer_count: config.peers.len(),
    };
    let encoded = serde_json::to_vec(&journal)
        .map_err(|_| InstallError("rotation_journal_encoding_failed"))?;
    if encoded.len() as u64 > MAX_JOURNAL {
        return Err(InstallError("rotation_journal_too_large"));
    }
    claim_global_intent(&config, &journal)?;
    create_private(&config.state_dir.join(PENDING), &encoded)?;
    finish(&config, &journal, new_entropy)
}

/// The caller must reverify `metadata.signed_plan_json` against the pinned rotation authority.
/// This accepts exactly the already-verified metadata, never a journal's self-asserted authority.
pub(crate) fn recover(
    config_path: &Path,
    key_path: &Path,
    new_entropy: &[u8; 32],
    metadata: &InstallMetadata,
) -> Result<InstalledState> {
    metadata.validate()?;
    let (config, _) = load_config(config_path)?;
    check_config_binding(&config, metadata)?;
    let _locks = acquire_locks(&config, key_path)?;
    require_drained(&config)?;
    inspect_jobs(&config)?;
    let journal = if missing(&config.state_dir.join(PENDING))? {
        let global = read_global_intent(key_path)?;
        if global.state_dir != config.state_dir
            || global.workspace != metadata.workspace
            || global.epoch != metadata.epoch
            || global.plan_sha256 != metadata.plan_sha256
        {
            return Err(InstallError("rotation_other_node_recovery_required"));
        }
        *global
            .journal
            .ok_or(InstallError("rotation_global_intent_missing_journal"))?
    } else {
        read_journal(&config.state_dir)?
    };
    if journal.metadata != *metadata
        || journal.config_path != config_path
        || journal.key_path != key_path
    {
        return Err(InstallError("rotation_recovery_binding_mismatch"));
    }
    if missing(&config.state_dir.join(PENDING))? {
        create_private(
            &config.state_dir.join(PENDING),
            &serde_json::to_vec(&journal)
                .map_err(|_| InstallError("rotation_journal_encoding_failed"))?,
        )?;
    }
    finish(&config, &journal, new_entropy)
}

fn finish(
    config: &NodeConfig,
    journal: &Journal,
    new_entropy: &[u8; 32],
) -> Result<InstalledState> {
    validate_journal(journal)?;
    // A prior publication may have returned an error after rename but before directory fsync.
    // Re-establish both local and shared recovery fences before any forward-only key replacement.
    sync_private_path(&config.state_dir.join(PENDING))?;
    if let Some(installed) = read_installed(&config.state_dir)? {
        if installed.epoch.checked_add(1) != Some(journal.metadata.epoch)
            && !(installed.epoch == journal.metadata.epoch
                && installed.plan_sha256 == journal.metadata.plan_sha256)
        {
            return Err(InstallError("rotation_recovery_epoch_conflict"));
        }
    } else if journal.metadata.epoch != 1 {
        return Err(InstallError("rotation_recovery_epoch_conflict"));
    }
    if let Some(global) = read_global(&journal.key_path)?
        && !global_matches(&global, &journal.metadata, &journal.new_key_sha256)
        && !(global.epoch.checked_add(1) == Some(journal.metadata.epoch)
            && global.workspace == journal.metadata.workspace
            && global.current_key_id == journal.metadata.old_key_id
            && global.current_key_sha256 == journal.old_key_sha256)
    {
        return Err(InstallError("rotation_recovery_global_epoch_conflict"));
    }
    let current_key = read_current_key(&journal.key_path)?;
    let current_key_sha256 = sha256(current_key.as_ref());
    let current_key_id = WorkspaceKey::from_entropy(*current_key).key_id();
    let old = current_key_sha256 == journal.old_key_sha256
        && current_key_id == journal.metadata.old_key_id;
    let new = current_key_sha256 == journal.new_key_sha256
        && current_key_id == journal.metadata.new_key_id;
    if !old && !new {
        return Err(InstallError("rotation_recovery_key_conflict"));
    }
    let current_config = read_private(&journal.config_path, MAX_CONFIG)?;
    let config_sha256 = sha256(&current_config);
    if config_sha256 != journal.old_config_sha256 && config_sha256 != journal.new_config_sha256 {
        return Err(InstallError("rotation_recovery_config_conflict"));
    }
    if sha256(new_entropy) != journal.new_key_sha256
        || WorkspaceKey::from_entropy(*new_entropy).key_id() != journal.metadata.new_key_id
    {
        return Err(InstallError(
            "rotation_recovery_new_key_commitment_mismatch",
        ));
    }
    // The full signed-plan intent and global owner fence precede every secret staging byte.
    let pending_path = global_pending_path(&journal.key_path);
    claim_global_intent(config, journal)?;
    if old {
        let path = key_stage(journal)?;
        if !missing(&path)? {
            let staged = read_key(&path)?;
            if sha256(staged.as_ref()) != journal.new_key_sha256
                || WorkspaceKey::from_entropy(*staged).key_id() != journal.metadata.new_key_id
            {
                return Err(InstallError("rotation_recovery_staged_key_conflict"));
            }
        }
        write_stage(&path, new_entropy)?;
    }
    if config_sha256 != journal.new_config_sha256 {
        let path = config_stage(journal)?;
        if !missing(&path)?
            && sha256(&read_private(&path, MAX_CONFIG)?) != journal.new_config_sha256
        {
            return Err(InstallError("rotation_recovery_staged_config_conflict"));
        }
        let mut replacement = config.clone();
        reconcile_direct_trust(&mut replacement, &journal.metadata)?;
        let bytes = toml::to_string(&replacement)
            .map_err(|_| InstallError("rotation_config_encoding_failed"))?
            .into_bytes();
        if sha256(&bytes) != journal.new_config_sha256 {
            return Err(InstallError(
                "rotation_recovery_config_reconstruction_conflict",
            ));
        }
        write_stage(&path, &bytes)?;
    }
    if journal.metadata.history_policy == HistoryPolicy::RetainPrivateHistory {
        if old {
            retain_history(&journal.key_path, &journal.metadata, current_key.as_ref())?;
        } else if sha256(read_key(&history_path(&journal.key_path, &journal.metadata)?)?.as_ref())
            != journal.old_key_sha256
        {
            return Err(InstallError("rotation_private_history_missing"));
        }
    }

    if old {
        let staged = read_key(&key_stage(journal)?)?;
        if sha256(staged.as_ref()) != journal.new_key_sha256
            || WorkspaceKey::from_entropy(*staged).key_id() != journal.metadata.new_key_id
        {
            return Err(InstallError("rotation_recovery_staged_key_conflict"));
        }
        replace_inner(&key_stage(journal)?, &journal.key_path, true)?;
    }
    if config_sha256 != journal.new_config_sha256 {
        if sha256(&read_private(&config_stage(journal)?, MAX_CONFIG)?) != journal.new_config_sha256
        {
            return Err(InstallError("rotation_recovery_staged_config_conflict"));
        }
        replace(&config_stage(journal)?, &journal.config_path)?;
    }
    // Validate the installed configuration before publishing completion. Keys are never rolled back.
    let (installed_config, _) = load_config(&journal.config_path)?;
    check_config_binding(&installed_config, &journal.metadata)?;
    if installed_config.peers.len() != journal.direct_peer_count {
        return Err(InstallError("rotation_recovery_peer_conflict"));
    }
    let state = InstalledState::from_metadata(&journal.metadata, journal.direct_peer_count);
    state.validate()?;
    validate_direct_trust(
        &installed_config,
        &journal.metadata.approved_peers,
        journal.direct_peer_count,
    )?;
    let global = global_from_journal(journal);
    atomic_write(
        &global_state_path(&journal.key_path),
        &serde_json::to_vec(&global).map_err(|_| InstallError("rotation_state_encoding_failed"))?,
    )?;
    atomic_write(
        &config.state_dir.join(INSTALLED),
        &serde_json::to_vec(&state).map_err(|_| InstallError("rotation_state_encoding_failed"))?,
    )?;
    // Clean up the private current-key staging copy before journal recovery is declared complete.
    remove_stage_if_present(&key_stage(journal)?)?;
    remove_stage_if_present(&config_stage(journal)?)?;
    fs::remove_file(config.state_dir.join(PENDING)).map_err(io)?;
    sync_directory(&config.state_dir)?;
    #[cfg(test)]
    if MARKER_CLEAR_FAULT.with(|fault| fault.replace(false)) {
        return Err(InstallError("rotation_injected_after_local_marker_clear"));
    }
    // The shared fence is the first committed marker and the last marker removed.
    // A crash here leaves a recoverable global-only intent and blocks all sibling states.
    fs::remove_file(&pending_path).map_err(io)?;
    sync_directory(
        pending_path
            .parent()
            .ok_or(InstallError("rotation_invalid_path"))?,
    )?;
    Ok(state)
}

pub(crate) fn global_preparation_pending(key_path: &Path) -> Result<bool> {
    Ok(!missing(&global_pending_path(key_path))?)
}
fn read_global_intent(key_path: &Path) -> Result<GlobalPending> {
    serde_json::from_slice(&read_private(&global_pending_path(key_path), MAX_JOURNAL)?)
        .map_err(|_| InstallError("rotation_invalid_global_pending"))
}
fn claim_global_intent(config: &NodeConfig, journal: &Journal) -> Result<()> {
    let expected = GlobalPending {
        version: 1,
        state_dir: config.state_dir.clone(),
        workspace: journal.metadata.workspace.clone(),
        epoch: journal.metadata.epoch,
        plan_sha256: journal.metadata.plan_sha256.clone(),
        journal: Some(Box::new(journal.clone())),
    };
    let path = global_pending_path(&journal.key_path);
    let bytes = serde_json::to_vec(&expected)
        .map_err(|_| InstallError("rotation_state_encoding_failed"))?;
    if missing(&path)? {
        create_private(&path, &bytes)?;
    } else {
        let current = read_global_intent(&journal.key_path)?;
        if current.version != expected.version
            || current.state_dir != expected.state_dir
            || current.workspace != expected.workspace
            || current.epoch != expected.epoch
            || current.plan_sha256 != expected.plan_sha256
            || current
                .journal
                .as_deref()
                .is_some_and(|stored| stored != journal)
        {
            return Err(InstallError("rotation_other_node_recovery_required"));
        }
        if current.journal.is_none() {
            atomic_write(&path, &bytes)?;
        }
    }
    sync_private_path(&path)
}

fn reconcile_direct_trust(config: &mut NodeConfig, metadata: &InstallMetadata) -> Result<()> {
    let own = metadata
        .approved_peers
        .iter()
        .find(|peer| peer.node_id == config.node_id)
        .ok_or(InstallError("rotation_recipient_excluded"))?;
    if sha256(&read_public(&config.certificate, MAX_CONFIG)?) != own.certificate_sha256 {
        return Err(InstallError("rotation_recipient_certificate_mismatch"));
    }
    for peer in &mut config.peers {
        peer.certificate_sha256.make_ascii_lowercase();
    }
    config.peers.retain(|peer| {
        metadata.approved_peers.iter().any(|approved| {
            approved.node_id == peer.node_id
                && approved.certificate_sha256 == peer.certificate_sha256
        })
    });
    for peer in &config.peers {
        if sha256(&read_public(&peer.certificate, MAX_CONFIG)?) != peer.certificate_sha256 {
            return Err(InstallError("rotation_peer_certificate_mismatch"));
        }
    }
    // A general CA root could keep an excluded certificate trusted. Rebuild explicit certificate roots.
    config.trust_anchors = config
        .peers
        .iter()
        .map(|peer| peer.certificate.clone())
        .collect();
    // TLS pins do not bind independent result signing keys. Re-pin them explicitly after rotation
    // rather than retaining a compromised predecessor's authority by node name alone.
    config.result_trust.clear();
    Ok(())
}
fn validate_direct_trust(
    config: &NodeConfig,
    approved: &[ApprovedPeer],
    expected_count: usize,
) -> Result<()> {
    let own = approved
        .iter()
        .find(|peer| peer.node_id == config.node_id)
        .ok_or(InstallError("rotation_recipient_excluded"))?;
    if sha256(&read_public(&config.certificate, MAX_CONFIG)?) != own.certificate_sha256
        || config.peers.len() != expected_count
        || config.trust_anchors
            != config
                .peers
                .iter()
                .map(|peer| peer.certificate.clone())
                .collect::<Vec<_>>()
        || config
            .result_trust
            .keys()
            .any(|node| !approved.iter().any(|peer| &peer.node_id == node))
    {
        return Err(InstallError("rotation_direct_trust_update_required"));
    }
    for peer in &config.peers {
        if !approved.iter().any(|approved| {
            approved.node_id == peer.node_id
                && approved.certificate_sha256 == peer.certificate_sha256
        }) || sha256(&read_public(&peer.certificate, MAX_CONFIG)?) != peer.certificate_sha256
        {
            return Err(InstallError("rotation_direct_trust_update_required"));
        }
    }
    Ok(())
}
fn check_config_binding(config: &NodeConfig, metadata: &InstallMetadata) -> Result<()> {
    if config.node_id != metadata.node_id || config.workspace != metadata.workspace {
        return Err(InstallError("rotation_config_identity_mismatch"));
    }
    Ok(())
}
fn load_config(path: &Path) -> Result<(NodeConfig, Vec<u8>)> {
    require_parent(path)?;
    let bytes = read_private(path, MAX_CONFIG)?;
    let config =
        NodeConfig::load(path).map_err(|_| InstallError("invalid_rotation_node_config"))?;
    require_directory(&config.state_dir)?;
    Ok((config, bytes))
}
fn require_drained(config: &NodeConfig) -> Result<()> {
    if !crate::executor::read_drain_flag(&config.state_dir.join("operator-drain"))
        .map_err(|_| InstallError("rotation_drain_state_invalid"))?
    {
        return Err(InstallError("rotation_requires_local_drain"));
    }
    Ok(())
}
fn inspect_jobs(config: &NodeConfig) -> Result<()> {
    let executor_dir = config.state_dir.join("executor");
    if missing(&executor_dir)? {
        return Ok(());
    }
    require_directory(&executor_dir)?;
    let jobs = executor_dir.join("jobs");
    if missing(&jobs)? {
        return Ok(());
    }
    require_directory(&jobs)?;
    let mut count = 0;
    for entry in fs::read_dir(&jobs).map_err(io)? {
        count += 1;
        if count > MAX_JOBS {
            return Err(InstallError("rotation_job_inspection_limit"));
        }
        let entry = entry.map_err(io)?;
        let id = entry.file_name();
        let id = id
            .to_str()
            .ok_or(InstallError("rotation_invalid_job_directory"))?;
        if !wire::valid_ulid(id) {
            return Err(InstallError("rotation_invalid_job_directory"));
        }
        require_directory(&entry.path())?;
        let bytes = read_private(&entry.path().join("record.json"), MAX_RECORD)?;
        let record: JobRecord = serde_json::from_slice(&bytes)
            .map_err(|_| InstallError("rotation_invalid_job_record"))?;
        if record.spec.id != id {
            return Err(InstallError("rotation_invalid_job_record"));
        }
        if !record.state.is_terminal() {
            return Err(InstallError("rotation_requires_drained_known_jobs"));
        }
    }
    Ok(())
}

/// Offline maintenance boundary for signed binary updates. This does not install a key,
/// open an executor, launch recovery or relax the workspace rotation fences.
pub(crate) struct MaintenanceGuard {
    _host: File,
    _executor: File,
    _workflow: File,
    _dispatch: File,
    _key: KeyReadGuard,
}
pub(crate) fn offline_maintenance_guard(
    config: &NodeConfig,
    key_path: &Path,
) -> Result<MaintenanceGuard> {
    require_directory(&config.state_dir)?;
    let host = lock_file(&config.state_dir.join("host.lock"))?;
    let executor_dir = config.state_dir.join("executor");
    create_directory(&executor_dir)?;
    let executor = lock_file(&executor_dir.join("executor.lock"))?;
    let workflow = crate::workflow::offline_rotation_guard(
        &config.state_dir,
        &config.workflow.clone().unwrap_or_default(),
        &config.workspace,
        &config.node_id,
    )
    .map_err(|error| InstallError(error.0))?;
    let dispatch = crate::incarnation::offline_dispatch_guard(config)
        .map_err(|_| InstallError("maintenance_requires_reconciled_outbound_jobs"))?;
    let key = guard_workspace_key(key_path)?;
    require_no_pending(&config.state_dir)?;
    require_global_binding(config, key_path)?;
    require_drained(config)?;
    inspect_jobs(config)?;
    Ok(MaintenanceGuard {
        _host: host,
        _executor: executor,
        _workflow: workflow,
        _dispatch: dispatch,
        _key: key,
    })
}

struct Locks {
    _host: File,
    _executor: File,
    _key: File,
    _workflow: File,
    _dispatch: File,
}
fn acquire_locks(config: &NodeConfig, key_path: &Path) -> Result<Locks> {
    require_directory(&config.state_dir)?;
    require_parent(key_path)?;
    if key_path.file_name().and_then(|name| name.to_str())
        != Some(&format!("{}.key", config.workspace))
    {
        return Err(InstallError("rotation_workspace_key_path_mismatch"));
    }
    let host = lock_file(&config.state_dir.join("host.lock"))?;
    let executor_dir = config.state_dir.join("executor");
    create_directory(&executor_dir)?;
    let executor = lock_file(&executor_dir.join("executor.lock"))?;
    let key = lock_file(&key_path.with_extension("rotation.lock"))?;
    let workflow = crate::workflow::offline_rotation_guard(
        &config.state_dir,
        &config.workflow.clone().unwrap_or_default(),
        &config.workspace,
        &config.node_id,
    )
    .map_err(|error| InstallError(error.0))?;
    let dispatch = crate::incarnation::offline_dispatch_guard(config)
        .map_err(|_| InstallError("rotation_requires_reconciled_outbound_work"))?;
    Ok(Locks {
        _host: host,
        _executor: executor,
        _key: key,
        _workflow: workflow,
        _dispatch: dispatch,
    })
}
#[cfg(unix)]
fn lock_file(path: &Path) -> Result<File> {
    use std::os::fd::AsRawFd;
    let file = open_lock(path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(InstallError("rotation_requires_stopped_node"));
    }
    Ok(file)
}
fn open_lock(path: &Path) -> Result<File> {
    require_parent(path)?;
    let mut options = private_options();
    options.read(true).write(true).create(true);
    let file = options.open(path).map_err(io)?;
    require_file(&file, true, 0, false)?;
    Ok(file)
}
fn global_state_path(key_path: &Path) -> PathBuf {
    key_path.with_extension("rotation.json")
}
fn global_pending_path(key_path: &Path) -> PathBuf {
    key_path.with_extension("rotation.pending.json")
}
fn require_no_global_pending(key_path: &Path) -> Result<()> {
    if !missing(&global_pending_path(key_path))? {
        return Err(InstallError("workspace_rotation_recovery_required"));
    }
    Ok(())
}
fn read_global(key_path: &Path) -> Result<Option<GlobalState>> {
    let path = global_state_path(key_path);
    if missing(&path)? {
        return Ok(None);
    }
    let global: GlobalState = serde_json::from_slice(&read_private(&path, MAX_CONFIG)?)
        .map_err(|_| InstallError("rotation_invalid_global_state"))?;
    if global.version != 1
        || !wire::valid_name(&global.workspace)
        || global.epoch == 0
        || !valid_key_id(&global.previous_key_id)
        || !valid_key_id(&global.current_key_id)
        || global.previous_key_id == global.current_key_id
        || !valid_digest(&global.previous_key_sha256)
        || !valid_digest(&global.current_key_sha256)
        || !valid_digest(&global.plan_sha256)
        || global.approved_peers.is_empty()
        || global.approved_peers.len() > 512
    {
        return Err(InstallError("rotation_invalid_global_state"));
    }
    let mut previous: Option<&str> = None;
    let mut pins = BTreeSet::new();
    for peer in &global.approved_peers {
        if !wire::valid_name(&peer.node_id)
            || !valid_digest(&peer.certificate_sha256)
            || previous.is_some_and(|previous| previous >= peer.node_id.as_str())
            || !pins.insert(&peer.certificate_sha256)
        {
            return Err(InstallError("rotation_invalid_global_state"));
        }
        previous = Some(&peer.node_id);
    }
    Ok(Some(global))
}
fn global_matches(global: &GlobalState, metadata: &InstallMetadata, new_key_sha256: &str) -> bool {
    global.workspace == metadata.workspace
        && global.epoch == metadata.epoch
        && global.previous_key_id == metadata.old_key_id
        && global.current_key_id == metadata.new_key_id
        && global.current_key_sha256 == new_key_sha256
        && global.plan_sha256 == metadata.plan_sha256
        && global.history_policy == metadata.history_policy
        && global.approved_peers == metadata.approved_peers
}
fn global_from_journal(journal: &Journal) -> GlobalState {
    GlobalState {
        version: 1,
        workspace: journal.metadata.workspace.clone(),
        epoch: journal.metadata.epoch,
        previous_key_id: journal.metadata.old_key_id.clone(),
        previous_key_sha256: journal.old_key_sha256.clone(),
        current_key_id: journal.metadata.new_key_id.clone(),
        current_key_sha256: journal.new_key_sha256.clone(),
        plan_sha256: journal.metadata.plan_sha256.clone(),
        history_policy: journal.metadata.history_policy,
        approved_peers: journal.metadata.approved_peers.clone(),
    }
}
fn read_journal(state_dir: &Path) -> Result<Journal> {
    let journal: Journal =
        serde_json::from_slice(&read_private(&state_dir.join(PENDING), MAX_JOURNAL)?)
            .map_err(|_| InstallError("rotation_invalid_pending_journal"))?;
    validate_journal(&journal)?;
    Ok(journal)
}
fn validate_journal(journal: &Journal) -> Result<()> {
    journal.metadata.validate()?;
    if journal.version != 1
        || !valid_digest(&journal.old_key_sha256)
        || !valid_digest(&journal.new_key_sha256)
        || !valid_digest(&journal.old_config_sha256)
        || !valid_digest(&journal.new_config_sha256)
        || journal.direct_peer_count >= journal.metadata.approved_peers.len()
    {
        return Err(InstallError("rotation_invalid_pending_journal"));
    }
    require_parent(&journal.config_path)?;
    require_parent(&journal.key_path)?;
    Ok(())
}
fn key_stage(journal: &Journal) -> Result<PathBuf> {
    stage_path(&journal.key_path, &journal.metadata.plan_sha256, "key")
}
fn config_stage(journal: &Journal) -> Result<PathBuf> {
    stage_path(
        &journal.config_path,
        &journal.metadata.plan_sha256,
        "config",
    )
}
fn stage_path(path: &Path, plan: &str, kind: &str) -> Result<PathBuf> {
    let parent = path.parent().ok_or(InstallError("rotation_invalid_path"))?;
    let destination = sha256(path.as_os_str().as_encoded_bytes());
    Ok(parent.join(format!(
        ".workspace-rotation-{plan}-{destination}-{kind}.next"
    )))
}
fn retain_history(key_path: &Path, metadata: &InstallMetadata, old_entropy: &[u8]) -> Result<()> {
    let root = key_path
        .parent()
        .ok_or(InstallError("rotation_invalid_path"))?
        .join("history");
    create_directory(&root)?;
    let workspace = root.join(&metadata.workspace);
    create_directory(&workspace)?;
    write_stage(
        &workspace.join(format!("{}.key", metadata.old_key_id)),
        old_entropy,
    )
}
fn history_path(key_path: &Path, metadata: &InstallMetadata) -> Result<PathBuf> {
    Ok(key_path
        .parent()
        .ok_or(InstallError("rotation_invalid_path"))?
        .join("history")
        .join(&metadata.workspace)
        .join(format!("{}.key", metadata.old_key_id)))
}
fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    decode_key(read_file(path, 32, true, false)?)
}
fn read_current_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    // Create-only key publication can leave a private staging hardlink after a crash. Its current
    // key remains valid; journal and newly staged files still require a single filesystem link.
    decode_key(read_file(path, 32, true, true)?)
}
fn decode_key(bytes: Vec<u8>) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != 32 {
        return Err(InstallError("rotation_invalid_workspace_key"));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}
fn write_stage(path: &Path, bytes: &[u8]) -> Result<()> {
    if !missing(path)? {
        if Zeroizing::new(read_private(path, MAX_JOURNAL)?).as_slice() != bytes {
            return Err(InstallError("rotation_staging_conflict"));
        }
        return sync_private_path(path);
    }
    create_private(path, bytes)
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    publish_complete(path, bytes, true)
}
fn create_private(path: &Path, bytes: &[u8]) -> Result<()> {
    publish_complete(path, bytes, false)
}
fn publication_prefix(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .ok_or(InstallError("rotation_invalid_path"))?;
    Ok(format!(
        ".rotation-publish-{}-",
        sha256(name.as_encoded_bytes())
    ))
}
fn cleanup_unpublished(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(InstallError("rotation_invalid_path"))?;
    let prefix = publication_prefix(path)?;
    let mut removed = false;
    for (index, entry) in fs::read_dir(parent).map_err(io)?.enumerate() {
        if index >= MAX_JOBS {
            return Err(InstallError("rotation_publication_directory_limit"));
        }
        let entry = entry.map_err(io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".tmp"))
        else {
            continue;
        };
        if !wire::valid_ulid(id) {
            return Err(InstallError("rotation_invalid_publication_temporary"));
        }
        let file = private_options()
            .read(true)
            .open(entry.path())
            .map_err(io)?;
        require_file(&file, true, MAX_JOURNAL, false)?;
        fs::remove_file(entry.path()).map_err(io)?;
        removed = true;
    }
    if removed {
        sync_directory(parent)?;
    }
    Ok(())
}
fn sync_private_path(path: &Path) -> Result<()> {
    let file = private_options().read(true).open(path).map_err(io)?;
    require_file(&file, true, MAX_JOURNAL, false)?;
    file.sync_all().map_err(io)?;
    sync_directory(path.parent().ok_or(InstallError("rotation_invalid_path"))?)
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicationFault {
    PartialWrite,
    AfterPublish,
}
#[cfg(test)]
thread_local! {static MARKER_CLEAR_FAULT:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
#[cfg(test)]
thread_local! {static PUBLICATION_FAULT:std::cell::RefCell<Option<(PathBuf,PublicationFault)>>=const{std::cell::RefCell::new(None)};}
#[cfg(test)]
fn take_publication_fault(path: &Path) -> Option<PublicationFault> {
    PUBLICATION_FAULT.with(|slot| {
        let mut value = slot.borrow_mut();
        if value.as_ref().is_some_and(|(target, _)| target == path) {
            value.take().map(|(_, fault)| fault)
        } else {
            None
        }
    })
}
fn publish_complete(path: &Path, bytes: &[u8], replace_existing: bool) -> Result<()> {
    require_parent(path)?;
    if bytes.len() as u64 > MAX_JOURNAL {
        return Err(InstallError("rotation_file_too_large"));
    }
    if replace_existing && !missing(path)? {
        let _checked = Zeroizing::new(read_private(path, MAX_JOURNAL)?);
    }
    // Writers of this exact destination are serialized by the host/executor/key maintenance locks.
    // Only the destination-specific prefix is cleaned; another workspace may share this parent.
    cleanup_unpublished(path)?;
    let parent = path.parent().ok_or(InstallError("rotation_invalid_path"))?;
    let temp = parent.join(format!(
        "{}{}.tmp",
        publication_prefix(path)?,
        wire::new_id().map_err(|_| InstallError("rotation_entropy_unavailable"))?
    ));
    let mut options = private_options();
    let mut file = options
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(io)?;
    require_file(&file, true, MAX_JOURNAL, false)?;
    #[cfg(test)]
    let fault = take_publication_fault(path);
    #[cfg(test)]
    if fault == Some(PublicationFault::PartialWrite) {
        file.write_all(&bytes[..bytes.len() / 2]).map_err(io)?;
        file.sync_all().map_err(io)?;
        sync_directory(parent)?;
        return Err(InstallError("rotation_injected_partial_write"));
    }
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(io)?;
        if replace_existing {
            lockyard_core::fsio::rename(&temp, path).map_err(io)?;
        } else {
            rename_create_only(&temp, path)?;
        }
        #[cfg(test)]
        if fault == Some(PublicationFault::AfterPublish) {
            return Err(InstallError("rotation_injected_after_publish"));
        }
        sync_directory(parent)
    })();
    if result.is_err() && !missing(&temp)? {
        fs::remove_file(&temp).map_err(io)?;
        sync_directory(parent)?;
    }
    result
}
#[cfg(target_os = "linux")]
fn rename_create_only(source: &Path, destination: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| InstallError("rotation_invalid_path"))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| InstallError("rotation_invalid_path"))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(InstallError(
            "rotation_atomic_create_publish_unavailable_or_conflict",
        ));
    }
    Ok(())
}
#[cfg(all(not(target_os = "linux"), not(windows)))]
fn rename_create_only(_source: &Path, _destination: &Path) -> Result<()> {
    Err(InstallError(
        "rotation_atomic_create_publish_requires_linux",
    ))
}
fn replace(source: &Path, destination: &Path) -> Result<()> {
    replace_inner(source, destination, false)
}
fn replace_inner(source: &Path, destination: &Path, allow_destination_links: bool) -> Result<()> {
    require_parent(source)?;
    require_parent(destination)?;
    if source.parent() != destination.parent() {
        return Err(InstallError("rotation_cross_directory_replace"));
    }
    if !missing(destination)? {
        let _validated = Zeroizing::new(read_file(
            destination,
            MAX_JOURNAL,
            true,
            allow_destination_links,
        )?);
    }
    lockyard_core::fsio::rename(source, destination).map_err(io)?;
    sync_directory(
        destination
            .parent()
            .ok_or(InstallError("rotation_invalid_path"))?,
    )
}
fn remove_stage_if_present(path: &Path) -> Result<()> {
    if !missing(path)? {
        let _validated = Zeroizing::new(read_private(path, MAX_JOURNAL)?);
        fs::remove_file(path).map_err(io)?;
        sync_directory(path.parent().ok_or(InstallError("rotation_invalid_path"))?)?;
    }
    Ok(())
}
#[cfg(unix)]
fn create_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if missing(path)? {
        fs::DirBuilder::new().mode(0o700).create(path).map_err(io)?;
        sync_directory(path.parent().ok_or(InstallError("rotation_invalid_path"))?)?;
    }
    require_directory(path)
}
fn sync_directory(path: &Path) -> Result<()> {
    lockyard_core::fsio::sync_path(path).map_err(io)
}
fn missing(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(io(error)),
    }
}
fn require_parent(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(InstallError("rotation_invalid_path"));
    }
    require_directory(path.parent().ok_or(InstallError("rotation_invalid_path"))?)
}
#[cfg(unix)]
fn require_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(InstallError("rotation_invalid_path"));
    }
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || !has_canonical_location(path)?
    {
        return Err(InstallError("rotation_directory_not_private"));
    }
    Ok(())
}
// macOS may spell its OS-owned /private directories through /var or /tmp. Resolve
// just that exact prefix: every other directory or file symlink remains refused.
fn has_canonical_location(path: &Path) -> Result<bool> {
    #[cfg(windows)]
    {
        lockyard_core::windows::reject_reparse(path).map_err(io)?;
        Ok(true)
    }
    #[cfg(unix)]
    {
        let canonical = fs::canonicalize(path).map_err(io)?;
        if canonical == path {
            return Ok(true);
        }
        #[cfg(target_os = "macos")]
        for (alias, target) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
            if let Ok(remainder) = path.strip_prefix(alias)
                && fs::read_link(alias).is_ok_and(|link| {
                    link == Path::new(target) || Path::new("/").join(link) == Path::new(target)
                })
            {
                return Ok(canonical == Path::new(target).join(remainder));
            }
        }
        Ok(false)
    }
}

#[cfg(unix)]
fn private_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options
}
#[cfg(unix)]
fn require_file(file: &File, private: bool, max: u64, allow_links: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || (!allow_links && metadata.nlink() != 1)
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
        || metadata.len() > max
    {
        return Err(InstallError("rotation_file_not_private_or_bounded"));
    }
    Ok(())
}
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    read_file(path, max, true, false)
}
fn read_public(path: &Path, max: u64) -> Result<Vec<u8>> {
    read_file(path, max, false, false)
}
fn read_file(path: &Path, max: u64, private: bool, allow_links: bool) -> Result<Vec<u8>> {
    if !path.is_absolute() || !has_canonical_location(path)? {
        return Err(InstallError("rotation_unsafe_file_path"));
    }
    let file = private_options().read(true).open(path).map_err(io)?;
    require_file(&file, private, max, allow_links)?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() as u64 > max {
        return Err(InstallError("rotation_file_too_large"));
    }
    Ok(bytes)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_key_id(value: &str) -> bool {
    value.len() == 11
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(windows)]
pub fn guard_workspace_key(key_path: &Path) -> Result<KeyReadGuard> {
    require_parent(key_path)?;
    let file = open_lock(&key_path.with_extension("rotation.lock"))?;
    file.try_lock_shared()
        .map_err(|_| InstallError("workspace_rotation_installing"))?;
    Ok(KeyReadGuard { _file: file })
}

#[cfg(windows)]
fn lock_file(path: &Path) -> Result<File> {
    let file = open_lock(path)?;
    file.try_lock()
        .map_err(|_| InstallError("rotation_requires_stopped_node"))?;
    Ok(file)
}

#[cfg(windows)]
fn create_directory(path: &Path) -> Result<()> {
    lockyard_core::windows::private_dir(path).map_err(io)
}

#[cfg(windows)]
fn require_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(InstallError("rotation_invalid_path"));
    }
    lockyard_core::windows::require_private(path).map_err(io)
}

#[cfg(windows)]
fn private_options() -> OpenOptions {
    lockyard_core::windows::OpenOptions::new()
}

#[cfg(windows)]
fn require_file(file: &File, private: bool, max: u64, allow_links: bool) -> Result<()> {
    let metadata = file.metadata().map_err(io)?;
    let _ = (private, allow_links);
    if !metadata.is_file() || metadata.len() > max {
        return Err(InstallError("rotation_file_not_private_or_bounded"));
    }
    lockyard_core::windows::require_private_file(file).map_err(io)
}

#[cfg(windows)]
fn rename_create_only(source: &Path, destination: &Path) -> Result<()> {
    lockyard_core::windows::rename_create_only(source, destination).map_err(io)
}

#[cfg(windows)]
use lockyard_core::windows::OpenOptions;
#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{host::PeerConfig, wire::JobState};
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture {
        _dir: tempfile::TempDir,
        config_path: PathBuf,
        key_path: PathBuf,
        metadata: InstallMetadata,
        new_entropy: [u8; 32],
    }
    fn private_write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fixture(history_policy: HistoryPolicy) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = dir.path().canonicalize().unwrap();
        for name in ["state", "keys"] {
            create_directory(&root.join(name)).unwrap();
        }
        let mut peers = Vec::new();
        let mut approved = Vec::new();
        for node in ["allowed", "excluded", "worker"] {
            let cert =
                rcgen::generate_simple_self_signed(vec![format!("{node}.lockyard")]).unwrap();
            let path = root.join(format!("{node}.der"));
            private_write(&path, cert.cert.der());
            let pin = sha256(cert.cert.der());
            if node != "excluded" {
                approved.push(ApprovedPeer {
                    node_id: node.into(),
                    certificate_sha256: pin.clone(),
                });
            }
            if node != "worker" {
                peers.push(PeerConfig {
                    node_id: node.into(),
                    address: None,
                    tls_name: format!("{node}.lockyard"),
                    certificate_sha256: pin,
                    certificate: path,
                    allowed_operations: Vec::new(),
                });
            }
        }
        let config = NodeConfig {
            node_id: "worker".into(),
            workspace: "workspace".into(),
            state_dir: root.join("state"),
            listen: None,
            certificate: root.join("worker.der"),
            private_key: root.join("worker-key.der"),
            trust_anchors: vec![root.join("excluded.der")],
            peers,
            relay: None,
            executor: None,
            metadata_notifications: false,
            result_trust: ["allowed", "excluded"]
                .into_iter()
                .map(|node| {
                    (
                        node.to_string(),
                        crate::provenance::TrustedSigningKey {
                            public_key: "01".repeat(32),
                        },
                    )
                })
                .collect(),
            project_retention: Default::default(),
            workflow: None,
            delegation_socket: None,
            revocations: None,
            rpc_timeout_seconds: 60,
        };
        private_write(&config.private_key, b"unused synthetic private key");
        private_write(&config.state_dir.join("operator-drain"), b"1");
        let config_path = root.join("node.toml");
        private_write(&config_path, toml::to_string(&config).unwrap().as_bytes());
        let key_path = root.join("keys/workspace.key");
        private_write(&key_path, &[7; 32]);
        let metadata = InstallMetadata {
            workspace: "workspace".into(),
            node_id: "worker".into(),
            epoch: 1,
            old_key_id: WorkspaceKey::from_entropy([7; 32]).key_id(),
            new_key_id: WorkspaceKey::from_entropy([8; 32]).key_id(),
            plan_sha256: "a".repeat(64),
            history_policy,
            approved_peers: approved,
            signed_plan_json: "synthetic-authorized-bundle".into(),
        };
        Fixture {
            _dir: dir,
            config_path,
            key_path,
            metadata,
            new_entropy: [8; 32],
        }
    }
    fn config(f: &Fixture) -> NodeConfig {
        NodeConfig::load(&f.config_path).unwrap()
    }
    fn install(f: &Fixture) -> Result<InstalledState> {
        install_verified(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata)
    }
    fn job(f: &Fixture, state: JobState) -> PathBuf {
        let executor = config(f).state_dir.join("executor");
        create_directory(&executor).unwrap();
        create_directory(&executor.join("jobs")).unwrap();
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let dir = executor.join("jobs").join(id);
        create_directory(&dir).unwrap();
        let record: JobRecord = serde_json::from_value(serde_json::json!({
            "spec":{"id":id,"repository":"repo","revision":"HEAD","runner":"runner"},
            "state":state,"agent":"agent","submitter":"worker","created_at":1,"updated_at":2,
            "log_bytes":0,"log_truncated":false
        }))
        .unwrap();
        let path = dir.join("record.json");
        private_write(&path, &serde_json::to_vec(&record).unwrap());
        path
    }
    #[cfg(target_os = "linux")]
    fn pending(f: &Fixture) -> (NodeConfig, Journal) {
        let (mut config, original) = load_config(&f.config_path).unwrap();
        let old = read_key(&f.key_path).unwrap();
        reconcile_direct_trust(&mut config, &f.metadata).unwrap();
        let replacement = toml::to_string(&config).unwrap().into_bytes();
        let journal = Journal {
            version: 1,
            metadata: f.metadata.clone(),
            config_path: f.config_path.clone(),
            key_path: f.key_path.clone(),
            old_key_sha256: sha256(old.as_ref()),
            new_key_sha256: sha256(&f.new_entropy),
            old_config_sha256: sha256(&original),
            new_config_sha256: sha256(&replacement),
            direct_peer_count: config.peers.len(),
        };
        write_stage(&key_stage(&journal).unwrap(), &f.new_entropy).unwrap();
        write_stage(&config_stage(&journal).unwrap(), &replacement).unwrap();
        create_private(
            &config.state_dir.join(PENDING),
            &serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        (config, journal)
    }
    #[cfg(target_os = "linux")]
    fn global_pending(config: &NodeConfig, journal: &Journal) {
        let global = GlobalPending {
            version: 1,
            state_dir: config.state_dir.clone(),
            workspace: journal.metadata.workspace.clone(),
            epoch: journal.metadata.epoch,
            plan_sha256: journal.metadata.plan_sha256.clone(),
            journal: Some(Box::new(journal.clone())),
        };
        create_private(
            &global_pending_path(&journal.key_path),
            &serde_json::to_vec(&global).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn private_directory_check_accepts_standard_macos_tempdir_alias() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        require_directory(dir.path()).unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn private_file_check_accepts_only_system_aliases_in_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        private_write(&path, &[7; 32]);
        assert_eq!(read_file(&path, 32, true, false).unwrap(), [7; 32]);
        let alias = dir.path().join("alias");
        symlink(dir.path(), &alias).unwrap();
        assert!(require_directory(&alias).is_err());
        assert!(read_file(&alias.join("key"), 32, true, false).is_err());
        let file_alias = dir.path().join("key-alias");
        symlink(&path, &file_alias).unwrap();
        assert!(read_file(&file_alias, 32, true, false).is_err());
    }

    #[test]
    fn fixture_has_canonical_private_directory_and_readable_key_paths() {
        let f = fixture(HistoryPolicy::Discard);
        let state = config(&f).state_dir;
        assert_eq!(state.canonicalize().unwrap(), state);
        require_directory(&state).unwrap();
        assert_eq!(read_file(&f.key_path, 32, true, false).unwrap(), [7; 32]);
    }

    #[test]
    fn private_path_checks_refuse_managed_directory_and_file_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let state = root.join("state");
        create_directory(&state).unwrap();
        let file = state.join("key");
        private_write(&file, &[7; 32]);
        let directory_alias = root.join("state-alias");
        symlink(&state, &directory_alias).unwrap();
        assert!(require_directory(&directory_alias).is_err());
        assert!(read_file(&directory_alias.join("key"), 32, true, false).is_err());
        let file_alias = state.join("key-alias");
        symlink(&file, &file_alias).unwrap();
        assert!(read_file(&file_alias, 32, true, false).is_err());
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_directory(&state).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file(&file, 32, true, false).is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn unsupported_atomic_publication_preserves_rotation_inputs_and_never_publishes_intent() {
        for policy in [HistoryPolicy::Discard, HistoryPolicy::RetainPrivateHistory] {
            let f = fixture(policy);
            let original_config = fs::read(&f.config_path).unwrap();
            let original_key = fs::read(&f.key_path).unwrap();
            let state_dir = config(&f).state_dir;
            for _ in 0..2 {
                assert_eq!(
                    install(&f).unwrap_err().0,
                    "rotation_atomic_create_publish_requires_linux"
                );
                assert_eq!(fs::read(&f.key_path).unwrap(), original_key);
                assert_eq!(fs::read(&f.config_path).unwrap(), original_config);
                require_no_pending(&state_dir).unwrap();
                require_no_global_pending(&f.key_path).unwrap();
                assert_eq!(read_installed(&state_dir).unwrap(), None);
                assert!(missing(&global_state_path(&f.key_path)).unwrap());
                assert!(missing(&history_path(&f.key_path, &f.metadata).unwrap()).unwrap());
                assert_no_publication_orphans(f._dir.path());
            }
            let source = state_dir.join("publish-source");
            let destination = state_dir.join("publish-destination");
            private_write(&source, b"new bytes");
            private_write(&destination, b"existing bytes");
            assert_eq!(
                rename_create_only(&source, &destination).unwrap_err().0,
                "rotation_atomic_create_publish_requires_linux"
            );
            assert_eq!(fs::read(source).unwrap(), b"new bytes");
            assert_eq!(fs::read(destination).unwrap(), b"existing bytes");
        }
    }

    // Successful create-only publication/recovery is a Linux acceptance contract.
    // Other Unix platforms exercise the explicit refusal and no-mutation path above.
    #[test]
    #[cfg(target_os = "linux")]
    fn install_is_durable_idempotent_and_removes_excluded_direct_certificates() {
        let f = fixture(HistoryPolicy::RetainPrivateHistory);
        job(&f, JobState::Succeeded);
        let state = install(&f).unwrap();
        assert_eq!(*read_key(&f.key_path).unwrap(), f.new_entropy);
        assert_eq!(
            *read_key(&history_path(&f.key_path, &f.metadata).unwrap()).unwrap(),
            [7; 32]
        );
        let installed_config = config(&f);
        assert_eq!(installed_config.peers.len(), 1);
        assert_eq!(installed_config.peers[0].node_id, "allowed");
        assert!(installed_config.result_trust.is_empty());
        assert_eq!(
            installed_config.trust_anchors,
            vec![installed_config.peers[0].certificate.clone()]
        );
        assert!(state.direct_certificates_reconciled);
        assert_eq!(state.direct_peer_count, 1);
        assert_eq!(
            read_installed(&installed_config.state_dir).unwrap(),
            Some(state.clone())
        );
        require_no_pending(&installed_config.state_dir).unwrap();
        require_global_binding(&installed_config, &f.key_path).unwrap();
        assert_eq!(install(&f).unwrap(), state);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn discard_does_not_create_a_history_copy() {
        let f = fixture(HistoryPolicy::Discard);
        install(&f).unwrap();
        assert!(missing(&history_path(&f.key_path, &f.metadata).unwrap()).unwrap());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn retained_uppercase_certificate_pins_are_normalized_before_trust_reconciliation() {
        let f = fixture(HistoryPolicy::Discard);
        let mut before = config(&f);
        for peer in &mut before.peers {
            peer.certificate_sha256.make_ascii_uppercase();
        }
        private_write(&f.config_path, toml::to_string(&before).unwrap().as_bytes());
        install(&f).unwrap();
        let after = config(&f);
        assert_eq!(after.peers.len(), 1);
        assert_eq!(
            after.peers[0].certificate_sha256,
            after.peers[0].certificate_sha256.to_ascii_lowercase()
        );
        require_global_binding(&after, &f.key_path).unwrap();
    }
    #[tokio::test]
    async fn unfinished_remote_child_blocks_rotation_with_no_local_job_or_workflow() {
        let f = fixture(HistoryPolicy::Discard);
        let config = config(&f);
        let parent = wire::new_id().unwrap();
        let child = wire::new_id().unwrap();
        let spec = serde_json::json!({"id":child,"repository":"repo","revision":"HEAD","runner":"fixture","arguments":[],"prompt":null,"timeout_seconds":null});
        crate::incarnation::target_pin_bound(
            &config,
            "allowed",
            wire::Operation::JobSubmit,
            &spec,
            None,
            &crate::incarnation::DispatchOrigin::Job(parent),
        )
        .await
        .unwrap();
        assert_eq!(
            crate::incarnation::unresolved_dispatches(&config).unwrap(),
            1
        );
        assert_eq!(
            install(&f).unwrap_err().0,
            "rotation_requires_reconciled_outbound_work"
        );
        assert_eq!(*read_current_key(&f.key_path).unwrap(), [7; 32]);
        require_no_pending(&config.state_dir).unwrap();
    }
    fn assert_no_publication_orphans(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                assert_no_publication_orphans(&entry.path());
            } else {
                assert!(
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".rotation-publish-"),
                    "unpublished private temporary remained"
                );
            }
        }
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn partial_private_publication_of_key_config_history_or_markers_is_retryable_without_partial_final_files()
     {
        for target in [
            "key",
            "config",
            "history",
            "local_pending",
            "global_pending",
        ] {
            let f = fixture(HistoryPolicy::RetainPrivateHistory);
            let (_, journal) = pending(&f);
            // pending() prepares synthetic crash inputs; start from a clean pre-install fixture.
            for path in [
                key_stage(&journal).unwrap(),
                config_stage(&journal).unwrap(),
                config(&f).state_dir.join(PENDING),
            ] {
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
            let path = match target {
                "key" => key_stage(&journal).unwrap(),
                "config" => config_stage(&journal).unwrap(),
                "history" => history_path(&f.key_path, &f.metadata).unwrap(),
                "local_pending" => config(&f).state_dir.join(PENDING),
                _ => global_pending_path(&f.key_path),
            };
            PUBLICATION_FAULT.with(|slot| {
                *slot.borrow_mut() = Some((path.clone(), PublicationFault::PartialWrite))
            });
            assert_eq!(
                install(&f).unwrap_err().0,
                "rotation_injected_partial_write"
            );
            assert!(
                !path.exists(),
                "partial deterministic destination was exposed: {target}"
            );
            assert_eq!(*read_current_key(&f.key_path).unwrap(), [7; 32]);
            let state = if config(&f).state_dir.join(PENDING).exists()
                || global_pending_path(&f.key_path).exists()
            {
                recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata).unwrap()
            } else {
                install(&f).unwrap()
            };
            assert_eq!(state.current_key_id, f.metadata.new_key_id);
            assert_eq!(*read_current_key(&f.key_path).unwrap(), f.new_entropy);
            assert_eq!(
                *read_key(&history_path(&f.key_path, &f.metadata).unwrap()).unwrap(),
                [7; 32]
            );
            assert_no_publication_orphans(f._dir.path());
            require_no_pending(&config(&f).state_dir).unwrap();
        }
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn publication_after_rename_before_directory_sync_recovers_durable_fences_and_complete_files() {
        for target in [
            "key",
            "config",
            "history",
            "local_pending",
            "global_pending",
        ] {
            let f = fixture(HistoryPolicy::RetainPrivateHistory);
            let (_, journal) = pending(&f);
            for path in [
                key_stage(&journal).unwrap(),
                config_stage(&journal).unwrap(),
                config(&f).state_dir.join(PENDING),
            ] {
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
            let path = match target {
                "key" => key_stage(&journal).unwrap(),
                "config" => config_stage(&journal).unwrap(),
                "history" => history_path(&f.key_path, &f.metadata).unwrap(),
                "local_pending" => config(&f).state_dir.join(PENDING),
                _ => global_pending_path(&f.key_path),
            };
            PUBLICATION_FAULT.with(|slot| {
                *slot.borrow_mut() = Some((path.clone(), PublicationFault::AfterPublish))
            });
            assert_eq!(
                install(&f).unwrap_err().0,
                "rotation_injected_after_publish"
            );
            assert!(path.exists());
            assert_eq!(*read_current_key(&f.key_path).unwrap(), [7; 32]);
            if config(&f).state_dir.join(PENDING).exists()
                || global_pending_path(&f.key_path).exists()
            {
                recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata).unwrap();
            } else {
                install(&f).unwrap();
            }
            assert_eq!(*read_current_key(&f.key_path).unwrap(), f.new_entropy);
            assert_no_publication_orphans(f._dir.path());
            require_global_binding(&config(&f), &f.key_path).unwrap();
        }
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn a_second_plan_cannot_abandon_secret_staging_owned_by_a_durable_first_plan_intent() {
        for fault in [
            PublicationFault::PartialWrite,
            PublicationFault::AfterPublish,
        ] {
            let f = fixture(HistoryPolicy::Discard);
            let (_, journal) = pending(&f);
            for path in [
                key_stage(&journal).unwrap(),
                config_stage(&journal).unwrap(),
                config(&f).state_dir.join(PENDING),
            ] {
                if path.exists() {
                    fs::remove_file(path).unwrap();
                }
            }
            PUBLICATION_FAULT
                .with(|slot| *slot.borrow_mut() = Some((key_stage(&journal).unwrap(), fault)));
            assert!(install(&f).is_err());
            assert!(config(&f).state_dir.join(PENDING).exists());
            assert!(global_pending_path(&f.key_path).exists());
            let mut second = f.metadata.clone();
            second.plan_sha256 = "b".repeat(64);
            second.new_key_id = WorkspaceKey::from_entropy([9; 32]).key_id();
            second.signed_plan_json = "synthetic-second-authorized-plan".into();
            assert_eq!(
                install_verified(&f.config_path, &f.key_path, &[9; 32], &second)
                    .unwrap_err()
                    .0,
                "workspace_rotation_recovery_required"
            );
            assert_eq!(*read_current_key(&f.key_path).unwrap(), [7; 32]);
            recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata).unwrap();
            assert_no_publication_orphans(f._dir.path());
            assert!(!key_stage(&journal).unwrap().exists());
            assert!(!config_stage(&journal).unwrap().exists());
            assert_eq!(*read_current_key(&f.key_path).unwrap(), f.new_entropy);
            assert!(install_verified(&f.config_path, &f.key_path, &[9; 32], &second).is_err());
        }
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn global_only_preparation_fence_recovers_owner_and_blocks_another_local_node_plan() {
        let f = fixture(HistoryPolicy::Discard);
        let (_, journal) = pending(&f);
        for path in [
            key_stage(&journal).unwrap(),
            config_stage(&journal).unwrap(),
            config(&f).state_dir.join(PENDING),
        ] {
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
        PUBLICATION_FAULT.with(|slot| {
            *slot.borrow_mut() = Some((
                global_pending_path(&f.key_path),
                PublicationFault::AfterPublish,
            ))
        });
        assert_eq!(
            install(&f).unwrap_err().0,
            "rotation_injected_after_publish"
        );
        assert!(!config(&f).state_dir.join(PENDING).exists());
        assert!(global_pending_path(&f.key_path).exists());
        assert!(!key_stage(&journal).unwrap().exists());
        assert!(!config_stage(&journal).unwrap().exists());
        let mut other = config(&f);
        other.node_id = "allowed".into();
        other.state_dir = f.config_path.parent().unwrap().join("other-state");
        create_directory(&other.state_dir).unwrap();
        other.certificate = f.config_path.parent().unwrap().join("allowed.der");
        other.peers.retain(|peer| peer.node_id != "allowed");
        private_write(&other.state_dir.join("operator-drain"), b"1");
        let other_path = f.config_path.parent().unwrap().join("other.toml");
        private_write(&other_path, toml::to_string(&other).unwrap().as_bytes());
        let mut second = f.metadata.clone();
        second.node_id = "allowed".into();
        second.plan_sha256 = "b".repeat(64);
        second.new_key_id = WorkspaceKey::from_entropy([9; 32]).key_id();
        second.signed_plan_json = "synthetic-other-authorized-plan".into();
        assert_eq!(
            install_verified(&other_path, &f.key_path, &[9; 32], &second)
                .unwrap_err()
                .0,
            "workspace_rotation_recovery_required"
        );
        recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata).unwrap();
        assert_no_publication_orphans(f._dir.path());
        let mut join = f.metadata.clone();
        join.node_id = "allowed".into();
        install_verified(&other_path, &f.key_path, &f.new_entropy, &join).unwrap();
        require_global_binding(&config(&f), &f.key_path).unwrap();
        require_global_binding(&NodeConfig::load(&other_path).unwrap(), &f.key_path).unwrap();
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn completion_keeps_global_fence_until_local_intent_is_durably_gone_and_recovery_is_idempotent()
    {
        let f = fixture(HistoryPolicy::Discard);
        MARKER_CLEAR_FAULT.with(|fault| fault.set(true));
        assert_eq!(
            install(&f).unwrap_err().0,
            "rotation_injected_after_local_marker_clear"
        );
        assert!(!config(&f).state_dir.join(PENDING).exists());
        assert!(global_pending_path(&f.key_path).exists());
        assert_eq!(*read_current_key(&f.key_path).unwrap(), f.new_entropy);
        let mut other = config(&f);
        other.node_id = "allowed".into();
        other.state_dir = f.config_path.parent().unwrap().join("closing-other-state");
        create_directory(&other.state_dir).unwrap();
        other.certificate = f.config_path.parent().unwrap().join("allowed.der");
        other.peers.clear();
        private_write(&other.state_dir.join("operator-drain"), b"1");
        let path = f.config_path.parent().unwrap().join("closing-other.toml");
        private_write(&path, toml::to_string(&other).unwrap().as_bytes());
        let mut next = f.metadata.clone();
        next.node_id = "allowed".into();
        next.epoch = 2;
        next.old_key_id = f.metadata.new_key_id.clone();
        next.new_key_id = WorkspaceKey::from_entropy([9; 32]).key_id();
        next.plan_sha256 = "b".repeat(64);
        next.signed_plan_json = "synthetic-next-authorized-plan".into();
        assert_eq!(
            install_verified(&path, &f.key_path, &[9; 32], &next)
                .unwrap_err()
                .0,
            "workspace_rotation_recovery_required"
        );
        recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata).unwrap();
        assert!(!global_pending_path(&f.key_path).exists());
        let mut join = f.metadata.clone();
        join.node_id = "allowed".into();
        install_verified(&path, &f.key_path, &f.new_entropy, &join).unwrap();
        require_global_binding(&config(&f), &f.key_path).unwrap();
        require_global_binding(&NodeConfig::load(&path).unwrap(), &f.key_path).unwrap();
        assert_no_publication_orphans(f._dir.path());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn rotation_requires_explicit_local_drain_and_stopped_host_executor_and_key_readers() {
        let f = fixture(HistoryPolicy::Discard);
        let c = config(&f);
        private_write(&c.state_dir.join("operator-drain"), b"0");
        assert_eq!(install(&f).unwrap_err().0, "rotation_requires_local_drain");
        private_write(&c.state_dir.join("operator-drain"), b"1");
        let host = lock_file(&c.state_dir.join("host.lock")).unwrap();
        assert_eq!(install(&f).unwrap_err().0, "rotation_requires_stopped_node");
        drop(host);
        create_directory(&c.state_dir.join("executor")).unwrap();
        let executor = lock_file(&c.state_dir.join("executor/executor.lock")).unwrap();
        assert_eq!(install(&f).unwrap_err().0, "rotation_requires_stopped_node");
        drop(executor);
        let guard = guard_workspace_key(&f.key_path).unwrap();
        assert_eq!(install(&f).unwrap_err().0, "rotation_requires_stopped_node");
        drop(guard);
        install(&f).unwrap();
    }

    #[test]
    fn queued_active_and_unknown_records_block_without_opening_or_rewriting_executor() {
        for state in [
            JobState::Queued,
            JobState::Starting,
            JobState::Running,
            JobState::InterruptedUnknown,
        ] {
            let f = fixture(HistoryPolicy::Discard);
            let path = job(&f, state);
            let original = fs::read(&path).unwrap();
            assert_eq!(
                install(&f).unwrap_err().0,
                "rotation_requires_drained_known_jobs"
            );
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(*read_key(&f.key_path).unwrap(), [7; 32]);
            require_no_pending(&config(&f).state_dir).unwrap();
        }
    }

    #[test]
    fn invalid_terminal_records_and_unjournaled_directories_fail_closed() {
        let f = fixture(HistoryPolicy::Discard);
        let path = job(&f, JobState::Succeeded);
        private_write(
            &path,
            br#"{"spec":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"},"state":"succeeded"}"#,
        );
        assert_eq!(install(&f).unwrap_err().0, "rotation_invalid_job_record");
        fs::remove_file(&path).unwrap();
        assert!(install(&f).is_err());
        assert_eq!(*read_key(&f.key_path).unwrap(), [7; 32]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn forward_recovery_covers_crashes_before_key_after_key_and_after_config_replace() {
        for policy in [HistoryPolicy::Discard, HistoryPolicy::RetainPrivateHistory] {
            for phase in 0..=4 {
                let f = fixture(policy);
                let (c, journal) = pending(&f);
                if phase >= 1 {
                    if policy == HistoryPolicy::RetainPrivateHistory {
                        retain_history(&f.key_path, &f.metadata, &[7; 32]).unwrap();
                    }
                    global_pending(&c, &journal);
                    replace(&key_stage(&journal).unwrap(), &f.key_path).unwrap();
                }
                if phase >= 2 {
                    replace(&config_stage(&journal).unwrap(), &f.config_path).unwrap();
                }
                if phase >= 3 {
                    atomic_write(
                        &global_state_path(&f.key_path),
                        &serde_json::to_vec(&global_from_journal(&journal)).unwrap(),
                    )
                    .unwrap();
                }
                if phase >= 4 {
                    atomic_write(
                        &c.state_dir.join(INSTALLED),
                        &serde_json::to_vec(&InstalledState::from_metadata(
                            &f.metadata,
                            journal.direct_peer_count,
                        ))
                        .unwrap(),
                    )
                    .unwrap();
                }
                assert_eq!(
                    require_no_pending(&c.state_dir).unwrap_err().0,
                    "workspace_rotation_recovery_required"
                );
                if phase >= 1 {
                    assert_eq!(
                        require_global_binding(&c, &f.key_path).unwrap_err().0,
                        "workspace_rotation_recovery_required"
                    );
                }
                let state =
                    recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata).unwrap();
                assert_eq!(state.epoch, 1);
                assert_eq!(*read_key(&f.key_path).unwrap(), f.new_entropy);
                require_no_pending(&c.state_dir).unwrap();
                require_global_binding(&config(&f), &f.key_path).unwrap();
                if policy == HistoryPolicy::RetainPrivateHistory {
                    assert_eq!(
                        *read_key(&history_path(&f.key_path, &f.metadata).unwrap()).unwrap(),
                        [7; 32]
                    );
                }
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn corrupt_staged_inputs_or_wrong_verified_plan_leave_pending_and_preserve_old_key() {
        let f = fixture(HistoryPolicy::Discard);
        let (c, journal) = pending(&f);
        let mut wrong = f.metadata.clone();
        wrong.signed_plan_json.push('x');
        assert_eq!(
            recover(&f.config_path, &f.key_path, &f.new_entropy, &wrong)
                .unwrap_err()
                .0,
            "rotation_recovery_binding_mismatch"
        );
        private_write(&config_stage(&journal).unwrap(), b"corrupt");
        assert_eq!(
            recover(&f.config_path, &f.key_path, &f.new_entropy, &f.metadata)
                .unwrap_err()
                .0,
            "rotation_recovery_staged_config_conflict"
        );
        assert_eq!(*read_key(&f.key_path).unwrap(), [7; 32]);
        assert!(require_no_pending(&c.state_dir).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn current_key_copy_orphan_hardlinks_survive_while_symlinks_permissions_and_pending_are_rejected()
     {
        let orphan = fixture(HistoryPolicy::Discard);
        let orphan_link = orphan.key_path.with_extension("copy");
        fs::hard_link(&orphan.key_path, &orphan_link).unwrap();
        install(&orphan).unwrap();
        assert_eq!(fs::read(orphan_link).unwrap(), vec![7; 32]);
        assert_eq!(*read_key(&orphan.key_path).unwrap(), orphan.new_entropy);
        let f = fixture(HistoryPolicy::Discard);
        let c = config(&f);
        symlink(&f.key_path, c.state_dir.join(PENDING)).unwrap();
        assert_eq!(
            require_no_pending(&c.state_dir).unwrap_err().0,
            "workspace_rotation_recovery_required"
        );
        fs::remove_file(c.state_dir.join(PENDING)).unwrap();
        fs::set_permissions(&f.key_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(install(&f).is_err());
        fs::set_permissions(&f.key_path, fs::Permissions::from_mode(0o600)).unwrap();
        let saved = f.key_path.with_extension("saved");
        lockyard_core::fsio::rename(&f.key_path, &saved).unwrap();
        symlink(saved, &f.key_path).unwrap();
        assert!(install(&f).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn shared_key_rotation_blocks_other_local_state_until_its_approved_plan_is_installed() {
        for policy in [HistoryPolicy::Discard, HistoryPolicy::RetainPrivateHistory] {
            let f = fixture(policy);
            let first = config(&f);
            let second_state = first.state_dir.parent().unwrap().join("other-state");
            create_directory(&second_state).unwrap();
            private_write(&second_state.join("operator-drain"), b"1");
            let mut second = first.clone();
            second.node_id = "allowed".into();
            second.state_dir = second_state;
            second.certificate = first.peers[0].certificate.clone();
            second.private_key = first.private_key.clone();
            second.peers = vec![PeerConfig {
                node_id: "worker".into(),
                address: None,
                tls_name: "worker.lockyard".into(),
                certificate_sha256: sha256(&fs::read(&first.certificate).unwrap()),
                certificate: first.certificate.clone(),
                allowed_operations: Vec::new(),
            }];
            second.trust_anchors = Vec::new();
            let second_path = f.config_path.with_file_name("other-node.toml");
            private_write(&second_path, toml::to_string(&second).unwrap().as_bytes());
            install(&f).unwrap();
            assert_eq!(
                require_global_binding(&second, &f.key_path).unwrap_err().0,
                "rotation_local_state_update_required"
            );
            let mut metadata = f.metadata.clone();
            metadata.node_id = "allowed".into();
            install_verified(&second_path, &f.key_path, &f.new_entropy, &metadata).unwrap();
            require_global_binding(&NodeConfig::load(&second_path).unwrap(), &f.key_path).unwrap();
            require_global_binding(&config(&f), &f.key_path).unwrap();
            assert_eq!(*read_key(&f.key_path).unwrap(), f.new_entropy);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn stale_epochs_new_key_mismatches_and_post_install_direct_pin_drift_are_denied() {
        let mut f = fixture(HistoryPolicy::Discard);
        f.metadata.epoch = 2;
        assert_eq!(install(&f).unwrap_err().0, "rotation_epoch_conflict");
        f.metadata.epoch = 1;
        assert_eq!(
            install_verified(&f.config_path, &f.key_path, &[9; 32], &f.metadata)
                .unwrap_err()
                .0,
            "rotation_new_key_mismatch"
        );
        install(&f).unwrap();
        let mut c = config(&f);
        c.trust_anchors
            .push(f.config_path.with_file_name("excluded.der"));
        private_write(&f.config_path, toml::to_string(&c).unwrap().as_bytes());
        assert_eq!(
            require_global_binding(&c, &f.key_path).unwrap_err().0,
            "rotation_direct_trust_update_required"
        );
        assert_eq!(
            install(&f).unwrap_err().0,
            "rotation_direct_trust_update_required"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn standalone_executor_binds_current_epoch_key_context_and_retains_shared_lock() {
        let f = fixture(HistoryPolicy::Discard);
        install(&f).unwrap();
        let c = config(&f);
        let old = WorkspaceKey::from_entropy([7; 32]);
        assert!(
            guard_executor_workspace_key_at(
                &c.state_dir,
                &c.node_id,
                &c.workspace,
                &f.key_path,
                &old
            )
            .is_err()
        );
        let current = WorkspaceKey::from_entropy(f.new_entropy);
        let guard = guard_executor_workspace_key_at(
            &c.state_dir,
            &c.node_id,
            &c.workspace,
            &f.key_path,
            &current,
        )
        .unwrap();
        assert!(guard.is_some());
        assert_eq!(install(&f).unwrap_err().0, "rotation_requires_stopped_node");
        drop(guard);
        install(&f).unwrap();
        assert!(
            guard_executor_workspace_key_at(
                &c.state_dir,
                "excluded",
                &c.workspace,
                &f.key_path,
                &current
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn standalone_workflow_lock_blocks_rotation_even_when_executor_has_no_active_jobs() {
        let f = fixture(HistoryPolicy::Discard);
        let c = config(&f);
        let policy = c.workflow.clone().unwrap_or_default();
        let guard = crate::workflow::offline_rotation_guard(
            &c.state_dir,
            &policy,
            &c.workspace,
            &c.node_id,
        )
        .unwrap();
        assert!(install(&f).is_err());
        assert_eq!(*read_key(&f.key_path).unwrap(), [7; 32]);
        drop(guard);
        install(&f).unwrap();
    }
}
