// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Explicit offline signed binary maintenance. Nothing downloads, executes, restarts or updates itself.
use crate::{
    host::NodeConfig,
    provenance::{self, SignedDocument, SigningKey, TrustedSigningKey},
};
use ring::digest;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const DOMAIN: &[u8] = b"lockyard-node-managed-update-v1\0";
const FORMAT: u8 = 1;
const MAX_BINARY: u64 = 256 * 1024 * 1024;
const MAX_JSON: u64 = 256 * 1024;
const MAX_STAGED: usize = 8;
const POLICY: &str = "update-policy.json";
const STATE: &str = "installed.json";
const PENDING: &str = "pending.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateError(pub &'static str);
impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for UpdateError {}
pub type Result<T> = std::result::Result<T, UpdateError>;
fn io(_: std::io::Error) -> UpdateError {
    UpdateError("managed_update_io")
}
fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UpdateError("managed_update_clock_invalid"))?
        .as_millis()
        .try_into()
        .map_err(|_| UpdateError("managed_update_clock_invalid"))
}
pub fn platform() -> String {
    format!(
        "{}-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(target_env = "gnu") {
            "gnu"
        } else if cfg!(target_env = "musl") {
            "musl"
        } else {
            "unsupported"
        }
    )
}
fn version(value: &str) -> Result<[u32; 3]> {
    let parts = value
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| UpdateError("managed_update_requires_numeric_semver"))?;
    let result: [u32; 3] = parts
        .try_into()
        .map_err(|_| UpdateError("managed_update_requires_numeric_semver"))?;
    if format!("{}.{}.{}", result[0], result[1], result[2]) != value {
        return Err(UpdateError("managed_update_requires_numeric_semver"));
    }
    Ok(result)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub format: u8,
    pub release_id: String,
    pub version: String,
    pub sequence: u64,
    pub platform: String,
    pub minimum_current_version: String,
    pub state_schema_version: u8,
    pub binary_sha256: String,
    pub binary_bytes: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
impl Release {
    fn validate(&self) -> Result<()> {
        if self.format != FORMAT
            || !crate::wire::valid_ulid(&self.release_id)
            || self.sequence == 0
            || self.platform != platform()
            || self.state_schema_version != 1
            || !crate::wire::valid_certificate_pin(&self.binary_sha256)
            || self.binary_bytes < 64
            || self.binary_bytes > MAX_BINARY
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms.saturating_sub(self.issued_at_ms) > 365 * 24 * 60 * 60 * 1000
            || version(&self.minimum_current_version)? > version(&self.version)?
        {
            return Err(UpdateError("invalid_managed_update_release"));
        }
        Ok(())
    }
    fn fresh(&self, now: u64) -> Result<()> {
        self.validate()?;
        if now < self.issued_at_ms || now >= self.expires_at_ms {
            return Err(UpdateError("managed_update_authorization_expired"));
        }
        Ok(())
    }
}
pub fn sign_release(release: &Release, key_file: &Path) -> Result<SignedDocument> {
    release.validate()?;
    SigningKey::load(key_file)
        .map_err(|_| UpdateError("managed_update_signing_key_invalid"))?
        .sign_document(DOMAIN, release)
        .map_err(|_| UpdateError("managed_update_signing_failed"))
}
fn verify(document: &SignedDocument, key: &TrustedSigningKey) -> Result<Release> {
    let release: Release = provenance::verify_document(document, DOMAIN, key)
        .map_err(|_| UpdateError("managed_update_signature_invalid"))?;
    release.validate()?;
    Ok(release)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    format: u8,
    node_id: String,
    workspace: String,
    binary: PathBuf,
    trusted: TrustedSigningKey,
    minimum_sequence: u64,
    minimum_version: String,
}
impl Policy {
    fn validate(&self, config: &NodeConfig) -> Result<()> {
        self.validate_identity(&config.node_id, &config.workspace)
    }
    fn validate_identity(&self, node_id: &str, workspace: &str) -> Result<()> {
        if self.format != FORMAT
            || self.node_id != node_id
            || self.workspace != workspace
            || !crate::wire::valid_name(node_id)
            || !crate::wire::valid_name(workspace)
            || self.minimum_sequence == 0
            || !self.binary.is_absolute()
            || self.trusted.key_id().is_err()
        {
            return Err(UpdateError("managed_update_policy_invalid"));
        }
        version(&self.minimum_version)?;
        parent(&self.binary)?;
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    format: u8,
    policy_sha256: String,
    generation: u64,
    high_water_sequence: u64,
    current: SignedDocument,
    previous: Option<SignedDocument>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    format: u8,
    node_id: String,
    workspace: String,
    policy_sha256: String,
    base_generation: u64,
    base_binary_sha256: String,
    prepared_at_ms: u64,
    release: SignedDocument,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Apply,
    Rollback,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u8,
    node_id: String,
    workspace: String,
    policy_sha256: String,
    approval_sha256: String,
    authorized_at_ms: u64,
    action: Action,
    from: Installed,
    to: Installed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryOwner {
    format: u8,
    node_id: String,
    workspace: String,
    state_dir: PathBuf,
    binary: PathBuf,
}
struct Context {
    config: NodeConfig,
    key_path: PathBuf,
    executable: PathBuf,
}
impl Context {
    fn load(config_path: &Path) -> Result<Self> {
        let config = NodeConfig::load(config_path)
            .map_err(|_| UpdateError("managed_update_config_invalid"))?;
        if config.delegation_socket.is_some() {
            return Err(UpdateError("managed_update_local_operator_required"));
        }
        let key_path = lockyard_cloud_client::WorkspaceKey::storage_path(&config.workspace)
            .map_err(|_| UpdateError("managed_update_key_path_invalid"))?;
        let executable = std::env::current_exe().map_err(io)?;
        Ok(Self {
            config,
            key_path,
            executable,
        })
    }
    fn root(&self) -> PathBuf {
        self.config.state_dir.join("managed-updates")
    }
    fn policy(&self) -> Result<Policy> {
        let policy: Policy = load_json(&self.config.state_dir.join(POLICY))?;
        policy.validate(&self.config)?;
        Ok(policy)
    }
    fn maintenance(&self) -> Result<crate::rotation_install::MaintenanceGuard> {
        crate::rotation_install::offline_maintenance_guard(&self.config, &self.key_path)
            .map_err(|_| UpdateError("managed_update_requires_drained_stopped_and_reconciled_node"))
    }
}
/// Hold for the full daemon lifetime. A running managed executable prevents replacement.
pub struct BinaryReadGuard {
    file: File,
}
impl Drop for BinaryReadGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn binary_lock(policy: &Policy, exclusive: bool) -> Result<BinaryReadGuard> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    parent(&policy.binary)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(policy.binary.with_extension("managed-update.lock"))
        .map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(UpdateError("managed_update_lock_invalid"));
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
        return Err(UpdateError("managed_update_binary_in_use"));
    }
    File::open(
        policy
            .binary
            .parent()
            .ok_or(UpdateError("managed_update_path_invalid"))?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(io)?;
    Ok(BinaryReadGuard { file })
}
fn owner_path(policy: &Policy) -> PathBuf {
    policy.binary.with_extension("managed-owner.json")
}
fn expected_owner(context: &Context, policy: &Policy) -> BinaryOwner {
    BinaryOwner {
        format: FORMAT,
        node_id: context.config.node_id.clone(),
        workspace: context.config.workspace.clone(),
        state_dir: context.config.state_dir.clone(),
        binary: policy.binary.clone(),
    }
}
fn require_owner(context: &Context, policy: &Policy) -> Result<()> {
    if load_json::<BinaryOwner>(&owner_path(policy))? != expected_owner(context, policy) {
        return Err(UpdateError(
            "managed_update_installation_owned_by_another_node",
        ));
    }
    Ok(())
}
fn installed(context: &Context, policy: &Policy) -> Result<Installed> {
    let state: Installed = load_json(&context.root().join(STATE))?;
    validate_installed(policy, &state)?;
    Ok(state)
}
fn validate_installed(policy: &Policy, state: &Installed) -> Result<()> {
    let current = verify(&state.current, &policy.trusted)?;
    if state.format != FORMAT
        || state.generation == 0
        || state.policy_sha256 != json_hash(policy)?
        || state.high_water_sequence < current.sequence
        || current.sequence < policy.minimum_sequence
        || version(&current.version)? < version(&policy.minimum_version)?
    {
        return Err(UpdateError("managed_update_installed_state_invalid"));
    }
    if let Some(previous) = &state.previous {
        let previous = verify(previous, &policy.trusted)?;
        if previous.sequence > state.high_water_sequence
            || previous.sequence < policy.minimum_sequence
            || version(&previous.version)? < version(&policy.minimum_version)?
        {
            return Err(UpdateError("managed_update_previous_state_invalid"));
        }
    }
    Ok(())
}
fn pending_absent(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root.join(PENDING)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(UpdateError("managed_update_pending_unavailable")),
        Ok(_) => Err(UpdateError("managed_update_recovery_required")),
    }
}
fn require_running_image(context: &Context, policy: &Policy, state: &Installed) -> Result<()> {
    require_exact_image(policy, state, &context.executable)
}
fn require_exact_image(policy: &Policy, state: &Installed, executable: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let release = verify(&state.current, &policy.trusted)?;
    let target = open_binary(&policy.binary, true)?;
    let running = File::open(executable).map_err(io)?;
    let a = target.metadata().map_err(io)?;
    let b = running.metadata().map_err(io)?;
    if a.dev() != b.dev() || a.ino() != b.ino() || release.version != env!("CARGO_PKG_VERSION") {
        return Err(UpdateError("managed_update_invoke_current_managed_binary"));
    }
    check_binary(&policy.binary, &release, true)
}
/// Call under executor.lock before loading journals, and retain the returned guard.
/// This supports the standalone Executor API without inventing TLS/cloud configuration.
pub(crate) fn standalone_startup_guard(
    node_state: &Path,
    node_id: &str,
    workspace: Option<&str>,
) -> Result<Option<BinaryReadGuard>> {
    require_no_pending(node_state)?;
    let path = node_state.join(POLICY);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
        Ok(_) => (),
    }
    let policy: Policy = load_json(&path)?;
    policy.validate_identity(node_id, workspace.unwrap_or(&policy.workspace))?;
    let guard = binary_lock(&policy, false)?;
    require_no_pending(node_state)?;
    let owner = BinaryOwner {
        format: FORMAT,
        node_id: node_id.into(),
        workspace: policy.workspace.clone(),
        state_dir: node_state.into(),
        binary: policy.binary.clone(),
    };
    if load_json::<BinaryOwner>(&owner_path(&policy))? != owner {
        return Err(UpdateError(
            "managed_update_installation_owned_by_another_node",
        ));
    }
    let state: Installed = load_json(&node_state.join("managed-updates").join(STATE))?;
    validate_installed(&policy, &state)?;
    require_exact_image(&policy, &state, &std::env::current_exe().map_err(io)?)?;
    Ok(Some(guard))
}
pub fn require_no_pending(node_state_dir: &Path) -> Result<()> {
    pending_absent(&node_state_dir.join("managed-updates"))
}
/// Only opt-in installations have a policy. A partial/corrupt policy or pending update fails closed.
pub fn startup_guard(config: &NodeConfig) -> Result<Option<BinaryReadGuard>> {
    let root = config.state_dir.join("managed-updates");
    pending_absent(&root)?;
    match fs::symlink_metadata(config.state_dir.join(POLICY)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(error)),
        Ok(_) => (),
    }
    let context = Context {
        config: config.clone(),
        key_path: PathBuf::new(),
        executable: std::env::current_exe().map_err(io)?,
    };
    let policy = context.policy()?;
    let guard = binary_lock(&policy, false)?;
    pending_absent(&root)?;
    require_owner(&context, &policy)?;
    let state = installed(&context, &policy)?;
    require_running_image(&context, &policy, &state)?;
    Ok(Some(guard))
}

fn parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(UpdateError("managed_update_path_must_be_absolute"));
    }
    let parent = path
        .parent()
        .ok_or(UpdateError("managed_update_path_invalid"))?;
    crate::retention::require_directory(parent)
        .map_err(|_| UpdateError("managed_update_directory_must_be_private"))?;
    if fs::canonicalize(parent).map_err(io)? != parent {
        return Err(UpdateError("managed_update_path_alias_forbidden"));
    }
    Ok(())
}
fn directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    parent(path)?;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => File::open(
            path.parent()
                .ok_or(UpdateError("managed_update_path_invalid"))?,
        )
        .and_then(|file| file.sync_all())
        .map_err(io)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(io(error)),
    }
    crate::retention::require_directory(path)
        .map_err(|_| UpdateError("managed_update_directory_must_be_private"))
}
fn open_regular(path: &Path, private: bool) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o022 != 0
        || (private && (meta.mode() & 0o077 != 0 || meta.nlink() != 1))
    {
        return Err(UpdateError("managed_update_file_unsafe"));
    }
    Ok(file)
}
fn open_binary(path: &Path, installed: bool) -> Result<File> {
    use std::os::unix::fs::MetadataExt;
    let file = open_regular(path, false)?;
    let meta = file.metadata().map_err(io)?;
    if meta.len() < 64
        || meta.len() > MAX_BINARY
        || (installed && (meta.nlink() != 1 || meta.mode() & 0o100 == 0))
    {
        return Err(UpdateError("managed_update_binary_unsafe"));
    }
    Ok(file)
}
fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut file = open_regular(path, true)?;
    if file.metadata().map_err(io)?.len() > MAX_JSON {
        return Err(UpdateError("managed_update_metadata_too_large"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_JSON + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_JSON {
        return Err(UpdateError("managed_update_metadata_too_large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| UpdateError("managed_update_metadata_invalid"))
}
fn private_new(path: &Path, executable: bool) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    parent(path)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if executable { 0o700 } else { 0o600 })
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io)
}
fn json_hash<T: Serialize>(value: &T) -> Result<String> {
    Ok(provenance::sha256(&serde_json::to_vec(value).map_err(
        |_| UpdateError("managed_update_metadata_invalid"),
    )?))
}
fn temporary_prefix(destination: &Path) -> String {
    format!(
        ".lockyard-managed-update-{}-",
        &provenance::sha256(destination.as_os_str().as_encoded_bytes())[..24]
    )
}
fn temporary_path(destination: &Path, namespace: &Path) -> Result<PathBuf> {
    Ok(destination.with_file_name(format!(
        "{}{}.tmp",
        temporary_prefix(namespace),
        crate::wire::new_id().map_err(|_| UpdateError("managed_update_entropy_unavailable"))?
    )))
}
fn is_managed_temporary(name: &str) -> bool {
    let Some(body) = name
        .strip_prefix(".lockyard-managed-update-")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    body.len() == 24 + 1 + 26
        && body.as_bytes()[24] == b'-'
        && body[..24]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && crate::wire::valid_ulid(&body[25..])
}
fn publish_json<T: Serialize>(path: &Path, value: &T, replace: bool) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| UpdateError("managed_update_metadata_invalid"))?;
    if bytes.len() as u64 > MAX_JSON {
        return Err(UpdateError("managed_update_metadata_too_large"));
    }
    let tmp = temporary_path(path, path)?;
    let result = (|| {
        let mut file = private_new(&tmp, false)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(io)?;
        if replace {
            fs::rename(&tmp, path).map_err(io)?;
        } else {
            fs::hard_link(&tmp, path).map_err(io)?;
            fs::remove_file(&tmp).map_err(io)?;
        }
        File::open(
            path.parent()
                .ok_or(UpdateError("managed_update_path_invalid"))?,
        )
        .and_then(|file| file.sync_all())
        .map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
fn hash_reader(mut file: File, expected: u64) -> Result<String> {
    let mut hash = digest::Context::new(&digest::SHA256);
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(UpdateError("managed_update_binary_changed"))?;
        if total > expected {
            return Err(UpdateError("managed_update_binary_changed"));
        }
        hash.update(&buffer[..count]);
    }
    if total != expected {
        return Err(UpdateError("managed_update_binary_changed"));
    }
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
fn check_binary(path: &Path, release: &Release, installed: bool) -> Result<()> {
    let mut file = open_binary(path, installed)?;
    if file.metadata().map_err(io)?.len() != release.binary_bytes {
        return Err(UpdateError("managed_update_binary_size_mismatch"));
    }
    let mut elf = [0u8; 64];
    file.read_exact(&mut elf).map_err(io)?;
    let machine = if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "aarch64") {
        183
    } else {
        return Err(UpdateError("managed_update_platform_unsupported"));
    };
    if &elf[..4] != b"\x7fELF"
        || elf[4] != 2
        || elf[5] != 1
        || !matches!(u16::from_le_bytes([elf[16], elf[17]]), 2 | 3)
        || u16::from_le_bytes([elf[18], elf[19]]) != machine
    {
        return Err(UpdateError("managed_update_elf_platform_mismatch"));
    }
    if hash_reader(open_binary(path, installed)?, release.binary_bytes)? != release.binary_sha256 {
        return Err(UpdateError("managed_update_binary_hash_mismatch"));
    }
    Ok(())
}
fn copy_verified(source: &Path, destination: &Path, release: &Release) -> Result<()> {
    copy_verified_in_namespace(source, destination, release, destination)
}
fn copy_verified_in_namespace(
    source: &Path,
    destination: &Path,
    release: &Release,
    namespace: &Path,
) -> Result<()> {
    check_binary(source, release, false)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => return check_binary(destination, release, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(io(error)),
    }
    let tmp = temporary_path(destination, namespace)?;
    let result = (|| {
        let mut input = open_binary(source, false)?;
        let mut output = private_new(&tmp, true)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        let mut total = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = input.read(&mut buffer).map_err(io)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(UpdateError("managed_update_binary_changed"))?;
            if total > release.binary_bytes {
                return Err(UpdateError("managed_update_binary_changed"));
            }
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count]).map_err(io)?;
        }
        if total != release.binary_bytes
            || hash
                .finish()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                != release.binary_sha256
        {
            return Err(UpdateError("managed_update_binary_changed"));
        }
        output.sync_all().map_err(io)?;
        fs::hard_link(&tmp, destination).map_err(io)?;
        fs::remove_file(&tmp).map_err(io)?;
        File::open(
            destination
                .parent()
                .ok_or(UpdateError("managed_update_path_invalid"))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(io)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

pub fn initialize(
    config_path: &Path,
    binary: &Path,
    public_key: &str,
    baseline_path: &Path,
) -> Result<serde_json::Value> {
    initialize_inner(
        &Context::load(config_path)?,
        binary,
        public_key,
        baseline_path,
    )
}
fn initialize_inner(
    context: &Context,
    binary: &Path,
    public_key: &str,
    baseline_path: &Path,
) -> Result<serde_json::Value> {
    let _maintenance = context.maintenance()?;
    cleanup_temporaries(
        &context.config.state_dir,
        Some(&[&context.config.state_dir.join(POLICY)]),
    )?;
    parent(binary)?;
    let baseline: SignedDocument = load_json(baseline_path)?;
    let trusted = TrustedSigningKey {
        public_key: public_key.into(),
    };
    let release = verify(&baseline, &trusted)?;
    release.fresh(now_ms()?)?;
    if release.version != env!("CARGO_PKG_VERSION") {
        return Err(UpdateError("managed_update_baseline_version_mismatch"));
    }
    check_binary(binary, &release, true)?;
    // The running CLI must be this exact baseline, or a byte-identical private copy.
    if hash_reader(
        open_binary(&context.executable, false)?,
        release.binary_bytes,
    )? != release.binary_sha256
    {
        return Err(UpdateError(
            "managed_update_baseline_is_not_current_executable",
        ));
    }
    let policy = Policy {
        format: FORMAT,
        node_id: context.config.node_id.clone(),
        workspace: context.config.workspace.clone(),
        binary: binary.into(),
        trusted,
        minimum_sequence: release.sequence,
        minimum_version: release.version.clone(),
    };
    let _binary = binary_lock(&policy, true)?;
    let root = context.root();
    directory(&root)?;
    pending_absent(&root)?;
    directory(&root.join("artifacts"))?;
    directory(&root.join("staged"))?;
    cleanup_unpublished(context, &policy.binary)?;
    let owner = expected_owner(context, &policy);
    match fs::symlink_metadata(owner_path(&policy)) {
        Ok(_) => require_owner(context, &policy)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            publish_json(&owner_path(&policy), &owner, false)?
        }
        Err(error) => return Err(io(error)),
    }
    copy_verified(binary, &artifact(&root, &release.binary_sha256), &release)?;
    let state = Installed {
        format: FORMAT,
        policy_sha256: json_hash(&policy)?,
        generation: 1,
        high_water_sequence: release.sequence,
        current: baseline,
        previous: None,
    };
    match fs::symlink_metadata(root.join(STATE)) {
        Ok(_) => {
            if load_json::<Installed>(&root.join(STATE))? != state {
                return Err(UpdateError("managed_update_already_initialized"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            publish_json(&root.join(STATE), &state, false)?
        }
        Err(error) => return Err(io(error)),
    }
    match fs::symlink_metadata(context.config.state_dir.join(POLICY)) {
        Ok(_) => {
            if context.policy()? != policy {
                return Err(UpdateError("managed_update_policy_conflict"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            publish_json(&context.config.state_dir.join(POLICY), &policy, false)?
        }
        Err(error) => return Err(io(error)),
    }
    Ok(
        serde_json::json!({"initialized":true,"binary":binary,"version":release.version,"sequence":release.sequence,"platform":platform(),"automatic_execution":false}),
    )
}
fn cleanup_temporaries(directory: &Path, allowed: Option<&[&Path]>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    crate::retention::require_directory(directory)
        .map_err(|_| UpdateError("managed_update_directory_must_be_private"))?;
    let mut removed = 0usize;
    for entry in fs::read_dir(directory).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_managed_temporary(name)
            || allowed.is_some_and(|paths| {
                !paths
                    .iter()
                    .any(|path| name.starts_with(&temporary_prefix(path)))
            })
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(io)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(UpdateError("managed_update_temporary_file_unsafe"));
        }
        fs::remove_file(entry.path()).map_err(io)?;
        removed += 1;
        if removed >= 64 {
            File::open(directory)
                .and_then(|file| file.sync_all())
                .map_err(io)?;
            return Err(UpdateError(
                "managed_update_temporary_cleanup_retry_required",
            ));
        }
    }
    if removed > 0 {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(io)?;
    }
    Ok(())
}
fn cleanup_unpublished(context: &Context, binary: &Path) -> Result<()> {
    let owner = binary.with_extension("managed-owner.json");
    cleanup_temporaries(
        binary
            .parent()
            .ok_or(UpdateError("managed_update_path_invalid"))?,
        Some(&[binary, &owner]),
    )?;
    let policy = context.config.state_dir.join(POLICY);
    cleanup_temporaries(&context.config.state_dir, Some(&[&policy]))?;
    let root = context.root();
    cleanup_temporaries(&root, None)?;
    cleanup_temporaries(&root.join("artifacts"), None)?;
    for entry in fs::read_dir(root.join("staged"))
        .map_err(io)?
        .take(MAX_STAGED + 1)
    {
        let entry = entry.map_err(io)?;
        cleanup_temporaries(&entry.path(), None)?;
    }
    Ok(())
}
fn artifact(root: &Path, sha256: &str) -> PathBuf {
    root.join("artifacts").join(format!("{sha256}.bin"))
}
fn prepared_path(root: &Path, release_sha256: &str) -> PathBuf {
    root.join("staged")
        .join(release_sha256)
        .join("prepared.json")
}
fn validate_prepared(
    context: &Context,
    policy: &Policy,
    state: &Installed,
    prepared: &Prepared,
) -> Result<Release> {
    let release = verify(&prepared.release, &policy.trusted)?;
    let current = verify(&state.current, &policy.trusted)?;
    if prepared.format != FORMAT
        || prepared.node_id != context.config.node_id
        || prepared.workspace != context.config.workspace
        || prepared.policy_sha256 != json_hash(policy)?
        || prepared.base_generation != state.generation
        || prepared.base_binary_sha256 != current.binary_sha256
        || release.sequence <= state.high_water_sequence
        || version(&release.version)? <= version(&current.version)?
        || version(&current.version)? < version(&release.minimum_current_version)?
    {
        return Err(UpdateError("managed_update_rollback_or_base_conflict"));
    }
    release.fresh(prepared.prepared_at_ms)?;
    Ok(release)
}
pub fn prepare(
    config_path: &Path,
    release_path: &Path,
    binary_path: &Path,
) -> Result<serde_json::Value> {
    prepare_inner(&Context::load(config_path)?, release_path, binary_path)
}
fn prepare_inner(
    context: &Context,
    release_path: &Path,
    binary_path: &Path,
) -> Result<serde_json::Value> {
    let _maintenance = context.maintenance()?;
    let policy = context.policy()?;
    let _binary = binary_lock(&policy, true)?;
    let root = context.root();
    pending_absent(&root)?;
    cleanup_unpublished(context, &policy.binary)?;
    require_owner(context, &policy)?;
    let state = installed(context, &policy)?;
    require_operator_image(context, &policy, &state, false)?;
    let document: SignedDocument = load_json(release_path)?;
    let release = verify(&document, &policy.trusted)?;
    let now = now_ms()?;
    release.fresh(now)?;
    let expected = Prepared {
        format: FORMAT,
        node_id: context.config.node_id.clone(),
        workspace: context.config.workspace.clone(),
        policy_sha256: json_hash(&policy)?,
        base_generation: state.generation,
        base_binary_sha256: verify(&state.current, &policy.trusted)?.binary_sha256,
        prepared_at_ms: now,
        release: document,
    };
    validate_prepared(context, &policy, &state, &expected)?;
    check_binary(binary_path, &release, false)?;
    let id = json_hash(&expected.release)?;
    let directory_path = root.join("staged").join(&id);
    let path = prepared_path(&root, &id);
    let prepared = match fs::symlink_metadata(&directory_path) {
        Ok(_) => match fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing: Prepared = load_json(&path)?;
                validate_prepared(context, &policy, &state, &existing)?;
                if existing.release != expected.release {
                    return Err(UpdateError("managed_update_preparation_conflict"));
                }
                existing
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                copy_verified(binary_path, &directory_path.join("binary"), &release)?;
                publish_json(&path, &expected, false)?;
                expected
            }
            Err(error) => return Err(io(error)),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut count = 0usize;
            for entry in fs::read_dir(root.join("staged")).map_err(io)? {
                entry.map_err(io)?;
                count += 1;
                if count >= MAX_STAGED {
                    return Err(UpdateError("managed_update_staging_capacity_reached"));
                }
            }
            directory(&directory_path)?;
            copy_verified(binary_path, &directory_path.join("binary"), &release)?;
            publish_json(&path, &expected, false)?;
            expected
        }
        Err(error) => return Err(io(error)),
    };
    check_binary(&directory_path.join("binary"), &release, false)?;
    Ok(
        serde_json::json!({"prepared":path,"approval_sha256":json_hash(&prepared)?,"version":release.version,"sequence":release.sequence,
        "binary_sha256":release.binary_sha256,"platform":release.platform,"requires_stopped_drained_node":true,"automatic_execution":false}),
    )
}
fn rollback_approval(context: &Context, policy: &Policy, state: &Installed) -> Result<String> {
    let previous = state
        .previous
        .as_ref()
        .ok_or(UpdateError("managed_update_no_verified_previous_install"))?;
    json_hash(&(
        "lockyard-managed-rollback-v1",
        &context.config.node_id,
        &context.config.workspace,
        json_hash(policy)?,
        json_hash(state)?,
        json_hash(previous)?,
    ))
}
fn require_operator_image(
    context: &Context,
    policy: &Policy,
    state: &Installed,
    previous_allowed: bool,
) -> Result<()> {
    let candidates = std::iter::once(&state.current).chain(if previous_allowed {
        state.previous.as_ref()
    } else {
        None
    });
    for document in candidates {
        let release = verify(document, &policy.trusted)?;
        if release.version == env!("CARGO_PKG_VERSION")
            && check_binary(&context.executable, &release, false).is_ok()
        {
            return Ok(());
        }
    }
    Err(UpdateError(
        "managed_update_invoke_verified_current_or_previous_binary",
    ))
}
fn next_state(
    policy: &Policy,
    state: &Installed,
    new_image: SignedDocument,
    rollback: bool,
) -> Result<Installed> {
    let release = verify(&new_image, &policy.trusted)?;
    Ok(Installed {
        format: FORMAT,
        policy_sha256: state.policy_sha256.clone(),
        generation: state
            .generation
            .checked_add(1)
            .ok_or(UpdateError("managed_update_generation_exhausted"))?,
        high_water_sequence: if rollback {
            state.high_water_sequence
        } else {
            state.high_water_sequence.max(release.sequence)
        },
        current: new_image,
        previous: Some(state.current.clone()),
    })
}
pub fn apply(
    config_path: &Path,
    prepared_file: &Path,
    approval_sha256: &str,
) -> Result<serde_json::Value> {
    apply_inner(
        &Context::load(config_path)?,
        prepared_file,
        approval_sha256,
        None,
    )
}
fn apply_inner(
    context: &Context,
    prepared_file: &Path,
    approval_sha256: &str,
    interrupt: Option<Phase>,
) -> Result<serde_json::Value> {
    let _maintenance = context.maintenance()?;
    let policy = context.policy()?;
    let _binary = binary_lock(&policy, true)?;
    let root = context.root();
    pending_absent(&root)?;
    cleanup_unpublished(context, &policy.binary)?;
    require_owner(context, &policy)?;
    let state = installed(context, &policy)?;
    require_operator_image(context, &policy, &state, false)?;
    let prepared: Prepared = load_json(prepared_file)?;
    let release = validate_prepared(context, &policy, &state, &prepared)?;
    if json_hash(&prepared)? != approval_sha256 {
        return Err(UpdateError("managed_update_approval_digest_mismatch"));
    }
    let canonical_prepared = prepared_path(&root, &json_hash(&prepared.release)?);
    if prepared_file != canonical_prepared {
        return Err(UpdateError("managed_update_preparation_path_mismatch"));
    }
    let now = now_ms()?;
    release.fresh(now)?;
    if now < prepared.prepared_at_ms {
        return Err(UpdateError("managed_update_clock_rollback"));
    }
    let from = verify(&state.current, &policy.trusted)?;
    check_binary(&policy.binary, &from, true)?;
    copy_verified(&policy.binary, &artifact(&root, &from.binary_sha256), &from)?;
    copy_verified(
        &prepared_file
            .parent()
            .ok_or(UpdateError("managed_update_path_invalid"))?
            .join("binary"),
        &artifact(&root, &release.binary_sha256),
        &release,
    )?;
    let to = next_state(&policy, &state, prepared.release.clone(), false)?;
    let journal = Journal {
        format: FORMAT,
        node_id: context.config.node_id.clone(),
        workspace: context.config.workspace.clone(),
        policy_sha256: json_hash(&policy)?,
        approval_sha256: approval_sha256.into(),
        authorized_at_ms: now,
        action: Action::Apply,
        from: state,
        to,
    };
    publish_json(&root.join("approved-preparation.json"), &prepared, true)?;
    publish_json(&root.join(PENDING), &journal, false)?;
    finish_transaction(context, &policy, &journal, interrupt)?;
    status_inner(context)
}
pub fn rollback(config_path: &Path, approval_sha256: &str) -> Result<serde_json::Value> {
    rollback_inner(&Context::load(config_path)?, approval_sha256, None)
}
fn rollback_inner(
    context: &Context,
    approval_sha256: &str,
    interrupt: Option<Phase>,
) -> Result<serde_json::Value> {
    let _maintenance = context.maintenance()?;
    let policy = context.policy()?;
    let _binary = binary_lock(&policy, true)?;
    let root = context.root();
    pending_absent(&root)?;
    cleanup_unpublished(context, &policy.binary)?;
    require_owner(context, &policy)?;
    let state = installed(context, &policy)?;
    require_operator_image(context, &policy, &state, true)?;
    if rollback_approval(context, &policy, &state)? != approval_sha256 {
        return Err(UpdateError("managed_update_approval_digest_mismatch"));
    }
    let previous = state
        .previous
        .clone()
        .ok_or(UpdateError("managed_update_no_verified_previous_install"))?;
    let release = verify(&previous, &policy.trusted)?;
    check_binary(&artifact(&root, &release.binary_sha256), &release, false)?;
    let now = now_ms()?;
    let to = next_state(&policy, &state, previous, true)?;
    let journal = Journal {
        format: FORMAT,
        node_id: context.config.node_id.clone(),
        workspace: context.config.workspace.clone(),
        policy_sha256: json_hash(&policy)?,
        approval_sha256: approval_sha256.into(),
        authorized_at_ms: now,
        action: Action::Rollback,
        from: state,
        to,
    };
    publish_json(&root.join(PENDING), &journal, false)?;
    finish_transaction(context, &policy, &journal, interrupt)?;
    status_inner(context)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Journal,
    Binary,
    State,
}
fn verify_transition(context: &Context, policy: &Policy, journal: &Journal) -> Result<()> {
    validate_installed(policy, &journal.from)?;
    validate_installed(policy, &journal.to)?;
    let from = verify(&journal.from.current, &policy.trusted)?;
    let to = verify(&journal.to.current, &policy.trusted)?;
    if journal.format != FORMAT
        || journal.node_id != context.config.node_id
        || journal.workspace != context.config.workspace
        || journal.policy_sha256 != json_hash(policy)?
        || journal.from.policy_sha256 != journal.policy_sha256
        || journal.to.policy_sha256 != journal.policy_sha256
        || journal.to.format != FORMAT
        || journal.from.format != FORMAT
        || journal.from.generation == 0
        || journal.to.generation
            != journal
                .from
                .generation
                .checked_add(1)
                .ok_or(UpdateError("managed_update_generation_exhausted"))?
        || journal.to.previous.as_ref() != Some(&journal.from.current)
        || journal.from.high_water_sequence < from.sequence
        || from.sequence < policy.minimum_sequence
        || to.sequence < policy.minimum_sequence
        || version(&to.version)? < version(&policy.minimum_version)?
    {
        return Err(UpdateError("managed_update_journal_invalid"));
    }
    match journal.action {
        Action::Apply => {
            let prepared: Prepared = load_json(&context.root().join("approved-preparation.json"))?;
            let release = validate_prepared(context, policy, &journal.from, &prepared)?;
            release.fresh(journal.authorized_at_ms)?;
            if prepared.prepared_at_ms > journal.authorized_at_ms
                || json_hash(&prepared)? != journal.approval_sha256
                || prepared.release != journal.to.current
                || journal.to.high_water_sequence
                    != journal.from.high_water_sequence.max(to.sequence)
            {
                return Err(UpdateError("managed_update_journal_approval_invalid"));
            }
        }
        Action::Rollback => {
            if journal.from.previous.as_ref() != Some(&journal.to.current)
                || journal.to.high_water_sequence != journal.from.high_water_sequence
                || rollback_approval(context, policy, &journal.from)? != journal.approval_sha256
            {
                return Err(UpdateError("managed_update_journal_rollback_invalid"));
            }
        }
    }
    Ok(())
}
fn finish_transaction(
    context: &Context,
    policy: &Policy,
    journal: &Journal,
    interrupt: Option<Phase>,
) -> Result<()> {
    verify_transition(context, policy, journal)?;
    if interrupt == Some(Phase::Journal) {
        return Err(UpdateError("managed_update_injected_crash"));
    }
    let root = context.root();
    let from = verify(&journal.from.current, &policy.trusted)?;
    let to = verify(&journal.to.current, &policy.trusted)?;
    let state: Installed = load_json(&root.join(STATE))?;
    if state != journal.from && state != journal.to {
        return Err(UpdateError("managed_update_state_changed_during_recovery"));
    }
    let current_hash = hash_reader(
        open_binary(&policy.binary, true)?,
        fs::metadata(&policy.binary).map_err(io)?.len(),
    )?;
    if current_hash != from.binary_sha256 && current_hash != to.binary_sha256 {
        return Err(UpdateError("managed_update_binary_changed_during_recovery"));
    }
    let source = artifact(&root, &to.binary_sha256);
    check_binary(&source, &to, false)?;
    if current_hash != to.binary_sha256 {
        let replacement = policy
            .binary
            .with_extension(format!("replacement-{}", journal.approval_sha256));
        copy_verified_in_namespace(&source, &replacement, &to, &policy.binary)?;
        check_binary(&replacement, &to, true)?;
        fs::rename(&replacement, &policy.binary).map_err(io)?;
        File::open(
            policy
                .binary
                .parent()
                .ok_or(UpdateError("managed_update_path_invalid"))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(io)?;
    }
    if interrupt == Some(Phase::Binary) {
        return Err(UpdateError("managed_update_injected_crash"));
    }
    publish_json(&root.join(STATE), &journal.to, true)?;
    if interrupt == Some(Phase::State) {
        return Err(UpdateError("managed_update_injected_crash"));
    }
    fs::remove_file(root.join(PENDING)).map_err(io)?;
    File::open(&root)
        .and_then(|directory| directory.sync_all())
        .map_err(io)?;
    cleanup_artifacts(context, policy, &journal.to)?;
    Ok(())
}
pub fn recover(config_path: &Path, approval_sha256: &str) -> Result<serde_json::Value> {
    recover_inner(&Context::load(config_path)?, approval_sha256)
}
fn recover_inner(context: &Context, approval_sha256: &str) -> Result<serde_json::Value> {
    let _maintenance = context.maintenance()?;
    let policy = context.policy()?;
    let _binary = binary_lock(&policy, true)?;
    cleanup_unpublished(context, &policy.binary)?;
    require_owner(context, &policy)?;
    let journal: Journal = load_json(&context.root().join(PENDING))?;
    verify_transition(context, &policy, &journal)?;
    if journal.approval_sha256 != approval_sha256 {
        return Err(UpdateError("managed_update_approval_digest_mismatch"));
    }
    // A verified previous executable is an explicit recovery tool if the new image cannot start.
    if require_operator_image(context, &policy, &journal.from, true).is_err() {
        require_operator_image(context, &policy, &journal.to, true)?;
    }
    finish_transaction(context, &policy, &journal, None)?;
    status_inner(context)
}
fn cleanup_artifacts(context: &Context, policy: &Policy, state: &Installed) -> Result<()> {
    let current = verify(&state.current, &policy.trusted)?.binary_sha256;
    let previous = state
        .previous
        .as_ref()
        .map(|value| verify(value, &policy.trusted).map(|release| release.binary_sha256))
        .transpose()?;
    let dir = context.root().join("artifacts");
    let mut count = 0usize;
    for entry in fs::read_dir(&dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        count += 1;
        if count > MAX_STAGED + 4 {
            return Err(UpdateError("managed_update_artifact_capacity_invalid"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError("managed_update_artifact_invalid"))?;
        let Some(hash) = name
            .strip_suffix(".bin")
            .filter(|hash| crate::wire::valid_certificate_pin(hash))
        else {
            return Err(UpdateError("managed_update_artifact_invalid"));
        };
        if hash != current && previous.as_deref() != Some(hash) {
            fs::remove_file(entry.path()).map_err(io)?;
        }
    }
    File::open(dir)
        .and_then(|directory| directory.sync_all())
        .map_err(io)?;
    let staged = context.root().join("staged");
    let mut count = 0usize;
    for entry in fs::read_dir(&staged).map_err(io)? {
        let entry = entry.map_err(io)?;
        count += 1;
        if count > MAX_STAGED {
            return Err(UpdateError("managed_update_staging_capacity_invalid"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UpdateError("managed_update_staging_invalid"))?;
        if !crate::wire::valid_certificate_pin(&name) {
            return Err(UpdateError("managed_update_staging_invalid"));
        }
        crate::retention::require_directory(&entry.path())
            .map_err(|_| UpdateError("managed_update_staging_invalid"))?;
        fs::remove_dir_all(entry.path()).map_err(io)?;
    }
    File::open(staged)
        .and_then(|directory| directory.sync_all())
        .map_err(io)
}
pub fn status(config_path: &Path) -> Result<serde_json::Value> {
    status_inner(&Context::load(config_path)?)
}
fn status_inner(context: &Context) -> Result<serde_json::Value> {
    let policy = context.policy()?;
    require_owner(context, &policy)?;
    let state = installed(context, &policy)?;
    let current = verify(&state.current, &policy.trusted)?;
    let previous = state
        .previous
        .as_ref()
        .map(|value| verify(value, &policy.trusted))
        .transpose()?;
    let pending = match fs::symlink_metadata(context.root().join(PENDING)) {
        Ok(_) => {
            let journal: Journal = load_json(&context.root().join(PENDING))?;
            verify_transition(context, &policy, &journal)?;
            Some(
                serde_json::json!({"action":journal.action,"approval_sha256":journal.approval_sha256,"target":verify(&journal.to.current,&policy.trusted)?}),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(io(error)),
    };
    let rollback_approval = if state.previous.is_some() {
        Some(rollback_approval(context, &policy, &state)?)
    } else {
        None
    };
    Ok(
        serde_json::json!({"binary":policy.binary,"current":current,"previous":previous,"generation":state.generation,
        "high_water_sequence":state.high_water_sequence,"pending":pending,"rollback_approval_sha256":rollback_approval,
        "verified_previous_binary":previous.as_ref().map(|release|artifact(&context.root(),&release.binary_sha256)),"automatic_execution":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
        context: Context,
        signer: SigningKey,
        baseline: SignedDocument,
    }
    fn private(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn future_version(patch_offset: u32) -> String {
        let [major, minor, patch] = version(env!("CARGO_PKG_VERSION")).unwrap();
        format!(
            "{major}.{minor}.{}",
            patch.checked_add(patch_offset).unwrap()
        )
    }
    fn executable(path: &Path, marker: &[u8]) {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[16] = 3;
        let machine: u16 = if cfg!(target_arch = "x86_64") {
            62
        } else {
            183
        };
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes.extend_from_slice(marker);
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn release(
        signer: &SigningKey,
        binary: &Path,
        version_value: &str,
        sequence: u64,
    ) -> SignedDocument {
        let bytes = fs::read(binary).unwrap();
        let now = now_ms().unwrap();
        signer
            .sign_document(
                DOMAIN,
                &Release {
                    format: FORMAT,
                    release_id: crate::wire::new_id().unwrap(),
                    version: version_value.into(),
                    sequence,
                    platform: platform(),
                    minimum_current_version: env!("CARGO_PKG_VERSION").into(),
                    state_schema_version: 1,
                    binary_sha256: provenance::sha256(&bytes),
                    binary_bytes: bytes.len() as u64,
                    issued_at_ms: now - 1000,
                    expires_at_ms: now + 3_600_000,
                },
            )
            .unwrap()
    }
    fn fixture() -> Fixture {
        // Tiny signed ELF-shaped byte fixtures prove verification/file/journal behavior.
        // No fixture is executed and this does not claim a release binary E2E rollout.
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path().canonicalize().unwrap();
        private(root.as_path());
        let state = root.as_path().join("node");
        fs::create_dir(&state).unwrap();
        private(&state);
        let keys = root.as_path().join("keys");
        fs::create_dir(&keys).unwrap();
        private(&keys);
        let key_path = keys.join("workspace.key");
        fs::write(&key_path, [7u8; 32]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(state.join("operator-drain"), b"1").unwrap();
        fs::set_permissions(
            state.join("operator-drain"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let install = root.as_path().join("install");
        fs::create_dir(&install).unwrap();
        private(&install);
        let binary = install.join("lockyard");
        executable(&binary, b"baseline-never-executed");
        let config:NodeConfig=serde_json::from_value(serde_json::json!({"node_id":"worker","workspace":"workspace","state_dir":state,
            "certificate":root.as_path().join("cert"),"private_key":root.as_path().join("tls-key"),"trust_anchors":[],"peers":[],"rpc_timeout_seconds":60})).unwrap();
        let signer = SigningKey::generate(&root.as_path().join("release.pk8")).unwrap();
        let baseline = release(&signer, &binary, env!("CARGO_PKG_VERSION"), 1);
        let baseline_path = root.as_path().join("baseline.json");
        publish_json(&baseline_path, &baseline, false).unwrap();
        let context = Context {
            config,
            key_path,
            executable: binary.clone(),
        };
        initialize_inner(
            &context,
            &binary,
            &signer.trusted_key().public_key,
            &baseline_path,
        )
        .unwrap();
        Fixture {
            _root: tempdir,
            root,
            context,
            signer,
            baseline,
        }
    }
    fn candidate(
        f: &Fixture,
        version_value: &str,
        sequence: u64,
    ) -> (PathBuf, PathBuf, SignedDocument) {
        let binary = f.root.as_path().join(format!("candidate-{sequence}"));
        executable(
            &binary,
            format!("candidate-{sequence}-never-executed").as_bytes(),
        );
        let document = release(&f.signer, &binary, version_value, sequence);
        let release_path = f.root.as_path().join(format!("release-{sequence}.json"));
        publish_json(&release_path, &document, false).unwrap();
        (binary, release_path, document)
    }
    fn prepared(f: &Fixture) -> (PathBuf, String, SignedDocument) {
        let (binary, path, document) = candidate(f, &future_version(1), 2);
        let result = prepare_inner(&f.context, &path, &binary).unwrap();
        (
            PathBuf::from(result["prepared"].as_str().unwrap()),
            result["approval_sha256"].as_str().unwrap().into(),
            document,
        )
    }
    fn previous_context(f: &Fixture) -> Context {
        let policy = f.context.policy().unwrap();
        let baseline = verify(&f.baseline, &policy.trusted).unwrap();
        Context {
            config: f.context.config.clone(),
            key_path: f.context.key_path.clone(),
            executable: artifact(&f.context.root(), &baseline.binary_sha256),
        }
    }
    #[test]
    fn signed_update_and_explicit_verified_previous_rollback_preserve_high_water_and_never_execute()
    {
        let f = fixture();
        let (prepared, approval, new_document) = prepared(&f);
        let policy = f.context.policy().unwrap();
        let result = apply_inner(&f.context, &prepared, &approval, None).unwrap();
        assert_eq!(result["current"]["version"], future_version(1));
        let new = verify(&new_document, &policy.trusted).unwrap();
        assert_eq!(
            provenance::sha256(&fs::read(&policy.binary).unwrap()),
            new.binary_sha256
        );
        assert_eq!(result["automatic_execution"], false);
        assert!(!f.context.root().join(PENDING).exists());
        let recovery = previous_context(&f);
        let digest = result["rollback_approval_sha256"].as_str().unwrap();
        let rolled = rollback_inner(&recovery, digest, None).unwrap();
        assert_eq!(rolled["current"]["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(rolled["high_water_sequence"], 2);
        assert_eq!(rolled["generation"], 3);
        assert!(rollback_inner(&recovery, digest, None).is_err()); // Reviewed generation digest is one use.
        let new_path = f.root.as_path().join("release-2.json");
        let binary = f.root.as_path().join("candidate-2");
        assert_eq!(
            prepare_inner(&f.context, &new_path, &binary).unwrap_err().0,
            "managed_update_rollback_or_base_conflict"
        );
        assert_eq!(
            fs::read(f.context.config.state_dir.join("operator-drain")).unwrap(),
            b"1"
        );
    }
    #[test]
    fn wrong_approval_changed_binary_signature_platform_and_minimum_version_refuse_before_mutation()
    {
        let f = fixture();
        let (prepared, approval, _) = prepared(&f);
        let policy = f.context.policy().unwrap();
        let old = fs::read(&policy.binary).unwrap();
        assert_eq!(
            apply_inner(&f.context, &prepared, &"a".repeat(64), None)
                .unwrap_err()
                .0,
            "managed_update_approval_digest_mismatch"
        );
        assert_eq!(fs::read(&policy.binary).unwrap(), old);
        assert!(!f.context.root().join(PENDING).exists());
        fs::write(prepared.parent().unwrap().join("binary"), b"tampered").unwrap();
        assert!(apply_inner(&f.context, &prepared, &approval, None).is_err());
        assert_eq!(fs::read(&policy.binary).unwrap(), old);
        let (candidate, path, document) = candidate(&f, &future_version(2), 3);
        let mut statement = verify(&document, &policy.trusted).unwrap();
        statement.platform = "different-platform".into();
        let wrong = f.signer.sign_document(DOMAIN, &statement).unwrap();
        let wrong_path = f.root.as_path().join("wrong-platform.json");
        publish_json(&wrong_path, &wrong, false).unwrap();
        assert!(prepare_inner(&f.context, &wrong_path, &candidate).is_err());
        statement.platform = platform();
        statement.minimum_current_version = future_version(1);
        let wrong = f.signer.sign_document(DOMAIN, &statement).unwrap();
        let wrong_path = f.root.as_path().join("wrong-minimum.json");
        publish_json(&wrong_path, &wrong, false).unwrap();
        assert!(prepare_inner(&f.context, &wrong_path, &candidate).is_err());
        let attacker = SigningKey::generate(&f.root.as_path().join("attacker.pk8")).unwrap();
        let attack = attacker.sign_document(DOMAIN, &statement).unwrap();
        let attack_path = f.root.as_path().join("wrong-signature.json");
        publish_json(&attack_path, &attack, false).unwrap();
        assert!(prepare_inner(&f.context, &attack_path, &candidate).is_err());
        assert!(prepare_inner(&f.context, &path, &candidate).is_ok());
    }
    #[test]
    fn every_committed_crash_boundary_blocks_startup_and_recovers_only_the_original_approved_transition()
     {
        for phase in [Phase::Journal, Phase::Binary, Phase::State] {
            let f = fixture();
            let (prepared, approval, new) = prepared(&f);
            assert_eq!(
                apply_inner(&f.context, &prepared, &approval, Some(phase))
                    .unwrap_err()
                    .0,
                "managed_update_injected_crash"
            );
            assert!(f.context.root().join(PENDING).exists());
            // Crash between create-only link publication and temporary unlink.
            let alias = temporary_path(
                &f.context.root().join(PENDING),
                &f.context.root().join(PENDING),
            )
            .unwrap();
            fs::hard_link(f.context.root().join(PENDING), &alias).unwrap();
            assert_eq!(
                startup_guard(&f.context.config).err().unwrap().0,
                "managed_update_recovery_required"
            );
            assert!(recover_inner(&previous_context(&f), &"b".repeat(64)).is_err());
            let recovered = recover_inner(&previous_context(&f), &approval).unwrap();
            assert_eq!(recovered["current"]["version"], future_version(1));
            assert!(!f.context.root().join(PENDING).exists());
            assert!(!alias.exists());
            let policy = f.context.policy().unwrap();
            assert_eq!(installed(&f.context, &policy).unwrap().current, new);
        }
    }
    #[test]
    fn rollback_crash_is_durable_and_recovery_does_not_lower_the_antirollback_sequence() {
        let f = fixture();
        let (prepared, approval, _) = prepared(&f);
        let installed_value = apply_inner(&f.context, &prepared, &approval, None).unwrap();
        let rollback = installed_value["rollback_approval_sha256"]
            .as_str()
            .unwrap();
        let previous = previous_context(&f);
        assert_eq!(
            rollback_inner(&previous, rollback, Some(Phase::Binary))
                .unwrap_err()
                .0,
            "managed_update_injected_crash"
        );
        let recovered = recover_inner(&previous, rollback).unwrap();
        assert_eq!(recovered["high_water_sequence"], 2);
        assert_eq!(recovered["current"]["version"], env!("CARGO_PKG_VERSION"));
    }
    #[test]
    fn corrupt_pending_or_unknown_replacement_is_never_overwritten_during_recovery() {
        let f = fixture();
        let (prepared, approval, _) = prepared(&f);
        apply_inner(&f.context, &prepared, &approval, Some(Phase::Journal)).unwrap_err();
        let policy = f.context.policy().unwrap();
        let mut bytes = fs::read(&policy.binary).unwrap();
        bytes[63] ^= 1;
        fs::write(&policy.binary, &bytes).unwrap();
        assert!(recover_inner(&previous_context(&f), &approval).is_err());
        assert_eq!(fs::read(&policy.binary).unwrap(), bytes);
        assert!(f.context.root().join(PENDING).exists());
        fs::remove_file(f.context.root().join(PENDING)).unwrap();
        symlink(f.root.as_path(), f.context.root().join(PENDING)).unwrap();
        assert_eq!(
            startup_guard(&f.context.config).err().unwrap().0,
            "managed_update_recovery_required"
        );
    }
    #[test]
    fn active_jobs_running_host_binary_readers_or_missing_drain_block_all_installs() {
        let f = fixture();
        let (prepared, approval, _) = prepared(&f);
        let policy = f.context.policy().unwrap();
        let before = fs::read(&policy.binary).unwrap();
        let reader = binary_lock(&policy, false).unwrap();
        assert_eq!(
            apply_inner(&f.context, &prepared, &approval, None)
                .unwrap_err()
                .0,
            "managed_update_binary_in_use"
        );
        drop(reader);
        use std::os::fd::AsRawFd;
        let host = OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.context.config.state_dir.join("host.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(host.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(apply_inner(&f.context, &prepared, &approval, None).is_err());
        unsafe {
            libc::flock(host.as_raw_fd(), libc::LOCK_UN);
        }
        fs::write(f.context.config.state_dir.join("operator-drain"), b"0").unwrap();
        assert!(apply_inner(&f.context, &prepared, &approval, None).is_err());
        fs::write(f.context.config.state_dir.join("operator-drain"), b"1").unwrap();
        let jobs = f.context.config.state_dir.join("executor/jobs");
        directory(&jobs).unwrap();
        let id = crate::wire::new_id().unwrap();
        let job = jobs.join(&id);
        directory(&job).unwrap();
        let record = serde_json::json!({"spec":{"id":id,"repository":"repo","revision":"HEAD","runner":"runner","arguments":[],"prompt":null,"timeout_seconds":null},
            "state":"interrupted_unknown","agent":"derived","submitter":"controller","created_at":1,"updated_at":1,"resolved_revision":null,"worktree":null,"pid":null,
            "exit_code":null,"error_code":null,"log_bytes":0,"log_truncated":false});
        publish_json(&job.join("record.json"), &record, false).unwrap();
        assert!(apply_inner(&f.context, &prepared, &approval, None).is_err());
        assert_eq!(fs::read(&policy.binary).unwrap(), before);
        assert!(!f.context.root().join(PENDING).exists());
    }
    #[test]
    fn temporary_cleanup_preserves_unrelated_private_files_and_other_installation_namespaces() {
        let f = fixture();
        let policy = f.context.policy().unwrap();
        let parent = policy.binary.parent().unwrap();
        let generic = parent.join(".01ARZ3NDEKTSV4RRFFQ69G5FAV.tmp");
        let user_state = f
            .context
            .config
            .state_dir
            .join(".01ARZ3NDEKTSV4RRFFQ69G5FAV.tmp");
        let other_binary = parent.join("another-managed-node");
        let other_stage = temporary_path(&other_binary, &other_binary).unwrap();
        for path in [&generic, &user_state, &other_stage] {
            let mut file = private_new(path, false).unwrap();
            file.write_all(b"private-unrelated-data").unwrap();
        }
        let (candidate, release, _) = candidate(&f, &future_version(1), 2);
        let other_path = other_stage.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let other = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            done_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
            assert_eq!(fs::read(other_path).unwrap(), b"private-unrelated-data");
        });
        ready_rx.recv().unwrap();
        prepare_inner(&f.context, &release, &candidate).unwrap();
        done_tx.send(()).unwrap();
        other.join().unwrap();
        for path in [&generic, &user_state, &other_stage] {
            assert_eq!(fs::read(path).unwrap(), b"private-unrelated-data");
        }
    }
    #[test]
    fn partial_preparation_resumes_but_links_permissions_and_unsupported_elf_fail_closed() {
        let f = fixture();
        let (binary, release_path, document) = candidate(&f, &future_version(1), 2);
        let staged = f
            .context
            .root()
            .join("staged")
            .join(json_hash(&document).unwrap());
        directory(&staged).unwrap();
        let orphan = temporary_path(&staged.join("binary"), &staged.join("binary")).unwrap();
        let mut interrupted = private_new(&orphan, true).unwrap();
        interrupted
            .write_all(b"uncommitted-partial-binary")
            .unwrap();
        drop(interrupted);
        assert!(prepare_inner(&f.context, &release_path, &binary).is_ok());
        assert!(!orphan.exists());
        let alias = f.root.as_path().join("binary-alias");
        symlink(&binary, &alias).unwrap();
        assert!(prepare_inner(&f.context, &release_path, &alias).is_err());
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prepare_inner(&f.context, &release_path, &binary).is_err());
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let mut malformed = fs::read(&binary).unwrap();
        malformed[..4].copy_from_slice(b"nope");
        fs::write(&binary, &malformed).unwrap();
        let document = release(&f.signer, &binary, &future_version(2), 3);
        let path = f.root.as_path().join("non-elf.json");
        publish_json(&path, &document, false).unwrap();
        assert!(prepare_inner(&f.context, &path, &binary).is_err());
    }
}
