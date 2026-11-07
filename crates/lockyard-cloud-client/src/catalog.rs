// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! EP-07: authenticate metadata before decrypting, then publish envelope and highwater together.
use crate::WorkspaceKey;
use lockyard_core::catalog::{
    CATALOG_FORMAT, CatalogError, CoordinationZoneCatalog, CoordinationZoneCatalogWrite,
    MAX_CATALOG_REVISION, MAX_CATALOG_WIRE, ZoneCatalogV1, validate_catalog_scope,
};
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

pub const CATALOG_CONTENT_FIELD: &str = "zone_catalog_content";
const MAC_PURPOSE: &[u8] = b"lockyard-zone-catalog-metadata-hmac-v1";
fn error(code: &'static str) -> CatalogError {
    CatalogError::new(code)
}
fn sha256(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
/// These canonical arrays contain only strings, booleans and safe unsigned integers;
/// serde_json emits the exact RFC8785 spelling of those restricted scalar types.
fn authenticated_bytes(wire: &CoordinationZoneCatalog) -> Vec<u8> {
    serde_json::to_vec(&json!([
        wire.format,
        wire.workspace_id,
        wire.repository,
        wire.revision,
        wire.key_id,
        wire.case_insensitive_paths,
        wire.content_sha256
    ]))
    .expect("fixed scalar array")
}
fn metadata_key(
    key: &WorkspaceKey,
    workspace: &str,
    repository: &str,
) -> Result<WorkspaceKey, CatalogError> {
    key.derive_context(
        MAC_PURPOSE,
        &serde_json::to_vec(&[workspace, repository]).expect("string array"),
    )
    .map_err(|_| error("catalog_authentication_failed"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogHighwater {
    pub revision: u64,
    pub authenticated_fingerprint: String,
}
/// Construction is private: an arbitrary JSON `verified:true` never creates this capability.
#[derive(Debug, Clone)]
pub struct VerifiedZoneCatalog {
    wire: CoordinationZoneCatalog,
    plaintext: ZoneCatalogV1,
    highwater: CatalogHighwater,
    offline: bool,
}
impl VerifiedZoneCatalog {
    pub fn wire(&self) -> &CoordinationZoneCatalog {
        &self.wire
    }
    pub fn highwater(&self) -> &CatalogHighwater {
        &self.highwater
    }
    pub fn expand(&self, names: &[String]) -> Result<Vec<String>, CatalogError> {
        self.plaintext.expand(names)
    }
    pub fn read_json(&self) -> Value {
        let mut value = json!({"format":self.wire.format,"repository":self.wire.repository,
            "revision":self.wire.revision,"case_insensitive_paths":self.wire.case_insensitive_paths,
            "zones":self.plaintext.zones,"groups":self.plaintext.groups,"verified":true});
        if self.offline {
            value["offline"] = json!(true);
        }
        value
    }
}

/// Encrypt exactly once; callers retain this complete body and their idempotency key for retries.
pub fn seal_catalog(
    key: &WorkspaceKey,
    workspace: &str,
    repository: &str,
    expected_revision: u64,
    case_insensitive_paths: bool,
    plaintext: &ZoneCatalogV1,
) -> Result<CoordinationZoneCatalogWrite, CatalogError> {
    validate_catalog_scope(workspace, repository)?;
    plaintext.validate()?;
    if expected_revision >= MAX_CATALOG_REVISION {
        return Err(error("catalog_invalid"));
    }
    let content = key
        .encrypt(
            workspace,
            CATALOG_CONTENT_FIELD,
            &serde_json::to_string(plaintext).map_err(|_| error("catalog_invalid"))?,
        )
        .map_err(|_| error("catalog_authentication_failed"))?;
    let mut catalog = CoordinationZoneCatalog {
        format: CATALOG_FORMAT.into(),
        workspace_id: workspace.into(),
        repository: repository.into(),
        revision: expected_revision + 1,
        key_id: key.key_id(),
        case_insensitive_paths,
        content_sha256: sha256(content.as_bytes()),
        content,
        metadata_hmac: String::new(),
    };
    catalog.metadata_hmac =
        metadata_key(key, workspace, repository)?.sign_hmac(&authenticated_bytes(&catalog));
    let body = CoordinationZoneCatalogWrite {
        expected_revision,
        catalog,
    };
    body.validate()?;
    Ok(body)
}

pub fn verify_catalog(
    key: &WorkspaceKey,
    workspace: &str,
    repository: &str,
    wire: &CoordinationZoneCatalog,
    highwater: Option<&CatalogHighwater>,
) -> Result<VerifiedZoneCatalog, CatalogError> {
    validate_catalog_scope(workspace, repository)?;
    wire.validate()?;
    if wire.workspace_id != workspace || wire.repository != repository {
        return Err(error("catalog_authentication_failed"));
    }
    if wire.key_id != key.key_id() {
        return Err(error("catalog_key_unavailable"));
    }
    if sha256(wire.content.as_bytes()) != wire.content_sha256 {
        return Err(error("catalog_authentication_failed"));
    }
    let metadata = authenticated_bytes(wire);
    metadata_key(key, workspace, repository)?
        .verify_hmac(&metadata, &wire.metadata_hmac)
        .map_err(|_| error("catalog_authentication_failed"))?;
    // The HMAC covers the ciphertext and all clear metadata before the generic AEAD API runs.
    let plaintext = key
        .decrypt(workspace, CATALOG_CONTENT_FIELD, &wire.content)
        .map_err(|_| error("catalog_authentication_failed"))?;
    let plaintext = ZoneCatalogV1::from_json(&plaintext)?;
    let next = CatalogHighwater {
        revision: wire.revision,
        authenticated_fingerprint: sha256(&metadata),
    };
    if highwater.is_some_and(|old| {
        next.revision < old.revision
            || next.revision == old.revision
                && next.authenticated_fingerprint != old.authenticated_fingerprint
    }) {
        return Err(error("catalog_replay_detected"));
    }
    Ok(VerifiedZoneCatalog {
        wire: wire.clone(),
        plaintext,
        highwater: next,
        offline: false,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    version: u8,
    workspace_id: String,
    repository: String,
    highwater: CatalogHighwater,
    catalog: CoordinationZoneCatalog,
}
/// One workspace/repository cache. No decrypted content or freshness timestamp is persisted.
#[derive(Debug, Clone)]
pub struct CatalogStore {
    path: PathBuf,
}
impl CatalogStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    pub fn for_scope(workspace: &str, repository: &str) -> Result<Self, CatalogError> {
        validate_catalog_scope(workspace, repository)?;
        let key_path = WorkspaceKey::storage_path(workspace)
            .map_err(|_| error("catalog_offline_unavailable"))?;
        let name = if repository.is_empty() {
            "legacy"
        } else {
            repository
        };
        let parent = key_path
            .parent()
            .ok_or_else(|| error("catalog_offline_unavailable"))?;
        // The empty namespace has a distinct directory, so a repository named `legacy` is safe.
        let namespace = if repository.is_empty() {
            "legacy"
        } else {
            "repositories"
        };
        Ok(Self::new(
            parent
                .join("catalogs")
                .join(workspace)
                .join(namespace)
                .join(format!("{name}.json")),
        ))
    }
    pub fn accept(
        &self,
        key: &WorkspaceKey,
        workspace: &str,
        repository: &str,
        wire: &CoordinationZoneCatalog,
    ) -> Result<VerifiedZoneCatalog, CatalogError> {
        validate_catalog_scope(workspace, repository)?;
        let _lock = self.lock(true)?;
        let old = self.load(workspace, repository)?;
        let verified = verify_catalog(
            key,
            workspace,
            repository,
            wire,
            old.as_ref().map(|record| &record.highwater),
        )?;
        let record = CacheRecord {
            version: 1,
            workspace_id: workspace.into(),
            repository: repository.into(),
            highwater: verified.highwater.clone(),
            catalog: wire.clone(),
        };
        // Check substituted destinations explicitly even though atomic rename would replace them.
        self.check_file(&self.path)?;
        lockyard_core::fsio::replace(
            &self.path,
            &serde_json::to_vec(&record).map_err(|_| error("catalog_offline_unavailable"))?,
            0o600,
        )
        .map_err(|_| error("catalog_offline_unavailable"))?;
        Ok(verified)
    }
    pub fn offline(
        &self,
        key: &WorkspaceKey,
        workspace: &str,
        repository: &str,
    ) -> Result<VerifiedZoneCatalog, CatalogError> {
        validate_catalog_scope(workspace, repository)?;
        let _lock = self.lock(false)?;
        let record = self
            .load(workspace, repository)?
            .ok_or_else(|| error("catalog_offline_unavailable"))?;
        let mut verified = verify_catalog(
            key,
            workspace,
            repository,
            &record.catalog,
            Some(&record.highwater),
        )?;
        verified.offline = true;
        Ok(verified)
    }
    fn load(&self, workspace: &str, repository: &str) -> Result<Option<CacheRecord>, CatalogError> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = match options.open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(error("catalog_offline_unavailable")),
        };
        validate_private_file(&file)?;
        let mut bytes = Vec::new();
        file.take((MAX_CATALOG_WIRE + 4097) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| error("catalog_offline_unavailable"))?;
        if bytes.len() > MAX_CATALOG_WIRE + 4096 {
            return Err(error("catalog_offline_unavailable"));
        }
        let record: CacheRecord =
            serde_json::from_slice(&bytes).map_err(|_| error("catalog_offline_unavailable"))?;
        if record.version != 1
            || record.workspace_id != workspace
            || record.repository != repository
            || record.catalog.workspace_id != workspace
            || record.catalog.repository != repository
            || record.highwater.revision != record.catalog.revision
            || record.highwater.authenticated_fingerprint
                != sha256(&authenticated_bytes(&record.catalog))
        {
            return Err(error("catalog_offline_unavailable"));
        }
        Ok(Some(record))
    }
    fn check_file(&self, path: &Path) -> Result<(), CatalogError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(error("catalog_offline_unavailable"))
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(error("catalog_offline_unavailable")),
        }
    }
    fn lock(&self, create: bool) -> Result<File, CatalogError> {
        if !self.path.is_absolute() {
            return Err(error("catalog_offline_unavailable"));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| error("catalog_offline_unavailable"))?;
        validate_ancestors(parent)?;
        if create {
            create_private_directory(parent)?;
        }
        validate_private_directory(parent)?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let lock = options
            .open(self.path.with_extension("lock"))
            .map_err(|_| error("catalog_offline_unavailable"))?;
        validate_private_file(&lock)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(error("catalog_offline_unavailable"));
            }
        }
        #[cfg(not(unix))]
        {
            return Err(error("catalog_offline_unavailable"));
        }
        #[allow(unreachable_code)]
        Ok(lock)
    }
}
fn validate_ancestors(path: &Path) -> Result<(), CatalogError> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component);
        let metadata = match fs::symlink_metadata(&ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(error("catalog_offline_unavailable")),
        };
        if metadata.file_type().is_symlink() {
            // macOS exposes these root-owned aliases for its physical private directories.
            // User-created links, including any cache-local aliases, are always rejected.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let system_alias = match ancestor.to_str() {
                    Some("/var") => Some(Path::new("/private/var")),
                    Some("/tmp") => Some(Path::new("/private/tmp")),
                    _ => None,
                };
                if metadata.uid() == 0
                    && system_alias.is_some_and(|target| {
                        fs::canonicalize(&ancestor).ok().as_deref() == Some(target)
                    })
                {
                    continue;
                }
            }
            return Err(error("catalog_offline_unavailable"));
        }
        if !metadata.is_dir() {
            return Err(error("catalog_offline_unavailable"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o022 != 0
                    && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
            {
                return Err(error("catalog_offline_unavailable"));
            }
        }
    }
    Ok(())
}
fn create_private_directory(path: &Path) -> Result<(), CatalogError> {
    if fs::symlink_metadata(path).is_ok() {
        return validate_private_directory(path);
    }
    // Create each missing component separately so a symlink at the selected cache root is refused.
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        create_private_directory(parent)?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(error("catalog_offline_unavailable")),
    }
    validate_private_directory(path)
}
fn validate_private_directory(path: &Path) -> Result<(), CatalogError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error("catalog_offline_unavailable"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(error("catalog_offline_unavailable"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(error("catalog_offline_unavailable"));
        }
    }
    #[cfg(not(unix))]
    {
        return Err(error("catalog_offline_unavailable"));
    }
    #[allow(unreachable_code)]
    Ok(())
}
fn validate_private_file(file: &File) -> Result<(), CatalogError> {
    let metadata = file
        .metadata()
        .map_err(|_| error("catalog_offline_unavailable"))?;
    if !metadata.is_file() {
        return Err(error("catalog_offline_unavailable"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(error("catalog_offline_unavailable"));
        }
    }
    #[cfg(not(unix))]
    {
        return Err(error("catalog_offline_unavailable"));
    }
    #[allow(unreachable_code)]
    Ok(())
}
