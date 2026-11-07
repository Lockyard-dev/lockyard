// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Signed, content-free result provenance. Verification always needs an independently pinned key.
use crate::wire::JobState;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const MAX_SIGNED_DOCUMENT_BYTES: usize = 64 * 1024;
pub const RESULT_DOMAIN: &[u8] = b"lockyard-result-manifest-v1\0";
pub(crate) const IMAGE_DOMAIN: &[u8] = b"lockyard-image-attestation-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceError(pub &'static str);
impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for ProvenanceError {}
pub type Result<T> = std::result::Result<T, ProvenanceError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSigningConfig {
    pub workspace: String,
    pub key_file: std::path::PathBuf,
    pub public_key: String,
}
impl ResultSigningConfig {
    pub fn load(&self) -> Result<SigningKey> {
        if !crate::wire::valid_name(&self.workspace) {
            return Err(ProvenanceError("invalid_signing_workspace"));
        }
        let key = SigningKey::load(&self.key_file)?;
        if key.trusted_key().public_key != self.public_key {
            return Err(ProvenanceError("signing_public_key_mismatch"));
        }
        Ok(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    /// Canonical JSON bytes, base64 encoded. Never use the included key ID as a trust anchor.
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSigningKey {
    /// Exactly 32 bytes encoded as lowercase hexadecimal. Pin through an authenticated channel.
    pub public_key: String,
}
impl TrustedSigningKey {
    pub fn validate(&self) -> Result<()> {
        public_key_bytes(&self.public_key).map(|_| ())
    }
    pub fn key_id(&self) -> Result<String> {
        Ok(sha256(&public_key_bytes(&self.public_key)?))
    }
}

/// Private PKCS#8 never enters a manifest, node configuration, environment variable or argv.
pub struct SigningKey(Ed25519KeyPair);
impl SigningKey {
    pub fn generate(path: &Path) -> Result<Self> {
        require_private_parent(path)?;
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| ProvenanceError("signing_entropy_unavailable"))?;
        let mut options = private_options();
        options.write(true).create_new(true);
        let mut file = options
            .open(path)
            .map_err(|_| ProvenanceError("signing_key_create_failed"))?;
        file.write_all(document.as_ref())
            .and_then(|()| file.sync_all())
            .map_err(|_| ProvenanceError("signing_key_write_failed"))?;
        File::open(
            path.parent()
                .ok_or(ProvenanceError("invalid_signing_key_path"))?,
        )
        .and_then(|file| file.sync_all())
        .map_err(|_| ProvenanceError("signing_key_write_failed"))?;
        Self::from_pkcs8(document.as_ref())
    }
    pub fn load(path: &Path) -> Result<Self> {
        require_private_parent(path)?;
        let mut options = private_options();
        options.read(true);
        let file = options
            .open(path)
            .map_err(|_| ProvenanceError("signing_key_unavailable"))?;
        require_private_file(&file)?;
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| ProvenanceError("signing_key_unavailable"))?;
        if bytes.len() > 4096 {
            return Err(ProvenanceError("invalid_signing_key"));
        }
        Self::from_pkcs8(&bytes)
    }
    fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        Ed25519KeyPair::from_pkcs8(bytes)
            .map(Self)
            .map_err(|_| ProvenanceError("invalid_signing_key"))
    }
    pub fn trusted_key(&self) -> TrustedSigningKey {
        TrustedSigningKey {
            public_key: hex(self.0.public_key().as_ref()),
        }
    }
    pub fn sign_result(&self, manifest: &ResultManifest) -> Result<SignedDocument> {
        manifest.validate()?;
        self.sign_document(RESULT_DOMAIN, manifest)
    }
    pub(crate) fn sign_document<T: Serialize>(
        &self,
        domain: &[u8],
        payload: &T,
    ) -> Result<SignedDocument> {
        let bytes =
            serde_json::to_vec(payload).map_err(|_| ProvenanceError("manifest_encoding_failed"))?;
        if bytes.len() > MAX_SIGNED_DOCUMENT_BYTES / 2 {
            return Err(ProvenanceError("manifest_too_large"));
        }
        let signature = self.0.sign(&domain_message(domain, &bytes));
        Ok(SignedDocument {
            version: 1,
            algorithm: "Ed25519".into(),
            key_id: self.trusted_key().key_id()?,
            payload: STANDARD.encode(bytes),
            signature: STANDARD.encode(signature.as_ref()),
        })
    }
}

pub(crate) fn verify_document<T: DeserializeOwned + Serialize>(
    document: &SignedDocument,
    domain: &[u8],
    key: &TrustedSigningKey,
) -> Result<T> {
    let encoded_len = serde_json::to_vec(document)
        .map_err(|_| ProvenanceError("manifest_encoding_failed"))?
        .len();
    if encoded_len > MAX_SIGNED_DOCUMENT_BYTES
        || document.payload.len() > MAX_SIGNED_DOCUMENT_BYTES / 2 * 4 / 3 + 4
    {
        return Err(ProvenanceError("manifest_too_large"));
    }
    if document.version != 1
        || document.algorithm != "Ed25519"
        || document.key_id != key.key_id()?
    {
        return Err(ProvenanceError("untrusted_manifest_signer"));
    }
    let bytes = STANDARD
        .decode(&document.payload)
        .map_err(|_| ProvenanceError("invalid_manifest_encoding"))?;
    let signature = STANDARD
        .decode(&document.signature)
        .map_err(|_| ProvenanceError("invalid_manifest_encoding"))?;
    if STANDARD.encode(&bytes) != document.payload
        || STANDARD.encode(&signature) != document.signature
        || signature.len() != 64
    {
        return Err(ProvenanceError("invalid_manifest_encoding"));
    }
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes(&key.public_key)?)
        .verify(&domain_message(domain, &bytes), &signature)
        .map_err(|_| ProvenanceError("manifest_signature_invalid"))?;
    let value: T =
        serde_json::from_slice(&bytes).map_err(|_| ProvenanceError("invalid_manifest_payload"))?;
    if serde_json::to_vec(&value).map_err(|_| ProvenanceError("manifest_encoding_failed"))? != bytes
    {
        return Err(ProvenanceError("noncanonical_manifest_payload"));
    }
    Ok(value)
}
fn domain_message(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 8 + bytes.len());
    output.extend_from_slice(domain);
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub size_bytes: u64,
    pub sha256: String,
    pub truncated: bool,
    pub error_code: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultManifest {
    pub version: u8,
    pub node_id: String,
    pub workspace: String,
    pub job_id: String,
    pub repository: String,
    pub runner: String,
    /// SHA-256 of the complete canonical JobSpec, binding arguments/prompt without disclosing them.
    pub request_sha256: String,
    pub resolved_revision: String,
    pub image_reference: String,
    pub image_digest: String,
    pub image_config_digest: Option<String>,
    pub image_attestation_sha256: Option<String>,
    pub execution_attempted: bool,
    pub completed_at_ms: u64,
    pub state: JobState,
    pub exit_code: Option<i32>,
    pub error_code: Option<String>,
    /// Only output.log and result.patch are valid names. No host paths are signed or trusted.
    pub artifacts: BTreeMap<String, ArtifactDigest>,
}
impl ResultManifest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !crate::wire::valid_name(&self.node_id)
            || !crate::wire::valid_name(&self.workspace)
            || !crate::wire::valid_ulid(&self.job_id)
            || !crate::wire::valid_name(&self.repository)
            || !crate::wire::valid_name(&self.runner)
            || !valid_sha256(&self.request_sha256)
            || !valid_revision(&self.resolved_revision)
            || !self.state.is_terminal()
            || self.completed_at_ms == 0
            || self.artifacts.len() > 2
            || !valid_optional_error(&self.error_code)
        {
            return Err(ProvenanceError("invalid_result_manifest"));
        }
        let digest = crate::supply_chain::immutable_image_digest(&self.image_reference)
            .map_err(|_| ProvenanceError("invalid_result_image"))?;
        if digest != self.image_digest
            || !valid_digest(&self.image_digest)
            || self
                .image_config_digest
                .as_ref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .image_attestation_sha256
                .as_ref()
                .is_some_and(|value| !valid_sha256(value))
            || (self.execution_attempted
                && (self.image_config_digest.is_none() || self.image_attestation_sha256.is_none()))
            || self.image_config_digest.is_some() != self.image_attestation_sha256.is_some()
        {
            return Err(ProvenanceError("invalid_result_image"));
        }
        for (name, artifact) in &self.artifacts {
            if !matches!(name.as_str(), "output.log" | "result.patch")
                || !valid_sha256(&artifact.sha256)
                || artifact.size_bytes
                    > if name == "result.patch" {
                        crate::executor::MAX_PATCH_BYTES
                    } else {
                        1024 * 1024 * 1024
                    }
                || !valid_optional_error(&artifact.error_code)
            {
                return Err(ProvenanceError("invalid_result_artifact"));
            }
        }
        Ok(())
    }
}

/// An included public key is never enough: the caller pins the expected node/workspace key.
pub struct ResultExpectation<'a> {
    pub node_id: &'a str,
    pub workspace: &'a str,
    pub job_id: &'a str,
    pub resolved_revision: &'a str,
    pub image_digest: &'a str,
    pub request_sha256: Option<&'a str>,
}
/// Read a signed document without unbounded allocation or following a final-component symlink.
pub fn load_document(path: &Path) -> Result<SignedDocument> {
    let bytes = read_bounded(path, MAX_SIGNED_DOCUMENT_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| ProvenanceError("invalid_signed_document"))
}
pub fn verify_result(
    document: &SignedDocument,
    key: &TrustedSigningKey,
    expected: &ResultExpectation<'_>,
) -> Result<ResultManifest> {
    let manifest: ResultManifest = verify_document(document, RESULT_DOMAIN, key)?;
    manifest.validate()?;
    if manifest.node_id != expected.node_id
        || manifest.workspace != expected.workspace
        || manifest.job_id != expected.job_id
        || manifest.resolved_revision != expected.resolved_revision
        || manifest.image_digest != expected.image_digest
        || expected
            .request_sha256
            .is_some_and(|hash| manifest.request_sha256 != hash)
    {
        return Err(ProvenanceError("result_context_mismatch"));
    }
    Ok(manifest)
}
/// Authenticate a node's statement when the resolved revision/image are not yet known locally.
/// Call `verify_result` instead when enforcing independently selected revision/image policy.
pub fn verify_result_identity(
    document: &SignedDocument,
    key: &TrustedSigningKey,
    node: &str,
    workspace: &str,
    job: &str,
) -> Result<ResultManifest> {
    let manifest: ResultManifest = verify_document(document, RESULT_DOMAIN, key)?;
    manifest.validate()?;
    if manifest.node_id != node || manifest.workspace != workspace || manifest.job_id != job {
        return Err(ProvenanceError("result_context_mismatch"));
    }
    Ok(manifest)
}
pub fn verify_artifact(manifest: &ResultManifest, name: &str, file: &Path) -> Result<()> {
    manifest.validate()?;
    let expected = manifest
        .artifacts
        .get(name)
        .ok_or(ProvenanceError("result_artifact_missing"))?;
    let actual = hash_file(file, expected.size_bytes)?;
    if actual != (expected.size_bytes, expected.sha256.clone()) {
        return Err(ProvenanceError("result_artifact_mismatch"));
    }
    Ok(())
}

/// Verify the same opened file that received a download, without reopening its path.
pub fn verify_artifact_file(manifest: &ResultManifest, name: &str, file: &mut File) -> Result<()> {
    manifest.validate()?;
    let expected = manifest
        .artifacts
        .get(name)
        .ok_or(ProvenanceError("result_artifact_missing"))?;
    let actual = hash_open_file(file, expected.size_bytes)?;
    if actual != (expected.size_bytes, expected.sha256.clone()) {
        return Err(ProvenanceError("result_artifact_mismatch"));
    }
    Ok(())
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}
pub fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256)
}
fn valid_revision(value: &str) -> bool {
    [40, 64].contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_optional_error(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|value| {
        !value.is_empty()
            && value.len() <= 96
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn public_key_bytes(value: &str) -> Result<[u8; 32]> {
    if !valid_sha256(value) {
        return Err(ProvenanceError("invalid_signing_public_key"));
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ProvenanceError("invalid_signing_public_key"))?;
    }
    Ok(bytes)
}
pub fn hash_file(path: &Path, limit: u64) -> Result<(u64, String)> {
    let mut file = regular_file(path)?;
    hash_open_file(&mut file, limit)
}
pub fn hash_open_file(file: &mut File, limit: u64) -> Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ProvenanceError("artifact_unavailable"))?;
    if !file
        .metadata()
        .map_err(|_| ProvenanceError("artifact_unavailable"))?
        .is_file()
    {
        return Err(ProvenanceError("artifact_unavailable"));
    }
    if file
        .metadata()
        .map_err(|_| ProvenanceError("artifact_unavailable"))?
        .len()
        > limit
    {
        return Err(ProvenanceError("artifact_too_large"));
    }
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = [0; 65536];
    let mut count = 0u64;
    loop {
        let bytes = file
            .read(&mut buffer)
            .map_err(|_| ProvenanceError("artifact_unavailable"))?;
        if bytes == 0 {
            break;
        }
        count = count
            .checked_add(bytes as u64)
            .ok_or(ProvenanceError("artifact_too_large"))?;
        if count > limit {
            return Err(ProvenanceError("artifact_too_large"));
        }
        context.update(&buffer[..bytes]);
    }
    Ok((count, hex(context.finish().as_ref())))
}
pub(crate) fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = regular_file(path)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProvenanceError("artifact_unavailable"))?;
    if bytes.len() > limit {
        return Err(ProvenanceError("artifact_too_large"));
    }
    Ok(bytes)
}
fn regular_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| ProvenanceError("artifact_unavailable"))?;
    if !file
        .metadata()
        .map_err(|_| ProvenanceError("artifact_unavailable"))?
        .is_file()
    {
        return Err(ProvenanceError("artifact_not_regular"));
    }
    Ok(file)
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options
}
fn require_private_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent = path
            .parent()
            .ok_or(ProvenanceError("invalid_signing_key_path"))?;
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| ProvenanceError("signing_key_parent_unavailable"))?;
        if !path.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(ProvenanceError("signing_key_parent_not_private"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ProvenanceError("private_signing_keys_require_unix"))
    }
}
fn require_private_file(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|_| ProvenanceError("signing_key_unavailable"))?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(ProvenanceError("signing_key_not_private"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(ProvenanceError("private_signing_keys_require_unix"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn fixture() -> (tempfile::TempDir, SigningKey, ResultManifest) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = SigningKey::generate(&root.path().join("signing.pk8")).unwrap();
        let manifest = ResultManifest {
            version: 1,
            node_id: "worker".into(),
            workspace: "workspace".into(),
            job_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            repository: "repo".into(),
            runner: "runner".into(),
            request_sha256: "a".repeat(64),
            resolved_revision: "b".repeat(40),
            image_reference: format!("sha256:{}", "c".repeat(64)),
            image_digest: format!("sha256:{}", "c".repeat(64)),
            image_config_digest: Some(format!("sha256:{}", "c".repeat(64))),
            image_attestation_sha256: Some("d".repeat(64)),
            execution_attempted: true,
            completed_at_ms: 1234,
            state: JobState::Succeeded,
            exit_code: Some(0),
            error_code: None,
            artifacts: BTreeMap::from([(
                "result.patch".into(),
                ArtifactDigest {
                    size_bytes: 5,
                    sha256: sha256(b"patch"),
                    truncated: false,
                    error_code: None,
                },
            )]),
        };
        (root, key, manifest)
    }
    fn expected(manifest: &ResultManifest) -> ResultExpectation<'_> {
        ResultExpectation {
            node_id: &manifest.node_id,
            workspace: &manifest.workspace,
            job_id: &manifest.job_id,
            resolved_revision: &manifest.resolved_revision,
            image_digest: &manifest.image_digest,
            request_sha256: Some(&manifest.request_sha256),
        }
    }
    #[test]
    fn result_signature_requires_pinned_key_and_exact_execution_context() {
        let (_root, key, manifest) = fixture();
        let signed = key.sign_result(&manifest).unwrap();
        assert_eq!(
            verify_result(&signed, &key.trusted_key(), &expected(&manifest)).unwrap(),
            manifest
        );
        let (_other_root, other_key, _) = fixture();
        assert_eq!(
            verify_result(&signed, &other_key.trusted_key(), &expected(&manifest))
                .unwrap_err()
                .0,
            "untrusted_manifest_signer"
        );
        let mut other = manifest.clone();
        for field in 0..6 {
            match field {
                0 => other.node_id = "attacker".into(),
                1 => other.workspace = "other".into(),
                2 => other.job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
                3 => other.resolved_revision = "f".repeat(40),
                4 => other.image_digest = format!("sha256:{}", "f".repeat(64)),
                _ => other.request_sha256 = "f".repeat(64),
            }
            assert_eq!(
                verify_result(&signed, &key.trusted_key(), &expected(&other))
                    .unwrap_err()
                    .0,
                "result_context_mismatch"
            );
            other = manifest.clone();
        }
        let mut tampered = signed;
        let mut bytes = STANDARD.decode(&tampered.payload).unwrap();
        bytes[0] = b'[';
        tampered.payload = STANDARD.encode(bytes);
        assert_eq!(
            verify_result(&tampered, &key.trusted_key(), &expected(&manifest))
                .unwrap_err()
                .0,
            "manifest_signature_invalid"
        );
    }
    #[test]
    fn valid_signature_does_not_allow_unknown_fields_noncanonical_json_or_wrong_domain() {
        let (_root, key, manifest) = fixture();
        let value = serde_json::to_value(&manifest).unwrap();
        let reordered = key.sign_document(RESULT_DOMAIN, &value).unwrap();
        assert_eq!(
            verify_result(&reordered, &key.trusted_key(), &expected(&manifest))
                .unwrap_err()
                .0,
            "noncanonical_manifest_payload"
        );
        let mut value = value;
        value["unknown"] = serde_json::json!("hidden");
        let unknown = key.sign_document(RESULT_DOMAIN, &value).unwrap();
        assert_eq!(
            verify_result(&unknown, &key.trusted_key(), &expected(&manifest))
                .unwrap_err()
                .0,
            "invalid_manifest_payload"
        );
        let other_domain = key.sign_document(IMAGE_DOMAIN, &manifest).unwrap();
        assert_eq!(
            verify_result(&other_domain, &key.trusted_key(), &expected(&manifest))
                .unwrap_err()
                .0,
            "manifest_signature_invalid"
        );
        let mut outer = serde_json::to_value(key.sign_result(&manifest).unwrap()).unwrap();
        outer["public_key"] = serde_json::json!(key.trusted_key());
        assert!(serde_json::from_value::<SignedDocument>(outer).is_err());
    }
    #[test]
    fn artifacts_are_bounded_named_and_verified_against_signed_bytes() {
        let (root, key, manifest) = fixture();
        let path = root.path().join("download.patch");
        fs::write(&path, b"patch").unwrap();
        let verified = verify_result(
            &key.sign_result(&manifest).unwrap(),
            &key.trusted_key(),
            &expected(&manifest),
        )
        .unwrap();
        verify_artifact(&verified, "result.patch", &path).unwrap();
        fs::write(&path, b"PATCH").unwrap();
        assert_eq!(
            verify_artifact(&verified, "result.patch", &path)
                .unwrap_err()
                .0,
            "result_artifact_mismatch"
        );
        fs::write(&path, b"patch plus data").unwrap();
        assert_eq!(
            verify_artifact(&verified, "result.patch", &path)
                .unwrap_err()
                .0,
            "artifact_too_large"
        );
        let mut invalid = manifest.clone();
        invalid.artifacts.insert(
            "../escape".into(),
            invalid.artifacts["result.patch"].clone(),
        );
        assert!(key.sign_result(&invalid).is_err());
        invalid = manifest;
        invalid.state = JobState::InterruptedUnknown;
        assert!(key.sign_result(&invalid).is_err());
    }
    #[test]
    fn signing_key_requires_private_owned_parent_regular_file_and_create_only() {
        let (root, key, _) = fixture();
        let path = root.path().join("signing.pk8");
        assert_eq!(
            SigningKey::load(&path).unwrap().trusted_key(),
            key.trusted_key()
        );
        assert!(SigningKey::generate(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SigningKey::load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link.pk8");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(SigningKey::load(&link).is_err());
        let hard = root.path().join("hard.pk8");
        fs::hard_link(&path, &hard).unwrap();
        assert!(SigningKey::load(&path).is_err());
        fs::remove_file(&hard).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(SigningKey::load(&path).is_err());
    }
}
