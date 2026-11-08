// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Customer-authorized, offline workspace-key rotation. The cloud is never a key authority.
//! Capsules use RFC 9180 DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM.
use crate::{
    Result,
    host::NodeConfig,
    provenance::{self, SignedDocument, SigningKey, TrustedSigningKey},
    rotation_install,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    kem::DhP256HkdfSha256,
};
use lockyard_cloud_client::WorkspaceKey;
use p256::{
    elliptic_curve::sec1::ToSec1Point,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use rand_core::SeedableRng;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
pub use rotation_install::HistoryPolicy;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
#[cfg(windows)]
use std::fs::File;

#[cfg(unix)]
use std::io::Read;

const DOMAIN: &[u8] = b"lockyard-workspace-key-rotation-v1\0";
const CAPSULE_DOMAIN: &[u8] = b"lockyard-workspace-key-hpke-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"lockyard-workspace-key-installed-v1\0";
pub const MAX_ROTATION_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 512;
const MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
type KemP256 = DhP256HkdfSha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    MemberRevocation,
    Compromise,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientSpec {
    pub node_id: String,
    pub certificate: PathBuf,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationHeader {
    pub workspace: String,
    pub epoch: u64,
    pub old_key_id: String,
    pub new_key_id: String,
    pub reason: RotationReason,
    pub history_policy: HistoryPolicy,
    pub authority_key_id: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRecipient {
    pub node_id: String,
    pub certificate_sha256: String,
    pub capsule_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPlan {
    pub header: RotationHeader,
    pub recipients: Vec<ApprovedRecipient>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule {
    pub encapsulated_key: String,
    pub ciphertext: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationDraft {
    pub version: u8,
    pub plan: RotationPlan,
    pub capsules: BTreeMap<String, Capsule>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationBundle {
    pub draft: RotationDraft,
    pub authorization: SignedDocument,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanAuthorization {
    workspace: String,
    epoch: u64,
    new_key_id: String,
    plan_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityPin {
    version: u8,
    workspace: String,
    key: TrustedSigningKey,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPayload {
    pub workspace: String,
    pub node_id: String,
    pub epoch: u64,
    pub new_key_id: String,
    pub plan_sha256: String,
    pub certificate_sha256: String,
    pub installed_at_ms: u64,
    pub direct_trust_reconciled: bool,
    pub new_key_possession: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationReceipt {
    pub payload: ReceiptPayload,
    pub certificate_der: String,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientStatus {
    pub node_id: String,
    pub installed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationStatus {
    pub workspace: String,
    pub epoch: u64,
    pub plan_sha256: String,
    pub complete: bool,
    pub recipients: Vec<RecipientStatus>,
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn sha<T: Serialize>(value: &T) -> Result<String> {
    Ok(provenance::sha256(&serde_json::to_vec(value)?))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_key_id(value: &str) -> bool {
    value.len() == 11
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn authority_path(config: &NodeConfig) -> PathBuf {
    config.state_dir.join("rotation-authority.json")
}
fn authority_directory() -> Result<PathBuf> {
    Ok(WorkspaceKey::storage_path("rotation-authority")?
        .parent()
        .ok_or("invalid_rotation_authority_path")?
        .join("rotation-authorities"))
}
fn validate_authority_location(path: &Path, root: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.parent() != Some(root)
        || path.file_name().is_none()
        || path
            .file_name()
            .is_some_and(|name| name.as_encoded_bytes().starts_with(b"."))
    {
        return Err("rotation_authority_key_requires_protected_global_directory".into());
    }
    crate::retention::require_directory(root)?;
    if std::fs::canonicalize(root)? != root {
        return Err("rotation_authority_key_requires_protected_global_directory".into());
    }
    Ok(())
}
/// Normal authority keys live under the global keys tree excluded from every workload mount.
pub fn authority_generate(path: &Path) -> Result<TrustedSigningKey> {
    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt;
    let root = authority_directory()?;
    let parent = root.parent().ok_or("invalid_rotation_authority_path")?;
    crate::retention::require_directory(parent)?;
    #[cfg(windows)]
    lockyard_core::windows::private_dir(&root)?;
    #[cfg(unix)]
    match std::fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => lockyard_core::fsio::sync_path(parent)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    validate_authority_location(path, &root)?;
    Ok(SigningKey::generate(path)?.trusted_key())
}
fn pinned_authority(config: &NodeConfig) -> Result<AuthorityPin> {
    let pin: AuthorityPin = read_private_json(&authority_path(config))?;
    pin.key.validate()?;
    if pin.version != 1 || pin.workspace != config.workspace {
        return Err("rotation_authority_workspace_mismatch".into());
    }
    Ok(pin)
}
/// Explicit local trust installation, create-only. Distribute this public pin independently.
pub fn authority_pin(config_path: &Path, public_key_hex: &str) -> Result<()> {
    let config = NodeConfig::load(config_path)?;
    let key = TrustedSigningKey {
        public_key: public_key_hex.into(),
    };
    key.validate()?;
    rotation_install::require_no_pending(&config.state_dir)?;
    write_private_json(
        &authority_path(&config),
        &AuthorityPin {
            version: 1,
            workspace: config.workspace,
            key,
        },
    )
}
fn confirmed_phrase(key: &WorkspaceKey, confirmation: &str) -> Result<String> {
    if confirmation.trim() != "SHOW" {
        return Err("rotation_phrase_display_not_confirmed".into());
    }
    Ok(key.phrase())
}
/// Explicit local display for customer-controlled human redistribution; no server chooses the slot.
pub fn local_recovery_phrase(config_path: &Path, confirmation: &str) -> Result<(String, String)> {
    if confirmation.trim() != "SHOW" {
        return Err("rotation_phrase_display_not_confirmed".into());
    }
    let config = NodeConfig::load(config_path)?;
    crate::updates::require_no_pending(&config.state_dir)?;
    rotation_install::require_no_pending(&config.state_dir)?;
    let path = WorkspaceKey::storage_path(&config.workspace)?;
    let _guard = rotation_install::guard_workspace_key(&path)?;
    rotation_install::require_global_binding(&config, &path)?;
    let key = WorkspaceKey::load_private(&path)?.ok_or("workspace_key_unavailable")?;
    Ok((config.workspace, confirmed_phrase(&key, confirmation)?))
}
impl RotationDraft {
    pub fn plan_sha256(&self) -> Result<String> {
        sha(&self.plan)
    }
    fn authorization(&self) -> Result<PlanAuthorization> {
        Ok(PlanAuthorization {
            workspace: self.plan.header.workspace.clone(),
            epoch: self.plan.header.epoch,
            new_key_id: self.plan.header.new_key_id.clone(),
            plan_sha256: self.plan_sha256()?,
        })
    }
    fn validate(&self, current_time: u64, check_expiry: bool) -> Result<()> {
        let h = &self.plan.header;
        if self.version != 1
            || !crate::wire::valid_name(&h.workspace)
            || h.epoch == 0
            || !valid_key_id(&h.old_key_id)
            || !valid_key_id(&h.new_key_id)
            || h.old_key_id == h.new_key_id
            || !valid_digest(&h.authority_key_id)
            || h.created_at_ms > current_time.saturating_add(60_000)
            || h.expires_at_ms <= h.created_at_ms
            || h.expires_at_ms - h.created_at_ms > MAX_LIFETIME_MS
            || (check_expiry && current_time >= h.expires_at_ms)
            || self.plan.recipients.is_empty()
            || self.plan.recipients.len() > MAX_RECIPIENTS
            || self.capsules.len() != self.plan.recipients.len()
        {
            return Err("invalid_or_expired_rotation_plan".into());
        }
        let mut last: Option<&str> = None;
        let mut pins = BTreeSet::new();
        for r in &self.plan.recipients {
            if !crate::wire::valid_name(&r.node_id)
                || last.is_some_and(|l| l >= r.node_id.as_str())
                || !valid_digest(&r.certificate_sha256)
                || !valid_digest(&r.capsule_sha256)
                || !pins.insert(&r.certificate_sha256)
            {
                return Err("invalid_rotation_roster".into());
            }
            last = Some(&r.node_id);
            let c = self
                .capsules
                .get(&r.node_id)
                .ok_or("missing_rotation_capsule")?;
            if sha(c)? != r.capsule_sha256
                || decode(&c.encapsulated_key, 65)?.len() != 65
                || decode(&c.ciphertext, 48)?.len() != 48
            {
                return Err("invalid_rotation_capsule".into());
            }
        }
        Ok(())
    }
}
fn decode(value: &str, limit: usize) -> Result<Vec<u8>> {
    if value.len() > limit.div_ceil(3) * 4 {
        return Err("invalid_rotation_encoding".into());
    }
    let bytes = STANDARD.decode(value)?;
    if bytes.len() > limit || STANDARD.encode(&bytes) != value {
        return Err("invalid_rotation_encoding".into());
    }
    Ok(bytes)
}
fn certificate_public(der: &[u8]) -> Result<Vec<u8>> {
    let (remaining, cert) =
        X509Certificate::from_der(der).map_err(|_| "invalid_rotation_certificate")?;
    if !remaining.is_empty() {
        return Err("invalid_rotation_certificate".into());
    }
    let key = p256::PublicKey::from_public_key_der(cert.public_key().raw)
        .map_err(|_| "rotation_requires_p256_identity")?;
    Ok(key.to_sec1_point(false).as_bytes().to_vec())
}
fn private_key_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_private(path, 8192).map(Zeroizing::new)
}
fn aad(header: &RotationHeader, node: &str, pin: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(header, node, pin))?)
}
fn hpke_info(header: &RotationHeader) -> Result<Vec<u8>> {
    let mut info = CAPSULE_DOMAIN.to_vec();
    info.extend_from_slice(sha(header)?.as_bytes());
    Ok(info)
}
/// Builds an unsigned draft with no raw new key. Only the explicitly approved local roster can unwrap it.
pub fn prepare(
    config_path: &Path,
    roster_path: &Path,
    reason: RotationReason,
    history_policy: HistoryPolicy,
    epoch: u64,
    expires_at_ms: u64,
) -> Result<RotationDraft> {
    let config = NodeConfig::load(config_path)?;
    rotation_install::require_no_pending(&config.state_dir)?;
    let authority = pinned_authority(&config)?;
    let _key_guard =
        rotation_install::guard_workspace_key(&WorkspaceKey::storage_path(&config.workspace)?)?;
    rotation_install::require_global_binding(
        &config,
        &WorkspaceKey::storage_path(&config.workspace)?,
    )?;
    let old =
        WorkspaceKey::load_for_workspace(&config.workspace)?.ok_or("workspace_key_unavailable")?;
    let installed = rotation_install::read_installed(&config.state_dir)?;
    if epoch != installed.as_ref().map_or(1, |s| s.epoch.saturating_add(1)) {
        return Err("rotation_epoch_must_advance_once".into());
    }
    let specs: Vec<RecipientSpec> = read_private_json(roster_path)?;
    if specs.is_empty() || specs.len() > MAX_RECIPIENTS {
        return Err("invalid_rotation_roster".into());
    }
    prepare_for(
        &config,
        specs,
        &authority.key,
        &old,
        reason,
        history_policy,
        epoch,
        expires_at_ms,
    )
}
#[allow(clippy::too_many_arguments)]
fn prepare_for(
    config: &NodeConfig,
    specs: Vec<RecipientSpec>,
    authority: &TrustedSigningKey,
    old: &WorkspaceKey,
    reason: RotationReason,
    history_policy: HistoryPolicy,
    epoch: u64,
    expires_at_ms: u64,
) -> Result<RotationDraft> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(entropy.as_mut())
        .map_err(|_| "rotation_entropy_unavailable")?;
    let new_key_id = WorkspaceKey::from_entropy(*entropy).key_id();
    let header = RotationHeader {
        workspace: config.workspace.clone(),
        epoch,
        old_key_id: old.key_id(),
        new_key_id,
        reason,
        history_policy,
        authority_key_id: authority.key_id()?,
        created_at_ms: now_ms()?,
        expires_at_ms,
    };
    let info = hpke_info(&header)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(seed.as_mut())
        .map_err(|_| "rotation_entropy_unavailable")?;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
    let mut recipients = Vec::new();
    let mut capsules = BTreeMap::new();
    let mut public_keys = BTreeSet::new();
    for spec in specs {
        if !crate::wire::valid_name(&spec.node_id) || !spec.certificate.is_absolute() {
            return Err("invalid_rotation_roster".into());
        }
        let der = provenance::read_bounded(&spec.certificate, 64 * 1024)?;
        let pin = provenance::sha256(&der);
        let public_bytes = certificate_public(&der)?;
        if !public_keys.insert(public_bytes.clone()) {
            return Err("rotation_recipients_must_have_distinct_private_identities".into());
        }
        let public = <KemP256 as Kem>::PublicKey::from_bytes(&public_bytes)
            .map_err(|_| "invalid_rotation_public_key")?;
        let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, KemP256>(
            &OpModeS::Base,
            &public,
            &info,
            entropy.as_ref(),
            &aad(&header, &spec.node_id, &pin)?,
            &mut rng,
        )
        .map_err(|_| "rotation_capsule_seal_failed")?;
        let capsule = Capsule {
            encapsulated_key: STANDARD.encode(enc.to_bytes()),
            ciphertext: STANDARD.encode(ciphertext),
        };
        recipients.push(ApprovedRecipient {
            node_id: spec.node_id.clone(),
            certificate_sha256: pin,
            capsule_sha256: sha(&capsule)?,
        });
        if capsules.insert(spec.node_id, capsule).is_some() {
            return Err("duplicate_rotation_recipient".into());
        }
    }
    recipients.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    for peer in &config.peers {
        if !recipients.iter().any(|r| {
            r.node_id == peer.node_id
                && r.certificate_sha256
                    .eq_ignore_ascii_case(&peer.certificate_sha256)
        }) && public_keys.contains(&certificate_public(&provenance::read_bounded(
            &peer.certificate,
            64 * 1024,
        )?)?) {
            return Err("rotation_reuses_excluded_or_replaced_private_identity".into());
        }
    }
    let own_der = provenance::read_bounded(&config.certificate, 64 * 1024)?;
    if !recipients.iter().any(|r| {
        r.node_id == config.node_id && r.certificate_sha256 == provenance::sha256(&own_der)
    }) {
        return Err("rotation_owner_node_must_remain_in_roster".into());
    }
    let draft = RotationDraft {
        version: 1,
        plan: RotationPlan { header, recipients },
        capsules,
    };
    draft.validate(now_ms()?, true)?;
    Ok(draft)
}
/// Requires the operator to provide the exact reviewed plan digest, then signs its semantic bindings.
pub fn commit(
    draft_path: &Path,
    signing_key_path: &Path,
    approved_plan_sha256: &str,
) -> Result<RotationBundle> {
    validate_authority_location(signing_key_path, &authority_directory()?)?;
    let draft: RotationDraft = read_private_json(draft_path)?;
    authorize_draft(
        draft,
        &SigningKey::load(signing_key_path)?,
        approved_plan_sha256,
    )
}
fn authorize_draft(
    draft: RotationDraft,
    signer: &SigningKey,
    approved_plan_sha256: &str,
) -> Result<RotationBundle> {
    draft.validate(now_ms()?, true)?;
    if !valid_digest(approved_plan_sha256) || draft.plan_sha256()? != approved_plan_sha256 {
        return Err("rotation_plan_not_explicitly_approved".into());
    }
    if signer.trusted_key().key_id()? != draft.plan.header.authority_key_id {
        return Err("rotation_authority_key_mismatch".into());
    }
    let authorization = signer.sign_document(DOMAIN, &draft.authorization()?)?;
    Ok(RotationBundle {
        draft,
        authorization,
    })
}
fn verify_bundle(config: &NodeConfig, bundle: &RotationBundle, check_expiry: bool) -> Result<()> {
    bundle.draft.validate(now_ms()?, check_expiry)?;
    let pin = pinned_authority(config)?;
    if config.workspace != bundle.draft.plan.header.workspace
        || pin.key.key_id()? != bundle.draft.plan.header.authority_key_id
    {
        return Err("rotation_workspace_or_authority_mismatch".into());
    }
    let signed: PlanAuthorization =
        provenance::verify_document(&bundle.authorization, DOMAIN, &pin.key)?;
    if signed != bundle.draft.authorization()? {
        return Err("rotation_plan_signature_mismatch".into());
    }
    Ok(())
}
fn unwrap(config: &NodeConfig, bundle: &RotationBundle) -> Result<Zeroizing<[u8; 32]>> {
    let recipient = bundle
        .draft
        .plan
        .recipients
        .iter()
        .find(|r| r.node_id == config.node_id)
        .ok_or("node_excluded_from_rotation")?;
    let der = provenance::read_bounded(&config.certificate, 64 * 1024)?;
    if provenance::sha256(&der) != recipient.certificate_sha256 {
        return Err("rotation_node_certificate_mismatch".into());
    }
    let private = p256::SecretKey::from_pkcs8_der(&private_key_bytes(&config.private_key)?)
        .map_err(|_| "invalid_rotation_private_key")?;
    let scalar = Zeroizing::new(private.to_bytes());
    let secret = <KemP256 as Kem>::PrivateKey::from_bytes(&scalar)
        .map_err(|_| "invalid_rotation_private_key")?;
    if KemP256::sk_to_pk(&secret).to_bytes().as_slice() != certificate_public(&der)?.as_slice() {
        return Err("rotation_private_key_certificate_mismatch".into());
    }
    let capsule = bundle
        .draft
        .capsules
        .get(&config.node_id)
        .ok_or("missing_rotation_capsule")?;
    let enc = <KemP256 as Kem>::EncappedKey::from_bytes(&decode(&capsule.encapsulated_key, 65)?)
        .map_err(|_| "invalid_rotation_capsule")?;
    let mut plaintext = Zeroizing::new(
        hpke::single_shot_open::<AesGcm256, HkdfSha256, KemP256>(
            &OpModeR::Base,
            &secret,
            &enc,
            &hpke_info(&bundle.draft.plan.header)?,
            &decode(&capsule.ciphertext, 48)?,
            &aad(
                &bundle.draft.plan.header,
                &config.node_id,
                &recipient.certificate_sha256,
            )?,
        )
        .map_err(|_| "rotation_capsule_open_failed")?,
    );
    if plaintext.len() != 32 {
        return Err("invalid_rotation_key_length".into());
    }
    let mut entropy = Zeroizing::new([0; 32]);
    entropy.copy_from_slice(&plaintext);
    plaintext.zeroize();
    if WorkspaceKey::from_entropy(*entropy).key_id() != bundle.draft.plan.header.new_key_id {
        return Err("rotation_key_commitment_mismatch".into());
    }
    Ok(entropy)
}

// Disk installation and receipt wiring are below; private material never enters public structures.
fn install_metadata(
    config: &NodeConfig,
    bundle: &RotationBundle,
) -> Result<rotation_install::InstallMetadata> {
    let h = &bundle.draft.plan.header;
    Ok(rotation_install::InstallMetadata {
        workspace: h.workspace.clone(),
        node_id: config.node_id.clone(),
        epoch: h.epoch,
        old_key_id: h.old_key_id.clone(),
        new_key_id: h.new_key_id.clone(),
        plan_sha256: bundle.draft.plan_sha256()?,
        history_policy: h.history_policy,
        approved_peers: bundle
            .draft
            .plan
            .recipients
            .iter()
            .map(|r| rotation_install::ApprovedPeer {
                node_id: r.node_id.clone(),
                certificate_sha256: r.certificate_sha256.clone(),
            })
            .collect(),
        signed_plan_json: serde_json::to_string(bundle)?,
    })
}
pub fn apply(config_path: &Path, bundle_path: &Path) -> Result<RotationReceipt> {
    let config = NodeConfig::load(config_path)?;
    crate::updates::require_no_pending(&config.state_dir)?;
    let bundle: RotationBundle = read_private_json(bundle_path)?;
    verify_bundle(&config, &bundle, true)?;
    let entropy = unwrap(&config, &bundle)?;
    let key_path = WorkspaceKey::storage_path(&config.workspace)?;
    rotation_install::install_verified(
        config_path,
        &key_path,
        &entropy,
        &install_metadata(&config, &bundle)?,
    )?;
    make_receipt(&NodeConfig::load(config_path)?, &bundle)
}
pub fn recover(config_path: &Path, bundle_path: &Path) -> Result<RotationReceipt> {
    let config = NodeConfig::load(config_path)?;
    crate::updates::require_no_pending(&config.state_dir)?;
    let bundle: RotationBundle = read_private_json(bundle_path)?;
    // Recovery of an already committed pending transaction is permitted after capsule expiry.
    verify_bundle(&config, &bundle, false)?;
    let entropy = unwrap(&config, &bundle)?;
    if rotation_install::pending_metadata(&config.state_dir)?.is_some()
        || rotation_install::global_preparation_pending(&WorkspaceKey::storage_path(
            &config.workspace,
        )?)?
    {
        rotation_install::recover(
            config_path,
            &WorkspaceKey::storage_path(&config.workspace)?,
            &entropy,
            &install_metadata(&config, &bundle)?,
        )?;
    } else {
        // Losing the CLI's receipt file after durable installation must not require another key.
        // An expired, never-installed plan still cannot enter this branch as a fresh installation.
        let installed =
            rotation_install::read_installed(&config.state_dir)?.ok_or("rotation_not_installed")?;
        if installed.plan_sha256 != bundle.draft.plan_sha256()?
            || installed.epoch != bundle.draft.plan.header.epoch
            || installed.current_key_id != bundle.draft.plan.header.new_key_id
        {
            return Err("rotation_recovery_binding_mismatch".into());
        }
    }
    make_receipt(&NodeConfig::load(config_path)?, &bundle)
}
fn receipt_message(payload: &ReceiptPayload) -> Result<Vec<u8>> {
    let mut bytes = RECEIPT_DOMAIN.to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(payload)?);
    Ok(bytes)
}
fn possession_plaintext(bundle: &RotationBundle, node_id: &str) -> Result<String> {
    Ok(format!(
        "installed:{}:{}:{}",
        bundle.draft.plan.header.epoch,
        bundle.draft.plan_sha256()?,
        node_id
    ))
}
fn make_receipt(config: &NodeConfig, bundle: &RotationBundle) -> Result<RotationReceipt> {
    rotation_install::require_no_pending(&config.state_dir)?;
    let _key_guard =
        rotation_install::guard_workspace_key(&WorkspaceKey::storage_path(&config.workspace)?)?;
    rotation_install::require_global_binding(
        config,
        &WorkspaceKey::storage_path(&config.workspace)?,
    )?;
    let installed =
        rotation_install::read_installed(&config.state_dir)?.ok_or("rotation_not_installed")?;
    let key =
        WorkspaceKey::load_for_workspace(&config.workspace)?.ok_or("workspace_key_unavailable")?;
    if key.key_id() != bundle.draft.plan.header.new_key_id
        || installed.plan_sha256 != bundle.draft.plan_sha256()?
    {
        return Err("rotation_not_installed".into());
    }
    sign_receipt(config, bundle, &key)
}
fn sign_receipt(
    config: &NodeConfig,
    bundle: &RotationBundle,
    key: &WorkspaceKey,
) -> Result<RotationReceipt> {
    let der = provenance::read_bounded(&config.certificate, 64 * 1024)?;
    let signing = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &private_key_bytes(&config.private_key)?,
        &SystemRandom::new(),
    )
    .map_err(|_| "invalid_rotation_receipt_key")?;
    if signing.public_key().as_ref() != certificate_public(&der)?.as_slice() {
        return Err("rotation_private_key_certificate_mismatch".into());
    }
    let payload = ReceiptPayload {
        workspace: config.workspace.clone(),
        node_id: config.node_id.clone(),
        epoch: bundle.draft.plan.header.epoch,
        new_key_id: key.key_id(),
        plan_sha256: bundle.draft.plan_sha256()?,
        certificate_sha256: provenance::sha256(&der),
        installed_at_ms: now_ms()?,
        direct_trust_reconciled: true,
        new_key_possession: key.encrypt(
            &config.workspace,
            "rotation-receipt-v1",
            &possession_plaintext(bundle, &config.node_id)?,
        )?,
    };
    let signed = signing
        .sign(&SystemRandom::new(), &receipt_message(&payload)?)
        .map_err(|_| "rotation_receipt_sign_failed")?;
    Ok(RotationReceipt {
        payload,
        certificate_der: STANDARD.encode(&der),
        signature: STANDARD.encode(signed.as_ref()),
    })
}
fn verify_receipt(
    bundle: &RotationBundle,
    key: &WorkspaceKey,
    receipt: &RotationReceipt,
) -> Result<String> {
    let p = &receipt.payload;
    let recipient = bundle
        .draft
        .plan
        .recipients
        .iter()
        .find(|r| r.node_id == p.node_id)
        .ok_or("unapproved_rotation_receipt")?;
    if p.workspace != bundle.draft.plan.header.workspace
        || p.epoch != bundle.draft.plan.header.epoch
        || p.new_key_id != key.key_id()
        || p.new_key_id != bundle.draft.plan.header.new_key_id
        || p.plan_sha256 != bundle.draft.plan_sha256()?
        || p.certificate_sha256 != recipient.certificate_sha256
        || !p.direct_trust_reconciled
        || p.installed_at_ms.saturating_add(60_000) < bundle.draft.plan.header.created_at_ms
        || p.installed_at_ms > now_ms()?.saturating_add(60_000)
    {
        return Err("invalid_rotation_receipt_binding".into());
    }
    let der = decode(&receipt.certificate_der, 64 * 1024)?;
    if provenance::sha256(&der) != recipient.certificate_sha256 {
        return Err("rotation_receipt_certificate_mismatch".into());
    }
    signature::UnparsedPublicKey::new(
        &signature::ECDSA_P256_SHA256_FIXED,
        certificate_public(&der)?,
    )
    .verify(&receipt_message(p)?, &decode(&receipt.signature, 64)?)
    .map_err(|_| "rotation_receipt_signature_invalid")?;
    if key.decrypt(
        &bundle.draft.plan.header.workspace,
        "rotation-receipt-v1",
        &p.new_key_possession,
    )? != possession_plaintext(bundle, &p.node_id)?
    {
        return Err("invalid_rotation_key_possession".into());
    }
    Ok(p.node_id.clone())
}

pub fn status(
    config_path: &Path,
    bundle_path: &Path,
    receipt_paths: &[PathBuf],
) -> Result<RotationStatus> {
    let config = NodeConfig::load(config_path)?;
    let bundle: RotationBundle = read_private_json(bundle_path)?;
    verify_bundle(&config, &bundle, false)?;
    rotation_install::require_no_pending(&config.state_dir)?;
    let _key_guard =
        rotation_install::guard_workspace_key(&WorkspaceKey::storage_path(&config.workspace)?)?;
    rotation_install::require_global_binding(
        &config,
        &WorkspaceKey::storage_path(&config.workspace)?,
    )?;
    let key =
        WorkspaceKey::load_for_workspace(&config.workspace)?.ok_or("workspace_key_unavailable")?;
    if key.key_id() != bundle.draft.plan.header.new_key_id {
        return Err("apply_owner_node_before_verifying_receipts".into());
    }
    let mut received = BTreeSet::new();
    for path in receipt_paths {
        let receipt: RotationReceipt = read_private_json(path)?;
        if !received.insert(verify_receipt(&bundle, &key, &receipt)?) {
            return Err("duplicate_rotation_receipt".into());
        }
    }
    Ok(RotationStatus {
        workspace: config.workspace,
        epoch: bundle.draft.plan.header.epoch,
        plan_sha256: bundle.draft.plan_sha256()?,
        complete: received.len() == bundle.draft.plan.recipients.len(),
        recipients: bundle
            .draft
            .plan
            .recipients
            .iter()
            .map(|r| RecipientStatus {
                node_id: r.node_id.clone(),
                installed: received.contains(&r.node_id),
            })
            .collect(),
    })
}

pub fn read_private_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&read_private(
        path,
        MAX_ROTATION_FILE_BYTES,
    )?)?)
}
#[cfg(unix)]
fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    if !path.is_absolute() || std::fs::canonicalize(path)? != path {
        return Err("rotation_unsafe_file_path".into());
    }
    crate::retention::require_directory(path.parent().ok_or("invalid_rotation_path")?)?;
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > limit as u64
    {
        return Err("rotation_file_must_be_private_owned_regular_and_bounded".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("rotation_file_too_large".into());
    }
    Ok(bytes)
}
#[cfg(unix)]
pub fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    crate::retention::require_directory(path.parent().ok_or("invalid_rotation_path")?)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > MAX_ROTATION_FILE_BYTES {
        return Err("rotation_file_too_large".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    lockyard_core::fsio::sync_path(path.parent().ok_or("invalid_rotation_path")?)?;
    Ok(())
}

#[cfg(windows)]
fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>> {
    Ok(lockyard_core::windows::read_private(path, limit as u64)?)
}

#[cfg(windows)]
pub fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    crate::retention::require_directory(path.parent().ok_or("invalid_rotation_path")?)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() > MAX_ROTATION_FILE_BYTES {
        return Err("rotation_file_too_large".into());
    }
    let mut file = lockyard_core::windows::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };
    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
        config: NodeConfig,
        worker: NodeConfig,
        excluded: NodeConfig,
        signer: SigningKey,
        signer_path: PathBuf,
        draft_path: PathBuf,
        old: WorkspaceKey,
    }
    impl Fixture {
        fn new() -> Self {
            let tempdir = tempfile::tempdir().unwrap();
            let root = tempdir.path().canonicalize().unwrap();
            fs::set_permissions(root.as_path(), fs::Permissions::from_mode(0o700)).unwrap();
            let make = |name: &str| {
                let dir = root.as_path().join(name);
                fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
                let identity = crate::quic::generate_identity(
                    &dir.join("identity"),
                    vec![format!("{name}.test")],
                )
                .unwrap();
                let state = dir.join("state");
                fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
                serde_json::from_value::<NodeConfig>(serde_json::json!({"node_id":name,"workspace":"rotation-fixture","state_dir":state,"listen":null,"certificate":identity.certificate,"private_key":identity.private_key,"relay":null,"executor":null})).unwrap()
            };
            let config = make("owner");
            let worker = make("worker");
            let excluded = make("excluded");
            let signer_path = root.as_path().join("authority.pk8");
            let signer = SigningKey::generate(&signer_path).unwrap();
            for node in [&config, &worker, &excluded] {
                write_private_json(
                    &authority_path(node),
                    &AuthorityPin {
                        version: 1,
                        workspace: node.workspace.clone(),
                        key: signer.trusted_key(),
                    },
                )
                .unwrap();
            }
            let draft_path = root.as_path().join("draft.json");
            Self {
                _root: tempdir,
                root,
                config,
                worker,
                excluded,
                signer,
                signer_path,
                draft_path,
                old: WorkspaceKey::from_entropy([27; 32]),
            }
        }
        fn draft(&self) -> RotationDraft {
            prepare_for(
                &self.config,
                vec![
                    RecipientSpec {
                        node_id: self.config.node_id.clone(),
                        certificate: self.config.certificate.clone(),
                    },
                    RecipientSpec {
                        node_id: self.worker.node_id.clone(),
                        certificate: self.worker.certificate.clone(),
                    },
                ],
                &self.signer.trusted_key(),
                &self.old,
                RotationReason::MemberRevocation,
                HistoryPolicy::Discard,
                1,
                now_ms().unwrap() + 3_600_000,
            )
            .unwrap()
        }
        fn bundle(&self) -> RotationBundle {
            let draft = self.draft();
            let authorization = self
                .signer
                .sign_document(DOMAIN, &draft.authorization().unwrap())
                .unwrap();
            RotationBundle {
                draft,
                authorization,
            }
        }
    }
    #[test]
    fn hpke_capsules_install_same_new_key_only_for_explicit_approved_nodes() {
        let f = Fixture::new();
        let b = f.bundle();
        verify_bundle(&f.config, &b, true).unwrap();
        verify_bundle(&f.worker, &b, true).unwrap();
        let owner = unwrap(&f.config, &b).unwrap();
        let worker = unwrap(&f.worker, &b).unwrap();
        assert_eq!(owner.as_ref(), worker.as_ref());
        assert_ne!(*owner, [27; 32]);
        assert!(
            unwrap(&f.excluded, &b)
                .unwrap_err()
                .to_string()
                .contains("excluded")
        );
        let old_rpc = f
            .old
            .encrypt(&f.config.workspace, "rpc", "private old content")
            .unwrap();
        assert!(
            WorkspaceKey::from_entropy(*owner)
                .decrypt(&f.config.workspace, "rpc", &old_rpc)
                .is_err()
        );
    }
    #[test]
    fn cloud_cannot_replace_pinned_authority_or_resign_chosen_key() {
        let f = Fixture::new();
        let mut b = f.bundle();
        let attacker_path = f.root.as_path().join("attacker.pk8");
        let attacker = SigningKey::generate(&attacker_path).unwrap();
        b.draft.plan.header.authority_key_id = attacker.trusted_key().key_id().unwrap();
        b.authorization = attacker
            .sign_document(DOMAIN, &b.draft.authorization().unwrap())
            .unwrap();
        assert!(verify_bundle(&f.worker, &b, true).is_err());
        let mut b = f.bundle();
        b.authorization.signature = STANDARD.encode([0; 64]);
        assert!(verify_bundle(&f.worker, &b, true).is_err());
    }
    #[test]
    fn signed_digest_binds_header_roster_capsules_and_recipient_aad() {
        let f = Fixture::new();
        let b = f.bundle();
        let mut changed = b.clone();
        changed.draft.plan.header.epoch = 2;
        assert!(verify_bundle(&f.worker, &changed, true).is_err());
        assert!(unwrap(&f.worker, &changed).is_err());
        let mut changed = b.clone();
        changed.draft.capsules.get_mut("worker").unwrap().ciphertext = STANDARD.encode([1; 48]);
        assert!(verify_bundle(&f.worker, &changed, true).is_err());
        assert!(unwrap(&f.worker, &changed).is_err());
        let mut changed = b.clone();
        changed.draft.plan.recipients[1].certificate_sha256 = "a".repeat(64);
        assert!(verify_bundle(&f.worker, &changed, true).is_err());
        assert!(unwrap(&f.worker, &changed).is_err());
        let mut changed = b.clone();
        changed
            .draft
            .capsules
            .insert("excluded".into(), b.draft.capsules["worker"].clone());
        assert!(verify_bundle(&f.worker, &changed, true).is_err());
    }
    #[test]
    fn recipient_certificate_and_private_key_must_match() {
        let f = Fixture::new();
        let b = f.bundle();
        let mut swapped = f.worker.clone();
        swapped.private_key = f.excluded.private_key.clone();
        assert!(
            unwrap(&swapped, &b)
                .unwrap_err()
                .to_string()
                .contains("certificate_mismatch")
        );
        swapped.certificate = f.excluded.certificate.clone();
        assert!(unwrap(&swapped, &b).is_err());
    }
    #[test]
    fn commit_requires_exact_operator_approved_digest_and_unexpired_plan() {
        let f = Fixture::new();
        let draft = f.draft();
        write_private_json(&f.draft_path, &draft).unwrap();
        assert!(commit(&f.draft_path, &f.signer_path, &"0".repeat(64)).is_err());
        assert!(authorize_draft(draft.clone(), &f.signer, &"0".repeat(64)).is_err());
        let b = authorize_draft(draft.clone(), &f.signer, &draft.plan_sha256().unwrap()).unwrap();
        verify_bundle(&f.worker, &b, true).unwrap();
        let mut expired = draft;
        expired.plan.header.created_at_ms = now_ms().unwrap() - 2000;
        expired.plan.header.expires_at_ms = now_ms().unwrap() - 1000;
        assert!(expired.validate(now_ms().unwrap(), true).is_err());
        assert!(expired.validate(now_ms().unwrap(), false).is_ok());
    }
    #[test]
    fn roster_requires_canonical_unique_nodes_and_distinct_recipient_identities() {
        let f = Fixture::new();
        let mut d = f.draft();
        d.plan.recipients.reverse();
        assert!(d.validate(now_ms().unwrap(), true).is_err());
        let mut d = f.draft();
        d.plan.recipients[1].certificate_sha256 = d.plan.recipients[0].certificate_sha256.clone();
        assert!(d.validate(now_ms().unwrap(), true).is_err());
        let mut d = f.draft();
        d.capsules
            .get_mut("owner")
            .unwrap()
            .encapsulated_key
            .push('=');
        assert!(d.validate(now_ms().unwrap(), true).is_err());
    }
    #[test]
    fn authority_pin_is_create_only_and_workspace_bound() {
        let f = Fixture::new();
        let mut b = f.bundle();
        b.draft.plan.header.workspace = "other-workspace".into();
        b.authorization = f
            .signer
            .sign_document(DOMAIN, &b.draft.authorization().unwrap())
            .unwrap();
        assert!(verify_bundle(&f.worker, &b, true).is_err());
        assert!(
            write_private_json(
                &authority_path(&f.worker),
                &AuthorityPin {
                    version: 1,
                    workspace: f.worker.workspace.clone(),
                    key: f.signer.trusted_key()
                }
            )
            .is_err()
        );
    }
    #[test]
    fn normal_authority_private_keys_require_exact_protected_directory() {
        let f = Fixture::new();
        let root = f.root.as_path().join("rotation-authorities");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        validate_authority_location(&root.join("customer.pk8"), &root).unwrap();
        assert!(validate_authority_location(&f.signer_path, &root).is_err());
        assert!(validate_authority_location(&root.join(".hidden.pk8"), &root).is_err());
        let nested = root.join("nested");
        fs::DirBuilder::new().mode(0o700).create(&nested).unwrap();
        assert!(validate_authority_location(&nested.join("customer.pk8"), &root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_authority_location(&root.join("customer.pk8"), &root).is_err());
    }
    #[test]
    fn local_phrase_display_requires_explicit_confirmation_and_returns_only_the_chosen_local_key() {
        let f = Fixture::new();
        assert!(confirmed_phrase(&f.old, "").is_err());
        assert!(confirmed_phrase(&f.old, "yes").is_err());
        let phrase = confirmed_phrase(&f.old, "SHOW\n").unwrap();
        assert_eq!(
            WorkspaceKey::from_phrase(&phrase).unwrap().key_id(),
            f.old.key_id()
        );
    }
    #[test]
    fn retained_uppercase_configured_certificate_pin_is_not_an_excluded_identity() {
        let mut f = Fixture::new();
        f.config.peers.push(crate::host::PeerConfig {
            node_id: f.worker.node_id.clone(),
            address: None,
            tls_name: "worker.test".into(),
            certificate_sha256: provenance::sha256(&fs::read(&f.worker.certificate).unwrap())
                .to_ascii_uppercase(),
            certificate: f.worker.certificate.clone(),
            allowed_operations: Vec::new(),
        });
        f.draft().validate(now_ms().unwrap(), true).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn rotation_file_read_rejects_symlinks_fifos_oversize_and_public_permissions() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        write_private_json(&f.draft_path, &f.draft()).unwrap();
        let link = f.root.as_path().join("link");
        symlink(&f.draft_path, &link).unwrap();
        assert!(read_private_json::<RotationDraft>(&link).is_err());
        let alias = f.root.as_path().join("hardlink");
        fs::hard_link(&f.draft_path, &alias).unwrap();
        assert!(read_private_json::<RotationDraft>(&f.draft_path).is_err());
        fs::remove_file(alias).unwrap();
        fs::set_permissions(&f.draft_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_json::<RotationDraft>(&f.draft_path).is_err());
        let fifo = f.root.as_path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_private_json::<RotationDraft>(&fifo).is_err());
        assert!(decode(&"a".repeat(10_000), 65).is_err());
    }
    #[test]
    fn maximum_roster_authorization_signs_bounded_digest_without_truncating_the_plan() {
        let f = Fixture::new();
        let mut draft = f.draft();
        let capsule = draft.capsules["owner"].clone();
        draft.plan.recipients.clear();
        draft.capsules.clear();
        // Structural scale proof; copied capsules intentionally are not recipient-decryption proof.
        for index in 0..MAX_RECIPIENTS {
            let node_id = format!("node-{index:03}");
            draft.plan.recipients.push(ApprovedRecipient {
                certificate_sha256: provenance::sha256(node_id.as_bytes()),
                node_id: node_id.clone(),
                capsule_sha256: sha(&capsule).unwrap(),
            });
            draft.capsules.insert(node_id, capsule.clone());
        }
        draft.validate(now_ms().unwrap(), true).unwrap();
        assert!(
            serde_json::to_vec(&draft.plan).unwrap().len() > provenance::MAX_SIGNED_DOCUMENT_BYTES
        );
        let signed = f
            .signer
            .sign_document(DOMAIN, &draft.authorization().unwrap())
            .unwrap();
        assert!(serde_json::to_vec(&signed).unwrap().len() < 2048);
        let verified: PlanAuthorization =
            provenance::verify_document(&signed, DOMAIN, &f.signer.trusted_key()).unwrap();
        assert_eq!(verified.plan_sha256, draft.plan_sha256().unwrap());
        draft.plan.recipients[511].certificate_sha256 = "1".repeat(64);
        assert_ne!(verified.plan_sha256, draft.plan_sha256().unwrap());
    }
    #[test]
    fn completion_receipts_require_approved_tls_signature_new_key_and_exact_epoch_plan() {
        let f = Fixture::new();
        let b = f.bundle();
        let key = WorkspaceKey::from_entropy(*unwrap(&f.config, &b).unwrap());
        let owner = sign_receipt(&f.config, &b, &key).unwrap();
        let worker = sign_receipt(&f.worker, &b, &key).unwrap();
        assert_eq!(verify_receipt(&b, &key, &owner).unwrap(), "owner");
        assert_eq!(verify_receipt(&b, &key, &worker).unwrap(), "worker");
        let old_key_receipt = sign_receipt(&f.worker, &b, &f.old).unwrap();
        assert!(verify_receipt(&b, &key, &old_key_receipt).is_err());
        let excluded = sign_receipt(&f.excluded, &b, &key).unwrap();
        assert!(verify_receipt(&b, &key, &excluded).is_err());
        let mut changed = worker.clone();
        changed.payload.direct_trust_reconciled = false;
        assert!(verify_receipt(&b, &key, &changed).is_err());
        let mut changed = worker.clone();
        changed.payload.epoch += 1;
        assert!(verify_receipt(&b, &key, &changed).is_err());
        let mut changed = worker.clone();
        changed.payload.new_key_possession = owner.payload.new_key_possession.clone();
        assert!(verify_receipt(&b, &key, &changed).is_err());
        let mut changed = worker;
        changed.certificate_der = excluded.certificate_der;
        assert!(verify_receipt(&b, &key, &changed).is_err());
        assert!(verify_receipt(&f.bundle(), &key, &owner).is_err());
    }
    // Paste into rotation.rs's existing tests module. Uses its Fixture/private prepare_for helpers.
    fn same_private_key_certificates(
        first_name: &str,
        second_name: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let first = rcgen::CertificateParams::new(vec![first_name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let second = rcgen::CertificateParams::new(vec![second_name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let first = first.der().to_vec();
        let second = second.der().to_vec();
        assert_ne!(provenance::sha256(&first), provenance::sha256(&second));
        assert_eq!(
            certificate_public(&first).unwrap(),
            certificate_public(&second).unwrap()
        );
        (first, second, key.serialize_der())
    }

    #[test]
    fn recipient_certificates_with_distinct_der_but_same_p256_key_are_rejected() {
        let f = Fixture::new();
        let (owner_der, worker_der, shared_pkcs8) =
            same_private_key_certificates("owner.test", "worker.test");
        fs::write(&f.config.certificate, owner_der).unwrap();
        fs::write(&f.worker.certificate, worker_der).unwrap();
        // Both already-existing private files retain their fixture permissions.
        fs::write(&f.config.private_key, &shared_pkcs8).unwrap();
        fs::write(&f.worker.private_key, &shared_pkcs8).unwrap();
        let specs = vec![
            RecipientSpec {
                node_id: f.config.node_id.clone(),
                certificate: f.config.certificate.clone(),
            },
            RecipientSpec {
                node_id: f.worker.node_id.clone(),
                certificate: f.worker.certificate.clone(),
            },
        ];
        assert!(
            prepare_for(
                &f.config,
                specs,
                &f.signer.trusted_key(),
                &f.old,
                RotationReason::Compromise,
                HistoryPolicy::Discard,
                1,
                now_ms().unwrap() + 3_600_000
            )
            .is_err()
        );
    }

    #[test]
    fn approved_new_certificate_reusing_locally_known_excluded_private_key_is_rejected() {
        let mut f = Fixture::new();
        let (worker_der, excluded_der, shared_pkcs8) =
            same_private_key_certificates("worker.test", "excluded.test");
        fs::write(&f.worker.certificate, &worker_der).unwrap();
        fs::write(&f.excluded.certificate, &excluded_der).unwrap();
        fs::write(&f.worker.private_key, &shared_pkcs8).unwrap();
        fs::write(&f.excluded.private_key, &shared_pkcs8).unwrap();
        f.config.peers.push(crate::host::PeerConfig {
            node_id: f.excluded.node_id.clone(),
            address: None,
            tls_name: "excluded.test".into(),
            certificate_sha256: provenance::sha256(&excluded_der),
            certificate: f.excluded.certificate.clone(),
            allowed_operations: Vec::new(),
        });
        let specs = vec![
            RecipientSpec {
                node_id: f.config.node_id.clone(),
                certificate: f.config.certificate.clone(),
            },
            RecipientSpec {
                node_id: f.worker.node_id.clone(),
                certificate: f.worker.certificate.clone(),
            },
        ];
        assert!(
            prepare_for(
                &f.config,
                specs,
                &f.signer.trusted_key(),
                &f.old,
                RotationReason::Compromise,
                HistoryPolicy::Discard,
                1,
                now_ms().unwrap() + 3_600_000
            )
            .is_err()
        );
    }
}
