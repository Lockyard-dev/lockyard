// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! One-use enrollment. The invitation secret never goes to the broker: separate HMAC
//! domains derive its claim proof and envelope key. Recipients prove their certificate key.
//! Neither Debug implementations nor errors expose invitation, bearer or workspace secrets.
use crate::{Result, cloud::NodeCloudClient, host::NodeConfig, quic, wire};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lockyard_cloud_client::WorkspaceKey;
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_FILE: u64 = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub v: u32,
    pub node_id: String,
    pub tls_name: String,
    pub certificate_der: String,
    pub certificate_sha256: String,
    pub result_signing_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    id: String,
    workspace_id: String,
    node_id: String,
    certificate_sha256: String,
    request_sha256: String,
    issuer_sha256: String,
    broker_url: String,
    expires_at: u64,
    credential_expires_at: u64,
}

/// The transferable ticket has NO ciphertext bundle. Expiry and one-use redemption must
/// succeed on the broker before a first-time recipient can obtain the encrypted key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    v: u32,
    metadata: Metadata,
    secret: String,
    broker_tls_roots: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    metadata: Metadata,
    recipient_tls_name: String,
    workspace_key_phrase: String,
    broker_tls_roots: Vec<String>,
    /// Public signing trust is part of the authenticated, encrypted enrollment bundle.
    #[serde(default)]
    result_trust: Value,
    /// Pinned by the owner and carried only inside the authenticated ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocations: Option<crate::revocations::RevocationConfig>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    id: String,
    node_id: String,
    certificate_der: String,
    certificate_sha256: String,
    request_sha256: String,
    issuer_sha256: String,
    broker_url: String,
    claim_sha256: String,
    expires_at: u64,
    credential_expires_at: u64,
    payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingInvite {
    ticket: Ticket,
    request: CreateRequest,
    output: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    id: String,
    workspace_id: String,
    node_id: String,
    expires_at: u64,
    redeemed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    id: String,
    workspace_id: String,
    node_id: String,
    certificate_sha256: String,
    token_sha256: String,
    proof: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingJoin {
    ticket_sha256: String,
    config: PathBuf,
    machine_token: String,
    claim: Claim,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedJoin {
    id: String,
    token_id: String,
    config: PathBuf,
    ticket_sha256: String,
    token_sha256: String,
    node_id: String,
    workspace_id: String,
    credential_expires_at: u64,
    workspace_key_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: String,
    workspace_id: String,
    node_id: String,
    certificate_sha256: String,
    token_id: String,
    credential_expires_at: u64,
    payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    node_id: String,
    credential_id: String,
    certificate_sha256: String,
    machine: bool,
    credential_live: bool,
    registered_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    node_id: String,
    credential_id: String,
    certificate_sha256: String,
    retired_at: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}
fn unhex(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid private enrollment material".into());
    }
    let mut bytes = [0; 32];
    for (offset, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[offset * 2..offset * 2 + 2], 16)
            .map_err(|_| "invalid private enrollment material")?;
    }
    Ok(bytes)
}
fn random() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "enrollment random source unavailable")?;
    Ok(bytes)
}
fn derive(secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(hmac::sign(&key, label).as_ref());
    bytes
}
fn claim_proof(secret: &[u8; 32]) -> String {
    hex(&derive(secret, b"lockyard-node-invite-claim-v1"))
}
fn bundle_key(secret: &[u8; 32]) -> WorkspaceKey {
    WorkspaceKey::from_entropy(derive(secret, b"lockyard-node-invite-encryption-v1"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    })
}

fn secure_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
        File::open(path.parent().ok_or("invalid enrollment directory")?)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err("enrollment state directory must be private and owned by this user".into());
    }
    Ok(())
}

fn private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot read private enrollment file")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > limit
    {
        return Err("enrollment file must be private, regular and bounded".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("enrollment file exceeds limit".into());
    }
    Ok(bytes)
}

/// Durable create-only publication: a kill cannot leave a partially visible receipt. Every
/// contender syncs the parent before it may send an irreversible claim to the broker.
fn persist(path: &Path, bytes: &[u8]) -> Result<bool> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = path.parent().ok_or("invalid enrollment output path")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "enrollment output parent must be owned by this user and not writable by others".into(),
        );
    }
    let temporary = parent.join(format!(
        ".lockyard-enroll-{}.partial",
        lockyard_cloud_client::ulid()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let result = match fs::hard_link(&temporary, path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    };
    // If the target already exists, the winning creator might not have synced yet.
    File::open(parent)?.sync_all()?;
    fs::remove_file(&temporary)?;
    result.map_err(Into::into)
}
fn persist_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if !persist(path, bytes)? && private(path, MAX_FILE)? != bytes {
        return Err("enrollment destination already contains different material".into());
    }
    Ok(())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(|_| "cannot encode private enrollment receipt".into())
}
fn decode<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    serde_json::from_slice(&private(path, MAX_FILE)?)
        .map_err(|_| "invalid private enrollment receipt".into())
}
fn retire(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    File::open(path.parent().ok_or("invalid enrollment receipt")?)?.sync_all()?;
    Ok(())
}

fn validate_request(request: &JoinRequest) -> Result<Vec<u8>> {
    let certificate = URL_SAFE_NO_PAD
        .decode(&request.certificate_der)
        .map_err(|_| "invalid recipient certificate")?;
    if request.v != 1
        || !wire::valid_name(&request.node_id)
        || request.node_id.starts_with("web_")
        || request.tls_name.is_empty()
        || request.tls_name.len() > 253
        || certificate.is_empty()
        || certificate.len() > 8192
        || quic::PeerPin::certificate(&certificate).to_hex() != request.certificate_sha256
    {
        return Err("invalid recipient join request".into());
    }
    crate::provenance::TrustedSigningKey {
        public_key: request.result_signing_public_key.clone(),
    }
    .validate()?;
    Ok(certificate)
}
fn validate_metadata(metadata: &Metadata) -> Result<()> {
    let workspace = &metadata.workspace_id;
    if workspace.len() != 36
        || !workspace.bytes().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        || !wire::valid_name(&metadata.node_id)
        || metadata.node_id.starts_with("web_")
        || !wire::valid_ulid(&metadata.id)
        || metadata.credential_expires_at <= metadata.expires_at
    {
        return Err("invitation metadata is not bound to a canonical cloud workspace".into());
    }
    unhex(&metadata.certificate_sha256)?;
    unhex(&metadata.request_sha256)?;
    unhex(&metadata.issuer_sha256)?;
    Ok(())
}

fn valid_guid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn aad(metadata: &Metadata) -> String {
    format!(
        "node-invite-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        metadata.id,
        metadata.node_id,
        metadata.certificate_sha256,
        metadata.request_sha256,
        metadata.issuer_sha256,
        metadata.broker_url,
        metadata.expires_at,
        metadata.credential_expires_at
    )
}
fn signature_message(metadata: &Metadata, token_hash: &str) -> Vec<u8> {
    format!(
        "lockyard-node-invite-redeem-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        metadata.id,
        metadata.workspace_id,
        metadata.node_id,
        metadata.certificate_sha256,
        metadata.request_sha256,
        metadata.issuer_sha256,
        metadata.broker_url,
        metadata.expires_at,
        metadata.credential_expires_at,
        token_hash
    )
    .into_bytes()
}

pub fn prepare(
    node_id: String,
    tls_name: String,
    state_dir: &Path,
    output: &Path,
) -> Result<Value> {
    if !wire::valid_name(&node_id)
        || node_id.starts_with("web_")
        || tls_name.is_empty()
        || tls_name.len() > 253
    {
        return Err("invalid recipient node identity".into());
    }
    let state_dir = absolute(state_dir)?;
    let output = absolute(output)?;
    secure_dir(&state_dir)?;
    let result_signing =
        crate::provenance::SigningKey::generate(&state_dir.join("result-signing.pk8"))?;
    let identity = quic::generate_identity(&state_dir, vec![tls_name.clone()])?;
    let certificate = fs::read(&identity.certificate)?;
    let request = JoinRequest {
        v: 1,
        node_id,
        tls_name,
        certificate_der: URL_SAFE_NO_PAD.encode(certificate),
        certificate_sha256: identity.certificate_sha256,
        result_signing_public_key: result_signing.trusted_key().public_key,
    };
    let bytes = encode(&request)?;
    persist_exact(&state_dir.join("join-request.json"), &bytes)?;
    persist_exact(&output, &bytes)?;
    Ok(
        json!({"request":output,"state_dir":state_dir,"certificate_sha256":request.certificate_sha256,"result_signing_public_key":request.result_signing_public_key}),
    )
}

pub fn create(
    config_path: &Path,
    request_path: &Path,
    output: &Path,
    expires_seconds: u64,
    credential_days: u64,
) -> Result<Value> {
    if !(60..=86400).contains(&expires_seconds)
        || !(1..=366).contains(&credential_days)
        || credential_days * 86400 <= expires_seconds
    {
        return Err("invitation lifetime must be 60..86400 seconds and shorter than the 1..366 day credential lifetime".into());
    }
    let output = absolute(output)?;
    if fs::symlink_metadata(&output).is_ok() {
        return Err(
            "invitation output already exists; use another path or resume its private receipt"
                .into(),
        );
    }
    let config = NodeConfig::load(config_path)?;
    let client = NodeCloudClient::from_config(&config)?;
    let recipient: JoinRequest = decode(request_path)?;
    validate_request(&recipient)?;
    let key = WorkspaceKey::load_for_workspace(&config.workspace)?
        .ok_or("inviting node requires its local workspace key")?;
    let issued = now()?;
    let metadata = Metadata {
        id: lockyard_cloud_client::ulid(),
        workspace_id: config.workspace.clone(),
        node_id: recipient.node_id.clone(),
        certificate_sha256: recipient.certificate_sha256.clone(),
        request_sha256: sha(
            &serde_json::to_vec(&recipient).map_err(|_| "cannot encode recipient request")?
        ),
        issuer_sha256: client.credential_hash()?,
        broker_url: client.broker_url(),
        expires_at: issued + expires_seconds,
        credential_expires_at: issued + credential_days * 86400,
    };
    validate_metadata(&metadata)?;
    let secret = random()?;
    let roots = config
        .relay
        .as_ref()
        .ok_or("node relay required")?
        .tls_roots
        .iter()
        .map(|path| {
            let bytes = fs::read(path)?;
            if bytes.len() > 8192 {
                return Err("invitation trust anchor exceeds limit".into());
            }
            Ok(URL_SAFE_NO_PAD.encode(bytes))
        })
        .collect::<Result<Vec<_>>>()?;
    if roots.len() > 8 {
        return Err("too many invitation broker trust anchors".into());
    }
    let mut result_trust = serde_json::to_value(&config)?
        .get("result_trust")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if result_trust
        .get(&recipient.node_id)
        .is_some_and(|entry| entry["public_key"] != recipient.result_signing_public_key)
    {
        return Err("recipient signing key conflicts with an existing independent pin".into());
    }
    result_trust[&recipient.node_id] = json!({"public_key":recipient.result_signing_public_key});
    let bundle = Bundle {
        metadata: metadata.clone(),
        recipient_tls_name: recipient.tls_name,
        workspace_key_phrase: key.phrase(),
        broker_tls_roots: roots.clone(),
        result_trust,
        revocations: config.revocations.clone(),
    };
    let plaintext = serde_json::to_string(&bundle).map_err(|_| "cannot seal enrollment bundle")?;
    let payload = bundle_key(&secret).encrypt(&config.workspace, &aad(&metadata), &plaintext)?;
    if payload.len() > 64 * 1024 {
        return Err("enrollment bundle exceeds broker limit".into());
    }
    let request = CreateRequest {
        id: metadata.id.clone(),
        node_id: metadata.node_id.clone(),
        certificate_der: recipient.certificate_der,
        certificate_sha256: metadata.certificate_sha256.clone(),
        request_sha256: metadata.request_sha256.clone(),
        issuer_sha256: metadata.issuer_sha256.clone(),
        broker_url: metadata.broker_url.clone(),
        claim_sha256: sha(claim_proof(&secret).as_bytes()),
        expires_at: metadata.expires_at,
        credential_expires_at: metadata.credential_expires_at,
        payload,
    };
    let pending = PendingInvite {
        ticket: Ticket {
            v: 1,
            metadata,
            secret: hex(&secret),
            broker_tls_roots: roots,
        },
        request,
        output: output.clone(),
    };
    let mut pending_name = output.as_os_str().to_os_string();
    pending_name.push(".pending");
    let receipt = PathBuf::from(pending_name);
    if !persist(&receipt, &encode(&pending)?)? {
        return Err("pending invitation already exists; resume its receipt".into());
    }
    resume(config_path, &receipt)
}

pub fn resume(config_path: &Path, receipt_path: &Path) -> Result<Value> {
    let pending: PendingInvite = decode(receipt_path)?;
    let config = NodeConfig::load(config_path)?;
    let client = NodeCloudClient::from_config(&config)?;
    if pending.ticket.metadata.workspace_id != config.workspace
        || pending.ticket.metadata.broker_url != client.broker_url()
        || pending.ticket.metadata.issuer_sha256 != client.credential_hash()?
    {
        return Err("pending invitation belongs to another issuer context".into());
    }
    let body =
        serde_json::to_string(&pending.request).map_err(|_| "cannot encode enrollment request")?;
    let response = client
        .request("POST", "/invitations")
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|_| "invitation creation failed; resume the same private receipt")?;
    let receipt: Receipt = NodeCloudClient::decode(response)?;
    if receipt.id != pending.ticket.metadata.id
        || receipt.workspace_id != config.workspace
        || receipt.node_id != pending.ticket.metadata.node_id
        || receipt.expires_at != pending.ticket.metadata.expires_at
    {
        return Err("invitation broker returned mismatched metadata".into());
    }
    persist_exact(&pending.output, &encode(&pending.ticket)?)?;
    let secret = unhex(&pending.ticket.secret)?;
    let bundle: Bundle = serde_json::from_str(
        &bundle_key(&secret)
            .decrypt(
                &config.workspace,
                &aad(&pending.ticket.metadata),
                &pending.request.payload,
            )
            .map_err(|_| "pending invitation bundle failed authentication")?,
    )
    .map_err(|_| "invalid pending invitation bundle")?;
    let proposed_pin = json!({"node_id":pending.ticket.metadata.node_id,"trusted_key":bundle.result_trust[&pending.ticket.metadata.node_id],
        "invitation_id":receipt.id,"request_sha256":pending.ticket.metadata.request_sha256});
    let mut pin_name = pending.output.as_os_str().to_os_string();
    pin_name.push(".result-trust.json");
    let proposed_path = PathBuf::from(pin_name);
    persist_exact(&proposed_path, &encode(&proposed_pin)?)?;
    retire(receipt_path)?;
    Ok(
        json!({"invitation":pending.output,"id":receipt.id,"node_id":receipt.node_id,"expires_at":receipt.expires_at,"proposed_result_trust":proposed_path}),
    )
}

fn stage_workspace_key(workspace: &str, key: &WorkspaceKey) -> Result<()> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unavailable")?).join(".config"),
    };
    let base = absolute(&base)?;
    if !base.exists() {
        secure_dir(&base)?;
    }
    let lockyard = base.join("lockyard");
    secure_dir(&lockyard)?;
    let keys = lockyard.join("keys");
    secure_dir(&keys)?;
    let destination = keys.join(format!("{workspace}.key"));
    let verify = || -> Result<()> {
        let bytes = private(&destination, 32)?;
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "existing workspace key is malformed")?;
        let probe = key.encrypt(workspace, "node-join-key-check", "local key confirmation")?;
        if WorkspaceKey::from_entropy(raw)
            .decrypt(workspace, "node-join-key-check", &probe)
            .as_deref()
            != Ok("local key confirmation")
        {
            return Err("join cannot overwrite a different local workspace key".into());
        }
        // The winning publisher may have linked the complete key and died before syncing
        // its parent. Recovery must establish that directory durability itself.
        File::open(&keys)?.sync_all()?;
        Ok(())
    };
    if destination.exists() {
        verify()?;
    } else if let Err(error) = key.copy_to_private(&destination) {
        if destination.exists() {
            verify()?;
        } else {
            return Err(error.into());
        }
    }
    Ok(())
}

pub fn join(ticket_path: &Path, state_dir: &Path, config_path: &Path) -> Result<Value> {
    let ticket_bytes = private(ticket_path, MAX_FILE)?;
    let ticket: Ticket =
        serde_json::from_slice(&ticket_bytes).map_err(|_| "invalid private node invitation")?;
    if ticket.v != 1 {
        return Err("unsupported node invitation version".into());
    }
    validate_metadata(&ticket.metadata)?;
    let secret = unhex(&ticket.secret)?;
    let state_dir = absolute(state_dir)?;
    secure_dir(&state_dir)?;
    let config_path = absolute(config_path)?;
    let ticket_hash = sha(&ticket_bytes);
    let recipient: JoinRequest = decode(&state_dir.join("join-request.json"))?;
    let certificate = validate_request(&recipient)?;
    if recipient.node_id != ticket.metadata.node_id
        || recipient.certificate_sha256 != ticket.metadata.certificate_sha256
        || sha(&serde_json::to_vec(&recipient).map_err(|_| "cannot encode recipient request")?)
            != ticket.metadata.request_sha256
        || fs::read(state_dir.join("node-cert.der"))? != certificate
    {
        return Err("invitation was issued to another prepared recipient".into());
    }
    let result_signing =
        crate::provenance::SigningKey::load(&state_dir.join("result-signing.pk8"))?;
    if result_signing.trusted_key().public_key != recipient.result_signing_public_key {
        return Err("recipient result-signing key differs from its bound join request".into());
    }
    let completed_path = state_dir.join(format!("join-{}.completed.json", ticket.metadata.id));
    if completed_path.exists() {
        let completed: CompletedJoin = decode(&completed_path)?;
        let config = NodeConfig::load(&config_path)?;
        let token = private(&state_dir.join("node-token"), 4096)?;
        let key = WorkspaceKey::load_for_workspace(&ticket.metadata.workspace_id)?.ok_or("completed node enrollment lost its local workspace key; restore it without minting another identity")?;
        if completed.id != ticket.metadata.id
            || completed.ticket_sha256 != ticket_hash
            || completed.config != config_path
            || completed.node_id != ticket.metadata.node_id
            || completed.workspace_id != ticket.metadata.workspace_id
            || completed.token_sha256 != sha(&token)
            || config.node_id != completed.node_id
            || config.workspace != completed.workspace_id
            || key.key_id() != completed.workspace_key_id
            || config.state_dir != state_dir
            || config.certificate != state_dir.join("node-cert.der")
            || config.private_key != state_dir.join("node-key.der")
            || sha(&private(&config.certificate, 8192)?) != ticket.metadata.certificate_sha256
            || config.relay.as_ref().is_none_or(|relay| {
                relay.url != ticket.metadata.broker_url
                    || relay.token_file != state_dir.join("node-token")
            })
        {
            return Err(
                "completed enrollment no longer matches the local node configuration".into(),
            );
        }
        return Ok(
            json!({"config":config_path,"node_id":completed.node_id,"workspace":completed.workspace_id,
            "token_id":completed.token_id,"credential_expires_at":completed.credential_expires_at,"already_joined":true,
            "result_signing":{"workspace":ticket.metadata.workspace_id,"key_file":state_dir.join("result-signing.pk8"),"public_key":recipient.result_signing_public_key}}),
        );
    }
    let private_key = private(&state_dir.join("node-key.der"), 8192)?;
    let signer = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &private_key,
        &SystemRandom::new(),
    )
    .map_err(|_| "recipient certificate key is not supported")?;
    let receipt_path = state_dir.join(format!("join-{}.pending.json", ticket.metadata.id));
    if !receipt_path.exists() {
        if now()? >= ticket.metadata.expires_at {
            return Err("node invitation expired before first redemption".into());
        }
        let machine_token = hex(&random()?);
        let token_hash = sha(machine_token.as_bytes());
        let signature = signer
            .sign(
                &SystemRandom::new(),
                &signature_message(&ticket.metadata, &token_hash),
            )
            .map_err(|_| "cannot sign node enrollment claim")?;
        let claim = Claim {
            id: ticket.metadata.id.clone(),
            workspace_id: ticket.metadata.workspace_id.clone(),
            node_id: recipient.node_id.clone(),
            certificate_sha256: recipient.certificate_sha256.clone(),
            token_sha256: token_hash,
            proof: claim_proof(&secret),
            signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
        };
        let pending = PendingJoin {
            ticket_sha256: ticket_hash.clone(),
            config: config_path.clone(),
            machine_token,
            claim,
        };
        persist(&receipt_path, &encode(&pending)?)?;
    }
    // Read the durable winner even when two local join invocations raced to create it.
    let pending: PendingJoin = decode(&receipt_path)?;
    if pending.ticket_sha256 != ticket_hash
        || pending.config != config_path
        || pending.claim.token_sha256 != sha(pending.machine_token.as_bytes())
        || pending.claim.id != ticket.metadata.id
        || pending.claim.node_id != recipient.node_id
        || pending.claim.workspace_id != ticket.metadata.workspace_id
        || pending.claim.certificate_sha256 != recipient.certificate_sha256
        || pending.claim.proof != claim_proof(&secret)
    {
        return Err(
            "pending enrollment receipt differs from this invitation or destination".into(),
        );
    }
    File::open(&state_dir)?.sync_all()?;
    let roots = ticket
        .broker_tls_roots
        .iter()
        .map(|root| {
            URL_SAFE_NO_PAD
                .decode(root)
                .map_err(|_| "invalid invitation broker trust anchor".into())
        })
        .collect::<Result<Vec<_>>>()?;
    if roots.len() > 8 || roots.iter().any(|root| root.len() > 8192) {
        return Err("invitation trust material exceeds limit".into());
    }
    let client = NodeCloudClient::anonymous(
        &ticket.metadata.broker_url,
        recipient.node_id.clone(),
        &roots,
    )?;
    if client.broker_url() != ticket.metadata.broker_url {
        return Err("invitation broker namespace is not canonical".into());
    }
    let body =
        serde_json::to_string(&pending.claim).map_err(|_| "cannot encode node enrollment claim")?;
    let response = client.request("POST", "/invitations/redeem").set("Content-Type", "application/json").send_string(&body)
        .map_err(|_| "node enrollment failed or reply was lost; retry this same invitation and state directory")?;
    let grant: Grant = NodeCloudClient::decode(response)?;
    if grant.id != ticket.metadata.id
        || grant.workspace_id != ticket.metadata.workspace_id
        || grant.node_id != recipient.node_id
        || grant.certificate_sha256 != recipient.certificate_sha256
        || grant.credential_expires_at != ticket.metadata.credential_expires_at
        || grant.payload.len() > 64 * 1024
    {
        return Err("node enrollment grant does not match its authenticated metadata".into());
    }
    let plaintext = bundle_key(&secret)
        .decrypt(
            &ticket.metadata.workspace_id,
            &aad(&ticket.metadata),
            &grant.payload,
        )
        .map_err(|_| "node enrollment envelope failed authentication")?;
    let bundle: Bundle =
        serde_json::from_str(&plaintext).map_err(|_| "invalid encrypted enrollment bundle")?;
    if encode(&bundle.metadata)? != encode(&ticket.metadata)?
        || bundle.recipient_tls_name != recipient.tls_name
        || bundle.broker_tls_roots != ticket.broker_tls_roots
    {
        return Err("node enrollment trust context does not match its invitation".into());
    }
    if let Some(revocations) = &bundle.revocations {
        revocations.validate()?;
        if revocations.trust.workspace_id != ticket.metadata.workspace_id
            || revocations.trust.server_origin.trim_end_matches('/')
                != ticket.metadata.broker_url.trim_end_matches('/')
        {
            return Err("revocation_signer_untrusted".into());
        }
    }
    let key = WorkspaceKey::from_phrase(&bundle.workspace_key_phrase)
        .map_err(|_| "invalid encrypted workspace key")?;
    stage_workspace_key(&ticket.metadata.workspace_id, &key)?;
    let token_file = state_dir.join("node-token");
    persist_exact(&token_file, pending.machine_token.as_bytes())?;
    let mut root_paths = Vec::new();
    for (index, bytes) in roots.iter().enumerate() {
        let path = state_dir.join(format!("broker-root-{index}.der"));
        persist_exact(&path, bytes)?;
        root_paths.push(path);
    }
    let mut config = json!({"node_id":recipient.node_id,"workspace":ticket.metadata.workspace_id,"state_dir":state_dir,
        "certificate":state_dir.join("node-cert.der"),"private_key":state_dir.join("node-key.der"),"trust_anchors":[],"peers":[],
        "relay":{"url":ticket.metadata.broker_url,"token_file":token_file,"tls_roots":root_paths},"rpc_timeout_seconds":60});
    if !bundle.result_trust.is_null() && bundle.result_trust != json!({}) {
        config["result_trust"] = bundle.result_trust;
    }
    if let Some(revocations) = bundle.revocations {
        config["revocations"] = serde_json::to_value(revocations)?;
    }
    let encoded =
        toml::to_string_pretty(&config).map_err(|_| "cannot encode joined node configuration")?;
    persist_exact(&config_path, encoded.as_bytes())?;
    NodeConfig::load(&config_path).map_err(|_| "joined node configuration failed validation")?;
    // Leave the immutable pending claim until the completed receipt is durably published.
    let completed = CompletedJoin {
        id: grant.id,
        token_id: grant.token_id.clone(),
        config: config_path.clone(),
        ticket_sha256: ticket_hash,
        token_sha256: pending.claim.token_sha256,
        node_id: recipient.node_id.clone(),
        workspace_id: ticket.metadata.workspace_id.clone(),
        credential_expires_at: grant.credential_expires_at,
        workspace_key_id: key.key_id(),
    };
    persist_exact(&completed_path, &encode(&completed)?)?;
    retire(&receipt_path)?;
    Ok(
        json!({"config":config_path,"node_id":recipient.node_id,"workspace":ticket.metadata.workspace_id,"token_id":grant.token_id,"credential_expires_at":grant.credential_expires_at,
        "result_signing":{"workspace":ticket.metadata.workspace_id,"key_file":state_dir.join("result-signing.pk8"),"public_key":recipient.result_signing_public_key}}),
    )
}

pub fn revoke(config_path: &Path, id: &str) -> Result<Value> {
    if id.len() != 26
        || !id
            .bytes()
            .all(|byte| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&byte))
    {
        return Err("invalid invitation ID".into());
    }
    let config = NodeConfig::load(config_path)?;
    let client = NodeCloudClient::from_config(&config)?;
    let response = client
        .request("POST", &format!("/invitations/{id}/revoke"))
        .set("Content-Type", "application/json")
        .send_string("{}")
        .map_err(|_| "invitation revocation failed")?;
    let receipt: Receipt = NodeCloudClient::decode(response)?;
    if receipt.id != id || receipt.workspace_id != config.workspace {
        return Err("invitation revocation identity mismatch".into());
    }
    Ok(json!({"id":receipt.id,"revoked":true,"redeemed":receipt.redeemed}))
}

/// Owner-only lookup includes expired/revoked bindings so retirement can pin an exact
/// generation even after that node is no longer in the ordinary live directory.
pub fn binding(config_path: &Path, node_id: &str) -> Result<Value> {
    if !wire::valid_name(node_id) {
        return Err("invalid node identity".into());
    }
    let config = NodeConfig::load(config_path)?;
    let client = NodeCloudClient::from_config(&config)?;
    let response = client
        .request("GET", &format!("/{node_id}/binding"))
        .call()
        .map_err(|_| "owner node-binding lookup failed")?;
    let binding: Binding = NodeCloudClient::decode(response)?;
    if binding.node_id != node_id
        || !valid_guid(&binding.credential_id)
        || unhex(&binding.certificate_sha256).is_err()
    {
        return Err("node binding identity mismatch".into());
    }
    serde_json::to_value(binding).map_err(|_| "cannot encode node binding".into())
}

/// Expected credential and certificate make retirement retries safe after a replacement
/// generation takes the same name. This operation never mutates direct peer trust.
pub fn retire_node(
    config_path: &Path,
    node_id: &str,
    credential_id: &str,
    certificate_sha256: &str,
) -> Result<Value> {
    let credential_id = credential_id.to_ascii_lowercase();
    let certificate_sha256 = certificate_sha256.to_ascii_lowercase();
    if !wire::valid_name(node_id)
        || !valid_guid(&credential_id)
        || unhex(&certificate_sha256).is_err()
    {
        return Err("retirement requires the exact node credential ID and certificate pin".into());
    }
    let config = NodeConfig::load(config_path)?;
    let client = NodeCloudClient::from_config(&config)?;
    let body =
        json!({"credential_id":credential_id,"certificate_sha256":certificate_sha256}).to_string();
    let response=client.request("POST",&format!("/{node_id}/retire")).set("Content-Type","application/json").send_string(&body)
        .map_err(|_| "node retirement failed or reply was lost; retry the same credential ID and certificate pin")?;
    let retired: Retirement = NodeCloudClient::decode(response)?;
    if retired.node_id != node_id
        || retired.credential_id != credential_id
        || retired.certificate_sha256 != certificate_sha256
    {
        return Err("node retirement identity mismatch".into());
    }
    serde_json::to_value(retired).map_err(|_| "cannot encode node retirement receipt".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::Mutex,
    };
    static KEY_ENV: Mutex<()> = Mutex::new(());
    const WORKSPACE: &str = "123e4567-e89b-12d3-a456-426614174000";
    #[test]
    fn native_preparation_cannot_reserve_a_browser_identity() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let request = temp.path().join("request.json");
        assert!(
            prepare(
                "web_reserved".into(),
                "node.example".into(),
                &state,
                &request
            )
            .is_err()
        );
        assert!(!state.exists());
        assert!(!request.exists());
    }
    fn metadata() -> Metadata {
        Metadata {
            id: lockyard_cloud_client::ulid(),
            workspace_id: WORKSPACE.into(),
            node_id: "recipient".into(),
            certificate_sha256: "a".repeat(64),
            request_sha256: "c".repeat(64),
            issuer_sha256: "b".repeat(64),
            broker_url: "https://broker.example".into(),
            expires_at: now().unwrap() + 900,
            credential_expires_at: now().unwrap() + 86400,
        }
    }

    #[test]
    fn encrypted_enrollment_preserves_independent_revocation_pin() {
        use ring::signature::KeyPair;
        let metadata = metadata();
        let signer = signature::Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let public_key = hex(signer.public_key().as_ref());
        let key_id = sha(signer.public_key().as_ref());
        let revocations = json!({"required":true,"poll_seconds":30,"max_offline_seconds":600,
            "trust":{"workspace_id":WORKSPACE,"key_id":key_id,
                "public_key":public_key,"server_origin":"https://broker.example"}});
        let plaintext = json!({"metadata":metadata,"recipient_tls_name":"node.example",
            "workspace_key_phrase":WorkspaceKey::from_entropy([42;32]).phrase(),
            "broker_tls_roots":[],"result_trust":{},"revocations":revocations});
        let secret = [41; 32];
        let encrypted = bundle_key(&secret)
            .encrypt(WORKSPACE, &aad(&metadata), &plaintext.to_string())
            .unwrap();
        let decrypted = bundle_key(&secret)
            .decrypt(WORKSPACE, &aad(&metadata), &encrypted)
            .unwrap();
        let bundle: Bundle = serde_json::from_str(&decrypted)
            .expect("encrypted enrollment must accept pinned revocation trust");
        let restored = serde_json::to_value(bundle).unwrap();
        assert_eq!(restored["revocations"], revocations);
        assert_ne!(
            restored["revocations"]["trust"]["public_key"],
            restored["workspace_key_phrase"]
        );
    }

    #[test]
    fn claim_derivation_cannot_decrypt_bundle_and_all_enrollment_metadata_is_authenticated() {
        let secret = [41; 32];
        let metadata = metadata();
        let phrase = WorkspaceKey::from_entropy([42; 32]).phrase();
        let envelope = bundle_key(&secret)
            .encrypt(WORKSPACE, &aad(&metadata), &phrase)
            .unwrap();
        assert_eq!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&metadata), &envelope)
                .unwrap(),
            phrase
        );
        let proof = claim_proof(&secret);
        assert!(
            WorkspaceKey::from_entropy(unhex(&proof).unwrap())
                .decrypt(WORKSPACE, &aad(&metadata), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.node_id.push('x');
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.id = lockyard_cloud_client::ulid();
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.issuer_sha256 = "c".repeat(64);
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.request_sha256 = "d".repeat(64);
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.broker_url.push('x');
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.expires_at += 1;
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let mut changed = metadata.clone();
        changed.credential_expires_at += 1;
        assert!(
            bundle_key(&secret)
                .decrypt(WORKSPACE, &aad(&changed), &envelope)
                .is_err()
        );
        let ticket = Ticket {
            v: 1,
            metadata,
            secret: hex(&secret),
            broker_tls_roots: vec![],
        };
        let text = String::from_utf8(encode(&ticket).unwrap()).unwrap();
        assert!(!text.contains(&phrase));
        assert!(!text.contains(&envelope));
        assert!(!text.contains("payload"));
    }

    #[test]
    fn recipient_preparation_has_private_identity_and_contains_only_public_request_data() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let state = temp.path().join("recipient");
        let output = temp.path().join("request.json");
        prepare(
            "recipient".into(),
            "recipient.example".into(),
            &state,
            &output,
        )
        .unwrap();
        let public: JoinRequest = decode(&output).unwrap();
        validate_request(&public).unwrap();
        assert_eq!(public.node_id, "recipient");
        assert_eq!(
            fs::metadata(state.join("node-key.der"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let original = fs::read(state.join("node-key.der")).unwrap();
        assert!(
            prepare(
                "recipient".into(),
                "recipient.example".into(),
                &state,
                &output
            )
            .is_err()
        );
        assert_eq!(original, fs::read(state.join("node-key.der")).unwrap());
        assert!(
            !String::from_utf8(fs::read(output).unwrap())
                .unwrap()
                .contains("private_key")
        );
    }

    #[test]
    fn create_only_receipt_publication_is_atomic_between_competing_local_processes() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = temp.path().join("receipt");
        let winners = std::thread::scope(|scope| {
            (0..16)
                .map(|index| {
                    let path = path.clone();
                    scope.spawn(move || {
                        let body = vec![b'a' + index; 4096];
                        persist(&path, &body).unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(winners, 1);
        let body = private(&path, 4096).unwrap();
        assert_eq!(body.len(), 4096);
        assert!(body.iter().all(|byte| *byte == body[0]));
        let link = temp.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(private(&link, 4096).is_err());
    }

    #[test]
    fn receipt_publication_rejects_writable_output_parents_before_creating_files() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        for mode in [0o720, 0o702, 0o777] {
            let parent = temp.path().join(format!("parent-{mode:o}"));
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
            let receipt = parent.join("receipt");
            assert!(
                persist(&receipt, b"private enrollment receipt")
                    .unwrap_err()
                    .to_string()
                    .contains("not writable by others"),
                "unsafe parent mode {mode:o} was not rejected"
            );
            assert!(!receipt.exists());
            assert_eq!(
                fs::read_dir(&parent).unwrap().count(),
                0,
                "unsafe parent mode {mode:o} received a partial file"
            );
        }
    }

    #[test]
    fn malformed_invitation_ids_cannot_escape_the_private_state_directory() {
        let mut metadata = metadata();
        metadata.id = "x/../../../../bad-path-xxxx".into();
        assert!(validate_metadata(&metadata).is_err());
        metadata.id = lockyard_cloud_client::ulid();
        metadata.workspace_id = "../another".into();
        assert!(validate_metadata(&metadata).is_err());
    }

    #[test]
    fn an_expired_ticket_or_wrong_recipient_never_creates_a_claim_or_workspace_key() {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let state = temp.path().join("recipient");
        let request_path = temp.path().join("request");
        prepare(
            "recipient".into(),
            "recipient.example".into(),
            &state,
            &request_path,
        )
        .unwrap();
        let request: JoinRequest = decode(&request_path).unwrap();
        let mut metadata = metadata();
        metadata.certificate_sha256 = request.certificate_sha256.clone();
        metadata.request_sha256 = sha(&serde_json::to_vec(&request).unwrap());
        metadata.expires_at = now().unwrap() - 1;
        let ticket = Ticket {
            v: 1,
            metadata: metadata.clone(),
            secret: hex(&[43; 32]),
            broker_tls_roots: vec![],
        };
        let ticket_path = temp.path().join("ticket");
        persist_exact(&ticket_path, &encode(&ticket).unwrap()).unwrap();
        assert!(
            join(&ticket_path, &state, &temp.path().join("node.toml"))
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert!(
            !state
                .join(format!("join-{}.pending.json", metadata.id))
                .exists()
        );
        assert!(!temp.path().join("node.toml").exists());
    }

    #[test]
    fn staged_workspace_key_is_private_create_only_and_cannot_follow_a_symlink() {
        let _lock = KEY_ENV.lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        unsafe { std::env::set_var("XDG_CONFIG_HOME", temp.path()) };
        let key = WorkspaceKey::from_entropy([44; 32]);
        stage_workspace_key(WORKSPACE, &key).unwrap();
        stage_workspace_key(WORKSPACE, &key).unwrap();
        let destination = temp.path().join(format!("lockyard/keys/{WORKSPACE}.key"));
        let original = fs::read(&destination).unwrap();
        assert!(stage_workspace_key(WORKSPACE, &WorkspaceKey::from_entropy([45; 32])).is_err());
        assert_eq!(original, fs::read(&destination).unwrap());
        fs::remove_file(&destination).unwrap();
        let other = temp.path().join("other");
        fs::write(&other, [44; 32]).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&other, &destination).unwrap();
        assert!(stage_workspace_key(WORKSPACE, &key).is_err());
        unsafe {
            match previous {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        };
    }
}
