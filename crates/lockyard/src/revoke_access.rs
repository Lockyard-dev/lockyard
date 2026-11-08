// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! One durable owner action, shared by CLI and both MCP surfaces.
use lockyard_cloud_client::{
    Client,
    revocations::{RevocationError, RevocationReceipt, RevocationTarget, RevocationTrust, hex},
};
use lockyard_core::{Error, Result, config::Config, paths::find_root};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

#[derive(clap::Subcommand)]
pub(crate) enum RevokeCommand {
    Token {
        token_id: String,
        #[arg(long)]
        node_config: Option<PathBuf>,
    },
    Identity {
        node_id: String,
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        certificate_sha256: String,
        #[arg(long)]
        node_config: Option<PathBuf>,
    },
    CertPin {
        certificate_sha256: String,
        #[arg(long)]
        node_config: Option<PathBuf>,
    },
    SsoSession {
        token_id: String,
        #[arg(long)]
        node_config: Option<PathBuf>,
    },
}
impl RevokeCommand {
    pub(crate) fn parts(self) -> (RevocationTarget, Option<PathBuf>) {
        match self {
            Self::Token {
                token_id,
                node_config,
            } => (RevocationTarget::Token { token_id }, node_config),
            Self::Identity {
                node_id,
                credential_id,
                certificate_sha256,
                node_config,
            } => (
                RevocationTarget::Machine {
                    node_id,
                    credential_id,
                    certificate_sha256,
                },
                node_config,
            ),
            Self::CertPin {
                certificate_sha256,
                node_config,
            } => (
                RevocationTarget::CertPin { certificate_sha256 },
                node_config,
            ),
            Self::SsoSession {
                token_id,
                node_config,
            } => (RevocationTarget::SsoSession { token_id }, node_config),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    protocol: u8,
    path: String,
    origin: String,
    workspace_id: String,
    key: String,
    body: String,
    created_at_ms: i64,
    /// Persisted before handing bytes to HTTP. A crash preserves an uncertain write.
    attempted: bool,
    receipt: Option<RevocationReceipt>,
}
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Direct {
    pub(crate) acked: Vec<String>,
    pub(crate) pending: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub(crate) struct Outcome {
    pub(crate) epoch: Option<u64>,
    pub(crate) cloud_committed: Option<bool>,
    pub(crate) local_applied: bool,
    pub(crate) direct: Direct,
    pub(crate) propagation_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hint: Option<String>,
}
impl Outcome {
    pub(crate) fn exit(&self) -> u8 {
        if self.cloud_committed != Some(true) {
            1
        } else if !self.propagation_complete {
            2
        } else {
            0
        }
    }
}
fn failed(code: &str, committed: Option<bool>, epoch: Option<u64>, peers: Vec<String>) -> Outcome {
    Outcome {
        epoch,
        cloud_committed: committed,
        local_applied: false,
        direct: Direct {
            acked: vec![],
            pending: peers,
        },
        propagation_complete: false,
        code: Some(code.into()),
        hint: (code == "revocation_signer_untrusted").then(|| {
            "Configure signer trust with lockyard node revocation-trust --config <node-config> --output <trusted-node-config>, then pass --node-config <trusted-node-config> to revoke (node_config in MCP).".into()
        }),
    }
}
fn client_error(e: RevocationError, prior_unknown: bool, peers: Vec<String>) -> Outcome {
    let unknown = prior_unknown || e.commit_unknown;
    failed(
        if unknown {
            "revocation_commit_unknown"
        } else {
            e.code()
        },
        if unknown { None } else { Some(false) },
        None,
        peers,
    )
}
pub(crate) fn execute(
    cwd: &Path,
    target: RevocationTarget,
    node_config: Option<PathBuf>,
) -> Result<Outcome> {
    if let Err(e) = target.validate() {
        return Ok(failed(e.code(), Some(false), None, vec![]));
    }
    let root = find_root(cwd).ok_or_else(|| Error::Invalid("not a Lockyard project".into()))?;
    let config = Config::load(&root)?;
    let (url, _workspace) = crate::open::endpoint(&config)?;
    let url = lockyard_cloud_client::revocations::canonical_origin(&url)
        .map_err(|e| Error::Invalid(e.to_string()))?;
    let (node_trust, peers) = node_context(node_config.as_deref())?;
    // An explicitly selected node must have its own provisioned pin. A legacy node configuration
    // cannot inherit project-local trust or fail later while building its revocation HTTP agent.
    if node_config.is_some() && node_trust.is_none() {
        return Ok(failed(
            "revocation_signer_untrusted",
            Some(false),
            None,
            peers,
        ));
    }
    let directory = root.join(".lockyard/private-revocations");
    let trust_path = directory.join(format!("trust-{}.json", digest(url.as_bytes())));
    let trust = if let Some(trust) = node_trust {
        trust
    } else if trust_path.exists() {
        match read_private_json::<RevocationTrust>(&trust_path) {
            Ok(trust) => trust,
            Err(_) => {
                return Ok(failed(
                    "revocation_signer_untrusted",
                    Some(false),
                    None,
                    peers,
                ));
            }
        }
    } else {
        return Ok(failed(
            "revocation_signer_untrusted",
            Some(false),
            None,
            peers,
        ));
    };
    if trust.validate().is_err() || trust.server_origin != url {
        return Ok(failed(
            "revocation_signer_untrusted",
            Some(false),
            None,
            peers,
        ));
    }
    private_directory(&directory)?;
    let mut client = crate::open::direct_client(&url)?;
    if let Some(path) = node_config.as_deref() {
        let node = lockyard_node::host::NodeConfig::load(path)
            .map_err(|_| Error::Invalid("invalid node configuration".into()))?;
        let agent = match lockyard_node::cloud::NodeCloudClient::revocation_http_agent(&node) {
            Ok(agent) => agent,
            Err(error) => {
                let code = if error.to_string() == "revocation_signer_untrusted" {
                    "revocation_signer_untrusted"
                } else {
                    "revocation_state_unavailable"
                };
                return Ok(failed(code, Some(false), None, peers));
            }
        };
        client = client.with_revocation_agent(agent);
    }
    let session = client.service_session("lockyard-revoke");
    let body = serde_json::to_string(&json!({"target":target,"reason_code":"owner_request"}))
        .map_err(|_| Error::Invalid("invalid_revocation_request".into()))?;
    let identity =
        digest(format!("{}\n{}\n{body}", trust.server_origin, trust.workspace_id).as_bytes());
    let _lock = operation_lock(&directory.join(format!("{identity}.lock")))?;
    let pending_path = directory.join(format!("{identity}.json"));
    let mut pending = if pending_path.exists() {
        read_private_json::<Pending>(&pending_path)?
    } else {
        Pending {
            version: 1,
            protocol: 1,
            path: "/api/v1/revocations".into(),
            origin: trust.server_origin.clone(),
            workspace_id: trust.workspace_id.clone(),
            key: lockyard_cloud_client::ulid(),
            body: body.clone(),
            created_at_ms: crate::now_ms(),
            attempted: false,
            receipt: None,
        }
    };
    if pending.version != 1
        || pending.protocol != 1
        || pending.path != "/api/v1/revocations"
        || pending.origin != trust.server_origin
        || pending.workspace_id != trust.workspace_id
        || pending.body != body
    {
        return Ok(failed("idempotency_conflict", None, None, peers));
    }
    if pending.receipt.is_none() {
        // A process restart cannot prove an endpoint ledger retention window. Preserve the operation
        // for reconciliation, rather than turn an old uncertain operation into a new write.
        if pending.attempted {
            return Ok(failed("revocation_commit_unknown", None, None, peers));
        }
        pending.attempted = true;
        save(&pending_path, &pending)?;
        match post_once_with_retry(&client, &session, &target, &pending.key, &trust) {
            Ok(receipt) => {
                let epoch = receipt.epoch;
                pending.receipt = Some(receipt);
                if save(&pending_path, &pending).is_err() {
                    return Ok(failed(
                        "revocation_state_unavailable",
                        Some(true),
                        Some(epoch),
                        peers,
                    ));
                }
            }
            Err(e) => {
                if !e.commit_unknown {
                    pending.attempted = false;
                    // The HTTP outcome remains definite even if clearing the local attempt marker
                    // fails. The old marker remains conservative for the next process.
                    let _ = save(&pending_path, &pending);
                }
                return Ok(client_error(e, false, peers));
            }
        }
    }
    let receipt = pending
        .receipt
        .as_ref()
        .expect("receipt after successful POST");
    // Stored receipts remain independently verified on every resume, including signer re-provisioning.
    if lockyard_cloud_client::revocations::verify_receipt(receipt, &target, &trust, &url).is_err() {
        return Ok(failed(
            "revocation_signer_untrusted",
            Some(true),
            Some(receipt.epoch),
            peers,
        ));
    }
    let documents = match client.revocation_refresh_documents(
        &session,
        receipt.epoch.saturating_sub(1),
        &trust,
    ) {
        Ok(docs) => docs,
        Err(e) => return Ok(failed(e.code(), Some(true), Some(receipt.epoch), peers)),
    };
    let mut includes_target = false;
    for document in &documents {
        let page = match lockyard_cloud_client::revocations::verify_document(document, &trust, &url)
        {
            Ok(page) => page,
            Err(_) => {
                return Ok(failed(
                    "protocol_response_invalid",
                    Some(true),
                    Some(receipt.epoch),
                    peers,
                ));
            }
        };
        if page.epoch < receipt.epoch {
            return Ok(failed(
                "protocol_response_invalid",
                Some(true),
                Some(receipt.epoch),
                peers,
            ));
        }
        includes_target |= page
            .entries
            .iter()
            .any(|entry| entry.epoch == receipt.epoch && entry.target == target);
    }
    if !includes_target {
        return Ok(failed(
            "protocol_response_invalid",
            Some(true),
            Some(receipt.epoch),
            peers,
        ));
    }
    let Some(path) = node_config else {
        return Ok(failed(
            "revocation_state_unavailable",
            Some(true),
            Some(receipt.epoch),
            peers,
        ));
    };
    let applied = apply_local(&path, documents);
    match applied {
        Ok(value) => {
            let local_applied = value
                .get("local_applied")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let direct: Direct =
                serde_json::from_value(value.get("direct").cloned().unwrap_or(Value::Null))
                    .unwrap_or(Direct {
                        acked: vec![],
                        pending: peers.clone(),
                    });
            let propagation_complete = local_applied && direct.pending.is_empty();
            Ok(Outcome {
                epoch: Some(receipt.epoch),
                cloud_committed: Some(true),
                local_applied,
                direct,
                propagation_complete,
                code: None,
                hint: None,
            })
        }
        Err(_) => Ok(failed(
            "revocation_state_unavailable",
            Some(true),
            Some(receipt.epoch),
            peers,
        )),
    }
}
fn post_once_with_retry(
    client: &Client,
    session: &str,
    target: &RevocationTarget,
    key: &str,
    trust: &RevocationTrust,
) -> std::result::Result<RevocationReceipt, RevocationError> {
    match client.revocation_post(session, target, key, trust) {
        Err(first) if first.commit_unknown => {
            // Immediate recovery of this ongoing request uses identical target, serialization and key.
            // If the bearer revoked itself, the retry's 401 still cannot prove the first outcome.
            client
                .revocation_post(session, target, key, trust)
                .map_err(|mut next| {
                    next.commit_unknown = true;
                    next
                })
        }
        result => result,
    }
}
fn digest(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}
fn node_context(path: Option<&Path>) -> Result<(Option<RevocationTrust>, Vec<String>)> {
    match path {
        None => Ok((None, vec![])),
        Some(path) => {
            let config = lockyard_node::host::NodeConfig::load(path)
                .map_err(|_| Error::Invalid("invalid node configuration".into()))?;
            Ok((
                config.revocations.as_ref().map(|r| r.trust.clone()),
                config.peers.iter().map(|p| p.node_id.clone()).collect(),
            ))
        }
    }
}

fn apply_local(
    path: &Path,
    docs: Vec<lockyard_cloud_client::revocations::SignedDocument>,
) -> Result<Value> {
    tokio::runtime::Runtime::new()?
        .block_on(lockyard_node::host::local_revocations(path, docs))
        .map_err(|_| Error::Invalid("revocation_state_unavailable".into()))
}

#[cfg(unix)]
fn private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(Error::Invalid(
            "revocation state directory must be private".into(),
        ));
    }
    Ok(())
}
#[cfg(unix)]
fn operation_lock(path: &Path) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&f),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
    {
        return Err(Error::Invalid(
            "revocation operation is locked or state is unsafe".into(),
        ));
    }
    Ok(f)
}
#[cfg(unix)]
fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > 1_048_576
    {
        return Err(Error::Invalid("unsafe revocation state".into()));
    }
    let mut bytes = Vec::new();
    f.take(1_048_577).read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("invalid revocation state".into()))
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| Error::Invalid("invalid revocation state".into()))?;
    lockyard_core::fsio::replace(path, &bytes, 0o600)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeArguments {
    target: RevocationTarget,
    node_config: Option<PathBuf>,
}
pub(crate) fn mcp(cwd: &Path, args: &Value) -> Value {
    let outcome = match serde_json::from_value::<RevokeArguments>(args.clone()) {
        Ok(args) => execute(cwd, args.target, args.node_config)
            .unwrap_or_else(|_| failed("revocation_commit_unknown", None, None, vec![])),
        Err(_) => failed("invalid_revocation_request", Some(false), None, vec![]),
    };
    let failed = outcome.exit() != 0;
    let value = serde_json::to_value(outcome)
        .unwrap_or_else(|_| json!({"code":"protocol_response_invalid"}));
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":failed})
}

#[cfg(windows)]
fn private_directory(path: &Path) -> Result<()> {
    Ok(lockyard_core::windows::private_dir(path)?)
}

#[cfg(windows)]
fn operation_lock(path: &Path) -> Result<File> {
    let file = lockyard_core::windows::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    file.try_lock()
        .map_err(|_| Error::Invalid("revocation operation already running".into()))?;
    Ok(file)
}

#[cfg(windows)]
fn read_private_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = lockyard_core::windows::read_private(path, 1_048_576)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Invalid("invalid revocation state".into()))
}

#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(unix)]
use std::{fs, io::Read};
