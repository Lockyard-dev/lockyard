// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Credential-bound enrollment and directory lookups. Application content never enters this API.
use crate::{Result, host::NodeConfig, quic::PeerPin, wire::valid_name};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path, sync::Arc, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeDirectoryEntry {
    pub node_id: String,
    pub certificate_sha256: String,
    pub quic_endpoint: Option<String>,
    pub registered_at: String,
    pub last_seen_at: String,
    #[serde(default)]
    pub identity_proof: Option<String>,
    #[serde(default)]
    pub controller_only: bool,
}

#[derive(Serialize)]
struct Registration<'a> {
    node_id: &'a str,
    certificate_sha256: String,
    quic_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_proof: Option<&'a str>,
}

/// Neither Debug nor errors expose the credential, response body or configured URL.
#[derive(Clone)]
pub struct NodeCloudClient {
    base: url::Url,
    node_id: String,
    token: Option<String>,
    agent: Arc<ureq::Agent>,
    operations: Arc<tokio::sync::Semaphore>,
    identity_proof: Option<String>,
}

impl NodeCloudClient {
    pub fn new(base: &str, node_id: String, token: String, roots: &[Vec<u8>]) -> Result<Self> {
        if token.is_empty()
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err("invalid node identity or credential".into());
        }
        Self::build(base, node_id, Some(token), roots)
    }

    /// Anonymous bootstrap retains exactly the normal verified TLS and no-redirect policy.
    pub(crate) fn anonymous(base: &str, node_id: String, roots: &[Vec<u8>]) -> Result<Self> {
        Self::build(base, node_id, None, roots)
    }

    fn build(
        base: &str,
        node_id: String,
        token: Option<String>,
        roots: &[Vec<u8>],
    ) -> Result<Self> {
        let mut base = url::Url::parse(base).map_err(|_| "invalid node broker URL")?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err("node broker URL cannot include credentials, query or fragment".into());
        }
        match base.scheme() {
            "https" => {}
            "wss" => {
                base.set_scheme("https").map_err(|_| "invalid broker URL")?;
            }
            _ => return Err("node enrollment and directory require HTTPS".into()),
        }
        if !valid_name(&node_id) {
            return Err("invalid node identity or credential".into());
        }
        let tls = crate::relay::tls(roots)?;
        let agent = ureq::AgentBuilder::new()
            .resolver(|netloc: &str| {
                crate::bounded_dns::resolve(
                    netloc,
                    std::time::Instant::now() + Duration::from_secs(10),
                )
            })
            .try_proxy_from_env(!crate::relay::bypass_proxy(&base))
            .redirects(0)
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(15))
            .timeout_write(Duration::from_secs(15))
            .timeout(Duration::from_secs(30))
            .tls_config(tls)
            .build();
        Ok(Self {
            base,
            node_id,
            token,
            agent: Arc::new(agent),
            operations: Arc::new(tokio::sync::Semaphore::new(2)),
            identity_proof: None,
        })
    }

    pub fn from_config(config: &NodeConfig) -> Result<Self> {
        let relay = config
            .relay
            .as_ref()
            .ok_or("node relay is not configured")?;
        let bytes = private_file(&relay.token_file, 4096)?;
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| "invalid node credential file")?
            .trim()
            .to_owned();
        let roots = relay
            .tls_roots
            .iter()
            .map(|p| crate::local_files::read_public(p, 64 * 1024))
            .collect::<Result<Vec<_>>>()?;
        let mut client = Self::new(&relay.url, config.node_id.clone(), token, &roots)?;
        if let Some(key) =
            lockyard_cloud_client::WorkspaceKey::load_for_workspace(&config.workspace)?
        {
            let certificate = crate::local_files::read_public(&config.certificate, 64 * 1024)?;
            client.identity_proof = Some(crate::incarnation::seal_identity(
                &config.workspace,
                &config.node_id,
                &PeerPin::certificate(&certificate).to_hex(),
                &key,
            )?);
        }
        Ok(client)
    }

    /// Keep the node's independently configured TLS roots, resolver and redirect policy.
    pub fn revocation_client(&self) -> Result<lockyard_cloud_client::Client> {
        let token = self.token.clone().ok_or("unauthorized")?;
        Ok(
            lockyard_cloud_client::Client::new(&self.broker_url(), token)?
                .with_revocation_agent(self.agent.as_ref().clone()),
        )
    }

    /// Reuse configured TLS policy with a separately selected live owner credential.
    pub fn revocation_http_agent(config: &NodeConfig) -> Result<ureq::Agent> {
        let settings = config
            .revocations
            .as_ref()
            .ok_or("revocation_signer_untrusted")?;
        settings.validate()?;
        let paths = if let Some(relay) = &config.relay {
            let mut origin = url::Url::parse(&relay.url)?;
            if origin.scheme() == "wss" {
                origin
                    .set_scheme("https")
                    .map_err(|_| "revocation_signer_untrusted")?;
            }
            if origin.as_str().trim_end_matches('/') != settings.trust.server_origin {
                return Err("revocation_signer_untrusted".into());
            }
            relay.tls_roots.clone()
        } else {
            (0..8)
                .map(|index| config.state_dir.join(format!("broker-root-{index}.der")))
                .filter(|path| path.exists())
                .collect()
        };
        let roots = paths
            .iter()
            .map(|path| crate::local_files::read_public(path, 64 * 1024))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::anonymous(
            &settings.trust.server_origin,
            config.node_id.clone(),
            &roots,
        )?
        .agent
        .as_ref()
        .clone())
    }

    /// Explicit owner provisioning over authenticated HTTPS; received lists never select this key.
    pub fn bootstrap_revocation_trust(
        &self,
        workspace_id: &str,
    ) -> Result<lockyard_cloud_client::revocations::RevocationTrust> {
        let trust = self.revocation_client()?.revocation_key(&self.node_id)?;
        if trust.workspace_id != workspace_id {
            return Err("revocation_signer_untrusted".into());
        }
        Ok(trust)
    }

    /// Refresh direct-only nodes as well: enrollment retains the cloud credential and roots
    /// independently of whether the relay transport is enabled.
    pub fn for_revocations(config: &NodeConfig) -> Result<Self> {
        let revocations = config
            .revocations
            .as_ref()
            .ok_or("revocation_signer_untrusted")?;
        revocations.validate()?;
        let (token_file, root_files) = if let Some(relay) = &config.relay {
            let mut origin = url::Url::parse(&relay.url)?;
            if origin.scheme() == "wss" {
                origin
                    .set_scheme("https")
                    .map_err(|_| "revocation_signer_untrusted")?;
            }
            if origin.as_str().trim_end_matches('/') != revocations.trust.server_origin {
                return Err("revocation_signer_untrusted".into());
            }
            (relay.token_file.clone(), relay.tls_roots.clone())
        } else {
            let roots = (0..8)
                .map(|index| config.state_dir.join(format!("broker-root-{index}.der")))
                .filter(|path| path.exists())
                .collect();
            (config.state_dir.join("node-token"), roots)
        };
        let bytes = private_file(&token_file, 4096)?;
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| "unauthorized")?
            .trim()
            .to_owned();
        let roots = root_files
            .iter()
            .map(|path| crate::local_files::read_public(path, 64 * 1024))
            .collect::<Result<Vec<_>>>()?;
        Self::new(
            &revocations.trust.server_origin,
            config.node_id.clone(),
            token,
            &roots,
        )
    }

    pub(crate) fn with_identity_proof(mut self, proof: String) -> Result<Self> {
        if proof.len() > 8192 || !crate::wire::valid_ciphertext(&proof) {
            return Err("invalid node registration identity proof".into());
        }
        self.identity_proof = Some(proof);
        Ok(self)
    }

    fn endpoint(&self, suffix: &str) -> String {
        let mut url = self.base.clone();
        url.set_path(&format!(
            "{}/api/v1/nodes{suffix}",
            self.base.path().trim_end_matches('/')
        ));
        url.into()
    }

    pub(crate) fn decode<T: for<'de> Deserialize<'de>>(response: ureq::Response) -> Result<T> {
        if response.status() != 200 {
            return Err("node broker returned an unexpected status".into());
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read node broker response")?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err("node broker response exceeds limit".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid node broker response".into())
    }

    pub(crate) fn request(&self, method: &str, suffix: &str) -> ureq::Request {
        let request = self
            .agent
            .request(method, &self.endpoint(suffix))
            .set("X-Lockyard-Session", &self.node_id)
            .set("Accept", "application/json");
        match &self.token {
            Some(token) => request.set("Authorization", &format!("Bearer {token}")),
            None => request,
        }
    }

    pub(crate) fn credential_hash(&self) -> Result<String> {
        let token = self.token.as_ref().ok_or("node credential unavailable")?;
        Ok(
            ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }

    pub(crate) fn broker_url(&self) -> String {
        self.base.as_str().trim_end_matches('/').to_string()
    }

    /// Reports only a locally verified terminal result's opaque ID and state.
    pub(crate) async fn report_job_outcome(
        &self,
        job_id: String,
        state: crate::wire::JobState,
        certificate_sha256: String,
    ) -> Result<()> {
        if !crate::wire::valid_ulid(&job_id)
            || !state.is_terminal()
            || certificate_sha256.len() != 64
            || !certificate_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid job notification metadata".into());
        }
        let permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| "node directory request capacity reached")?;
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let body = serde_json::json!({"job_id": job_id, "state": state, "certificate_sha256": certificate_sha256});
            let response = client.request("POST", "/job-outcomes").set("Content-Type", "application/json")
                .send_json(body).map_err(|_| "job metadata notification failed")?;
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Receipt { accepted: bool }
            let receipt: Receipt = Self::decode(response)?;
            if !receipt.accepted { return Err("job metadata notification not accepted".into()); }
            Ok(())
        }).await.map_err(|_| "job metadata notification task failed")?
    }

    pub async fn register(
        &self,
        certificate: Vec<u8>,
        endpoint: Option<String>,
    ) -> Result<NodeDirectoryEntry> {
        if certificate.is_empty() || certificate.len() > 64 * 1024 {
            return Err("invalid node certificate".into());
        }
        let permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| "node directory request capacity reached")?;
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let registration = Registration {
                node_id: &client.node_id,
                certificate_sha256: PeerPin::certificate(&certificate).to_hex(),
                quic_endpoint: endpoint,
                identity_proof: client.identity_proof.as_deref(),
            };
            let body = serde_json::to_string(&registration)
                .map_err(|_| "cannot encode node registration")?;
            let response = client
                .request("POST", "/register")
                .set("Content-Type", "application/json")
                .send_string(&body)
                .map_err(
                    |_| "node registration failed; check credential, ownership and connectivity",
                )?;
            let entry: NodeDirectoryEntry = Self::decode(response)?;
            if entry.node_id != client.node_id
                || entry.certificate_sha256.to_ascii_lowercase() != registration.certificate_sha256
            {
                return Err("node broker registration identity mismatch".into());
            }
            Ok(entry)
        })
        .await
        .map_err(|_| "node registration task failed")?
    }

    pub async fn directory(&self) -> Result<Vec<NodeDirectoryEntry>> {
        let permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| "node directory request capacity reached")?;
        let client = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let response = client
                .request("GET", "")
                .call()
                .map_err(|_| "node directory unavailable; check credential and connectivity")?;
            let entries: Vec<NodeDirectoryEntry> = Self::decode(response)?;
            if entries.len() > 4096
                || entries.iter().any(|entry| {
                    !valid_name(&entry.node_id)
                        || PeerPin::from_hex(&entry.certificate_sha256).is_err()
                })
            {
                return Err("invalid node directory".into());
            }
            Ok(entries)
        })
        .await
        .map_err(|_| "node directory task failed")?
    }
}

fn private_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open private node credential file")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err("node credential file must be private and bounded".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read node credential")?;
    if bytes.len() as u64 > limit {
        return Err("node credential file exceeds limit".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_blocking_requests_cannot_bypass_directory_capacity() {
        let client = NodeCloudClient::new(
            "https://example.test",
            "worker".into(),
            "synthetic".into(),
            &[],
        )
        .unwrap();
        let _first = client.operations.clone().try_acquire_owned().unwrap();
        let _second = client.operations.clone().try_acquire_owned().unwrap();
        assert_eq!(
            client.directory().await.err().unwrap().to_string(),
            "node directory request capacity reached"
        );
    }
    #[test]
    fn enrollment_credentials_reject_hardlinks_and_fifos_without_blocking() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("token");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .unwrap();
        fs::hard_link(&source, root.path().join("alias")).unwrap();
        assert!(private_file(&source, 4096).is_err());
        let fifo = root.path().join("fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(private_file(&fifo, 4096).is_err());
        });
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn broker_urls_and_credentials_are_not_silently_downgraded_or_forwarded() {
        for url in [
            "http://localhost",
            "ws://localhost",
            "https://name:secret@example.test",
            "https://example.test/?token=secret",
        ] {
            assert!(NodeCloudClient::new(url, "worker".into(), "synthetic".into(), &[]).is_err());
        }
        assert!(
            NodeCloudClient::new(
                "https://example.test",
                "bad/name".into(),
                "synthetic".into(),
                &[]
            )
            .is_err()
        );
        assert!(
            NodeCloudClient::new(
                "https://example.test",
                "worker".into(),
                "bad\nvalue".into(),
                &[]
            )
            .is_err()
        );
    }
}
