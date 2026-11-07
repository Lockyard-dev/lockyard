// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Persistent direct QUIC transport. TLS trust and registered peer pins are both mandatory.
use futures_util::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    Result,
    wire::{FrameKind, MAX_FRAME_BYTES, Operation, RpcFrame, valid_name},
};
use serde::{Deserialize, Serialize};
#[path = "quic/revocation_tls.rs"]
mod revocation_tls;
use crate::revocations::RevocationManager;
pub const ALPN: &[u8] = b"lockyard-node/1";

pub struct Identity {
    pub certificates: Vec<CertificateDer<'static>>,
    pub private_key: PrivatePkcs8KeyDer<'static>,
}
fn transport() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.keep_alive_interval(Some(Duration::from_secs(15)));
    config.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    config.max_concurrent_bidi_streams(16u32.into());
    config.max_concurrent_uni_streams(0u32.into());
    config.stream_receive_window((1024u32 * 1024).into());
    config.receive_window((8u32 * 1024 * 1024).into());
    config.send_window(8 * 1024 * 1024);
    Arc::new(config)
}
fn roots(certificates: Vec<CertificateDer<'static>>) -> Result<rustls::RootCertStore> {
    if certificates.is_empty() {
        return Err("direct trust anchors are required".into());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    Ok(roots)
}
fn server(
    bind: SocketAddr,
    identity: Identity,
    roots: rustls::RootCertStore,
    revocations: Option<Arc<RevocationManager>>,
) -> Result<Endpoint> {
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_client_cert_verifier(Arc::new(revocation_tls::ClientVerifier {
        inner: verifier,
        state: revocations,
        local_pin: PeerPin::certificate(
            identity
                .certificates
                .first()
                .ok_or("node certificate missing")?
                .as_ref(),
        )
        .to_hex(),
    }))
    .with_single_cert(identity.certificates, identity.private_key.into())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    config
        .max_incoming(128)
        .incoming_buffer_size(64 * 1024)
        .incoming_buffer_size_total(8 * 1024 * 1024);
    Ok(Endpoint::server(config, bind)?)
}
fn client(
    bind: SocketAddr,
    identity: Identity,
    roots: rustls::RootCertStore,
    revocations: Option<Arc<RevocationManager>>,
) -> Result<Endpoint> {
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()?;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(revocation_tls::ServerVerifier {
        inner: verifier,
        state: revocations,
        local_pin: PeerPin::certificate(
            identity
                .certificates
                .first()
                .ok_or("node certificate missing")?
                .as_ref(),
        )
        .to_hex(),
    }))
    .with_client_auth_cert(identity.certificates, identity.private_key.into())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}
/// An authenticated peer close is an error signal, not trusted revocation evidence.
/// Keep every other QUIC/stream error intact, including application close reasons
/// that merely contain the word "revoked".
fn transport_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> Box<dyn std::error::Error + Send + Sync> {
    let error: Box<dyn std::error::Error + Send + Sync> = Box::new(error);
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
    while let Some(current) = cause {
        if matches!(current.downcast_ref::<quinn::ConnectionError>(),Some(quinn::ConnectionError::ApplicationClosed(close)) if close.error_code==quinn::VarInt::from_u32(0x105))
        {
            return "revoked".into();
        }
        cause = current.source();
    }
    error
}
struct Stream {
    send: SendStream,
    recv: RecvStream,
}
impl Stream {
    pub async fn write(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err("node frame is too large".into());
        }
        self.send
            .write_all(&(frame.len() as u32).to_be_bytes())
            .await
            .map_err(transport_error)?;
        self.send.write_all(frame).await.map_err(transport_error)?;
        Ok(())
    }
    pub async fn read(&mut self) -> Result<Vec<u8>> {
        let mut size = [0; 4];
        self.recv
            .read_exact(&mut size)
            .await
            .map_err(transport_error)?;
        let size = u32::from_be_bytes(size) as usize;
        if size > MAX_FRAME_BYTES {
            return Err("node frame is too large".into());
        }
        let mut frame = vec![0; size];
        self.recv
            .read_exact(&mut frame)
            .await
            .map_err(transport_error)?;
        Ok(frame)
    }
}
async fn open(connection: &Connection) -> Result<Stream> {
    let (send, recv) = connection.open_bi().await.map_err(transport_error)?;
    Ok(Stream { send, recv })
}
async fn accept(connection: &Connection) -> Result<Stream> {
    let (send, recv) = connection.accept_bi().await.map_err(transport_error)?;
    Ok(Stream { send, recv })
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerPin(pub [u8; 32]);
impl PeerPin {
    pub fn certificate(certificate: &[u8]) -> Self {
        let d = ring::digest::digest(&ring::digest::SHA256, certificate);
        let mut bytes = [0; 32];
        bytes.copy_from_slice(d.as_ref());
        Self(bytes)
    }
}
fn check_pin(connection: Connection, pins: &[PeerPin]) -> Result<Connection> {
    let trusted = connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .and_then(|chain| {
            chain
                .first()
                .map(|cert| PeerPin::certificate(cert.as_ref()))
        })
        .is_some_and(|pin| pins.contains(&pin));
    if !trusted {
        connection.close(1u32.into(), b"peer identity not registered");
        return Err("peer identity not registered".into());
    }
    Ok(connection)
}
async fn connect(
    endpoint: &Endpoint,
    address: SocketAddr,
    name: &str,
    pin: PeerPin,
) -> Result<Connection> {
    let connection =
        tokio::time::timeout(Duration::from_secs(10), endpoint.connect(address, name)?)
            .await?
            .map_err(transport_error)?;
    check_pin(connection, &[pin])
}
impl Identity {
    pub fn from_der(certificates: Vec<Vec<u8>>, private_key: Vec<u8>) -> Result<Self> {
        if certificates.is_empty() || private_key.is_empty() {
            return Err("certificate and PKCS8 private key are required".into());
        }
        Ok(Self {
            certificates: certificates.into_iter().map(CertificateDer::from).collect(),
            private_key: PrivatePkcs8KeyDer::from(private_key),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub certificate_sha256: String,
}

/// Generates a persistent identity once. Trust distribution remains an authenticated control-plane action.
pub fn generate_identity(directory: &Path, tls_names: Vec<String>) -> Result<IdentityFiles> {
    use std::io::Write;
    if tls_names.is_empty() {
        return Err("at least one TLS certificate name is required".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)?;
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(
                "node identity directory must be private and owned by the current user".into(),
            );
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(directory)?;
    let generated = rcgen::generate_simple_self_signed(tls_names)?;
    let certificate = generated.cert.der().to_vec();
    let private_key = generated.signing_key.serialize_der();
    let files = IdentityFiles {
        certificate: directory.join("node-cert.der"),
        private_key: directory.join("node-key.der"),
        certificate_sha256: PeerPin::certificate(&certificate).to_hex(),
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut key_file = options.open(&files.private_key)?;
    let mut certificate_file = match options.open(&files.certificate) {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(&files.private_key);
            return Err(error.into());
        }
    };
    key_file.write_all(&private_key)?;
    key_file.sync_all()?;
    certificate_file.write_all(&certificate)?;
    certificate_file.sync_all()?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(files)
}

pub fn load_identity(certificate: &Path, private_key: &Path) -> Result<Identity> {
    Identity::from_der(
        vec![crate::local_files::read_public(certificate, 64 * 1024)?],
        crate::local_files::read_private(private_key, 64 * 1024)?,
    )
}
impl PeerPin {
    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("certificate pin must be 64 hexadecimal characters".into());
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self(bytes))
    }
    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPolicy {
    pub node_id: String,
    pub certificate_sha256: String,
    #[serde(default)]
    pub allowed_operations: Vec<Operation>,
}
impl PeerPolicy {
    fn validate(&self) -> Result<PeerPin> {
        if !valid_name(&self.node_id) {
            return Err("invalid peer node identity".into());
        }
        PeerPin::from_hex(&self.certificate_sha256)
    }
}
/// A listener never exposes a connection before TLS and registered peer identity checks pass.
pub struct DirectServer {
    endpoint: Endpoint,
    local_node_id: String,
    peers: Vec<PeerPolicy>,
    local_pin: String,
    revocations: Option<Arc<RevocationManager>>,
    handshakes: tokio::sync::Mutex<FuturesUnordered<BoxFuture<'static, Result<DirectConnection>>>>,
}
impl DirectServer {
    pub fn bind(
        bind: SocketAddr,
        local_node_id: String,
        identity: Identity,
        trust_anchors: Vec<Vec<u8>>,
        peers: Vec<PeerPolicy>,
    ) -> Result<Self> {
        Self::bind_with_revocations(bind, local_node_id, identity, trust_anchors, peers, None)
    }
    pub fn bind_with_revocations(
        bind: SocketAddr,
        local_node_id: String,
        identity: Identity,
        trust_anchors: Vec<Vec<u8>>,
        peers: Vec<PeerPolicy>,
        revocations: Option<Arc<RevocationManager>>,
    ) -> Result<Self> {
        if !valid_name(&local_node_id) || peers.is_empty() {
            return Err("local identity and registered peers are required".into());
        }
        let mut identities = HashSet::new();
        let mut pins = HashSet::new();
        for peer in &peers {
            peer.validate()?;
            if !identities.insert(&peer.node_id)
                || !pins.insert(peer.certificate_sha256.to_ascii_lowercase())
            {
                return Err("peer identities and certificate pins must be unique".into());
            }
        }
        let local_pin = PeerPin::certificate(
            identity
                .certificates
                .first()
                .ok_or("node certificate missing")?
                .as_ref(),
        )
        .to_hex();
        let endpoint = server(
            bind,
            identity,
            roots(
                trust_anchors
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect(),
            )?,
            revocations.clone(),
        )?;
        Ok(Self {
            endpoint,
            local_node_id,
            peers,
            local_pin,
            revocations,
            handshakes: tokio::sync::Mutex::new(FuturesUnordered::new()),
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"node shutting down");
    }
    pub async fn accept(&self) -> Result<DirectConnection> {
        let mut handshakes = self.handshakes.lock().await;
        loop {
            tokio::select! {
                completed=handshakes.next(), if !handshakes.is_empty() => {
                    if let Some(connection)=completed { return connection; }
                }
                incoming=self.endpoint.accept(), if handshakes.len()<128 => {
                    let incoming=incoming.ok_or("direct endpoint closed")?;
                    let peers=self.peers.clone();
                    let local_node_id=self.local_node_id.clone();
                    let revocations=self.revocations.clone();
                    let local_pin=self.local_pin.clone();
                    handshakes.push(Box::pin(async move {
                        let pins=peers.iter().map(PeerPolicy::validate).collect::<Result<Vec<_>>>()?;
                        let connection=tokio::time::timeout(Duration::from_secs(10),incoming).await?.map_err(transport_error)?;
                        let connection=check_pin(connection,&pins)?;
                        let pin=connection.peer_identity().and_then(|identity|identity.downcast::<Vec<CertificateDer<'static>>>().ok()).and_then(|chain|chain.first().map(|certificate|PeerPin::certificate(certificate.as_ref()))).ok_or("peer certificate missing")?;
                        let peer=peers.iter().zip(pins).find(|(_,expected)|*expected==pin).map(|(peer,_)|peer.clone()).ok_or("peer identity not registered")?;
                        if let Some(state)=&revocations {state.register(pin.to_hex(),local_pin.clone(),peer.node_id.clone(),connection.clone())?;}
                        Ok(DirectConnection {connection,local_node_id,peer,revocations,local_pin,revocations_negotiated:Arc::new(std::sync::atomic::AtomicBool::new(false))})
                    }));
                }
            }
        }
    }
}
pub struct DirectClient {
    endpoint: Endpoint,
    local_node_id: String,
    sessions: Arc<Mutex<HashMap<String, DirectConnection>>>,
    local_pin: String,
    revocations: Option<Arc<RevocationManager>>,
}
impl DirectClient {
    pub fn bind(
        bind: SocketAddr,
        local_node_id: String,
        identity: Identity,
        trust_anchors: Vec<Vec<u8>>,
    ) -> Result<Self> {
        Self::bind_with_revocations(bind, local_node_id, identity, trust_anchors, None)
    }
    pub fn bind_with_revocations(
        bind: SocketAddr,
        local_node_id: String,
        identity: Identity,
        trust_anchors: Vec<Vec<u8>>,
        revocations: Option<Arc<RevocationManager>>,
    ) -> Result<Self> {
        if !valid_name(&local_node_id) {
            return Err("invalid local node identity".into());
        }
        let local_pin = PeerPin::certificate(
            identity
                .certificates
                .first()
                .ok_or("node certificate missing")?
                .as_ref(),
        )
        .to_hex();
        let sessions: Arc<Mutex<HashMap<String, DirectConnection>>> =
            Arc::new(Mutex::new(HashMap::new()));
        if let Some(state) = &revocations {
            let weak = Arc::downgrade(&sessions);
            let own_pin = local_pin.clone();
            state.register_cache_pruner(Box::new(move |deny| {
                if let Some(cache) = weak.upgrade()
                    && let Ok(mut cache) = cache.lock()
                {
                    cache.retain(|_, connection| {
                        !deny.contains(&own_pin)
                            && !deny.contains(&connection.peer.certificate_sha256)
                            && connection.connection.close_reason().is_none()
                    });
                }
            }))?;
        }
        Ok(Self {
            endpoint: client(
                bind,
                identity,
                roots(
                    trust_anchors
                        .into_iter()
                        .map(CertificateDer::from)
                        .collect(),
                )?,
                revocations.clone(),
            )?,
            local_node_id,
            sessions,
            local_pin,
            revocations,
        })
    }
    pub async fn connect(
        &self,
        address: SocketAddr,
        tls_name: &str,
        peer: PeerPolicy,
    ) -> Result<DirectConnection> {
        let pin = peer.validate()?;
        if let Some(state) = &self.revocations {
            state.authorize_pin(&pin.to_hex())?;
            state.authorize_pin(&self.local_pin)?;
        }
        let key = format!("{address}|{tls_name}|{}", serde_json::to_string(&peer)?);
        let cached = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "direct session cache is unavailable")?;
            sessions.retain(|_, connection| connection.connection.close_reason().is_none());
            sessions.get(&key).cloned()
        };
        if let Some(connection) = cached {
            if let Some(state) = &self.revocations {
                state.register(
                    pin.to_hex(),
                    self.local_pin.clone(),
                    connection.peer.node_id.clone(),
                    connection.connection.clone(),
                )?;
            }
            return Ok(connection);
        }
        let connection = connect(&self.endpoint, address, tls_name, pin).await?;
        let connection = DirectConnection {
            connection,
            local_node_id: self.local_node_id.clone(),
            peer,
            revocations: self.revocations.clone(),
            local_pin: self.local_pin.clone(),
            revocations_negotiated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        if let Some(state) = &self.revocations {
            state.register(
                pin.to_hex(),
                self.local_pin.clone(),
                connection.peer.node_id.clone(),
                connection.connection.clone(),
            )?;
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "direct session cache is unavailable")?;
        if sessions.len() >= 128
            && let Some(key) = sessions.keys().next().cloned()
        {
            sessions.remove(&key);
        }
        sessions.insert(key.clone(), connection.clone());
        drop(sessions);
        if let Some(state) = &self.revocations
            && let Err(error) = state.register(
                pin.to_hex(),
                self.local_pin.clone(),
                connection.peer.node_id.clone(),
                connection.connection.clone(),
            )
        {
            self.sessions
                .lock()
                .map_err(|_| "direct session cache is unavailable")?
                .remove(&key);
            return Err(error);
        }
        Ok(connection)
    }
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"node shutting down");
    }
}
#[derive(Clone)]
pub struct DirectConnection {
    connection: Connection,
    local_node_id: String,
    peer: PeerPolicy,
    local_pin: String,
    revocations: Option<Arc<RevocationManager>>,
    revocations_negotiated: Arc<std::sync::atomic::AtomicBool>,
}
impl DirectConnection {
    pub(crate) fn revocations_negotiated(&self) -> bool {
        self.revocations_negotiated
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn mark_revocations_negotiated(&self) {
        self.revocations_negotiated
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub fn peer(&self) -> &PeerPolicy {
        &self.peer
    }
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"node shutting down");
    }
    pub async fn closed(&self) -> String {
        let reason = self.connection.closed().await;
        if self
            .authorize()
            .is_err_and(|error| error.to_string() == "revoked")
        {
            return "revoked".into();
        }
        match reason {
            quinn::ConnectionError::ApplicationClosed(close)
                if close.error_code == quinn::VarInt::from_u32(0x105) =>
            {
                "revoked".into()
            }
            error => error.to_string(),
        }
    }
    fn authorize(&self) -> Result<()> {
        if let Some(state) = &self.revocations {
            state.authorize_pin(&self.peer.certificate_sha256)?;
            state.authorize_pin(&self.local_pin)?;
        }
        Ok(())
    }
    pub async fn open(&self) -> Result<RpcStream> {
        self.authorize()?;
        let stream =
            tokio::time::timeout(Duration::from_secs(30), open(&self.connection)).await??;
        self.authorize()?;
        Ok(RpcStream {
            stream,
            local_node_id: self.local_node_id.clone(),
            peer: self.peer.clone(),
        })
    }
    pub async fn accept(&self) -> Result<RpcStream> {
        let stream = accept(&self.connection).await?;
        self.authorize()?;
        Ok(RpcStream {
            stream,
            local_node_id: self.local_node_id.clone(),
            peer: self.peer.clone(),
        })
    }
    /// A failed request may have reached the peer; the caller must query its stable job ID.
    pub async fn rpc(&self, request: &RpcFrame) -> Result<RpcFrame> {
        if request.kind != FrameKind::Request {
            return Err("RPC requires a request frame".into());
        }
        let mut stream = self.open().await?;
        stream.send(request).await?;
        let response = stream.recv().await?;
        if response.kind != FrameKind::Response
            || response.in_reply_to.as_deref() != Some(&request.id)
            || response.operation != request.operation
        {
            return Err("response does not match request".into());
        }
        Ok(response)
    }
}
pub struct RpcStream {
    stream: Stream,
    local_node_id: String,
    peer: PeerPolicy,
}
impl RpcStream {
    pub async fn send(&mut self, frame: &RpcFrame) -> Result<()> {
        frame.validate()?;
        if frame.source != self.local_node_id || frame.target != self.peer.node_id {
            return Err("outgoing RPC identity mismatch".into());
        }
        let bytes = serde_json::to_vec(frame)?;
        tokio::time::timeout(Duration::from_secs(30), self.stream.write(&bytes)).await??;
        Ok(())
    }
    pub async fn recv(&mut self) -> Result<RpcFrame> {
        let bytes = tokio::time::timeout(Duration::from_secs(30), self.stream.read()).await??;
        let frame: RpcFrame =
            serde_json::from_slice(&bytes).map_err(|_| "invalid node RPC frame")?;
        frame.validate()?;
        if frame.source != self.peer.node_id || frame.target != self.local_node_id {
            return Err("incoming RPC identity mismatch".into());
        }
        if frame.kind == FrameKind::Request
            && !self.peer.allowed_operations.contains(&frame.operation)
        {
            return Err("peer operation is not permitted".into());
        }
        Ok(frame)
    }
    pub fn finish(&mut self) -> Result<()> {
        self.stream.send.finish()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "quic/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "quic/revocation_error_tests.rs"]
mod revocation_error_tests;
