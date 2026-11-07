// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! TLS WebSocket relay connection with inherited proxy routing.
use crate::wire::{RelayControl, RelayMessage, valid_name, valid_ulid};
use crate::{Result, wire::MAX_FRAME_BYTES};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig},
};
use url::Url;
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type RelaySocket = WebSocketStream<MaybeTlsStream<Box<dyn Io>>>;
pub(crate) fn tls(additional_certificates: &[Vec<u8>]) -> Result<Arc<rustls::ClientConfig>> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(loaded.certs);
    for certificate in additional_certificates {
        roots.add(rustls::pki_types::CertificateDer::from(certificate.clone()))?;
    }
    if roots.is_empty() {
        return Err("no system TLS trust anchors available".into());
    }
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ))
}
pub(crate) fn bypass_proxy(url: &Url) -> bool {
    let no_proxy = std::env::var("no_proxy")
        .or_else(|_| std::env::var("NO_PROXY"))
        .unwrap_or_default();
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });
    no_proxy.split(',').any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        if entry == "*" {
            return true;
        }
        let (domain, required_port) = match entry.rsplit_once(':') {
            Some((domain, candidate)) if !domain.contains(':') => {
                (domain, candidate.parse::<u16>().ok())
            }
            _ => (entry, None),
        };
        if required_port.is_some_and(|required| required != port) {
            return false;
        }
        let domain = domain.trim_start_matches('.').trim_matches(['[', ']']);
        host.eq_ignore_ascii_case(domain)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", domain.to_ascii_lowercase()))
    })
}
async fn stream(url: &Url, config: Arc<rustls::ClientConfig>) -> Result<Box<dyn Io>> {
    let host = url
        .host_str()
        .ok_or("relay host is missing")?
        .trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .unwrap_or(if url.scheme() == "wss" { 443 } else { 80 });
    let proxy = if bypass_proxy(url) {
        None
    } else {
        std::env::var("https_proxy")
            .or_else(|_| std::env::var("HTTPS_PROXY"))
            .ok()
            .filter(|p| !p.is_empty())
    };
    let Some(proxy) = proxy else {
        return Ok(Box::new(TcpStream::connect((host, port)).await?));
    };
    let proxy = Url::parse(&proxy).map_err(|_| "invalid HTTPS proxy URL")?;
    if !matches!(proxy.scheme(), "http" | "https") {
        return Err("HTTPS proxy requires http or https scheme".into());
    }
    let proxy_host = proxy
        .host_str()
        .ok_or("proxy host is missing")?
        .trim_matches(['[', ']']);
    let proxy_port = proxy
        .port_or_known_default()
        .ok_or("proxy port is missing")?;
    let socket = TcpStream::connect((proxy_host, proxy_port)).await?;
    let mut socket: Box<dyn Io> = if proxy.scheme() == "https" {
        let name = rustls::pki_types::ServerName::try_from(proxy_host.to_string())?;
        Box::new(
            tokio_rustls::TlsConnector::from(config)
                .connect(name, socket)
                .await?,
        )
    } else {
        Box::new(socket)
    };
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let authorization = if proxy.username().is_empty() {
        String::new()
    } else {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(format!(
                "{}:{}",
                proxy.username(),
                proxy.password().unwrap_or_default()
            ))
        )
    };
    socket
        .write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= 8192 {
            return Err("proxy response headers are too large".into());
        }
        let mut byte = [0];
        socket.read_exact(&mut byte).await?;
        response.push(byte[0]);
    }
    let line = std::str::from_utf8(&response)
        .map_err(|_| "invalid proxy response")?
        .lines()
        .next()
        .unwrap_or_default();
    if line.split_whitespace().nth(1) != Some("200") {
        return Err("proxy refused relay tunnel".into());
    }
    Ok(socket)
}
pub async fn connect(url: Url, token: &str) -> Result<RelaySocket> {
    connect_with_trust(url, token, &[]).await
}

async fn connect_with_trust(
    url: Url,
    token: &str,
    additional_certificates: &[Vec<u8>],
) -> Result<RelaySocket> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("relay URL cannot contain credentials or a fragment".into());
    }
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]"));
    if url.scheme() != "wss" && !(url.scheme() == "ws" && loopback) {
        return Err("relay requires TLS; plaintext is only permitted on loopback".into());
    }
    if token.is_empty() {
        return Err("relay bearer token is required".into());
    }
    let mut request = url.as_str().into_client_request()?;
    let identities = url
        .query_pairs()
        .filter(|(name, _)| name == "node_id")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    if identities.len() != 1 || !valid_name(&identities[0]) {
        return Err("relay URL requires exactly one valid node_id".into());
    }
    request
        .headers_mut()
        .insert("X-Lockyard-Session", identities[0].parse()?);
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {token}").parse()?);
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", "lockyard-node.v1".parse()?);
    let tls = tls(additional_certificates)?;
    let future = async {
        let stream = stream(&url, tls.clone()).await?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_FRAME_BYTES))
            .max_frame_size(Some(MAX_FRAME_BYTES))
            .write_buffer_size(16 * 1024)
            .max_write_buffer_size(MAX_FRAME_BYTES * 2);
        let (socket, response) = client_async_tls_with_config(
            request,
            stream,
            Some(config),
            Some(tokio_tungstenite::Connector::Rustls(tls)),
        )
        .await?;
        if response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|h| h.to_str().ok())
            != Some("lockyard-node.v1")
        {
            return Err("relay did not negotiate lockyard-node.v1".into());
        }
        Ok(socket)
    };
    tokio::time::timeout(Duration::from_secs(15), future).await?
}

/// The bearer credential is deliberately absent from Debug and event diagnostics.
pub struct RelayConfig {
    url: Url,
    node_id: String,
    token: String,
    additional_certificates: Vec<Vec<u8>>,
    enrollment: Option<Enrollment>,
}
struct Enrollment {
    client: crate::cloud::NodeCloudClient,
    certificate: Vec<u8>,
    endpoint: Option<String>,
}
impl RelayConfig {
    pub fn new(base_url: &str, node_id: String, token: String) -> Result<Self> {
        if !valid_name(&node_id)
            || token.is_empty()
            || token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err("node identity and relay token are required".into());
        }
        let mut url = Url::parse(base_url)?;
        let scheme = match url.scheme() {
            "http" | "ws" => "ws",
            "https" | "wss" => "wss",
            _ => return Err("unsupported relay URL scheme".into()),
        };
        url.set_scheme(scheme).map_err(|_| "invalid relay URL")?;
        if url.scheme() == "ws"
            && !url
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]"))
        {
            return Err("node relay requires TLS outside loopback".into());
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("relay base URL cannot contain credentials, query, or fragment".into());
        }
        let path = format!("{}/api/v1/nodes/connect", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url.query_pairs_mut().append_pair("node_id", &node_id);
        Ok(Self {
            url,
            node_id,
            token,
            additional_certificates: Vec::new(),
            enrollment: None,
        })
    }
    /// Adds operator-provisioned CA certificates while preserving certificate/name verification.
    pub fn with_trust_anchors(mut self, certificates: Vec<Vec<u8>>) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in &certificates {
            roots.add(rustls::pki_types::CertificateDer::from(certificate.clone()))?;
        }
        self.additional_certificates = certificates;
        Ok(self)
    }

    /// Enroll on the same verified HTTPS origin before opening each relay connection.
    /// The returned persistent sender remains usable while enrollment retries in the background.
    pub fn with_enrollment(
        mut self,
        certificate: Vec<u8>,
        endpoint: Option<String>,
    ) -> Result<Self> {
        if self.url.scheme() != "wss" || certificate.is_empty() || certificate.len() > 64 * 1024 {
            return Err("node enrollment requires verified TLS and a valid certificate".into());
        }
        let mut base = self.url.clone();
        let path = base
            .path()
            .strip_suffix("/api/v1/nodes/connect")
            .ok_or("invalid node relay enrollment path")?
            .to_owned();
        base.set_path(&path);
        base.set_query(None);
        base.set_scheme("https")
            .map_err(|_| "invalid enrollment URL")?;
        let client = crate::cloud::NodeCloudClient::new(
            base.as_str(),
            self.node_id.clone(),
            self.token.clone(),
            &self.additional_certificates,
        )?;
        self.enrollment = Some(Enrollment {
            client,
            certificate,
            endpoint,
        });
        Ok(self)
    }

    /// Add a workspace-authenticated incarnation advertisement without sharing its key.
    pub fn with_enrollment_proof(mut self, proof: String) -> Result<Self> {
        let enrollment = self
            .enrollment
            .take()
            .ok_or("node enrollment must be configured before its identity proof")?;
        self.enrollment = Some(Enrollment {
            client: enrollment.client.with_identity_proof(proof)?,
            certificate: enrollment.certificate,
            endpoint: enrollment.endpoint,
        });
        Ok(self)
    }
}

pub enum RelayEvent {
    Connected,
    /// Metadata only: connection failures never dump HTTP responses or credentials.
    Disconnected {
        code: &'static str,
    },
    Message(RelayMessage),
}
struct Pending {
    text: String,
    generation: u64,
    result: oneshot::Sender<std::result::Result<(), &'static str>>,
}

#[derive(Clone)]
pub struct RelaySender {
    node_id: String,
    outbound: mpsc::Sender<Pending>,
    connected: watch::Receiver<u64>,
    reconnect: watch::Sender<u64>,
}
impl RelaySender {
    /// Ask for a new authenticated connection without replaying any frame at this layer.
    /// Durable application state remains responsible for retry and reconciliation.
    pub fn request_reconnect(&self) {
        self.reconnect
            .send_modify(|value| *value = value.wrapping_add(1));
    }
    /// Completion means bytes reached the socket, not that the broker durably acknowledged them.
    /// After an error the caller must retain IDs and reconcile; this client never replays writes.
    pub async fn send(&self, message: &RelayMessage) -> Result<()> {
        let generation = *self.connected.borrow();
        if generation == 0 {
            return Err("node relay is disconnected".into());
        }
        validate_message(message, &self.node_id, true)?;
        let text = serde_json::to_string(message)?;
        if text.len() > MAX_FRAME_BYTES {
            return Err("node frame is too large".into());
        }
        let (result, received) = oneshot::channel();
        self.outbound
            .send(Pending {
                text,
                generation,
                result,
            })
            .await
            .map_err(|_| "node relay stopped")?;
        tokio::time::timeout(Duration::from_secs(45), received)
            .await
            .map_err(|_| "relay write timed out; delivery is unknown")?
            .map_err(|_| "node relay stopped; delivery is unknown")?
            .map_err(Into::into)
    }
    pub async fn wait_connected(&mut self, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                if *self.connected.borrow() != 0 {
                    return Ok(());
                }
                self.connected
                    .changed()
                    .await
                    .map_err(|_| "node relay stopped")?;
            }
        })
        .await?
    }
}

/// One persistent authenticated connection, bounded queues, keepalives and reconnect.
/// Reconnect does not resend frames; durable orchestration owns explicit replay with stable IDs.
pub struct RelayClient {
    sender: RelaySender,
    events: mpsc::Receiver<RelayEvent>,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl RelayClient {
    pub fn spawn(config: RelayConfig) -> Result<Self> {
        tokio::runtime::Handle::try_current().map_err(|_| "relay requires a Tokio runtime")?;
        let (outbound, rx) = mpsc::channel(16);
        let (tx, events) = mpsc::channel(16);
        let (state_tx, connected) = watch::channel(0);
        let (shutdown, stop) = watch::channel(false);
        let (reconnect, reconnect_rx) = watch::channel(0u64);
        let sender = RelaySender {
            node_id: config.node_id.clone(),
            outbound,
            connected,
            reconnect,
        };
        let task = tokio::spawn(run(config, rx, tx, state_tx, stop, reconnect_rx));
        Ok(Self {
            sender,
            events,
            shutdown,
            task: Some(task),
        })
    }
    pub fn sender(&self) -> RelaySender {
        self.sender.clone()
    }
    pub async fn recv(&mut self) -> Option<RelayEvent> {
        self.events.recv().await
    }
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for RelayClient {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn validate_message(message: &RelayMessage, local_node_id: &str, outgoing: bool) -> Result<()> {
    match message {
        RelayMessage::Frame(frame) => {
            frame.validate()?;
            if (outgoing && frame.source != local_node_id)
                || (!outgoing && frame.target != local_node_id)
            {
                return Err("relay RPC identity mismatch".into());
            }
        }
        RelayMessage::Control(RelayControl::Ack { v, id }) => {
            if *v != 1 || !valid_ulid(id) {
                return Err("invalid relay acknowledgement".into());
            }
        }
        RelayMessage::Control(RelayControl::Error {
            v,
            id,
            code,
            message,
        }) => {
            if outgoing
                || *v != 1
                || id.as_deref().is_some_and(|id| !valid_ulid(id))
                || code.len() > 64
                || message.len() > 1024
            {
                return Err("invalid relay error".into());
            }
        }
    }
    Ok(())
}

async fn event(tx: &mpsc::Sender<RelayEvent>, event: RelayEvent) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(30), tx.send(event)).await,
        Ok(Ok(()))
    )
}

fn reconnect_delay(base_ms: u64) -> Duration {
    use ring::rand::SecureRandom;
    let mut random = [0u8; 2];
    let jitter = if ring::rand::SystemRandom::new().fill(&mut random).is_ok() {
        u16::from_be_bytes(random) as u64 % 251
    } else {
        125
    };
    Duration::from_millis(base_ms + jitter)
}

async fn run(
    config: RelayConfig,
    mut outbound: mpsc::Receiver<Pending>,
    events: mpsc::Sender<RelayEvent>,
    state: watch::Sender<u64>,
    mut stop: watch::Receiver<bool>,
    mut reconnect: watch::Receiver<u64>,
) {
    let mut delay_ms = 250u64;
    let mut generation = 0u64;
    loop {
        if *stop.borrow() {
            break;
        }
        // Coalesce requests made while disconnected; the next connection is already fresh.
        let _ = reconnect.borrow_and_update();
        if let Some(enrollment) = &config.enrollment {
            let enrolled = tokio::select! {
                _ = stop.changed() => break,
                result = enrollment.client.register(enrollment.certificate.clone(), enrollment.endpoint.clone()) => result,
            };
            if enrolled.is_err() {
                if !event(
                    &events,
                    RelayEvent::Disconnected {
                        code: "relay_enrollment_failed",
                    },
                )
                .await
                {
                    break;
                }
                tokio::select! { _ = stop.changed() => break, _ = tokio::time::sleep(reconnect_delay(delay_ms)) => {} }
                delay_ms = (delay_ms * 2).min(15_000);
                continue;
            }
        }
        let connection = tokio::select! {
            _ = stop.changed() => break,
            connection = connect_with_trust(config.url.clone(),&config.token,&config.additional_certificates) => connection,
        };
        let mut socket = match connection {
            Ok(socket) => socket,
            Err(_) => {
                if !event(
                    &events,
                    RelayEvent::Disconnected {
                        code: "relay_connect_failed",
                    },
                )
                .await
                {
                    break;
                }
                tokio::select! { _ = stop.changed() => break, _ = tokio::time::sleep(reconnect_delay(delay_ms)) => {} }
                delay_ms = (delay_ms * 2).min(15_000);
                continue;
            }
        };
        delay_ms = 250;
        generation = generation.wrapping_add(1).max(1);
        let _ = state.send(generation);
        if !event(&events, RelayEvent::Connected).await {
            break;
        }
        let mut ping = tokio::time::interval(Duration::from_secs(15));
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_received = tokio::time::Instant::now();
        let code = loop {
            tokio::select! {
                _ = stop.changed() => break "relay_shutdown",
                changed = reconnect.changed() => {
                    if changed.is_err() { break "relay_shutdown"; }
                    break "relay_reconnect_requested";
                },
                pending = outbound.recv() => {
                    let Some(pending) = pending else { break "relay_shutdown"; };
                    if pending.generation != generation { let _ = pending.result.send(Err("relay connection changed before queued write")); continue; }
                    match tokio::time::timeout(Duration::from_secs(10),socket.send(Message::Text(pending.text.into()))).await {
                        Ok(Ok(())) => { let _ = pending.result.send(Ok(())); }
                        _ => { let _ = pending.result.send(Err("relay write failed; delivery is unknown")); break "relay_write_failed"; }
                    }
                }
                incoming = socket.next() => {
                    last_received = tokio::time::Instant::now();
                    match incoming {
                        Some(Ok(Message::Text(text))) => {
                            let parsed = serde_json::from_str::<RelayMessage>(&text).ok().filter(|message| validate_message(message,&config.node_id,false).is_ok());
                            let Some(message) = parsed else { break "relay_protocol_error"; };
                            if !event(&events,RelayEvent::Message(message)).await { break "relay_consumer_stalled"; }
                        }
                        Some(Ok(Message::Ping(bytes))) => {
                            if !matches!(tokio::time::timeout(Duration::from_secs(10),socket.send(Message::Pong(bytes))).await,Ok(Ok(()))) { break "relay_write_failed"; }
                        }
                        Some(Ok(Message::Pong(_))) => {},
                        Some(Ok(Message::Close(_))) | None => break "relay_closed",
                        Some(Ok(_)) | Some(Err(_)) => break "relay_protocol_error",
                    }
                }
                _ = ping.tick() => {
                    if last_received.elapsed() > Duration::from_secs(45) { break "relay_keepalive_timeout"; }
                    if !matches!(tokio::time::timeout(Duration::from_secs(10),socket.send(Message::Ping(Vec::new().into()))).await,Ok(Ok(()))) { break "relay_write_failed"; }
                }
            }
        };
        let _ = state.send(0);
        while let Ok(pending) = outbound.try_recv() {
            let _ = pending
                .result
                .send(Err("relay disconnected before queued write"));
        }
        if code == "relay_shutdown" || *stop.borrow() {
            break;
        }
        if !event(&events, RelayEvent::Disconnected { code }).await {
            break;
        }
        if code == "relay_reconnect_requested" {
            delay_ms = delay_ms.max(1000);
        }
        tokio::select! { _ = stop.changed() => break, _ = tokio::time::sleep(reconnect_delay(delay_ms)) => {} }
    }
    let _ = state.send(0);
}
