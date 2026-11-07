// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;
use futures_util::{SinkExt, StreamExt};
use lockyard_node::{
    host::{self, NodeConfig, RelaySettings},
    quic,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    net::SocketAddr,
    sync::{Arc, atomic::AtomicUsize},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, watch},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, handshake::derive_accept_key, protocol::Role},
};

const HELPER: &str = "LOCKYARD_NATIVE_BROKER_HOST_CONFIG";
const TOKEN: &str = "native-broker-fixture-token";

#[test]
fn native_broker_host_helper() {
    let Some(path) = std::env::var_os(HELPER) else {
        return;
    };
    let config: NodeConfig = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let expected_key = WorkspaceKey::from_entropy([117; 32]);
    match WorkspaceKey::load_for_workspace(&config.workspace)
        .expect("cannot load broker fixture workspace key")
    {
        Some(key) => assert_eq!(
            key.key_id(),
            expected_key.key_id(),
            "broker fixture workspace key changed across host restart"
        ),
        None => expected_key
            .store_for_workspace(&config.workspace)
            .expect("cannot provision broker fixture workspace key"),
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(host::serve(config))
        .unwrap();
}

struct ChildHost(std::process::Child);
impl ChildHost {
    fn start(config: &Path, home: &Path, log: &Path) -> Self {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_cases::linux::broker::native_broker_host_helper",
                "--nocapture",
            ])
            .env(HELPER, config)
            .env("XDG_CONFIG_HOME", home)
            .env("NO_PROXY", "localhost,127.0.0.1")
            .env("no_proxy", "localhost,127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        Self(child)
    }
    fn stop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Drop for ChildHost {
    fn drop(&mut self) {
        self.stop();
    }
}

struct TestBroker {
    address: SocketAddr,
    certificate: PathBuf,
    online: watch::Sender<bool>,
    connections: Arc<AtomicUsize>,
    disconnections: Arc<AtomicUsize>,
    outcomes: mpsc::Receiver<Value>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for TestBroker {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TestBroker {
    async fn start(path: &Path, node_pin: String) -> Self {
        let identity =
            quic::generate_identity(&path.join("broker-identity"), vec!["localhost".into()])
                .unwrap();
        let certificate = fs::read(&identity.certificate).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(identity.private_key).unwrap(),
        ));
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate)], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (online, status) = watch::channel(true);
        let (outcomes, delivered) = mpsc::channel(8);
        let connections = Arc::new(AtomicUsize::new(0));
        let disconnections = Arc::new(AtomicUsize::new(0));
        let sessions = connections.clone();
        let broken = disconnections.clone();
        let task = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        if !*status.borrow() { drop(stream); continue; }
                        let acceptor = acceptor.clone();
                        let status = status.clone();
                        let outcomes = outcomes.clone();
                        let pin = node_pin.clone();
                        let sessions = sessions.clone();
                        let broken = broken.clone();
                        clients.spawn(async move {
                            if let Err(error) = serve_connection(stream, acceptor, status, pin, outcomes, sessions, broken).await {
                                // TLS connects may be interrupted by the deliberate outage.
                                eprintln!("fixture broker connection ended: {error}");
                            }
                        });
                    }
                    result = clients.join_next(), if !clients.is_empty() => {
                        if let Some(result) = result { result.unwrap(); }
                    }
                }
            }
        });
        Self {
            address,
            certificate: identity.certificate,
            online,
            connections,
            disconnections,
            outcomes: delivered,
            task,
        }
    }
    fn url(&self) -> String {
        format!("https://localhost:{}", self.address.port())
    }
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    mut online: watch::Receiver<bool>,
    node_pin: String,
    outcomes: mpsc::Sender<Value>,
    connections: Arc<AtomicUsize>,
    disconnections: Arc<AtomicUsize>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = acceptor.accept(stream).await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        headers.push(byte[0]);
        assert!(headers.len() <= 16_384);
    }
    let headers = String::from_utf8(headers)?;
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains(&format!("authorization: bearer {TOKEN}\r\n")));
    assert!(lower.contains("x-lockyard-session: native-fixture\r\n"));
    if !*online.borrow() {
        return Ok(());
    }
    if lower.contains("upgrade: websocket\r\n") {
        assert!(headers.starts_with("GET /api/v1/nodes/connect?node_id=native-fixture "));
        let key = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("sec-websocket-key")
                    .then(|| value.trim())
            })
            .unwrap();
        let reply = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: lockyard-node.v1\r\n\r\n",
            derive_accept_key(key.as_bytes())
        );
        stream.write_all(reply.as_bytes()).await?;
        let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
        connections.fetch_add(1, Ordering::SeqCst);
        loop {
            tokio::select! {
                changed = online.changed() => {
                    if changed.is_err() || !*online.borrow() {
                        disconnections.fetch_add(1, Ordering::SeqCst);
                        // Dropping the socket closes the real TLS/WebSocket transport.
                        return Ok(());
                    }
                }
                message = socket.next() => match message {
                    Some(Ok(Message::Ping(bytes))) => socket.send(Message::Pong(bytes)).await?,
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(lockyard_node::wire::RelayMessage::Frame(frame)) = serde_json::from_str(&text) {
                            let ack = lockyard_node::wire::RelayControl::Ack { v: 1, id: frame.id };
                            socket.send(Message::Text(serde_json::to_string(&ack)?.into())).await?;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Err(error)) => return Err(Box::new(error)),
                    _ => {}
                }
            }
        }
    }
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(length <= 65_536);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    let result = if headers.starts_with("POST /api/v1/nodes/register ") {
        assert_eq!(body["node_id"], "native-fixture");
        assert_eq!(body["certificate_sha256"], node_pin);
        serde_json::json!({"node_id":"native-fixture","certificate_sha256":node_pin,"quic_endpoint":null,"registered_at":"2026-11-07T00:00:00Z","last_seen_at":"2026-11-07T00:00:00Z"})
    } else {
        assert!(
            headers.starts_with("POST /api/v1/nodes/job-outcomes "),
            "unexpected fixture endpoint: {}",
            headers.lines().next().unwrap()
        );
        assert_eq!(body.as_object().unwrap().len(), 3);
        assert_eq!(body["certificate_sha256"], node_pin);
        assert_eq!(body["state"], "succeeded");
        outcomes.send(body).await?;
        serde_json::json!({"accepted":true})
    };
    let body = serde_json::to_vec(&result)?;
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn ready(config: &Path, child: &mut ChildHost, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if host::status(config).await.is_ok() {
            return;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "node host exited: {}",
            fs::read_to_string(log).unwrap_or_default()
        );
        assert!(
            Instant::now() < deadline,
            "node host did not start: {}",
            fs::read_to_string(log).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
async fn status(config: &Path, job: &str) -> JobRecord {
    let response = host::local_rpc(
        config,
        "native-fixture",
        Operation::JobStatus,
        serde_json::json!({"job_id":job}),
    )
    .await
    .unwrap();
    assert!(response.ok);
    serde_json::from_value(response.result.unwrap()).unwrap()
}

#[tokio::test]
async fn native_real_websocket_broker_loss_recovers_durable_notification_after_node_restart() {
    let Some(resources) = resources() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut executor = config(dir.path(), &resources);
        let identity = quic::generate_identity(&dir.path().join("node-identity"), vec!["native-fixture".into()]).unwrap();
        let pin = quic::PeerPin::certificate(&fs::read(&identity.certificate).unwrap()).to_hex();
        let mut broker = TestBroker::start(dir.path(), pin).await;
        let token = dir.path().join("node-token");
        fs::write(&token, TOKEN).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let state = dir.path().join("node-state");
        executor.state_dir = state.join("executor");
        let node = NodeConfig {
            node_id: executor.node_id.clone(), workspace: executor.provenance.as_ref().unwrap().workspace.clone(), state_dir: state.clone(),
            listen: None, certificate: identity.certificate, private_key: identity.private_key,
            trust_anchors: vec![], peers: vec![], relay: Some(RelaySettings { url: broker.url(), token_file: token, tls_roots: vec![broker.certificate.clone()] }),
            revocations: None, result_trust: BTreeMap::new(), project_retention: BTreeMap::new(), workflow: None,
            delegation_socket: None, metadata_notifications: true, rpc_timeout_seconds: 10, executor: Some(executor),
        };
        let config_json = dir.path().join("node.json");
        let config_toml = dir.path().join("node.toml");
        fs::write(&config_json, serde_json::to_vec(&node).unwrap()).unwrap();
        fs::write(&config_toml, toml::to_string(&node).unwrap()).unwrap();
        for path in [&config_json, &config_toml] { fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap(); }
        let home = dir.path().join("key-home");
        let log = dir.path().join("host.log");
        let mut child = ChildHost::start(&config_json, &home, &log);
        ready(&config_toml, &mut child, &log).await;
        let deadline = Instant::now() + Duration::from_secs(20);
        while broker.connections.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "node never opened real broker WebSocket: {}", fs::read_to_string(&log).unwrap_or_default());
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let request = spec(46, "import pathlib,time; print('started-before-outage',flush=True); time.sleep(4); p=pathlib.Path('executions'); p.write_text(str(int(p.read_text())+1) if p.exists() else '1'); print('completed-while-broker-down')");
        let accepted = host::local_rpc(&config_toml, "native-fixture", Operation::JobSubmit, serde_json::to_value(&request).unwrap()).await.unwrap();
        assert!(accepted.ok, "{}", serde_json::to_string(&accepted).unwrap());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = host::local_rpc(&config_toml, "native-fixture", Operation::JobLog, serde_json::json!({"job_id":request.id,"offset":0,"limit":4096})).await.unwrap();
            let chunk: lockyard_node::wire::LogChunk = serde_json::from_value(response.result.unwrap()).unwrap();
            if String::from_utf8_lossy(&chunk.bytes).contains("started-before-outage") { break; }
            assert!(Instant::now() < deadline, "native workload never started");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        broker.online.send(false).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while broker.disconnections.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "actual WebSocket did not close on broker outage");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let completed = loop {
            let record = status(&config_toml, &request.id).await;
            if record.state.is_terminal() && record.result_manifest.is_some() { break record; }
            assert!(Instant::now() < deadline, "native job did not finish during real broker outage: {record:?}");
            tokio::time::sleep(Duration::from_millis(30)).await;
        };
        assert_eq!(completed.state, JobState::Succeeded, "{completed:?}");
        let report = host::status(&config_toml).await.unwrap().job_notifications.unwrap();
        assert_eq!(report.pending, 1);
        assert_eq!(report.capture_failures, 0);
        assert!(broker.outcomes.try_recv().is_err());
        let saved: Value = serde_json::from_slice(&fs::read(state.join("job-notifications.json")).unwrap()).unwrap();
        assert!(saved["entries"].as_array().unwrap().iter().any(|entry| entry["job_id"] == request.id && entry["delivered"] == false));
        child.stop();
        let mut child = ChildHost::start(&config_json, &home, &log);
        ready(&config_toml, &mut child, &log).await;
        assert_eq!(host::status(&config_toml).await.unwrap().job_notifications.unwrap().pending, 1);
        let recovered = status(&config_toml, &request.id).await;
        assert_eq!(recovered.result_manifest, completed.result_manifest);
        assert_eq!(recovered.pid, completed.pid);
        broker.online.send(true).unwrap();
        let notification = tokio::time::timeout(Duration::from_secs(35), broker.outcomes.recv()).await.unwrap().unwrap();
        assert_eq!(notification["job_id"], request.id);
        let deadline = Instant::now() + Duration::from_secs(10);
        while host::status(&config_toml).await.unwrap().job_notifications.unwrap().pending != 0 {
            assert!(Instant::now() < deadline, "accepted notification was not durably acknowledged");
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(fs::read_to_string(recovered.worktree.unwrap().join("executions")).unwrap(), "1");
        child.stop();
        let mut child = ChildHost::start(&config_json, &home, &log);
        ready(&config_toml, &mut child, &log).await;
        assert_eq!(host::status(&config_toml).await.unwrap().job_notifications.unwrap().pending, 0);
        assert_eq!(status(&config_toml, &request.id).await.result_manifest, completed.result_manifest);
    }).await.unwrap();
}
