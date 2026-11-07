use super::*;
use crate::{crypto::PayloadCodec, wire::new_id};
use lockyard_cloud_client::WorkspaceKey;

fn pair() -> (Vec<u8>, Vec<u8>) {
    let generated = rcgen::generate_simple_self_signed(vec!["lockyard-node".into()]).unwrap();
    (
        generated.cert.der().to_vec(),
        generated.signing_key.serialize_der(),
    )
}
fn identity(pair: &(Vec<u8>, Vec<u8>)) -> Identity {
    Identity::from_der(vec![pair.0.clone()], pair.1.clone()).unwrap()
}
fn policy(node: &str, certificate: &[u8]) -> PeerPolicy {
    PeerPolicy {
        node_id: node.into(),
        certificate_sha256: PeerPin::certificate(certificate).to_hex(),
        allowed_operations: vec![Operation::NodePing],
    }
}

#[tokio::test]
async fn malicious_peer_cannot_spoof_source_or_allocate_oversized_frame() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server_pair = pair();
        let client_pair = pair();
        let server = DirectServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&server_pair),
            vec![client_pair.0.clone()],
            vec![policy("controller", &client_pair.0)],
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let mut oversized = connection.accept().await.unwrap();
            assert_eq!(
                oversized.recv().await.unwrap_err().to_string(),
                "node frame is too large"
            );
            let mut spoofed = connection.accept().await.unwrap();
            assert_eq!(
                spoofed.recv().await.unwrap_err().to_string(),
                "incoming RPC identity mismatch"
            );
        });
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&client_pair),
            vec![server_pair.0.clone()],
        )
        .unwrap();
        let connection = client
            .connect(address, "lockyard-node", policy("worker", &server_pair.0))
            .await
            .unwrap();
        let (mut oversized, _) = connection.connection.open_bi().await.unwrap();
        oversized
            .write_all(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        let mut frame = RpcFrame {
            v: 1,
            kind: FrameKind::Request,
            id: new_id().unwrap(),
            source: "spoofed-node".into(),
            target: "worker".into(),
            operation: Operation::NodePing,
            in_reply_to: None,
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32]))
            .unwrap()
            .encode(&mut frame, &serde_json::json!({}))
            .unwrap();
        let mut raw = open(&connection.connection).await.unwrap();
        raw.write(&serde_json::to_vec(&frame).unwrap())
            .await
            .unwrap();
        task.await.unwrap();
        client.close();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn anonymous_tls_client_is_never_exposed_as_an_authenticated_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server_pair = pair();
        let registered = pair();
        let server = DirectServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&server_pair),
            vec![registered.0.clone()],
            vec![policy("controller", &registered.0)],
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            assert!(server.accept().await.is_err());
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(vec![CertificateDer::from(server_pair.0)]).unwrap())
        .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);
        let _ = endpoint.connect(address, "lockyard-node").unwrap().await;
        task.await.unwrap();
        endpoint.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_handshake_does_not_serialize_other_peers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server_pair = pair();
        let client_pair = pair();
        let server = DirectServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&server_pair),
            vec![client_pair.0.clone()],
            vec![policy("controller", &client_pair.0)],
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let mut stream = connection.accept().await.unwrap();
            assert!(stream.recv().await.is_ok());
        });
        // Forward just the first QUIC Initial. Keep the socket alive while dropping the
        // rest of the handshake, so the server must poll other incoming handshakes.
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let stalled = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&client_pair),
            vec![server_pair.0.clone()],
        )
        .unwrap();
        let stalled_policy = policy("worker", &server_pair.0);
        let stalled_task = tokio::spawn(async move {
            let _ = stalled
                .connect(relay_address, "lockyard-node", stalled_policy)
                .await;
        });
        let mut datagram = [0u8; 65536];
        let (bytes, _) = relay.recv_from(&mut datagram).await.unwrap();
        relay.send_to(&datagram[..bytes], address).await.unwrap();
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&client_pair),
            vec![server_pair.0.clone()],
        )
        .unwrap();
        let connection = tokio::time::timeout(
            Duration::from_secs(2),
            client.connect(address, "lockyard-node", policy("worker", &server_pair.0)),
        )
        .await
        .unwrap()
        .unwrap();
        let mut stream = connection.open().await.unwrap();
        let mut frame = RpcFrame {
            v: 1,
            kind: FrameKind::Request,
            id: new_id().unwrap(),
            source: "controller".into(),
            target: "worker".into(),
            operation: Operation::NodePing,
            in_reply_to: None,
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32]))
            .unwrap()
            .encode(&mut frame, &serde_json::json!({}))
            .unwrap();
        stream.send(&frame).await.unwrap();
        task.await.unwrap();
        stalled_task.abort();
        client.close();
    })
    .await
    .unwrap();
}
