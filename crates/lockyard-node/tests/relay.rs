// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use futures_util::{SinkExt, StreamExt};
use lockyard_node::{
    relay::{RelayClient, RelayConfig, RelayEvent},
    wire::*,
};
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};

#[allow(clippy::result_large_err)] // tungstenite's callback requires this response type.
fn handshake(request: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    if request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        != Some("Bearer test-credential")
    {
        return Err(Response::builder()
            .status(401)
            .body(Some("unauthorized".into()))
            .unwrap());
    }
    assert_eq!(request.uri().path(), "/api/v1/nodes/connect");
    assert_eq!(request.uri().query(), Some("node_id=controller"));
    assert_eq!(
        request.headers().get("X-Lockyard-Session").unwrap(),
        "controller"
    );
    response.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "lockyard-node.v1".parse().unwrap(),
    );
    Ok(response)
}

fn request() -> RelayMessage {
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
    lockyard_node::crypto::PayloadCodec::new(
        "workspace".into(),
        lockyard_cloud_client::WorkspaceKey::from_entropy([7; 32]),
    )
    .unwrap()
    .encode(&mut frame, &serde_json::json!({}))
    .unwrap();
    RelayMessage::Frame(frame)
}

#[tokio::test]
async fn authenticated_reconnect_requires_explicit_stable_id_replay() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (observed_no_replay, confirmed_no_replay) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = accept_hdr_async(socket, handshake).await.unwrap();
            let first = loop {
                match socket.next().await.unwrap().unwrap() {
                    Message::Text(text) => break serde_json::from_str::<RpcFrame>(&text).unwrap(),
                    Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                    _ => {}
                }
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&RelayControl::Ack {
                        v: 1,
                        id: first.id.clone(),
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
            socket.close(None).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = accept_hdr_async(socket, handshake).await.unwrap();
            let quiet = tokio::time::timeout(Duration::from_millis(250), async {
                loop {
                    match socket.next().await.unwrap().unwrap() {
                        Message::Text(_) => panic!("a prior frame was automatically replayed"),
                        Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                        _ => {}
                    }
                }
            })
            .await;
            assert!(quiet.is_err());
            observed_no_replay.send(()).unwrap();
            let replay = loop {
                match socket.next().await.unwrap().unwrap() {
                    Message::Text(text) => break serde_json::from_str::<RpcFrame>(&text).unwrap(),
                    Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                    _ => {}
                }
            };
            assert_eq!(first, replay);
        });
        let mut client = RelayClient::spawn(
            RelayConfig::new(&url, "controller".into(), "test-credential".into()).unwrap(),
        )
        .unwrap();
        let mut sender = client.sender();
        sender.wait_connected(Duration::from_secs(2)).await.unwrap();
        let request = request();
        sender.send(&request).await.unwrap();
        let mut connections = 0;
        let mut acknowledged = false;
        while connections < 2 {
            match client.recv().await.unwrap() {
                RelayEvent::Connected => connections += 1,
                RelayEvent::Message(RelayMessage::Control(RelayControl::Ack { .. })) => {
                    acknowledged = true
                }
                _ => {}
            }
        }
        assert!(acknowledged);
        confirmed_no_replay.await.unwrap();
        sender.send(&request).await.unwrap();
        server.await.unwrap();
        client.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_rejects_bad_authentication_and_source_spoofing() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}/api/v1/nodes/connect?node_id=controller",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(accept_hdr_async(socket, handshake).await.is_err());
        });
        assert!(
            lockyard_node::relay::connect(url.parse().unwrap(), "wrong-credential")
                .await
                .is_err()
        );
        server.await.unwrap();
        assert!(
            RelayConfig::new(
                "https://example.com?token=secret",
                "controller".into(),
                "credential".into()
            )
            .is_err()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wss_verifies_certificate_and_uses_only_explicit_additional_trust() {
    tokio::time::timeout(Duration::from_secs(8), async {
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate = generated.cert.der().to_vec();
        let tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.clone())],
            PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            assert!(acceptor.accept(socket).await.is_err());
            let (socket, _) = listener.accept().await.unwrap();
            let socket = acceptor.accept(socket).await.unwrap();
            let mut socket = accept_hdr_async(socket, handshake).await.unwrap();
            loop {
                match socket.next().await.unwrap().unwrap() {
                    Message::Text(text) => {
                        let frame: RpcFrame = serde_json::from_str(&text).unwrap();
                        let codec = lockyard_node::crypto::PayloadCodec::new(
                            "workspace".into(),
                            lockyard_cloud_client::WorkspaceKey::from_entropy([7; 32]),
                        )
                        .unwrap();
                        let value: serde_json::Value = codec.decode(&frame).unwrap();
                        assert_eq!(value, serde_json::json!({}));
                        socket
                            .send(Message::Text(
                                serde_json::to_string(&RelayControl::Ack { v: 1, id: frame.id })
                                    .unwrap()
                                    .into(),
                            ))
                            .await
                            .unwrap();
                        break;
                    }
                    Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let url = format!("wss://{address}/api/v1/nodes/connect?node_id=controller");
        assert!(
            lockyard_node::relay::connect(url.parse().unwrap(), "test-credential")
                .await
                .is_err()
        );
        let config = RelayConfig::new(
            &format!("https://{address}"),
            "controller".into(),
            "test-credential".into(),
        )
        .unwrap()
        .with_trust_anchors(vec![certificate])
        .unwrap();
        let mut client = RelayClient::spawn(config).unwrap();
        let mut sender = client.sender();
        sender.wait_connected(Duration::from_secs(2)).await.unwrap();
        let mut spoofed = request();
        if let RelayMessage::Frame(frame) = &mut spoofed {
            frame.source = "spoofed-node".into();
        }
        assert!(sender.send(&spoofed).await.is_err());
        sender.send(&request()).await.unwrap();
        loop {
            if matches!(
                client.recv().await.unwrap(),
                RelayEvent::Message(RelayMessage::Control(RelayControl::Ack { .. }))
            ) {
                break;
            }
        }
        server.await.unwrap();
        client.shutdown().await;
    })
    .await
    .unwrap();
}
