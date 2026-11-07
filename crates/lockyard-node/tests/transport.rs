// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_cloud_client::WorkspaceKey;
use lockyard_node::{
    crypto::PayloadCodec,
    quic::{DirectClient, DirectServer, Identity, PeerPin, PeerPolicy},
    wire::*,
};
use std::{sync::Arc, time::Duration};

fn frame(source: &str, target: &str) -> RpcFrame {
    let mut frame = RpcFrame {
        v: 1,
        kind: FrameKind::Request,
        id: new_id().unwrap(),
        source: source.into(),
        target: target.into(),
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
    frame
}
fn keypair() -> (Vec<u8>, Vec<u8>) {
    let generated = rcgen::generate_simple_self_signed(vec!["lockyard-node".into()]).unwrap();
    (
        generated.cert.der().to_vec(),
        generated.signing_key.serialize_der(),
    )
}
fn identity(pair: &(Vec<u8>, Vec<u8>)) -> Identity {
    Identity::from_der(vec![pair.0.clone()], pair.1.clone()).unwrap()
}
fn peer(node: &str, certificate: &[u8]) -> PeerPolicy {
    PeerPolicy {
        node_id: node.into(),
        certificate_sha256: PeerPin::certificate(certificate).to_hex(),
        allowed_operations: vec![Operation::NodePing],
    }
}

#[test]
fn encryption_binds_every_routing_field_and_fails_closed() {
    let codec = PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32])).unwrap();
    let mut original = frame("controller", "worker");
    codec
        .encode(
            &mut original,
            &serde_json::json!({"prompt":"private payload"}),
        )
        .unwrap();
    assert!(
        !serde_json::to_string(&original)
            .unwrap()
            .contains("private payload")
    );
    assert_eq!(
        codec.decode::<serde_json::Value>(&original).unwrap()["prompt"],
        "private payload"
    );
    let mut mutations = Vec::new();
    let mut changed = original.clone();
    changed.id = new_id().unwrap();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.source = "other-controller".into();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.target = "other-worker".into();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.operation = Operation::JobSubmit;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.kind = FrameKind::Response;
    changed.in_reply_to = Some(new_id().unwrap());
    mutations.push(changed);
    let mut changed = original.clone();
    changed.v = 2;
    mutations.push(changed);
    for changed in mutations {
        assert!(codec.decode::<serde_json::Value>(&changed).is_err());
    }
    let wrong_workspace = PayloadCodec::new(
        "other-workspace".into(),
        WorkspaceKey::from_entropy([7; 32]),
    )
    .unwrap();
    assert!(
        wrong_workspace
            .decode::<serde_json::Value>(&original)
            .is_err()
    );
    let mut plaintext = frame("controller", "worker");
    plaintext.payload = "{}".into();
    assert!(codec.decode::<serde_json::Value>(&plaintext).is_err());
}

#[test]
fn bounded_log_wire_and_strict_frame_validation() {
    let chunk = LogChunk {
        offset: 0,
        next_offset: lockyard_node::wire::MAX_TRANSFER_BYTES.into(),
        bytes: vec![255; lockyard_node::wire::MAX_TRANSFER_BYTES as usize],
        eof: true,
        truncated: false,
    };
    let encoded = serde_json::to_string(&chunk).unwrap();
    assert!(encoded.len() < MAX_FRAME_BYTES);
    assert_eq!(serde_json::from_str::<LogChunk>(&encoded).unwrap(), chunk);
    // The actual AEAD frame must fit too, not only the unencrypted JSON array.
    let codec =
        PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([91; 32])).unwrap();
    let mut response = frame(&"s".repeat(64), &"t".repeat(64));
    response.v = lockyard_node::wire::PROTOCOL_VERSION;
    response.kind = lockyard_node::wire::FrameKind::Response;
    response.in_reply_to = Some(new_id().unwrap());
    response.operation = Operation::JobPatch;
    response.source_certificate_sha256 = Some("a".repeat(64));
    response.target_certificate_sha256 = Some("b".repeat(64));
    let reply = lockyard_node::wire::RpcReply::success(chunk.clone());
    codec.encode(&mut response, &reply).unwrap();
    assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_FRAME_BYTES);
    let decoded: lockyard_node::wire::RpcReply<LogChunk> = codec.decode(&response).unwrap();
    assert_eq!(decoded.result.unwrap(), chunk);

    let mut request = frame("controller", "worker");
    request.id = "not-an-ulid".into();
    assert!(request.validate().is_err());
    request.id = new_id().unwrap();
    request.source = "node|spoof".into();
    assert!(request.validate().is_err());
    request.source = "controller".into();
    request.payload = "x".repeat(MAX_FRAME_BYTES);
    assert!(request.validate().is_err());
}

#[tokio::test]
async fn persistent_authenticated_connection_reuses_independent_streams() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server_pair = keypair();
        let client_pair = keypair();
        let server = Arc::new(
            DirectServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                "worker".into(),
                identity(&server_pair),
                vec![client_pair.0.clone()],
                vec![peer("controller", &client_pair.0)],
            )
            .unwrap(),
        );
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&client_pair),
            vec![server_pair.0.clone()],
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            for _ in 0..3 {
                let mut stream = connection.accept().await.unwrap();
                let request = stream.recv().await.unwrap();
                let codec =
                    PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32]))
                        .unwrap();
                let payload: serde_json::Value = codec.decode(&request).unwrap();
                let mut response = RpcFrame {
                    v: 1,
                    kind: FrameKind::Response,
                    id: new_id().unwrap(),
                    source: "worker".into(),
                    target: "controller".into(),
                    operation: request.operation,
                    in_reply_to: Some(request.id),
                    source_certificate_sha256: None,
                    target_certificate_sha256: None,
                    retention: None,
                    payload: String::new(),
                };
                codec.encode(&mut response, &payload).unwrap();
                stream.send(&response).await.unwrap();
                stream.finish().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        for _ in 0..3 {
            let connection = client
                .connect(address, "lockyard-node", peer("worker", &server_pair.0))
                .await
                .unwrap();
            let reply = connection
                .rpc(&frame("controller", "worker"))
                .await
                .unwrap();
            assert_eq!(
                PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32]))
                    .unwrap()
                    .decode::<serde_json::Value>(&reply)
                    .unwrap(),
                serde_json::json!({})
            );
        }
        client.close();
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unregistered_certificate_and_operation_are_rejected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let server_pair = keypair();
        let client_pair = keypair();
        let server = DirectServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&server_pair),
            vec![client_pair.0.clone()],
            vec![peer("controller", &client_pair.0)],
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&client_pair),
            vec![server_pair.0.clone()],
        )
        .unwrap();
        let task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            let mut stream = connection.accept().await.unwrap();
            assert!(stream.recv().await.is_err());
        });
        let connection = client
            .connect(address, "lockyard-node", peer("worker", &server_pair.0))
            .await
            .unwrap();
        let mut request = frame("controller", "worker");
        request.operation = Operation::JobSubmit;
        request.v = PROTOCOL_VERSION;
        request.source_certificate_sha256 = Some(PeerPin::certificate(&client_pair.0).to_hex());
        request.target_certificate_sha256 = Some(PeerPin::certificate(&server_pair.0).to_hex());
        request.retention = Some(
            lockyard_node::retention::ContentRetention::for_copy(
                &lockyard_node::retention::RetentionPolicy {
                    content_ttl_seconds: 3600,
                },
                lockyard_node::retention::id_timestamp_ms(&request.id).unwrap(),
                None,
            )
            .unwrap(),
        );
        PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32]))
            .unwrap()
            .encode(&mut request, &serde_json::json!({}))
            .unwrap();
        let mut stream = connection.open().await.unwrap();
        stream.send(&request).await.unwrap();
        task.await.unwrap();
        client.close();

        let server = DirectServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&server_pair),
            vec![client_pair.0.clone()],
            vec![peer("controller", &client_pair.0)],
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = server.accept().await;
        });
        let mut policy = peer("worker", &server_pair.0);
        policy.certificate_sha256 = "00".repeat(32);
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&client_pair),
            vec![server_pair.0.clone()],
        )
        .unwrap();
        assert!(
            client
                .connect(address, "lockyard-node", policy)
                .await
                .is_err()
        );
        client.close();
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn identity_is_persistent_private_and_never_overwritten() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("identity");
    let files =
        lockyard_node::quic::generate_identity(&directory, vec!["lockyard-node".into()]).unwrap();
    let before = std::fs::read(&files.private_key).unwrap();
    lockyard_node::quic::load_identity(&files.certificate, &files.private_key).unwrap();
    assert!(
        lockyard_node::quic::generate_identity(&directory, vec!["lockyard-node".into()]).is_err()
    );
    assert_eq!(std::fs::read(&files.private_key).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&files.private_key, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(
            lockyard_node::quic::load_identity(&files.certificate, &files.private_key).is_err()
        );
    }
}
