// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! A peer's authenticated QUIC close is an SDK error, never a signed deny-list update.
use super::*;
use crate::{
    crypto::PayloadCodec,
    provenance::SigningKey,
    revocations::{
        RevocationConfig, RevocationManager, RevocationPage, RevocationTrust, SignedDocument,
    },
    wire::new_id,
};
use lockyard_cloud_client::WorkspaceKey;
const WORKSPACE: &str = "11111111-1111-1111-1111-111111111111";
fn pair() -> (Vec<u8>, Vec<u8>) {
    let p = rcgen::generate_simple_self_signed(vec!["lockyard-node".into()]).unwrap();
    (p.cert.der().to_vec(), p.signing_key.serialize_der())
}
fn identity(pair: &(Vec<u8>, Vec<u8>)) -> Identity {
    Identity::from_der(vec![pair.0.clone()], pair.1.clone()).unwrap()
}
fn policy(node: &str, pair: &(Vec<u8>, Vec<u8>)) -> PeerPolicy {
    PeerPolicy {
        node_id: node.into(),
        certificate_sha256: PeerPin::certificate(&pair.0).to_hex(),
        allowed_operations: vec![Operation::NodePing],
    }
}
fn document(key: &SigningKey, epoch: u64, nonce: &str, pin: Option<String>) -> SignedDocument {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let entries=pin.into_iter().map(|pin|serde_json::json!({"epoch":epoch,"ordinal":0,"target":{"kind":"cert_pin","certificate_sha256":pin},"revoked_at_ms":now})).collect::<Vec<_>>();
    let page:RevocationPage=serde_json::from_value(serde_json::json!({"schema":1,"workspace_id":WORKSPACE,"from_epoch":0,"epoch":epoch,"snapshot_id":"22222222-2222-2222-2222-222222222222","issued_at_ms":now,"valid_until_ms":now+60000,"nonce":nonce,"page_index":0,"next_cursor":null,"entries":entries})).unwrap();
    serde_json::from_value(
        serde_json::to_value(
            key.sign_document(lockyard_cloud_client::revocations::DOMAIN, &page)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}
async fn connected() -> (
    tempfile::TempDir,
    SigningKey,
    Arc<RevocationManager>,
    Arc<RevocationManager>,
    DirectClient,
    DirectServer,
    DirectConnection,
    DirectConnection,
) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let signer = SigningKey::generate(&root.path().join("signer.pk8")).unwrap();
    let key = signer.trusted_key();
    let settings = RevocationConfig {
        required: true,
        poll_seconds: 30,
        max_offline_seconds: 600,
        trust: RevocationTrust {
            workspace_id: WORKSPACE.into(),
            key_id: key.key_id().unwrap(),
            public_key: key.public_key,
            server_origin: "https://example.test".into(),
        },
    };
    let local = RevocationManager::open(settings.clone(), &root.path().join("local")).unwrap();
    let remote = RevocationManager::open(settings, &root.path().join("remote")).unwrap();
    let nonce = "aa".repeat(32);
    let signed = document(&signer, 0, &nonce, None);
    let page = lockyard_cloud_client::revocations::verify_document(
        &signed,
        local.trust(),
        &local.trust().server_origin,
    )
    .unwrap();
    for state in [&local, &remote] {
        state
            .refresh(
                std::slice::from_ref(&signed),
                &nonce,
                page.issued_at_ms,
                std::time::Instant::now(),
            )
            .unwrap();
    }
    let worker = pair();
    let controller = pair();
    let server = DirectServer::bind_with_revocations(
        "127.0.0.1:0".parse().unwrap(),
        "worker".into(),
        identity(&worker),
        vec![controller.0.clone()],
        vec![policy("controller", &controller)],
        Some(remote.clone()),
    )
    .unwrap();
    let client = DirectClient::bind_with_revocations(
        "127.0.0.1:0".parse().unwrap(),
        "controller".into(),
        identity(&controller),
        vec![worker.0.clone()],
        Some(local.clone()),
    )
    .unwrap();
    let (outgoing, incoming) = tokio::join!(
        client.connect(
            server.local_addr().unwrap(),
            "lockyard-node",
            policy("worker", &worker)
        ),
        server.accept()
    );
    (
        root,
        signer,
        local,
        remote,
        client,
        server,
        outgoing.unwrap(),
        incoming.unwrap(),
    )
}
fn ping(connection: &DirectConnection) -> RpcFrame {
    let mut frame = RpcFrame {
        v: 1,
        kind: FrameKind::Request,
        id: new_id().unwrap(),
        source: "controller".into(),
        target: connection.peer().node_id.clone(),
        operation: Operation::NodePing,
        in_reply_to: None,
        source_certificate_sha256: None,
        target_certificate_sha256: None,
        retention: None,
        payload: String::new(),
    };
    PayloadCodec::new(WORKSPACE.into(), WorkspaceKey::from_entropy([7; 32]))
        .unwrap()
        .encode(&mut frame, &serde_json::json!({}))
        .unwrap();
    frame
}
#[tokio::test]
async fn remote_only_signed_revocation_maps_open_rpc_read_and_write_to_revoked_without_trusting_close()
 {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_root, signer, local, remote, client, server, outgoing, incoming) = connected().await;
        let local_pin = incoming.peer().certificate_sha256.clone();
        let mut reading = outgoing.open().await.unwrap();
        let mut writing = outgoing.open().await.unwrap();
        let request = ping(&outgoing);
        remote
            .apply_additive(&document(&signer, 1, "", Some(local_pin.clone())))
            .unwrap();
        assert_eq!(outgoing.closed().await, "revoked");
        assert_eq!(outgoing.open().await.err().unwrap().to_string(), "revoked");
        assert_eq!(
            outgoing.rpc(&request).await.err().unwrap().to_string(),
            "revoked"
        );
        assert_eq!(reading.recv().await.err().unwrap().to_string(), "revoked");
        assert_eq!(
            writing.send(&request).await.err().unwrap().to_string(),
            "revoked"
        );
        assert_eq!(local.snapshot().unwrap().observed_epoch, 0);
        local.authorize_pin(&local_pin).unwrap();
        local
            .authorize_pin(&outgoing.peer().certificate_sha256)
            .unwrap();
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn unrelated_remote_close_and_stream_errors_preserve_original_sdk_error() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_root, _signer, local, _remote, client, server, outgoing, incoming) =
            connected().await;
        let mut reading = outgoing.open().await.unwrap();
        let mut writing = outgoing.open().await.unwrap();
        let request = ping(&outgoing);
        incoming.connection.close(0x104u32.into(), b"revoked");
        let reason = outgoing.connection.closed().await;
        let original = reason.to_string();
        assert_ne!(original, "revoked");
        assert_eq!(outgoing.open().await.err().unwrap().to_string(), original);
        let expected_read =
            quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(reason.clone()))
                .to_string();
        let expected_write = quinn::WriteError::ConnectionLost(reason).to_string();
        assert_eq!(
            reading.recv().await.err().unwrap().to_string(),
            expected_read
        );
        assert_eq!(
            writing.send(&request).await.err().unwrap().to_string(),
            expected_write
        );
        assert_eq!(local.snapshot().unwrap().observed_epoch, 0);
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
