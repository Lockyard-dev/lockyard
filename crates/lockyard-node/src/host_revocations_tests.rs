// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;
use crate::{
    provenance::SigningKey,
    quic::{Identity, PeerPolicy},
    revocations::{
        RevocationConfig, RevocationManager, RevocationPage, RevocationTrust, SignedDocument,
    },
};
use std::sync::atomic::AtomicUsize;
const WORKSPACE: &str = "11111111-1111-1111-1111-111111111111";
fn pair() -> (Vec<u8>, Vec<u8>) {
    let p = rcgen::generate_simple_self_signed(vec!["lockyard-node".into()]).unwrap();
    (p.cert.der().to_vec(), p.signing_key.serialize_der())
}
fn identity(pair: &(Vec<u8>, Vec<u8>)) -> Identity {
    Identity::from_der(vec![pair.0.clone()], pair.1.clone()).unwrap()
}
fn codec() -> PayloadCodec {
    PayloadCodec::new(WORKSPACE.into(), WorkspaceKey::from_entropy([7; 32])).unwrap()
}
type CertificatePair = (Vec<u8>, Vec<u8>);
fn fixture() -> (tempfile::TempDir, Host, CertificatePair, CertificatePair) {
    let (root, mut host) = tests::fixture();
    let own = pair();
    let peer = pair();
    host.config.workspace = WORKSPACE.into();
    host.codec = codec();
    host.certificate_sha256 = PeerPin::certificate(&own.0).to_hex();
    host.config.peers[0].tls_name = "lockyard-node".into();
    host.config.peers[0].certificate_sha256 = PeerPin::certificate(&peer.0).to_hex();
    host.config.peers[0].allowed_operations = vec![
        Operation::NodePing,
        Operation::JobStatus,
        Operation::RevocationsApply,
    ];
    let signer =
        SigningKey::generate(&host.config.state_dir.join("revocation-signer.pk8")).unwrap();
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
    let state = RevocationManager::open(settings.clone(), &host.config.state_dir).unwrap();
    let now = wall_ms().unwrap();
    let nonce = "aa".repeat(32);
    let page = RevocationPage {
        schema: 1,
        workspace_id: WORKSPACE.into(),
        from_epoch: 0,
        epoch: 0,
        snapshot_id: "22222222-2222-2222-2222-222222222222".into(),
        issued_at_ms: now,
        valid_until_ms: now + 60000,
        nonce: nonce.clone(),
        page_index: 0,
        next_cursor: None,
        entries: vec![],
    };
    let signed = signer
        .sign_document(lockyard_cloud_client::revocations::DOMAIN, &page)
        .unwrap();
    let signed: SignedDocument =
        serde_json::from_value(serde_json::to_value(signed).unwrap()).unwrap();
    state
        .refresh(&[signed], &nonce, now, Instant::now())
        .unwrap();
    host.config.revocations = Some(settings);
    host.revocations = Some(state);
    (root, host, own, peer)
}
fn frame(
    source: &str,
    target: &str,
    source_pin: &str,
    target_pin: &str,
    op: Operation,
    payload: Value,
) -> RpcFrame {
    let mut frame = RpcFrame {
        v: wire::PROTOCOL_VERSION,
        kind: FrameKind::Request,
        id: wire::new_id().unwrap(),
        source: source.into(),
        target: target.into(),
        operation: op,
        in_reply_to: None,
        source_certificate_sha256: Some(source_pin.into()),
        target_certificate_sha256: Some(target_pin.into()),
        retention: None,
        payload: String::new(),
    };
    codec().encode(&mut frame, &payload).unwrap();
    frame
}
async fn reply(connection: &quic::DirectConnection, request: &RpcFrame) -> RpcReply<Value> {
    codec()
        .decode(&connection.rpc(request).await.unwrap())
        .unwrap()
}
#[tokio::test]
async fn required_direct_incoming_peer_must_negotiate_enforced_revocations_before_rpc() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_root, host, own, peer) = fixture();
        let own_pin = PeerPin::certificate(&own.0).to_hex();
        let peer_pin = PeerPin::certificate(&peer.0).to_hex();
        let state = host.revocations.clone();
        let host = Arc::new(host);
        let server = DirectServer::bind_with_revocations(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&own),
            vec![peer.0.clone()],
            vec![host.config.peers[0].policy()],
            state,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let serving = {
            let host = host.clone();
            tokio::spawn(async move {
                while let Ok(connection) = server.accept().await {
                    let host = host.clone();
                    tokio::spawn(async move {
                        direct_connection(host, connection).await;
                    });
                }
            })
        };
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "caller".into(),
            identity(&peer),
            vec![own.0.clone()],
        )
        .unwrap();
        let connection = client
            .connect(
                address,
                "lockyard-node",
                PeerPolicy {
                    node_id: "worker".into(),
                    certificate_sha256: own_pin.clone(),
                    allowed_operations: vec![],
                },
            )
            .await
            .unwrap();
        let job = || {
            frame(
                "caller",
                "worker",
                &peer_pin,
                &own_pin,
                Operation::JobStatus,
                json!({"job_id":wire::new_id().unwrap()}),
            )
        };
        assert_eq!(
            reply(&connection, &job()).await.error.unwrap().code,
            "feature_unsupported"
        );
        // An unsolicited response is not an authorized capability request.
        let mut unsolicited = frame(
            "caller",
            "worker",
            &peer_pin,
            &own_pin,
            Operation::NodePing,
            json!({}),
        );
        unsolicited.kind = FrameKind::Response;
        unsolicited.in_reply_to = Some(wire::new_id().unwrap());
        codec()
            .encode(
                &mut unsolicited,
                &json!({"capabilities":["revocations_v1"],"revocations_enforced":true}),
            )
            .unwrap();
        let mut stream = connection.open().await.unwrap();
        stream.send(&unsolicited).await.unwrap();
        stream.finish().unwrap();
        assert!(stream.recv().await.is_err());
        assert_eq!(
            reply(&connection, &job()).await.error.unwrap().code,
            "feature_unsupported"
        );
        let announcement = frame(
            "caller",
            "worker",
            &peer_pin,
            &own_pin,
            Operation::NodePing,
            json!({"capabilities":["revocations_v1"],"revocations_enforced":false}),
        );
        assert!(reply(&connection, &announcement).await.ok);
        assert_eq!(
            reply(&connection, &job()).await.error.unwrap().code,
            "feature_unsupported"
        );
        let announcement = frame(
            "caller",
            "worker",
            &peer_pin,
            &own_pin,
            Operation::NodePing,
            json!({"capabilities":["revocations_v1"],"revocations_enforced":true}),
        );
        assert!(reply(&connection, &announcement).await.ok);
        assert_eq!(
            reply(&connection, &job()).await.error.unwrap().code,
            "executor_disabled"
        );
        // A new TLS connection must announce again; node ID or earlier-session claims do not suffice.
        connection.close();
        let connection = client
            .connect(
                address,
                "lockyard-node",
                PeerPolicy {
                    node_id: "worker".into(),
                    certificate_sha256: own_pin.clone(),
                    allowed_operations: vec![],
                },
            )
            .await
            .unwrap();
        assert_eq!(
            reply(&connection, &job()).await.error.unwrap().code,
            "feature_unsupported"
        );
        client.close();
        serving.abort();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn required_direct_outgoing_blocks_legacy_and_reuses_negotiation_on_cached_session() {
    tokio::time::timeout(Duration::from_secs(10),async {
        for (supported,enforced) in [(false,false),(true,false),(true,true)] {
            let (_root,mut host,own,peer)=fixture();let own_pin=PeerPin::certificate(&own.0).to_hex();let peer_pin=PeerPin::certificate(&peer.0).to_hex();
            let server=DirectServer::bind("127.0.0.1:0".parse().unwrap(),"caller".into(),identity(&peer),vec![own.0.clone()],vec![PeerPolicy{node_id:"worker".into(),certificate_sha256:own_pin,allowed_operations:vec![Operation::NodePing,Operation::JobStatus]}]).unwrap();host.config.peers[0].address=Some(server.local_addr().unwrap());
            host.direct=Some(DirectClient::bind_with_revocations("127.0.0.1:0".parse().unwrap(),"worker".into(),identity(&own),vec![peer.0.clone()],host.revocations.clone()).unwrap());
            let calls=Arc::new(AtomicUsize::new(0));let pings=Arc::new(AtomicUsize::new(0));
            let serving={let calls=calls.clone();let pings=pings.clone();tokio::spawn(async move {
                let connection=server.accept().await.unwrap();while let Ok(mut stream)=connection.accept().await {let request=stream.recv().await.unwrap();let payload:Value=codec().decode(&request).unwrap();
                    let result=if request.operation==Operation::NodePing {pings.fetch_add(1,Ordering::SeqCst);assert_eq!(payload["capabilities"],json!(["revocations_v1"]));assert_eq!(payload["revocations_enforced"],true);RpcReply::success(json!({"node_id":"caller","capabilities":if supported {vec!["revocations_v1"]}else{vec![]},"revocations_enforced":enforced}))}else{calls.fetch_add(1,Ordering::SeqCst);RpcReply::<Value>::failure("executor_disabled","fixture reached")};
                    let mut response=RpcFrame{v:request.v,kind:FrameKind::Response,id:wire::new_id().unwrap(),source:request.target.clone(),target:request.source.clone(),operation:request.operation,in_reply_to:Some(request.id.clone()),source_certificate_sha256:request.target_certificate_sha256.clone(),target_certificate_sha256:request.source_certificate_sha256.clone(),retention:None,payload:String::new()};codec().encode(&mut response,&result).unwrap();stream.send(&response).await.unwrap();stream.finish().unwrap();
                }
            })};
            if supported&&enforced {assert!(host.rpc_once("caller",Operation::NodePing,Value::Null,None,Some(peer_pin.clone())).await.unwrap().ok);}
            for _ in 0..2 {let response=host.rpc_once("caller",Operation::JobStatus,json!({"job_id":wire::new_id().unwrap()}),None,Some(peer_pin.clone())).await.unwrap();assert_eq!(response.error.unwrap().code,if supported&&enforced {"executor_disabled"}else{"feature_unsupported"});}
            assert_eq!(calls.load(Ordering::SeqCst),if supported&&enforced {2}else{0});if supported&&enforced {assert_eq!(pings.load(Ordering::SeqCst),1);}
            host.direct.as_ref().unwrap().close();serving.abort();
        }
    }).await.unwrap();
}
