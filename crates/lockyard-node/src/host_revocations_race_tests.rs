// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;
use crate::{
    provenance::SigningKey,
    quic::Identity,
    revocations::{
        RevocationConfig, RevocationManager, RevocationPage, RevocationTrust, SignedDocument,
    },
};

fn sign(signer: &SigningKey, page: &RevocationPage) -> SignedDocument {
    serde_json::from_value(
        serde_json::to_value(
            signer
                .sign_document(lockyard_cloud_client::revocations::DOMAIN, page)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn revoked_during_direct_connect_cannot_fall_back_to_relay() {
    tokio::time::timeout(Duration::from_secs(4), async {
        let (_root, mut host) = tests::fixture();
        let workspace = "11111111-1111-1111-1111-111111111111";
        host.config.workspace = workspace.into();
        host.codec =
            PayloadCodec::new(workspace.into(), WorkspaceKey::from_entropy([7; 32])).unwrap();
        host.config.rpc_timeout_seconds = 1;
        let own = rcgen::generate_simple_self_signed(vec!["worker".into()]).unwrap();
        let own_certificate = own.cert.der().to_vec();
        host.certificate_sha256 = PeerPin::certificate(&own_certificate).to_hex();
        let signer =
            SigningKey::generate(&host.config.state_dir.join("race-revocation-key.pk8")).unwrap();
        let key = signer.trusted_key();
        let settings = RevocationConfig {
            required: true,
            poll_seconds: 30,
            max_offline_seconds: 600,
            trust: RevocationTrust {
                workspace_id: workspace.into(),
                key_id: key.key_id().unwrap(),
                public_key: key.public_key,
                server_origin: "https://example.test".into(),
            },
        };
        let state = RevocationManager::open(settings.clone(), &host.config.state_dir).unwrap();
        let now = wall_ms().unwrap();
        let nonce = "aa".repeat(32);
        let mut page = RevocationPage {
            schema: 1,
            workspace_id: workspace.into(),
            from_epoch: 0,
            epoch: 0,
            snapshot_id: "22222222-2222-2222-2222-222222222222".into(),
            issued_at_ms: now,
            valid_until_ms: now + 60_000,
            nonce: nonce.clone(),
            page_index: 0,
            next_cursor: None,
            entries: vec![],
        };
        state
            .refresh(&[sign(&signer, &page)], &nonce, now, Instant::now())
            .unwrap();
        host.config.revocations = Some(settings);
        host.revocations = Some(state.clone());
        host.direct = Some(
            DirectClient::bind_with_revocations(
                "127.0.0.1:0".parse().unwrap(),
                "worker".into(),
                Identity::from_der(vec![own_certificate], own.signing_key.serialize_der()).unwrap(),
                vec![fs::read(&host.config.peers[0].certificate).unwrap()],
                Some(state.clone()),
            )
            .unwrap(),
        );
        let stalled = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        host.config.peers[0].address = Some(stalled.local_addr().unwrap());
        let pin = host.config.peers[0].certificate_sha256.clone();
        page.epoch = 1;
        page.nonce.clear();
        page.entries
            .push(lockyard_cloud_client::revocations::RevocationEntry {
                epoch: 1,
                ordinal: 0,
                target: lockyard_cloud_client::revocations::RevocationTarget::CertPin {
                    certificate_sha256: pin.clone(),
                },
                revoked_at_ms: now,
            });
        let document = sign(&signer, &page);
        let applying = tokio::spawn(async move {
            // Receiving ClientHello proves rpc_once already passed its initial deny check.
            let mut bytes = [0; 2048];
            stalled.recv_from(&mut bytes).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            state.apply_additive(&document).unwrap();
        });
        let response = host
            .rpc_once(
                "caller",
                Operation::JobStatus,
                json!({"job_id":wire::new_id().unwrap()}),
                None,
                Some(pin),
            )
            .await;
        applying.await.unwrap();
        let response =
            response.expect("known revocation must return revoked before selecting absent relay");
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().code, "revoked");
        assert!(host.pending.lock().unwrap().is_empty());
        assert_eq!(
            fs::read_dir(host.config.state_dir.join("relay-outbox"))
                .unwrap()
                .count(),
            0
        );
        host.direct.as_ref().unwrap().close();
    })
    .await
    .unwrap();
}
