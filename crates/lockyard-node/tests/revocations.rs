// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use base64::{Engine, engine::general_purpose::STANDARD};
use lockyard_cloud_client::revocations::{RevocationPage, RevocationTrust, SignedDocument};
use lockyard_node::{
    quic::{DirectClient, DirectServer, Identity, PeerPin, PeerPolicy},
    revocations::{RevocationConfig, RevocationManager},
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn private_temp() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fixture_permissions(root.path(), 0o700).unwrap();
    root
}

#[test]
fn legacy_uppercase_peer_pin_has_the_same_revoked_sdk_code() {
    let root = private_temp();
    let state = RevocationManager::open(config(), root.path()).unwrap();
    let pin = "ab".repeat(32);
    state
        .apply_additive(&doc(1, "", std::slice::from_ref(&pin)))
        .unwrap();
    for configured in [pin.clone(), pin.to_ascii_uppercase()] {
        assert_eq!(
            state.authorize_pin(&configured).unwrap_err().to_string(),
            "revoked"
        );
    }
}
fn signer() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn config() -> RevocationConfig {
    let key = signer();
    RevocationConfig {
        required: true,
        poll_seconds: 30,
        max_offline_seconds: 600,
        trust: RevocationTrust {
            workspace_id: "11111111-1111-1111-1111-111111111111".into(),
            key_id: hex(
                ring::digest::digest(&ring::digest::SHA256, key.public_key().as_ref()).as_ref(),
            ),
            public_key: hex(key.public_key().as_ref()),
            server_origin: "https://example.test".into(),
        },
    }
}
fn doc(epoch: u64, nonce: &str, pins: &[String]) -> SignedDocument {
    let entries=pins.iter().enumerate().map(|(ordinal,pin)|serde_json::json!({"epoch":epoch,"ordinal":ordinal,"target":{"kind":"cert_pin","certificate_sha256":pin},"revoked_at_ms":100000})).collect::<Vec<_>>();
    let page:RevocationPage=serde_json::from_value(serde_json::json!({"schema":1,"workspace_id":config().trust.workspace_id,"from_epoch":0,"epoch":epoch,"snapshot_id":"22222222-2222-2222-2222-222222222222","issued_at_ms":100000,"valid_until_ms":160000,"nonce":nonce,"page_index":0,"next_cursor":null,"entries":entries})).unwrap();
    let bytes = serde_json::to_vec(&page).unwrap();
    let mut framed = b"lockyard-revocations-v1\0".to_vec();
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(&bytes);
    SignedDocument {
        version: 1,
        algorithm: "Ed25519".into(),
        key_id: config().trust.key_id,
        payload: STANDARD.encode(bytes),
        signature: STANDARD.encode(signer().sign(&framed).as_ref()),
    }
}
const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
#[test]
fn offline_config_defaults_to_600_and_rejects_out_of_range_before_persisting() {
    let mut json = serde_json::to_value(config()).unwrap();
    json.as_object_mut().unwrap().remove("max_offline_seconds");
    let defaults: RevocationConfig = serde_json::from_value(json).unwrap();
    assert_eq!(defaults.max_offline_seconds, 600);
    defaults.validate().unwrap();
    for seconds in [0, 1, 59, 86_401, u64::MAX] {
        let root = private_temp();
        let mut invalid = config();
        invalid.max_offline_seconds = seconds;
        assert_eq!(
            RevocationManager::open(invalid, root.path())
                .err()
                .expect("out-of-range grace must be rejected")
                .to_string(),
            "invalid_revocation_request",
            "grace={seconds}"
        );
        assert!(!root.path().join("revocations.json").exists());
    }
}
#[test]
fn configured_offline_limit_fences_at_its_boundary() {
    let pin = "bb".repeat(32);
    for seconds in [60, 3_600, 86_400] {
        let root = private_temp();
        let mut configured = config();
        configured.max_offline_seconds = seconds;
        let state = RevocationManager::open(configured.clone(), root.path()).unwrap();
        for (age, nonce) in [(seconds - 1, NONCE.to_string()), (seconds, "dd".repeat(32))] {
            state
                .refresh(
                    &[doc(1, &nonce, &["ee".repeat(32)])],
                    &nonce,
                    100001,
                    Instant::now() - Duration::from_secs(age),
                )
                .unwrap();
            if age < seconds {
                state.authorize_pin(&pin).unwrap();
                assert!(!state.snapshot().unwrap().stale);
            } else {
                assert_eq!(
                    state.authorize_pin(&pin).unwrap_err().to_string(),
                    "revocations_stale"
                );
                assert!(state.snapshot().unwrap().stale);
            }
        }
        drop(state);
        let restarted = RevocationManager::open(configured, root.path()).unwrap();
        assert_eq!(
            restarted.authorize_pin(&pin).unwrap_err().to_string(),
            "revocations_stale"
        );
        assert_eq!(
            restarted
                .authorize_pin(&"ee".repeat(32))
                .unwrap_err()
                .to_string(),
            "revoked"
        );
    }
}
#[test]
fn poll_wake_offline_restart_and_replay_fence() {
    let tmp = private_temp();
    let state = RevocationManager::open(config(), tmp.path()).unwrap();
    let pin = "bb".repeat(32);
    assert_eq!(
        state.authorize_pin(&pin).unwrap_err().to_string(),
        "revocations_stale"
    );
    state
        .refresh(
            &[doc(1, NONCE, &["ee".repeat(32)])],
            NONCE,
            100001,
            Instant::now() - Duration::from_secs(599),
        )
        .unwrap();
    state.authorize_pin(&pin).unwrap();
    state
        .refresh(
            &[doc(1, &"dd".repeat(32), &["ee".repeat(32)])],
            &"dd".repeat(32),
            100001,
            Instant::now() - Duration::from_secs(600),
        )
        .unwrap();
    assert_eq!(
        state.authorize_pin(&pin).unwrap_err().to_string(),
        "revocations_stale"
    );
    state
        .apply_additive(&doc(2, "", std::slice::from_ref(&pin)))
        .unwrap();
    assert_eq!(
        state.authorize_pin(&pin).unwrap_err().to_string(),
        "revoked"
    );
    assert_eq!(
        state
            .authorize_pin(&"cc".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
    assert_eq!(state.snapshot().unwrap().complete_epoch, 1);
    assert_eq!(state.snapshot().unwrap().observed_epoch, 2);
    assert!(
        state
            .refresh(&[doc(0, NONCE, &[])], NONCE, 100001, Instant::now())
            .is_err()
    );
    drop(state);
    let restarted = RevocationManager::open(config(), tmp.path()).unwrap();
    assert_eq!(
        restarted.authorize_pin(&pin).unwrap_err().to_string(),
        "revoked"
    );
    assert_eq!(
        restarted
            .authorize_pin(&"cc".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
    let mut other = config();
    other.trust.public_key = "00".repeat(32);
    assert!(RevocationManager::open(other, tmp.path()).is_err());
}
fn pair() -> (Vec<u8>, Vec<u8>) {
    let p = rcgen::generate_simple_self_signed(vec!["lockyard-node".into()]).unwrap();
    (p.cert.der().to_vec(), p.signing_key.serialize_der())
}
fn identity(p: &(Vec<u8>, Vec<u8>)) -> Identity {
    Identity::from_der(vec![p.0.clone()], p.1.clone()).unwrap()
}
fn peer(name: &str, p: &(Vec<u8>, Vec<u8>)) -> PeerPolicy {
    PeerPolicy {
        node_id: name.into(),
        certificate_sha256: PeerPin::certificate(&p.0).to_hex(),
        allowed_operations: vec![],
    }
}
async fn connected() -> (
    tempfile::TempDir,
    Arc<RevocationManager>,
    DirectClient,
    DirectServer,
    lockyard_node::quic::DirectConnection,
    lockyard_node::quic::DirectConnection,
) {
    let tmp = private_temp();
    let state = RevocationManager::open(config(), tmp.path()).unwrap();
    state
        .refresh(&[doc(0, NONCE, &[])], NONCE, 100001, Instant::now())
        .unwrap();
    let a = pair();
    let b = pair();
    let server = DirectServer::bind_with_revocations(
        "127.0.0.1:0".parse().unwrap(),
        "worker".into(),
        identity(&a),
        vec![b.0.clone()],
        vec![peer("controller", &b)],
        Some(state.clone()),
    )
    .unwrap();
    let client = DirectClient::bind_with_revocations(
        "127.0.0.1:0".parse().unwrap(),
        "controller".into(),
        identity(&b),
        vec![a.0.clone()],
        Some(state.clone()),
    )
    .unwrap();
    let (out, inc) = tokio::join!(
        client.connect(
            server.local_addr().unwrap(),
            "lockyard-node",
            peer("worker", &a)
        ),
        server.accept()
    );
    (tmp, state, client, server, out.unwrap(), inc.unwrap())
}
#[tokio::test]
async fn signed_revocation_closes_live_sessions_within_five_seconds() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_tmp, state, client, server, out, inc) = connected().await;
        let start = Instant::now();
        state
            .apply_additive(&doc(
                1,
                "",
                &[
                    out.peer().certificate_sha256.clone(),
                    inc.peer().certificate_sha256.clone(),
                ],
            ))
            .unwrap();
        assert_eq!(out.open().await.err().unwrap().to_string(), "revoked");
        assert_eq!(inc.open().await.err().unwrap().to_string(), "revoked");
        assert_eq!(out.closed().await, "revoked");
        assert_eq!(inc.closed().await, "revoked");
        assert!(start.elapsed() < Duration::from_secs(5));
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn revoked_pin_is_denied_during_handshake_and_cached_reuse_race() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_tmp, state, client, server, out, _inc) = connected().await;
        let policy = out.peer().clone();
        state
            .apply_additive(&doc(
                1,
                "",
                std::slice::from_ref(&policy.certificate_sha256),
            ))
            .unwrap();
        assert_eq!(
            client
                .connect(server.local_addr().unwrap(), "lockyard-node", policy)
                .await
                .err()
                .unwrap()
                .to_string(),
            "revoked"
        );
        assert_eq!(out.open().await.err().unwrap().to_string(), "revoked");
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn local_identity_revocation_closes_outgoing_and_incoming_without_peer_binding() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let tmp = private_temp();
        let state = RevocationManager::open(config(), tmp.path()).unwrap();
        state
            .refresh(&[doc(0, NONCE, &[])], NONCE, 100001, Instant::now())
            .unwrap();
        let a = pair();
        let b = pair();
        let own_pin = PeerPin::certificate(&b.0).to_hex();
        let server = DirectServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&a),
            vec![b.0.clone()],
            vec![peer("controller", &b)],
        )
        .unwrap();
        let client = DirectClient::bind_with_revocations(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&b),
            vec![a.0.clone()],
            Some(state.clone()),
        )
        .unwrap();
        let policy = peer("worker", &a);
        let (out, inc) = tokio::join!(
            client.connect(
                server.local_addr().unwrap(),
                "lockyard-node",
                policy.clone()
            ),
            server.accept()
        );
        let out = out.unwrap();
        let inc = inc.unwrap();
        state.apply_additive(&doc(1, "", &[own_pin])).unwrap();
        assert_eq!(out.open().await.err().unwrap().to_string(), "revoked");
        assert_eq!(out.closed().await, "revoked");
        assert_eq!(inc.closed().await, "revoked");
        assert_eq!(
            client
                .connect(server.local_addr().unwrap(), "lockyard-node", policy)
                .await
                .err()
                .unwrap()
                .to_string(),
            "revoked"
        );
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn incoming_tls_denies_revoked_pin_before_exposing_authenticated_connection() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let tmp = private_temp();
        let state = RevocationManager::open(config(), tmp.path()).unwrap();
        state
            .refresh(&[doc(0, NONCE, &[])], NONCE, 100001, Instant::now())
            .unwrap();
        let a = pair();
        let b = pair();
        state
            .apply_additive(&doc(1, "", &[PeerPin::certificate(&b.0).to_hex()]))
            .unwrap();
        let server = DirectServer::bind_with_revocations(
            "127.0.0.1:0".parse().unwrap(),
            "worker".into(),
            identity(&a),
            vec![b.0.clone()],
            vec![peer("controller", &b)],
            Some(state),
        )
        .unwrap();
        let client = DirectClient::bind(
            "127.0.0.1:0".parse().unwrap(),
            "controller".into(),
            identity(&b),
            vec![a.0.clone()],
        )
        .unwrap();
        let (out, inc) = tokio::join!(
            client.connect(
                server.local_addr().unwrap(),
                "lockyard-node",
                peer("worker", &a)
            ),
            server.accept()
        );
        assert!(inc.is_err());
        if let Ok(out) = out {
            let _ = out.closed().await;
            assert!(out.open().await.is_err());
        }
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn concurrent_cached_returns_cannot_open_stream_after_signed_apply() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_tmp, state, client, server, out, _inc) = connected().await;
        let policy = out.peer().clone();
        let client = Arc::new(client);
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let client = client.clone();
            let barrier = barrier.clone();
            let policy = policy.clone();
            let address = server.local_addr().unwrap();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                client.connect(address, "lockyard-node", policy).await
            }));
        }
        barrier.wait().await;
        state
            .apply_additive(&doc(1, "", &[policy.certificate_sha256]))
            .unwrap();
        for task in tasks {
            match task.await.unwrap() {
                Ok(conn) => assert_eq!(conn.open().await.err().unwrap().to_string(), "revoked"),
                Err(error) => assert_eq!(error.to_string(), "revoked"),
            }
        }
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[test]
fn repeated_fresh_nonce_snapshots_do_not_grow_persisted_history() {
    let tmp = private_temp();
    let state = RevocationManager::open(config(), tmp.path()).unwrap();
    for index in 0..200 {
        let nonce = format!("{index:064x}");
        state
            .refresh(&[doc(0, &nonce, &[])], &nonce, 100001, Instant::now())
            .unwrap();
    }
    assert!(
        std::fs::metadata(tmp.path().join("revocations.json"))
            .unwrap()
            .len()
            < 4096
    );
}
#[tokio::test]
async fn stale_cached_session_denies_new_rpc_and_requires_fresh_signed_recovery() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_tmp, state, client, server, out, _inc) = connected().await;
        let nonce = "dd".repeat(32);
        state
            .refresh(
                &[doc(0, &nonce, &[])],
                &nonce,
                100001,
                Instant::now() - Duration::from_secs(601),
            )
            .unwrap();
        assert_eq!(
            out.open().await.err().unwrap().to_string(),
            "revocations_stale"
        );
        assert_eq!(
            client
                .connect(
                    server.local_addr().unwrap(),
                    "lockyard-node",
                    out.peer().clone()
                )
                .await
                .err()
                .unwrap()
                .to_string(),
            "revocations_stale"
        );
        state.reject_clock_skew().unwrap();
        assert_eq!(
            out.open().await.err().unwrap().to_string(),
            "revocation_clock_skew"
        );
        let nonce = "ee".repeat(32);
        state
            .refresh(&[doc(0, &nonce, &[])], &nonce, 100001, Instant::now())
            .unwrap();
        out.open().await.unwrap();
        client.close();
        server.close();
    })
    .await
    .unwrap();
}
#[test]
fn signed_nonce_replay_and_failed_persistence_cannot_extend_freshness() {
    let tmp = private_temp();
    let state = RevocationManager::open(config(), tmp.path()).unwrap();
    let signed = doc(0, NONCE, &[]);
    state
        .refresh(
            std::slice::from_ref(&signed),
            NONCE,
            100001,
            Instant::now() - Duration::from_secs(601),
        )
        .unwrap();
    assert!(
        state
            .refresh(&[signed], NONCE, 100001, Instant::now())
            .is_err()
    );
    assert_eq!(
        state
            .authorize_pin(&"bb".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
    std::fs::create_dir(tmp.path().join("revocations.json.tmp")).unwrap();
    let nonce = "dd".repeat(32);
    assert!(
        state
            .refresh(
                &[doc(1, &nonce, &["ee".repeat(32)])],
                &nonce,
                100001,
                Instant::now()
            )
            .is_err()
    );
    assert_eq!(state.snapshot().unwrap().complete_epoch, 0);
    assert_eq!(
        state
            .authorize_pin(&"bb".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
    assert_eq!(
        state
            .authorize_pin(&"ee".repeat(32))
            .unwrap_err()
            .to_string(),
        "revoked"
    );
}

#[test]
fn retry_after_cooldown_survives_wakes_without_extending_offline_grace() {
    let tmp = private_temp();
    let state = RevocationManager::open(config(), tmp.path()).unwrap();
    state
        .refresh(
            &[doc(0, NONCE, &[])],
            NONCE,
            100001,
            Instant::now() - Duration::from_secs(601),
        )
        .unwrap();
    let limited = lockyard_cloud_client::revocations::RevocationError {
        code: "rate_limited".into(),
        commit_unknown: false,
        retry_after: Some(120),
    };
    state.record_http_failure(false, &limited).unwrap();
    state.record_http_failure(true, &limited).unwrap();
    for _ in 0..100 {
        state.wake();
    }
    assert!(state.retry_delay(false).unwrap() > Duration::from_secs(119));
    assert!(state.retry_delay(true).unwrap() > Duration::from_secs(119));
    assert_eq!(
        state
            .authorize_pin(&"bb".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
    assert_eq!(
        state
            .snapshot()
            .unwrap()
            .refresh_failures_total
            .get("rate_limited"),
        Some(&1)
    );
    let revoked = lockyard_cloud_client::revocations::RevocationError {
        code: "credential_revoked".into(),
        commit_unknown: false,
        retry_after: None,
    };
    state.record_http_failure(false, &revoked).unwrap();
    assert_eq!(state.retry_delay(false).unwrap(), Duration::MAX);
    assert_eq!(state.retry_delay(true).unwrap(), Duration::MAX);
}
#[test]
fn explicit_owner_signer_reprovision_preserves_denies_and_requires_new_key_refresh() {
    let tmp = private_temp();
    let state = RevocationManager::open(config(), tmp.path()).unwrap();
    let pin = "bb".repeat(32);
    state
        .refresh(
            &[doc(1, NONCE, std::slice::from_ref(&pin))],
            NONCE,
            100001,
            Instant::now(),
        )
        .unwrap();
    drop(state);
    let new_key = Ed25519KeyPair::from_seed_unchecked(&[43; 32]).unwrap();
    let mut updated = config();
    updated.trust.public_key = hex(new_key.public_key().as_ref());
    updated.trust.key_id =
        hex(ring::digest::digest(&ring::digest::SHA256, new_key.public_key().as_ref()).as_ref());
    let state = RevocationManager::open(updated.clone(), tmp.path()).unwrap();
    assert_eq!(state.snapshot().unwrap().complete_epoch, 1);
    assert_eq!(state.refresh_from_epoch().unwrap(), 0);
    assert_eq!(
        state.authorize_pin(&pin).unwrap_err().to_string(),
        "revoked"
    );
    assert_eq!(
        state
            .authorize_pin(&"cc".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
    assert!(
        state
            .apply_additive(&doc(2, "", &["cc".repeat(32)]))
            .is_err()
    );
    let nonce = "dd".repeat(32);
    let mut signed = doc(1, &nonce, std::slice::from_ref(&pin));
    let bytes = STANDARD.decode(&signed.payload).unwrap();
    let mut framed = b"lockyard-revocations-v1\0".to_vec();
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(&bytes);
    signed.key_id = updated.trust.key_id.clone();
    signed.signature = STANDARD.encode(new_key.sign(&framed).as_ref());
    state
        .refresh(&[signed], &nonce, 100001, Instant::now())
        .unwrap();
    state.authorize_pin(&"cc".repeat(32)).unwrap();
    drop(state);
    let restarted = RevocationManager::open(updated, tmp.path()).unwrap();
    assert_eq!(
        restarted.authorize_pin(&pin).unwrap_err().to_string(),
        "revoked"
    );
    assert_eq!(
        restarted
            .authorize_pin(&"cc".repeat(32))
            .unwrap_err()
            .to_string(),
        "revocations_stale"
    );
}

#[path = "revocations/runtime.rs"]
mod runtime;

fn fixture_permissions(path: impl AsRef<std::path::Path>, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let _ = mode;
        lockyard_core::windows::secure_owned(path.as_ref())
    }
}
