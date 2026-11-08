// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use lockyard_node::{cloud::NodeCloudClient, quic};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::{fs, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";

async fn fixture(case: &str) -> (String, Vec<u8>, tokio::task::JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    let identity =
        quic::generate_identity(&dir.path().join("identity"), vec!["localhost".into()]).unwrap();
    let certificate = fs::read(identity.certificate).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(identity.private_key).unwrap(),
        )),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut body = json!({"workspace_id":WORKSPACE,"key_id":hex(ring::digest::digest(&ring::digest::SHA256,key.public_key().as_ref()).as_ref()),"algorithm":"Ed25519","public_key":hex(key.public_key().as_ref())});
    match case {
        "workspace" => body["workspace_id"] = json!("22222222-2222-4222-8222-222222222222"),
        "key" => body["key_id"] = json!("0".repeat(64)),
        "algorithm" => body["algorithm"] = json!("unknown"),
        _ => {}
    }
    let capability = if case == "legacy" {
        ""
    } else {
        "Lockyard-Capabilities: revocations_v1\r\n"
    };
    let server = tokio::spawn(async move {
        let _dir = dir;
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                continue;
            };
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /api/v1/revocations/key "));
            assert!(request.contains("authorization: bearer owner-fixture\r\n"));
            assert!(request.contains("x-lockyard-session: owner\r\n"));
            let body = body.to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\n{capability}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            break;
        }
    });
    (url, certificate, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_bootstrap_uses_configured_tls_roots_and_binds_workspace_origin() {
    let (origin, root, server) = fixture("ok").await;
    let client =
        NodeCloudClient::new(&origin, "owner".into(), "owner-fixture".into(), &[root]).unwrap();
    let trust = tokio::task::spawn_blocking(move || client.bootstrap_revocation_trust(WORKSPACE))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(trust.workspace_id, WORKSPACE);
    assert_eq!(trust.server_origin, origin);
    assert_ne!(trust.key_id, trust.public_key);
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_bootstrap_rejects_legacy_wrong_workspace_key_and_algorithm() {
    for case in ["legacy", "workspace", "key", "algorithm"] {
        let (origin, root, server) = fixture(case).await;
        let client =
            NodeCloudClient::new(&origin, "owner".into(), "owner-fixture".into(), &[root]).unwrap();
        assert!(
            tokio::task::spawn_blocking(move || client.bootstrap_revocation_trust(WORKSPACE))
                .await
                .unwrap()
                .is_err(),
            "accepted {case}"
        );
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_only_enrollment_retains_refresh_credential_and_custom_roots() {
    let (origin, root, server) = fixture("ok").await;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("node-token"), "owner-fixture").unwrap();
    fixture_permissions(dir.path().join("node-token"), 0o600).unwrap();
    fs::write(dir.path().join("broker-root-0.der"), root).unwrap();
    let key = Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let configuration: lockyard_node::host::NodeConfig = serde_json::from_value(json!({
        "node_id":"owner","workspace":WORKSPACE,"state_dir":dir.path(),
        "certificate":dir.path().join("cert.der"),"private_key":dir.path().join("key.der"),
        "revocations":{"required":true,"poll_seconds":30,"max_offline_seconds":600,
            "trust":{"workspace_id":WORKSPACE,"server_origin":origin,
                "public_key":hex(key.public_key().as_ref()),
                "key_id":hex(ring::digest::digest(&ring::digest::SHA256,key.public_key().as_ref()).as_ref())}}
    })).unwrap();
    assert!(configuration.relay.is_none());
    let trust = tokio::task::spawn_blocking(move || {
        NodeCloudClient::for_revocations(&configuration)
            .unwrap()
            .bootstrap_revocation_trust(WORKSPACE)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(trust.server_origin, origin);
    server.await.unwrap();
}

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
