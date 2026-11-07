use lockyard_node::{cloud::NodeCloudClient, quic};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::{fs, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[test]
fn key_staging_is_private_create_only_and_rejects_links_and_open_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("private");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let key = lockyard_cloud_client::WorkspaceKey::from_entropy([9; 32]);
    let destination = directory.join("workspace.key");
    key.copy_to_private(&destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), [9; 32]);
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(key.copy_to_private(&destination).is_err());
    let link = directory.join("key-link");
    symlink(&destination, &link).unwrap();
    assert!(key.copy_to_private(&link).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(key.copy_to_private(&directory.join("other.key")).is_err());
    assert_eq!(fs::read(destination).unwrap(), [9; 32]);
}

async fn fixture(status: u16, count: usize) -> (String, Vec<u8>, tokio::task::JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    let identity =
        quic::generate_identity(&dir.path().join("identity"), vec!["localhost".into()]).unwrap();
    let certificate = fs::read(identity.certificate).unwrap();
    let pin = quic::PeerPin::certificate(&certificate).to_hex();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        fs::read(identity.private_key).unwrap(),
    ));
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![CertificateDer::from(certificate.clone())], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let server = tokio::spawn(async move {
        let _dir = dir;
        let mut accepted = 0;
        while accepted < count {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                continue;
            };
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read_exact(&mut byte).await.is_err() {
                    break;
                }
                bytes.push(byte[0]);
                assert!(bytes.len() < 8192);
            }
            let headers = String::from_utf8(bytes).unwrap();
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("authorization: bearer fixture-node-token\r\n")
            );
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("x-lockyard-session: worker\r\n")
            );
            let entry = json!({"node_id":"worker","certificate_sha256":pin,"quic_endpoint":null,
                "registered_at":"2026-11-07T00:00:00Z","last_seen_at":"2026-11-07T00:00:00Z"});
            let response = if headers.starts_with("POST /api/v1/nodes/register ") {
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await.unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["node_id"], "worker");
                assert_eq!(body["certificate_sha256"], pin);
                assert!(!body.to_string().contains("fixture-node-token"));
                entry
            } else {
                assert!(headers.starts_with("GET /api/v1/nodes "));
                json!([entry])
            };
            let body = serde_json::to_vec(&response).unwrap();
            let headers = format!(
                "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nLocation: https://must-not-follow.invalid/\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
            accepted += 1;
        }
    });
    (url, certificate, server)
}

#[tokio::test]
async fn enrollment_and_directory_use_verified_tls_and_bound_credentials() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (url, certificate, server) = fixture(200, 2).await;
        let untrusted =
            NodeCloudClient::new(&url, "worker".into(), "fixture-node-token".into(), &[]).unwrap();
        assert!(
            untrusted.directory().await.is_err(),
            "untrusted TLS certificate was accepted"
        );
        let client = NodeCloudClient::new(
            &url,
            "worker".into(),
            "fixture-node-token".into(),
            std::slice::from_ref(&certificate),
        )
        .unwrap();
        let entry = client.register(certificate.clone(), None).await.unwrap();
        assert_eq!(
            entry.certificate_sha256,
            quic::PeerPin::certificate(&certificate).to_hex()
        );
        let entries = client.directory().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].node_id, "worker");
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn metadata_api_refuses_redirects_instead_of_forwarding_the_credential() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (url, certificate, server) = fixture(307, 1).await;
        let client = NodeCloudClient::new(
            &url,
            "worker".into(),
            "fixture-node-token".into(),
            &[certificate],
        )
        .unwrap();
        let error = client.directory().await.err().unwrap();
        assert!(!error.to_string().contains("fixture-node-token"));
        assert!(error.to_string().contains("status"));
        server.await.unwrap();
    })
    .await
    .unwrap();
}
