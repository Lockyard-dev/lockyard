// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;
#[tokio::test]
async fn direct_only_daemon_refreshes_on_sse_and_timer_without_relay() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = tempfile::tempdir().unwrap();
    let root_path = std::fs::canonicalize(root.path()).unwrap();
    let state_dir = root_path.join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let https_pair = {
        let p = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        (p.cert.der().to_vec(), p.signing_key.serialize_der())
    };
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(
            https_pair.0.clone(),
        )],
        rustls::pki_types::PrivatePkcs8KeyDer::from(https_pair.1).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let mut settings = config();
    settings.trust.server_origin = url.clone();
    settings.poll_seconds = 1;
    let epoch = Arc::new(AtomicU64::new(0));
    let events = Arc::new(tokio::sync::Notify::new());
    let gets = Arc::new(AtomicU64::new(0));
    let limited = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let http = {
        let epoch = epoch.clone();
        let events = events.clone();
        let gets = gets.clone();
        let limited = limited.clone();
        tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let epoch = epoch.clone();
                let events = events.clone();
                let gets = gets.clone();
                let limited = limited.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    let mut byte = [0; 1];
                    while request.len() < 8192 {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        request.push(byte[0]);
                        if request.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8(request).unwrap();
                    let path = text
                        .lines()
                        .next()
                        .unwrap()
                        .split_whitespace()
                        .nth(1)
                        .unwrap();
                    if !path.starts_with("/api/v1/revocations/events")
                        && limited.load(Ordering::SeqCst)
                    {
                        gets.fetch_add(1, Ordering::SeqCst);
                        let body = r#"{"code":"rate_limited","status":429}"#;
                        let response = format!(
                            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/problem+json\r\nRetry-After: 120\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        return;
                    }
                    let (kind, body) = if path.starts_with("/api/v1/revocations/events") {
                        let changed =
                            tokio::time::timeout(Duration::from_millis(500), events.notified())
                                .await
                                .is_ok();
                        (
                            "text/event-stream",
                            if changed {
                                format!(
                                    "event: revocations_changed\ndata: {{\"epoch\":{}}}\n\n",
                                    epoch.load(Ordering::SeqCst)
                                )
                            } else {
                                ": heartbeat\n\n".into()
                            },
                        )
                    } else {
                        gets.fetch_add(1, Ordering::SeqCst);
                        let parsed = url::Url::parse(&format!("https://fixture{path}")).unwrap();
                        let query = parsed
                            .query_pairs()
                            .collect::<std::collections::HashMap<_, _>>();
                        let nonce = query.get("nonce").unwrap();
                        let since = query.get("since").unwrap().parse::<u64>().unwrap();
                        let current = epoch.load(Ordering::SeqCst);
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let entries = if current > since {
                            vec![
                                serde_json::json!({"epoch":current,"ordinal":0,"target":{"kind":"cert_pin","certificate_sha256":"ff".repeat(32)},"revoked_at_ms":now}),
                            ]
                        } else {
                            vec![]
                        };
                        let page:RevocationPage=serde_json::from_value(serde_json::json!({"schema":1,"workspace_id":config().trust.workspace_id,"from_epoch":since,"epoch":current,"snapshot_id":"22222222-2222-2222-2222-222222222222","issued_at_ms":now,"valid_until_ms":now+60000,"nonce":nonce,"page_index":0,"next_cursor":null,"entries":entries})).unwrap();
                        let bytes = serde_json::to_vec(&page).unwrap();
                        let mut framed = b"lockyard-revocations-v1\0".to_vec();
                        framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                        framed.extend_from_slice(&bytes);
                        let signed = SignedDocument {
                            version: 1,
                            algorithm: "Ed25519".into(),
                            key_id: config().trust.key_id,
                            payload: STANDARD.encode(bytes),
                            signature: STANDARD.encode(signer().sign(&framed).as_ref()),
                        };
                        ("application/json", serde_json::to_string(&signed).unwrap())
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nLockyard-Capabilities: revocations_v1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        })
    };
    std::fs::write(state_dir.join("broker-root-0.der"), https_pair.0).unwrap();
    std::fs::write(state_dir.join("node-token"), b"fixture").unwrap();
    std::fs::set_permissions(
        state_dir.join("node-token"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let identity =
        lockyard_node::quic::generate_identity(&state_dir.join("identity"), vec!["worker".into()])
            .unwrap();
    let node:lockyard_node::host::NodeConfig=serde_json::from_value(serde_json::json!({"node_id":"worker","workspace":config().trust.workspace_id,"state_dir":state_dir,"listen":null,"certificate":identity.certificate,"private_key":identity.private_key,"relay":null,"revocations":settings})).unwrap();
    let path = root_path.join("node.toml");
    std::fs::write(&path, toml::to_string(&node).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key_dir = root_path.join("config/lockyard/keys");
    std::fs::create_dir_all(&key_dir).unwrap();
    for dir in [key_dir.parent().unwrap(), key_dir.as_path()] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key_file = key_dir.join(format!("{}.key", config().trust.workspace_id));
    std::fs::write(&key_file, [7; 32]).unwrap();
    std::fs::set_permissions(key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut daemon = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "runtime::runtime_daemon_child", "--nocapture"])
        .env("XDG_CONFIG_HOME", root_path.join("config"))
        .env("LOCKYARD_REVOCATION_DAEMON_CONFIG", &path)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(status) = lockyard_node::host::status(&path).await
                && status
                    .revocations
                    .as_ref()
                    .is_some_and(|s| s.complete_epoch == 0 && s.age_seconds.is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let initial = gets.load(Ordering::SeqCst);
    epoch.store(1, Ordering::SeqCst);
    events.notify_one();
    tokio::time::timeout(Duration::from_millis(750), async {
        loop {
            if lockyard_node::host::status(&path)
                .await
                .unwrap()
                .revocations
                .unwrap()
                .complete_epoch
                == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(gets.load(Ordering::SeqCst) > initial);
    let refreshed = gets.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(gets.load(Ordering::SeqCst) > refreshed);
    limited.store(true, Ordering::SeqCst);
    events.notify_one();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if lockyard_node::host::status(&path)
                .await
                .unwrap()
                .revocations
                .unwrap()
                .refresh_failures_total
                .contains_key("rate_limited")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let blocked = gets.load(Ordering::SeqCst);
    for _ in 0..20 {
        events.notify_one();
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        gets.load(Ordering::SeqCst),
        blocked,
        "timer or SSE wake bypassed Retry-After"
    );
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    http.abort();
    let _ = http.await;
}
#[test]
fn runtime_daemon_child() {
    if let Some(path) = std::env::var_os("LOCKYARD_REVOCATION_DAEMON_CONFIG") {
        let config = lockyard_node::host::NodeConfig::load(std::path::Path::new(&path)).unwrap();
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(lockyard_node::host::serve(config))
            .unwrap();
    }
}
