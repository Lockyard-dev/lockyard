use lockyard_cloud_client::{Client, revocations::*};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

const WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";
fn read_headers(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() <= 8192);
    }
    String::from_utf8(bytes).unwrap()
}
fn fixture(origin: &str) -> (Ed25519KeyPair, RevocationTrust) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let public_key = hex(key.public_key().as_ref());
    let key_id =
        hex(ring::digest::digest(&ring::digest::SHA256, key.public_key().as_ref()).as_ref());
    (
        key,
        RevocationTrust {
            workspace_id: WORKSPACE.into(),
            key_id,
            public_key,
            server_origin: origin.into(),
        },
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn page(nonce: &str) -> RevocationPage {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    RevocationPage {
        schema: 1,
        workspace_id: WORKSPACE.into(),
        from_epoch: 0,
        epoch: 1,
        snapshot_id: "22222222-2222-4222-8222-222222222222".into(),
        issued_at_ms: now,
        valid_until_ms: now + 60_000,
        nonce: nonce.into(),
        page_index: 0,
        next_cursor: None,
        entries: vec![RevocationEntry {
            epoch: 1,
            ordinal: 0,
            target: RevocationTarget::CertPin {
                certificate_sha256: "a".repeat(64),
            },
            revoked_at_ms: now,
        }],
    }
}
fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let x = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | (c.get(2).copied().unwrap_or(0) as u32);
        for shift in [18, 12, 6, 0] {
            out.push(T[((x >> shift) & 63) as usize] as char);
        }
        if c.len() < 3 {
            out.truncate(out.len() - (3 - c.len()));
            for _ in 0..3 - c.len() {
                out.push('=');
            }
        }
    }
    out
}
fn signed(key: &Ed25519KeyPair, trust: &RevocationTrust, page: &RevocationPage) -> SignedDocument {
    let payload = serde_json::to_vec(page).unwrap();
    let mut framed = b"lockyard-revocations-v1\0".to_vec();
    framed.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    framed.extend_from_slice(&payload);
    SignedDocument {
        version: 1,
        algorithm: "Ed25519".into(),
        key_id: trust.key_id.clone(),
        payload: b64(&payload),
        signature: b64(key.sign(&framed).as_ref()),
    }
}
#[test]
fn golden_signature_tamper_wrong_key_workspace_and_noncanonical_rejected() {
    let origin = "https://fixture.example";
    let (key, trust) = fixture(origin);
    let mut page = page(&"b".repeat(64));
    let doc = signed(&key, &trust, &page);
    assert_eq!(verify_document(&doc, &trust, origin).unwrap(), page);
    assert!(verify_document(&doc, &trust, "https://other.example").is_err());
    let mut wrong = trust.clone();
    wrong.public_key = "00".repeat(32);
    assert!(verify_document(&doc, &wrong, origin).is_err());
    let mut tamper = doc.clone();
    tamper.signature.replace_range(
        0..1,
        if doc.signature.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert!(verify_document(&tamper, &trust, origin).is_err());
    page.workspace_id = "33333333-3333-4333-8333-333333333333".into();
    assert_eq!(
        verify_document(&signed(&key, &trust, &page), &trust, origin)
            .unwrap_err()
            .code(),
        "revocation_signer_untrusted"
    );
    let mut union = serde_json::to_value(&page.entries[0].target).unwrap();
    union["unexpected"] = json!(true);
    assert!(serde_json::from_value::<RevocationTarget>(union).is_err());
}
#[test]
fn signed_http_refresh_uses_nonce_session_capability_and_rejects_legacy() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (key, trust) = fixture(&origin);
    let server_trust = trust.clone();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_headers(&mut stream);
        assert!(
            request
                .to_lowercase()
                .contains("x-lockyard-session: fixture")
        );
        assert!(request.contains("Bearer fixture-token"));
        let path = request.split_whitespace().nth(1).unwrap();
        assert!(path.starts_with("/api/v1/revocations?since=0&nonce="));
        let nonce = path.split("nonce=").nth(1).unwrap();
        assert_eq!(nonce.len(), 64);
        let body = serde_json::to_string(&signed(&key, &server_trust, &page(nonce))).unwrap();
        write!(stream,"HTTP/1.1 200 OK\r\nLockyard-Capabilities: revocations_v1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
    });
    let client = Client::new(&origin, "fixture-token".into()).unwrap();
    let docs = client
        .revocation_refresh_documents("fixture", 0, &trust)
        .unwrap();
    assert_eq!(docs.len(), 1);
    worker.join().unwrap();
}
#[test]
fn refresh_rejects_signed_nonce_replay_and_missing_capability() {
    for capability in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (key, trust) = fixture(&origin);
        let st = trust.clone();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_headers(&mut stream);
            let body = serde_json::to_string(&signed(&key, &st, &page(&"0".repeat(64)))).unwrap();
            let cap = if capability {
                "Lockyard-Capabilities: revocations_v1\r\n"
            } else {
                ""
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\n{cap}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let client = Client::new(&origin, "fixture-token".into()).unwrap();
        assert!(
            client
                .revocation_refresh_documents("fixture", 0, &trust)
                .is_err()
        );
        worker.join().unwrap();
    }
}
fn signed_raw(
    key: &Ed25519KeyPair,
    trust: &RevocationTrust,
    payload: &[u8],
    domain: &[u8],
) -> SignedDocument {
    let mut framed = domain.to_vec();
    framed.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    framed.extend_from_slice(payload);
    SignedDocument {
        version: 1,
        algorithm: "Ed25519".into(),
        key_id: trust.key_id.clone(),
        payload: b64(payload),
        signature: b64(key.sign(&framed).as_ref()),
    }
}
#[test]
fn signed_noncanonical_unknown_duplicate_and_wrong_domain_are_rejected() {
    let origin = "https://fixture.example";
    let (key, trust) = fixture(origin);
    let p = page(&"a".repeat(64));
    let raw = serde_json::to_string(&p).unwrap();
    let variants = [
        format!(" {raw}"),
        raw.replacen("{", "{\"schema\":1,", 1),
        raw.replacen("{", "{\"unknown\":1,", 1),
        raw.replacen("\"schema\":1", "\"schema\":1.0", 1),
        raw.replace("\"schema\":1,\"workspace_id\"", "\"workspace_id\""),
    ];
    for raw in variants {
        assert!(
            verify_document(
                &signed_raw(&key, &trust, raw.as_bytes(), b"lockyard-revocations-v1\0"),
                &trust,
                origin
            )
            .is_err(),
            "{raw}"
        );
    }
    assert!(
        verify_document(
            &signed_raw(
                &key,
                &trust,
                raw.as_bytes(),
                b"lockyard-result-manifest-v1\0"
            ),
            &trust,
            origin
        )
        .is_err()
    );
    let mut noncanonical = signed(&key, &trust, &p);
    noncanonical.payload.push('=');
    assert!(verify_document(&noncanonical, &trust, origin).is_err());
}
#[test]
fn multipage_snapshot_and_timestamp_continuity_are_verified() {
    for mismatch in [false, true] {
        let applied = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = applied.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let (key, trust) = fixture(&origin);
        let st = trust.clone();
        let worker = thread::spawn(move || {
            let mut first: Option<RevocationPage> = None;
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                if index == 1 {
                    assert_eq!(
                        observed.load(std::sync::atomic::Ordering::SeqCst),
                        1,
                        "first page must apply before second GET"
                    );
                }
                let req = read_headers(&mut stream);
                let path = req.split_whitespace().nth(1).unwrap();
                let nonce = path
                    .split("nonce=")
                    .nth(1)
                    .unwrap()
                    .split('&')
                    .next()
                    .unwrap();
                let mut p = first.clone().unwrap_or_else(|| page(nonce));
                p.page_index = index;
                p.next_cursor = if index == 0 {
                    Some("cursor_1".into())
                } else {
                    None
                };
                p.entries[0].ordinal = index;
                p.entries[0].target = RevocationTarget::CertPin {
                    certificate_sha256: if index == 0 { "a" } else { "b" }.repeat(64),
                };
                if mismatch && index == 1 {
                    p.issued_at_ms += 1;
                }
                if index == 1 {
                    assert!(path.contains("cursor=cursor_1"));
                } else {
                    first = Some(p.clone());
                }
                let body = serde_json::to_string(&signed(&key, &st, &p)).unwrap();
                write!(stream,"HTTP/1.1 200 OK\r\nLockyard-Capabilities: revocations_v1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
        });
        let result = Client::new(&origin, "fixture-token".into())
            .unwrap()
            .revocation_refresh_documents_with_apply("fixture", 0, &trust, |_| {
                applied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            });
        assert_eq!(result.is_err(), mismatch);
        if !mismatch {
            assert_eq!(result.unwrap().len(), 2);
        }
        worker.join().unwrap();
    }
}
#[test]
fn problem_details_preserves_auth_code_and_never_retries_revoked_credential() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (_, trust) = fixture(&origin);
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_headers(&mut stream);
        let body = r#"{"type":"urn:lockyard:problem:credential_revoked","title":"Revoked","status":401,"detail":"revoked","instance":"urn:request:1","code":"credential_revoked","details":{}}"#;
        write!(stream,"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
    });
    let err = Client::new(&origin, "fixture-token".into())
        .unwrap()
        .revocation_refresh_documents("fixture", 0, &trust)
        .unwrap_err();
    assert_eq!(err.code(), "credential_revoked");
    assert!(!err.commit_unknown);
    worker.join().unwrap();
}
#[test]
fn revocations_v1_contract_golden_independent_ed25519_bytes() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/revocations-v1.json")).unwrap();
    let trust: RevocationTrust = serde_json::from_value(fixture["trust"].clone()).unwrap();
    for item in fixture["fixtures"].as_array().unwrap() {
        let document: SignedDocument = serde_json::from_value(item["document"].clone()).unwrap();
        let page = verify_document(&document, &trust, &trust.server_origin).unwrap();
        let payload = serde_json::to_vec(&page).unwrap();
        assert_eq!(
            String::from_utf8(payload.clone()).unwrap(),
            item["payload_utf8"].as_str().unwrap()
        );
        let mut framed = b"lockyard-revocations-v1\0".to_vec();
        framed.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        framed.extend_from_slice(&payload);
        assert_eq!(hex(&framed), item["signed_message_hex"].as_str().unwrap());
    }
}

#[test]
fn fixed_snapshot_late_page_age_is_not_clock_skew_but_wall_jump_is() {
    use std::time::Duration;
    assert!(validate_refresh_times(1_000, 61_000, 1_000, 33_000, Duration::from_secs(32)).is_ok());
    assert_eq!(
        validate_refresh_times(1_000, 61_000, 32_000, 33_000, Duration::from_secs(1))
            .unwrap_err()
            .code(),
        "revocation_clock_skew"
    );
    assert_eq!(
        validate_refresh_times(33_001, 61_000, 1_000, 3_000, Duration::from_secs(2))
            .unwrap_err()
            .code(),
        "revocation_clock_skew"
    );
    assert_eq!(
        validate_refresh_times(1_000, 90_000, 1_000, 34_001, Duration::from_secs(3))
            .unwrap_err()
            .code(),
        "revocation_clock_skew"
    );
    assert_eq!(
        validate_refresh_times(1_000, 33_000, 1_000, 33_000, Duration::from_secs(32))
            .unwrap_err()
            .code(),
        "revocations_stale"
    );
}
