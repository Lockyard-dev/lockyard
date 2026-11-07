use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RevocationTarget {
    Token {
        token_id: String,
    },
    Machine {
        node_id: String,
        credential_id: String,
        certificate_sha256: String,
    },
    CertPin {
        certificate_sha256: String,
    },
    SsoSession {
        token_id: String,
    },
}
#[derive(Serialize)]
struct RevocationEntry {
    epoch: u64,
    ordinal: u32,
    target: RevocationTarget,
    revoked_at_ms: u64,
}
#[derive(Serialize)]
struct RevocationPage {
    schema: u8,
    workspace_id: String,
    from_epoch: u64,
    epoch: u64,
    snapshot_id: String,
    issued_at_ms: u64,
    valid_until_ms: u64,
    nonce: String,
    page_index: u32,
    next_cursor: Option<String>,
    entries: Vec<RevocationEntry>,
}
#[derive(Serialize)]
struct SignedDocument {
    version: u8,
    algorithm: String,
    key_id: String,
    payload: String,
    signature: String,
}
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};
#[derive(Clone, Copy)]
pub enum Mode {
    Normal,
    LostReply,
    ClosureUnavailable,
    Unknown,
    Legacy,
    DeniedStateFailure,
    StaleClosure,
    OmittedTarget,
    CommittedStateFailure,
}
pub struct Server {
    pub url: String,
    pub requests: Arc<Mutex<Vec<(String, String)>>>,
    pub posts: Arc<Mutex<Vec<(String, String)>>>,
    pub fail_state: Arc<Mutex<Option<std::path::PathBuf>>>,
    pub signer_seed: Arc<std::sync::atomic::AtomicU8>,
}
impl Server {
    pub fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let posts = Arc::new(Mutex::new(vec![]));
        let log = posts.clone();
        let requests = Arc::new(Mutex::new(vec![]));
        let request_log = requests.clone();
        let fail_state = Arc::new(Mutex::new(None::<std::path::PathBuf>));
        let fault = fail_state.clone();
        let signer_seed = Arc::new(std::sync::atomic::AtomicU8::new(7));
        let seed = signer_seed.clone();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let key = Ed25519KeyPair::from_seed_unchecked(
                    &[seed.load(std::sync::atomic::Ordering::SeqCst); 32],
                )
                .unwrap();
                let key_id = hex(ring::digest::digest(
                    &ring::digest::SHA256,
                    key.public_key().as_ref(),
                )
                .as_ref());
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let parts: Vec<_> = line.split_whitespace().collect();
                let method = parts[0].to_string();
                let path = parts[1].to_string();
                request_log
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone()));
                let mut length = 0;
                let mut idem = String::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        match k.to_ascii_lowercase().as_str() {
                            "content-length" => length = v.trim().parse().unwrap(),
                            "idempotency-key" => idem = v.trim().into(),
                            _ => {}
                        }
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let mut status = 200;
                let mut capability = true;
                let response = if path == "/api/v1/revocations/key" {
                    capability = !matches!(mode, Mode::Legacy);
                    json!({"workspace_id":"11111111-1111-4111-8111-111111111111","key_id":key_id,"algorithm":"Ed25519","public_key":hex(key.public_key().as_ref())})
                } else if method == "POST" {
                    let mut posts = log.lock().unwrap();
                    posts.push((idem, String::from_utf8(body.clone()).unwrap()));
                    if matches!(mode, Mode::Unknown)
                        || (matches!(mode, Mode::LostReply) && posts.len() == 1)
                    {
                        continue;
                    }
                    if matches!(mode, Mode::DeniedStateFailure | Mode::CommittedStateFailure) {
                        use std::os::unix::fs::PermissionsExt;
                        let directory = fault.lock().unwrap().clone().unwrap();
                        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o500))
                            .unwrap();
                    }
                    if matches!(mode, Mode::DeniedStateFailure) {
                        status = 403;
                        json!({"type":"urn:lockyard:problem:forbidden","title":"Forbidden","status":403,"detail":"Owner required","instance":"urn:request:1","code":"forbidden","details":{}})
                    } else {
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        let target: RevocationTarget =
                            serde_json::from_value(body["target"].clone()).unwrap();
                        json!({"epoch":1,"already_revoked":posts.len()>1,"document":sign(&key,&key_id,page("",vec![target]))})
                    }
                } else if path.starts_with("/api/v1/revocations?") {
                    if matches!(mode, Mode::ClosureUnavailable) {
                        status = 503;
                        json!({"type":"urn:lockyard:problem:revocation_state_unavailable","title":"Unavailable","status":503,"detail":"Unavailable","instance":"urn:request:1","code":"revocation_state_unavailable","details":{}})
                    } else {
                        let nonce = path
                            .split("nonce=")
                            .nth(1)
                            .unwrap()
                            .split('&')
                            .next()
                            .unwrap();
                        let target: Value =
                            serde_json::from_str(&log.lock().unwrap().last().unwrap().1).unwrap();
                        let mut targets = if matches!(mode, Mode::OmittedTarget) {
                            vec![]
                        } else {
                            vec![serde_json::from_value(target["target"].clone()).unwrap()]
                        };
                        targets.push(RevocationTarget::CertPin {
                            certificate_sha256: "a".repeat(64),
                        });
                        targets.push(RevocationTarget::CertPin {
                            certificate_sha256: "b".repeat(64),
                        });
                        let mut closure = page(nonce, targets);
                        if matches!(mode, Mode::StaleClosure) {
                            closure.epoch = 0;
                            closure.entries.clear();
                        }
                        serde_json::to_value(sign(&key, &key_id, closure)).unwrap()
                    }
                } else {
                    panic!("unexpected route {method} {path}")
                };
                let body = serde_json::to_vec(&response).unwrap();
                let cap = if capability {
                    "Lockyard-Capabilities: revocations_v1\r\n"
                } else {
                    ""
                };
                write!(stream,"HTTP/1.1 {status} Status\r\n{cap}Content-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        Self {
            url,
            requests,
            posts,
            fail_state,
            signer_seed,
        }
    }
}
fn page(nonce: &str, targets: Vec<RevocationTarget>) -> RevocationPage {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    RevocationPage {
        schema: 1,
        workspace_id: "11111111-1111-4111-8111-111111111111".into(),
        from_epoch: 0,
        epoch: 1,
        snapshot_id: "22222222-2222-4222-8222-222222222222".into(),
        issued_at_ms: now,
        valid_until_ms: now + 60_000,
        nonce: nonce.into(),
        page_index: 0,
        next_cursor: None,
        entries: targets
            .into_iter()
            .enumerate()
            .map(|(i, target)| RevocationEntry {
                epoch: 1,
                ordinal: i as u32,
                target,
                revoked_at_ms: now,
            })
            .collect(),
    }
}
fn sign(key: &Ed25519KeyPair, key_id: &str, page: RevocationPage) -> SignedDocument {
    let bytes = serde_json::to_vec(&page).unwrap();
    let mut msg = b"lockyard-revocations-v1\0".to_vec();
    msg.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    msg.extend_from_slice(&bytes);
    SignedDocument {
        version: 1,
        algorithm: "Ed25519".into(),
        key_id: key_id.into(),
        payload: b64(&bytes),
        signature: b64(key.sign(&msg).as_ref()),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | (c.get(2).copied().unwrap_or(0) as u32);
        for shift in [18, 12, 6, 0] {
            out.push(T[((n >> shift) & 63) as usize] as char);
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
pub fn project(url: &str) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let root = project_without_trust(url);
    let directory = root.path().join(".lockyard/private-revocations");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Fixtures model a pin delivered by trusted registration, independently of the HTTP server.
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let trust = json!({
        "workspace_id": "11111111-1111-4111-8111-111111111111",
        "key_id": hex(ring::digest::digest(&ring::digest::SHA256, key.public_key().as_ref()).as_ref()),
        "public_key": hex(key.public_key().as_ref()),
        "server_origin": url,
    });
    let path = trust_path(root.path(), url);
    std::fs::write(&path, serde_json::to_vec(&trust).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    root
}
pub fn trust_path(root: &std::path::Path, url: &str) -> std::path::PathBuf {
    let origin = lockyard_cloud_client::revocations::canonical_origin(url).unwrap();
    let id = hex(ring::digest::digest(&ring::digest::SHA256, origin.as_bytes()).as_ref());
    root.join(format!(".lockyard/private-revocations/trust-{id}.json"))
}
pub fn project_without_trust(url: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".lockyard")).unwrap();
    std::fs::write(
        root.path().join(".lockyard/config.toml"),
        format!("mode='cloud'\nurl='{url}'\nworkspace='team'\n"),
    )
    .unwrap();
    root
}
pub fn invoke(root: &std::path::Path, url: &str, mcp: bool) -> (i32, Value) {
    invoke_surface(root, url, mcp.then_some("compact"))
}
pub fn invoke_surface(
    root: &std::path::Path,
    url: &str,
    mcp_surface: Option<&str>,
) -> (i32, Value) {
    invoke_with_node_config(root, url, mcp_surface, None)
}
pub fn legacy_node_config(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("legacy-node.toml");
    let configuration = json!({
        "node_id": "owner",
        "workspace": "team",
        "state_dir": root.join("node-state"),
        "certificate": root.join("cert.der"),
        "private_key": root.join("key.der"),
    });
    let node: lockyard_node::host::NodeConfig = serde_json::from_value(configuration).unwrap();
    std::fs::write(&path, toml::to_string(&node).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(lockyard_node::host::NodeConfig::load(&path).is_ok());
    path
}
pub fn invoke_with_node_config(
    root: &std::path::Path,
    url: &str,
    mcp_surface: Option<&str>,
    node_config: Option<&std::path::Path>,
) -> (i32, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    cmd.current_dir(root)
        .env("LOCKYARD_URL", url)
        .env("LOCKYARD_TOKEN", "fixture-token")
        .env_remove("LOCKYARD_REQUIRE_E2EE")
        .env_remove("LOCKYARD_E2EE_WORKSPACE_ID")
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID");
    if let Some(surface) = mcp_surface {
        let mut child = cmd
            .args(["mcp", "--tools", surface])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut args =
            json!({"target":{"kind":"token","token_id":"33333333-3333-4333-8333-333333333333"}});
        if let Some(path) = node_config {
            args["node_config"] = json!(path);
        }
        let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"revoke_access","arguments":args}});
        writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
        let output = child.wait_with_output().unwrap();
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code().unwrap(), response["result"].clone())
    } else {
        cmd.args([
            "revoke",
            "token",
            "33333333-3333-4333-8333-333333333333",
            "--json",
        ]);
        if let Some(path) = node_config {
            cmd.arg("--node-config").arg(path);
        }
        let output = cmd.output().unwrap();
        let parsed = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code().unwrap(), parsed)
    }
}
