// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives the real binary in cloud mode against a fake server, with and without the agent process.

#![cfg(unix)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    body: Value,
    key: Option<String>,
    session: Option<String>,
}

#[derive(Default)]
struct State {
    seen: Vec<Seen>,
    claims: Vec<Value>,
    inbox: Vec<Value>,
    refuse_claims: Option<(u16, Value)>,
}

#[derive(Clone)]
struct Server {
    url: String,
    state: Arc<Mutex<State>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let shared = Arc::clone(&shared);
                thread::spawn(move || serve(stream, &shared));
            }
        });
        Self { url, state }
    }

    fn seen(&self, method: &str, route: &str) -> Vec<Seen> {
        let state = self.state.lock().unwrap();
        state
            .seen
            .iter()
            .filter(|r| r.method == method && r.path.split('?').next() == Some(route))
            .cloned()
            .collect()
    }
}

fn serve(mut stream: TcpStream, state: &Mutex<State>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let (mut length, mut key, mut session, mut token) = (0, None, None, None);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(": ") {
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.parse().unwrap_or(0),
                "idempotency-key" => key = Some(value.to_string()),
                "x-lockyard-session" => session = Some(value.to_string()),
                "authorization" => token = Some(value.to_string()),
                _ => {}
            }
        }
    }
    let mut body = vec![0_u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let route = path.split('?').next().unwrap_or_default().to_string();
    if route.ends_with("/events") {
        // A short long poll keeps the agent's threads moving and its view fresh.
        thread::sleep(Duration::from_millis(30));
    }
    let (status, answer) = {
        let mut state = state.lock().unwrap();
        if !route.ends_with("/events") {
            let record = Seen {
                method: method.clone(),
                path: path.clone(),
                body: body.clone(),
                key,
                session,
            };
            state.seen.push(record);
        }
        if token.as_deref() != Some("Bearer test-token") {
            (
                401,
                json!({"error": {"code": "unauthorized", "message": "bad token"}}),
            )
        } else {
            route_reply(&mut state, &method, &route, &body)
        }
    };
    let text = answer.to_string();
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nRetry-After: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn route_reply(state: &mut State, method: &str, route: &str, body: &Value) -> (u16, Value) {
    match (method, route) {
        ("POST", "/api/v1/zones/claims") => {
            if let Some(refusal) = state.refuse_claims.clone() {
                return refusal;
            }
            let id = state.claims.len() as i64 + 1;
            let claim = json!({"id": id, "session": "alice", "paths": body["paths"], "fence": 1, "expires_at": "later"});
            state.claims.push(claim.clone());
            (200, claim)
        }
        ("GET", "/api/v1/zones/claims") => (200, json!({"claims": state.claims})),
        ("POST", "/api/v1/zones/check") => (
            200,
            json!({"paths": [{"path": body["paths"][0], "status": "free"}]}),
        ),
        ("GET", "/api/v1/bus/inbox") => (200, json!({"messages": state.inbox, "skipped": 0})),
        ("POST", "/api/v1/bus/inbox/claim") => (200, json!({"claimed": body["ids"]})),
        ("POST", "/api/v1/bus/inbox/seen") => {
            let ids = body["ids"].as_array().cloned().unwrap_or_default();
            state.inbox.retain(|message| !ids.contains(&message["id"]));
            (200, json!({"seen": ids.len()}))
        }
        ("POST", "/api/v1/bus/messages") => (
            200,
            json!({"id": 44, "from_session": "alice", "to": body["to"], "body": body["body"]}),
        ),
        ("GET", "/api/v1/bus/board") | ("GET", "/api/v1/bus/tasks") => (200, json!([])),
        ("POST", "/api/v1/bus/tasks") => (
            200,
            json!({"id": 6, "title": body["title"], "status": "offered", "version": 1}),
        ),
        ("POST", "/api/v1/bus/tasks/6/claim") => {
            (200, json!({"id": 6, "status": "claimed", "version": 2}))
        }
        _ if route.ends_with("/events") => (200, json!({"events": []})),
        _ => (200, json!({"id": 1})),
    }
}

fn cloud_project(server: &Server) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join(".lockyard");
    std::fs::create_dir(&state).unwrap();
    let config = format!(
        "mode = 'cloud'\nurl = '{}'\nworkspace = 'team'\n",
        server.url
    );
    std::fs::write(state.join("config.toml"), config).unwrap();
    dir
}

fn binary(dir: &Path, runtime: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(dir)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", runtime.join("state"))
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_TOKEN_FILE");
    command
}

fn cli(dir: &Path, runtime: &Path, args: &[&str]) -> Output {
    binary(dir, runtime)
        .args(args)
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap()
}

fn json_of(result: &Output) -> Value {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn the_config_selects_the_cloud_backend_and_the_token_comes_only_from_the_environment() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let claim = json_of(&cli(
        dir.path(),
        runtime.path(),
        &["--json", "zone", "claim", "src", "--note", "n", "--lazy"],
    ));
    assert_eq!(claim["id"], 1);
    let sent = &server.seen("POST", "/api/v1/zones/claims")[0];
    assert_eq!(sent.body["lazy"], true);
    assert_eq!(sent.session.as_deref(), Some("alice"));
    assert!(sent.key.is_some());

    let bare = binary(dir.path(), runtime.path())
        .args(["zone", "list"])
        .env_remove("LOCKYARD_TOKEN")
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bare.stderr).contains("LOCKYARD_TOKEN"));

    let token_file = runtime.path().join("token");
    std::fs::write(&token_file, "test-token\n").unwrap();
    let listed = binary(dir.path(), runtime.path())
        .args(["--json", "zone", "list"])
        .env_remove("LOCKYARD_TOKEN")
        .env("LOCKYARD_TOKEN_FILE", &token_file)
        .output()
        .unwrap();
    assert_eq!(json_of(&listed).as_array().unwrap().len(), 1);
}

#[test]
fn a_token_in_the_config_file_is_refused() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let path = dir.path().join(".lockyard/config.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{text}token = 'secret'\n")).unwrap();
    let runtime = tempfile::tempdir().unwrap();
    assert_eq!(
        cli(dir.path(), runtime.path(), &["zone", "list"])
            .status
            .code(),
        Some(1)
    );
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn refusals_map_to_exit_codes_and_kinds() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let refusal = |status: u16, details: Value| {
        let body = json!({"error": {"code": "x", "message": "refused here", "details": details}});
        server.state.lock().unwrap().refuse_claims = Some((status, body));
    };
    let held =
        json!({"conflicts": [{"path": "src", "session": "bob", "claim_id": 3, "note": "busy"}]});
    refusal(409, held);
    let conflict = cli(dir.path(), runtime.path(), &["zone", "claim", "src"]);
    assert_eq!(conflict.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("src is held by bob"));
    refusal(409, json!({"priority_of": "carol"}));
    let reserved = cli(dir.path(), runtime.path(), &["zone", "claim", "src"]);
    assert_eq!(reserved.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&reserved.stderr).contains("carol"));
    for (status, kind) in [
        (403, "denied"),
        (404, "not_found"),
        (412, "stale_fence"),
        (503, "frozen"),
    ] {
        refusal(status, Value::Null);
        let refused = cli(
            dir.path(),
            runtime.path(),
            &["--json", "zone", "claim", "src"],
        );
        assert_eq!(refused.status.code(), Some(1));
        let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
        assert_eq!(error["error"]["kind"], kind);
    }
}

#[test]
fn the_new_commands_reach_their_routes() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let root = dir.path();
    let run = |args: &[&str]| {
        let result = cli(root, runtime.path(), args);
        assert!(
            result.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    run(&["zone", "queue", "src", "--note", "n", "--ttl", "90"]);
    run(&["zone", "unwait", "Q-3"]);
    run(&["zone", "request", "src", "--text", "please", "--urgent"]);
    run(&["zone", "answer", "4", "--reply", "soon"]);
    run(&["zone", "handover", "5", "--to", "bob", "--fence", "2"]);
    run(&["zone", "narrow", "5", "src", "--fence", "2"]);
    run(&["zone", "add-path", "5", "docs"]);
    run(&["zone", "takeover", "5", "--reason", "gone"]);
    run(&["zone", "dirty", "report", "src", "--owner", "bob"]);
    run(&["zone", "dirty", "disown", "src"]);
    run(&["zone", "dirty", "adopt", "src", "--reason", "left"]);
    run(&["msg", "ack", "9"]);
    run(&[
        "presence",
        "beat",
        "--state",
        "api-failure",
        "--tool-running",
    ]);
    run(&["cloud", "freeze", "on", "--reason", "switch"]);
    let offered = json_of(&cli(
        root,
        runtime.path(),
        &[
            "--json", "work", "offer", "t", "--to", "bob", "--accept", "tests",
        ],
    ));
    assert_eq!(offered["status"], "offered");
    let claimed = json_of(&cli(
        root,
        runtime.path(),
        &["--json", "work", "claim", "6", "--if-version", "1"],
    ));
    assert_eq!(claimed["status"], "claimed");
    for (method, route) in [
        ("POST", "/api/v1/zones/queue"),
        ("DELETE", "/api/v1/zones/queue/3"),
        ("POST", "/api/v1/zones/requests"),
        ("POST", "/api/v1/zones/requests/4/answer"),
        ("POST", "/api/v1/zones/claims/5/handover"),
        ("POST", "/api/v1/zones/claims/5/narrow"),
        ("POST", "/api/v1/zones/claims/5/add-path"),
        ("POST", "/api/v1/zones/claims/5/takeover"),
        ("POST", "/api/v1/zones/dirty"),
        ("POST", "/api/v1/zones/dirty/disown"),
        ("POST", "/api/v1/zones/dirty/adopt"),
        ("POST", "/api/v1/bus/messages/9/ack"),
        ("POST", "/api/v1/presence"),
        ("POST", "/api/v1/admin/freeze"),
        ("POST", "/api/v1/bus/tasks"),
    ] {
        assert_eq!(server.seen(method, route).len(), 1, "{method} {route}");
    }
    let claim = &server.seen("POST", "/api/v1/bus/tasks/6/claim");
    assert!(claim[0].path.ends_with("?version=1"));
    let beat = &server.seen("POST", "/api/v1/presence")[0];
    assert_eq!(beat.body["activity"]["state"], "api_failure");
}

#[test]
fn the_task_commands_read_the_registry_in_cloud_mode() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let listed = cli(dir.path(), runtime.path(), &["task", "list"]);
    assert_eq!(listed.status.code(), Some(0), "{listed:?}");
    let state = server.state.lock().unwrap();
    assert!(
        state
            .seen
            .iter()
            .any(|seen| seen.path.starts_with("/api/v1/registry/items"))
    );
}

fn hook(dir: &Path, runtime: &Path, event: &Value) -> Output {
    // No token and no agent name: a hook in cloud mode can only reach the socket.
    let mut child = binary(dir, runtime)
        .args(["hook", "claude"])
        .env_remove("LOCKYARD_AGENT")
        .env_remove("LOCKYARD_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Kills the agent process when a test ends, however it ends.
struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_agent(dir: &Path, runtime: &Path) -> Agent {
    let child = binary(dir, runtime)
        .arg("agent")
        .env("LOCKYARD_TOKEN", "test-token")
        .spawn()
        .unwrap();
    let agent = Agent(child);
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let status = cli(dir, runtime, &["--json", "agent", "status"]);
        let status = json_of(&status);
        if status["status"]["view_fresh"] == true {
            return agent;
        }
        assert!(Instant::now() < end, "the agent never became ready");
        thread::sleep(Duration::from_millis(20));
    }
}

fn socket(runtime: &Path) -> PathBuf {
    runtime.join("lockyard/agent.sock")
}

fn pre_edit(root: &Path) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "session_id": "me",
        "cwd": root,
        "tool_name": "Edit",
        "tool_input": {"file_path": root.join("src/a.rs")},
    })
}

#[test]
fn without_an_agent_a_hook_allows_and_says_so_and_sends_nothing() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let result = hook(dir.path(), runtime.path(), &pre_edit(dir.path()));
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("allowing"));
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn through_the_agent_a_hook_denies_a_held_path_from_memory() {
    let server = Server::start();
    server
        .state
        .lock()
        .unwrap()
        .claims
        .push(json!({"id": 1, "session": "bob", "paths": ["src"], "note": "busy"}));
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let checks_before = server.seen("POST", "/api/v1/zones/check").len();
    let result = hook(dir.path(), runtime.path(), &pre_edit(dir.path()));
    let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        answer["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("bob")
    );
    assert_eq!(
        server.seen("POST", "/api/v1/zones/check").len(),
        checks_before
    );

    let cli_check = cli(dir.path(), runtime.path(), &["zone", "check", "src/a.rs"]);
    assert_eq!(cli_check.status.code(), Some(3));
}

#[test]
fn through_the_agent_a_hook_delivers_mail_in_two_phases() {
    let server = Server::start();
    server
        .state
        .lock()
        .unwrap()
        .inbox
        .push(json!({"id": 7, "from_session": "bob", "to": "me", "body": "look at src"}));
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let event =
        json!({"hook_event_name": "UserPromptSubmit", "session_id": "me", "cwd": dir.path()});
    let result = hook(dir.path(), runtime.path(), &event);
    assert!(String::from_utf8_lossy(&result.stdout).contains("look at src"));
    let claimed = server.seen("POST", "/api/v1/bus/inbox/claim");
    assert_eq!(claimed[0].body, json!({"ids": [7], "lease_seconds": 60}));
    let end = Instant::now() + Duration::from_secs(5);
    while server.seen("POST", "/api/v1/bus/inbox/seen").is_empty() {
        assert!(Instant::now() < end, "seen never arrived");
        thread::sleep(Duration::from_millis(10));
    }
    let seen = server.seen("POST", "/api/v1/bus/inbox/seen");
    assert_eq!(seen[0].body, json!({"ids": [7]}));
    assert!(seen[0].key.is_some());
    assert_eq!(seen[0].session.as_deref(), Some("me"));
}

#[test]
fn the_cli_goes_through_a_running_agent_and_needs_no_token() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let sent = binary(dir.path(), runtime.path())
        .args(["--json", "msg", "send", "bob", "hello"])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .output()
        .unwrap();
    assert_eq!(json_of(&sent)["id"], 44);
    assert_eq!(
        server.seen("POST", "/api/v1/bus/messages")[0]
            .session
            .as_deref(),
        Some("alice")
    );
}

#[test]
fn the_socket_and_its_folder_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let path = socket(runtime.path());
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
}

#[test]
fn install_refuses_a_bare_token_and_writes_a_unit_naming_the_file() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let home = tempfile::tempdir().unwrap();
    let bare = binary(dir.path(), home.path())
        .args(["agent", "install", "--no-start"])
        .env("HOME", home.path())
        .env("LOCKYARD_TOKEN", "test-token")
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bare.stderr).contains("LOCKYARD_TOKEN_FILE"));

    let token = home.path().join("token");
    std::fs::write(&token, "test-token").unwrap();
    let installed = binary(dir.path(), home.path())
        .args(["--json", "agent", "install", "--no-start"])
        .env("HOME", home.path())
        .env("LOCKYARD_TOKEN_FILE", &token)
        .output()
        .unwrap();
    let unit = json_of(&installed)["unit"].as_str().unwrap().to_string();
    let text = std::fs::read_to_string(&unit).unwrap();
    assert!(text.contains("LOCKYARD_TOKEN_FILE"));
    assert!(!text.contains("test-token"));

    let status = binary(dir.path(), home.path())
        .args(["--json", "agent", "status"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    let status = json_of(&status);
    assert_eq!(
        (status["installed"].as_bool(), status["running"].as_bool()),
        (Some(true), Some(false))
    );

    let removed = binary(dir.path(), home.path())
        .args(["agent", "uninstall", "--no-start"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(removed.status.success());
    assert!(!Path::new(&unit).exists());
}
