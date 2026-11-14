// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Exercises the CLI wire contract against an isolated loopback fixture, never a live server.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
enum Capability {
    Protocol,
    Header,
    Legacy,
}

struct State {
    capability: Capability,
    requests: Vec<(String, String, Value)>,
    refusal: Option<(u16, Value)>,
    paths: Option<Value>,
}

struct Server {
    url: String,
    state: Arc<Mutex<State>>,
}

impl Server {
    fn new(capability: Capability) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State {
            capability,
            requests: Vec::new(),
            refusal: None,
            paths: Some(json!(["repo/src/a.rs", "repo/docs"])),
        }));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                answer(stream, &shared);
            }
        });
        Self { url, state }
    }

    fn posts(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(method, route, _)| method == "POST" && route == "/api/v1/registry/items")
            .map(|(_, _, body)| body.clone())
            .collect()
    }

    fn project(&self) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".lockyard")).unwrap();
        std::fs::write(
            dir.path().join(".lockyard/config.toml"),
            format!(
                "mode='cloud'\nurl='{}'\nworkspace='auto-area-test'\n",
                self.url
            ),
        )
        .unwrap();
        dir
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> Output {
        // A fresh private runtime also prevents attaching to an existing agent process or journal.
        #[cfg(unix)]
        let runtime = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(unix))]
        let runtime = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        Command::new(
            std::env::var_os("LOCKYARD_TEST_BINARY")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_lockyard").into()),
        )
        .current_dir(cwd)
        .args(args)
        .env("LOCKYARD_AGENT", "lead")
        .env("LOCKYARD_TOKEN", "isolated-test-token")
        .env("LOCKYARD_URL", &self.url)
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_CONFIG_HOME", runtime.path().join("config"))
        .env("XDG_STATE_HOME", runtime.path().join("state"))
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .env_remove("LOCKYARD_REQUIRE_E2EE")
        .env_remove("LOCKYARD_E2EE_WORKSPACE_ID")
        .output()
        .unwrap()
    }
}

fn answer(mut stream: TcpStream, shared: &Mutex<State>) {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap();
    let route = parts.next().unwrap().split('?').next().unwrap();
    let mut length = 0;
    let mut repository = "-".to_string();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap(),
                "x-lockyard-repository" => repository = value.trim().to_string(),
                _ => {}
            }
        }
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).unwrap();
    let request = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let (status, body, capability) = {
        let mut state = shared.lock().unwrap();
        state.requests.push((method.into(), route.into(), request));
        let mut item = json!({
            "id":"PA-0001", "title":"fix files", "body":"details", "status":"ready",
            "author":"token:test:lead", "version":1,
        });
        if let Some(paths) = &state.paths {
            item["paths"] = paths.clone();
        }
        let reply = match (method, route) {
            ("GET", "/api/v1/protocol") => (
                200,
                json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,
                    "capabilities": if matches!(state.capability, Capability::Protocol) {
                        vec!["registry_auto_area_v1"]
                    } else { vec![] }}),
            ),
            ("GET", "/api/v1/workspace/encryption") => (
                200,
                json!({"encryption":"off","key_id":null,
                    "workspace_id":"00000000-0000-0000-0000-000000000001"}),
            ),
            ("GET", "/api/v1/registry/areas") => (
                200,
                json!([{"id":"area-id","key":"general","prefix":"PA","pad":4}]),
            ),
            ("POST", "/api/v1/registry/items") => state.refusal.clone().unwrap_or((201, item)),
            ("GET", "/api/v1/registry/items/PA-0001") => (200, item),
            ("GET", "/api/v1/registry/items/PA-0001/history") => (200, json!([])),
            _ => (
                404,
                json!({"error":{"code":"not_found","message":"unexpected fixture route"}}),
            ),
        };
        // Discovery can advertise in its body alone; later successful responses must
        // confirm current support. Header-only mode first enables it on a later response.
        let capability =
            if !matches!(state.capability, Capability::Legacy) && route != "/api/v1/protocol" {
                "Lockyard-Capabilities: registry_auto_area_v1\r\n"
            } else {
                ""
            };
        (reply.0, reply.1, capability)
    };
    let body = body.to_string();
    write!(stream, "HTTP/1.1 {status} X\r\nLockyard-Protocol: 2\r\nX-Lockyard-Repository: {repository}\r\n{capability}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
}

fn assert_ok(result: &Output) {
    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
}

#[test]
fn cli_auto_area_sends_normalized_workspace_paths_without_an_area_lookup() {
    for capability in [Capability::Protocol, Capability::Header] {
        let server = Server::new(capability);
        let project = server.project();
        let root = project.path().canonicalize().unwrap();
        let nested = root.join("unrelated/deep");
        std::fs::create_dir_all(&nested).unwrap();
        let absolute = root.join("repo/src/new.rs");
        let result = server.run(
            &nested,
            &[
                "task",
                "add",
                "fix files",
                "--path",
                "repo//src/../a.rs",
                "--path",
                "repo\\docs\\.\\guide.md",
                "--path",
                absolute.to_str().unwrap(),
                "--path",
                "repo/a.rs",
            ],
        );
        assert_ok(&result);
        let posts = server.posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(
            posts[0]["paths"],
            json!(["repo/a.rs", "repo/docs/guide.md", "repo/src/new.rs"])
        );
        assert!(posts[0].get("area").is_none());
        assert!(posts[0].get("area_id").is_none());
        assert!(
            !server
                .state
                .lock()
                .unwrap()
                .requests
                .iter()
                .any(|(_, route, _)| route == "/api/v1/registry/areas")
        );
    }
}

#[test]
fn cli_auto_area_sends_an_explicit_area_override_verbatim() {
    let server = Server::new(Capability::Protocol);
    let project = server.project();
    let result = server.run(
        project.path(),
        &[
            "task",
            "add",
            "fix files",
            "--path",
            "repo/src/a.rs",
            "--area",
            "MiXeD-area-key",
        ],
    );
    assert_ok(&result);
    let posts = server.posts();
    assert_eq!(posts[0]["area"], "MiXeD-area-key");
    assert!(posts[0].get("area_id").is_none());
}

#[test]
fn cli_auto_area_requires_paths_before_sending_a_task_creation_request() {
    for capability in [Capability::Protocol, Capability::Header] {
        let server = Server::new(capability);
        let project = server.project();
        let result = server.run(project.path(), &["task", "add", "fix files"]);
        assert!(!result.status.success());
        let text = String::from_utf8_lossy(&result.stderr);
        assert!(
            text.contains("--path <путь>") && text.contains("корня рабочего места"),
            "{text}"
        );
        assert!(server.posts().is_empty());
    }
}

#[test]
fn cli_old_server_omits_paths_warns_and_keeps_legacy_task_creation() {
    let server = Server::new(Capability::Legacy);
    let project = server.project();
    let with_paths = server.run(
        project.path(),
        &[
            "task",
            "add",
            "fix files",
            "--path",
            "repo/src/a.rs",
            "--area",
            "general",
        ],
    );
    assert_ok(&with_paths);
    let text = String::from_utf8_lossy(&with_paths.stderr);
    assert!(
        text.contains("warning") && text.contains("server") && text.contains("will not be sent"),
        "{text}"
    );
    let without_paths = server.run(project.path(), &["task", "add", "fix files"]);
    assert_ok(&without_paths);
    let posts = server.posts();
    assert_eq!(posts.len(), 2);
    for post in posts {
        assert!(post.get("paths").is_none(), "{post}");
        assert_eq!(post["area_id"], "area-id");
    }
}

#[test]
fn cli_auto_area_refuses_outside_workspace_paths_without_posting() {
    let server = Server::new(Capability::Protocol);
    let project = server.project();
    let outside = tempfile::tempdir().unwrap();
    let absolute = outside.path().join("a.rs");
    for path in ["../outside/a.rs", absolute.to_str().unwrap()] {
        let result = server.run(
            project.path(),
            &["task", "add", "fix files", "--path", path],
        );
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("outside"));
    }
    assert!(server.posts().is_empty());
}

#[test]
fn cli_auto_area_explains_all_contract_errors_and_lists_repository_roots() {
    for (status, code, details, expected) in [
        (
            422,
            "task_paths_required",
            json!({}),
            vec!["--path <путь>", "корня рабочего места"],
        ),
        (
            422,
            "task_paths_span_repositories",
            json!({"roots":["games/game-a","repo"]}),
            vec![
                "games/game-a",
                "repo",
                "заведи по одной задаче на репозиторий",
            ],
        ),
        (
            422,
            "area_mismatch",
            json!({"derived":"derived-area"}),
            vec!["область", "derived-area"],
        ),
        (422, "area_closed", json!({}), vec!["область закрыта"]),
        (
            409,
            "area_template_conflict",
            json!({"root":"repo","prefix":"RP","existing_area":"other-area"}),
            vec!["repo", "RP", "other-area", "Ведущий"],
        ),
    ] {
        let server = Server::new(Capability::Protocol);
        server.state.lock().unwrap().refusal = Some((
            status,
            json!({
                "type":format!("urn:lockyard:problem:{code}"),"title":"Creation refused",
                "status":status,"code":code,"detail":"opaque server detail","details":details,
            }),
        ));
        let project = server.project();
        let result = server.run(
            project.path(),
            &["task", "add", "fix files", "--path", "repo/a.rs"],
        );
        assert!(!result.status.success());
        let text = String::from_utf8_lossy(&result.stderr);
        for expected in expected {
            assert!(
                text.contains(expected),
                "{code}: missing {expected:?} in {text}"
            );
        }
        assert_eq!(server.posts().len(), 1);
    }
}

#[test]
fn cli_task_show_exposes_paths_and_preserves_tasks_without_them() {
    let server = Server::new(Capability::Protocol);
    let project = server.project();
    for with_paths in [true, false] {
        if !with_paths {
            server.state.lock().unwrap().paths = None;
        }
        let human = server.run(project.path(), &["task", "show", "PA-0001"]);
        assert_ok(&human);
        let human = String::from_utf8(human.stdout).unwrap();
        let structured = server.run(project.path(), &["--json", "task", "show", "PA-0001"]);
        assert_ok(&structured);
        let structured: Value = serde_json::from_slice(&structured.stdout).unwrap();
        if with_paths {
            assert!(human.contains("paths: repo/src/a.rs, repo/docs"), "{human}");
            assert_eq!(
                structured["task"]["paths"],
                json!(["repo/src/a.rs", "repo/docs"])
            );
        } else {
            assert_eq!(human, "PA-0001  ready  -  fix files\ndetails\n");
            assert!(structured["task"].get("paths").is_none());
        }
    }
}
