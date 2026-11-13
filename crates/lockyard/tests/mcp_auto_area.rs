// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Exercise MCP discovery, validation, wire payloads and output against a loopback-only stub.
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Default)]
struct State {
    seen: Vec<(String, String, Value)>,
    refusal: Option<(u16, Value)>,
    task_paths: Option<Vec<String>>,
}

struct Server {
    url: String,
    state: Arc<Mutex<State>>,
}

impl Server {
    fn start(capability: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        let capability = capability.to_string();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                reply(stream, &shared, &capability);
            }
        });
        Self { url, state }
    }

    fn writes(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|(method, path, _)| method == "POST" && path == "/api/v1/registry/items")
            .map(|(_, _, body)| body.clone())
            .collect()
    }
}

fn reply(mut stream: TcpStream, shared: &Mutex<State>, capability: &str) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request = String::new();
    if reader.read_line(&mut request).unwrap() == 0 {
        return;
    }
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap().to_string();
    let path = parts.next().unwrap().split('?').next().unwrap().to_string();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut raw = vec![0; length];
    reader.read_exact(&mut raw).unwrap();
    let body = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let (status, answer) = {
        let mut state = shared.lock().unwrap();
        state.seen.push((method.clone(), path.clone(), body));
        let mut task = json!({"id":"FE-0001","title":"stub task","status":"ready","version":1});
        if let Some(paths) = &state.task_paths {
            task["paths"] = json!(paths);
        }
        match (method.as_str(), path.as_str()) {
            ("GET", "/api/v1/protocol") => (
                200,
                json!({
                    "selected_protocol":2,"min_protocol":1,"max_protocol":2,
                    "capabilities":if capability == "body" {vec!["registry_auto_area_v1"]} else {vec![]}
                }),
            ),
            ("GET", "/api/v1/workspace/encryption") => (
                200,
                json!({
                    "encryption":"off","key_id":null,"workspace_id":"00000000-0000-0000-0000-000000000001"
                }),
            ),
            ("GET", "/api/v1/presence") => (200, json!({"sessions":[]})),
            ("GET", "/api/v1/registry/areas") => (
                200,
                json!({"areas":[
                    {"id":"engine-id","key":"engine","prefix":"FE"}
                ]}),
            ),
            ("POST", "/api/v1/registry/items") => state.refusal.clone().unwrap_or((200, task)),
            ("GET", "/api/v1/registry/ready") => (200, json!({"items":[task]})),
            ("GET", "/api/v1/registry/items/FE-0001") => (200, task),
            ("GET", "/api/v1/registry/items/FE-0001/history") => (200, json!({"events":[]})),
            _ => (200, json!({"id":1})),
        }
    };
    let text = answer.to_string();
    let capabilities =
        if capability == "header" || (capability == "body" && path != "/api/v1/protocol") {
            "Lockyard-Capabilities: registry_auto_area_v1\r\n"
        } else {
            ""
        };
    let response = format!(
        "HTTP/1.1 {status} X\r\nLockyard-Protocol: 2\r\n{capabilities}X-Lockyard-Repository: -\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
}

struct Project {
    root: tempfile::TempDir,
    runtime: tempfile::TempDir,
}

impl Project {
    fn new(server: &Server) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".lockyard")).unwrap();
        std::fs::write(
            root.path().join(".lockyard/config.toml"),
            format!(
                "mode = 'cloud'\nurl = '{}'\nworkspace = 'team'\n",
                server.url
            ),
        )
        .unwrap();
        Self {
            root,
            runtime: tempfile::tempdir().unwrap(),
        }
    }

    fn rpc(&self, server: &Server, cwd: &Path, surface: &str, requests: Vec<Value>) -> Vec<Value> {
        self.rpc_bounded(
            server,
            cwd,
            surface,
            requests,
            std::time::Duration::from_secs(10),
        )
    }

    fn rpc_bounded(
        &self,
        server: &Server,
        cwd: &Path,
        surface: &str,
        requests: Vec<Value>,
        budget: std::time::Duration,
    ) -> Vec<Value> {
        let mut child = Command::new(
            std::env::var_os("LOCKYARD_TEST_BINARY")
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_lockyard").into()),
        )
        .args(["mcp", "--tools", surface])
        .current_dir(cwd)
        .env_clear()
        .env("HOME", self.runtime.path())
        .env("XDG_RUNTIME_DIR", self.runtime.path())
        .env("XDG_STATE_HOME", self.runtime.path().join("state"))
        .env("XDG_CONFIG_HOME", self.runtime.path().join("config"))
        .env("LOCKYARD_URL", &server.url)
        .env("LOCKYARD_TOKEN", "synthetic-test-token")
        .env("LOCKYARD_AGENT", "test-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        let mut input = child.stdin.take().unwrap();
        for request in &requests {
            writeln!(input, "{request}").unwrap();
        }
        drop(input);
        let mut stdout = child.stdout.take().unwrap();
        let drained = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let deadline = std::time::Instant::now() + budget;
        let completed = loop {
            if child.try_wait().unwrap().is_some() {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                break false;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        let stdout = drained.join().unwrap();
        assert!(
            completed,
            "MCP exceeded its test deadline: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let answers: Vec<Value> = String::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["result"].clone())
            .collect();
        assert_eq!(answers.len(), requests.len());
        answers
    }

    fn call(&self, server: &Server, surface: &str, tool: &str, args: Value) -> Value {
        self.rpc(server, self.root.path(), surface, vec![call(tool, args)])
            .remove(0)
    }
}

fn call(tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":arguments}})
}

fn text(answer: &Value) -> &str {
    answer["content"][0]["text"].as_str().unwrap()
}

#[test]
fn mcp_auto_area_catalogs_use_one_local_schema_for_every_server() {
    for capability in ["body", "header", "absent"] {
        let server = Server::start(capability);
        let project = Project::new(&server);
        for surface in ["compact", "full"] {
            let answers = project.rpc(
                &server,
                project.root.path(),
                surface,
                vec![json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})],
            );
            let tool = answers[0]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tool| tool["name"] == "task_add")
                .unwrap();
            let paths = &tool["inputSchema"]["properties"]["paths"];
            assert_eq!(paths["type"], "array", "{capability} {surface}: {tool}");
            assert_eq!(paths["items"]["type"], "string");
            let description = paths["description"].as_str().unwrap();
            for words in [
                "Files or directories",
                "relative to the workspace root",
                "registry_auto_area_v1",
                "On other servers paths are not sent; supply area",
            ] {
                assert!(description.contains(words), "{tool}");
            }
            let required = json!(["title"]);
            assert_eq!(tool["inputSchema"]["properties"]["area"]["type"], "string");
            let description = tool["description"].as_str().unwrap();
            assert!(
                description.contains("supporting servers derive area, otherwise use area"),
                "{tool}"
            );
            assert_eq!(
                tool["inputSchema"]["required"], required,
                "{capability} {surface}"
            );
        }
        assert!(
            server.state.lock().unwrap().seen.is_empty(),
            "tools/list contacted the server"
        );
    }
}

fn discovery_requests() -> Vec<Value> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    ]
}

#[test]
fn mcp_auto_area_discovery_ignores_an_unresponsive_server() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = Server {
        url: format!("http://{}", listener.local_addr().unwrap()),
        state: Arc::new(Mutex::new(State::default())),
    };
    let project = Project::new(&server);
    for surface in ["compact", "full"] {
        let answers = project.rpc_bounded(
            &server,
            project.root.path(),
            surface,
            discovery_requests(),
            std::time::Duration::from_secs(2),
        );
        assert_eq!(answers[0]["serverInfo"]["version"], "0.3.8");
        assert_eq!(answers[1], answers[2]);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "MCP startup or tools/list connected to the server"
        );
    }
}

#[cfg(unix)]
#[test]
fn mcp_auto_area_discovery_ignores_an_unresponsive_daemon() {
    let server = Server::start("absent");
    let project = Project::new(&server);
    let directory = project.runtime.path().join("lockyard");
    std::fs::create_dir(&directory).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(directory.join("agent.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    for surface in ["compact", "full"] {
        let answers = project.rpc_bounded(
            &server,
            project.root.path(),
            surface,
            discovery_requests(),
            std::time::Duration::from_secs(2),
        );
        assert_eq!(answers[1], answers[2]);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "MCP startup or tools/list connected to the daemon"
        );
    }
    assert!(server.state.lock().unwrap().seen.is_empty());
}

#[test]
fn mcp_auto_area_adds_normalized_workspace_paths_without_area_and_preserves_an_override() {
    for capability in ["body", "header"] {
        let server = Server::start(capability);
        let project = Project::new(&server);
        let nested = project.root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        for surface in ["compact", "full"] {
            let absolute = project.root.path().join("engine/src/main.rs");
            let answers = project.rpc(&server, &nested, surface, vec![
                call("task_add", json!({"title":"paths","paths":["engine\\src\\lib.rs", absolute]})),
                call("task_add", json!({"title":"override","paths":["engine/src"],"area":"Case Sensitive Override"}))
            ]);
            for answer in answers {
                assert_eq!(answer["isError"], false, "{answer}");
            }
            let writes = server.writes();
            let last = &writes[writes.len() - 2..];
            assert_eq!(
                last[0]["paths"],
                json!(["engine/src/lib.rs", "engine/src/main.rs"])
            );
            assert!(last[0].get("area").is_none());
            assert!(last[0].get("area_id").is_none());
            assert_eq!(last[1]["area"], "Case Sensitive Override");
        }
    }
}

#[test]
fn mcp_auto_area_missing_paths_are_refused_before_the_task_request_with_array_guidance() {
    let server = Server::start("body");
    let project = Project::new(&server);
    for surface in ["compact", "full"] {
        for args in [
            json!({"title":"missing","area":"engine"}),
            json!({"title":"empty","paths":[],"area":"engine"}),
        ] {
            let answer = project.call(&server, surface, "task_add", args);
            assert_eq!(answer["isError"], true, "{surface}: {answer}");
            assert!(text(&answer).contains("paths: ["), "{answer}");
            assert!(text(&answer).contains("корня рабочего места"), "{answer}");
        }
    }
    assert!(server.writes().is_empty());
}

#[test]
fn mcp_auto_area_old_servers_drop_paths_warn_and_preserve_compact_area_requirement() {
    let server = Server::start("absent");
    let project = Project::new(&server);
    let refused = project.call(
        &server,
        "compact",
        "task_add",
        json!({"title":"old","paths":["engine/src"]}),
    );
    assert_eq!(refused["isError"], true);
    assert!(text(&refused).contains("requires a non-empty area"));
    assert!(text(&refused).contains("does not yet understand task paths"));
    assert!(server.writes().is_empty());
    for surface in ["compact", "full"] {
        let mut args = json!({"title":"old","paths":["engine/src"]});
        if surface == "compact" {
            args["area"] = json!("engine");
        }
        let added = project.call(&server, surface, "task_add", args);
        assert_eq!(added["isError"], false, "{added}");
        assert!(
            text(&added).contains("does not yet understand task paths"),
            "{added}"
        );
        let writes = server.writes();
        assert!(writes.last().unwrap().get("paths").is_none());
        assert_eq!(writes.last().unwrap()["area_id"], "engine-id");
        let ordinary = project.call(
            &server,
            surface,
            "task_add",
            json!({"title":"legacy","area":"engine"}),
        );
        assert_eq!(ordinary["isError"], false, "{ordinary}");
        assert!(ordinary["structuredContent"].get("warning").is_none());
    }
}

#[test]
fn mcp_auto_area_rejects_paths_that_are_not_an_array_of_strings() {
    let server = Server::start("body");
    let project = Project::new(&server);
    for paths in [
        json!("engine/src"),
        json!([42]),
        json!(["engine/src", true]),
    ] {
        let answer = project.call(
            &server,
            "full",
            "task_add",
            json!({"title":"bad","paths":paths}),
        );
        assert_eq!(answer["isError"], true, "{answer}");
        assert!(
            text(&answer).contains("paths must be an array of strings"),
            "{answer}"
        );
    }
    assert!(server.writes().is_empty());
}

#[test]
fn mcp_auto_area_rejects_outside_and_parent_paths_before_creating_a_task() {
    let server = Server::start("body");
    let project = Project::new(&server);
    let outside = tempfile::tempdir().unwrap();
    for path in [
        outside.path().to_string_lossy().to_string(),
        "../outside".into(),
        "engine/../../outside".into(),
    ] {
        let answer = project.call(
            &server,
            "full",
            "task_add",
            json!({"title":"bad","paths":[path]}),
        );
        assert_eq!(answer["isError"], true, "{answer}");
    }
    assert!(server.writes().is_empty());
}

#[test]
fn mcp_auto_area_tasks_show_and_list_preserve_server_paths_and_legacy_output() {
    let server = Server::start("body");
    let project = Project::new(&server);
    for paths in [
        Some(vec![
            "engine/src".to_string(),
            "engine/README.md".to_string(),
        ]),
        None,
    ] {
        server.state.lock().unwrap().task_paths = paths.clone();
        for surface in ["compact", "full"] {
            for (args, key) in [
                (json!({"action":"show","id":"FE-0001"}), "task"),
                (json!({"action":"list"}), "0"),
            ] {
                let answer = project.call(&server, surface, "tasks", args);
                assert_eq!(answer["isError"], false, "{answer}");
                let task = if key == "task" {
                    &answer["structuredContent"]["task"]
                } else {
                    &answer["structuredContent"][0]
                };
                match &paths {
                    Some(paths) => assert_eq!(task["paths"], json!(paths), "{answer}"),
                    None => assert!(task.get("paths").is_none(), "{answer}"),
                }
            }
        }
    }
}

#[test]
fn mcp_auto_area_server_errors_explain_recovery_and_preserve_problem_details() {
    let server = Server::start("body");
    let project = Project::new(&server);
    for (code, details, expected) in [
        (
            "task_paths_required",
            json!({}),
            vec!["paths: [", "корня рабочего места"],
        ),
        (
            "task_paths_span_repositories",
            json!({"roots":["engine","games/game-test"]}),
            vec![
                "engine",
                "games/game-test",
                "заведи по одной задаче на репозиторий",
            ],
        ),
        (
            "area_mismatch",
            json!({"derived":"engine"}),
            vec!["engine", "Убери --area / area"],
        ),
        (
            "area_closed",
            json!({}),
            vec!["закрыта", "открытую область"],
        ),
        (
            "area_template_conflict",
            json!({"root":"engine","prefix":"EN","existing_area":"taken"}),
            vec!["engine", "EN", "taken", "Ведущий"],
        ),
    ] {
        let status = if code == "area_template_conflict" {
            409
        } else {
            422
        };
        server.state.lock().unwrap().refusal = Some((
            status,
            json!({
                "type":format!("urn:lockyard:problem:{code}"),"title":"Task refused","status":status,"detail":"opaque server refusal","code":code,"details":details
            }),
        ));
        let answer = project.call(
            &server,
            "full",
            "task_add",
            json!({"title":"failure","paths":["engine/src"]}),
        );
        assert_eq!(answer["isError"], true, "{answer}");
        for expected in expected {
            assert!(text(&answer).contains(expected), "{code}: {answer}");
        }
        assert_eq!(answer["structuredContent"]["code"], code);
        assert_eq!(answer["structuredContent"]["details"], details);
    }
}
