// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Real process shutdown must move committed WAL records into the database file.

use lockyard_core::{DIR_NAME, Store};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);

impl Process {
    fn finish(&mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.0.try_wait().unwrap().is_some() {
                let mut stdout = String::new();
                let mut stderr = String::new();
                use std::io::Read;
                if let Some(mut pipe) = self.0.stdout.take() {
                    pipe.read_to_string(&mut stdout).unwrap();
                }
                if let Some(mut pipe) = self.0.stderr.take() {
                    pipe.read_to_string(&mut stderr).unwrap();
                }
                return Output {
                    status: self.0.wait().unwrap(),
                    stdout: stdout.into_bytes(),
                    stderr: stderr.into_bytes(),
                };
            }
            assert!(Instant::now() < deadline, "process did not stop cleanly");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(root)
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_MCP_TOOLS")
        .env_remove("LOCKYARD_REQUIRE_E2EE")
        .env_remove("LOCKYARD_E2EE_WORKSPACE_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    let mut store = Store::init(project.path()).unwrap();
    // A real MCP request uses the current time and performs the normal retention sweep.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    store.touch("bob", now).unwrap();
    store.send("alice", "bob", "short CLI write", now).unwrap();
    drop(store);
    project
}

fn assert_wal_has_records(root: &Path) {
    assert!(
        fs::metadata(root.join(DIR_NAME).join("lockyard.db-wal"))
            .unwrap()
            .len()
            > 32,
        "test requires committed records still in WAL before shutdown"
    );
}

fn database_copy(root: &Path) -> (tempfile::TempDir, Store) {
    let isolated = tempfile::tempdir().unwrap();
    fs::create_dir(isolated.path().join(DIR_NAME)).unwrap();
    fs::copy(
        root.join(DIR_NAME).join("lockyard.db"),
        isolated.path().join(DIR_NAME).join("lockyard.db"),
    )
    .unwrap();
    let store = Store::open(isolated.path()).unwrap();
    (isolated, store)
}

fn assert_message_in_database_file(root: &Path, body: &str) {
    let (_isolated, store) = database_copy(root);
    assert!(
        store
            .peek_inbox("bob", true, 100)
            .unwrap()
            .iter()
            .any(|message| message.body == body),
        "database-only copy lost committed message {body:?}"
    );
}

fn writing_mcp(root: &Path) -> Process {
    let mut process = Process(
        command(root)
            .args(["mcp", "--tools", "full"])
            .spawn()
            .unwrap(),
    );
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"msg_send","arguments":{"to":"bob","body":"MCP write"}}});
    writeln!(process.0.stdin.as_mut().unwrap(), "{request}").unwrap();
    process.0.stdin.as_mut().unwrap().flush().unwrap();
    let mut response = String::new();
    BufReader::new(process.0.stdout.as_mut().unwrap())
        .read_line(&mut response)
        .unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_wal_has_records(root);
    process
}

#[test]
fn mcp_clean_eof_makes_database_file_self_contained() {
    let project = project();
    let mut process = writing_mcp(project.path());
    drop(process.0.stdin.take());
    let output = process.finish();
    assert!(output.status.success(), "{output:?}");
    assert_message_in_database_file(project.path(), "short CLI write");
    assert_message_in_database_file(project.path(), "MCP write");
}

#[cfg(unix)]
fn signal(process: &Process, signal: libc::c_int) {
    assert_eq!(
        unsafe { libc::kill(process.0.id() as libc::pid_t, signal) },
        0
    );
}

#[cfg(unix)]
#[test]
fn mcp_sigterm_with_partial_stdin_stops_cleanly_and_checkpoints() {
    let project = project();
    let mut process = writing_mcp(project.path());
    // Shutdown must not depend on receiving another whole request or EOF.
    process
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"partial\":")
        .unwrap();
    process.0.stdin.as_mut().unwrap().flush().unwrap();
    signal(&process, libc::SIGTERM);
    let output = process.finish();
    assert!(output.status.success(), "{output:?}");
    assert_message_in_database_file(project.path(), "short CLI write");
    assert_message_in_database_file(project.path(), "MCP write");
}

#[cfg(unix)]
#[test]
fn mcp_sigint_stops_cleanly_and_checkpoints() {
    let project = project();
    let mut process = writing_mcp(project.path());
    signal(&process, libc::SIGINT);
    let output = process.finish();
    assert!(output.status.success(), "{output:?}");
    assert_message_in_database_file(project.path(), "short CLI write");
    assert_message_in_database_file(project.path(), "MCP write");
}

#[test]
fn monitor_timeout_checkpoints_its_final_receipt() {
    let project = project();
    let output = command(project.path())
        .env("LOCKYARD_AGENT", "bob")
        .env("LOCKYARD_WATCH", "off")
        .args([
            "monitor",
            "--timeout",
            "1",
            "--reconcile",
            "1",
            "--no-zones",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let (_isolated, store) = database_copy(project.path());
    assert_eq!(store.peek_inbox("bob", true, 100).unwrap().len(), 1);
    assert!(store.peek_inbox("bob", false, 100).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn monitor_sigterm_interrupts_a_long_reconcile_wait() {
    let project = project();
    let mut process = Process(
        command(project.path())
            .env("LOCKYARD_WATCH", "off")
            .args(["monitor", "--reconcile", "60", "--no-mail", "--no-zones"])
            .spawn()
            .unwrap(),
    );
    // Let command parsing and handler installation finish before sending the signal.
    std::thread::sleep(Duration::from_millis(300));
    assert_wal_has_records(project.path());
    signal(&process, libc::SIGTERM);
    let output = process.finish();
    assert!(output.status.success(), "{output:?}");
    assert_message_in_database_file(project.path(), "short CLI write");
}

#[cfg(unix)]
#[test]
fn agent_sigterm_stops_workers_and_checkpoints_existing_project_database() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let project = project();
    // The gate sets TMPDIR to its private evidence directory; keep socket suffixes short.
    let private = tempfile::Builder::new()
        .prefix("lys-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let server = std::thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let mut request = [0; 8192];
                let _ = stream.read(&mut request);
                let body = "{\"error\":{\"code\":\"not_found\",\"message\":\"not found\"}}";
                let _ = write!(
                    stream,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    });
    fs::write(
        project.path().join(DIR_NAME).join("config.toml"),
        format!("mode = \"cloud\"\nurl = \"{url}\"\nworkspace = \"test\"\n"),
    )
    .unwrap();
    let mut process = Process(
        command(project.path())
            .env("LOCKYARD_URL", &url)
            .env("LOCKYARD_TOKEN", "shutdown-test-token")
            .env("XDG_RUNTIME_DIR", private.path().join("run"))
            .env("XDG_STATE_HOME", private.path().join("state"))
            .env("XDG_CONFIG_HOME", private.path().join("config"))
            .arg("agent")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !private.path().join("run/lockyard/agent.sock").exists() {
        if process.0.try_wait().unwrap().is_some() {
            let output = process.finish();
            stop.store(true, Ordering::Relaxed);
            server.join().unwrap();
            panic!(
                "agent exited before binding socket (private state root {}): {output:?}",
                private.path().display()
            );
        }
        assert!(Instant::now() < deadline, "agent did not bind socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    signal(&process, libc::SIGTERM);
    let output = process.finish();
    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_message_in_database_file(project.path(), "short CLI write");
}

#[cfg(unix)]
#[test]
fn node_sigterm_stops_runtime_and_checkpoints_existing_project_database() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let project = project();
    let private = tempfile::Builder::new()
        .prefix("lyn-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let private_root = private.path().canonicalize().unwrap();
    let state = private_root.join("node");
    let identity = lockyard_node::quic::generate_identity(&state, vec!["worker".into()]).unwrap();
    let config_root = private_root.join("config");
    let keys = config_root.join("lockyard/keys");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&keys)
        .unwrap();
    fs::write(keys.join("workspace.key"), [7u8; 32]).unwrap();
    fs::set_permissions(
        keys.join("workspace.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let configuration = private_root.join("node.toml");
    let config = json!({"node_id":"worker", "workspace":"workspace", "state_dir":state,
        "certificate":identity.certificate, "private_key":identity.private_key,
        "trust_anchors":[], "peers":[], "rpc_timeout_seconds":1});
    fs::write(&configuration, toml::to_string_pretty(&config).unwrap()).unwrap();
    fs::set_permissions(&configuration, fs::Permissions::from_mode(0o600)).unwrap();
    let mut process = Process(
        command(project.path())
            .env("XDG_CONFIG_HOME", config_root)
            .args(["node", "serve", "--config"])
            .arg(&configuration)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !state.join("control.sock").exists() {
        if process.0.try_wait().unwrap().is_some() {
            panic!("node exited before binding socket: {:?}", process.finish());
        }
        assert!(Instant::now() < deadline, "node did not bind socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    signal(&process, libc::SIGTERM);
    let output = process.finish();
    assert!(output.status.success(), "{output:?}");
    assert_message_in_database_file(project.path(), "short CLI write");
}
