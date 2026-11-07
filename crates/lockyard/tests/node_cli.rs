// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Executable-level node CLI and MCP checks with isolated test keys.
#![cfg(unix)]
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

fn command(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    c.current_dir(dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env_remove("LOCKYARD_NODE_CONFIG");
    c
}
fn init(dir: &Path) -> std::process::Output {
    command(dir)
        .args([
            "--json",
            "node",
            "init",
            "--config",
            dir.join("node.toml").to_str().unwrap(),
            "--state-dir",
            dir.join("state").to_str().unwrap(),
            "--node-id",
            "one",
            "--workspace",
            "test-workspace",
            "--tls-name",
            "one.example",
        ])
        .output()
        .unwrap()
}
#[test]
fn init_requires_existing_key_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    assert!(!init(path).status.success());
    assert!(!path.join("state").exists());
    let keys = path.join("config/lockyard/keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(keys.join("test-workspace.key"), [7u8; 32]).unwrap();
    fs::set_permissions(
        keys.join("test-workspace.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let result = init(path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(receipt["certificate_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        fs::metadata(path.join("node.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let before = fs::read(path.join("node.toml")).unwrap();
    assert!(!init(path).status.success());
    assert_eq!(before, fs::read(path.join("node.toml")).unwrap());
    let list = command(path)
        .args([
            "--json",
            "node",
            "list",
            "--config",
            path.join("node.toml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&list.stdout).unwrap()["peers"],
        json!([])
    );
}
#[test]
fn mcp_exposes_job_tools_and_reports_uncertain_submission_with_same_id_without_project() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("config/lockyard/keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(keys.join("test-workspace.key"), [7u8; 32]).unwrap();
    fs::set_permissions(
        keys.join("test-workspace.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(init(dir.path()).status.success());
    let config = dir.path().join("node.toml");
    let mut child = command(dir.path())
        .args(["mcp", "--tools", "full"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let input = child.stdin.as_mut().unwrap();
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})
    )
    .unwrap();
    let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    writeln!(input,"{}",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"job_submit","arguments":{"target":"worker","id":id,"repository":"repo","runner":"runner","config":config}}})).unwrap();
    drop(child.stdin.take());
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let lines: Vec<Value> = String::from_utf8(result.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        lines[0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "job_patch")
    );
    assert_eq!(lines[1]["result"]["isError"], true);
    let payload: Value =
        serde_json::from_str(lines[1]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["job_id"], id);
    assert_eq!(payload["error"]["code"], "outcome_unknown");
}

#[test]
fn real_node_service_serves_cli_and_mcp_over_control_socket() {
    struct Service(std::process::Child);
    impl Drop for Service {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let keys = path.join("config/lockyard/keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(keys.join("test-workspace.key"), [7u8; 32]).unwrap();
    fs::set_permissions(
        keys.join("test-workspace.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(init(path).status.success());
    let config = path.join("node.toml");
    let config_text = config.to_str().unwrap();
    let _service = Service(
        command(path)
            .args(["node", "serve", "--config", config_text])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = path.join("state/control.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(socket.exists(), "node service did not start");
    let ping = command(path)
        .args(["--json", "node", "ping", "one", "--config", config_text])
        .output()
        .unwrap();
    assert!(
        ping.status.success(),
        "{}",
        String::from_utf8_lossy(&ping.stderr)
    );
    let response: Value = serde_json::from_slice(&ping.stdout).unwrap();
    assert_eq!(response["result"]["node_id"], "one");
    let mut child = command(path)
        .args(["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(),"{}",json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"node_ping","arguments":{"target":"one","config":config_text}}})).unwrap();
    drop(child.stdin.take());
    let response = child.wait_with_output().unwrap();
    assert!(response.status.success());
    let mcp: Value = serde_json::from_slice(&response.stdout).unwrap();
    assert_eq!(mcp["result"]["isError"], false);
    let payload: Value =
        serde_json::from_str(mcp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["result"]["node_id"], "one");
}

#[test]
fn killed_submitter_recovers_id_and_rejects_changed_specification() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let keys = path.join("config/lockyard/keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(keys.join("test-workspace.key"), [7u8; 32]).unwrap();
    fs::set_permissions(
        keys.join("test-workspace.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(init(path).status.success());
    let config = path.join("node.toml");
    let config_text = config.to_str().unwrap();
    let prompt = path.join("prompt");
    fs::write(&prompt, "private test prompt").unwrap();
    let listener = UnixListener::bind(path.join("state/control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = command(path)
        .args([
            "--json",
            "job",
            "submit",
            "one",
            "--repository",
            "repo",
            "--runner",
            "runner",
            "--config",
            config_text,
            "--prompt-file",
            prompt.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stream = None;
    for _ in 0..250 {
        match listener.accept() {
            Ok((s, _)) => {
                stream = Some(s);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("{e}"),
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("submit exited before dispatch: {status}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let mut stream = stream.expect("submit did not reach control socket");
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).unwrap();
    let mut packet = vec![0; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut packet).unwrap();
    let request: Value = serde_json::from_slice(&packet).unwrap();
    let id = request["payload"]["id"].as_str().unwrap().to_string();
    child.kill().unwrap();
    child.wait().unwrap();
    drop(stream);
    drop(listener);
    let submissions = path.join("state/submissions");
    // An interrupted temporary write is invisible. A corrupt receipt from an
    // older version is reported individually without hiding valid receipts.
    fs::write(submissions.join(".receipt-interrupted.tmp"), b"{").unwrap();
    let bad_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let bad_path = submissions.join(format!("{bad_id}.json"));
    fs::write(&bad_path, b"{").unwrap();
    fs::set_permissions(&bad_path, fs::Permissions::from_mode(0o600)).unwrap();
    let list = command(path)
        .args(["--json", "job", "receipts", "--config", config_text])
        .output()
        .unwrap();
    assert!(list.status.success());
    let list: Value = serde_json::from_slice(&list.stdout).unwrap();
    let entries = list["receipts"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|entry| entry["job_id"] == bad_id && entry["error"].is_string())
    );
    let receipt = &entries.iter().find(|entry| entry["job_id"] == id).unwrap()["receipt"];
    assert_eq!(receipt["job_id"], id);
    assert_eq!(receipt["status"], "dispatching");
    assert_eq!(receipt["target"], "one");
    let receipt_path = path.join("state/submissions").join(format!("{id}.json"));
    assert_eq!(
        fs::metadata(&receipt_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !String::from_utf8(fs::read(&receipt_path).unwrap())
            .unwrap()
            .contains("private test prompt")
    );
    let changed = command(path)
        .args([
            "--json",
            "job",
            "submit",
            "one",
            "--repository",
            "different",
            "--runner",
            "runner",
            "--id",
            &id,
            "--config",
            config_text,
            "--prompt-file",
            prompt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!changed.status.success());
    let response: Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(response["job_id"], id);
    assert_eq!(response["error"]["code"], "receipt_unavailable_or_conflict");
}

#[test]
fn concurrent_different_specs_cannot_claim_one_receipt_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    let keys = path.join("config/lockyard/keys");
    fs::create_dir_all(&keys).unwrap();
    fs::set_permissions(keys.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(keys.join("test-workspace.key"), [7u8; 32]).unwrap();
    fs::set_permissions(
        keys.join("test-workspace.key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(init(path).status.success());
    let config = path.join("node.toml");
    let config = config.to_str().unwrap();
    let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let spawn = |repository| {
        command(path)
            .args([
                "--json",
                "job",
                "submit",
                "one",
                "--repository",
                repository,
                "--runner",
                "runner",
                "--id",
                id,
                "--config",
                config,
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let one = spawn("one");
    let two = spawn("two");
    let one = one.wait_with_output().unwrap();
    let two = two.wait_with_output().unwrap();
    let one: Value = serde_json::from_slice(&one.stdout).unwrap();
    let two: Value = serde_json::from_slice(&two.stdout).unwrap();
    let mut codes = vec![
        one["error"]["code"].as_str().unwrap(),
        two["error"]["code"].as_str().unwrap(),
    ];
    codes.sort_unstable();
    assert_eq!(
        codes,
        vec!["outcome_unknown", "receipt_unavailable_or_conflict"]
    );
    let bytes = fs::read(path.join("state/submissions").join(format!("{id}.json"))).unwrap();
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved["job_id"], id);
}
