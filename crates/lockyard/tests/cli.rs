// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives the real binary, the way agents do: separate processes on one project.

use serde_json::{Value, json};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn lockyard(dir: &Path, agent: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(args)
        .current_dir(dir)
        .env("LOCKYARD_AGENT", agent)
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap()
}

fn ok(dir: &Path, agent: &str, args: &[&str]) -> String {
    let result = lockyard(dir, agent, args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), "setup", &["init"]);
    dir
}

#[test]
fn version_about_and_usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let version = ok(dir.path(), "a", &["--version"]);
    assert_eq!(
        version.trim(),
        format!("lockyard {}", lockyard_core::VERSION)
    );
    assert!(ok(dir.path(), "a", &["about"]).contains(lockyard_core::HOMEPAGE));
    assert_eq!(lockyard(dir.path(), "a", &["nope"]).status.code(), Some(2));
    assert_eq!(lockyard(dir.path(), "a", &[]).status.code(), Some(2));
}

#[test]
fn commands_outside_a_project_say_so() {
    // Prefer a real system temp dir: the sandbox often sets TMPDIR inside a tree that already
    // has a Lockyard project above it, and find_root would walk into that instead.
    let dir = tempfile::Builder::new()
        .prefix("lockyard-no-project-")
        .tempdir_in("/tmp")
        .unwrap_or_else(|_| tempfile::tempdir().unwrap());
    if lockyard_core::paths::find_root(dir.path()).is_some() {
        return;
    }
    let result = lockyard(dir.path(), "a", &["zone", "list"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("lockyard init"));
}

#[test]
fn a_write_without_an_agent_name_is_refused() {
    let dir = project();
    let result = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["zone", "claim", "src"])
        .current_dir(dir.path())
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("LOCKYARD_AGENT"));
}

#[test]
fn zones_collide_across_folders_and_exit_with_the_conflict_code() {
    let dir = project();
    let deep = dir.path().join("src/deep");
    std::fs::create_dir_all(&deep).unwrap();
    ok(
        dir.path(),
        "a",
        &["zone", "claim", "src", "--note", "refactor"],
    );

    let refused = lockyard(&deep, "b", &["zone", "claim", "x.rs"]);
    assert_eq!(refused.status.code(), Some(3));
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("src/deep/x.rs is held by a"));
    assert!(message.contains("refactor"));

    assert_eq!(
        lockyard(&deep, "b", &["zone", "check", "x.rs"])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(ok(&deep, "a", &["zone", "check", "x.rs"]).trim(), "free");

    ok(dir.path(), "a", &["zone", "release"]);
    ok(&deep, "b", &["zone", "claim", "x.rs"]);
}

#[test]
fn a_path_outside_the_project_cannot_be_claimed() {
    let dir = project();
    let result = lockyard(dir.path(), "a", &["zone", "claim", "../elsewhere"]);
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn one_process_wins_a_race_for_a_path() {
    let dir = project();
    let racers: Vec<_> = (0..12)
        .map(|index| {
            Command::new(env!("CARGO_BIN_EXE_lockyard"))
                .args(["zone", "claim", "src"])
                .current_dir(dir.path())
                .env("LOCKYARD_AGENT", format!("agent-{index}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    let codes: Vec<_> = racers
        .into_iter()
        .map(|mut racer| racer.wait().unwrap().code())
        .collect();
    assert_eq!(codes.iter().filter(|code| **code == Some(0)).count(), 1);
    assert_eq!(codes.iter().filter(|code| **code == Some(3)).count(), 11);
}

#[test]
fn a_full_conversation_and_task_cycle_over_json() {
    let dir = project();
    let root = dir.path();
    ok(root, "lead", &["who"]);
    ok(root, "worker", &["zone", "list"]);
    ok(root, "lead", &["zone", "list"]);

    let added = ok(
        root,
        "lead",
        &["--json", "task", "add", "ship it", "--body", "details"],
    );
    let added: Value = serde_json::from_str(&added).unwrap();
    assert_eq!(added["status"], "open");
    let id = added["id"].as_str().unwrap().to_string();

    ok(root, "worker", &["task", "claim", &id]);
    ok(
        root,
        "worker",
        &["task", "submit", &id, "--evidence", "ran the tests"],
    );
    let own = lockyard(root, "worker", &["task", "accept", &id]);
    assert_eq!(own.status.code(), Some(1));
    ok(root, "lead", &["task", "accept", &format!("T-{id}")]);
    assert_eq!(ok(root, "lead", &["task", "list"]).trim(), "no tasks");
    assert!(ok(root, "lead", &["task", "show", &id]).contains("ran the tests"));
}

#[test]
fn status_only_shows_the_current_agents_claims_and_tasks() {
    let dir = project();
    let root = dir.path();
    ok(root, "alice", &["zone", "claim", "src"]);
    ok(root, "bob", &["zone", "claim", "docs"]);
    ok(root, "alice", &["task", "add", "alice task"]);
    ok(root, "bob", &["task", "add", "bob task"]);
    ok(root, "alice", &["task", "claim", "D-1"]);
    ok(root, "bob", &["task", "claim", "D-2"]);
    lockyard_core::Store::open(root)
        .unwrap()
        .record_unannounced("docs/outside.rs", "bob", 99, 1_000)
        .unwrap();
    let status = ok(root, "alice", &["--json", "status"]);
    let status: Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status["claims"].as_array().unwrap().len(), 1);
    assert_eq!(status["claims"][0]["agent"], "alice");
    assert_eq!(status["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(status["tasks"][0]["title"], "alice task");
    assert!(status["unannounced"].as_array().unwrap().is_empty());
}

/// Exercise the cloud CLI against actual HTTP responses, without an agent or live credentials.
fn cloud_status(claims: Value, work: Value, json_output: bool) -> String {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            let path = first.split_whitespace().nth(1).unwrap();
            let answer = match path.split('?').next().unwrap() {
                "/api/v1/workspace/encryption" => json!({"encryption":"off", "key_id":null,
                    "workspace_id":"00000000-0000-0000-0000-000000000001"}),
                "/api/v1/zones/claims" => claims.clone(),
                "/api/v1/bus/inbox" => json!({"messages":[], "skipped":0}),
                "/api/v1/bus/tasks" => work.clone(),
                "/api/v1/registry/items" => json!({"items":[], "cursor":null}),
                other => panic!("unexpected status route: {other}"),
            };
            let body = answer.to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".lockyard")).unwrap();
    std::fs::write(
        dir.path().join(".lockyard/config.toml"),
        format!("mode = 'cloud'\nurl = '{url}'\nworkspace = 'team'\n"),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    if json_output {
        command.arg("--json");
    }
    let result = command
        .arg("status")
        .current_dir(dir.path())
        .env("LOCKYARD_AGENT", "alice")
        .env("LOCKYARD_TOKEN", "test-token")
        .env("LOCKYARD_URL", url)
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", runtime.path().join("state"))
        .env_remove("LOCKYARD_TOKEN_FILE")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn cloud_status_only_lists_active_relevant_work_in_json_and_text() {
    let task = |id, status, to, assignee| {
        json!({"id":id, "title":format!("work-{id}"),
        "status":status, "to":to, "assignee":assignee, "version":1})
    };
    let work = json!([
        task(1, "claimed", "*", "alice"), task(2, "offered", "alice", ""),
        task(3, "claimed", "bob", "bob"), task(4, "accepted", "alice", "alice"),
        task(5, "offered", "*", ""), task(6, "failed", "alice", "alice"),
        task(7, "expired", "alice", "alice"), task(8, "cancelled", "alice", "alice"),
        {"id":9, "title":"work-9", "status":"review", "to":"bob", "lead":"alice", "version":1},
        {"id":10, "title":"work-10", "status":"claimed", "to":"*", "executor":"alice", "version":1}
    ]);
    let status: Value = serde_json::from_str(&cloud_status(json!([]), work.clone(), true)).unwrap();
    let ids: Vec<_> = status["work"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, vec![1, 2, 9, 10]);
    let text = cloud_status(json!([]), work, false);
    for id in [1, 2, 9, 10] {
        assert!(text.contains(&format!("work-{id}")), "{text}");
    }
    for id in [3, 4, 5, 6, 7, 8] {
        assert!(!text.contains(&format!("work-{id}")), "{text}");
    }
}

#[test]
fn cloud_status_bounds_work_after_filtering() {
    let mut work =
        vec![json!({"id":1, "title":"foreign-final", "status":"accepted", "to":"*", "version":1})];
    work.extend((2..17).map(|id| {
        json!({"id":id, "title":format!("work-{id}"),
        "status":"offered", "to":"alice", "version":1})
    }));
    let status: Value = serde_json::from_str(&cloud_status(json!([]), json!(work), true)).unwrap();
    let work = status["work"].as_array().unwrap();
    assert_eq!(work.len(), 10);
    assert_eq!(work[0]["id"], 2);
    assert_eq!(work[9]["id"], 11);
}

#[test]
fn cloud_status_separates_incoming_handover_offers_from_owned_claims() {
    let claims = json!([
        {"id":41, "session":"bob", "paths":["incoming/path"], "note":"please take over", "handover_to":"alice", "offered_to_you":true},
        {"id":42, "session":"alice", "paths":["owned/path"]}
    ]);
    let status: Value =
        serde_json::from_str(&cloud_status(claims.clone(), json!([]), true)).unwrap();
    assert_eq!(status["claims"].as_array().unwrap().len(), 1);
    assert_eq!(status["claims"][0]["id"], 42);
    assert_eq!(status["offers"].as_array().unwrap().len(), 1);
    assert_eq!(status["offers"][0]["id"], 41);
    assert_eq!(status["offers"][0]["from"], "bob");
    assert_eq!(status["offers"][0]["paths"], json!(["incoming/path"]));
    let text = cloud_status(claims, json!([]), false);
    assert!(text.contains("Z-41 offered to you by bob"), "{text}");
    assert!(text.contains("incoming/path"), "{text}");
    assert!(text.contains("Z-42  alice  owned/path"), "{text}");
    assert!(!text.contains("Z-41  bob"), "{text}");
}

#[test]
fn task_commands_print_the_registry_identifier_once() {
    let dir = project();
    let added = ok(dir.path(), "lead", &["task", "add", "ship"]);
    assert!(added.starts_with("D-1  "), "{added}");
    assert!(!added.starts_with("T-D-1"));
}

#[test]
fn task_cancel_help_matches_author_permissions() {
    let dir = project();
    let help = ok(dir.path(), "lead", &["task", "cancel", "--help"]);
    assert!(help.contains("Cancel a task you wrote"), "{help}");
}

#[test]
fn task_lookup_errors_include_the_requested_identifier() {
    let dir = project();
    let output = lockyard(dir.path(), "lead", &["task", "show", "ZZ-9999"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("ZZ-9999"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_closed_status_pipe_exits_quietly() {
    let dir = project();
    for index in 0..80 {
        let path = format!("src/long-path-{index:03}-with-some-extra-content.rs");
        ok(dir.path(), "alice", &["zone", "claim", &path]);
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["status"])
        .current_dir(dir.path())
        .env("LOCKYARD_AGENT", "alice")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn repeated_case_insensitive_claims_reuse_one_claim() {
    let dir = project();
    let first: Value = serde_json::from_str(&ok(
        dir.path(),
        "alice",
        &["--json", "zone", "claim", "Auth/a.cs"],
    ))
    .unwrap();
    let second: Value = serde_json::from_str(&ok(
        dir.path(),
        "alice",
        &["--json", "zone", "claim", "auth/a.cs"],
    ))
    .unwrap();
    assert_eq!(first["id"], second["id"]);
    let claims: Value =
        serde_json::from_str(&ok(dir.path(), "alice", &["--json", "zone", "list"])).unwrap();
    assert_eq!(claims.as_array().unwrap().len(), 1);
}

#[test]
fn mail_needs_a_known_addressee_and_reads_once() {
    let dir = project();
    let root = dir.path();
    let unknown = lockyard(root, "a", &["msg", "send", "ghost", "hi"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("ghost"));
    ok(root, "b", &["msg", "inbox"]);
    ok(root, "a", &["msg", "send", "b", "hi there"]);
    assert!(ok(root, "b", &["msg", "inbox", "--peek"]).contains("hi there"));
    assert!(ok(root, "b", &["status"]).contains("unread mail: 1"));
    assert!(ok(root, "b", &["msg", "inbox"]).contains("hi there"));
    assert_eq!(ok(root, "b", &["msg", "inbox"]).trim(), "no new mail");
}

#[test]
fn zone_release_errors_name_the_missing_claim_and_keep_live_claims() {
    let dir = project();
    let root = dir.path();
    let claim: Value =
        serde_json::from_str(&ok(root, "alice", &["--json", "zone", "claim", "src"])).unwrap();
    let actual_id = claim["id"].as_i64().unwrap();

    let missing = lockyard(root, "alice", &["zone", "release", "999999"]);

    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("Z-999999"));
    let claims: Value =
        serde_json::from_str(&ok(root, "alice", &["--json", "zone", "list"])).unwrap();
    assert!(
        claims
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == actual_id)
    );
}

#[test]
fn the_board_and_presence_work_in_local_mode() {
    let dir = project();
    let root = dir.path();
    ok(root, "a", &["board", "set", "deploy", "ready"]);
    assert_eq!(
        ok(root, "a", &["board", "get", "deploy"]).trim(),
        "deploy = ready"
    );
    let listed: Value = serde_json::from_str(&ok(root, "a", &["--json", "board", "list"])).unwrap();
    assert_eq!(listed[0]["value"], "ready");
    ok(root, "a", &["presence", "beat"]);
    assert!(ok(root, "a", &["presence", "list"]).contains("cli"));
    ok(root, "a", &["board", "rm", "deploy"]);
    assert_eq!(
        lockyard(root, "a", &["board", "get", "deploy"])
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn cloud_only_commands_explain_themselves_in_local_mode() {
    let dir = project();
    let root = dir.path();
    for args in [
        &["zone", "wait", "src"][..],
        &["zone", "queue", "src"],
        &["zone", "queue"],
        &["zone", "unwait", "1"],
        &["zone", "request", "src", "--text", "please"],
        &["zone", "answer", "1"],
        &["zone", "handover", "1", "--to", "b"],
        &["zone", "accept", "1"],
        &["zone", "narrow", "1", "src"],
        &["zone", "add-path", "1", "src"],
        &["zone", "takeover", "1", "--reason", "gone"],
        &["zone", "dirty", "list"],
        &["zone", "claim", "src", "--shared"],
        &["msg", "ack", "1"],
        &["msg", "thread", "1"],
        &["events"],
        &["work", "list"],
        &["cloud", "export"],
        &["agent"],
    ] {
        let result = lockyard(root, "a", args);
        assert_eq!(result.status.code(), Some(1), "{args:?}");
        let message = String::from_utf8_lossy(&result.stderr);
        assert!(message.contains("needs cloud mode"), "{args:?}: {message}");
    }
}

#[test]
fn errors_are_json_under_the_json_flag() {
    let dir = project();
    let result = lockyard(dir.path(), "a", &["--json", "work", "list"]);
    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "needs_cloud");
}

/// Runs the binary with a home folder of its own and an empty search path, so detection answers
/// from the folders the test made and never from the machine running it.
fn lockyard_at_home(dir: &Path, home: &Path, agent: &str, args: &[&str]) -> Output {
    let empty = home.join("empty-bin");
    std::fs::create_dir_all(&empty).unwrap();
    Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(args)
        .current_dir(dir)
        .env("LOCKYARD_AGENT", agent)
        .env("PATH", &empty)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("CODEX_HOME", home.join(".codex"))
        .env("COPILOT_HOME", home.join(".copilot"))
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .output()
        .unwrap()
}

fn ok_at_home(dir: &Path, home: &Path, agent: &str, args: &[&str]) -> String {
    let result = lockyard_at_home(dir, home, agent, args);
    assert!(
        result.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

/// Gemini stands in for the clients here: its files sit in folders a sandbox will let a test
/// create, while `.claude/` and `.cursor/` are refused by some hosts.
#[test]
fn setup_writes_a_client_config_and_uninstall_takes_it_back() {
    let dir = project();
    let root = dir.path();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let settings = root.join(".gemini/settings.json");
    let instructions = root.join("GEMINI.md");
    std::fs::write(&instructions, "# House rules\n").unwrap();

    let dry = ok_at_home(
        root,
        &home,
        "a",
        &["setup", "--client", "gemini", "--dry-run"],
    );
    assert!(dry.contains("would create"), "{dry}");
    assert!(!settings.exists(), "a dry run writes nothing");

    let done = ok_at_home(root, &home, "a", &["setup", "--client", "gemini"]);
    assert!(done.contains("create"), "{done}");
    let written = std::fs::read_to_string(&settings).unwrap();
    assert!(written.contains("\"lockyard\""));
    let block = std::fs::read_to_string(&instructions).unwrap();
    assert!(block.starts_with("# House rules\n"));
    assert!(block.contains("lockyard:start"));

    let again = ok_at_home(root, &home, "a", &["setup", "--client", "gemini"]);
    assert!(
        !again.contains("create") && !again.contains("update"),
        "a second run must change nothing: {again}"
    );

    let health: Value =
        serde_json::from_str(&ok_at_home(root, &home, "a", &["--json", "doctor"])).unwrap();
    assert_eq!(health["ok"], true, "{health}");

    ok_at_home(
        root,
        &home,
        "a",
        &["setup", "--client", "gemini", "--uninstall"],
    );
    assert!(
        !settings.exists(),
        "a file Lockyard created alone goes away"
    );
    assert_eq!(
        std::fs::read_to_string(&instructions).unwrap(),
        "# House rules\n"
    );
}

#[test]
fn doctor_fails_outside_a_project_and_names_the_fix() {
    let dir = tempfile::Builder::new()
        .prefix("lockyard-no-project-")
        .tempdir_in("/tmp")
        .unwrap_or_else(|_| tempfile::tempdir().unwrap());
    if lockyard_core::paths::find_root(dir.path()).is_some() {
        return;
    }
    let result = lockyard_at_home(dir.path(), dir.path(), "a", &["doctor"]);
    assert_eq!(result.status.code(), Some(1));
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(text.contains("lockyard init"), "{text}");
}

#[test]
fn every_new_command_accepts_the_json_flag() {
    let dir = project();
    let setup: Value = serde_json::from_str(&ok(
        dir.path(),
        "a",
        &["--json", "setup", "--print", "--client", "claude"],
    ))
    .unwrap();
    assert!(
        setup["setup"]
            .as_str()
            .unwrap()
            .contains("lockyard hook claude")
    );
    let board: Value =
        serde_json::from_str(&ok(dir.path(), "a", &["--json", "board", "list"])).unwrap();
    assert!(board.is_array());
}

#[test]
fn printed_mail_is_marked_after_the_output_and_peek_marks_nothing() {
    let dir = project();
    let root = dir.path();
    ok(root, "b", &["msg", "inbox"]);
    ok(root, "a", &["msg", "send", "b", "hello"]);
    assert_eq!(ok(root, "b", &["msg", "unread"]).trim(), "unread mail: 1");
    ok(root, "b", &["msg", "inbox", "--peek"]);
    assert_eq!(ok(root, "b", &["msg", "unread"]).trim(), "unread mail: 1");
    ok(root, "b", &["msg", "inbox"]);
    assert_eq!(ok(root, "b", &["msg", "unread"]).trim(), "unread mail: 0");
}

fn hook(dir: &Path, event: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["hook", "claude"])
        .current_dir(dir)
        .env_remove("LOCKYARD_AGENT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(event.to_string().as_bytes()).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn the_hook_process_denies_a_held_path_in_the_shape_claude_code_reads() {
    let dir = project();
    ok(dir.path(), "other", &["zone", "claim", "src"]);
    let result = hook(
        dir.path(),
        &json!({
            "hook_event_name": "PreToolUse",
            "session_id": "me",
            "cwd": dir.path(),
            "tool_name": "Write",
            "tool_input": { "file_path": dir.path().join("src/new.rs") },
        }),
    );
    assert!(result.status.success());
    let answer: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_broken_project_never_blocks_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join(".lockyard");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("lockyard.db"), "not a database, not at all").unwrap();
    let result = hook(
        dir.path(),
        &json!({ "hook_event_name": "PostToolUse", "session_id": "me", "cwd": dir.path() }),
    );
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("lockyard hook"));
}

fn mcp(dir: &Path, agent: &str, input: &str) -> Output {
    mcp_with(dir, agent, &[], &[], input)
}

/// The same server with extra flags or environment, for the two tool surfaces.
fn mcp_with(dir: &Path, agent: &str, extra: &[&str], env: &[(&str, &str)], input: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command.arg("mcp").args(extra);
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command
        .current_dir(dir)
        .env("LOCKYARD_AGENT", agent)
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn mcp_stdio_initializes_lists_claims_and_reports_conflicts_and_parse_errors() {
    let dir = project();
    let init = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
    );
    let init: Value = serde_json::from_slice(&init.stdout).unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    let list = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
    );
    let list: Value = serde_json::from_slice(&list.stdout).unwrap();
    let compact = list["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = compact
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "start_work",
            "check",
            "update",
            "handover",
            "finish_work",
            "status",
            "tasks",
            "task_bulk",
            "registry_import",
            "area_list",
            "area_create",
            "area_update"
        ],
        "the default surface is the short one"
    );

    let claim = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"zone_claim\",\"arguments\":{\"paths\":[\"src\"]}}}\n",
    );
    let claim: Value = serde_json::from_slice(&claim.stdout).unwrap();
    assert_eq!(claim["result"]["isError"], false);

    let conflict = mcp(
        dir.path(),
        "second",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"zone_claim\",\"arguments\":{\"paths\":[\"src/file.rs\"]}}}\n",
    );
    let conflict: Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(conflict["result"]["isError"], true);
    assert!(
        conflict["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("first")
    );

    let bad = mcp(dir.path(), "first", "{bad json}\n");
    let bad: Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(bad["error"]["code"], -32700);
}

#[test]
fn the_full_tool_surface_is_a_flag_or_an_environment_variable_away() {
    let dir = project();
    let list = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
    let count = |out: Output| -> usize {
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        value["result"]["tools"].as_array().unwrap().len()
    };
    let compact = count(mcp(dir.path(), "a", list));
    let by_flag = count(mcp_with(dir.path(), "a", &["--tools", "full"], &[], list));
    let by_env = count(mcp_with(
        dir.path(),
        "a",
        &[],
        &[("LOCKYARD_MCP_TOOLS", "full")],
        list,
    ));
    assert_eq!(
        compact, 12,
        "the compact registry surface intentionally adds six tools"
    );
    assert!(by_flag > 50, "the full surface keeps every tool: {by_flag}");
    assert_eq!(by_flag, by_env, "the flag and the variable agree");
    // The flag wins, so a client can ask for the short surface on a machine set to full.
    assert_eq!(
        count(mcp_with(
            dir.path(),
            "a",
            &["--tools", "compact"],
            &[("LOCKYARD_MCP_TOOLS", "full")],
            list,
        )),
        12
    );
    let bad = mcp_with(dir.path(), "a", &["--tools", "nope"], &[], list);
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("compact"));
}

#[test]
fn a_composite_tool_claims_and_finishes_a_whole_piece_of_work() {
    let dir = project();
    let start = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"start_work\",\"arguments\":{\"paths\":[\"src/api\"],\"note\":\"rewrite\"}}}\n",
    );
    let start: Value = serde_json::from_slice(&start.stdout).unwrap();
    assert_eq!(start["result"]["isError"], false, "{start}");

    let refused = mcp(
        dir.path(),
        "second",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"start_work\",\"arguments\":{\"paths\":[\"src/api/routes.rs\"]}}}\n",
    );
    let refused: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(
        refused["result"]["isError"], true,
        "a composite refuses a held path exactly as the plain claim does"
    );

    let finish = mcp(
        dir.path(),
        "first",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"finish_work\",\"arguments\":{\"paths\":[\"src/api\"]}}}\n",
    );
    let finish: Value = serde_json::from_slice(&finish.stdout).unwrap();
    assert_eq!(finish["result"]["isError"], false, "{finish}");

    let after = mcp(
        dir.path(),
        "second",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"start_work\",\"arguments\":{\"paths\":[\"src/api/routes.rs\"]}}}\n",
    );
    let after: Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(after["result"]["isError"], false, "the release frees it");
}

#[test]
fn logout_forgets_one_server_and_login_refuses_a_plain_http_one() {
    let dir = project();
    let credentials = dir.path().join("credentials.toml");
    let run = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_lockyard"))
            .args(args)
            .current_dir(dir.path())
            .env("LOCKYARD_AGENT", "a")
            .env("LOCKYARD_CREDENTIALS", &credentials)
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .output()
            .unwrap()
    };

    let empty = run(&["--json", "cloud", "logout", "--url", "https://cloud.test"]);
    assert!(empty.status.success());
    let empty: Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert_eq!(empty["removed"], false);

    std::fs::write(
        &credentials,
        "[servers.\"https://cloud.test\"]\ntoken = \"lk_1\"\nworkspace_name = \"Team\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let gone = run(&["--json", "cloud", "logout", "--url", "https://cloud.test/"]);
    let gone: Value = serde_json::from_slice(&gone.stdout).unwrap();
    assert_eq!(gone["removed"], true);
    assert!(
        !credentials.exists(),
        "the last login takes the file with it"
    );

    // A token must never travel over plain HTTP, and that is decided before anything is sent.
    let insecure = run(&["cloud", "login", "--url", "http://cloud.test"]);
    assert!(!insecure.status.success());
    assert!(String::from_utf8_lossy(&insecure.stderr).contains("HTTPS"));

    // Without a URL and outside cloud mode there is nothing to log in to, and saying so beats
    // guessing a server.
    let guessing = run(&["cloud", "login"]);
    assert!(!guessing.status.success());
}

#[test]
fn a_sender_can_see_whether_mail_was_delivered_read_or_answered() {
    let dir = project();
    let root = dir.path();
    ok(root, "b", &["msg", "inbox"]);
    let sent_output = ok(
        root,
        "a",
        &["--json", "msg", "send", "b", "take src/api\u{202e}spoof"],
    );
    assert!(!sent_output.contains('\u{202e}'), "{sent_output}");
    let sent: Value = serde_json::from_str(&sent_output).unwrap();
    assert_eq!(sent["body"], "take src/api\\u{202e}spoof");
    let id = sent["id"].as_i64().unwrap();

    let status = |expected: &str| {
        let stdout = ok(root, "a", &["--json", "msg", "sent"]);
        assert!(!stdout.contains('\u{202e}'), "{stdout}");
        let list: Value = serde_json::from_str(&stdout).unwrap();
        let line = list
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("M-{id} is missing from msg sent"))
            .clone();
        assert_eq!(line["status"], expected, "{line}");
        assert_eq!(line["body"], "take src/api\\u{202e}spoof");
    };
    status("sent");
    ok(root, "b", &["msg", "inbox", "--peek"]);
    status("delivered");
    ok(root, "b", &["msg", "inbox"]);
    status("read");
    ok(root, "b", &["msg", "reply", &format!("M-{id}"), "on it"]);
    status("replied");

    let text = ok(root, "a", &["msg", "sent"]);
    assert!(text.contains("replied"), "{text}");
    assert!(text.contains("\\u{202e}"), "{text}");
    assert!(!text.contains('\u{202e}'), "{text}");
}

#[test]
fn json_mailbox_outputs_escape_bidi_controls_and_remain_valid_json() {
    let dir = project();
    let root = dir.path();
    ok(root, "b", &["msg", "inbox", "--peek"]);
    let sent: Value = serde_json::from_str(&ok(
        root,
        "a",
        &["--json", "msg", "send", "b", "safe\u{202e}hidden"],
    ))
    .unwrap();
    assert_eq!(sent["body"], "safe\\u{202e}hidden");

    let inbox = ok(root, "b", &["--json", "msg", "inbox", "--peek"]);
    assert!(!inbox.contains('\u{202e}'), "{inbox}");
    let messages: Value = serde_json::from_str(&inbox).unwrap();
    assert_eq!(messages[0]["body"], "safe\\u{202e}hidden");

    let receipts = ok(root, "a", &["--json", "msg", "sent"]);
    assert!(!receipts.contains('\u{202e}'), "{receipts}");
    let receipts: Value = serde_json::from_str(&receipts).unwrap();
    assert_eq!(receipts[0]["body"], "safe\\u{202e}hidden");
}
