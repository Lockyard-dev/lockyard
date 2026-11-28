// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

const SESSION: &str = "11111111-2222-4333-8444-555555555555";
const SOURCE: &str = "agent (fallback: имя занято)";
const WARNING: &str = lockyard_core::session_key::WARNING;

fn keys(runtime: &Path) {
    let config = runtime.join("config/lockyard");
    std::fs::create_dir_all(&config).unwrap();
    lockyard_core::fsio::replace(config.join("token").as_path(), b"test-token", 0o600).unwrap();
    lockyard_core::fsio::replace(
        config.join("claude.token").as_path(),
        b"claude-test-token",
        0o600,
    )
    .unwrap();
}

fn command(dir: &Path, runtime: &Path) -> Command {
    let mut command = binary(dir, runtime);
    command
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_AGENT")
        .env("CLAUDE_CODE_SESSION_ID", SESSION);
    command
}

fn mcp(dir: &Path, runtime: &Path) -> Vec<Value> {
    let mut command = command(dir, runtime);
    command.env("LOCKYARD_CLAUDE_MCP", "1");
    command.env("LOCKYARD_AGENT", SESSION);
    let mut child = command
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for id in 1..=2 {
        writeln!(stdin, "{}", json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"status","arguments":{}}})).unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let answer: Value = serde_json::from_str(line).unwrap();
            let result = answer["result"].clone();
            assert_eq!(result["isError"], false, "{result}");
            result
        })
        .collect()
}

fn claude_attempts(server: &Server) -> usize {
    server
        .state
        .lock()
        .unwrap()
        .seen
        .iter()
        .filter(|row| {
            row.session.as_deref() == Some(SESSION)
                && row.token.as_deref() == Some("Bearer claude-test-token")
        })
        .count()
}

fn claude_agent(dir: &Path, runtime: &Path) -> Agent {
    write_agent_service_config(dir, runtime);
    let daemon = Agent(command(dir, runtime).arg("agent").spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if socket(runtime).exists() {
            let status = json_of(&cli(dir, runtime, &["--json", "agent", "status"]));
            if status["status"]["view_fresh"] == true {
                return daemon;
            }
        }
        assert!(Instant::now() < end, "Claude daemon did not become ready");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn survey1118_r5_status_omits_unknown_legacy_unread_direct_and_service() {
    for service in [false, true] {
        let server = Server::start();
        let messages: Vec<_> = (1..=50)
            .map(|id| {
                json!({
                    "id":id,"from_session":"bob","to":"alice","reader_state":"seen","seen_at":123
                })
            })
            .collect();
        server.state.lock().unwrap().refuse_inbox_get =
            Some((200, json!({"messages":messages,"skipped":1})));
        server.state.lock().unwrap().claims = vec![json!({
            "id":17,"session":"alice","paths":["src"],"fence":23,"expires_at":HOLD_EXPIRES_AT
        })];
        server.state.lock().unwrap().registry_items = vec![json!({
            "id":"D-17","title":"Still assigned","status":"active",
            "assignment":{"executor":"alice"}
        })];
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let _daemon = service.then(|| start_agent(dir.path(), runtime.path()));
        let result = cli(dir.path(), runtime.path(), &["--json", "status"]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let answer = json_of(&result);
        assert!(answer["unread"].is_null(), "service={service}: {answer}");
        assert_eq!(
            answer["freshness"]["sections"]["unread"]["available"], false,
            "{answer}"
        );
        for surface in ["compact", "full"] {
            let answers = mcp_calls(
                dir.path(),
                runtime.path(),
                surface,
                &[("status", json!({}))],
            );
            let result = &answers[0];
            assert_eq!(
                result["isError"], false,
                "service={service}, {surface}: {result}"
            );
            let status = &result["structuredContent"];
            assert!(status["unread"].is_null(), "{status}");
            assert_eq!(status["unread_unavailable"], true, "{status}");
            assert_eq!(status["claims"][0]["id"], 17, "{status}");
            assert_eq!(status["claims"][0]["fence"], 23, "{status}");
            assert_eq!(status["tasks"][0]["id"], "D-17", "{status}");
        }
    }
}

#[test]
fn survey1118_r5_auto_claude_uses_fresh_zone_cache_and_retains_offline_mail() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let daemon = claude_agent(dir.path(), runtime.path());
    server._lifecycle.stop.store(true, Ordering::Release);
    server
        ._lifecycle
        .worker
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap();
    let started = Instant::now();
    let checked = command(dir.path(), runtime.path())
        .args(["--json", "zone", "check", "src/a.rs"])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "local check took {:?}",
        started.elapsed()
    );
    let sent = command(dir.path(), runtime.path())
        .args(["--json", "msg", "send", "bob", "offline Claude mail"])
        .output()
        .unwrap();
    assert_eq!(json_of(&sent)["queued"], true);
    // With no policy response the service keeps the logical call queued before its first send.
    let status = json_of(&cli(
        dir.path(),
        runtime.path(),
        &["--json", "agent", "status"],
    ));
    assert_eq!(status["status"]["outbox"], 1);
    assert_eq!(status["status"]["rejected"], 0);
    let state = Path::new(status["status"]["hook_mail_state_dir"].as_str().unwrap());
    let queue = std::fs::read_to_string(state.join("outbox.jsonl")).unwrap();
    assert_eq!(queue.lines().count(), 1);
    let entry: Value = serde_json::from_str(queue.trim()).unwrap();
    assert_eq!(entry["call"]["path"], "/api/v1/bus/messages");
    assert_eq!(entry["call"]["session"], SESSION);
    assert_eq!(entry["call"]["body"]["body"], "offline Claude mail");
    let scope = lockyard_cloud_client::credential_fingerprint(&format!(
        "{}\0claude-test-token",
        server.url
    ));
    let journal = runtime.path().join("state/lockyard/pending-writes");
    let count: i64 = pending_db(&journal)
        .query_row(
            "SELECT count(*) FROM pending_writes WHERE scope = ?1 AND state = 'pending'",
            [&scope],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    daemon.stop();
}

#[test]
fn survey1118_r5_service_cloud_refusal_falls_back_to_agent_key() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let daemon = claude_agent(dir.path(), runtime.path());
    // A different existing session can be agent-bound even on a Claude service.
    let session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    server.state.lock().unwrap().survey_agent_bound_session = Some(session.into());
    let result = command(dir.path(), runtime.path())
        .env("CLAUDE_CODE_SESSION_ID", session)
        .args(["--json", "msg", "inbox", "--peek"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&result.stderr)
            .matches(WARNING)
            .count(),
        1
    );
    let seen = server.state.lock().unwrap().seen.clone();
    assert!(seen.iter().any(|r| r.session.as_deref() == Some(session)
        && r.token.as_deref() == Some("Bearer test-token")
        && r.path.starts_with("/api/v1/bus/inbox")));
    assert!(
        seen.iter().any(|r| r.session.as_deref() == Some(session)
            && r.token.as_deref() == Some("Bearer claude-test-token")
            && r.path.starts_with("/api/v1/bus/inbox")),
        "{seen:?}"
    );
    // Fallback is triggered by the actual service call, without a front-loaded presence probe.
    assert!(
        !seen.iter().any(|r| r.session.as_deref() == Some(session)
            && r.token.as_deref() == Some("Bearer claude-test-token")
            && r.path == "/api/v1/presence"),
        "{seen:?}"
    );
    daemon.stop();
}

#[test]
fn survey1118_r4_cli_fallback_is_sticky_shared_with_mcp_and_daemon_and_warns_once() {
    for existing_daemon in [false, true] {
        let server = Server::start();
        server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        keys(runtime.path());
        let old_daemon = existing_daemon.then(|| start_agent(dir.path(), runtime.path()));
        let first = command(dir.path(), runtime.path())
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&first.stderr)
                .matches(WARNING)
                .count(),
            1
        );
        assert_eq!(json_of(&first)["token_source"], SOURCE);
        assert_eq!(claude_attempts(&server), 1);
        let count = server.state.lock().unwrap().seen.len();
        let answers = mcp(dir.path(), runtime.path());
        assert!(
            answers
                .iter()
                .all(|row| row["structuredContent"]["token_source"] == SOURCE),
            "daemon={existing_daemon}: {answers:?}"
        );
        assert!(!serde_json::to_string(&answers).unwrap().contains(WARNING));
        // Keep the decision even after the server would allow Claude again.
        server.state.lock().unwrap().survey_agent_bound_session = None;
        let doctor = command(dir.path(), runtime.path())
            .args(["--json", "doctor"])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&doctor.stdout).contains(SOURCE),
            "{}",
            String::from_utf8_lossy(&doctor.stdout)
        );
        assert!(!String::from_utf8_lossy(&doctor.stderr).contains(WARNING));
        if let Some(daemon) = old_daemon {
            daemon.stop();
        }
        // A service started after the downgrade resolves the same ordinary agent source.
        let daemon = start_agent_until_env(
            dir.path(),
            runtime.path(),
            true,
            &[("CLAUDE_CODE_SESSION_ID", SESSION)],
        );
        let next = command(dir.path(), runtime.path())
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(json_of(&next)["freshness"]["via"], "agent");
        assert!(!String::from_utf8_lossy(&next.stderr).contains(WARNING));
        assert_eq!(claude_attempts(&server), 1);
        assert!(
            server.state.lock().unwrap().seen[count..]
                .iter()
                .filter(|row| row.session.as_deref() == Some(SESSION))
                .all(|row| row.token.as_deref() == Some("Bearer test-token"))
        );
        daemon.stop();
    }
}

#[test]
fn survey1118_r4_mcp_first_answer_warns_once_and_cli_reuses_its_choice() {
    let server = Server::start();
    server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let answers = mcp(dir.path(), runtime.path());
    assert_eq!(
        answers[0]["structuredContent"]["session_key_warning"],
        WARNING
    );
    assert!(
        answers[0]["content"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["text"] == WARNING)
    );
    assert!(
        answers[1]["structuredContent"]
            .get("session_key_warning")
            .is_none()
    );
    assert_eq!(claude_attempts(&server), 1);
    let next = command(dir.path(), runtime.path())
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(json_of(&next)["token_source"], SOURCE);
    assert!(!String::from_utf8_lossy(&next.stderr).contains(WARNING));
    assert_eq!(claude_attempts(&server), 1);
}

#[test]
fn survey1118_r4_explicit_file_never_downgrades_and_keeps_bound_name_hint() {
    for flag in [false, true] {
        let server = Server::start();
        server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        keys(runtime.path());
        let key = runtime.path().join("config/lockyard/claude.token");
        let mut cmd = command(dir.path(), runtime.path());
        if flag {
            cmd.arg("--token-file").arg(&key);
        } else {
            cmd.env("LOCKYARD_TOKEN_FILE", &key);
        }
        let out = cmd.args(["--json", "zone", "list"]).output().unwrap();
        assert!(!out.status.success());
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(
            text.contains("session_name_bound")
                && text.contains("верни ключ агента")
                && text.contains("lockyard cloud release-session <имя>"),
            "{text}"
        );
        assert!(!text.contains(WARNING));
        assert!(!runtime.path().join("state/lockyard/session-keys").exists());
        assert!(
            server
                .state
                .lock()
                .unwrap()
                .seen
                .iter()
                .all(|row| row.token.as_deref() == Some("Bearer claude-test-token"))
        );
    }
}

#[test]
fn survey1118_r4_new_session_uses_claude_after_another_session_downgraded() {
    let server = Server::start();
    server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let first = command(dir.path(), runtime.path())
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(json_of(&first)["token_source"], SOURCE);
    let new = command(dir.path(), runtime.path())
        .env("CLAUDE_CODE_SESSION_ID", "new-session")
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(json_of(&new)["token_source"], "claude");
    assert!(!String::from_utf8_lossy(&new.stderr).contains(WARNING));
    assert!(
        server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|row| row.session.as_deref() == Some("new-session"))
            .all(|row| row.token.as_deref() == Some("Bearer claude-test-token"))
    );
}

#[test]
fn survey1118_r4_fallback_uses_normal_agent_source_order_before_any_write() {
    for source in ["inline", "credentials", "default", "mcp-file"] {
        let server = Server::start();
        server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
        server.state.lock().unwrap().claim_reused_on_post = Some(json!({
            "id":1190,"session":SESSION,"paths":["src/r4"],"fence":2712,
            "expires_at":HOLD_EXPIRES_AT,"mode":"exclusive"
        }));
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        keys(runtime.path());
        let agent = runtime.path().join("config/lockyard/token");
        let mut cmd = command(dir.path(), runtime.path());
        match source {
            "inline" => {
                lockyard_core::fsio::replace(&agent, b"wrong-default-token", 0o600).unwrap();
                cmd.env("LOCKYARD_TOKEN", "test-token");
            }
            "credentials" => {
                lockyard_core::fsio::replace(&agent, b"wrong-default-token", 0o600).unwrap();
                let credentials = runtime.path().join("credentials.toml");
                lockyard_core::credentials::save_in(
                    &credentials,
                    &lockyard_core::credentials::Entry {
                        url: server.url.clone(),
                        token: "test-token".into(),
                        workspace_id: "test".into(),
                        workspace_name: "test".into(),
                        role: "agent".into(),
                    },
                )
                .unwrap();
                cmd.env("LOCKYARD_CREDENTIALS", credentials);
            }
            "mcp-file" => {
                std::fs::remove_file(&agent).unwrap();
                let key = runtime.path().join("mcp.token");
                lockyard_core::fsio::replace(&key, b"test-token", 0o600).unwrap();
                std::fs::write(dir.path().join(".mcp.json"), json!({"mcpServers":{"lockyard":{"command":"lockyard", "env":{"LOCKYARD_TOKEN_FILE":key}}}}).to_string()).unwrap();
            }
            _ => {}
        }
        cmd.env(
            "LOCKYARD_CREDENTIALS",
            if source == "credentials" {
                runtime.path().join("credentials.toml")
            } else {
                runtime.path().join("missing-credentials")
            },
        );
        let out = cmd
            .args(["--json", "zone", "claim", "src/r4"])
            .output()
            .unwrap();
        let writes = server.seen("POST", "/api/v1/zones/claims");
        assert_eq!(claude_attempts(&server), 1);
        if source == "mcp-file" {
            assert!(!out.status.success());
            assert!(String::from_utf8_lossy(&out.stderr).contains("no token for the cloud"));
            assert!(writes.is_empty());
            continue;
        }
        assert!(
            out.status.success(),
            "{source}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].token.as_deref(), Some("Bearer test-token"));
    }
}

#[test]
fn survey1118_r4_agent_refusal_never_upgrades_to_claude() {
    let server = Server::start();
    server.state.lock().unwrap().survey_bound_session = Some(SESSION.into());
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let out = command(dir.path(), runtime.path())
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env("LOCKYARD_AGENT", SESSION)
        .args(["--json", "zone", "list"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(claude_attempts(&server), 0);
    assert!(!runtime.path().join("state/lockyard/session-keys").exists());
}

#[test]
fn survey1118_r4_daemon_discovers_fallback_without_consuming_the_warning() {
    let server = Server::start();
    server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let daemon = start_agent_until_env(
        dir.path(),
        runtime.path(),
        true,
        &[("CLAUDE_CODE_SESSION_ID", SESSION)],
    );
    let out = command(dir.path(), runtime.path())
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(json_of(&out)["token_source"], SOURCE);
    assert_eq!(json_of(&out)["freshness"]["via"], "agent");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr)
            .matches(WARNING)
            .count(),
        1
    );
    assert_eq!(claude_attempts(&server), 1);
    daemon.stop();
}

#[test]
fn survey1118_r12_status_falls_back_after_claude_service_cloud_refusal() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let daemon = claude_agent(dir.path(), runtime.path());
    let session = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    server.state.lock().unwrap().survey_agent_bound_session = Some(session.into());

    let out = command(dir.path(), runtime.path())
        .env("CLAUDE_CODE_SESSION_ID", session)
        .args(["--json", "status"])
        .output()
        .unwrap();
    let status = json_of(&out);
    assert_eq!(status["freshness"]["via"], "direct");
    assert_eq!(status["token_source"], SOURCE);
    let seen = server.state.lock().unwrap();
    let attempts: Vec<_> = seen
        .seen
        .iter()
        .filter(|row| {
            row.session.as_deref() == Some(session) && row.path.starts_with("/api/v1/zones/claims")
        })
        .collect();
    assert!(
        attempts
            .first()
            .is_some_and(|row| row.token.as_deref() == Some("Bearer claude-test-token"))
    );
    assert!(
        attempts
            .iter()
            .skip(1)
            .any(|row| row.token.as_deref() == Some("Bearer test-token"))
    );
    assert!(!seen.seen.iter().any(|row| {
        row.session.as_deref() == Some(session)
            && row.path == "/api/v1/presence"
            && row.token.as_deref() == Some("Bearer claude-test-token")
    }));
    drop(seen);
    daemon.stop();
}
