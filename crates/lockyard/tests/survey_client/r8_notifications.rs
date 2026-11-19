// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

const CLAUDE: &str = "11111111-2222-4333-8444-555555555555";
const AGENT: &str = "agent-session";

fn keys(runtime: &Path) {
    let config = runtime.join("config/lockyard");
    std::fs::create_dir_all(&config).unwrap();
    for (name, key) in [
        ("token", "test-token"),
        ("claude.token", "claude-test-token"),
    ] {
        lockyard_core::fsio::replace(&config.join(name), key.as_bytes(), 0o600).unwrap();
    }
}

fn command(dir: &Path, runtime: &Path, session: &str) -> Command {
    let mut cmd = binary(dir, runtime);
    cmd.env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_AGENT");
    if session == CLAUDE {
        cmd.env("CLAUDE_CODE_SESSION_ID", session);
    } else {
        cmd.env("LOCKYARD_AGENT", session);
    }
    cmd
}

fn mail(id: i64, session: &str) -> Value {
    json!({"id":id,"thread_id":id,"from_session":"bob","to":session,"role":"recipient",
        "body":format!("private mail {id}"),"kind":"ask","needs":"reply","reader_state":"new"})
}

fn setup() -> (Server, tempfile::TempDir, tempfile::TempDir, Agent) {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state
            .notification_owners
            .insert(CLAUDE.into(), "Bearer claude-test-token".into());
        state
            .notification_owners
            .insert(AGENT.into(), "Bearer test-token".into());
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    let daemon = start_agent(dir.path(), runtime.path());
    // Sessions bind through CLI/MCP before notification waiting. The daemon only
    // subscribes names whose ownership was confirmed by a client request.
    let bound = command(dir.path(), runtime.path(), AGENT)
        .args(["--json", "who"])
        .output()
        .unwrap();
    assert!(bound.status.success(), "{bound:?}");
    (server, dir, runtime, daemon)
}

fn wait(mut cmd: Command, session: &str, stop: bool, timeout: &str) -> Child {
    cmd.args(["mail", "wait", "--timeout", timeout]);
    if !stop {
        cmd.args(["--session", session]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if stop {
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            json!({"hook_event_name":"Stop","session_id":session})
        )
        .unwrap();
    } else {
        drop(child.stdin.take());
    }
    child
}

fn woke(child: Child, id: i64) {
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!("M-{id}")),
        "{out:?}"
    );
}

fn hook_mail(dir: &Path, runtime: &Path, session: &str) -> Output {
    let mut child = command(dir, runtime, session)
        .args(["hook", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"hook_event_name":"UserPromptSubmit","session_id":session,"cwd":dir})
    )
    .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn survey1118_r8_mail_wait_and_stop_use_claude_key_beside_agent_service() {
    let (server, dir, runtime, _daemon) = setup();
    server.state.lock().unwrap().inbox.push(mail(71, CLAUDE));
    woke(
        wait(
            command(dir.path(), runtime.path(), CLAUDE),
            CLAUDE,
            false,
            "3",
        ),
        71,
    );
    // Same key/session cursor survives a short-lived CLI process.
    let quiet = wait(
        command(dir.path(), runtime.path(), CLAUDE),
        CLAUDE,
        true,
        "1",
    )
    .wait_with_output()
    .unwrap();
    assert_eq!(quiet.status.code(), Some(0), "{quiet:?}");
    server.state.lock().unwrap().inbox.push(mail(72, CLAUDE));
    woke(
        wait(
            command(dir.path(), runtime.path(), CLAUDE),
            CLAUDE,
            true,
            "3",
        ),
        72,
    );
    assert!(server.writes_to("/bus/inbox/seen").is_empty());
    let hook = hook_mail(dir.path(), runtime.path(), CLAUDE);
    assert!(hook.status.success(), "{hook:?}");
    assert!(
        String::from_utf8_lossy(&hook.stdout).contains("private mail 71"),
        "{hook:?}"
    );
    assert!(
        server
            .seen("GET", "/api/v1/bus/inbox")
            .iter()
            .any(|r| r.session.as_deref() == Some(CLAUDE)
                && r.token.as_deref() == Some("Bearer claude-test-token"))
    );
}

#[test]
fn survey1118_r8_agent_key_wait_and_stop_keep_service_route() {
    let (server, dir, runtime, _daemon) = setup();
    let deliver = |id| {
        let mut state = server.state.lock().unwrap();
        let message = mail(id, AGENT);
        state.inbox.push(message.clone());
        state.notification_events.push(json!({
            "seq":id,"type":"bus.message","session":AGENT,"payload":message
        }));
    };
    deliver(71);
    woke(
        wait(
            command(dir.path(), runtime.path(), AGENT),
            AGENT,
            true,
            "30",
        ),
        71,
    );
    deliver(72);
    woke(
        wait(
            command(dir.path(), runtime.path(), AGENT),
            AGENT,
            false,
            "30",
        ),
        72,
    );
    assert!(
        server
            .seen("GET", "/api/v1/bus/inbox")
            .iter()
            .filter(|r| r.session.as_deref() == Some(AGENT))
            .all(|r| r.token.as_deref() == Some("Bearer test-token"))
    );
    assert!(server.writes_to("/bus/inbox/seen").is_empty());
}

#[test]
fn survey1118_r8_two_keys_wait_simultaneously_without_consuming_each_other() {
    let (server, dir, runtime, _daemon) = setup();
    let claude = wait(
        command(dir.path(), runtime.path(), CLAUDE),
        CLAUDE,
        true,
        "5",
    );
    let agent = wait(
        command(dir.path(), runtime.path(), AGENT),
        AGENT,
        false,
        "5",
    );
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        let state = server.state.lock().unwrap();
        let listening = [CLAUDE, AGENT].iter().all(|session| {
            state.seen.iter().any(|r| {
                r.path.starts_with("/api/v1/events")
                    && query_value(&r.path, "session").as_deref() == Some(session)
            })
        });
        drop(state);
        if listening {
            break;
        }
        assert!(Instant::now() < end, "both keys did not start waiting");
        thread::sleep(Duration::from_millis(10));
    }
    // Identical IDs deliberately exercise delivery identity, not global-ID ordering.
    server
        .state
        .lock()
        .unwrap()
        .inbox
        .extend([mail(81, CLAUDE), mail(81, AGENT)]);
    woke(claude, 81);
    woke(agent, 81);
    for session in [CLAUDE, AGENT] {
        let out = wait(
            command(dir.path(), runtime.path(), session),
            session,
            false,
            "1",
        )
        .wait_with_output()
        .unwrap();
        assert_eq!(out.status.code(), Some(0), "{session}: {out:?}");
    }
}

#[test]
fn survey1118_r8_direct_long_poll_retains_arrival_during_inbox_seed() {
    let (server, dir, runtime, _daemon) = setup();
    server.state.lock().unwrap().notification_seed_race = Some(CLAUDE.into());
    woke(
        wait(
            command(dir.path(), runtime.path(), CLAUDE),
            CLAUDE,
            true,
            "3",
        ),
        88,
    );
    let requests = server.seen("GET", "/api/v1/events");
    assert!(
        requests
            .iter()
            .any(|r| r.token.as_deref() == Some("Bearer claude-test-token")
                && query_value(&r.path, "wait").is_some()
                && query_value(&r.path, "session").as_deref() == Some(CLAUDE))
    );
    assert!(
        server.state.lock().unwrap().inbox.is_empty(),
        "wake must come from the retained event"
    );
    let identity = format!(
        "{}\0team\0{}",
        server.url,
        lockyard_cloud_client::token_id("claude-test-token")
    );
    let cursor = runtime
        .path()
        .join("state/lockyard")
        .join(format!(
            "notifications-{}",
            lockyard_cloud_client::token_id(&identity)
        ))
        .join(format!(
            "wake-mail-{}",
            lockyard_cloud_client::token_id(CLAUDE)
        ));
    assert_eq!(std::fs::read_to_string(cursor).unwrap(), "88");
    assert!(server.state.lock().unwrap().seen_ids.contains(&88));
}

#[test]
fn survey1118_r8_explicit_file_and_sticky_agent_fallback_select_notification_key() {
    let (server, dir, runtime, _daemon) = setup();
    // An explicit agent file overrides the Claude session marker.
    server
        .state
        .lock()
        .unwrap()
        .notification_owners
        .insert(CLAUDE.into(), "Bearer test-token".into());
    server.state.lock().unwrap().inbox.push(mail(91, CLAUDE));
    let bound = command(dir.path(), runtime.path(), CLAUDE)
        .env(
            "LOCKYARD_TOKEN_FILE",
            runtime.path().join("config/lockyard/token"),
        )
        .args(["--json", "who"])
        .output()
        .unwrap();
    assert!(bound.status.success(), "{bound:?}");
    let mut explicit = command(dir.path(), runtime.path(), CLAUDE);
    explicit.env(
        "LOCKYARD_TOKEN_FILE",
        runtime.path().join("config/lockyard/token"),
    );
    woke(wait(explicit, CLAUDE, true, "5"), 91);
    server.state.lock().unwrap().inbox.push(mail(92, CLAUDE));
    // Automatic Claude selection gets session_name_bound and remembers the downgrade.
    // The legacy snapshot worker can enter its existing five-second idle interval
    // while fallback is being negotiated. Leave room for that unchanged cadence.
    let out = wait(
        command(dir.path(), runtime.path(), CLAUDE),
        CLAUDE,
        false,
        "10",
    )
    .wait_with_output()
    .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{out:?}; requests: {:?}",
        server.state.lock().unwrap().seen
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("M-92"),
        "{out:?}"
    );
    assert!(runtime.path().join("state/lockyard/session-keys").exists());
    let hook = hook_mail(dir.path(), runtime.path(), CLAUDE);
    assert!(
        String::from_utf8_lossy(&hook.stdout).contains("private mail"),
        "{hook:?}"
    );
}

#[test]
fn survey1118_r8_same_session_wake_cursor_is_separate_after_key_rebinding() {
    let (server, dir, runtime, _daemon) = setup();
    server.state.lock().unwrap().inbox.push(mail(101, CLAUDE));
    woke(
        wait(
            command(dir.path(), runtime.path(), CLAUDE),
            CLAUDE,
            false,
            "3",
        ),
        101,
    );
    // Model an authorized administrative rebind; the same unread mail must also wake
    // the new credential. A session-only cursor would incorrectly suppress this ID.
    server
        .state
        .lock()
        .unwrap()
        .notification_owners
        .insert(CLAUDE.into(), "Bearer test-token".into());
    let mut bound = command(dir.path(), runtime.path(), CLAUDE);
    bound.env(
        "LOCKYARD_TOKEN_FILE",
        runtime.path().join("config/lockyard/token"),
    );
    assert!(
        bound
            .args(["--json", "who"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut agent = command(dir.path(), runtime.path(), CLAUDE);
    agent.env(
        "LOCKYARD_TOKEN_FILE",
        runtime.path().join("config/lockyard/token"),
    );
    woke(wait(agent, CLAUDE, true, "5"), 101);
    server
        .state
        .lock()
        .unwrap()
        .notification_owners
        .insert(CLAUDE.into(), "Bearer claude-test-token".into());
    let quiet = wait(
        command(dir.path(), runtime.path(), CLAUDE),
        CLAUDE,
        false,
        "1",
    )
    .wait_with_output()
    .unwrap();
    assert_eq!(quiet.status.code(), Some(0), "{quiet:?}");
}

#[test]
fn survey1118_r8_direct_wait_ignores_read_historical_events() {
    let (server, dir, runtime, _daemon) = setup();
    // Not in the unread inbox: a historical message already read before this waiter.
    server
        .state
        .lock()
        .unwrap()
        .notification_events
        .push(json!({
            "seq":51,"type":"bus.message","session":CLAUDE,"payload":mail(51, CLAUDE)
        }));
    let quiet = wait(
        command(dir.path(), runtime.path(), CLAUDE),
        CLAUDE,
        true,
        "1",
    )
    .wait_with_output()
    .unwrap();
    assert_eq!(quiet.status.code(), Some(0), "{quiet:?}");
    assert!(
        server
            .seen("GET", "/api/v1/events")
            .iter()
            .any(|r| r.session.as_deref() == Some(CLAUDE)
                && query_value(&r.path, "after").as_deref() == Some("51"))
    );
}

#[test]
fn survey1118_r8_explicit_different_key_file_uses_direct_wait_without_claude_marker() {
    let (server, dir, runtime, _daemon) = setup();
    server.state.lock().unwrap().inbox.push(mail(121, CLAUDE));
    let mut explicit = command(dir.path(), runtime.path(), CLAUDE);
    explicit
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env("LOCKYARD_AGENT", CLAUDE)
        .env(
            "LOCKYARD_TOKEN_FILE",
            runtime.path().join("config/lockyard/claude.token"),
        );
    woke(wait(explicit, CLAUDE, true, "3"), 121);
    assert!(
        server
            .seen("GET", "/api/v1/bus/inbox")
            .iter()
            .any(|r| r.session.as_deref() == Some(CLAUDE)
                && r.token.as_deref() == Some("Bearer claude-test-token"))
    );
}

#[test]
fn survey1118_r8_agent_fallback_uses_direct_mail_beside_claude_service() {
    let (server, dir, runtime, daemon) = setup();
    daemon.stop();
    write_agent_service_config(dir.path(), runtime.path());
    let _claude_daemon = Agent(
        command(dir.path(), runtime.path(), CLAUDE)
            .arg("agent")
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let status = json_of(&cli(
            dir.path(),
            runtime.path(),
            &["--json", "agent", "status"],
        ));
        if status["status"]["token_id"] == lockyard_cloud_client::token_id("claude-test-token")
            && status["status"]["view_fresh"] == true
        {
            break;
        }
        assert!(Instant::now() < end, "Claude service not ready");
        thread::sleep(Duration::from_millis(20));
    }
    server
        .state
        .lock()
        .unwrap()
        .notification_owners
        .insert(CLAUDE.into(), "Bearer test-token".into());
    server.state.lock().unwrap().inbox.push(mail(111, CLAUDE));
    // Selection downgrades before routing, and the daemon's Claude key is rejected.
    woke(
        wait(
            command(dir.path(), runtime.path(), CLAUDE),
            CLAUDE,
            true,
            "3",
        ),
        111,
    );
    let hook = hook_mail(dir.path(), runtime.path(), CLAUDE);
    assert!(
        String::from_utf8_lossy(&hook.stdout).contains("private mail 111"),
        "{hook:?}"
    );
    assert!(
        server
            .seen("GET", "/api/v1/bus/inbox")
            .iter()
            .any(|r| r.session.as_deref() == Some(CLAUDE)
                && r.token.as_deref() == Some("Bearer test-token"))
    );
}

#[test]
fn survey1118_r10_first_hook_discovers_agent_binding_beside_claude_service() {
    let (server, dir, runtime, daemon) = setup();
    daemon.stop();
    write_agent_service_config(dir.path(), runtime.path());
    let _claude_daemon = Agent(
        command(dir.path(), runtime.path(), CLAUDE)
            .arg("agent")
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let status = json_of(&cli(
            dir.path(),
            runtime.path(),
            &["--json", "agent", "status"],
        ));
        if status["status"]["token_id"] == lockyard_cloud_client::token_id("claude-test-token")
            && status["status"]["view_fresh"] == true
        {
            break;
        }
        assert!(Instant::now() < end, "Claude service not ready");
        thread::sleep(Duration::from_millis(20));
    }
    server
        .state
        .lock()
        .unwrap()
        .notification_owners
        .insert(CLAUDE.into(), "Bearer test-token".into());
    server.state.lock().unwrap().inbox.push(mail(141, CLAUDE));
    assert!(!runtime.path().join("state/lockyard/session-keys").exists());
    // No CLI request or mail wait for S: the hook itself must discover the old binding.
    let hook = hook_mail(dir.path(), runtime.path(), CLAUDE);
    assert!(
        String::from_utf8_lossy(&hook.stdout).contains("private mail 141"),
        "{hook:?}"
    );
    assert!(runtime.path().join("state/lockyard/session-keys").exists());
    assert!(
        server
            .seen("GET", "/api/v1/bus/inbox")
            .iter()
            .any(|request| request.session.as_deref() == Some(CLAUDE)
                && request.token.as_deref() == Some("Bearer test-token"))
    );
    // The next process remembers the downgrade and does not try the Claude key again.
    let before = server
        .seen("GET", "/api/v1/presence")
        .iter()
        .filter(|request| {
            request.session.as_deref() == Some(CLAUDE)
                && request.token.as_deref() == Some("Bearer claude-test-token")
        })
        .count();
    let next = command(dir.path(), runtime.path(), CLAUDE)
        .args(["--json", "who"])
        .output()
        .unwrap();
    assert!(next.status.success(), "{next:?}");
    assert_eq!(
        server
            .seen("GET", "/api/v1/presence")
            .iter()
            .filter(|request| request.session.as_deref() == Some(CLAUDE)
                && request.token.as_deref() == Some("Bearer claude-test-token"))
            .count(),
        before
    );
}

fn warm_mail_cache(runtime: &Path, session: &str, id: i64, token: Option<&str>) {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let mut stream = std::os::unix::net::UnixStream::connect(socket(runtime)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        writeln!(
            stream,
            "{}",
            json!({
                "workspace":"team","op":"peek_mail","session":session,
                "expected_token_id":token.map(lockyard_cloud_client::token_id),
                "credential_proof":token.map(lockyard_cloud_client::ipc_credential_proof)
            })
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        if reply["messages"]
            .as_array()
            .is_some_and(|mail| mail.iter().any(|m| m["id"] == id))
        {
            return;
        }
        assert!(Instant::now() < end, "mail cache did not warm: {reply}");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn survey1118_r9_direct_hook_filters_seen_before_delivery_limit() {
    let (server, dir, runtime, _daemon) = setup();
    {
        let mut state = server.state.lock().unwrap();
        state.inbox.extend((1..=5).map(|id| mail(id, CLAUDE)));
        state.seen_ids.extend(1..=5);
        let mut fresh = mail(6, CLAUDE);
        fresh["kind"] = json!("info");
        fresh["needs"] = json!("none");
        state.inbox.push(fresh);
    }
    let output = hook_mail(dir.path(), runtime.path(), CLAUDE);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("private mail 6"),
        "{output:?}"
    );
    let claims = server.writes_to("/bus/inbox/claim");
    assert_eq!(claims.last().unwrap().body["ids"], json!([6]));
}

#[test]
fn survey1118_r9_hooks_deliver_confirmed_info_with_unknown_total_direct_and_service() {
    for service in [false, true] {
        let (server, dir, runtime, _daemon) = setup();
        let session = if service { AGENT } else { CLAUDE };
        {
            let mut state = server.state.lock().unwrap();
            for id in 1..=51 {
                let mut fresh = mail(id, session);
                fresh["kind"] = json!("info");
                fresh["needs"] = json!("none");
                state.inbox.push(fresh);
            }
        }
        if service {
            warm_mail_cache(runtime.path(), session, 2, None);
            let end = Instant::now() + Duration::from_secs(5);
            while server.writes_to("/bus/inbox/claim").is_empty() {
                assert!(
                    Instant::now() < end,
                    "daemon did not reserve confirmed mail"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let output = hook_mail(dir.path(), runtime.path(), session);
            assert!(output.status.success(), "{output:?}");
            if String::from_utf8_lossy(&output.stdout).contains("private mail") {
                break;
            }
            // Observing the HTTP request only proves that the reservation has
            // begun. The daemon publishes the reserved buffer after the reply.
            assert!(
                service && Instant::now() < deadline,
                "service={service}: {output:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let end = Instant::now() + Duration::from_secs(5);
        while server.writes_to("/bus/inbox/seen").is_empty() {
            assert!(Instant::now() < end, "seen acknowledgement was not flushed");
            thread::sleep(Duration::from_millis(10));
        }
        let seen = server.writes_to("/bus/inbox/seen");
        let ids = seen.last().unwrap().body["ids"].as_array().unwrap();
        assert!(!ids.is_empty() && ids.len() <= 5, "{seen:?}");
        assert!(ids.iter().all(|id| id.as_i64().unwrap() >= 2));
    }
}

#[test]
fn survey1118_r9_matching_claude_service_uses_warm_cache_with_api_offline() {
    let (server, dir, runtime, daemon) = setup();
    daemon.stop();
    write_agent_service_config(dir.path(), runtime.path());
    let _claude_daemon = Agent(
        command(dir.path(), runtime.path(), CLAUDE)
            .arg("agent")
            .spawn()
            .unwrap(),
    );
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if socket(runtime.path()).exists() {
            let status = json_of(&cli(
                dir.path(),
                runtime.path(),
                &["--json", "agent", "status"],
            ));
            if status["status"]["view_fresh"] == true
                && status["status"]["token_id"]
                    == lockyard_cloud_client::token_id("claude-test-token")
            {
                break;
            }
        }
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(10));
    }
    let bound = command(dir.path(), runtime.path(), CLAUDE)
        .args(["--json", "who"])
        .output()
        .unwrap();
    assert!(bound.status.success(), "{bound:?}");
    server.state.lock().unwrap().inbox.push(mail(131, CLAUDE));
    warm_mail_cache(runtime.path(), CLAUDE, 131, Some("claude-test-token"));
    server.state.lock().unwrap().api_offline = true;
    let before = server.seen("GET", "/api/v1/presence").len();
    let mut event = pre_edit(dir.path());
    event["session_id"] = json!(CLAUDE);
    let mut child = command(dir.path(), runtime.path(), CLAUDE)
        .args(["hook", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{event}").unwrap();
    let output = child.wait_with_output().unwrap();
    if !output.stdout.is_empty() {
        let answer: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_ne!(
            answer["hookSpecificOutput"]["permissionDecision"], "deny",
            "{output:?}"
        );
    }
    woke(
        wait(
            command(dir.path(), runtime.path(), CLAUDE),
            CLAUDE,
            false,
            "1",
        ),
        131,
    );
    assert_eq!(server.seen("GET", "/api/v1/presence").len(), before);
}

#[test]
fn survey1118_r13_mixed_truncated_inbox_warns_hook_and_mail_wait() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    keys(runtime.path());
    {
        let mut state = server.state.lock().unwrap();
        state.inbox.push(
            json!({"id":1,"thread_id":1,"from_session":"bob","to":CLAUDE,
            "kind":"info","needs":"none","body":"older unread"}),
        );
        for id in 2..=51 {
            state.inbox.push(mail(id, CLAUDE));
            state.seen_ids.push(id);
        }
    }
    let out = hook_mail(dir.path(), runtime.path(), CLAUDE);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("есть непоказанные письма, `lockyard msg inbox --all`"),
        "{out:?}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("private mail"));
    let out = wait(
        command(dir.path(), runtime.path(), CLAUDE),
        CLAUDE,
        false,
        "1",
    )
    .wait_with_output()
    .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("есть непоказанные письма, `lockyard msg inbox --all`"),
        "{out:?}"
    );
    assert!(server.writes_to("/inbox/seen").is_empty());
}
