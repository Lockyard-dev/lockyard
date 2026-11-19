// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use std::os::unix::fs::PermissionsExt;

fn private_key(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    lockyard_core::fsio::replace(path, b"test-token", 0o600).unwrap();
}

fn session_cli(dir: &Path, runtime: &Path) -> Command {
    let mut command = binary(dir, runtime);
    command
        .env_remove("LOCKYARD_AGENT")
        .env("CLAUDE_CODE_SESSION_ID", "survey-session")
        .env("LOCKYARD_TOKEN", "test-token");
    command
}

#[test]
fn survey1118_claude_identity_cli_mcp_and_forwarded_calls() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    for via_agent in [false, true] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.registry_items =
                vec![json!({"id":"D-1","title":"reviewed work","status":"review","version":1})];
            state.survey_require_claude_accept = true;
            state.survey_claude_session = Some(SESSION.into());
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        private_key(&runtime.path().join("config/lockyard/token"));
        let claude = runtime.path().join("config/lockyard/claude.token");
        lockyard_core::fsio::replace(&claude, b"claude-test-token", 0o600).unwrap();
        let daemon = via_agent.then(|| {
            start_agent_until_env(
                dir.path(),
                runtime.path(),
                true,
                &[("LOCKYARD_TOKEN_FILE", claude.to_str().unwrap())],
            )
        });
        // Distinct Claude credential, implicit session name, both entry points.
        let out = session_cli(dir.path(), runtime.path())
            .env_remove("LOCKYARD_TOKEN")
            .env("CLAUDE_CODE_SESSION_ID", SESSION)
            .env("LOCKYARD_CLAUDE_MCP", "1")
            .args(["--json", "task", "accept", "D-1"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut child = session_cli(dir.path(), runtime.path())
            .env_remove("LOCKYARD_TOKEN")
            .env("CLAUDE_CODE_SESSION_ID", SESSION)
            .env("LOCKYARD_CLAUDE_MCP", "1")
            .args(["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tasks","arguments":{"action":"accept","id":"D-1"}}})).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(answer["result"]["isError"], false, "{answer}");
        let out = session_cli(dir.path(), runtime.path())
            .env_remove("LOCKYARD_TOKEN")
            .env("CLAUDE_CODE_SESSION_ID", SESSION)
            .env("LOCKYARD_CLAUDE_MCP", "1")
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let status: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(status["token_source"], "claude");
        assert_eq!(
            status["freshness"]["via"],
            if via_agent { "agent" } else { "direct" }
        );
        let accepts = server.seen("POST", "/api/v1/registry/items/D-1/transition");
        assert_eq!(accepts.len(), 2);
        let seen = server.state.lock().unwrap().seen.clone();
        let original: Vec<_> = seen
            .iter()
            .filter(|r| r.session.as_deref() == Some(SESSION))
            .collect();
        assert!(!original.is_empty());
        assert!(
            original
                .iter()
                .all(|r| r.product.is_none()
                    && r.token.as_deref() == Some("Bearer claude-test-token")),
            "{original:?}"
        );
        assert!(
            accepts
                .iter()
                .all(|r| r.session.as_deref() == Some(SESSION))
        );
        if via_agent {
            let out = binary(dir.path(), runtime.path())
                .env("LOCKYARD_AGENT", "alice")
                .env("LOCKYARD_TOKEN", "test-token")
                .args(["--json", "status"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let status: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert_eq!(status["freshness"]["via"], "direct");
            assert!(
                server
                    .state
                    .lock()
                    .unwrap()
                    .seen
                    .iter()
                    .filter(|r| r.session.as_deref() == Some("alice"))
                    .all(|r| r.token.as_deref() == Some("Bearer test-token"))
            );
        }
        if let Some(daemon) = daemon {
            daemon.stop();
        }
    }
}

#[test]
fn survey1118_header_excludes_parent_other_names_codex_and_cursor() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let daemon = start_agent_until_env(
        dir.path(),
        runtime.path(),
        true,
        &[("CLAUDE_CODE_SESSION_ID", "survey-session")],
    );
    for (name, claude, parent) in [
        ("survey-session", "survey-session", Some("1178")),
        ("survey-session", "survey-session", Some("")),
        ("codex-worker", "codex-worker", None),
        ("cursor-worker", "cursor-worker", None),
        ("other", "survey-session", None),
        ("survey-session", "", None),
    ] {
        let mut cmd = binary(dir.path(), runtime.path());
        cmd.args(["--agent", name, "zone", "list"])
            .env("CLAUDE_CODE_SESSION_ID", claude)
            .env("LOCKYARD_TOKEN", "test-token");
        if let Some(parent) = parent {
            cmd.env("LOCKYARD_PARENT_CLAIM", parent);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let status = session_cli(dir.path(), runtime.path())
        .env("LOCKYARD_PARENT_CLAIM", "1178")
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .all(|r| r.product.is_none())
    );
    daemon.stop();
}

#[test]
fn survey1118_release_session_avoids_binding_and_bound_error_has_recovery() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    server.state.lock().unwrap().survey_bound_session = Some("survey-session".into());
    let bound = session_cli(dir.path(), runtime.path())
        .args(["--json", "zone", "list"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&bound.stderr);
    assert!(
        text.contains("session_name_bound")
            && text.contains("верни ключ агента")
            && text.contains("lockyard cloud release-session <имя>"),
        "{text}"
    );
    assert!(!text.contains("test-token"));
    let released = session_cli(dir.path(), runtime.path())
        .args(["--json", "cloud", "release-session", "survey-session"])
        .output()
        .unwrap();
    assert!(
        released.status.success(),
        "{}",
        String::from_utf8_lossy(&released.stderr)
    );
    let request = server.seen("POST", "/api/v1/admin/sessions/survey-session/release");
    assert_eq!(request.len(), 1);
    assert_ne!(request[0].session.as_deref(), Some("survey-session"));
    assert!(request[0].product.is_none());
}

#[test]
fn survey1118_token_output_is_private_raw_atomic_and_never_overwrites_session_keys() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let current = runtime.path().join("current-key");
    private_key(&current);
    let default = runtime.path().join("config/lockyard/token");
    private_key(&default);
    let alias = runtime.path().join("key-alias");
    std::os::unix::fs::symlink(&current, &alias).unwrap();
    let hardlink = runtime.path().join("key-hardlink");
    std::fs::hard_link(&current, &hardlink).unwrap();
    for path in [&default, &current, &alias, &hardlink] {
        let out = binary(dir.path(), runtime.path())
            .env_remove("LOCKYARD_TOKEN")
            .env("LOCKYARD_TOKEN_FILE", &current)
            .args([
                "cloud",
                "token",
                "create",
                "lead",
                "--role",
                "lead",
                "--output-file",
            ])
            .arg(path)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--output-file"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(std::fs::read(path).unwrap(), b"test-token");
    }
    assert!(server.seen("POST", "/api/v1/registry/tokens").is_empty());
    let saved = runtime.path().join("lead-key");
    std::fs::write(&saved, "old-complete-value").unwrap();
    let out = binary(dir.path(), runtime.path())
        .env("LOCKYARD_TOKEN", "test-token")
        .args([
            "--json",
            "cloud",
            "token",
            "create",
            "lead",
            "--role",
            "lead",
            "--output-file",
        ])
        .arg(&saved)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&saved).unwrap(), b"new-secret-key");
    assert_eq!(
        std::fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("new-secret-key"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("new-secret-key"));
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(parsed.get("raw").is_none());
    let text_path = runtime.path().join("text-issued-key");
    let out = binary(dir.path(), runtime.path())
        .env("LOCKYARD_TOKEN", "test-token")
        .args([
            "cloud",
            "token",
            "create",
            "lead",
            "--role",
            "lead",
            "--output-file",
        ])
        .arg(&text_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("key saved to"));
    assert!(!text.contains("new-secret-key"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("new-secret-key"));
    assert_eq!(
        std::fs::metadata(text_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let before = server.seen("POST", "/api/v1/registry/tokens").len();
    for json in [false, true] {
        let mut command = binary(dir.path(), runtime.path());
        command.env("LOCKYARD_TOKEN", "test-token");
        if json {
            command.arg("--json");
        }
        let out = command
            .args(["cloud", "token", "create", "lead", "--role", "lead"])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("--output-file"));
        assert!(out.stdout.is_empty());
    }
    assert_eq!(server.seen("POST", "/api/v1/registry/tokens").len(), before);
    let help = binary(dir.path(), runtime.path())
        .args(["cloud", "token", "create", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("private file")
            && help.contains("--output-file")
            && !help.contains("metadata"),
        "{help}"
    );
}

#[test]
fn survey1118_explicit_token_implies_cloud_from_local_config_for_env_and_flag() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    // Simulates a subrepository with a local-only Lockyard config.
    std::fs::write(dir.path().join(".lockyard/config.toml"), "mode = 'local'\n").unwrap();
    let key = runtime.path().join("explicit-key");
    private_key(&key);
    for flag in [false, true] {
        let mut cmd = binary(dir.path(), runtime.path());
        cmd.env_remove("LOCKYARD_TOKEN")
            .env("LOCKYARD_URL", &server.url);
        if flag {
            cmd.arg("--token-file").arg(&key);
        } else {
            cmd.env("LOCKYARD_TOKEN_FILE", &key);
        }
        let out = cmd
            .args([
                "--json",
                "cloud",
                "token",
                "create",
                "lead",
                "--role",
                "lead",
                "--output-file",
            ])
            .arg(runtime.path().join(format!("issued-{flag}")))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(answer.get("raw").is_none());
        assert!(answer["output_file"].is_string());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("new-secret-key"));
    }
    assert_eq!(server.seen("POST", "/api/v1/registry/tokens").len(), 2);
}

#[test]
fn survey1118_doctor_warns_and_status_marks_privileged_default_token() {
    for role in ["lead", "owner", "agent"] {
        let server = Server::start();
        server.state.lock().unwrap().survey_default_role = Some(role.into());
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        private_key(&runtime.path().join("config/lockyard/token"));
        let doctor = binary(dir.path(), runtime.path())
            .env("LOCKYARD_AGENT", "alice")
            .env_remove("LOCKYARD_TOKEN")
            .args(["--json", "doctor"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&doctor.stdout);
        assert_eq!(
            text.contains("ключ по умолчанию должен быть ключом агента"),
            role != "agent",
            "{text}"
        );
        assert!(!text.contains("test-token"));
        let out = binary(dir.path(), runtime.path())
            .env("LOCKYARD_AGENT", "alice")
            .env_remove("LOCKYARD_TOKEN")
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
        if role == "agent" {
            assert!(answer.get("default_token_role").is_none());
        } else {
            assert_eq!(answer["default_token_role"], role);
        }
    }
}

#[test]
fn survey1118_mcp_bad_body_and_ttl_name_the_correct_fields() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[
            ("update", json!({"to":"bob","message":"hello"})),
            ("start_work", json!({"paths":["src"],"ttl":"120"})),
            ("zone_renew", json!({"ttl":"120"})),
            ("zone_renew", json!({"ttl_minutes":120})),
        ],
    );
    for (index, answer) in answers.iter().enumerate() {
        assert_eq!(answer["isError"], true, "{answer}");
        let text = answer["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(if index == 0 { "body" } else { "ttl" }),
            "{text}"
        );
        if index > 0 {
            assert!(
                text.contains("integer") && text.contains("minutes"),
                "{text}"
            );
        }
    }
    assert!(server.writes_to("/claims").is_empty());
    assert!(server.writes_to("/messages").is_empty());
}

#[test]
fn survey1118_start_work_reports_idle_deadline_and_renew_auto_extends_hold() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let claim = json!({"id":1,"session":"alice","paths":["src"],"fence":1,"expires_at":HOLD_EXPIRES_AT,"idle_release_at":"2099-11-11T21:20:00Z"});
    server.state.lock().unwrap().claim_reused_on_post = Some(claim);
    let answer = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[("start_work", json!({"paths":["src"],"ttl":120}))],
    );
    assert_eq!(answer[0]["isError"], false, "{answer:?}");
    let text = answer[0]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("idle_release_at")
            && text.contains("без hold_reason заявка отпустится по простою в 21:20 UTC"),
        "{text}"
    );
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let answer = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[("zone_renew", json!({"id":1,"hold_reason":"overnight"}))],
    );
    assert_eq!(answer[0]["isError"], false, "{answer:?}");
    let out = cli(
        dir.path(),
        runtime.path(),
        &["zone", "renew", "1", "--hold-reason", "overnight"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let renews = server.seen("POST", "/api/v1/zones/claims/1/renew");
    assert_eq!(renews.len(), 2);
    for request in renews {
        let until =
            lockyard_core::proto::parse_rfc3339(request.body["hold_until"].as_str().unwrap())
                .unwrap();
        assert!(until >= before + 240 * 60_000 - 1000 && until <= after + 240 * 60_000);
    }
}

#[test]
fn survey1118_explicit_key_finds_ancestor_cloud_config_without_url_env() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let nested = dir.path().join("cloud");
    std::fs::create_dir_all(nested.join(".lockyard")).unwrap();
    let key = runtime.path().join("explicit-key");
    private_key(&key);
    let trust = binary(dir.path(), runtime.path())
        .args(["cloud", "trust", &server.url])
        .output()
        .unwrap();
    assert!(
        trust.status.success(),
        "{}",
        String::from_utf8_lossy(&trust.stderr)
    );
    let out = binary(&nested, runtime.path())
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_URL")
        .env("LOCKYARD_TOKEN_FILE", key)
        .args([
            "cloud",
            "token",
            "create",
            "lead",
            "--role",
            "lead",
            "--output-file",
        ])
        .arg(runtime.path().join("issued-key"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(server.seen("POST", "/api/v1/registry/tokens").len(), 1);
}

#[test]
fn survey1118_key_selection_branches_and_diagnostics() {
    for case in [
        "claude",
        "parent",
        "empty-parent",
        "different-name",
        "no-session",
        "empty-session",
        "missing-file",
        "override",
        "bad-permissions",
        "read-only",
        "executable",
        "explicit-env",
        "explicit-empty",
        "explicit-missing",
        "explicit-flag",
    ] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let agent = runtime.path().join("config/lockyard/token");
        private_key(&agent);
        let claude = runtime.path().join("config/lockyard/claude.token");
        lockyard_core::fsio::replace(&claude, b"claude-test-token", 0o600).unwrap();
        let mut cmd = session_cli(dir.path(), runtime.path());
        cmd.env_remove("LOCKYARD_TOKEN");
        match case {
            "parent" => {
                cmd.env("LOCKYARD_PARENT_CLAIM", "1178");
            }
            "empty-parent" => {
                cmd.env("LOCKYARD_PARENT_CLAIM", "");
            }
            "different-name" => {
                cmd.arg("--agent").arg("other");
            }
            "no-session" => {
                cmd.env_remove("CLAUDE_CODE_SESSION_ID")
                    .env("LOCKYARD_AGENT", "alice");
            }
            "empty-session" => {
                cmd.env("CLAUDE_CODE_SESSION_ID", "")
                    .env("LOCKYARD_AGENT", "alice");
            }
            "missing-file" => {
                std::fs::remove_file(&claude).unwrap();
            }
            "override" => {
                let custom = runtime.path().join("custom-claude-key");
                std::fs::rename(&claude, &custom).unwrap();
                cmd.env("LOCKYARD_CLAUDE_TOKEN_FILE", custom);
            }
            "bad-permissions" | "read-only" | "executable" => {
                let mode = match case {
                    "read-only" => 0o400,
                    "executable" => 0o700,
                    _ => 0o644,
                };
                std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(mode)).unwrap();
            }
            "explicit-empty" => {
                cmd.env("LOCKYARD_TOKEN_FILE", "");
            }
            "explicit-missing" => {
                cmd.env("LOCKYARD_TOKEN_FILE", runtime.path().join("missing-token"));
            }
            "explicit-env" => {
                cmd.env("LOCKYARD_TOKEN_FILE", &agent)
                    .env("LOCKYARD_TOKEN", "ignored-inline");
                std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            "explicit-flag" => {
                cmd.env("LOCKYARD_TOKEN_FILE", runtime.path().join("does-not-exist"))
                    .env("LOCKYARD_TOKEN", "ignored-inline")
                    .arg("--token-file")
                    .arg(&agent);
            }
            _ => {}
        }
        let out = cmd.args(["--json", "status"]).output().unwrap();
        let denied = matches!(
            case,
            "bad-permissions" | "read-only" | "executable" | "explicit-empty" | "explicit-missing"
        );
        assert_eq!(
            out.status.success(),
            !denied,
            "{case}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if denied {
            assert!(
                String::from_utf8_lossy(&out.stderr).contains(if case.starts_with("explicit-") {
                    "LOCKYARD_TOKEN_FILE"
                } else {
                    "0600"
                }),
                "{case}: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                server.state.lock().unwrap().seen.is_empty(),
                "must not use a different credential"
            );
            continue;
        }
        let expected = match case {
            "claude" | "override" => "claude",
            "explicit-env" | "explicit-flag" => "явный файл",
            _ => "agent",
        };
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(answer["token_source"], expected, "{case}: {answer}");
        let token = if expected == "claude" {
            "Bearer claude-test-token"
        } else {
            "Bearer test-token"
        };
        let requests = server.seen("GET", "/api/v1/zones/claims");
        assert!(!requests.is_empty(), "{case}");
        assert!(
            requests
                .iter()
                .all(|r| r.token.as_deref() == Some(token) && r.product.is_none()),
            "{case}: {requests:?}"
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("test-token"));
    }
}

#[test]
fn survey1118_claude_key_bypasses_daemon_with_another_key_and_invalid_key_is_not_hidden() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    private_key(&runtime.path().join("config/lockyard/token"));
    let claude = runtime.path().join("config/lockyard/claude.token");
    lockyard_core::fsio::replace(&claude, b"claude-test-token", 0o600).unwrap();
    let daemon = start_agent(dir.path(), runtime.path());
    let out = session_cli(dir.path(), runtime.path())
        .env_remove("LOCKYARD_TOKEN")
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(answer["freshness"]["via"], "direct");
    assert_eq!(answer["token_source"], "claude");
    assert!(
        server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|r| r.session.as_deref() == Some("survey-session"))
            .all(|r| r.token.as_deref() == Some("Bearer claude-test-token"))
    );
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = session_cli(dir.path(), runtime.path())
        .env_remove("LOCKYARD_TOKEN")
        .args(["zone", "list"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("0600"));
    daemon.stop();
}

#[test]
fn survey1118_agent_key_cannot_accept_by_forging_claude_environment() {
    let server = Server::start();
    server.state.lock().unwrap().survey_require_claude_accept = true;
    server.state.lock().unwrap().registry_items =
        vec![json!({"id":"D-1","title":"reviewed work","status":"review","version":1})];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let out = session_cli(dir.path(), runtime.path())
        .args(["--json", "task", "accept", "D-1"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("claude_key_required"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .all(|r| r.product.is_none())
    );
}

#[test]
fn survey1118_r7_mcp_claude_key_requires_explicit_marker_and_matching_identity() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    for (case, marker, claude, parent, name, explicit, expected) in [
        ("uuid-only", None, None, None, SESSION, false, "agent"),
        (
            "matching-env-only",
            None,
            Some(SESSION),
            None,
            SESSION,
            false,
            "agent",
        ),
        (
            "empty-marker",
            Some(""),
            None,
            None,
            SESSION,
            false,
            "agent",
        ),
        (
            "wrong-marker",
            Some("true"),
            None,
            None,
            SESSION,
            false,
            "agent",
        ),
        ("marker", Some("1"), None, None, SESSION, false, "agent"),
        ("codex", Some("1"), None, None, SESSION, false, "agent"),
        (
            "cursor",
            Some("1"),
            Some(SESSION),
            None,
            SESSION,
            false,
            "agent",
        ),
        (
            "matching-env",
            Some("1"),
            Some(SESSION),
            None,
            SESSION,
            false,
            "claude",
        ),
        (
            "parent",
            Some("1"),
            None,
            Some("1178"),
            SESSION,
            false,
            "agent",
        ),
        (
            "empty-parent",
            Some("1"),
            None,
            Some(""),
            SESSION,
            false,
            "agent",
        ),
        (
            "mismatch",
            Some("1"),
            Some("other-session"),
            None,
            SESSION,
            false,
            "agent",
        ),
        (
            "empty-session-env",
            Some("1"),
            Some(""),
            None,
            SESSION,
            false,
            "agent",
        ),
        (
            "non-uuid",
            Some("1"),
            Some("ordinary-agent"),
            None,
            "ordinary-agent",
            false,
            "agent",
        ),
        (
            "explicit-file",
            Some("1"),
            Some(SESSION),
            None,
            SESSION,
            true,
            "явный файл",
        ),
    ] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let agent = runtime.path().join("config/lockyard/token");
        private_key(&agent);
        lockyard_core::fsio::replace(
            &runtime.path().join("config/lockyard/claude.token"),
            b"claude-test-token",
            0o600,
        )
        .unwrap();
        let mut cmd = binary(dir.path(), runtime.path());
        cmd.env_remove("LOCKYARD_TOKEN").env("LOCKYARD_AGENT", name);
        for (key, value) in [
            ("LOCKYARD_CLAUDE_MCP", marker),
            ("CLAUDE_CODE_SESSION_ID", claude),
            ("LOCKYARD_PARENT_CLAIM", parent),
        ] {
            if let Some(value) = value {
                cmd.env(key, value);
            }
        }
        if explicit {
            cmd.env("LOCKYARD_TOKEN_FILE", &agent);
        }
        match case {
            "codex" => {
                cmd.env("CODEX_THREAD_ID", "executor-fixture");
            }
            "cursor" => {
                cmd.env("CURSOR_AGENT", "1");
            }
            _ => {}
        }
        let mut child = cmd
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}})).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(answer["result"]["isError"], false, "{case}: {answer}");
        assert_eq!(
            answer["result"]["structuredContent"]["token_source"], expected,
            "{case}: {answer}"
        );
        let requests = server.seen("GET", "/api/v1/zones/claims");
        assert!(!requests.is_empty(), "{case}");
        let token = if expected == "claude" {
            "Bearer claude-test-token"
        } else {
            "Bearer test-token"
        };
        assert!(
            requests
                .iter()
                .all(|row| row.token.as_deref() == Some(token)),
            "{case}: {requests:?}"
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("test-token"));

        if case == "matching-env" {
            let out = session_cli(dir.path(), runtime.path())
                .env("CLAUDE_CODE_SESSION_ID", SESSION)
                .env("LOCKYARD_CLAUDE_MCP", "1")
                .env_remove("LOCKYARD_TOKEN")
                .args(["--json", "status"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(json_of(&out)["token_source"], expected);
            assert!(
                server
                    .seen("GET", "/api/v1/zones/claims")
                    .iter()
                    .all(|row| row.token.as_deref() == Some(token))
            );
        }
        // A marker on an ordinary CLI cannot replace CLAUDE_CODE_SESSION_ID.
        if matches!(case, "marker" | "codex") {
            let mut cli = binary(dir.path(), runtime.path());
            cli.env("LOCKYARD_AGENT", SESSION)
                .env("LOCKYARD_CLAUDE_MCP", "1")
                .env_remove("LOCKYARD_TOKEN");
            if case == "codex" {
                cli.env("CODEX_THREAD_ID", "executor-fixture");
            }
            let out = cli.args(["--json", "status"]).output().unwrap();
            assert!(out.status.success());
            assert_eq!(json_of(&out)["token_source"], expected);
            assert!(
                server
                    .seen("GET", "/api/v1/zones/claims")
                    .iter()
                    .all(|row| row.token.as_deref() == Some(token))
            );
        }
    }
}

#[test]
fn r14_project_mcp_key_is_ignored_after_launcher_cleanup_and_downgrade() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    for executor in [true, false] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let agent = runtime.path().join("config/lockyard/token");
        let claude = agent.with_file_name("claude.token");
        std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
        lockyard_core::fsio::replace(&claude, b"claude-test-token", 0o600).unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            json!({"mcpServers":{"lockyard":{"command":"lockyard","args":["mcp"],"env":{
                "LOCKYARD_TOKEN_FILE": claude, "LOCKYARD_URL": server.url
            }}}})
            .to_string(),
        )
        .unwrap();

        if !executor {
            // Let the server trigger a real downgrade in the first process.
            server.state.lock().unwrap().survey_agent_bound_session = Some(SESSION.into());
            let first = binary(dir.path(), runtime.path())
                .env_remove("LOCKYARD_TOKEN")
                .env_remove("LOCKYARD_CREDENTIALS")
                .env_remove("LOCKYARD_AGENT")
                .env_remove("FLEX_RUNNER_NESTED")
                .env("CLAUDE_CODE_SESSION_ID", SESSION)
                .args(["--json", "zone", "list"])
                .output()
                .unwrap();
            assert!(!first.status.success());
            assert!(String::from_utf8_lossy(&first.stderr).contains("no token for the cloud"));
            assert!(server.seen("GET", "/api/v1/zones/claims").is_empty());
            assert!(server.state.lock().unwrap().seen.iter().any(|request| {
                request.session.as_deref() == Some(SESSION)
                    && request.token.as_deref() == Some("Bearer claude-test-token")
            }));
            server.state.lock().unwrap().seen.clear();
        }

        let list_zones = || {
            let mut command = binary(dir.path(), runtime.path());
            command
                .env_remove("LOCKYARD_TOKEN")
                .env_remove("LOCKYARD_CREDENTIALS")
                .env_remove("LOCKYARD_AGENT")
                .env_remove("CLAUDECODE")
                .env_remove("CLAUDE_CODE_ENTRYPOINT")
                .env_remove("FLEX_RUNNER_NESTED");
            if executor {
                // The runner strips the Claude context and leaves this marker even without a parent claim.
                command.env("FLEX_RUNNER_NESTED", "1");
            } else {
                command.env("CLAUDE_CODE_SESSION_ID", SESSION);
            }
            command.args(["--json", "zone", "list"]).output().unwrap()
        };
        let missing = list_zones();
        assert!(!missing.status.success());
        assert!(String::from_utf8_lossy(&missing.stderr).contains("no token for the cloud"));
        assert!(server.state.lock().unwrap().seen.is_empty());

        private_key(&agent);
        assert!(list_zones().status.success());
        let requests = server.seen("GET", "/api/v1/zones/claims");
        assert!(!requests.is_empty());
        assert!(
            requests
                .iter()
                .all(|request| request.token.as_deref() == Some("Bearer test-token"))
        );
    }
}

#[test]
fn survey1118_doctor_reports_selected_key_without_values() {
    for source in ["claude", "agent", "явный файл"] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let agent = runtime.path().join("config/lockyard/token");
        private_key(&agent);
        lockyard_core::fsio::replace(
            &runtime.path().join("config/lockyard/claude.token"),
            b"claude-test-token",
            0o600,
        )
        .unwrap();
        let mut cmd = session_cli(dir.path(), runtime.path());
        cmd.env_remove("LOCKYARD_TOKEN");
        match source {
            "agent" => {
                cmd.env("LOCKYARD_PARENT_CLAIM", "1178");
            }
            "явный файл" => {
                cmd.env("LOCKYARD_TOKEN_FILE", &agent);
            }
            _ => {}
        }
        let out = cmd.args(["--json", "doctor"]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let answer: Value = serde_json::from_str(&text).unwrap();
        let selected = answer["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["check"] == "selected key")
            .unwrap();
        assert_eq!(selected["detail"], source, "{answer}");
        assert!(!text.contains("test-token"));
    }
}

#[test]
fn survey1118_r7_doctor_explains_claude_selection_without_environment_values() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    for case in [
        "selected",
        "no-marker",
        "parent",
        "mismatch",
        "empty-session",
        "explicit",
        "missing-key",
        "invalid-key",
        "non-uuid",
    ] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let agent = runtime.path().join("config/lockyard/token");
        let claude_key = runtime.path().join("config/lockyard/claude.token");
        private_key(&agent);
        lockyard_core::fsio::replace(&claude_key, b"claude-test-token", 0o600).unwrap();
        for variant in ["ordinary", "client", "smoke"] {
            let mut cmd = binary(dir.path(), runtime.path());
            cmd.env("LOCKYARD_AGENT", SESSION)
                .env("LOCKYARD_CLAUDE_MCP", "1")
                .env("CLAUDE_CODE_SESSION_ID", SESSION)
                .env_remove("LOCKYARD_TOKEN");
            let expected = match case {
                "no-marker" => {
                    cmd.env_remove("LOCKYARD_CLAUDE_MCP");
                    "LOCKYARD_CLAUDE_MCP=1"
                }
                "parent" => {
                    cmd.env("LOCKYARD_PARENT_CLAIM", "1178");
                    "LOCKYARD_PARENT_CLAIM is set"
                }
                "mismatch" => {
                    cmd.env("CLAUDE_CODE_SESSION_ID", "private-other-session");
                    "does not match"
                }
                "empty-session" => {
                    cmd.env("CLAUDE_CODE_SESSION_ID", "");
                    "does not match"
                }
                "explicit" => {
                    cmd.env("LOCKYARD_TOKEN_FILE", &agent);
                    "explicit LOCKYARD_TOKEN_FILE"
                }
                "missing-key" => {
                    let _ = std::fs::remove_file(&claude_key);
                    "key file is missing"
                }
                "invalid-key" => {
                    std::fs::set_permissions(&claude_key, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                    "mode 0600"
                }
                "non-uuid" => {
                    cmd.env("LOCKYARD_AGENT", "private-non-uuid-name")
                        .env("CLAUDE_CODE_SESSION_ID", "private-non-uuid-name");
                    "session UUID"
                }
                _ => "selected: session conditions match",
            };
            cmd.args(["--json", "doctor"]);
            match variant {
                "client" => {
                    cmd.args(["--client", "claude"]);
                }
                "smoke" => {
                    cmd.arg("--smoke");
                }
                _ => {}
            }
            let out = cmd.output().unwrap();
            let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
            let checks = answer["checks"].as_array().unwrap();
            let diagnostic = checks
                .iter()
                .find(|c| {
                    matches!(
                        c["check"].as_str(),
                        Some("Claude key (MCP)" | "claude_key_mcp")
                    )
                })
                .unwrap();
            let reason = diagnostic["detail"].as_str().unwrap();
            assert!(reason.contains(expected), "{case}/{variant}: {reason}");
            for value in [
                SESSION,
                "private-other-session",
                "private-non-uuid-name",
                "test-token",
                "1178",
            ] {
                assert!(!reason.contains(value), "{case}/{variant}: {reason}");
            }
            assert!(checks.iter().any(|c| matches!(
                c["check"].as_str(),
                Some("Claude key (CLI)" | "claude_key_cli")
            )));
            assert!(!String::from_utf8_lossy(&out.stdout).contains("test-token"));
        }
    }
}

#[test]
fn survey1118_r7_mcp_help_explains_marker_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let out = binary(dir.path(), runtime.path())
        .args(["mcp", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("LOCKYARD_CLAUDE_MCP=1"), "{text}");
    assert!(text.contains("mcpServers.lockyard.env"), "{text}");
}

#[test]
fn survey1118_r9_offline_doctor_variants_warn_about_privileged_default_key() {
    for args in [
        vec!["--json", "doctor", "--client", "claude"],
        vec!["--json", "doctor", "--smoke"],
    ] {
        for role in ["lead", "owner"] {
            let server = Server::start();
            server.state.lock().unwrap().survey_default_role = Some(role.into());
            let dir = cloud_project(&server);
            let runtime = tempfile::tempdir().unwrap();
            private_key(&runtime.path().join("config/lockyard/token"));
            let output = binary(dir.path(), runtime.path())
                .env("LOCKYARD_AGENT", "alice")
                .env_remove("LOCKYARD_TOKEN")
                .args(&args)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                text.contains("ключ по умолчанию должен быть ключом агента"),
                "{output:?}"
            );
            assert!(
                text.contains("offline") && text.contains("lead/owner"),
                "{text}"
            );
            assert!(!text.contains("test-token"));
            assert!(
                server.state.lock().unwrap().seen.is_empty(),
                "offline doctor contacted API"
            );
        }
    }
}

#[test]
fn survey1118_setup_claude_preserves_cli_and_mcp_key_selection_on_reapply() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    let server = Server::start();
    for setup in [
        ["setup", "--client", "claude"],
        ["setup", "claude", "--apply"],
    ] {
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let config = dir.path().join(".mcp.json");
        std::fs::write(
            &config,
            r#"{"mcpServers":{"lockyard":{"command":"lockyard","args":["mcp"],"env":{"USER_ENV":"kept","LOCKYARD_TOKEN_FILE":"unused-fixture-path","LOCKYARD_AGENT":"pinned-fixture"}}}}"#,
        ).unwrap();
        private_key(&runtime.path().join("config/lockyard/token"));
        lockyard_core::fsio::replace(
            &runtime.path().join("config/lockyard/claude.token"),
            b"claude-test-token",
            0o600,
        )
        .unwrap();
        let command = || {
            let mut cmd = binary(dir.path(), runtime.path());
            cmd.env_remove("LOCKYARD_TOKEN")
                .env_remove("LOCKYARD_AGENT")
                .env("CLAUDE_CODE_SESSION_ID", SESSION);
            cmd
        };
        for round in 0..2 {
            let out = command().args(setup).output().unwrap();
            assert!(out.status.success(), "setup failed");
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                output.contains("Explicit LOCKYARD_TOKEN_FILE disables Claude key selection"),
                round == 0
            );
            assert!(!output.contains("unused-fixture-path"));
            let installed: Value =
                serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
            let env = installed["mcpServers"]["lockyard"]["env"]
                .as_object()
                .unwrap();
            assert_eq!(env["LOCKYARD_CLAUDE_MCP"], "1");
            assert_eq!(env["USER_ENV"], "kept");
            assert!(env.get("LOCKYARD_AGENT").is_none());
            assert!(env.get("LOCKYARD_TOKEN_FILE").is_none());

            let cli = command().args(["--json", "status"]).output().unwrap();
            assert_eq!(json_of(&cli)["token_source"], "claude");

            let mut mcp = command()
                .envs(
                    env.iter()
                        .map(|(name, value)| (name, value.as_str().unwrap())),
                )
                .arg("mcp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            writeln!(mcp.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}})).unwrap();
            let mcp = mcp.wait_with_output().unwrap();
            assert!(mcp.status.success());
            let answer: Value = serde_json::from_slice(&mcp.stdout).unwrap();
            assert_eq!(answer["result"]["isError"], false);
            assert_eq!(
                answer["result"]["structuredContent"]["token_source"],
                "claude"
            );
        }
    }
}

#[test]
fn survey1118_r13_claude_service_rejects_uncredentialed_cli_mcp_and_notifications() {
    for source in ["env", "file", "automatic"] {
        claude_service_rejects_executor(source);
    }
}

fn claude_service_rejects_executor(source: &str) {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let claude = runtime.path().join("config/lockyard/claude.token");
    std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
    lockyard_core::fsio::replace(&claude, b"claude-test-token", 0o600).unwrap();
    let variables = match source {
        "env" => vec![("LOCKYARD_TOKEN", "claude-test-token")],
        "file" => vec![("LOCKYARD_TOKEN_FILE", claude.to_str().unwrap())],
        _ => vec![
            ("LOCKYARD_AGENT", SESSION),
            ("CLAUDE_CODE_SESSION_ID", SESSION),
        ],
    };
    let daemon = start_agent_until_env(dir.path(), runtime.path(), true, &variables);
    let service_identity = server.seen("GET", "/api/v1/registry/actor");
    assert!(
        service_identity
            .iter()
            .any(|request| request.token.as_deref() == Some("Bearer claude-test-token")),
        "{source}"
    );
    let info = cli(dir.path(), runtime.path(), &["--json", "agent", "status"]);
    assert_eq!(json_of(&info)["status"]["requires_matching_token"], true);

    for (session, delegated, unavailable) in [
        ("missing-agent-key", false, false),
        ("unavailable-agent-key", true, true),
    ] {
        let command = || {
            let mut cmd = binary(dir.path(), runtime.path());
            cmd.env("LOCKYARD_AGENT", session)
                .env_remove("LOCKYARD_TOKEN")
                .env("HOME", runtime.path())
                .env_remove("LOCKYARD_CONFIG_DIR");
            if delegated {
                cmd.env("LOCKYARD_PARENT_CLAIM", "1249");
            }
            if unavailable {
                cmd.env(
                    "LOCKYARD_TOKEN_FILE",
                    runtime.path().join("missing-explicit-agent-key"),
                );
            }
            cmd
        };

        for args in [["--json", "who"], ["--json", "status"]] {
            let output = command().args(args).output().unwrap();
            assert!(!output.status.success(), "{session}: {args:?}");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("token") || error.contains("key"),
                "{session}: {args:?}: {error}"
            );
        }
        let notification = command()
            .args(["mail", "wait", "--session", session, "--timeout", "1"])
            .output()
            .unwrap();
        // Notification hooks fail quietly, and must not borrow the service's key.
        assert_eq!(notification.status.code(), Some(0));
        assert!(notification.stdout.is_empty() && notification.stderr.is_empty());
        let mut child = command()
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "{}",
            json!({
                "jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"status","arguments":{}}
            })
        )
        .unwrap();
        let out = child.wait_with_output().unwrap();
        let answer: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(answer["result"]["isError"], true);
        assert!(
            !server
                .state
                .lock()
                .unwrap()
                .seen
                .iter()
                .any(|row| { row.session.as_deref() == Some(session) })
        );
    }

    // IPC cannot use the public fingerprint alone as proof of possession.
    let mut stream = std::os::unix::net::UnixStream::connect(socket(runtime.path())).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    writeln!(
        stream,
        "{}",
        json!({"workspace":"team","op":"wait_mail","session":"fingerprint-only","since":0,
            "timeout_ms":500,"expected_token_id":json_of(&info)["status"]["token_id"]})
    )
    .unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["error"]["invalid"], "agent credential mismatch");
    assert!(
        !server
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .any(|row| { row.session.as_deref() == Some("fingerprint-only") })
    );

    // An explicit matching credential still cannot route a delegated caller via Claude.
    let status = binary(dir.path(), runtime.path())
        .env("LOCKYARD_AGENT", "delegated-matching-key")
        .env("LOCKYARD_PARENT_CLAIM", "1249")
        .env("LOCKYARD_TOKEN_FILE", &claude)
        .args(["--json", "status"])
        .output()
        .unwrap();
    assert_eq!(json_of(&status)["freshness"]["via"], "direct");
    daemon.stop();
}

#[test]
fn survey1118_r13_offline_status_uses_real_matching_claude_service() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    let api = Server::start();
    api.state.lock().unwrap().claims = vec![json!({
        "id":71,"session":SESSION,"paths":["src"],"fence":1,"expires_at":HOLD_EXPIRES_AT
    })];
    let dir = cloud_project(&api);
    let runtime = tempfile::tempdir().unwrap();
    let key = runtime.path().join("config/lockyard/claude.token");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    lockyard_core::fsio::replace(&key, b"claude-test-token", 0o600).unwrap();
    let _daemon = start_agent_until_env(
        dir.path(),
        runtime.path(),
        true,
        &[
            ("LOCKYARD_AGENT", SESSION),
            ("CLAUDE_CODE_SESSION_ID", SESSION),
        ],
    );
    let command = || {
        let mut cmd = session_cli(dir.path(), runtime.path());
        cmd.env_remove("LOCKYARD_TOKEN")
            .env("CLAUDE_CODE_SESSION_ID", SESSION);
        cmd
    };
    let warm = json_of(&command().args(["--json", "status"]).output().unwrap());
    assert_eq!(warm["freshness"]["via"], "agent");
    assert_eq!(warm["claims"][0]["id"], 71);
    api.state.lock().unwrap().api_offline = true;
    let offline = json_of(&command().args(["--json", "status"]).output().unwrap());
    assert_eq!(offline["freshness"]["via"], "agent");
    assert_eq!(offline["freshness"]["source"], "cached");
    assert_eq!(
        offline["freshness"]["sections"]["claims"]["source"],
        "cached"
    );
    assert!(offline["freshness"]["cache_age_ms"].as_u64().unwrap() > 0);
    assert_eq!(offline["claims"][0]["id"], 71);
    assert_eq!(offline["token_source"], "claude");
    let plain = command().arg("status").output().unwrap();
    assert!(String::from_utf8_lossy(&plain.stdout).contains("cached ("));
    let mutation = command()
        .args(["zone", "renew", "71", "--ttl", "10"])
        .output()
        .unwrap();
    assert!(
        !mutation.status.success(),
        "cached status cannot authorize renewal"
    );
}

#[test]
fn survey1118_r13_cli_and_mcp_share_executor_detection() {
    const SESSION: &str = "00112233-4455-6677-8899-aabbccddeeff";
    for marker in [None, Some("CODEX_THREAD_ID"), Some("CURSOR_AGENT")] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        private_key(&runtime.path().join("config/lockyard/token"));
        lockyard_core::fsio::replace(
            &runtime.path().join("config/lockyard/claude.token"),
            b"claude-test-token",
            0o600,
        )
        .unwrap();
        let command = || {
            let mut cmd = binary(dir.path(), runtime.path());
            cmd.env_remove("LOCKYARD_TOKEN")
                .env_remove("LOCKYARD_AGENT")
                .env("CLAUDE_CODE_SESSION_ID", SESSION)
                .env("LOCKYARD_CLAUDE_MCP", "1")
                .env("CODEX_HOME", runtime.path());
            if let Some(marker) = marker {
                cmd.env(marker, "fixture");
            }
            cmd
        };
        let cli = json_of(&command().args(["--json", "status"]).output().unwrap());
        let mut child = command()
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"status","arguments":{}}})).unwrap();
        let answer = json_of(&child.wait_with_output().unwrap());
        let mcp = &answer["result"]["structuredContent"];
        let (source, bearer) = if marker.is_none() {
            ("claude", "Bearer claude-test-token")
        } else {
            ("agent", "Bearer test-token")
        };
        assert_eq!(cli["token_source"], source, "{marker:?}");
        assert_eq!(mcp["token_source"], source, "{marker:?}");
        let claims = server.seen("GET", "/api/v1/zones/claims");
        assert_eq!(
            claims
                .iter()
                .filter(|row| row.session.as_deref() == Some(SESSION)
                    && row.token.as_deref() == Some(bearer))
                .count(),
            2
        );
    }
}
