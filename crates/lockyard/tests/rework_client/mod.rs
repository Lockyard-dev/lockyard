// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

#[test]
fn agent_status_prints_macos_permission_hint_for_a_live_service_without_socket() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let commands = runtime.path().join("bin");
    std::fs::create_dir(&commands).unwrap();
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    // Model the OS service-manager/ps boundary; the process itself really is alive.
    // This also runs in the sandbox where the real ps is forbidden.
    for (name, body) in [
        ("launchctl", format!("printf 'pid = {}\\n'", child.id())),
        ("systemctl", format!("printf '{}\\n'", child.id())),
        ("ps", format!("test \"$2\" = '{}' && kill -0 '{}' && printf '00:10\\n'", child.id(), child.id())),
    ] {
        let path = commands.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let invoke = |json: bool| {
        let mut command = binary(dir.path(), runtime.path());
        command.args(["agent", "status"])
            .env("PATH", format!("{}:/usr/bin:/bin", commands.display()));
        if json { command.arg("--json"); }
        command.output().unwrap()
    };
    let output = invoke(false);
    let data = invoke(true);
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("ждёт разрешения macOS"), "{text}");
    assert!(text.contains("Полный доступ к диску"), "{text}");
    let value = json_of(&data);
    assert_eq!(value["running"], false);
    assert_eq!(value["socket_missing_hint"], true);
}

#[test]
fn renew_403_takeover_fetches_lost_reason_and_time() {
    assert_renew_loss(403, "taken", "перехвачена bob в 12:34");
}

#[test]
fn renew_409_ttl_fetches_lost_reason_and_time() {
    assert_renew_loss(409, "expired", "истекла по ttl в 12:34");
}

fn assert_renew_loss(status: u16, reason: &str, expected: &str) {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.claims = vec![json!({"id":71,"session":"bob","paths":["src"],"fence":9})];
        state.survey_lost = vec![json!({"claim_id":71,"session":"alice","reason":reason,"lost_at":"2026-11-17T12:34:00Z"})];
        state.refuse_renew = Some((status, json!({"error":{"code":"claim_unavailable","message":"claim unavailable"}})));
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let output = cli(dir.path(), runtime.path(), &["zone", "renew", "71", "--fence", "1"]);
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains(expected), "HTTP {status}: {message}");
    let replies = mcp_calls(dir.path(), runtime.path(), "full", &[
        ("zone_renew", json!({"id":71,"fence":1})),
    ]);
    assert_eq!(replies[0]["isError"], true);
    assert!(replies[0]["content"][0]["text"].as_str().unwrap().contains(expected), "{replies:?}");
    assert_eq!(server.seen("GET", "/api/v1/zones/lost").len(), 2);
}

fn rework_claim(id: i64) -> Value {
    json!({"id":id,"session":"alice","paths":["src"],"fence":1,"expires_at":HOLD_EXPIRES_AT})
}

#[test]
fn service_cli_keeps_chat_session_and_sees_own_claim_in_list_check_and_status() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![rework_claim(71)];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let via_service = |args: &[&str]| {
        binary(dir.path(), runtime.path())
            .args(args)
            .env("LOCKYARD_AGENT", "alice")
            .env_remove("LOCKYARD_TOKEN")
            .env_remove("LOCKYARD_TOKEN_FILE")
            .env(
                "LOCKYARD_CREDENTIALS",
                runtime.path().join("absent-credentials"),
            )
            .output()
            .unwrap()
    };
    let list = json_of(&via_service(&[
        "zone",
        "list",
        "--json",
        "--session",
        "alice",
    ]));
    assert_eq!(list[0]["id"], 71);
    // A forwarded CLI read must register the chat for daemon upkeep, not only bind its token.
    let end = Instant::now() + Duration::from_secs(10);
    while !server
        .state
        .lock()
        .unwrap()
        .coordination_event_sessions
        .contains("alice")
    {
        assert!(
            Instant::now() < end,
            "forwarded CLI chat was not registered for upkeep"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let check = json_of(&via_service(&["zone", "check", "src/file.rs", "--json"]));
    assert_eq!(check["own"], true);
    let status = json_of(&via_service(&["status", "--json"]));
    assert_eq!(status["claims"][0]["id"], 71);
    assert!(
        server
            .seen("GET", "/api/v1/zones/claims")
            .iter()
            .any(|call| call.session.as_deref() == Some("alice"))
    );
}

#[test]
fn renew_cli_and_mcp_return_open_mail_numbers_and_explicit_unknown() {
    for fail in [false, true] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.claims = vec![rework_claim(71)];
            state.inbox = vec![
                json!({"id":547,"from_session":"bob","to":"alice","kind":"ask","needs":"reply","body":"review"}),
            ];
            if fail {
                state.refuse_inbox_get = Some((
                    503,
                    json!({"error":{"code":"unavailable","message":"mail unavailable"}}),
                ));
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let value = json_of(&cli(
            dir.path(),
            runtime.path(),
            &["zone", "renew", "71", "--json"],
        ));
        if fail {
            assert_eq!(value["open_mail_unknown"], true);
        } else {
            assert_eq!(value["open_mail_count"], 1);
            assert_eq!(value["open_mail"][0]["id"], 547);
        }
        let text = cli(dir.path(), runtime.path(), &["zone", "renew", "71"]);
        assert!(text.status.success(), "{text:?}");
        let text = String::from_utf8(text.stdout).unwrap();
        assert!(
            text.contains(if fail {
                "почта: неизвестно"
            } else {
                "M-547"
            }),
            "{text}"
        );
        let answers = mcp_calls(
            dir.path(),
            runtime.path(),
            "compact",
            &[("zone_renew", json!({"id":71}))],
        );
        let value = &answers[0]["structuredContent"];
        assert_eq!(answers[0]["isError"], false, "{answers:?}");
        if fail {
            assert_eq!(value["open_mail_unknown"], true);
        } else {
            assert_eq!(value["open_mail"][0]["id"], 547);
        }
    }
}

#[test]
fn keepalive_ping_and_file_inputs_reach_real_cloud_requests() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.claims = vec![rework_claim(71)];
        state.registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let value = json_of(&cli(
        dir.path(),
        runtime.path(),
        &["keepalive", "71", "--json"],
    ));
    assert_eq!(value["activity"], json!([71]));
    assert!(
        server
            .seen("POST", "/api/v1/presence")
            .iter()
            .any(|r| r.body["activity"]["state"] == "working")
    );
    assert_eq!(
        server.seen("POST", "/api/v1/zones/claims/71/activity")[0].body["paths"],
        json!(["src"])
    );
    let replies = mcp_calls(
        dir.path(),
        runtime.path(),
        "compact",
        &[("keepalive", json!({"id":71}))],
    );
    assert_eq!(replies[0]["isError"], false, "{replies:?}");
    assert!(
        cli(dir.path(), runtime.path(), &["ping", "src", "--json"])
            .status
            .success()
    );
    let paths = runtime.path().join("paths.txt");
    let body = runtime.path().join("body.txt");
    let acceptance = runtime.path().join("acceptance.txt");
    std::fs::write(&paths, "tests\nassets\n").unwrap();
    std::fs::write(&body, "body from file\nsecond line").unwrap();
    std::fs::write(&acceptance, "acceptance from file").unwrap();
    let result = cli(
        dir.path(),
        runtime.path(),
        &[
            "zone",
            "claim",
            "--paths-file",
            paths.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        server.seen("POST", "/api/v1/zones/claims")[0].body["paths"],
        json!(["tests", "assets"])
    );
    let result = cli(
        dir.path(),
        runtime.path(),
        &[
            "task",
            "add",
            "file task",
            "--area",
            "engine",
            "--body-file",
            body.to_str().unwrap(),
            "--acceptance-file",
            acceptance.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(result.status.success(), "{result:?}");
    let request = &server.seen("POST", "/api/v1/registry/items")[0];
    assert_eq!(request.body["body"], "body from file\nsecond line");
    assert_eq!(request.body["acceptance"], "acceptance from file");
}

#[test]
fn cli_without_env_uses_the_same_project_mcp_token_file() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let token = runtime.path().join("mcp-agent.token");
    std::fs::write(&token, "test-token\n").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.path().join(".mcp.json"),json!({"mcpServers":{"lockyard":{"command":"lockyard","args":["mcp"],"env":{"LOCKYARD_URL":server.url,"LOCKYARD_TOKEN_FILE":token}}}}).to_string()).unwrap();
    let result = binary(dir.path(), runtime.path())
        .args(["task", "list", "--json"])
        .env("LOCKYARD_AGENT", "alice")
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_TOKEN_FILE")
        .env("LOCKYARD_CREDENTIALS", runtime.path().join("missing"))
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(
        serde_json::from_slice::<Value>(&result.stdout)
            .unwrap()
            .is_array()
    );
    assert!(!server.seen("GET", "/api/v1/registry/items").is_empty());
}

#[test]
fn cloud_task_list_is_a_single_json_document_for_json_loads() {
    let server = Server::start();
    server.state.lock().unwrap().registry_items =
        vec![json!({"id":"FE-1","title":"line\nwith controls","status":"ready"})];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    for agent in [false, true] {
        let _daemon = agent.then(|| start_agent(dir.path(), runtime.path()));
        let result = cli(
            dir.path(),
            runtime.path(),
            &["task", "list", "--all", "--json"],
        );
        assert!(result.status.success(), "{result:?}");
        let parsed: Value =
            serde_json::from_slice(&result.stdout).expect("json.loads compatible single document");
        assert_eq!(parsed[0]["id"], "FE-1");
        assert_eq!(result.stdout.iter().filter(|c| **c == b'\n').count(), 1);
    }
}

#[test]
fn cli_and_mcp_partial_zone_mutations_use_server_paths_and_except_contracts() {
    for mcp in [false, true] {
        let server = Server::start();
        server.state.lock().unwrap().claims = vec![rework_claim(71)];
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        if mcp {
            let replies = mcp_calls(
                dir.path(),
                runtime.path(),
                "full",
                &[
                    (
                        "zone_narrow",
                        json!({"id":71,"except":["src/private"],"fence":1}),
                    ),
                    (
                        "zone_handover",
                        json!({"id":71,"to":"bob","paths":["src/a"]}),
                    ),
                    (
                        "zone_takeover",
                        json!({"id":71,"reason":"holder silent","paths":["src/b"]}),
                    ),
                    ("zone_release", json!({"id":71,"paths":["src/a"]})),
                ],
            );
            for reply in replies {
                assert_eq!(reply["isError"], false, "{reply}");
            }
        } else {
            for args in [
                vec![
                    "zone",
                    "narrow",
                    "71",
                    "--except",
                    "src/private",
                    "--fence",
                    "1",
                ],
                vec!["zone", "handover", "71", "--to", "bob", "--paths", "src/a"],
                vec![
                    "zone",
                    "takeover",
                    "71",
                    "--reason",
                    "holder silent",
                    "--paths",
                    "src/b",
                ],
                vec!["zone", "release", "71", "--path", "src/a"],
            ] {
                let result = cli(dir.path(), runtime.path(), &args);
                assert!(result.status.success(), "{args:?}: {result:?}");
            }
        }
        let narrow = server.seen("POST", "/api/v1/zones/claims/71/narrow");
        assert_eq!(narrow[0].body["except"], json!(["src/private"]));
        assert!(narrow[0].body.get("paths").is_none());
        assert_eq!(
            server.seen("POST", "/api/v1/zones/claims/71/handover")[0].body["paths"],
            json!(["src/a"])
        );
        assert_eq!(
            server.seen("POST", "/api/v1/zones/claims/71/takeover")[0].body["paths"],
            json!(["src/b"])
        );
        assert_eq!(
            server.seen("DELETE", "/api/v1/zones/claims/71")[0].body["paths"],
            json!(["src/a"])
        );
    }
}

#[test]
fn multiple_add_paths_roll_back_completed_additions_on_later_refusal() {
    for (mcp, queued, raced) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (false, true, true),
        (true, true, true),
    ] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.claims = vec![rework_claim(71)];
            state.grant_before_queue_cancel = raced;
            if queued {
                state.queued_add_path = Some("blocked".into());
            } else {
                state.refuse_add_path = Some("blocked".into());
            }
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let error = if mcp {
            let answers = mcp_calls(
                dir.path(),
                runtime.path(),
                "full",
                &[(
                    "zone_add_path",
                    json!({"id":71,"paths":["tests","blocked"]}),
                )],
            );
            assert_eq!(answers[0]["isError"], true);
            answers[0].to_string()
        } else {
            let result = cli(
                dir.path(),
                runtime.path(),
                &["zone", "add-path", "71", "tests", "blocked"],
            );
            assert!(!result.status.success());
            String::from_utf8(result.stderr).unwrap()
        };
        assert!(
            error.contains("added tests") && error.contains("rolled back"),
            "{error}"
        );
        // Releasing the blocker would grant any queued add-path left behind.
        let mut state = server.state.lock().unwrap();
        let pending = std::mem::take(&mut state.deferred_add_paths);
        for (id, path) in pending {
            if let Some(claim) = state.claims.iter_mut().find(|claim| claim["id"] == id) {
                claim["paths"].as_array_mut().unwrap().push(json!(path));
            }
        }
        assert_eq!(state.claims[0]["paths"], json!(["src"]));
        drop(state);
        if queued {
            assert_eq!(server.seen("DELETE", "/api/v1/zones/queue/900").len(), 1);
        }
        assert_eq!(
            server.seen("POST", "/api/v1/zones/claims/71/narrow")[0].body["fence"],
            if raced { 3 } else { 2 }
        );
    }
}

#[test]
fn agent_reports_dirty_paths_from_a_real_uncommitted_hook_write() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![rework_claim(71)];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/a.rs"), "uncommitted write").unwrap();
    let _agent = start_agent(dir.path(), runtime.path());
    let output = hook(
        dir.path(),
        runtime.path(),
        &json!({"hook_event_name":"PostToolUse","session_id":"alice","cwd":dir.path(),"tool_name":"Write","tool_input":{"file_path":dir.path().join("src/a.rs")}}),
    );
    assert!(output.status.success(), "{output:?}");
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let seen = server.seen("POST", "/api/v1/zones/dirty");
        if !seen.is_empty() {
            assert!(
                seen.iter().any(|r| r.body.to_string().contains("src/a.rs")),
                "{seen:?}"
            );
            break;
        }
        assert!(Instant::now() < end, "daemon did not report dirty");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn parent_and_child_foreign_claims_return_held_with_the_holder() {
    for (held, checked) in [("src", "src/a.rs"), ("src/a.rs", "src")] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.claims = vec![
                json!({"id":72,"session":"bob","paths":[held],"expires_at":HOLD_EXPIRES_AT,"fence":1}),
            ];
            state.check_reply = Some(
                json!({"paths":[{"path":checked,"status":"held","holder":{"session":"bob","claim_id":72,"path":checked,"held_path":held}}]}),
            );
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        for agent in [false, true] {
            let _daemon = agent.then(|| start_agent(dir.path(), runtime.path()));
            let result = cli(
                dir.path(),
                runtime.path(),
                &["zone", "check", checked, "--json"],
            );
            assert_eq!(result.status.code(), Some(3), "{result:?}");
            let value: Value = serde_json::from_slice(&result.stderr).unwrap();
            assert!(value.to_string().contains("bob"), "{value}");
        }
    }
}

#[test]
fn p0_create_without_category_and_task_update_with_bad_category_are_rejected() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
        state.registry_items =
            vec![json!({"id":"FE-1","title":"task","status":"ready","priority":"P2","version":1})];
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let result = cli(
        dir.path(),
        runtime.path(),
        &[
            "task",
            "add",
            "no category",
            "--area",
            "engine",
            "--priority",
            "P0",
        ],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("p0_category"));
    assert!(server.seen("POST", "/api/v1/registry/items").is_empty());
    let replies = mcp_calls(
        dir.path(),
        runtime.path(),
        "full",
        &[
            ("task_update", json!({"id":"FE-1","priority":"P0"})),
            ("task_update", json!({"id":"FE-1","p0_category":"invalid"})),
            (
                "task_update",
                json!({"id":"FE-1","priority":"P0","p0_category":"prod_outage"}),
            ),
        ],
    );
    assert_eq!(replies[0]["isError"], true, "{replies:?}");
    assert_eq!(replies[1]["isError"], true, "{replies:?}");
    assert_eq!(replies[2]["isError"], false, "{replies:?}");
    let writes = server.seen("POST", "/api/v1/registry/items/FE-1/plan");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].body["p0_category"], "prod_outage");
}


#[test]
fn round4_legacy_p0_due_can_change_without_category() {
    let server = Server::start();
    server.state.lock().unwrap().registry_items = vec![json!({"id":"FE-1","title":"legacy","status":"ready","priority":"P0","version":1})];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let replies = mcp_calls(dir.path(), runtime.path(), "full", &[("task_update",json!({"id":"FE-1","due":"2026-12-01T00:00:00Z"}))]);
    assert_eq!(replies[0]["isError"], false, "{replies:?}");
    let writes = server.seen("POST", "/api/v1/registry/items/FE-1/plan");
    assert_eq!(writes.len(),1);
    assert_eq!(writes[0].body["priority"], "P0");
    assert!(writes[0].body["p0_category"].is_null());
    assert_eq!(writes[0].body["due_at"], "2026-12-01T00:00:00Z");
}

#[test]
fn round4_claim_fixture_filters_the_requested_session() {
    let server = Server::start();
    let mut other = rework_claim(72); other["session"] = json!("bob");
    server.state.lock().unwrap().claims = vec![rework_claim(71),other];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let claims = json_of(&cli(dir.path(),runtime.path(), &["zone","list","--session","bob","--json"]));
    assert_eq!(claims.as_array().unwrap().len(),1,"{claims}");
    assert_eq!(claims[0]["id"],72);
}

#[test]
fn round5_e2ee_handover_keeps_label_and_both_sessions_can_read_all_views() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let created = binary(dir.path(), runtime.path())
        .args(["--agent","alice","--json","zone","claim","src"])
        .env("LOCKYARD_TOKEN","test-token").env("LOCKYARD_SESSION_LABEL","original chat")
        .output().unwrap();
    assert_eq!(json_of(&created)["meta"]["session_label"],"original chat");
    let meta = server.state.lock().unwrap().claims[0]["meta"].clone();
    assert!(meta.get("session_label").is_none());
    json_of(&cli(dir.path(),runtime.path(), &["--agent","alice","--json","zone","handover","1","--to","bob"]));
    let accepted = json_of(&cli(dir.path(),runtime.path(), &["--agent","bob","--json","zone","accept","1"]));
    assert_eq!(accepted["meta"]["session_label"], "original chat");
    assert_eq!(accepted["session"], "bob");
    assert_eq!(server.state.lock().unwrap().claims[0]["meta"], meta);
    for session in ["alice","bob"] {
        let listed = json_of(&cli(dir.path(),runtime.path(), &["--agent",session,"--json","zone","list"]));
        assert_eq!(listed[0]["meta"]["session_label"],"original chat");
        let status = json_of(&cli(dir.path(),runtime.path(), &["--agent",session,"--json","status"]));
        if session == "bob" {
            assert_eq!(status["claims"][0]["meta"]["session_label"],"original chat", "{status}");
        } else { assert_eq!(status["claims"], json!([])); }
        json_of(&cli(dir.path(),runtime.path(), &["--agent",session,"--json","zone","check","src"]));
    }
    let mut damaged = server.state.lock().unwrap().claims[0].clone();
    damaged["id"] = json!(99);
    damaged["meta"]["$lockyard_session_v1"] = json!("lyenc1.corrupt");
    server.state.lock().unwrap().claims.push(damaged);
    for session in ["alice","bob"] {
        let listed = json_of(&cli(dir.path(),runtime.path(), &["--agent",session,"--json","zone","list"]));
        assert_eq!(listed[0]["meta"]["session_label"],"original chat");
        assert_eq!(listed[1]["meta"]["identity_unavailable"],true);
        json_of(&cli(dir.path(),runtime.path(), &["--agent",session,"--json","status"]));
        json_of(&cli(dir.path(),runtime.path(), &["--agent",session,"--json","zone","check","src"]));
        let text = cli(dir.path(),runtime.path(), &["--agent",session,"zone","list"]);
        assert!(String::from_utf8_lossy(&text.stdout).contains("identity недоступна"));
    }
}
