// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

#[test]
fn survey_r4_required_e2ee_accepts_soft_claims_and_preserves_explicit_exclusive() {
    let server = Server::start();
    server.state.lock().unwrap().survey_soft_zones = true;
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let answers = mcp_calls_env(dir.path(), runtime.path(), "full", &[
        ("zone_claim", json!({"paths":["src"]})),
        ("start_work", json!({"paths":["tests"],"shared":false})),
        ("zone_wait", json!({"paths":["other"],"shared":true})),
    ], &[("LOCKYARD_E2EE_WORKSPACE_ID", "00000000-0000-0000-0000-000000000001")]);
    for answer in &answers { assert_eq!(answer["isError"], false, "{answer}"); }
    let writes = server.seen("POST", "/api/v1/zones/claims");
    assert_eq!(writes.len(), 3);
    assert!(writes[0].body.get("mode").is_none());
    assert_eq!(writes[1].body["mode"], "exclusive");
    assert_eq!(writes[2].body["mode"], "shared");
    assert_eq!(answers[0]["structuredContent"]["mode"], "shared");
    assert_eq!(answers[0]["structuredContent"]["held"], false);
    assert_eq!(answers[1]["structuredContent"]["claim"]["mode"], "exclusive");
}

#[test]
fn survey_r4_cli_and_mcp_preserve_unspecified_shared_and_exclusive_modes() {
    for soft in [false, true] {
        let server = Server::start();
        server.state.lock().unwrap().survey_soft_zones = soft;
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        for command in ["claim", "wait"] {
            for (flag, mode) in [(None, None), (Some("--shared"), Some("shared")), (Some("--exclusive"), Some("exclusive"))] {
                server.state.lock().unwrap().claims.clear();
                let mut args = vec!["--json", "zone", command, "src"];
                if let Some(flag) = flag { args.push(flag); }
                let answer = cli(dir.path(), runtime.path(), &args);
                json_of(&answer);
                let writes = server.seen("POST", "/api/v1/zones/claims");
                let body = &writes.last().unwrap().body;
                assert_eq!(body.get("mode").and_then(Value::as_str), mode.or(if soft { None } else { Some("exclusive") }), "{body}");
            }
        }
        for tool in ["start_work", "zone_claim", "zone_wait"] {
            for shared in [None, Some(true), Some(false)] {
                server.state.lock().unwrap().claims.clear();
                let mut args = json!({"paths":["src"]});
                if let Some(shared) = shared { args["shared"] = json!(shared); }
                let answers = mcp_calls(dir.path(), runtime.path(), "full", &[(tool, args)]);
                assert_eq!(answers[0]["isError"], false, "{answers:?}");
                let writes = server.seen("POST", "/api/v1/zones/claims");
                let body = &writes.last().unwrap().body;
                let expected = shared.map(|shared| if shared { "shared" } else { "exclusive" })
                    .or(if soft { None } else { Some("exclusive") });
                assert_eq!(body.get("mode").and_then(Value::as_str), expected, "{body}");
                if soft {
                    let status = json_of(&cli(dir.path(), runtime.path(), &["--json", "status"]));
                    assert_eq!(status["claims"][0]["mode"], expected.unwrap_or("shared"));
                    let text = cli(dir.path(), runtime.path(), &["status"]);
                    assert!(String::from_utf8_lossy(&text.stdout).contains(&format!("mode={}", expected.unwrap_or("shared"))));
                }
            }
        }
        let count = server.seen("POST", "/api/v1/zones/claims").len();
        let conflict = cli(dir.path(), runtime.path(), &["zone", "claim", "src", "--shared", "--exclusive"]);
        assert!(!conflict.status.success());
        assert_eq!(server.seen("POST", "/api/v1/zones/claims").len(), count);
    }
}

#[test]
fn survey_r4_mode_help_explains_defaults_and_explicit_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = tempfile::tempdir().unwrap();
    for command in ["claim", "wait", "queue"] {
        let answer = cli(dir.path(), runtime.path(), &["zone", command, "--help"]);
        assert!(answer.status.success());
        let text = String::from_utf8_lossy(&answer.stdout);
        for expected in ["--shared", "--exclusive", "server default", "migrations", "contracts", "hosts"] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
    }
}
