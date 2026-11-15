// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

fn update_content(answer: &Value) -> Value {
    assert_eq!(answer["isError"], false, "{answer}");
    let text = answer["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text.lines().last().unwrap()).unwrap()
}

#[test]
fn survey_0011_update_reply_new_mail_all_and_handled_capability() {
    let server = Server::start();
    server.state.lock().unwrap().inbox = vec![
        json!({"id":10,"from_session":"bob","to":"alice","body":"old","needs":"reply"}),
        json!({"id":11,"from_session":"bob","to":"alice","body":"new","needs":"reply"}),
    ];
    server.state.lock().unwrap().seen_ids = vec![10];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[
        ("update", json!({"peek":true})),
        ("update", json!({"peek":true,"all":true})),
        ("update", json!({"reply_to":11,"body":"done"})),
        ("update", json!({"handled":[10],"peek":true})),
    ]);
    assert_eq!(update_content(&answers[0])["mail"].as_array().unwrap().len(), 1);
    assert_eq!(update_content(&answers[1])["mail"].as_array().unwrap().len(), 2);
    assert_eq!(update_content(&answers[2])["sent"]["reply_to"], 11);
    assert_eq!(answers[3]["isError"], true);
    assert!(answers[3]["content"][0]["text"].as_str().unwrap().contains("mail_handled_v1"));
    assert!(server.writes_to("/inbox/seen").is_empty());
    assert!(server.writes_to("/inbox/handled").is_empty());
    server.state.lock().unwrap().survey_handled = true;
    let handled = mcp_calls(dir.path(), runtime.path(), "compact", &[("update", json!({"handled":[10],"peek":true}))]);
    assert_eq!(update_content(&handled[0])["handled"]["marked"], 1);
    assert_eq!(server.writes_to("/inbox/handled")[0].body, json!({"ids":[10]}));
    assert_eq!(server.state.lock().unwrap().seen_ids, vec![10]);
}

#[test]
fn survey_0011_status_omits_task_body_and_keeps_fence() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![json!({"id":1,"session":"alice","paths":["src"],"fence":17,"expires_at":HOLD_EXPIRES_AT})];
    server.state.lock().unwrap().registry_items = vec![json!({"id":"FE-1","title":"short","body":"large private body","status":"active","assignment":{"executor":"alice"}})];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answer = mcp_calls(dir.path(), runtime.path(), "compact", &[("status", json!({}))]);
    let status = &answer[0]["structuredContent"];
    assert_eq!(status["tasks"].as_array().unwrap().len(), 1, "{answer:?}");
    assert!(status["tasks"][0].get("body").is_none(), "{status}");
    assert_eq!(status["claims"][0]["fence"], 17);
    let status = json_of(&cli(dir.path(), runtime.path(), &["--json","status"]));
    assert!(status["tasks"][0].get("body").is_none());
    let text = cli(dir.path(), runtime.path(), &["status"]);
    assert!(String::from_utf8_lossy(&text.stdout).contains("fence=17"));
}

#[test]
fn survey_0012_fenceless_renew_cli_and_mcp_refuse_transferred_claim() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![json!({"id":1,"session":"alice","paths":["src"],"fence":7,"expires_at":HOLD_EXPIRES_AT})];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let cli_result = cli(dir.path(), runtime.path(), &["zone","renew","1","--ttl","10"]);
    assert!(cli_result.status.success(), "{}", String::from_utf8_lossy(&cli_result.stderr));
    assert_eq!(server.seen("POST", "/api/v1/zones/claims/1/renew")[0].body["fence"], 7);
    server.state.lock().unwrap().claims[0]["session"] = json!("bob");
    server.state.lock().unwrap().claims[0]["fence"] = json!(8);
    let answer = mcp_calls(dir.path(), runtime.path(), "compact", &[("zone_renew", json!({"id":1}))]);
    assert_eq!(answer[0]["isError"], true, "{answer:?}");
    assert_eq!(server.seen("POST", "/api/v1/zones/claims/1/renew").len(), 1);
    let cli_result = cli(dir.path(), runtime.path(), &["zone","renew","1"]);
    assert!(!cli_result.status.success());
    assert_eq!(server.seen("POST", "/api/v1/zones/claims/1/renew").len(), 1);
}

#[test]
fn survey_0013_task_and_area_lists_are_records() {
    let server = Server::start();
    server.state.lock().unwrap().registry_items = vec![json!({"id":"FE-1","title":"find this title","status":"ready"})];
    server.state.lock().unwrap().registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[
        ("tasks",json!({"action":"list","prefix":"FE","status":"open"})),
        ("area_list",json!({})),
    ]);
    for answer in &answers { assert_eq!(answer["isError"], false, "{answer}"); assert!(answer["structuredContent"].is_object(), "{answer}"); }
    assert_eq!(answers[0]["structuredContent"]["tasks"][0]["title"], "find this title");
    assert_eq!(answers[1]["structuredContent"]["areas"][0]["prefix"], "FE");
}

#[test]
fn survey_0014_reconcile_exact_creation_identity_or_report_unknown() {
    for exact in [false, true] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
            state.survey_uncertain_create = true;
            state.survey_echo_client_key = exact;
            state.registry_items = vec![json!({"id":"FE-3","title":"same title","author":"alice","status":"ready"})];
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[("task_add", json!({"title":"same title","area":"engine"}))]);
        let answer = &answers[0];
        if exact {
            assert_eq!(answer["isError"], false, "{answer}");
            assert_eq!(answer["structuredContent"]["created"], true);
            assert_eq!(answer["structuredContent"]["id"], "FE-77");
        } else {
            assert_eq!(answer["isError"], true, "{answer}");
            assert!(answer["content"][0]["text"].as_str().unwrap().contains("created=unknown"), "{answer}");
        }
        let requests = server.seen("POST", "/api/v1/registry/items");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].key, requests[1].key);
        assert_eq!(requests[0].body, requests[1].body);
        assert!(server.seen("GET", "/api/v1/registry/items").is_empty());
    }
}

#[test]
fn survey_0015_zones_paths_ttl_minutes_and_workspace_root() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let nested = dir.path().join("meta");
    std::fs::create_dir(&nested).unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(&nested, runtime.path(), "compact", &[
        ("start_work",json!({"zones":["sun-host/sims"]})),
        ("start_work",json!({"paths":["sun-host/sims"],"ttl":1800})),
        ("start_work",json!({"paths":["sun-host/sims"],"ttl":10})),
    ]);
    assert_eq!(answers[0]["isError"], true);
    assert!(answers[0]["content"][0]["text"].as_str().unwrap().contains("paths:"), "{answers:?}");
    assert_eq!(answers[1]["isError"], true);
    assert!(answers[1]["content"][0]["text"].as_str().unwrap().contains("minutes"));
    assert_eq!(answers[2]["isError"], false, "{answers:?}");
    let writes = server.seen("POST", "/api/v1/zones/claims");
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].body["paths"], json!(["sun-host/sims"]));
    assert_eq!(writes[0].body["ttl_minutes"], 10);
}

#[test]
fn survey_0016_lost_reason_time_and_finish_work_ids() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.survey_lost = vec![json!({"claim_id":9,"session":"alice","reason":"idle_released","lost_at":"2026-11-15T12:34:00Z"})];
        state.refuse_release = Some((404, json!({"error":{"code":"resource_not_found","message":"Resource not found."}})));
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[
        ("zone_renew",json!({"id":9})),
        ("finish_work",json!({"id":"9"})),
    ]);
    let error = answers[0]["content"][0]["text"].as_str().unwrap();
    assert!(error.contains("idle_released") && error.contains("12:34"), "{answers:?}");
    assert_eq!(answers[1]["isError"], false, "{answers:?}");
    assert_eq!(answers[1]["structuredContent"]["already_gone"], json!([9]));
    let cli_result = cli(dir.path(), runtime.path(), &["zone","release","9"]);
    let text = String::from_utf8_lossy(&cli_result.stderr);
    assert!(text.contains("idle_released") && text.contains("12:34"), "{text}");
    let lost = json_of(&cli(dir.path(), runtime.path(), &["--json","status","--lost"]));
    assert_eq!(lost[0]["claim_id"], 9);
    server.state.lock().unwrap().refuse_release = None;
    server.state.lock().unwrap().claims = vec![json!({"id":2,"session":"alice","paths":["src"],"fence":1})];
    let freed = mcp_calls(dir.path(), runtime.path(), "compact", &[("finish_work", json!({"id":"2"}))]);
    assert_eq!(freed[0]["structuredContent"]["released_ids"], json!([2]));
}

#[test]
fn survey_0017_session_label_survives_start_work_nonce_and_mail() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answer = mcp_calls(dir.path(), runtime.path(), "compact", &[("start_work",json!({"paths":["src"],"hold_reason":"build","hold_until":"2099-11-11T21:30:00Z"}))]);
    assert_eq!(answer[0]["isError"], false, "{answer:?}");
    let meta = &server.seen("POST", "/api/v1/zones/claims")[0].body["meta"];
    assert!(meta["parent_pid"].as_u64().is_some(), "{meta}");
    assert!(meta.get("session_label").is_some());
    assert!(meta.get("lockyard_start_work_nonce").is_some());
    let sent = cli(dir.path(), runtime.path(), &["msg","send","bob","hello"]);
    assert!(sent.status.success(), "{}", String::from_utf8_lossy(&sent.stderr));
    let messages = server.seen("POST", "/api/v1/bus/messages");
    assert!(messages[0].body["from_client"].as_str().unwrap().contains("parent_pid="));
}

#[test]
fn survey_0015_cli_and_mcp_add_multiple_paths_then_narrow_from_nested_cwd() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let nested = dir.path().join("meta");
    std::fs::create_dir(&nested).unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let claim = json_of(&cli(&nested, runtime.path(), &["--json","zone","claim","src","--ttl","10"]));
    assert_eq!(claim["paths"], json!(["src"]));
    let expanded = json_of(&cli(&nested, runtime.path(), &["--json","zone","add-path","1","docs","tests"]));
    assert_eq!(expanded["paths"], json!(["src","docs","tests"]));
    let narrowed = json_of(&cli(&nested, runtime.path(), &["--json","zone","narrow","1","docs"]));
    assert_eq!(narrowed["paths"], json!(["docs"]));
    let expanded = mcp_calls(&nested, runtime.path(), "full", &[("zone_add_path",json!({"id":1,"paths":["src","tests"]}))]);
    assert_eq!(expanded[0]["isError"], false, "{expanded:?}");
    assert_eq!(expanded[0]["structuredContent"]["paths"], json!(["docs","src","tests"]));
}

#[test]
fn survey_0012_renew_each_own_claim_with_its_own_current_fence() {
    let server = Server::start();
    server.state.lock().unwrap().claims = vec![
        json!({"id":1,"session":"alice","paths":["src"],"fence":7,"expires_at":HOLD_EXPIRES_AT}),
        json!({"id":2,"session":"alice","paths":["docs"],"fence":8,"expires_at":HOLD_EXPIRES_AT}),
        json!({"id":3,"session":"bob","paths":["tests"],"fence":9,"expires_at":HOLD_EXPIRES_AT}),
    ];
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answer = mcp_calls(dir.path(), runtime.path(), "compact", &[("zone_renew",json!({"ttl":10}))]);
    assert_eq!(answer[0]["isError"], false, "{answer:?}");
    assert_eq!(answer[0]["structuredContent"]["renewed"], 2);
    for (id, fence) in [(1,7),(2,8)] {
        assert_eq!(server.seen("POST", &format!("/api/v1/zones/claims/{id}/renew"))[0].body["fence"], fence);
    }
    assert!(server.seen("POST", "/api/v1/zones/claims/3/renew").is_empty());
}

#[test]
fn survey_0017_explicit_chat_label_and_caller_meta_are_visible_to_peers() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let claim = binary(dir.path(), runtime.path())
        .args(["--json","zone","claim","src","--meta", r#"{"custom":"keep"}"#])
        .env("LOCKYARD_AGENT","alice").env("LOCKYARD_TOKEN","test-token")
        .env("LOCKYARD_SESSION_LABEL","survey chat").output().unwrap();
    let claim = json_of(&claim);
    assert_eq!(claim["meta"]["custom"], "keep");
    let listed = json_of(&cli(dir.path(), runtime.path(), &["--agent","bob","--json","zone","list"]));
    assert_eq!(listed[0]["meta"]["session_label"], "survey chat");
    let listed = cli(dir.path(), runtime.path(), &["--agent","bob","zone","list"]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("survey chat") && text.contains("parent_pid="), "{text}");
    let reply = cli(dir.path(), runtime.path(), &["msg","reply","10","done"]);
    assert!(reply.status.success(), "{}", String::from_utf8_lossy(&reply.stderr));
    assert!(server.seen("POST", "/api/v1/bus/messages/10/reply")[0].body["from_client"].as_str().unwrap().contains("parent_pid="));
}
