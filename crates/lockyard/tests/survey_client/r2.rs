// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

#[test]
fn survey_r2_update_preflights_handled_before_sending() {
    for handled in [json!([10]), json!([0]), json!([-1]), json!(["10"])] {
        let server = Server::start();
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[
            ("update", json!({"to":"bob","body":"done","handled":handled})),
            ("update", json!({"to":"bob","body":"done"})),
        ]);
        assert_eq!(answers[0]["isError"], true, "{answers:?}");
        assert_eq!(answers[1]["isError"], false, "{answers:?}");
        assert_eq!(server.seen("POST", "/api/v1/bus/messages").len(), 1, "a preflight refusal must not send mail");
        assert!(server.writes_to("/inbox/handled").is_empty());
    }
}

#[test]
fn survey_r2_update_preserves_sent_when_handling_fails() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.survey_handled = true;
        state.survey_handled_failure = true;
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[("update", json!({"to":"bob","body":"done","handled":[10]}))]);
    let result = update_content(&answers[0]);
    assert!(result["sent"].is_object(), "{result}");
    assert!(result["handled_error"].to_string().contains("handling refused"), "{result}");
    assert_eq!(server.seen("POST", "/api/v1/bus/messages").len(), 1);
}

#[test]
fn survey_r2_finish_work_keeps_going_after_release_failure() {
    for only_failure in [false, true] {
        let server = Server::start();
        {
            let mut state = server.state.lock().unwrap();
            state.survey_release_failure_id = Some(1);
            state.claims = (1..=if only_failure { 1 } else { 2 }).map(|id| json!({"id":id,"session":"alice","paths":[format!("src/{id}")],"fence":id})).collect();
        }
        let dir = cloud_project(&server);
        let runtime = tempfile::tempdir().unwrap();
        let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[("finish_work",json!({"all":true}))]);
        let answer = &answers[0];
        assert_eq!(answer["isError"], only_failure, "{answer}");
        let result = &answer["structuredContent"];
        assert_eq!(result["released_ids"], if only_failure { json!([]) } else { json!([2]) }, "{answer}");
        assert_eq!(result["already_gone"], json!([]));
        assert_eq!(result["failed"][0]["id"], 1);
        assert!(result["failed"][0]["error"].to_string().contains("owner changed"));
        assert_eq!(server.seen("DELETE", "/api/v1/zones/claims/1").len(), 1);
        assert_eq!(server.seen("DELETE", "/api/v1/zones/claims/2").len(), usize::from(!only_failure));
    }
}

#[test]
fn survey_r2_long_session_label_fits_production_claim_and_mail_limits() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let label = format!("review\n\t\u{1b}\u{202e}{}", "session-".repeat(1000));
    for args in [vec!["--json","msg","send","bob","hello"], vec!["--json","zone","claim","src"]] {
        let output = binary(dir.path(), runtime.path()).args(args)
            .env("LOCKYARD_AGENT", "alice").env("LOCKYARD_TOKEN", "test-token")
            .env("LOCKYARD_SESSION_LABEL", &label).output().unwrap();
        json_of(&output);
    }
    let sent = server.seen("POST", "/api/v1/bus/messages");
    let sender = sent[0].body["from_client"].as_str().unwrap();
    assert!(sender.len() <= 256 && sender.chars().all(|c| !c.is_control()), "sender has {} bytes", sender.len());
    let claims = server.seen("POST", "/api/v1/zones/claims");
    let meta = &claims[0].body["meta"];
    let name = meta["session_label"].as_str().unwrap();
    assert!(name.chars().count() <= 64 && name.is_ascii(), "label has {} chars", name.chars().count());
    assert!(meta.to_string().len() <= 4096);
}

#[test]
fn survey_r2_e2ee_claim_and_start_work_omit_session_identity() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    required_catalog_fixture(&server, dir.path(), runtime.path());
    let hold_until = lockyard_core::proto::rfc3339(lockyard_core::proto::parse_rfc3339("2099-11-11T21:30:00Z").unwrap());
    let answers = mcp_calls_env(dir.path(), runtime.path(), "full", &[
        ("zone_claim",json!({"paths":["src"]})),
        ("start_work",json!({"paths":["tests"],"hold_reason":"build","hold_until":hold_until})),
    ], &[("LOCKYARD_E2EE_WORKSPACE_ID", "00000000-0000-0000-0000-000000000001")]);
    for answer in &answers { assert_eq!(answer["isError"], false, "{answer}"); }
    for write in server.seen("POST", "/api/v1/zones/claims") {
        for key in ["session_label", "parent_pid", "pid"] { assert!(write.body["meta"].get(key).is_none(), "{write:?}"); }
    }
}

#[test]
fn survey_r2_invalid_meta_and_ambiguous_update_are_preflight_errors() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(dir.path(), runtime.path(), "full", &[
        ("zone_claim",json!({"paths":["src"],"meta":"wrong"})),
        ("start_work",json!({"paths":["tests"],"meta":[1]})),
        ("update",json!({"reply_to":10,"to":"bob","body":"hello"})),
    ]);
    for answer in &answers { assert_eq!(answer["isError"], true, "{answer}"); }
    assert!(server.seen("POST", "/api/v1/zones/claims").is_empty());
    assert!(server.writes_to("/reply").is_empty());
    assert!(server.seen("POST", "/api/v1/bus/messages").is_empty());
}

#[test]
fn survey_r2_cwd_only_path_explains_workspace_root() {
    let server = Server::start();
    let dir = cloud_project(&server);
    let nested = dir.path().join("meta");
    std::fs::create_dir_all(nested.join("src")).unwrap();
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(&nested, runtime.path(), "compact", &[("start_work",json!({"paths":["src"]}))]);
    assert_eq!(answers[0]["isError"], true, "{answers:?}");
    let error = answers[0]["content"][0]["text"].as_str().unwrap();
    assert!(error.contains("workspace root") && error.contains("meta/src"), "{error}");
    assert!(server.seen("POST", "/api/v1/zones/claims").is_empty());
}

#[test]
fn survey_r2_idempotent_create_avoids_first_page_lookup_and_retires_pending() {
    let server = Server::start();
    {
        let mut state = server.state.lock().unwrap();
        state.registry_areas = vec![json!({"id":"area","key":"engine","prefix":"FE"})];
        state.registry_items = (1..=250).map(|id| json!({"id":format!("FE-{id}"),"title":"same title","status":"ready"})).collect();
        state.survey_uncertain_create = true;
        state.survey_echo_client_key = true;
        state.registry_page_size = Some(20);
    }
    let dir = cloud_project(&server);
    let runtime = tempfile::tempdir().unwrap();
    let answers = mcp_calls(dir.path(), runtime.path(), "compact", &[("task_add",json!({"title":"same title","area":"engine"}))]);
    assert_eq!(answers[0]["isError"], false, "{answers:?}");
    assert_eq!(answers[0]["structuredContent"]["created"], true);
    let writes = server.seen("POST", "/api/v1/registry/items");
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].body, writes[1].body);
    assert_eq!(writes[0].key, writes[1].key);
    assert!(server.seen("GET", "/api/v1/registry/items").is_empty());
    assert_eq!(server.state.lock().unwrap().registry_items.len(), 251);
    let journal = runtime.path().join("state/lockyard/pending-writes").canonicalize().unwrap();
    let client = lockyard_cloud_client::Client::new(&server.url, "test-token".into()).unwrap().with_pending_journal(journal).unwrap();
    assert!(client.pending_operations().is_empty());
}
