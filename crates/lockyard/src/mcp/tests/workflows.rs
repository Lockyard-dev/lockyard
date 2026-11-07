// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

    #[test]
    fn the_default_surface_lists_compact_tools_and_full_lists_them_all() {
        let dir = project();
        let compact = listed(Surface::Compact, &dir);
        assert_eq!(
            compact,
            [
                "revoke_access",
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
            ]
        );
        let full = listed(Surface::Full, &dir);
        assert!(
            full.len() >= 61,
            "the full surface lost tools: {}",
            full.len()
        );
        for name in ["zone_claim", "msg_inbox", "task_submit", "work_offer"] {
            assert!(full.contains(&name.to_string()), "{name}");
        }
        // A compact description costs the model context on every turn; keep them one line.
        for tool in compact_tools() {
            let description = tool["description"].as_str().unwrap();
            assert!(description.len() <= 110, "{description}");
        }
    }

    #[test]
    fn the_surface_comes_from_the_flag_then_the_environment_then_the_default() {
        assert_eq!(Surface::choose(Some("full")).unwrap(), Surface::Full);
        assert_eq!(Surface::choose(Some("compact")).unwrap(), Surface::Compact);
        assert!(Surface::choose(Some("some")).is_err());
        // SAFETY: single-threaded test process; the variable is removed before it returns.
        unsafe { std::env::set_var("LOCKYARD_MCP_TOOLS", "full") };
        assert_eq!(Surface::choose(None).unwrap(), Surface::Full);
        assert_eq!(
            Surface::choose(Some("compact")).unwrap(),
            Surface::Compact,
            "the flag wins over the environment"
        );
        unsafe { std::env::remove_var("LOCKYARD_MCP_TOOLS") };
        assert_eq!(Surface::choose(None).unwrap(), Surface::Compact);
    }

    #[test]
    fn start_work_claims_and_is_still_refused_when_another_agent_holds_the_path() {
        let dir = project();
        let started = call(
            &dir,
            "a",
            "start_work",
            json!({"paths": ["src"], "note": "auth"}),
        );
        assert_eq!(started["isError"], false);
        assert!(text(&started).contains("\"unread\":0"));
        let refused = call(&dir, "b", "start_work", json!({"paths": ["src/api"]}));
        assert_eq!(refused["isError"], true);
        assert!(text(&refused).contains("held by a"));
    }

    #[test]
    fn compact_start_work_accepts_handover_and_requires_a_target() {
        let dir = project();
        let no_args = call(&dir, "a", "start_work", json!({}));
        assert_eq!(no_args["isError"], true);
        assert!(text(&no_args).contains("needs paths or zones"));
        let opened = call(&dir, "a", "start_work", json!({"paths": ["src"]}));
        let id: i64 = serde_json::from_str::<Value>(text(&opened)).unwrap()["claim"]["id"]
            .as_i64()
            .unwrap();
        let accepted = call(&dir, "b", "start_work", json!({"handover_id": id}));
        assert_eq!(
            accepted["isError"], true,
            "local mode has no handover offers"
        );
    }

    #[test]
    fn compact_start_work_can_claim_a_task_without_paths() {
        let dir = project();
        call(&dir, "lead", "task_add", json!({"title": "ship"}));
        let started = call(&dir, "worker", "start_work", json!({"task": "D-1"}));
        assert_eq!(started["isError"], false);
        assert!(text(&started).contains("\"status\":\"claimed\""));
    }

    #[test]
    fn status_only_returns_the_callers_claims() {
        let dir = project();
        call(&dir, "a", "start_work", json!({"paths": ["src"]}));
        call(&dir, "b", "start_work", json!({"paths": ["docs"]}));
        let status = call(&dir, "a", "status", json!({}));
        let parsed: Value = serde_json::from_str(text(&status)).unwrap();
        assert!(
            parsed["claims"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["agent"] == "a")
        );
    }

    #[test]
    fn registry_task_ids_are_strings_and_integer_ids_are_refused() {
        let dir = project();
        let error = call(&dir, "lead", "task_show", json!({"id": 12}));
        assert!(text(&error).contains("integers are not accepted"));
        let compact = compact_tools();
        let start = compact
            .iter()
            .find(|tool| tool["name"] == "start_work")
            .unwrap();
        assert_eq!(start["inputSchema"]["properties"]["task"]["type"], "string");
        let finish = compact
            .iter()
            .find(|tool| tool["name"] == "finish_work")
            .unwrap();
        assert_eq!(
            finish["inputSchema"]["properties"]["task"]["type"],
            "string"
        );
    }

    #[test]
    fn compact_registry_list_and_bulk_close_use_string_ids_idempotently() {
        let dir = project();
        call(&dir, "lead", "task_add", json!({"title": "ship"}));
        let listed = call(&dir, "worker", "tasks", json!({"action": "list"}));
        assert!(text(&listed).contains("\"id\":\"D-1\""));
        let first = call(
            &dir,
            "lead",
            "task_bulk",
            json!({"ids": ["D-1"], "evidence": "owner decision"}),
        );
        let second = call(
            &dir,
            "lead",
            "task_bulk",
            json!({"ids": ["D-1"], "evidence": "owner decision"}),
        );
        assert_eq!(first["isError"], false);
        assert_eq!(second["isError"], false);
        assert!(text(&second).contains("cancelled"));
    }

    #[test]
    fn compact_handover_schema_allows_implicit_claim_selection() {
        let definition = compact_tools()
            .into_iter()
            .find(|tool| tool["name"] == "handover")
            .unwrap();
        assert_eq!(definition["inputSchema"]["required"], json!(["to"]));
    }

    #[test]
    fn finish_without_id_reports_the_claim_ids_it_releases() {
        let dir = project();
        call(&dir, "a", "start_work", json!({"paths": ["src"]}));
        let finished = call(&dir, "a", "finish_work", json!({}));
        let answer: Value = serde_json::from_str(text(&finished)).unwrap();
        assert_eq!(answer["released"], 1);
        assert_eq!(answer["released_ids"], json!([1]));
    }

    #[test]
    fn finish_with_an_id_reports_the_released_id() {
        let dir = project();
        call(&dir, "a", "zone_claim", json!({"paths": ["src"]}));
        let finished = call(&dir, "a", "finish_work", json!({"id": "Z-1"}));
        let answer: Value = serde_json::from_str(text(&finished)).unwrap();
        assert_eq!(answer["released_ids"], json!([1]));
    }

    #[test]
    fn start_work_ttl_schema_names_minutes() {
        let definition = compact_tools()
            .into_iter()
            .find(|tool| tool["name"] == "start_work")
            .unwrap();
        let ttl = &definition["inputSchema"]["properties"]["ttl"];
        let description = ttl["description"].as_str().unwrap();
        assert!(description.contains("minutes"), "{description}");
        assert!(description.contains('1'), "{description}");
        assert!(description.contains("240"), "{description}");
        assert_eq!(ttl["minimum"], json!(1));
        assert_eq!(ttl["maximum"], json!(240));
    }

    #[test]
    fn finish_work_accepts_claim_ids_with_or_without_the_zone_prefix() {
        let dir = project();
        call(&dir, "a", "zone_claim", json!({"paths": ["src"]}));
        let finished = call(&dir, "a", "finish_work", json!({"id": "Z-1"}));
        assert_eq!(finished["isError"], false, "{}", text(&finished));
        call(&dir, "a", "zone_claim", json!({"paths": ["docs"]}));
        let finished = call(&dir, "a", "finish_work", json!({"id": "2"}));
        assert_eq!(finished["isError"], false, "{}", text(&finished));
    }

    #[test]
    fn start_work_rejects_unknown_zone_with_catalog_hint() {
        let dir = project();
        let result = call(&dir, "a", "start_work", json!({"zones": ["not-a-zone"]}));
        assert_eq!(result["isError"], true);
        assert!(text(&result).contains("unknown zone"));
    }

    #[test]
    fn start_work_gives_the_zone_back_when_the_task_it_was_asked_for_is_taken() {
        let dir = project();
        call(&dir, "lead", "task_add", json!({"title": "ship"}));
        call(&dir, "first", "task_claim", json!({"id": "1"}));
        let refused = call(
            &dir,
            "second",
            "start_work",
            json!({"paths": ["src"], "task": "1"}),
        );
        assert_eq!(refused["isError"], true);
        let free = call(&dir, "third", "zone_claim", json!({"paths": ["src"]}));
        assert_eq!(free["isError"], false, "the rolled-back zone is free again");
    }

    #[test]
    fn start_work_failure_preserves_unrelated_and_reused_claims() {
        for (held, requested) in [("docs", "src"), ("src", "src/sub")] {
            let dir = project();
            call(&dir, "lead", "task_add", json!({"title": "ship"}));
            call(&dir, "first", "task_claim", json!({"id": "1"}));
            let original = call(&dir, "second", "zone_claim", json!({"paths": [held]}));
            assert_eq!(original["isError"], false);
            let original: Value = serde_json::from_str(text(&original)).unwrap();
            let refused = call(
                &dir,
                "second",
                "start_work",
                json!({"paths": [requested], "task": "1"}),
            );
            assert_eq!(refused["isError"], true);
            let status = call(&dir, "second", "status", json!({}));
            let status: Value = serde_json::from_str(text(&status)).unwrap();
            assert!(
                status["claims"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|claim| claim["id"] == original["id"]),
                "failed start_work removed the pre-existing {held} claim: {status}"
            );
            if held == "docs" {
                let free = call(&dir, "third", "zone_claim", json!({"paths": [requested]}));
                assert_eq!(
                    free["isError"], false,
                    "only the newly created claim rolls back"
                );
            }
        }
    }

    #[test]
    fn start_work_validates_task_before_acquiring_a_zone() {
        let dir = project();
        let refused = call(
            &dir,
            "worker",
            "start_work",
            json!({"paths": ["src"], "task": []}),
        );
        assert_eq!(refused["isError"], true);
        let free = call(&dir, "other", "zone_claim", json!({"paths": ["src"]}));
        assert_eq!(
            free["isError"], false,
            "invalid arguments must leave no claim behind"
        );
    }

    #[test]
    fn update_sends_then_reads_and_marks_the_mail_it_showed() {
        let dir = project();
        call(&dir, "b", "msg_inbox", json!({}));
        call(&dir, "a", "msg_send", json!({"to": "b", "body": "ping"}));
        let read = call(&dir, "b", "update", json!({"to": "a", "body": "on it"}));
        assert!(text(&read).starts_with(MAIL_WARNING));
        assert!(text(&read).contains("ping"));
        assert!(text(&read).contains("on it"));
        assert!(text(&call(&dir, "b", "msg_unread", json!({}))).contains("\"unread\":0"));
        let half = call(&dir, "b", "update", json!({"to": "a"}));
        assert_eq!(half["isError"], true);
    }

    #[test]
    fn mail_tools_escape_bidi_controls_in_message_bodies() {
        let dir = project();
        call(&dir, "b", "msg_inbox", json!({}));
        call(
            &dir,
            "a",
            "msg_send",
            json!({"to": "b", "body": "safe\u{202e}hidden"}),
        );
        let inbox = call(&dir, "b", "msg_inbox", json!({}));
        assert!(!text(&inbox).contains('\u{202e}'));
        assert!(text(&inbox).contains("\\u{202e}"));
    }

    #[test]
    fn handover_in_local_mode_releases_the_zone_and_says_so() {
        let dir = project();
        call(&dir, "b", "msg_inbox", json!({}));
        call(&dir, "a", "start_work", json!({"paths": ["src"]}));
        let handed = call(
            &dir,
            "a",
            "handover",
            json!({"to": "b", "note": "all yours"}),
        );
        assert!(text(&handed).contains("\"mode\":\"released\""));
        assert!(text(&handed).contains("\"released\":1"));
        let taken = call(&dir, "b", "start_work", json!({"paths": ["src"]}));
        assert_eq!(taken["isError"], false);
        assert!(text(&call(&dir, "b", "msg_unread", json!({}))).contains("\"unread\":1"));
    }

    #[test]
    fn finish_work_submits_with_evidence_and_releases() {
        let dir = project();
        call(&dir, "lead", "task_add", json!({"title": "ship"}));
        call(
            &dir,
            "w",
            "start_work",
            json!({"paths": ["src"], "task": "1"}),
        );
        let without = call(&dir, "w", "finish_work", json!({"task": "1"}));
        assert_eq!(without["isError"], true, "evidence is not optional");
        let done = call(
            &dir,
            "w",
            "finish_work",
            json!({"task": "1", "evidence": "abc1234, 9/9 tests"}),
        );
        assert!(text(&done).contains("\"review\""));
        assert!(text(&done).contains("\"released\":1"));
        assert!(text(&call(&dir, "w", "zone_list", json!({}))).starts_with('['));
    }

    #[test]
    fn check_is_the_short_name_for_a_zone_check() {
        let dir = project();
        call(&dir, "a", "zone_claim", json!({"paths": ["src"]}));
        let held = call(&dir, "b", "check", json!({"path": "src/x.rs"}));
        assert_eq!(held["isError"], false);
        let answer: Value = serde_json::from_str(text(&held)).unwrap();
        assert_eq!(answer["free"], false);
        assert_eq!(answer["holder"]["agent"], "a");
        assert!(text(&call(&dir, "b", "check", json!({"path": "docs"}))).contains("free"));
    }

    #[test]
    fn check_identifies_a_path_held_by_the_calling_agent() {
        let dir = project();
        call(&dir, "a", "zone_claim", json!({"paths": ["src"]}));
        let failed_finish = call(&dir, "a", "finish_work", json!({"id": 999}));
        assert_eq!(failed_finish["isError"], true);
        let result = call(&dir, "a", "check", json!({"path": "src/file.rs"}));
        assert_eq!(result["isError"], false);
        let answer: Value = serde_json::from_str(text(&result)).unwrap();
        assert_eq!(answer["free"], false);
        assert_eq!(answer["own"], true);
        assert_eq!(answer["holder"], "you");
    }

    #[test]
    fn a_pending_handover_is_an_offer_and_not_the_receivers_claim() {
        let offered: Claim = serde_json::from_value(json!({
            "id": 414,
            "session": "sender",
            "paths": ["src/Auth"],
            "note": "pass"
        }))
        .unwrap();
        let mine: Claim = serde_json::from_value(json!({
            "id": 7,
            "session": "receiver",
            "paths": ["docs"]
        }))
        .unwrap();
        let (claims, offers) = split_handover_offers("receiver", vec![offered, mine]);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, 7);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0]["id"], 414);
        assert_eq!(offers[0]["from"], "sender");
        assert_eq!(offers[0]["paths"], json!(["src/Auth"]));
    }

    #[test]
    fn equivalent_reclaims_reuse_the_existing_claim() {
        let dir = project();
        let first = call(&dir, "a", "zone_claim", json!({"paths": ["Auth/a.cs"]}));
        let first: Value = serde_json::from_str(text(&first)).unwrap();
        let again = call(&dir, "a", "zone_claim", json!({"paths": ["auth/a.cs"]}));
        let again: Value = serde_json::from_str(text(&again)).unwrap();
        assert_eq!(first["id"], again["id"]);
        let claims = call(&dir, "a", "zone_list", json!({}));
        assert_eq!(
            serde_json::from_str::<Value>(text(&claims))
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn unicode_normalized_reclaims_reuse_the_existing_claim() {
        let dir = project();
        let first = call(
            &dir,
            "a",
            "zone_claim",
            json!({"paths": ["caf\u{e9}/menu"]}),
        );
        let first: Value = serde_json::from_str(text(&first)).unwrap();
        let again = call(
            &dir,
            "a",
            "zone_claim",
            json!({"paths": ["cafe\u{301}/menu"]}),
        );
        let again: Value = serde_json::from_str(text(&again)).unwrap();
        assert_eq!(first["id"], again["id"]);
    }

    #[test]
    fn compact_task_id_errors_name_the_requested_id() {
        let dir = project();
        let result = call(&dir, "a", "task_show", json!({"id": "ZZ-9999"}));
        assert!(text(&result).contains("ZZ-9999"), "{}", text(&result));
    }

    #[test]
    fn unknown_message_target_and_claim_errors_name_the_requested_object() {
        let dir = project();
        let unknown = call(&dir, "a", "msg_send", json!({"to": "ghost", "body": "hi"}));
        assert_eq!(unknown["isError"], true);
        assert!(text(&unknown).contains("ghost"), "{}", text(&unknown));

        call(&dir, "a", "zone_claim", json!({"paths": ["src"]}));
        let missing = call(&dir, "a", "zone_release", json!({"id": 999999}));
        assert_eq!(missing["isError"], true);
        assert!(text(&missing).contains("Z-999999"), "{}", text(&missing));
        let claims = call(&dir, "a", "zone_list", json!({}));
        assert!(text(&claims).contains("\"id\":1"), "{}", text(&claims));
    }

    #[test]
    fn contention_error_uses_the_mcp_zone_tool_hint_once() {
        let message = tool_error_message(
            "task_release",
            &json!({"id": "1"}),
            &Error::Contended("Only an active item has a lease.".into()),
        );
        assert!(message.contains("Only an active item has a lease. Next:"));
        assert!(message.contains("the zone_list tool"));
        assert!(!message.contains("lockyard zone list"));
        assert!(!message.contains(".."));
    }

    #[test]
    fn a_full_task_cycle_works_and_the_worker_cannot_accept() {
        let dir = project();
        call(&dir, "lead", "task_add", json!({"title": "ship"}));
        call(&dir, "worker", "task_claim", json!({"id": "1"}));
        call(
            &dir,
            "worker",
            "task_submit",
            json!({"id": "1", "evidence": "tests"}),
        );
        let own = call(&dir, "worker", "task_accept", json!({"id": "1"}));
        assert_eq!(own["isError"], true);
        assert!(text(&own).contains("own work"));
        let self_cancel = call(&dir, "worker", "task_cancel", json!({"id": "1"}));
        assert_eq!(self_cancel["isError"], true);
        assert!(text(&self_cancel).contains("only lead can cancel T-1"));
        let early = call(&dir, "claude", "task_accept", json!({"id": "1"}));
        assert_eq!(early["isError"], true);
        call(
            &dir,
            "codex",
            "task_review",
            json!({"id": "1", "decision": "pass"}),
        );
        let accepted = call(&dir, "claude", "task_accept", json!({"id": "1"}));
        assert!(text(&accepted).contains("\"accepted\""));
        let unknown = call(&dir, "lead", "task_list", json!({"status": "nope"}));
        assert_eq!(unknown["isError"], true);
    }
