// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

    #[test]
    fn compact_definitions_are_projection_of_full_registry() {
        let full = tools(Surface::Full);
        for mut compact in tools(Surface::Compact) {
            let name = compact["name"].as_str().unwrap().to_string();
            let canonical = full
                .iter()
                .find(|tool| tool["name"] == name)
                .unwrap_or_else(|| panic!("compact tool {name} is absent from full registry"));
            match name.as_str() {
                "task_add" => {
                    assert_eq!(canonical["inputSchema"]["required"], json!(["title"]));
                    assert_eq!(compact["inputSchema"]["required"], json!(["title", "area"]));
                    compact["inputSchema"]["required"] = canonical["inputSchema"]["required"].clone();
                    compact["description"] = canonical["description"].clone();
                }
                "zone_renew" => {
                    assert_eq!(canonical["inputSchema"]["required"], json!([]));
                    assert_eq!(canonical["inputSchema"]["properties"]["ttl"], json!({"type":"integer"}));
                    assert_eq!(compact["inputSchema"]["required"], json!([]));
                    let ttl = &compact["inputSchema"]["properties"]["ttl"];
                    assert_eq!(ttl["type"], "integer");
                    assert_eq!(ttl["minimum"], 1);
                    assert_eq!(ttl["maximum"], 240);
                    assert_eq!(ttl["default"], 30);
                    assert!(compact["description"].as_str().unwrap().contains("fence is required in cloud mode"));
                    compact["inputSchema"]["required"] = canonical["inputSchema"]["required"].clone();
                    compact["inputSchema"]["properties"]["ttl"] = canonical["inputSchema"]["properties"]["ttl"].clone();
                    compact["description"] = canonical["description"].clone();
                }
                _ => {}
            }
            assert_eq!(&compact, canonical, "{name} has a second definition");
        }
        for name in ["zone_catalog_put", "cloud_drain", "cloud_drain_status"] {
            assert!(full.iter().any(|tool| tool["name"] == name));
            assert!(
                !tools(Surface::Compact)
                    .iter()
                    .any(|tool| tool["name"] == name)
            );
        }
        let check = full.iter().find(|tool| tool["name"] == "check").unwrap();
        let zone_check = full
            .iter()
            .find(|tool| tool["name"] == "zone_check")
            .unwrap();
        assert_eq!(check["inputSchema"], zone_check["inputSchema"]);
        assert_eq!(check["description"], zone_check["description"]);
    }

    #[test]
    fn all_task_ingresses_share_legacy_conversion_and_counter() {
        let metric = "lockyard_compat_conversions_total{kind=legacy_task_id,source=http,protocol=1}";
        let before = lockyard_compat::counters()
            .get(metric)
            .copied()
            .unwrap_or(0);
        for raw in [json!("FE-0012"), json!("D-12")] {
            lockyard_compat::LegacyCompatibilityV1::task_id(
                &raw,
                lockyard_compat::TaskDomain::Registry,
                lockyard_compat::Source::Http,
                1,
            )
            .unwrap();
        }
        assert_eq!(
            lockyard_compat::counters()
                .get(metric)
                .copied()
                .unwrap_or(0),
            before
        );
        assert_eq!(
            lockyard_compat::LegacyCompatibilityV1::task_id(
                &json!(12),
                lockyard_compat::TaskDomain::Registry,
                lockyard_compat::Source::Http,
                1
            )
            .unwrap(),
            "D-12"
        );
        assert_eq!(lockyard_compat::counters()[metric], before + 1);
        assert!(
            lockyard_compat::LegacyCompatibilityV1::task_id(
                &json!(0),
                lockyard_compat::TaskDomain::Registry,
                lockyard_compat::Source::Http,
                1
            )
            .is_err()
        );
        assert_eq!(lockyard_compat::counters()[metric], before + 1);

        for (input, expected) in [
            (json!(12), "D-12"),
            (json!("12"), "D-12"),
            (json!("FE-0012"), "FE-0012"),
        ] {
            let args = json!({"id": input});
            assert_eq!(Args(&args).task_key("id").unwrap(), expected);
            assert_eq!(Args(&args).task_key("id").unwrap(), expected);
            assert_eq!(Args(&args).task_key_for(false).unwrap(), expected);
            assert_eq!(
                crate::task_key(input.as_str().unwrap_or("12")).unwrap(),
                expected
            );
        }
        for input in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!("1e2"),
            json!(" 12"),
            json!("D-0"),
            json!("9007199254740992"),
            json!("FE-9007199254740992"),
        ] {
            let args = json!({"id": input});
            assert!(Args(&args).task_key("id").is_err(), "{input}");
            assert!(Args(&args).task_key("id").is_err(), "{input}");
        }
    }

    #[test]
    fn handoff_tool_exposes_and_preserves_context_and_commit_references() {
        let definitions = tools(Surface::Full);
        let tool = definitions
            .iter()
            .find(|tool| tool["name"] == "work_handoff")
            .unwrap();
        assert!(tool["inputSchema"]["properties"].get("report").is_some());
        assert!(tool["inputSchema"]["properties"].get("commits").is_some());
        let arguments = json!({"id":12,"to":"next","if_version":3,"report":"Checks passed; verify staging next","commits":["abc123","def456"]});
        let step = Args(&arguments).step().unwrap();
        assert_eq!(step.to.as_deref(), Some("next"));
        assert_eq!(
            step.report.as_deref(),
            Some("Checks passed; verify staging next")
        );
        assert_eq!(step.commits, ["abc123", "def456"]);
        assert_eq!(step.version, Some(3));
    }

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        dir
    }

    fn call(dir: &tempfile::TempDir, agent: &str, name: &str, arguments: Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        });
        handle(&request, Some(agent), dir.path(), Surface::Full).unwrap()["result"].clone()
    }

    fn listed(surface: Surface, dir: &tempfile::TempDir) -> Vec<String> {
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        handle(&request, None, dir.path(), surface).unwrap()["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect()
    }

    fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap()
    }

    #[test]
    fn full_task_list_accepts_ready_and_exposes_area_selectors() {
        let dir = project();
        call(&dir, "lead", "task_add", json!({"title": "ready task"}));
        call(&dir, "lead", "task_add", json!({"title": "taken task"}));
        call(&dir, "worker", "task_claim", json!({"id": "D-2"}));
        let listed = call(
            &dir,
            "worker",
            "task_list",
            json!({"status": "ready", "area": "PA"}),
        );
        assert_ne!(listed["isError"], true, "{}", text(&listed));
        let tasks: Value = serde_json::from_str(text(&listed)).unwrap();
        assert_eq!(tasks.as_array().unwrap().len(), 1);
        assert_eq!(tasks[0]["title"], "ready task");
        let schema = tools(Surface::Full)
            .into_iter()
            .find(|tool| tool["name"] == "task_list")
            .unwrap();
        assert_eq!(
            schema["inputSchema"]["properties"]["area"]["type"],
            "string"
        );
        assert_eq!(
            schema["inputSchema"]["properties"]["prefix"]["type"],
            "string"
        );
        let claimed = call(&dir, "worker", "task_list", json!({"status": "claimed"}));
        let tasks: Value = serde_json::from_str(text(&claimed)).unwrap();
        assert_eq!(tasks[0]["title"], "taken task");
    }

    #[test]
    fn finish_work_ids_exclude_incoming_handover_offers() {
        let claim = |id, session| {
            serde_json::from_value(json!({"id": id, "session": session, "paths": ["src"]})).unwrap()
        };
        assert_eq!(
            owned_claim_ids(
                Some("receiver"),
                vec![claim(10, "sender"), claim(11, "receiver")]
            ),
            vec![11]
        );
        assert!(owned_claim_ids(Some("receiver"), vec![claim(10, "sender")]).is_empty());
    }

    #[test]
    fn target_resolution_uses_wire_alias_and_rejects_ambiguous_prefixes() {
        let person = |session, alias| {
            serde_json::from_value(json!({"session": session, "client": "codex", "alias": alias}))
                .unwrap()
        };
        let presence = vec![
            person("session-one", "codex-real-bus-name"),
            person("session-two", "codex-reviewer"),
        ];
        assert_eq!(
            resolve_presence_target(&presence, "codex-real-bus-name").unwrap(),
            "session-one"
        );
        assert_eq!(
            resolve_presence_target(&presence, "CODEX-REAL").unwrap(),
            "session-one"
        );
        assert_eq!(
            resolve_presence_target(&presence, "session-one").unwrap(),
            "session-one"
        );
        let ambiguous = resolve_presence_target(&presence, "codex")
            .unwrap_err()
            .to_string();
        assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
        assert!(
            ambiguous.contains("session-one") && ambiguous.contains("session-two"),
            "{ambiguous}"
        );
    }

    #[test]
    fn cloud_status_work_is_only_active_and_relevant_to_the_agent() {
        let make = |id, status: &str, to: &str| {
            serde_json::from_value(json!({
                "id": format!("BT-{id}"), "title": "work", "to": to, "accept": "", "status": status,
                "version": 1
            }))
            .unwrap()
        };
        let visible = visible_work(
            Some("me"),
            vec![
                make(1, "offered", "me"),
                make(2, "accepted", "me"),
                make(3, "claimed", "someone-else"),
                make(4, "claimed", "*"),
            ],
        );
        assert_eq!(
            visible.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
            vec!["BT-1"]
        );
    }

    #[test]
    fn first_cloud_call_registers_an_agent_but_local_and_present_agents_are_untouched() {
        assert!(needs_presence(Some("new-agent"), true, false));
        assert!(!needs_presence(Some("known-agent"), true, true));
        assert!(!needs_presence(Some("local-agent"), false, false));
        assert!(!needs_presence(None, true, false));
    }

    #[test]
    fn handover_reports_a_missing_claim_before_target_resolution() {
        assert!(
            validate_handover_claim(999_999, &[])
                .unwrap_err()
                .to_string()
                .contains("claim Z-999999")
        );
    }

    #[test]
    fn target_resolution_accepts_bus_names_and_session_prefixes() {
        let dir = project();
        call(
            &dir,
            "43ed9726-ba41-session",
            "presence_beat",
            json!({"client":"codex-d3176-slot-handover"}),
        );
        assert_eq!(
            resolve_target(dir.path(), Some("sender"), "codex-d3176-slot-handover").unwrap(),
            "43ed9726-ba41-session"
        );
        assert_eq!(
            resolve_target(dir.path(), Some("sender"), "43ed9726").unwrap(),
            "43ed9726-ba41-session"
        );
    }

    #[test]
    fn tasks_without_action_explain_the_allowed_actions() {
        let dir = project();
        let result = call(&dir, "agent", "tasks", json!({}));
        assert_eq!(result["isError"], true);
        assert!(text(&result).contains("list, show, claim, submit"));
    }

    #[test]
    fn handles_initialize_tools_and_bad_method() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        let init = handle(&init, None, path, Surface::Full).unwrap();
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSION);
        let bad = json!({"jsonrpc": "2.0", "id": 3, "method": "absent"});
        assert_eq!(
            handle(&bad, None, path, Surface::Full).unwrap()["error"]["code"],
            -32601
        );
        let wrong = json!({"id": 4, "method": "ping"});
        assert_eq!(
            handle(&wrong, None, path, Surface::Full).unwrap()["error"]["code"],
            -32600
        );
    }

    #[test]
    fn full_cloud_task_tools_keep_numeric_ids_and_native_paths() {
        use lockyard_cloud_client::{Call, ClientError, CloudBackend, Transport};
        use lockyard_core::Backend;
        use std::sync::{Arc, Mutex};

        struct Recording(Arc<Mutex<Vec<Call>>>);
        impl Transport for Recording {
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                self.0.lock().unwrap().push(call.clone());
                if call.path.ends_with("/history") {
                    Ok(json!([]))
                } else {
                    let id = call
                        .path
                        .trim_start_matches("/api/v1/registry/items/")
                        .split('/')
                        .next()
                        .unwrap();
                    Ok(
                        json!({"id":id,"title":"task","status":if call.method == "POST" {"active"} else {"ready"},"version":4}),
                    )
                }
            }
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut backend = CloudBackend::new(Recording(calls.clone()), "worker");
        for (argument, expected_id) in [
            (json!(12), "D-12"),
            (json!("FE-0319"), "FE-0319"),
            (json!("G-SG-0012"), "G-SG-0012"),
        ] {
            let arguments = json!({"id":argument});
            let id = Args(&arguments).task_key_for(backend.is_cloud()).unwrap();
            assert_eq!(id, expected_id);
            assert_eq!(backend.task(&id).unwrap().id, expected_id);
            assert!(backend.task_history(&id).unwrap().is_empty());
            assert_eq!(
                backend.claim_task("worker", &id, 30, 1).unwrap().id,
                expected_id
            );
            let recorded = calls.lock().unwrap();
            let tail = &recorded[recorded.len() - 4..];
            let route = format!("/api/v1/registry/items/{expected_id}");
            assert_eq!(
                tail.iter()
                    .map(|call| (call.method.as_str(), call.path.as_str()))
                    .collect::<Vec<_>>(),
                [
                    ("GET", route.as_str()),
                    ("GET", format!("{route}/history").as_str()),
                    ("GET", route.as_str()),
                    ("POST", format!("{route}/claim").as_str()),
                ]
            );
            assert_eq!(tail[3].body.as_ref().unwrap()["expected_version"], 4);
            assert_eq!(tail[3].body.as_ref().unwrap()["session"], "worker");
        }
        let integer = json!({"id":12});
        assert_eq!(Args(&integer).task_key_for(false).unwrap(), "D-12");
        assert_eq!(Args(&integer).task_key("id").unwrap(), "D-12");
        for value in [json!(0), json!(-1), json!(1.5)] {
            assert!(Args(&json!({"id":value})).task_key_for(true).is_err());
        }
        for tool in tools(Surface::Full).into_iter().filter(|tool| {
            [
                "task_show",
                "task_plan",
                "task_claim",
                "task_renew",
                "task_release",
                "task_submit",
                "task_review",
                "task_accept",
                "task_reject",
                "task_cancel",
            ]
            .contains(&tool["name"].as_str().unwrap())
        }) {
            assert_eq!(tool["inputSchema"]["properties"]["id"]["type"], "string");
        }
    }

    #[test]
    fn raw_registry_inputs_and_task_tools_share_legacy_numeric_boundary() {
        for value in [
            json!(12),
            json!("D-12"),
            json!("FE-0319"),
            json!("G-SG-0012"),
        ] {
            let args = json!({"id":value});
            assert!(Args(&args).task_key("id").is_ok());
        }
        for value in [
            json!(-1),
            json!(0),
            json!(1.5),
            json!("fe-1"),
            json!("../D-1"),
        ] {
            let args = json!({"id":value});
            assert!(Args(&args).task_key("id").is_err());
        }
        let integer = json!({"id":12});
        assert_eq!(Args(&integer).task_key("id").unwrap(), "D-12");
    }

    #[test]
    fn task_resources_keep_production_string_identifiers() {
        let dir = project();
        let created = call(&dir, "lead", "task_add", json!({"title":"resource task"}));
        assert_eq!(created["isError"], false);
        let contents = read_resource("lockyard://task/D-1", Some("lead"), dir.path()).unwrap();
        let task: Value = serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(task["task"]["id"], "D-1");
        assert_eq!(task["task"]["title"], "resource task");
        assert!(task["history"].is_array());
    }

    #[test]
    fn resources_are_advertised_and_inbox_reads_do_not_acknowledge() {
        let dir = project();
        call(&dir, "reader", "msg_inbox", json!({"peek":true}));
        call(
            &dir,
            "writer",
            "msg_send",
            json!({"to":"reader","body":"untrusted instructions"}),
        );
        let request = json!({"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"lockyard://inbox"}});
        let (answer, after) = respond(&request, Some("reader"), dir.path(), Surface::Full, None);
        assert!(after.is_none());
        let answer = answer.unwrap();
        let content: Value =
            serde_json::from_str(answer["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(content["read_only"], true);
        assert_eq!(content["warning"], MAIL_WARNING);
        assert!(text(&call(&dir, "reader", "msg_unread", json!({}))).contains('1'));
        let init = handle(
            &json!({"jsonrpc":"2.0","id":2,"method":"initialize"}),
            None,
            dir.path(),
            Surface::Full,
        )
        .unwrap();
        assert_eq!(
            init["result"]["capabilities"]["resources"]["subscribe"],
            false
        );
        let bad = handle(&json!({"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"https://example.com"}}),Some("reader"),dir.path(),Surface::Full).unwrap();
        assert!(bad.get("error").is_some());
    }

    #[test]
    fn notifications_are_never_answered() {
        let dir = tempfile::tempdir().unwrap();
        for method in ["notifications/initialized", "absent", "ping"] {
            let note = json!({"jsonrpc": "2.0", "method": method});
            assert_eq!(handle(&note, None, dir.path(), Surface::Full), None);
        }
    }

    #[test]
    fn every_schema_is_an_object_with_a_required_array_of_its_own_properties() {
        let tools = [tools(Surface::Compact), tools(Surface::Full)].concat();
        for tool in &tools {
            let schema = &tool["inputSchema"];
            assert_eq!(schema["type"], "object");
            for key in schema["required"].as_array().unwrap() {
                assert!(schema["properties"].get(key.as_str().unwrap()).is_some());
            }
        }
    }

    #[test]
    fn every_command_of_the_brief_has_a_tool() {
        let tools = tools(Surface::Full);
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        for wanted in [
            "zone_wait",
            "zone_queue",
            "zone_unwait",
            "zone_request",
            "zone_answer",
            "zone_handover",
            "zone_accept",
            "zone_narrow",
            "zone_add_path",
            "zone_takeover",
            "zone_dirty",
            "msg_ack",
            "msg_thread",
            "board_set",
            "events",
            "presence",
            "work_offer",
            "work_claim",
            "work_beat",
            "work_done",
            "work_accept",
            "work_reject",
            "work_fail",
            "work_cancel",
            "work_handoff",
            "work_take",
            "work_decline",
        ] {
            assert!(names.contains(&wanted), "{wanted}");
        }
    }

    #[test]
    fn every_listed_tool_is_implemented() {
        let dir = project();
        for tool in [tools(Surface::Compact), tools(Surface::Full)].concat() {
            let name = tool["name"].as_str().unwrap();
            let result = call(&dir, "a", name, json!({}));
            assert!(!text(&result).contains("unknown tool"), "{name}");
        }
    }

    #[test]
    fn a_cloud_only_tool_says_so_in_local_mode() {
        let dir = project();
        let refused = call(&dir, "a", "work_list", json!({}));
        assert_eq!(refused["isError"], true);
        assert!(text(&refused).contains("needs cloud mode"));
    }

    #[test]
    fn the_board_and_presence_work_locally() {
        let dir = project();
        call(&dir, "a", "board_set", json!({"key": "k", "value": "v"}));
        assert!(text(&call(&dir, "a", "board_get", json!({"key": "k"}))).contains("\"v\""));
        call(&dir, "a", "presence_beat", json!({}));
        assert!(text(&call(&dir, "a", "presence", json!({}))).contains("mcp"));
    }

    #[test]
    fn board_write_tool_descriptions_name_the_required_cloud_roles() {
        for name in ["board_set", "board_remove"] {
            let tool = tools(Surface::Full)
                .into_iter()
                .find(|tool| tool["name"] == name)
                .unwrap();
            assert!(
                tool["description"]
                    .as_str()
                    .unwrap()
                    .contains("lead or owner")
            );
        }
    }

    #[test]
    fn a_failure_is_an_error_result_and_names_the_holder() {
        let dir = project();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "task_add", "arguments": {"title": "x"}}
        });
        let nameless = handle(&request, None, dir.path(), Surface::Full).unwrap();
        assert_eq!(nameless["result"]["isError"], true);

        call(
            &dir,
            "a",
            "zone_claim",
            json!({"paths": ["src"], "note": "busy"}),
        );
        let refused = call(&dir, "b", "zone_claim", json!({"paths": ["src/x"]}));
        assert_eq!(refused["isError"], true);
        assert!(text(&refused).contains("held by a"));
        assert!(text(&refused).contains("busy"));
    }

    #[test]
    fn a_bad_id_does_not_become_all_claims() {
        let dir = project();
        call(&dir, "a", "zone_claim", json!({"paths": ["src"]}));
        let refused = call(&dir, "a", "zone_release", json!({"id": "Z-1"}));
        assert_eq!(refused["isError"], true);
        let renew = call(&dir, "a", "zone_renew", json!({"id": "Z-1"}));
        assert_eq!(renew["isError"], true);
        assert!(text(&call(&dir, "a", "zone_list", json!({}))).contains("src"));
        let released = call(&dir, "a", "zone_release", json!({"id": 1}));
        assert!(text(&released).contains("\"released\":1"));
    }

    #[test]
    fn mail_always_carries_the_warning_once_and_has_no_unlabelled_copy() {
        let dir = project();
        call(&dir, "b", "msg_inbox", json!({}));
        call(&dir, "a", "msg_send", json!({"to": "b", "body": "hello"}));
        let mail = call(&dir, "b", "msg_inbox", json!({"peek": true}));
        assert!(text(&mail).starts_with(MAIL_WARNING));
        assert_eq!(text(&mail).matches(MAIL_WARNING).count(), 1);
        assert!(text(&mail).contains("hello"));
        assert!(mail.get("structuredContent").is_none());
    }

    #[test]
    fn mail_read_over_mcp_is_marked_only_by_the_follow_up() {
        let dir = project();
        call(&dir, "b", "msg_inbox", json!({}));
        call(&dir, "a", "msg_send", json!({"to": "b", "body": "hello"}));
        let request = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "msg_inbox", "arguments": {}}
        });
        let (_, after) = respond(&request, Some("b"), dir.path(), Surface::Full, None);
        let unread =
            |dir: &tempfile::TempDir| text(&call(dir, "b", "msg_unread", json!({}))).to_string();
        assert!(unread(&dir).contains('1'), "the answer has not left yet");
        after.unwrap()().unwrap();
        assert!(unread(&dir).contains('0'));
    }
