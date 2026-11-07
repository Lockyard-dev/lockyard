// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

    /// A fake backend that logs what happens, in order.
    struct Recording {
        log: Rc<RefCell<Vec<String>>>,
        unread: Option<i64>,
        mail: Option<Vec<Message>>,
        verdict: Option<Verdict>,
    }

    impl Port for Recording {
        fn root(&self) -> &Path {
            Path::new("/")
        }
        fn check(&mut self, _: &str, path: &str, _: i64) -> Result<Verdict> {
            self.log.borrow_mut().push(format!("check {path}"));
            self.verdict
                .take()
                .ok_or_else(|| Error::Unavailable("gone".into()))
        }
        fn unread(&mut self, _: &str) -> Result<Option<i64>> {
            Ok(self.unread)
        }
        fn take_mail(&mut self, _: &str, _: usize, _: i64) -> Result<Option<Vec<Message>>> {
            self.log.borrow_mut().push("claim".into());
            Ok(self.mail.take())
        }
        fn mark_seen(&mut self, _: &str, ids: &[i64], _: i64) -> Result<()> {
            self.log.borrow_mut().push(format!("seen {ids:?}"));
            Ok(())
        }
        fn report(&mut self, _: &str, moment: Moment, _: Vec<String>) {
            self.log.borrow_mut().push(format!("{moment:?}"));
        }
    }

    /// Records the moment output reaches it.
    struct LoggedOutput(Rc<RefCell<Vec<String>>>);

    impl Write for LoggedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().push("print".into());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.borrow_mut().push("flush".into());
            Ok(())
        }
    }

    fn letter() -> Message {
        serde_json::from_value(json!({"id": 4, "from_session": "bob", "to": "me", "body": "hi"}))
            .unwrap()
    }

    fn recording(
        unread: Option<i64>,
        mail: Option<Vec<Message>>,
    ) -> (Recording, Rc<RefCell<Vec<String>>>) {
        let log = Rc::new(RefCell::new(Vec::new()));
        (
            Recording {
                log: Rc::clone(&log),
                unread,
                mail,
                verdict: None,
            },
            log,
        )
    }

    #[test]
    fn delivery_goes_claim_then_print_then_seen() {
        let (mut port, log) = recording(Some(1), Some(vec![letter()]));
        let event = json!({"hook_event_name": "UserPromptSubmit"});
        let mut out = LoggedOutput(Rc::clone(&log));
        handle(
            Tool::Claude,
            &mut port,
            &event,
            "me",
            Path::new("/"),
            1,
            &lockyard_core::machine::MachineConfig::default(),
            &mut out,
        )
        .unwrap();
        let steps = log.borrow().clone();
        let at = |step: &str| steps.iter().position(|item| item == step).unwrap();
        assert!(at("claim") < at("print"), "{steps:?}");
        assert!(at("flush") < at("seen [4]"), "{steps:?}");
    }

    #[test]
    fn mail_the_channel_did_not_win_is_neither_shown_nor_marked() {
        let (mut port, log) = recording(Some(1), Some(Vec::new()));
        let event = json!({"hook_event_name": "UserPromptSubmit"});
        let mut out = Vec::new();
        handle(
            Tool::Claude,
            &mut port,
            &event,
            "me",
            Path::new("/"),
            1,
            &lockyard_core::machine::MachineConfig::default(),
            &mut out,
        )
        .unwrap();
        assert!(out.is_empty());
        assert!(!log.borrow().iter().any(|step| step.starts_with("seen")));
    }

    #[test]
    fn an_unknown_count_or_failed_reservation_delivers_nothing_and_marks_nothing() {
        for (unread, mail) in [(None, None), (Some(2), None)] {
            let (mut port, log) = recording(unread, mail);
            let mut out = Vec::new();
            deliver_mail(&mut port, "PostToolUse", "me", 1, &mut out).unwrap();
            assert!(out.is_empty());
            assert!(!log.borrow().iter().any(|step| step.starts_with("seen")));
        }
    }

    #[test]
    fn an_unknown_zone_state_is_refused() {
        let (mut port, log) = recording(None, None);
        port.verdict = Some(Verdict::Unknown);
        let event = json!({"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {"file_path": "/src/a.rs"}});
        let mut out = Vec::new();
        handle(
            Tool::Claude,
            &mut port,
            &event,
            "me",
            Path::new("/"),
            1,
            &lockyard_core::machine::MachineConfig::default(),
            &mut out,
        )
        .unwrap();
        let answer: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            answer["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("not fresh enough")
        );
        assert_eq!(*log.borrow(), ["check src/a.rs"]);
    }

    #[test]
    fn failed_hook_zone_checks_deny_without_reporting_a_running_tool() {
        for tool in [Tool::Claude, Tool::Codex, Tool::Cursor] {
            let (mut port, log) = recording(None, None);
            let event = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Edit",
                "tool_input": {"file_path": "/src/a.rs"},
            });
            let mut out = Vec::new();
            handle(
                tool,
                &mut port,
                &event,
                "me",
                Path::new("/"),
                1,
                &lockyard_core::machine::MachineConfig::default(),
                &mut out,
            )
            .unwrap();
            let answer: Value = serde_json::from_slice(&out).unwrap();
            let decision = if tool == Tool::Cursor {
                &answer["permission"]
            } else {
                &answer["hookSpecificOutput"]["permissionDecision"]
            };
            assert_eq!(decision, "deny");
            assert_eq!(*log.borrow(), ["check src/a.rs"]);
        }
    }

    #[test]
    fn a_free_path_is_announced_so_outside_writes_can_be_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut store = Store::open(&root).unwrap();
        Backend::touch_agent(&mut store, "me", 0).unwrap();
        let mut port = LocalPort {
            store,
            root: root.clone(),
            now: 1_000,
        };
        let event = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": root.join("src/a.rs")}
        });
        let mut out = Vec::new();
        handle(
            Tool::Claude,
            &mut port,
            &event,
            "me",
            &root,
            1_000,
            &lockyard_core::machine::MachineConfig::default(),
            &mut out,
        )
        .unwrap();
        assert!(out.is_empty(), "free path must allow: {out:?}");
        let seen = lockyard_core::outside::announcements(&root, 0).unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "src/a.rs");
        assert_eq!(seen[0].agent, "me");
    }

    #[test]
    fn denied_pre_tool_use_does_not_report_a_running_tool() {
        let (mut port, log) = recording(None, None);
        port.verdict = Some(Verdict::Held(Box::new(
            serde_json::from_value(json!({"path":"src/a.rs","agent":"holder","claim":1})).unwrap(),
        )));
        let event = json!({"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/src/a.rs"}});
        let mut out = Vec::new();
        handle(
            Tool::Claude,
            &mut port,
            &event,
            "me",
            Path::new("/"),
            1,
            &lockyard_core::machine::MachineConfig::default(),
            &mut out,
        )
        .unwrap();
        assert_eq!(*log.borrow(), ["check src/a.rs"]);
        let answer: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn writes_are_reported_after_the_tool_ran() {
        let (mut port, log) = recording(Some(0), None);
        let event = json!({"hook_event_name": "SessionEnd"});
        handle(
            Tool::Claude,
            &mut port,
            &event,
            "me",
            Path::new("/"),
            1,
            &lockyard_core::machine::MachineConfig::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(*log.borrow(), ["End"]);
    }

    #[test]
    fn shortening_never_splits_a_character() {
        let long = "é".repeat(MAIL_BODY_CHARS + 1);
        let short = shorten(&long);
        assert_eq!(short.matches('é').count(), MAIL_BODY_CHARS);
        assert_eq!(shorten("short"), "short");
    }

    #[test]
    fn outside_a_project_or_on_bad_input_the_hook_is_silent() {
        let dir = tempfile::tempdir().unwrap();
        let input =
            json!({ "hook_event_name": "PostToolUse", "session_id": "me", "cwd": dir.path() });
        assert_eq!(
            claude(&input.to_string(), None, Path::new("/"), 1).unwrap(),
            None
        );
        assert_eq!(claude("not json", None, dir.path(), 1).unwrap(), None);
    }

    #[test]
    fn the_override_wins_over_the_session_id() {
        let (_dir, mut store) = project();
        let held = zone(&store, "src");
        store.claim("named", &[held], "", 10, 0).unwrap();
        let input = json!({
            "hook_event_name": "PreToolUse",
            "session_id": "session",
            "cwd": store.root(),
            "tool_name": "Edit",
            "tool_input": { "file_path": "src/a.rs" },
        });
        let answer = claude(
            &input.to_string(),
            Some("named".to_string()),
            Path::new("/"),
            1,
        );
        assert_eq!(answer.unwrap(), None);
    }

    #[test]
    fn a_damaged_database_is_an_error_for_the_caller_to_report() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(lockyard_core::DIR_NAME);
        fs::create_dir(&state).unwrap();
        fs::write(state.join("lockyard.db"), "this is not a database at all").unwrap();
        let input =
            json!({ "hook_event_name": "PostToolUse", "session_id": "me", "cwd": dir.path() });
        let answer = claude(&input.to_string(), None, Path::new("/"), 1);
        assert!(matches!(answer, Err(Error::Db(_))));
    }

    #[test]
    fn an_edit_is_denied_when_project_config_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        fs::write(dir.path().join(".lockyard/config.toml"), "mode = [broken").unwrap();
        let event = json!({
            "hook_event_name": "PreToolUse",
            "session_id": "me",
            "cwd": dir.path(),
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/a.rs"}
        });
        let mut out = Vec::new();
        run(
            Tool::Claude,
            &event.to_string(),
            None,
            Path::new("/"),
            1,
            &mut out,
        )
        .unwrap();
        let answer: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            answer["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("configuration is unavailable")
        );
    }

    #[test]
    fn an_edit_without_a_session_identity_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        let event = json!({
            "hook_event_name": "PreToolUse",
            "cwd": dir.path(),
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/a.rs"}
        });
        let mut out = Vec::new();

        run(
            Tool::Claude,
            &event.to_string(),
            None,
            Path::new("/"),
            1,
            &mut out,
        )
        .unwrap();

        let answer: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            answer["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("session identity")
        );
    }

    #[test]
    fn an_edit_without_a_project_root_is_denied() {
        let event = json!({
            "hook_event_name": "PreToolUse",
            "cwd": "/tmp",
            "session_id": "me",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/a.rs"}
        });
        let mut out = Vec::new();

        run(
            Tool::Claude,
            &event.to_string(),
            None,
            Path::new("/"),
            1,
            &mut out,
        )
        .unwrap();

        let answer: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            answer["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap()
                .contains("no project root")
        );
    }

    #[test]
    fn codex_uses_the_shared_tool_decision() {
        let (dir, mut store) = project();
        store
            .claim("holder", &[zone(&store, "src")], "busy", 30, 0)
            .unwrap();
        let event = json!({"hook_event_name":"PreToolUse","session_id":"worker","cwd":dir.path(),"tool_name":"Write","tool_input":{"file_path":dir.path().join("src/a.rs")}}).to_string();
        let mut out = Vec::new();
        run(Tool::Codex, &event, None, Path::new("/"), 1, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("\"permissionDecision\":\"deny\"")
        );
    }

    #[test]
    fn cursor_fields_are_normalized_before_the_shared_decision() {
        let (dir, mut store) = project();
        store
            .claim("holder", &[zone(&store, "src")], "busy", 30, 0)
            .unwrap();
        let event = json!({"hook_event_name":"preToolUse","conversation_id":"worker","workspace_roots":[dir.path()],"tool_name":"edit_file","file_path":dir.path().join("src/a.rs")}).to_string();
        let mut out = Vec::new();
        run(Tool::Cursor, &event, None, Path::new("/"), 1, &mut out).unwrap();
        let answer: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(answer["permission"], "deny");
        assert!(
            answer["agent_message"]
                .as_str()
                .unwrap()
                .contains("held by holder")
        );
    }
