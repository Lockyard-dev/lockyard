// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use clap::CommandFactory;

#[test]
fn the_command_line_definition_is_consistent() {
    Cli::command().debug_assert();
}

#[cfg(unix)]
#[test]
fn deferred_nested_commands_keep_global_flags_defaults_and_required_arguments() {
    let cli = Cli::try_parse_from([
        "lockyard", "node", "workflow", "list", "--offset", "3", "--agent", "worker", "--json",
    ])
    .unwrap();
    assert_eq!(cli.agent.as_deref(), Some("worker"));
    assert!(cli.json);
    let Command::Node(node_cli::NodeCommand::Workflow {
        command:
            node_cli::DistributedWorkflowCommand::List {
                offset,
                limit,
                config,
            },
    }) = cli.command
    else {
        panic!("expected distributed workflow list")
    };
    assert_eq!(offset, 3);
    assert_eq!(limit, 100);
    assert!(config.is_none());
    for args in [
        vec!["lockyard", "node", "workflow", "submit"],
        vec!["lockyard", "job", "manifest", "worker", "job-id"],
        vec!["lockyard", "hook", "unknown-client"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn setup_accepts_both_production_and_managed_client_forms() {
    let prod =
        Cli::try_parse_from(["lockyard", "setup", "--client", "gemini", "--dry-run"]).unwrap();
    let Command::Setup(args) = prod.command else {
        panic!("expected setup")
    };
    assert_eq!(args.clients, ["gemini"]);
    assert!(args.dry_run);
    assert!(args.client.is_none());
    let managed = Cli::try_parse_from(["lockyard", "setup", "codex", "--apply"]).unwrap();
    let Command::Setup(args) = managed.command else {
        panic!("expected setup")
    };
    assert!(matches!(args.client, Some(SetupClient::Codex)));
    assert!(args.apply);
    assert!(args.clients.is_empty());
    for args in [
        vec!["lockyard", "setup", "--apply"],
        vec!["lockyard", "setup", "codex", "--client", "claude"],
        vec!["lockyard", "setup", "codex", "--apply", "--dry-run"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn production_doctor_checks_keep_both_json_field_conventions() {
    let result =
        doctor_output(vec![setup::Finding::failed("project", "run lockyard init")]).unwrap();
    assert_eq!(result.json["checks"][0]["check"], "project");
    assert_eq!(result.json["checks"][0]["name"], "project");
    assert_eq!(result.json["checks"][0]["state"], "failed");
    assert_eq!(result.exit, EXIT_FAILURE);
}

#[test]
fn zone_answer_help_states_the_eta_format() {
    let mut command = Cli::command();
    command.build();
    let help = command
        .find_subcommand_mut("zone")
        .unwrap()
        .find_subcommand_mut("answer")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(help.contains("ISO 8601"));
}

#[test]
fn work_handoff_accepts_context_and_commit_references() {
    let cli = Cli::try_parse_from([
        "lockyard",
        "work",
        "handoff",
        "BT-12",
        "--to",
        "next",
        "--if-version",
        "3",
        "--report",
        "Tests passed; next verify staging",
        "--commit",
        "abc123",
        "--commit",
        "def456",
    ])
    .unwrap();
    let Command::Work(WorkCommand::Handoff {
        task,
        to,
        report,
        commits,
    }) = cli.command
    else {
        panic!("expected work handoff")
    };
    assert_eq!(task.id, "BT-12");
    assert_eq!(task.if_version, Some(3));
    assert_eq!(to, "next");
    assert_eq!(report.as_deref(), Some("Tests passed; next verify staging"));
    assert_eq!(commits, ["abc123", "def456"]);
}

#[test]
fn ids_read_with_or_without_a_prefix() {
    assert_eq!(parse_id("12"), Ok(12));
    assert_eq!(parse_id("T-12"), Ok(12));
    assert_eq!(parse_id("z-3"), Ok(3));
    assert_eq!(parse_id("W-3"), Ok(3));
    assert!(parse_id("T12").is_err());
    assert!(parse_id("nope").is_err());
}

#[test]
fn raw_registry_commands_accept_native_and_legacy_task_identifiers() {
    for id in ["12", "D-12", "FE-0319", "G-SG-0012"] {
        for verb in ["links", "why-blocked"] {
            assert!(Cli::try_parse_from(["lockyard", "task", verb, id]).is_ok());
        }
        let cli = Cli::try_parse_from([
            "lockyard",
            "task",
            "link",
            id,
            "PA-0007",
            "--if-version",
            "1",
        ])
        .unwrap();
        let Command::Task(TaskCommand::Link { id: parsed, to, .. }) = cli.command else {
            panic!("expected task link")
        };
        assert_eq!(parsed, if id == "12" { "D-12" } else { id });
        assert_eq!(to, "PA-0007");
    }
}

#[test]
fn registry_task_ids_keep_area_prefixes() {
    for id in ["FE-0001", "G-SG-0012", "D-3176"] {
        assert_eq!(task_key(id).unwrap(), id);
    }
    for id in ["fe-1", "FE-", "-1"] {
        assert!(task_key(id).is_err(), "{id}");
    }
}

#[test]
fn a_task_lookup_error_names_the_requested_identifier() {
    let dir = tempfile::tempdir().unwrap();
    lockyard_core::Store::init(dir.path()).unwrap();
    let error = run(
        Cli::try_parse_from(["lockyard", "task", "show", "ZZ-9999"]).unwrap(),
        dir.path(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("ZZ-9999"));
}

#[test]
fn cli_task_add_accepts_repeated_paths_and_an_optional_area_override() {
    for extra in [vec![], vec!["--area", "MiXeD-area-key"]] {
        let mut args = vec![
            "lockyard",
            "task",
            "add",
            "fix files",
            "--path",
            "repo/src/a.rs",
            "--path",
            "repo/docs",
        ];
        args.extend(extra);
        let cli = Cli::try_parse_from(args).unwrap();
        let Command::Task(TaskCommand::Add { area, .. }) = cli.command else {
            panic!("expected task add")
        };
        assert!(area.is_none() || area.as_deref() == Some("MiXeD-area-key"));
    }
}

#[test]
fn cli_task_add_help_explains_workspace_paths_and_automatic_areas() {
    let mut command = Cli::command();
    command.build();
    let help = command
        .find_subcommand_mut("task")
        .unwrap()
        .find_subcommand_mut("add")
        .unwrap()
        .render_long_help()
        .to_string();
    for text in [
        "--path <PATH>",
        "workspace root",
        "Repeat for each path",
        "server determines its area",
        "Optional area override",
    ] {
        assert!(help.contains(text), "{text}: {help}");
    }
}

fn cli_task_with_paths(paths: &[&str]) -> Task {
    serde_json::from_value(json!({
        "id": "PA-0001", "title": "fix files", "body": "details", "status": "open",
        "author": "lead", "assignee": null, "lease_until": null, "evidence": null,
        "created_at": 0, "updated_at": 0, "paths": paths,
    }))
    .unwrap()
}

fn cli_task_command(args: &[&str]) -> TaskCommand {
    let mut argv = vec!["lockyard", "task"];
    argv.extend_from_slice(args);
    let Command::Task(command) = Cli::try_parse_from(argv).unwrap().command else {
        panic!("expected task command")
    };
    command
}

#[test]
fn cli_task_add_normalizes_workspace_paths_and_preserves_the_area_override() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let nested = root.join("unrelated/deep");
    std::fs::create_dir_all(&nested).unwrap();
    let absolute = root.join("repo/src/new.rs");
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::<TaskSpec>::new()));
    let opened = Opened {
        root,
        backend: Box::new(Scripted {
            cloud: true,
            task: Some(cli_task_with_paths(&[])),
            added_tasks: Some(captured.clone()),
            ..Default::default()
        }),
    };
    run_task(
        opened,
        cli_task_command(&[
            "add",
            "fix files",
            "--path",
            "repo//src/../lib.rs",
            "--path",
            "repo\\docs\\.\\guide.md",
            "--path",
            absolute.to_str().unwrap(),
            "--area",
            "MiXeD-area-key",
        ]),
        Some(&"lead".to_string()),
    )
    .unwrap();
    let captured = captured.borrow();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].area.as_deref(), Some("MiXeD-area-key"));
    // Compare the request itself: the local store deliberately has no task-path column.
    let request = format!("{:?}", captured[0]);
    assert!(
        request.contains("paths: [\"repo/docs/guide.md\", \"repo/lib.rs\", \"repo/src/new.rs\"]"),
        "{request}"
    );
}

#[test]
fn cli_task_add_rejects_relative_and_absolute_outside_paths_before_adding() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let absolute = outside.path().join("outside.rs");
    for path in ["../outside.rs", absolute.to_str().unwrap()] {
        let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::<TaskSpec>::new()));
        let opened = Opened {
            root: root.clone(),
            backend: Box::new(Scripted {
                cloud: true,
                task: Some(cli_task_with_paths(&[])),
                added_tasks: Some(captured.clone()),
                ..Default::default()
            }),
        };
        let error = run_task(
            opened,
            cli_task_command(&["add", "fix files", "--path", path]),
            Some(&"lead".to_string()),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("outside"), "{error}");
        assert!(captured.borrow().is_empty());
    }
}

#[cfg(unix)]
#[test]
fn cli_task_add_reuses_claim_path_checks_for_symlink_escapes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();
    let captured = std::rc::Rc::new(std::cell::RefCell::new(Vec::<TaskSpec>::new()));
    let opened = Opened {
        root,
        backend: Box::new(Scripted {
            cloud: true,
            task: Some(cli_task_with_paths(&[])),
            added_tasks: Some(captured.clone()),
            ..Default::default()
        }),
    };
    let error = run_task(
        opened,
        cli_task_command(&["add", "fix files", "--path", "escape/new.rs"]),
        Some(&"lead".to_string()),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("outside"), "{error}");
    assert!(captured.borrow().is_empty());
}

#[test]
fn cli_task_show_displays_server_paths_and_keeps_the_legacy_display_without_them() {
    for paths in [vec!["repo/src/a.rs", "repo/docs"], vec![]] {
        let opened = Opened {
            root: std::path::PathBuf::from("/unused"),
            backend: Box::new(Scripted {
                cloud: true,
                task: Some(cli_task_with_paths(&paths)),
                ..Default::default()
            }),
        };
        let result = run_task(opened, cli_task_command(&["show", "PA-0001"]), None).unwrap();
        if paths.is_empty() {
            assert_eq!(result.text, "PA-0001  open  -  fix files\ndetails");
            assert!(result.json["task"].get("paths").is_none());
        } else {
            assert!(result.text.contains("paths: repo/src/a.rs, repo/docs"));
            assert_eq!(result.json["task"]["paths"], json!(paths));
        }
    }
}

#[test]
fn minutes_round_up_and_stop_at_zero() {
    assert_eq!(minutes_left(60_001, 0), 2);
    assert_eq!(minutes_left(60_000, 0), 1);
    assert_eq!(minutes_left(0, 5), 0);
}

#[test]
fn a_cloud_lease_is_shown_and_never_counted_down() {
    let claim: Claim = serde_json::from_value(json!({
        "id": 1,
        "session": "a",
        "expires_at": 90_000,
        "foreign_dirty_paths": [{"path": "src/a.rs", "owner_session": "other"}]
    }))
    .unwrap();
    assert!(claim_line(&claim, Some(30_000)).contains("1 min left"));
    assert!(claim_line(&claim, None).contains("until 90000"));
    assert!(claim_line(&claim, None).contains("Foreign uncommitted work: \"src/a.rs\""));
    assert!(claim_line(&claim, None).contains("owner: \"other\""));
}

#[derive(Default)]
struct Scripted {
    cloud: bool,
    task: Option<Task>,
    added_tasks: Option<std::rc::Rc<std::cell::RefCell<Vec<TaskSpec>>>>,
    answers: Vec<Result<Claim>>,
    waits: Vec<Option<i64>>,
    claims: Vec<Claim>,
    releases: Vec<(Option<i64>, ReleaseRequest)>,
}

impl Backend for Scripted {
    fn is_cloud(&self) -> bool {
        self.cloud
    }
    fn touch_agent(&mut self, _: &str, _: i64) -> Result<()> {
        Ok(())
    }
    fn agents(&self) -> Result<Vec<lockyard_core::proto::AgentSeen>> {
        unreachable!()
    }
    fn claim(&mut self, _: &str, request: &ClaimRequest, _: i64) -> Result<Claim> {
        self.waits.push(request.queue_wait_seconds);
        self.answers.remove(0)
    }
    fn renew(&mut self, _: &str, _: Option<i64>, _: &RenewRequest, _: i64) -> Result<usize> {
        unreachable!()
    }
    fn release(
        &mut self,
        _: &str,
        id: Option<i64>,
        request: &ReleaseRequest,
        _: i64,
    ) -> Result<usize> {
        self.releases.push((id, request.clone()));
        Ok(id.map_or(self.claims.len(), |_| 1))
    }
    fn claims(&self, _: &ClaimQuery, _: i64) -> Result<Vec<Claim>> {
        Ok(self.claims.clone())
    }
    fn check(
        &self,
        _: &str,
        _: &[String],
        _: Option<i64>,
        _: i64,
    ) -> Result<Vec<lockyard_core::proto::PathCheck>> {
        unreachable!()
    }
    fn send(&mut self, _: &str, _: &SendRequest, _: i64) -> Result<Message> {
        unreachable!()
    }
    fn reply(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Message> {
        unreachable!()
    }
    fn inbox(&mut self, _: &str, _: InboxQuery, _: i64) -> Result<InboxPage> {
        unreachable!()
    }
    fn unread(&self, _: &str) -> Result<i64> {
        Ok(0)
    }
    fn inbox_seen(&mut self, _: &str, _: &[i64], _: i64) -> Result<usize> {
        unreachable!()
    }
    fn inbox_claim(&mut self, _: &str, _: &str, _: &[i64], _: i64, _: i64) -> Result<Vec<i64>> {
        unreachable!()
    }
    fn tasks(&self, _: Option<Status>, _: bool) -> Result<Vec<Task>> {
        Ok(Vec::new())
    }
    fn work_list(&self, _: &str) -> Result<Vec<WorkTask>> {
        Ok(Vec::new())
    }
    fn lost(&self, _: &str) -> Result<Vec<lockyard_core::proto::LostClaim>> {
        panic!("CLI status must not fetch lost claims")
    }
    fn task(&self, _: &str) -> Result<Task> {
        Ok(self.task.clone().expect("scripted task"))
    }
    fn task_history(&self, _: &str) -> Result<Vec<lockyard_core::tasks::TaskEvent>> {
        Ok(Vec::new())
    }
    fn add_task(&mut self, _: &str, task: &TaskSpec, _: i64) -> Result<Task> {
        if let Some(captured) = &self.added_tasks {
            captured.borrow_mut().push(task.clone());
        }
        Ok(self.task.clone().expect("scripted task"))
    }
    fn claim_task(&mut self, _: &str, _: &str, _: i64, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn renew_task(&mut self, _: &str, _: &str, _: i64, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn release_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn submit_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn accept_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn reject_task(&mut self, _: &str, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn cancel_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
        unreachable!()
    }
    fn board_set(&mut self, _: &str, _: &BoardWrite, _: i64) -> Result<BoardEntry> {
        unreachable!()
    }
    fn board_get(&self, _: &str, _: i64) -> Result<Option<BoardEntry>> {
        unreachable!()
    }
    fn board_remove(&mut self, _: &str, _: &str) -> Result<bool> {
        unreachable!()
    }
    fn board_list(&self, _: Option<&str>, _: i64) -> Result<Vec<BoardEntry>> {
        unreachable!()
    }
    fn heartbeat(&mut self, _: &str, _: &PresenceBeat, _: i64) -> Result<()> {
        unreachable!()
    }
    fn presence(&self, _: i64, _: i64) -> Result<Vec<lockyard_core::proto::Presence>> {
        unreachable!()
    }
}

fn claim() -> Claim {
    serde_json::from_value(json!({"id": 1})).unwrap()
}

#[test]
fn a_short_wait_retries_a_conflict_and_stops_on_anything_else() {
    let mut backend = Scripted {
        answers: vec![Err(Error::Contended("reserved".into())), Ok(claim())],
        waits: Vec::new(),
        ..Default::default()
    };
    assert_eq!(
        wait_for_claim(&mut backend, "a", ClaimRequest::default(), 3)
            .unwrap()
            .id,
        1
    );
    assert_eq!(backend.waits.len(), 2);
    assert!(backend.waits[0].is_some());

    let mut failing = Scripted {
        answers: vec![Err(Error::Frozen("x".into()))],
        waits: Vec::new(),
        ..Default::default()
    };
    assert!(matches!(
        wait_for_claim(&mut failing, "a", ClaimRequest::default(), 3),
        Err(Error::Frozen(_))
    ));
    assert_eq!(failing.waits.len(), 1);
}

#[test]
fn a_short_wait_gives_up_at_its_limit_and_refuses_a_long_one() {
    let mut backend = Scripted {
        answers: vec![Err(Error::Contended("reserved".into()))],
        waits: Vec::new(),
        ..Default::default()
    };
    assert!(matches!(
        wait_for_claim(&mut backend, "a", ClaimRequest::default(), 0),
        Err(Error::Contended(_))
    ));
    assert!(wait_for_claim(&mut backend, "a", ClaimRequest::default(), 121).is_err());
}

fn owned_claim(id: i64, session: &str) -> Claim {
    serde_json::from_value(json!({"id": id, "session": session})).unwrap()
}

#[test]
fn zone_release_without_id_handles_zero_one_and_offered_claims() {
    for all in [false, true] {
        let mut backend = Scripted {
            // A claim offered to this agent still belongs to its sender.
            claims: vec![owned_claim(99, "sender")],
            ..Default::default()
        };
        assert_eq!(
            release_claims(&mut backend, "a", None, all, &ReleaseRequest::default(), 0).unwrap(),
            0
        );
        assert!(backend.releases.is_empty());

        backend.claims.push(owned_claim(7, "a"));
        let request = ReleaseRequest {
            note: Some("finished".into()),
            fence: Some(15),
            ..ReleaseRequest::default()
        };
        assert_eq!(
            release_claims(&mut backend, "a", None, all, &request, 0).unwrap(),
            1
        );
        assert_eq!(backend.releases, [(Some(7), request)]);
    }
}

#[test]
fn zone_release_requires_an_id_or_all_before_any_release_with_multiple_claims() {
    let mut backend = Scripted {
        claims: vec![owned_claim(7, "a"), owned_claim(8, "a")],
        ..Default::default()
    };
    let error = release_claims(
        &mut backend,
        "a",
        None,
        false,
        &ReleaseRequest::default(),
        0,
    )
    .unwrap_err();
    assert!(matches!(error, Error::Invalid(_)));
    let text = error.to_string();
    for expected in ["Z-7", "Z-8", "id", "--all"] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(backend.releases.is_empty());

    assert_eq!(
        release_claims(&mut backend, "a", None, true, &ReleaseRequest::default(), 0).unwrap(),
        2
    );
    assert_eq!(backend.releases[0].0, None);
}

#[test]
fn zone_release_explicit_id_is_scoped_and_id_with_all_is_invalid() {
    let mut backend = Scripted {
        claims: vec![owned_claim(7, "a"), owned_claim(8, "a")],
        ..Default::default()
    };
    assert!(matches!(
        release_claims(
            &mut backend,
            "a",
            Some(7),
            true,
            &ReleaseRequest::default(),
            0,
        ),
        Err(Error::Invalid(_))
    ));
    assert!(backend.releases.is_empty());
    assert_eq!(
        release_claims(
            &mut backend,
            "a",
            Some(7),
            false,
            &ReleaseRequest::default(),
            0,
        )
        .unwrap(),
        1
    );
    assert_eq!(backend.releases[0].0, Some(7));
}

#[test]
fn zone_claim_accepts_local_hold_flags_without_storing_a_hold() {
    let dir = tempfile::tempdir().unwrap();
    Store::init(dir.path()).unwrap();
    let out = run(
        Cli::try_parse_from([
            "lockyard",
            "--agent",
            "a",
            "zone",
            "claim",
            "src",
            "--hold-reason",
            "long review",
        ])
        .unwrap(),
        dir.path(),
    )
    .unwrap();
    assert!(out.json.get("hold_reason").is_none());
    assert!(out.json.get("hold_until").is_none());
    let held: Claim = serde_json::from_value(out.json).unwrap();
    assert!(held.id > 0);
    assert_eq!(held.paths, ["src"]);
    assert_eq!(held.hold_reason, None);
    assert_eq!(held.hold_until, None);

    let until = rfc3339(now_ms() + 60_000);
    let out = run(
        Cli::try_parse_from([
            "lockyard",
            "--agent",
            "a",
            "zone",
            "claim",
            "src",
            "--hold-reason",
            "short review",
            "--hold-until",
            until.as_str(),
        ])
        .unwrap(),
        dir.path(),
    )
    .unwrap();
    assert!(out.json.get("hold_reason").is_none());
    assert!(out.json.get("hold_until").is_none());
    let reused: Claim = serde_json::from_value(out.json).unwrap();
    assert_eq!(reused.id, held.id);
    assert_eq!(reused.expires_at, held.expires_at);
    assert_eq!(reused.hold_reason, None);
    assert_eq!(reused.hold_until, None);
    let claims = Store::open(dir.path()).unwrap().claims(now_ms()).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, held.id);
}

#[test]
fn zone_claim_hold_until_without_reason_refuses_before_creating_a_claim() {
    let dir = tempfile::tempdir().unwrap();
    Store::init(dir.path()).unwrap();
    let error = run(
        Cli::try_parse_from([
            "lockyard",
            "--agent",
            "a",
            "zone",
            "claim",
            "src",
            "--hold-until",
            "2026-11-11T20:00:00Z",
        ])
        .unwrap(),
        dir.path(),
    )
    .err()
    .unwrap();
    assert!(matches!(error, Error::Invalid(_)));
    assert!(error.to_string().contains("hold_reason"));
    assert!(
        Store::open(dir.path())
            .unwrap()
            .claims(now_ms())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn zone_release_and_claim_help_explain_the_explicit_flags() {
    let mut command = Cli::command();
    command.build();
    let zone = command.find_subcommand_mut("zone").unwrap();
    let claim = zone
        .find_subcommand_mut("claim")
        .unwrap()
        .render_long_help()
        .to_string();
    for text in ["--hold-reason", "--hold-until", "RFC 3339"] {
        assert!(claim.contains(text), "{claim}");
    }
    let release = zone
        .find_subcommand_mut("release")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(release.contains("give an id or --all"), "{release}");
    assert!(
        release.contains("Cannot be combined with an id"),
        "{release}"
    );
    let cli = Cli::try_parse_from(["lockyard", "zone", "release", "--all"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Zone(ZoneCommand::Release {
            id: None,
            all: true,
            ..
        })
    ));
}

#[test]
fn cli_status_json_keeps_its_fields_and_does_not_request_lost_claims() {
    let dir = tempfile::tempdir().unwrap();
    Store::init(dir.path()).unwrap();
    for cloud in [false, true] {
        let opened = Opened {
            backend: Box::new(Scripted {
                cloud,
                ..Default::default()
            }),
            root: dir.path().to_path_buf(),
        };
        let out = run_status(&opened, Some(&"a".to_string())).unwrap();
        assert_eq!(out.json["claims"], json!([]));
        assert_eq!(out.json["tasks"], json!([]));
        assert_eq!(out.json["unread"], 0);
        assert!(out.json.get("lost").is_none());
        let mut keys: Vec<_> = out
            .json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut expected = vec!["claims", "machine_level", "tasks", "unannounced", "unread"];
        if cloud {
            assert_eq!(out.json["offers"], json!([]));
            assert_eq!(out.json["work"], json!([]));
            // Scripted cloud has no zone_requests → unknown, never an empty array.
            assert!(out.json.get("incoming_requests").is_none(), "{}", out.json);
            assert_eq!(out.json["incoming_requests_unknown"], true);
            // 0.3.16: the category of the selected key (claude / agent / explicit file), never its value.
            expected.extend([
                "offers",
                "work",
                "freshness",
                "incoming_requests_unknown",
                "token_source",
            ]);
            expected.sort_unstable();
        } else {
            assert!(out.json.get("incoming_requests").is_none(), "{}", out.json);
            assert!(
                out.json.get("incoming_requests_unknown").is_none(),
                "{}",
                out.json
            );
        }
        assert_eq!(keys, expected);
    }
}

#[test]
fn incoming_fetch_unknown_omits_empty_array() {
    let mut data = json!({"renewed": 1});
    let mut lines = vec!["renewed 1".into()];
    attach_incoming(&mut data, &mut lines, IncomingFetch::Unknown);
    assert!(data.get("incoming_requests").is_none(), "{data}");
    assert_eq!(data["incoming_requests_unknown"], true);
    assert_eq!(lines, vec!["renewed 1"]);

    let mut known = json!({"renewed": 1});
    let mut known_lines = vec!["renewed 1".into()];
    attach_incoming(&mut known, &mut known_lines, IncomingFetch::Known(vec![]));
    assert_eq!(known["incoming_requests"], json!([]));
    assert!(known.get("incoming_requests_unknown").is_none());
}

#[test]
fn keepalive_help_mentions_presence_and_hold_for_is_documented() {
    let mut command = Cli::command();
    command.build();
    let keepalive = command
        .find_subcommand_mut("keepalive")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(
        keepalive.contains("holder_available") || keepalive.contains("presence"),
        "{keepalive}"
    );
    assert!(
        keepalive.contains("zone renew") || keepalive.contains("Does not extend"),
        "{keepalive}"
    );
    let renew = command
        .find_subcommand_mut("zone")
        .unwrap()
        .find_subcommand_mut("renew")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(renew.contains("hold-for"), "{renew}");
    let mut command = Cli::command();
    command.build();
    let claim = command
        .find_subcommand_mut("zone")
        .unwrap()
        .find_subcommand_mut("claim")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(claim.contains("paths-file"), "{claim}");
    let mut command = Cli::command();
    command.build();
    let add = command
        .find_subcommand_mut("task")
        .unwrap()
        .find_subcommand_mut("add")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(add.contains("body-file"), "{add}");
    assert!(add.contains("acceptance-file"), "{add}");
    let mut command = Cli::command();
    command.build();
    let ping = command
        .find_subcommand_mut("ping")
        .unwrap()
        .render_long_help()
        .to_string();
    assert!(ping.contains("status") || ping.contains("round"), "{ping}");
}

#[test]
fn hold_for_minutes_maps_to_rfc3339_and_rejects_out_of_range() {
    let until = hold_until_from_minutes(30, 1_700_000_000_000).unwrap();
    assert!(
        until.contains("T") || until.ends_with('Z') || until.contains('+'),
        "{until}"
    );
    assert!(hold_until_from_minutes(0, 0).is_err());
    assert!(hold_until_from_minutes(241, 0).is_err());
    assert!(hold_until_from_minutes(1, 0).is_ok());
    assert!(hold_until_from_minutes(240, 0).is_ok());
}

#[test]
fn body_and_paths_files_refuse_nul_symlinks_and_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let body = dir.path().join("body.txt");
    std::fs::write(&body, b"ok\0bad").unwrap();
    let err = read_text_file(&body).unwrap_err().to_string();
    assert!(err.contains("NUL"), "{err}");
    let big = dir.path().join("big.txt");
    std::fs::write(&big, vec![b'a'; BODY_FILE_MAX_BYTES as usize + 1]).unwrap();
    assert!(
        read_text_file(&big)
            .unwrap_err()
            .to_string()
            .contains("byte limit")
    );
    let paths = dir.path().join("paths.txt");
    let mut lines = String::new();
    for i in 0..PATHS_FILE_MAX_LINES + 1 {
        lines.push_str(&format!("path-{i}\n"));
    }
    std::fs::write(&paths, lines).unwrap();
    assert!(
        read_lines_file(&paths)
            .unwrap_err()
            .to_string()
            .contains("more than")
    );
    #[cfg(unix)]
    {
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&body, &link).unwrap();
        assert!(
            read_text_file(&link)
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }
}

#[test]
fn claim_line_marks_unavailable_holder_with_keepalive_hint() {
    let mut claim = serde_json::from_value(json!({
        "id": 853,
        "session": "me",
        "paths": ["meta"],
        "expires_at": 9_999_999_999_i64,
        "holder_available": false
    }))
    .unwrap();
    let line = claim_line(&claim, None);
    assert!(line.contains("держатель недоступен"), "{line}");
    assert!(line.contains("keepalive"), "{line}");
    claim.holder_available = Some(true);
    assert!(!claim_line(&claim, None).contains("держатель недоступен"));
}

#[test]
fn incoming_path_requests_keep_unanswered_foreign_asks() {
    let records = vec![
        serde_json::from_value(json!({
            "id": 1, "from": "other", "paths": ["a"], "text": "please"
        }))
        .unwrap(),
        serde_json::from_value(json!({
            "id": 2, "from": "other", "paths": ["b"], "text": "x", "reply": "later"
        }))
        .unwrap(),
        serde_json::from_value(json!({
            "id": 3, "from": "me", "paths": ["c"], "text": "mine"
        }))
        .unwrap(),
    ];
    let incoming = incoming_path_requests(records, "me");
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].id, 1);
    let lines = incoming_request_lines(&incoming);
    assert!(lines[0].contains("R-1"), "{lines:?}");
    assert!(lines[0].contains("lockyard zone answer"), "{lines:?}");
    let json = incoming_requests_json(&incoming);
    assert_eq!(json[0]["id"], 1);
    assert_eq!(json[0]["from"], "other");
}

#[test]
fn round4_busy_agent_probe_preserves_the_normal_command_route() {
    for kind in [std::io::ErrorKind::TimedOut, std::io::ErrorKind::WouldBlock] {
        assert!(no_access_probe_allows_route(
            Err(std::io::Error::from(kind)),
            "http://127.0.0.1:9",
            "w"
        ));
    }
    assert!(!no_access_probe_allows_route(
        Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        "http://127.0.0.1:9",
        "w"
    ));
}

#[test]
fn round4_absent_agent_probe_has_a_short_windows_budget() {
    assert!(no_access_probe_budget() <= std::time::Duration::from_millis(250));
    let dir = tempfile::tempdir().unwrap();
    let start = std::time::Instant::now();
    assert!(
        crate::agent::socket::AgentSocket::status(
            &dir.path().join("absent"),
            no_access_probe_budget()
        )
        .is_err()
    );
    assert!(start.elapsed() < std::time::Duration::from_millis(500));
}

#[test]
fn no_cloud_access_exits_with_dedicated_code_and_message() {
    const CHILD: &str = "LOCKYARD_NO_ACCESS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::no_cloud_access_exits_with_dedicated_code_and_message",
            ])
            .env(CHILD, "1")
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", dir.path().join("run"))
            .env("LOCKYARD_CREDENTIALS", dir.path().join("missing"))
            .env_remove("LOCKYARD_TOKEN")
            .env_remove("LOCKYARD_TOKEN_FILE")
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(result.status.success(), "{result:?}");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("1 passed"),
            "child filter missed test: {result:?}"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join(".lockyard")).unwrap();
    std::fs::write(
        root.join(".lockyard/config.toml"),
        r#"mode = "cloud"
url = "https://example.test"
workspace = "team"
"#,
    )
    .unwrap();
    let out = no_cloud_access_output(root, None)
        .unwrap()
        .expect("cloud without token");
    assert_eq!(out.exit, EXIT_NO_CLOUD_ACCESS);
    assert!(out.text.contains("LOCKYARD_TOKEN_FILE"), "{}", out.text);
    assert!(
        out.text.contains("почта и запросы путей недоступны"),
        "{}",
        out.text
    );
}

#[test]
fn agent_accepts_root_flag_for_safe_service_cwd() {
    let cli = Cli::try_parse_from(["lockyard", "agent", "--root", "/tmp/project"]).unwrap();
    let Command::Agent(args) = cli.command else {
        panic!("expected agent");
    };
    assert_eq!(
        args.root.as_deref(),
        Some(std::path::Path::new("/tmp/project"))
    );
    assert!(args.command.is_none());
}

#[test]
fn mail_push_cli_addresses_urgent_and_wait_defaults() {
    use lockyard_cloud_client::{
        Client, CloudBackend,
        fake::{FakeServer, Reply},
    };
    for push in [true, false] {
        let server =
            FakeServer::start_routed_with_capabilities(if push { &["mail_push_v1"] } else { &[] });
        for to in [
            "*",
            "all",
            "все",
            "everyone",
            "@claude",
            "@cursor",
            "@codex",
            "@zone:client",
            "@path:src/lib.rs",
        ] {
            let mut args = vec!["lockyard", "msg", "send", to, "test"];
            if push {
                args.push("--urgent");
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let Command::Msg(command) = cli.command else {
                panic!("msg command")
            };
            server.enqueue(
                "/api/v1/bus/messages",
                Reply::json(200, json!({"id":42,"to":to,"body":"test","from":"alice"})),
            );
            let opened = Opened {
                backend: Box::new(CloudBackend::new(
                    Client::new(&server.url(), "test-token".into()).unwrap(),
                    "alice",
                )),
                root: PathBuf::from("/unused"),
            };
            let result = run_msg(opened, command, Some(&"alice".to_string()));
            if push || matches!(to, "*" | "all" | "все" | "everyone") {
                assert!(result.is_ok(), "{to}");
            } else {
                assert!(
                    result
                        .err()
                        .unwrap()
                        .to_string()
                        .contains("сервер не поддерживает")
                );
            }
        }
        let sent: Vec<_> = server
            .requests()
            .into_iter()
            .filter(|r| r.path == "/api/v1/bus/messages")
            .collect();
        assert_eq!(sent.len(), if push { 9 } else { 4 });
        for (i, request) in sent.iter().enumerate() {
            assert_eq!(
                request.body["to"],
                if push {
                    [
                        "*",
                        "all",
                        "все",
                        "everyone",
                        "@claude",
                        "@cursor",
                        "@codex",
                        "@zone:client",
                        "@path:src/lib.rs",
                    ][i]
                } else {
                    "*"
                }
            );
            assert_eq!(request.body.get("urgent"), push.then_some(&json!(true)));
        }
    }
    let cli = Cli::try_parse_from(["lockyard", "mail", "wait"]).unwrap();
    let Command::Mail(MailCommand::Wait { session, timeout }) = cli.command else {
        panic!("wait command")
    };
    assert!(session.is_none());
    assert_eq!(timeout, 21600);
    let cli = Cli::try_parse_from([
        "lockyard",
        "mail",
        "wait",
        "--session",
        "a",
        "--timeout",
        "0",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Mail(MailCommand::Wait {
            session: Some(_),
            timeout: 0
        })
    ));
}

#[test]
fn mail_wait_environment_order_matches_other_commands() {
    assert_eq!(
        env_agent_from(|name| Some(
            if name == "LOCKYARD_AGENT" {
                "lockyard-session"
            } else {
                "claude-session"
            }
            .into()
        ))
        .as_deref(),
        Some("lockyard-session")
    );
    assert_eq!(
        env_agent_from(|name| Some(
            if name == "LOCKYARD_AGENT" {
                ""
            } else {
                "claude-session"
            }
            .into()
        ))
        .as_deref(),
        Some("claude-session")
    );
    assert_eq!(env_agent_from(|_| None), None);
}

#[test]
fn mail_events_cli_hides_json_tombstones() {
    use lockyard_cloud_client::{
        Client, CloudBackend,
        fake::{FakeServer, Reply},
    };
    let server = FakeServer::start(vec![Reply::json(
        200,
        json!({"events":[
            {"seq":1,"type":42,"session":"alice"},
            {"seq":2,"type":"zone.claimed","payload":{"id":7}}
        ]}),
    )]);
    let opened = Opened {
        root: PathBuf::from("/unused"),
        backend: Box::new(CloudBackend::new(
            Client::new(&server.url(), "fixture".into()).unwrap(),
            "alice",
        )),
    };
    let cli = Cli::try_parse_from(["lockyard", "events"]).unwrap();
    let Command::Events(args) = cli.command else {
        panic!("events command")
    };
    let result = run_events(&opened, args, Some(&"alice".to_string())).unwrap();
    assert_eq!(result.json.as_array().unwrap().len(), 1);
    assert_eq!(result.json[0]["seq"], 2);
    assert_eq!(result.text, "2  zone.claimed");
}

#[test]
fn zone_wait_free_cli_parses_timeout_without_taking_a_claim() {
    let cli = Cli::try_parse_from([
        "lockyard",
        "zone",
        "wait-free",
        "src/lib.rs",
        "--timeout",
        "7",
    ])
    .unwrap();
    assert!(
        matches!(cli.command, Command::Zone(ZoneCommand::WaitFree { path, timeout:7 }) if path == "src/lib.rs")
    );
}

#[test]
fn task_add_accepts_explicit_client_key() {
    let cli = Cli::try_parse_from([
        "lockyard",
        "task",
        "add",
        "title",
        "--client-key",
        "retry-key",
    ])
    .unwrap();
    assert!(
        matches!(cli.command, Command::Task(TaskCommand::Add { client_key:Some(key), .. }) if key == "retry-key")
    );
}
