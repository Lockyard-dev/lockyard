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
        "W-12",
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
    assert_eq!(task.id, 12);
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
        assert_eq!(parsed, id);
        assert_eq!(to, "PA-0007");
    }
}

#[test]
fn registry_task_ids_keep_area_prefixes() {
    for id in ["FE-0001", "G-SG-0012", "D-3176"] {
        assert_eq!(parse_task_id(id).unwrap(), id);
    }
    for id in ["fe-1", "FE-", "-1"] {
        assert!(parse_task_id(id).is_err(), "{id}");
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

struct Scripted {
    answers: Vec<Result<Claim>>,
    waits: Vec<Option<i64>>,
}

impl Backend for Scripted {
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
    fn release(&mut self, _: &str, _: Option<i64>, _: &ReleaseRequest, _: i64) -> Result<usize> {
        unreachable!()
    }
    fn claims(&self, _: &ClaimQuery, _: i64) -> Result<Vec<Claim>> {
        unreachable!()
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
        unreachable!()
    }
    fn inbox_seen(&mut self, _: &str, _: &[i64], _: i64) -> Result<usize> {
        unreachable!()
    }
    fn inbox_claim(&mut self, _: &str, _: &str, _: &[i64], _: i64, _: i64) -> Result<Vec<i64>> {
        unreachable!()
    }
    fn tasks(&self, _: Option<Status>, _: bool) -> Result<Vec<Task>> {
        unreachable!()
    }
    fn task(&self, _: &str) -> Result<Task> {
        unreachable!()
    }
    fn task_history(&self, _: &str) -> Result<Vec<lockyard_core::tasks::TaskEvent>> {
        unreachable!()
    }
    fn add_task(&mut self, _: &str, _: &TaskSpec, _: i64) -> Result<Task> {
        unreachable!()
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
    };
    assert!(matches!(
        wait_for_claim(&mut backend, "a", ClaimRequest::default(), 0),
        Err(Error::Contended(_))
    ));
    assert!(wait_for_claim(&mut backend, "a", ClaimRequest::default(), 121).is_err());
}
