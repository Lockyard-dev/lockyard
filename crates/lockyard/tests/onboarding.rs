// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Runs the actual executable with isolated project and home directories. No test installs
//! client settings in the developer's real home directory.

use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(project: &Path, home: &Path, args: &[&str]) -> Output {
    command(project, home, args).output().unwrap()
}

fn command(project: &Path, home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(project)
        .args(args)
        .env("HOME", home)
        .env_remove("CODEX_HOME")
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .env("XDG_RUNTIME_DIR", home.join(".runtime"))
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("LOCKYARD_URL")
        .env_remove("LOCKYARD_TOKEN")
        .env_remove("LOCKYARD_TOKEN_FILE");
    command
}

fn ok(project: &Path, home: &Path, args: &[&str]) -> Value {
    let result = run(project, home, args);
    assert!(
        result.status.success(),
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn doctor_reports_missing_project_as_failure_without_leaking_configuration() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let result = run(project.path(), home.path(), &["doctor", "--json"]);
    assert_eq!(result.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "project" && check["state"] == "failed")
    );
    assert_eq!(fs::read_dir(project.path()).unwrap().count(), 0);
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn doctor_smoke_proves_two_real_agents_conflict_and_recovers_after_release() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    ok(project.path(), home.path(), &["init", "--json"]);
    let report = ok(
        project.path(),
        home.path(),
        &["doctor", "--smoke", "--json", "--agent", "alice"],
    );
    assert_eq!(report["ok"], true);
    assert_eq!(report["smoke"]["ok"], true);
    let steps = report["smoke"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 5);
    assert_eq!(steps[2]["step"], "conflict_b");
    assert_eq!(steps[2]["exit_code"], 3);
    assert_eq!(steps[4]["step"], "claim_b");
    assert_eq!(steps[4]["exit_code"], 0);
    // The smoke project must not have added a claim in the real project.
    let claims = ok(project.path(), home.path(), &["zone", "list", "--json"]);
    assert_eq!(claims, json!([]));
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn preview_apply_check_remove_preserve_unrelated_servers_and_hooks() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".mcp.json"),
        "{\"mcpServers\":{\"other\":{\"command\":\"other\"}}}",
    )
    .unwrap();
    fs::create_dir(project.path().join(".claude")).unwrap();
    fs::write(project.path().join(".claude/settings.json"), "{\"hooks\":{\"PreToolUse\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"user-check\"}]}]},\"userSetting\":true}").unwrap();
    let before = fs::read(project.path().join(".mcp.json")).unwrap();
    let preview = ok(
        project.path(),
        home.path(),
        &["setup", "claude", "--preview", "--json"],
    );
    assert_eq!(preview["action"], "preview");
    assert_eq!(before, fs::read(project.path().join(".mcp.json")).unwrap());
    assert!(
        !project
            .path()
            .join(".mcp.json.lockyard-setup.json")
            .exists()
    );
    ok(
        project.path(),
        home.path(),
        &["setup", "claude", "--apply", "--json"],
    );
    let first = fs::read(project.path().join(".claude/settings.json")).unwrap();
    ok(
        project.path(),
        home.path(),
        &["setup", "claude", "--apply", "--json"],
    );
    assert_eq!(
        first,
        fs::read(project.path().join(".claude/settings.json")).unwrap()
    );
    ok(
        project.path(),
        home.path(),
        &["setup", "claude", "--check", "--json"],
    );
    ok(
        project.path(),
        home.path(),
        &["setup", "claude", "--remove", "--json"],
    );
    let mcp: Value =
        serde_json::from_slice(&fs::read(project.path().join(".mcp.json")).unwrap()).unwrap();
    assert_eq!(mcp["mcpServers"]["other"]["command"], "other");
    assert!(mcp["mcpServers"].get("lockyard").is_none());
    let settings: Value =
        serde_json::from_slice(&fs::read(project.path().join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(settings["userSetting"], true);
    assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "user-check"
    );
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn codex_install_uses_isolated_home_and_keeps_toml_comments() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join(".codex");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("config.toml");
    let original =
        "# my settings\nmodel = 'custom-model'\n[mcp_servers.other]\ncommand = 'other'\n";
    fs::write(&path, original).unwrap();
    ok(
        project.path(),
        home.path(),
        &["setup", "codex", "--apply", "--json"],
    );
    assert!(fs::read_to_string(&path).unwrap().starts_with(original));
    let installed: toml::Value = fs::read_to_string(&path).unwrap().parse().unwrap();
    assert_eq!(
        installed["mcp_servers"]["lockyard"]["env_vars"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "LOCKYARD_AGENT",
            "LOCKYARD_URL",
            "LOCKYARD_TOKEN_FILE",
            "LOCKYARD_TOKEN",
            "LOCKYARD_NODE_CONFIG",
            "XDG_CONFIG_HOME",
            "LOCKYARD_REQUIRE_E2EE",
            "LOCKYARD_E2EE_WORKSPACE_ID"
        ]
    );
    ok(
        project.path(),
        home.path(),
        &["setup", "codex", "--check", "--json"],
    );
    ok(
        project.path(),
        home.path(),
        &["setup", "codex", "--remove", "--json"],
    );
    assert_eq!(fs::read_to_string(path).unwrap(), original);
}

#[test]
fn codex_custom_home_is_shared_by_preview_apply_check_doctor_and_remove() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let custom = tempfile::tempdir().unwrap();
    let default_directory = home.path().join(".codex");
    fs::create_dir(&default_directory).unwrap();
    let default_path = default_directory.join("config.toml");
    let default_original = "# unrelated default profile\nmodel = 'keep-me'\n";
    fs::write(&default_path, default_original).unwrap();
    let custom_path = custom.path().join("config.toml");
    ok(project.path(), home.path(), &["init", "--json"]);

    let selected = |args: &[&str]| {
        let result = command(project.path(), home.path(), args)
            .env("CODEX_HOME", custom.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        serde_json::from_slice::<Value>(&result.stdout).unwrap()
    };
    let preview = selected(&["setup", "codex", "--preview", "--json"]);
    assert_eq!(preview["files"][0]["path"], custom_path.to_str().unwrap());
    assert!(!custom_path.exists());
    selected(&["setup", "codex", "--apply", "--json"]);
    assert!(custom_path.exists());
    selected(&["setup", "codex", "--check", "--json"]);
    let doctor = selected(&["doctor", "--client", "codex", "--agent", "doctor", "--json"]);
    assert!(
        doctor["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "client_configuration" && check["state"] == "ok")
    );
    // The other profile is still unconfigured, rather than accidentally receiving this install.
    assert_eq!(
        run(
            project.path(),
            home.path(),
            &["setup", "codex", "--check", "--json"]
        )
        .status
        .code(),
        Some(1)
    );
    selected(&["setup", "codex", "--remove", "--json"]);
    assert!(
        !fs::read_to_string(&custom_path)
            .unwrap()
            .contains("mcp_servers.lockyard")
    );
    assert_eq!(fs::read_to_string(&default_path).unwrap(), default_original);
    assert_eq!(fs::read_dir(default_directory).unwrap().count(), 1);
    assert_eq!(
        command(
            project.path(),
            home.path(),
            &["setup", "codex", "--check", "--json"]
        )
        .env("CODEX_HOME", custom.path())
        .output()
        .unwrap()
        .status
        .code(),
        Some(1)
    );
}

#[test]
fn applying_a_conflicting_server_fails_without_overwriting_it() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let directory = project.path().join(".cursor");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("mcp.json");
    let original = "{\"mcpServers\":{\"lockyard\":{\"command\":\"custom\"}}}";
    fs::write(&path, original).unwrap();
    let result = run(
        project.path(),
        home.path(),
        &["setup", "cursor", "--apply", "--json"],
    );
    assert_eq!(result.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(fs::read_to_string(path).unwrap(), original);
}

#[test]
fn doctor_redacts_invalid_project_configuration_and_credentials() {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    ok(project.path(), home.path(), &["init", "--json"]);
    fs::write(
        project.path().join(".lockyard/config.toml"),
        "mode='cloud'\nurl='https://example.test'\nworkspace='w'\ntoken='must-never-be-output'\n",
    )
    .unwrap();
    let result = run(project.path(), home.path(), &["doctor", "--json"]);
    assert_eq!(result.status.code(), Some(1));
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!all.contains("must-never-be-output"));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "configuration" && check["state"] == "failed")
    );
}
