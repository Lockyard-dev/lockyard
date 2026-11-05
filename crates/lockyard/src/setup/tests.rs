// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use serde_json::json;

/// A project and a home folder of its own, with no executable on the search path, so detection
/// answers from the folders a test creates and never from the machine running it.
///
/// Claude's settings sit outside `.claude/` here: some sandboxes refuse to let a process write
/// into an agent's own configuration folder, and that would make these tests report the host
/// rather than Lockyard. Where the real file goes is checked separately, by
/// `discover_puts_claude_settings_in_the_project`.
fn site() -> (tempfile::TempDir, Site) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("project");
    let home = dir.path().join("home");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();
    let site = Site {
        claude_settings: root.join("claude-settings/settings.json"),
        root,
        codex_home: home.join(".codex"),
        copilot_home: home.join(".copilot"),
        home,
        command_path: Vec::new(),
    };
    (dir, site)
}

fn install(client: Client, site: &Site) -> Vec<Applied> {
    let changes = plan(&[client], site, false).unwrap();
    apply(&changes, false).unwrap()
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn a_run_writes_mcp_hook_and_instructions_for_claude() {
    let (_dir, site) = site();
    let done = install(Client::Claude, &site);
    assert_eq!(done.len(), 3);
    assert!(done.iter().all(|item| item.action == "create"));

    let mcp = read_text(&site.root.join(".mcp.json"));
    assert!(merge::mcp_present(&mcp));
    let settings = read_text(&site.claude_settings);
    assert!(merge::claude_hooks_present(&settings));
    let instructions = read_text(&site.root.join("CLAUDE.md"));
    assert!(instructions.contains(merge::BLOCK_START));
    assert!(instructions.contains("claim"));
}

#[test]
fn a_second_run_changes_nothing() {
    let (_dir, site) = site();
    install(Client::Claude, &site);
    let again = install(Client::Claude, &site);
    assert!(
        again.iter().all(|item| item.action == "unchanged"),
        "{again:?}"
    );
    assert!(
        !site.root.join(format!(".mcp.json{BACKUP_SUFFIX}")).exists(),
        "an unchanged file is never backed up"
    );
}

#[test]
fn a_dry_run_writes_nothing_and_reports_the_same_plan() {
    let (_dir, site) = site();
    let changes = plan(&[Client::Claude], &site, false).unwrap();
    let planned = apply(&changes, true).unwrap();
    assert!(!site.root.join(".mcp.json").exists());
    let real = apply(&changes, false).unwrap();
    assert_eq!(
        planned
            .iter()
            .map(|item| (item.part, item.action))
            .collect::<Vec<_>>(),
        real.iter()
            .map(|item| (item.part, item.action))
            .collect::<Vec<_>>()
    );
    assert!(describe(&planned, true).contains("would create"));
}

#[test]
fn an_existing_config_is_merged_and_backed_up_not_clobbered() {
    let (_dir, site) = site();
    let mcp = site.root.join(".mcp.json");
    let original = json!({"mcpServers": {"other": {"command": "serve"}}}).to_string();
    fs::write(&mcp, &original).unwrap();
    install(Client::Claude, &site);

    let written: Value = serde_json::from_str(&read_text(&mcp)).unwrap();
    assert_eq!(written["mcpServers"]["other"]["command"], "serve");
    assert_eq!(written["mcpServers"]["lockyard"]["command"], "lockyard");
    assert_eq!(
        read_text(&site.root.join(format!(".mcp.json{BACKUP_SUFFIX}"))),
        original,
        "the backup holds the file as it was before Lockyard touched it"
    );
}

#[test]
fn backups_are_private_and_an_existing_backup_is_never_overwritten() {
    let (_dir, site) = site();
    let mcp = site.root.join(".mcp.json");
    let backup = site.root.join(format!(".mcp.json{BACKUP_SUFFIX}"));
    fs::write(&mcp, r#"{"theme":"dark"}"#).unwrap();
    fs::write(&backup, "user backup").unwrap();

    install(Client::Claude, &site);

    assert_eq!(read_text(&backup), "user backup");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let (_private_dir, private_site) = self::site();
        let original = private_site.root.join(".mcp.json");
        fs::write(&original, r#"{"theme":"private"}"#).unwrap();
        install(Client::Claude, &private_site);
        let private_backup = private_site.root.join(format!(".mcp.json{BACKUP_SUFFIX}"));
        let mode = fs::metadata(private_backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[cfg(unix)]
#[test]
fn setup_replaces_a_symlink_without_writing_through_to_its_target() {
    use std::os::unix::fs::symlink;

    let (_dir, site) = site();
    let target = site.root.join("outside-settings.json");
    let config = site.root.join(".mcp.json");
    fs::write(&target, r#"{"theme":"do not overwrite"}"#).unwrap();
    symlink(&target, &config).unwrap();

    install(Client::Claude, &site);

    assert_eq!(read_text(&target), r#"{"theme":"do not overwrite"}"#);
    assert!(
        !fs::symlink_metadata(&config)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn an_unparseable_config_stops_the_run_instead_of_overwriting_it() {
    let (_dir, site) = site();
    let mcp = site.root.join(".mcp.json");
    fs::write(&mcp, "{ not json").unwrap();
    let failed = plan(&[Client::Claude], &site, false);
    assert!(failed.is_err(), "{failed:?}");
    assert_eq!(read_text(&mcp), "{ not json");
}

#[test]
fn uninstall_takes_back_what_setup_added_and_leaves_the_rest() {
    let (_dir, site) = site();
    let mcp = site.root.join(".mcp.json");
    let claude_md = site.root.join("CLAUDE.md");
    fs::write(&mcp, json!({"mcpServers": {"other": {}}}).to_string()).unwrap();
    fs::write(&claude_md, "# Project\n\nHouse rules.\n").unwrap();
    install(Client::Claude, &site);

    let changes = plan(&[Client::Claude], &site, true).unwrap();
    apply(&changes, false).unwrap();
    let left: Value = serde_json::from_str(&read_text(&mcp)).unwrap();
    assert!(left["mcpServers"].get("lockyard").is_none());
    assert!(left["mcpServers"].get("other").is_some());
    assert_eq!(read_text(&claude_md), "# Project\n\nHouse rules.\n");
    assert!(
        !site.claude_settings.exists(),
        "a settings file Lockyard created alone is removed again"
    );
}

#[test]
fn uninstall_restores_original_bytes_when_owned_files_were_not_changed() {
    let (_dir, site) = site();
    let mcp = site.root.join(".mcp.json");
    let instructions = site.root.join("CLAUDE.md");
    let original_mcp = "{\"theme\":\"dark\",\"mcpServers\":{\"other\":{}}}\n";
    let original_instructions = "# Project\n\nKeep this formatting.\n";
    fs::write(&mcp, original_mcp).unwrap();
    fs::write(&instructions, original_instructions).unwrap();
    install(Client::Claude, &site);

    apply(&plan(&[Client::Claude], &site, true).unwrap(), false).unwrap();

    assert_eq!(read_text(&mcp), original_mcp);
    assert_eq!(read_text(&instructions), original_instructions);
}

#[test]
fn uninstall_preserves_edits_made_after_setup() {
    let (_dir, site) = site();
    let mcp = site.root.join(".mcp.json");
    let instructions = site.root.join("CLAUDE.md");
    fs::write(&mcp, r#"{"theme":"dark"}"#).unwrap();
    install(Client::Claude, &site);
    let mut config: Value = serde_json::from_str(&read_text(&mcp)).unwrap();
    config["userSetting"] = json!(true);
    fs::write(&mcp, serde_json::to_string(&config).unwrap()).unwrap();
    fs::write(&instructions, "User added this after setup.\n").unwrap();

    apply(&plan(&[Client::Claude], &site, true).unwrap(), false).unwrap();

    let config: Value = serde_json::from_str(&read_text(&mcp)).unwrap();
    assert_eq!(config["userSetting"], true);
    assert!(config.get("mcpServers").is_none());
    assert_eq!(read_text(&instructions), "User added this after setup.\n");
}

#[test]
fn uninstall_runs_twice_without_complaining() {
    let (_dir, site) = site();
    install(Client::Claude, &site);
    apply(&plan(&[Client::Claude], &site, true).unwrap(), false).unwrap();
    let again = apply(&plan(&[Client::Claude], &site, true).unwrap(), false).unwrap();
    assert!(again.iter().all(|item| item.action == "unchanged"));
}

#[test]
fn codex_gets_a_toml_table_in_its_home_and_an_agents_file_in_the_project() {
    let (_dir, site) = site();
    fs::create_dir_all(&site.codex_home).unwrap();
    fs::write(
        site.codex_home.join("config.toml"),
        "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n",
    )
    .unwrap();
    install(Client::Codex, &site);
    let config = read_text(&site.codex_home.join("config.toml"));
    assert!(config.contains("model = \"o3\""));
    assert!(config.contains("[mcp_servers.other]"));
    assert!(merge::toml_table_present(&config, "mcp_servers.lockyard"));
    toml::from_str::<toml::Value>(&config).expect("Codex config stays valid TOML");
    assert!(read_text(&site.root.join("AGENTS.md")).contains(merge::BLOCK_START));
}

/// The text a plan would write to one part, or nothing when there is no such part.
fn planned(changes: &[Change], part: &str) -> Option<String> {
    changes
        .iter()
        .find(|change| change.part == part)
        .and_then(|change| change.after.clone())
}

fn planned_path(changes: &[Change], part: &str) -> PathBuf {
    changes
        .iter()
        .find(|change| change.part == part)
        .unwrap_or_else(|| panic!("no {part} in the plan"))
        .path
        .clone()
}

#[test]
fn every_client_plans_its_own_files_and_only_claude_gets_a_hook() {
    let (_dir, site) = site();
    let expected = [
        (Client::Claude, ".mcp.json", "CLAUDE.md"),
        (
            Client::Cursor,
            ".cursor/mcp.json",
            ".cursor/rules/lockyard.mdc",
        ),
        (Client::Gemini, ".gemini/settings.json", "GEMINI.md"),
        (Client::Copilot, "", ".github/copilot-instructions.md"),
        (Client::Codex, "", "AGENTS.md"),
    ];
    for (client, mcp, instructions) in expected {
        let changes = plan(&[client], &site, false).unwrap();
        let parts: Vec<&str> = changes.iter().map(|change| change.part).collect();
        if client == Client::Claude {
            assert_eq!(parts, ["mcp", "hook", "instructions"], "{client}");
        } else {
            assert_eq!(parts, ["mcp", "instructions"], "{client}");
        }
        assert_eq!(
            planned_path(&changes, "instructions"),
            site.root.join(instructions)
        );
        if !mcp.is_empty() {
            assert_eq!(planned_path(&changes, "mcp"), site.root.join(mcp));
        }
        let registered = planned(&changes, "mcp").unwrap();
        if client == Client::Codex {
            assert_eq!(
                planned_path(&changes, "mcp"),
                site.codex_home.join("config.toml")
            );
            assert!(merge::toml_table_present(
                &registered,
                "mcp_servers.lockyard"
            ));
        } else {
            assert!(merge::mcp_present(&registered), "{client}");
        }
        assert!(merge::block_present(
            &planned(&changes, "instructions").unwrap()
        ));
    }
    assert_eq!(
        planned_path(&plan(&[Client::Copilot], &site, false).unwrap(), "mcp"),
        site.copilot_home.join("mcp-config.json")
    );
    // A Cursor rule is read only when its front matter asks for it, so the block is not enough.
    let rule = planned(
        &plan(&[Client::Cursor], &site, false).unwrap(),
        "instructions",
    )
    .unwrap();
    assert!(
        rule.starts_with("---\n"),
        "a Cursor rule needs front matter"
    );
    assert!(rule.contains("alwaysApply: true"));
}

#[test]
fn gemini_and_copilot_runs_write_the_files_they_planned() {
    let (_dir, site) = site();
    install(Client::Gemini, &site);
    install(Client::Copilot, &site);
    assert!(merge::mcp_present(&read_text(
        &site.root.join(".gemini/settings.json")
    )));
    assert!(read_text(&site.root.join("GEMINI.md")).contains(merge::BLOCK_START));
    assert!(merge::mcp_present(&read_text(
        &site.copilot_home.join("mcp-config.json")
    )));
    assert!(
        read_text(&site.root.join(".github/copilot-instructions.md")).contains(merge::BLOCK_START)
    );
}

#[test]
fn detection_answers_from_folders_and_from_the_search_path() {
    let (_dir, mut site) = site();
    assert!(ALL.iter().all(|client| !client.installed(&site)));
    fs::create_dir_all(site.home.join(".gemini")).unwrap();
    assert!(Client::Gemini.installed(&site));
    assert!(!Client::Claude.installed(&site));

    let bin = site.home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("claude"), "#!/bin/sh\n").unwrap();
    site.command_path.push(bin);
    assert!(Client::Claude.installed(&site));
}

#[test]
fn inspect_reports_each_part_before_and_after_a_run() {
    let (_dir, site) = site();
    let before = inspect(Client::Claude, &site).unwrap();
    assert_eq!(before.len(), 3);
    assert!(before.iter().all(|finding| !finding.ok));
    assert!(before[1].detail.contains("edits are not blocked"));
    install(Client::Claude, &site);
    let after = inspect(Client::Claude, &site).unwrap();
    assert!(after.iter().all(|finding| finding.ok), "{after:?}");
}

#[test]
fn inspect_recognizes_claude_project_local_mcp_registration() {
    let (_dir, site) = site();
    let root = site.root.to_string_lossy().to_string();
    fs::write(
        site.home.join(".claude.json"),
        serde_json::to_vec(&json!({
            "projects": {
                root: {"mcpServers": {"lockyard": {"command": "lockyard"}}}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let findings = inspect(Client::Claude, &site).unwrap();
    assert!(findings[0].ok, "{}", findings[0].detail);
}

#[test]
fn the_printed_snippet_names_the_same_files_the_run_writes() {
    let (_dir, site) = site();
    for client in ALL {
        let snippet = client.snippet(&site);
        for change in plan(&[client], &site, false).unwrap() {
            assert!(
                snippet.contains(&change.path.display().to_string()),
                "{client} snippet does not mention {}",
                change.path.display()
            );
        }
        if client != Client::Claude {
            assert!(
                snippet.contains("No blocking pre-edit hook"),
                "{client} must say plainly that edits are not blocked"
            );
        }
    }
}

#[test]
fn the_instruction_block_tells_the_agent_to_claim_check_mail_and_submit() {
    let block = Client::Claude.block();
    assert!(block.starts_with(merge::BLOCK_START));
    assert!(block.trim_end().ends_with(merge::BLOCK_END));
    for wanted in [
        "zone claim",
        "zone check",
        "msg inbox",
        "task submit",
        "zone release",
    ] {
        assert!(block.contains(wanted), "the block never mentions {wanted}");
    }
    // Short enough to sit in front of every turn.
    assert!(
        block.lines().count() < 25,
        "{} lines",
        block.lines().count()
    );
}

#[test]
fn discover_puts_claude_settings_in_the_project() {
    let dir = tempfile::tempdir().unwrap();
    let site = Site::discover(dir.path()).unwrap();
    assert_eq!(
        site.claude_settings,
        dir.path().join(".claude/settings.json")
    );
    assert_eq!(
        Client::Claude.hook(&site),
        Some(dir.path().join(".claude/settings.json"))
    );
}
