// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_hook(command: HookCommand, agent: Option<String>, cwd: &Path) -> Result<Output> {
    if let HookCommand::Check { path } = &command {
        let agent = resolve_agent(agent.as_ref())?;
        let opened = open::open(cwd, Some(&agent))?;
        let path = opened.zone_path(cwd, path)?;
        let mut checks =
            opened
                .backend
                .check(&agent, std::slice::from_ref(&path), None, now_ms())?;
        if checks.len() != 1 || checks[0].path != path {
            return Err(Error::Unavailable(
                "the zone check did not answer this path".into(),
            ));
        }
        let check = checks.pop().expect("one path checked above");
        match check.status {
            CheckStatus::Held => {
                return match check.holder {
                    Some(holder) => Err(Error::Conflict(vec![holder])),
                    None => Err(Error::Contended(format!("{path} is held"))),
                };
            }
            CheckStatus::Unknown => {
                return Err(Error::Unavailable(
                    "the zone view is not fresh enough to check this edit".into(),
                ));
            }
            CheckStatus::Free | CheckStatus::Own => {}
        }
        return output(&json!({"free": true}), "free");
    }
    let tool = match command {
        HookCommand::Claude => hook::Tool::Claude,
        HookCommand::Codex => hook::Tool::Codex,
        HookCommand::Cursor => hook::Tool::Cursor,
        HookCommand::Check { .. } => unreachable!(),
    };
    let mut input = String::new();
    let read = std::io::stdin().read_to_string(&mut input);
    let mut out = std::io::stdout().lock();
    let answer = read.map_err(Error::Io).and_then(|_| {
        hook::run(
            tool,
            &input,
            agent.or_else(env_agent_explicit),
            cwd,
            now_ms(),
            &mut out,
        )
    });
    // Parsed PreToolUse edits turn failed checks into permission denials in hook::run.
    // Mail and presence stay advisory; keep their failures visible for troubleshooting.
    if let Err(error) = answer {
        eprintln!("lockyard hook: {error}");
    }
    output(&Value::Null, "")
}

pub(super) fn setup(client: SetupClient) -> String {
    let server = r#"{
  "mcpServers": {
    "lockyard": { "command": "lockyard", "args": ["mcp"] }
  }
}"#;
    let mut sections = match client {
        SetupClient::Claude => vec![
            format!("Add to .claude/settings.json:\n{}", hook::SETTINGS),
            format!("Add to .mcp.json:\n{server}"),
        ],
        SetupClient::Codex => vec![
            "Add to ~/.codex/config.toml:\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]\nenv_vars = [\"LOCKYARD_AGENT\", \"LOCKYARD_URL\", \"LOCKYARD_TOKEN_FILE\", \"LOCKYARD_TOKEN\", \"LOCKYARD_NODE_CONFIG\", \"XDG_CONFIG_HOME\", \"LOCKYARD_REQUIRE_E2EE\", \"LOCKYARD_E2EE_WORKSPACE_ID\"]"
                .to_string(),
        ],
        SetupClient::Cursor => vec![format!("Add to .cursor/mcp.json:\n{server}")],
    };
    sections.push("Set LOCKYARD_AGENT to a unique name for each agent.".to_string());
    sections.join("\n\n")
}

pub(super) fn onboarding_output(mut data: Value) -> Result<Output> {
    if let Some(checks) = data.get_mut("checks").and_then(Value::as_array_mut) {
        for check in checks {
            check["check"] = check["name"].clone();
            check["ok"] = json!(check["state"] != "failed");
            check["detail"] = check["message"].clone();
        }
    }
    let mut result = output(&data, onboarding::text(&data))?;
    if data["ok"] == false {
        result.exit = EXIT_FAILURE;
    }
    Ok(result)
}

/// The clients a run covers: the named ones, or every one found in this project and home.
pub(super) fn chosen_clients(args: &SetupArgs, site: &setup::Site) -> Result<Vec<setup::Client>> {
    if args.clients.iter().any(|name| name == "all") {
        return Ok(setup::ALL.to_vec());
    }
    if args.clients.is_empty() {
        return Ok(setup::ALL
            .into_iter()
            .filter(|client| client.installed(site))
            .collect());
    }
    args.clients
        .iter()
        .map(|name| {
            setup::Client::parse(name).ok_or_else(|| {
                Error::Invalid(format!(
                    "unknown client {name:?}: use claude, codex, cursor, gemini, copilot or all"
                ))
            })
        })
        .collect()
}

pub(super) fn run_setup(args: SetupArgs, cwd: &Path) -> Result<Output> {
    if let Some(client) = args.client {
        if args.dry_run || args.uninstall || args.print {
            return Err(Error::Invalid("use --preview/--remove with positional CLIENT, or --client CLIENT for legacy setup options".into()));
        }
        if !(args.apply || args.check || args.remove || args.preview) {
            let text = setup(client);
            return output(&json!({"setup": text}), text);
        }
        let client = match client {
            SetupClient::Claude => "claude",
            SetupClient::Codex => "codex",
            SetupClient::Cursor => "cursor",
        };
        let action = if args.apply {
            onboarding::SetupAction::Apply
        } else if args.check {
            onboarding::SetupAction::Check
        } else if args.remove {
            onboarding::SetupAction::Remove
        } else {
            onboarding::SetupAction::Preview
        };
        return onboarding_output(onboarding::setup(cwd, client, action)?);
    }
    // Setup configures one project, so it needs one: the files it writes name this folder.
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let site = setup::Site::discover(&root)?;
    let clients = chosen_clients(&args, &site)?;
    if args.print {
        let text = clients
            .iter()
            .map(|client| format!("# {}\n{}", client.label(), client.snippet(&site)))
            .collect::<Vec<_>>()
            .join("\n\n");
        return output(&json!({"setup": text}), text);
    }
    let changes = setup::plan(&clients, &site, args.uninstall)?;
    let done = setup::apply(&changes, args.dry_run)?;
    let mut text = setup::describe(&done, args.dry_run);
    if !args.dry_run && !args.uninstall && !done.is_empty() {
        text.push_str(
            "\n\nRestart the clients you had open, then set LOCKYARD_AGENT to a unique name for each agent.",
        );
    }
    output(&setup::as_json(&done), text)
}

pub(super) fn run_doctor(cwd: &Path, agent: Option<&String>) -> Result<Output> {
    use lockyard_core::config::{Config, Mode};
    let mut findings = Vec::new();
    let root = lockyard_core::paths::find_root(cwd);
    let Some(root) = root else {
        findings.push(setup::Finding::missing_project(cwd));
        return doctor_output(findings);
    };
    findings.push(setup::Finding::ok_check(
        "project",
        format!("{} holds the Lockyard store", root.display()),
    ));
    match Store::open(&root).and_then(|mut store| {
        // A read-only store would fail only at the first claim, which is the worst moment.
        lockyard_core::Backend::touch_agent(&mut store, "lockyard-doctor", now_ms())
    }) {
        Ok(()) => findings.push(setup::Finding::ok_check("store", "writable")),
        Err(error) => findings.push(setup::Finding::failed("store", error.to_string())),
    }
    let name = agent.cloned().or_else(env_agent);
    findings.push(match &name {
        Some(name) => setup::Finding::ok_check("agent name", name.to_string()),
        None => setup::Finding::failed(
            "agent name",
            "unset: export LOCKYARD_AGENT=<name> so your work is attributed",
        ),
    });

    let config = Config::load(&root)?;
    if config.mode == Mode::Cloud {
        findings.push(cloud_finding(&config, name.as_deref()));
    } else {
        findings.push(setup::Finding::ok_check(
            "mode",
            "local: everything stays in .lockyard/",
        ));
    }

    let site = setup::Site::discover(&root)?;
    let detected: Vec<setup::Client> = setup::ALL
        .into_iter()
        .filter(|client| client.installed(&site))
        .collect();
    if detected.is_empty() {
        // Not a failure: Lockyard is useful from the command line with no agent tool installed.
        findings.push(setup::Finding::ok_check(
            "clients",
            "none detected; name one with `lockyard setup --client <name>`",
        ));
    }
    for client in detected {
        findings.extend(setup::inspect(client, &site)?);
    }

    findings.push(setup::Finding::ok_check(
        "file watch",
        format!(
            "{} (events accelerate; a 10s reconcile is the source of truth)",
            monitor::backend_name(&root)
        ),
    ));
    if let Ok(store) = Store::open(&root) {
        let recent = store.unannounced(now_ms().saturating_sub(24 * 60 * 60 * 1000))?;
        if recent.is_empty() {
            findings.push(setup::Finding::ok_check(
                "outside writes",
                "none recorded in the last day",
            ));
        } else {
            findings.push(setup::Finding::failed(
                "outside writes",
                format!(
                    "{} path(s) changed under a claim without a hook — detection only, see `lockyard status`",
                    recent.len()
                ),
            ));
        }
    }

    doctor_output(findings)
}

/// Asks the configured server for something only a working token and URL can answer.
pub(super) fn cloud_finding(
    config: &lockyard_core::config::Config,
    agent: Option<&str>,
) -> setup::Finding {
    let endpoint = match open::endpoint(config) {
        Ok((url, _)) => url,
        Err(error) => return setup::Finding::failed("cloud", error.to_string()),
    };
    match open::direct_client(&endpoint) {
        Ok(client) => {
            let session = agent.unwrap_or("lockyard-doctor");
            let call = lockyard_cloud_client::Call::get(session, "/api/v1/presence".into());
            match lockyard_cloud_client::Transport::call(&client, &call) {
                Ok(_) => setup::Finding::ok_check("cloud", format!("{endpoint} answers")),
                Err(error) => setup::Finding::failed("cloud", format!("{endpoint}: {error}")),
            }
        }
        Err(error) => setup::Finding::failed("cloud", error.to_string()),
    }
}

pub(super) fn doctor_output(findings: Vec<setup::Finding>) -> Result<Output> {
    let text = findings
        .iter()
        .map(|finding| {
            format!(
                "{} {:<24} {}",
                if finding.ok { "ok  " } else { "FAIL" },
                finding.check,
                finding.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let healthy = findings.iter().all(|finding| finding.ok);
    let checks: Vec<Value> = findings
        .iter()
        .map(|finding| {
            json!({
                "ok": finding.ok, "check": finding.check, "detail": finding.detail,
                "name": finding.check, "state": if finding.ok { "ok" } else { "failed" },
                "message": finding.detail,
            })
        })
        .collect();
    let network_authorization_verified = findings
        .iter()
        .any(|finding| finding.check == "cloud" && finding.ok);
    let mut out = output(
        &json!({"ok": healthy, "checks": checks, "smoke": null, "network_authorization_verified": network_authorization_verified, "build": lockyard_core::build_info()}),
        format!("Lockyard {}\n{text}", lockyard_core::BUILD_VERSION),
    )?;
    if !healthy {
        out.exit = EXIT_FAILURE;
    }
    Ok(out)
}
