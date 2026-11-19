// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// Inside a hook the event names the session, so only an explicit name overrides it.
pub(super) fn env_agent_explicit() -> Option<String> {
    env_lockyard_agent()
}

pub(super) fn env_lockyard_agent() -> Option<String> {
    std::env::var("LOCKYARD_AGENT")
        .ok()
        .filter(|value| !value.is_empty())
}

use agent::daemon::CredentialProduct;

fn credential_product(actor: &Value) -> CredentialProduct {
    if actor["role"].as_str() != Some("agent") {
        return CredentialProduct::Unknown;
    }
    // Older servers expose Claude through the authenticated acceptance permission.
    if actor["can_accept_review"] == true {
        return CredentialProduct::Claude;
    }
    match actor["product"]
        .as_str()
        .or_else(|| actor["review_product"].as_str())
    {
        Some("agent") => CredentialProduct::Agent,
        Some("claude") => CredentialProduct::Claude,
        // The production actor DTO omits product and returns an explicit permission.
        None if actor["product"].is_null()
            && actor["review_product"].is_null()
            && actor["can_accept_review"] == false =>
        {
            CredentialProduct::Agent
        }
        _ => CredentialProduct::Unknown,
    }
}

pub(super) fn run_agent(args: AgentArgs, cwd: &Path) -> Result<Output> {
    use agent::daemon::{AgentConfig, Daemon};
    use agent::service;
    use agent::socket::AgentSocket;
    use lockyard_cloud_client::Client;
    use lockyard_core::config::{Config, Mode};
    #[cfg(windows)]
    if args.service_token_file.is_some() && args.command.is_some() {
        return Err(Error::Invalid(
            "--service-token-file only applies to the running agent".into(),
        ));
    }
    match args.command {
        None => {
            let _shutdown = crate::shutdown::Guard::new(cwd)?;
            // An explicit manual target wins; service starts without --root read only the copy.
            // Neither path writes the installed service's settings.
            let snapshot = if let Some(root) = args.root.as_deref() {
                project_snapshot(root)?
            } else {
                service::load_agent_config().or_else(|error| {
                    let project_cwd = std::env::var_os("LOCKYARD_AGENT_ROOT")
                        .filter(|value| !value.is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| cwd.to_path_buf());
                    if lockyard_core::paths::find_root(&project_cwd).is_none() {
                        return Err(error);
                    }
                    project_snapshot(&project_cwd)
                })?
            };
            let url = snapshot.url;
            let workspace = snapshot.workspace;
            open::trusted_url(&url)?;
            let session = crate::env_agent().unwrap_or_default();
            #[cfg(unix)]
            let client = Client::for_session(&url, &session, None)?;
            #[cfg(windows)]
            let client = match args.service_token_file.as_deref() {
                Some(path) => Client::new(&url, service::read_service_token(path)?)?,
                None => Client::for_session(&url, &session, None)?,
            };
            let actor = open::credential_actor(&client, Duration::from_millis(500));
            let product = actor
                .as_ref()
                .map_or(CredentialProduct::Unknown, credential_product);
            let token_id = client.credential_id();
            let credential_proof = (product != CredentialProduct::Agent)
                .then(|| crate::agent::wire::CredentialProof(client.ipc_credential_proof()));
            let mut client = agent_client(open::journal_client(client)?)?
                .with_live_write_encryption_policy()
                .reconcile_pending_on_startup()?;
            // Includes upkeep and long polls. The bounded client explicitly reserves one worker
            // for writes and one for event long polls; general reads share the remaining six.
            client.set_http_worker_limit(8);
            let socket = agent::socket_path_for(&url, &workspace);
            let settings = AgentConfig {
                url,
                workspace,
                token_id,
                credential_proof,
                credential_product: product,
                socket,
                state_root: agent::state_root()?,
                timing: Default::default(),
            };
            Daemon::start(settings, client)?.wait();
            output(&Value::Null, "")
        }
        Some(command) => {
            // Install/status/uninstall: --root or cwd only — never LOCKYARD_AGENT_ROOT.
            let project_cwd = args.root.clone().unwrap_or_else(|| cwd.to_path_buf());
            let project = || -> Result<(PathBuf, Config)> {
                let root = lockyard_core::paths::find_root(&project_cwd).ok_or(Error::NoProject)?;
                let config = Config::load(&root)?;
                if config.mode != Mode::Cloud {
                    return Err(Error::needs_cloud("lockyard agent"));
                }
                Ok((root, config))
            };
            match command {
                AgentCommand::Install { no_start } => {
                    let (root, config) = project()?;
                    let path = service::install(&root, &config, !no_start)?;
                    let shown = path.display().to_string();
                    output(&json!({"unit": shown}), format!("installed {shown}"))
                }
                AgentCommand::Uninstall { no_start } => {
                    let path = service::uninstall(!no_start)?;
                    let shown = path.display().to_string();
                    output(&json!({"unit": shown}), format!("removed {shown}"))
                }
                AgentCommand::Status => {
                    let installed = service::installed()?;
                    #[cfg(unix)]
                    let socket = agent::socket_path();
                    #[cfg(windows)]
                    let socket = {
                        let snapshot = status_snapshot(&project_cwd)?;
                        agent::socket_path_for(&snapshot.url, &snapshot.workspace)
                    };
                    let stale = service::load_agent_config()
                        .ok()
                        .filter(service::agent_config_stale);
                    match AgentSocket::status(&socket, Duration::from_secs(1)) {
                        Ok(status) => {
                            let age = status
                                .view_age_ms
                                .map_or("none".to_string(), |ms| format!("{ms} ms"));
                            let mut text = format!(
                                "running, pid {}, workspace {}, view age {age}, outbox {}, rejected {}",
                                status.pid, status.workspace, status.outbox, status.rejected
                            );
                            let mut data = json!({
                                "running": true,
                                "installed": installed,
                                "status": status
                            });
                            if stale.is_some() {
                                text.push_str(
                                    "\nagent-config.toml older than project config — run `lockyard agent install`",
                                );
                                data["agent_config_stale"] = json!(true);
                            }
                            output(&data, text)
                        }
                        Err(_) => {
                            let hint = if !socket.exists() {
                                service::socket_missing_hint(&socket)
                            } else {
                                None
                            };
                            let mut text = format!(
                                "not running, unit {}",
                                if installed {
                                    "installed"
                                } else {
                                    "not installed"
                                }
                            );
                            if let Some(hint) = hint {
                                text.push('\n');
                                text.push_str(hint);
                            }
                            if stale.is_some() {
                                text.push_str(
                                    "\nagent-config.toml older than project config — run `lockyard agent install`",
                                );
                            }
                            let mut data = json!({"running": false, "installed": installed});
                            if hint.is_some() {
                                data["socket_missing_hint"] = json!(true);
                            }
                            if stale.is_some() {
                                data["agent_config_stale"] = json!(true);
                            }
                            output(&data, text)
                        }
                    }
                }
            }
        }
    }
}

/// Read a manual project's target without updating the installed service snapshot.
fn project_snapshot(cwd: &Path) -> Result<agent::service::AgentServiceConfig> {
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let config = lockyard_core::config::Config::load(&root)?;
    if config.mode != lockyard_core::config::Mode::Cloud {
        return Err(Error::needs_cloud("lockyard agent"));
    }
    let (url, workspace) = open::endpoint(&config)?;
    Ok(agent::service::AgentServiceConfig {
        url,
        workspace,
        repository: config.repository,
        project_root: root.display().to_string(),
        project_config_mtime: None,
    })
}

#[cfg(windows)]
fn status_snapshot(cwd: &Path) -> Result<agent::service::AgentServiceConfig> {
    agent::service::load_agent_config().or_else(|_| project_snapshot(cwd))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn status_without_installed_copy_uses_project_target() {
        // Run this assertion in a child so its private XDG state cannot race other tests.
        const CHILD: &str = "LOCKYARD_TEST_STATUS_NO_COPY";
        if let Some(root) = std::env::var_os(CHILD) {
            let snapshot = status_snapshot(Path::new(&root)).unwrap();
            assert_eq!(snapshot.workspace, "manual-status-test");
            assert_eq!(snapshot.url, "http://127.0.0.1:1");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".lockyard")).unwrap();
        std::fs::write(
            dir.path().join(".lockyard/config.toml"),
            "mode = 'cloud'\nurl = 'http://127.0.0.1:1'\nworkspace = 'manual-status-test'\n",
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli_agent::windows_tests::status_without_installed_copy_uses_project_target",
            ])
            .env(CHILD, dir.path())
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child filter skipped regression: {output:?}"
        );
        assert!(!dir.path().join("state/lockyard/agent-config.toml").exists());
    }
}
