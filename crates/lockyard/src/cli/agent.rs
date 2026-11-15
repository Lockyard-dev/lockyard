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
            // Prefer agent-config.toml so a unit never opens the project tree (LY-0007).
            // When the copy is missing, inspect cwd/--root only for a clear local-mode error.
            let snapshot = match service::load_agent_config() {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    // Units always have the copy after `agent install`. Manual/dev starts may
                    // still launch from a cloud project; local mode keeps the old needs-cloud text.
                    let project_cwd = args
                        .root
                        .clone()
                        .or_else(|| {
                            std::env::var_os("LOCKYARD_AGENT_ROOT")
                                .filter(|value| !value.is_empty())
                                .map(PathBuf::from)
                        })
                        .unwrap_or_else(|| cwd.to_path_buf());
                    let Some(root) = lockyard_core::paths::find_root(&project_cwd) else {
                        return Err(error);
                    };
                    let config = Config::load(&root)?;
                    if config.mode != Mode::Cloud {
                        return Err(Error::needs_cloud("lockyard agent"));
                    }
                    let (url, workspace) = open::endpoint(&config)?;
                    service::AgentServiceConfig {
                        url,
                        workspace,
                        repository: config.repository.clone(),
                        project_root: root.display().to_string(),
                        project_config_mtime: None,
                    }
                }
            };
            let url = snapshot.url;
            let workspace = snapshot.workspace;
            open::trusted_url(&url)?;
            #[cfg(unix)]
            let token = Config::token_for(&url)?;
            #[cfg(windows)]
            let token = match args.service_token_file.as_deref() {
                Some(path) => service::read_service_token(path)?,
                None => Config::token_for(&url)?,
            };
            let token_id = lockyard_cloud_client::token_id(&token);
            let mut client = agent_client(open::journal_client(Client::new(&url, token)?)?)?;
            // Includes upkeep and long polls. The bounded client explicitly reserves one worker
            // for writes and one for event long polls; general reads share the remaining six.
            client.set_http_worker_limit(8);
            let socket = agent::socket_path_for(&url, &workspace);
            let settings = AgentConfig {
                url,
                workspace,
                token_id,
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
                        let snapshot = service::load_agent_config()?;
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
