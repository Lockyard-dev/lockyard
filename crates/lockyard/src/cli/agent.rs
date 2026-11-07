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

#[cfg(unix)]
pub(super) fn run_agent(args: AgentArgs, cwd: &Path) -> Result<Output> {
    use agent::daemon::{AgentConfig, Daemon};
    use agent::service;
    use agent::socket::AgentSocket;
    use lockyard_cloud_client::Client;
    use lockyard_core::config::{Config, Mode};
    let project = || -> Result<(PathBuf, Config)> {
        let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
        let config = Config::load(&root)?;
        if config.mode != Mode::Cloud {
            return Err(Error::needs_cloud("lockyard agent"));
        }
        Ok((root, config))
    };
    match args.command {
        None => {
            let (_, config) = project()?;
            let (url, workspace) = open::endpoint(&config)?;
            open::trusted_url(&url)?;
            let token = Config::token_for(&url)?;
            let token_id = lockyard_cloud_client::token_id(&token);
            let client = agent_client(Client::new(&url, token)?)?;
            let settings = AgentConfig {
                url,
                workspace,
                token_id,
                socket: agent::socket_path(),
                state_root: agent::state_root()?,
                timing: Default::default(),
            };
            Daemon::start(settings, client)?.wait();
            output(&Value::Null, "")
        }
        Some(AgentCommand::Install { no_start }) => {
            let (root, _) = project()?;
            let path = service::install(&root, !no_start)?;
            let shown = path.display().to_string();
            output(&json!({"unit": shown}), format!("installed {shown}"))
        }
        Some(AgentCommand::Uninstall { no_start }) => {
            let path = service::uninstall(!no_start)?;
            let shown = path.display().to_string();
            output(&json!({"unit": shown}), format!("removed {shown}"))
        }
        Some(AgentCommand::Status) => {
            let installed = service::installed()?;
            let socket = agent::socket_path();
            match AgentSocket::status(&socket, Duration::from_secs(1)) {
                Ok(status) => {
                    let age = status
                        .view_age_ms
                        .map_or("none".to_string(), |ms| format!("{ms} ms"));
                    let text = format!(
                        "running, pid {}, workspace {}, view age {age}, outbox {}, rejected {}",
                        status.pid, status.workspace, status.outbox, status.rejected
                    );
                    output(
                        &json!({"running": true, "installed": installed, "status": status}),
                        text,
                    )
                }
                Err(_) => output(
                    &json!({"running": false, "installed": installed}),
                    format!(
                        "not running, unit {}",
                        if installed {
                            "installed"
                        } else {
                            "not installed"
                        }
                    ),
                ),
            }
        }
    }
}

#[cfg(not(unix))]
pub(super) fn run_agent(_: AgentArgs, _: &Path) -> Result<Output> {
    Err(Error::Invalid("lockyard agent needs a Unix socket".into()))
}
