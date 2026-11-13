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
    let project = || -> Result<(PathBuf, Config)> {
        let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
        let config = Config::load(&root)?;
        if config.mode != Mode::Cloud {
            return Err(Error::needs_cloud("lockyard agent"));
        }
        Ok((root, config))
    };
    #[cfg(windows)]
    if args.service_token_file.is_some() && args.command.is_some() {
        return Err(Error::Invalid(
            "--service-token-file only applies to the running agent".into(),
        ));
    }
    match args.command {
        None => {
            let _shutdown = crate::shutdown::Guard::new(cwd)?;
            let (_, config) = project()?;
            let (url, workspace) = open::endpoint(&config)?;
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
            #[cfg(unix)]
            let socket = agent::socket_path();
            #[cfg(windows)]
            let socket = {
                let (_, config) = project()?;
                let (url, workspace) = open::endpoint(&config)?;
                agent::socket_path_for(&url, &workspace)
            };
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
