// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Picks the one backend of a project from `.lockyard/config.toml`.

use lockyard_cloud_client::{Client, CloudBackend};
use lockyard_core::config::{Config, Mode};
use lockyard_core::paths::find_root;
use lockyard_core::{Backend, Error, Result, Store, ZonePath};
use std::path::{Path, PathBuf};

/// Session name of a call that names no agent.
const ANONYMOUS: &str = "lockyard-cli";

/// A project and its backend.
pub struct Opened {
    pub backend: Box<dyn Backend>,
    pub root: PathBuf,
}

impl Opened {
    /// Reads a raw path as a project path.
    pub fn zone_path(&self, cwd: &Path, raw: &str) -> Result<String> {
        let path = ZonePath::resolve(&self.root, cwd, raw)?
            .ok_or_else(|| Error::Invalid(format!("{raw} is outside this project")))?;
        Ok(path.as_str().to_string())
    }

    /// Reads raw paths as project paths.
    pub fn zone_paths(&self, cwd: &Path, raw: &[String]) -> Result<Vec<String>> {
        raw.iter().map(|path| self.zone_path(cwd, path)).collect()
    }
}

/// The URL and label of a cloud project. `load` already refused a config without them.
pub fn endpoint(config: &Config) -> Result<(String, String)> {
    match (&config.url, &config.workspace) {
        (Some(url), Some(workspace)) => Ok((url.clone(), workspace.clone())),
        _ => Err(Error::Invalid(
            "cloud mode requires url and workspace in .lockyard/config.toml".into(),
        )),
    }
}

/// Opens the project that contains `cwd`.
pub fn open(cwd: &Path, agent: Option<&str>) -> Result<Opened> {
    let root = find_root(cwd).ok_or(Error::NoProject)?;
    let config = Config::load(&root)?;
    let session = agent.unwrap_or(ANONYMOUS);
    let backend: Box<dyn Backend> = match config.mode {
        Mode::Local => Box::new(Store::open(&root)?),
        Mode::Cloud => cloud(&config, session)?,
    };
    Ok(Opened { backend, root })
}

fn direct(url: &str, session: &str) -> Result<Box<dyn Backend>> {
    let client = Client::new(url, Config::token()?)?;
    Ok(Box::new(CloudBackend::new(client, session)))
}

#[cfg(unix)]
fn cloud(config: &Config, session: &str) -> Result<Box<dyn Backend>> {
    use crate::agent::socket::AgentSocket;
    use std::time::Duration;
    /// Long enough for a long poll passed through the agent.
    const CLI_TIMEOUT: Duration = Duration::from_secs(40);
    let (url, workspace) = endpoint(config)?;
    match AgentSocket::connect(&crate::agent::socket_path(), &url, &workspace, CLI_TIMEOUT) {
        Some(socket) => Ok(Box::new(CloudBackend::new(socket, session))),
        None => direct(&url, session),
    }
}

#[cfg(not(unix))]
fn cloud(config: &Config, session: &str) -> Result<Box<dyn Backend>> {
    direct(&endpoint(config)?.0, session)
}
