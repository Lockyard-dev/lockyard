// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Picks the one backend of a project from `.lockyard/config.toml`.

use lockyard_cloud_client::{Client, CloudBackend, RepositoryTransport, token_id};
use lockyard_core::config::{Config, Mode};
use lockyard_core::paths::find_root;
use lockyard_core::{Backend, Error, Result, Store, ZonePath};
use std::path::{Path, PathBuf};
use std::{fs, io::Write};

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

pub(crate) fn trusted_url(url: &str) -> Result<()> {
    let trusted = std::env::var("LOCKYARD_URL").unwrap_or_default();
    if url_matches(&trusted, url) || trusted_file_contains(url)? {
        return Ok(());
    }
    Err(Error::Invalid(format!(
        "server {url} is not trusted; run `lockyard cloud trust {url}` before sending a token there"
    )))
}

fn trusted_file() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| Error::Invalid("HOME is not set".into()))?,
        )
        .join(".config"),
    };
    Ok(base.join("lockyard/trusted-servers"))
}

fn trusted_file_contains(url: &str) -> Result<bool> {
    let path = trusted_file()?;
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(contents.lines().any(|line| url_matches(line.trim(), url)))
}

pub(crate) fn trust_url(url: &str) -> Result<()> {
    if url.is_empty() || url.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "a trusted server URL must be one non-empty line".into(),
        ));
    }
    let path = trusted_file()?;
    let parent = path.parent().expect("trusted server file has parent");
    fs::create_dir_all(parent)?;
    if trusted_file_contains(url)? {
        return Ok(());
    }
    let existing = match fs::read(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if existing.last().is_some_and(|byte| *byte != b'\n') {
        file.write_all(b"\n")?;
    }
    file.write_all(url.as_bytes())?;
    file.write_all(b"\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn url_matches(trusted: &str, url: &str) -> bool {
    !trusted.is_empty() && trusted.trim_end_matches('/') == url.trim_end_matches('/')
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

fn direct(url: &str, session: &str, repository: Option<&str>) -> Result<Box<dyn Backend>> {
    trusted_url(url)?;
    let client = journal_client(Client::new(url, Config::token_for(url)?)?)?
        .configure_content_encryption(session)?;
    Ok(Box::new(CloudBackend::new(
        RepositoryTransport::new(client, repository)?,
        session,
    )))
}

/// Freeze wire writes privately before the network so a process restart cannot re-encrypt a pending key.
pub(crate) fn journal_client(client: Client) -> Result<Client> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| Error::Invalid("private state directory is unavailable".into()))?;
    let mut directories = fs::DirBuilder::new();
    directories.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directories.mode(0o700);
    }
    directories.create(&state)?;
    let state = state.canonicalize()?;
    Ok(client.with_pending_journal(state.join("lockyard/pending-writes"))?)
}

/// A trusted direct client for workspace administration commands.
pub(crate) fn direct_client(url: &str) -> Result<Client> {
    trusted_url(url)?;
    journal_client(Client::new(url, Config::token_for(url)?)?)
}

#[cfg(unix)]
fn cloud(config: &Config, session: &str) -> Result<Box<dyn Backend>> {
    use crate::agent::socket::AgentSocket;
    use std::time::Duration;
    /// Long enough for a long poll passed through the agent.
    const CLI_TIMEOUT: Duration = Duration::from_secs(40);
    let (url, workspace) = endpoint(config)?;
    // Legacy agent handshakes identify the URL/token but don't attest an encryption
    // policy or key binding. Node jobs must use their own verified client context.
    if std::env::var_os("LOCKYARD_REQUIRE_E2EE").is_some()
        || std::env::var_os("LOCKYARD_E2EE_WORKSPACE_ID").is_some()
    {
        return direct(&url, session, config.repository.as_deref());
    }
    let socket = AgentSocket::connect(&crate::agent::socket_path(), &url, &workspace, CLI_TIMEOUT);
    let token = Config::token_for(&url).ok();
    match socket {
        // An agent running under another token would act with that token's role.
        Some(socket)
            if token
                .as_deref()
                .is_none_or(|token| socket.token_id().is_ok_and(|id| id == token_id(token))) =>
        {
            Ok(Box::new(CloudBackend::new(
                RepositoryTransport::new(socket, config.repository.as_deref())?,
                session,
            )))
        }
        _ => direct(&url, session, config.repository.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::url_matches;

    #[test]
    fn a_project_url_must_match_the_user_trust_url() {
        assert!(url_matches("https://one.test/", "https://one.test"));
        assert!(!url_matches("", "https://one.test"));
        assert!(!url_matches("https://one.test", "https://two.test"));
    }
}

#[cfg(not(unix))]
fn cloud(config: &Config, session: &str) -> Result<Box<dyn Backend>> {
    let (url, _) = endpoint(config)?;
    direct(&url, session, config.repository.as_deref())
}
