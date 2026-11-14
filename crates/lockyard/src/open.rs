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

    /// Task paths use the same resolver as claims, anchored at the workspace root.
    pub fn task_paths(&self, raw: &[String]) -> Result<Vec<String>> {
        if raw.len() > 64 {
            return Err(Error::Invalid("a task accepts at most 64 paths".into()));
        }
        let slashed: Vec<String> = raw.iter().map(|path| path.replace('\\', "/")).collect();
        let mut paths = self.zone_paths(&self.root, &slashed)?;
        if paths.iter().any(|path| path.chars().count() > 512) {
            return Err(Error::Invalid(
                "each task path must be at most 512 characters".into(),
            ));
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
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
            lockyard_core::paths::home_dir()
                .ok_or_else(|| Error::Invalid("HOME is not set".into()))?,
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

/// A status-specific open: probing an old or unresponsive daemon must not consume the command's
/// deadline. Reads use its existing authenticated connection pool when the aggregate is supported.
///
/// Open mail is derived on the same backend after the mandatory status reads when time remains,
/// so status does not open a second cloud client. An agent aggregate carries `StatusRead.open_mail`
/// computed by the daemon on its warm client.
pub(crate) fn status_read(
    cwd: &Path,
    session: &str,
    deadline: std::time::Instant,
) -> Result<(
    PathBuf,
    bool,
    lockyard_core::StatusRead,
    Option<crate::open_mail::OpenMailSnapshot>,
)> {
    use std::time::Instant;
    let _span = lockyard_core::perf::Span::new("status.open_and_read");
    let root = find_root(cwd).ok_or(Error::NoProject)?;
    let config = Config::load(&root)?;
    let left = || deadline.saturating_duration_since(Instant::now());
    if config.mode == Mode::Local {
        let store = Store::open(&root)?;
        let read = store.status_read(session, crate::now_ms(), left())?;
        let budget = left()
            .saturating_sub(std::time::Duration::from_millis(50))
            .min(crate::open_mail::SENT_BUDGET);
        let open_mail = if budget.is_zero() {
            None
        } else {
            crate::open_mail::open_mail_within(&store, session, crate::now_ms(), budget)
        };
        return Ok((root, false, read, open_mail));
    }
    let (url, workspace) = endpoint(&config)?;
    let token = Config::token_for(&url).ok();
    let expected_token = token.as_deref().map(token_id);
    // Preserve the direct-client encryption attestation used by ordinary opens.
    if std::env::var_os("LOCKYARD_REQUIRE_E2EE").is_none()
        && std::env::var_os("LOCKYARD_E2EE_WORKSPACE_ID").is_none()
    {
        let probe = status_probe_budget(left());
        if !probe.is_zero()
            && let Some(socket) = crate::agent::socket::AgentSocket::connect_status(
                &crate::agent::socket_path_for(&url, &workspace),
                &url,
                &workspace,
                expected_token.as_deref(),
                probe,
            )
        {
            // Spend at most one quarter of what remains on the aggregate, capped at the warm
            // route's existing 1500 ms. At least three quarters remain for ONE cold claims-first
            // fallback; a hung agent never consumes a fixed 1500 ms out of a shortened budget.
            let budget = status_agent_budget(left());
            match socket.status_read(session, config.repository.as_deref(), budget) {
                Ok(mut read) => {
                    read.freshness["via"] = serde_json::json!("agent");
                    let open_mail =
                        read.open_mail
                            .as_ref()
                            .map(|items| crate::open_mail::OpenMailSnapshot {
                                items: items.clone(),
                                truncated: read
                                    .freshness
                                    .get("open_mail_truncated")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                            });
                    return Ok((root, true, read, open_mail));
                }
                Err(lockyard_cloud_client::ClientError::Transport(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    if left().is_zero() {
        return Err(Error::Unavailable(
            "status deadline elapsed before direct fallback".into(),
        ));
    }
    trusted_url(&url)?;
    let client = journal_client(Client::new(&url, Config::token_for(&url)?)?)?
        .with_status_protocol_cache()
        .configure_content_encryption_with_deadline(session, left())?;
    let backend = CloudBackend::new(
        RepositoryTransport::new(client, config.repository.as_deref())?,
        session,
    );
    let mut read = backend.status_read(session, crate::now_ms(), left())?;
    read.freshness["via"] = serde_json::json!("direct");
    // After a cold-agent fallback the outer deadline may already be nearly spent. Require
    // comfortable headroom and cap the optional peek so bad-link latency cannot fail status.
    let remaining = left();
    let open_mail = if remaining < std::time::Duration::from_millis(800) {
        None
    } else {
        let budget = remaining
            .saturating_sub(std::time::Duration::from_millis(200))
            .min(std::time::Duration::from_millis(300));
        crate::open_mail::open_mail_within(&backend, session, crate::now_ms(), budget)
    };
    Ok((root, true, read, open_mail))
}

fn status_probe_budget(left: std::time::Duration) -> std::time::Duration {
    left.div_f64(20.0)
        .min(std::time::Duration::from_millis(100))
}

fn status_agent_budget(left: std::time::Duration) -> std::time::Duration {
    (left / 4).min(std::time::Duration::from_millis(1500))
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
        .or_else(|| {
            lockyard_core::paths::home_dir().map(|home| PathBuf::from(home).join(".local/state"))
        })
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
    let socket = AgentSocket::connect(
        &crate::agent::socket_path_for(&url, &workspace),
        &url,
        &workspace,
        CLI_TIMEOUT,
    );
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
    use super::{Opened, status_agent_budget, status_probe_budget, url_matches};
    use std::time::Duration;

    #[test]
    fn task_paths_reuse_claim_resolution_with_workspace_slashes_and_limits() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let backend = Box::new(lockyard_core::Store::init(&root).unwrap());
        let opened = Opened {
            root: root.clone(),
            backend,
        };
        let paths = opened
            .task_paths(&[
                r"platform\src\login.rs".into(),
                "./platform/src/../src//login.rs".into(),
                root.join("platform/new.rs").to_str().unwrap().into(),
            ])
            .unwrap();
        assert_eq!(paths, vec!["platform/new.rs", "platform/src/login.rs"]);
        assert!(opened.task_paths(&["../outside.rs".into()]).is_err());
        assert!(opened.task_paths(&[String::new()]).is_err());
        assert!(opened.task_paths(&vec!["platform/x".into(); 65]).is_err());
        assert!(
            opened
                .task_paths(&[format!("platform/{}", "x".repeat(512))])
                .is_err()
        );
        assert!(opened.task_paths(&[]).unwrap().is_empty());
    }

    #[test]
    fn status_fallback_reserves_three_quarters_of_remaining_budget() {
        for millis in [0, 20, 100, 850, 1500, 2800, 5940, 10000] {
            let left = Duration::from_millis(millis);
            let probe = status_probe_budget(left);
            assert!(probe <= left / 20);
            assert!(probe <= Duration::from_millis(100));
            let after_probe = left.saturating_sub(probe);
            let aggregate = status_agent_budget(after_probe);
            assert!(aggregate <= after_probe / 4);
            assert!(aggregate <= Duration::from_millis(1500));
            assert!(after_probe - aggregate >= after_probe.mul_f64(0.75));
        }
        let after_probe = Duration::from_millis(5940 - 100);
        assert_eq!(
            status_agent_budget(after_probe),
            Duration::from_millis(1460)
        );
        assert_eq!(
            after_probe - status_agent_budget(after_probe),
            Duration::from_millis(4380)
        );
    }

    #[test]
    fn a_project_url_must_match_the_user_trust_url() {
        assert!(url_matches("https://one.test/", "https://one.test"));
        assert!(!url_matches("", "https://one.test"));
        assert!(!url_matches("https://one.test", "https://two.test"));
    }
}
