// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Project mode settings. Credentials are deliberately excluded from this file format.

use crate::{DIR_NAME, Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    pub url: Option<String>,
    pub workspace: Option<String>,
    /// Stable shared identity, identical in every checkout of this repository. Omission is legacy mode.
    pub repository: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Local,
    Cloud,
}

impl Config {
    pub fn load(root: &Path) -> Result<Self> {
        let _span = crate::perf::Span::new("project.config");
        let path = root.join(DIR_NAME).join("config.toml");
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self::with_explicit_cloud(
                    Self {
                        mode: Mode::Local,
                        url: None,
                        workspace: None,
                        repository: None,
                    },
                    root,
                );
            }
            Err(error) => return Err(error.into()),
        };
        let config: Self = toml::from_str(&content)
            .map_err(|error| Error::Invalid(format!("invalid .lockyard/config.toml: {error}")))?;
        let config = Self::with_explicit_cloud(config, root)?;
        if let Some(repository) = config.repository.as_deref() {
            crate::repository::validate_id(repository)?;
        }
        if config.mode == Mode::Cloud
            && (config.url.as_deref().is_none_or(str::is_empty)
                || config.workspace.as_deref().is_none_or(str::is_empty))
        {
            return Err(Error::Invalid(
                "cloud mode requires url and workspace in .lockyard/config.toml".into(),
            ));
        }
        if config.mode == Mode::Local && (config.url.is_some() || config.workspace.is_some()) {
            return Err(Error::Invalid(
                "url and workspace are only valid in cloud mode".into(),
            ));
        }
        Ok(config)
    }

    fn with_explicit_cloud(mut config: Self, root: &Path) -> Result<Self> {
        if std::env::var_os("LOCKYARD_TOKEN_FILE").is_some_and(|p| !p.is_empty()) {
            config.mode = Mode::Cloud;
            if let Ok(url) = std::env::var("LOCKYARD_URL")
                && !url.is_empty()
            {
                config.url = Some(url);
            }
            if config.url.as_deref().is_none_or(str::is_empty) {
                // A nested local store must not hide the workspace's cloud endpoint when a
                // caller explicitly chose a cloud credential. Trust checks still apply.
                for parent in root.ancestors().skip(1) {
                    let path = parent.join(DIR_NAME).join("config.toml");
                    let Ok(text) = fs::read_to_string(path) else {
                        continue;
                    };
                    let Ok(ancestor) = toml::from_str::<Self>(&text) else {
                        continue;
                    };
                    if ancestor.mode == Mode::Cloud
                        && ancestor.url.as_deref().is_some_and(|url| !url.is_empty())
                    {
                        config.url = ancestor.url;
                        if config.workspace.is_none() {
                            config.workspace = ancestor.workspace;
                        }
                        break;
                    }
                }
            }
            config.workspace.get_or_insert_with(|| {
                std::env::var("LOCKYARD_WORKSPACE").unwrap_or_else(|_| "cloud".into())
            });
            if config.url.as_deref().is_none_or(str::is_empty) {
                return Err(Error::Invalid("explicit cloud token needs LOCKYARD_URL or a cloud URL in .lockyard/config.toml".into()));
            }
        }
        Ok(config)
    }

    /// Gets the bearer token from the environment or the named file, never from project config.
    pub fn token() -> Result<String> {
        Self::token_for("")
    }

    /// Resolve cloud access using the environment's session name. Explicit token files
    /// win, then the matching Claude session's key, then existing agent credential sources.
    /// Inline MCP bearer tokens are ignored.
    pub fn token_for(url: &str) -> Result<String> {
        let session = std::env::var("LOCKYARD_AGENT")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("CLAUDE_CODE_SESSION_ID").ok())
            .unwrap_or_default();
        Self::token_for_session(url, &session)
    }

    /// CLI and MCP pass their resolved session name through this same selector.
    pub fn token_for_session(url: &str, session: &str) -> Result<String> {
        let mut searched = Vec::new();
        if let Some((path, source)) = selected_token_file_for(url, session)? {
            let token = read_token_file(&path, source)?;
            if token.trim().is_empty() {
                return Err(Error::Invalid(format!(
                    "token file {} is empty",
                    path.display()
                )));
            }
            return Ok(token.trim().to_string());
        }
        searched.push("LOCKYARD_TOKEN_FILE (unset)".into());
        if let Ok(token) = std::env::var("LOCKYARD_TOKEN") {
            searched.push("LOCKYARD_TOKEN".into());
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        } else {
            searched.push("LOCKYARD_TOKEN (unset)".into());
        }
        if !url.is_empty() {
            let creds = crate::credentials::path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "credentials".into());
            searched.push(format!("credentials for {url} ({creds})"));
            if let Some(entry) = crate::credentials::find(url)?
                && !entry.token.trim().is_empty()
            {
                return Ok(entry.token.trim().to_string());
            }
        } else {
            searched.push("credentials (no url)".into());
        }
        if let Some(path) = default_token_file() {
            searched.push(format!("default token file {}", path.display()));
            match read_token_file(&path, TokenFileSource::DefaultAgent) {
                Ok(token) if !token.trim().is_empty() => return Ok(token.trim().to_string()),
                Ok(_) => {}
                Err(error) => {
                    searched.push(error.to_string());
                }
            }
        } else {
            searched.push("default token file (HOME unset)".into());
        }
        // Project MCP settings can point to any product's key. A downgraded
        // session or executor can only use its regular agent credential sources.
        let search_mcp = std::env::var_os("LOCKYARD_PARENT_CLAIM").is_none()
            && !executor_environment()
            && !crate::session_key::is_fallback(url, session)?;
        if search_mcp {
            for (config, token_path) in mcp_token_files(url) {
                searched.push(format!(
                    "MCP {} -> {}",
                    config.display(),
                    token_path.display()
                ));
                if let Ok(token) = read_token_file(&token_path, TokenFileSource::ExplicitEnv)
                    && !token.trim().is_empty()
                {
                    return Ok(token.trim().to_string());
                }
            }
        }
        let mcp_help = if search_mcp {
            " MCP token-file settings are searched in the project .mcp.json; \
             for the command line set LOCKYARD_TOKEN_FILE=<path shown below>."
        } else {
            ""
        };
        Err(Error::Invalid(format!(
            "no token for the cloud: run `lockyard cloud login`, or set LOCKYARD_TOKEN \
             or LOCKYARD_TOKEN_FILE.{mcp_help} Looked in: {}",
            searched.join("; ")
        )))
    }
}

/// Diagnostic category only; never contains credential values.
pub fn token_source(session: &str) -> Result<&'static str> {
    token_source_for(&std::env::var("LOCKYARD_URL").unwrap_or_default(), session)
}

pub fn token_source_for(url: &str, session: &str) -> Result<&'static str> {
    Ok(match selected_token_file_for(url, session)? {
        Some((_, TokenFileSource::Claude)) => "claude",
        Some((_, TokenFileSource::ExplicitEnv)) => "явный файл",
        _ if crate::session_key::is_fallback(url, session)? => "agent (fallback: имя занято)",
        _ => "agent",
    })
}

/// Preserve tokenless daemon access, but never hide an invalid explicitly selected key.
pub fn optional_session_token(url: &str, session: &str) -> Result<Option<String>> {
    if selected_token_file_for(url, session)?.is_some()
        || crate::session_key::is_fallback(url, session)?
    {
        Config::token_for_session(url, session).map(Some)
    } else {
        Ok(Config::token_for_session(url, session).ok())
    }
}

fn selected_token_file(session: &str) -> Result<Option<(PathBuf, TokenFileSource)>> {
    selected_token_file_in(session, MCP_SESSION.get().map(String::as_str))
}

fn selected_token_file_in(
    session: &str,
    mcp_session: Option<&str>,
) -> Result<Option<(PathBuf, TokenFileSource)>> {
    if let Some(path) = std::env::var_os("LOCKYARD_TOKEN_FILE") {
        return Ok(Some((path.into(), TokenFileSource::ExplicitEnv)));
    }
    if claude_session_eligibility(session, mcp_session).is_ok()
        && let Some(path) = claude_token_file()
    {
        match fs::metadata(&path) {
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.mode() & 0o7777 != 0o600
                        || metadata.uid() != unsafe { libc::geteuid() }
                    {
                        return Err(Error::Invalid(format!(
                            "Claude token file {} must be owned by this user with mode 0600 (LOCKYARD_CLAUDE_TOKEN_FILE)",
                            path.display()
                        )));
                    }
                }
                #[cfg(not(unix))]
                let _ = metadata;
                return Ok(Some((path, TokenFileSource::Claude)));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::Invalid(format!(
                    "cannot inspect Claude token file {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(None)
}

fn executor_environment() -> bool {
    std::env::var("FLEX_RUNNER_NESTED").as_deref() == Ok("1")
        || [
            "CODEX_SESSION_ID",
            "CODEX_THREAD_ID",
            "CODEX_TOOL_CALL_ID",
            "CURSOR_AGENT",
        ]
        .into_iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

fn claude_session_eligibility(
    session: &str,
    mcp_session: Option<&str>,
) -> std::result::Result<(), &'static str> {
    if std::env::var_os("LOCKYARD_TOKEN_FILE").is_some() {
        return Err("not selected: explicit LOCKYARD_TOKEN_FILE takes precedence");
    }
    if std::env::var_os("LOCKYARD_PARENT_CLAIM").is_some() {
        return Err("not selected: LOCKYARD_PARENT_CLAIM is set");
    }
    if executor_environment() {
        return Err("not selected: Codex or Cursor executor environment");
    }
    let claude = std::env::var_os("CLAUDE_CODE_SESSION_ID");
    if let Some(mcp_session) = mcp_session {
        if std::env::var("LOCKYARD_CLAUDE_MCP").as_deref() != Ok("1") {
            return Err(
                "not selected: set LOCKYARD_CLAUDE_MCP=1 in Claude Code .mcp.json at mcpServers.lockyard.env",
            );
        }
        if mcp_session != session || !claude_session_uuid(session) {
            return Err("not selected: MCP agent name must be the resolved session UUID");
        }
        let Some(claude) = claude.as_deref() else {
            return Err("not selected: MCP requires CLAUDE_CODE_SESSION_ID");
        };
        if claude != std::ffi::OsStr::new(session)
            || std::env::var_os("LOCKYARD_AGENT")
                .is_some_and(|name| !name.is_empty() && name != session)
        {
            return Err("not selected: CLAUDE_CODE_SESSION_ID does not match the agent name");
        }
    } else {
        match claude {
            Some(id) if !id.is_empty() && id == std::ffi::OsStr::new(session) => {}
            Some(id) if !id.is_empty() => {
                return Err("not selected: CLAUDE_CODE_SESSION_ID does not match the agent name");
            }
            _ => return Err("not selected: CLI requires nonempty CLAUDE_CODE_SESSION_ID"),
        }
    }
    Ok(())
}

/// Explain CLI or MCP selection using this environment, without disclosing its values.
/// Doctor can evaluate MCP conditions without changing the current process's channel.
pub fn claude_key_reason_for(url: &str, session: &str, mcp: bool) -> Result<&'static str> {
    let mcp_session = mcp.then_some(session);
    if let Err(reason) = claude_session_eligibility(session, mcp_session) {
        return Ok(reason);
    }
    if crate::session_key::is_fallback(url, session)? {
        return Ok("not selected: session_name_bound fallback to agent key is active");
    }
    Ok(match selected_token_file_in(session, mcp_session) {
        Ok(Some((_, TokenFileSource::Claude))) => {
            "selected: session conditions match and Claude key file is private"
        }
        Ok(_) => "not selected: Claude key file is missing",
        Err(_) => {
            "not selected: Claude key file cannot be read or is not owned by this user with mode 0600"
        }
    })
}

fn selected_token_file_for(url: &str, session: &str) -> Result<Option<(PathBuf, TokenFileSource)>> {
    // Explicit files always win, including after a previous automatic downgrade.
    if std::env::var_os("LOCKYARD_TOKEN_FILE").is_none()
        && crate::session_key::is_fallback(url, session)?
    {
        return Ok(None);
    }
    selected_token_file(session)
}

static MCP_SESSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Mark the MCP channel and capture its resolved name. Claude selection additionally
/// requires LOCKYARD_CLAUDE_MCP=1; a UUID name alone never selects the Claude key.
pub fn set_mcp_session(session: &str) {
    let _ = MCP_SESSION.set(session.to_owned());
}

fn claude_session_uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

pub fn claude_token_file() -> Option<PathBuf> {
    std::env::var_os("LOCKYARD_CLAUDE_TOKEN_FILE")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| default_token_file().map(|p| p.with_file_name("claude.token")))
}

pub fn default_agent_token() -> Result<Option<String>> {
    default_token_file()
        .filter(|path| path.exists())
        .map(|path| read_token_file(&path, TokenFileSource::DefaultAgent))
        .transpose()
}

pub fn default_token_file() -> Option<std::path::PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => std::path::PathBuf::from(path),
        _ => std::path::PathBuf::from(crate::paths::home_dir()?).join(".config"),
    };
    Some(base.join("lockyard/token"))
}

#[derive(Clone, Copy)]
enum TokenFileSource {
    Claude,
    /// `LOCKYARD_TOKEN_FILE` was set by the caller — owner-token is allowed.
    ExplicitEnv,
    /// Conventional agent path, with the same private-file checks as explicit paths.
    DefaultAgent,
}

/// Search only the current project's MCP settings. Never use an inline host secret.
pub fn session_token_files(url: &str) -> Vec<std::path::PathBuf> {
    mcp_token_files(url)
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

fn mcp_token_files(url: &str) -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
    let Ok(cwd) = std::env::current_dir() else {
        return Vec::new();
    };
    let root = crate::paths::find_root(&cwd).unwrap_or(cwd);
    let config = root.join(".mcp.json");
    let Ok(bytes) = fs::read(&config) else {
        return Vec::new();
    };
    let Ok(settings) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    let Some(servers) = settings
        .get("mcpServers")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for (name, server) in servers {
        let command = server
            .get("command")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if name != "lockyard"
            && std::path::Path::new(command)
                .file_stem()
                .and_then(|s| s.to_str())
                != Some("lockyard")
        {
            continue;
        }
        let Some(env) = server.get("env") else {
            continue;
        };
        if let Some(target) = env.get("LOCKYARD_URL").and_then(serde_json::Value::as_str)
            && target.trim_end_matches('/') != url.trim_end_matches('/')
        {
            continue;
        }
        if let Some(path) = env
            .get("LOCKYARD_TOKEN_FILE")
            .and_then(serde_json::Value::as_str)
        {
            let path = std::path::PathBuf::from(path);
            files.push((
                config.clone(),
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                },
            ));
        }
    }
    files
}

fn read_token_file(path: &Path, _source: TokenFileSource) -> Result<String> {
    #[cfg(windows)]
    return crate::windows::read_private(path, 1024 * 1024)
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })
        .map_err(|error| {
            Error::Invalid(format!(
                "cannot read token file {} (LOCKYARD_TOKEN_FILE): {error}",
                path.display()
            ))
        });
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).map_err(|error| {
            Error::Invalid(format!(
                "cannot read token file {} (LOCKYARD_TOKEN_FILE): {error}",
                path.display()
            ))
        })?;
        // The token is sent as a bearer credential. Refuse files readable by another user or
        // owned by someone else, matching the private agent-state directory policy.
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Invalid(format!(
                "token file {} must be owned by this user and private (mode 0600)",
                path.display()
            )));
        }
        fs::read_to_string(path).map_err(|error| {
            Error::Invalid(format!(
                "cannot read token file {} (LOCKYARD_TOKEN_FILE): {error}",
                path.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn absent_config_defaults_to_local_and_cloud_requires_endpoint_fields() {
        let _guard = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        assert_eq!(Config::load(dir.path()).unwrap().mode, Mode::Local);
        fs::write(
            dir.path().join(DIR_NAME).join("config.toml"),
            "mode = 'cloud'\n",
        )
        .unwrap();
        assert!(Config::load(dir.path()).is_err());
        fs::write(
            dir.path().join(DIR_NAME).join("config.toml"),
            "mode = 'cloud'\nurl = 'https://example.test'\nworkspace = 'w'\n",
        )
        .unwrap();
        assert_eq!(Config::load(dir.path()).unwrap().mode, Mode::Cloud);
    }

    #[cfg(unix)]
    #[test]
    fn token_files_readable_by_other_users_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token_file(&path, TokenFileSource::ExplicitEnv).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_token_file(&path, TokenFileSource::ExplicitEnv).unwrap(),
            "secret"
        );
    }

    #[test]
    fn missing_token_file_error_names_path_and_environment_variable() {
        let path = std::env::temp_dir().join("lockyard-token-file-that-does-not-exist");
        let error = read_token_file(&path, TokenFileSource::ExplicitEnv)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("LOCKYARD_TOKEN_FILE"));
    }

    #[test]
    fn config_rejects_credentials() {
        let _guard = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        fs::write(
            dir.path().join(DIR_NAME).join("config.toml"),
            "mode='cloud'\nurl='https://example.test'\nworkspace='w'\ntoken='secret'\n",
        )
        .unwrap();
        assert!(Config::load(dir.path()).is_err());
    }

    #[test]
    fn project_config_does_not_contain_machine_policy() {
        let _guard = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        Store::init(dir.path()).unwrap();
        fs::write(
            dir.path().join(DIR_NAME).join("config.toml"),
            "[machine]\nslots=2\n",
        )
        .unwrap();
        assert!(Config::load(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn token_for_uses_mcp_token_file_without_reading_inline_host_secret() {
        let _guard = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let cfg = dir.path().join("cfg");
        fs::create_dir_all(home.join(".config/lockyard")).unwrap();
        fs::create_dir_all(&cfg).unwrap();
        // Trap: if opened, this sentinel is observed.
        let claude = home.join(".claude.json");
        fs::write(
            &claude,
            r#"{"mcpServers":{"lockyard":{"env":{"LOCKYARD_TOKEN":"TRAP"}}}}"#,
        )
        .unwrap();
        let token_path = dir.path().join("agent.token");
        crate::fsio::replace(&token_path, b"from-mcp-trap\n", 0o600).unwrap();
        fs::write(
            dir.path().join(".mcp.json"),
            format!(
                r#"{{"mcpServers":{{"lockyard":{{"command":"lockyard","args":["mcp"],"env":{{"LOCKYARD_TOKEN_FILE":"{}"}}}}}}}}"#,
                token_path.display()
            ),
        )
        .unwrap();
        // Owner-token under the default search must not be used automatically.
        let owner = cfg.join("lockyard/owner-token");
        fs::create_dir_all(owner.parent().unwrap()).unwrap();
        crate::fsio::replace(&owner, b"owner-secret\n", 0o600).unwrap();

        let previous = std::env::current_dir().unwrap();
        let prior_token = std::env::var_os("LOCKYARD_TOKEN");
        let prior_file = std::env::var_os("LOCKYARD_TOKEN_FILE");
        let prior_creds = std::env::var_os("LOCKYARD_CREDENTIALS");
        let prior_home = std::env::var_os("HOME");
        let prior_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let claude_before = fs::metadata(&claude).unwrap().modified().unwrap();
        unsafe {
            std::env::remove_var("LOCKYARD_TOKEN");
            std::env::remove_var("LOCKYARD_TOKEN_FILE");
            std::env::set_var(
                "LOCKYARD_CREDENTIALS",
                dir.path().join("missing-credentials.toml"),
            );
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
            std::env::set_current_dir(dir.path()).unwrap();
        }
        let got = Config::token_for("https://example.test");
        let claude_after = fs::metadata(&claude).unwrap().modified().unwrap();
        // Explicit owner-token via LOCKYARD_TOKEN_FILE must still work.
        unsafe {
            std::env::set_var("LOCKYARD_TOKEN_FILE", &owner);
        }
        let explicit = Config::token_for("https://example.test");
        unsafe {
            std::env::set_current_dir(&previous).unwrap();
            match prior_token {
                Some(value) => std::env::set_var("LOCKYARD_TOKEN", value),
                None => std::env::remove_var("LOCKYARD_TOKEN"),
            }
            match prior_file {
                Some(value) => std::env::set_var("LOCKYARD_TOKEN_FILE", value),
                None => std::env::remove_var("LOCKYARD_TOKEN_FILE"),
            }
            match prior_creds {
                Some(value) => std::env::set_var("LOCKYARD_CREDENTIALS", value),
                None => std::env::remove_var("LOCKYARD_CREDENTIALS"),
            }
            match prior_home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match prior_xdg {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
        assert_eq!(got.unwrap(), "from-mcp-trap");
        assert_eq!(claude_before, claude_after);
        assert_eq!(explicit.unwrap(), "owner-secret");
    }

    #[test]
    fn token_for_error_lists_only_four_sources() {
        let _guard = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::current_dir().unwrap();
        let prior_token = std::env::var_os("LOCKYARD_TOKEN");
        let prior_file = std::env::var_os("LOCKYARD_TOKEN_FILE");
        let prior_creds = std::env::var_os("LOCKYARD_CREDENTIALS");
        let prior_home = std::env::var_os("XDG_CONFIG_HOME");
        unsafe {
            std::env::remove_var("LOCKYARD_TOKEN");
            std::env::remove_var("LOCKYARD_TOKEN_FILE");
            std::env::set_var(
                "LOCKYARD_CREDENTIALS",
                dir.path().join("missing-credentials.toml"),
            );
            std::env::set_var("XDG_CONFIG_HOME", dir.path().join("cfg"));
            std::env::set_current_dir(dir.path()).unwrap();
        }
        let error = Config::token_for("https://example.test")
            .unwrap_err()
            .to_string();
        unsafe {
            std::env::set_current_dir(&previous).unwrap();
            match prior_token {
                Some(value) => std::env::set_var("LOCKYARD_TOKEN", value),
                None => std::env::remove_var("LOCKYARD_TOKEN"),
            }
            match prior_file {
                Some(value) => std::env::set_var("LOCKYARD_TOKEN_FILE", value),
                None => std::env::remove_var("LOCKYARD_TOKEN_FILE"),
            }
            match prior_creds {
                Some(value) => std::env::set_var("LOCKYARD_CREDENTIALS", value),
                None => std::env::remove_var("LOCKYARD_CREDENTIALS"),
            }
            match prior_home {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
        assert!(error.contains("Looked in:"), "{error}");
        let looked = error.split("Looked in: ").nth(1).unwrap_or("");
        assert!(looked.contains("LOCKYARD_TOKEN"), "{error}");
        assert!(looked.contains("LOCKYARD_TOKEN_FILE"), "{error}");
        assert!(looked.contains("credentials"), "{error}");
        assert!(looked.contains("default token file"), "{error}");
        assert!(!looked.contains(".mcp.json"), "{error}");
        assert!(!looked.contains("agent unit"), "{error}");
        assert!(!looked.contains(".claude.json"), "{error}");
    }

    #[test]
    fn token_file_name_does_not_change_explicit_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner-token");
        crate::fsio::replace(&path, b"secret", 0o600).unwrap();
        assert_eq!(
            read_token_file(&path, TokenFileSource::DefaultAgent).unwrap(),
            "secret"
        );
        assert_eq!(
            read_token_file(&path, TokenFileSource::ExplicitEnv).unwrap(),
            "secret"
        );
    }
}
