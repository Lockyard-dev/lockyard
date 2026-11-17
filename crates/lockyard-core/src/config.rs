// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Project mode settings. Credentials are deliberately excluded from this file format.

use crate::{DIR_NAME, Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

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
                return Ok(Self {
                    mode: Mode::Local,
                    url: None,
                    workspace: None,
                    repository: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let config: Self = toml::from_str(&content)
            .map_err(|error| Error::Invalid(format!("invalid .lockyard/config.toml: {error}")))?;
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

    /// Gets the bearer token from the environment or the named file, never from project config.
    pub fn token() -> Result<String> {
        Self::token_for("")
    }

    /// Resolve cloud access: explicit env, login credentials, default token, then the
    /// current project's MCP token-file setting. Inline MCP bearer tokens are ignored.
    pub fn token_for(url: &str) -> Result<String> {
        let mut searched = Vec::new();
        if let Ok(token) = std::env::var("LOCKYARD_TOKEN") {
            searched.push("LOCKYARD_TOKEN".into());
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        } else {
            searched.push("LOCKYARD_TOKEN (unset)".into());
        }
        if let Ok(path) = std::env::var("LOCKYARD_TOKEN_FILE") {
            searched.push(format!("LOCKYARD_TOKEN_FILE={path}"));
            // Explicit LOCKYARD_TOKEN_FILE may name owner-token; that is a deliberate human choice.
            let token = read_token_file(Path::new(&path), TokenFileSource::ExplicitEnv)?;
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        } else {
            searched.push("LOCKYARD_TOKEN_FILE (unset)".into());
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
        Err(Error::Invalid(format!(
            "no token for the cloud: run `lockyard cloud login`, or set LOCKYARD_TOKEN \
             or LOCKYARD_TOKEN_FILE. MCP token-file settings are searched in the project .mcp.json; \
             for the command line set LOCKYARD_TOKEN_FILE=<path shown below>. \
             Looked in: {}",
            searched.join("; ")
        )))
    }
}

fn default_token_file() -> Option<std::path::PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => std::path::PathBuf::from(path),
        _ => std::path::PathBuf::from(crate::paths::home_dir()?).join(".config"),
    };
    Some(base.join("lockyard/token"))
}

#[derive(Clone, Copy)]
enum TokenFileSource {
    /// `LOCKYARD_TOKEN_FILE` was set by the caller — owner-token is allowed.
    ExplicitEnv,
    /// Conventional agent path, with the same private-file checks as explicit paths.
    DefaultAgent,
}

/// Search only the current project's MCP settings. Never use an inline host secret.
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
