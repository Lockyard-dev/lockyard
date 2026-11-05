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
        let path = root.join(DIR_NAME).join("config.toml");
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    mode: Mode::Local,
                    url: None,
                    workspace: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let config: Self = toml::from_str(&content)
            .map_err(|error| Error::Invalid(format!("invalid .lockyard/config.toml: {error}")))?;
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

    /// The same, falling back to the token `lockyard cloud login` stored for this server.
    ///
    /// The environment still wins, so a CI job that exports `LOCKYARD_TOKEN` is unaffected by
    /// whatever a developer happens to be logged in to on the same machine.
    pub fn token_for(url: &str) -> Result<String> {
        if let Ok(token) = std::env::var("LOCKYARD_TOKEN")
            && !token.trim().is_empty()
        {
            return Ok(token.trim().to_string());
        }
        if let Ok(path) = std::env::var("LOCKYARD_TOKEN_FILE") {
            let token = read_token_file(Path::new(&path))?;
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        }
        if !url.is_empty()
            && let Some(entry) = crate::credentials::find(url)?
            && !entry.token.trim().is_empty()
        {
            return Ok(entry.token.trim().to_string());
        }
        Err(Error::Invalid(
            "no token for the cloud: run `lockyard cloud login`, or set LOCKYARD_TOKEN \
             or LOCKYARD_TOKEN_FILE"
                .into(),
        ))
    }
}

fn read_token_file(path: &Path) -> Result<String> {
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
    }
    fs::read_to_string(path).map_err(|error| {
        Error::Invalid(format!(
            "cannot read token file {} (LOCKYARD_TOKEN_FILE): {error}",
            path.display()
        ))
    })
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
        assert!(read_token_file(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token_file(&path).unwrap(), "secret");
    }

    #[test]
    fn missing_token_file_error_names_path_and_environment_variable() {
        let path = std::env::temp_dir().join("lockyard-token-file-that-does-not-exist");
        let error = read_token_file(&path).unwrap_err().to_string();
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
}
