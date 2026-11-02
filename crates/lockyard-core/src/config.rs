// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Project mode settings. Credentials are deliberately excluded from this file format.

use crate::{DIR_NAME, Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
        if let Ok(token) = std::env::var("LOCKYARD_TOKEN")
            && !token.trim().is_empty()
        {
            return Ok(token.trim().to_string());
        }
        if let Ok(path) = std::env::var("LOCKYARD_TOKEN_FILE") {
            let token = fs::read_to_string(path)?;
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        }
        Err(Error::Invalid(
            "cloud mode requires LOCKYARD_TOKEN or LOCKYARD_TOKEN_FILE".into(),
        ))
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
}
