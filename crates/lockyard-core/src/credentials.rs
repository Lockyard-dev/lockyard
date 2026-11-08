// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Where a token lives between runs, once `lockyard cloud login` has one.
//!
//! One file for the whole machine, next to the trusted-server list, keyed by server URL so two
//! workspaces on two servers do not overwrite each other. It is a credential, so it is written
//! and read as `0600` and never copied into a project: `.lockyard/config.toml` still refuses a
//! `token` field.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// One server a user is logged in to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub url: String,
    pub token: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub role: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    servers: BTreeMap<String, Server>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Server {
    token: String,
    #[serde(default)]
    workspace_id: String,
    #[serde(default)]
    workspace_name: String,
    #[serde(default)]
    role: String,
}

fn key(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// The credentials file for this user, overridable so a test never touches a real one.
pub fn path() -> Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("LOCKYARD_CREDENTIALS").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(explicit));
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(
            crate::paths::home_dir().ok_or_else(|| Error::Invalid("HOME is not set".into()))?,
        )
        .join(".config"),
    };
    Ok(base.join("lockyard/credentials.toml"))
}

fn read(path: &Path) -> Result<File> {
    #[cfg(unix)]
    let contents = fs::read_to_string(path);
    #[cfg(windows)]
    let contents = crate::windows::read_private(path, 1024 * 1024).and_then(|bytes| {
        String::from_utf8(bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    });
    let text = match contents {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(File::default()),
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)?;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Invalid(format!(
                "{} holds a token and must be owned by this user and private (mode 0600); \
                 run `lockyard cloud logout` and log in again",
                path.display()
            )));
        }
    }
    toml::from_str(&text).map_err(|error| {
        Error::Invalid(format!(
            "{} is not readable as credentials ({error}); \
             run `lockyard cloud logout` and log in again",
            path.display()
        ))
    })
}

fn write(path: &Path, file: &File) -> Result<()> {
    let text = toml::to_string(file)
        .map_err(|error| Error::Invalid(format!("credentials could not be written: {error}")))?;
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        fs::create_dir_all(parent)?;
        #[cfg(windows)]
        crate::windows::private_dir(parent)?;
    }
    // Atomic rename after fsync: a crash leaves the old file or the new one, never a half-written
    // token. Mode 0600 is set on the temporary before the rename.
    crate::fsio::replace(path, text.as_bytes(), 0o600)
        .map_err(|error| Error::Invalid(format!("credentials could not be written: {error}")))
}

/// The entry for one server, if there is one.
pub fn find_in(path: &Path, url: &str) -> Result<Option<Entry>> {
    let file = read(path)?;
    Ok(file.servers.get(&key(url)).map(|server| Entry {
        url: key(url),
        token: server.token.clone(),
        workspace_id: server.workspace_id.clone(),
        workspace_name: server.workspace_name.clone(),
        role: server.role.clone(),
    }))
}

/// Stores one server's token, replacing any earlier one for the same server.
pub fn save_in(path: &Path, entry: &Entry) -> Result<()> {
    if entry.token.trim().is_empty() {
        return Err(Error::Invalid("an empty token is not a login".into()));
    }
    let mut file = read(path)?;
    file.servers.insert(
        key(&entry.url),
        Server {
            token: entry.token.clone(),
            workspace_id: entry.workspace_id.clone(),
            workspace_name: entry.workspace_name.clone(),
            role: entry.role.clone(),
        },
    );
    write(path, &file)
}

/// Drops one server's token. Answers whether there was one.
pub fn forget_in(path: &Path, url: &str) -> Result<bool> {
    let mut file = read(path)?;
    if file.servers.remove(&key(url)).is_none() {
        return Ok(false);
    }
    if file.servers.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        }
    }
    write(path, &file)?;
    Ok(true)
}

/// Every server this machine is logged in to, without the tokens.
pub fn servers_in(path: &Path) -> Result<Vec<(String, String)>> {
    let file = read(path)?;
    Ok(file
        .servers
        .into_iter()
        .map(|(url, server)| (url, server.workspace_name))
        .collect())
}

/// The entry for one server from this user's credentials file.
pub fn find(url: &str) -> Result<Option<Entry>> {
    find_in(&path()?, url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str, token: &str) -> Entry {
        Entry {
            url: url.into(),
            token: token.into(),
            workspace_id: "w1".into(),
            workspace_name: "Team".into(),
            role: "member".into(),
        }
    }

    #[test]
    fn a_saved_token_comes_back_for_its_own_server_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/credentials.toml");
        assert_eq!(find_in(&path, "https://a.test").unwrap(), None);
        save_in(&path, &entry("https://a.test", "one")).unwrap();
        save_in(&path, &entry("https://b.test", "two")).unwrap();
        assert_eq!(
            find_in(&path, "https://a.test").unwrap().unwrap().token,
            "one"
        );
        assert_eq!(
            find_in(&path, "https://b.test/").unwrap().unwrap().token,
            "two",
            "a trailing slash names the same server"
        );
        assert_eq!(find_in(&path, "https://c.test").unwrap(), None);
    }

    #[test]
    fn a_second_login_to_one_server_replaces_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        save_in(&path, &entry("https://a.test", "old")).unwrap();
        save_in(&path, &entry("https://a.test/", "new")).unwrap();
        assert_eq!(
            find_in(&path, "https://a.test").unwrap().unwrap().token,
            "new"
        );
        assert_eq!(servers_in(&path).unwrap().len(), 1);
    }

    #[test]
    fn logging_out_removes_one_server_and_the_file_when_it_was_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        assert!(!forget_in(&path, "https://a.test").unwrap());
        save_in(&path, &entry("https://a.test", "one")).unwrap();
        save_in(&path, &entry("https://b.test", "two")).unwrap();
        assert!(forget_in(&path, "https://a.test").unwrap());
        assert!(path.exists(), "the other server is still logged in");
        assert!(forget_in(&path, "https://b.test").unwrap());
        assert!(!path.exists(), "no empty credentials file is left behind");
    }

    #[test]
    fn an_empty_token_is_not_a_login() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        assert!(save_in(&path, &entry("https://a.test", "  ")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_when_written_and_refused_when_it_is_not() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        save_in(&path, &entry("https://a.test", "one")).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = find_in(&path, "https://a.test").unwrap_err();
        assert!(format!("{error}").contains("0600"), "{error}");
    }

    #[test]
    #[cfg(unix)]
    fn an_unreadable_file_says_so_instead_of_losing_the_other_logins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        fs::write(&path, "this is not toml = = =").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(find_in(&path, "https://a.test").is_err());
        assert!(save_in(&path, &entry("https://a.test", "one")).is_err());
    }
}
