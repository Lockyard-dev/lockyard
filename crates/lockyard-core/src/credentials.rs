// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Where a token lives between runs, once `lockyard cloud login` has one.
//!
//! One file for the whole machine, next to the trusted-server list, keyed by server URL so two
//! workspaces on two servers do not overwrite each other. It is a credential, so it is written
//! and read as `0600` and never copied into a project: `.lockyard/config.toml` still refuses a
//! `token` field.

#[cfg(windows)]
use crate::windows::OpenOptions;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::{fs, io};

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

fn read_contents(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let contents = read_private(path);
    #[cfg(windows)]
    let contents = crate::windows::read_private(path, 1024 * 1024).map_err(Error::from);
    match contents {
        Ok(bytes) => Ok(bytes),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn read_private(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !is_private_file(&metadata, unsafe { libc::geteuid() }) {
        return Err(Error::Invalid(format!(
            "{} holds a token and must be owned by this user and private (mode 0600); \
             correct its owner and permissions before using it",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
fn is_private_file(metadata: &fs::Metadata, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_file() && metadata.mode() & 0o077 == 0 && metadata.uid() == owner
}

/// Returns only the byte offset, if known, on a decoding or parsing error.
fn parse(bytes: &[u8]) -> std::result::Result<File, Option<usize>> {
    let text = std::str::from_utf8(bytes).map_err(|error| Some(error.valid_up_to()))?;
    // The parser's Display and Debug include the source, which may contain tokens.
    toml::from_str(text).map_err(|error| error.span().map(|span| span.start))
}

fn read(path: &Path) -> Result<File> {
    let bytes = read_contents(path)?;
    parse(&bytes).map_err(|offset| {
        let location = offset.map_or_else(String::new, |offset| {
            let prefix = &bytes[..offset.min(bytes.len())];
            let line = prefix.iter().filter(|&&byte| byte == b'\n').count() + 1;
            let line_prefix = prefix.rsplit(|&byte| byte == b'\n').next().unwrap_or(&[]);
            let column = String::from_utf8_lossy(line_prefix).chars().count() + 1;
            format!(" (line {line}, column {column})")
        });
        Error::Invalid(format!(
            "{} is not readable as credentials{location}; \
             run `lockyard cloud logout --url <server-url>` to move the entire credentials file \
             aside, then log in again to each server you use",
            path.display()
        ))
    })
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn lock_for_update(path: &Path) -> io::Result<fs::File> {
    // Keep this file in place so writers lock the same file even when credentials are replaced,
    // removed, or moved aside. Dropping the handle releases the lock.
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let lock = options.open(with_suffix(path, ".lock"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = lock.metadata()?;
        if !is_private_file(&metadata, unsafe { libc::geteuid() }) || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credentials lock must be a private file owned by this user",
            ));
        }
    }
    #[cfg(test)]
    tests::before_lock();
    lock.lock()?;
    Ok(lock)
}

fn write(path: &Path, file: &File) -> Result<()> {
    let text = toml::to_string(file)
        .map_err(|error| Error::Invalid(format!("credentials could not be written: {error}")))?;
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
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        #[cfg(unix)]
        fs::create_dir_all(parent)?;
        #[cfg(windows)]
        crate::windows::private_dir(parent)?;
    }
    let _lock = lock_for_update(path)?;
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
    let Some(_lock) = lock_for_removal(path)? else {
        return Ok(false);
    };
    forget(path, url, read(path)?)
}

fn lock_for_removal(path: &Path) -> Result<Option<fs::File>> {
    match lock_for_update(path) {
        Ok(lock) => Ok(Some(lock)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn forget(path: &Path, url: &str, mut file: File) -> Result<bool> {
    if file.servers.remove(&key(url)).is_none() {
        return Ok(false);
    }
    if file.servers.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => {
                crate::fsio::sync_dir(parent_directory(path))?;
                return Ok(true);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        }
    }
    write(path, &file)?;
    Ok(true)
}

/// What happened to the local credentials during logout.
pub enum Logout {
    NoToken,
    Removed,
    MovedAside(PathBuf),
}

/// Drops one server's token, or moves the entire private file aside if its TOML is invalid.
pub fn logout_in(path: &Path, url: &str) -> Result<Logout> {
    let Some(_lock) = lock_for_removal(path)? else {
        return Ok(Logout::NoToken);
    };
    match parse(&read_contents(path)?) {
        Ok(file) => Ok(if forget(path, url, file)? {
            Logout::Removed
        } else {
            Logout::NoToken
        }),
        Err(_) => Ok(Logout::MovedAside(move_aside(path)?)),
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn move_aside(path: &Path) -> Result<PathBuf> {
    let mut backup = with_suffix(path, ".corrupt");
    let mut serial = 1;
    loop {
        match publish_corrupt_backup(path, &backup) {
            Ok(()) => return Ok(backup),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                backup = with_suffix(path, &format!(".corrupt.{serial}"));
                serial += 1;
            }
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "could not move credentials {} to {}: {error}",
                        path.display(),
                        backup.display()
                    ),
                )
                .into());
            }
        }
    }
}

#[cfg(unix)]
fn publish_corrupt_backup(path: &Path, backup: &Path) -> io::Result<()> {
    publish_corrupt_backup_with(path, backup, |source, destination| {
        fs::hard_link(source, destination)
    })
}

#[cfg(unix)]
fn publish_corrupt_backup_with(
    path: &Path,
    backup: &Path,
    link: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    match link(path, backup) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Resume an interrupted move after the backup was linked.
            let source = fs::symlink_metadata(path)?;
            let destination = fs::symlink_metadata(backup)?;
            if (source.dev(), source.ino()) != (destination.dev(), destination.ino()) {
                return Err(error);
            }
        }
        Err(error) => return Err(error),
    }
    let parent = parent_directory(path);
    crate::fsio::sync_dir(parent)?;
    fs::remove_file(path)?;
    crate::fsio::sync_dir(parent)
}

#[cfg(windows)]
fn publish_corrupt_backup(path: &Path, backup: &Path) -> io::Result<()> {
    crate::windows::rename_create_only(path, backup)
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
    use std::cell::RefCell;
    use std::sync::mpsc;

    thread_local! {
        static LOCK_STARTED: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) };
    }

    pub(super) fn before_lock() {
        if let Some(started) = LOCK_STARTED.take() {
            started.send(()).unwrap();
        }
    }

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
        assert!(logout_in(&path, "https://a.test").is_err());
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_lock_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        fs::write(with_suffix(&path, ".lock"), b"").unwrap();
        fs::set_permissions(
            with_suffix(&path, ".lock"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(save_in(&path, &entry("https://a.test", "fixture")).is_err());
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn lock_rejects_non_regular_links_and_an_unexpected_owner() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let lock_path = with_suffix(&path, ".lock");
        let other = dir.path().join("other");
        crate::fsio::replace(&other, b"fixture", 0o600).unwrap();
        let meta = fs::File::open(&other).unwrap().metadata().unwrap();
        assert!(is_private_file(&meta, meta.uid()));
        assert!(!is_private_file(&meta, meta.uid() ^ 1));

        symlink(&other, &lock_path).unwrap();
        assert!(lock_for_update(&path).is_err());
        fs::remove_file(&lock_path).unwrap();
        fs::hard_link(&other, &lock_path).unwrap();
        assert!(lock_for_update(&path).is_err());
        fs::remove_file(&lock_path).unwrap();
        fs::create_dir(&lock_path).unwrap();
        assert!(lock_for_update(&path).is_err());
        assert_eq!(fs::read(other).unwrap(), b"fixture");
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_filesystem_without_hard_links_leaves_the_source_and_backup_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let backup = with_suffix(&path, ".corrupt");
        let broken = b"invalid fixture [";
        crate::fsio::replace(&path, broken, 0o600).unwrap();
        crate::fsio::replace(&backup, b"older backup", 0o600).unwrap();
        let error = publish_corrupt_backup_with(&path, &backup, |_, _| {
            Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(fs::read(path).unwrap(), broken);
        assert_eq!(fs::read(backup).unwrap(), b"older backup");
    }

    #[cfg(unix)]
    #[test]
    fn logout_resumes_after_the_backup_was_linked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let backup = with_suffix(&path, ".corrupt");
        let broken = b"invalid fixture [";
        crate::fsio::replace(&path, broken, 0o600).unwrap();
        fs::hard_link(&path, &backup).unwrap();
        assert!(matches!(
            logout_in(&path, "https://a.test").unwrap(),
            Logout::MovedAside(actual) if actual == backup
        ));
        assert_eq!(fs::read(backup).unwrap(), broken);
        assert!(!path.exists());
        assert!(!with_suffix(&path, ".corrupt.1").exists());
    }

    #[test]
    fn malformed_credentials_errors_contain_the_position_but_no_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let token = "lk_fake_core_parse_error_token";
        let broken = format!("[servers.'https://a.test']\ntoken = [{token}]\n");
        crate::fsio::replace(&path, broken.as_bytes(), 0o600).unwrap();

        let error = find_in(&path, "https://a.test").unwrap_err();
        assert!(error.to_string().contains("(line 2, column 10)"));
        assert!(!error.to_string().contains(token));
        assert!(!format!("{error:?}").contains(token));
        assert!(save_in(&path, &entry("https://a.test", "one")).is_err());
        assert!(forget_in(&path, "https://a.test").is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), broken);
    }

    #[test]
    fn a_waiting_login_does_not_restore_credentials_removed_under_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let removed = "https://a.test";
        let incoming = entry("https://b.test", "fake-login-token");
        save_in(&path, &entry(removed, "fake-logout-token")).unwrap();

        let lock = lock_for_update(&path).unwrap();
        std::thread::scope(|scope| {
            let (started, ready) = mpsc::channel();
            let (path, incoming) = (&path, &incoming);
            let login = scope.spawn(move || {
                LOCK_STARTED.set(Some(started));
                save_in(path, incoming)
            });
            let ready = ready.recv_timeout(std::time::Duration::from_secs(5));
            // Remove the last credential while the second writer is at the lock.
            let result = read(path).and_then(|file| forget(path, removed, file));
            drop(lock);
            login.join().unwrap().unwrap();
            ready.unwrap();
            assert!(result.unwrap());
        });

        assert_eq!(find_in(&path, removed).unwrap(), None);
        assert_eq!(find_in(&path, &incoming.url).unwrap(), Some(incoming));
    }

    #[test]
    fn concurrent_login_and_forget_serialize_updates_to_different_servers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let removed = "https://a.test";
        let incoming = entry("https://b.test", "fake-login-token");
        save_in(&path, &entry(removed, "fake-logout-token")).unwrap();

        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let login = scope.spawn(|| {
                start.wait();
                save_in(&path, &incoming).unwrap();
            });
            start.wait();
            assert!(forget_in(&path, removed).unwrap());
            login.join().unwrap();
        });

        assert_eq!(find_in(&path, removed).unwrap(), None);
        assert_eq!(find_in(&path, &incoming.url).unwrap(), Some(incoming));
    }
}
