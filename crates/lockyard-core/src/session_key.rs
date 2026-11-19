// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A sticky downgrade for one server/session. No credentials are persisted here.

use crate::{Error, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const WARNING: &str =
    "эта сессия начата до ключа Claude: приёмка недоступна, перезапусти чат; остальное работает";

static FALLBACKS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashSet<PathBuf>> {
    FALLBACKS.get_or_init(Mutex::default)
}

fn identity(url: &str, session: &str) -> String {
    serde_json::to_string(&(url.trim_end_matches('/'), session)).expect("string pair")
}

fn path(url: &str, session: &str) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from);
    #[cfg(unix)]
    let base = base
        .or_else(|| crate::paths::home_dir().map(|home| PathBuf::from(home).join(".local/state")));
    #[cfg(windows)]
    let base = base.or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from));
    let base =
        base.ok_or_else(|| Error::Invalid("private state directory is unavailable".into()))?;
    // Same stable FNV naming as the Windows agent socket; verify the full identity on read.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in identity(url, session).bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(base
        .join("lockyard/session-keys")
        .join(format!("{hash:016x}.agent")))
}

fn private_dir(path: &Path) -> Result<()> {
    #[cfg(windows)]
    crate::windows::private_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::Invalid(
                "session key state must be a private directory of this user".into(),
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn is_fallback(url: &str, session: &str) -> Result<bool> {
    if url.is_empty() || session.is_empty() {
        return Ok(false);
    }
    let path = path(url, session)?;
    if cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(&path)
    {
        return Ok(true);
    }
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if contents != identity(url, session) {
        return Err(Error::Invalid("session key state identity mismatch".into()));
    }
    cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path);
    Ok(true)
}

/// Publish before retrying, so other entry points and service starts see the same choice.
pub fn remember_fallback(url: &str, session: &str) -> Result<()> {
    let path = path(url, session)?;
    private_dir(path.parent().expect("state parent"))?;
    crate::fsio::replace(&path, identity(url, session).as_bytes(), 0o600)?;
    cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path);
    Ok(())
}

/// Atomically take the one warning shared by CLI and MCP processes. Daemons never take it.
pub fn take_warning(url: &str, session: &str) -> Result<Option<&'static str>> {
    if std::env::var_os("LOCKYARD_TOKEN_FILE").is_some() || !is_fallback(url, session)? {
        return Ok(None);
    }
    let path = path(url, session)?.with_extension("warned");
    #[cfg(unix)]
    let mut options = fs::OpenOptions::new();
    #[cfg(windows)]
    let mut options = crate::windows::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            file.sync_all()?;
            Ok(Some(WARNING))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_survives_restart_stays_in_memory_and_warning_has_one_consumer() {
        let _guard = crate::test_env_lock();
        let state = tempfile::tempdir().unwrap();
        struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for Environment {
            fn drop(&mut self) {
                for (name, value) in &self.0 {
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
            }
        }
        let _environment = Environment(
            ["XDG_STATE_HOME", "LOCKYARD_TOKEN_FILE"]
                .map(|name| (name, std::env::var_os(name)))
                .to_vec(),
        );
        unsafe {
            std::env::set_var("XDG_STATE_HOME", state.path());
            std::env::remove_var("LOCKYARD_TOKEN_FILE");
        }
        let url = "https://session-state.test";
        remember_fallback(url, "old").unwrap();
        let file = path(url, "old").unwrap();
        cache().lock().unwrap().remove(&file);
        assert!(is_fallback(&format!("{url}/"), "old").unwrap());
        assert!(!is_fallback(url, "new").unwrap());
        assert!(!is_fallback("https://another.test", "old").unwrap());
        // Concurrent entry points cannot both print the one session warning.
        let threads: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(move || take_warning(url, "old").unwrap().is_some()))
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| usize::from(thread.join().unwrap()))
                .sum::<usize>(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(file.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        fs::remove_file(&file).unwrap();
        assert!(is_fallback(url, "old").unwrap());
    }
}
