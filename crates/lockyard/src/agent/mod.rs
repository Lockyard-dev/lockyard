// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! `lockyard agent`: one background process per user, reached over a Unix socket.
//!
//! It keeps a view of claims, unread counts and the board, so a hook answers without touching the
//! network, and it holds an outbox so mail and heartbeats survive an outage. It uses plain threads:
//! a hook only opens the socket, with no HTTP and no async runtime on that path.

#[cfg(unix)]
pub mod daemon;
#[cfg(unix)]
pub mod outbox;
#[cfg(unix)]
pub mod service;
#[cfg(unix)]
pub mod socket;
#[cfg(unix)]
pub mod wire;

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::fs::{self, DirBuilder};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    unsafe extern "C" {
        safe fn getuid() -> u32;
    }

    /// The real user id of this process.
    pub fn uid() -> u32 {
        getuid()
    }

    /// `$XDG_RUNTIME_DIR/lockyard/agent.sock`, or `/tmp/lockyard-<uid>/agent.sock`.
    pub fn socket_path() -> PathBuf {
        match std::env::var_os("XDG_RUNTIME_DIR").filter(|dir| !dir.is_empty()) {
            Some(dir) => PathBuf::from(dir).join("lockyard").join("agent.sock"),
            None => PathBuf::from(format!("/tmp/lockyard-{}", uid())).join("agent.sock"),
        }
    }

    /// `$XDG_STATE_HOME/lockyard`, or `~/.local/state/lockyard`.
    pub fn state_root() -> io::Result<PathBuf> {
        if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|dir| !dir.is_empty()) {
            return Ok(PathBuf::from(dir).join("lockyard"));
        }
        let home = std::env::var_os("HOME")
            .filter(|dir| !dir.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        Ok(PathBuf::from(home).join(".local/state/lockyard"))
    }

    /// Makes `dir` a folder only this user can enter, and refuses one that someone else prepared.
    pub fn private_dir(dir: &Path) -> io::Result<()> {
        match DirBuilder::new().recursive(false).mode(0o700).create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = dir.parent() {
                    fs::create_dir_all(parent)?;
                }
                DirBuilder::new().mode(0o700).create(dir)?;
            }
            Err(error) => return Err(error),
        }
        // symlink_metadata: a link planted at this name must not pass for the folder.
        let found = fs::symlink_metadata(dir)?;
        if !found.is_dir() || found.uid() != uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not a folder of this user", dir.display()),
            ));
        }
        if found.mode() & 0o777 != 0o700 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_private_folder_is_0700_and_a_link_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let folder = dir.path().join("a/b");
            private_dir(&folder).unwrap();
            assert_eq!(fs::metadata(&folder).unwrap().mode() & 0o777, 0o700);
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
            private_dir(&folder).unwrap();
            assert_eq!(fs::metadata(&folder).unwrap().mode() & 0o777, 0o700);
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&folder, &link).unwrap();
            assert!(private_dir(&link).is_err());
        }
    }
}
