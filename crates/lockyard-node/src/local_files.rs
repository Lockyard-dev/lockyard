// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Read configured identity/trust files through one checked, bounded descriptor.
use crate::Result;
use std::path::Path;

#[cfg(unix)]
use std::fs;

#[cfg(unix)]
use std::io::Read;

pub(crate) fn read_public(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read(path, limit, false)
}
pub(crate) fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read(path, limit, true)
}
#[cfg(unix)]
fn read(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "node identity file unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "node identity file unavailable")?;
    if !metadata.is_file()
        || metadata.len() > limit as u64
        || private
            && (metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1)
    {
        return Err("node identity file must be regular, bounded and appropriately private".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "node identity file unavailable")?;
    if bytes.len() > limit {
        return Err("node identity file exceeds limit".into());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn read(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    Ok(if private {
        lockyard_core::windows::read_private(path, limit as u64)?
    } else {
        lockyard_core::windows::read_public(path, limit as u64)?
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    };
    #[test]
    #[cfg(unix)]
    fn trust_and_identity_files_reject_fifos_symlinks_and_oversize_before_reading() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_public(&fifo, 65536).is_err());
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
        let path = root.path().join("large");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(65537).unwrap();
        assert!(read_public(&path, 65536).is_err());
        let alias = root.path().join("symlink");
        symlink(&path, &alias).unwrap();
        assert!(read_public(&alias, 65536).is_err());
        file.set_len(32).unwrap();
        assert_eq!(read_private(&path, 65536).unwrap().len(), 32);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 65536).is_err());
    }
    #[test]
    fn private_identity_hardlinks_fail_while_public_trust_hardlinks_remain_readable() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("identity");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .set_len(32)
            .unwrap();
        fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(read_private(&path, 65536).is_err());
        assert_eq!(read_public(&path, 65536).unwrap().len(), 32);
    }
}
