// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Keep one download descriptor and publish only inside a trusted output directory.
use super::{absolute, invalid};
use lockyard_core::Result;
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
};
use std::{
    ffi::CString,
    fs::{self, File},
    io,
    path::Path,
};

pub(super) struct Download {
    parent: File,
    temporary: CString,
    destination: CString,
    file: File,
}
impl Download {
    pub(super) fn new(destination: &Path, kind: &str) -> Result<Self> {
        let destination = absolute(destination)?;
        let parent_path = destination
            .parent()
            .ok_or_else(|| invalid("download output needs a parent directory"))?
            .canonicalize()?;
        let parent = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&parent_path)?;
        let metadata = parent.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid(
                "download output directory must be owned by you and not writable by group or others",
            ));
        }
        let destination = CString::new(
            destination
                .file_name()
                .ok_or_else(|| invalid("invalid download filename"))?
                .as_bytes(),
        )
        .map_err(|_| invalid("invalid download filename"))?;
        let temporary = CString::new(format!(
            ".lockyard-{kind}-{}",
            lockyard_node::wire::new_id().map_err(|_| invalid("download entropy unavailable"))?
        ))
        .map_err(|_| invalid("invalid download filename"))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        parent.sync_all()?;
        Ok(Self {
            parent,
            temporary,
            destination,
            file,
        })
    }
    pub(super) fn file(&mut self) -> &mut File {
        &mut self.file
    }
    pub(super) fn publish(self) -> Result<()> {
        self.file.sync_all()?;
        // The parent descriptor pins the directory despite ancestor renames. Its
        // permissions exclude other users from replacing the private temporary.
        let current_fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if current_fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let current = unsafe { File::from_raw_fd(current_fd) };
        let named = current.metadata()?;
        let opened = self.file.metadata()?;
        if !named.is_file() || named.dev() != opened.dev() || named.ino() != opened.ino() {
            return Err(invalid("download temporary identity changed"));
        }
        if unsafe {
            libc::linkat(
                self.parent.as_raw_fd(),
                self.temporary.as_ptr(),
                self.parent.as_raw_fd(),
                self.destination.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        self.parent.sync_all()?;
        // Drop unlinks only the private temporary; an existing destination is never replaced.
        Ok(())
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        unsafe {
            libc::unlinkat(self.parent.as_raw_fd(), self.temporary.as_ptr(), 0);
        }
        let _ = self.parent.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn private_root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[test]
    fn private_descriptor_publishes_exact_bytes_and_never_overwrites_existing_output() {
        let root = private_root();
        let path = root.path().join("result.patch");
        let mut download = Download::new(&path, "patch").unwrap();
        download.file().write_all(b"verified").unwrap();
        download.file().seek(SeekFrom::Start(0)).unwrap();
        let mut checked = Vec::new();
        download.file().read_to_end(&mut checked).unwrap();
        assert_eq!(checked, b"verified");
        download.publish().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"verified");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut second = Download::new(&path, "patch").unwrap();
        second.file().write_all(b"replacement").unwrap();
        assert!(second.publish().is_err());
        assert_eq!(fs::read(path).unwrap(), b"verified");
    }
    #[test]
    fn symlink_swap_cannot_clobber_a_victim_or_publish_unverified_replacement() {
        let root = private_root();
        let path = root.path().join("result.patch");
        let victim = root.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let mut download = Download::new(&path, "patch").unwrap();
        let temporary = root
            .path()
            .join(std::ffi::OsStr::from_bytes(download.temporary.as_bytes()));
        fs::remove_file(&temporary).unwrap();
        symlink(&victim, &temporary).unwrap();
        download.file().write_all(b"untrusted RPC bytes").unwrap();
        assert!(download.publish().is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert!(!path.exists());
    }
    #[test]
    fn replacement_after_verification_cannot_be_published_as_the_verified_file() {
        let root = private_root();
        let path = root.path().join("result.patch");
        let mut download = Download::new(&path, "patch").unwrap();
        download.file().write_all(b"verified").unwrap();
        let (_, hash) = lockyard_node::provenance::hash_open_file(download.file(), 4096).unwrap();
        assert_eq!(hash, lockyard_node::provenance::sha256(b"verified"));
        let temporary = root
            .path()
            .join(std::ffi::OsStr::from_bytes(download.temporary.as_bytes()));
        fs::remove_file(&temporary).unwrap();
        fs::write(&temporary, b"unverified replacement").unwrap();
        assert!(download.publish().is_err());
        assert!(!path.exists());
    }

    #[test]
    fn shared_writable_output_directory_is_rejected_before_creating_temporary() {
        let root = private_root();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Download::new(&root.path().join("result"), "patch").is_err());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
