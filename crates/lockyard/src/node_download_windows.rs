// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Keep a private synced download and publish without replacing an existing output.
use super::{absolute, invalid};
use lockyard_core::{Result, windows};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};
pub(super) struct Download {
    parent: windows::Directory,
    parent_path: PathBuf,
    temporary: PathBuf,
    destination: PathBuf,
    file: File,
}
impl Download {
    pub(super) fn new(destination: &Path, kind: &str) -> Result<Self> {
        let destination = absolute(destination)?;
        windows::reject_reparse(&destination)?;
        let parent_path = destination
            .parent()
            .ok_or_else(|| invalid("download output needs a parent directory"))?
            .to_path_buf();
        let parent = windows::open_directory(&parent_path)?;
        let temporary = parent_path.join(format!(
            ".lockyard-{kind}-{}",
            lockyard_cloud_client::ulid()
        ));
        let file = windows::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        Ok(Self {
            parent,
            parent_path,
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
        let parent = windows::open_directory(&self.parent_path)?;
        if windows::file_identity(&parent)? != windows::file_identity(&self.parent)? {
            return Err(invalid("download parent identity changed"));
        }
        let named = windows::OpenOptions::new()
            .read(true)
            .open(&self.temporary)?;
        if windows::file_identity(&named)? != windows::file_identity(&self.file)? {
            return Err(invalid("download temporary identity changed"));
        }
        windows::publish_handle(
            &self.file,
            &self.parent,
            self.destination
                .file_name()
                .ok_or_else(|| invalid("invalid download filename"))?,
            false,
        )?;
        Ok(())
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}
