// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Replacing a file so that a crash leaves either the old contents or the new ones.
//!
//! Writing to a temporary name and renaming is only half of it. Without flushing the temporary file
//! first, the rename can reach the disk before the bytes do, and the reader after a power cut finds
//! the right name holding nothing. Without flushing the folder afterwards, the rename itself can be
//! lost and the old file comes back. Both calls are here so no caller has to remember them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// Replaces `path` with `bytes`, or leaves it exactly as it was.
///
/// `mode` is the Unix permission of the result; it is ignored elsewhere.
pub fn replace(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other(format!("{} is not a file name", path.display())))?;
    let (temporary, file) = create_temporary(parent, name, mode)?;
    let result = write_then_rename(&temporary, path, parent, bytes, file);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_temporary(
    parent: &Path,
    name: &std::ffi::OsStr,
    mode: u32,
) -> io::Result<(PathBuf, File)> {
    for _ in 0..128 {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            serial
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary file",
    ))
}

fn write_then_rename(
    temporary: &Path,
    path: &Path,
    parent: &Path,
    bytes: &[u8],
    mut file: File,
) -> io::Result<()> {
    file.write_all(bytes)?;
    // The bytes must be on the disk before the name points at them.
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    sync_dir(parent)
}

/// Flushes a folder, so the rename inside it survives a power cut.
///
/// Windows has no handle for a folder and needs none: `MoveFileEx` is already ordered there.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Appends one line and flushes it, so a crash loses nothing that was written before it.
///
/// A short append under `PIPE_BUF` reaches the file whole, so a reader never sees half a line.
pub fn append_line(path: &Path, line: &str, mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path)?;
    file.write_all(line.as_bytes())?;
    if !line.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    // The announcement journal is how a hook proves an edit was allowed. Losing the last line
    // after a crash would look like an outside write, so the bytes must reach the disk.
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacing_leaves_the_new_contents_and_no_temporary_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        replace(&path, b"first", 0o600).unwrap();
        replace(&path, b"second", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_precreated_temporary_symlink_is_never_truncated() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("outside");
        fs::write(&target, "keep me").unwrap();
        let serial = NEXT_TEMP.load(Ordering::Relaxed);
        let temporary = dir
            .path()
            .join(format!(".state.{}.{}.tmp", std::process::id(), serial));
        symlink(&target, &temporary).unwrap();

        replace(&dir.path().join("state"), b"new value", 0o600).unwrap();

        assert_eq!(fs::read_to_string(target).unwrap(), "keep me");
        assert_eq!(
            fs::read_to_string(dir.path().join("state")).unwrap(),
            "new value"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_result_is_private_to_this_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        replace(&path, b"token", 0o600).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_failed_write_leaves_the_old_contents_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("state");
        fs::create_dir(path.parent().unwrap()).unwrap();
        replace(&path, b"old", 0o600).unwrap();
        // A folder where a file is wanted: the open of the temporary fails.
        let blocked = dir.path().join("sub").join("blocked");
        fs::create_dir(&blocked).unwrap();
        assert!(replace(&blocked, b"new", 0o600).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old");
        let left: Vec<String> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn appending_adds_the_newline_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        append_line(&path, "one", 0o600).unwrap();
        append_line(&path, "two\n", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    }
}
