// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Real-process backup checks: committed WAL data, private standalone output and no clobbering.

use lockyard_core::{DIR_NAME, Store};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn command(cwd: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command
        .current_dir(cwd)
        .env_remove("LOCKYARD_AGENT")
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run(cwd: &Path, args: &[&OsStr]) -> Output {
    command(cwd).args(args).output().unwrap()
}

fn success(cwd: &Path, args: &[&str]) -> Output {
    let output = command(cwd).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn project(root: &Path) {
    fs::create_dir_all(root).unwrap();
    success(root, &["init"]);
    for body in ["first WAL commit", "second WAL commit", "third WAL commit"] {
        success(root, &["--agent", "writer", "msg", "send", "*", body]);
    }
}

fn assert_snapshot_contents(snapshot: &Path) {
    let restored = tempfile::tempdir().unwrap();
    let state = restored.path().join(DIR_NAME);
    fs::create_dir(&state).unwrap();
    fs::copy(snapshot, state.join("lockyard.db")).unwrap();
    // Rollback-journal format guarantees this file can be opened without a retained source WAL.
    let bytes = fs::read(snapshot).unwrap();
    assert_eq!(&bytes[18..20], &[1, 1]);
    let store = Store::open(restored.path()).unwrap();
    let messages = store.peek_inbox("reader", true, 10).unwrap();
    assert_eq!(
        messages
            .iter()
            .map(|message| message.body.as_str())
            .collect::<Vec<_>>(),
        ["first WAL commit", "second WAL commit", "third WAL commit"]
    );
    drop(store);
    assert_eq!(fs::read_dir(state).unwrap().count(), 1);
}

#[test]
fn backup_contains_short_cli_commits_and_opens_without_sidecars() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("project");
    project(&root);
    let exports = fixture.path().join("exports");
    fs::create_dir(&exports).unwrap();
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    let wal = root.join(DIR_NAME).join("lockyard.db-wal");
    let retained_wal = fs::read(&wal).unwrap();
    assert!(
        retained_wal.len() > 32,
        "fixture must exercise committed WAL pages"
    );

    let output = success(
        &nested,
        &["--json", "db", "backup", "../../exports/snapshot.db"],
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["path"].is_string(), "{report}");
    let snapshot = exports.join("snapshot.db");
    assert_snapshot_contents(&snapshot);
    assert_eq!(
        fs::read(&wal).unwrap(),
        retained_wal,
        "backup must preserve the short-CLI WAL policy"
    );
    assert_eq!(fs::read_dir(&exports).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn backup_refuses_existing_file_and_directory_without_modifying_them() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("project");
    project(&root);
    let existing = fixture.path().join("existing.db");
    fs::write(&existing, b"do not replace this backup").unwrap();
    let directory = fixture.path().join("existing-directory");
    fs::create_dir(&directory).unwrap();
    for destination in [&existing, &directory] {
        let output = run(
            &root,
            &[
                OsStr::new("db"),
                OsStr::new("backup"),
                destination.as_os_str(),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(fs::read(existing).unwrap(), b"do not replace this backup");
    assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 3);
}

#[cfg(unix)]
#[test]
fn backup_refuses_existing_and_dangling_symlinks() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("project");
    project(&root);
    let victim = fixture.path().join("victim.db");
    fs::write(&victim, b"preserve target bytes").unwrap();
    let missing = fixture.path().join("missing.db");
    let linked = fixture.path().join("linked.db");
    let dangling = fixture.path().join("dangling.db");
    symlink(&victim, &linked).unwrap();
    symlink(&missing, &dangling).unwrap();
    for destination in [&linked, &dangling] {
        let output = run(
            &root,
            &[
                OsStr::new("db"),
                OsStr::new("backup"),
                destination.as_os_str(),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fs::symlink_metadata(destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    assert_eq!(fs::read_link(linked).unwrap(), victim);
    assert_eq!(fs::read_link(dangling).unwrap(), missing);
    assert_eq!(fs::read(victim).unwrap(), b"preserve target bytes");
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 4);
}

#[test]
fn concurrent_backups_publish_exactly_one_complete_snapshot() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("project");
    project(&root);
    let snapshot = fixture.path().join("snapshot.db");
    let first = command(&root)
        .args([OsStr::new("db"), OsStr::new("backup"), snapshot.as_os_str()])
        .spawn()
        .unwrap();
    let second = command(&root)
        .args([OsStr::new("db"), OsStr::new("backup"), snapshot.as_os_str()])
        .spawn()
        .unwrap();
    let results = [
        first.wait_with_output().unwrap(),
        second.wait_with_output().unwrap(),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status.success())
            .count(),
        1
    );
    assert!(
        results
            .iter()
            .all(|result| matches!(result.status.code(), Some(0 | 1)))
    );
    assert_snapshot_contents(&snapshot);
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 2);
}

#[test]
fn backup_is_local_maintenance_even_with_cloud_mode_and_no_agent() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("project");
    project(&root);
    fs::write(
        root.join(DIR_NAME).join("config.toml"),
        "mode = \"cloud\"\nurl = \"http://127.0.0.1:1\"\nworkspace = \"offline-backup\"\n",
    )
    .unwrap();
    let snapshot = fixture.path().join("snapshot.db");
    let output = run(
        &root,
        &[OsStr::new("db"), OsStr::new("backup"), snapshot.as_os_str()],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_snapshot_contents(&snapshot);
}
