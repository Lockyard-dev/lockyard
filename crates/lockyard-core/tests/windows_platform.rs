// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#![cfg(windows)]
use lockyard_core::windows::{self, OpenOptions};
use std::io::{Read, Write};

#[test]
fn private_state_is_owner_only_and_replaces_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    windows::private_dir(&state).unwrap();
    windows::require_private(&state).unwrap();
    let path = state.join("key");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(b"first").unwrap();
    let pinned = windows::pin_file(&file).unwrap();
    assert!(std::fs::rename(&path, state.join("substituted")).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    assert!(windows::rename(&path, &state.join("substituted")).is_err());
    drop(pinned);
    drop(file);
    windows::require_private(&path).unwrap();
    lockyard_core::fsio::replace(&path, b"second", 0o600).unwrap();
    let mut value = String::new();
    OpenOptions::new()
        .read(true)
        .open(&path)
        .unwrap()
        .read_to_string(&mut value)
        .unwrap();
    assert_eq!(value, "second");
}

#[test]
fn named_pipe_namespace_is_per_user_and_workspace() {
    let a = windows::pipe_path("workspace-a").unwrap();
    let b = windows::pipe_path("workspace-b").unwrap();
    assert_ne!(a, b);
    assert_eq!(a, windows::pipe_path("workspace-a").unwrap());
    assert!(a.to_string_lossy().starts_with(r"\\.\pipe\lockyard-"));
}

#[test]
fn named_pipe_first_instance_and_framing_are_enforced() {
    use lockyard_core::windows::ipc::{LocalListener, LocalStream};
    use std::{sync::mpsc, time::Duration};
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    let timeout = Duration::from_secs(2);
    let unique = tempfile::tempdir().unwrap();
    let path = windows::pipe_path(&unique.path().display().to_string()).unwrap();
    let listener = LocalListener::bind(&path).unwrap();
    let duplicate = LocalListener::bind(&path)
        .err()
        .expect("a second first-instance listener must be refused");
    assert_eq!(duplicate.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    let (written, write_completed) = mpsc::channel();
    let (verified, reply_verified) = mpsc::channel();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(timeout)).unwrap();
        stream.set_write_timeout(Some(timeout)).unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"frame\n");
        stream.write_all(b"reply\n").unwrap();
        written.send(()).unwrap();
        // Keep the server and listener alive until the client has checked the frame.
        reply_verified.recv_timeout(timeout).unwrap();
    });
    let mut client = LocalStream::connect(&path).unwrap();
    client.set_read_timeout(Some(timeout)).unwrap();
    client.set_write_timeout(Some(timeout)).unwrap();
    client.write_all(b"frame\n").unwrap();
    let mut bytes = [0; 6];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"reply\n");
    // Reading the bytes can precede completion of the server's overlapped write.
    // Closing now can make its drain fail with ERROR_NO_DATA/ERROR_PIPE_NOT_CONNECTED.
    write_completed.recv_timeout(timeout).unwrap();
    verified.send(()).unwrap();
    peer.join().unwrap();
    drop(client);
}

#[test]
fn append_handles_opened_before_writes_never_overwrite_each_other() {
    let dir = tempfile::tempdir().unwrap();
    windows::private_dir(dir.path()).unwrap();
    let path = dir.path().join("journal");
    let mut first = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let mut second = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    first.write_all(b"one\n").unwrap();
    second.write_all(b"two\n").unwrap();
    windows::sync_file(&first).unwrap();
    windows::sync_file(&second).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"one\ntwo\n");
}

#[test]
fn managed_directories_reject_files_and_junction_ancestors() {
    let dir = tempfile::tempdir().unwrap();
    windows::private_dir(dir.path()).unwrap();
    let file = dir.path().join("file");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file)
        .unwrap();
    assert!(windows::private_dir(&file).is_err());
    let target = dir.path().join("target");
    windows::private_dir(&target).unwrap();
    let junction = dir.path().join("junction");
    let status = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .status()
        .unwrap();
    assert!(status.success(), "junction fixture was not created");
    assert!(windows::private_dir(&junction).is_err());
    assert!(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(junction.join("key"))
            .is_err()
    );
    assert!(!target.join("key").exists());
    std::fs::remove_dir(junction).unwrap();
}

#[test]
fn idle_pipe_reads_obey_the_deadline() {
    use lockyard_core::windows::ipc::{LocalListener, LocalStream};
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let path = windows::pipe_path(&dir.path().to_string_lossy()).unwrap();
    let listener = LocalListener::bind(&path).unwrap();
    let mut client = LocalStream::connect(&path).unwrap();
    let (_server, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    let started = Instant::now();
    let error = client.read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn listener_shutdown_cancels_a_blocked_writer_and_releases_the_name() {
    use lockyard_core::windows::ipc::{LocalListener, LocalStream};
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let path = windows::pipe_path(&dir.path().to_string_lossy()).unwrap();
    let listener = LocalListener::bind(&path).unwrap();
    let _client = LocalStream::connect(&path).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let (started, ready) = std::sync::mpsc::channel();
    let (sent, done) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        started.send(()).unwrap();
        let result = server.write_all(&vec![7u8; 2 * 1024 * 1024]);
        sent.send(result).unwrap();
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        done.recv_timeout(Duration::from_millis(30)).is_err(),
        "writer did not reach backpressure"
    );
    drop(listener);
    assert!(done.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    writer.join().unwrap();
    let _replacement = LocalListener::bind(&path).unwrap();
}

#[test]
fn pinned_managed_directory_prevents_ancestor_redirection() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("ancestor/parent");
    windows::private_dir(&parent).unwrap();
    let pinned = windows::open_directory(&parent).unwrap();
    assert!(std::fs::rename(root.path().join("ancestor"), root.path().join("moved")).is_err());
    assert!(std::fs::rename(&parent, root.path().join("replacement")).is_err());
    drop(pinned);
    std::fs::rename(root.path().join("ancestor"), root.path().join("moved")).unwrap();
}

#[test]
fn sqlite_snapshot_is_private_and_existing_linked_database_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let store = lockyard_core::Store::init(root.path()).unwrap();
    let snapshot = root.path().join("snapshot.db");
    store.backup(&snapshot).unwrap();
    windows::require_private(&snapshot).unwrap();
    assert!(store.backup(&snapshot).is_err());
    drop(store);
    let database = root.path().join(".lockyard/lockyard.db");
    std::fs::hard_link(&database, root.path().join("alias.db")).unwrap();
    assert!(lockyard_core::Store::open(root.path()).is_err());
}

#[test]
fn timed_out_writer_drop_does_not_leave_an_orphan_pipe() {
    use lockyard_core::windows::ipc::{LocalListener, LocalStream};
    use std::time::{Duration, Instant};
    let root = tempfile::tempdir().unwrap();
    let path = windows::pipe_path(&root.path().to_string_lossy()).unwrap();
    let listener = LocalListener::bind(&path).unwrap();
    let _client = LocalStream::connect(&path).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_write_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    assert_eq!(
        server
            .write_all(&vec![7; 2 * 1024 * 1024])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    drop(server);
    drop(listener);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match LocalListener::bind(&path) {
            Ok(_replacement) => break,
            Err(error) => {
                assert!(Instant::now() < deadline, "orphan pipe: {error}");
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_async_write_releases_the_server_instance() {
    use std::time::{Duration, Instant};
    use tokio::io::AsyncWriteExt;
    use windows::ipc::{AsyncListener, AsyncStream};
    let root = tempfile::tempdir().unwrap();
    let path = windows::pipe_path(&root.path().to_string_lossy()).unwrap();
    let listener = AsyncListener::bind(&path).unwrap();
    let client = AsyncStream::connect(&path).await.unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    let writing = async {
        server.write_all(&vec![7; 2 * 1024 * 1024]).await?;
        server.flush().await
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(30), writing)
            .await
            .is_err()
    );
    drop(server);
    drop(listener);
    // The client remains alive: releasing the server must not depend on it draining the payload.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match AsyncListener::bind(&path) {
            Ok(_replacement) => break,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "pending async write retained the name: {error}"
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
    drop(client);
}
