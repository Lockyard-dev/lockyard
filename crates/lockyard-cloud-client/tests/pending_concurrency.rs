// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_cloud_client::{Call, Client, ClientError, Transport, WorkspaceKey};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);

struct Journal(PathBuf);

impl Journal {
    fn new() -> Self {
        Self(std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ly-pending-concurrency-{}",
            lockyard_cloud_client::ulid()
        )))
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct PendingRequest {
    stream: TcpStream,
    path: String,
    body: String,
    key: String,
}

impl PendingRequest {
    fn reply(mut self, status: u16, code: Option<&str>) {
        let body = code.map_or_else(
            || json!({"id":"A-1"}),
            |code| json!({"status":status,"code":code,"detail":"fixture","details":{}}),
        );
        write_reply(&mut self.stream, status, body);
    }
}

struct Server {
    url: String,
    requests: mpsc::Receiver<PendingRequest>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut first_write = true;
            while !stopping.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                };
                // Windows inherits the listener's nonblocking mode; request I/O is blocking.
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                let (path, body, key) = read_request(&mut stream);
                if path == "/api/v1/protocol" {
                    write_reply(
                        &mut stream,
                        200,
                        json!({
                            "selected_protocol":2,"min_protocol":1,"max_protocol":2,
                            "capabilities":[]
                        }),
                    );
                } else if first_write {
                    first_write = false;
                    write_reply(
                        &mut stream,
                        429,
                        json!({
                            "status":429,"code":"rate_limited","detail":"fixture","details":{}
                        }),
                    );
                } else if sender
                    .send(PendingRequest {
                        stream,
                        path,
                        body,
                        key,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn client(&self, journal: &Journal) -> Client {
        Client::new(&self.url, "fixture-token".into())
            .unwrap()
            .with_pending_journal(&journal.0)
            .unwrap()
            .with_content_encryption(
                "fixture-workspace",
                Some(WorkspaceKey::from_entropy([73; 32])),
                true,
            )
    }

    fn shutdown(&mut self) -> std::thread::Result<()> {
        self.stop.store(true, Ordering::Release);
        self.worker.take().map_or(Ok(()), |worker| worker.join())
    }

    fn finish(mut self) {
        // Report a worker failure on the normal path, before unwinding starts.
        if let Err(failure) = self.shutdown() {
            std::panic::resume_unwind(failure);
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.shutdown().is_err() {
            // The worker's panic hook already printed its cause. Panicking again here can
            // abort the process while another assertion is unwinding, hiding both failures.
            let _ = writeln!(
                std::io::stderr(),
                "pending-concurrency fixture worker failed during cleanup"
            );
        }
    }
}

fn write_reply(stream: &mut TcpStream, status: u16, value: Value) {
    let body = value.to_string();
    let response = format!(
        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLockyard-Protocol: 2\r\nRetry-After: 2\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
}

fn read_request(stream: &mut TcpStream) -> (String, String, String) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let end = loop {
        if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let path = lines.next().unwrap().split(' ').nth(1).unwrap().to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .collect::<Vec<_>>();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    };
    let length = header("Content-Length")
        .unwrap_or("0")
        .parse::<usize>()
        .unwrap();
    let key = header("Idempotency-Key").unwrap_or_default().to_owned();
    while bytes.len() < end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
    }
    (
        path,
        String::from_utf8(bytes[end..end + length].to_vec()).unwrap(),
        key,
    )
}

fn start_call(client: Arc<Client>, call: Call) -> mpsc::Receiver<Result<Value, ClientError>> {
    let (started, ready) = mpsc::sync_channel(0);
    let (finished, result) = mpsc::channel();
    std::thread::spawn(move || {
        started.send(()).unwrap();
        let _ = finished.send(client.call(&call));
    });
    ready.recv_timeout(WAIT).unwrap();
    result
}

fn concurrent_retry(same_client: bool) {
    let journal = Journal::new();
    let server = Server::start();
    let mut call = if same_client {
        Call::write(
            "fixture-session",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({
                "to":"other","body":"private original body"
            }),
        )
    } else {
        Call::write(
            "fixture-session",
            "POST",
            "/api/v1/registry/items".into(),
            json!({
                "title":"private original body"
            }),
        )
    };
    call.deadline_ms = Some(1_000);
    call.defer_pending_ack = same_client;
    let seed = server.client(&journal);
    assert_eq!(seed.call(&call).unwrap_err().code(), Some("rate_limited"));
    let key = call.key.as_deref().unwrap();
    let original = seed.pending_operation(key).unwrap();
    assert!(original.pre_execution_rejected);
    drop(seed);

    let first_client = Arc::new(server.client(&journal));
    let second_client = if same_client {
        Arc::clone(&first_client)
    } else {
        Arc::new(server.client(&journal))
    };
    // The first network operation stays held while the second caller starts. This puts the
    // durable marker in its unknown/in-flight state before the contender inspects it.
    call.deadline_ms = Some(10_000);
    let first_done = start_call(Arc::clone(&first_client), call.clone());
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let first_body = first.body.clone();
    assert_eq!(first_body, original.body.as_deref().unwrap());
    let second_done = start_call(Arc::clone(&second_client), call.clone());
    let overlapping = server.requests.recv_timeout(Duration::from_secs(1));
    let did_overlap = overlapping.is_ok();
    if let Ok(second) = overlapping {
        assert_eq!(second.body, first_body);
        assert_eq!(second.key, key);
        // Make the other operation succeed first. A stale refusal must never recreate safe
        // replay permission after that success, including in a separately restored Client.
        second.reply(200, None);
        assert!(second_done.recv_timeout(WAIT).unwrap().is_ok());
        first.reply(503, Some("server_draining"));
        assert!(first_done.recv_timeout(WAIT).unwrap().is_err());
    } else {
        first.reply(200, None);
        assert!(first_done.recv_timeout(WAIT).unwrap().is_ok());
        let until = Instant::now() + WAIT;
        loop {
            match second_done.try_recv() {
                Ok(_) => break,
                Err(mpsc::TryRecvError::Disconnected) => panic!("second caller vanished"),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if let Ok(later) = server.requests.try_recv() {
                assert_eq!(later.path, call.path);
                assert_eq!(later.key, key);
                assert_eq!(
                    later.body, first_body,
                    "serialization must not reencrypt a stale call"
                );
                later.reply(200, None);
            }
            assert!(
                Instant::now() < until,
                "serialized contender did not finish"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let restored = server.client(&journal);
    assert!(
        restored
            .pending_operation(key)
            .is_none_or(|pending| !pending.pre_execution_rejected),
        "a successful overlapping operation must not be restored as a safe refusal"
    );
    assert!(
        !did_overlap,
        "two retries transmitted concurrently for one pending operation"
    );
    server.finish();
}

#[test]
fn restored_clients_cannot_overlap_or_recreate_safe_refusal() {
    concurrent_retry(false);
}

#[test]
fn deferred_retries_share_one_in_flight_send() {
    concurrent_retry(true);
}

#[test]
fn fixture_cleanup_preserves_failure_instead_of_aborting() {
    const CHILD: &str = "LOCKYARD_PENDING_FIXTURE_UNWIND";
    if std::env::var_os(CHILD).is_some() {
        let (_sender, requests) = mpsc::channel();
        let _server = Server {
            url: String::new(),
            requests,
            stop: Arc::new(AtomicBool::new(false)),
            worker: Some(std::thread::spawn(|| panic!("injected fixture failure"))),
        };
        panic!("original caller failure");
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fixture_cleanup_preserves_failure_instead_of_aborting",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(101),
        "fixture cleanup must preserve the ordinary test failure: {stderr}"
    );
    assert!(stderr.contains("original caller failure"), "{stderr}");
    assert!(stderr.contains("injected fixture failure"), "{stderr}");
    assert!(!stderr.contains("panic in a destructor"), "{stderr}");
}
