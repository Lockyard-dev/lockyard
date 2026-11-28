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

fn survey_wait_call(deadline: u64) -> Call {
    let mut call = Call::write(
        "me",
        "POST",
        "/api/v1/zones/claims".into(),
        json!({"paths":["src"]}),
    );
    call.key = Some("survey-wait-key".into());
    call.long_poll = true;
    call.deadline_ms = Some(deadline);
    call
}

fn survey_prime(server: &Server, journal: &Journal) {
    let mut call = Call::write("me", "POST", "/api/v1/presence".into(), json!({}));
    call.deadline_ms = Some(500);
    let client = server.client(journal);
    assert_eq!(client.call(&call).unwrap_err().code(), Some("rate_limited"));
    // This is only a transport warmup, not an orphan that startup must reconcile.
    client
        .resolve_pending(call.key.as_deref().unwrap())
        .unwrap();
}

#[test]
fn survey_r3_same_key_in_process_waits_until_deadline_without_resending() {
    let server = Server::start();
    let client = Arc::new(Client::new(&server.url, "fixture-token".into()).unwrap());
    let mut prime = Call::write("me", "POST", "/api/v1/presence".into(), json!({}));
    prime.deadline_ms = Some(500);
    assert_eq!(
        client.call(&prime).unwrap_err().code(),
        Some("rate_limited")
    );
    let done = start_call(Arc::clone(&client), survey_wait_call(5_000));
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let original = client.pending_operation("survey-wait-key").unwrap();
    let started = Instant::now();
    let error = client.call(&survey_wait_call(450)).unwrap_err();
    assert_eq!(error.code(), Some("journal_busy"));
    assert!(started.elapsed() >= Duration::from_millis(400));
    assert!(server.requests.try_recv().is_err());
    assert_eq!(
        client.pending_operation("survey-wait-key").unwrap(),
        original
    );
    first.reply(200, None);
    assert!(done.recv_timeout(WAIT).unwrap().is_ok());
    assert!(client.pending_operation("survey-wait-key").is_none());
    server.finish();
}

#[test]
fn a_second_process_replays_the_exact_long_poll_while_the_first_response_is_open() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let client = Arc::new(server.client(&journal));
    let done = start_call(Arc::clone(&client), survey_wait_call(10_000));
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "same_key_child", "--nocapture"])
        .env("LY_R2_URL", &server.url)
        .env("LY_R2_JOURNAL", &journal.0)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let second = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(second.key, first.key);
    assert_eq!(second.body, first.body);
    assert_eq!(second.path, first.path);
    let second_key = second.key.clone();
    let second_body = second.body.clone();
    second.reply(200, None);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    first.reply(200, None);
    assert_eq!(done.recv_timeout(WAIT).unwrap().unwrap()["id"], "A-1");
    let restored = Arc::new(server.client(&journal));
    assert!(restored.pending_operation("survey-wait-key").is_none());
    let done = start_call(restored, survey_wait_call(10_000));
    let after_completion = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(after_completion.key, second_key);
    assert_eq!(after_completion.body, second_body);
    after_completion.reply(200, None);
    assert_eq!(done.recv_timeout(WAIT).unwrap().unwrap()["id"], "A-1");
    let db = rusqlite::Connection::open(journal.0.join(".sqlite/pending.db")).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM pending_writes WHERE key = 'survey-wait-key'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    server.finish();
}

#[test]
fn same_key_child() {
    let Ok(url) = std::env::var("LY_R2_URL") else {
        return;
    };
    let journal = PathBuf::from(std::env::var_os("LY_R2_JOURNAL").unwrap());
    let client = Client::new(&url, "fixture-token".into())
        .unwrap()
        .load_pending_journal(journal)
        .unwrap()
        .with_content_encryption(
            "fixture-workspace",
            Some(WorkspaceKey::from_entropy([73; 32])),
            true,
        );
    assert_eq!(client.call(&survey_wait_call(8_000)).unwrap()["id"], "A-1");
}

#[test]
fn long_poll_completion_is_durable_while_an_unrelated_write_is_in_flight() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let waiter = Arc::new(server.client(&journal));
    let done = start_call(Arc::clone(&waiter), survey_wait_call(700));
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let sibling = Arc::new(server.client(&journal));
    let call = Call::write("me", "POST", "/api/v1/presence".into(), json!({}));
    let sibling_result = start_call(sibling, call);
    let other = server.requests.recv_timeout(WAIT).unwrap();
    assert_ne!(first.key, other.key);
    let first_body = first.body.clone();
    let owner = journal.begin_write();
    first.reply(200, None);
    assert!(matches!(
        done.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(owner);
    let success = done.recv_timeout(WAIT).unwrap();
    assert!(
        success.is_ok(),
        "a verified successful response was lost: {success:?}"
    );
    drop(waiter);
    let restored = server.client(&journal);
    assert!(restored.pending_operation("survey-wait-key").is_none());
    assert_eq!(journal.stored_body("survey-wait-key"), first_body);
    assert!(restored.pending_operation(&other.key).is_some());
    other.reply(200, None);
    assert!(sibling_result.recv_timeout(WAIT).unwrap().is_ok());
    server.finish();
}

struct Journal(PathBuf);

impl Journal {
    fn new() -> Self {
        Self(std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ly-pending-concurrency-{}",
            lockyard_cloud_client::ulid()
        )))
    }

    fn begin_write(&self) -> rusqlite::Connection {
        let db = rusqlite::Connection::open(self.0.join(".sqlite/pending.db")).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        db
    }

    fn stored_body(&self, key: &str) -> String {
        let db = rusqlite::Connection::open(self.0.join(".sqlite/pending.db")).unwrap();
        let payload: Vec<u8> = db
            .query_row(
                "SELECT payload FROM pending_writes WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_slice::<Value>(&payload).unwrap()["body"]
            .as_str()
            .unwrap()
            .to_owned()
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

    fn rate_limit(mut self, retry_after: u64) {
        write_reply_with_retry_after(
            &mut self.stream,
            429,
            json!({"status":429,"code":"rate_limited","detail":"fixture","details":{}}),
            retry_after,
        );
    }
}

struct Server {
    url: String,
    requests: mpsc::Receiver<PendingRequest>,
    hold_discovery: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (sender, requests) = mpsc::channel();
        let hold_discovery = Arc::new(AtomicBool::new(false));
        let hold_next_discovery = Arc::clone(&hold_discovery);
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
                if path == "/api/v1/protocol" && !hold_next_discovery.swap(false, Ordering::AcqRel)
                {
                    write_reply(
                        &mut stream,
                        200,
                        json!({
                            "selected_protocol":2,"min_protocol":1,"max_protocol":2,
                            "capabilities":["signed_results_v1"]
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
            hold_discovery,
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

    fn load_client(&self, journal: &Journal) -> Client {
        Client::new(&self.url, "fixture-token".into())
            .unwrap()
            .load_pending_journal(&journal.0)
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
    write_reply_with_retry_after(stream, status, value, 2);
}

fn write_reply_with_retry_after(
    stream: &mut TcpStream,
    status: u16,
    value: Value,
    retry_after: u64,
) {
    let body = value.to_string();
    let response = format!(
        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nLockyard-Protocol: 2\r\nDate: Thu, 12 Nov 2026 10:21:00 GMT\r\nRetry-After: {retry_after}\r\n\r\n{body}",
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

fn same_key_waiter_gets_the_first_reply(same_client: bool) {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let sender = Arc::new(server.client(&journal));
    let waiter = if same_client {
        Arc::clone(&sender)
    } else {
        Arc::new(server.client(&journal))
    };
    let mut call = Call::write(
        "me",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title": "one create"}),
    );
    call.deadline_ms = Some(4_000);
    let key = call.key.clone().unwrap();

    let sent = start_call(sender, call.clone());
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let waiting = start_call(waiter, call.clone());
    let resent = server.requests.recv_timeout(WAIT).unwrap();
    assert!(waiting.try_recv().is_err());
    assert_eq!(resent.key, first.key);
    assert_eq!(resent.path, call.path);
    assert_eq!(
        resent.body, first.body,
        "the resend must reuse the journaled wire bytes"
    );
    assert_eq!(resent.body, journal.stored_body(&key));
    assert!(
        first.body.contains("lyenc1."),
        "fixture must exercise encrypted wire bytes"
    );
    first.reply(200, None);
    assert_eq!(
        sent.recv_timeout(WAIT).unwrap().unwrap(),
        json!({"id":"A-1"})
    );
    resent.reply(200, None);
    assert_eq!(
        waiting.recv_timeout(WAIT).unwrap().unwrap(),
        json!({"id":"A-1"})
    );
    assert!(
        server
            .requests
            .recv_timeout(Duration::from_millis(300))
            .is_err()
    );
    assert!(server.client(&journal).pending_operation(&key).is_none());
    server.finish();
}

#[test]
fn same_key_waiter_in_another_client_gets_the_first_reply() {
    same_key_waiter_gets_the_first_reply(false);
}

#[test]
fn same_key_waiter_in_the_same_client_gets_the_first_reply() {
    same_key_waiter_gets_the_first_reply(true);
}

#[test]
fn same_key_resend_refused_as_reused_reconciles_by_key() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let sender = Arc::new(server.client(&journal));
    let waiter = Arc::new(server.client(&journal));
    let mut call = Call::write(
        "me",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title": "one create"}),
    );
    call.deadline_ms = Some(4_000);
    let key = call.key.clone().unwrap();
    let sent = start_call(sender, call.clone());
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let waiting = start_call(waiter, call);
    let resent = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(resent.body, first.body);
    first.reply(200, None);
    assert!(sent.recv_timeout(WAIT).unwrap().is_ok());
    let mut stream = resent.stream;
    write_reply(
        &mut stream,
        409,
        json!({"status":409,"code":"conflict",
               "detail":"Idempotency-Key was used for another request.","details":{}}),
    );
    let error = waiting.recv_timeout(WAIT).unwrap().unwrap_err();
    assert_eq!(error.code(), Some("outcome_unknown"));
    // The waiter learns which key to reconcile, and the refused resend is not retried.
    let reported = match &error {
        ClientError::OutcomeUnknown(pending) => pending.key.clone(),
        other => other.to_string(),
    };
    assert!(reported.contains(&key), "{reported}");
    assert!(
        server
            .requests
            .recv_timeout(Duration::from_millis(300))
            .is_err()
    );
    // The finished sender's row is never written back by the waiter.
    assert!(server.client(&journal).pending_operation(&key).is_none());
    server.finish();
}

#[test]
fn pending_replay_http_uses_the_time_left_after_journal_wait() {
    let server = Server::start();
    let journal = Journal::new();
    let client = Arc::new(server.client(&journal));
    let mut call = Call::write(
        "me",
        "POST",
        "/api/v1/registry/items".into(),
        json!({"title":"replay"}),
    );
    call.deadline_ms = Some(1_000);
    assert_eq!(client.call(&call).unwrap_err().code(), Some("rate_limited"));
    assert!(
        client
            .pending_operation(call.key.as_deref().unwrap())
            .unwrap()
            .pre_execution_rejected
    );

    let held = journal.begin_write();
    let done = start_call(Arc::clone(&client), call.clone());
    std::thread::sleep(Duration::from_millis(800));
    assert!(server.requests.try_recv().is_err());
    drop(held);

    let replay = server
        .requests
        .recv_timeout(WAIT)
        .expect("the pending create reached HTTP");
    assert_eq!(replay.key, call.key.unwrap());
    // Keep the HTTP response open. At most 200 ms of the original budget were
    // left when the journal unlocked. Allow scheduler slack when observing it.
    let result = done.recv_timeout(Duration::from_millis(350));
    drop(replay);
    let error = result
        .expect("pending replay exceeded the remaining HTTP budget")
        .unwrap_err();
    assert!(matches!(error, ClientError::OutcomeUnknown(_)), "{error:?}");
    server.finish();
}

#[test]
fn long_poll_protocol_rediscovery_allows_a_sibling_zone_release() {
    for same_client in [false, true] {
        check_sibling_release_during_rediscovery(same_client);
    }
}

fn check_sibling_release_during_rediscovery(same_client: bool) {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let waiter = Arc::new(server.client(&journal));
    let sibling = if same_client {
        Arc::clone(&waiter)
    } else {
        let sibling = Arc::new(server.client(&journal));
        sibling.negotiated_protocol("other").unwrap();
        sibling
    };

    let done = start_call(waiter, survey_wait_call(8_000));
    let mut first = server.requests.recv_timeout(WAIT).unwrap();
    let key = first.key.clone();
    let body = first.body.clone();
    server.hold_discovery.store(true, Ordering::Release);
    write_reply(
        &mut first.stream,
        400,
        json!({"status":400,"code":"protocol_unsupported","detail":"fixture","details":{}}),
    );
    let mut discovery = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(discovery.path, "/api/v1/protocol");

    let mut release = Call::write(
        "other",
        "DELETE",
        "/api/v1/zones/claims/1".into(),
        json!({}),
    );
    release.deadline_ms = Some(2_000);
    let released = start_call(sibling, release);
    if let Ok(request) = server.requests.recv_timeout(Duration::from_millis(2_200)) {
        assert_eq!(request.path, "/api/v1/zones/claims/1");
        request.reply(200, None);
    }
    assert_eq!(
        released
            .recv_timeout(WAIT)
            .unwrap()
            .map_err(|error| error.to_string()),
        Ok(json!({"id":"A-1"})),
        "sibling release was blocked during protocol rediscovery"
    );

    std::thread::sleep(Duration::from_millis(2_100));
    write_reply(
        &mut discovery.stream,
        200,
        json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":[]}),
    );
    let retry = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(retry.key, key);
    assert_eq!(retry.body, body);
    retry.reply(200, None);
    assert!(done.recv_timeout(WAIT).unwrap().is_ok());
    server.finish();
}

#[test]
fn long_poll_retry_after_allows_a_sibling_zone_release() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let waiter = Arc::new(server.client(&journal));
    let sibling = Arc::new(server.client(&journal));
    let done = start_call(Arc::clone(&waiter), survey_wait_call(8_000));
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let original_body = first.body.clone();
    let refused_at = Instant::now();
    first.rate_limit(5);
    let until = Instant::now() + Duration::from_secs(2);
    while !waiter
        .pending_operation("survey-wait-key")
        .is_some_and(|row| row.pre_execution_rejected)
    {
        assert!(
            Instant::now() < until,
            "the rate limit was not recorded before backoff"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut release = Call::write(
        "other",
        "DELETE",
        "/api/v1/zones/claims/1".into(),
        json!({}),
    );
    release.deadline_ms = Some(2_000);
    let released = start_call(sibling, release);
    if let Ok(request) = server.requests.recv_timeout(Duration::from_millis(2_200)) {
        assert_eq!(request.path, "/api/v1/zones/claims/1");
        request.reply(200, None);
    }
    assert_eq!(
        released
            .recv_timeout(WAIT)
            .unwrap()
            .map_err(|error| error.to_string()),
        Ok(json!({"id":"A-1"})),
        "sibling release was blocked during Retry-After"
    );
    let retry = server
        .requests
        .recv_timeout(Duration::from_secs(8))
        .unwrap_or_else(|error| {
            panic!(
                "no claim retry: {error}; wait result: {:?}",
                done.try_recv()
            )
        });
    assert!(refused_at.elapsed() >= Duration::from_secs(5));
    assert_eq!(retry.key, "survey-wait-key");
    assert_eq!(retry.body, original_body);
    retry.reply(200, None);
    assert!(done.recv_timeout(WAIT).unwrap().is_ok());
    server.finish();
}

fn concurrent_retry(same_client: bool, success_first: bool) {
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
    let first_client = Arc::new(server.load_client(&journal));
    let second_client = if same_client {
        Arc::clone(&first_client)
    } else {
        Arc::new(server.load_client(&journal))
    };
    // The first network operation stays held while the second caller starts. This puts the
    // durable marker in its unknown/in-flight state before the contender inspects it.
    call.deadline_ms = Some(10_000);
    let first_done = start_call(Arc::clone(&first_client), call.clone());
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let first_body = first.body.clone();
    assert_eq!(first_body, original.body.as_deref().unwrap());
    let second_done = start_call(Arc::clone(&second_client), call.clone());
    let second = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(second.body, first_body);
    assert_eq!(second.key, key);
    assert_eq!(second.path, first.path);
    // A refusal cannot restore safe-retry permission while an overlapping send
    // can still succeed or after its success became durable.
    let succeed = || {
        second.reply(200, None);
        assert_eq!(
            second_done.recv_timeout(WAIT).unwrap().unwrap()["id"],
            "A-1"
        );
    };
    let refuse = || {
        first.reply(503, Some("server_draining"));
        assert!(matches!(
            first_done.recv_timeout(WAIT).unwrap(),
            Err(ClientError::OutcomeUnknown(_))
        ));
        assert!(
            seed.pending_operation(key)
                .is_none_or(|row| !row.pre_execution_rejected)
        );
    };
    if success_first {
        succeed();
        refuse();
    } else {
        refuse();
        succeed();
    }

    let restored = server.client(&journal);
    assert!(
        restored
            .pending_operation(key)
            .is_none_or(|pending| !pending.pre_execution_rejected),
        "a successful overlapping operation must not be restored as a safe refusal"
    );
    server.finish();
}

#[test]
fn restored_clients_replay_same_bytes_and_cannot_recreate_safe_refusal() {
    for success_first in [true, false] {
        concurrent_retry(false, success_first);
    }
}

#[test]
fn deferred_retries_replay_same_bytes_and_cannot_recreate_safe_refusal() {
    for success_first in [true, false] {
        concurrent_retry(true, success_first);
    }
}

#[test]
fn concurrent_signed_result_refusals_keep_the_longest_retry_after() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let open = || {
        server.client(&journal).with_content_encryption(
            "00000000-0000-4000-8000-000000000001",
            Some(WorkspaceKey::from_entropy([73; 32])),
            true,
        )
    };
    let first = open();
    let second = open();
    let job = lockyard_cloud_client::ulid();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let expiry =
        Client::signed_result_expiry("worker", &job, now.as_millis() as u64 + 60_000).unwrap();
    let earliest_retry = now.as_secs() + 3600;

    let send = |client: &Client| {
        client.put_signed_result("worker", "worker", &job, b"synthetic result", expiry)
    };
    std::thread::scope(|scope| {
        let original = scope.spawn(|| send(&first));
        let request = server.requests.recv_timeout(WAIT).unwrap();
        let replay = scope.spawn(|| send(&second));
        let repeated = server.requests.recv_timeout(WAIT).unwrap();
        assert_eq!(request.path, repeated.path);
        assert_eq!(request.body, repeated.body);
        request.reply(408, Some("request_timeout"));
        assert_eq!(
            original.join().unwrap().unwrap_err().code(),
            Some("outcome_unknown")
        );
        repeated.rate_limit(3600);
        assert_eq!(
            replay.join().unwrap().unwrap_err().code(),
            Some("outcome_unknown")
        );
    });

    let reopened = server.load_client(&journal);
    let row = reopened.signed_result_pending("worker", &job).unwrap();
    assert!(
        row.result_retry_at.unwrap() >= earliest_retry,
        "{:?}",
        row.result_retry_at
    );
    assert!(!row.pre_execution_rejected);
    assert!(!Client::result_retry_ready(&row));
    server.finish();
}

#[test]
fn full_byte_budget_keeps_a_signed_result_quota_suspension() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let client = server.client(&journal).with_content_encryption(
        "00000000-0000-4000-8000-000000000001",
        Some(WorkspaceKey::from_entropy([73; 32])),
        true,
    );
    let job = lockyard_cloud_client::ulid();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let expiry =
        Client::signed_result_expiry("worker", &job, now.as_millis() as u64 + 60_000).unwrap();
    let (original, error) = std::thread::scope(|scope| {
        let send = scope.spawn(|| {
            client.put_signed_result("worker", "worker", &job, b"synthetic result", expiry)
        });
        let mut put = server.requests.recv_timeout(WAIT).unwrap();
        let original = client.signed_result_pending("worker", &job).unwrap();
        let db = journal.begin_write();
        let mut filler = original.clone();
        filler.key = "fixture-filler".into();
        filler.body = Some(String::new());
        let extra = 16 * 1024 * 1024
            - serde_json::to_vec(&original).unwrap().len()
            - serde_json::to_vec(&filler).unwrap().len();
        filler.body = Some("x".repeat(extra));
        db.execute(
            "INSERT INTO pending_writes (scope, key, state, payload, budget_bytes)
             SELECT scope, ?2, 'pending', ?3, length(?3) FROM pending_writes WHERE key = ?1",
            rusqlite::params![
                original.key,
                filler.key,
                serde_json::to_vec(&filler).unwrap()
            ],
        )
        .unwrap();
        db.execute_batch("COMMIT").unwrap();
        write_reply_with_retry_after(
            &mut put.stream,
            429,
            json!({"status":429,"code":"relay_budget_exceeded","detail":"fixture","details":{}}),
            3600,
        );
        (original, send.join().unwrap().unwrap_err())
    });
    let reopened = server.load_client(&journal).with_content_encryption(
        "00000000-0000-4000-8000-000000000001",
        Some(WorkspaceKey::from_entropy([73; 32])),
        true,
    );
    let suspended = reopened.signed_result_pending("worker", &job).unwrap();
    assert_eq!(suspended.body, original.body);
    assert_eq!(suspended.result_expires_at, original.result_expires_at);
    assert!(suspended.result_retry_at.unwrap() >= now.as_secs() + 3600);
    assert_eq!(suspended.cause_status, Some(429));
    assert_eq!(suspended.cause_code, "relay_budget_exceeded");
    assert!(suspended.pre_execution_rejected);
    assert!(!Client::result_retry_ready(&suspended));
    assert_eq!(error.code(), Some("relay_budget_exceeded"));
    reopened.resume_signed_result(&suspended.key).unwrap();
    let resumed = reopened.signed_result_pending("worker", &job).unwrap();
    assert_eq!(resumed.cause_status, None);
    assert!(resumed.replay_paused);
    assert_eq!(resumed.result_retry_at, suspended.result_retry_at);
    assert_eq!(resumed.body, suspended.body);
    assert_eq!(resumed.result_expires_at, suspended.result_expires_at);
    assert!(!Client::result_retry_ready(&resumed));
    assert_eq!(
        reopened
            .replay_signed_result(&resumed.key)
            .unwrap_err()
            .code(),
        Some("outcome_unknown")
    );
    assert!(server.requests.try_recv().is_err());
    server.finish();
}

#[test]
fn fixture_cleanup_preserves_failure_instead_of_aborting() {
    const CHILD: &str = "LOCKYARD_PENDING_FIXTURE_UNWIND";
    if std::env::var_os(CHILD).is_some() {
        let (_sender, requests) = mpsc::channel();
        let _server = Server {
            hold_discovery: Arc::new(AtomicBool::new(false)),
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

#[test]
fn write_waits_out_a_busy_pending_journal_within_the_deadline() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let waiter = Arc::new(server.client(&journal));
    let held = journal.begin_write();
    let mut call = Call::write("me", "POST", "/api/v1/presence".into(), json!({}));
    call.key = Some("wait-key".into());
    call.deadline_ms = Some(2_000);
    let started = Instant::now();
    let wait = start_call(waiter, call);
    std::thread::sleep(Duration::from_millis(200));
    assert!(server.requests.try_recv().is_err());
    drop(held);

    let sent = server.requests.recv_timeout(WAIT).unwrap();
    assert_eq!(sent.key, "wait-key");
    sent.reply(200, None);
    assert!(wait.recv_timeout(WAIT).unwrap().is_ok());
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() <= Duration::from_millis(2_000) + Duration::from_millis(750));
    server.finish();
    assert!(
        !lockyard_core::Error::Unavailable("pending journal is busy".into())
            .to_string()
            .contains("check the network")
    );
    assert!(matches!(
        lockyard_cloud_client::ClientError::JournalBusy
            .to_string()
            .as_str(),
        "pending journal is busy"
    ));
}

#[test]
fn unrelated_short_writes_can_reach_the_server_concurrently() {
    let server = Server::start();
    let journal = Journal::new();
    survey_prime(&server, &journal);
    let first_client = Arc::new(server.client(&journal));
    let second_client = Arc::new(server.client(&journal));
    let call = || Call::write("me", "POST", "/api/v1/presence".into(), json!({}));
    let first_result = start_call(first_client, call());
    let first = server.requests.recv_timeout(WAIT).unwrap();
    let second_result = start_call(second_client, call());
    let second = server.requests.recv_timeout(WAIT).unwrap();
    assert_ne!(first.key, second.key);
    second.reply(200, None);
    assert!(second_result.recv_timeout(WAIT).unwrap().is_ok());
    first.reply(200, None);
    assert!(first_result.recv_timeout(WAIT).unwrap().is_ok());
    server.finish();
}

/// A sibling release can reach the server while a long-poll claim is still open.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn long_poll_releases_the_pending_journal_while_waiting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (ready_tx, ready_rx) = mpsc::channel::<TcpStream>();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while !stopping.load(Ordering::Acquire) {
            let (mut stream, _) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            stream.set_nonblocking(false).unwrap();
            let (path, _body, _key) = read_request(&mut stream);
            if path == "/api/v1/protocol" {
                write_reply(
                    &mut stream,
                    200,
                    json!({
                        "selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":[]
                    }),
                );
            } else {
                let _ = ready_tx.send(stream);
            }
        }
    });

    let journal = Journal::new();
    let waiter = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(&journal.0)
        .unwrap();

    let wait = std::thread::spawn(move || {
        let mut call = Call::write(
            "me",
            "POST",
            "/api/v1/zones/claims".into(),
            json!({"paths":["src"],"note":"","ttl_minutes":30}),
        );
        call.key = Some("wait-key".into());
        call.long_poll = true;
        call.deadline_ms = Some(8_000);
        waiter.call(&call)
    });
    let held = ready_rx
        .recv_timeout(WAIT)
        .expect("long-poll claim reached the server");

    let mut release = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "long_poll_sibling_process", "--nocapture"])
        .env("LY_SURVEY_URL", &url)
        .env("LY_SURVEY_JOURNAL", &journal.0)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let release_stream = ready_rx
        .recv_timeout(WAIT)
        .expect("sibling release must reach the server while wait still holds its HTTP response");
    write_reply(&mut { release_stream }, 200, json!({"released": 1}));
    assert!(release.wait().unwrap().success());

    write_reply(
        &mut { held },
        200,
        json!({"claim":{"id":1,"session":"me","paths":["src"],"fence":1,"expires_at":999999},
               "created":true}),
    );
    assert!(wait.join().unwrap().is_ok());
    stop.store(true, Ordering::Release);
    let _ = worker.join();
}

#[test]
fn long_poll_sibling_process() {
    let Ok(url) = std::env::var("LY_SURVEY_URL") else {
        return;
    };
    let journal = std::env::var_os("LY_SURVEY_JOURNAL").unwrap();
    let client = Client::new(&url, "fixture-token".into())
        .unwrap()
        .with_pending_journal(PathBuf::from(journal))
        .unwrap();
    let mut call = Call::write("me", "DELETE", "/api/v1/zones/claims/9".into(), json!({}));
    call.key = Some("release-key".into());
    call.deadline_ms = Some(2_000);
    client.call(&call).unwrap();
}
