// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Bounded SSE framing. A partial frame at EOF is discarded and replayed after reconnect.
use crate::{Client, ClientError};
use lockyard_core::proto::Event;
use std::io::{self, BufRead, BufReader, Read};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub const READ_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_FRAME: usize = 1024 * 1024;

pub struct EventStream {
    reader: BufReader<Box<dyn Read + Send>>,
    interrupt: Arc<AtomicBool>,
}

impl EventStream {
    pub fn new(reader: Box<dyn Read + Send>) -> Self {
        Self {
            reader: BufReader::new(reader),
            interrupt: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn interrupt_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupt)
    }

    /// None is EOF. Comments return an empty frame so the daemon can check shutdown.
    pub fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        let mut frame = Frame::default();
        let mut size = 0;
        loop {
            let mut bytes = Vec::new();
            let n = self
                .reader
                .by_ref()
                .take((MAX_FRAME.saturating_sub(size) + 1) as u64)
                .read_until(b'\n', &mut bytes)?;
            if n == 0 {
                return Ok(None);
            }
            size = size.saturating_add(n);
            if size > MAX_FRAME {
                // Drain through the next delimiter without allocating an unbounded line.
                frame.invalid = Some("SSE frame too large");
                let mut ended_line = bytes.ends_with(b"\n");
                loop {
                    let mut chunk = Vec::new();
                    let n = self
                        .reader
                        .by_ref()
                        .take(8192)
                        .read_until(b'\n', &mut chunk)?;
                    if n == 0 {
                        return Ok(None);
                    }
                    if ended_line && matches!(chunk.as_slice(), b"\n" | b"\r\n") {
                        break;
                    }
                    ended_line = chunk.ends_with(b"\n");
                }
                return Ok(Some(frame));
            }
            let line = match std::str::from_utf8(&bytes) {
                Ok(line) => line,
                Err(_) => {
                    frame.invalid = Some("SSE frame is not UTF-8");
                    continue;
                }
            };
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                return Ok(Some(frame));
            }
            if line.starts_with(':') {
                if frame.id.is_none() && frame.data.is_empty() && frame.event.is_empty() {
                    return Ok(Some(frame));
                }
                continue;
            }
            let (key, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match key {
                "id" if !value.contains('\0') => frame.id = Some(value.to_string()),
                "event" => frame.event = value.to_string(),
                "data" => {
                    frame.data.push_str(value);
                    frame.data.push('\n');
                }
                _ => {}
            }
        }
    }
}

// The body stays on this worker's runtime. Cancellation drops the pending async read,
// then dropping Response closes the connection; no detached reader or 45-second join.
struct NetworkReader {
    runtime: tokio::runtime::Runtime,
    response: reqwest::Response,
    interrupt: Arc<AtomicBool>,
    pending: Vec<u8>,
    offset: usize,
}
impl Read for NetworkReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let started = Instant::now();
        while self.offset == self.pending.len() {
            if self.interrupt.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "SSE cancelled",
                ));
            }
            let next = self.runtime.block_on(async {
                tokio::time::timeout(Duration::from_millis(50), self.response.chunk()).await
            });
            match next {
                Ok(Ok(Some(bytes))) => {
                    self.pending = bytes.to_vec();
                    self.offset = 0;
                }
                Ok(Ok(None)) => return Ok(0),
                Ok(Err(e)) => return Err(io::Error::other(e)),
                Err(_) if started.elapsed() < READ_TIMEOUT => continue,
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "SSE idle timeout")),
            }
        }
        let n = out.len().min(self.pending.len() - self.offset);
        out[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

#[derive(Default, Debug)]
pub struct Frame {
    pub id: Option<String>,
    pub event: String,
    pub data: String,
    pub invalid: Option<&'static str>,
}

impl Frame {
    pub fn decode(&self) -> Result<Option<Event>, ClientError> {
        if let Some(error) = self.invalid {
            return Err(ClientError::Decode(error.into()));
        }
        if self.data.is_empty() {
            return Ok(None);
        }
        let mut value: serde_json::Value = serde_json::from_str(&self.data)
            .map_err(|error| ClientError::Decode(format!("SSE data: {error}")))?;
        if !value.is_object() {
            return Err(ClientError::Decode("SSE data must be an object".into()));
        }
        if value.get("seq").is_none() {
            value["seq"] = self
                .id
                .as_deref()
                .and_then(|id| id.parse::<i64>().ok())
                .unwrap_or(0)
                .into();
        }
        if value.get("type").is_none() {
            value["type"] = self.event.clone().into();
        }
        // Accept both the ordinary event envelope and mail metadata directly in SSE data.
        if value.get("payload").is_none_or(serde_json::Value::is_null) {
            let object = value.as_object_mut().expect("checked object");
            let keys: Vec<_> = object
                .keys()
                .filter(|key| {
                    !matches!(
                        key.as_str(),
                        "seq" | "type" | "event_id" | "session" | "created_at" | "payload"
                    )
                })
                .cloned()
                .collect();
            let mut payload = serde_json::Map::new();
            for key in keys {
                if let Some(value) = object.remove(&key) {
                    payload.insert(key, value);
                }
            }
            if !payload.is_empty() {
                object.insert("payload".into(), payload.into());
            }
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(|e| ClientError::Decode(e.to_string()))
    }
}

impl Client {
    pub(crate) fn open_event_stream(
        &self,
        session: &str,
        after: i64,
    ) -> Result<EventStream, ClientError> {
        self.open_event_stream_sessions(
            session,
            &[session.to_string()],
            after,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub(crate) fn open_event_stream_sessions(
        &self,
        session: &str,
        sessions: &[String],
        after: i64,
        interrupt: Arc<AtomicBool>,
    ) -> Result<EventStream, ClientError> {
        if sessions.is_empty() || sessions.len() > 32 {
            return Err(ClientError::Invalid("SSE requires 1..=32 sessions".into()));
        }
        let protocol = self.negotiated_protocol(session)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        // Match ureq: direct connections and the bundled Mozilla/WebPKI roots.
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .read_timeout(READ_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let response = runtime.block_on(async {
            let pending = client
                .get(format!("{}/api/v1/events", self.base_url))
                .query(&[
                    ("sessions", sessions.join(",")),
                    ("after", after.to_string()),
                ])
                .header("Accept", "text/event-stream")
                .bearer_auth(&self.token)
                .header("X-Lockyard-Session", session)
                .header("X-Lockyard-Capabilities", "mail_push_v1")
                .header("Lockyard-Protocol", protocol.selected.to_string())
                .header("Last-Event-ID", after.to_string())
                .send();
            tokio::pin!(pending);
            loop {
                if interrupt.load(Ordering::Acquire) {
                    return Err(ClientError::Transport("SSE handshake cancelled".into()));
                }
                match tokio::time::timeout(Duration::from_millis(50), &mut pending).await {
                    Ok(result) => {
                        return result.map_err(|e| ClientError::Transport(format!("SSE: {e}")));
                    }
                    Err(_) => continue,
                }
            }
        })?;
        let status = response.status().as_u16();
        if status != 200 {
            let retry_after = response
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            // Bound both time and allocation even for a hostile error response.
            let body = runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    let mut response = response;
                    let mut bytes = Vec::new();
                    while let Some(chunk) = response
                        .chunk()
                        .await
                        .map_err(|e| ClientError::Transport(e.to_string()))?
                    {
                        if bytes.len() + chunk.len() > 64 * 1024 {
                            return Err(ClientError::Decode("SSE error body too large".into()));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    Ok(String::from_utf8_lossy(&bytes).into_owned())
                })
                .await
                .map_err(|_| ClientError::Transport("SSE error body timeout".into()))?
            })?;
            return Err(ClientError::from_api(crate::protocol::parse_api_error(
                status,
                &body,
                retry_after,
            )?));
        }
        if !protocol.legacy {
            let values: Vec<_> = response
                .headers()
                .get_all("Lockyard-Protocol")
                .iter()
                .collect();
            if values.len() != 1
                || values[0].to_str().ok() != Some(protocol.selected.to_string().as_str())
            {
                return Err(ClientError::Decode("SSE protocol echo mismatch".into()));
            }
        }
        if response
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| {
                !v.split(';')
                    .next()
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
            })
        {
            return Err(ClientError::Decode(
                "SSE response is not text/event-stream".into(),
            ));
        }
        let reader = NetworkReader {
            runtime,
            response,
            interrupt: interrupt.clone(),
            pending: Vec::new(),
            offset: 0,
        };
        Ok(EventStream {
            reader: BufReader::new(Box::new(reader)),
            interrupt,
        })
    }

    /// Isolate bad events without publishing unauthenticated content. Sequence-only
    /// tombstones preserve progress for JSON consumers just as skipped SSE ids do.
    pub(crate) fn decode_json_events(
        &self,
        value: &mut serde_json::Value,
    ) -> Result<(), ClientError> {
        let events = if value.is_array() {
            value.as_array_mut()
        } else {
            value
                .get_mut("events")
                .and_then(serde_json::Value::as_array_mut)
        }
        .ok_or_else(|| ClientError::Decode("event page must contain an array".into()))?;
        for raw in events {
            let seq = raw
                .get("seq")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);
            // Structural failures and a plaintext event in an encrypted field become tombstones
            // (content never surfaced): retrying cannot fix them, and one bad server event must
            // not wedge the JSON cursor forever. Authentication failures and a missing key may be
            // a key rotation in progress, so they fail the page and it is replayed later.
            let decoded = serde_json::from_value::<Event>(raw.clone())
                .map_err(|e| ClientError::Decode(e.to_string()))
                .and_then(|event| {
                    let mut event = event;
                    self.decode_stream_event(&mut event)?;
                    Ok(event)
                });
            match decoded {
                Ok(event) => {
                    *raw = serde_json::to_value(event)
                        .map_err(|e| ClientError::Decode(e.to_string()))?
                }
                Err(ClientError::Invalid(error)) if error.ends_with("contains plaintext") => {
                    eprintln!("lockyard: dropping JSON event {seq} with rejected content: {error}");
                    *raw = serde_json::json!({"seq":seq,"type":"","payload":null});
                }
                Err(error) if !matches!(error, ClientError::Decode(_)) => return Err(error),
                Err(_) => {
                    eprintln!("lockyard: skipping malformed JSON event at {seq}");
                    *raw = serde_json::json!({"seq":seq,"type":"","payload":null});
                }
            }
        }
        Ok(())
    }

    pub(crate) fn decode_stream_event(&self, event: &mut Event) -> Result<(), ClientError> {
        if let Some(workspace) = &self.workspace {
            let key = self.resolved_content_key()?;
            let mut value = serde_json::json!([&*event]);
            crate::crypto::transform_fields_policy(
                &mut value,
                "GET",
                "/api/v1/events",
                workspace,
                key.as_ref(),
                false,
                self.expected_e2ee_workspace.is_some(),
            )
            .map_err(|error| {
                if crate::crypto::is_content_failure(&error) {
                    ClientError::Invalid(error)
                } else {
                    ClientError::Decode(error)
                }
            })?;
            *event = serde_json::from_value(value[0].take())
                .map_err(|e| ClientError::Decode(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Transport,
        fake::{FakeServer, Reply},
    };

    #[test]
    fn mail_push_json_required_skips_bad_event_and_advances_past_it() {
        use crate::{Call, WorkspaceKey};
        use lockyard_core::proto::EventPage;
        let workspace = "00000000-0000-0000-0000-000000000001";
        let key = WorkspaceKey::from_entropy([19; 32]);
        let unread = serde_json::json!({"seq":1,"type":"bus.unread","session":"alice","payload":{
            "id":5000000000i64,"thread_id":5000000000i64,"reply_to":null,"from":"bob","from_alias":null,
            "to":"alice","address":null,"urgent":true,"kind":"ask","needs":"reply",
            "created_at":"2026-11-16T01:02:03Z","role":"recipient"}});
        for wrapped in [false, true] {
            let mut bad = unread.clone();
            bad["seq"] = 2.into();
            bad["payload"]["id"] = "42".into();
            let events = serde_json::json!([unread, bad,
                {"seq":3,"type":42,"payload":{"body":"PRIVATE"}},
                {"seq":4,"type":"future.event","payload":{"body":"PRIVATE"}},
                {"seq":5,"type":"bus.delivery_claimed","payload":{"ids":[42]}},
                {"seq":6,"type":"bus.imported","payload":{"threads":1,"board":0,"tasks":0}},
                {"seq":7,"type":"bus.message","session":"alice","payload":{"id":43,"thread_id":43,
                    "from":"bob","to":"alice","urgent":true,"body":key.encrypt(workspace,"body","private").unwrap()}}
            ]);
            let body = if wrapped {
                serde_json::json!({"events":events})
            } else {
                events
            };
            let server = FakeServer::start(vec![Reply::json(200, body)]);
            let client = Client::new(&server.url(), "fixture-token".into())
                .unwrap()
                .require_e2ee_for(workspace)
                .unwrap()
                .with_content_encryption(workspace, Some(key.clone()), true);
            let value = client
                .call(&Call::get("alice", "/api/v1/events".into()))
                .unwrap();
            let events = if wrapped {
                value["events"].clone()
            } else {
                value
            };
            let page: EventPage =
                serde_json::from_value(serde_json::json!({"events":events})).unwrap();
            assert_eq!(page.last_seq(0), 7);
            for i in 1..=3 {
                assert_eq!(page.events[i].kind, "");
                assert!(page.events[i].payload.is_null());
            }
            assert_eq!(page.events[0].kind, "bus.unread");
            assert_eq!(page.events[6].payload["body"], "private");
        }
        // A malformed final/only event still yields a cursor-bearing tombstone.
        let client = Client::new("http://127.0.0.1:1", "fixture".into())
            .unwrap()
            .require_e2ee_for(workspace)
            .unwrap()
            .with_content_encryption(workspace, Some(key), true);
        let mut value = serde_json::json!({"events":[{"seq":99,"type":"unknown","payload":{"body":"PRIVATE"}}]});
        client.decode_json_events(&mut value).unwrap();
        assert_eq!(
            value["events"][0],
            serde_json::json!({"seq":99,"type":"","payload":null})
        );
    }

    #[test]
    fn mail_push_json_key_and_auth_failures_replay_whole_page() {
        use crate::WorkspaceKey;
        use lockyard_core::proto::EventPage;
        // Unit-test key storage is isolated from the user's real key directory.
        let workspace = format!("r4-{}", crate::ulid().to_lowercase());
        let key = WorkspaceKey::from_entropy([81; 32]);
        let wire = serde_json::json!({"events":[
            {"seq":1,"type":"zone.claimed","payload":{"id":1}},
            {"seq":2,"type":"bus.message","session":"alice","payload":{
                "id":2,"thread_id":2,"from":"bob","to":"alice","body":key.encrypt(&workspace,"body","private").unwrap()
            }}
        ]});
        let server = FakeServer::start(vec![
            Reply::json(200, wire.clone()),
            Reply::json(200, wire.clone()),
        ]);
        let client = Client::new(&server.url(), "fixture".into())
            .unwrap()
            .with_content_encryption(&workspace, None, true);
        let call = crate::Call::get("alice", "/api/v1/events?after=0".into());
        assert!(matches!(client.call(&call), Err(ClientError::Invalid(_))));
        key.store_for_workspace(&workspace).unwrap();
        let value = client.call(&call).unwrap();
        let page: EventPage = serde_json::from_value(value).unwrap();
        assert_eq!(page.last_seq(0), 2);
        assert_eq!(page.events[1].payload["body"], "private");
        let polls = server.requests();
        assert_eq!(
            polls
                .iter()
                .filter(|r| r.path == "/api/v1/events?after=0")
                .count(),
            2
        );
        // Authentication failure is retryable in both optional and required encryption.
        for required in [false, true] {
            let client = Client::new(&server.url(), "fixture".into())
                .unwrap()
                .with_content_encryption(&workspace, None, true);
            let client = if required {
                client.require_e2ee_for(&workspace).unwrap()
            } else {
                client
            };
            let mut broken = wire.clone();
            broken["events"][1]["payload"]["body"] =
                key.encrypt(&workspace, "text", "wrong AAD").unwrap().into();
            assert!(matches!(
                client.decode_json_events(&mut broken),
                Err(ClientError::Invalid(_))
            ));
        }
        // A nullable nested claim must not turn an authentication error into a
        // schema error after trying its alternative JSON-schema branches.
        for required in [false, true] {
            let client = Client::new(&server.url(), "fixture".into())
                .unwrap()
                .with_content_encryption(&workspace, None, true);
            let client = if required {
                client.require_e2ee_for(&workspace).unwrap()
            } else {
                client
            };
            let mut nested = serde_json::json!({"events":[{"seq":3,"type":"zone.answered","payload":{
                "claim":{"id":7,"note":key.encrypt(&workspace,"body","wrong AAD").unwrap()}
            }}]});
            assert!(matches!(
                client.decode_json_events(&mut nested),
                Err(ClientError::Invalid(_))
            ));
            nested["events"][0]["payload"]["claim"]["note"] =
                key.encrypt(&workspace, "note", "held").unwrap().into();
            client.decode_json_events(&mut nested).unwrap();
            assert_eq!(nested["events"][0]["payload"]["claim"]["note"], "held");
        }
        std::fs::remove_file(WorkspaceKey::storage_path(&workspace).unwrap()).unwrap();
    }

    #[test]
    fn mail_push_sse_forbidden_reports_real_token_binding_details() {
        let server = FakeServer::start_routed_with_capabilities(&["mail_push_v1"]);
        server.bind_session("alice", "own");
        server.bind_session("foreign", "another-token");
        let client = Client::new(&server.url(), "own".into()).unwrap();
        let error = client
            .event_stream_sessions(
                "agent",
                &["alice".into(), "foreign".into(), "typo".into()],
                0,
                Arc::new(AtomicBool::new(false)),
            )
            .err()
            .unwrap();
        let ClientError::Denied(error) = error else {
            panic!("expected forbidden binding error");
        };
        assert_eq!(
            error.details["sessions"],
            serde_json::json!(["foreign", "typo"])
        );
    }

    #[test]
    fn mail_push_sse_frames_multiline_heartbeat_and_truncated_eof() {
        let server = FakeServer::start(vec![Reply::sse(
            ": heartbeat\r\n\r\nid: 17\r\nevent: bus.message\r\ndata: {\"id\":4,\r\ndata: \"to\":\"a\",\"urgent\":true}\r\n\r\nid: 18\ndata: {\"partial\":",
        )]);
        let client = Client::new(&server.url(), "test-token".into()).unwrap();
        let mut stream = client.event_stream("agent", 0).unwrap();
        assert!(
            stream
                .next_frame()
                .unwrap()
                .unwrap()
                .decode()
                .unwrap()
                .is_none()
        );
        let mut frame = stream.next_frame().unwrap().unwrap();
        if frame.data.is_empty() {
            frame = stream.next_frame().unwrap().unwrap();
        }
        assert_eq!(frame.id.as_deref(), Some("17"));
        assert!(frame.data.contains('\n'));
        let event = frame.decode().unwrap().unwrap();
        assert_eq!(event.seq, 17);
        assert_eq!(event.kind, "bus.message");
        assert_eq!(event.field("to").unwrap(), "a");
        assert!(stream.next_frame().unwrap().is_none());
        assert_eq!(READ_TIMEOUT, Duration::from_secs(45));
        assert_eq!(
            server.requests()[0].header("accept"),
            Some("text/event-stream")
        );
    }

    #[test]
    fn mail_push_sse_bounds_frames_and_rejects_invalid_json() {
        let mut stream = EventStream::new(Box::new(io::Cursor::new(vec![b'x'; MAX_FRAME + 1])));
        assert!(stream.next_frame().unwrap().is_none());
        let frame = Frame {
            data: "invalid".into(),
            ..Default::default()
        };
        assert!(frame.decode().is_err());
    }
    #[test]
    fn mail_push_urgent_metadata_preserves_content_encryption() {
        let key = crate::WorkspaceKey::from_entropy([71; 32]);
        let mut request = serde_json::json!({"to":"@claude","body":"private","urgent":true});
        crate::crypto::transform_fields_policy(
            &mut request,
            "POST",
            "/api/v1/bus/messages",
            "mail-push-test",
            Some(&key),
            true,
            true,
        )
        .unwrap();
        assert_ne!(request["body"], "private");
        assert_eq!(request["urgent"], true);
        let mut event = serde_json::json!([{"seq":1,"type":"bus.message","payload":{"id":42,"to":"@claude","from":"bob","body":request["body"],"urgent":true}}]);
        crate::crypto::transform_fields_policy(
            &mut event,
            "GET",
            "/api/v1/events",
            "mail-push-test",
            Some(&key),
            false,
            true,
        )
        .unwrap();
        assert_eq!(event[0]["payload"]["body"], "private");
        assert_eq!(event[0]["payload"]["urgent"], true);
    }
    #[test]
    fn mail_push_sse_cancellation_interrupts_idle_body_and_pending_headers() {
        use std::sync::mpsc;
        for sse in [true, false] {
            let server = FakeServer::start_routed(Vec::new());
            server.enqueue(
                "/api/v1/events#sse",
                if sse {
                    Reply::sse(": initial\n\n")
                } else {
                    Reply::text(200, "no headers yet")
                }
                .delay(Duration::from_millis(600)),
            );
            let client = Client::new(&server.url(), "test-token".into()).unwrap();
            let interrupt = Arc::new(AtomicBool::new(false));
            let flag = interrupt.clone();
            let (sent, received) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = client
                    .open_event_stream_sessions("daemon", &["alice".into()], 0, flag)
                    .and_then(|mut stream| {
                        stream
                            .next_frame()
                            .map_err(|e| ClientError::Transport(e.to_string()))?;
                        Ok(())
                    });
                sent.send(result).unwrap();
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while server.requests().is_empty() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(20));
            let started = Instant::now();
            interrupt.store(true, Ordering::Release);
            assert!(
                received
                    .recv_timeout(Duration::from_millis(250))
                    .unwrap()
                    .is_err()
            );
            worker.join().unwrap();
            assert!(started.elapsed() < Duration::from_millis(250));
        }
    }

    #[test]
    fn mail_push_sse_invalid_utf8_and_oversized_frame_keep_next_frame() {
        let mut wire = b"id: 11\nevent: bus.message\ndata: ".to_vec();
        wire.extend(vec![b'x'; MAX_FRAME]);
        wire.extend_from_slice(b"\n\nid: 12\ndata: ");
        wire.push(0xff);
        wire.extend_from_slice(b"\n\nid: 13\nevent: bus.seen\ndata: {\"session\":\"alice\",\"payload\":{\"seen\":[42]}}\n\n");
        let mut stream = EventStream::new(Box::new(io::Cursor::new(wire)));
        for id in ["11", "12"] {
            let frame = stream.next_frame().unwrap().unwrap();
            assert_eq!(frame.id.as_deref(), Some(id));
            assert!(frame.decode().is_err());
        }
        let event = stream
            .next_frame()
            .unwrap()
            .unwrap()
            .decode()
            .unwrap()
            .unwrap();
        assert_eq!(event.seq, 13);
        assert_eq!(event.kind, "bus.seen");
    }
}
