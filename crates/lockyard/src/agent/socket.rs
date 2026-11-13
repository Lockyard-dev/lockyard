// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client side of the agent socket. A connection carries one request: connecting costs microseconds, and
//! nothing can be left half-read for the next caller.

use super::wire::{AgentStatus, Envelope, Reply, Request};
use lockyard_cloud_client::{Call, ClientError, Transport};
use lockyard_core::proto::PathCheck;
use serde_json::Value;
#[cfg(unix)]
use std::fs;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(windows)]
use lockyard_core::windows::ipc::LocalStream as UnixStream;

pub struct AgentSocket {
    path: PathBuf,
    workspace: String,
    timeout: Duration,
    #[cfg(windows)]
    state_root: PathBuf,
}

impl AgentSocket {
    /// Connects to the agent serving `url` and `workspace`. `None` when there is no such process.
    pub fn connect(path: &Path, url: &str, workspace: &str, timeout: Duration) -> Option<Self> {
        let socket = Self {
            path: path.to_path_buf(),
            workspace: workspace.to_string(),
            timeout,
            #[cfg(windows)]
            state_root: super::state_root().ok()?,
        };
        socket.match_target(url, workspace)
    }

    /// Probes once, within `timeout`, for a status-capable daemon using this target and, when
    /// available locally, this exact token. Tokenless callers retain the existing daemon-only mode.
    /// Old daemons are a fast miss, so the caller can use a bounded direct network read instead.
    pub fn connect_status(
        path: &Path,
        url: &str,
        workspace: &str,
        token_id: Option<&str>,
        timeout: Duration,
    ) -> Option<Self> {
        let socket = Self {
            path: path.to_path_buf(),
            workspace: workspace.to_string(),
            timeout,
            #[cfg(windows)]
            state_root: super::state_root().ok()?,
        };
        let status = socket.ping().ok()?;
        (status.url.trim_end_matches('/') == url.trim_end_matches('/')
            && status.workspace == workspace
            && token_id.is_none_or(|expected| status.token_id == expected)
            && status.status_read_v1
            // The abandoned worker cannot be interrupted inside ureq. With independent
            // credentials, preserve the full direct budget rather than spending 1.5s here.
            // A tokenless caller still needs this authenticated daemon, so keep its route.
            && !(token_id.is_some() && status.status_read_abandoned == Some(true)))
        .then_some(socket)
    }

    /// Reads all cloud status sections through the daemon with one end-to-end local deadline.
    /// Claims are always read from the server; the daemon's zone mirror is never lock authority here.
    pub fn status_read(
        &self,
        session: &str,
        repository: Option<&str>,
        budget: Duration,
    ) -> Result<lockyard_core::StatusRead, ClientError> {
        let request = Request::StatusRead {
            session: session.to_string(),
            repository: repository.map(str::to_string),
            deadline_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
        };
        let reply = self
            .ask_with_timeout(&request, budget)
            .map_err(|error| ClientError::Transport(format!("agent status deadline: {error}")))?;
        if let Some(error) = reply.error {
            return Err(error);
        }
        reply.status_read.ok_or_else(|| {
            ClientError::Decode("the agent sent no authoritative status response".into())
        })
    }

    fn match_target(self, url: &str, workspace: &str) -> Option<Self> {
        let status = self.ping().ok()?;
        (status.url.trim_end_matches('/') == url.trim_end_matches('/')
            && status.workspace == workspace)
            .then_some(self)
    }

    #[cfg(all(test, windows))]
    pub(crate) fn connect_in_state(
        path: &Path,
        url: &str,
        workspace: &str,
        timeout: Duration,
        state_root: &Path,
    ) -> Option<Self> {
        Self {
            path: path.to_path_buf(),
            workspace: workspace.to_string(),
            timeout,
            state_root: state_root.to_path_buf(),
        }
        .match_target(url, workspace)
    }

    /// The token this process runs under. Calls through it carry that token's role, not the caller's.
    pub fn token_id(&self) -> io::Result<String> {
        self.ping().map(|status| status.token_id)
    }

    /// Asks the process at `path` how it is, whichever workspace it serves.
    pub fn status(path: &Path, timeout: Duration) -> io::Result<AgentStatus> {
        Self {
            path: path.to_path_buf(),
            workspace: String::new(),
            timeout,
            #[cfg(windows)]
            state_root: super::state_root()?,
        }
        .ping()
    }

    fn ping(&self) -> io::Result<AgentStatus> {
        self.trust_folder()?;
        self.ask(&Request::Ping)?
            .status
            .ok_or_else(|| io::Error::other("the agent sent no status"))
    }

    /// The default folder sits in `/tmp`, where anyone could prepare it first. A process listening in a
    /// folder this user does not alone control could pose as the agent and read mail, so it is refused.
    #[cfg(unix)]
    fn trust_folder(&self) -> io::Result<()> {
        let folder = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("the socket has no folder"))?;
        let found = fs::symlink_metadata(folder)?;
        if found.is_dir() && found.uid() == super::uid() && found.mode() & 0o077 == 0 {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not private to this user", folder.display()),
        ))
    }

    #[cfg(windows)]
    fn trust_folder(&self) -> io::Result<()> {
        trust_windows_endpoint(&self.path, &self.state_root)
    }

    fn line(&self, request: &Request) -> io::Result<Vec<u8>> {
        let envelope = Envelope {
            workspace: self.workspace.clone(),
            request: request.clone(),
        };
        let mut line = serde_json::to_vec(&envelope).map_err(io::Error::other)?;
        line.push(b'\n');
        Ok(line)
    }

    fn open(&self) -> io::Result<UnixStream> {
        #[cfg(windows)]
        self.trust_folder()?;
        let stream = connect_bounded(&self.path, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
    }

    /// Sends one request and reads its answer.
    pub fn ask(&self, request: &Request) -> io::Result<Reply> {
        self.ask_with_timeout(request, self.timeout)
    }

    fn ask_with_timeout(&self, request: &Request, budget: Duration) -> io::Result<Reply> {
        let deadline = Instant::now() + budget;
        #[cfg(windows)]
        self.trust_folder()?;
        let mut stream = connect_bounded(&self.path, remaining(deadline)?)?;
        let line = self.line(request)?;
        let mut pending = line.as_slice();
        while !pending.is_empty() {
            apply_deadline(stream.set_write_timeout(Some(remaining(deadline)?)))?;
            let written = stream.write(pending)?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the agent closed the socket",
                ));
            }
            pending = &pending[written..];
        }
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            // A peer that trickles bytes must not restart the deadline on every read.
            apply_deadline(stream.set_read_timeout(Some(remaining(deadline)?)))?;
            let count = stream.read(&mut chunk)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the agent closed the socket before its answer ended",
                ));
            }
            if let Some(end) = chunk[..count].iter().position(|byte| *byte == b'\n') {
                answer.extend_from_slice(&chunk[..end]);
                remaining(deadline)?;
                return serde_json::from_slice(&answer).map_err(io::Error::other);
            }
            answer.extend_from_slice(&chunk[..count]);
        }
    }

    /// Sends one request without waiting for the answer.
    pub fn tell(&self, request: &Request) -> io::Result<()> {
        self.open()?.write_all(&self.line(request)?)
    }

    fn ask_for(&self, request: &Request) -> Result<Reply, ClientError> {
        let reply = self
            .ask(request)
            .map_err(|error| ClientError::Transport(format!("agent socket: {error}")))?;
        match reply.error {
            Some(error) => Err(error),
            None => Ok(reply),
        }
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "agent socket deadline exceeded",
        ))
    } else {
        Ok(left)
    }
}

/// Applies a deadline update to the stream.
///
/// macOS answers `EINVAL` to `setsockopt` once the peer has shut its end down. An agent that
/// replies and closes before the client updates the read deadline would then lose an answer
/// that is already in the buffer. The deadline set by the previous update stays in force, so
/// the call remains bounded.
fn apply_deadline(result: io::Result<()>) -> io::Result<()> {
    match result {
        #[cfg(target_os = "macos")]
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(()),
        other => other,
    }
}

#[cfg(windows)]
fn trust_windows_endpoint(path: &Path, state_root: &Path) -> io::Result<()> {
    use lockyard_core::windows;
    // A named pipe has no filesystem parent. Its environment is the agent's
    // private state directory and its current-user SID namespace.
    windows::require_private_directory(state_root)?;
    let text = path.to_string_lossy();
    let pipe = if text.starts_with(r"\\.\pipe\") {
        path.to_path_buf()
    } else {
        // Match ipc::endpoint for callers that name a pipe with an opaque path.
        windows::pipe_path(&text)?
    };
    let prefix = format!(r"\\.\pipe\lockyard-{}-", windows::user_id()?);
    let pipe = pipe.to_string_lossy();
    if pipe.strip_prefix(&prefix).is_some_and(|suffix| {
        suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "agent endpoint is outside this user's pipe namespace",
    ))
}

#[cfg(unix)]
fn connect_bounded(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as _;
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = length as u8;
    }
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            length,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        // AF_UNIX EAGAIN means the listener queue is full and this socket did not start
        // connecting. POLLOUT/SO_ERROR=0 can still be reported on that unconnected socket;
        // only EINPROGRESS represents a connection whose completion we can poll.
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "agent socket connect timed out",
            ));
        }
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut socket_error: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut size,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error));
        }
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UnixStream::from(owned))
}

#[cfg(windows)]
fn connect_bounded(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    UnixStream::connect_timeout(path, timeout)
}

impl Transport for AgentSocket {
    fn registry_auto_area(&self, session: &str) -> Result<bool, ClientError> {
        match self.call(&Call::get(session, "/api/v1/protocol".into())) {
            Ok(value) => Ok(value["capabilities"].as_array().is_some_and(|values| {
                values
                    .iter()
                    .any(|capability| capability == "registry_auto_area_v1")
            })),
            Err(error) if matches!(error.status(), Some(404 | 405)) => Ok(false),
            Err(error) => Err(error),
        }
    }
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        let reply = self.ask_for(&Request::Call { call: call.clone() })?;
        let value = reply.value.unwrap_or(Value::Null);
        if let Some(repository) = call.repository.as_deref().filter(|id| !id.is_empty())
            && call.method == "GET"
            && call.path.starts_with("/api/v1/zones/claims?")
            && call.path.ends_with("&namespace_probe=1")
            && (value["repository_namespace_supported"] != true
                || value["repository"] != repository)
        {
            return Err(ClientError::Invalid(
                "this agent does not confirm repository namespace support; restart or upgrade the agent before using repository-scoped coordination".into(),
            ));
        }
        Ok(value)
    }

    fn catalog_expand(&self, call: &Call, names: &[String]) -> Result<Vec<String>, ClientError> {
        let status = self
            .ping()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        if !status.catalog_expansion_v1 {
            return Err(ClientError::Protocol(lockyard_cloud_client::Problem {
                code: "feature_unsupported".into(),
                status: None,
                details: Value::Null,
                detail: "restart or upgrade the local agent for verified catalog expansion".into(),
            }));
        }
        let reply = self.ask_for(&Request::ExpandCatalog {
            call: call.clone(),
            names: names.to_vec(),
        })?;
        serde_json::from_value(reply.value.unwrap_or(Value::Null))
            .map_err(|e| ClientError::Decode(e.to_string()))
    }

    fn fast_check(
        &self,
        session: &str,
        paths: &[String],
    ) -> Option<Result<Vec<PathCheck>, ClientError>> {
        let request = Request::Check {
            session: session.to_string(),
            paths: paths.to_vec(),
        };
        Some(
            self.ask_for(&request)
                .map(|reply| reply.checks.unwrap_or_default()),
        )
    }

    fn fast_unread(&self, session: &str) -> Option<Result<Option<i64>, ClientError>> {
        let request = Request::Unread {
            session: session.to_string(),
        };
        Some(self.ask_for(&request).map(|reply| reply.unread))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader};
    use std::os::{fd::AsRawFd, unix::net::UnixListener};

    fn fixture_accept(listener: &UnixListener) -> UnixStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "fixture received no socket request"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        }
    }

    fn socket_reply(call: Call, value: Value) -> Result<Value, ClientError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let expected = call.clone();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let envelope: Envelope = serde_json::from_str(&line).unwrap();
            let Request::Call { call } = envelope.request else {
                panic!("expected a call")
            };
            assert_eq!(call.path, expected.path);
            assert_eq!(call.repository, expected.repository);
            serde_json::to_writer(
                &mut stream,
                &Reply {
                    value: Some(value),
                    ..Reply::default()
                },
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let answer = AgentSocket {
            path,
            workspace: "test".into(),
            timeout: Duration::from_secs(2),
        }
        .call(&call);
        peer.join().unwrap();
        answer
    }

    #[test]
    fn repository_probe_requires_an_explicit_matching_capability_from_the_agent() {
        let mut probe = Call::get(
            "alice",
            "/api/v1/zones/claims?path=.lockyard-repository%2Fapi&namespace_probe=1".into(),
        );
        probe.repository = Some("api".into());
        for unsupported in [
            json!([]),
            json!({}),
            json!({"repository_namespace_supported":true}),
            json!({"repository_namespace_supported":false,"repository":"api"}),
            json!({"repository_namespace_supported":true,"repository":"web"}),
        ] {
            let error = socket_reply(probe.clone(), unsupported).unwrap_err();
            assert!(matches!(error, ClientError::Invalid(_)));
            assert!(error.to_string().contains("namespace support"));
        }
        let supported = json!({"repository_namespace_supported":true,"repository":"api"});
        assert_eq!(socket_reply(probe, supported.clone()).unwrap(), supported);
        assert_eq!(
            socket_reply(Call::get("alice", "/api/v1/zones/claims".into()), json!([])).unwrap(),
            json!([])
        );
    }

    #[test]
    fn a_full_unix_listener_queue_does_not_block_connect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // The platform's default backlog can exceed the process's descriptor limit.
        // Keep this fixture small so it fills the listener queue rather than the FD table.
        assert_eq!(
            unsafe { libc::listen(listener.as_raw_fd(), 1) },
            0,
            "cannot set fixture listener backlog: {}",
            io::Error::last_os_error()
        );
        let mut connected = Vec::new();
        let mut bounded = false;
        for _ in 0..16 {
            match connect_bounded(&path, Duration::from_millis(20)) {
                Ok(stream) => {
                    assert!(
                        stream.peer_addr().is_ok(),
                        "connect returned an unconnected socket"
                    );
                    connected.push(stream);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    bounded = true;
                    break;
                }
                Err(error) => panic!("unexpected connect error: {error}"),
            }
        }
        assert!(bounded, "listener backlog never filled");
    }

    #[test]
    fn status_probe_absent_agent_returns_without_waiting_for_its_budget() {
        let dir = tempfile::tempdir().unwrap();
        crate::agent::private_dir(dir.path()).unwrap();
        let started = Instant::now();
        assert!(
            AgentSocket::connect_status(
                &dir.path().join("absent.sock"),
                "https://example.test",
                "team",
                Some("token"),
                Duration::from_millis(100),
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn status_probe_hung_agent_returns_within_its_small_budget() {
        let dir = tempfile::tempdir().unwrap();
        crate::agent::private_dir(dir.path()).unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = std::thread::spawn(move || {
            let stream = fixture_accept(&listener);
            // Hold the connection open without ever answering the capability probe.
            std::thread::sleep(Duration::from_millis(200));
            drop(stream);
        });
        let started = Instant::now();
        assert!(
            AgentSocket::connect_status(
                &path,
                "https://example.test",
                "team",
                Some("token"),
                Duration::from_millis(30),
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_millis(150));
        peer.join().unwrap();
    }

    #[test]
    fn status_probe_uses_one_ping_and_rejects_old_or_wrong_token_daemons() {
        for (supports_status, token, expected, abandoned, accepted) in [
            (false, "token", Some("token"), false, false),
            (true, "other-token", Some("token"), false, false),
            (true, "token", Some("token"), false, true),
            (true, "daemon-only-token", None, false, true),
            (true, "token", Some("token"), true, false),
            (true, "daemon-only-token", None, true, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            crate::agent::private_dir(dir.path()).unwrap();
            let path = dir.path().join("agent.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (ready, listening) = std::sync::mpsc::channel();
            let peer = std::thread::spawn(move || {
                ready.send(()).unwrap();
                let mut stream = fixture_accept(&listener);
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: Envelope = serde_json::from_str(&line).unwrap();
                assert_eq!(request.request, Request::Ping);
                let mut value = json!({
                    "status": {
                        "url": "https://example.test/", "workspace": "team", "token_id": token,
                        "pid": 42, "view_fresh": false, "view_age_ms": null,
                        "claims": 0, "board": 0, "sessions": 0, "outbox": 0,
                        "coordination_seq": 0, "registry_seq": 0
                    }
                });
                if supports_status {
                    value["status"]["status_read_v1"] = json!(true);
                }
                if abandoned {
                    value["status"]["status_read_abandoned"] = json!(true);
                }
                serde_json::to_writer(&mut stream, &value).unwrap();
                stream.write_all(b"\n").unwrap();
                listener.set_nonblocking(true).unwrap();
                assert!(
                    listener.accept().is_err(),
                    "the probe must use only one ping"
                );
            });
            listening.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(
                AgentSocket::connect_status(
                    &path,
                    "https://example.test",
                    "team",
                    expected,
                    Duration::from_millis(100),
                )
                .is_some(),
                accepted,
                "capability={supports_status}, token={token}, expected={expected:?}, abandoned={abandoned}",
            );
            peer.join().unwrap();
        }
    }

    #[test]
    fn status_local_deadline_is_not_extended_by_trickled_reply_bytes() {
        let dir = tempfile::tempdir().unwrap();
        crate::agent::private_dir(dir.path()).unwrap();
        let path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = std::thread::spawn(move || {
            let mut stream = fixture_accept(&listener);
            for _ in 0..20 {
                if stream.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let socket = AgentSocket {
            path,
            workspace: "team".into(),
            timeout: Duration::from_secs(1),
        };
        let started = Instant::now();
        let error = socket
            .status_read("me", None, Duration::from_millis(40))
            .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_millis(150));
        peer.join().unwrap();
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use lockyard_core::windows;

    #[test]
    fn endpoint_trust_requires_a_private_state_directory_and_our_pipe_namespace() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let endpoint = windows::pipe_path("trust-regression").unwrap();
        assert!(trust_windows_endpoint(&endpoint, &state).is_err());
        windows::private_dir(&state).unwrap();
        trust_windows_endpoint(&endpoint, &state).unwrap();
        assert!(
            trust_windows_endpoint(
                Path::new(r"\\.\pipe\lockyard-S-1-1-0-0123456789abcdef"),
                &state
            )
            .is_err()
        );
        assert!(trust_windows_endpoint(Path::new(r"\\.\pipe\foreign-agent"), &state).is_err());
        let grant = std::process::Command::new("icacls.exe")
            .arg(&state)
            .args(["/grant", "*S-1-1-0:(OI)(CI)R"])
            .status()
            .unwrap();
        assert!(grant.success(), "cannot expose fixture directory");
        assert!(trust_windows_endpoint(&endpoint, &state).is_err());
    }
}
