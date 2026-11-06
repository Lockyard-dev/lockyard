// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client side of the agent socket. A connection carries one request: connecting costs microseconds, and
//! nothing can be left half-read for the next caller.

use super::wire::{AgentStatus, Envelope, Reply, Request};
use lockyard_cloud_client::{Call, ClientError, Transport};
use lockyard_core::proto::PathCheck;
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct AgentSocket {
    path: PathBuf,
    workspace: String,
    timeout: Duration,
}

impl AgentSocket {
    /// Connects to the agent serving `url` and `workspace`. `None` when there is no such process.
    pub fn connect(path: &Path, url: &str, workspace: &str, timeout: Duration) -> Option<Self> {
        let socket = Self {
            path: path.to_path_buf(),
            workspace: workspace.to_string(),
            timeout,
        };
        let status = socket.ping().ok()?;
        (status.url.trim_end_matches('/') == url.trim_end_matches('/')
            && status.workspace == workspace)
            .then_some(socket)
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
        let stream = connect_bounded(&self.path, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(stream)
    }

    /// Sends one request and reads its answer.
    pub fn ask(&self, request: &Request) -> io::Result<Reply> {
        let mut stream = self.open()?;
        stream.write_all(&self.line(request)?)?;
        let mut answer = String::new();
        BufReader::new(stream).read_line(&mut answer)?;
        if answer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the agent closed the socket",
            ));
        }
        serde_json::from_str(&answer).map_err(io::Error::other)
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

impl Transport for AgentSocket {
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        let reply = self.ask_for(&Request::Call { call: call.clone() })?;
        Ok(reply.value.unwrap_or(Value::Null))
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

#[cfg(test)]
mod tests {
    use super::connect_bounded;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    #[test]
    fn a_full_unix_listener_queue_does_not_block_connect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        let mut connected = Vec::new();
        let mut bounded = false;
        for _ in 0..5000 {
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
}
