// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client side of the agent socket. A connection carries one request: connecting costs microseconds, and
//! nothing can be left half-read for the next caller.

use super::wire::{AgentStatus, Envelope, Reply, Request};
use lockyard_cloud_client::{Call, ClientError, Transport};
use lockyard_core::proto::PathCheck;
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
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
        let stream = UnixStream::connect(&self.path)?;
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
