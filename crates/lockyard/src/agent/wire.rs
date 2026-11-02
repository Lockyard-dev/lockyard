// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Messages on the agent socket: one JSON object per line, one answer per request.

use lockyard_cloud_client::{Call, ClientError};
use lockyard_core::proto::{Message, PathCheck};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a hook reports about a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// A tool is about to run.
    Pre,
    /// A tool finished.
    Post,
    /// The user sent a prompt.
    Prompt,
    /// The session closed.
    End,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Who are you, and how fresh is your view?
    Ping,
    /// May this session touch these paths?
    Check { session: String, paths: Vec<String> },
    /// How much mail is waiting?
    Unread { session: String },
    /// Reserve mail for showing. It is marked later, through a `Call` to `inbox/seen`.
    TakeMail {
        session: String,
        limit: usize,
        lease_seconds: i64,
    },
    /// Read coordination events addressed to this session without advancing its cursor.
    TakeEvents { session: String },
    /// Acknowledge events after they have been written to the hook output.
    AckEvents { session: String, through: i64 },
    /// Tool activity of a session.
    Touch {
        session: String,
        client: String,
        phase: Phase,
        write_paths: Vec<String>,
    },
    /// Any protocol request.
    Call { call: Call },
}

/// A request and the workspace its sender believes it belongs to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub workspace: String,
    #[serde(flatten)]
    pub request: Request,
}

/// Where a check or a count came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Memory, fresher than the limit.
    View,
    /// One server call inside the deadline.
    Server,
    /// Neither: the answer is unknown.
    None,
}

/// State of the process, for `lockyard agent status`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentStatus {
    pub url: String,
    pub workspace: String,
    /// Which token the process runs under. See `lockyard_cloud_client::token_id`.
    #[serde(default)]
    pub token_id: String,
    pub pid: u32,
    pub view_fresh: bool,
    pub view_age_ms: Option<u64>,
    pub claims: usize,
    pub board: usize,
    pub sessions: usize,
    pub outbox: usize,
    #[serde(default)]
    pub rejected: usize,
    pub coordination_seq: i64,
    pub registry_seq: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ClientError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<Vec<PathCheck>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<Message>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<lockyard_core::proto::Event>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
}

impl Reply {
    pub fn failed(error: ClientError) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_one_flat_object() {
        let envelope = Envelope {
            workspace: "w".into(),
            request: Request::Unread {
                session: "s".into(),
            },
        };
        let line = serde_json::to_string(&envelope).unwrap();
        assert_eq!(line, r#"{"workspace":"w","op":"unread","session":"s"}"#);
        assert_eq!(serde_json::from_str::<Envelope>(&line).unwrap(), envelope);
    }

    #[test]
    fn an_error_crosses_the_socket_intact() {
        let error = ClientError::Transport("down".into());
        let line = serde_json::to_string(&Reply::failed(error.clone())).unwrap();
        assert_eq!(
            serde_json::from_str::<Reply>(&line).unwrap().error,
            Some(error)
        );
    }
}
