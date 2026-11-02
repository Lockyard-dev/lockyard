// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Records of the coordination protocol, shared by both backends.
//!
//! Read side: unknown fields are ignored and everything but an id may be absent, so a newer server
//! cannot make a client report a failure for a write that already happened. `session` and `from_session`
//! on the wire are `agent` and `from` in output, the names local mode has always printed.

use crate::zones::Conflict;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// A moment as the server spells it. Local mode uses milliseconds since the epoch, and the protocol
/// leaves the format open, so numbers and text both read. Clients show it and never compare it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Stamp {
    Millis(i64),
    Text(String),
}

impl Default for Stamp {
    fn default() -> Self {
        Self::Millis(0)
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Millis(value) => write!(f, "{value}"),
            Self::Text(text) => f.write_str(text),
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaimMode {
    #[default]
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    #[default]
    Work,
    Deploy,
}

/// A lease on paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub id: i64,
    #[serde(
        rename(serialize = "agent", deserialize = "session"),
        alias = "agent",
        default
    )]
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_paths: Vec<String>,
    #[serde(default)]
    pub mode: ClaimMode,
    #[serde(default)]
    pub purpose: Purpose,
    #[serde(default, skip_serializing_if = "is_false")]
    pub lazy: bool,
    #[serde(default)]
    pub fence: i64,
    #[serde(default)]
    pub created_at: Stamp,
    #[serde(default)]
    pub expires_at: Stamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_until_ref: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_write_at: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ClaimRequest {
    pub paths: Vec<String>,
    pub note: String,
    pub ttl_minutes: i64,
    pub mode: ClaimMode,
    pub purpose: Purpose,
    pub lazy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_wait_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct RenewRequest {
    pub ttl_minutes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fence: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ReleaseRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub leave_dirty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fence: Option<i64>,
}

/// Filter of the claim list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimQuery {
    pub session: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Free,
    Own,
    Held,
    /// Only from the agent process: the view was stale and the server did not answer in time.
    Unknown,
}

/// What a check found for one path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathCheck {
    pub path: String,
    pub status: CheckStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<Conflict>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct QueueRequest {
    pub paths: Vec<String>,
    pub note: String,
    pub mode: ClaimMode,
    pub purpose: Purpose,
    pub ttl_minutes: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
}

/// A long wait for paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: i64,
    #[serde(
        rename(serialize = "agent", deserialize = "session"),
        alias = "agent",
        default
    )]
    pub session: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub mode: ClaimMode,
    #[serde(default)]
    pub purpose: Purpose,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<i64>,
    #[serde(default)]
    pub created_at: Stamp,
    #[serde(default)]
    pub expires_at: Stamp,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AccessRequest {
    pub paths: Vec<String>,
    pub text: String,
    pub urgent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need_by: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AccessAnswer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<String>,
}

/// A request to a holder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessRecord {
    pub id: i64,
    #[serde(default, alias = "session", alias = "requester")]
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub urgent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub need_by: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eta: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Stamp>,
}

/// One path whose changes are not committed, and who owns them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirtyPath {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<i64>,
}

/// A claim taken away from its session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LostClaim {
    #[serde(alias = "id")]
    pub claim_id: i64,
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_at: Option<Stamp>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ActivityRequest {
    pub write: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fence: Option<i64>,
}

/// One message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(default)]
    pub id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<i64>,
    #[serde(default, alias = "in_reply_to")]
    pub reply_to: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, alias = "from_session")]
    pub from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_client: Option<String>,
    #[serde(default)]
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub re: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
    #[serde(default)]
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Stamp>,
    #[serde(default)]
    pub created_at: Stamp,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deduplicated: bool,
    /// The agent process holds this message in its outbox: the server has not seen it yet.
    #[serde(default, skip_serializing_if = "is_false")]
    pub queued: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SendRequest {
    pub to: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub re: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_minutes: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboxQuery {
    pub all: bool,
    pub limit: usize,
}

/// A page of mail. Unread mail past the server's limit is folded into `skipped`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InboxPage {
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub skipped: i64,
}

/// Unseen mail across sessions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Undelivered {
    #[serde(alias = "message_id")]
    pub id: i64,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub age_seconds: i64,
}

/// One board value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoardEntry {
    pub key: String,
    #[serde(default)]
    pub value: Value,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub expires_at: Option<Stamp>,
    #[serde(default)]
    pub updated_at: Stamp,
}

impl BoardEntry {
    /// The value for a person to read.
    pub fn text(&self) -> String {
        match &self.value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct BoardWrite {
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_minutes: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkStatus {
    Offered,
    Claimed,
    Review,
    Accepted,
    Failed,
    Expired,
    Cancelled,
    Declined,
}

/// A task offer between agents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkTask {
    pub id: i64,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub re: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default)]
    pub accept: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brief: Option<String>,
    pub status: WorkStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_until: Option<Stamp>,
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
    #[serde(default)]
    pub version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_token: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WorkOffer {
    pub title: String,
    pub to: String,
    pub accept: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub re: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brief: Option<String>,
}

/// A step of the work task state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkAction {
    Claim,
    Beat,
    Done,
    Accept,
    Reject,
    Fail,
    Cancel,
    Handoff,
    Take,
    Decline,
}

impl WorkAction {
    /// Last segment of the route.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Beat => "beat",
            Self::Done => "done",
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Fail => "fail",
            Self::Cancel => "cancel",
            Self::Handoff => "handoff",
            Self::Take => "take",
            Self::Decline => "decline",
        }
    }
}

/// Fields a work task step can carry. `version` travels in the query string, not in this body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct WorkStep {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
    #[serde(skip)]
    pub version: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Working,
    Idle,
    Ended,
    ApiFailure,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionActivity {
    #[serde(default)]
    pub tool_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_started_at: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SessionState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// One heartbeat.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PresenceBeat {
    pub client: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnd_until: Option<Stamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity: Option<SessionActivity>,
}

/// One live session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Presence {
    #[serde(rename(serialize = "agent", deserialize = "session"), alias = "agent")]
    pub session: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub last_seen: Stamp,
    #[serde(default)]
    pub dnd_until: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<SessionActivity>,
}

/// Someone seen in this project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSeen {
    pub id: String,
    #[serde(default)]
    pub first_seen: Stamp,
    #[serde(default)]
    pub last_seen: Stamp,
}

/// The two event streams. `seq` counts per stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Stream {
    #[default]
    Coordination,
    Registry,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventQuery {
    pub stream: Stream,
    pub after: i64,
    pub wait_seconds: u64,
    pub session: Option<String>,
    pub types: Vec<String>,
}

/// One event. Its fields may sit under `payload` or beside `seq`, so [`Event::field`] looks in both.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: i64,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, Value>,
}

impl Event {
    /// A named field of the event.
    pub fn field(&self, key: &str) -> Option<&Value> {
        self.payload.get(key).or_else(|| self.rest.get(key))
    }
}

/// A page of events.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventPage {
    #[serde(default)]
    pub events: Vec<Event>,
}

impl EventPage {
    /// The sequence to continue after.
    pub fn last_seq(&self, after: i64) -> i64 {
        self.events
            .iter()
            .map(|event| event.seq)
            .fold(after, i64::max)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Freeze {
    pub on: bool,
    pub reason: String,
}

/// Expands zone names and groups of a catalog into paths, keeping first-seen order.
///
/// The server stores the catalog as an opaque document. This client reads `zones.<name>` as a list of
/// paths or as an object with `paths`, and `groups.<name>` as a list of zone names.
pub fn expand_zones(catalog: &Value, names: &[String]) -> Result<Vec<String>> {
    let mut paths: Vec<String> = Vec::new();
    for name in names {
        let members: Vec<String> = match catalog
            .pointer(&pointer("groups", name))
            .and_then(Value::as_array)
        {
            Some(list) => list
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect(),
            None => vec![name.clone()],
        };
        for member in &members {
            let entry = catalog
                .pointer(&pointer("zones", member))
                .ok_or_else(|| Error::NotFound(format!("zone {member:?} is not in the catalog")))?;
            let list = entry
                .get("paths")
                .unwrap_or(entry)
                .as_array()
                .ok_or_else(|| {
                    Error::Protocol(format!("catalog entry for zone {member:?} has no paths"))
                })?;
            for path in list.iter().filter_map(Value::as_str) {
                if !paths.iter().any(|known| known == path) {
                    paths.push(path.to_string());
                }
            }
        }
    }
    Ok(paths)
}

fn pointer(section: &str, name: &str) -> String {
    format!("/{section}/{}", name.replace('~', "~0").replace('/', "~1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_claim_reads_the_wire_names_and_prints_the_local_ones() {
        let claim: Claim = serde_json::from_value(json!({
            "id": 7, "session": "s", "paths": ["src"], "mode": "shared", "purpose": "deploy", "lazy": true,
            "fence": 3, "created_at": "2026-11-02T10:00:00Z", "expires_at": 1000, "excluded_paths": ["src/x"],
            "return_to": "r", "hold_until_ref": 4, "meta": {"k": 1}, "future_field": true
        }))
        .unwrap();
        assert_eq!(claim.session, "s");
        assert_eq!(claim.mode, ClaimMode::Shared);
        assert_eq!(claim.created_at, Stamp::Text("2026-11-02T10:00:00Z".into()));
        assert_eq!(claim.expires_at, Stamp::Millis(1000));
        let printed = serde_json::to_value(&claim).unwrap();
        assert_eq!(printed["agent"], "s");
        let again: Claim = serde_json::from_value(printed).unwrap();
        assert_eq!(again, claim);
    }

    #[test]
    fn a_message_reads_wire_aliases() {
        let message: Message = serde_json::from_value(json!({
            "id": 1, "from_session": "a", "to": "*", "in_reply_to": 9, "needs": "ack", "body": "x"
        }))
        .unwrap();
        assert_eq!((message.from.as_str(), message.reply_to), ("a", Some(9)));
    }

    #[test]
    fn an_event_finds_fields_under_payload_and_beside_it() {
        let nested: Event = serde_json::from_value(
            json!({"seq": 1, "type": "bus.message", "payload": {"to": "a"}}),
        )
        .unwrap();
        let flat: Event =
            serde_json::from_value(json!({"seq": 2, "type": "bus.message", "to": "b"})).unwrap();
        assert_eq!(nested.field("to"), Some(&json!("a")));
        assert_eq!(flat.field("to"), Some(&json!("b")));
        let page = EventPage {
            events: vec![nested, flat],
        };
        assert_eq!(page.last_seq(0), 2);
        assert_eq!(EventPage::default().last_seq(5), 5);
    }

    #[test]
    fn zones_and_groups_expand_to_paths() {
        let catalog = json!({
            "zones": {"api": ["src/api", "docs"], "web": {"paths": ["web", "docs"]}},
            "groups": {"all": ["api", "web"]}
        });
        assert_eq!(
            expand_zones(&catalog, &["all".into()]).unwrap(),
            ["src/api", "docs", "web"]
        );
        assert!(matches!(
            expand_zones(&catalog, &["nope".into()]),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn work_steps_keep_the_version_out_of_the_body() {
        let step = WorkStep {
            version: Some(3),
            report: Some("r".into()),
            ..WorkStep::default()
        };
        assert_eq!(serde_json::to_value(&step).unwrap(), json!({"report": "r"}));
    }

    #[test]
    fn offered_is_the_status_spelling() {
        let task: WorkTask = serde_json::from_value(json!({"id": 1, "status": "offered"})).unwrap();
        assert_eq!(task.status, WorkStatus::Offered);
    }
}
