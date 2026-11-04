// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! [`Backend`] over the cloud protocol.
//!
//! The protocol names the fields of a record but not the envelope of a response, so a list reads
//! either as a bare array or under its plural name, and a record either bare or under its singular name.

use crate::{Call, ClientError, MAX_POLL_WAIT_SECONDS, Transport, encode, ulid};
use lockyard_core::proto::{
    AccessAnswer, AccessRecord, AccessRequest, ActivityRequest, AgentSeen, BoardEntry, BoardWrite,
    CheckStatus, Claim, ClaimQuery, ClaimRequest, DirtyPath, EventPage, EventQuery, Freeze,
    InboxPage, InboxQuery, LostClaim, Message, PathCheck, Presence, PresenceBeat, QueueEntry,
    QueueRequest, ReleaseRequest, RenewRequest, SendRequest, Stream, TokenRequest, Undelivered,
    WorkAction, WorkOffer, WorkStep, WorkTask, parse_rfc3339, rfc3339,
};
use lockyard_core::zones::Conflict;
use lockyard_core::{Backend, Error, Result, bus, tasks};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const ITEMS: &str = "/api/v1/registry/items";
const TOKENS: &str = "/api/v1/registry/tokens";
const AREAS: &str = "/api/v1/registry/areas";
const MAX_REGISTRY_TEXT_BYTES: usize = 8 * 1024;
const MAX_EVIDENCE_BYTES: usize = 1024;
const MAX_EVIDENCE_COUNT: usize = 4;
const ITEM_PAGE: usize = 200;
const DEFAULT_PRIORITY: &str = "P2";
const DEFAULT_TARGET: &str = "code_accepted";
/// The area a workspace gets when the first item needs one.
const DEFAULT_AREA: &str = "general";
/// The server keeps at most this many unread messages per addressee and refuses a larger page.
const INBOX_PAGE: usize = 50;
/// The protocol requires a lifetime on every board value.
const DEFAULT_BOARD_MINUTES: i64 = 24 * 60;
/// The kind of a message that names none: mail stays seven days, as it does in local mode.
const DEFAULT_KIND: &str = "ask";
/// `who` lists sessions seen in this window, the time mail is kept.
const WHO_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Reads a list from a bare array or from the first named field that holds one.
pub fn list<T: DeserializeOwned>(
    value: Value,
    names: &[&str],
) -> std::result::Result<Vec<T>, ClientError> {
    let items = match value {
        Value::Array(_) => value,
        Value::Null => Value::Array(Vec::new()),
        other => names
            .iter()
            .find_map(|name| other.get(*name).filter(|field| field.is_array()).cloned())
            .ok_or_else(|| {
                ClientError::Decode(format!("expected a list under {names:?}, got {other}"))
            })?,
    };
    serde_json::from_value(items).map_err(|error| ClientError::Decode(error.to_string()))
}

/// Reads one record, bare or under `name`.
pub fn one<T: DeserializeOwned>(value: Value, name: &str) -> std::result::Result<T, ClientError> {
    let record = match value.get(name) {
        Some(inner) if inner.is_object() => inner.clone(),
        _ => value,
    };
    serde_json::from_value(record).map_err(|error| ClientError::Decode(error.to_string()))
}

/// Reads the answer of `zones/check`: for each path, free, own, or the holder.
pub fn checks(value: Value) -> std::result::Result<Vec<PathCheck>, ClientError> {
    let items: Vec<Value> = list(value, &["paths", "results", "checks"])?;
    items.into_iter().map(check_item).collect()
}

fn check_item(item: Value) -> std::result::Result<PathCheck, ClientError> {
    let path = item
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let holder = match item.get("holder") {
        None | Some(Value::Null) => None,
        Some(Value::String(session)) => Some(Conflict {
            path: path.clone(),
            held_path: String::new(),
            claim: 0,
            agent: session.clone(),
            note: String::new(),
            expires_at: Default::default(),
        }),
        Some(object) => {
            let mut conflict: Conflict = serde_json::from_value(object.clone())
                .map_err(|error| ClientError::Decode(error.to_string()))?;
            if conflict.path.is_empty() {
                conflict.path.clone_from(&path);
            }
            Some(conflict)
        }
    };
    // An answer this client cannot read must never count as free.
    let status = match item.get("status").and_then(Value::as_str) {
        Some("own") => CheckStatus::Own,
        Some("held") => CheckStatus::Held,
        Some("free") => CheckStatus::Free,
        other => {
            return Err(ClientError::Decode(format!(
                "a zone check for {path} has status {other:?}"
            )));
        }
    };
    Ok(PathCheck {
        path,
        status,
        holder,
    })
}

/// [`Backend`] on a [`Transport`]. The `agent` of each call is its session.
pub struct CloudBackend<T: Transport> {
    transport: T,
    session: String,
}

impl<T: Transport> CloudBackend<T> {
    /// `session` names calls that carry no agent, such as listing claims.
    pub fn new(transport: T, session: &str) -> Self {
        Self {
            transport,
            session: session.to_string(),
        }
    }

    fn get(&self, session: &str, path: String) -> Result<Value> {
        Ok(self.transport.call(&Call::get(session, path))?)
    }

    fn post(&self, session: &str, path: String, body: &impl Serialize) -> Result<Value> {
        self.write(session, "POST", path, body)
    }

    fn item(&self, session: &str, id: i64) -> Result<Value> {
        self.get(session, format!("{ITEMS}/{}", item_id(id)))
    }

    /// Tells the server how far a message got, for the sender's `lockyard msg sent`.
    ///
    /// Only ever called from a path that already writes. Reading the inbox stays a read — hooks
    /// run it on every edit, and a frozen or read-only server must not turn that into a refusal
    /// — so `delivered` is the server's own observation of what its inbox endpoint handed out.
    ///
    /// Best effort by design: a receipt is a courtesy to the sender, and a server that has not
    /// shipped the endpoint must not stop the recipient marking mail read. A receipt can never
    /// move backwards, which the contract makes the server's job.
    fn report_receipts(&self, agent: &str, ids: &[i64], status: &str) {
        for id in ids {
            let _ = self.post(
                agent,
                format!("/api/v1/messages/{id}/receipt"),
                &json!({"status": status}),
            );
        }
    }

    /// One registry operation on an item, at the version the caller read.
    fn item_step(
        &self,
        agent: &str,
        id: i64,
        operation: &str,
        mut body: Value,
        item: &Value,
    ) -> Result<tasks::Task> {
        body["expected_version"] = item["version"].clone();
        let route = format!("{ITEMS}/{}/{operation}", item_id(id));
        task_from(&self.post(agent, route, &body)?)
    }

    /// The area named by key. Without a key, the first one, created on first use where the role allows.
    fn area_id(&self, agent: &str, wanted: Option<&str>) -> Result<String> {
        let value = self.get(agent, AREAS.into())?;
        let areas: Vec<Value> = list(value, &["areas", "items"])?;
        let found = match wanted {
            Some(key) => areas.iter().find(|area| text(area, "key") == key),
            None => areas.first(),
        };
        match (found, wanted) {
            (Some(area), _) => Ok(text(area, "id").to_string()),
            (None, Some(key)) => Err(Error::NotFound(format!("no area {key:?}"))),
            (None, None) => {
                let body = json!({"key": DEFAULT_AREA, "name": "General"});
                Ok(text(&self.post(agent, AREAS.into(), &body)?, "id").to_string())
            }
        }
    }

    fn write(
        &self,
        session: &str,
        method: &str,
        path: String,
        body: &impl Serialize,
    ) -> Result<Value> {
        let body = serde_json::to_value(body).map_err(|error| Error::Invalid(error.to_string()))?;
        Ok(self
            .transport
            .call(&Call::write(session, method, path, body))?)
    }
}

fn query(pairs: &[(&str, Option<String>)]) -> String {
    let mut text = String::new();
    for (name, value) in pairs {
        if let Some(value) = value {
            text.push(if text.is_empty() { '?' } else { '&' });
            text.push_str(name);
            text.push('=');
            text.push_str(&encode(value));
        }
    }
    text
}

fn count(value: &Value, names: &[&str], fallback: usize) -> usize {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_u64))
        .and_then(|found| usize::try_from(found).ok())
        .unwrap_or(fallback)
}

fn inbox_page(value: Value) -> std::result::Result<InboxPage, ClientError> {
    if value.is_array() {
        return Ok(InboxPage {
            messages: list(value, &[])?,
            skipped: 0,
        });
    }
    let skipped = value.get("skipped").and_then(Value::as_i64).unwrap_or(0);
    Ok(InboxPage {
        messages: list(value, &["messages", "items"])?,
        skipped,
    })
}

/// Reads one line of `msg sent` from the server.
///
/// An unknown status is reported as it came rather than being rounded down to `sent`: a sender
/// deciding whether to nudge is worse off with a confident wrong answer than with a strange one.
fn receipt_from(value: &Value) -> bus::Receipt {
    let stamp = |name: &str| value.get(name).and_then(Value::as_i64);
    let status = value.get("status").and_then(Value::as_str).unwrap_or("");
    bus::Receipt {
        id: value.get("id").and_then(Value::as_i64).unwrap_or_default(),
        to: value
            .get("to")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        body: value
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        created_at: stamp("created_at").unwrap_or_default(),
        status: match status {
            "replied" => bus::Delivery::Replied,
            "read" => bus::Delivery::Read,
            "delivered" => bus::Delivery::Delivered,
            "failed" => bus::Delivery::Failed,
            _ => bus::Delivery::Sent,
        },
        delivered_at: stamp("delivered_at"),
        read_at: stamp("read_at"),
        replied_at: stamp("replied_at"),
    }
}

fn message(value: Value) -> Result<Message> {
    if value.get("queued").and_then(Value::as_bool) == Some(true) && value.get("id").is_none() {
        return Ok(Message {
            id: 0,
            thread_id: None,
            reply_to: None,
            kind: None,
            from: String::new(),
            from_client: None,
            to: String::new(),
            zone: None,
            re: None,
            status: None,
            needs: None,
            body: String::new(),
            key: value.get("key").and_then(Value::as_str).map(str::to_string),
            expires_at: None,
            created_at: Default::default(),
            deduplicated: false,
            queued: true,
        });
    }
    Ok(one(value, "message")?)
}

fn item_id(id: i64) -> String {
    format!("D-{id}")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn millis(value: &Value, key: &str) -> Option<i64> {
    parse_rfc3339(value.get(key)?.as_str()?)
}

fn validate_registry_text(field: &str, value: &str) -> Result<()> {
    if value.len() > MAX_REGISTRY_TEXT_BYTES {
        return Err(Error::Invalid(format!(
            "registry {field} exceeds {MAX_REGISTRY_TEXT_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_title(value: &str) -> Result<()> {
    if value.chars().count() > 200 {
        return Err(Error::Invalid(
            "registry title exceeds 200 characters".into(),
        ));
    }
    Ok(())
}

fn validate_evidence(values: &[String]) -> Result<()> {
    if values.len() > MAX_EVIDENCE_COUNT {
        return Err(Error::Invalid(format!(
            "registry items allow at most {MAX_EVIDENCE_COUNT} evidence records"
        )));
    }
    for value in values {
        if value.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::Invalid(format!(
                "registry evidence value exceeds {MAX_EVIDENCE_BYTES} UTF-8 bytes"
            )));
        }
    }
    Ok(())
}

fn validate_registry_import(dump: &Value) -> Result<()> {
    let Some(items) = dump.get("items").and_then(Value::as_array) else {
        return Ok(());
    };
    for item in items {
        if let Some(title) = item.get("title").and_then(Value::as_str) {
            validate_title(title)?;
        }
        for field in ["body", "acceptance", "legacy_raw"] {
            if let Some(value) = item.get(field).and_then(Value::as_str) {
                validate_registry_text(field, value)?;
            }
        }
        if let Some(evidence) = item.get("evidence").and_then(Value::as_array) {
            if evidence.len() > MAX_EVIDENCE_COUNT {
                return Err(Error::Invalid(format!(
                    "registry items allow at most {MAX_EVIDENCE_COUNT} evidence records"
                )));
            }
            let values: Vec<String> = evidence
                .iter()
                .filter_map(|entry| entry.get("value").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            validate_evidence(&values)?;
        }
    }
    Ok(())
}

/// The session inside an identity `token:<id>:<session>`.
fn session_of(identity: &str) -> String {
    identity
        .splitn(3, ':')
        .nth(2)
        .unwrap_or(identity)
        .to_string()
}

fn reason_or<'a>(reason: &'a str, fallback: &'a str) -> &'a str {
    if reason.trim().is_empty() {
        fallback
    } else {
        reason
    }
}

/// Evidence for a code or CI target. A deploy target also needs a probe, which `task` does not record.
fn evidence_body(agent: &str, target: &str, value: &str, now: i64) -> Value {
    json!({
        "kind": if target == "ci_passed" { "ci_run" } else { "commit" },
        "environment": "local",
        "value": value,
        "observed_at": rfc3339(now),
        "verifier": agent,
    })
}

fn task_status(status: &str) -> tasks::Status {
    match status {
        "active" => tasks::Status::Claimed,
        "review" => tasks::Status::Review,
        "done" => tasks::Status::Accepted,
        "cancelled" => tasks::Status::Cancelled,
        _ => tasks::Status::Open,
    }
}

/// A backlog item in the shape of a task. Open covers `ready`, `blocked` and `intake`.
fn task_from(item: &Value) -> Result<tasks::Task> {
    let id = text(item, "id");
    let number = id
        .strip_prefix("D-")
        .and_then(|digits| digits.parse().ok())
        .ok_or_else(|| Error::Protocol(format!("{id:?} is not a backlog id")))?;
    let assignment = item.get("assignment").filter(|found| found.is_object());
    let evidence: Vec<&str> = item
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| text(entry, "value"))
        .collect();
    Ok(tasks::Task {
        id: number,
        title: text(item, "title").to_string(),
        body: text(item, "body").to_string(),
        status: task_status(text(item, "status")),
        author: session_of(text(item, "created_by")),
        assignee: assignment.map(|found| session_of(text(found, "executor"))),
        lease_until: assignment.and_then(|found| millis(found, "lease_expires_at")),
        evidence: (!evidence.is_empty()).then(|| evidence.join(", ")),
        created_at: millis(item, "created_at").unwrap_or(0),
        updated_at: millis(item, "updated_at").unwrap_or(0),
        priority: item
            .get("priority")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

impl<T: Transport> Backend for CloudBackend<T> {
    fn is_cloud(&self) -> bool {
        true
    }

    fn touch_agent(&mut self, _agent: &str, _now: i64) -> Result<()> {
        // Presence is reported through heartbeats. A read must not write in cloud mode.
        Ok(())
    }

    fn agents(&self) -> Result<Vec<AgentSeen>> {
        Ok(self
            .presence(WHO_WINDOW_SECONDS, 0)?
            .into_iter()
            .map(|entry| AgentSeen {
                id: entry.session,
                first_seen: entry.last_seen.clone(),
                last_seen: entry.last_seen,
            })
            .collect())
    }

    fn claim(&mut self, agent: &str, request: &ClaimRequest, _now: i64) -> Result<Claim> {
        let body =
            serde_json::to_value(request).map_err(|error| Error::Invalid(error.to_string()))?;
        let mut call = Call::write(agent, "POST", "/api/v1/zones/claims".into(), body);
        // With a short wait the server holds the answer until the zone frees up.
        call.long_poll = request
            .queue_wait_seconds
            .is_some_and(|seconds| seconds > 0);
        Ok(one(self.transport.call(&call)?, "claim")?)
    }

    fn renew(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &RenewRequest,
        now: i64,
    ) -> Result<usize> {
        let ids = match id {
            Some(id) => vec![id],
            None => {
                let own = ClaimQuery {
                    session: Some(agent.to_string()),
                    path: None,
                };
                self.claims(&own, now)?
                    .into_iter()
                    .map(|claim| claim.id)
                    .collect()
            }
        };
        for id in &ids {
            self.post(agent, format!("/api/v1/zones/claims/{id}/renew"), request)?;
        }
        Ok(ids.len())
    }

    fn release(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &ReleaseRequest,
        _now: i64,
    ) -> Result<usize> {
        match id {
            Some(id) => {
                self.write(
                    agent,
                    "DELETE",
                    format!("/api/v1/zones/claims/{id}"),
                    request,
                )?;
                Ok(1)
            }
            None => {
                if request.fence.is_some() {
                    let claims = self.claims(
                        &ClaimQuery {
                            session: Some(agent.to_string()),
                            ..ClaimQuery::default()
                        },
                        _now,
                    )?;
                    if claims.len() != 1 {
                        return Err(Error::Invalid(
                            "a release fence requires exactly one live claim".into(),
                        ));
                    }
                }
                let route = format!(
                    "/api/v1/zones/claims{}",
                    query(&[("session", Some(agent.to_string()))])
                );
                let value = self.write(agent, "DELETE", route, request)?;
                Ok(count(&value, &["released", "count"], 0))
            }
        }
    }

    fn claims(&self, filter: &ClaimQuery, _now: i64) -> Result<Vec<Claim>> {
        let tail = query(&[
            ("session", filter.session.clone()),
            ("path", filter.path.clone()),
        ]);
        let value = self.get(&self.session, format!("/api/v1/zones/claims{tail}"))?;
        Ok(list(value, &["claims", "items"])?)
    }

    fn check(
        &self,
        agent: &str,
        paths: &[String],
        fence: Option<i64>,
        _now: i64,
    ) -> Result<Vec<PathCheck>> {
        if fence.is_none()
            && let Some(answer) = self.transport.fast_check(agent, paths)
        {
            return Ok(answer?);
        }
        let mut call = Call {
            session: agent.to_string(),
            method: "POST".into(),
            path: "/api/v1/zones/check".into(),
            body: Some(json!({"paths": paths})),
            ..Call::default()
        };
        if let (Some(fence), Some(body)) = (fence, call.body.as_mut()) {
            body["fence"] = json!(fence);
        }
        Ok(checks(self.transport.call(&call)?)?)
    }

    fn queue_add(&mut self, agent: &str, request: &QueueRequest) -> Result<QueueEntry> {
        let value = self.post(agent, "/api/v1/zones/queue".into(), request)?;
        Ok(one(value, "entry")?)
    }

    fn queue_list(&self, agent: &str) -> Result<Vec<QueueEntry>> {
        let value = self.get(agent, "/api/v1/zones/queue".into())?;
        Ok(list(value, &["queue", "entries", "items"])?)
    }

    fn queue_cancel(&mut self, agent: &str, id: i64) -> Result<()> {
        self.write(
            agent,
            "DELETE",
            format!("/api/v1/zones/queue/{id}"),
            &json!({}),
        )?;
        Ok(())
    }

    fn zone_request(&mut self, agent: &str, request: &AccessRequest) -> Result<AccessRecord> {
        let value = self.post(agent, "/api/v1/zones/requests".into(), request)?;
        Ok(one(value, "request")?)
    }

    fn zone_requests(&self, agent: &str) -> Result<Vec<AccessRecord>> {
        let value = self.get(agent, "/api/v1/zones/requests".into())?;
        Ok(list(value, &["requests", "items"])?)
    }

    fn zone_answer(&mut self, agent: &str, id: i64, answer: &AccessAnswer) -> Result<AccessRecord> {
        let value = self.post(agent, format!("/api/v1/zones/requests/{id}/answer"), answer)?;
        Ok(one(value, "request")?)
    }

    fn handover(&mut self, agent: &str, id: i64, to: &str, fence: Option<i64>) -> Result<Value> {
        let mut body = json!({"to": to});
        if let Some(fence) = fence {
            body["fence"] = json!(fence);
        }
        self.post(agent, format!("/api/v1/zones/claims/{id}/handover"), &body)
    }

    fn handover_accept(&mut self, agent: &str, id: i64) -> Result<Claim> {
        let value = self.post(
            agent,
            format!("/api/v1/zones/claims/{id}/accept"),
            &json!({}),
        )?;
        Ok(one(value, "claim")?)
    }

    fn takeover(&mut self, agent: &str, id: i64, reason: &str) -> Result<Claim> {
        if reason.trim().is_empty() {
            return Err(Error::Invalid("a takeover needs a reason".into()));
        }
        let value = self.post(
            agent,
            format!("/api/v1/zones/claims/{id}/takeover"),
            &json!({"reason": reason}),
        )?;
        Ok(one(value, "claim")?)
    }

    fn narrow(
        &mut self,
        agent: &str,
        id: i64,
        paths: &[String],
        fence: Option<i64>,
    ) -> Result<Claim> {
        let mut body = json!({"paths": paths});
        if let Some(fence) = fence {
            body["fence"] = json!(fence);
        }
        let value = self.post(agent, format!("/api/v1/zones/claims/{id}/narrow"), &body)?;
        Ok(one(value, "claim")?)
    }

    fn add_path(&mut self, agent: &str, id: i64, path: &str, fence: Option<i64>) -> Result<Claim> {
        let mut body = json!({"path": path});
        if let Some(fence) = fence {
            body["fence"] = json!(fence);
        }
        let value = self.post(agent, format!("/api/v1/zones/claims/{id}/add-path"), &body)?;
        Ok(one(value, "claim")?)
    }

    fn activity(&mut self, agent: &str, id: i64, request: &ActivityRequest) -> Result<()> {
        self.post(
            agent,
            format!("/api/v1/zones/claims/{id}/activity"),
            request,
        )?;
        Ok(())
    }

    fn dirty_report(&mut self, agent: &str, paths: &[DirtyPath]) -> Result<()> {
        self.post(
            agent,
            "/api/v1/zones/dirty".into(),
            &json!({"paths": paths}),
        )?;
        Ok(())
    }

    fn dirty_list(&self, agent: &str, path: Option<&str>) -> Result<Vec<DirtyPath>> {
        let tail = query(&[("path", path.map(str::to_string))]);
        let value = self.get(agent, format!("/api/v1/zones/dirty{tail}"))?;
        Ok(list(value, &["paths", "dirty", "items"])?)
    }

    fn dirty_disown(&mut self, agent: &str, paths: &[String]) -> Result<()> {
        self.post(
            agent,
            "/api/v1/zones/dirty/disown".into(),
            &json!({"paths": paths}),
        )?;
        Ok(())
    }

    fn dirty_adopt(&mut self, agent: &str, paths: &[String], reason: &str) -> Result<()> {
        self.post(
            agent,
            "/api/v1/zones/dirty/adopt".into(),
            &json!({"paths": paths, "reason": reason}),
        )?;
        Ok(())
    }

    fn lost(&self, agent: &str) -> Result<Vec<LostClaim>> {
        let tail = query(&[("session", Some(agent.to_string()))]);
        let value = self.get(agent, format!("/api/v1/zones/lost{tail}"))?;
        Ok(list(value, &["lost", "claims", "items"])?)
    }

    fn catalog(&self) -> Result<Value> {
        self.get(&self.session, "/api/v1/zones/catalog".into())
    }

    fn send(&mut self, agent: &str, request: &SendRequest, _now: i64) -> Result<Message> {
        let mut request = request.clone();
        request.kind.get_or_insert_with(|| DEFAULT_KIND.to_string());
        message(self.post(agent, "/api/v1/bus/messages".into(), &request)?)
    }

    fn reply(&mut self, agent: &str, id: i64, body: &str, _now: i64) -> Result<Message> {
        message(self.post(
            agent,
            format!("/api/v1/bus/messages/{id}/reply"),
            &json!({"body": body}),
        )?)
    }

    fn ack(&mut self, agent: &str, id: i64) -> Result<()> {
        self.post(agent, format!("/api/v1/bus/messages/{id}/ack"), &json!({}))?;
        Ok(())
    }

    fn inbox(&mut self, agent: &str, filter: InboxQuery, _now: i64) -> Result<InboxPage> {
        let tail = query(&[
            ("all", filter.all.then(|| "true".to_string())),
            (
                "limit",
                (filter.limit > 0).then(|| filter.limit.min(INBOX_PAGE).to_string()),
            ),
        ]);
        Ok(inbox_page(
            self.get(agent, format!("/api/v1/bus/inbox{tail}"))?,
        )?)
    }

    fn unread(&self, agent: &str) -> Result<i64> {
        if let Some(answer) = self.transport.fast_unread(agent) {
            return answer?.ok_or_else(|| Error::Unavailable("unread count unknown".into()));
        }
        let page = inbox_page(self.get(agent, "/api/v1/bus/inbox".into())?)?;
        Ok(i64::try_from(page.messages.len())
            .unwrap_or(i64::MAX)
            .saturating_add(page.skipped))
    }

    fn inbox_seen(&mut self, agent: &str, ids: &[i64], _now: i64) -> Result<usize> {
        let value = self.post(agent, "/api/v1/bus/inbox/seen".into(), &json!({"ids": ids}))?;
        self.report_receipts(agent, ids, "read");
        if let Some(marked) = value.get("seen").and_then(Value::as_array) {
            return Ok(marked.len());
        }
        Ok(count(&value, &["seen", "marked", "count"], ids.len()))
    }

    /// The protocol ties a delivery claim to the call, not to a named channel, so `channel` stays local.
    fn inbox_claim(
        &mut self,
        agent: &str,
        _channel: &str,
        ids: &[i64],
        lease_seconds: i64,
        _now: i64,
    ) -> Result<Vec<i64>> {
        let body = json!({"ids": ids, "lease_seconds": lease_seconds});
        let value = self.post(agent, "/api/v1/bus/inbox/claim".into(), &body)?;
        Ok(claimed_ids(value, ids)?)
    }

    fn thread(&self, agent: &str, id: i64) -> Result<Vec<Message>> {
        let value = self.get(agent, format!("/api/v1/bus/threads/{id}"))?;
        Ok(list(value, &["messages", "items"])?)
    }

    fn overdue(&self, agent: &str) -> Result<Vec<Message>> {
        let value = self.get(agent, "/api/v1/bus/overdue".into())?;
        Ok(list(value, &["messages", "items"])?)
    }

    fn undelivered(&self, agent: &str, older_than_seconds: i64) -> Result<Vec<Undelivered>> {
        let tail = query(&[("older_than_seconds", Some(older_than_seconds.to_string()))]);
        let value = self.get(agent, format!("/api/v1/bus/undelivered{tail}"))?;
        Ok(list(value, &["messages", "undelivered", "items"])?)
    }

    fn sent(&self, agent: &str, limit: usize) -> Result<Vec<bus::Receipt>> {
        let tail = query(&[("limit", (limit > 0).then(|| limit.to_string()))]);
        let value = self.get(agent, format!("/api/v1/bus/sent{tail}"))?;
        let items = value
            .get("messages")
            .or_else(|| value.get("items"))
            .unwrap_or(&value);
        let empty = Vec::new();
        Ok(items
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(receipt_from)
            .collect())
    }

    fn tasks(
        &self,
        status: Option<tasks::Status>,
        include_final: bool,
    ) -> Result<Vec<tasks::Task>> {
        let mut found = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let tail = query(&[
                ("limit", Some(ITEM_PAGE.to_string())),
                ("cursor", cursor.clone()),
            ]);
            let page = self.get(&self.session, format!("{ITEMS}{tail}"))?;
            let items = page.get("items").and_then(Value::as_array);
            for item in items.into_iter().flatten() {
                found.push(task_from(item)?);
            }
            match page.get("cursor").and_then(Value::as_str) {
                Some(next) => cursor = Some(next.to_string()),
                None => break,
            }
        }
        found.retain(|task| match status {
            Some(wanted) => task.status == wanted,
            None => include_final || !task.status.is_final(),
        });
        Ok(found)
    }

    fn task(&self, id: i64) -> Result<tasks::Task> {
        task_from(&self.item(&self.session, id)?)
    }

    fn task_history(&self, id: i64) -> Result<Vec<tasks::TaskEvent>> {
        let value = self.get(&self.session, format!("{ITEMS}/{}/history", item_id(id)))?;
        let rows: Vec<Value> = list(value, &["events", "items"])?;
        Ok(rows
            .iter()
            .map(|row| tasks::TaskEvent {
                agent: session_of(text(row, "actor")),
                action: text(row, "op").to_string(),
                note: text(row, "reason").to_string(),
                at: millis(row, "at").unwrap_or(0),
            })
            .collect())
    }

    fn add_task(&mut self, author: &str, spec: &tasks::TaskSpec, now: i64) -> Result<tasks::Task> {
        validate_title(&spec.title)?;
        validate_registry_text("body", &spec.body)?;
        validate_registry_text(
            "acceptance",
            spec.acceptance.as_deref().unwrap_or(&spec.title),
        )?;
        validate_evidence(&spec.evidence.iter().cloned().collect::<Vec<_>>())?;
        let target = spec.target.as_deref().unwrap_or(DEFAULT_TARGET);
        if !matches!(target, "code_accepted" | "ci_passed") {
            return Err(Error::Invalid(format!(
                "task target {target:?} needs evidence this client cannot provide; use code_accepted or ci_passed"
            )));
        }
        let evidence: Vec<Value> = spec
            .evidence
            .iter()
            .map(|value| evidence_body(author, target, value, now))
            .collect();
        let body = json!({
            "client_key": ulid(),
            "title": spec.title,
            "body": spec.body,
            "acceptance": spec.acceptance.as_deref().unwrap_or(&spec.title),
            "type": spec.kind.as_deref().unwrap_or("code"),
            "actor": "agent",
            "area_id": self.area_id(author, spec.area.as_deref())?,
            "priority": spec.priority.as_deref().unwrap_or(DEFAULT_PRIORITY),
            "p0_category": spec.p0_category,
            "due_at": spec.due_at,
            "target": target,
            "verification": spec.verification.as_deref().unwrap_or("auto"),
            "audience": [],
            "evidence": evidence,
        });
        task_from(&self.post(author, ITEMS.into(), &body)?)
    }

    fn plan_task(&mut self, agent: &str, id: i64, plan: &tasks::TaskPlan) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        let body = json!({
            "priority": plan.priority.as_deref().map_or(item["priority"].clone(), |p| json!(p)),
            "p0_category": plan.p0_category.as_deref().map_or(item["p0_category"].clone(), |p| json!(p)),
            "due_at": plan.due_at.as_deref().map_or(item["due_at"].clone(), |p| json!(p)),
            "revisit_after": item["revisit_after"],
            "revisit_on": item["revisit_on"],
            "expected_version": item["version"],
        });
        task_from(&self.post(agent, format!("{ITEMS}/{}/plan", item_id(id)), &body)?)
    }

    /// The registry leases an item for two hours, so `ttl` has no meaning here.
    fn claim_task(&mut self, agent: &str, id: i64, _ttl: i64, _now: i64) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        self.item_step(agent, id, "claim", json!({"session": agent}), &item)
    }

    fn renew_task(&mut self, agent: &str, id: i64, _ttl: i64, _now: i64) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        self.item_step(agent, id, "heartbeat", json!({}), &item)
    }

    fn release_task(
        &mut self,
        agent: &str,
        id: i64,
        _note: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        self.item_step(agent, id, "release", json!({}), &item)
    }

    fn submit_task(
        &mut self,
        agent: &str,
        id: i64,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        validate_evidence(&[evidence.to_string()])?;
        let item = self.item(agent, id)?;
        let target = item["target"].as_str().unwrap_or(DEFAULT_TARGET);
        let body = evidence_body(agent, target, evidence, now);
        let proved = self.item_step(agent, id, "evidence", body, &item);
        proved?;
        let item = self.item(agent, id)?;
        let body = json!({"to": "review", "reason": "submitted for review"});
        self.item_step(agent, id, "transition", body, &item)
    }

    fn accept_task(&mut self, agent: &str, id: i64, note: &str, _now: i64) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        let body =
            json!({"to": "done", "resolution": "completed", "reason": reason_or(note, "accepted")});
        self.item_step(agent, id, "transition", body, &item)
    }

    fn reject_task(
        &mut self,
        agent: &str,
        id: i64,
        reason: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        let body = json!({"to": "ready", "reason": reason_or(reason, "rejected")});
        self.item_step(agent, id, "transition", body, &item)
    }

    fn cancel_task(&mut self, agent: &str, id: i64, note: &str, _now: i64) -> Result<tasks::Task> {
        let item = self.item(agent, id)?;
        let body = json!({
            "to": "cancelled",
            "resolution": "wont_do",
            "reason": reason_or(note, "cancelled"),
        });
        self.item_step(agent, id, "transition", body, &item)
    }

    fn board_set(&mut self, agent: &str, write: &BoardWrite, _now: i64) -> Result<BoardEntry> {
        let mut write = write.clone();
        write.ttl_minutes.get_or_insert(DEFAULT_BOARD_MINUTES);
        let value = self.post(agent, "/api/v1/bus/board".into(), &write)?;
        Ok(one(value, "entry")?)
    }

    fn board_get(&self, key: &str, now: i64) -> Result<Option<BoardEntry>> {
        Ok(self
            .board_list(None, now)?
            .into_iter()
            .find(|entry| entry.key == key))
    }

    fn board_remove(&mut self, agent: &str, key: &str) -> Result<bool> {
        match self.write(
            agent,
            "DELETE",
            format!("/api/v1/bus/board/{}", encode(key)),
            &json!({}),
        ) {
            Ok(_) => Ok(true),
            Err(Error::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn board_list(&self, zone: Option<&str>, _now: i64) -> Result<Vec<BoardEntry>> {
        let tail = query(&[("zone", zone.map(str::to_string))]);
        let value = self.get(&self.session, format!("/api/v1/bus/board{tail}"))?;
        Ok(list(value, &["board", "entries", "items"])?)
    }

    fn work_offer(&mut self, agent: &str, offer: &WorkOffer) -> Result<WorkTask> {
        let value = self.post(agent, "/api/v1/bus/tasks".into(), offer)?;
        Ok(one(value, "task")?)
    }

    fn work_list(&self, agent: &str) -> Result<Vec<WorkTask>> {
        let value = self.get(agent, "/api/v1/bus/tasks".into())?;
        Ok(list(value, &["tasks", "items"])?)
    }

    fn work_get(&self, agent: &str, id: i64) -> Result<WorkTask> {
        let value = self.get(agent, format!("/api/v1/bus/tasks/{id}"))?;
        Ok(one(value, "task")?)
    }

    fn work_step(
        &mut self,
        agent: &str,
        id: i64,
        action: WorkAction,
        step: &WorkStep,
    ) -> Result<WorkTask> {
        if action == WorkAction::Take && step.version.is_none() {
            return Err(Error::Invalid("take needs the task's version".into()));
        }
        let tail = query(&[("version", step.version.map(|version| version.to_string()))]);
        let value = self.post(
            agent,
            format!("/api/v1/bus/tasks/{id}/{}{tail}", action.as_str()),
            step,
        )?;
        Ok(one(value, "task")?)
    }

    fn heartbeat(&mut self, agent: &str, beat: &PresenceBeat, _now: i64) -> Result<()> {
        let mut beat = beat.clone();
        beat.dnd_until = beat.dnd_until.map(|stamp| stamp.on_the_wire());
        if let Some(activity) = beat.activity.as_mut() {
            activity.tool_started_at = activity
                .tool_started_at
                .take()
                .map(|stamp| stamp.on_the_wire());
        }
        self.post(agent, "/api/v1/presence".into(), &beat)?;
        Ok(())
    }

    fn presence(&self, active_within_seconds: i64, _now: i64) -> Result<Vec<Presence>> {
        let tail = query(&[("active_within", Some(active_within_seconds.to_string()))]);
        let value = self.get(&self.session, format!("/api/v1/presence{tail}"))?;
        Ok(list(value, &["sessions", "presence", "items"])?)
    }

    fn events(&self, request: &EventQuery) -> Result<EventPage> {
        if request.wait_seconds > MAX_POLL_WAIT_SECONDS {
            return Err(Error::Invalid(format!(
                "wait is at most {MAX_POLL_WAIT_SECONDS} seconds"
            )));
        }
        let mut call = Call::get(&self.session, event_route(request));
        call.long_poll = request.wait_seconds > 0;
        let value = self.transport.call(&call)?;
        Ok(EventPage {
            events: list(value, &["events", "items"])?,
        })
    }

    fn export(&self) -> Result<Value> {
        self.get(&self.session, "/api/v1/export/coordination".into())
    }

    fn freeze(&mut self, agent: &str, freeze: &Freeze) -> Result<Value> {
        self.post(agent, "/api/v1/admin/freeze".into(), freeze)
    }

    fn import_zones(&mut self, agent: &str, catalog: &Value) -> Result<Value> {
        self.post(
            agent,
            "/api/v1/import/zones".into(),
            &json!({"catalog": catalog}),
        )
    }

    fn import_bus(&mut self, agent: &str, dump: &Value) -> Result<Value> {
        self.post(agent, "/api/v1/import/bus".into(), dump)
    }

    fn registry_import(&mut self, agent: &str, dump: &Value) -> Result<Value> {
        validate_registry_import(dump)?;
        self.post(agent, "/api/v1/registry/import".into(), dump)
    }

    fn tokens(&self) -> Result<Value> {
        self.get(&self.session, TOKENS.into())
    }

    fn token_create(&mut self, agent: &str, request: &TokenRequest) -> Result<Value> {
        self.post(agent, TOKENS.into(), request)
    }

    fn token_revoke(&mut self, agent: &str, id: &str) -> Result<Value> {
        self.post(agent, format!("{TOKENS}/{}/revoke", encode(id)), &json!({}))
    }
}

/// Route of one event poll. `seq` is per stream, so each stream keeps its own cursor.
pub fn event_route(request: &EventQuery) -> String {
    let wait = (request.wait_seconds > 0).then(|| request.wait_seconds.to_string());
    match request.stream {
        Stream::Coordination => {
            let types = (!request.types.is_empty()).then(|| request.types.join(","));
            let tail = query(&[
                ("after", Some(request.after.to_string())),
                ("wait", wait),
                ("session", request.session.clone()),
                ("types", types),
            ]);
            format!("/api/v1/events{tail}")
        }
        Stream::Registry => {
            let tail = query(&[("after", Some(request.after.to_string())), ("wait", wait)]);
            format!("/api/v1/registry/events{tail}")
        }
    }
}

/// Ids a delivery claim granted. An answer without a list grants everything asked: a duplicate over a loss.
pub fn claimed_ids(value: Value, asked: &[i64]) -> std::result::Result<Vec<i64>, ClientError> {
    if value.is_array()
        || value.get("claimed").is_some_and(Value::is_array)
        || value.get("ids").is_some_and(Value::is_array)
    {
        return list(value, &["claimed", "ids"]);
    }
    Ok(asked.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use crate::fake::{FakeServer, Reply, Seen};
    use lockyard_core::proto::{ClaimMode, Purpose, SessionActivity, SessionState, WorkStatus};
    use std::collections::HashSet;

    fn backend(script: Vec<Value>) -> (FakeServer, CloudBackend<Client>) {
        let replies = script
            .into_iter()
            .map(|body| Reply::json(200, body))
            .collect();
        let server = FakeServer::start(replies);
        let client = Client::new(&server.url(), "token".into()).unwrap();
        (server, CloudBackend::new(client, "me"))
    }

    fn sees(server: &FakeServer, routes: &[(&str, &str)]) -> Vec<Seen> {
        let seen = server.requests();
        let actual: Vec<(&str, &str)> = seen
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect();
        assert_eq!(actual, routes);
        let mut keys = HashSet::new();
        for request in &seen {
            let is_read = request.method == "GET" || request.path == "/api/v1/zones/check";
            let key = request.header("idempotency-key");
            if is_read {
                assert_eq!(key, None, "{}", request.path);
            } else {
                assert!(
                    keys.insert(key.expect("every write has a key").to_string()),
                    "keys are unique"
                );
            }
            assert_eq!(request.header("x-lockyard-session"), Some("me"));
        }
        seen
    }

    fn claim_json(id: i64) -> Value {
        json!({"id": id, "session": "me", "paths": ["src"], "fence": 2})
    }

    #[test]
    fn claims_carry_lazy_mode_purpose_meta_and_short_waits() {
        let (server, mut cloud) = backend(vec![json!({"claim": claim_json(1)}), claim_json(2)]);
        let request = ClaimRequest {
            paths: vec!["src".into()],
            note: "n".into(),
            ttl_minutes: 30,
            mode: ClaimMode::Shared,
            purpose: Purpose::Deploy,
            lazy: true,
            zone: Some("api".into()),
            zones: vec!["api".into(), "web".into()],
            queue_wait_seconds: Some(60),
            meta: Some(json!({"change": "abc"})),
        };
        assert_eq!(cloud.claim("me", &request, 0).unwrap().id, 1);
        assert_eq!(
            cloud
                .claim("me", &ClaimRequest::default(), 0)
                .unwrap()
                .fence,
            2
        );
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/claims"),
                ("POST", "/api/v1/zones/claims"),
            ],
        );
        let body = &seen[0].body;
        assert_eq!(body["mode"], "shared");
        assert_eq!(body["purpose"], "deploy");
        assert_eq!(body["lazy"], true);
        assert_eq!(body["queue_wait_seconds"], 60);
        assert_eq!(body["meta"]["change"], "abc");
        assert_eq!(body["zones"], json!(["api", "web"]));
    }

    #[test]
    fn claim_lifecycle_routes_and_fences() {
        let (server, mut cloud) = backend(vec![
            claim_json(5),
            claim_json(5),
            json!({"pending": true}),
            claim_json(5),
            claim_json(5),
            json!({}),
            json!({}),
            json!({}),
            json!([claim_json(5), claim_json(6)]),
            json!({}),
            json!({}),
            json!({"released": 2}),
        ]);
        cloud.add_path("me", 5, "docs", Some(7)).unwrap();
        cloud
            .narrow("me", 5, &["src".to_string()], Some(7))
            .unwrap();
        cloud.handover("me", 5, "bob", Some(7)).unwrap();
        cloud.handover_accept("me", 5).unwrap();
        cloud.takeover("me", 5, "holder is gone").unwrap();
        cloud
            .activity(
                "me",
                5,
                &ActivityRequest {
                    write: true,
                    paths: vec!["src".into()],
                    fence: Some(7),
                },
            )
            .unwrap();
        let renew = RenewRequest {
            ttl_minutes: 10,
            fence: Some(7),
            ..RenewRequest::default()
        };
        assert_eq!(cloud.renew("me", Some(5), &renew, 0).unwrap(), 1);
        let release = ReleaseRequest {
            note: Some("done".into()),
            leave_dirty: true,
            fence: Some(7),
        };
        assert_eq!(cloud.release("me", Some(5), &release, 0).unwrap(), 1);
        let renew_all = RenewRequest {
            ttl_minutes: 10,
            ..RenewRequest::default()
        };
        assert_eq!(cloud.renew("me", None, &renew_all, 0).unwrap(), 2);
        assert_eq!(
            cloud
                .release("me", None, &ReleaseRequest::default(), 0)
                .unwrap(),
            2
        );
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/claims/5/add-path"),
                ("POST", "/api/v1/zones/claims/5/narrow"),
                ("POST", "/api/v1/zones/claims/5/handover"),
                ("POST", "/api/v1/zones/claims/5/accept"),
                ("POST", "/api/v1/zones/claims/5/takeover"),
                ("POST", "/api/v1/zones/claims/5/activity"),
                ("POST", "/api/v1/zones/claims/5/renew"),
                ("DELETE", "/api/v1/zones/claims/5"),
                ("GET", "/api/v1/zones/claims?session=me"),
                ("POST", "/api/v1/zones/claims/5/renew"),
                ("POST", "/api/v1/zones/claims/6/renew"),
                ("DELETE", "/api/v1/zones/claims?session=me"),
            ],
        );
        assert_eq!(seen[0].body, json!({"path": "docs", "fence": 7}));
        assert_eq!(seen[1].body, json!({"paths": ["src"], "fence": 7}));
        assert_eq!(seen[2].body, json!({"to": "bob", "fence": 7}));
        assert_eq!(seen[4].body, json!({"reason": "holder is gone"}));
        assert_eq!(
            seen[5].body,
            json!({"write": true, "paths": ["src"], "fence": 7})
        );
        assert_eq!(seen[6].body["fence"], 7);
        assert_eq!(
            seen[7].body,
            json!({"note": "done", "leave_dirty": true, "fence": 7})
        );
    }

    #[test]
    fn bulk_release_sends_options_in_the_delete_body_and_fences_only_one_live_claim() {
        let (server, mut cloud) = backend(vec![
            json!([claim_json(5)]),
            json!({"released": 1}),
            json!([claim_json(5), claim_json(6)]),
        ]);
        let request = ReleaseRequest {
            note: Some("finished".into()),
            leave_dirty: true,
            fence: Some(9),
        };
        assert_eq!(cloud.release("me", None, &request, 0).unwrap(), 1);
        assert!(matches!(
            cloud.release("me", None, &request, 0),
            Err(Error::Invalid(_))
        ));
        let seen = server.requests();
        assert_eq!(seen[1].method, "DELETE");
        assert_eq!(seen[1].path, "/api/v1/zones/claims?session=me");
        assert_eq!(
            seen[1].body,
            json!({"note": "finished", "leave_dirty": true, "fence": 9})
        );
        assert_eq!(
            seen.len(),
            3,
            "a multi-claim fence must be rejected before DELETE"
        );
    }

    #[test]
    fn seen_returns_only_ids_the_server_marked() {
        let (_server, mut cloud) = backend(vec![json!({"seen": [7]})]);
        assert_eq!(cloud.inbox_seen("me", &[7, 8], 0).unwrap(), 1);
    }

    #[test]
    fn a_takeover_needs_a_reason_before_any_request() {
        let (server, mut cloud) = backend(vec![]);
        assert!(matches!(
            cloud.takeover("me", 1, "  "),
            Err(Error::Invalid(_))
        ));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn claim_listing_and_check_read_free_own_and_holder() {
        let (server, cloud) = backend(vec![
            json!({"claims": [claim_json(1)]}),
            json!({"paths": [
                {"path": "a", "status": "free"},
                {"path": "b", "status": "own"},
                {"path": "c", "status": "held", "holder": {"session": "bob", "claim_id": 9, "note": "n"}},
                {"path": "d", "status": "held", "holder": "carol"}
            ]}),
        ]);
        let filter = ClaimQuery {
            session: Some("me".into()),
            path: Some("src/a b".into()),
        };
        assert_eq!(cloud.claims(&filter, 0).unwrap()[0].id, 1);
        let paths: Vec<String> = ["a", "b", "c", "d"].iter().map(|p| p.to_string()).collect();
        let found = cloud.check("me", &paths, Some(4), 0).unwrap();
        let statuses: Vec<_> = found.iter().map(|check| check.status).collect();
        assert_eq!(
            statuses,
            [
                CheckStatus::Free,
                CheckStatus::Own,
                CheckStatus::Held,
                CheckStatus::Held
            ]
        );
        assert_eq!(found[2].holder.as_ref().unwrap().agent, "bob");
        assert_eq!(found[3].holder.as_ref().unwrap().agent, "carol");
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/zones/claims?session=me&path=src%2Fa%20b"),
                ("POST", "/api/v1/zones/check"),
            ],
        );
        assert_eq!(
            seen[1].body,
            json!({"paths": ["a", "b", "c", "d"], "fence": 4})
        );
    }

    #[test]
    fn queue_routes() {
        let (server, mut cloud) = backend(vec![
            json!({"id": 3, "session": "me", "paths": ["src"]}),
            json!([{"id": 3, "session": "me"}]),
            Value::Null,
        ]);
        let request = QueueRequest {
            paths: vec!["src".into()],
            ttl_minutes: 60,
            zones: vec!["api".into()],
            ..QueueRequest::default()
        };
        assert_eq!(cloud.queue_add("me", &request).unwrap().id, 3);
        assert_eq!(cloud.queue_list("me").unwrap().len(), 1);
        cloud.queue_cancel("me", 3).unwrap();
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/queue"),
                ("GET", "/api/v1/zones/queue"),
                ("DELETE", "/api/v1/zones/queue/3"),
            ],
        );
        assert_eq!(seen[0].body["ttl_minutes"], 60);
        assert_eq!(seen[0].body["zones"], json!(["api"]));
    }

    #[test]
    fn request_routes() {
        let (server, mut cloud) = backend(vec![
            json!({"id": 4, "session": "me", "paths": ["src"], "text": "please"}),
            json!({"request": {"id": 4, "reply": "soon"}}),
        ]);
        let request = AccessRequest {
            paths: vec!["src".into()],
            text: "please".into(),
            urgent: true,
            need_by: Some("soon".into()),
        };
        assert_eq!(cloud.zone_request("me", &request).unwrap().from, "me");
        let answer = AccessAnswer {
            reply: Some("soon".into()),
            eta: Some("10m".into()),
        };
        assert_eq!(
            cloud
                .zone_answer("me", 4, &answer)
                .unwrap()
                .reply
                .as_deref(),
            Some("soon")
        );
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/requests"),
                ("POST", "/api/v1/zones/requests/4/answer"),
            ],
        );
        assert_eq!(seen[0].body["urgent"], true);
        assert_eq!(seen[1].body, json!({"reply": "soon", "eta": "10m"}));
    }

    #[test]
    fn dirty_routes_disown_and_adopt() {
        let (server, mut cloud) = backend(vec![
            json!({}),
            json!({"paths": [{"path": "a", "owner_session": "bob", "task_id": 2}]}),
            json!({}),
            json!({}),
        ]);
        let report = DirtyPath {
            path: "a".into(),
            owner_session: Some("bob".into()),
            reason: None,
            task_id: Some(2),
        };
        cloud
            .dirty_report("me", std::slice::from_ref(&report))
            .unwrap();
        assert_eq!(cloud.dirty_list("me", Some("a")).unwrap(), [report]);
        cloud.dirty_disown("me", &["a".to_string()]).unwrap();
        cloud
            .dirty_adopt("me", &["a".to_string()], "left behind")
            .unwrap();
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/dirty"),
                ("GET", "/api/v1/zones/dirty?path=a"),
                ("POST", "/api/v1/zones/dirty/disown"),
                ("POST", "/api/v1/zones/dirty/adopt"),
            ],
        );
        assert_eq!(seen[0].body["paths"][0]["owner_session"], "bob");
        assert_eq!(
            seen[3].body,
            json!({"paths": ["a"], "reason": "left behind"})
        );
    }

    #[test]
    fn lost_claims_and_the_catalog() {
        let (server, cloud) = backend(vec![
            json!([{"claim_id": 8, "session": "me", "paths": ["src"], "reason": "unavailable"}]),
            json!({"zones": {"api": ["src"]}}),
        ]);
        assert_eq!(cloud.lost("me").unwrap()[0].claim_id, 8);
        assert_eq!(cloud.catalog().unwrap()["zones"]["api"][0], "src");
        sees(
            &server,
            &[
                ("GET", "/api/v1/zones/lost?session=me"),
                ("GET", "/api/v1/zones/catalog"),
            ],
        );
    }

    #[test]
    fn mail_is_two_phase_with_delivery_claims() {
        let (server, mut cloud) = backend(vec![
            json!({"id": 10, "thread_id": 10, "from_session": "me", "to": "bob", "body": "x", "deduplicated": true}),
            json!({"id": 11, "thread_id": 10, "in_reply_to": 10, "from_session": "me", "to": "bob", "body": "y"}),
            json!({}),
            json!({"messages": [{"id": 12, "from_session": "bob", "to": "me", "body": "z"}], "skipped": 3}),
            json!({"messages": [{"id": 12}], "skipped": 3}),
            json!({"claimed": [12]}),
            json!({"seen": 1}),
            json!({}),
        ]);
        let send = SendRequest {
            to: "bob".into(),
            body: "x".into(),
            kind: Some("ask".into()),
            needs: Some("reply".into()),
            key: Some("k".into()),
            ..SendRequest::default()
        };
        assert!(cloud.send("me", &send, 0).unwrap().deduplicated);
        assert_eq!(cloud.reply("me", 10, "y", 0).unwrap().reply_to, Some(10));
        cloud.ack("me", 10).unwrap();
        let page = cloud
            .inbox(
                "me",
                InboxQuery {
                    all: true,
                    limit: 20,
                },
                0,
            )
            .unwrap();
        assert_eq!((page.messages[0].id, page.skipped), (12, 3));
        assert_eq!(cloud.unread("me").unwrap(), 4);
        assert_eq!(
            cloud.inbox_claim("me", "hook", &[12, 13], 60, 0).unwrap(),
            [12]
        );
        assert_eq!(cloud.inbox_seen("me", &[12], 0).unwrap(), 1);
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/bus/messages"),
                ("POST", "/api/v1/bus/messages/10/reply"),
                ("POST", "/api/v1/bus/messages/10/ack"),
                ("GET", "/api/v1/bus/inbox?all=true&limit=20"),
                ("GET", "/api/v1/bus/inbox"),
                ("POST", "/api/v1/bus/inbox/claim"),
                ("POST", "/api/v1/bus/inbox/seen"),
                // Marking mail read tells the sender so, through the endpoint in the contract.
                ("POST", "/api/v1/messages/12/receipt"),
            ],
        );
        assert_eq!(seen[0].body["needs"], "reply");
        assert_eq!(seen[5].body, json!({"ids": [12, 13], "lease_seconds": 60}));
        assert_eq!(seen[6].body, json!({"ids": [12]}));
        assert_eq!(seen[7].body, json!({"status": "read"}));
    }

    #[test]
    fn sent_mail_comes_back_with_the_status_the_server_gave_each_message() {
        let (server, cloud) = backend(vec![json!({"messages": [
            {"id": 7, "to": "bob", "body": "take src/api", "created_at": 10,
             "status": "replied", "delivered_at": 20, "read_at": 30, "replied_at": 40},
            {"id": 8, "to": "bob", "body": "and this", "created_at": 11, "status": "sent"},
            {"id": 9, "to": "gone", "body": "", "created_at": 12, "status": "failed"},
            {"id": 10, "to": "bob", "body": "?", "created_at": 13, "status": "something new"}
        ]})]);
        let receipts = cloud.sent("me", 20).unwrap();
        let statuses: Vec<bus::Delivery> = receipts.iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [
                bus::Delivery::Replied,
                bus::Delivery::Sent,
                bus::Delivery::Failed,
                bus::Delivery::Sent
            ]
        );
        assert_eq!(receipts[0].delivered_at, Some(20));
        assert_eq!(receipts[0].read_at, Some(30));
        assert_eq!(receipts[0].replied_at, Some(40));
        assert_eq!(receipts[0].to, "bob");
        let seen = server.requests();
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].path, "/api/v1/bus/sent?limit=20");
    }

    #[test]
    fn a_read_of_the_inbox_never_writes() {
        let (server, mut cloud) = backend(vec![json!({"messages": []})]);
        cloud.inbox("me", InboxQuery::default(), 0).unwrap();
        assert_eq!(server.requests().len(), 1);
        assert_eq!(server.requests()[0].method, "GET");
    }

    #[test]
    fn an_answer_without_a_list_grants_what_was_asked() {
        assert_eq!(claimed_ids(json!({}), &[1, 2]).unwrap(), [1, 2]);
        assert_eq!(claimed_ids(json!({"ids": [2]}), &[1, 2]).unwrap(), [2]);
        assert_eq!(claimed_ids(json!([]), &[1, 2]).unwrap(), Vec::<i64>::new());
    }

    #[test]
    fn threads_overdue_and_undelivered() {
        let (server, cloud) = backend(vec![
            json!({"messages": [{"id": 1}]}),
            json!([{"id": 2, "needs": "ack"}]),
            json!([{"message_id": 3, "to": "bob", "age_seconds": 70}]),
        ]);
        assert_eq!(cloud.thread("me", 1).unwrap().len(), 1);
        assert_eq!(cloud.overdue("me").unwrap()[0].id, 2);
        assert_eq!(cloud.undelivered("me", 60).unwrap()[0].to, "bob");
        sees(
            &server,
            &[
                ("GET", "/api/v1/bus/threads/1"),
                ("GET", "/api/v1/bus/overdue"),
                ("GET", "/api/v1/bus/undelivered?older_than_seconds=60"),
            ],
        );
    }

    #[test]
    fn board_routes() {
        let (server, mut cloud) = backend(vec![
            json!({"key": "a/b", "value": "v"}),
            json!([{"key": "a/b", "value": "v", "zone": "api"}]),
            json!([{"key": "a/b", "value": 3}]),
            json!({}),
        ]);
        let write = BoardWrite {
            key: "a/b".into(),
            value: "v".into(),
            zone: Some("api".into()),
            ttl_minutes: Some(5),
        };
        assert_eq!(cloud.board_set("me", &write, 0).unwrap().text(), "v");
        assert_eq!(cloud.board_list(Some("api"), 0).unwrap().len(), 1);
        assert_eq!(cloud.board_get("a/b", 0).unwrap().unwrap().text(), "3");
        assert!(cloud.board_remove("me", "a/b").unwrap());
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/bus/board"),
                ("GET", "/api/v1/bus/board?zone=api"),
                ("GET", "/api/v1/bus/board"),
                ("DELETE", "/api/v1/bus/board/a%2Fb"),
            ],
        );
        assert_eq!(seen[0].body["ttl_minutes"], 5);
    }

    #[test]
    fn removing_an_absent_board_key_reads_as_false() {
        let server = FakeServer::start(vec![Reply::json(404, json!({"error": {"message": "no"}}))]);
        let client = Client::new(&server.url(), "t".into()).unwrap();
        assert!(
            !CloudBackend::new(client, "me")
                .board_remove("me", "k")
                .unwrap()
        );
    }

    #[test]
    fn work_tasks_walk_every_transition() {
        let task = |status: &str, version: i64| json!({"id": 6, "status": status, "version": version, "to": "bob", "title": "t"});
        let actions = [
            (WorkAction::Claim, "claimed"),
            (WorkAction::Beat, "claimed"),
            (WorkAction::Done, "review"),
            (WorkAction::Reject, "claimed"),
            (WorkAction::Handoff, "offered"),
            (WorkAction::Take, "claimed"),
            (WorkAction::Done, "review"),
            (WorkAction::Accept, "accepted"),
            (WorkAction::Fail, "failed"),
            (WorkAction::Cancel, "cancelled"),
            (WorkAction::Decline, "offered"),
        ];
        let mut script = vec![task("offered", 1)];
        script.extend(
            actions
                .iter()
                .enumerate()
                .map(|(index, (_, status))| task(status, index as i64 + 2)),
        );
        script.push(json!([task("offered", 1)]));
        script.push(task("offered", 1));
        let (server, mut cloud) = backend(script);
        let offer = WorkOffer {
            title: "t".into(),
            to: "bob".into(),
            accept: "tests pass".into(),
            re: Some("D-1".into()),
            zone: Some("api".into()),
            brief: Some("b".into()),
        };
        assert_eq!(
            cloud.work_offer("me", &offer).unwrap().status,
            WorkStatus::Offered
        );
        let mut routes: Vec<String> = vec!["/api/v1/bus/tasks".into()];
        for (action, _) in actions {
            let step = WorkStep {
                version: (action == WorkAction::Take).then_some(4),
                to: (action == WorkAction::Handoff).then(|| "carol".to_string()),
                report: (action == WorkAction::Done).then(|| "done".to_string()),
                reason: (action == WorkAction::Reject).then(|| "no".to_string()),
                commits: if action == WorkAction::Done {
                    vec!["abc".into()]
                } else {
                    Vec::new()
                },
            };
            cloud.work_step("me", 6, action, &step).unwrap();
            let tail = if action == WorkAction::Take {
                "?version=4"
            } else {
                ""
            };
            routes.push(format!("/api/v1/bus/tasks/6/{}{tail}", action.as_str()));
        }
        assert_eq!(cloud.work_list("me").unwrap().len(), 1);
        assert_eq!(cloud.work_get("me", 6).unwrap().title, "t");
        routes.push("/api/v1/bus/tasks".into());
        routes.push("/api/v1/bus/tasks/6".into());
        let expected: Vec<(&str, &str)> = routes
            .iter()
            .enumerate()
            .map(|(index, route)| {
                (
                    if index + 2 >= routes.len() {
                        "GET"
                    } else {
                        "POST"
                    },
                    route.as_str(),
                )
            })
            .collect();
        let seen = sees(&server, &expected);
        assert_eq!(seen[3].body, json!({"report": "done", "commits": ["abc"]}));
        assert_eq!(seen[5].body, json!({"to": "carol"}));
        assert_eq!(seen[4].body, json!({"reason": "no"}));
    }

    #[test]
    fn take_refuses_to_go_without_a_version() {
        let (server, mut cloud) = backend(vec![]);
        assert!(
            cloud
                .work_step("me", 1, WorkAction::Take, &WorkStep::default())
                .is_err()
        );
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_stale_version_is_a_conflict_that_names_it() {
        let body =
            json!({"error": {"code": "conflict", "message": "stale", "details": {"version": 9}}});
        let server = FakeServer::start(vec![Reply::json(409, body)]);
        let client = Client::new(&server.url(), "t".into()).unwrap();
        let mut cloud = CloudBackend::new(client, "me");
        let step = WorkStep {
            version: Some(1),
            ..WorkStep::default()
        };
        let error = cloud
            .work_step("me", 1, WorkAction::Claim, &step)
            .unwrap_err();
        assert!(matches!(&error, Error::Contended(text) if text.contains("version 9")));
    }

    #[test]
    fn presence_carries_activity() {
        let (server, mut cloud) = backend(vec![
            json!({"server_time": 5}),
            json!({"sessions": [{"session": "me", "client": "cli", "last_seen": "t", "activity": {"tool_running": true, "state": "working"}}]}),
            json!([{"session": "bob"}]),
        ]);
        let beat = PresenceBeat {
            client: "cli".into(),
            model: Some("m".into()),
            activity: Some(SessionActivity {
                tool_running: true,
                tool_started_at: None,
                state: Some(SessionState::ApiFailure),
                meta: Some(json!({"pid": 1})),
            }),
            ..PresenceBeat::default()
        };
        cloud.heartbeat("me", &beat, 0).unwrap();
        let live = cloud.presence(60, 0).unwrap();
        assert_eq!(
            live[0].activity.as_ref().unwrap().state,
            Some(SessionState::Working)
        );
        assert_eq!(cloud.agents().unwrap()[0].id, "bob");
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/presence"),
                ("GET", "/api/v1/presence?active_within=60"),
                ("GET", "/api/v1/presence?active_within=604800"),
            ],
        );
        assert_eq!(seen[0].body["activity"]["state"], "api_failure");
        assert_eq!(seen[0].body["activity"]["meta"]["pid"], 1);
    }

    #[test]
    fn both_event_streams_poll_with_their_own_routes() {
        let (server, cloud) = backend(vec![
            json!({"events": [{"seq": 9, "type": "zone.claimed", "payload": {"claim_id": 1}}]}),
            json!([{"seq": 3, "type": "registry.item", "payload": {}}]),
        ]);
        let coordination = EventQuery {
            after: 4,
            wait_seconds: 25,
            session: Some("me".into()),
            types: vec!["zone.claimed".into(), "bus.message".into()],
            ..EventQuery::default()
        };
        let page = cloud.events(&coordination).unwrap();
        assert_eq!(page.last_seq(4), 9);
        assert_eq!(page.events[0].field("claim_id"), Some(&json!(1)));
        let registry = EventQuery {
            stream: Stream::Registry,
            after: 2,
            ..EventQuery::default()
        };
        assert_eq!(cloud.events(&registry).unwrap().last_seq(2), 3);
        sees(
            &server,
            &[
                (
                    "GET",
                    "/api/v1/events?after=4&wait=25&session=me&types=zone.claimed%2Cbus.message",
                ),
                ("GET", "/api/v1/registry/events?after=2"),
            ],
        );
    }

    #[test]
    fn a_wait_past_the_protocol_limit_is_refused() {
        let (server, cloud) = backend(vec![]);
        let query = EventQuery {
            wait_seconds: 26,
            ..EventQuery::default()
        };
        assert!(matches!(cloud.events(&query), Err(Error::Invalid(_))));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn export_freeze_and_import() {
        let (server, mut cloud) = backend(vec![
            json!({"claims": [], "messages": [{"id": 4, "seen_by": ["alice"]}], "board": [{"key": "k", "expires_at": "2027-01-01T00:00:00Z"}]}),
            json!({"frozen": true}),
            json!({"ok": true}),
            json!({"ok": true}),
        ]);
        let exported = cloud.export().unwrap();
        assert_eq!(exported["messages"][0]["seen_by"], json!(["alice"]));
        assert_eq!(exported["board"][0]["expires_at"], "2027-01-01T00:00:00Z");
        cloud
            .freeze(
                "me",
                &Freeze {
                    on: true,
                    reason: "switch".into(),
                },
            )
            .unwrap();
        cloud.import_zones("me", &json!({"zones": {}})).unwrap();
        let bus_dump = json!({"messages": [{"id": 4, "seen_by": ["alice"]}], "board": [{"key": "k", "expires_at": "2027-01-01T00:00:00Z"}]});
        cloud.import_bus("me", &bus_dump).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/export/coordination"),
                ("POST", "/api/v1/admin/freeze"),
                ("POST", "/api/v1/import/zones"),
                ("POST", "/api/v1/import/bus"),
            ],
        );
        assert_eq!(seen[1].body, json!({"on": true, "reason": "switch"}));
        assert_eq!(seen[2].body["catalog"], json!({"zones": {}}));
        assert_eq!(
            seen[3].body, bus_dump,
            "import must retain seen_by and board expiry"
        );
    }

    #[test]
    fn registry_create_and_import_limits_are_checked_before_requests() {
        let (server, mut cloud) = backend(vec![json!([])]);
        let too_long = tasks::TaskSpec {
            title: "t".into(),
            body: "é".repeat(4097),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &too_long, 0),
            Err(Error::Invalid(_))
        ));
        let too_long_evidence = tasks::TaskSpec {
            title: "t".into(),
            evidence: Some("x".repeat(1025)),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &too_long_evidence, 0),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            cloud.registry_import("me", &json!({"items": [{"legacy_raw": "x".repeat(8193)}]})),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            cloud.registry_import(
                "me",
                &json!({"items": [{"evidence": [{"value": "x".repeat(1025)}]}]})
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(cloud.registry_import("me", &json!({"items": [{"evidence": [{"value": "1"}, {"value": "2"}, {"value": "3"}, {"value": "4"}, {"value": "5"}]}]})), Err(Error::Invalid(_))));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn requests_for_the_active_session_use_the_new_list_route() {
        let (server, cloud) = backend(vec![
            json!({"requests": [{"id": 4, "from": "me", "text": "please"}]}),
        ]);
        assert_eq!(cloud.zone_requests("me").unwrap()[0].id, 4);
        let seen = sees(&server, &[("GET", "/api/v1/zones/requests")]);
        assert_eq!(seen[0].header("x-lockyard-session"), Some("me"));
    }

    fn item(status: &str, version: i64) -> Value {
        json!({
            "id": "D-7", "title": "t", "body": "b", "status": status, "priority": "P1", "version": version,
            "target": "ci_passed", "created_by": "token:ab:writer",
            "created_at": "2026-11-02T10:00:00+00:00", "updated_at": "2026-11-02T10:00:00+00:00",
            "assignment": {"executor": "token:ab:s:1", "lease_expires_at": "2026-11-02T12:00:00+00:00"},
            "evidence": [{"value": "run 5"}],
        })
    }

    #[test]
    fn a_new_item_sets_its_urgency_and_finds_an_area() {
        let (server, mut cloud) = backend(vec![
            json!([{"id": "a1", "key": "api"}, {"id": "a2", "key": "web"}]),
            item("ready", 1),
        ]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            priority: Some("P1".into()),
            area: Some("web".into()),
            ..tasks::TaskSpec::default()
        };
        let task = cloud.add_task("me", &spec, 0).unwrap();
        assert_eq!((task.id, task.priority.as_deref()), (7, Some("P1")));
        assert_eq!(task.status, tasks::Status::Open);
        assert_eq!(task.author, "writer");
        assert_eq!(task.assignee.as_deref(), Some("s:1"));
        assert_eq!(task.evidence.as_deref(), Some("run 5"));
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/areas"),
                ("POST", "/api/v1/registry/items"),
            ],
        );
        let body = &seen[1].body;
        assert_eq!(body["area_id"], "a2");
        assert_eq!(body["priority"], "P1");
        assert_eq!(body["type"], "code");
        assert_eq!(body["target"], "code_accepted");
        assert_eq!(body["client_key"].as_str().unwrap().len(), 26);
    }

    #[test]
    fn a_new_item_refuses_targets_the_client_cannot_prove_before_sending_it() {
        struct UnexpectedTransport;
        impl Transport for UnexpectedTransport {
            fn call(&self, _: &Call) -> std::result::Result<Value, ClientError> {
                panic!("unsupported targets must be rejected before any server call")
            }
        }
        let mut cloud = CloudBackend::new(UnexpectedTransport, "me");
        for target in [
            "deployed_staging",
            "deployed_prod",
            "verified_prod",
            "owner_decision",
            "external_confirmation",
        ] {
            let spec = tasks::TaskSpec {
                title: "t".into(),
                target: Some(target.into()),
                ..tasks::TaskSpec::default()
            };
            assert!(matches!(
                cloud.add_task("me", &spec, 0),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn an_unknown_area_is_refused_and_a_workspace_without_one_gets_the_default() {
        let (_server, mut cloud) = backend(vec![json!([])]);
        let named = tasks::TaskSpec {
            title: "t".into(),
            area: Some("nope".into()),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &named, 0),
            Err(Error::NotFound(_))
        ));
        let (server, mut cloud) = backend(vec![json!([]), json!({"id": "new"}), item("ready", 1)]);
        let plain = tasks::TaskSpec {
            title: "t".into(),
            ..tasks::TaskSpec::default()
        };
        cloud.add_task("me", &plain, 0).unwrap();
        let seen = server.requests();
        assert_eq!(seen[1].body["key"], "general");
        assert_eq!(seen[2].body["area_id"], "new");
    }

    #[test]
    fn a_submission_proves_first_and_each_step_carries_the_version_it_read() {
        let (server, mut cloud) = backend(vec![
            item("active", 3),
            item("active", 4),
            item("active", 4),
            item("review", 5),
        ]);
        cloud.submit_task("me", 7, "run 5", 0).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/D-7"),
                ("POST", "/api/v1/registry/items/D-7/evidence"),
                ("GET", "/api/v1/registry/items/D-7"),
                ("POST", "/api/v1/registry/items/D-7/transition"),
            ],
        );
        assert_eq!(seen[1].body["expected_version"], 3);
        assert_eq!(seen[1].body["kind"], "ci_run");
        assert_eq!(
            seen[3].body,
            json!({"to": "review", "reason": "submitted for review", "expected_version": 4})
        );
    }

    #[test]
    fn listing_walks_every_page_and_hides_final_items() {
        let (server, cloud) = backend(vec![
            json!({"items": [item("ready", 1)], "cursor": "7"}),
            json!({"items": [item("done", 1)], "cursor": null}),
        ]);
        assert_eq!(cloud.tasks(None, false).unwrap().len(), 1);
        let seen = server.requests();
        assert_eq!(seen[1].path, "/api/v1/registry/items?limit=200&cursor=7");
    }

    #[test]
    fn history_reads_the_session_out_of_the_identity() {
        let (_server, cloud) = backend(vec![json!([
            {"actor": "token:ab:bob", "op": "claimed", "reason": null, "at": "2026-11-02T10:00:00+00:00"}
        ])]);
        let history = cloud.task_history(7).unwrap();
        assert_eq!(
            (history[0].agent.as_str(), history[0].action.as_str()),
            ("bob", "claimed")
        );
    }

    #[test]
    fn tokens_use_the_registry_routes() {
        let (server, mut cloud) = backend(vec![json!([]), json!({"raw": "x"}), json!({})]);
        cloud.tokens().unwrap();
        let request = TokenRequest {
            name: "n".into(),
            role: "agent".into(),
            expires_at: "2027-01-01T00:00:00.000Z".into(),
        };
        assert_eq!(cloud.token_create("me", &request).unwrap()["raw"], "x");
        cloud.token_revoke("me", "abc").unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/tokens"),
                ("POST", "/api/v1/registry/tokens"),
                ("POST", "/api/v1/registry/tokens/abc/revoke"),
            ],
        );
        assert_eq!(seen[1].body["role"], "agent");
    }

    /// Keeps the calls it is given, for what HTTP does not show.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<Call>>);

    impl Transport for Recorder {
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            self.0.lock().unwrap().push(call.clone());
            Ok(claim_json(1))
        }
    }

    #[test]
    fn a_claim_that_waits_uses_the_long_read_limit() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let mut cloud = CloudBackend::new(std::sync::Arc::clone(&recorder), "me");
        let waiting = ClaimRequest {
            queue_wait_seconds: Some(25),
            ..ClaimRequest::default()
        };
        cloud.claim("me", &ClaimRequest::default(), 0).unwrap();
        cloud.claim("me", &waiting, 0).unwrap();
        let calls = recorder.0.lock().unwrap();
        assert!(!calls[0].long_poll);
        assert!(calls[1].long_poll);
    }

    #[test]
    fn undelivered_mail_names_its_addressee() {
        let (_server, cloud) = backend(vec![
            json!([{"id": 3, "addressee": "bob", "age_seconds": 7}]),
        ]);
        assert_eq!(cloud.undelivered("me", 0).unwrap()[0].to, "bob");
    }

    #[test]
    fn a_check_without_a_status_is_refused_and_never_reads_as_free() {
        assert!(checks(json!([{"path": "a", "state": "held"}])).is_err());
    }

    #[test]
    fn a_large_inbox_page_is_cut_to_what_the_server_takes() {
        let (server, mut cloud) = backend(vec![json!({"messages": []})]);
        let filter = InboxQuery {
            all: false,
            limit: 200,
        };
        cloud.inbox("me", filter, 0).unwrap();
        assert_eq!(server.requests()[0].path, "/api/v1/bus/inbox?limit=50");
    }

    #[test]
    fn plain_mail_names_a_kind_and_a_plain_board_value_a_lifetime() {
        let (server, mut cloud) =
            backend(vec![json!({"id": 1}), json!({"key": "k", "value": "v"})]);
        let send = SendRequest {
            to: "bob".into(),
            body: "x".into(),
            ..SendRequest::default()
        };
        cloud.send("me", &send, 0).unwrap();
        let write = BoardWrite {
            key: "k".into(),
            value: "v".into(),
            ..BoardWrite::default()
        };
        cloud.board_set("me", &write, 0).unwrap();
        let seen = server.requests();
        assert_eq!(seen[0].body["kind"], "ask");
        assert_eq!(seen[1].body["ttl_minutes"], 1440);
    }

    #[test]
    fn a_heartbeat_writes_its_times_as_text() {
        let (server, mut cloud) = backend(vec![json!({})]);
        let beat = PresenceBeat {
            client: "cli".into(),
            dnd_until: Some(lockyard_core::proto::Stamp::Millis(0)),
            activity: Some(SessionActivity {
                tool_running: true,
                tool_started_at: Some(lockyard_core::proto::Stamp::Millis(0)),
                state: None,
                meta: None,
            }),
            ..PresenceBeat::default()
        };
        cloud.heartbeat("me", &beat, 0).unwrap();
        let body = &server.requests()[0].body;
        assert_eq!(body["dnd_until"], "1970-01-01T00:00:00.000Z");
        assert_eq!(
            body["activity"]["tool_started_at"],
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn a_body_that_is_not_a_list_is_a_decode_error() {
        let (_server, cloud) = backend(vec![json!({"nope": 1})]);
        assert!(matches!(
            cloud.claims(&ClaimQuery::default(), 0),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn a_message_queued_by_the_agent_process_reads_as_queued() {
        let message = message(json!({"queued": true, "key": "k"})).unwrap();
        assert!(message.queued);
        assert_eq!(message.key.as_deref(), Some("k"));
    }
}
