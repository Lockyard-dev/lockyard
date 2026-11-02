// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! [`Backend`] over the cloud protocol.
//!
//! The protocol names the fields of a record but not the envelope of a response, so a list reads
//! either as a bare array or under its plural name, and a record either bare or under its singular name.

use crate::{Call, ClientError, MAX_POLL_WAIT_SECONDS, Transport, encode};
use lockyard_core::proto::{
    AccessAnswer, AccessRecord, AccessRequest, ActivityRequest, AgentSeen, BoardEntry, BoardWrite,
    CheckStatus, Claim, ClaimQuery, ClaimRequest, DirtyPath, EventPage, EventQuery, Freeze,
    InboxPage, InboxQuery, LostClaim, Message, PathCheck, Presence, PresenceBeat, QueueEntry,
    QueueRequest, ReleaseRequest, RenewRequest, SendRequest, Stream, Undelivered, WorkAction,
    WorkOffer, WorkStep, WorkTask,
};
use lockyard_core::zones::Conflict;
use lockyard_core::{Backend, Error, Result, tasks};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const TASKS_IN_CLOUD: &str = "the task commands: cloud work goes through `lockyard work`, and";
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
    let status = match item.get("status").and_then(Value::as_str) {
        Some("own") => CheckStatus::Own,
        Some("held") | Some("holder") => CheckStatus::Held,
        Some("free") => CheckStatus::Free,
        _ if holder.is_some() => CheckStatus::Held,
        _ => CheckStatus::Free,
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

fn no_tasks<T>() -> Result<T> {
    Err(Error::NeedsLocal(TASKS_IN_CLOUD.into()))
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
        let value = self.post(agent, "/api/v1/zones/claims".into(), request)?;
        Ok(one(value, "claim")?)
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
        message(self.post(agent, "/api/v1/bus/messages".into(), request)?)
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
                (filter.limit > 0).then(|| filter.limit.to_string()),
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

    fn tasks(
        &self,
        _status: Option<tasks::Status>,
        _include_final: bool,
    ) -> Result<Vec<tasks::Task>> {
        no_tasks()
    }
    fn task(&self, _id: i64) -> Result<tasks::Task> {
        no_tasks()
    }
    fn task_history(&self, _id: i64) -> Result<Vec<tasks::TaskEvent>> {
        no_tasks()
    }
    fn add_task(
        &mut self,
        _author: &str,
        _title: &str,
        _body: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        no_tasks()
    }
    fn claim_task(&mut self, _agent: &str, _id: i64, _ttl: i64, _now: i64) -> Result<tasks::Task> {
        no_tasks()
    }
    fn renew_task(&mut self, _agent: &str, _id: i64, _ttl: i64, _now: i64) -> Result<tasks::Task> {
        no_tasks()
    }
    fn release_task(
        &mut self,
        _agent: &str,
        _id: i64,
        _note: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        no_tasks()
    }
    fn submit_task(
        &mut self,
        _agent: &str,
        _id: i64,
        _evidence: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        no_tasks()
    }
    fn accept_task(
        &mut self,
        _agent: &str,
        _id: i64,
        _note: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        no_tasks()
    }
    fn reject_task(
        &mut self,
        _agent: &str,
        _id: i64,
        _reason: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        no_tasks()
    }
    fn cancel_task(
        &mut self,
        _agent: &str,
        _id: i64,
        _note: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        no_tasks()
    }

    fn board_set(&mut self, agent: &str, write: &BoardWrite, _now: i64) -> Result<BoardEntry> {
        let value = self.post(agent, "/api/v1/bus/board".into(), write)?;
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
        self.post(agent, "/api/v1/presence".into(), beat)?;
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
                {"path": "d", "holder": "carol"}
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
            ],
        );
        assert_eq!(seen[0].body["needs"], "reply");
        assert_eq!(seen[5].body, json!({"ids": [12, 13], "lease_seconds": 60}));
        assert_eq!(seen[6].body, json!({"ids": [12]}));
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
            json!({"claims": []}),
            json!({"frozen": true}),
            json!({"ok": true}),
            json!({"ok": true}),
        ]);
        assert!(cloud.export().unwrap().get("claims").is_some());
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
        cloud.import_bus("me", &json!({"threads": []})).unwrap();
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
    }

    #[test]
    fn the_task_commands_say_they_are_local() {
        let (_server, mut cloud) = backend(vec![]);
        assert!(matches!(
            cloud.add_task("me", "t", "", 0),
            Err(Error::NeedsLocal(_))
        ));
        assert!(matches!(
            cloud.tasks(None, false),
            Err(Error::NeedsLocal(_))
        ));
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
