// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! The one storage boundary used by the command line, MCP tools and hooks.
//!
//! Local mode keeps zones, mail, tasks, the board and presence. Everything else exists on the server
//! only, and the default bodies below refuse it with [`Error::NeedsCloud`].

use crate::proto::{
    AccessAnswer, AccessRecord, AccessRequest, ActivityRequest, AgentSeen, BoardEntry, BoardWrite,
    CheckStatus, Claim, ClaimMode, ClaimQuery, ClaimRequest, DirtyPath, EventPage, EventQuery,
    Freeze, InboxPage, InboxQuery, LostClaim, Message, PathCheck, Presence, PresenceBeat, Purpose,
    QueueEntry, QueueRequest, ReleaseRequest, RenewRequest, SendRequest, Stamp, TokenRequest,
    Undelivered, WorkAction, WorkOffer, WorkStep, WorkTask,
};
use crate::{Error, Result, Store, ZonePath, bus, coordination, tasks, zones};
use serde_json::Value;

fn task_number(id: &str) -> Result<i64> {
    id.rsplit_once('-')
        .map(|(_, number)| number)
        .unwrap_or(id)
        .parse()
        .map_err(|_| Error::Invalid(format!("{id:?} is not a task id")))
}

fn cloud<T>(feature: &str) -> Result<T> {
    Err(Error::needs_cloud(feature))
}

/// Every operation of Lockyard, in either mode.
pub trait Backend {
    /// True when state lives on the server, so local clocks must not be compared with leases.
    fn is_cloud(&self) -> bool {
        false
    }

    fn touch_agent(&mut self, agent: &str, now: i64) -> Result<()>;
    fn agents(&self) -> Result<Vec<AgentSeen>>;

    fn claim(&mut self, agent: &str, request: &ClaimRequest, now: i64) -> Result<Claim>;
    fn renew(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &RenewRequest,
        now: i64,
    ) -> Result<usize>;
    fn release(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &ReleaseRequest,
        now: i64,
    ) -> Result<usize>;
    fn claims(&self, query: &ClaimQuery, now: i64) -> Result<Vec<Claim>>;
    fn check(
        &self,
        agent: &str,
        paths: &[String],
        fence: Option<i64>,
        now: i64,
    ) -> Result<Vec<PathCheck>>;

    fn queue_add(&mut self, _agent: &str, _request: &QueueRequest) -> Result<QueueEntry> {
        cloud("zone queue")
    }
    fn queue_list(&self, _agent: &str) -> Result<Vec<QueueEntry>> {
        cloud("zone queue")
    }
    fn queue_cancel(&mut self, _agent: &str, _id: i64) -> Result<()> {
        cloud("zone unwait")
    }
    fn zone_request(&mut self, _agent: &str, _request: &AccessRequest) -> Result<AccessRecord> {
        cloud("zone request")
    }
    fn zone_requests(&self, _agent: &str) -> Result<Vec<AccessRecord>> {
        cloud("zone requests")
    }
    fn zone_answer(
        &mut self,
        _agent: &str,
        _id: i64,
        _answer: &AccessAnswer,
    ) -> Result<AccessRecord> {
        cloud("zone answer")
    }
    fn handover(
        &mut self,
        _agent: &str,
        _id: i64,
        _to: &str,
        _fence: Option<i64>,
    ) -> Result<Value> {
        cloud("zone handover")
    }
    fn handover_accept(&mut self, _agent: &str, _id: i64) -> Result<Claim> {
        cloud("zone accept")
    }
    fn takeover(&mut self, _agent: &str, _id: i64, _reason: &str) -> Result<Claim> {
        cloud("zone takeover")
    }
    fn narrow(
        &mut self,
        _agent: &str,
        _id: i64,
        _paths: &[String],
        _fence: Option<i64>,
    ) -> Result<Claim> {
        cloud("zone narrow")
    }
    fn add_path(
        &mut self,
        _agent: &str,
        _id: i64,
        _path: &str,
        _fence: Option<i64>,
    ) -> Result<Claim> {
        cloud("zone add-path")
    }
    fn activity(&mut self, _agent: &str, _id: i64, _request: &ActivityRequest) -> Result<()> {
        cloud("zone activity")
    }
    fn dirty_report(&mut self, _agent: &str, _paths: &[DirtyPath]) -> Result<()> {
        cloud("zone dirty")
    }
    fn dirty_list(&self, _agent: &str, _path: Option<&str>) -> Result<Vec<DirtyPath>> {
        cloud("zone dirty")
    }
    fn dirty_disown(&mut self, _agent: &str, _paths: &[String]) -> Result<()> {
        cloud("zone dirty disown")
    }
    fn dirty_adopt(&mut self, _agent: &str, _paths: &[String], _reason: &str) -> Result<()> {
        cloud("zone dirty adopt")
    }
    fn lost(&self, _agent: &str) -> Result<Vec<LostClaim>> {
        cloud("zone lost")
    }
    fn catalog(&self) -> Result<Value> {
        cloud("zone catalog")
    }

    fn send(&mut self, agent: &str, request: &SendRequest, now: i64) -> Result<Message>;
    fn reply(&mut self, agent: &str, id: i64, body: &str, now: i64) -> Result<Message>;
    fn ack(&mut self, _agent: &str, _id: i64) -> Result<()> {
        cloud("msg ack")
    }
    /// Reads mail and marks nothing: the caller shows it first, then calls [`Backend::inbox_seen`].
    fn inbox(&mut self, agent: &str, query: InboxQuery, now: i64) -> Result<InboxPage>;
    fn unread(&self, agent: &str) -> Result<i64>;
    fn inbox_seen(&mut self, agent: &str, ids: &[i64], now: i64) -> Result<usize>;
    fn inbox_claim(
        &mut self,
        agent: &str,
        channel: &str,
        ids: &[i64],
        lease_seconds: i64,
        now: i64,
    ) -> Result<Vec<i64>>;
    fn thread(&self, _agent: &str, _id: i64) -> Result<Vec<Message>> {
        cloud("msg thread")
    }
    fn overdue(&self, _agent: &str) -> Result<Vec<Message>> {
        cloud("msg overdue")
    }
    fn undelivered(&self, _agent: &str, _older_than_seconds: i64) -> Result<Vec<Undelivered>> {
        cloud("msg undelivered")
    }
    /// This agent's own messages and how far each one got.
    fn sent(&self, _agent: &str, _limit: usize) -> Result<Vec<bus::Receipt>> {
        cloud("msg sent")
    }

    fn tasks(&self, status: Option<tasks::Status>, include_final: bool)
    -> Result<Vec<tasks::Task>>;
    fn ready_tasks(&self, _area: Option<&str>) -> Result<Vec<tasks::Task>> {
        self.tasks(Some(tasks::Status::Open), false)
    }
    fn block_task(
        &mut self,
        _agent: &str,
        _id: &str,
        _blocked: bool,
        _reason: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        cloud("registry block")
    }
    fn task(&self, id: &str) -> Result<tasks::Task>;
    fn task_history(&self, id: &str) -> Result<Vec<tasks::TaskEvent>>;
    fn add_task(&mut self, author: &str, spec: &tasks::TaskSpec, now: i64) -> Result<tasks::Task>;
    /// Changes the urgency of a task.
    fn plan_task(
        &mut self,
        _agent: &str,
        _id: &str,
        _plan: &tasks::TaskPlan,
    ) -> Result<tasks::Task> {
        cloud("task plan")
    }
    fn claim_task(&mut self, agent: &str, id: &str, ttl: i64, now: i64) -> Result<tasks::Task>;
    fn renew_task(&mut self, agent: &str, id: &str, ttl: i64, now: i64) -> Result<tasks::Task>;
    fn release_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task>;
    fn submit_task(
        &mut self,
        agent: &str,
        id: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task>;
    fn accept_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task>;
    fn review_task(
        &mut self,
        _agent: &str,
        _id: &str,
        _decision: &str,
        _reason: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        Err(Error::Invalid("this backend does not review tasks".into()))
    }
    fn reject_task(
        &mut self,
        agent: &str,
        id: &str,
        reason: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task>;
    fn cancel_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task>;
    fn batch_close_tasks(
        &mut self,
        agent: &str,
        ids: &[String],
        evidence: &str,
        now: i64,
    ) -> Result<Value> {
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let mut changed = true;
            let result = match self.task(id) {
                Ok(task)
                    if task.status == tasks::Status::Cancelled
                        || task.status == tasks::Status::Accepted =>
                {
                    changed = false;
                    Ok(task)
                }
                Ok(_) => self.cancel_task(agent, id, evidence, now),
                Err(error) => Err(error),
            };
            results.push(match result {
                Ok(task) => serde_json::json!({"id": id, "changed": changed, "item": task}),
                Err(error) => {
                    serde_json::json!({"id": id, "changed": false, "error": error.to_string()})
                }
            });
        }
        Ok(serde_json::json!({"results": results}))
    }

    fn board_set(&mut self, agent: &str, write: &BoardWrite, now: i64) -> Result<BoardEntry>;
    fn board_get(&self, key: &str, now: i64) -> Result<Option<BoardEntry>>;
    fn board_remove(&mut self, agent: &str, key: &str) -> Result<bool>;
    fn board_list(&self, zone: Option<&str>, now: i64) -> Result<Vec<BoardEntry>>;

    fn work_offer(&mut self, _agent: &str, _offer: &WorkOffer) -> Result<WorkTask> {
        cloud("work")
    }
    fn work_list(&self, _agent: &str) -> Result<Vec<WorkTask>> {
        cloud("work")
    }
    fn work_get(&self, _agent: &str, _id: i64) -> Result<WorkTask> {
        cloud("work")
    }
    fn work_step(
        &mut self,
        _agent: &str,
        _id: i64,
        _action: WorkAction,
        _step: &WorkStep,
    ) -> Result<WorkTask> {
        cloud("work")
    }

    fn heartbeat(&mut self, agent: &str, beat: &PresenceBeat, now: i64) -> Result<()>;
    fn presence(&self, active_within_seconds: i64, now: i64) -> Result<Vec<Presence>>;

    fn events(&self, _query: &EventQuery) -> Result<EventPage> {
        cloud("events")
    }
    fn export(&self) -> Result<Value> {
        cloud("export")
    }
    fn freeze(&mut self, _agent: &str, _freeze: &Freeze) -> Result<Value> {
        cloud("freeze")
    }
    /// Frees a session name bound to an old token, e.g. after the token was reissued (D-3124).
    fn release_session(&mut self, _agent: &str, _session: &str) -> Result<Value> {
        cloud("session release")
    }
    fn import_zones(&mut self, _agent: &str, _catalog: &Value) -> Result<Value> {
        cloud("import")
    }
    fn import_bus(&mut self, _agent: &str, _dump: &Value) -> Result<Value> {
        cloud("import")
    }
    fn registry_import(&mut self, _agent: &str, _dump: &Value) -> Result<Value> {
        cloud("registry import")
    }
    fn area_list(&self, _agent: &str) -> Result<Value> {
        cloud("registry areas")
    }
    fn area_create(&mut self, _agent: &str, _request: &Value) -> Result<Value> {
        cloud("registry areas")
    }
    fn area_update(&mut self, _agent: &str, _key: &str, _request: &Value) -> Result<Value> {
        cloud("registry areas")
    }
    fn tokens(&self) -> Result<Value> {
        cloud("cloud token")
    }
    fn token_create(&mut self, _agent: &str, _request: &TokenRequest) -> Result<Value> {
        cloud("cloud token")
    }
    fn token_revoke(&mut self, _agent: &str, _id: &str) -> Result<Value> {
        cloud("cloud token")
    }
}

/// Reuses an agent's existing claim when it already covers every requested path.
/// This makes equivalent case and Unicode spellings idempotent across backends.
pub fn claim_or_reuse(
    backend: &mut dyn Backend,
    agent: &str,
    request: &ClaimRequest,
    now: i64,
) -> Result<Claim> {
    if !request.paths.is_empty() {
        let existing = backend.claims(
            &ClaimQuery {
                session: Some(agent.to_string()),
                path: None,
            },
            now,
        )?;
        if let Some(claim) = existing.into_iter().find(|claim| {
            claim.mode == request.mode
                && request.paths.iter().all(|requested| {
                    let requested = crate::paths::ZonePath::stored(requested.clone());
                    claim.paths.iter().any(|held| {
                        crate::paths::ZonePath::stored(held.clone()).contains(&requested)
                    })
                })
        }) {
            return Ok(claim);
        }
    }
    backend.claim(agent, request, now)
}

fn claim_record(claim: zones::Claim) -> Claim {
    Claim {
        id: claim.id,
        session: claim.agent,
        actor: None,
        note: claim.note,
        zone: None,
        paths: claim.paths,
        excluded_paths: Vec::new(),
        mode: ClaimMode::Exclusive,
        purpose: Purpose::Work,
        lazy: false,
        fence: 0,
        created_at: Stamp::Millis(claim.created_at),
        expires_at: Stamp::Millis(claim.expires_at),
        hold_until: None,
        hold_reason: None,
        hold_until_ref: None,
        return_to: None,
        last_activity_at: None,
        last_write_at: None,
        meta: None,
        version: None,
        holder_available: None,
        foreign_dirty_paths: Vec::new(),
    }
}

fn message_record(message: bus::Message) -> Message {
    Message {
        id: message.id,
        thread_id: None,
        reply_to: message.reply_to,
        kind: None,
        from: message.from,
        from_client: None,
        to: message.to,
        zone: None,
        re: None,
        status: None,
        needs: None,
        body: message.body,
        key: None,
        expires_at: None,
        created_at: Stamp::Millis(message.created_at),
        deduplicated: false,
        queued: false,
    }
}

fn board_record(entry: coordination::BoardEntry) -> BoardEntry {
    BoardEntry {
        key: entry.key,
        value: Value::String(entry.value),
        zone: entry.zone,
        expires_at: entry.expires_at.map(Stamp::Millis),
        updated_at: Stamp::Millis(entry.updated_at),
    }
}

fn stored_paths(paths: &[String]) -> Vec<ZonePath> {
    paths
        .iter()
        .map(|path| ZonePath::stored(path.clone()))
        .collect()
}

impl Backend for Store {
    fn touch_agent(&mut self, agent: &str, now: i64) -> Result<()> {
        self.touch(agent, now)
    }

    fn agents(&self) -> Result<Vec<AgentSeen>> {
        Ok(Store::agents(self)?
            .into_iter()
            .map(|agent| AgentSeen {
                id: agent.id,
                first_seen: Stamp::Millis(agent.first_seen),
                last_seen: Stamp::Millis(agent.last_seen),
            })
            .collect())
    }

    fn claim(&mut self, agent: &str, request: &ClaimRequest, now: i64) -> Result<Claim> {
        let refused = [
            (request.lazy, "a lazy claim"),
            (request.mode != ClaimMode::Exclusive, "a shared claim"),
            (request.purpose != Purpose::Work, "a deploy claim"),
            (request.queue_wait_seconds.is_some(), "zone wait"),
            (request.meta.is_some(), "claim meta"),
            (
                request.zone.is_some() || !request.zones.is_empty(),
                "a zone label",
            ),
        ];
        if let Some((_, feature)) = refused.iter().find(|(refused, _)| *refused) {
            return cloud(feature);
        }
        let paths = stored_paths(&request.paths);
        Ok(claim_record(Store::claim(
            self,
            agent,
            &paths,
            &request.note,
            request.ttl_minutes,
            now,
        )?))
    }

    fn renew(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &RenewRequest,
        now: i64,
    ) -> Result<usize> {
        if request.hold_reason.is_some() || request.hold_until.is_some() {
            return cloud("a held claim");
        }
        if request.fence.is_some() {
            return cloud("a fence");
        }
        Store::renew(self, agent, id, request.ttl_minutes, now)
    }

    fn release(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &ReleaseRequest,
        now: i64,
    ) -> Result<usize> {
        if request.leave_dirty {
            return cloud("leave_dirty");
        }
        if request.fence.is_some() {
            return cloud("a fence");
        }
        Store::release(self, agent, id, now)
    }

    fn claims(&self, query: &ClaimQuery, now: i64) -> Result<Vec<Claim>> {
        let wanted = query
            .path
            .as_ref()
            .map(|path| ZonePath::stored(path.clone()));
        Ok(Store::claims(self, now)?
            .into_iter()
            .filter(|claim| {
                query
                    .session
                    .as_ref()
                    .is_none_or(|session| *session == claim.agent)
            })
            .filter(|claim| {
                wanted.as_ref().is_none_or(|wanted| {
                    claim
                        .paths
                        .iter()
                        .any(|held| wanted.overlaps(&ZonePath::stored(held.clone())))
                })
            })
            .map(claim_record)
            .collect())
    }

    fn check(
        &self,
        agent: &str,
        paths: &[String],
        fence: Option<i64>,
        now: i64,
    ) -> Result<Vec<PathCheck>> {
        if fence.is_some() {
            return cloud("a fence");
        }
        stored_paths(paths)
            .iter()
            .map(|path| {
                let holder = Store::check(self, agent, path, now)?;
                Ok(PathCheck {
                    path: path.as_str().to_string(),
                    status: if holder.is_some() {
                        CheckStatus::Held
                    } else {
                        CheckStatus::Free
                    },
                    holder,
                })
            })
            .collect()
    }

    fn send(&mut self, agent: &str, request: &SendRequest, now: i64) -> Result<Message> {
        let extras = request.kind.is_some()
            || request.needs.is_some()
            || request.zone.is_some()
            || request.re.is_some()
            || request.key.is_some()
            || request.ttl_minutes.is_some();
        if extras {
            return cloud("message kind, needs, zone, re, key and ttl");
        }
        Ok(message_record(Store::send(
            self,
            agent,
            &request.to,
            &request.body,
            now,
        )?))
    }

    fn reply(&mut self, agent: &str, id: i64, body: &str, now: i64) -> Result<Message> {
        Ok(message_record(Store::reply(self, agent, id, body, now)?))
    }

    fn inbox(&mut self, agent: &str, query: InboxQuery, now: i64) -> Result<InboxPage> {
        let messages = Store::inbox(self, agent, query.all, false, query.limit, now)?;
        Ok(InboxPage {
            messages: messages.into_iter().map(message_record).collect(),
            skipped: 0,
        })
    }

    fn unread(&self, agent: &str) -> Result<i64> {
        Store::unread(self, agent)
    }

    fn inbox_seen(&mut self, agent: &str, ids: &[i64], now: i64) -> Result<usize> {
        Store::inbox_seen(self, agent, ids, now)
    }

    fn inbox_claim(
        &mut self,
        agent: &str,
        channel: &str,
        ids: &[i64],
        lease_seconds: i64,
        now: i64,
    ) -> Result<Vec<i64>> {
        Store::inbox_claim(self, agent, channel, ids, lease_seconds, now)
    }

    fn sent(&self, agent: &str, limit: usize) -> Result<Vec<bus::Receipt>> {
        Store::sent(self, agent, limit)
    }

    fn tasks(
        &self,
        status: Option<tasks::Status>,
        include_final: bool,
    ) -> Result<Vec<tasks::Task>> {
        Store::tasks(self, status, include_final)
    }

    fn task(&self, id: &str) -> Result<tasks::Task> {
        Store::task(self, task_number(id)?)
    }

    fn task_history(&self, id: &str) -> Result<Vec<tasks::TaskEvent>> {
        Store::task_history(self, task_number(id)?)
    }

    fn add_task(&mut self, author: &str, spec: &tasks::TaskSpec, now: i64) -> Result<tasks::Task> {
        if spec.uses_registry_fields() {
            return cloud("task priority, type, target, area and evidence");
        }
        Store::add_task(self, author, &spec.title, &spec.body, now)
    }

    fn claim_task(&mut self, agent: &str, id: &str, ttl: i64, now: i64) -> Result<tasks::Task> {
        Store::claim_task(self, agent, task_number(id)?, ttl, now)
    }

    fn renew_task(&mut self, agent: &str, id: &str, ttl: i64, now: i64) -> Result<tasks::Task> {
        Store::renew_task(self, agent, task_number(id)?, ttl, now)
    }

    fn release_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task> {
        Store::release_task(self, agent, task_number(id)?, note, now)
    }

    fn submit_task(
        &mut self,
        agent: &str,
        id: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        Store::submit_task(self, agent, task_number(id)?, evidence, now)
    }

    fn accept_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task> {
        Store::accept_task(self, agent, task_number(id)?, note, now)
    }

    fn review_task(
        &mut self,
        agent: &str,
        id: &str,
        decision: &str,
        reason: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        Store::review_task(self, agent, task_number(id)?, decision, reason, now)
    }

    fn reject_task(
        &mut self,
        agent: &str,
        id: &str,
        reason: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        Store::reject_task(self, agent, task_number(id)?, reason, evidence, now)
    }

    fn cancel_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task> {
        Store::cancel_task(self, agent, task_number(id)?, note, now)
    }

    fn board_set(&mut self, _agent: &str, write: &BoardWrite, now: i64) -> Result<BoardEntry> {
        let zone = write.zone.as_deref();
        Ok(board_record(Store::board_set(
            self,
            &write.key,
            &write.value,
            zone,
            write.ttl_minutes,
            now,
        )?))
    }

    fn board_get(&self, key: &str, now: i64) -> Result<Option<BoardEntry>> {
        Ok(Store::board_get(self, key, now)?.map(board_record))
    }

    fn board_remove(&mut self, _agent: &str, key: &str) -> Result<bool> {
        Store::board_remove(self, key)
    }

    fn board_list(&self, zone: Option<&str>, now: i64) -> Result<Vec<BoardEntry>> {
        Ok(Store::board_list(self, zone, now)?
            .into_iter()
            .map(board_record)
            .collect())
    }

    fn heartbeat(&mut self, agent: &str, beat: &PresenceBeat, now: i64) -> Result<()> {
        if beat.activity.is_some() {
            return cloud("session activity");
        }
        if beat.model.is_some() {
            return cloud("the model field");
        }
        let dnd_until = match &beat.dnd_until {
            None => None,
            Some(Stamp::Millis(value)) => Some(*value),
            Some(Stamp::Text(text)) => {
                return Err(Error::Invalid(format!(
                    "dnd_until must be milliseconds in local mode, got {text:?}"
                )));
            }
        };
        let update = coordination::PresenceUpdate {
            role: beat.role.as_deref(),
            version: beat.version.as_deref(),
            cwd: beat.cwd.as_deref(),
            dnd_until,
        };
        Store::heartbeat(self, agent, &beat.client, update, now)
    }

    fn presence(&self, active_within_seconds: i64, now: i64) -> Result<Vec<Presence>> {
        Ok(Store::presence(self, active_within_seconds, now)?
            .into_iter()
            .map(|entry| Presence {
                session: entry.agent,
                client: entry.client,
                alias: None,
                role: entry.role,
                version: entry.version,
                cwd: entry.cwd,
                last_seen: Stamp::Millis(entry.last_seen),
                dnd_until: entry.dnd_until.map(Stamp::Millis),
                activity: None,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;
    use serde_json::json;

    fn request(paths: &[&str]) -> ClaimRequest {
        ClaimRequest {
            paths: paths.iter().map(|path| path.to_string()).collect(),
            ttl_minutes: 10,
            ..ClaimRequest::default()
        }
    }

    #[test]
    fn every_cloud_only_feature_is_refused_with_a_clear_error_in_local_mode() {
        let (_dir, mut store) = test_store();
        let backend: &mut dyn Backend = &mut store;
        assert!(!backend.is_cloud());
        let refusals = [
            backend.queue_add("a", &QueueRequest::default()).map(|_| ()),
            backend.queue_list("a").map(|_| ()),
            backend.queue_cancel("a", 1),
            backend
                .zone_request("a", &AccessRequest::default())
                .map(|_| ()),
            backend
                .zone_answer("a", 1, &AccessAnswer::default())
                .map(|_| ()),
            backend.handover("a", 1, "b", None).map(|_| ()),
            backend.handover_accept("a", 1).map(|_| ()),
            backend.takeover("a", 1, "gone").map(|_| ()),
            backend.narrow("a", 1, &[], None).map(|_| ()),
            backend.add_path("a", 1, "x", None).map(|_| ()),
            backend.activity("a", 1, &ActivityRequest::default()),
            backend.dirty_report("a", &[]),
            backend.dirty_list("a", None).map(|_| ()),
            backend.dirty_disown("a", &[]),
            backend.dirty_adopt("a", &[], "r"),
            backend.lost("a").map(|_| ()),
            backend.catalog().map(|_| ()),
            backend.ack("a", 1),
            backend.thread("a", 1).map(|_| ()),
            backend.overdue("a").map(|_| ()),
            backend.undelivered("a", 0).map(|_| ()),
            backend.work_offer("a", &WorkOffer::default()).map(|_| ()),
            backend.work_list("a").map(|_| ()),
            backend.work_get("a", 1).map(|_| ()),
            backend
                .work_step("a", 1, WorkAction::Beat, &WorkStep::default())
                .map(|_| ()),
            backend.events(&EventQuery::default()).map(|_| ()),
            backend.export().map(|_| ()),
            backend.freeze("a", &Freeze::default()).map(|_| ()),
            backend.import_zones("a", &json!({})).map(|_| ()),
            backend.import_bus("a", &json!({})).map(|_| ()),
            backend.tokens().map(|_| ()),
            backend
                .token_create("a", &TokenRequest::default())
                .map(|_| ()),
            backend.token_revoke("a", "x").map(|_| ()),
            backend
                .plan_task("a", "D-1", &tasks::TaskPlan::default())
                .map(|_| ()),
            backend
                .add_task(
                    "a",
                    &tasks::TaskSpec {
                        title: "t".into(),
                        priority: Some("P1".into()),
                        ..tasks::TaskSpec::default()
                    },
                    0,
                )
                .map(|_| ()),
        ];
        for refusal in refusals {
            let error = refusal.unwrap_err();
            assert!(error.to_string().contains("needs cloud mode"), "{error}");
        }
    }

    #[test]
    fn cloud_options_on_local_operations_are_refused_not_ignored() {
        let (_dir, mut store) = test_store();
        let backend: &mut dyn Backend = &mut store;
        let shared = ClaimRequest {
            mode: ClaimMode::Shared,
            ..request(&["src"])
        };
        assert!(matches!(
            backend.claim("a", &shared, 0),
            Err(Error::NeedsCloud(_))
        ));
        let lazy = ClaimRequest {
            lazy: true,
            ..request(&[])
        };
        assert!(matches!(
            backend.claim("a", &lazy, 0),
            Err(Error::NeedsCloud(_))
        ));
        let beat = PresenceBeat {
            client: "cli".into(),
            activity: Some(Default::default()),
            ..PresenceBeat::default()
        };
        assert!(matches!(
            backend.heartbeat("a", &beat, 0),
            Err(Error::NeedsCloud(_))
        ));
        let needs = SendRequest {
            to: "*".into(),
            body: "x".into(),
            needs: Some("ack".into()),
            ..SendRequest::default()
        };
        assert!(matches!(
            backend.send("a", &needs, 0),
            Err(Error::NeedsCloud(_))
        ));
        assert!(
            backend
                .claims(&ClaimQuery::default(), 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_local_backend_answers_through_the_shared_records() {
        let (_dir, mut store) = test_store();
        let backend: &mut dyn Backend = &mut store;
        let claim = backend.claim("a", &request(&["src"]), 0).unwrap();
        assert_eq!(
            (claim.session.as_str(), claim.mode),
            ("a", ClaimMode::Exclusive)
        );
        let check = backend.check("b", &["src/x".to_string()], None, 1).unwrap();
        assert_eq!(check[0].status, CheckStatus::Held);
        assert_eq!(check[0].holder.as_ref().unwrap().agent, "a");
        let filter = ClaimQuery {
            session: Some("b".into()),
            path: None,
        };
        assert!(backend.claims(&filter, 1).unwrap().is_empty());
        let by_path = ClaimQuery {
            session: None,
            path: Some("src/deep".into()),
        };
        assert_eq!(backend.claims(&by_path, 1).unwrap().len(), 1);
        backend.touch_agent("b", 0).unwrap();
        let send = SendRequest {
            to: "b".into(),
            body: "hi".into(),
            ..SendRequest::default()
        };
        let id = backend.send("a", &send, 1).unwrap().id;
        let page = backend
            .inbox(
                "b",
                InboxQuery {
                    all: false,
                    limit: 5,
                },
                2,
            )
            .unwrap();
        assert_eq!(page.messages[0].id, id);
        assert_eq!(backend.unread("b").unwrap(), 1, "reading must not mark");
        assert_eq!(backend.inbox_seen("b", &[id], 3).unwrap(), 1);
        assert_eq!(backend.unread("b").unwrap(), 0);
    }
}
