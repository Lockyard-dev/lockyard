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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// The independent reads needed by status, including their provenance. Claims and assigned tasks
/// are mandatory: a failed read must never look like an empty set to an action or Stop hook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusRead {
    pub claims: Vec<Claim>,
    pub unread: Option<i64>,
    pub work: Vec<WorkTask>,
    pub tasks: Vec<tasks::Task>,
    pub freshness: Value,
}

fn cloud<T>(feature: &str) -> Result<T> {
    Err(Error::needs_cloud(feature))
}

/// Every operation of Lockyard, in either mode.
pub trait Backend {
    /// Read status within one caller-owned budget. Cloud implementations share the deadline across
    /// concurrent reads and all pages; local mode needs no remote deadline.
    fn status_read(&self, session: &str, now: i64, _budget: Duration) -> Result<StatusRead> {
        let claims = self.claims(
            &ClaimQuery {
                session: Some(session.into()),
                path: None,
            },
            now,
        )?;
        Ok(StatusRead {
            claims,
            unread: Some(self.unread(session)?),
            work: if self.is_cloud() {
                self.work_list(session)?
            } else {
                Vec::new()
            },
            tasks: self.assigned_tasks(session)?,
            freshness: serde_json::json!({"source": "local", "age_ms": 0}),
        })
    }

    /// Override the key for a workflow's single write step. Always clear after the step.
    /// Local writes do not have a remote idempotency ledger; uncertain outcomes must be reconciled.
    fn set_write_idempotency_key(&mut self, _key: Option<String>) {}

    /// True when state lives on the server, so local clocks must not be compared with leases.
    fn is_cloud(&self) -> bool {
        false
    }

    fn touch_agent(&mut self, agent: &str, now: i64) -> Result<()>;
    fn agents(&self) -> Result<Vec<AgentSeen>>;

    fn claim(&mut self, agent: &str, request: &ClaimRequest, now: i64) -> Result<Claim>;
    /// Creation is an outcome of this write, never a property of a stored claim.
    /// Legacy cloud backends cannot distinguish creation from server-side reuse.
    fn claim_with_creation_status(
        &mut self,
        agent: &str,
        request: &ClaimRequest,
        now: i64,
    ) -> Result<(Claim, Option<bool>)> {
        let created = (!self.is_cloud()).then_some(true);
        self.claim(agent, request, now)
            .map(|claim| (claim, created))
    }
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

    fn catalog_expand(&self, names: &[String]) -> Result<Vec<String>> {
        crate::proto::expand_zones(&self.catalog()?, names)
    }
    fn catalog_put(
        &mut self,
        _agent: &str,
        _catalog: &Value,
        _expected_revision: u64,
        _key: &str,
    ) -> Result<Value> {
        cloud("zone catalog publish")
    }
    fn cloud_protocol(&self) -> Result<Value> {
        cloud("protocol discovery")
    }
    fn cloud_drain(&mut self, _agent: &str, _request: &Value, _key: &str) -> Result<Value> {
        cloud("drain")
    }
    fn cloud_drain_status(&self, _id: &str) -> Result<Value> {
        cloud("drain status")
    }

    fn send(&mut self, agent: &str, request: &SendRequest, now: i64) -> Result<Message>;
    fn reply(&mut self, agent: &str, id: i64, body: &str, now: i64) -> Result<Message>;
    fn ack(&mut self, _agent: &str, _id: i64) -> Result<()> {
        cloud("msg ack")
    }
    /// Reads mail and marks nothing: the caller shows it first, then calls [`Backend::inbox_seen`].
    fn inbox(&mut self, agent: &str, query: InboxQuery, now: i64) -> Result<InboxPage>;
    /// Observe mail without registering an agent, updating presence or marking receipts.
    fn peek_inbox(&self, _agent: &str, _query: InboxQuery, _now: i64) -> Result<InboxPage> {
        cloud("read-only inbox")
    }
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
    /// Unfinished tasks assigned to this session. Cloud backends should filter on the server
    /// before paging; the local default preserves the existing task selection and order.
    fn assigned_tasks(&self, session: &str) -> Result<Vec<tasks::Task>> {
        Ok(self
            .tasks(None, false)?
            .into_iter()
            .filter(|task| task.assignee.as_deref() == Some(session))
            .collect())
    }
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
    /// The full cloud registry protocol, without collapsing registry states into local task states.
    fn registry_search(&self, _query: &Value) -> Result<Value> {
        cloud("task search")
    }
    fn registry_ready(&self, _query: &Value) -> Result<Value> {
        cloud("task ready")
    }

    /// Read a registry item without discarding its area prefix or number padding.
    fn registry_item_by_id(&self, _id: &str) -> Result<Value> {
        cloud("task registry")
    }
    fn registry_blockers_by_id(&self, _id: &str) -> Result<Value> {
        cloud("task why-blocked")
    }

    #[allow(clippy::too_many_arguments)]
    fn registry_link_by_id(
        &mut self,
        _agent: &str,
        _id: &str,
        _to: &str,
        _kind: &str,
        _version: i64,
        _key: &str,
    ) -> Result<Value> {
        cloud("task link")
    }
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
    /// A workflow claim result, preserving ownership evidence from the mutation response itself.
    /// Cloud implementations must retain the assignment identity; a later read cannot establish
    /// which assignment this write created. Local tasks use their current-owner policy on resume.
    ///
    /// Preserve the full task identity in a workflow claim receipt.
    fn claim_task_receipt_by_id(
        &mut self,
        agent: &str,
        id: &str,
        ttl: i64,
        now: i64,
    ) -> Result<Value> {
        serde_json::to_value(self.claim_task(agent, id, ttl, now)?)
            .map_err(|error| Error::Protocol(error.to_string()))
    }
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
    fn work_get(&self, _agent: &str, _id: &str) -> Result<WorkTask> {
        cloud("work")
    }
    fn work_step(
        &mut self,
        _agent: &str,
        _id: &str,
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
/// Equivalent spellings use the claim's server-selected repository path policy.
pub fn claim_or_reuse(
    backend: &mut dyn Backend,
    agent: &str,
    request: &ClaimRequest,
    now: i64,
) -> Result<Claim> {
    claim_or_reuse_with_status(backend, agent, request, now).map(|(claim, _)| claim)
}

/// Returns the claim and whether a claim request was submitted to the backend.
/// A submitted cloud request may itself reuse a claim, so this flag does not prove creation.
pub fn claim_or_reuse_with_status(
    backend: &mut dyn Backend,
    agent: &str,
    request: &ClaimRequest,
    now: i64,
) -> Result<(Claim, bool)> {
    acquire_claim(backend, agent, request, now).map(|(claim, submitted, _)| (claim, submitted))
}

/// Returns an operation-scoped creation receipt. `None` must never authorize rollback.
pub fn claim_or_reuse_with_creation_status(
    backend: &mut dyn Backend,
    agent: &str,
    request: &ClaimRequest,
    now: i64,
) -> Result<(Claim, Option<bool>)> {
    acquire_claim(backend, agent, request, now).map(|(claim, _, created)| (claim, created))
}

/// Acquires a claim, then installs a hold through the legacy-compatible renew endpoint.
/// Only an operation-scoped creation receipt authorizes compensating release.
pub fn claim_or_reuse_with_hold(
    backend: &mut dyn Backend,
    agent: &str,
    request: &ClaimRequest,
    hold_reason: Option<String>,
    hold_until: Option<String>,
    now: i64,
) -> Result<(Claim, Option<bool>)> {
    validate_hold(hold_reason.as_deref(), hold_until.as_deref())?;
    let (claim, created) = claim_or_reuse_with_creation_status(backend, agent, request, now)?;
    if !backend.is_cloud() {
        // Local claims are never released for inactivity, so they need no hold.
        return Ok((claim, created));
    }
    let Some(reason) = hold_reason else {
        return Ok((claim, created));
    };
    let until = hold_until.unwrap_or_else(|| match claim.expires_at.on_the_wire() {
        Stamp::Text(text) => text,
        Stamp::Millis(_) => unreachable!("on_the_wire returns text"),
    });
    let fence = backend.is_cloud().then_some(claim.fence);
    let expected_reason = reason.clone();
    let expected_until = crate::proto::parse_rfc3339(&until);
    let result = (|| {
        let renewed = backend.renew(
            agent,
            Some(claim.id),
            &RenewRequest {
                ttl_minutes: request.ttl_minutes,
                hold_reason: Some(reason),
                hold_until: Some(until),
                fence,
            },
            now,
        )?;
        if renewed != 1 {
            return Err(Error::Protocol(
                "hold renewal did not renew the claim".into(),
            ));
        }
        backend
            .claims(
                &ClaimQuery {
                    session: Some(agent.to_string()),
                    path: None,
                },
                now,
            )?
            .into_iter()
            .find(|current| current.id == claim.id && current.session == agent)
            .ok_or_else(|| Error::Protocol("held claim is missing after renewal".into()))
            .and_then(|held| {
                let until = held.hold_until.as_ref().and_then(|stamp| match stamp {
                    Stamp::Millis(value) => Some(*value),
                    Stamp::Text(text) => crate::proto::parse_rfc3339(text),
                });
                if held.hold_reason.as_deref() != Some(expected_reason.as_str())
                    || until != expected_until
                    || until.is_none()
                {
                    return Err(Error::Protocol(
                        "claim renewal did not install the requested hold".into(),
                    ));
                }
                Ok(held)
            })
    })();
    match result {
        Ok(held) => Ok((held, created)),
        Err(error) => {
            if created == Some(true) && (!backend.is_cloud() || (claim.id > 0 && claim.fence > 0)) {
                let _ = backend.release(
                    agent,
                    Some(claim.id),
                    &ReleaseRequest {
                        fence,
                        ..ReleaseRequest::default()
                    },
                    now,
                );
            }
            Err(error)
        }
    }
}

/// Checks the hold's shape only. The server owns its 240-minute limit.
pub fn validate_hold(reason: Option<&str>, until: Option<&str>) -> Result<()> {
    if until.is_some() && reason.is_none() {
        return Err(Error::Invalid("hold_until requires hold_reason".into()));
    }
    if reason.is_some_and(|reason| reason.trim().is_empty()) {
        return Err(Error::Invalid("hold_reason must not be empty".into()));
    }
    if until.is_some_and(|until| !valid_hold_timestamp(until)) {
        return Err(Error::Invalid("hold_until must be RFC 3339 text".into()));
    }
    Ok(())
}

// The protocol's permissive timestamp reader also reads historical server spellings.
// New hold input must satisfy the RFC 3339 calendar, separators and complete timezone.
fn valid_hold_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || !bytes.is_ascii()
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    let digits = |from: usize, to: usize| {
        let found = text.get(from..to)?;
        found
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| found.parse::<u32>().ok())
            .flatten()
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0, 4),
        digits(5, 7),
        digits(8, 10),
        digits(11, 13),
        digits(14, 16),
        digits(17, 19),
    ) else {
        return false;
    };
    let leap_year = year % 400 == 0 || (year % 4 == 0 && year % 100 != 0);
    let last_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > last_day || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let mut zone_at = 19;
    if bytes[zone_at] == b'.' {
        zone_at += 1;
        let fraction_at = zone_at;
        while bytes.get(zone_at).is_some_and(u8::is_ascii_digit) {
            zone_at += 1;
        }
        if zone_at == fraction_at {
            return false;
        }
    }
    match bytes.get(zone_at).copied() {
        Some(b'Z' | b'z') => bytes.len() == zone_at + 1,
        Some(b'+' | b'-') => {
            bytes.len() == zone_at + 6
                && bytes[zone_at + 3] == b':'
                && digits(zone_at + 1, zone_at + 3).is_some_and(|hour| hour <= 23)
                && digits(zone_at + 4, zone_at + 6).is_some_and(|minute| minute <= 59)
        }
        _ => false,
    }
}

fn acquire_claim(
    backend: &mut dyn Backend,
    agent: &str,
    request: &ClaimRequest,
    now: i64,
) -> Result<(Claim, bool, Option<bool>)> {
    if !request.paths.is_empty() {
        let existing = backend.claims(
            &ClaimQuery {
                session: Some(agent.to_string()),
                path: None,
            },
            now,
        )?;
        if let Some(claim) = existing
            .into_iter()
            .find(|claim| claim_covers_request(claim, agent, request))
        {
            return Ok((claim, false, Some(false)));
        }
    }
    let (claim, created) = backend.claim_with_creation_status(agent, request, now)?;
    if !claim_covers_request(&claim, agent, request) {
        return Err(Error::Protocol(
            "claim response did not grant the requested paths to this session".into(),
        ));
    }
    Ok((claim, true, created))
}

fn claim_covers_request(claim: &Claim, agent: &str, request: &ClaimRequest) -> bool {
    let fold_case = claim.case_insensitive_paths.unwrap_or(true);
    claim.session == agent
        && claim.mode == request.mode
        && request.paths.iter().all(|requested| {
            let requested = crate::paths::ZonePath::stored(requested.clone());
            claim.paths.iter().any(|held| {
                crate::paths::ZonePath::stored(held.clone())
                    .contains_with_case(&requested, fold_case)
            }) && !claim.excluded_paths.iter().any(|excluded| {
                crate::paths::ZonePath::stored(excluded.clone())
                    .overlaps_with_case(&requested, fold_case)
            })
        })
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
        idle_release_at: None,
        hold_reason: None,
        hold_until_ref: None,
        return_to: None,
        last_activity_at: None,
        last_write_at: None,
        meta: None,
        version: None,
        holder_available: None,
        case_insensitive_paths: None,
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
        // Legacy local records do not store author or creation metadata.
        session: String::new(),
        created_at: Stamp::default(),
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

    fn peek_inbox(&self, agent: &str, query: InboxQuery, _now: i64) -> Result<InboxPage> {
        Ok(InboxPage {
            messages: Store::peek_inbox(self, agent, query.all, query.limit)?
                .into_iter()
                .map(message_record)
                .collect(),
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
        Store::task(self, id)
    }

    fn task_history(&self, id: &str) -> Result<Vec<tasks::TaskEvent>> {
        Store::task_history(self, id)
    }

    fn add_task(&mut self, author: &str, spec: &tasks::TaskSpec, now: i64) -> Result<tasks::Task> {
        if spec.uses_registry_fields() {
            return cloud("task priority, type, target, area and evidence");
        }
        Store::add_task(self, author, &spec.title, &spec.body, now)
    }

    fn claim_task(&mut self, agent: &str, id: &str, ttl: i64, now: i64) -> Result<tasks::Task> {
        Store::claim_task(self, agent, id, ttl, now)
    }

    fn renew_task(&mut self, agent: &str, id: &str, ttl: i64, now: i64) -> Result<tasks::Task> {
        Store::renew_task(self, agent, id, ttl, now)
    }

    fn release_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task> {
        Store::release_task(self, agent, id, note, now)
    }

    fn submit_task(
        &mut self,
        agent: &str,
        id: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        Store::submit_task(self, agent, id, evidence, now)
    }

    fn accept_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task> {
        Store::accept_task(self, agent, id, note, now)
    }

    fn review_task(
        &mut self,
        agent: &str,
        id: &str,
        decision: &str,
        reason: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        Store::review_task(self, agent, id, decision, reason, now)
    }

    fn reject_task(
        &mut self,
        agent: &str,
        id: &str,
        reason: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        Store::reject_task(self, agent, id, reason, evidence, now)
    }

    fn cancel_task(&mut self, agent: &str, id: &str, note: &str, now: i64) -> Result<tasks::Task> {
        Store::cancel_task(self, agent, id, note, now)
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
mod w4_contract_tests {
    use super::*;

    #[test]
    fn local_task_lookup_never_discards_area_prefix() {
        let (_dir, mut store) = crate::store::test_store();
        let task = store.add_task("lead", "local", "", 0).unwrap();
        assert!(Backend::task(&store, &task.id).is_ok());
        for foreign in ["FE-1", "D-01", "FE-0001"] {
            assert!(
                matches!(Backend::task(&store, foreign), Err(Error::NotFound(_))),
                "{foreign} must not resolve to {}",
                task.id
            );
            assert!(Backend::claim_task(&mut store, "worker", foreign, 10, 1).is_err());
        }
        assert_eq!(
            Backend::task(&store, &task.id).unwrap().status,
            tasks::Status::Open
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;
    use serde_json::json;

    #[test]
    fn malformed_hold_timestamps_are_rejected_before_acquiring_a_claim() {
        let (_dir, mut store) = test_store();
        for until in [
            "2026-99-99T99:99:99Z",
            "2026-00-11T21:00:00Z",
            "2026-11-00T21:00:00Z",
            "2026-11-31T21:00:00Z",
            "2026-02-29T21:00:00Z",
            "1900-02-29T21:00:00Z",
            "2026-11-11X21:00:00Z",
            "2026-11-11T21:00x00Z",
            "2026-11-11T24:00:00Z",
            "2026-11-11T21:60:00Z",
            "2026-11-11T21:00:60Z",
            "2026-11-11T21:00:61Z",
            "2026-11-11T21:00:00",
            "2026-11-11T21:00:00.Z",
            "2026-11-11T21:00:00.123abcZ",
            "2026-11-11T21:00:00Ztrailing",
            "2026-11-11T21:00:00+24:00",
            "2026-11-11T21:00:00+00:60",
            "2026-11-11T21:00:00+00x00",
            "2026-11-11T21:00:00+0000",
            "2026-11-11T21:00:00+00:00extra",
        ] {
            let error = claim_or_reuse_with_hold(
                &mut store,
                "worker",
                &request(&["src"]),
                Some("review".into()),
                Some(until.into()),
                1,
            )
            .unwrap_err();
            assert!(
                matches!(&error, Error::Invalid(_)),
                "accepted {until}: {error}"
            );
            assert!(error.to_string().contains("RFC 3339"));
        }
        assert!(
            Backend::claims(&store, &ClaimQuery::default(), 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn hold_timestamps_accept_valid_offsets_fractions_and_leap_days() {
        for until in [
            "2026-11-11T21:00:00Z",
            "2026-11-11t21:00:00z",
            "2026-11-11T21:00:00+05:00",
            "2026-11-11T21:00:00-02:30",
            "2026-11-11T21:00:00.1Z",
            "2026-11-11T21:00:00.1234567+02:30",
            "2000-02-29T00:00:00Z",
            "2028-02-29T00:00:00Z",
        ] {
            validate_hold(Some("review"), Some(until)).unwrap();
            assert!(crate::proto::parse_rfc3339(until).is_some());
        }
        // Hold duration remains a server decision, independent of timestamp input validation.
        validate_hold(Some("review"), Some("2099-11-11T21:00:00Z")).unwrap();
    }

    #[test]
    fn local_hold_inputs_acquire_or_reuse_without_renewing_or_storing_a_hold() {
        for until in [None, Some("2026-11-11T21:00:00Z")] {
            for reuse in [false, true] {
                let (_dir, mut store) = test_store();
                let original = reuse
                    .then(|| Backend::claim(&mut store, "worker", &request(&["src"]), 0).unwrap());
                let (claim, created) = claim_or_reuse_with_hold(
                    &mut store,
                    "worker",
                    &ClaimRequest {
                        ttl_minutes: 20,
                        ..request(&["src"])
                    },
                    Some("review".into()),
                    until.map(str::to_string),
                    1,
                )
                .unwrap();
                assert_eq!(created, Some(!reuse));
                assert!(claim.hold_until.is_none());
                assert!(claim.hold_reason.is_none());
                assert!(claim.idle_release_at.is_none());
                if let Some(original) = original {
                    assert_eq!(claim, original);
                } else {
                    assert_eq!(claim.expires_at, Stamp::Millis(1 + 20 * 60_000));
                }
                assert_eq!(
                    Backend::claims(&store, &ClaimQuery::default(), 1).unwrap(),
                    [claim]
                );
            }
        }
    }

    #[test]
    fn local_renew_with_hold_still_requires_cloud_mode() {
        let (_dir, mut store) = test_store();
        let claim = Backend::claim(&mut store, "worker", &request(&["src"]), 0).unwrap();
        for (reason, until) in [
            (Some("review"), None),
            (None, Some("2026-11-11T21:00:00Z")),
            (Some("review"), Some("2026-11-11T21:00:00Z")),
        ] {
            let error = Backend::renew(
                &mut store,
                "worker",
                Some(claim.id),
                &RenewRequest {
                    ttl_minutes: 20,
                    hold_reason: reason.map(str::to_string),
                    hold_until: until.map(str::to_string),
                    fence: None,
                },
                1,
            )
            .unwrap_err();
            assert!(error.to_string().contains("needs cloud mode"));
        }
        assert_eq!(
            Backend::claims(&store, &ClaimQuery::default(), 1).unwrap(),
            [claim]
        );
    }

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
            backend.work_get("a", "BT-1").map(|_| ()),
            backend
                .work_step("a", "BT-1", WorkAction::Beat, &WorkStep::default())
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
            backend.registry_search(&json!({})).map(|_| ()),
            backend.registry_ready(&json!({})).map(|_| ()),
            backend.registry_item_by_id("D-1").map(|_| ()),
            backend.registry_blockers_by_id("D-1").map(|_| ()),
            backend.registry_item_by_id("FE-0319").map(|_| ()),
            backend.registry_blockers_by_id("FE-0319").map(|_| ()),
            backend
                .registry_link_by_id("a", "FE-0319", "G-SG-0012", "blocks", 1, "key")
                .map(|_| ()),
            backend
                .registry_link_by_id("a", "D-1", "D-2", "blocks", 1, "key")
                .map(|_| ()),
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
    fn local_general_tasks_keep_default_ids_and_refuse_registry_options_without_writes() {
        let (_dir, mut store) = test_store();
        let backend: &mut dyn Backend = &mut store;
        let general = tasks::TaskSpec {
            title: "local general task".into(),
            area: Some("general".into()),
            ..tasks::TaskSpec::default()
        };
        let task = backend.add_task("lead", &general, 0).unwrap();
        assert_eq!(task.id, "D-1");
        let refused = [
            tasks::TaskSpec {
                area: Some("engine".into()),
                ..general.clone()
            },
            tasks::TaskSpec {
                priority: Some("P1".into()),
                ..general.clone()
            },
            tasks::TaskSpec {
                prefix: Some("FE".into()),
                ..general.clone()
            },
            tasks::TaskSpec {
                pad: Some(4),
                ..general
            },
        ];
        for spec in refused {
            assert!(matches!(
                backend.add_task("refused", &spec, 1),
                Err(Error::NeedsCloud(_))
            ));
            assert_eq!(
                backend.tasks(None, true).unwrap().as_slice(),
                std::slice::from_ref(&task)
            );
            assert_eq!(backend.task_history(&task.id).unwrap().len(), 1);
        }
        let agents = store.agents().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, "lead");
    }

    #[test]
    fn a_numeric_workflow_claim_preserves_the_local_string_task_contract() {
        let (_dir, mut store) = test_store();
        let backend: &mut dyn Backend = &mut store;
        let task = backend
            .add_task(
                "lead",
                &tasks::TaskSpec {
                    title: "workflow claim".into(),
                    ..tasks::TaskSpec::default()
                },
                0,
            )
            .unwrap();
        let id = task.id.as_str();
        let receipt = backend
            .claim_task_receipt_by_id("worker", id, 10, 1)
            .unwrap();
        assert_eq!(receipt["id"], task.id);
        assert_eq!(receipt["status"], "claimed");
        assert_eq!(receipt["assignee"], "worker");
        assert_eq!(
            backend.task(&task.id).unwrap().assignee.as_deref(),
            Some("worker")
        );
    }

    #[test]
    fn a_string_workflow_claim_uses_the_local_task_contract() {
        let (_dir, mut store) = test_store();
        let backend: &mut dyn Backend = &mut store;
        let task = backend
            .add_task(
                "lead",
                &tasks::TaskSpec {
                    title: "string workflow claim".into(),
                    ..tasks::TaskSpec::default()
                },
                0,
            )
            .unwrap();
        let receipt = backend
            .claim_task_receipt_by_id("worker", &task.id, 10, 1)
            .unwrap();
        assert_eq!(receipt["id"], task.id);
        assert_eq!(receipt["status"], "claimed");
        assert_eq!(receipt["assignee"], "worker");
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
