// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use lockyard_core::proto::Event;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct PushState {
    epoch: u64,
    zone_alerts: HashMap<String, BTreeMap<i64, lockyard_core::proto::LostClaim>>,
    zone_alert_versions: HashMap<(String, i64), i64>,
    status_claims: HashMap<String, HashSet<i64>>,
    local_zone_mutations: HashMap<(String, i64), Vec<LocalZoneMutation>>,
    next_zone_mutation: u64,
    seen_claims: HashMap<String, HashSet<i64>>,
    zone_alert_times: HashMap<(String, i64), Instant>,
    replacement: Option<Replacement>,
    #[cfg(test)]
    clock_now: Option<Instant>,
    #[cfg(test)]
    reconnect_delays: Option<Vec<Duration>>,
    subscribed: HashSet<String>,
    pub(super) bound_sessions: HashSet<String>,
    pub(super) zone_version: u64,
    next_waiter: u64,
    waiters: HashMap<String, u64>,
    mailboxes: HashMap<String, Mailbox>,
    /// Events retained during a first inbox seed so arrival cannot race past that seed.
    arrivals: VecDeque<(i64, String, Message)>,
    woken: HashMap<String, WakeCursor>,
    pending_wakes: HashSet<String>,
}

impl PushState {
    fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(now) = self.clock_now {
            return now;
        }
        Instant::now()
    }
}

struct LocalZoneMutation {
    token: u64,
    input_fence: Option<i64>,
    result_fence: Option<i64>,
    until: Instant,
    events: Vec<Event>,
}

fn reclaimed_paths_overlap(a: &str, b: &str, fold_case: Option<bool>) -> bool {
    if let Some(fold_case) = fold_case {
        return ZonePath::stored(a.into())
            .overlaps_with_case(&ZonePath::stored(b.into()), fold_case);
    }
    // Legacy events and claims may omit the policy. Keep alerts for spelling aliases
    // unless the server has confirmed that the repository treats them as equivalent.
    a == b
        || a.strip_prefix(b).is_some_and(|tail| tail.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|tail| tail.starts_with('/'))
}

enum PushExit {
    Replaced,
    Unavailable,
}

struct Replacement {
    sessions: Vec<String>,
    retry_at: Instant,
    retried: bool,
}

#[derive(Default)]
struct Mailbox {
    unread: BTreeMap<i64, Message>,
    open: BTreeMap<i64, Message>,
    seeded: bool,
    seeded_at: Option<Instant>,
    seeding: bool,
    sequences: HashMap<i64, i64>,
    open_known: bool,
    skipped: i64,
    open_truncated: bool,
    read_ids: HashSet<i64>,
    handled_ids: HashSet<i64>,
    delivered: HashMap<i64, Instant>,
}

impl Mailbox {
    fn unread_count(&self) -> Option<i64> {
        // Legacy skipped counts include seen rows; their new/seen split is unknown.
        (self.skipped == 0).then_some(self.unread.len() as i64)
    }
}

struct SeedGuard<'a, T: Transport + 'static> {
    shared: &'a Shared<T>,
    session: &'a str,
}
pub(super) fn known_event(kind: &str) -> bool {
    matches!(
        kind,
        "bus.message"
            | "bus.unread"
            | "bus.seen"
            | "bus.handled"
            | "bus.ack"
            | "bus.delivery_claimed"
            | "bus.imported"
    ) || matches!(
        kind,
        "task.offered"
            | "task.claim"
            | "task.beat"
            | "task.done"
            | "task.accept"
            | "task.reject"
            | "task.fail"
            | "task.cancel"
            | "task.handoff"
            | "task.take"
            | "task.decline"
            | "task.expired"
            | "board.changed"
            | "zone.requested"
            | "zone.answered"
            | "zone.queued"
            | "zone.dequeued"
            | "zone.taken"
            | "zone.claimed"
            | "zone.released"
            | "zone.expired"
            | "zone.lost"
            | "zone.granted"
            | "zone.handover"
            | "zone.takeover"
            | "zone.catalog"
            | "zone.dirty"
            | "zone.dirty_adopted"
            | "zone.dirty_disowned"
            | "presence.activity"
            | "presence.heartbeat"
            | "presence.unavailable"
            | "admin.freeze"
            | "integration.github"
    )
}

impl<T: Transport + 'static> Drop for SeedGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(mailbox) = self
            .shared
            .push
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mailboxes
            .get_mut(self.session)
        {
            mailbox.seeding = false;
        }
        self.shared.mail_ready.notify_all();
    }
}

fn wakes(message: &Message, session: &str) -> bool {
    crate::mail_wait::wakes(message, session)
}

fn is_personal_open(mail: &Message, session: &str) -> bool {
    crate::mail_wait::requires_reply(mail, session)
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct WakeCursor {
    seq: i64,
    id: i64,
}

fn addressed(event: &Event, session: &str) -> bool {
    event.rest.get("session").and_then(Value::as_str) == Some(session)
        && event.payload.get("role").and_then(Value::as_str) != Some("sender")
}

impl<T: Transport + 'static> Shared<T> {
    pub(super) fn zone_alerts(&self, session: &str) -> Vec<lockyard_core::proto::LostClaim> {
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        let now = push.now();
        let expired: Vec<_> = push
            .zone_alert_times
            .iter()
            .filter(|((owner, _), at)| {
                owner == session && now.saturating_duration_since(**at) > Duration::from_secs(1800)
            })
            .map(|((_, id), _)| *id)
            .collect();
        for id in expired {
            if let Some(alerts) = push.zone_alerts.get_mut(session) {
                alerts.remove(&id);
            }
            push.zone_alert_times.remove(&(session.into(), id));
        }
        push.zone_alerts
            .get(session)
            .map(|alerts| alerts.values().cloned().collect())
            .unwrap_or_default()
    }

    pub(super) fn ack_zone_alerts(
        &self,
        session: &str,
        acknowledgements: &[lockyard_core::proto::LostClaim],
    ) {
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        for ack in acknowledgements {
            if ack.session == session
                && push
                    .zone_alerts
                    .get(session)
                    .and_then(|alerts| alerts.get(&ack.claim_id))
                    == Some(ack)
            {
                push.zone_alerts
                    .get_mut(session)
                    .unwrap()
                    .remove(&ack.claim_id);
                push.zone_alert_times
                    .remove(&(session.into(), ack.claim_id));
            }
        }
    }

    #[cfg(all(test, unix))]
    fn take_zone_alerts(&self, session: &str) -> Vec<lockyard_core::proto::LostClaim> {
        let alerts = self.zone_alerts(session);
        self.ack_zone_alerts(session, &alerts);
        alerts
    }

    pub(super) fn retain_zone_sessions(&self, sessions: &HashMap<String, SessionTrack>) {
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        push.seen_claims
            .retain(|session, _| sessions.contains_key(session));
        push.status_claims
            .retain(|session, _| sessions.contains_key(session));
        push.zone_alerts
            .retain(|session, _| sessions.contains_key(session));
        push.zone_alert_versions
            .retain(|(session, _), _| sessions.contains_key(session));
        push.zone_alert_times
            .retain(|(session, _), _| sessions.contains_key(session));
        push.local_zone_mutations
            .retain(|(session, _), _| sessions.contains_key(session));
    }

    pub(super) fn begin_zone_mutation(&self, call: &Call) -> Option<(String, i64, u64)> {
        let route = call.path.split('?').next()?;
        let parts: Vec<_> = route.split('/').collect();
        if call.method != "POST"
            || !matches!(
                parts.as_slice(),
                ["", "api", "v1", "zones", "claims", _, "narrow"]
            )
        {
            return None;
        }
        let id = parts[5].parse().ok()?;
        // Some callers omit the optional precondition. The successful receipt still
        // supplies the fence needed to identify our event, including an early SSE.
        let fence = call.body.as_ref()?.get("fence").and_then(Value::as_i64);
        let key = (call.session.clone(), id);
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        let now = push.now();
        push.local_zone_mutations.retain(|_, mutations| {
            mutations.retain(|mutation| mutation.until > now);
            !mutations.is_empty()
        });
        push.next_zone_mutation += 1;
        let token = push.next_zone_mutation;
        let mutations = push.local_zone_mutations.entry(key.clone()).or_default();
        // Keep every receipt fence until its echo-retention deadline; replacing an
        // older completed mutation can misclassify its delayed SSE as a foreign loss.
        mutations.push(LocalZoneMutation {
            token,
            input_fence: fence,
            result_fence: None,
            until: now + Duration::from_secs(1800),
            events: Vec::new(),
        });
        Some((key.0, key.1, token))
    }

    pub(super) fn finish_zone_mutation(
        &self,
        mutation: Option<(String, i64, u64)>,
        value: Option<&Value>,
    ) {
        let Some((session, id, token)) = mutation else {
            return;
        };
        let events = {
            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(mutations) = push.local_zone_mutations.get_mut(&(session, id)) else {
                return;
            };
            let Some(index) = mutations.iter().position(|m| m.token == token) else {
                return;
            };
            if let Some(fence) = value
                .and_then(|value| value.get("fence"))
                .and_then(Value::as_i64)
            {
                mutations[index].result_fence = Some(fence);
                std::mem::take(&mut mutations[index].events)
            } else {
                mutations.remove(index).events
            }
        };
        for event in events {
            self.observe_zone_loss(&event);
        }
    }

    fn clear_reclaimed_alerts(
        &self,
        session: &str,
        new_id: i64,
        paths: &[String],
        fold_case: Option<bool>,
    ) {
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(alerts) = push.zone_alerts.get_mut(session) {
            alerts.retain(|id, alert| {
                *id == new_id
                    || !alert.paths.iter().any(|old| {
                        paths
                            .iter()
                            .any(|new| reclaimed_paths_overlap(old, new, fold_case))
                    })
            });
            let remaining: HashSet<_> = alerts.keys().copied().collect();
            push.zone_alert_times
                .retain(|(owner, id), _| owner != session || remaining.contains(id));
        }
    }

    fn observe_zone_loss(&self, event: &Event) {
        if !event.kind.starts_with("zone.") {
            return;
        }
        if matches!(event.kind.as_str(), "zone.claimed" | "zone.granted") {
            if let (Some(session), Some(id)) = (
                event.field("session").and_then(Value::as_str),
                event.field("claim_id").and_then(Value::as_i64),
            ) {
                if !self.sessions().contains_key(session) {
                    return;
                }
                let unseen = self
                    .push
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .seen_claims
                    .entry(session.into())
                    .or_default()
                    .insert(id);
                if unseen
                    && matches!(
                        event.field("reason").and_then(Value::as_str),
                        Some("claimed" | "granted")
                    )
                {
                    let paths: Vec<String> = event
                        .field("paths")
                        .cloned()
                        .and_then(|v| serde_json::from_value(v).ok())
                        .unwrap_or_default();
                    let fold_case = event
                        .field("case_insensitive_paths")
                        .and_then(Value::as_bool);
                    self.clear_reclaimed_alerts(session, id, &paths, fold_case);
                }
            }
            return;
        }
        let reason = event
            .field("reason")
            .and_then(Value::as_str)
            .unwrap_or("expired");
        if !matches!(
            event.kind.as_str(),
            "zone.expired" | "zone.lost" | "zone.taken"
        ) && !(event.kind == "zone.released"
            && matches!(reason, "narrowed" | "taken" | "idle" | "unused_grant"))
        {
            return;
        }
        let Some(session) = event.field("session").and_then(Value::as_str) else {
            return;
        };
        if !self.sessions().contains_key(session) {
            return;
        }
        let Some(id) = event.field("claim_id").and_then(Value::as_i64) else {
            return;
        };
        if event.kind == "zone.released" && reason == "narrowed" {
            let actor = event
                .field("actor")
                .or_else(|| event.field("by"))
                .and_then(|actor| {
                    actor
                        .as_str()
                        .or_else(|| actor.get("session").and_then(Value::as_str))
                });
            if actor == Some(session) {
                return;
            }
            if actor.is_none() {
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                let now = push.now();
                if let Some(mutations) = push.local_zone_mutations.get_mut(&(session.into(), id)) {
                    mutations.retain(|m| m.until > now);
                    let fence = event.field("fence").and_then(Value::as_i64);
                    if mutations.iter().any(|m| {
                        fence.is_some()
                            && m.result_fence == fence
                            && m.input_fence.is_none_or(|input| fence.unwrap() >= input)
                    }) {
                        return;
                    }
                    if let Some(mutation) = mutations.iter_mut().find(|m| m.result_fence.is_none())
                    {
                        if mutation.events.len() < 256 {
                            mutation.events.push(event.clone());
                        }
                        return;
                    }
                }
            }
        }
        let paths = event
            .field("paths")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let at = event
            .field("at")
            .or_else(|| event.field("created_at"))
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or(lockyard_core::proto::Stamp::Millis(now_ms()));
        let lost = lockyard_core::proto::LostClaim {
            claim_id: id,
            session: session.into(),
            paths,
            reason: Some(
                if matches!(event.kind.as_str(), "zone.lost" | "zone.taken") {
                    if reason == "taken" || reason.starts_with("taken:") {
                        reason.into()
                    } else {
                        format!("taken: {reason}")
                    }
                } else {
                    reason.into()
                },
            ),
            lost_at: Some(at),
        };
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        push.seen_claims
            .entry(session.into())
            .or_default()
            .insert(id);
        let version = push
            .zone_alert_versions
            .entry((session.into(), id))
            .or_insert(i64::MIN);
        if *version >= event.seq {
            return;
        }
        *version = event.seq;
        let now = push.now();
        push.zone_alert_times.insert((session.into(), id), now);
        let alerts = push.zone_alerts.entry(session.into()).or_default();
        alerts.insert(id, lost);
        let mut removed = Vec::new();
        while alerts.len() > 256 {
            let key = *alerts.keys().next().unwrap();
            alerts.remove(&key);
            removed.push(key);
        }
        for id in removed {
            push.zone_alert_versions.remove(&(session.into(), id));
        }
    }

    pub(super) fn observe_status_claims(
        &self,
        session: &str,
        claims: &[Claim],
        backend: &dyn Backend,
        budget: Duration,
    ) {
        let current: HashSet<_> = claims
            .iter()
            .filter(|c| c.session == session)
            .map(|c| c.id)
            .collect();
        let (missing, acquired): (HashSet<_>, Vec<_>) = {
            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            let seen = push.seen_claims.entry(session.into()).or_default();
            let acquired: Vec<_> = claims
                .iter()
                .filter(|claim| claim.session == session && seen.insert(claim.id))
                .collect();
            let previous = push.status_claims.entry(session.into()).or_default();
            let missing = previous.difference(&current).copied().collect();
            previous.extend(current.iter().copied());
            (missing, acquired)
        };
        // Repeated snapshots of the same id cannot acknowledge a later loss.
        if !missing.is_empty()
            && !budget.is_zero()
            && let Ok(lost) = backend.lost_within(session, budget)
        {
            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            push.status_claims
                .entry(session.into())
                .or_default()
                .retain(|id| !missing.contains(id));
            for mut claim in lost.into_iter().filter(|c| {
                missing.contains(&c.claim_id) && (c.session.is_empty() || c.session == session)
            }) {
                if push
                    .zone_alert_versions
                    .contains_key(&(session.into(), claim.claim_id))
                {
                    continue;
                }
                // Older lost endpoints omit the owner. Preserve the known mailbox
                // identity so an exact output acknowledgement can retire this alert.
                if claim.session.is_empty() {
                    claim.session = session.into();
                }
                let now = push.now();
                push.zone_alert_times
                    .insert((session.into(), claim.claim_id), now);
                push.zone_alert_versions
                    .insert((session.into(), claim.claim_id), i64::MIN);
                let alerts = push.zone_alerts.entry(session.into()).or_default();
                alerts.insert(claim.claim_id, claim);
                while alerts.len() > 256 {
                    let id = *alerts.keys().next().unwrap();
                    alerts.remove(&id);
                }
            }
        }
        // Share acquisition history with SSE and clear after fallback seeding so
        // an old /lost record cannot resurrect an alert in this same snapshot.
        for claim in acquired {
            self.clear_reclaimed_alerts(
                session,
                claim.id,
                &claim.paths,
                claim.case_insensitive_paths,
            );
        }
    }

    pub(super) fn peek_hook_mail(&self, session: &str) -> Reply {
        self.hear(session);
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(mailbox) = push.mailboxes.get(session).filter(|m| m.seeded) {
            return Reply {
                mail_truncated: mailbox.skipped > 0,
                messages: Some(
                    mailbox
                        .unread
                        .values()
                        .filter(|m| !mailbox.handled_ids.contains(&m.id))
                        .cloned()
                        .collect(),
                ),
                ..Reply::default()
            };
        }
        drop(push);
        Reply {
            messages: self
                .read_view()
                .mail
                .get(session)
                .map(|b| b.messages.iter().cloned().collect()),
            ..Reply::default()
        }
    }

    pub(super) fn wait_zone_free(
        &self,
        session: &str,
        path: &str,
        timeout_ms: u64,
        disconnected: &mut dyn FnMut() -> bool,
    ) -> Reply {
        let result = (|| -> lockyard_core::Result<bool> {
            let deadline = self
                .push_now()
                .checked_add(Duration::from_millis(timeout_ms))
                .ok_or_else(|| Error::Invalid("zone wait timeout is too large".into()))?;
            self.hear(session);

            loop {
                // Capture before the authoritative read so an event racing the read is observed.
                let version = self
                    .push
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .zone_version;
                let mut call = Call::write(
                    session,
                    "POST",
                    "/api/v1/zones/check".into(),
                    json!({"paths":[path],"mode":"exclusive"}),
                );
                call.key = None;
                let left = deadline.saturating_duration_since(self.push_now());
                let ms = left.as_millis().max(1).min(u64::MAX as u128) as u64;
                call.deadline_ms = Some(ms);
                call.attempt_timeout_ms = Some(ms);
                let answer = match self.transport.call(&call) {
                    Ok(answer) => answer,
                    Err(_) if self.push_now() >= deadline && timeout_ms > 0 => return Ok(false),
                    Err(error) => return Err(error.into()),
                };
                self.confirm_session_binding(&call);
                let rows = lockyard_cloud_client::decode_checks(answer)?;
                match rows.as_slice() {
                    [row] if matches!(row.status, CheckStatus::Free | CheckStatus::Own) => {
                        return Ok(true);
                    }
                    [row] if row.status == CheckStatus::Held => {}
                    _ => {
                        return Err(Error::Unavailable(
                            "zone check returned unknown state".into(),
                        ));
                    }
                }
                if self.push_now() >= deadline || self.stopped() {
                    return Ok(false);
                }
                let push_ready = self.push_ready.load(Ordering::Acquire);
                let next = if push_ready {
                    deadline
                } else {
                    deadline.min(self.push_now() + Duration::from_secs(60))
                };
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                while push.zone_version == version
                    && push.now() < next
                    && !self.stopped()
                    && self.push_ready.load(Ordering::Acquire) == push_ready
                {
                    if disconnected() {
                        return Ok(false);
                    }
                    let wait = next
                        .saturating_duration_since(push.now())
                        .min(Duration::from_millis(100));
                    push = self
                        .mail_ready
                        .wait_timeout(push, wait)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                    // Refresh session liveness without making any HTTP requests.
                    drop(push);
                    self.hear(session);
                    push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                }
                drop(push);
                if self.push_now() >= deadline || self.stopped() {
                    return Ok(false);
                }
            }
        })();
        match result {
            Ok(free) => Reply {
                value: Some(json!({"free":free,"timed_out":!free})),
                ..Reply::default()
            },
            Err(error) => Reply::failed(ClientError::Invalid(error.to_string())),
        }
    }

    pub(super) fn mail_cache_ready(&self) -> bool {
        self.push_ready.load(Ordering::Acquire)
            || (self.push_fallback.load(Ordering::Acquire)
                && self.mail_protocol.load(Ordering::Acquire) == 1)
    }

    /// Seed each stream generation after ready; fall back to bounded snapshots when SSE is unavailable.
    fn seed_push_mail(&self, session: &str) -> Result<(), Error> {
        if !self.mail_cache_ready() {
            return Err(Error::Unavailable("mail stream is not ready".into()));
        }
        let poll = self.poll_push_session(session);
        let epoch = {
            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            loop {
                let mailbox = push.mailboxes.entry(session.into()).or_default();
                if mailbox.seeded
                    && (!poll
                        || mailbox
                            .seeded_at
                            .is_some_and(|at| at.elapsed() < Duration::from_secs(1)))
                {
                    return Ok(());
                }
                mailbox.seeded = false;
                if !mailbox.seeding {
                    mailbox.seeding = true;
                    break push.epoch;
                }
                push = self
                    .mail_ready
                    .wait(push)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        let _seed = SeedGuard {
            shared: self,
            session,
        };
        let started_seq = self.coordination_seq.load(Ordering::Relaxed);
        let backend = self.backend(session);
        let page = backend.peek_inbox_within(
            session,
            InboxQuery {
                all: false,
                limit: 200,
            },
            now_ms(),
            Duration::from_secs(2),
        )?;
        let open = if self.transport.mail_open_v1(session).unwrap_or(false) {
            backend.peek_open_inbox_within(session, 200, now_ms(), Duration::from_secs(1))
        } else {
            backend.peek_inbox_within(
                session,
                InboxQuery {
                    all: true,
                    limit: 200,
                },
                now_ms(),
                Duration::from_secs(1),
            )
        }
        .ok();
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if epoch != push.epoch || !self.mail_cache_ready() {
            return Err(Error::Unavailable(
                "mail stream changed during snapshot".into(),
            ));
        }
        let arrivals: Vec<_> = push
            .arrivals
            .iter()
            .filter(|(seq, target, _)| *seq > started_seq && target == session)
            .map(|(_, _, mail)| mail.clone())
            .collect();
        let mailbox = push.mailboxes.entry(session.into()).or_default();
        if mailbox.seeded {
            return Ok(());
        }
        mailbox.unread.clear();
        mailbox.open.clear();
        mailbox.open_known = open.is_some();
        mailbox.skipped = page.skipped;
        mailbox.open_truncated = open.as_ref().is_some_and(|page| page.skipped > 0);
        for mail in page.messages {
            mailbox.unread.insert(mail.id, mail);
        }
        for mail in open.map(|p| p.messages).unwrap_or_default() {
            if is_personal_open(&mail, session) {
                mailbox.open.insert(mail.id, mail);
            }
        }
        for mut mail in arrivals {
            if mail.body.is_empty()
                && let Some(existing) = mailbox.unread.get(&mail.id)
            {
                mail.body.clone_from(&existing.body);
            }
            if is_personal_open(&mail, session) {
                mailbox.open.insert(mail.id, mail.clone());
            }
            mailbox.unread.insert(mail.id, mail);
        }
        for id in &mailbox.read_ids {
            mailbox.unread.remove(id);
        }
        for id in &mailbox.handled_ids {
            mailbox.open.remove(id);
        }
        mailbox.seeded = true;
        mailbox.seeded_at = Some(Instant::now());
        let count = mailbox.unread_count();
        drop(push);
        self.update_push_count(session, count);
        Ok(())
    }

    fn update_push_count(&self, session: &str, count: Option<i64>) {
        let mut view = self.write_view();
        let entry = view.unread.entry(session.into()).or_default();
        let Some(count) = count else {
            entry.generation += 1;
            entry.at = None;
            entry.wall_at = None;
            return;
        };
        if entry.count != count {
            entry.generation += 1;
        }
        entry.count = count;
        entry.clean = entry.generation;
        entry.at = Some(Instant::now());
        entry.wall_at = Some(SystemTime::now());
    }

    pub(super) fn wait_mail(
        &self,
        session: &str,
        since: i64,
        timeout_ms: u64,
        disconnected: &mut dyn FnMut() -> bool,
    ) -> Reply {
        let Some(deadline) = Instant::now().checked_add(Duration::from_millis(timeout_ms)) else {
            return Reply::default();
        };
        self.hear(session);
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        push.next_waiter += 1;
        let token = push.next_waiter;
        push.waiters.insert(session.into(), token);
        self.mail_ready.notify_all();
        let wake_name = format!("wake-mail-{}", lockyard_cloud_client::token_id(session));
        push.woken.entry(session.into()).or_insert_with(|| {
            fs::read(self.state_dir.join(&wake_name))
                .ok()
                .and_then(|data| serde_json::from_slice(&data).ok())
                .unwrap_or_default()
        });
        let mut next_seed_retry = Instant::now();
        let mut truncated = false;
        let reply = loop {
            if self.stopped()
                || Instant::now() >= deadline
                || disconnected()
                || self.mail_protocol.load(Ordering::Acquire) == 0
                || push.waiters.get(session) != Some(&token)
            {
                break Reply::default();
            }
            drop(push);
            // A transient snapshot failure or negotiation in flight keeps the wait alive.
            self.hear(session);
            push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            let mailbox = push.mailboxes.get(session).filter(|m| m.seeded);
            let seeded = mailbox.is_some();
            truncated |= mailbox.is_some_and(|m| m.skipped > 0);
            if !seeded && Instant::now() >= next_seed_retry {
                self.nudge();
                next_seed_retry = Instant::now() + Duration::from_secs(1);
            }
            if seeded
                && !push.pending_wakes.contains(session)
                && self.mail_cache_ready()
                && Instant::now() < deadline
                && push.waiters.get(session) == Some(&token)
            {
                let last = &push.woken[session];
                let mail = push.mailboxes.get(session).and_then(|mailbox| {
                    mailbox
                        .unread
                        .values()
                        .find(|mail| {
                            let seq = mailbox.sequences.get(&mail.id).copied().unwrap_or(0);
                            wakes(mail, session)
                                && (mail.id > last.id || (seq > last.seq && mail.id != last.id))
                                && (seq == 0 || seq > since)
                        })
                        .cloned()
                });
                if let Some(mail) = mail {
                    break Reply {
                        messages: Some(vec![mail]),
                        ..Reply::default()
                    };
                }
            }
            push = self
                .mail_ready
                .wait_timeout(
                    push,
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(100)),
                )
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        };
        drop(push);
        let mut reply = reply;
        reply.mail_truncated = truncated;
        if let Some(mail) = reply.messages.as_mut().and_then(|m| m.first_mut()) {
            self.hydrate_push_mail(session, mail, deadline);
        }
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if push.waiters.get(session) != Some(&token) {
            return Reply::default();
        }
        if reply.messages.as_ref().is_some_and(|m| !m.is_empty()) {
            push.pending_wakes.insert(session.into());
        }
        push.waiters.remove(session);
        reply
    }

    // Called only after the socket reply was successfully written (or returned in process).
    pub(super) fn confirm_mail_wake(&self, session: &str, reply: &Reply, sent: bool) {
        let Some(mail) = reply.messages.as_ref().and_then(|m| m.first()) else {
            return;
        };
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        push.pending_wakes.remove(session);
        self.mail_ready.notify_all();
        if !sent {
            return;
        }
        let seq = push
            .mailboxes
            .get(session)
            .and_then(|m| m.sequences.get(&mail.id))
            .copied()
            .unwrap_or(0);
        let previous = push.woken.entry(session.into()).or_default();
        let cursor = WakeCursor {
            seq: seq.max(previous.seq),
            id: mail.id.max(previous.id),
        };
        let wake_name = format!("wake-mail-{}", lockyard_cloud_client::token_id(session));
        let saved = serde_json::to_vec(&cursor)
            .map_err(io::Error::other)
            .and_then(|data| self.save_push_file(&wake_name, &data));
        if let Err(error) = saved {
            eprintln!("lockyard agent: cannot save mail wake cursor: {error}");
        } else {
            push.woken.insert(session.into(), cursor);
        }
    }

    fn save_push_file(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let path = self.state_dir.join(name);
        #[cfg(unix)]
        {
            let temp = self.state_dir.join(format!("{name}.tmp"));
            fs::write(&temp, data)?;
            lockyard_core::fsio::rename(&temp, &path)
        }
        #[cfg(windows)]
        {
            lockyard_core::fsio::replace(&path, data, 0o600)
        }
    }

    fn hydrate_push_mail(&self, session: &str, mail: &mut Message, deadline: Instant) {
        if !mail.body.is_empty() {
            return;
        }
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2));
        if budget.is_zero() {
            return;
        }
        let mut call = Call::get(
            session,
            format!("/api/v1/bus/threads/{}", mail.thread_id.unwrap_or(mail.id)),
        );
        call.deadline_ms = Some(budget.as_millis() as u64);
        if let Ok(value) = self.transport.call(&call)
            && let Some(rows) = value.as_array().or_else(|| {
                value
                    .get("messages")
                    .or_else(|| value.get("items"))
                    .and_then(Value::as_array)
            })
            && let Some(message) = rows.iter().find(|m| m["id"] == mail.id)
            && let Some(body) = message["body"].as_str()
        {
            mail.body = body.to_string();
            mail.from_client = message["from_client"].as_str().map(str::to_owned);
            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(mailbox) = push.mailboxes.get_mut(session) {
                if let Some(cached) = mailbox.unread.get_mut(&mail.id) {
                    cached.body.clone_from(&mail.body);
                    cached.from_client.clone_from(&mail.from_client);
                }
                if let Some(cached) = mailbox.open.get_mut(&mail.id) {
                    cached.body.clone_from(&mail.body);
                    cached.from_client.clone_from(&mail.from_client);
                }
            }
        }
    }

    pub(super) fn push_open_snapshot(
        &self,
        session: &str,
    ) -> Option<crate::open_mail::OpenMailSnapshot> {
        if !self.mail_cache_ready() {
            return None;
        }
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        let mailbox = push
            .mailboxes
            .get(session)
            .filter(|m| m.seeded && m.open_known)?;
        Some(crate::open_mail::OpenMailSnapshot {
            items: mailbox
                .open
                .values()
                .filter(|mail| is_personal_open(mail, session))
                .map(crate::open_mail::to_open)
                .collect(),
            truncated: mailbox.open_truncated,
        })
    }

    pub(super) fn confirm_push_counts(&self) {
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        for (session, mailbox) in &push.mailboxes {
            if mailbox.seeded {
                self.update_push_count(session, mailbox.unread_count());
            }
        }
    }

    pub(super) fn poll_push_session(&self, session: &str) -> bool {
        self.push_fallback.load(Ordering::Acquire)
            || !self
                .push
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .subscribed
                .contains(session)
    }

    pub(super) fn polling_mail_waiters(&self) -> bool {
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        push.waiters
            .keys()
            .any(|s| self.push_fallback.load(Ordering::Acquire) || !push.subscribed.contains(s))
    }

    pub(super) fn seed_active_push_mail(&self) {
        let sessions: Vec<_> = self
            .sessions()
            .iter()
            .filter(|(_, t)| {
                t.push_bound
                    && t.heard
                        .is_some_and(|at| at.elapsed() < self.timing().active_window)
            })
            .map(|(s, _)| s.clone())
            .collect();
        for session in sessions {
            let needed = {
                let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                let seeded = push.mailboxes.get(&session).is_some_and(|m| m.seeded);
                !seeded
                    || (push.waiters.contains_key(&session)
                        && (self.push_fallback.load(Ordering::Acquire)
                            || !push.subscribed.contains(&session)))
            };
            if needed {
                let _ = self.seed_push_mail(&session);
            }
        }
    }

    /// Preserve server delivery leases for hooks, selecting candidates from the SSE cache.
    /// Waiting never calls this routine and never consumes a delivery reservation.
    pub(super) fn refresh_push_mail(&self) -> bool {
        let now = Instant::now();
        self.write_view()
            .mail
            .retain(|_, buffer| buffer.lease_expires_at > now);
        let sessions: Vec<_> = self
            .push
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .mailboxes
            .keys()
            .cloned()
            .collect();
        let mut busy = false;
        for session in sessions {
            if self.read_view().mail.contains_key(&session) {
                continue;
            }
            let mut messages: Vec<Message> = {
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                let mailbox = push.mailboxes.get_mut(&session).expect("known mailbox");
                if !mailbox.seeded {
                    continue;
                }
                mailbox.delivered.retain(|_, until| *until > now);
                mailbox
                    .unread
                    .values()
                    .filter(|mail| !mailbox.delivered.contains_key(&mail.id))
                    .take(MAIL_BUFFER_LIMIT)
                    .cloned()
                    .collect()
            };
            if messages.is_empty() {
                continue;
            }
            let ids: Vec<_> = messages.iter().map(|m| m.id).collect();
            let reserved_at = Instant::now();
            let granted = match self.backend(&session).inbox_claim(
                &session,
                "agent",
                &ids,
                MAIL_DELIVERY_LEASE.as_secs() as i64,
                now_ms(),
            ) {
                Ok(ids) => ids,
                Err(error) => {
                    busy |= error.to_string().contains("pending journal is busy");
                    continue;
                }
            };
            messages.retain(|mail| granted.contains(&mail.id));
            if messages.is_empty() {
                continue;
            }
            let has_waiter = self
                .push
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .waiters
                .contains_key(&session);
            if !has_waiter {
                let deadline = Instant::now() + self.timing().deadline;
                for mail in &mut messages {
                    self.hydrate_push_mail(&session, mail, deadline);
                }
            }
            let until = reserved_at + MAIL_DELIVERY_LEASE;
            {
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(mailbox) = push.mailboxes.get_mut(&session) {
                    messages.retain(|mail| mailbox.unread.contains_key(&mail.id));
                    for mail in &messages {
                        mailbox.delivered.insert(mail.id, until);
                    }
                }
            }
            if !messages.is_empty() {
                self.write_view().mail.entry(session).or_insert(MailBuffer {
                    messages: messages.into(),
                    reserved_at,
                    lease_expires_at: until,
                });
            }
        }
        busy
    }

    pub(super) fn push_seen(&self, session: &str, ids: Option<&Value>) {
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(mailbox) = push.mailboxes.get_mut(session) {
            for id in ids
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_i64)
            {
                mailbox.unread.remove(&id);
                mailbox.read_ids.insert(id);
            }
            self.update_push_count(session, mailbox.unread_count());
        }
    }

    pub(super) fn push_read(&self, call: &Call) -> Option<Reply> {
        if !self.mail_cache_ready()
            || call.method != "GET"
            || !call.path.starts_with("/api/v1/bus/inbox?")
        {
            return None;
        }
        let open = call.path.contains("open=true");
        if !open && call.path.contains("all=true") {
            return None;
        }
        if self.seed_push_mail(&call.session).is_err() {
            return None;
        }
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        let mailbox = push.mailboxes.get(&call.session)?;
        if open && !mailbox.open_known {
            return None;
        }
        let messages: Vec<_> = if open {
            mailbox.open.values().collect()
        } else {
            mailbox.unread.values().collect()
        };
        Some(Reply {
            value: Some(
                json!({"messages":messages,"skipped": if open { i64::from(mailbox.open_truncated) } else { mailbox.skipped }}),
            ),
            source: Some(Source::View),
            ..Reply::default()
        })
    }

    fn push_session_event(&self, event: &Event) {
        if event.kind.is_empty() {
            return;
        }
        let sessions: Vec<_> = self.sessions().keys().cloned().collect();
        for session in sessions {
            // Mail is routed by the authenticated envelope, never by group strings in payload.
            let routed = if event.kind.starts_with("bus.") {
                addressed(event, &session)
            } else {
                event.rest.get("session").and_then(Value::as_str) == Some(session.as_str())
                    || event.field("to").and_then(Value::as_str) == Some(session.as_str())
            };
            if !routed {
                continue;
            }
            let acked = {
                let name = format!(
                    "cursor-session-{}",
                    lockyard_cloud_client::token_id(&session)
                );
                *self
                    .session_event_cursors
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entry(session.clone())
                    .or_insert_with(|| load_seq(&self.state_dir, &name))
            };
            let mut caches = self
                .session_events
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let cache = caches.entry(session).or_default();
            cache.after = cache.after.max(acked);
            if event.seq > cache.after && !cache.events.iter().any(|e| e.seq == event.seq) {
                cache.events.push_back(event.clone());
            }
            while cache.events.len() > SESSION_EVENT_CACHE {
                if let Some(event) = cache.events.pop_front() {
                    cache.after = cache.after.max(event.seq);
                }
            }
        }
    }

    fn push_event(&self, event: Event) -> bool {
        let accepted = self.apply_push_event(event);
        if !accepted {
            self.invalidate_event_views();
        }
        accepted
    }

    fn apply_push_event(&self, event: Event) -> bool {
        self.observe_zone_loss(&event);
        if matches!(event.kind.as_str(), "bus.delivery_claimed" | "bus.imported") {
            return true;
        }
        if event.kind == "bus.unread" {
            // Metadata notification only; bus.message and snapshots own unread delivery.
            return event.payload.as_object().is_some_and(|p| {
                p.iter().all(|(name, v)| match name.as_str() {
                    "id" | "thread_id" => v.as_i64().is_some(),
                    "reply_to" => v.is_null() || v.as_i64().is_some(),
                    "urgent" => v.is_boolean(),
                    "from" | "from_alias" | "to" | "address" | "kind" | "needs" | "created_at"
                    | "role" => v.is_null() || v.is_string(),
                    _ => false,
                })
            });
        }
        if !event.kind.starts_with("bus.") {
            if !known_event(&event.kind) {
                return false;
            }
            self.push_session_event(&event);
            self.apply_events(&EventPage {
                events: vec![event],
            });
            return true;
        }
        let Some(target) = event.rest.get("session").and_then(Value::as_str) else {
            return false;
        };
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if event.kind == "bus.message" {
            // Deserialize even replay/sender copies, so malformed numeric ids are logged.
            if event.payload.get("id").and_then(Value::as_i64).is_none()
                || event
                    .payload
                    .get("thread_id")
                    .and_then(Value::as_i64)
                    .is_none()
                || !matches!(
                    event.payload.get("role").and_then(Value::as_str),
                    Some("recipient" | "sender")
                )
            {
                return false;
            }
            let Ok(mail) = serde_json::from_value::<Message>(event.payload.clone()) else {
                return false;
            };
            if let Some(parent) = mail.reply_to {
                // Both recipient and sender copies close the answered parent for this session.
                let mailbox = push.mailboxes.entry(target.into()).or_default();
                mailbox.open.remove(&parent);
                mailbox.handled_ids.insert(parent);
            }
            if (self.push_ready.load(Ordering::Acquire)
                || push.mailboxes.get(target).is_some_and(|m| m.seeded))
                && addressed(&event, target)
            {
                push.arrivals
                    .push_back((event.seq, target.into(), mail.clone()));
                while push.arrivals.len() > 2048 {
                    push.arrivals.pop_front();
                }
                let mailbox = push.mailboxes.entry(target.into()).or_default();
                if !mailbox.handled_ids.contains(&mail.id) && is_personal_open(&mail, target) {
                    mailbox.open.insert(mail.id, mail.clone());
                }
                if !mailbox.read_ids.contains(&mail.id) && !mailbox.handled_ids.contains(&mail.id) {
                    mailbox.sequences.insert(mail.id, event.seq);
                    mailbox.unread.insert(mail.id, mail);
                }
            }
        } else if matches!(event.kind.as_str(), "bus.seen" | "bus.handled" | "bus.ack") {
            let ids: Vec<i64> = if event.kind == "bus.ack" {
                let Some(id) = event.payload.get("id").and_then(Value::as_i64) else {
                    return false;
                };
                vec![id]
            } else {
                let key = if event.kind == "bus.seen" {
                    "seen"
                } else {
                    "handled"
                };
                let Some(ids) = event.payload.get(key).and_then(Value::as_array) else {
                    return false;
                };
                let Some(ids) = ids.iter().map(Value::as_i64).collect::<Option<Vec<_>>>() else {
                    return false;
                };
                ids
            };
            let mailbox = push.mailboxes.entry(target.into()).or_default();
            for id in ids {
                mailbox.unread.remove(&id);
                mailbox.read_ids.insert(id);
                if event.kind != "bus.seen" {
                    mailbox.open.remove(&id);
                    mailbox.handled_ids.insert(id);
                }
            }
        } else {
            return false;
        }
        for (session, mailbox) in &push.mailboxes {
            self.update_push_count(session, mailbox.unread_count());
        }
        drop(push);
        self.push_session_event(&event);
        self.mail_ready.notify_all();
        self.nudge();
        true
    }

    pub(super) fn interrupt_push(&self) {
        self.push_ready.store(false, Ordering::Release);
        if let Some(interrupt) = self
            .stream_interrupt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            interrupt.store(true, Ordering::Release);
        }
        self.mail_ready.notify_all();
    }

    pub(super) fn active_push_sessions(&self) -> Vec<String> {
        let waiting: HashSet<_> = self
            .push
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .waiters
            .keys()
            .cloned()
            .collect();
        let mut sessions: Vec<_> = self
            .sessions()
            .iter()
            .filter(|(name, track)| {
                track.push_bound
                    && (waiting.contains(*name)
                        || track
                            .heard
                            .is_some_and(|at| at.elapsed() < self.timing().active_window))
            })
            .map(|(name, _)| name.clone())
            .collect();
        sessions.sort();
        sessions.truncate(32);
        sessions
    }

    pub(super) fn confirm_session_binding(&self, call: &Call) {
        // Ordinary coordination routes bind the header session during server admission.
        // Discovery and multi-session streams deliberately do not bind it.
        let route = call.path.split('?').next().unwrap_or_default();
        if !route.starts_with("/api/v1/")
            || route == "/api/v1/protocol"
            || (route == "/api/v1/events" && call.path.contains("sessions="))
        {
            return;
        }
        self.push
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bound_sessions
            .insert(call.session.clone());
        let changed = {
            let mut sessions = self.sessions();
            let track = sessions.entry(call.session.clone()).or_default();
            let changed = !track.push_bound;
            track.push_bound = true;
            changed
        };
        if changed {
            self.interrupt_push();
            self.nudge();
        }
    }

    fn advance_push_cursor(&self, seq: i64) {
        if seq > self.coordination_seq.load(Ordering::Relaxed) {
            if let Err(error) = save_seq(&self.state_dir, "coordination", seq) {
                eprintln!("lockyard agent: cannot save SSE cursor: {error}");
            }
            self.coordination_seq.store(seq, Ordering::Relaxed);
        }
    }

    fn push_now(&self) -> Instant {
        self.push
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .now()
    }

    fn replacement_allows_stream(&self, sessions: &[String]) -> bool {
        let now = self.push_now();
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if push
            .replacement
            .as_ref()
            .is_some_and(|r| r.sessions != sessions)
        {
            push.replacement = None;
        }
        push.replacement
            .as_ref()
            .is_none_or(|r| !r.retried && now >= r.retry_at)
    }

    fn stream_replaced(&self, sessions: Vec<String>, started: Instant) {
        let now = self.push_now();
        let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        let retried = push
            .replacement
            .as_ref()
            .is_some_and(|r| r.sessions == sessions)
            && now.saturating_duration_since(started) <= Duration::from_secs(10 * 60);
        push.replacement = Some(Replacement {
            sessions,
            retry_at: now + Duration::from_secs(60),
            retried,
        });
    }

    /// Returns on endpoint incompatibility / repeated failures, so discovery and long-poll
    /// can resume on this same coordination worker.
    fn push_stream(&self) -> PushExit {
        let mut exit = PushExit::Unavailable;
        let mut pause = self.timing().retry_min;
        let mut failures = 0;
        while !self.stopped() {
            let sessions = self.active_push_sessions();
            // Set changes on an already running stream also reset displacement history.
            if !self.replacement_allows_stream(&sessions) {
                exit = PushExit::Replaced;
                break;
            }
            if sessions.is_empty() {
                self.pause(Duration::from_millis(100));
                continue;
            }
            self.push_ready.store(false, Ordering::Release);
            {
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                let changed = sessions.iter().cloned().collect::<HashSet<_>>() != push.subscribed;
                let subscribed = push.subscribed.clone();
                push.epoch += 1;
                push.arrivals.clear();
                for (session, mailbox) in &mut push.mailboxes {
                    if !changed || !subscribed.contains(session) || !sessions.contains(session) {
                        mailbox.seeded = false;
                    }
                }
            }
            let after = self.coordination_seq.load(Ordering::Relaxed);
            let interrupt = Arc::new(AtomicBool::new(false));
            *self
                .stream_interrupt
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(interrupt.clone());
            if self.stopped() || self.active_push_sessions() != sessions {
                interrupt.store(true, Ordering::Release);
            }
            let stream = self.transport.event_stream_sessions(
                &self.session,
                &sessions,
                after,
                interrupt.clone(),
            );
            match stream {
                Ok(mut stream) => {
                    // A successful handshake resets the delay even if the stream stays idle.
                    pause = self.timing().retry_min;

                    if self.stopped() || self.active_push_sessions() != sessions {
                        interrupt.store(true, Ordering::Release);
                    }
                    let started = self.push_now();
                    let mut ready = false;
                    let mut replaced = false;
                    while !self.stopped() && !interrupt.load(Ordering::Acquire) {
                        let frame = match stream.next_frame() {
                            Ok(Some(frame)) => frame,
                            Ok(None) => break,
                            Err(error) => {
                                if !interrupt.load(Ordering::Acquire) {
                                    eprintln!("lockyard agent: SSE read: {error}");
                                }
                                break;
                            }
                        };
                        if self.active_push_sessions() != sessions {
                            interrupt.store(true, Ordering::Release);
                            break;
                        }
                        if frame.event == "replaced" && frame.invalid.is_none() {
                            replaced = true;
                            eprintln!("lockyard agent: другой демон того же токена держит поток");
                            break;
                        }
                        let frame_seq = frame.id.as_deref().and_then(|id| id.parse::<i64>().ok());
                        if frame.event == "ready" && frame.invalid.is_none() {
                            let head = serde_json::from_str::<Value>(&frame.data)
                                .ok()
                                .and_then(|v| v["head"].as_i64());
                            if let Some(head) = head.filter(|head| Some(*head) == frame_seq) {
                                self.advance_push_cursor(head);
                                let mut push =
                                    self.push.lock().unwrap_or_else(PoisonError::into_inner);
                                push.subscribed = sessions.iter().cloned().collect();
                                // Recheck waiting paths after ready closes the subscription race.
                                push.zone_version += 1;
                                self.push_ready.store(true, Ordering::Release);
                                drop(push);
                                ready = true;
                                failures = 0;
                                self.nudge();
                                self.mail_ready.notify_all();
                            } else {
                                self.invalidate_event_views();
                                eprintln!("lockyard agent: skipping invalid SSE ready frame");
                                if let Some(seq) = frame_seq {
                                    self.advance_push_cursor(seq);
                                }
                            }
                            continue;
                        }
                        let decoded = frame.decode().and_then(|event| {
                            if let Some(mut event) = event {
                                self.transport.decode_stream_event(&mut event)?;
                                Ok(Some(event))
                            } else {
                                Ok(None)
                            }
                        });
                        match decoded {
                            Ok(Some(event)) => {
                                let seq = frame_seq.unwrap_or(event.seq);
                                if seq > self.coordination_seq.load(Ordering::Relaxed)
                                    && !self.push_event(event)
                                {
                                    eprintln!(
                                        "lockyard agent: skipping malformed or unsupported SSE event at {seq}"
                                    );
                                }
                                self.advance_push_cursor(seq);
                            }
                            Ok(None) if frame.id.is_none() && frame.event.is_empty() => {
                                self.confirm_push_counts()
                            }
                            Ok(None) => {
                                self.invalidate_event_views();
                                if let Some(seq) = frame_seq {
                                    self.advance_push_cursor(seq);
                                }
                            }
                            Err(error) if !matches!(error, ClientError::Decode(_)) => {
                                // Content/key errors must replay this frame after backoff.
                                // Until replay, the unapplied mutation cannot leave a fresh view.
                                self.invalidate_event_views();
                                eprintln!("lockyard agent: SSE content unavailable: {error}");
                                break;
                            }
                            Err(error) => {
                                self.invalidate_event_views();
                                eprintln!("lockyard agent: skipping malformed SSE frame: {error}");
                                if let Some(seq) = frame_seq {
                                    self.advance_push_cursor(seq);
                                }
                            }
                        }
                    }
                    *self
                        .stream_interrupt
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = None;
                    self.push_ready.store(false, Ordering::Release);
                    if interrupt.load(Ordering::Acquire) {
                        continue;
                    }
                    if replaced {
                        self.stream_replaced(sessions, started);
                        exit = PushExit::Replaced;
                        // Return to coordination JSON long-poll during cooldown and
                        // indefinitely after a second displacement of this session set.
                        break;
                    }
                    if !ready {
                        failures += 1;
                    }
                }
                Err(error) => {
                    *self
                        .stream_interrupt
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = None;
                    if interrupt.load(Ordering::Acquire) {
                        continue;
                    }
                    if let ClientError::Denied(api) = &error
                        && api.status == 403
                        && let Some(foreign) = api.details.get("sessions").and_then(Value::as_array)
                    {
                        {
                            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                            for name in foreign.iter().filter_map(Value::as_str) {
                                push.bound_sessions.remove(name);
                            }
                        }
                        let mut tracks = self.sessions();
                        let mut removed = false;
                        for name in foreign.iter().filter_map(Value::as_str) {
                            if sessions.iter().any(|s| s == name)
                                && let Some(track) = tracks.get_mut(name)
                            {
                                track.push_bound = false;
                                removed = true;
                            }
                        }
                        drop(tracks);
                        if removed {
                            self.nudge();
                            continue;
                        }
                    }
                    let incompatible = matches!(&error, ClientError::Decode(_))
                        || matches!(
                            &error,
                            ClientError::NotFound(_)
                                | ClientError::Http(lockyard_cloud_client::ApiError {
                                    status: 404 | 406,
                                    ..
                                })
                        );
                    eprintln!("lockyard agent: SSE connect: {error}");
                    if incompatible {
                        break;
                    }
                    failures += 1;
                }
            }
            if failures >= 5 {
                break;
            }
            let jitter = u64::from_le_bytes(
                lockyard_cloud_client::ulid().as_bytes()[18..26]
                    .try_into()
                    .unwrap(),
            ) % 101;
            let delay = pause
                .mul_f64(0.75 + jitter as f64 / 200.0)
                .min(Duration::from_secs(30));
            #[cfg(test)]
            let scheduled = {
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(delays) = &mut push.reconnect_delays {
                    delays.push(delay);
                    true
                } else {
                    false
                }
            };
            #[cfg(not(test))]
            let scheduled = false;
            if !scheduled {
                self.pause(delay);
            }
            pause = (pause * 2).min(Duration::from_secs(30));
        }
        self.push_ready.store(false, Ordering::Release);
        self.push_enabled.store(false, Ordering::Release);
        self.mail_ready.notify_all();
        exit
    }

    pub(super) fn coordination_loop(&self) {
        self.coordination_loop_with_interval(Duration::from_secs(600));
    }

    fn coordination_loop_with_interval(&self, interval: Duration) {
        let mut next_discovery = self.push_now();
        let mut fallback_until = None;
        let mut first_discovery = true;
        let mut pause = self.timing().retry_min;
        while !self.stopped() {
            if self.push_now() >= next_discovery {
                let discovery = if first_discovery {
                    self.transport.mail_push_v1(&self.session)
                } else {
                    self.transport.renegotiate_mail_push(&self.session)
                };
                match discovery {
                    Ok(supported) => {
                        first_discovery = false;
                        self.mail_protocol
                            .store(i64::from(supported), Ordering::Release);
                        self.mail_ready.notify_all();
                        next_discovery = self.push_now() + interval;
                    }
                    Err(error) => {
                        eprintln!("lockyard agent: mail protocol discovery: {error}");
                        next_discovery = self.push_now() + self.timing().retry_min;
                    }
                }
            }
            if self.mail_protocol.load(Ordering::Acquire) == 1
                && fallback_until.is_none_or(|until| self.push_now() >= until)
                && self.replacement_allows_stream(&self.active_push_sessions())
            {
                self.push_fallback.store(false, Ordering::Release);
                self.push_enabled.store(true, Ordering::Release);
                let exit = self.push_stream();
                if self.stopped() {
                    return;
                }
                self.push_fallback.store(true, Ordering::Release);
                self.nudge();
                if matches!(exit, PushExit::Unavailable) {
                    // Incompatibility/failures renegotiate immediately, then retain JSON
                    // for the discovery interval even if push remains advertised.
                    fallback_until = Some(self.push_now() + interval);
                    next_discovery = self.push_now();
                } else {
                    // Replacement has its own retry policy, independent of discovery.
                    fallback_until = None;
                }
                continue;
            }
            let replacement_pending = self
                .push
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .replacement
                .is_some();
            let query = EventQuery {
                stream: Stream::Coordination,
                after: self.coordination_seq.load(Ordering::Relaxed),
                wait_seconds: self
                    .timing()
                    .poll_wait_seconds
                    .min(if replacement_pending { 1 } else { u64::MAX })
                    .min(
                        next_discovery
                            .saturating_duration_since(self.push_now())
                            .as_secs(),
                    ),
                session: Some(self.session.clone()),
                types: Vec::new(),
            };
            let started = Instant::now();
            match self.backend(&self.session).events(&query) {
                Ok(page) => {
                    pause = self.timing().retry_min;
                    let seq = page.last_seq(query.after);
                    if self.push_fallback.load(Ordering::Acquire) {
                        for event in page.events.iter().filter(|e| e.kind.starts_with("bus.")) {
                            if !self.push_event(event.clone()) {
                                eprintln!(
                                    "lockyard agent: skipping malformed fallback mail event at {}",
                                    event.seq
                                );
                            }
                        }
                    }
                    self.apply_events(&page);
                    self.advance_push_cursor(seq);
                    if started.elapsed() < pause {
                        self.pause(pause);
                    }
                }
                Err(error) => {
                    if matches!(error, Error::Invalid(_) | Error::Protocol(_)) {
                        self.invalidate_event_views();
                    }
                    self.pause(pause);
                    pause = (pause * 2).min(self.timing().retry_max.min(MAX_POLL_PAUSE));
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::agent::socket::AgentSocket;
    use lockyard_cloud_client::{
        Client,
        fake::{FakeServer, Reply as HttpReply},
    };
    use std::sync::mpsc;

    const EVENT_TIMEOUT: Duration = Duration::from_secs(30);

    struct Rig {
        daemon: Daemon<Client>,
        server: FakeServer,
        _dir: tempfile::TempDir,
    }
    #[track_caller]
    fn eventually(mut test: impl FnMut() -> bool) {
        let until = Instant::now() + EVENT_TIMEOUT;
        while !test() {
            assert!(Instant::now() < until, "condition timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn mail_reply_without_needs_is_closed_but_wakes_the_asker() {
        let mut mail: Message = serde_json::from_value(
            json!({"id":1,"from":"bob","to":"alice","reply_to":9,"needs":"none","body":"Принято"}),
        )
        .unwrap();
        assert!(wakes(&mail, "alice"));
        assert!(!is_personal_open(&mail, "alice"));
        mail.needs = Some("ack".into());
        assert!(wakes(&mail, "alice"));
        assert!(is_personal_open(&mail, "alice"));
        mail.needs = None;
        mail.urgent = true;
        assert!(wakes(&mail, "alice"));
        assert!(!is_personal_open(&mail, "alice"));
    }

    fn rig(push: bool, pending: Option<Value>) -> Rig {
        rig_with(push, pending, |_, _| {})
    }
    fn rig_with(
        push: bool,
        pending: Option<Value>,
        setup: impl FnOnce(&FakeServer, &AgentConfig),
    ) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let server = FakeServer::start_routed_with_headers_and_capabilities(
            if push {
                vec![(
                    "Lockyard-Capabilities".into(),
                    "mail_push_v1,mail_open_v1".into(),
                )]
            } else {
                Vec::new()
            },
            if push {
                &["mail_push_v1", "mail_open_v1"]
            } else {
                &[]
            },
        );
        if let Some(mail) = pending {
            for _ in 0..2 {
                server.enqueue(
                    "/api/v1/bus/inbox",
                    HttpReply::json(200, json!({"messages":[mail.clone()],"skipped":0})),
                );
            }
        }
        let config = AgentConfig {
            url: server.url(),
            workspace: "test".into(),
            token_id: "test".into(),
            credential_proof: None,
            credential_product: super::super::CredentialProduct::Agent,
            socket: dir.path().join("run/agent.sock"),
            state_root: dir.path().join("state"),
            timing: Timing {
                retry_min: Duration::from_millis(5),
                poll_wait_seconds: 25,
                upkeep: Duration::from_secs(60),
                ..Timing::default()
            },
        };
        setup(&server, &config);
        for session in ["alice", "bob", "charlie"] {
            server.bind_session(session, "test-token");
        }
        let daemon = Daemon::start(
            config,
            Client::new(&server.url(), "test-token".into()).unwrap(),
        )
        .unwrap();
        for session in ["alice", "bob", "charlie"] {
            daemon
                .shared
                .push
                .lock()
                .unwrap()
                .bound_sessions
                .insert(session.into());
            daemon
                .shared
                .sessions()
                .entry(session.into())
                .or_default()
                .push_bound = true;
        }
        if push {
            eventually(|| daemon.shared.push_enabled.load(Ordering::Acquire));
        }
        Rig {
            daemon,
            server,
            _dir: dir,
        }
    }
    fn socket(rig: &Rig) -> AgentSocket {
        AgentSocket::connect(
            &rig.daemon.shared.config.socket,
            &rig.server.url(),
            "test",
            EVENT_TIMEOUT,
        )
        .unwrap()
    }
    fn mail(id: i64, to: &str, urgent: bool, needs: &str) -> Value {
        json!({"id":id,"thread_id":id,"reply_to":null,"from":"bob","from_alias":"Боб","to":to,"address":null,"role":"recipient","kind":"ask","urgent":urgent,"needs":needs,"body":"hello"})
    }
    fn publish(rig: &Rig, seq: i64, value: Value) {
        let target = value["to"].as_str().unwrap().to_string();
        publish_to(rig, seq, &target, value);
    }
    fn publish_to(rig: &Rig, seq: i64, session: &str, value: Value) {
        rig.server.enqueue(
            "/api/v1/events",
            HttpReply::sse(&format!(
                "id: {seq}\nevent: bus.message\ndata: {}\n\n",
                json!({"seq":seq,"type":"bus.message","session":session,"payload":value})
            )),
        );
        eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) >= seq);
    }
    fn receipt(rig: &Rig, seq: i64, kind: &str, session: &str, payload: Value) {
        rig.server.enqueue(
            "/api/v1/events",
            HttpReply::sse(&format!(
                "id: {seq}\nevent: {kind}\ndata: {}\n\n",
                json!({"seq":seq,"type":kind,"session":session,"payload":payload})
            )),
        );
        eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) >= seq);
    }
    fn waiting(
        rig: &Rig,
        session: &str,
        timeout: Duration,
    ) -> (mpsc::Receiver<Reply>, JoinHandle<()>) {
        let socket = socket(rig);
        let session = session.to_string();
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let reply = socket.wait_mail(&session, 0, timeout).unwrap_or_default();
            sent.send(reply).unwrap();
        });
        (received, worker)
    }
    fn seeded(rig: &Rig, session: &str) {
        eventually(|| {
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .mailboxes
                .get(session)
                .is_some_and(|m| m.seeded)
        });
    }

    #[test]
    fn mail_push_wait_urgent_reply_ack_info_and_cache_without_polling() {
        for (urgent, needs) in [(true, "none"), (false, "reply"), (false, "ack")] {
            let rig = rig(true, None);
            let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
            seeded(&rig, "alice");
            let reads = rig
                .server
                .requests()
                .iter()
                .filter(|r| r.method == "GET" && r.path.starts_with("/api/v1/bus/inbox"))
                .count();
            publish_to(&rig, 1, "alice", mail(1, "*", false, "reply"));
            assert!(
                received.try_recv().is_err(),
                "nonurgent broadcast must not wake"
            );
            publish(&rig, 2, mail(2, "other", true, "reply"));
            assert!(
                received.try_recv().is_err(),
                "another recipient must not wake"
            );
            publish(&rig, 3, mail(3, "alice", urgent, needs));
            let reply = received.recv_timeout(EVENT_TIMEOUT).unwrap();
            worker.join().unwrap();
            assert_eq!(reply.messages.unwrap()[0].id, 3);
            assert_eq!(rig.daemon.shared.unread("alice").unread, Some(2));
            assert!(
                rig.daemon
                    .shared
                    .push_open_snapshot("alice")
                    .unwrap()
                    .items
                    .iter()
                    .any(|m| m.id == 3)
            );
            assert_eq!(
                reads,
                rig.server
                    .requests()
                    .iter()
                    .filter(|r| r.method == "GET" && r.path.starts_with("/api/v1/bus/inbox"))
                    .count()
            );
            assert!(
                !rig.server
                    .requests()
                    .iter()
                    .any(|r| r.method == "POST" && r.path.contains("seen"))
            );
        }
    }

    #[test]
    fn round6_mail_push_sse_wake_matrix() {
        for (kind, needs, reply_to, to, address, urgent, wake, open) in [
            ("info", "none", None, "alice", None, false, true, false),
            ("ask", "none", Some(9), "alice", None, false, true, false),
            ("ask", "reply", None, "alice", None, false, true, true),
            ("ask", "reply", None, "*", None, false, false, false),
            ("info", "none", None, "*", None, true, true, false),
            (
                "ask",
                "reply",
                None,
                "alice",
                Some("@codex"),
                false,
                false,
                false,
            ),
        ] {
            let rig = rig(true, None);
            let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
            seeded(&rig, "alice");
            let mut value = mail(42, to, urgent, needs);
            value["status"] = json!("open");
            value["kind"] = json!(kind);
            value["reply_to"] = json!(reply_to);
            value["address"] = json!(address);
            publish_to(&rig, 1, "alice", value);
            assert_eq!(
                rig.daemon
                    .shared
                    .push_open_snapshot("alice")
                    .unwrap()
                    .items
                    .len(),
                usize::from(open),
                "kind={kind}, to={to}, urgent={urgent}"
            );
            if wake {
                let reply = received.recv_timeout(EVENT_TIMEOUT).unwrap();
                assert_eq!(reply.messages.as_ref().unwrap()[0].id, 42);
                assert!(crate::mail_wait::outcome(reply, "alice").is_some());
            } else {
                // A newer personal message releases the waiter; its id proves the
                // preceding broadcast was ignored without a timing-only assertion.
                publish(&rig, 2, mail(43, "alice", false, "reply"));
                let reply = received.recv_timeout(EVENT_TIMEOUT).unwrap();
                assert_eq!(reply.messages.unwrap()[0].id, 43);
            }
            worker.join().unwrap();
        }
    }

    #[test]
    fn round6_mail_push_snapshot_personal_wait_exits_two_once() {
        for fallback in [false, true] {
            for (kind, reply_to) in [("info", None), ("ask", Some(9)), ("ask", None)] {
                let mut value = mail(42, "alice", false, "none");
                value["kind"] = json!(kind);
                value["status"] = json!("open");
                value["reply_to"] = json!(reply_to);
                let rig = rig(true, Some(value));
                if fallback {
                    rig.daemon
                        .shared
                        .push_enabled
                        .store(false, Ordering::Release);
                }
                assert_eq!(
                    crate::mail_wait::wait_on(&socket(&rig), "alice", EVENT_TIMEOUT),
                    2,
                    "fallback={fallback}, kind={kind}, reply_to={reply_to:?}"
                );
                assert_eq!(
                    crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_millis(50)),
                    0,
                    "the same unread letter must not wake twice"
                );
                assert_eq!(rig.daemon.shared.unread("alice").unread, Some(1));
            }
        }
    }

    #[test]
    fn mail_push_wait_existing_is_immediate_and_does_not_mark_read() {
        let rig = rig(true, Some(mail(42, "alice", true, "none")));
        let reply = socket(&rig)
            .wait_mail("alice", 0, Duration::from_secs(2))
            .unwrap();
        assert_eq!(reply.messages.unwrap()[0].id, 42);
        // A text-only reply to the hook does not mark seen, but must not wake forever.
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_millis(100))
                .unwrap()
                .messages
                .is_none()
        );
        rig.daemon.shared.push.lock().unwrap().woken.clear(); // reload the persisted cursor
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_millis(100))
                .unwrap()
                .messages
                .is_none()
        );
        publish(&rig, 43, mail(43, "alice", true, "reply"));
        assert_eq!(
            socket(&rig)
                .wait_mail("alice", 0, EVENT_TIMEOUT)
                .unwrap()
                .messages
                .unwrap()[0]
                .id,
            43
        );
        publish(&rig, 44, mail(41, "alice", true, "reply"));
        assert_eq!(
            socket(&rig)
                .wait_mail("alice", 0, EVENT_TIMEOUT)
                .unwrap()
                .messages
                .unwrap()[0]
                .id,
            41
        );
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_millis(50))
                .unwrap()
                .messages
                .is_none()
        );
        assert!(
            !rig.server
                .requests()
                .iter()
                .any(|r| r.path.contains("seen"))
        );
    }

    #[test]
    fn mail_push_wait_timeout_and_replacement_are_silent() {
        let rig = rig(true, None);
        let (old, first) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        eventually(|| {
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .waiters
                .contains_key("alice")
        });
        let token = rig.daemon.shared.push.lock().unwrap().waiters["alice"];
        let (new, second) = waiting(&rig, "alice", Duration::from_millis(500));
        eventually(|| rig.daemon.shared.push.lock().unwrap().next_waiter > token);
        assert!(
            crate::mail_wait::outcome(old.recv_timeout(EVENT_TIMEOUT).unwrap(), "alice").is_none()
        );
        first.join().unwrap();
        assert!(
            crate::mail_wait::outcome(new.recv_timeout(EVENT_TIMEOUT).unwrap(), "alice").is_none()
        );
        second.join().unwrap();
        eventually(|| {
            !rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .waiters
                .contains_key("alice")
        });
    }

    #[test]
    fn mail_push_sse_reconnect_last_event_id_and_no_session_polls() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        publish(&rig, 7, mail(70, "alice", true, "none"));
        received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        rig.daemon.shared.hear("charlie");
        eventually(|| {
            rig.server
                .requests()
                .iter()
                .any(|r| r.header("last-event-id") == Some("7"))
        });
        let requests = rig.server.requests();
        let streams: Vec<_> = requests
            .iter()
            .filter(|r| {
                r.path.starts_with("/api/v1/events")
                    && r.header("accept") == Some("text/event-stream")
            })
            .collect();
        assert_eq!(
            streams.len(),
            2,
            "one stream, reopened only for the changed set"
        );
        assert!(streams[0].path.contains("sessions=alice"));
        assert!(streams[1].path.contains("sessions=alice%2Ccharlie"));
        eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
        let session_polls = || {
            rig.server
                .requests()
                .iter()
                .filter(|r| {
                    r.path.starts_with("/api/v1/events")
                        && r.header("accept") != Some("text/event-stream")
                })
                .count()
        };
        let reads = session_polls();
        rig.daemon.shared.refresh_session_events();
        assert_eq!(
            reads,
            session_polls(),
            "ready stream replaces session event polls"
        );
        rig.daemon
            .shared
            .sessions()
            .get_mut("charlie")
            .unwrap()
            .heard = Some(
            Instant::now() - rig.daemon.shared.timing().active_window - Duration::from_secs(1),
        );
        eventually(|| {
            rig.server
                .requests()
                .iter()
                .filter(|r| r.header("accept") == Some("text/event-stream"))
                .count()
                == 3
        });
        let last = rig
            .server
            .requests()
            .into_iter()
            .rev()
            .find(|r| r.header("accept") == Some("text/event-stream"))
            .unwrap();
        assert!(last.path.contains("sessions=alice&"));
        assert_eq!(last.header("last-event-id"), Some("7"));
        assert!(
            rig.server
                .requests()
                .iter()
                .chain(rig.server.discovery_requests().iter())
                .all(|r| r.header("x-lockyard-capabilities") == Some("mail_push_v1"))
        );
    }

    #[test]
    fn mail_push_old_server_uses_long_poll_and_wait_returns_empty() {
        let rig = rig(false, None);
        eventually(|| {
            rig.server
                .requests()
                .iter()
                .any(|r| r.path.starts_with("/api/v1/events"))
        });
        assert!(
            rig.server
                .requests()
                .iter()
                .filter(|r| r.path.starts_with("/api/v1/events"))
                .all(|r| r.header("accept") != Some("text/event-stream")
                    && r.path.contains("wait=25"))
        );
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_secs(1))
                .unwrap()
                .messages
                .is_none()
        );
    }

    #[test]
    fn mail_push_envelope_recipient_groups_and_sender_copy() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        let mut group = mail(1, "*", true, "reply");
        group["address"] = "@zone:client".into();
        // A group-looking payload addressed to another session cannot wake alice.
        publish_to(&rig, 1, "other", group.clone());
        let mut sender = group.clone();
        sender["role"] = "sender".into();
        publish_to(&rig, 2, "alice", sender);
        assert!(received.try_recv().is_err());
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
        group["id"] = json!(i64::from(i32::MAX) + 10);
        group["thread_id"] = json!(i64::from(i32::MAX) + 10);
        publish_to(&rig, 3, "alice", group);
        let reply = received.recv_timeout(EVENT_TIMEOUT).unwrap();
        assert_eq!(reply.messages.unwrap()[0].id, i64::from(i32::MAX) + 10);
        worker.join().unwrap();
    }
    #[test]
    fn mail_push_legacy_skipped_never_becomes_an_unread_count() {
        let rig = rig_with(true, None, |server, _| {
            let messages: Vec<_> = (1..=50)
                .map(|id| {
                    let mut row = mail(id, "alice", false, "reply");
                    row["reader_state"] = json!("seen");
                    row["seen_at"] = json!(123);
                    row
                })
                .collect();
            for _ in 0..2 {
                server.enqueue(
                    "/api/v1/bus/inbox",
                    HttpReply::json(200, json!({"messages":messages,"skipped":1})),
                );
            }
        });
        let (received, worker) = waiting(&rig, "alice", Duration::from_millis(100));
        seeded(&rig, "alice");
        received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert!(
            rig.daemon.shared.push.lock().unwrap().mailboxes["alice"]
                .unread
                .is_empty()
        );
        assert_eq!(rig.daemon.shared.unread("alice").unread, None);
        rig.daemon.shared.confirm_push_counts();
        rig.daemon.shared.push_seen("alice", Some(&json!([1])));
        assert_eq!(rig.daemon.shared.unread("alice").unread, None);
    }

    #[test]
    fn mail_push_seed_open_cache_excludes_group_address_even_with_recipient_to() {
        let mut group = mail(42, "alice", true, "reply");
        group["address"] = json!("@zone:client");
        let rig = rig(true, Some(group));
        assert_eq!(
            crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_secs(2)),
            2
        );
        let push = rig.daemon.shared.push.lock().unwrap();
        assert!(push.mailboxes["alice"].open.is_empty());
        drop(push);
        assert!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn mail_push_warm_open_cache_excludes_broadcasts_after_seen() {
        let rig = rig(true, Some(mail(42, "alice", true, "reply")));
        assert_eq!(
            crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_secs(2)),
            2
        );
        for (index, to) in ["*", "all", "@claude", "@zone:client", "@path:src"]
            .iter()
            .enumerate()
        {
            let id = 50 + index as i64;
            let mut group = mail(id, to, true, "reply");
            let seq = 2 + 2 * index as i64;
            group["address"] = json!(to);
            // SSE envelopes may normalize `to` to the recipient while retaining the address.
            if index % 2 == 0 {
                group["to"] = json!("alice");
            }
            publish_to(&rig, seq, "alice", group.clone());
            assert!(
                !rig.daemon.shared.push.lock().unwrap().mailboxes["alice"]
                    .open
                    .contains_key(&id)
            );
            receipt(&rig, seq + 1, "bus.seen", "alice", json!({"seen":[id]}));
            // Also simulate an older warm cache to prove filtering at read time.
            let parsed: Message = serde_json::from_value(group).unwrap();
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .mailboxes
                .get_mut("alice")
                .unwrap()
                .open
                .insert(id, parsed);
        }
        receipt(&rig, 20, "bus.seen", "alice", json!({"seen":[42]}));
        let snapshot = rig.daemon.shared.push_open_snapshot("alice").unwrap();
        assert_eq!(
            snapshot.items.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![42]
        );
    }

    #[test]
    fn mail_push_wait_exit_codes_and_seen_handled_cache_updates() {
        let rig = rig(true, Some(mail(42, "alice", true, "reply")));
        assert_eq!(
            crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_secs(2)),
            2
        );
        receipt(&rig, 2, "bus.seen", "alice", json!({"seen":[42]}));
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
        assert_eq!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .len(),
            1,
            "Stop must still see an unanswered question after it was shown"
        );
        assert_eq!(
            crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_millis(30)),
            0
        );
        receipt(&rig, 3, "bus.handled", "alice", json!({"handled":[42]}));
        publish(&rig, 4, mail(43, "alice", true, "reply"));
        receipt(&rig, 5, "bus.handled", "alice", json!({"handled":[43]}));
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
        assert!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .is_empty()
        );
        publish(&rig, 6, mail(44, "alice", true, "ack"));
        receipt(&rig, 7, "bus.ack", "alice", json!({"id":44}));
        assert!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn mail_push_seed_race_preserves_arrival_and_read_tombstone() {
        let rig = rig(true, None);
        let (release, gated) = mpsc::channel();
        rig.server.enqueue(
            "/api/v1/bus/inbox",
            HttpReply::json(
                200,
                json!({"messages":[mail(9,"alice",true,"reply")],"skipped":0}),
            )
            .gated(gated),
        );
        let (received, worker) = waiting(&rig, "alice", Duration::from_millis(500));
        eventually(|| {
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .mailboxes
                .get("alice")
                .is_some_and(|m| m.seeding)
        });
        rig.daemon.shared.push_event(
            serde_json::from_value(
                json!({"seq":1,"type":"bus.message","session":"alice","payload":mail(9,"alice",true,"reply")}),
            )
            .unwrap(),
        );
        rig.daemon.shared.push_event(
            serde_json::from_value(
                json!({"seq":2,"type":"bus.seen","session":"alice","payload":{"seen":[9]}}),
            )
            .unwrap(),
        );
        release.send(()).unwrap();
        seeded(&rig, "alice");
        assert!(
            crate::mail_wait::outcome(received.recv_timeout(EVENT_TIMEOUT).unwrap(), "alice")
                .is_none()
        );
        worker.join().unwrap();
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
    }

    fn round4_zone(seq: i64, kind: &str, id: i64, fence: i64, actor: Option<&str>) -> Event {
        let mut event = json!({"seq":seq,"type":kind,"session":"alice","payload":{"session":"alice","claim_id":id,"fence":fence,"paths":["src"],"reason":if kind == "zone.lost" {"taken"} else {"narrowed"}}});
        if let Some(actor) = actor {
            event["payload"]["by"] = json!(actor);
        }
        serde_json::from_value(event).unwrap()
    }

    #[test]
    fn round6_status_reacquisition_clears_loss_before_or_without_sse() {
        for with_sse in [false, true] {
            let mut rig = rig(true, None);
            rig.daemon.stop_workers();
            let shared = &rig.daemon.shared;
            shared.hear("alice");
            let backend = lockyard_cloud_client::CloudBackend::new(
                Client::new(&rig.server.url(), "test-token".into()).unwrap(),
                "alice",
            );
            let claim = |id| {
                serde_json::from_value::<Claim>(
                    json!({"id":id,"session":"alice","paths":["src"],"fence":1}),
                )
                .unwrap()
            };
            shared.observe_status_claims("alice", &[claim(42)], &backend, Duration::ZERO);
            shared.push_event(round4_zone(1, "zone.released", 42, 2, Some("bob")));
            shared.observe_status_claims("alice", &[claim(43)], &backend, Duration::ZERO);
            assert!(shared.push.lock().unwrap().zone_alerts["alice"].is_empty());
            if with_sse {
                let mut event = round4_zone(2, "zone.claimed", 43, 3, None);
                event.payload["reason"] = json!("claimed");
                shared.push_event(event);
                assert!(shared.take_zone_alerts("alice").is_empty());
            }
            shared.push_event(round4_zone(3, "zone.released", 43, 4, Some("bob")));
            shared.observe_status_claims("alice", &[claim(43)], &backend, Duration::ZERO);
            assert_eq!(shared.push.lock().unwrap().zone_alerts["alice"].len(), 1);
        }
    }

    #[test]
    fn status_reacquisition_clears_case_alias_alerts_only_under_folding_policy() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        let backend = lockyard_cloud_client::CloudBackend::new(
            Client::new(&rig.server.url(), "test-token".into()).unwrap(),
            "alice",
        );
        let mut lost = round4_zone(1, "zone.lost", 42, 2, None);
        lost.payload["paths"] = json!(["src/ſ/file.rs"]);
        shared.push_event(lost);
        for (id, policy, remaining) in [(43, None, 1), (44, Some(false), 1), (45, Some(true), 0)] {
            let claim = serde_json::from_value::<Claim>(json!({
                "id": id, "session": "alice", "paths": ["src/s"],
                "case_insensitive_paths": policy
            }))
            .unwrap();
            shared.observe_status_claims("alice", &[claim], &backend, Duration::ZERO);
            assert_eq!(shared.zone_alerts("alice").len(), remaining, "{policy:?}");
        }
    }

    #[test]
    fn zone_acquisition_events_clear_case_alias_alerts_only_under_folding_policy() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        let mut lost = round4_zone(1, "zone.lost", 42, 2, None);
        lost.payload["paths"] = json!(["src/ſ/file.rs"]);
        shared.push_event(lost);
        for (seq, policy, remaining) in [(2, None, 1), (3, Some(false), 1), (4, Some(true), 0)] {
            let mut claimed = round4_zone(seq, "zone.claimed", 42 + seq, 3, None);
            claimed.payload["reason"] = json!("claimed");
            claimed.payload["paths"] = json!(["src/s"]);
            if let Some(policy) = policy {
                claimed.payload["case_insensitive_paths"] = json!(policy);
            }
            shared.push_event(claimed);
            assert_eq!(shared.zone_alerts("alice").len(), remaining, "{policy:?}");
        }
    }

    #[test]
    fn round5_same_claim_mutations_and_restart_snapshot_do_not_clear_loss() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        shared.push_event(round4_zone(1, "zone.released", 42, 2, Some("bob")));
        for (seq, reason) in [
            (2, "renewed"),
            (3, "meta_updated"),
            (4, "add_path"),
            (5, "claimed"),
        ] {
            let mut event = round4_zone(seq, "zone.claimed", 42, seq, None);
            event.payload["reason"] = json!(reason);
            shared.push_event(event);
            assert_eq!(
                shared.push.lock().unwrap().zone_alerts["alice"].len(),
                1,
                "{reason}"
            );
        }
        let claim: Claim =
            serde_json::from_value(json!({"id":42,"session":"alice","paths":["src"],"fence":1}))
                .unwrap();
        let backend = lockyard_cloud_client::CloudBackend::new(
            Client::new(&rig.server.url(), "test-token".into()).unwrap(),
            "alice",
        );
        shared.observe_status_claims("alice", &[claim], &backend, Duration::ZERO);
        assert_eq!(
            shared.push.lock().unwrap().zone_alerts["alice"].len(),
            1,
            "restart baseline"
        );
        // A repeated grant for a known id also cannot hide a later loss.
        let mut seen = round4_zone(6, "zone.granted", 42, 7, None);
        seen.payload["reason"] = json!("granted");
        shared.push_event(seen);
        assert_eq!(shared.push.lock().unwrap().zone_alerts["alice"].len(), 1);
        let mut fresh = round4_zone(7, "zone.claimed", 44, 8, None);
        fresh.payload["reason"] = json!("claimed");
        shared.push_event(fresh);
        assert!(shared.take_zone_alerts("alice").is_empty());
    }

    #[test]
    fn round5_multiple_own_fences_suppress_delayed_echoes() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        for fence in [1, 2] {
            let mutation = shared.begin_zone_mutation(&Call::write(
                "alice",
                "POST",
                "/api/v1/zones/claims/42/narrow".into(),
                json!({"fence":fence,"paths":["docs"]}),
            ));
            shared.finish_zone_mutation(mutation, Some(&json!({"fence":fence+1})));
        }
        shared.push_event(round4_zone(1, "zone.released", 42, 2, None));
        shared.push_event(round4_zone(2, "zone.released", 42, 3, None));
        assert!(
            shared.take_zone_alerts("alice").is_empty(),
            "first fence was overwritten"
        );
        shared.push_event(round4_zone(3, "zone.released", 42, 4, None));
        assert_eq!(shared.take_zone_alerts("alice").len(), 1);
    }

    #[test]
    fn round5_abandoned_unread_does_not_consume_attention() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        rig.daemon
            .shared
            .push_event(round4_zone(1, "zone.lost", 42, 2, None));
        for _ in 0..2 {
            let reply = rig.daemon.handle(Request::Unread {
                attention_ack: Vec::new(),
                session: "alice".into(),
                attention: true,
            });
            assert_eq!(reply.lost.unwrap().len(), 1, "socket closed before output");
        }
    }

    #[test]
    fn round5_fallback_loss_without_session_can_be_acknowledged() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        let backend = shared.backend("alice");
        let claim: Claim =
            serde_json::from_value(json!({"id":42,"session":"alice","paths":["src"]})).unwrap();
        shared.observe_status_claims("alice", &[claim], &backend, Duration::ZERO);
        rig.server.enqueue(
            "/api/v1/zones/lost",
            HttpReply::json(
                200,
                json!({"lost":[{"claim_id":42,"paths":["src"],"reason":"expired"}]}),
            ),
        );
        shared.observe_status_claims("alice", &[], &backend, EVENT_TIMEOUT);
        let printed = rig
            .daemon
            .handle(Request::Unread {
                session: "alice".into(),
                attention: true,
                attention_ack: Vec::new(),
            })
            .lost
            .unwrap();
        assert_eq!(printed.len(), 1);
        let after = rig.daemon.handle(Request::Unread {
            session: "alice".into(),
            attention: true,
            attention_ack: printed,
        });
        assert!(
            after.lost.unwrap().is_empty(),
            "confirmed fallback alert must retire too"
        );
    }

    #[test]
    fn round5_ack_only_removes_the_printed_snapshot() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        rig.daemon
            .shared
            .push_event(round4_zone(1, "zone.released", 42, 2, Some("bob")));
        let printed = rig
            .daemon
            .handle(Request::Unread {
                session: "alice".into(),
                attention: true,
                attention_ack: Vec::new(),
            })
            .lost
            .unwrap();
        rig.daemon
            .shared
            .push_event(round4_zone(2, "zone.lost", 42, 3, None));
        let newer = rig
            .daemon
            .handle(Request::Unread {
                session: "alice".into(),
                attention: true,
                attention_ack: printed,
            })
            .lost
            .unwrap();
        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].reason.as_deref(), Some("taken"));
        let confirmed = rig.daemon.handle(Request::Unread {
            session: "alice".into(),
            attention: true,
            attention_ack: newer,
        });
        assert!(confirmed.lost.unwrap().is_empty());
    }

    #[test]
    fn round5_socket_disconnect_before_output_keeps_attention() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        rig.daemon
            .shared
            .push_event(round4_zone(1, "zone.lost", 42, 2, None));
        {
            let mut peer = UnixStream::connect(&rig.daemon.shared.config.socket).unwrap();
            peer.write_all(b"{\"workspace\":\"test\",\"op\":\"unread\",\"session\":\"alice\",\"attention\":true}\n").unwrap();
            // The hook exits before receiving or rendering the answer.
        }
        for _ in 0..2 {
            let reply = socket(&rig)
                .ask(&Request::Unread {
                    session: "alice".into(),
                    attention: true,
                    attention_ack: Vec::new(),
                })
                .unwrap();
            assert_eq!(reply.lost.unwrap().len(), 1);
        }
    }

    #[test]
    fn round5_direct_http_while_agent_runs_has_documented_mutation_boundary() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        rig.server.enqueue(
            "/api/v1/zones/claims/42/narrow",
            HttpReply::json(
                200,
                json!({"id":42,"session":"alice","paths":["docs"],"fence":2}),
            ),
        );
        let direct = Client::new(&rig.server.url(), "test-token".into()).unwrap();
        direct
            .call(&Call::write(
                "alice",
                "POST",
                "/api/v1/zones/claims/42/narrow".into(),
                json!({"paths":["docs"],"fence":1}),
            ))
            .unwrap();
        assert!(
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .local_zone_mutations
                .is_empty()
        );
        // With no actor, direct HTTP has no receipt registered in the running daemon.
        rig.daemon
            .shared
            .push_event(round4_zone(1, "zone.released", 42, 2, None));
        assert_eq!(rig.daemon.shared.zone_alerts("alice").len(), 1);
    }

    #[test]
    fn round4_own_narrow_actor_and_receipt_fence_do_not_alert() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        let shared = &rig.daemon.shared;
        assert!(shared.push_event(round4_zone(1, "zone.released", 42, 2, Some("alice"))));
        assert!(shared.take_zone_alerts("alice").is_empty());
        rig.server.enqueue(
            "/api/v1/zones/claims/43/narrow",
            HttpReply::json(
                200,
                json!({"id":43,"session":"alice","paths":["docs"],"fence":5}),
            ),
        );
        let reply = shared.forward(Call::write(
            "alice",
            "POST",
            "/api/v1/zones/claims/43/narrow".into(),
            json!({"fence":3,"paths":["docs"]}),
        ));
        assert!(reply.error.is_none(), "{reply:?}");
        assert!(shared.push_event(round4_zone(2, "zone.released", 43, 5, None)));
        assert!(shared.take_zone_alerts("alice").is_empty());
        // A different fence is not an echo of our mutation.
        assert!(shared.push_event(round4_zone(3, "zone.released", 43, 6, None)));
        assert_eq!(shared.take_zone_alerts("alice").len(), 1);
    }

    #[test]
    fn round4_own_narrow_without_request_fence_uses_the_receipt_fence() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.server.enqueue(
            "/api/v1/zones/claims/43/narrow",
            HttpReply::json(
                200,
                json!({"id":43,"session":"alice","paths":["docs"],"fence":5}),
            ),
        );
        let shared = &rig.daemon.shared;
        let reply = shared.forward(Call::write(
            "alice",
            "POST",
            "/api/v1/zones/claims/43/narrow".into(),
            json!({"paths":["docs"]}),
        ));
        assert!(reply.error.is_none(), "{reply:?}");
        shared.push_event(round4_zone(1, "zone.released", 43, 5, None));
        assert!(
            shared.take_zone_alerts("alice").is_empty(),
            "our fenceless narrow was mistaken for a foreign loss"
        );
        // The receipt identifies only our mutation, never a later foreign loss.
        shared.push_event(round4_zone(2, "zone.released", 43, 5, Some("bob")));
        assert_eq!(shared.take_zone_alerts("alice").len(), 1);
        shared.push_event(round4_zone(3, "zone.released", 43, 6, None));
        assert_eq!(shared.take_zone_alerts("alice").len(), 1);

        // The same optional precondition applies when SSE precedes the receipt.
        let mutation = shared.begin_zone_mutation(&Call::write(
            "alice",
            "POST",
            "/api/v1/zones/claims/44/narrow".into(),
            json!({"paths":["docs"]}),
        ));
        assert!(mutation.is_some());
        shared.push_event(round4_zone(4, "zone.released", 44, 7, None));
        assert!(shared.take_zone_alerts("alice").is_empty());
        shared.finish_zone_mutation(mutation, Some(&json!({"id":44,"fence":7})));
        assert!(shared.take_zone_alerts("alice").is_empty());
    }

    #[test]
    fn round4_early_own_event_waits_for_mutation_receipt_and_foreign_actor_wins() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        let call = Call::write(
            "alice",
            "POST",
            "/api/v1/zones/claims/42/narrow".into(),
            json!({"fence":1,"paths":["docs"]}),
        );
        let mutation = shared.begin_zone_mutation(&call);
        shared.push_event(round4_zone(1, "zone.released", 42, 2, None));
        assert!(shared.take_zone_alerts("alice").is_empty());
        shared.finish_zone_mutation(mutation, Some(&json!({"id":42,"fence":2})));
        assert!(shared.take_zone_alerts("alice").is_empty());
        shared.push_event(round4_zone(2, "zone.released", 42, 2, Some("bob")));
        assert_eq!(shared.take_zone_alerts("alice").len(), 1);
    }

    #[test]
    fn round4_foreign_narrow_once_and_new_claim_clears_stale_alert() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        let event = round4_zone(1, "zone.released", 42, 2, Some("bob"));
        shared.push_event(event.clone());
        assert_eq!(shared.take_zone_alerts("alice").len(), 1);
        assert!(shared.take_zone_alerts("alice").is_empty());
        shared.push_event(event);
        assert!(shared.take_zone_alerts("alice").is_empty());
        shared.push_event(round4_zone(2, "zone.released", 43, 3, Some("bob")));
        let mut claimed = round4_zone(3, "zone.claimed", 44, 4, None);
        claimed.payload["reason"] = json!("claimed");
        shared.push_event(claimed);
        assert!(shared.take_zone_alerts("alice").is_empty());
        assert!(
            shared
                .push
                .lock()
                .unwrap()
                .zone_alerts
                .get("alice")
                .is_none_or(|a| a.is_empty())
        );
    }

    #[test]
    fn round4_new_claim_suppresses_an_undelivered_loss_on_the_same_paths() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        shared.push_event(round4_zone(1, "zone.released", 42, 2, Some("bob")));
        let mut claim = round4_zone(2, "zone.claimed", 43, 3, None);
        claim.payload["reason"] = json!("claimed");
        shared.push_event(claim);
        assert!(shared.take_zone_alerts("alice").is_empty());
    }

    #[test]
    fn round4_mail_counter_cannot_consume_hook_zone_attention() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        rig.daemon
            .shared
            .push_event(round4_zone(1, "zone.lost", 42, 2, None));
        let count = rig.daemon.handle(Request::Unread {
            attention_ack: Vec::new(),
            session: "alice".into(),
            attention: false,
        });
        assert!(count.lost.unwrap().is_empty());
        let first = rig.daemon.handle(Request::Unread {
            attention_ack: Vec::new(),
            session: "alice".into(),
            attention: true,
        });
        let printed = first.lost.unwrap();
        assert_eq!(printed.len(), 1);
        let next = rig.daemon.handle(Request::Unread {
            attention_ack: printed,
            session: "alice".into(),
            attention: true,
        });
        assert!(next.lost.unwrap().is_empty());
    }

    #[test]
    fn round4_finished_sessions_retire_zone_tracking() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        shared.hear("alice");
        shared.push_event(round4_zone(1, "zone.lost", 42, 2, None));
        shared
            .push
            .lock()
            .unwrap()
            .status_claims
            .insert("alice".into(), HashSet::from([42]));
        shared.sessions().get_mut("alice").unwrap().heard =
            Some(Instant::now() - shared.timing().active_window - Duration::from_secs(1));
        shared.refresh_unread();
        let push = shared.push.lock().unwrap();
        assert!(!push.status_claims.contains_key("alice"));
        assert!(
            !push
                .zone_alert_versions
                .keys()
                .any(|(session, _)| session == "alice")
        );
        assert!(!push.zone_alerts.contains_key("alice"));
    }

    #[test]
    fn round4_lost_taken_reason_is_not_duplicated() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        rig.daemon
            .shared
            .push_event(round4_zone(1, "zone.lost", 42, 2, None));
        assert_eq!(
            rig.daemon.shared.take_zone_alerts("alice")[0]
                .reason
                .as_deref(),
            Some("taken")
        );
    }

    #[test]
    fn round4_stream_disconnect_rechecks_zone_within_sixty_seconds() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let start = Instant::now();
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start);
        rig.server.enqueue(
            "/api/v1/zones/check",
            HttpReply::json(200, json!({"paths":[{"path":"src","status":"held"}]})),
        );
        let before = rig
            .server
            .requests()
            .iter()
            .filter(|r| r.path == "/api/v1/zones/check")
            .count();
        let shared = rig.daemon.shared.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let polled = progress.clone();
        let worker = thread::spawn(move || {
            let reply = shared.wait_zone_free("alice", "src", 600_000, &mut || {
                polled.fetch_add(1, Ordering::SeqCst);
                false
            });
            sent.send(reply).unwrap();
        });
        eventually(|| progress.load(Ordering::SeqCst) > 0);
        rig.daemon.shared.push_ready.store(false, Ordering::Release);
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start + Duration::from_secs(61));
        rig.daemon.shared.mail_ready.notify_all();
        let answer = received.recv_timeout(EVENT_TIMEOUT);
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start + Duration::from_secs(601));
        rig.daemon.shared.mail_ready.notify_all();
        worker.join().unwrap();
        assert!(answer.is_ok(), "disconnected stream prevented recheck");
        assert_eq!(answer.unwrap().value.unwrap()["free"], true);
        assert!(
            rig.server
                .requests()
                .iter()
                .filter(|r| r.path == "/api/v1/zones/check")
                .count()
                > before + 1
        );
    }

    #[test]
    fn zone_expiry_takeover_and_auto_narrowing_are_cached_only_for_the_holder() {
        let mut rig = rig(true, None);
        // This test injects events directly and measures cache reads. Join unrelated
        // upkeep/stream workers so their HTTP requests cannot race the no-RPC assertion.
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        for (id, kind, reason) in [
            (42, "zone.expired", "expired"),
            (43, "zone.lost", "taken"),
            (44, "zone.released", "narrowed"),
        ] {
            let event = serde_json::from_value(
                json!({"seq":id,"type":kind,"at":"2026-11-17T12:34:00Z", "session":"alice",
                "payload":{"session":"alice","claim_id":id,"paths":["src"],"reason":reason}}),
            )
            .unwrap();
            assert!(rig.daemon.shared.push_event(event));
        }
        let before = rig.server.requests().len();
        assert_eq!(rig.daemon.shared.take_zone_alerts("alice").len(), 3);
        assert!(rig.daemon.shared.take_zone_alerts("bob").is_empty());
        assert_eq!(rig.server.requests().len(), before);
    }

    #[test]
    fn newer_loss_replaces_narrowing_and_status_cannot_overwrite_sse() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        let backend = rig.daemon.shared.backend("alice");
        let claim: Claim =
            serde_json::from_value(json!({"id":42,"session":"alice","paths":["src"],"fence":1}))
                .unwrap();
        rig.daemon
            .shared
            .observe_status_claims("alice", &[claim], &backend, EVENT_TIMEOUT);
        for (seq, kind, reason) in [
            (10, "zone.released", "narrowed"),
            (12, "zone.lost", "holder offline"),
            (11, "zone.released", "narrowed"),
        ] {
            rig.daemon.shared.push_event(serde_json::from_value(json!({"seq":seq,"type":kind,"session":"alice","payload":{"session":"alice","claim_id":42,"paths":["src"],"reason":reason}})).unwrap());
        }
        rig.server.enqueue("/api/v1/zones/lost",HttpReply::json(200,json!({"claims":[{"claim_id":42,"session":"alice","paths":["src"],"reason":"holder offline"}]})));
        rig.daemon
            .shared
            .observe_status_claims("alice", &[], &backend, EVENT_TIMEOUT);
        assert_eq!(
            rig.daemon.shared.take_zone_alerts("alice")[0]
                .reason
                .as_deref(),
            Some("taken: holder offline")
        );
        let before = rig
            .server
            .requests()
            .iter()
            .filter(|r| r.path.starts_with("/api/v1/zones/lost"))
            .count();
        rig.daemon
            .shared
            .observe_status_claims("alice", &[], &backend, EVENT_TIMEOUT);
        assert_eq!(
            rig.server
                .requests()
                .iter()
                .filter(|r| r.path.starts_with("/api/v1/zones/lost"))
                .count(),
            before,
            "a successfully reconciled missing claim must retire"
        );
    }

    #[test]
    fn mail_push_coordination_events_keep_socket_ack_semantics() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        rig.daemon.shared.push_event(
            serde_json::from_value(
                json!({"seq":42,"type":"zone.requested","payload":{"to":"alice"}}),
            )
            .unwrap(),
        );
        assert_eq!(
            rig.daemon.shared.take_events("alice").events.unwrap().len(),
            1
        );
        assert_eq!(
            rig.daemon.shared.take_events("alice").events.unwrap().len(),
            1
        );
        rig.daemon.shared.ack_events("alice", 42);
        assert!(
            rig.daemon
                .shared
                .take_events("alice")
                .events
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn mail_push_metadata_only_event_hydrates_reminder_without_marking_read() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        let mut full = mail(42, "alice", true, "reply");
        full["from_client"] = json!("sender-chat parent_pid=123");
        rig.server.enqueue(
            "/api/v1/bus/threads/42",
            HttpReply::json(200, json!({"messages":[full]})),
        );
        let mut metadata = mail(42, "alice", true, "reply");
        metadata.as_object_mut().unwrap().remove("body");
        publish(&rig, 1, metadata);
        let reply = received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        let message = &reply.messages.unwrap()[0];
        assert_eq!(message.body, "hello");
        assert_eq!(
            message.from_client.as_deref(),
            Some("sender-chat parent_pid=123")
        );
        assert!(
            !rig.server
                .requests()
                .iter()
                .any(|r| r.path.contains("seen"))
        );
    }
    #[test]
    fn mail_push_status_uses_event_mail_cache_within_existing_budget() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        publish(&rig, 1, mail(42, "alice", true, "reply"));
        received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        let reads = rig
            .server
            .requests()
            .iter()
            .filter(|r| r.method == "GET" && r.path.starts_with("/api/v1/bus/inbox"))
            .count();
        let started = Instant::now();
        let status = socket(&rig)
            .status_read("alice", None, Duration::from_millis(1500))
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert_eq!(status.unread, Some(1));
        assert!(status.open_mail.unwrap().iter().any(|m| m.id == 42));
        assert_eq!(
            reads,
            rig.server
                .requests()
                .iter()
                .filter(|r| r.method == "GET" && r.path.starts_with("/api/v1/bus/inbox"))
                .count()
        );
        assert!(
            rig.server
                .requests()
                .iter()
                .any(|r| r.path.starts_with("/api/v1/zones/claims"))
        );
    }
    #[test]
    fn mail_push_replay_before_ready_old_cursor_never_wakes_seen_mail() {
        let (release, gated) = mpsc::channel();
        let rig = rig_with(true, None, |server, config| {
            let state = config.state_root.join(state_folder(config));
            fs::create_dir_all(&state).unwrap();
            save_seq(&state, "coordination", 4).unwrap();
            let message = json!({"seq":5,"type":"bus.message","session":"alice","payload":mail(42,"*",true,"reply")});
            let seen = json!({"seq":6,"type":"bus.seen","session":"alice","payload":{"seen":[42]}});
            server.enqueue("/api/v1/events", HttpReply::sse(&format!(
                "id: 5\nevent: bus.message\ndata: {message}\n\nid: 6\nevent: bus.seen\ndata: {seen}\n\nid: 6\nevent: ready\ndata: {{\"head\":6}}\n\n"))
                .gated(gated));
        });
        let (received, worker) = waiting(&rig, "alice", Duration::from_millis(400));
        eventually(|| {
            rig.server
                .requests()
                .iter()
                .any(|r| r.header("accept") == Some("text/event-stream"))
        });
        assert!(!rig.daemon.shared.push_ready.load(Ordering::Acquire));
        assert!(
            rig.server
                .requests()
                .iter()
                .all(|r| !r.path.starts_with("/api/v1/bus/inbox")),
            "no seed before ready"
        );
        rig.daemon
            .shared
            .session_events
            .lock()
            .unwrap()
            .get_mut("alice")
            .unwrap()
            .last_poll = None;
        let count = rig.server.requests().len();
        rig.daemon.shared.refresh_session_events();
        assert!(
            rig.server.requests().len() > count,
            "session polling remains active before ready"
        );
        release.send(()).unwrap();
        eventually(|| inbox_count(&rig.server, "alice") > 0);
        eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) == 6);
        assert!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_none()
        );
        worker.join().unwrap();
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
        assert!(
            rig.server
                .requests()
                .iter()
                .any(|r| r.header("last-event-id") == Some("4"))
        );
        assert!(
            rig.server
                .requests()
                .iter()
                .any(|r| r.path.starts_with("/api/v1/bus/inbox"))
        );
        assert_eq!(load_seq(&rig.daemon.shared.state_dir, "coordination"), 6);
    }

    #[test]
    fn mail_push_wait_retries_disabled_stream_and_temporary_snapshot_error() {
        let rig = rig(true, None);
        rig.server.enqueue(
            "/api/v1/bus/inbox",
            HttpReply::json(503, json!({"error":"temporary"})),
        );
        rig.daemon
            .shared
            .push_enabled
            .store(false, Ordering::Release);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        assert!(received.try_recv().is_err());
        publish(&rig, 1, mail(100, "alice", true, "reply"));
        assert_eq!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .unwrap()[0]
                .id,
            100
        );
        worker.join().unwrap();
        assert!(
            rig.server
                .requests()
                .iter()
                .filter(|r| r.path.starts_with("/api/v1/bus/inbox"))
                .count()
                >= 3
        );
    }

    #[test]
    fn mail_push_malformed_frames_advance_cursor_without_reconnect() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        let connections = rig
            .server
            .requests()
            .iter()
            .filter(|r| r.header("accept") == Some("text/event-stream"))
            .count();
        rig.server.enqueue(
            "/api/v1/events",
            HttpReply::sse("id: 1\nevent: bus.message\ndata: {broken\n\n"),
        );
        for (seq, field) in [(2, "id"), (3, "thread_id")] {
            let mut value = mail(101, "alice", true, "reply");
            value[field] = "101".into();
            publish(&rig, seq, value);
        }
        rig.server.enqueue(
            "/api/v1/events",
            HttpReply::sse("id: 4\nevent: mystery\ndata: {}\n\n"),
        );
        eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) == 4);
        assert_eq!(load_seq(&rig.daemon.shared.state_dir, "coordination"), 4);
        assert!(received.try_recv().is_err());
        publish(
            &rig,
            5,
            mail(i64::from(i32::MAX) + 42, "alice", true, "ack"),
        );
        assert!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_some()
        );
        worker.join().unwrap();
        assert_eq!(
            connections,
            rig.server
                .requests()
                .iter()
                .filter(|r| r.header("accept") == Some("text/event-stream"))
                .count()
        );
    }

    #[test]
    fn mail_push_skipped_zone_events_force_server_check_sse_and_json() {
        // No upkeep thread may repair the view before we assert the check's fallback.
        for sse in [false, true] {
            for (kind, data) in [
                ("zone.claimed", "{broken"),
                ("zone.claimed", r#"{"seq":1,"type":42,"session":"alice"}"#),
                ("zone.foo", r#"{"seq":1,"type":"zone.foo","payload":{}}"#),
            ] {
                let mut rig = rig(true, None);
                rig.daemon.stop_workers();
                rig.daemon.shared.signal().stop = false;
                rig.daemon.shared.hear("alice");
                {
                    let mut view = rig.daemon.shared.write_view();
                    view.claims.clear();
                    view.zones_clean = view.zones_generation;
                    view.board_clean = view.board_generation;
                    view.confirm(Instant::now());
                }
                assert_eq!(
                    rig.daemon.shared.check("alice", vec!["src".into()]).source,
                    Some(Source::View)
                );
                let (zones, board, at) = {
                    let view = rig.daemon.shared.read_view();
                    (view.zones_generation, view.board_generation, view.zones_at)
                };
                rig.server.enqueue(
                    "/api/v1/zones/check",
                    HttpReply::json(
                        200,
                        json!({"paths":[{
                            "path":"src", "status":"held", "holder":{"session":"bob", "claim_id":7}
                        }]}),
                    ),
                );
                let worker = if sse {
                    rig.server.enqueue(
                        "/api/v1/events#sse",
                        HttpReply::sse(&format!("id: 1\nevent: {kind}\ndata: {data}\n\n")),
                    );
                    let shared = rig.daemon.shared.clone();
                    let worker = thread::spawn(move || shared.push_stream());
                    eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) == 1);
                    Some(worker)
                } else {
                    // Invalid JSON inside an event page is represented by a wrong type;
                    // invalid JSON for the whole response must fail without any progress.
                    let raw = serde_json::from_str::<Value>(data).unwrap_or_else(|_| json!({
                        "seq":1, "type":"zone.claimed", "session":"alice", "payload":{}, "type_bad":true
                    }));
                    let raw = if data == "{broken" {
                        json!({"seq":1,"type":{},"session":"alice"})
                    } else {
                        raw
                    };
                    rig.server.enqueue(
                        "/api/v1/events",
                        HttpReply::json(200, json!({"events":[raw]})),
                    );
                    let page = rig
                        .daemon
                        .shared
                        .backend("alice")
                        .events(&EventQuery {
                            stream: Stream::Coordination,
                            after: 0,
                            wait_seconds: 0,
                            session: Some("alice".into()),
                            types: vec![],
                        })
                        .unwrap();
                    assert_eq!(page.last_seq(0), 1);
                    rig.daemon.shared.apply_events(&page);
                    None
                };
                {
                    let view = rig.daemon.shared.read_view();
                    assert!(view.zones_generation > zones, "{sse} {kind}");
                    assert!(view.board_generation > board, "{sse} {kind}");
                    assert_eq!(
                        view.zones_at, at,
                        "skipped cycle must not confirm freshness"
                    );
                    assert!(!view.fresh(Duration::from_secs(30)));
                    assert!(!view.board_fresh(Duration::from_secs(30)));
                }
                let reply = rig.daemon.shared.check("alice", vec!["src".into()]);
                assert_eq!(
                    reply.source,
                    Some(Source::Server),
                    "{sse} {kind}: {reply:?}"
                );
                assert_eq!(reply.checks.unwrap()[0].status, CheckStatus::Held);
                assert!(
                    rig.server
                        .requests()
                        .iter()
                        .any(|r| r.path.starts_with("/api/v1/zones/check"))
                );
                rig.daemon.shared.stop();
                if let Some(worker) = worker {
                    worker.join().unwrap();
                }
            }
        }
    }

    #[test]
    fn mail_push_json_tombstones_never_enter_session_cache_or_skip_unacked_events() {
        let mut rig = rig(false, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("alice");
        for seq in [1, 2] {
            rig.server.enqueue("/api/v1/events", HttpReply::json(200, json!({"events":[
                {"seq":seq,"type":if seq == 1 {json!("zone.claimed")} else {json!(42)},"session":"alice","payload":{}}
            ]})));
            rig.daemon
                .shared
                .session_events
                .lock()
                .unwrap()
                .entry("alice".into())
                .or_default()
                .last_poll = None;
            rig.daemon.shared.refresh_session_events();
        }
        let events = rig.daemon.shared.take_events("alice").events.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].kind, "zone.claimed");
        let caches = rig.daemon.shared.session_events.lock().unwrap();
        assert_eq!(caches["alice"].poll_after, 2);
        assert_eq!(caches["alice"].events.len(), 1);
        assert_eq!(
            caches["alice"].after, 0,
            "poll progress cannot acknowledge a real event"
        );
    }

    #[test]
    fn mail_push_unavailable_key_replays_frame_without_cursor_progress() {
        struct KeyGate {
            client: Client,
            available: AtomicBool,
            attempts: Mutex<Vec<i64>>,
        }
        impl Transport for KeyGate {
            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                self.client.call(call)
            }
            fn mail_push_v1(&self, _: &str) -> Result<bool, ClientError> {
                Ok(true)
            }
            fn event_stream_sessions(
                &self,
                _: &str,
                _: &[String],
                after: i64,
                _: Arc<AtomicBool>,
            ) -> Result<lockyard_cloud_client::sse::EventStream, ClientError> {
                self.attempts.lock().unwrap().push(after);
                let data = if after < 7 {
                    format!(
                        "id: 7\nevent: zone.claimed\ndata: {}\n\n",
                        json!({
                            "seq":7,"type":"zone.claimed","session":"alice","payload":{"id":7}
                        })
                    )
                } else {
                    String::new()
                };
                Ok(lockyard_cloud_client::sse::EventStream::new(Box::new(
                    io::Cursor::new(data.into_bytes()),
                )))
            }
            fn decode_stream_event(&self, _: &mut Event) -> Result<(), ClientError> {
                if self.available.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(ClientError::Invalid("workspace key unavailable".into()))
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let server = FakeServer::start_routed(Vec::new());
        let config = AgentConfig {
            url: server.url(),
            workspace: "test".into(),
            token_id: "test".into(),
            credential_proof: None,
            credential_product: super::super::CredentialProduct::Agent,
            socket: dir.path().join("run/agent.sock"),
            state_root: dir.path().join("state"),
            timing: Timing {
                retry_min: Duration::from_millis(60),
                ..Timing::default()
            },
        };
        let mut daemon = Daemon::start(
            config,
            KeyGate {
                client: Client::new(&server.url(), "test-token".into()).unwrap(),
                available: AtomicBool::new(false),
                attempts: Mutex::new(vec![]),
            },
        )
        .unwrap();
        // Isolate the SSE cursor worker from unrelated upkeep and discovery traffic.
        daemon.stop_workers();
        daemon.shared.signal().stop = false;
        daemon
            .shared
            .sessions()
            .entry("alice".into())
            .or_default()
            .push_bound = true;
        daemon.shared.hear("alice");
        {
            let mut view = daemon.shared.write_view();
            view.zones_clean = view.zones_generation;
            view.board_clean = view.board_generation;
            view.confirm(Instant::now());
            assert!(view.fresh(Duration::from_secs(30)));
        }
        let shared = daemon.shared.clone();
        let worker = thread::spawn(move || shared.push_stream());
        eventually(|| daemon.shared.transport.attempts.lock().unwrap().len() >= 2);
        assert!(
            !daemon.shared.read_view().fresh(Duration::from_secs(30)),
            "an unapplied encrypted event must force a server read"
        );
        assert_eq!(daemon.shared.coordination_seq.load(Ordering::Relaxed), 0);
        assert_eq!(load_seq(&daemon.shared.state_dir, "coordination"), 0);
        assert!(
            daemon
                .shared
                .take_events("alice")
                .events
                .unwrap()
                .is_empty()
        );
        assert!(
            daemon
                .shared
                .transport
                .attempts
                .lock()
                .unwrap()
                .iter()
                .all(|after| *after == 0)
        );
        daemon
            .shared
            .transport
            .available
            .store(true, Ordering::Release);
        eventually(|| daemon.shared.coordination_seq.load(Ordering::Relaxed) == 7);
        let events = daemon.shared.take_events("alice").events.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 7);
        daemon.shared.stop();
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_reply_to_closes_parent_including_sender_copy() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        publish(&rig, 1, mail(42, "alice", true, "reply"));
        received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        let mut reply = mail(43, "bob", false, "none");
        reply["reply_to"] = 42.into();
        reply["role"] = "sender".into();
        reply["from"] = "alice".into();
        publish_to(&rig, 2, "alice", reply);
        assert!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(1)); // reply is not new incoming mail
    }

    #[test]
    fn mail_push_wake_cursor_survives_daemon_restart() {
        let rig = rig(true, Some(mail(42, "alice", true, "reply")));
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_secs(2))
                .unwrap()
                .messages
                .is_some()
        );
        let Rig {
            daemon,
            server,
            _dir,
        } = rig;
        let config = daemon.shared.config.clone();
        drop(daemon);
        for _ in 0..2 {
            server.enqueue(
                "/api/v1/bus/inbox",
                HttpReply::json(200, json!({"messages":[mail(42,"alice",true,"reply")]})),
            );
        }
        let daemon = Daemon::start(
            config,
            Client::new(&server.url(), "test-token".into()).unwrap(),
        )
        .unwrap();
        daemon
            .shared
            .sessions()
            .entry("alice".into())
            .or_default()
            .push_bound = true;
        let rig = Rig {
            daemon,
            server,
            _dir,
        };
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_millis(350))
                .unwrap()
                .messages
                .is_none()
        );
        assert!(
            !fs::read_dir(&rig.daemon.shared.state_dir)
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[test]
    fn mail_push_sse_incompatibility_renegotiates_and_falls_back() {
        for response in [
            HttpReply::json(200, json!({})),
            HttpReply::text(404, "old"),
            HttpReply::text(406, "no SSE"),
        ] {
            let rig = rig_with(true, None, |server, _| {
                server.enqueue("/api/v1/events#sse", response);
            });
            rig.daemon.shared.hear("alice");
            eventually(|| {
                rig.server.discovery_requests().len() >= 2
                    && !rig.daemon.shared.push_enabled.load(Ordering::Acquire)
            });
            eventually(|| {
                rig.server
                    .requests()
                    .iter()
                    .any(|r| r.path.starts_with("/api/v1/events") && r.path.contains("wait=25"))
            });
            assert_eq!(
                rig.daemon.shared.mail_protocol.load(Ordering::Acquire),
                1,
                "send capability survives transport fallback"
            );
            assert!(socket(&rig).mail_push_v1("alice").unwrap());
            assert_eq!(
                rig.server
                    .requests()
                    .iter()
                    .filter(|r| r.header("accept") == Some("text/event-stream"))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn mail_push_five_failures_fall_back_and_idle_stream_shutdown_is_prompt() {
        let failing = rig_with(true, None, |server, _| {
            for _ in 0..5 {
                server.enqueue("/api/v1/events#sse", HttpReply::text(500, "failed"));
            }
        });
        failing.daemon.shared.hear("alice");
        eventually(|| {
            failing.server.discovery_requests().len() >= 2
                && !failing.daemon.shared.push_enabled.load(Ordering::Acquire)
        });
        assert_eq!(
            failing
                .server
                .requests()
                .iter()
                .filter(|r| r.header("accept") == Some("text/event-stream"))
                .count(),
            5
        );
        drop(failing);
        let mut rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        let started = Instant::now();
        rig.daemon.shutdown();
        assert!(started.elapsed() < Duration::from_secs(1));
        received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_reconnect_backoff_resets_on_handshake_without_event() {
        use std::sync::atomic::AtomicUsize;
        struct Script {
            client: Client,
            next: AtomicUsize,
        }
        impl Transport for Script {
            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                self.client.call(call)
            }
            fn mail_push_v1(&self, _: &str) -> Result<bool, ClientError> {
                Ok(true)
            }
            fn event_stream_sessions(
                &self,
                _: &str,
                _: &[String],
                _: i64,
                _: Arc<AtomicBool>,
            ) -> Result<lockyard_cloud_client::sse::EventStream, ClientError> {
                if self.next.fetch_add(1, Ordering::Relaxed) == 3 {
                    // Successful HTTP connection, no application event (or ready) before EOF.
                    Ok(lockyard_cloud_client::sse::EventStream::new(Box::new(
                        io::Cursor::new(Vec::<u8>::new()),
                    )))
                } else {
                    Err(ClientError::Transport("temporary refusal".into()))
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let server = FakeServer::start_routed(Vec::new());
        let config = AgentConfig {
            url: server.url(),
            workspace: "test".into(),
            token_id: "test".into(),
            credential_proof: None,
            credential_product: super::super::CredentialProduct::Agent,
            socket: dir.path().join("run/agent.sock"),
            state_root: dir.path().join("state"),
            timing: Timing {
                retry_min: Duration::from_millis(60),
                ..Timing::default()
            },
        };
        let mut daemon = Daemon::start(
            config,
            Script {
                client: Client::new(&server.url(), "test-token".into()).unwrap(),
                next: AtomicUsize::new(0),
            },
        )
        .unwrap();
        daemon.stop_workers();
        daemon.shared.signal().stop = false;
        daemon.shared.push.lock().unwrap().reconnect_delays = Some(Vec::new());
        server.bind_session("alice", "test-token");
        daemon
            .shared
            .sessions()
            .entry("alice".into())
            .or_default()
            .push_bound = true;
        daemon.shared.hear("alice");
        // Run the stream worker with an observable scheduler: no real backoff sleeps.
        daemon.shared.push_stream();
        assert_eq!(daemon.shared.transport.next.load(Ordering::Relaxed), 5);
        let push = daemon.shared.push.lock().unwrap();
        let delays = push.reconnect_delays.as_ref().unwrap();
        assert_eq!(delays.len(), 4);
        for (delay, base_ms) in delays.iter().zip([60, 120, 240, 60]) {
            assert!(
                *delay >= Duration::from_millis(base_ms).mul_f64(0.75),
                "{delays:?}"
            );
            assert!(
                *delay <= Duration::from_millis(base_ms).mul_f64(1.25),
                "{delays:?}"
            );
        }
        assert_eq!(daemon.shared.coordination_seq.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mail_push_fallback_rechecks_negotiation_after_interval() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.signal().stop = false;
        rig.daemon.shared.hear("alice");
        rig.server
            .enqueue("/api/v1/events#sse", HttpReply::text(406, "no SSE"));
        let start = Instant::now();
        let interval = Duration::from_secs(600);
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start);
        let before = rig.server.discovery_requests().len();
        let polls = || {
            rig.server
                .requests()
                .iter()
                .filter(|r| {
                    r.path.starts_with("/api/v1/events")
                        && r.header("accept") != Some("text/event-stream")
                })
                .count()
        };
        let initial_polls = polls();
        let shared = rig.daemon.shared.clone();
        let worker = thread::spawn(move || shared.coordination_loop_with_interval(interval));
        // The JSON request proves the immediate post-failure discovery completed and
        // scheduled its next deadline before we move the clock.
        eventually(|| {
            rig.server.discovery_requests().len() == before + 1 && polls() > initial_polls
        });
        assert!(!rig.daemon.shared.push_enabled.load(Ordering::Acquire));
        rig.daemon.shared.push.lock().unwrap().clock_now =
            Some(start + interval - Duration::from_secs(1));
        let before_boundary = polls();
        rig.daemon.shared.nudge();
        eventually(|| polls() > before_boundary);
        assert_eq!(
            rig.server.discovery_requests().len(),
            before + 1,
            "no early interval retry"
        );
        assert_eq!(stream_count(&rig.server), 1);
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start + interval);
        rig.daemon.shared.nudge();
        eventually(|| rig.server.discovery_requests().len() == before + 2);
        eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
        assert_eq!(
            rig.server
                .requests()
                .iter()
                .filter(|r| r.header("accept") == Some("text/event-stream"))
                .count(),
            2
        );
        rig.daemon.shared.stop();
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_fallback_wait_polls_snapshots_instead_of_exiting_early() {
        let rig = rig_with(true, Some(mail(42, "alice", true, "reply")), |server, _| {
            server.enqueue("/api/v1/events#sse", HttpReply::text(406, "fallback"));
        });
        assert_eq!(
            crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_secs(2)),
            2
        );
        assert!(rig.daemon.shared.push_fallback.load(Ordering::Acquire));
        assert!(!rig.daemon.shared.push_ready.load(Ordering::Acquire));
    }

    #[test]
    fn mail_push_fake_fanout_uses_envelopes_and_does_not_wake_sender() {
        let rig = rig(true, None);
        let (alice, a) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        let (charlie, c) = waiting(&rig, "charlie", EVENT_TIMEOUT);
        seeded(&rig, "charlie");
        let (bob, b) = waiting(&rig, "bob", Duration::from_millis(400));
        seeded(&rig, "bob");
        let mut message = mail(90, "@zone:client", true, "reply");
        message["address"] = "@zone:client".into();
        rig.server.enqueue(
            "/api/v1/events",
            HttpReply::mail(1, &["alice", "charlie"], message),
        );
        assert_eq!(
            alice.recv_timeout(EVENT_TIMEOUT).unwrap().messages.unwrap()[0].to,
            "alice"
        );
        assert_eq!(
            charlie
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .unwrap()[0]
                .to,
            "charlie"
        );
        assert!(bob.recv_timeout(EVENT_TIMEOUT).unwrap().messages.is_none());
        a.join().unwrap();
        c.join().unwrap();
        b.join().unwrap();
        assert_eq!(rig.daemon.shared.unread("bob").unread, Some(0));
    }
    #[test]
    fn mail_push_send_capability_waits_for_pending_protocol_negotiation() {
        struct Pending {
            client: Client,
            gate: Arc<(Mutex<bool>, Condvar)>,
            entered: mpsc::Sender<()>,
        }
        impl Pending {
            fn ready(&self) {
                let (lock, wake) = &*self.gate;
                let guard = lock.lock().unwrap();
                let (_guard, timeout) = wake
                    .wait_timeout_while(guard, EVENT_TIMEOUT, |ready| !*ready)
                    .unwrap();
                assert!(!timeout.timed_out());
            }
        }
        impl Transport for Pending {
            fn mail_push_v1(&self, _: &str) -> Result<bool, ClientError> {
                self.ready();
                Ok(true)
            }
            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                if call.path == "/api/v1/protocol" {
                    assert_eq!(call.deadline_ms, Some(2000));
                    self.entered.send(()).unwrap();
                    self.ready();
                    Ok(json!({"selected_protocol":2,"capabilities":["mail_push_v1"]}))
                } else {
                    self.client.call(call)
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let server = FakeServer::start_routed(Vec::new());
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered, pending) = mpsc::channel();
        let config = AgentConfig {
            url: server.url(),
            workspace: "test".into(),
            token_id: "test".into(),
            credential_proof: None,
            credential_product: super::super::CredentialProduct::Agent,
            socket: dir.path().join("run/agent.sock"),
            state_root: dir.path().join("state"),
            timing: Timing::default(),
        };
        let daemon = Daemon::start(
            config.clone(),
            Pending {
                client: Client::new(&server.url(), "test-token".into()).unwrap(),
                gate: gate.clone(),
                entered,
            },
        )
        .unwrap();
        let socket =
            AgentSocket::connect(&config.socket, &server.url(), "test", EVENT_TIMEOUT).unwrap();
        assert!(!daemon.shared.push_enabled.load(Ordering::Acquire));
        let release = thread::spawn(move || {
            pending.recv_timeout(EVENT_TIMEOUT).unwrap();
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
        });
        assert!(socket.mail_push_v1("alice").unwrap());
        release.join().unwrap();
    }
    fn stream_count(server: &FakeServer) -> usize {
        server
            .requests()
            .iter()
            .filter(|r| r.header("accept") == Some("text/event-stream"))
            .count()
    }
    fn inbox_count(server: &FakeServer, session: &str) -> usize {
        server
            .requests()
            .iter()
            .filter(|r| {
                r.method == "GET"
                    && r.path.starts_with("/api/v1/bus/inbox")
                    && r.header("x-lockyard-session") == Some(session)
            })
            .count()
    }

    #[test]
    fn mail_push_typo_waiter_never_joins_or_breaks_stream() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let streams = stream_count(&rig.server);
        let (received, worker) = waiting(&rig, "alic-typo", Duration::from_millis(350));
        assert!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_none()
        );
        worker.join().unwrap();
        assert_eq!(stream_count(&rig.server), streams);
        assert!(rig.daemon.shared.push_enabled.load(Ordering::Acquire));
        assert!(!rig.daemon.shared.push_fallback.load(Ordering::Acquire));
        assert!(
            !rig.daemon
                .shared
                .active_push_sessions()
                .contains(&"alic-typo".into())
        );
        // A real successful presence, rather than the waiter name, admits it.
        rig.daemon
            .shared
            .touch("alic-typo", "claude", Phase::Prompt, vec![]);
        eventually(|| {
            rig.daemon
                .shared
                .active_push_sessions()
                .contains(&"alic-typo".into())
        });
        eventually(|| stream_count(&rig.server) == streams + 1);
    }

    #[test]
    fn mail_push_403_prunes_sessions_without_failure_fallback() {
        for modern in [false, true] {
            let mut rig = rig(true, None);
            rig.daemon.stop_workers();
            rig.daemon.shared.signal().stop = false;
            for i in 0..6 {
                let name = format!("foreign-{i}");
                rig.server.bind_session(&name, "test-token");
                rig.daemon
                    .shared
                    .confirm_session_binding(&Call::get(&name, "/api/v1/presence".into()));
                rig.daemon.shared.hear(&name);
                let details = json!({"sessions":[name]});
                let error = json!({"code":"forbidden","message":"not bound","details":details});
                let body = if modern {
                    json!({"type":"urn:lockyard:problem:forbidden","status":403,
                    "code":"forbidden","detail":"not bound","details":details,"error":error})
                } else {
                    json!({"error":error})
                };
                rig.server
                    .enqueue("/api/v1/events#sse", HttpReply::json(403, body));
            }
            rig.daemon.shared.hear("alice");
            let shared = rig.daemon.shared.clone();
            let worker = thread::spawn(move || shared.push_stream());
            eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
            assert_eq!(
                stream_count(&rig.server),
                7,
                "six 403 prunings must not reach the five-failure cutoff"
            );
            assert_eq!(rig.daemon.shared.active_push_sessions(), vec!["alice"]);
            assert!(!rig.daemon.shared.push_fallback.load(Ordering::Acquire));
            rig.daemon.shared.stop();
            worker.join().unwrap();
        }
        let rig = rig(true, None);
        rig.server.bind_session("charlie", "foreign-token");
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        rig.daemon.shared.hear("charlie");
        eventually(|| !rig.daemon.shared.sessions()["charlie"].push_bound);
        eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
        assert_eq!(rig.daemon.shared.active_push_sessions(), vec!["alice"]);
        assert!(!rig.daemon.shared.push_fallback.load(Ordering::Acquire));
    }

    #[test]
    fn mail_push_idle_waiter_five_seconds_does_not_spin_or_read_inbox() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", Duration::from_millis(5500));
        seeded(&rig, "alice");
        eventually(|| {
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .waiters
                .contains_key("alice")
        });
        let reads = inbox_count(&rig.server, "alice");
        let cycles = rig.daemon.shared.upkeep_cycles.load(Ordering::Relaxed);
        thread::sleep(Duration::from_secs(5));
        assert_eq!(inbox_count(&rig.server, "alice"), reads);
        let rounds = rig.daemon.shared.upkeep_cycles.load(Ordering::Relaxed) - cycles;
        assert!(
            rounds <= 2,
            "idle waiter caused {rounds} maintenance cycles"
        );
        assert!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_none()
        );
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_changed_set_seeds_only_added_sessions() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let reads = inbox_count(&rig.server, "alice");
        rig.daemon.shared.hear("charlie");
        seeded(&rig, "charlie");
        assert_eq!(inbox_count(&rig.server, "alice"), reads);
        assert_eq!(inbox_count(&rig.server, "charlie"), 2);
    }

    #[test]
    fn mail_push_fallback_refreshes_only_waiter_sessions_each_second() {
        let rig = rig_with(true, None, |server, _| {
            server.enqueue("/api/v1/events#sse", HttpReply::text(406, "old"));
        });
        rig.daemon.shared.hear("bob");
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        seeded(&rig, "bob");
        eventually(|| {
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .waiters
                .contains_key("alice")
        });
        let bob_reads = inbox_count(&rig.server, "bob");
        let alice_reads = inbox_count(&rig.server, "alice");
        let cycles = rig.daemon.shared.upkeep_cycles.load(Ordering::Relaxed);
        let observation = Instant::now();
        eventually(|| {
            observation.elapsed() >= Duration::from_secs(5)
                && inbox_count(&rig.server, "alice") >= alice_reads + 6
        });
        assert_eq!(inbox_count(&rig.server, "bob"), bob_reads);
        let reads = inbox_count(&rig.server, "alice") - alice_reads;
        assert!(
            (6..=12).contains(&reads),
            "expected two snapshots per second, got {reads}"
        );
        let rounds = rig.daemon.shared.upkeep_cycles.load(Ordering::Relaxed) - cycles;
        assert!(
            rounds <= 7,
            "fallback waiter caused {rounds} maintenance cycles"
        );
        rig.daemon.shared.stop();
        assert!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_none()
        );
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_self_mail_recipient_wakes_sender_copy_does_not() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        let mut message = mail(77, "alice", true, "reply");
        message["from"] = "alice".into();
        message["role"] = "sender".into();
        publish_to(&rig, 1, "alice", message.clone());
        eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) == 1);
        assert!(received.try_recv().is_err());
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
        rig.server
            .enqueue("/api/v1/events", HttpReply::mail(2, &["alice"], message));
        assert_eq!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .unwrap()[0]
                .id,
            77
        );
        worker.join().unwrap();
        eventually(|| rig.daemon.shared.coordination_seq.load(Ordering::Relaxed) == 4);
    }

    #[test]
    fn mail_push_service_events_and_full_unread_are_accepted_without_wake() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", Duration::from_millis(400));
        seeded(&rig, "alice");
        for (seq, kind, payload) in [
            (1, "bus.unread", {
                let mut p = mail(10, "alice", true, "reply");
                p.as_object_mut().unwrap().remove("body");
                p
            }),
            (2, "bus.delivery_claimed", json!({"ids":[10]})),
            (3, "bus.imported", json!({"threads":1,"board":0,"tasks":0})),
        ] {
            let event: Event = serde_json::from_value(
                json!({"seq":seq,"type":kind,"session":"alice","payload":payload}),
            )
            .unwrap();
            assert!(rig.daemon.shared.push_event(event));
        }
        assert!(
            received
                .recv_timeout(EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_none()
        );
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_replacement_history_resets_only_after_ten_minutes_of_stream() {
        let rig = rig(false, None);
        let shared = &rig.daemon.shared;
        let start = Instant::now();
        let sessions = vec!["alice".to_string()];
        let set_now = |now| shared.push.lock().unwrap().clock_now = Some(now);
        set_now(start);
        shared.stream_replaced(sessions.clone(), start);
        set_now(start + Duration::from_secs(61));
        assert!(shared.replacement_allows_stream(&sessions));
        let retry = start + Duration::from_secs(61);
        set_now(retry + Duration::from_secs(600));
        shared.stream_replaced(sessions.clone(), retry);
        assert!(
            shared
                .push
                .lock()
                .unwrap()
                .replacement
                .as_ref()
                .unwrap()
                .retried
        );
        set_now(retry + Duration::from_secs(3600));
        assert!(!shared.replacement_allows_stream(&sessions));
        // A healthy retry gets a fresh single retry allowance after a later displacement.
        set_now(retry + Duration::from_secs(601));
        shared.stream_replaced(sessions.clone(), retry);
        assert!(
            !shared
                .push
                .lock()
                .unwrap()
                .replacement
                .as_ref()
                .unwrap()
                .retried
        );
        assert!(!shared.replacement_allows_stream(&sessions));
        set_now(retry + Duration::from_secs(662));
        assert!(shared.replacement_allows_stream(&sessions));
    }

    #[test]
    fn zone_wait_free_quiet_sse_five_controlled_minutes_adds_zero_checks() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let start = Instant::now();
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start);
        rig.server.enqueue(
            "/api/v1/zones/check",
            HttpReply::json(200, json!({"paths":[{"path":"src","status":"held"}]})),
        );
        let before = rig
            .server
            .requests()
            .iter()
            .filter(|r| r.path == "/api/v1/zones/check")
            .count();
        let shared = Arc::clone(&rig.daemon.shared);
        let observed = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let progress = observed.clone();
        let worker = thread::spawn(move || {
            shared.wait_zone_free("alice", "src", 600_000, &mut || {
                progress.fetch_add(1, Ordering::SeqCst);
                false
            })
        });
        eventually(|| observed.load(Ordering::SeqCst) > 0);
        for minute in 1..=5 {
            let before_tick = observed.load(Ordering::SeqCst);
            rig.daemon.shared.push.lock().unwrap().clock_now =
                Some(start + Duration::from_secs(61 * minute));
            rig.daemon.shared.mail_ready.notify_all();
            eventually(|| observed.load(Ordering::SeqCst) > before_tick || worker.is_finished());
        }
        // Finish the waiter before asserting so a broken polling implementation cannot leak it.
        let checks = rig
            .server
            .requests()
            .iter()
            .filter(|r| r.path == "/api/v1/zones/check")
            .count();
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(start + Duration::from_secs(601));
        rig.daemon.shared.mail_ready.notify_all();
        let reply = worker.join().unwrap();
        assert_eq!(
            checks,
            before + 1,
            "five quiet minutes must add zero checks after the initial read"
        );
        assert_eq!(reply.value.unwrap()["timed_out"], true);
    }

    #[test]
    fn zone_wait_free_reuses_daemon_sse_and_checks_only_after_zone_event() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let streams = stream_count(&rig.server);
        let checks = || {
            rig.server
                .requests()
                .iter()
                .filter(|r| r.path == "/api/v1/zones/check")
                .count()
        };
        let before = checks();
        rig.server.enqueue(
            "/api/v1/zones/check",
            HttpReply::json(200, json!({"paths":[{"path":"src","status":"held"}]})),
        );
        let socket = socket(&rig);
        let worker = thread::spawn(move || {
            socket
                .wait_zone_free("alice", "src", Duration::from_secs(3))
                .unwrap()
                .unwrap()
        });
        eventually(|| checks() == before + 1);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(checks(), before + 1, "push wait must not poll the path");
        rig.server.enqueue("/api/v1/events", HttpReply::sse("id: 10\nevent: zone.released\ndata: {\"seq\":10,\"type\":\"zone.released\",\"payload\":{\"paths\":[\"src\"]}}\n\n"));
        assert!(worker.join().unwrap());
        assert_eq!(checks(), before + 2);
        for request in rig
            .server
            .requests()
            .iter()
            .filter(|r| r.path == "/api/v1/zones/check")
        {
            assert_eq!(request.body["mode"], "exclusive");
        }
        assert_eq!(
            stream_count(&rig.server),
            streams,
            "waiter opened a competing SSE stream"
        );
    }

    #[test]
    fn mail_push_plain_none_and_reply_to_my_ask_both_wake() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        seeded(&rig, "alice");
        publish(&rig, 1, mail(29, "alice", false, "none"));
        let answer = received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert_eq!(answer.messages.unwrap()[0].id, 29);
        let (received, worker) = waiting(&rig, "alice", EVENT_TIMEOUT);
        let mut reply = mail(30, "alice", false, "none");
        reply["reply_to"] = json!(12);
        publish(&rig, 2, reply);
        let answer = received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert_eq!(answer.messages.unwrap()[0].id, 30);
        assert!(
            !rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .iter()
                .any(|item| item.id == 30)
        );
        assert!(
            !rig.server
                .requests()
                .iter()
                .any(|r| r.path.ends_with("/seen"))
        );
    }

    #[test]
    fn mail_push_replaced_does_not_advance_cursor_or_thrash_two_daemons() {
        let rig = rig(true, None);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let mut config = rig.daemon.shared.config.clone();
        config.socket = rig._dir.path().join("second/agent.sock");
        config.state_root = rig._dir.path().join("second-state");
        let second = Daemon::start(
            config,
            Client::new(&rig.server.url(), "test-token".into()).unwrap(),
        )
        .unwrap();
        second
            .shared
            .sessions()
            .entry("alice".into())
            .or_default()
            .push_bound = true;
        second.shared.hear("alice");
        eventually(|| second.shared.push_ready.load(Ordering::Acquire));
        eventually(|| !rig.daemon.shared.push_ready.load(Ordering::Acquire));
        let count = stream_count(&rig.server);
        thread::sleep(Duration::from_millis(1200));
        assert_eq!(
            stream_count(&rig.server),
            count,
            "two daemons must not displace each other repeatedly"
        );
        assert_eq!(
            rig.daemon.shared.coordination_seq.load(Ordering::Relaxed),
            0
        );
        // Session changes bypass the 60-second pause.
        rig.daemon.shared.hear("charlie");
        eventually(|| stream_count(&rig.server) == count + 1);
    }

    #[test]
    fn mail_push_second_replacement_blocks_until_set_change_with_long_poll() {
        fn polls(server: &FakeServer) -> usize {
            server
                .requests()
                .iter()
                .filter(|r| {
                    r.path.starts_with("/api/v1/events")
                        && r.header("accept") != Some("text/event-stream")
                        && r.path.contains("wait=1")
                })
                .count()
        }
        let rig = rig(true, None);
        let clock = Instant::now();
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(clock);
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let initial = stream_count(&rig.server);
        rig.server
            .enqueue("/api/v1/events", HttpReply::replaced("peer-1"));
        eventually(|| rig.daemon.shared.push.lock().unwrap().replacement.is_some());
        eventually(|| polls(&rig.server) > 0);
        let before = polls(&rig.server);
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(clock + Duration::from_secs(59));
        rig.daemon.shared.nudge();
        eventually(|| polls(&rig.server) > before);
        assert_eq!(
            stream_count(&rig.server),
            initial,
            "no retry before 60 seconds"
        );
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(clock + Duration::from_secs(61));
        rig.daemon.shared.nudge();
        eventually(|| stream_count(&rig.server) == initial + 1);
        eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
        rig.server
            .enqueue("/api/v1/events", HttpReply::replaced("peer-2"));
        eventually(|| {
            rig.daemon
                .shared
                .push
                .lock()
                .unwrap()
                .replacement
                .as_ref()
                .is_some_and(|r| r.retried)
        });
        let before = polls(&rig.server);
        rig.daemon.shared.push.lock().unwrap().clock_now = Some(clock + Duration::from_secs(3600));
        rig.daemon.shared.nudge();
        eventually(|| polls(&rig.server) > before + 1);
        assert_eq!(
            stream_count(&rig.server),
            initial + 1,
            "second replaced forbids hourly retries"
        );
        // Coordination events still invalidate the view during displacement fallback.
        let generation = rig.daemon.shared.read_view().zones_generation;
        rig.server.enqueue(
            "/api/v1/events",
            HttpReply::json(
                200,
                json!({"events":[
                    {"seq":3,"type":"zone.foo","payload":{}}
                ]}),
            ),
        );
        // Either the shared long-poll or a per-session fallback poll can receive
        // this scripted page; both must invalidate the same mirror.
        eventually(|| rig.daemon.shared.read_view().zones_generation > generation);
        rig.daemon.shared.hear("charlie");
        eventually(|| stream_count(&rig.server) == initial + 2);
        eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
    }

    #[test]
    fn mail_push_overflow_only_extra_sessions_poll() {
        let rig = rig(true, None);
        for i in 0..33 {
            let name = format!("session-{i:02}");
            rig.server.bind_session(&name, "test-token");
            let mut sessions = rig.daemon.shared.sessions();
            let track = sessions.entry(name).or_default();
            track.push_bound = true;
            track.heard = Some(Instant::now());
        }
        let (received, worker) = waiting(&rig, "session-32", EVENT_TIMEOUT);
        rig.daemon.shared.nudge();
        seeded(&rig, "session-32");
        assert_eq!(rig.daemon.shared.active_push_sessions().len(), 32);
        assert!(!rig.daemon.shared.push_fallback.load(Ordering::Acquire));
        assert!(rig.daemon.shared.poll_push_session("session-32"));
        assert!(!rig.daemon.shared.poll_push_session("session-00"));
        eventually(|| inbox_count(&rig.server, "session-32") >= 4);
        eventually(|| inbox_count(&rig.server, "session-00") == 2);
        rig.daemon.shared.stop();
        received.recv_timeout(EVENT_TIMEOUT).unwrap();
        worker.join().unwrap();
        assert!(inbox_count(&rig.server, "session-32") >= 4);
        assert_eq!(inbox_count(&rig.server, "session-00"), 2);
    }

    #[test]
    fn mail_push_failed_response_does_not_commit_wake() {
        let rig = rig(true, Some(mail(42, "alice", true, "reply")));
        rig.daemon.shared.hear("alice");
        seeded(&rig, "alice");
        let reply = rig.daemon.shared.wait_mail("alice", 0, 1000, &mut || false);
        assert_eq!(reply.messages.as_ref().unwrap()[0].id, 42);
        let (mut writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        assert!(write_reply(&mut writer, &reply).is_err());
        rig.daemon.shared.confirm_mail_wake("alice", &reply, false);
        assert_eq!(rig.daemon.shared.push.lock().unwrap().woken["alice"].id, 0);
        assert!(
            socket(&rig)
                .wait_mail("alice", 0, EVENT_TIMEOUT)
                .unwrap()
                .messages
                .is_some()
        );
        eventually(|| rig.daemon.shared.push.lock().unwrap().woken["alice"].id == 42);
    }
}
