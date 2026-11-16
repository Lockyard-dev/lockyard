// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use lockyard_core::proto::Event;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct PushState {
    epoch: u64,
    replacement: Option<Replacement>,
    #[cfg(test)]
    clock_now: Option<Instant>,
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

fn wakes(message: &Message) -> bool {
    crate::mail_wait::actionable(message)
}

fn is_open(mail: &Message) -> bool {
    !matches!(mail.status.as_deref(), Some("ack" | "info"))
        && (wakes(mail)
            || (mail.reply_to.is_none() && mail.kind.as_deref().unwrap_or("ask") == "ask"))
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
    pub(super) fn peek_hook_mail(&self, session: &str) -> Reply {
        self.hear(session);
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(mailbox) = push.mailboxes.get(session).filter(|m| m.seeded) {
            return Reply {
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
            let deadline = Instant::now()
                .checked_add(Duration::from_millis(timeout_ms))
                .ok_or_else(|| Error::Invalid("zone wait timeout is too large".into()))?;
            self.hear(session);
            let push_server = self.transport.mail_push_v1(session)?;
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
                let left = deadline.saturating_duration_since(Instant::now());
                let ms = left.as_millis().max(1).min(u64::MAX as u128) as u64;
                call.deadline_ms = Some(ms);
                call.attempt_timeout_ms = Some(ms);
                let answer = match self.transport.call(&call) {
                    Ok(answer) => answer,
                    Err(_) if Instant::now() >= deadline && timeout_ms > 0 => return Ok(false),
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
                if Instant::now() >= deadline || self.stopped() {
                    return Ok(false);
                }
                let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
                let next = if push_server {
                    deadline.min(Instant::now() + Duration::from_secs(60))
                } else {
                    deadline.min(Instant::now() + Duration::from_secs(10))
                };
                while push.zone_version == version && Instant::now() < next && !self.stopped() {
                    if disconnected() {
                        return Ok(false);
                    }
                    let wait = next
                        .saturating_duration_since(Instant::now())
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
                if Instant::now() >= deadline || self.stopped() {
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
            if is_open(&mail) {
                mailbox.open.insert(mail.id, mail);
            }
        }
        for mut mail in arrivals {
            if mail.body.is_empty()
                && let Some(existing) = mailbox.unread.get(&mail.id)
            {
                mail.body.clone_from(&existing.body);
            }
            if is_open(&mail) {
                mailbox.open.insert(mail.id, mail.clone());
            }
            mailbox.unread.insert(mail.id, mail);
        }
        for id in &mailbox.read_ids {
            mailbox.unread.remove(id);
            mailbox.open.remove(id);
        }
        for id in &mailbox.handled_ids {
            mailbox.open.remove(id);
        }
        mailbox.seeded = true;
        mailbox.seeded_at = Some(Instant::now());
        let count = mailbox.unread.len() as i64 + mailbox.skipped;
        drop(push);
        self.update_push_count(session, count);
        Ok(())
    }

    fn update_push_count(&self, session: &str, count: i64) {
        let mut view = self.write_view();
        let entry = view.unread.entry(session.into()).or_default();
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
            let seeded = push.mailboxes.get(session).is_some_and(|m| m.seeded);
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
                            wakes(mail)
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
            && let Some(body) = rows
                .iter()
                .find(|m| m["id"] == mail.id)
                .and_then(|m| m["body"].as_str())
        {
            mail.body = body.to_string();
            let mut push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(mailbox) = push.mailboxes.get_mut(session) {
                if let Some(cached) = mailbox.unread.get_mut(&mail.id) {
                    cached.body.clone_from(&mail.body);
                }
                if let Some(cached) = mailbox.open.get_mut(&mail.id) {
                    cached.body.clone_from(&mail.body);
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
                .map(crate::open_mail::to_open)
                .collect(),
            truncated: mailbox.open_truncated,
        })
    }

    pub(super) fn confirm_push_counts(&self) {
        let push = self.push.lock().unwrap_or_else(PoisonError::into_inner);
        for (session, mailbox) in &push.mailboxes {
            if mailbox.seeded {
                self.update_push_count(session, mailbox.unread.len() as i64 + mailbox.skipped);
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
                mailbox.open.remove(&id);
                mailbox.read_ids.insert(id);
            }
            self.update_push_count(session, mailbox.unread.len() as i64 + mailbox.skipped);
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
                if !mailbox.read_ids.contains(&mail.id) && !mailbox.handled_ids.contains(&mail.id) {
                    mailbox.sequences.insert(mail.id, event.seq);
                    if is_open(&mail) {
                        mailbox.open.insert(mail.id, mail.clone());
                    }
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
                mailbox.open.remove(&id);
                mailbox.read_ids.insert(id);
                mailbox.handled_ids.insert(id);
            }
        } else {
            return false;
        }
        for (session, mailbox) in &push.mailboxes {
            self.update_push_count(session, mailbox.unread.len() as i64 + mailbox.skipped);
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

    fn replacement_now(&self) -> Instant {
        #[cfg(test)]
        if let Some(now) = self
            .push
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clock_now
        {
            return now;
        }
        Instant::now()
    }

    fn replacement_allows_stream(&self, sessions: &[String]) -> bool {
        let now = self.replacement_now();
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
        let now = self.replacement_now();
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
                    let started = self.replacement_now();
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
            self.pause(
                pause
                    .mul_f64(0.75 + jitter as f64 / 200.0)
                    .min(Duration::from_secs(30)),
            );
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
        let mut next_discovery = Instant::now();
        let mut fallback_until = None;
        let mut first_discovery = true;
        let mut pause = self.timing().retry_min;
        while !self.stopped() {
            if Instant::now() >= next_discovery {
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
                        next_discovery = Instant::now() + interval;
                    }
                    Err(error) => {
                        eprintln!("lockyard agent: mail protocol discovery: {error}");
                        next_discovery = Instant::now() + self.timing().retry_min;
                    }
                }
            }
            if self.mail_protocol.load(Ordering::Acquire) == 1
                && fallback_until.is_none_or(|until| Instant::now() >= until)
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
                    fallback_until = Some(Instant::now() + interval);
                    next_discovery = Instant::now();
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
                            .saturating_duration_since(Instant::now())
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

    struct Rig {
        daemon: Daemon<Client>,
        server: FakeServer,
        _dir: tempfile::TempDir,
    }
    #[track_caller]
    fn eventually(mut test: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(5);
        while !test() {
            assert!(Instant::now() < until, "condition timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[test]
    fn mail_reply_without_needs_is_closed_and_does_not_wake() {
        let mut mail: Message = serde_json::from_value(
            json!({"id":1,"from":"bob","to":"alice","reply_to":9,"needs":"none","body":"Принято"}),
        )
        .unwrap();
        assert!(!wakes(&mail));
        assert!(!is_open(&mail));
        mail.needs = Some("ack".into());
        assert!(wakes(&mail));
        assert!(is_open(&mail));
        mail.needs = None;
        mail.urgent = true;
        assert!(wakes(&mail));
        assert!(is_open(&mail));
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
            Duration::from_secs(1),
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
            let (received, worker) = waiting(&rig, "alice", Duration::from_secs(3));
            seeded(&rig, "alice");
            let reads = rig
                .server
                .requests()
                .iter()
                .filter(|r| r.method == "GET" && r.path.starts_with("/api/v1/bus/inbox"))
                .count();
            publish(&rig, 1, mail(1, "alice", false, "none"));
            assert!(
                received.try_recv().is_err(),
                "informational mail must not wake"
            );
            publish(&rig, 2, mail(2, "other", true, "reply"));
            assert!(
                received.try_recv().is_err(),
                "another recipient must not wake"
            );
            publish(&rig, 3, mail(3, "alice", urgent, needs));
            let reply = received.recv_timeout(Duration::from_secs(2)).unwrap();
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
                .wait_mail("alice", 0, Duration::from_secs(1))
                .unwrap()
                .messages
                .unwrap()[0]
                .id,
            43
        );
        publish(&rig, 44, mail(41, "alice", true, "reply"));
        assert_eq!(
            socket(&rig)
                .wait_mail("alice", 0, Duration::from_secs(1))
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
        let (old, first) = waiting(&rig, "alice", Duration::from_secs(3));
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
            crate::mail_wait::outcome(old.recv_timeout(Duration::from_secs(1)).unwrap()).is_none()
        );
        first.join().unwrap();
        assert!(
            crate::mail_wait::outcome(new.recv_timeout(Duration::from_secs(2)).unwrap()).is_none()
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(2));
        seeded(&rig, "alice");
        publish(&rig, 7, mail(70, "alice", true, "none"));
        received.recv_timeout(Duration::from_secs(1)).unwrap();
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(3));
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
        let reply = received.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(reply.messages.unwrap()[0].id, i64::from(i32::MAX) + 10);
        worker.join().unwrap();
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
        assert!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(
            crate::mail_wait::wait_on(&socket(&rig), "alice", Duration::from_millis(30)),
            0
        );
        publish(&rig, 3, mail(43, "alice", true, "reply"));
        receipt(&rig, 4, "bus.handled", "alice", json!({"handled":[43]}));
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
        assert!(
            rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .is_empty()
        );
        publish(&rig, 5, mail(44, "alice", true, "ack"));
        receipt(&rig, 6, "bus.ack", "alice", json!({"id":44}));
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
        rig.server.enqueue(
            "/api/v1/bus/inbox",
            HttpReply::json(
                200,
                json!({"messages":[mail(9,"alice",true,"reply")],"skipped":0}),
            )
            .delay(Duration::from_millis(150)),
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
        assert!(
            crate::mail_wait::outcome(received.recv_timeout(Duration::from_secs(2)).unwrap())
                .is_none()
        );
        worker.join().unwrap();
        assert_eq!(rig.daemon.shared.unread("alice").unread, Some(0));
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(2));
        seeded(&rig, "alice");
        rig.server.enqueue(
            "/api/v1/bus/threads/42",
            HttpReply::json(200, json!({"messages":[mail(42,"alice",true,"reply")]})),
        );
        let mut metadata = mail(42, "alice", true, "reply");
        metadata.as_object_mut().unwrap().remove("body");
        publish(&rig, 1, metadata);
        let reply = received.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert_eq!(reply.messages.unwrap()[0].body, "hello");
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(2));
        seeded(&rig, "alice");
        publish(&rig, 1, mail(42, "alice", true, "reply"));
        received.recv_timeout(Duration::from_secs(1)).unwrap();
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
        let rig = rig_with(true, None, |server, config| {
            let state = config.state_root.join(state_folder(config));
            fs::create_dir_all(&state).unwrap();
            save_seq(&state, "coordination", 4).unwrap();
            let message = json!({"seq":5,"type":"bus.message","session":"alice","payload":mail(42,"*",true,"reply")});
            let seen = json!({"seq":6,"type":"bus.seen","session":"alice","payload":{"seen":[42]}});
            server.enqueue("/api/v1/events", HttpReply::sse(&format!(
                "id: 5\nevent: bus.message\ndata: {message}\n\nid: 6\nevent: bus.seen\ndata: {seen}\n\nid: 6\nevent: ready\ndata: {{\"head\":6}}\n\n"))
                .delay(Duration::from_millis(150)));
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
        assert!(
            received
                .recv_timeout(Duration::from_secs(2))
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(2));
        seeded(&rig, "alice");
        assert!(received.try_recv().is_err());
        publish(&rig, 1, mail(100, "alice", true, "reply"));
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(3));
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
                .recv_timeout(Duration::from_secs(1))
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(2));
        seeded(&rig, "alice");
        publish(&rig, 1, mail(42, "alice", true, "reply"));
        received.recv_timeout(Duration::from_secs(1)).unwrap();
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(3));
        seeded(&rig, "alice");
        let started = Instant::now();
        rig.daemon.shutdown();
        assert!(started.elapsed() < Duration::from_secs(1));
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_reconnect_backoff_resets_on_handshake_without_event() {
        use std::sync::atomic::AtomicUsize;
        struct Script {
            client: Client,
            attempts: Mutex<Vec<Instant>>,
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
                self.attempts.lock().unwrap().push(Instant::now());
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
            socket: dir.path().join("run/agent.sock"),
            state_root: dir.path().join("state"),
            timing: Timing {
                retry_min: Duration::from_millis(60),
                ..Timing::default()
            },
        };
        let daemon = Daemon::start(
            config,
            Script {
                client: Client::new(&server.url(), "test-token".into()).unwrap(),
                attempts: Mutex::new(Vec::new()),
                next: AtomicUsize::new(0),
            },
        )
        .unwrap();
        server.bind_session("alice", "test-token");
        daemon
            .shared
            .sessions()
            .entry("alice".into())
            .or_default()
            .push_bound = true;
        daemon.shared.hear("alice");
        eventually(|| daemon.shared.transport.attempts.lock().unwrap().len() >= 5);
        let attempts = daemon.shared.transport.attempts.lock().unwrap();
        let before_success = attempts[3].duration_since(attempts[2]);
        let after_success = attempts[4].duration_since(attempts[3]);
        assert!(
            after_success < before_success / 2,
            "successful handshake must reset backoff: {before_success:?} -> {after_success:?}"
        );
    }

    #[test]
    fn mail_push_fallback_rechecks_negotiation_after_interval() {
        let mut rig = rig(true, None);
        rig.daemon.stop_workers();
        rig.daemon.shared.signal().stop = false;
        rig.daemon.shared.hear("alice");
        rig.server
            .enqueue("/api/v1/events#sse", HttpReply::text(406, "no SSE"));
        let before = rig.server.discovery_requests().len();
        let shared = rig.daemon.shared.clone();
        let worker = thread::spawn(move || {
            shared.coordination_loop_with_interval(Duration::from_millis(200))
        });
        eventually(|| rig.server.discovery_requests().len() > before);
        assert!(!rig.daemon.shared.push_enabled.load(Ordering::Acquire));
        eventually(|| rig.daemon.shared.push_ready.load(Ordering::Acquire));
        assert!(rig.server.discovery_requests().len() >= before + 2);
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
        let (alice, a) = waiting(&rig, "alice", Duration::from_secs(2));
        seeded(&rig, "alice");
        let (charlie, c) = waiting(&rig, "charlie", Duration::from_secs(2));
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
            alice
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .messages
                .unwrap()[0]
                .to,
            "alice"
        );
        assert_eq!(
            charlie
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .messages
                .unwrap()[0]
                .to,
            "charlie"
        );
        assert!(
            bob.recv_timeout(Duration::from_secs(1))
                .unwrap()
                .messages
                .is_none()
        );
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
        }
        impl Pending {
            fn ready(&self) {
                let (lock, wake) = &*self.gate;
                let guard = lock.lock().unwrap();
                let (_guard, timeout) = wake
                    .wait_timeout_while(guard, Duration::from_secs(1), |ready| !*ready)
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
        let config = AgentConfig {
            url: server.url(),
            workspace: "test".into(),
            token_id: "test".into(),
            socket: dir.path().join("run/agent.sock"),
            state_root: dir.path().join("state"),
            timing: Timing::default(),
        };
        let daemon = Daemon::start(
            config.clone(),
            Pending {
                client: Client::new(&server.url(), "test-token".into()).unwrap(),
                gate: gate.clone(),
            },
        )
        .unwrap();
        let socket = AgentSocket::connect(
            &config.socket,
            &server.url(),
            "test",
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(!daemon.shared.push_enabled.load(Ordering::Acquire));
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
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
                .recv_timeout(Duration::from_secs(2))
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
        thread::sleep(Duration::from_millis(100));
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
                .recv_timeout(Duration::from_secs(2))
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
        let (received, worker) = waiting(&rig, "alice", Duration::from_millis(5500));
        seeded(&rig, "alice");
        seeded(&rig, "bob");
        thread::sleep(Duration::from_millis(100));
        let bob_reads = inbox_count(&rig.server, "bob");
        let alice_reads = inbox_count(&rig.server, "alice");
        let cycles = rig.daemon.shared.upkeep_cycles.load(Ordering::Relaxed);
        thread::sleep(Duration::from_secs(5));
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
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn mail_push_self_mail_recipient_wakes_sender_copy_does_not() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(3));
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
                .recv_timeout(Duration::from_secs(2))
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
                .recv_timeout(Duration::from_secs(2))
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
    fn mail_push_reply_to_needs_none_is_hook_only_without_wake_or_read_receipt() {
        let rig = rig(true, None);
        let (received, worker) = waiting(&rig, "alice", Duration::from_secs(3));
        seeded(&rig, "alice");
        let mut reply = mail(30, "alice", false, "none");
        reply["reply_to"] = json!(12);
        publish(&rig, 1, reply);
        assert!(received.recv_timeout(Duration::from_millis(150)).is_err());
        assert!(
            !rig.daemon
                .shared
                .push_open_snapshot("alice")
                .unwrap()
                .items
                .iter()
                .any(|item| item.id == 30)
        );
        let mut urgent = mail(31, "alice", true, "none");
        urgent["reply_to"] = json!(12);
        publish(&rig, 2, urgent);
        let answer = received.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        assert_eq!(answer.messages.unwrap()[0].id, 31);
        let peek = rig.daemon.shared.peek_hook_mail("alice");
        assert!(
            peek.messages
                .unwrap()
                .iter()
                .any(|message| message.id == 30)
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
        let (received, worker) = waiting(&rig, "session-32", Duration::from_millis(1500));
        rig.daemon.shared.nudge();
        seeded(&rig, "session-32");
        assert_eq!(rig.daemon.shared.active_push_sessions().len(), 32);
        assert!(!rig.daemon.shared.push_fallback.load(Ordering::Acquire));
        assert!(rig.daemon.shared.poll_push_session("session-32"));
        assert!(!rig.daemon.shared.poll_push_session("session-00"));
        received.recv_timeout(Duration::from_secs(3)).unwrap();
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
                .wait_mail("alice", 0, Duration::from_secs(1))
                .unwrap()
                .messages
                .is_some()
        );
        eventually(|| rig.daemon.shared.push.lock().unwrap().woken["alice"].id == 42);
    }
}
