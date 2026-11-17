// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Client-side "open mail": asks that still need this agent's reply or ack.
//!
//! When the server announces `mail_open_v1`, open mail is `GET /bus/inbox?open=true` (per-reader
//! handled state, including broadcasts). Otherwise open mail is derived from a peek of
//! `GET /bus/inbox?all=…` as in 0.3.10: cloud closes only on shared `status=ack`, local mode still
//! consults `sent`. A timed-out or failed optional read omits the open list rather than failing
//! status.

use lockyard_core::Backend;
use lockyard_core::OpenMail;
use lockyard_core::bus::BROADCAST;
use lockyard_core::proto::{InboxQuery, Message, Stamp, parse_rfc3339};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const OPEN_MAIL_DAYS_MS: i64 = 7 * 86_400_000;
/// Cap for one optional open-mail HTTP call (and the default whole-compute budget).
pub const SENT_BUDGET: Duration = Duration::from_millis(1_500);
/// Renew keeps open-mail enrichment even shorter so lease extension stays snappy.
pub const RENEW_BUDGET: Duration = Duration::from_secs(1);
const INBOX_PAGE: usize = 50;
/// Leave a little of the caller's budget for folding the answer after optional reads.
const CALL_RESERVE: Duration = Duration::from_millis(50);

/// Result of an open-mail compute, including whether the inbox page was truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMailSnapshot {
    pub items: Vec<OpenMail>,
    pub truncated: bool,
}

/// Compute open mail using an already-opened backend and a caller-owned budget.
///
/// Each network call is capped at `min(remaining − reserve, `[`SENT_BUDGET`]`)`. Returns `None`
/// when a required read fails or exceeds its cap, so status can omit the field.
pub fn open_mail_within(
    backend: &dyn Backend,
    me: &str,
    now: i64,
    budget: Duration,
) -> Option<OpenMailSnapshot> {
    let started = Instant::now();
    let left = || budget.saturating_sub(started.elapsed());
    let request_budget = || left().saturating_sub(CALL_RESERVE).min(SENT_BUDGET);

    // Capability first, inside the caller budget — never spend the open=true window on discovery.
    let capability_budget = request_budget();
    if capability_budget.is_zero() {
        return None;
    }
    let supported = match backend.mail_open_v1(capability_budget) {
        Ok(value) => value,
        // Capability probe failed: omit the list (do not fall back to the legacy filter).
        Err(_) => return None,
    };

    let inbox_budget = request_budget();
    if inbox_budget.is_zero() {
        return None;
    }

    if supported {
        let page = backend
            .peek_open_inbox_within(me, INBOX_PAGE, now, inbox_budget)
            .ok()?;
        return Some(OpenMailSnapshot {
            // Still drop shared ack/info rows if a rolled-back server listed them.
            items: page
                .messages
                .iter()
                .filter(|message| !is_shared_handled(message))
                .map(to_open)
                .collect(),
            truncated: page.skipped > 0,
        });
    }

    let page = backend
        .peek_inbox_within(
            me,
            InboxQuery {
                all: true,
                limit: INBOX_PAGE,
            },
            now,
            inbox_budget,
        )
        .ok()?;

    let replied = if backend.is_cloud() {
        // Cloud `/bus/sent` does not return reply_to / in_reply_to; skip the extra request.
        HashSet::new()
    } else {
        let sent_budget = request_budget();
        if sent_budget.is_zero() {
            return None;
        }
        let receipts = backend.sent_within(me, INBOX_PAGE, sent_budget).ok()?;
        receipts
            .into_iter()
            .filter_map(|receipt| receipt.reply_to)
            .collect()
    };

    Some(OpenMailSnapshot {
        items: filter_open(&page.messages, me, now, &replied),
        truncated: page.skipped > 0,
    })
}

/// Open-mail count for renew answers within a caller-owned budget.
#[cfg(test)]
pub fn open_mail_count_within(
    backend: &dyn Backend,
    me: &str,
    now: i64,
    budget: Duration,
) -> Option<usize> {
    open_mail_within(backend, me, now, budget).map(|snap| snap.items.len())
}

pub fn open_mail_lines(mail: &[OpenMail]) -> Vec<String> {
    let mut lines = Vec::new();
    for item in mail.iter().take(5) {
        let body: String = item.subject.chars().take(80).collect();
        let body = if item.subject.chars().count() > 80 {
            format!("{body}…")
        } else {
            body
        };
        lines.push(format!(
            "needs a reply: M-{} from {}, {}: {body}",
            item.id, item.from, item.at
        ));
    }
    if mail.len() > 5 {
        lines.push(format!("and {} more", mail.len() - 5));
    }
    lines
}

fn filter_open(messages: &[Message], me: &str, now: i64, replied: &HashSet<i64>) -> Vec<OpenMail> {
    messages
        .iter()
        .filter(|message| is_open(message, me, now, replied))
        .map(to_open)
        .collect()
}

fn is_shared_handled(message: &Message) -> bool {
    matches!(message.status.as_deref(), Some("ack") | Some("info"))
}

fn is_open(message: &Message, me: &str, now: i64, replied: &HashSet<i64>) -> bool {
    if message.from == me {
        return false;
    }
    let addressed = message.to == me || message.to == BROADCAST;
    if !addressed {
        return false;
    }
    if replied.contains(&message.id) {
        return false;
    }
    // Shared status: ack/info means handled for every reader until mail_open_v1 is used.
    if is_shared_handled(message) {
        return false;
    }
    // A stored reply is kind=ask, needs=none, in_reply_to set — not an outstanding ask.
    let needs = message.needs.as_deref().unwrap_or("none");
    if message.reply_to.is_some() && needs == "none" && !message.urgent {
        return false;
    }
    let kind = message.kind.as_deref().unwrap_or("ask");
    if kind != "ask" && needs == "none" && !message.urgent {
        return false;
    }
    let created = stamp_ms(&message.created_at);
    if created > 0 && now.saturating_sub(created) > OPEN_MAIL_DAYS_MS {
        return false;
    }
    true
}

pub(crate) fn to_open(message: &Message) -> OpenMail {
    let subject = message.body.lines().next().unwrap_or(message.body.as_str());
    OpenMail {
        id: message.id,
        from: escape_controls(&message.from),
        at: stamp_text(&message.created_at),
        kind: message.kind.clone(),
        needs: message.needs.clone(),
        subject: escape_controls(subject),
    }
}

fn escape_controls(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            ch if ch.is_control() || is_bidi_control(ch) => format!("\\u{{{:x}}}", ch as u32),
            ch => ch.to_string(),
        })
        .collect()
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch as u32,
        0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
    )
}

fn stamp_ms(stamp: &Stamp) -> i64 {
    match stamp {
        Stamp::Millis(ms) => *ms,
        Stamp::Text(text) => parse_rfc3339(text).unwrap_or(0),
    }
}

fn stamp_text(stamp: &Stamp) -> String {
    match stamp {
        Stamp::Text(text) => text.clone(),
        Stamp::Millis(ms) => lockyard_core::proto::rfc3339(*ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockyard_core::Error;
    use lockyard_core::Result;
    use lockyard_core::proto::{
        BoardEntry, BoardWrite, Claim, ClaimQuery, ClaimRequest, InboxPage, Message, PresenceBeat,
        ReleaseRequest, RenewRequest, SendRequest, Stamp, WorkTask,
    };
    use lockyard_core::tasks::{Status, Task, TaskEvent, TaskSpec};
    use std::sync::Mutex;

    fn ask(id: i64, from: &str, to: &str, body: &str, created: i64) -> Message {
        Message {
            urgent: false,
            replied_at: None,
            id,
            thread_id: None,
            reply_to: None,
            kind: Some("ask".into()),
            from: from.into(),
            from_alias: None,
            address: None,
            role: None,
            from_client: None,
            to: to.into(),
            zone: None,
            re: None,
            status: None,
            needs: Some("none".into()),
            body: body.into(),
            key: None,
            expires_at: None,
            created_at: Stamp::Millis(created),
            deduplicated: false,
            queued: false,
        }
    }

    #[derive(Default)]
    struct MailMock {
        cloud: bool,
        mail_open: bool,
        /// When set, `mail_open_v1` returns this error (list omitted).
        capability_error: Mutex<Option<Error>>,
        /// When set, `peek_open_inbox_within` / legacy peek return this error.
        fail: Mutex<Option<Error>>,
        /// Server `open=true` page (capability path).
        open_page: Mutex<InboxPage>,
        /// Legacy `all=true` page.
        all_page: Mutex<InboxPage>,
        last_open: Mutex<bool>,
        last_all: Mutex<bool>,
    }

    impl MailMock {
        fn take_fail(&self) -> Result<()> {
            match self.fail.lock().unwrap().take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    impl Backend for MailMock {
        fn is_cloud(&self) -> bool {
            self.cloud
        }
        fn mail_open_v1(&self, _timeout: Duration) -> Result<bool> {
            match self.capability_error.lock().unwrap().take() {
                Some(error) => Err(error),
                None => Ok(self.mail_open),
            }
        }
        fn peek_open_inbox_within(
            &self,
            _agent: &str,
            _limit: usize,
            _now: i64,
            _timeout: Duration,
        ) -> Result<InboxPage> {
            *self.last_open.lock().unwrap() = true;
            self.take_fail()?;
            Ok(self.open_page.lock().unwrap().clone())
        }
        fn peek_inbox(&self, _agent: &str, query: InboxQuery, _now: i64) -> Result<InboxPage> {
            *self.last_all.lock().unwrap() = query.all;
            self.take_fail()?;
            Ok(self.all_page.lock().unwrap().clone())
        }
        fn touch_agent(&mut self, _: &str, _: i64) -> Result<()> {
            unreachable!()
        }
        fn agents(&self) -> Result<Vec<lockyard_core::proto::AgentSeen>> {
            unreachable!()
        }
        fn claim(&mut self, _: &str, _: &ClaimRequest, _: i64) -> Result<Claim> {
            unreachable!()
        }
        fn renew(&mut self, _: &str, _: Option<i64>, _: &RenewRequest, _: i64) -> Result<usize> {
            unreachable!()
        }
        fn release(
            &mut self,
            _: &str,
            _: Option<i64>,
            _: &ReleaseRequest,
            _: i64,
        ) -> Result<usize> {
            unreachable!()
        }
        fn claims(&self, _: &ClaimQuery, _: i64) -> Result<Vec<Claim>> {
            unreachable!()
        }
        fn check(
            &self,
            _: &str,
            _: &[String],
            _: Option<i64>,
            _: i64,
        ) -> Result<Vec<lockyard_core::proto::PathCheck>> {
            unreachable!()
        }
        fn send(&mut self, _: &str, _: &SendRequest, _: i64) -> Result<Message> {
            unreachable!()
        }
        fn reply(&mut self, _: &str, _: i64, _: &str, _: i64) -> Result<Message> {
            unreachable!()
        }
        fn inbox(&mut self, _: &str, _: InboxQuery, _: i64) -> Result<InboxPage> {
            unreachable!()
        }
        fn unread(&self, _: &str) -> Result<i64> {
            Ok(0)
        }
        fn inbox_seen(&mut self, _: &str, _: &[i64], _: i64) -> Result<usize> {
            unreachable!()
        }
        fn inbox_claim(&mut self, _: &str, _: &str, _: &[i64], _: i64, _: i64) -> Result<Vec<i64>> {
            unreachable!()
        }
        fn tasks(&self, _: Option<Status>, _: bool) -> Result<Vec<Task>> {
            Ok(Vec::new())
        }
        fn work_list(&self, _: &str) -> Result<Vec<WorkTask>> {
            Ok(Vec::new())
        }
        fn lost(&self, _: &str) -> Result<Vec<lockyard_core::proto::LostClaim>> {
            Ok(Vec::new())
        }
        fn task(&self, _: &str) -> Result<Task> {
            unreachable!()
        }
        fn task_history(&self, _: &str) -> Result<Vec<TaskEvent>> {
            Ok(Vec::new())
        }
        fn add_task(&mut self, _: &str, _: &TaskSpec, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn claim_task(&mut self, _: &str, _: &str, _: i64, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn renew_task(&mut self, _: &str, _: &str, _: i64, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn release_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn submit_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn accept_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn reject_task(&mut self, _: &str, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn cancel_task(&mut self, _: &str, _: &str, _: &str, _: i64) -> Result<Task> {
            unreachable!()
        }
        fn board_set(&mut self, _: &str, _: &BoardWrite, _: i64) -> Result<BoardEntry> {
            unreachable!()
        }
        fn board_get(&self, _: &str, _: i64) -> Result<Option<BoardEntry>> {
            unreachable!()
        }
        fn board_remove(&mut self, _: &str, _: &str) -> Result<bool> {
            unreachable!()
        }
        fn board_list(&self, _: Option<&str>, _: i64) -> Result<Vec<BoardEntry>> {
            unreachable!()
        }
        fn heartbeat(&mut self, _: &str, _: &PresenceBeat, _: i64) -> Result<()> {
            unreachable!()
        }
        fn presence(&self, _: i64, _: i64) -> Result<Vec<lockyard_core::proto::Presence>> {
            unreachable!()
        }
    }

    #[test]
    fn a_seen_ask_stays_open_until_this_agent_replies() {
        let now = 1_000_000_i64;
        let mail = ask(7, "bob", "alice", "need a path", now);
        let open = filter_open(std::slice::from_ref(&mail), "alice", now, &HashSet::new());
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, 7);
        let replied = HashSet::from([7]);
        assert!(filter_open(&[mail], "alice", now, &replied).is_empty());
    }

    #[test]
    fn own_mail_and_ack_status_are_not_open() {
        let now = 1_000_000_i64;
        let mut own = ask(1, "alice", "bob", "mine", now);
        own.from = "alice".into();
        let mut acked = ask(2, "bob", "alice", "done", now);
        acked.status = Some("ack".into());
        assert!(filter_open(&[own, acked], "alice", now, &HashSet::new()).is_empty());
    }

    #[test]
    fn a_received_reply_with_needs_none_is_not_open() {
        let now = 1_000_000_i64;
        let mut reply = ask(9, "bob", "alice", "here is the path", now);
        reply.reply_to = Some(7);
        reply.needs = Some("none".into());
        assert!(filter_open(&[reply], "alice", now, &HashSet::new()).is_empty());
    }

    #[test]
    fn local_reply_with_unset_kind_and_needs_is_not_open() {
        let now = 1_000_000_i64;
        let mut reply = ask(9, "bob", "alice", "done", now);
        reply.reply_to = Some(7);
        reply.kind = None;
        reply.needs = None;
        assert!(filter_open(&[reply], "alice", now, &HashSet::new()).is_empty());
    }

    #[test]
    fn mail_older_than_seven_days_is_not_open() {
        let now = OPEN_MAIL_DAYS_MS + 1_000_000;
        let old = ask(3, "bob", "alice", "stale", now - OPEN_MAIL_DAYS_MS - 1);
        let fresh = ask(4, "bob", "alice", "fresh", now - OPEN_MAIL_DAYS_MS + 1_000);
        let open = filter_open(&[old, fresh], "alice", now, &HashSet::new());
        assert_eq!(open.iter().map(|m| m.id).collect::<Vec<_>>(), vec![4]);
    }

    #[test]
    fn subject_and_from_escape_controls() {
        let now = 1_000_000_i64;
        let mut mail = ask(1, "bo\nb", "alice", "sub\u{202e}ject", now);
        mail.from = "bo\nb".into();
        let open = to_open(&mail);
        assert_eq!(open.from, "bo\\nb");
        assert_eq!(open.subject, "sub\\u{202e}ject");
    }

    #[test]
    fn open_mail_lines_are_english() {
        let mail = [OpenMail {
            id: 1,
            from: "bob".into(),
            at: "t".into(),
            kind: None,
            needs: None,
            subject: "hello".into(),
        }];
        let lines = open_mail_lines(&mail);
        assert!(
            lines[0].starts_with("needs a reply: M-1 from bob"),
            "{lines:?}"
        );
    }

    #[test]
    fn with_mail_open_v1_the_server_open_list_is_trusted() {
        let now = 1_000_000_i64;
        // Legacy all-page still contains a broadcast this agent already answered — would stay
        // "open" under 0.3.10 cloud filtering. The server open page correctly omits it.
        let answered = ask(1, "bob", "*", "broadcast already answered", now);
        let pending = ask(2, "bob", "*", "still needs a reply", now);
        let backend = MailMock {
            cloud: true,
            mail_open: true,
            open_page: Mutex::new(InboxPage {
                messages: vec![pending.clone()],
                skipped: 0,
            }),
            all_page: Mutex::new(InboxPage {
                messages: vec![answered, pending],
                skipped: 0,
            }),
            ..MailMock::default()
        };
        let snap = open_mail_within(&backend, "alice", now, SENT_BUDGET).expect("open mail");
        assert_eq!(snap.items.iter().map(|m| m.id).collect::<Vec<_>>(), vec![2]);
        assert!(*backend.last_open.lock().unwrap());
        assert!(!*backend.last_all.lock().unwrap());
    }

    #[test]
    fn without_mail_open_v1_legacy_cloud_filtering_remains() {
        let now = 1_000_000_i64;
        let mut answered_broadcast = ask(1, "bob", "*", "acked for everyone", now);
        answered_broadcast.status = Some("ack".into());
        let pending = ask(2, "bob", "alice", "still open", now);
        let backend = MailMock {
            cloud: true,
            mail_open: false,
            all_page: Mutex::new(InboxPage {
                messages: vec![answered_broadcast, pending],
                skipped: 0,
            }),
            ..MailMock::default()
        };
        let snap = open_mail_within(&backend, "alice", now, SENT_BUDGET).expect("open mail");
        assert_eq!(snap.items.iter().map(|m| m.id).collect::<Vec<_>>(), vec![2]);
        assert!(!*backend.last_open.lock().unwrap());
        assert!(*backend.last_all.lock().unwrap());
    }

    #[test]
    fn open_inbox_error_omits_the_list() {
        let backend = MailMock {
            cloud: true,
            mail_open: true,
            fail: Mutex::new(Some(Error::Unavailable("timeout".into()))),
            ..MailMock::default()
        };
        assert!(open_mail_within(&backend, "alice", 1_000_000, SENT_BUDGET).is_none());
    }

    #[test]
    fn capability_error_omits_the_list_instead_of_legacy_filter() {
        let now = 1_000_000_i64;
        let pending = ask(2, "bob", "alice", "still open", now);
        let backend = MailMock {
            cloud: true,
            mail_open: false,
            capability_error: Mutex::new(Some(Error::Unavailable("capability unavailable".into()))),
            all_page: Mutex::new(InboxPage {
                messages: vec![pending],
                skipped: 0,
            }),
            ..MailMock::default()
        };
        assert!(open_mail_within(&backend, "alice", now, SENT_BUDGET).is_none());
        assert!(!*backend.last_all.lock().unwrap());
        assert!(!*backend.last_open.lock().unwrap());
    }

    #[test]
    fn server_open_page_still_drops_status_info() {
        let now = 1_000_000_i64;
        let mut info = ask(1, "bob", "alice", "informational", now);
        info.status = Some("info".into());
        let pending = ask(2, "bob", "alice", "still open", now);
        let backend = MailMock {
            cloud: true,
            mail_open: true,
            open_page: Mutex::new(InboxPage {
                messages: vec![info, pending],
                skipped: 0,
            }),
            ..MailMock::default()
        };
        let snap = open_mail_within(&backend, "alice", now, SENT_BUDGET).expect("open mail");
        assert_eq!(snap.items.iter().map(|m| m.id).collect::<Vec<_>>(), vec![2]);
    }
}
