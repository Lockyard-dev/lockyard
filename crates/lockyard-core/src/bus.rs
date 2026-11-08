// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! The message bus. Mail is addressed to one agent or to everyone, and each reader keeps its own
//! read marks, so a broadcast reaches every agent exactly once.

use crate::store::validate_agent;
use crate::{Error, Result, Store};
use rusqlite::{OptionalExtension, Row, params};
use serde::Serialize;

/// Address of a message for every agent.
pub const BROADCAST: &str = "*";
/// Longest message body in bytes. A larger text belongs in a file.
pub const MAX_BODY_BYTES: usize = 8 * 1024;
/// Age after which mail is deleted.
pub const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

const COLUMNS: &str = "id, from_agent, to_agent, body, reply_to, created_at";

/// How far a message got, in the words of the shared contract.
///
/// A sender who cannot tell "nobody has looked at it" from "they read it and said nothing" ends
/// up asking again, which is the noise the bus exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Delivery {
    /// Written down, not yet put in front of anyone.
    Sent,
    /// Shown to the recipient by a hook or an inbox read.
    Delivered,
    /// The recipient marked it read.
    Read,
    /// The recipient answered it.
    Replied,
    /// It will not arrive: it aged out before it was ever shown.
    Failed,
}

impl Delivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Read => "read",
            Self::Replied => "replied",
            Self::Failed => "failed",
        }
    }
}

/// One of this agent's own messages and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub id: i64,
    pub to: String,
    pub body: String,
    pub created_at: i64,
    pub status: Delivery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replied_at: Option<i64>,
}

/// One message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Message {
    pub id: i64,
    pub from: String,
    pub to: String,
    pub body: String,
    pub reply_to: Option<i64>,
    pub created_at: i64,
}

impl Store {
    /// Sends `body` to an agent seen in this project or to [`BROADCAST`].
    pub fn send(&mut self, from: &str, to: &str, body: &str, now: i64) -> Result<Message> {
        let _span = crate::perf::Span::new("message.send");
        if to != BROADCAST {
            validate_agent(to)?;
        }
        if to == from {
            return Err(Error::Invalid("cannot send a message to yourself".into()));
        }
        {
            let _touch = crate::perf::Span::new("message.touch_sender");
            self.touch(from, now)?;
        }
        let recipient_exists = {
            let _recipient = crate::perf::Span::new("message.recipient_lookup");
            to == BROADCAST || self.agent_exists(to)?
        };
        if !recipient_exists {
            return Err(Error::NotFound(format!(
                "no agent named {to} has been seen here, see `lockyard who`"
            )));
        }
        self.insert_message(from, to, body, None, now)
    }

    /// Answers message `id`. The answer goes to the other side of that message.
    pub fn reply(&mut self, agent: &str, id: i64, body: &str, now: i64) -> Result<Message> {
        self.touch(agent, now)?;
        let original = self.message(id)?;
        let to = if original.from == agent {
            original.to
        } else if original.to == agent || original.to == BROADCAST {
            original.from
        } else {
            return Err(Error::Denied(format!("M-{id} was not sent to this agent")));
        };
        self.insert_message(agent, &to, body, Some(id), now)
    }

    /// Mail for `agent`, oldest first: unread unless `all`, at most `limit` messages.
    /// With `mark`, the returned messages count as read afterwards.
    pub fn inbox(
        &mut self,
        agent: &str,
        all: bool,
        mark: bool,
        limit: usize,
        now: i64,
    ) -> Result<Vec<Message>> {
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let messages = {
            let mut statement = transaction.prepare(&format!(
                "SELECT {COLUMNS} FROM messages m
                 WHERE (m.to_agent = ?1 OR (m.to_agent = '*' AND m.from_agent <> ?1))
                   AND (?2 OR NOT EXISTS (
                       SELECT 1 FROM receipts r WHERE r.message_id = m.id AND r.agent = ?1))
                 ORDER BY m.id LIMIT ?3"
            ))?;
            statement
                .query_map(params![agent, all, limit], read_message)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        // Returning a message is the moment it reaches its recipient, whether or not the caller
        // goes on to mark it read: that is exactly "delivered" in the contract.
        for message in &messages {
            transaction.execute(
                "INSERT OR IGNORE INTO deliveries (message_id, agent, delivered_at)
                 VALUES (?1, ?2, ?3)",
                params![message.id, agent, now],
            )?;
        }
        if mark {
            for message in &messages {
                transaction.execute(
                    "INSERT OR IGNORE INTO receipts (message_id, agent, read_at)
                     VALUES (?1, ?2, ?3)",
                    params![message.id, agent, now],
                )?;
            }
        }
        transaction.commit()?;
        Ok(messages)
    }

    /// Read without changing agent registration, presence or delivery state.
    pub fn peek_inbox(&self, agent: &str, all: bool, limit: usize) -> Result<Vec<Message>> {
        validate_agent(agent)?;
        let mut statement = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM messages m
             WHERE (m.to_agent = ?1 OR (m.to_agent = '*' AND m.from_agent <> ?1))
               AND (?2 OR NOT EXISTS (SELECT 1 FROM receipts r WHERE r.message_id = m.id AND r.agent = ?1))
             ORDER BY m.id LIMIT ?3"))?;
        let rows = statement.query_map(
            params![agent, all, i64::try_from(limit).unwrap_or(i64::MAX)],
            read_message,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// How many messages `agent` has not read.
    pub fn unread(&self, agent: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM messages m
             WHERE (m.to_agent = ?1 OR (m.to_agent = '*' AND m.from_agent <> ?1))
               AND NOT EXISTS (
                   SELECT 1 FROM receipts r WHERE r.message_id = m.id AND r.agent = ?1)",
            [agent],
            |row| row.get(0),
        )?)
    }

    /// Marks only messages returned to the named reader as seen.
    pub fn inbox_seen(&mut self, agent: &str, ids: &[i64], now: i64) -> Result<usize> {
        self.touch(agent, now)?;
        if ids.iter().any(|id| *id <= 0) {
            return Err(Error::Invalid(
                "message ids must be positive integers".into(),
            ));
        }
        let transaction = self.write()?;
        let mut changed = 0;
        for id in ids {
            changed += transaction.execute(
                "INSERT OR IGNORE INTO receipts(message_id,agent,read_at)
                 SELECT id,?2,?3 FROM messages
                 WHERE id=?1 AND (to_agent=?2 OR (to_agent='*' AND from_agent<>?2))",
                params![id, agent, now],
            )?;
            // A message cannot be read without having arrived, so a receipt backfills the
            // delivery an earlier reader may have skipped.
            transaction.execute(
                "INSERT OR IGNORE INTO deliveries(message_id,agent,delivered_at)
                 SELECT id,?2,?3 FROM messages
                 WHERE id=?1 AND (to_agent=?2 OR (to_agent='*' AND from_agent<>?2))",
                params![id, agent, now],
            )?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    /// Reserves unseen mail for one delivery channel until the lease expires.
    pub fn inbox_claim(
        &mut self,
        agent: &str,
        channel: &str,
        ids: &[i64],
        lease_seconds: i64,
        now: i64,
    ) -> Result<Vec<i64>> {
        self.touch(agent, now)?;
        if channel.trim().is_empty() || lease_seconds <= 0 {
            return Err(Error::Invalid(
                "delivery channel is required and lease_seconds must be positive".into(),
            ));
        }
        if ids.iter().any(|id| *id <= 0) {
            return Err(Error::Invalid(
                "message ids must be positive integers".into(),
            ));
        }
        let transaction = self.write()?;
        let mut claimed = Vec::new();
        for id in ids {
            transaction.execute(
                "DELETE FROM delivery_claims WHERE message_id=?1 AND lease_until<=?2",
                params![id, now],
            )?;
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO delivery_claims(message_id,agent,channel,lease_until)
                 SELECT m.id,?2,?3,?4 FROM messages m
                 WHERE m.id=?1 AND (m.to_agent=?2 OR (m.to_agent='*' AND m.from_agent<>?2))
                   AND NOT EXISTS(SELECT 1 FROM receipts r WHERE r.message_id=m.id AND r.agent=?2)",
                params![
                    id,
                    agent,
                    channel,
                    now.saturating_add(lease_seconds.saturating_mul(1000))
                ],
            )?;
            if inserted != 0 {
                transaction.execute(
                    "INSERT OR IGNORE INTO deliveries(message_id,agent,delivered_at)
                     VALUES (?1,?2,?3)",
                    params![id, agent, now],
                )?;
                claimed.push(*id);
            }
        }
        transaction.commit()?;
        Ok(claimed)
    }

    /// This agent's own messages, newest first, each with how far it got.
    pub fn sent(&self, agent: &str, limit: usize) -> Result<Vec<Receipt>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(
            "SELECT m.id, m.to_agent, m.body, m.created_at,
                    (SELECT min(d.delivered_at) FROM deliveries d WHERE d.message_id = m.id),
                    (SELECT min(r.read_at) FROM receipts r WHERE r.message_id = m.id),
                    (SELECT min(a.created_at) FROM messages a
                      WHERE a.reply_to = m.id AND a.from_agent <> m.from_agent)
             FROM messages m WHERE m.from_agent = ?1
             ORDER BY m.id DESC LIMIT ?2",
        )?;
        let mut receipts = statement
            .query_map(params![agent, limit], |row| {
                let delivered_at: Option<i64> = row.get(4)?;
                let read_at: Option<i64> = row.get(5)?;
                let replied_at: Option<i64> = row.get(6)?;
                Ok(Receipt {
                    id: row.get(0)?,
                    to: row.get(1)?,
                    body: row.get(2)?,
                    created_at: row.get(3)?,
                    status: match (replied_at, read_at, delivered_at) {
                        (Some(_), _, _) => Delivery::Replied,
                        (_, Some(_), _) => Delivery::Read,
                        (_, _, Some(_)) => Delivery::Delivered,
                        _ => Delivery::Sent,
                    },
                    delivered_at,
                    read_at,
                    replied_at,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut expired = self
            .conn
            .prepare(
                "SELECT message_id, to_agent, created_at FROM message_outcomes
                 WHERE from_agent = ?1 AND outcome = 'failed'
                 ORDER BY message_id DESC LIMIT ?2",
            )?
            .query_map(params![agent, limit], |row| {
                Ok(Receipt {
                    id: row.get(0)?,
                    to: row.get(1)?,
                    // The body went with the message; only the fact of it is kept.
                    body: String::new(),
                    created_at: row.get(2)?,
                    status: Delivery::Failed,
                    delivered_at: None,
                    read_at: None,
                    replied_at: None,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        receipts.append(&mut expired);
        receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.id));
        receipts.truncate(limit.max(0) as usize);
        Ok(receipts)
    }

    fn insert_message(
        &mut self,
        from: &str,
        to: &str,
        body: &str,
        reply_to: Option<i64>,
        now: i64,
    ) -> Result<Message> {
        if body.trim().is_empty() {
            return Err(Error::Invalid("message is empty".into()));
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(Error::Invalid(format!(
                "message is {} bytes, the limit is {MAX_BODY_BYTES}: put the text in a file and send the path",
                body.len()
            )));
        }
        let transaction_span = crate::perf::Span::new("message.transaction");
        let transaction = self.write()?;
        let retention = crate::perf::Span::new("message.retention");
        // What the sweep removes is still worth one line to the sender: silence and "it expired
        // before anyone looked at it" are different answers to "did my message land?".
        transaction.execute(
            "INSERT OR IGNORE INTO message_outcomes
                 (message_id, from_agent, to_agent, outcome, created_at, at)
             SELECT m.id, m.from_agent, m.to_agent, 'failed', m.created_at, ?2 FROM messages m
             WHERE m.created_at <= ?1
               AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.message_id = m.id)",
            params![now - RETENTION_MS, now],
        )?;
        transaction.execute(
            "DELETE FROM messages WHERE created_at <= ?1",
            [now - RETENTION_MS],
        )?;
        // The outcomes outlive their messages but not for ever.
        transaction.execute(
            "DELETE FROM message_outcomes WHERE created_at <= ?1",
            [now - 2 * RETENTION_MS],
        )?;
        drop(retention);
        let insert = crate::perf::Span::new("message.insert");
        transaction.execute(
            "INSERT INTO messages (from_agent, to_agent, body, reply_to, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![from, to, body, reply_to, now],
        )?;
        let id = transaction.last_insert_rowid();
        drop(insert);
        let _commit = crate::perf::Span::new("sqlite.commit_full");
        transaction.commit()?;
        drop(_commit);
        drop(transaction_span);
        Ok(Message {
            id,
            from: from.to_string(),
            to: to.to_string(),
            body: body.to_string(),
            reply_to,
            created_at: now,
        })
    }

    fn message(&self, id: i64) -> Result<Message> {
        self.conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM messages WHERE id = ?1"),
                [id],
                read_message,
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("M-{id} does not exist")))
    }
}

fn read_message(row: &Row<'_>) -> rusqlite::Result<Message> {
    Ok(Message {
        id: row.get(0)?,
        from: row.get(1)?,
        to: row.get(2)?,
        body: row.get(3)?,
        reply_to: row.get(4)?,
        created_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;

    const ANY: usize = 100;

    fn with_agents(names: &[&str]) -> (tempfile::TempDir, Store) {
        let (dir, store) = test_store();
        for name in names {
            store.touch(name, 0).unwrap();
        }
        (dir, store)
    }

    fn bodies(messages: &[Message]) -> Vec<&str> {
        messages.iter().map(|m| m.body.as_str()).collect()
    }

    #[test]
    fn direct_mail_reaches_only_its_addressee_once() {
        let (_dir, mut store) = with_agents(&["a", "b", "c"]);
        store.send("a", "b", "hello", 1).unwrap();
        assert!(store.inbox("c", false, true, ANY, 2).unwrap().is_empty());
        assert_eq!(store.unread("b").unwrap(), 1);
        let first = store.inbox("b", false, true, ANY, 2).unwrap();
        assert_eq!(bodies(&first), ["hello"]);
        assert_eq!(store.unread("b").unwrap(), 0);
        assert!(store.inbox("b", false, true, ANY, 3).unwrap().is_empty());
        assert_eq!(store.inbox("b", true, true, ANY, 3).unwrap().len(), 1);
    }

    #[test]
    fn a_peek_leaves_the_mail_unread() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        store.send("a", "b", "hello", 1).unwrap();
        assert_eq!(store.inbox("b", false, false, ANY, 2).unwrap().len(), 1);
        assert_eq!(store.unread("b").unwrap(), 1);
    }

    #[test]
    fn a_limit_marks_only_what_was_returned() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        for text in ["one", "two", "three"] {
            store.send("a", "b", text, 1).unwrap();
        }
        assert_eq!(
            bodies(&store.inbox("b", false, true, 2, 2).unwrap()),
            ["one", "two"]
        );
        assert_eq!(store.unread("b").unwrap(), 1);
        assert_eq!(
            bodies(&store.inbox("b", false, true, 2, 3).unwrap()),
            ["three"]
        );
    }

    #[test]
    fn delivery_claim_is_exclusive_until_lease_or_seen_mark() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let message = store.send("a", "b", "hello", 1).unwrap();
        assert_eq!(
            store
                .inbox_claim("b", "hook-one", &[message.id], 10, 2)
                .unwrap(),
            [message.id]
        );
        assert!(
            store
                .inbox_claim("b", "hook-two", &[message.id], 10, 3)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .inbox_claim("b", "hook-two", &[message.id], 10, 10_002)
                .unwrap(),
            [message.id]
        );
        assert_eq!(store.inbox_seen("b", &[message.id], 10_003).unwrap(), 1);
        assert!(
            store
                .inbox_claim("b", "hook-one", &[message.id], 10, 10_004)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn seen_marks_only_mail_addressed_to_the_reader() {
        let (_dir, mut store) = with_agents(&["a", "b", "c"]);
        let direct = store.send("a", "b", "direct", 1).unwrap();
        let other = store.send("a", "c", "other", 1).unwrap();
        assert_eq!(store.inbox_seen("b", &[direct.id, other.id], 2).unwrap(), 1);
        assert_eq!(store.unread("b").unwrap(), 0);
    }

    #[test]
    fn a_broadcast_reaches_everyone_but_the_sender_and_each_reads_it_separately() {
        let (_dir, mut store) = with_agents(&["a", "b", "c"]);
        store.send("a", BROADCAST, "stop", 1).unwrap();
        assert_eq!(store.unread("a").unwrap(), 0);
        assert!(store.inbox("a", true, true, ANY, 2).unwrap().is_empty());
        store.inbox("b", false, true, ANY, 2).unwrap();
        assert_eq!(store.unread("b").unwrap(), 0);
        assert_eq!(store.unread("c").unwrap(), 1);
    }

    #[test]
    fn an_unknown_addressee_is_refused_instead_of_lost() {
        let (_dir, mut store) = with_agents(&["a"]);
        assert!(matches!(
            store.send("a", "typo", "hello", 1),
            Err(Error::NotFound(_))
        ));
        assert!(store.send("a", "two words", "hello", 1).is_err());
    }

    #[test]
    fn a_reply_goes_to_the_other_side() {
        let (_dir, mut store) = with_agents(&["a", "b", "c"]);
        let question = store.send("a", "b", "ready?", 1).unwrap();
        let answer = store.reply("b", question.id, "yes", 2).unwrap();
        assert_eq!(
            (answer.to.as_str(), answer.reply_to),
            ("a", Some(question.id))
        );
        assert!(matches!(
            store.reply("c", question.id, "me too", 3),
            Err(Error::Denied(_))
        ));
        assert_eq!(store.reply("a", question.id, "and?", 4).unwrap().to, "b");
    }

    #[test]
    fn any_reader_can_answer_a_broadcast_and_the_answer_is_private() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let notice = store.send("a", BROADCAST, "stop", 1).unwrap();
        assert_eq!(store.reply("b", notice.id, "ok", 2).unwrap().to, "a");
    }

    #[test]
    fn body_limits_hold() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        assert!(store.send("a", "b", "  \n", 1).is_err());
        assert!(
            store
                .send("a", "b", &"x".repeat(MAX_BODY_BYTES + 1), 1)
                .is_err()
        );
        assert!(store.send("a", "b", &"x".repeat(MAX_BODY_BYTES), 1).is_ok());
    }

    #[test]
    fn old_mail_and_its_read_marks_are_deleted_on_the_next_send() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        store.send("a", "b", "old", 0).unwrap();
        store.inbox("b", false, true, ANY, 1).unwrap();
        store.send("a", "b", "new", RETENTION_MS).unwrap();
        assert_eq!(
            bodies(&store.inbox("b", true, true, ANY, RETENTION_MS).unwrap()),
            ["new"]
        );
        let marks: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM receipts WHERE agent = 'b' AND read_at = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marks, 0);
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use crate::store::test_store;

    const ANY: usize = 100;

    fn with_agents(names: &[&str]) -> (tempfile::TempDir, Store) {
        let (dir, store) = test_store();
        for name in names {
            store.touch(name, 0).unwrap();
        }
        (dir, store)
    }

    fn status(store: &Store, agent: &str, id: i64) -> Delivery {
        store
            .sent(agent, ANY)
            .unwrap()
            .into_iter()
            .find(|receipt| receipt.id == id)
            .unwrap_or_else(|| panic!("M-{id} is not among the sent messages"))
            .status
    }

    #[test]
    fn a_message_walks_from_sent_to_delivered_to_read_to_replied() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let sent = store.send("a", "b", "look at src/api", 10).unwrap();
        assert_eq!(status(&store, "a", sent.id), Delivery::Sent);

        store.inbox("b", false, false, ANY, 20).unwrap();
        assert_eq!(
            status(&store, "a", sent.id),
            Delivery::Delivered,
            "showing mail to its recipient is delivery, even before it is marked read"
        );

        store.inbox_seen("b", &[sent.id], 30).unwrap();
        assert_eq!(status(&store, "a", sent.id), Delivery::Read);

        store.reply("b", sent.id, "looking", 40).unwrap();
        assert_eq!(status(&store, "a", sent.id), Delivery::Replied);

        let receipt = store
            .sent("a", ANY)
            .unwrap()
            .into_iter()
            .find(|receipt| receipt.id == sent.id)
            .unwrap();
        assert_eq!(receipt.delivered_at, Some(20));
        assert_eq!(receipt.read_at, Some(30));
        assert_eq!(receipt.replied_at, Some(40));
        assert_eq!(receipt.to, "b");
    }

    #[test]
    fn a_senders_own_reply_does_not_count_as_an_answer_to_itself() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let sent = store.send("a", "b", "first", 10).unwrap();
        store.reply("a", sent.id, "and another thing", 20).unwrap();
        assert_eq!(status(&store, "a", sent.id), Delivery::Sent);
    }

    #[test]
    fn reading_mail_marks_it_delivered_even_when_the_reader_never_looked_at_the_inbox() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let sent = store.send("a", "b", "hello", 10).unwrap();
        store.inbox_seen("b", &[sent.id], 30).unwrap();
        let receipt = store.sent("a", ANY).unwrap().remove(0);
        assert_eq!(receipt.status, Delivery::Read);
        assert_eq!(
            receipt.delivered_at,
            Some(30),
            "a message cannot be read without having arrived"
        );
    }

    #[test]
    fn a_claimed_message_counts_as_delivered_because_it_is_about_to_be_shown() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let sent = store.send("a", "b", "hello", 10).unwrap();
        let claimed = store.inbox_claim("b", "hook", &[sent.id], 60, 20).unwrap();
        assert_eq!(claimed, vec![sent.id]);
        assert_eq!(status(&store, "a", sent.id), Delivery::Delivered);
    }

    #[test]
    fn a_message_nobody_ever_saw_fails_when_it_ages_out() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        let seen = store.send("a", "b", "this one landed", 10).unwrap();
        store.inbox("b", false, false, ANY, 11).unwrap();
        let lost = store.send("a", "b", "nobody read this", 12).unwrap();

        // Any later send runs the sweep, which is where the outcome is written down.
        let now = 12 + RETENTION_MS + 1;
        store.send("a", "b", "much later", now).unwrap();

        let receipts = store.sent("a", ANY).unwrap();
        let failed: Vec<i64> = receipts
            .iter()
            .filter(|receipt| receipt.status == Delivery::Failed)
            .map(|receipt| receipt.id)
            .collect();
        assert_eq!(failed, vec![lost.id], "only the one nobody saw failed");
        assert!(
            !receipts.iter().any(|receipt| receipt.id == seen.id),
            "a delivered message that ages out leaves no failure behind"
        );
    }

    #[test]
    fn a_broadcast_is_delivered_once_the_first_agent_sees_it() {
        let (_dir, mut store) = with_agents(&["a", "b", "c"]);
        let sent = store.send("a", BROADCAST, "standup", 10).unwrap();
        assert_eq!(status(&store, "a", sent.id), Delivery::Sent);
        store.inbox("c", false, true, ANY, 20).unwrap();
        assert_eq!(status(&store, "a", sent.id), Delivery::Read);
    }

    #[test]
    fn sent_shows_the_newest_first_and_only_this_agents_own_messages() {
        let (_dir, mut store) = with_agents(&["a", "b"]);
        store.send("a", "b", "one", 10).unwrap();
        let second = store.send("a", "b", "two", 11).unwrap();
        store.send("b", "a", "not yours", 12).unwrap();
        let receipts = store.sent("a", ANY).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].id, second.id);
        assert_eq!(store.sent("a", 1).unwrap().len(), 1);
    }
}
