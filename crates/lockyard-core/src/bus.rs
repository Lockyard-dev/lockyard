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
        if to != BROADCAST {
            validate_agent(to)?;
        }
        self.touch(from, now)?;
        if to != BROADCAST && !self.agent_exists(to)? {
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
                claimed.push(*id);
            }
        }
        transaction.commit()?;
        Ok(claimed)
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
        let transaction = self.write()?;
        transaction.execute(
            "DELETE FROM messages WHERE created_at <= ?1",
            [now - RETENTION_MS],
        )?;
        transaction.execute(
            "INSERT INTO messages (from_agent, to_agent, body, reply_to, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![from, to, body, reply_to, now],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.commit()?;
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
