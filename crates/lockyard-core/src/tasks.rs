// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Tasks that outlive a session: open, claimed under a lease, submitted with evidence, then accepted
//! by a different agent. A claim that stops being renewed goes back up for grabs.

use crate::zones::{DEFAULT_TTL_MINUTES, MAX_TTL_MINUTES};
use crate::{Error, Result, Store};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use std::fmt;

const MINUTE_MS: i64 = 60_000;
const COLUMNS: &str =
    "id, title, body, status, author, assignee, lease_until, evidence, created_at, updated_at";

/// Where a task stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Open,
    Claimed,
    Review,
    Accepted,
    Cancelled,
}

impl Status {
    /// Name of the status in storage and output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Claimed => "claimed",
            Self::Review => "review",
            Self::Accepted => "accepted",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reads a status name.
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Open,
            Self::Claimed,
            Self::Review,
            Self::Accepted,
            Self::Cancelled,
        ]
        .into_iter()
        .find(|status| status.as_str() == text)
    }

    /// True when a task in this status will not change again.
    pub fn is_final(self) -> bool {
        matches!(self, Self::Accepted | Self::Cancelled)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Task {
    pub id: String,
    pub title: String,
    pub body: String,
    pub status: Status,
    pub author: String,
    pub assignee: Option<String>,
    pub lease_until: Option<i64>,
    pub evidence: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Urgency of a backlog item. Local tasks have none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
}

/// A new task. Everything past `body` belongs to the cloud backlog, where the agent that writes an
/// item also sets its urgency.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskSpec {
    pub title: String,
    pub body: String,
    pub acceptance: Option<String>,
    pub priority: Option<String>,
    pub p0_category: Option<String>,
    pub kind: Option<String>,
    pub target: Option<String>,
    pub verification: Option<String>,
    pub area: Option<String>,
    pub prefix: Option<String>,
    pub pad: Option<u8>,
    pub due_at: Option<String>,
    pub evidence: Option<String>,
}

impl TaskSpec {
    /// True when local mode would have to drop part of this request.
    pub fn uses_registry_fields(&self) -> bool {
        [
            &self.acceptance,
            &self.priority,
            &self.p0_category,
            &self.kind,
            &self.target,
            &self.verification,
            &self.area,
            &self.prefix,
            &self.due_at,
            &self.evidence,
        ]
        .iter()
        .any(|field| field.is_some())
            || self.pad.is_some()
    }
}

/// A change of urgency.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskPlan {
    pub priority: Option<String>,
    pub p0_category: Option<String>,
    pub due_at: Option<String>,
}

impl Task {
    fn lease_alive(&self, now: i64) -> bool {
        self.lease_until.is_some_and(|until| until > now)
    }
}

/// One step in a task's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskEvent {
    pub agent: String,
    pub action: String,
    pub note: String,
    pub at: i64,
}

impl Store {
    /// Adds an open task.
    pub fn add_task(&mut self, author: &str, title: &str, body: &str, now: i64) -> Result<Task> {
        if title.trim().is_empty() {
            return Err(Error::Invalid("a task needs a title".into()));
        }
        self.touch(author, now)?;
        let transaction = self.write()?;
        transaction.execute(
            "INSERT INTO tasks (title, body, status, author, created_at, updated_at)
             VALUES (?1, ?2, 'open', ?3, ?4, ?4)",
            params![title, body, author, now],
        )?;
        let id = transaction.last_insert_rowid();
        log(&transaction, id, author, "add", "", now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// One task.
    pub fn task(&self, id: i64) -> Result<Task> {
        load(&self.conn, id)
    }

    /// Tasks with this status, or all unfinished ones. Oldest first.
    pub fn tasks(&self, status: Option<Status>, include_final: bool) -> Result<Vec<Task>> {
        let mut statement = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM tasks
             WHERE (?1 IS NULL OR status = ?1)
               AND (?1 IS NOT NULL OR ?2 OR status NOT IN ('accepted', 'cancelled'))
             ORDER BY id"
        ))?;
        let rows = statement.query_map(
            params![status.map(Status::as_str), include_final],
            read_task,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// What happened to a task, oldest first.
    pub fn task_history(&self, id: i64) -> Result<Vec<TaskEvent>> {
        load(&self.conn, id)?;
        let mut statement = self.conn.prepare(
            "SELECT agent, action, note, at FROM task_events WHERE task_id = ?1 ORDER BY id",
        )?;
        let rows = statement.query_map([id], |row| {
            Ok(TaskEvent {
                agent: row.get(0)?,
                action: row.get(1)?,
                note: row.get(2)?,
                at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Takes an open task, or one whose previous assignee let the lease run out.
    pub fn claim_task(&mut self, agent: &str, id: i64, ttl_minutes: i64, now: i64) -> Result<Task> {
        let lease = lease_ms(ttl_minutes)?;
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        let free = task.status == Status::Open
            || (task.status == Status::Claimed
                && (task.assignee.as_deref() == Some(agent) || !task.lease_alive(now)));
        if !free {
            return Err(Error::Denied(describe_block(&task, "claimed")));
        }
        transaction.execute(
            "UPDATE tasks SET status = 'claimed', assignee = ?1, lease_until = ?2, updated_at = ?3
             WHERE id = ?4",
            params![agent, now + lease, now, id],
        )?;
        log(&transaction, id, agent, "claim", "", now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// Extends the lease on a task `agent` holds.
    pub fn renew_task(&mut self, agent: &str, id: i64, ttl_minutes: i64, now: i64) -> Result<Task> {
        let lease = lease_ms(ttl_minutes)?;
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        require_assignee(&task, agent)?;
        transaction.execute(
            "UPDATE tasks SET lease_until = ?1, updated_at = ?2 WHERE id = ?3",
            params![now + lease, now, id],
        )?;
        log(&transaction, id, agent, "renew", "", now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// Gives a held task back.
    pub fn release_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<Task> {
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        require_assignee(&task, agent)?;
        transaction.execute(
            "UPDATE tasks SET status = 'open', assignee = NULL, lease_until = NULL, updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
        log(&transaction, id, agent, "release", note, now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// Hands a held task to review. Evidence is required, a claim of success alone is not enough.
    pub fn submit_task(&mut self, agent: &str, id: i64, evidence: &str, now: i64) -> Result<Task> {
        if evidence.trim().is_empty() {
            return Err(Error::Invalid("submitting a task needs evidence".into()));
        }
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        require_assignee(&task, agent)?;
        transaction.execute(
            "UPDATE tasks SET status = 'review', evidence = ?1, lease_until = NULL, updated_at = ?2
             WHERE id = ?3",
            params![evidence, now, id],
        )?;
        log(&transaction, id, agent, "submit", evidence, now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// Accepts a submitted task. The agent that did the work cannot accept it.
    pub fn accept_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<Task> {
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        require_reviewer(&task, agent)?;
        transaction.execute(
            "UPDATE tasks SET status = 'accepted', updated_at = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        log(&transaction, id, agent, "accept", note, now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// Returns a submitted task to its assignee with a reason and a fresh lease.
    pub fn reject_task(&mut self, agent: &str, id: i64, reason: &str, now: i64) -> Result<Task> {
        if reason.trim().is_empty() {
            return Err(Error::Invalid("rejecting a task needs a reason".into()));
        }
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        require_reviewer(&task, agent)?;
        transaction.execute(
            "UPDATE tasks SET status = 'claimed', lease_until = ?1, updated_at = ?2 WHERE id = ?3",
            params![now + DEFAULT_TTL_MINUTES * MINUTE_MS, now, id],
        )?;
        log(&transaction, id, agent, "reject", reason, now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }

    /// Cancels a task. Only its author can, and only before it is final.
    pub fn cancel_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<Task> {
        self.touch(agent, now)?;
        let transaction = self.write()?;
        let task = load(&transaction, id)?;
        if task.author != agent {
            return Err(Error::Denied(format!(
                "only {} can cancel T-{id}",
                task.author
            )));
        }
        if task.status.is_final() {
            return Err(Error::Denied(format!("T-{id} is {}", task.status)));
        }
        transaction.execute(
            "UPDATE tasks SET status = 'cancelled', lease_until = NULL, updated_at = ?1
             WHERE id = ?2",
            params![now, id],
        )?;
        log(&transaction, id, agent, "cancel", note, now)?;
        let task = load(&transaction, id)?;
        transaction.commit()?;
        Ok(task)
    }
}

fn load(conn: &Connection, id: i64) -> Result<Task> {
    conn.query_row(
        &format!("SELECT {COLUMNS} FROM tasks WHERE id = ?1"),
        [id],
        read_task,
    )
    .optional()?
    .ok_or_else(|| Error::NotFound(format!("T-{id} does not exist")))
}

fn log(conn: &Connection, id: i64, agent: &str, action: &str, note: &str, at: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO task_events (task_id, agent, action, note, at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, agent, action, note, at],
    )?;
    Ok(())
}

fn read_task(row: &Row<'_>) -> rusqlite::Result<Task> {
    let status: String = row.get(3)?;
    Ok(Task {
        id: format!("D-{}", row.get::<_, i64>(0)?),
        title: row.get(1)?,
        body: row.get(2)?,
        status: Status::parse(&status).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                format!("unknown task status {status:?}").into(),
            )
        })?,
        author: row.get(4)?,
        assignee: row.get(5)?,
        lease_until: row.get(6)?,
        evidence: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        priority: None,
    })
}

fn require_assignee(task: &Task, agent: &str) -> Result<()> {
    if task.status == Status::Claimed && task.assignee.as_deref() == Some(agent) {
        return Ok(());
    }
    Err(Error::Denied(format!(
        "T-{} is {} and not held by this agent",
        task.id, task.status
    )))
}

fn require_reviewer(task: &Task, agent: &str) -> Result<()> {
    if task.status != Status::Review {
        return Err(Error::Denied(format!(
            "T-{} is {}, not in review",
            task.id, task.status
        )));
    }
    if task.assignee.as_deref() == Some(agent) {
        return Err(Error::Denied(format!(
            "T-{} needs a review by another agent",
            task.id
        )));
    }
    Ok(())
}

fn describe_block(task: &Task, verb: &str) -> String {
    match (&task.status, &task.assignee) {
        (Status::Claimed, Some(assignee)) => {
            format!("T-{} cannot be {verb}: {assignee} holds it", task.id)
        }
        (status, _) => format!("T-{} cannot be {verb}: it is {status}", task.id),
    }
}

fn lease_ms(ttl_minutes: i64) -> Result<i64> {
    if !(1..=MAX_TTL_MINUTES).contains(&ttl_minutes) {
        return Err(Error::Invalid(format!(
            "lease must be 1 to {MAX_TTL_MINUTES} minutes (got {ttl_minutes})"
        )));
    }
    Ok(ttl_minutes * MINUTE_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;

    const TTL: i64 = 10;
    const TTL_MS: i64 = TTL * MINUTE_MS;

    fn task_in_review(store: &mut Store) -> i64 {
        let id = store
            .add_task("lead", "ship", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        store.claim_task("worker", id, TTL, 1).unwrap();
        store.submit_task("worker", id, "tests pass", 2).unwrap();
        id
    }

    #[test]
    fn a_task_walks_from_open_to_accepted_and_keeps_its_history() {
        let (_dir, mut store) = test_store();
        let id = task_in_review(&mut store);
        let task = store.accept_task("lead", id, "good", 3).unwrap();
        assert_eq!(task.status, Status::Accepted);
        assert_eq!(task.evidence.as_deref(), Some("tests pass"));
        let actions: Vec<_> = store
            .task_history(id)
            .unwrap()
            .into_iter()
            .map(|event| event.action)
            .collect();
        assert_eq!(actions, ["add", "claim", "submit", "accept"]);
    }

    #[test]
    fn the_worker_cannot_accept_its_own_work() {
        let (_dir, mut store) = test_store();
        let id = task_in_review(&mut store);
        assert!(matches!(
            store.accept_task("worker", id, "", 3),
            Err(Error::Denied(_))
        ));
        assert!(matches!(
            store.reject_task("worker", id, "no", 3),
            Err(Error::Denied(_))
        ));
        assert_eq!(store.task(id).unwrap().status, Status::Review);
    }

    #[test]
    fn submitting_needs_evidence() {
        let (_dir, mut store) = test_store();
        let id = store
            .add_task("lead", "x", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        store.claim_task("worker", id, TTL, 1).unwrap();
        assert!(store.submit_task("worker", id, "  ", 2).is_err());
        assert_eq!(store.task(id).unwrap().status, Status::Claimed);
    }

    #[test]
    fn a_living_lease_keeps_others_out_and_an_expired_one_does_not() {
        let (_dir, mut store) = test_store();
        let id = store
            .add_task("lead", "x", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        store.claim_task("a", id, TTL, 0).unwrap();
        assert!(matches!(
            store.claim_task("b", id, TTL, TTL_MS - 1),
            Err(Error::Denied(_))
        ));
        let taken = store.claim_task("b", id, TTL, TTL_MS).unwrap();
        assert_eq!(taken.assignee.as_deref(), Some("b"));
        assert!(store.submit_task("a", id, "late", TTL_MS + 1).is_err());
    }

    #[test]
    fn a_rejected_task_returns_to_its_assignee_with_a_lease_and_the_reason_on_record() {
        let (_dir, mut store) = test_store();
        let id = task_in_review(&mut store);
        let task = store.reject_task("lead", id, "test is empty", 3).unwrap();
        assert_eq!(task.status, Status::Claimed);
        assert_eq!(task.assignee.as_deref(), Some("worker"));
        assert_eq!(task.lease_until, Some(3 + DEFAULT_TTL_MINUTES * MINUTE_MS));
        assert!(
            store
                .task_history(id)
                .unwrap()
                .iter()
                .any(|event| event.note == "test is empty")
        );
        store.submit_task("worker", id, "fixed", 4).unwrap();
    }

    #[test]
    fn rejecting_needs_a_reason() {
        let (_dir, mut store) = test_store();
        let id = task_in_review(&mut store);
        assert!(store.reject_task("lead", id, " ", 3).is_err());
    }

    #[test]
    fn only_the_assignee_renews_or_releases() {
        let (_dir, mut store) = test_store();
        let id = store
            .add_task("lead", "x", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        store.claim_task("a", id, TTL, 0).unwrap();
        assert!(store.renew_task("b", id, TTL, 1).is_err());
        assert!(store.release_task("b", id, "", 1).is_err());
        assert_eq!(
            store.renew_task("a", id, TTL, 5).unwrap().lease_until,
            Some(5 + TTL_MS)
        );
        let open = store.release_task("a", id, "blocked", 6).unwrap();
        assert_eq!((open.status, open.assignee), (Status::Open, None));
    }

    #[test]
    fn cancel_belongs_to_the_author_and_stops_at_a_final_state() {
        let (_dir, mut store) = test_store();
        let id = store
            .add_task("lead", "x", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        assert!(store.cancel_task("other", id, "", 1).is_err());
        store.cancel_task("lead", id, "dropped", 1).unwrap();
        assert!(store.cancel_task("lead", id, "", 2).is_err());
        assert!(store.claim_task("a", id, TTL, 2).is_err());

        let done = task_in_review(&mut store);
        store.accept_task("lead", done, "", 3).unwrap();
        assert!(store.cancel_task("lead", done, "", 4).is_err());
    }

    #[test]
    fn the_list_hides_finished_tasks_unless_asked() {
        let (_dir, mut store) = test_store();
        let open = store
            .add_task("lead", "open", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        let done = task_in_review(&mut store);
        store.accept_task("lead", done, "", 3).unwrap();
        let ids = |tasks: Vec<Task>| {
            tasks
                .into_iter()
                .map(|t| t.id.rsplit_once('-').unwrap().1.parse::<i64>().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(store.tasks(None, false).unwrap()), [open]);
        assert_eq!(ids(store.tasks(None, true).unwrap()), [open, done]);
        assert_eq!(
            ids(store.tasks(Some(Status::Accepted), false).unwrap()),
            [done]
        );
    }

    #[test]
    fn a_missing_task_is_reported() {
        let (_dir, mut store) = test_store();
        assert!(matches!(store.task(9), Err(Error::NotFound(_))));
        assert!(matches!(store.task_history(9), Err(Error::NotFound(_))));
        assert!(matches!(
            store.claim_task("a", 9, TTL, 0),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn only_one_of_many_racing_connections_takes_a_task() {
        let (dir, mut store) = test_store();
        let id = store
            .add_task("lead", "x", "", 0)
            .unwrap()
            .id
            .rsplit_once('-')
            .unwrap()
            .1
            .parse()
            .unwrap();
        let racers: Vec<_> = (0..16)
            .map(|index| {
                let root = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let mut store = Store::open(&root).unwrap();
                    store
                        .claim_task(&format!("agent-{index}"), id, TTL, 1)
                        .is_ok()
                })
            })
            .collect();
        let wins = racers
            .into_iter()
            .map(|racer| racer.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
    }
}
