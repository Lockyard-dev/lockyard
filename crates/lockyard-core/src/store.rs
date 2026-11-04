// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use crate::paths::find_root;
use crate::{Error, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Folder of a project's state.
pub const DIR_NAME: &str = ".lockyard";

const DB_NAME: &str = "lockyard.db";
const SCHEMA_VERSION: i32 = 5;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_AGENT_LEN: usize = 128;
const TOUCH_INTERVAL_MS: i64 = 60_000;

const SCHEMA: &str = "
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
) STRICT;

CREATE TABLE claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE TABLE claim_paths (
    claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    PRIMARY KEY (claim_id, path)
) STRICT;
CREATE INDEX claims_by_expiry ON claims(expires_at);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    body TEXT NOT NULL,
    reply_to INTEGER,
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE receipts (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    read_at INTEGER NOT NULL,
    PRIMARY KEY (message_id, agent)
) STRICT;
CREATE INDEX messages_by_recipient ON messages(to_agent, id);

CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL,
    author TEXT NOT NULL,
    assignee TEXT,
    lease_until INTEGER,
    evidence TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE task_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    note TEXT NOT NULL,
    at INTEGER NOT NULL
) STRICT;
CREATE INDEX tasks_by_status ON tasks(status, id);
CREATE INDEX task_events_by_task ON task_events(task_id, id);
";

const SCHEMA_V2: &str = "
CREATE TABLE zone_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT NOT NULL,
    paths TEXT NOT NULL,
    note TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'exclusive',
    purpose TEXT NOT NULL DEFAULT 'work',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX zone_queue_order ON zone_queue(created_at, id);
CREATE TABLE zone_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester TEXT NOT NULL,
    holder TEXT NOT NULL,
    paths TEXT NOT NULL,
    text TEXT NOT NULL,
    urgent INTEGER NOT NULL DEFAULT 0,
    reply TEXT,
    eta TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE TABLE handovers (
    claim_id INTEGER PRIMARY KEY REFERENCES claims(id) ON DELETE CASCADE,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE TABLE board (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    zone TEXT,
    expires_at INTEGER,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE presence (
    agent TEXT PRIMARY KEY,
    client TEXT NOT NULL,
    role TEXT,
    version TEXT,
    cwd TEXT,
    last_seen INTEGER NOT NULL,
    dnd_until INTEGER
) STRICT;
CREATE TABLE work_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    recipient TEXT,
    zone TEXT,
    accept TEXT NOT NULL,
    brief TEXT,
    status TEXT NOT NULL,
    lease_until INTEGER,
    assignee TEXT,
    report TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    session TEXT,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
";

const SCHEMA_V3: &str = "
CREATE TABLE delivery_claims (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    channel TEXT NOT NULL,
    lease_until INTEGER NOT NULL,
    PRIMARY KEY (message_id, agent)
) STRICT;
CREATE INDEX delivery_claims_by_lease ON delivery_claims(lease_until);
";

/// Tables reserved for features that now live on the server only. Nothing ever wrote to them.
const SCHEMA_V4: &str = "
DROP TABLE IF EXISTS zone_queue;
DROP TABLE IF EXISTS zone_requests;
DROP TABLE IF EXISTS handovers;
DROP TABLE IF EXISTS work_tasks;
DROP TABLE IF EXISTS events;
";

/// Message receipts: when a message was put in front of its recipient, and what became of one
/// that never was. Reading is kept in `receipts`, so the unread predicates are untouched.
const SCHEMA_V5: &str = "
CREATE TABLE deliveries (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    agent TEXT NOT NULL,
    delivered_at INTEGER NOT NULL,
    PRIMARY KEY (message_id, agent)
) STRICT;
CREATE TABLE message_outcomes (
    message_id INTEGER PRIMARY KEY,
    from_agent TEXT NOT NULL,
    to_agent TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    at INTEGER NOT NULL
) STRICT;
CREATE INDEX message_outcomes_by_sender ON message_outcomes(from_agent, message_id);
";

/// An agent that has acted in this project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Agent {
    pub id: String,
    pub first_seen: i64,
    pub last_seen: i64,
}

/// One project's state on disk.
pub struct Store {
    pub(crate) conn: Connection,
    root: PathBuf,
}

impl Store {
    /// Creates the project at `root` if needed and opens it.
    pub fn init(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let dir = root.join(DIR_NAME);
        fs::create_dir_all(&dir)?;
        restrict(&dir)?;
        // The database and its journals never belong in the repository.
        fs::write(dir.join(".gitignore"), "*\n")?;
        Self::open(&root)
    }

    /// Opens the project at `root`, which must already exist.
    pub fn open(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let dir = root.join(DIR_NAME);
        if !dir.is_dir() {
            return Err(Error::NoProject);
        }
        let conn = Connection::open(dir.join(DB_NAME))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // In WAL mode a power cut can then lose the last writes, which for leases and mail is cheap,
        // and it cannot damage the file.
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let mut store = Self { conn, root };
        store.migrate()?;
        Ok(store)
    }

    /// Opens the project that contains `cwd`.
    pub fn discover(cwd: &Path) -> Result<Self> {
        Self::open(&find_root(cwd).ok_or(Error::NoProject)?)
    }

    /// The canonical project root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Records that `agent` is alive, at most once per [`TOUCH_INTERVAL_MS`]. Hooks call this on every
    /// tool use, and a call that writes nothing skips the WAL checkpoint when its connection closes.
    pub fn touch(&self, agent: &str, now: i64) -> Result<()> {
        validate_agent(agent)?;
        self.conn.execute(
            "INSERT INTO agents (id, first_seen, last_seen) VALUES (?1, ?2, ?2)
             ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen
             WHERE excluded.last_seen >= agents.last_seen + ?3",
            params![agent, now, TOUCH_INTERVAL_MS],
        )?;
        Ok(())
    }

    /// Best-effort hook heartbeat, after the hook has made its permission decision.
    /// The read stays available in WAL while another process writes; the short timeout
    /// keeps a busy writer from delaying the next tool call.
    pub fn touch_best_effort(&self, agent: &str, now: i64) -> Result<()> {
        validate_agent(agent)?;
        self.conn
            .busy_timeout(std::time::Duration::from_millis(25))?;
        let last_seen: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_seen FROM agents WHERE id = ?1",
                [agent],
                |row| row.get(0),
            )
            .optional()?;
        if last_seen.is_none_or(|last| now >= last.saturating_add(TOUCH_INTERVAL_MS)) {
            self.touch(agent, now)?;
        }
        Ok(())
    }

    /// Every agent seen in this project, most recent first.
    pub fn agents(&self) -> Result<Vec<Agent>> {
        let mut statement = self
            .conn
            .prepare("SELECT id, first_seen, last_seen FROM agents ORDER BY last_seen DESC, id")?;
        let rows = statement.query_map([], |row| {
            Ok(Agent {
                id: row.get(0)?,
                first_seen: row.get(1)?,
                last_seen: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// True when `agent` has acted in this project.
    pub(crate) fn agent_exists(&self, agent: &str) -> Result<bool> {
        let found = self
            .conn
            .query_row("SELECT 1 FROM agents WHERE id = ?1", [agent], |_| Ok(()))
            .optional()?;
        Ok(found.is_some())
    }

    /// Starts a write that holds the database lock from its first statement.
    pub(crate) fn write(&mut self) -> Result<Transaction<'_>> {
        Ok(self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    fn migrate(&mut self) -> Result<()> {
        if self.schema_version()? == SCHEMA_VERSION {
            return Ok(());
        }
        // WAL lets the read side of a hook run while another agent writes. The setting persists.
        self.conn.pragma_update(None, "journal_mode", "WAL")?;
        let transaction = self.write()?;
        // Read again under the lock: another process may have finished first.
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 0 {
            transaction.execute_batch(SCHEMA)?;
            transaction.pragma_update(None, "user_version", 1)?;
        }
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 1 {
            transaction.execute_batch(SCHEMA_V2)?;
            transaction.pragma_update(None, "user_version", 2)?;
        }
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 2 {
            transaction.execute_batch(SCHEMA_V3)?;
            transaction.pragma_update(None, "user_version", 3)?;
        }
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 3 {
            transaction.execute_batch(SCHEMA_V4)?;
            transaction.pragma_update(None, "user_version", 4)?;
        }
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 4 {
            transaction.execute_batch(SCHEMA_V5)?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        transaction.commit()?;
        match self.schema_version()? {
            SCHEMA_VERSION => Ok(()),
            other => Err(Error::Invalid(format!(
                "project schema {other} is not supported by this build, which reads {SCHEMA_VERSION}"
            ))),
        }
    }

    fn schema_version(&self) -> Result<i32> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }
}

/// Checks an agent name. The name is an address, so `*` and spaces cannot be part of it.
pub fn validate_agent(agent: &str) -> Result<()> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':');
    if agent.is_empty() || agent.len() > MAX_AGENT_LEN || !agent.chars().all(allowed) {
        return Err(Error::Invalid(format!(
            "agent name must be 1 to {MAX_AGENT_LEN} letters, digits or _ - . : (got {agent:?})"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?)
}

#[cfg(not(unix))]
fn restrict(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::init(dir.path()).unwrap();
    (dir, store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_without_init_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(Store::open(dir.path()), Err(Error::NoProject)));
        assert!(matches!(Store::discover(dir.path()), Err(Error::NoProject)));
    }

    #[test]
    fn init_twice_keeps_the_data() {
        let (dir, store) = test_store();
        store.touch("a", 1).unwrap();
        drop(store);
        let again = Store::init(dir.path()).unwrap();
        assert_eq!(again.agents().unwrap().len(), 1);
    }

    #[test]
    fn the_state_folder_ignores_itself_in_git() {
        let (dir, _store) = test_store();
        let ignore = fs::read_to_string(dir.path().join(DIR_NAME).join(".gitignore")).unwrap();
        assert_eq!(ignore, "*\n");
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_changed() {
        let (dir, store) = test_store();
        store.conn.pragma_update(None, "user_version", 99).unwrap();
        drop(store);
        let refused = Store::open(dir.path());
        assert!(matches!(refused, Err(Error::Invalid(_))));
    }

    #[test]
    fn touch_keeps_the_first_seen_time() {
        let (_dir, store) = test_store();
        let later = 1 + TOUCH_INTERVAL_MS;
        store.touch("a", 1).unwrap();
        store.touch("a", later).unwrap();
        let agents = store.agents().unwrap();
        assert_eq!((agents[0].first_seen, agents[0].last_seen), (1, later));
    }

    #[test]
    fn a_touch_inside_the_interval_writes_nothing() {
        let (_dir, store) = test_store();
        store.touch("a", 1).unwrap();
        store.touch("a", TOUCH_INTERVAL_MS).unwrap();
        assert_eq!(store.conn.changes(), 0);
        assert_eq!(store.agents().unwrap()[0].last_seen, 1);
    }

    #[test]
    fn best_effort_touch_does_not_wait_for_another_writer() {
        let (dir, store) = test_store();
        store.touch("a", 1).unwrap();
        let blocker = Connection::open(dir.path().join(DIR_NAME).join(DB_NAME)).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = std::time::Instant::now();
        let _ = store.touch_best_effort("a", 1 + TOUCH_INTERVAL_MS);
        assert!(started.elapsed() < Duration::from_millis(250));
        blocker.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn version_one_database_migrates_and_preserves_existing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(DIR_NAME);
        fs::create_dir_all(&state).unwrap();
        let connection = Connection::open(state.join(DB_NAME)).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute("INSERT INTO agents VALUES ('old', 1, 2)", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 1).unwrap();
        drop(connection);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.agents().unwrap()[0].id, "old");
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            store
                .conn
                .query_row("SELECT count(*) FROM board", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn version_three_database_loses_the_placeholders_and_keeps_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(DIR_NAME);
        fs::create_dir_all(&state).unwrap();
        let connection = Connection::open(state.join(DB_NAME)).unwrap();
        connection
            .execute_batch(&format!("{SCHEMA}{SCHEMA_V2}{SCHEMA_V3}"))
            .unwrap();
        connection
            .execute("INSERT INTO agents VALUES ('old', 1, 2)", [])
            .unwrap();
        connection
            .execute("INSERT INTO board VALUES ('k', 'v', NULL, NULL, 1)", [])
            .unwrap();
        connection.pragma_update(None, "user_version", 3).unwrap();
        drop(connection);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.agents().unwrap()[0].id, "old");
        assert_eq!(store.board_get("k", 0).unwrap().unwrap().value, "v");
        let table = |name: &str| -> i64 {
            store
                .conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap()
        };
        for gone in [
            "zone_queue",
            "zone_requests",
            "handovers",
            "work_tasks",
            "events",
        ] {
            assert_eq!(table(gone), 0, "{gone}");
        }
        for kept in ["board", "presence", "delivery_claims"] {
            assert_eq!(table(kept), 1, "{kept}");
        }
    }

    #[test]
    fn agent_names_are_addresses() {
        assert!(validate_agent("codex-1.a:b_c").is_ok());
        assert!(validate_agent("").is_err());
        assert!(validate_agent("*").is_err());
        assert!(validate_agent("two words").is_err());
        assert!(validate_agent(&"x".repeat(129)).is_err());
    }
}
