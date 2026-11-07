// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use crate::paths::find_root;
use crate::{Error, Result};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, config::DbConfig, params,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Folder of a project's state.
pub const DIR_NAME: &str = ".lockyard";

const DB_NAME: &str = "lockyard.db";
const SCHEMA_VERSION: i32 = 7;
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

/// Writes to a claimed path that no hook announced. Detection only: by the time a row lands here the
/// write has already happened, and the holder is told rather than protected.
const SCHEMA_V6: &str = "
CREATE TABLE unannounced_writes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    holder TEXT NOT NULL,
    claim_id INTEGER NOT NULL,
    first_at INTEGER NOT NULL,
    last_at INTEGER NOT NULL,
    hits INTEGER NOT NULL,
    told_at INTEGER,
    UNIQUE (path, holder)
) STRICT;
CREATE INDEX unannounced_writes_by_time ON unannounced_writes(last_at);
";

// Canonical keys are additive; integer columns remain storage surrogates for old readers.
const SCHEMA_V7: &str = "
ALTER TABLE tasks ADD COLUMN task_key TEXT;
UPDATE tasks SET task_key = 'D-' || id;
CREATE UNIQUE INDEX tasks_by_key ON tasks(task_key);
ALTER TABLE task_events ADD COLUMN task_key TEXT REFERENCES tasks(task_key);
UPDATE task_events SET task_key = (SELECT task_key FROM tasks WHERE tasks.id = task_events.task_id);
CREATE INDEX task_events_by_key ON task_events(task_key, id);
CREATE TRIGGER task_key_required_insert BEFORE INSERT ON tasks
WHEN NEW.task_key IS NULL OR NEW.task_key != 'D-' || NEW.id
BEGIN SELECT RAISE(ABORT, 'task generation requires canonical key'); END;
CREATE TRIGGER task_key_immutable BEFORE UPDATE OF task_key ON tasks
WHEN NEW.task_key IS NOT OLD.task_key
BEGIN SELECT RAISE(ABORT, 'task key is immutable'); END;
CREATE TRIGGER task_event_key_required BEFORE INSERT ON task_events
WHEN NEW.task_key IS NULL OR NEW.task_key IS NOT (SELECT task_key FROM tasks WHERE id=NEW.task_id)
BEGIN SELECT RAISE(ABORT, 'task generation requires canonical event key'); END;
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
        // Triggers distinguish a connection from this generation from an already-open old binary.
        conn.create_scalar_function(
            "lockyard_writer_generation",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC
                | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(SCHEMA_VERSION),
        )?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // Short-lived CLI writers must not checkpoint, unlink and recreate WAL/SHM on every
        // command. Keep the normal automatic checkpoints, and sync each commit before returning
        // success: retaining a NORMAL-synchronous WAL would extend the power-loss window.
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let mut store = Self { conn, root };
        store.migrate()?;
        Ok(store)
    }

    /// Opens the project that contains `cwd`.
    pub fn discover(cwd: &Path) -> Result<Self> {
        Self::open(&find_root(cwd).ok_or(Error::NoProject)?)
    }

    /// Folds committed WAL frames into the existing database at a long-lived process's shutdown.
    /// SQLite arbitrates concurrent writers/readers; a busy checkpoint leaves the WAL intact.
    /// This never creates a local database for a cloud-only project or migrates its schema.
    pub fn checkpoint_on_shutdown(cwd: &Path) -> Result<()> {
        use rusqlite::OpenFlags;
        let Some(root) = find_root(cwd) else {
            return Ok(());
        };
        let path = root.join(DIR_NAME).join(DB_NAME);
        match fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // A failed explicit checkpoint must not turn into another implicit checkpoint on close.
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
        conn.busy_timeout(Duration::from_millis(250))?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let (busy, frames, checkpointed): (i32, i32, i32) =
            conn.query_row("PRAGMA main.wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        if busy != 0 {
            return Err(Error::Unavailable(format!(
                "WAL checkpoint busy ({checkpointed}/{frames} frames); committed data remains in the WAL"
            )));
        }
        Ok(())
    }

    /// Publishes a complete, private SQLite snapshot without replacing any existing path.
    pub fn backup(&self, destination: &Path) -> Result<()> {
        use rusqlite::{
            OpenFlags,
            backup::{Backup, StepResult},
        };
        use std::io;

        if !self.conn.is_autocommit() {
            return Err(Error::Invalid(
                "database backup requires no active transaction".into(),
            ));
        }
        let name = destination
            .file_name()
            .ok_or_else(|| Error::Invalid("backup destination must name a file".into()))?;
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()?;
        let destination = parent.join(name);
        // This preflight improves the error; hard_link below provides race-free no-clobber.
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "backup destination already exists: {}",
                        destination.display()
                    ),
                )
                .into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut staging_options = tempfile::Builder::new();
        staging_options.prefix(".lockyard-backup-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            staging_options.permissions(fs::Permissions::from_mode(0o700));
        }
        let staging = staging_options.tempdir_in(&parent)?;
        let file = tempfile::NamedTempFile::new_in(staging.path())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        let mut target = Connection::open_with_flags(
            file.path(),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        target.busy_timeout(BUSY_TIMEOUT)?;
        target.pragma_update(None, "synchronous", "FULL")?;
        {
            let backup = Backup::new(&self.conn, &mut target)?;
            if backup.step(-1)? != StepResult::Done {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "source database remained busy during backup; retry",
                )
                .into());
            }
        }
        // The backup copies a WAL-mode header too. Normalize it before exposing the snapshot.
        let mode: String = target.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
        if mode != "delete" {
            return Err(Error::Invalid(
                "could not finalize standalone database backup".into(),
            ));
        }
        target.close().map_err(|(_, error)| Error::Db(error))?;
        file.as_file().sync_all()?;
        fs::hard_link(file.path(), &destination)?;
        #[cfg(unix)]
        fs::File::open(&parent)?.sync_all()?;
        Ok(())
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
            transaction.pragma_update(None, "user_version", 5)?;
        }
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 5 {
            transaction.execute_batch(SCHEMA_V6)?;
            transaction.pragma_update(None, "user_version", 6)?;
        }
        let version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 6 {
            transaction.execute_batch(SCHEMA_V7)?;
            let tables = {
                let mut query=transaction.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
                query
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for table in tables {
                if !table
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err(Error::Invalid(
                        "unsupported local table name during generation cutover".into(),
                    ));
                }
                for operation in ["INSERT", "UPDATE", "DELETE"] {
                    transaction.execute_batch(&format!("CREATE TRIGGER writer_generation_{table}_{operation} BEFORE {operation} ON {table} WHEN lockyard_writer_generation() != {SCHEMA_VERSION} BEGIN SELECT RAISE(ABORT, 'incompatible writer generation'); END;"))?;
                }
            }
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
    fn short_lived_writers_reuse_durable_wal_and_keep_auto_checkpointing() {
        let (dir, mut store) = test_store();
        store.send("alice", "*", "before close", 0).unwrap();
        let wal = dir.path().join(DIR_NAME).join("lockyard.db-wal");
        let bytes_before_close = fs::metadata(&wal).unwrap().len();
        drop(store);
        assert_eq!(
            fs::metadata(&wal)
                .expect("closing a CLI writer must retain the WAL")
                .len(),
            bytes_before_close
        );

        // Repeated independent connections must see the committed messages in the retained WAL.
        for now in 1..=16 {
            let mut store = Store::open(dir.path()).unwrap();
            assert_eq!(
                store
                    .conn
                    .pragma_query_value(None, "synchronous", |row| row.get::<_, i32>(0))
                    .unwrap(),
                2,
                "retaining the WAL requires FULL durability at each commit"
            );
            store.send("alice", "*", "after reopen", now).unwrap();
        }
        let mut store = Store::open(dir.path()).unwrap();
        let checkpoint_pages: u32 = store
            .conn
            .pragma_query_value(None, "wal_autocheckpoint", |row| row.get(0))
            .unwrap();
        assert_eq!(
            checkpoint_pages, 1000,
            "automatic checkpoints must stay enabled"
        );
        let page_bytes: u32 = store
            .conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .unwrap();
        // Enough small commits to cross the normal checkpoint threshold repeatedly. Without
        // automatic checkpoints this workload grows the WAL beyond the bound below.
        for now in 17..=1116 {
            store
                .send("alice", "*", "checkpoint workload", now)
                .unwrap();
        }
        assert!(
            fs::metadata(&wal).unwrap().len()
                <= 32 + u64::from(checkpoint_pages + 32) * u64::from(page_bytes + 24)
        );
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        let count: i64 = store
            .conn
            .query_row("SELECT count(*) FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1117);
        let integrity: String = store
            .conn
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }

    #[test]
    fn shutdown_checkpoint_reports_busy_writer_without_losing_commits() {
        let (dir, mut store) = test_store();
        store
            .send("alice", "*", "committed before busy writer", 0)
            .unwrap();
        let writer = Store::open(dir.path()).unwrap();
        writer.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let wal = dir.path().join(DIR_NAME).join("lockyard.db-wal");
        assert!(fs::metadata(&wal).unwrap().len() > 0);
        let error = Store::checkpoint_on_shutdown(dir.path()).unwrap_err();
        assert!(error.to_string().contains("checkpoint"), "{error}");
        assert!(fs::metadata(&wal).unwrap().len() > 0);
        writer.conn.execute_batch("ROLLBACK").unwrap();
        drop(writer);
        drop(store);
        Store::checkpoint_on_shutdown(dir.path()).unwrap();
        let copy = tempfile::tempdir().unwrap();
        fs::copy(
            dir.path().join(DIR_NAME).join(DB_NAME),
            copy.path().join(DB_NAME),
        )
        .unwrap();
        let standalone = Connection::open(copy.path().join(DB_NAME)).unwrap();
        assert_eq!(
            standalone
                .query_row("SELECT body FROM messages", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "committed before busy writer"
        );
    }

    #[test]
    fn shutdown_checkpoint_reports_busy_reader_without_losing_newer_commits() {
        let (dir, mut store) = test_store();
        store.send("alice", "*", "before reader", 0).unwrap();
        let reader = Store::open(dir.path()).unwrap();
        reader
            .conn
            .execute_batch("BEGIN; SELECT count(*) FROM messages;")
            .unwrap();
        store.send("alice", "*", "after reader", 1).unwrap();
        let wal = dir.path().join(DIR_NAME).join("lockyard.db-wal");
        assert!(Store::checkpoint_on_shutdown(dir.path()).is_err());
        assert!(fs::metadata(&wal).unwrap().len() > 0);
        reader.conn.execute_batch("ROLLBACK").unwrap();
        drop(reader);
        drop(store);
        Store::checkpoint_on_shutdown(dir.path()).unwrap();
        let copy = tempfile::tempdir().unwrap();
        fs::copy(
            dir.path().join(DIR_NAME).join(DB_NAME),
            copy.path().join(DB_NAME),
        )
        .unwrap();
        let standalone = Connection::open(copy.path().join(DB_NAME)).unwrap();
        assert_eq!(
            standalone
                .query_row("SELECT count(*) FROM messages", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn shutdown_checkpoint_outside_a_project_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        if find_root(dir.path()).is_some() {
            return;
        }
        Store::checkpoint_on_shutdown(dir.path()).unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        fs::create_dir(dir.path().join(DIR_NAME)).unwrap();
        Store::checkpoint_on_shutdown(dir.path()).unwrap();
        assert_eq!(fs::read_dir(dir.path().join(DIR_NAME)).unwrap().count(), 0);
    }

    #[test]
    fn previous_generation_connection_cannot_write_after_cutover() {
        let (dir, mut store) = test_store();
        let task = store.add_task("lead", "original", "", 0).unwrap();
        let old = Connection::open(dir.path().join(DIR_NAME).join(DB_NAME)).unwrap();
        for sql in [
            "UPDATE tasks SET title='old writer' WHERE id=1",
            "INSERT INTO agents VALUES ('old',0,0)",
            "DELETE FROM agents",
        ] {
            assert!(
                old.execute(sql, []).is_err(),
                "old generation wrote with {sql}"
            );
        }
        assert_eq!(store.task(&task.id).unwrap().title, "original");
        store
            .cancel_task("lead", &task.id, "new writer", 1)
            .unwrap();
    }

    #[test]
    fn opening_without_init_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(Store::open(dir.path()), Err(Error::NoProject)));
        // discover walks ancestors. When TMPDIR sits under another Lockyard project (common in
        // sandboxes that relocate temp into the workspace tree), skip that half of the check.
        if crate::paths::find_root(dir.path()).is_none() {
            assert!(matches!(Store::discover(dir.path()), Err(Error::NoProject)));
        }
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
