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
    #[cfg(windows)]
    _directory: crate::windows::Directory,
}

impl Store {
    /// Creates the project at `root` if needed and opens it.
    pub fn init(root: &Path) -> Result<Self> {
        let root = root.canonicalize()?;
        let dir = root.join(DIR_NAME);
        #[cfg(unix)]
        fs::create_dir_all(&dir)?;
        #[cfg(windows)]
        {
            // Tightening an exposed existing SQL directory cannot revoke handles
            // another SID already opened. Refuse it before any SQLite access.
            if dir.try_exists()? {
                crate::windows::require_private(&dir)?;
            }
            crate::windows::private_dir(&dir)?;
        }
        restrict(&dir)?;
        // The database and its journals never belong in the repository.
        #[cfg(unix)]
        fs::write(dir.join(".gitignore"), "*\n")?;
        #[cfg(windows)]
        crate::fsio::replace(&dir.join(".gitignore"), b"*\n", 0o600)?;
        Self::open(&root)
    }

    /// Opens the project at `root`, which must already exist.
    pub fn open(root: &Path) -> Result<Self> {
        let _total = crate::perf::Span::new("store.total");
        let path_span = crate::perf::Span::new("store.directory");
        let root = root.canonicalize()?;
        let dir = root.join(DIR_NAME);
        if !dir.is_dir() {
            return Err(Error::NoProject);
        }
        #[cfg(windows)]
        let mut database = windows_database(&dir, true)?;
        drop(path_span);
        let open_span = crate::perf::Span::new("sqlite.open");
        let conn = Connection::open(dir.join(DB_NAME))?;
        #[cfg(windows)]
        {
            database.verify_connection(&conn)?;
            // SQLite may need to delete a hot rollback journal during its first read.
            // The database/WAL/SHM names stay pinned through configuration and migration.
            drop(database.journal.take());
        }
        drop(open_span);
        let config_span = crate::perf::Span::new("sqlite.configure");
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
        drop(config_span);
        #[cfg(windows)]
        let WindowsDatabase {
            directory,
            db: db_pin,
            sidecars: sidecar_pins,
            journal: _,
        } = database;
        let mut store = Self {
            conn,
            root,
            #[cfg(windows)]
            _directory: directory,
        };
        let _schema = crate::perf::Span::new("sqlite.schema");
        store.migrate()?;
        #[cfg(windows)]
        // SQLite's Win32 VFS now owns the database and WAL/SHM handles, which also
        // omit FILE_SHARE_DELETE. Release preflight pins before later SQLite cleanup.
        drop((db_pin, sidecar_pins));
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
        #[cfg(windows)]
        let mut database = match windows_database(&root.join(DIR_NAME), false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        match fs::metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        #[cfg(windows)]
        {
            database.verify_connection(&conn)?;
            drop(database.journal.take());
        }
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
        #[cfg(windows)]
        let output_pin = crate::windows::open_output_directory(&parent)?;
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
        #[cfg(unix)]
        let staging = {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .prefix(".lockyard-backup-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(&parent)?
        };
        #[cfg(windows)]
        let staging = PrivateBackupDirectory::new(&parent)?;
        #[cfg(windows)]
        let _staging_pin = crate::windows::open_directory(staging.path())?;
        #[cfg(unix)]
        let file = tempfile::NamedTempFile::new_in(staging.path())?;
        #[cfg(windows)]
        let file = {
            let path = staging.path().join("snapshot.db");
            let file = crate::windows::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)?;
            tempfile::NamedTempFile::from_parts(file, tempfile::TempPath::try_from_path(path)?)
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        let payload_pin = crate::windows::pin_file(file.as_file())?;
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
        #[cfg(unix)]
        fs::hard_link(file.path(), &destination)?;
        #[cfg(windows)]
        {
            // SQLite has closed its pathname-based connection. Publish the original
            // verified object by handle, even if its temporary name is changed now.
            drop(payload_pin);
            crate::windows::publish_output_handle(file.as_file(), &output_pin, name)?;
        }
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
        let _span = crate::perf::Span::new("presence.touch");
        validate_agent(agent)?;
        // A no-op UPSERT still acquires SQLite's single writer lock. Read first so
        // a recent heartbeat needs no write transaction; the UPSERT predicate below
        // remains authoritative when another process updates the row concurrently.
        let last_seen: Option<i64> = {
            let _read = crate::perf::Span::new("presence.read");
            self.conn
                .query_row(
                    "SELECT last_seen FROM agents WHERE id = ?1",
                    [agent],
                    |row| row.get(0),
                )
                .optional()?
        };
        if last_seen.is_some_and(|last| now < last.saturating_add(TOUCH_INTERVAL_MS)) {
            return Ok(());
        }
        let _upsert = crate::perf::Span::new("presence.upsert_commit");
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
        let previous: u32 = self
            .conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
        self.conn
            .busy_timeout(std::time::Duration::from_millis(25))?;
        let result = self.touch(agent, now);
        // The same connection next reserves hook mail. Restore its own timeout
        // even when the best-effort write fails under another writer's lock.
        self.conn
            .busy_timeout(Duration::from_millis(u64::from(previous)))?;
        result
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
        let _begin = crate::perf::Span::new("sqlite.begin_immediate");
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
fn restrict(dir: &Path) -> Result<()> {
    Ok(crate::windows::secure_owned(dir)?)
}

#[cfg(test)]
pub(crate) fn test_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::init(dir.path()).unwrap();
    (dir, store)
}

#[cfg(windows)]
struct WindowsDatabase {
    directory: crate::windows::Directory,
    db: fs::File,
    sidecars: Vec<fs::File>,
    journal: Option<fs::File>,
}

#[cfg(any(windows, test))]
fn require_database_identity(expected: (u32, u64), actual: (u32, u64)) -> std::io::Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SQLite opened a different database file from the pinned private file",
        ))
    }
}

#[cfg(windows)]
impl WindowsDatabase {
    fn verify_connection(&self, conn: &Connection) -> std::io::Result<()> {
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        // SQLite writes a borrowed native HANDLE; ownership remains with the
        // connection. Read its identity before any schema or journal access.
        let code = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                conn.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
                std::ptr::from_mut(&mut handle).cast(),
            )
        };
        if code != rusqlite::ffi::SQLITE_OK {
            return Err(std::io::Error::other(format!(
                "cannot verify SQLite native database handle: {code}"
            )));
        }
        require_database_identity(
            crate::windows::file_identity(&self.db)?,
            crate::windows::handle_identity(handle)?,
        )
    }
}

#[cfg(windows)]
fn windows_database(dir: &Path, create: bool) -> std::io::Result<WindowsDatabase> {
    let directory = crate::windows::open_directory(dir)?;
    let db = directory.pin_private_file(std::ffi::OsStr::new(DB_NAME), create)?;
    let mut sidecars = Vec::new();
    let mut journal = None;
    for suffix in ["-wal", "-shm", "-journal"] {
        let name = format!("{DB_NAME}{suffix}");
        match directory.pin_private_file(std::ffi::OsStr::new(&name), false) {
            Ok(file) if suffix == "-journal" => journal = Some(file),
            Ok(file) => sidecars.push(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(WindowsDatabase {
        directory,
        db,
        sidecars,
        journal,
    })
}

#[cfg(windows)]
struct PrivateBackupDirectory(PathBuf);
#[cfg(windows)]
impl PrivateBackupDirectory {
    fn new(parent: &Path) -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..128 {
            let path = parent.join(format!(
                ".lockyard-backup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match crate::windows::create_private_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "cannot allocate private backup directory",
        ))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
#[cfg(windows)]
impl Drop for PrivateBackupDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_identity_requires_both_the_volume_and_complete_file_index() {
        let identity = (7, (23_u64 << 32) | 41);
        require_database_identity(identity, identity).unwrap();
        for different in [
            (8, identity.1),
            (7, (24_u64 << 32) | 41),
            (7, identity.1 + 1),
        ] {
            assert_eq!(
                require_database_identity(identity, different)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_database_pins_validated_leaves_and_checks_sqlites_native_file() {
        let (root, store) = test_store();
        let dir = root.path().join(DIR_NAME);
        drop(store);
        // NO_CKPT_ON_CLOSE leaves real, valid WAL/SHM files for the next opener.
        for suffix in ["-wal", "-shm"] {
            assert!(dir.join(format!("{DB_NAME}{suffix}")).is_file());
        }
        crate::windows::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(format!("{DB_NAME}-journal")))
            .unwrap();
        let database = windows_database(&dir, false).unwrap();
        assert_eq!(database.sidecars.len(), 2);
        assert!(database.journal.is_some());
        let assert_pinned = || {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let leaf = dir.join(format!("{DB_NAME}{suffix}"));
                assert!(
                    fs::rename(&leaf, leaf.with_extension("substituted")).is_err(),
                    "validated SQLite leaf must remain pinned: {suffix}"
                );
            }
        };
        assert_pinned();
        let conn = Connection::open(dir.join(DB_NAME)).unwrap();
        database.verify_connection(&conn).unwrap();
        assert_pinned();
        let (_other_root, other) = test_store();
        assert_eq!(
            database.verify_connection(&other.conn).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "a valid private database at a different file ID must be rejected"
        );
        drop(conn);
        drop(database);
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let leaf = dir.join(format!("{DB_NAME}{suffix}"));
            let moved = leaf.with_extension(format!("released{suffix}"));
            fs::rename(leaf, moved).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_database_releases_the_rollback_journal_pin_before_hot_recovery() {
        let (source_root, store) = test_store();
        let source_dir = source_root.path().join(DIR_NAME);
        drop(store);
        let source = Connection::open(source_dir.join(DB_NAME)).unwrap();
        source
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        source
            .execute_batch("PRAGMA cache_size=4; CREATE TABLE recovery_probe(payload BLOB);")
            .unwrap();
        let committed = vec![0x11_u8; 65_536];
        source
            .execute("INSERT INTO recovery_probe VALUES (?1)", [&committed])
            .unwrap();
        source.execute_batch("BEGIN IMMEDIATE").unwrap();
        source
            .execute(
                "UPDATE recovery_probe SET payload=?1",
                [vec![0x22_u8; 65_536]],
            )
            .unwrap();
        let journal_name = format!("{DB_NAME}-journal");
        assert_eq!(
            &fs::read(source_dir.join(&journal_name)).unwrap()[..8],
            &[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7],
            "the fixture must contain a synced hot-journal header after cache spill"
        );
        // Snapshot the on-disk crash state without inheriting the writer's locks.
        let recovered_root = tempfile::tempdir().unwrap();
        let recovered_dir = recovered_root.path().join(DIR_NAME);
        crate::windows::private_dir(&recovered_dir).unwrap();
        for name in [DB_NAME, journal_name.as_str()] {
            let mut input = fs::File::open(source_dir.join(name)).unwrap();
            let mut output = crate::windows::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(recovered_dir.join(name))
                .unwrap();
            std::io::copy(&mut input, &mut output).unwrap();
            output.sync_all().unwrap();
        }
        source.execute_batch("ROLLBACK").unwrap();
        let recovered = Store::open(recovered_root.path()).unwrap();
        let actual: Vec<u8> = recovered
            .conn
            .query_row("SELECT payload FROM recovery_probe", [], |row| row.get(0))
            .unwrap();
        assert_eq!(actual, committed);
        assert!(!recovered_dir.join(journal_name).exists());
    }

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
        #[cfg(windows)]
        crate::windows::private_dir(&dir.path().join(DIR_NAME)).unwrap();
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
        let before = store.conn.total_changes();
        store.touch("a", TOUCH_INTERVAL_MS).unwrap();
        assert_eq!(store.conn.total_changes(), before);
        assert_eq!(store.agents().unwrap()[0].last_seen, 1);
    }

    #[test]
    fn a_fresh_touch_does_not_acquire_the_writer_lock() {
        let (dir, store) = test_store();
        store.touch("a", 1).unwrap();
        let blocker = Connection::open(dir.path().join(DIR_NAME).join(DB_NAME)).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        store.conn.busy_timeout(Duration::from_millis(25)).unwrap();
        store.touch("a", TOUCH_INTERVAL_MS).unwrap();
        assert!(store.touch("a", TOUCH_INTERVAL_MS + 1).is_err());
        assert!(store.touch("new", 1).is_err());
        blocker.execute_batch("ROLLBACK").unwrap();
        store.touch("a", TOUCH_INTERVAL_MS + 1).unwrap();
        store.touch("a", 0).unwrap();
        let agent = store.agents().unwrap().remove(0);
        assert_eq!(
            (agent.first_seen, agent.last_seen),
            (1, TOUCH_INTERVAL_MS + 1)
        );
    }

    #[test]
    fn best_effort_touch_does_not_wait_for_another_writer() {
        let (dir, store) = test_store();
        store.touch("a", 1).unwrap();
        let blocker = Connection::open(dir.path().join(DIR_NAME).join(DB_NAME)).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        let previous = Duration::from_millis(1_375);
        store.conn.busy_timeout(previous).unwrap();
        let started = std::time::Instant::now();
        assert!(store.touch_best_effort("a", 1 + TOUCH_INTERVAL_MS).is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
        let timeout = || {
            store
                .conn
                .pragma_query_value(None, "busy_timeout", |row| row.get::<_, u32>(0))
                .unwrap()
        };
        assert_eq!(timeout(), previous.as_millis() as u32);
        store.touch_best_effort("a", 2).unwrap();
        assert_eq!(timeout(), previous.as_millis() as u32);
        blocker.execute_batch("ROLLBACK").unwrap();
        store.touch_best_effort("a", 1 + TOUCH_INTERVAL_MS).unwrap();
        assert_eq!(timeout(), previous.as_millis() as u32);
    }

    #[test]
    fn touch_recreates_an_agent_deleted_between_select_and_upsert() {
        use std::sync::mpsc;

        let (dir, mut store) = test_store();
        store.touch("a", 1).unwrap();
        let blocker = Store::open(dir.path()).unwrap();
        blocker.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let (blocked_tx, blocked_rx) = mpsc::sync_channel(1);
        store
            .conn
            .busy_handler(Some(move |attempt| {
                if attempt == 0 {
                    blocked_tx.send(()).unwrap();
                }
                std::thread::sleep(Duration::from_millis(1));
                attempt < 1_000
            }))
            .unwrap();
        let writer = std::thread::spawn(move || {
            // WAL permits the SELECT; the callback proves the UPSERT is now blocked.
            blocked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(
                blocker
                    .conn
                    .execute("DELETE FROM agents WHERE id = 'a'", [])
                    .unwrap(),
                1
            );
            blocker.conn.execute_batch("COMMIT").unwrap();
        });
        let now = 1 + TOUCH_INTERVAL_MS;
        let result = store.touch("a", now);
        writer.join().unwrap();
        result.unwrap();
        store.conn.busy_timeout(BUSY_TIMEOUT).unwrap();
        assert_eq!(
            store.agents().unwrap(),
            vec![Agent {
                id: "a".into(),
                first_seen: now,
                last_seen: now,
            }]
        );
    }

    #[test]
    fn version_one_database_migrates_and_preserves_existing_rows() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(DIR_NAME);
        fs::create_dir_all(&state).unwrap();
        #[cfg(windows)]
        crate::windows::private_dir(&state).unwrap();
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
        #[cfg(windows)]
        crate::windows::private_dir(&state).unwrap();
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
