// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use lockyard_core::{PrivateStateDatabase, open_private_state_database};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use std::fs;
use std::sync::Mutex;

const DATABASE: &str = "pending.db";
const PRIVATE_DIRECTORY: &str = ".sqlite";
const SCHEMA: &str = "
CREATE TABLE pending_scopes (
    scope TEXT PRIMARY KEY,
    legacy_generation INTEGER NOT NULL DEFAULT 0,
    repair_cursor TEXT
) STRICT;
CREATE TABLE pending_writes (
    scope TEXT NOT NULL REFERENCES pending_scopes(scope),
    key TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'done', 'settled', 'archived', 'retired')),
    payload BLOB NOT NULL,
    budget_bytes INTEGER,
    shared INTEGER NOT NULL DEFAULT 0,
    receipt BLOB,
    archived_at INTEGER,
    completion_order INTEGER,
    PRIMARY KEY (scope, key)
) STRICT, WITHOUT ROWID;
CREATE INDEX pending_writes_active ON pending_writes(scope, key) WHERE state = 'pending';
CREATE INDEX pending_writes_budget ON pending_writes(scope, budget_bytes)
    WHERE budget_bytes IS NOT NULL;
CREATE INDEX pending_writes_done ON pending_writes(scope, completion_order DESC)
    WHERE state = 'done';
PRAGMA user_version = 1;
";

pub(crate) struct PendingJournal {
    db: Mutex<PrivateStateDatabase>,
    scope: String,
    legacy: PathBuf,
    directory: PathBuf,
}

pub(super) enum Admission {
    Inserted,
    Existing(Box<PendingWrite>),
    Full,
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, ClientError> {
    serde_json::to_vec(value).map_err(journal_error)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ClientError> {
    serde_json::from_slice(bytes).map_err(journal_decode_error)
}

fn charge(row: &PendingWrite, payload: &[u8]) -> Option<i64> {
    maintenance::uses_replay_budget(row).then_some(payload.len() as i64)
}

fn exists(path: &Path) -> Result<bool, ClientError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(journal_error(error)),
    }
}

fn journal_scope(client: &Client) -> String {
    crate::credential_fingerprint(&format!("{}\0{}", client.base_url, client.token))
}

pub(super) fn status_cache_path(client: &Client, root: &Path) -> PathBuf {
    root.join(PRIVATE_DIRECTORY)
        .join(format!("{}.status-protocol.cache", journal_scope(client)))
}

impl PendingJournal {
    pub(super) fn open(client: &Client, root: &Path) -> Result<Self, ClientError> {
        let scope = journal_scope(client);
        let legacy = root.join(&scope);
        let directory = root.join(PRIVATE_DIRECTORY);
        #[cfg(windows)]
        if exists(&directory)? {
            // Existing state must already be private. Rewriting the ACL would
            // leave any handles acquired under the old ACL usable.
            lockyard_core::windows::require_private(&directory).map_err(journal_error)?;
        }
        private_directory(&directory)?;
        let db = open_private_state_database(&directory, DATABASE).map_err(journal_error)?;
        let journal = Self {
            db: Mutex::new(db),
            scope,
            legacy,
            directory,
        };
        journal.initialize()?;
        journal.migrate_legacy(client)?;
        Ok(journal)
    }

    pub(super) fn status_cache_path(&self) -> PathBuf {
        self.directory
            .join(format!("{}.status-protocol.cache", self.scope))
    }

    fn transaction<T>(
        &self,
        mode: TransactionBehavior,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let mut db = self
            .db
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tx = db.transaction_with_behavior(mode).map_err(journal_error)?;
        let result = operation(&tx)?;
        tx.commit().map_err(journal_error)?;
        Ok(result)
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        self.transaction(TransactionBehavior::Deferred, operation)
    }

    fn read_before<T>(
        &self,
        deadline: Option<Instant>,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        self.transaction_before(TransactionBehavior::Deferred, deadline, operation)
    }

    fn write<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        self.transaction(TransactionBehavior::Immediate, operation)
    }

    fn write_before<T>(
        &self,
        deadline: Option<Instant>,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        self.transaction_before(TransactionBehavior::Immediate, deadline, operation)
    }

    // Short foreground calls share the SQLite connection with upkeep. Bound
    // both waits by the caller's deadline and keep the default for other work.
    fn transaction_before<T>(
        &self,
        mode: TransactionBehavior,
        deadline: Option<Instant>,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let Some(deadline) = deadline else {
            return self.transaction(mode, operation);
        };
        let mut db = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ClientError::JournalBusy);
            }
            match self.db.try_lock() {
                Ok(db) => break db,
                Err(std::sync::TryLockError::Poisoned(error)) => break error.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(left.min(Duration::from_millis(5)));
                }
            }
        };
        let default_ms: u32 = db
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .map_err(journal_error)?;
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ClientError::JournalBusy);
        }
        db.busy_timeout(left.min(Duration::from_millis(u64::from(default_ms))))
            .map_err(journal_error)?;
        let sql_error = |error: rusqlite::Error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) {
                ClientError::JournalBusy
            } else {
                journal_error(error)
            }
        };
        let result = (|| {
            let tx = db.transaction_with_behavior(mode).map_err(sql_error)?;
            let result = operation(&tx)?;
            tx.commit().map_err(sql_error)?;
            Ok(result)
        })();
        db.busy_timeout(Duration::from_millis(u64::from(default_ms)))
            .map_err(journal_error)?;
        result
    }

    fn initialize(&self) -> Result<(), ClientError> {
        let version = |tx: &Transaction<'_>| {
            tx.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))
                .map_err(journal_error)
        };
        if self.read(version)? == 1 {
            return Ok(());
        }
        self.write(|tx| match version(tx)? {
            0 => {
                // A first-use power loss must not remove a newly created
                // directory entry after an operation has reached the network.
                #[cfg(unix)]
                for ancestor in self.directory.ancestors().skip(1) {
                    if !ancestor.as_os_str().is_empty() {
                        lockyard_core::fsio::sync_dir(ancestor).map_err(journal_error)?;
                    }
                }
                tx.execute_batch(SCHEMA).map_err(journal_error)
            }
            1 => Ok(()),
            _ => Err(journal_error("unsupported pending database schema")),
        })
    }

    fn legacy_generation(&self, tx: &Transaction<'_>) -> Result<Option<i64>, ClientError> {
        tx.query_row(
            "SELECT legacy_generation FROM pending_scopes WHERE scope = ?1",
            [&self.scope],
            |row| row.get(0),
        )
        .optional()
        .map_err(journal_error)
    }

    fn legacy_archive(&self, generation: i64) -> PathBuf {
        if generation == 1 {
            self.legacy.with_extension("migrated")
        } else {
            self.legacy.with_extension(format!("migrated.{generation}"))
        }
    }

    fn migrate_legacy(&self, client: &Client) -> Result<(), ClientError> {
        let staged = self.legacy.with_extension("migrating");
        // A filesystem rename cannot join a SQLite transaction. The next archive
        // or the staging path is recoverable until its generation commits.
        loop {
            let is_current = self.read(|tx| {
                let Some(generation) = self.legacy_generation(tx)? else {
                    return Ok(false);
                };
                Ok(!exists(&self.legacy)?
                    && !exists(&staged)?
                    && !exists(&self.legacy_archive(generation + 1))?)
            })?;
            if is_current {
                return Ok(());
            }
            let imported = self.write(|tx| {
                tx.execute(
                    "INSERT INTO pending_scopes(scope) VALUES (?1) ON CONFLICT DO NOTHING",
                    [&self.scope],
                )
                .map_err(journal_error)?;
                let generation = self.legacy_generation(tx)?.unwrap() + 1;
                let archived = self.legacy_archive(generation);
                let source = if exists(&archived)? {
                    if exists(&staged)? {
                        return Err(journal_error("conflicting legacy pending archives"));
                    }
                    &archived
                } else if exists(&staged)? {
                    &staged
                } else if exists(&self.legacy)? {
                    private_directory(&self.legacy)?;
                    #[cfg(test)]
                    migration_test_event("before-staging");
                    lockyard_core::fsio::rename(&self.legacy, &staged).map_err(journal_error)?;
                    lockyard_core::fsio::sync_dir(self.legacy.parent().unwrap())
                        .map_err(journal_error)?;
                    #[cfg(test)]
                    migration_test_event("after-staging");
                    &staged
                } else {
                    return Ok(false);
                };
                private_directory(source)?;
                self.import_records(client, tx, source)?;
                let cursor = read_private_json::<String>(&source.join(".repair-cursor")).ok();
                tx.execute(
                    "UPDATE pending_scopes SET legacy_generation = ?2,
                        repair_cursor = coalesce(repair_cursor, ?3) WHERE scope = ?1",
                    params![self.scope, generation, cursor],
                )
                .map_err(journal_error)?;
                self.prune_done(tx)?;
                if source == &staged {
                    lockyard_core::fsio::rename(&staged, &archived).map_err(journal_error)?;
                }
                lockyard_core::fsio::sync_dir(self.legacy.parent().unwrap())
                    .map_err(journal_error)?;
                #[cfg(test)]
                migration_test_event("after-rename");
                Ok(true)
            })?;
            if !imported {
                return Ok(());
            }
            #[cfg(test)]
            migration_test_event("after-commit");
        }
    }

    fn import_records(
        &self,
        client: &Client,
        tx: &Transaction<'_>,
        source: &Path,
    ) -> Result<(), ClientError> {
        let mut paths = fs::read_dir(source)
            .map_err(journal_error)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(journal_error)?;
        // A failed legacy rename could leave both pending and terminal files.
        // Terminal evidence wins only if it describes the same frozen request.
        paths.sort_by_key(|path| match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => 0,
            Some("unknown") => 1,
            Some("completed") => 2,
            Some("settled") => 3,
            Some("quarantine") => 4,
            _ => 5,
        });
        let mut new_keys = BTreeSet::new();
        for path in paths {
            let extension = path.extension().and_then(|ext| ext.to_str());
            let (mut pending, state, mut receipt) = match extension {
                Some("json" | "unknown" | "quarantine") => {
                    let pending: PendingWrite = read_private_json(&path)?;
                    let state = if extension == Some("quarantine") {
                        "archived"
                    } else {
                        "pending"
                    };
                    (pending, state, None)
                }
                Some("settled") => {
                    let receipt: maintenance::SettledWrite = read_private_json(&path)?;
                    (receipt.pending.clone(), "settled", Some(receipt))
                }
                Some("completed") => {
                    // An invalid marker never authorizes dropping the original record.
                    // Preserve it in the renamed legacy directory for inspection.
                    let Ok(marker) = read_private_json::<Value>(&path) else {
                        continue;
                    };
                    let (Some(key), Some(digest)) =
                        (marker["key"].as_str(), marker["digest"].as_str())
                    else {
                        continue;
                    };
                    if key.is_empty()
                        || digest.len() != 64
                        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                        || path != journal_path(source, key).with_extension("completed")
                    {
                        continue;
                    }
                    let mut pending = match self.lookup(tx, key)? {
                        Some((_, Some(pending))) => pending,
                        Some((_, None)) => continue,
                        None => {
                            // The old client could unlink the request before
                            // unlinking the synced completion marker.
                            tx.execute(
                                "INSERT INTO pending_writes(scope, key, state, payload)
                                 VALUES (?1, ?2, 'retired', x'')",
                                params![self.scope, key],
                            )
                            .map_err(journal_error)?;
                            continue;
                        }
                    };
                    // The old marker hashes the record from this directory, before
                    // merging replay evidence from an earlier generation.
                    let raw = journal_path(source, key);
                    let unknown = raw.with_extension("unknown");
                    if exists(&unknown)? {
                        pending = read_private_json(&unknown)?;
                    } else if exists(&raw)? {
                        pending = read_private_json(&raw)?;
                    }
                    let payload = serde_json::to_string(&pending).map_err(journal_error)?;
                    if digest != crate::credential_fingerprint(&payload) {
                        continue;
                    }
                    (pending, "done", None)
                }
                _ => continue,
            };
            if !maintenance::valid_legacy_pending(client, &pending)
                || path.with_extension("json") != journal_path(source, &pending.key)
            {
                return Err(journal_error(
                    "legacy pending operation does not match its origin or credential",
                ));
            }
            // Old upkeep parked permanent-looking HTTP refusals before checking
            // the live server clock. Give an ambiguous legacy refusal with a
            // clock anchor that check again. Merge any SQLite stop evidence
            // below so a later import cannot undo a stop by the new client.
            if state == "pending"
                && !pending.pre_execution_rejected
                && pending.first_sent_server_secs.is_some()
                && crate::signed_results::is_result_path(&pending.path)
                && Client::result_permanently_refused(&pending)
            {
                pending.replay_stopped = false;
            }
            if let Some((previous_state, previous)) = self.lookup(tx, &pending.key)? {
                // A previously completed key remains reserved after its body is pruned.
                // Late old clients may still have a copy, but cannot reopen that key.
                let Some(previous) = previous else {
                    continue;
                };
                if !same_wire(&previous, &pending) {
                    return Err(journal_error(
                        "conflicting records in legacy pending journal",
                    ));
                }
                if !can_import_over(&previous_state, state)
                    || (receipt.as_ref().is_some_and(|r| r.error.is_some())
                        && !new_keys.contains(&pending.key))
                {
                    continue;
                }
                // Retained terminal records can be replayed by an already-running
                // caller, so their receipt window must also keep the original bound.
                pending.first_sent_unix_secs = pending
                    .first_sent_unix_secs
                    .min(previous.first_sent_unix_secs);
                pending.first_sent_server_secs = pending
                    .first_sent_server_secs
                    .min(previous.first_sent_server_secs);
                pending.replay_paused |= previous.replay_paused;
                pending.replay_stopped |= previous.replay_stopped;
                pending.pre_execution_rejected &= previous.pre_execution_rejected;
                pending.result_retry_at = pending.result_retry_at.max(previous.result_retry_at);
            } else {
                new_keys.insert(pending.key.clone());
            }
            // File journals could persist the latest HTTP status after an unknown
            // PUT without proving that the earlier PUT failed. Preserve the
            // explicit quota suspension and any absolute Retry-After.
            if !pending.pre_execution_rejected
                && crate::signed_results::is_result_path(&pending.path)
                && (pending.cause_status, pending.cause_code.as_str())
                    != (Some(429), "relay_budget_exceeded")
            {
                pending.cause_status = None;
            }
            if let Some(receipt) = &mut receipt {
                receipt.pending = pending.clone();
            }
            self.save_imported(
                tx,
                &pending,
                state,
                receipt.as_ref().map(encode).transpose()?,
            )?;
            #[cfg(test)]
            migration_test_event("in-transaction");
        }
        Ok(())
    }

    fn save_imported(
        &self,
        tx: &Transaction<'_>,
        pending: &PendingWrite,
        state: &str,
        receipt: Option<Vec<u8>>,
    ) -> Result<(), ClientError> {
        let payload = encode(pending)?;
        let charge = if state == "pending" {
            charge(pending, &payload)
        } else {
            None
        };
        let completion_order = (state == "done")
            .then(|| self.next_completion(tx))
            .transpose()?;
        tx.execute(
            "INSERT INTO pending_writes(scope, key, state, payload, budget_bytes, receipt,
                completion_order)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(scope, key) DO UPDATE SET state=excluded.state, payload=excluded.payload,
                 budget_bytes=excluded.budget_bytes, receipt=excluded.receipt,
                 completion_order=excluded.completion_order",
            params![
                self.scope,
                pending.key,
                state,
                payload,
                charge,
                receipt,
                completion_order
            ],
        )
        .map_err(journal_error)?;
        Ok(())
    }

    fn lookup(
        &self,
        tx: &Transaction<'_>,
        key: &str,
    ) -> Result<Option<(String, Option<PendingWrite>)>, ClientError> {
        tx.query_row(
            "SELECT state, payload FROM pending_writes WHERE scope = ?1 AND key = ?2",
            params![self.scope, key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(journal_error)?
        .map(|(state, bytes)| {
            let row = (state != "retired").then(|| decode(&bytes)).transpose()?;
            Ok((state, row))
        })
        .transpose()
    }

    pub(super) fn pending(&self, key: &str) -> Result<Option<PendingWrite>, ClientError> {
        self.pending_before(key, None)
    }

    pub(super) fn pending_before(
        &self,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<PendingWrite>, ClientError> {
        self.read_before(deadline, |tx| self.pending_in(tx, key))
    }

    fn pending_in(
        &self,
        tx: &Transaction<'_>,
        key: &str,
    ) -> Result<Option<PendingWrite>, ClientError> {
        Ok(self
            .lookup(tx, key)?
            .and_then(|(state, row)| row.filter(|_| state == "pending")))
    }

    pub(super) fn for_ack(
        &self,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<PendingWrite>, ClientError> {
        self.read_before(deadline, |tx| {
            Ok(self.lookup(tx, key)?.and_then(|(state, row)| {
                row.filter(|_| matches!(state.as_str(), "pending" | "archived"))
            }))
        })
    }

    pub(super) fn for_send(
        &self,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<PendingWrite>, ClientError> {
        self.read_before(deadline, |tx| self.for_send_in(tx, key))
    }

    fn for_send_in(
        &self,
        tx: &Transaction<'_>,
        key: &str,
    ) -> Result<Option<PendingWrite>, ClientError> {
        match self.lookup(tx, key)? {
            Some((state, Some(row)))
                if matches!(state.as_str(), "pending" | "done" | "settled") =>
            {
                Ok(Some(row))
            }
            Some((_, None)) => Err(reconcile_by_key(
                key,
                "operation was completed locally and its cached request was evicted",
            )),
            Some(_) => Err(local(
                "outcome_unknown",
                "pending operation is quarantined; original bytes retained; reconcile its outcome before using a new key",
            )),
            None => Ok(None),
        }
    }

    pub(super) fn parked(&self, key: &str) -> Result<Option<PendingWrite>, ClientError> {
        self.read(|tx| {
            Ok(self.lookup(tx, key)?.and_then(|(state, row)| {
                row.filter(|row| state == "archived" || (state == "pending" && row.replay_paused))
            }))
        })
    }

    fn rows(&self, tx: &Transaction<'_>) -> Result<Vec<PendingWrite>, ClientError> {
        let mut statement = tx.prepare(
            "SELECT payload FROM pending_writes WHERE scope = ?1 AND state = 'pending' ORDER BY key",
        ).map_err(journal_error)?;
        let rows = statement
            .query_map([&self.scope], |row| row.get::<_, Vec<u8>>(0))
            .map_err(journal_error)?;
        rows.map(|row| decode(&row.map_err(journal_error)?))
            .collect()
    }

    pub(super) fn pending_rows(&self) -> Result<Vec<PendingWrite>, ClientError> {
        self.read(|tx| self.rows(tx))
    }

    pub(super) fn repair_snapshot(
        &self,
        deadline: Option<Instant>,
    ) -> Result<(Vec<PendingWrite>, Option<String>), ClientError> {
        self.read_before(deadline, |tx| {
            let cursor = tx
                .query_row(
                    "SELECT repair_cursor FROM pending_scopes WHERE scope = ?1",
                    [&self.scope],
                    |row| row.get(0),
                )
                .map_err(journal_error)?;
            Ok((self.rows(tx)?, cursor))
        })
    }

    pub(super) fn advance_cursor(
        &self,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<(), ClientError> {
        self.write_before(deadline, |tx| {
            tx.execute(
                "UPDATE pending_scopes SET repair_cursor = ?2 WHERE scope = ?1",
                params![self.scope, key],
            )
            .map_err(journal_error)?;
            Ok(())
        })
    }

    fn is_full(
        &self,
        tx: &Transaction<'_>,
        extra_bytes: usize,
        replacing_key: Option<&str>,
    ) -> Result<bool, ClientError> {
        let (count, bytes, previous): (i64, i64, Option<i64>) = tx
            .query_row(
                "SELECT count(*), coalesce(sum(budget_bytes), 0),
                    max(CASE WHEN key = ?2 THEN budget_bytes END)
                 FROM pending_writes WHERE scope = ?1 AND budget_bytes IS NOT NULL",
                params![self.scope, replacing_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(journal_error)?;
        let new_bytes = bytes - previous.unwrap_or(0) + extra_bytes as i64;
        match previous {
            None => Ok(count >= MAX_PENDING as i64 || new_bytes > MAX_PENDING_BYTES as i64),
            // Historical imports may already be full. Let repair transition
            // their existing rows and keep the limit for new admissions.
            Some(_) => {
                Ok(new_bytes > MAX_PENDING_BYTES as i64 && bytes <= MAX_PENDING_BYTES as i64)
            }
        }
    }

    pub(super) fn full(&self, extra_bytes: usize, deadline: Instant) -> Result<bool, ClientError> {
        self.read_before(Some(deadline), |tx| self.is_full(tx, extra_bytes, None))
    }

    pub(super) fn admit(
        &self,
        row: &PendingWrite,
        payload: &[u8],
        deadline: Option<Instant>,
    ) -> Result<Admission, ClientError> {
        self.write_before(deadline, |tx| {
            if let Some(previous) = self.for_send_in(tx, &row.key)? {
                return Ok(Admission::Existing(Box::new(previous)));
            }
            let charge = charge(row, payload);
            if charge.is_some() && self.is_full(tx, payload.len(), None)? {
                return Ok(Admission::Full);
            }
            tx.execute(
                "INSERT INTO pending_writes(scope, key, state, payload, budget_bytes)
                 VALUES (?1, ?2, 'pending', ?3, ?4)",
                params![self.scope, row.key, payload, charge],
            )
            .map_err(journal_error)?;
            Ok(Admission::Inserted)
        })
    }

    pub(super) fn update(
        &self,
        previous: &PendingWrite,
        row: &PendingWrite,
        deadline: Option<Instant>,
    ) -> Result<bool, ClientError> {
        self.write_before(deadline, |tx| {
            if self.pending_in(tx, &previous.key)?.as_ref() != Some(previous) {
                return Ok(false);
            }
            self.update_in(tx, row)
        })
    }

    fn update_in(&self, tx: &Transaction<'_>, row: &PendingWrite) -> Result<bool, ClientError> {
        let payload = encode(row)?;
        let charge = charge(row, &payload);
        if charge.is_some() && self.is_full(tx, payload.len(), Some(&row.key))? {
            return Ok(false);
        }
        let changed = tx
            .execute(
                "UPDATE pending_writes SET payload = ?3, budget_bytes = ?4
                 WHERE scope = ?1 AND key = ?2 AND (shared = 0 OR NOT ?5)",
                params![
                    self.scope,
                    row.key,
                    payload,
                    charge,
                    row.pre_execution_rejected
                ],
            )
            .map_err(journal_error)?;
        Ok(changed != 0)
    }

    /// Record the response for this snapshot, or only extend the wait when a
    /// concurrent response already changed it. Return whether refusal was proven.
    pub(crate) fn record_result_failure(
        &self,
        attempted: &PendingWrite,
        refusal: Option<&PendingWrite>,
        unknown: &PendingWrite,
    ) -> Result<bool, ClientError> {
        self.write(|tx| {
            let Some(mut current) = self.pending_in(tx, &attempted.key)? else {
                return Ok(false);
            };
            if current == *attempted {
                if let Some(refusal) = refusal
                    && self.save_result_failure(tx, refusal)?
                {
                    return Ok(true);
                }
                // Even an identical snapshot may have acquired another sender.
                // update_in rejects solitary proof once that has happened.
                self.save_result_failure(tx, unknown)?;
            } else if !current.replay_stopped
                && unknown.result_retry_at > current.result_retry_at
                && same_wire(&current, attempted)
                && current.first_sent_unix_secs == attempted.first_sent_unix_secs
                && current.first_sent_server_secs == attempted.first_sent_server_secs
            {
                current.result_retry_at = unknown.result_retry_at;
                self.save_result_failure(tx, &current)?;
            }
            Ok(false)
        })
    }

    fn save_result_failure(
        &self,
        tx: &Transaction<'_>,
        row: &PendingWrite,
    ) -> Result<bool, ClientError> {
        if self.update_in(tx, row)? {
            return Ok(true);
        }
        if row.replay_paused {
            return Ok(false);
        }
        // Failure metadata must survive a full active budget. A parked result
        // remains visible to the signed-result worker and keeps its frozen body.
        let mut parked = row.clone();
        parked.replay_paused = true;
        self.update_in(tx, &parked)
    }

    /// Fence pre-execution proof before a retry can put bytes on the wire. Once
    /// multiple attempts may have run, an individual refusal proves nothing.
    pub(super) fn begin_replay_before(
        &self,
        previous: &PendingWrite,
        row: &PendingWrite,
        deadline: Option<Instant>,
    ) -> Result<bool, ClientError> {
        self.write_before(deadline, |tx| {
            let Some((state, Some(current))) = self.lookup(tx, &previous.key)? else {
                return Ok(false);
            };
            // Another retry may already have made this exact transition.
            // Treat it as a shared send without reviving any older refusal.
            if current != *previous
                && !(previous.pre_execution_rejected
                    && !row.pre_execution_rejected
                    && current == *row)
            {
                return Ok(false);
            }
            if state == "done" {
                return Ok(true);
            }
            if state != "pending" {
                return Ok(false);
            }
            let payload = encode(row)?;
            let charge = charge(row, &payload);
            if charge.is_some() && self.is_full(tx, payload.len(), Some(&row.key))? {
                return Ok(false);
            }
            tx.execute(
                "UPDATE pending_writes SET payload = ?3, budget_bytes = ?4,
                    shared = max(shared, ?5) WHERE scope = ?1 AND key = ?2",
                params![
                    self.scope,
                    previous.key,
                    payload,
                    charge,
                    !current.pre_execution_rejected
                ],
            )
            .map_err(journal_error)?;
            Ok(true)
        })
    }

    fn next_completion(&self, tx: &Transaction<'_>) -> Result<i64, ClientError> {
        tx.query_row(
            "SELECT coalesce(max(completion_order), 0) + 1 FROM pending_writes
             WHERE scope = ?1 AND state = 'done'",
            [&self.scope],
            |row| row.get(0),
        )
        .map_err(journal_error)
    }

    fn prune_done(&self, tx: &Transaction<'_>) -> Result<(), ClientError> {
        // Preserve the newest frozen requests for lagging retry callers. Keep
        // an empty key reservation after eviction: replay receipts can expire
        // on the server and a fresh send under an old key can execute again.
        tx.execute(
            "UPDATE pending_writes SET state = 'retired', payload = x'', completion_order = NULL
             WHERE scope = ?1 AND key IN (
                 SELECT key FROM (
                     SELECT key, row_number() OVER newest AS count,
                         sum(length(payload)) OVER newest AS bytes
                     FROM pending_writes WHERE scope = ?1 AND state = 'done'
                     WINDOW newest AS (ORDER BY completion_order DESC)
                 ) WHERE count > ?2 OR bytes > ?3
             )",
            params![self.scope, MAX_PENDING as i64, MAX_PENDING_BYTES as i64],
        )
        .map_err(journal_error)?;
        Ok(())
    }

    pub(super) fn complete(&self, key: &str) -> Result<(), ClientError> {
        self.write(|tx| self.complete_in(tx, key))
    }

    pub(super) fn complete_verified(&self, expected: &PendingWrite) -> Result<(), ClientError> {
        self.write(|tx| match self.lookup(tx, &expected.key)? {
            Some((state, Some(current))) if state == "pending" || state == "archived" => {
                if !same_wire(&current, expected) {
                    return Err(ClientError::OutcomeUnknown(Box::new(expected.clone())));
                }
                self.complete_in(tx, &expected.key)
            }
            Some(_) => Ok(()),
            None => Err(ClientError::OutcomeUnknown(Box::new(expected.clone()))),
        })
    }

    pub(crate) fn acknowledge(
        &self,
        call: &Call,
        key: &str,
        deadline: Instant,
    ) -> Result<bool, ClientError> {
        self.write_before(Some(deadline), |tx| {
            let Some((state, Some(row))) = self.lookup(tx, key)? else {
                return Ok(false);
            };
            if !matches!(state.as_str(), "pending" | "archived") {
                return Ok(false);
            }
            crate::verify_pending_ack(&row, call)?;
            self.complete_in(tx, key)?;
            Ok(true)
        })
    }

    fn complete_in(&self, tx: &Transaction<'_>, key: &str) -> Result<(), ClientError> {
        let changed = tx
            .execute(
                "UPDATE pending_writes SET state = 'done', budget_bytes = NULL,
                completion_order = ?3
                 WHERE scope = ?1 AND key = ?2 AND state IN ('pending', 'archived')",
                params![self.scope, key, self.next_completion(tx)?],
            )
            .map_err(journal_error)?;
        if changed != 0 {
            self.prune_done(tx)?;
        }
        Ok(())
    }

    pub(super) fn discard_unshared(&self, row: &PendingWrite) -> Result<bool, ClientError> {
        self.write(|tx| {
            if self.pending_in(tx, &row.key)?.as_ref() != Some(row) {
                return Ok(false);
            }
            let changed = tx
                .execute(
                    "DELETE FROM pending_writes WHERE scope = ?1 AND key = ?2
                 AND shared = 0",
                    params![self.scope, row.key],
                )
                .map_err(journal_error)?;
            Ok(changed != 0)
        })
    }

    pub(super) fn settle(
        &self,
        receipt: &maintenance::SettledWrite,
        deadline: Option<Instant>,
    ) -> Result<bool, ClientError> {
        self.write_before(deadline, |tx| {
            let Some((state, Some(current))) = self.lookup(tx, &receipt.pending.key)? else {
                return Ok(false);
            };
            if current != receipt.pending
                || !(state == "pending" || (state == "archived" && receipt.error.is_none()))
            {
                return Ok(false);
            }
            let changed = tx
                .execute(
                    "UPDATE pending_writes SET state = 'settled', receipt = ?3, budget_bytes = NULL
                 WHERE scope = ?1 AND key = ?2 AND (shared = 0 OR NOT ?4)",
                    params![
                        self.scope,
                        receipt.pending.key,
                        encode(receipt)?,
                        receipt.error.is_some()
                    ],
                )
                .map_err(journal_error)?;
            Ok(changed != 0)
        })
    }

    pub(super) fn receipt(
        &self,
        key: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<maintenance::SettledWrite>, ClientError> {
        self.read_before(deadline, |tx| {
            tx.query_row(
                "SELECT receipt FROM pending_writes WHERE scope = ?1 AND key = ?2 AND state = 'settled'",
                params![self.scope, key],
                |row| row.get::<_, Vec<u8>>(0),
            ).optional().map_err(journal_error)?
                .map(|bytes| decode(&bytes)).transpose()
        })
    }

    pub(super) fn settled_rows(&self) -> Result<Vec<maintenance::SettledWrite>, ClientError> {
        self.read(|tx| {
            let mut query = tx.prepare(
                "SELECT receipt FROM pending_writes WHERE scope = ?1 AND state = 'settled' ORDER BY key",
            ).map_err(journal_error)?;
            let rows = query.query_map([&self.scope], |row| row.get::<_, Vec<u8>>(0))
                .map_err(journal_error)?;
            rows.map(|row| decode(&row.map_err(journal_error)?)).collect()
        })
    }

    pub(super) fn update_receipt(
        &self,
        previous: &maintenance::SettledWrite,
        receipt: Option<&maintenance::SettledWrite>,
    ) -> Result<(), ClientError> {
        self.write(|tx| {
            let mut pending = previous.pending.clone();
            let mut payload = encode(&pending)?;
            let mut charge = charge(&pending, &payload);
            if receipt.is_none() && charge.is_some() && self.is_full(tx, payload.len(), None)? {
                // Keep the original wire bytes when the freed slot was filled.
                pending.replay_paused = true;
                payload = encode(&pending)?;
                charge = None;
            }
            tx.execute(
                "UPDATE pending_writes SET state = ?3, receipt = ?4, budget_bytes = ?5,
                    payload = ?7
                 WHERE scope = ?1 AND key = ?2 AND state = 'settled' AND receipt = ?6",
                params![
                    self.scope,
                    previous.pending.key,
                    if receipt.is_some() {
                        "settled"
                    } else {
                        "pending"
                    },
                    receipt.map(encode).transpose()?,
                    if receipt.is_some() { None } else { charge },
                    encode(previous)?,
                    payload,
                ],
            )
            .map_err(journal_error)?;
            Ok(())
        })
    }

    pub(super) fn archive_unknown(&self, selection: &str, now: u64) -> Result<usize, ClientError> {
        self.write(|tx| {
            tx.execute(
                "UPDATE pending_writes SET state = 'archived', archived_at = ?3
                 WHERE scope = ?1 AND state = 'pending' AND budget_bytes IS NULL
                 AND (key = ?2 OR ?2 = '--all')",
                params![self.scope, selection, now as i64],
            )
            .map_err(journal_error)
        })
    }

    #[cfg(test)]
    pub(super) fn seed_pending(&self, row: &PendingWrite) {
        self.write(|tx| self.save_imported(tx, row, "pending", None))
            .unwrap();
    }
}

fn can_import_over(previous: &str, incoming: &str) -> bool {
    match previous {
        "pending" => true,
        "archived" => matches!(incoming, "done" | "settled"),
        "done" => incoming == "settled",
        _ => false,
    }
}

fn same_wire(a: &PendingWrite, b: &PendingWrite) -> bool {
    a.key == b.key
        && a.method == b.method
        && a.path == b.path
        && a.body == b.body
        && a.protocol == b.protocol
        && a.repository == b.repository
        && a.session == b.session
        && a.request_path == b.request_path
        && a.request_digest == b.request_digest
        && a.encryption_context == b.encryption_context
        && a.result_expires_at == b.result_expires_at
}

#[cfg(test)]
fn migration_test_event(event: &str) {
    if std::env::var("LY_TEST_PENDING_MIGRATION_EXIT").as_deref() == Ok(event) {
        std::process::exit(92);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::pending_completion_tests::pending;
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    const CHILD: &str = "protocol::pending_store::tests::journal_child";

    fn client() -> Client {
        Client::new("http://127.0.0.1:1", "sqlite-journal-fixture".into()).unwrap()
    }

    fn child(root: &Path, action: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD, "--nocapture"])
            .env("LY_TEST_PENDING_ROOT", root)
            .env("LY_TEST_PENDING_ACTION", action);
        command
    }

    fn row_count(journal: &PendingJournal) -> usize {
        journal
            .read(|tx| {
                tx.query_row("SELECT count(*) FROM pending_writes", [], |r| {
                    r.get::<_, i64>(0)
                })
                .map(|count| count as usize)
                .map_err(journal_error)
            })
            .unwrap()
    }

    #[test]
    fn foreground_transaction_uses_the_same_deadline_for_the_connection_mutex() {
        let root = tempfile::tempdir().unwrap();
        let client = client()
            .load_pending_journal(root.path().canonicalize().unwrap())
            .unwrap();
        let journal = client.pending_journal.as_ref().unwrap();
        let owner = journal.db.lock().unwrap();
        let (finished, completion) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_millis(100);
                finished
                    .send(journal.advance_cursor("blocked", Some(deadline)))
                    .unwrap();
            });
            let result = completion.recv_timeout(Duration::from_secs(2));
            drop(owner);
            assert!(matches!(result, Ok(Err(ClientError::JournalBusy))));
        });
        let (_, cursor) = journal.repair_snapshot(None).unwrap();
        assert_eq!(cursor, None);
        journal.advance_cursor("next", None).unwrap();
        assert_eq!(
            journal.repair_snapshot(None).unwrap().1.as_deref(),
            Some("next")
        );
    }

    #[test]
    fn journal_child() {
        let Some(root) = std::env::var_os("LY_TEST_PENDING_ROOT") else {
            return;
        };
        let action = std::env::var("LY_TEST_PENDING_ACTION").unwrap();
        let root = Path::new(&root);
        if action.starts_with("writer-") {
            std::io::stdin().read_exact(&mut [0]).unwrap();
            let client = client().load_pending_journal(root).unwrap();
            for index in 0..40 {
                client
                    .retain_pending(pending(&client, &format!("{action}-{index:02}")))
                    .unwrap();
            }
        } else if action.starts_with("capacity-") {
            std::io::stdin().read_exact(&mut [0]).unwrap();
            let client = client().load_pending_journal(root).unwrap();
            match client.admit_pending(&pending(&client, &action)) {
                Ok(None) => {}
                Err(error) if error.to_string().contains("budget exceeded") => {
                    std::process::exit(94)
                }
                other => panic!("unexpected admission: {other:?}"),
            }
        } else if action == "crash-write" {
            let client = client().load_pending_journal(root).unwrap();
            let journal = client.pending_journal.as_ref().unwrap();
            journal
                .write::<()>(|tx| {
                    journal.save_imported(tx, &pending(&client, "uncommitted"), "pending", None)?;
                    std::process::exit(93);
                })
                .unwrap();
            unreachable!();
        } else {
            let _ = client().load_pending_journal(root).unwrap();
            panic!("migration interruption point was not reached");
        }
    }

    #[test]
    fn two_processes_can_initialize_and_write_without_busy_or_loss() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let mut children: Vec<_> = ["writer-a", "writer-b"]
            .into_iter()
            .map(|name| {
                child(&root, name)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        // Each process waits for input before opening the new database.
        for process in &mut children {
            process.stdin.take().unwrap().write_all(b"x").unwrap();
        }
        for process in children {
            let output = process.wait_with_output().unwrap();
            assert!(output.status.success(), "{output:?}");
        }
        let client = client().load_pending_journal(&root).unwrap();
        let rows = client.pending_operations();
        let expected: Vec<_> = ["writer-a", "writer-b"]
            .into_iter()
            .flat_map(|name| (0..40).map(move |index| format!("{name}-{index:02}")))
            .collect();
        assert_eq!(
            rows.iter().map(|row| row.key.clone()).collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn process_exit_during_write_keeps_only_committed_rows() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let initial = client().load_pending_journal(&root).unwrap();
        let durable = pending(&initial, "committed");
        initial.retain_pending(durable.clone()).unwrap();
        let exit = child(&root, "crash-write").output().unwrap();
        assert_eq!(exit.status.code(), Some(93), "{exit:?}");
        let reopened = client().load_pending_journal(root).unwrap();
        assert_eq!(reopened.pending_operations(), [durable]);
    }

    fn legacy_folder(client: &Client, root: &Path) -> PathBuf {
        let scope =
            crate::credential_fingerprint(&format!("{}\0{}", client.base_url, client.token));
        let legacy = root.join(scope);
        private_directory(&legacy).unwrap();
        legacy
    }

    fn write_legacy(legacy: &Path, row: &PendingWrite, extension: &str) {
        lockyard_core::fsio::replace(
            &journal_path(legacy, &row.key).with_extension(extension),
            &encode(row).unwrap(),
            0o600,
        )
        .unwrap();
    }

    #[test]
    fn migration_recovers_across_commit_and_archive_boundaries() {
        for phase in [
            "before-staging",
            "after-staging",
            "in-transaction",
            "after-rename",
            "after-commit",
        ] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let setup = client();
            let legacy = legacy_folder(&setup, &root);
            let archived = legacy.with_extension("migrated");
            let first = pending(&setup, "a-first");
            let mut parked = pending(&setup, "b-parked");
            parked.replay_paused = true;
            let mut completed = pending(&setup, "c-completed");
            completed.replay_paused = true;
            write_legacy(&legacy, &first, "json");
            write_legacy(&legacy, &parked, "unknown");
            write_legacy(&legacy, &completed, "json");
            let marker = json!({
                "key": completed.key,
                "digest": crate::credential_fingerprint(&serde_json::to_string(&completed).unwrap()),
            });
            let completed_path = journal_path(&legacy, &completed.key).with_extension("completed");
            lockyard_core::fsio::replace(&completed_path, &encode(&marker).unwrap(), 0o600)
                .unwrap();
            // A bad completion marker cannot suppress the original operation.
            lockyard_core::fsio::replace(
                &journal_path(&legacy, &first.key).with_extension("completed"),
                br#"{"key":"a-first","digest":"bad"}"#,
                0o600,
            )
            .unwrap();
            let exit = child(&root, "crash-migration")
                .env("LY_TEST_PENDING_MIGRATION_EXIT", phase)
                .output()
                .unwrap();
            assert_eq!(exit.status.code(), Some(92), "{phase}: {exit:?}");
            assert_eq!(legacy.exists(), phase == "before-staging");
            assert_eq!(
                archived.exists(),
                matches!(phase, "after-rename" | "after-commit")
            );
            assert_eq!(
                legacy.with_extension("migrating").exists(),
                matches!(phase, "after-staging" | "in-transaction")
            );
            let db = open_private_state_database(&root.join(".sqlite"), DATABASE).unwrap();
            let count: i64 = db
                .query_row("SELECT count(*) FROM pending_writes", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, if phase == "after-commit" { 3 } else { 0 });
            drop(db);
            for _ in 0..2 {
                let restored = client().load_pending_journal(&root).unwrap();
                let journal = restored.pending_journal.as_ref().unwrap();
                assert_eq!(
                    restored.pending_operations(),
                    [first.clone(), parked.clone()]
                );
                assert_eq!(
                    journal.for_send(&completed.key, None).unwrap(),
                    Some(completed.clone())
                );
                assert_eq!(row_count(journal), 3);
                assert!(!legacy.exists());
                assert_eq!(
                    fs::read(journal_path(&archived, &first.key)).unwrap(),
                    encode(&first).unwrap(),
                );
                assert!(archived.join(completed_path.file_name().unwrap()).exists());
            }
        }
    }

    #[test]
    fn a_recreated_legacy_scope_is_imported_without_reopening_completed_keys() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let setup = client();
        let legacy = legacy_folder(&setup, &root);
        let first = pending(&setup, "first");
        write_legacy(&legacy, &first, "json");
        let exit = child(&root, "crash-migration")
            .env("LY_TEST_PENDING_MIGRATION_EXIT", "after-rename")
            .output()
            .unwrap();
        assert_eq!(exit.status.code(), Some(92), "{exit:?}");

        // An older binary may create the original path again after the rename.
        let legacy = legacy_folder(&setup, &root);
        let late = pending(&setup, "late");
        let mut duplicate = first.clone();
        duplicate.first_sent_unix_secs = duplicate.first_sent_unix_secs.map(|secs| secs + 30);
        duplicate.first_sent_server_secs = duplicate.first_sent_server_secs.map(|secs| secs + 30);
        write_legacy(&legacy, &late, "json");
        write_legacy(&legacy, &duplicate, "json");
        let restored = client().load_pending_journal(&root).unwrap();
        assert_eq!(restored.pending_operations(), [first.clone(), late.clone()]);
        restored.resolve_pending(&first.key).unwrap();

        let legacy = legacy_folder(&setup, &root);
        write_legacy(&legacy, &first, "json");
        let restored = client().load_pending_journal(&root).unwrap();
        assert_eq!(restored.pending_operations(), std::slice::from_ref(&late));
        assert_eq!(restored.pending_for_send(&first.key).unwrap(), Some(first));
        assert!(legacy.with_extension("migrated").is_dir());
        assert!(legacy.with_extension("migrated.2").is_dir());
        assert!(legacy.with_extension("migrated.3").is_dir());
        assert!(!legacy.exists());
        assert_eq!(row_count(restored.pending_journal.as_ref().unwrap()), 2);
    }

    #[test]
    fn a_late_completion_marker_finishes_the_original_operation_without_extending_replay() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let setup = client();
        let legacy = legacy_folder(&setup, &root);
        let mut original = pending(&setup, "coordination-completed-late");
        original.first_sent_server_secs = Some(10);
        original.path = "/api/v1/zones/claims".into();
        original.request_path = original.path.clone();
        write_legacy(&legacy, &original, "json");
        let imported = client().load_pending_journal(&root).unwrap();
        assert_eq!(imported.pending_operations(), [original.clone()]);

        let legacy = legacy_folder(&setup, &root);
        let mut duplicate = original.clone();
        duplicate.first_sent_server_secs = Some(10 + PENDING_RETENTION_SECS);
        write_legacy(&legacy, &duplicate, "json");
        let marker = json!({
            "key": duplicate.key,
            "digest": crate::credential_fingerprint(&serde_json::to_string(&duplicate).unwrap()),
        });
        lockyard_core::fsio::replace(
            &journal_path(&legacy, &duplicate.key).with_extension("completed"),
            &encode(&marker).unwrap(),
            0o600,
        )
        .unwrap();
        let restored = client().load_pending_journal(&root).unwrap();
        assert!(restored.pending_operations().is_empty());
        assert_eq!(
            restored.pending_for_send(&original.key).unwrap(),
            Some(original)
        );
        assert_eq!(row_count(restored.pending_journal.as_ref().unwrap()), 1);
    }

    #[test]
    fn legacy_signed_result_refusal_without_pre_execution_proof_remains_unknown() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let setup = client();
        let mut row = pending(&setup, "legacy-result");
        row.method = "PUT".into();
        row.path = format!("/api/v1/nodes/worker/jobs/{}/signed-result", crate::ulid());
        row.request_path = row.path.clone();
        row.body = Some("lyenc1.synthetic-legacy-result".into());
        row.result_expires_at = Some("2026-12-01T00:00:00Z".into());
        row.cause_status = Some(403);
        row.cause_code = "revoked".into();
        row.result_retry_at = Some(maintenance::unix_now().unwrap() + 3600);
        row.first_sent_server_secs = Some(maintenance::unix_now().unwrap());
        row.replay_paused = true;
        row.replay_stopped = true;
        let legacy = legacy_folder(&setup, &root);
        write_legacy(&legacy, &row, "unknown");

        let reopened = setup.load_pending_journal(&root).unwrap();
        let imported = reopened.pending_operation(&row.key).unwrap();
        assert_eq!(imported.body, row.body);
        assert_eq!(imported.result_retry_at, row.result_retry_at);
        assert_eq!(imported.cause_status, None);
        assert!(imported.replay_paused);
        assert!(!imported.replay_stopped);
        assert!(!Client::result_permanently_refused(&imported));
        assert!(!Client::result_retry_ready(&imported));

        let mut stopped = imported.clone();
        stopped.replay_stopped = true;
        assert!(reopened.update_pending(&imported, stopped.clone()).unwrap());
        write_legacy(&legacy_folder(&reopened, &root), &row, "unknown");
        let reopened = client().load_pending_journal(root).unwrap();
        assert_eq!(reopened.pending_operation(&row.key), Some(stopped));
    }

    #[test]
    fn pending_record_decode_errors_do_not_include_record_contents() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let setup = client();
        let legacy = legacy_folder(&setup, &root);
        let row = pending(&setup, "invalid");
        let mut invalid = serde_json::to_value(row).unwrap();
        let secret = "synthetic-sensitive-journal-field";
        invalid["replay_paused"] = json!(secret);
        let bytes = encode(&invalid).unwrap();
        lockyard_core::fsio::replace(&journal_path(&legacy, "invalid"), &bytes, 0o600).unwrap();
        let error = client().load_pending_journal(&root).err().unwrap();
        assert!(error.to_string().contains("invalid pending record at line"));
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        assert!(
            !decode::<PendingWrite>(&bytes)
                .unwrap_err()
                .to_string()
                .contains(secret)
        );
    }

    #[test]
    fn two_processes_cannot_both_take_the_last_budget_slot() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let setup = client().load_pending_journal(&root).unwrap();
        for index in 0..MAX_PENDING - 1 {
            setup
                .retain_pending(pending(&setup, &format!("seed-{index}")))
                .unwrap();
        }
        let mut racers: Vec<_> = ["capacity-a", "capacity-b"]
            .into_iter()
            .map(|action| {
                child(&root, action)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for process in &mut racers {
            process.stdin.take().unwrap().write_all(b"x").unwrap();
        }
        let mut exits: Vec<_> = racers
            .into_iter()
            .map(|process| {
                let output = process.wait_with_output().unwrap();
                let code = output.status.code().unwrap();
                assert!(matches!(code, 0 | 94), "{output:?}");
                code
            })
            .collect();
        exits.sort_unstable();
        assert_eq!(exits, [0, 94]);
        assert_eq!(setup.try_pending_operations().unwrap().len(), MAX_PENDING);
    }

    #[test]
    fn admission_charges_the_entire_serialized_payload() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let client = client().load_pending_journal(root).unwrap();
        let mut first = pending(&client, "first");
        // JSON escapes double the stored size. A raw-body sum admits both.
        first.body = Some("\\".repeat(5 * 1024 * 1024));
        let mut second = first.clone();
        second.key = "second".into();
        client.retain_pending(first).unwrap();
        assert!(
            client
                .admit_pending(&second)
                .unwrap_err()
                .to_string()
                .contains("budget exceeded")
        );
        assert_eq!(row_count(client.pending_journal.as_ref().unwrap()), 1);
    }

    #[test]
    fn completed_requests_are_bounded_without_releasing_reserved_keys() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let writer = client().load_pending_journal(&root).unwrap();
        for index in 0..=MAX_PENDING {
            let row = pending(&writer, &format!("done-{index:03}"));
            writer.retain_pending(row.clone()).unwrap();
            writer.resolve_pending(&row.key).unwrap();
        }
        drop(writer);
        let reopened = client().load_pending_journal(&root).unwrap();
        let journal = reopened.pending_journal.as_ref().unwrap();
        let (state, bytes, retained) =
            journal
                .read(|tx| {
                    let record = tx.query_row(
                "SELECT state, length(payload) FROM pending_writes WHERE key = 'done-000'",
                [], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            ).map_err(journal_error)?;
                    let count = tx
                        .query_row(
                            "SELECT count(*) FROM pending_writes WHERE state = 'done'",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .map_err(journal_error)?;
                    Ok((record.0, record.1, count))
                })
                .unwrap();
        assert_eq!(
            (state.as_str(), bytes, retained),
            ("retired", 0, MAX_PENDING as i64)
        );
        let error = reopened
            .admit_pending(&pending(&reopened, "done-000"))
            .unwrap_err();
        assert_eq!(error.code(), Some("outcome_unknown"));
        assert_eq!(
            error.problem().unwrap().details["idempotency_key"],
            "done-000"
        );
        assert!(
            reopened
                .pending_for_send(&format!("done-{MAX_PENDING:03}"))
                .unwrap()
                .is_some()
        );
        assert!(reopened.try_pending_operations().unwrap().is_empty());
    }

    #[test]
    fn identical_replay_transition_cannot_restore_a_single_attempt_refusal() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let sender = client().load_pending_journal(&root).unwrap();
        let sibling = client().load_pending_journal(&root).unwrap();
        let mut refused = pending(&sender, "retry-same-snapshot");
        refused.pre_execution_rejected = true;
        sender.retain_pending(refused.clone()).unwrap();
        let mut retry = refused.clone();
        retry.pre_execution_rejected = false;
        assert!(sender.begin_pending_replay(&refused, &retry).unwrap());
        assert!(sibling.begin_pending_replay(&refused, &retry).unwrap());
        assert!(!sender.update_pending(&retry, refused).unwrap());
        assert_eq!(sibling.pending_operation(&retry.key), Some(retry));
    }

    #[test]
    fn survey_r6_short_sends_use_no_sidecars_and_an_open_sibling_sees_completion() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let sender = client().load_pending_journal(&root).unwrap();
        let sibling = client().load_pending_journal(&root).unwrap();
        for index in 0..3 {
            let row = pending(&sender, &format!("short-{index}"));
            assert!(sender.admit_pending(&row).unwrap().is_none());
            assert_eq!(sibling.pending_operation(&row.key), Some(row.clone()));
            let other = pending(&sibling, &format!("other-{index}"));
            assert!(sibling.admit_pending(&other).unwrap().is_none());
            sender.finish_pending(&row).unwrap();
            sibling.finish_pending(&other).unwrap();
            assert!(sibling.pending_operations().is_empty());
            assert_eq!(sibling.pending_for_send(&row.key).unwrap(), Some(row));
        }
        drop(sender);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        assert!(
            fs::read_dir(journal_directory(&sibling))
                .unwrap()
                .all(|entry| matches!(
                    entry.unwrap().file_name().to_str(),
                    Some("pending.db" | "pending.db-wal" | "pending.db-shm")
                ))
        );
        assert!(!journal_directory(&sibling).join(".repair-cursor").exists());
    }

    #[test]
    fn ly0019_legacy_long_poll_sidecars_migrate_under_sqlite_write_ownership() {
        for extension in ["inflight", "completed"] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let sender = client().load_pending_journal(&root).unwrap();
            let legacy = legacy_folder(&sender, &root);
            let row = pending(&sender, "poll");
            write_legacy(&legacy, &row, "json");
            let sidecar = journal_path(&legacy, &row.key).with_extension(extension);
            let bytes = if extension == "completed" {
                encode(&json!({
                    "key": row.key,
                    "digest": crate::credential_fingerprint(&serde_json::to_string(&row).unwrap()),
                }))
                .unwrap()
            } else {
                Vec::new()
            };
            lockyard_core::fsio::replace(&sidecar, &bytes, 0o600).unwrap();
            let owner =
                rusqlite::Connection::open(journal_directory(&sender).join(DATABASE)).unwrap();
            owner.execute_batch("BEGIN IMMEDIATE").unwrap();
            std::thread::scope(|scope| {
                let root = &root;
                let (send, result) = std::sync::mpsc::channel();
                scope.spawn(move || send.send(client().load_pending_journal(root)).unwrap());
                assert!(matches!(
                    result.recv_timeout(Duration::from_millis(100)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ));
                assert!(sidecar.exists());
                assert!(!legacy.with_extension("migrating").exists());
                assert!(sender.pending_operations().is_empty());
                drop(owner);
                result
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
            });
            assert!(!legacy.exists());
            assert_eq!(
                fs::read(
                    legacy
                        .with_extension("migrated")
                        .join(sidecar.file_name().unwrap())
                )
                .unwrap(),
                bytes
            );
            assert_eq!(
                sender.pending_operation(&row.key).is_some(),
                extension == "inflight"
            );
            assert_eq!(sender.pending_for_send(&row.key).unwrap(), Some(row));
        }
    }

    fn journal_directory(client: &Client) -> &Path {
        &client.pending_journal.as_ref().unwrap().directory
    }

    #[test]
    fn task_receipt_ack_waits_for_journal_owner_without_resending() {
        use crate::Transport;
        use std::sync::mpsc;

        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let client = client().load_pending_journal(&root).unwrap();
        let journal = client.pending_journal.as_ref().unwrap();
        let mut call = Call::write(
            "fixture",
            "POST",
            "/api/v1/registry/items".into(),
            json!({"title":"same"}),
        );
        call.deadline_ms = Some(2_000);
        let mut record = pending(&client, call.key.as_deref().unwrap());
        record.path = call.path.clone();
        record.request_path = call.path.clone();
        record.request_digest = Some(crate::request_identity(&call));
        client.retain_pending(record.clone()).unwrap();

        let owner = rusqlite::Connection::open(journal.directory.join(DATABASE)).unwrap();
        owner.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut short = call.clone();
        short.deadline_ms = Some(50);
        let started = Instant::now();
        assert!(matches!(
            client.acknowledge_write(&short),
            Err(ClientError::JournalBusy)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(client.pending_operation(&record.key), Some(record.clone()));
        let timeout: u32 = journal
            .db
            .lock()
            .unwrap()
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5_000);
        std::thread::scope(|scope| {
            let (send, done) = mpsc::channel();
            let client = &client;
            scope.spawn(move || send.send(client.acknowledge_write(&call)).unwrap());
            assert!(matches!(
                done.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            drop(owner);
            done.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
        });
        assert!(client.pending_operations().is_empty());
        let restored = self::client().load_pending_journal(root).unwrap();
        assert!(restored.pending_operations().is_empty());
        assert_eq!(
            restored.pending_for_send(&record.key).unwrap(),
            Some(record)
        );
    }

    #[test]
    fn bad_completion_markers_preserve_pending_and_do_not_block_other_keys_or_clients() {
        for fault in [
            "json",
            "key",
            "path",
            "digest",
            "mismatch",
            "changed_record",
        ] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let setup = client();
            let legacy = legacy_folder(&setup, &root);
            let mut bad = pending(&setup, "bad");
            let good = pending(&setup, "good");
            let mut marker = json!({
                "key": bad.key,
                "digest": crate::credential_fingerprint(&serde_json::to_string(&bad).unwrap()),
            });
            let mut marker_path = journal_path(&legacy, &bad.key).with_extension("completed");
            match fault {
                "json" => {}
                "key" => marker["key"] = Value::Null,
                "path" => marker_path = journal_path(&legacy, "wrong").with_extension("completed"),
                "digest" => marker["digest"] = json!("wrong-digest"),
                "mismatch" => marker["digest"] = json!("a".repeat(64)),
                "changed_record" => bad.body = Some("{\"new\":true}".into()),
                _ => unreachable!(),
            }
            let bytes = if fault == "json" {
                b"broken-json".to_vec()
            } else {
                encode(&marker).unwrap()
            };
            write_legacy(&legacy, &bad, "json");
            write_legacy(&legacy, &good, "json");
            lockyard_core::fsio::replace(&marker_path, &bytes, 0o600).unwrap();
            lockyard_core::fsio::replace(
                &journal_path(&legacy, &good.key).with_extension("completed"),
                &encode(&json!({
                    "key": good.key,
                    "digest": crate::credential_fingerprint(&serde_json::to_string(&good).unwrap()),
                }))
                .unwrap(),
                0o600,
            )
            .unwrap();

            for attempt in 0..2 {
                let restored = client().load_pending_journal(&root).unwrap();
                assert_eq!(
                    restored.pending_operations(),
                    std::slice::from_ref(&bad),
                    "{fault}"
                );
                assert_eq!(
                    restored.pending_for_send(&good.key).unwrap(),
                    Some(good.clone())
                );
                assert_eq!(
                    fs::read(
                        legacy
                            .with_extension("migrated")
                            .join(marker_path.file_name().unwrap())
                    )
                    .unwrap(),
                    bytes
                );
                assert!(!legacy.exists());
                let other = pending(&restored, &format!("unrelated-{attempt}"));
                assert!(restored.admit_pending(&other).unwrap().is_none());
                restored.resolve_pending(&other.key).unwrap();
            }
        }
    }

    #[test]
    fn a_verified_ack_can_complete_an_archived_operation() {
        use crate::Transport;

        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let writer = client().load_pending_journal(&root).unwrap();
        let mut call = Call::write(
            "fixture",
            "POST",
            "/api/v1/registry/tokens".into(),
            json!({}),
        );
        call.key = Some("archived-before-ack".into());
        let mut row = pending(&writer, call.key.as_deref().unwrap());
        row.path = call.path.clone();
        row.request_path = call.path.clone();
        row.request_digest = Some(crate::request_identity(&call));
        writer.retain_pending(row.clone()).unwrap();
        assert_eq!(client().forget_unknown_journal(&root, &row.key).unwrap(), 1);
        assert!(writer.pending_for_send(&row.key).is_err());
        let other = Client::new("http://127.0.0.1:1", "another-fixture".into())
            .unwrap()
            .load_pending_journal(&root)
            .unwrap();
        let mut other_row = row.clone();
        other_row.credential_scope = crate::credential_fingerprint(&other.token);
        other.retain_pending(other_row.clone()).unwrap();
        let mut changed = call.clone();
        changed.session = "different-session".into();
        assert_eq!(
            writer.acknowledge_write(&changed).unwrap_err().code(),
            Some("idempotency_conflict")
        );
        assert!(writer.pending_for_send(&row.key).is_err());
        writer.acknowledge_write(&call).unwrap();
        assert_eq!(writer.pending_for_send(&row.key).unwrap(), Some(row));
        assert_eq!(other.pending_operations(), [other_row]);
    }

    #[test]
    fn a_verified_response_cannot_complete_a_replacement_of_its_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let writer = client().load_pending_journal(&root).unwrap();
        let journal = writer.pending_journal.as_ref().unwrap();
        let previous = pending(&writer, "same-key");
        writer.retain_pending(previous.clone()).unwrap();
        assert!(journal.discard_unshared(&previous).unwrap());
        let mut replacement = previous.clone();
        replacement.body = Some("other frozen bytes".into());
        writer.retain_pending(replacement.clone()).unwrap();
        assert_eq!(
            writer.finish_pending(&previous).unwrap_err().code(),
            Some("outcome_unknown")
        );
        assert_eq!(writer.pending_operations(), [replacement]);
    }

    #[test]
    fn completed_payload_byte_limit_applies_before_the_row_limit() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let writer = client().load_pending_journal(&root).unwrap();
        let mut first = pending(&writer, "first-large");
        first.body = Some("x".repeat(9 * 1024 * 1024));
        let mut second = first.clone();
        second.key = "second-large".into();
        for row in [&first, &second] {
            writer.retain_pending(row.clone()).unwrap();
            writer.resolve_pending(&row.key).unwrap();
        }
        assert_eq!(
            writer.pending_for_send(&first.key).unwrap_err().code(),
            Some("outcome_unknown")
        );
        assert_eq!(writer.pending_for_send(&second.key).unwrap(), Some(second));
    }

    #[test]
    fn repeating_admission_keeps_the_first_wire_bytes_before_and_after_completion() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let first = client().load_pending_journal(&root).unwrap();
        let sibling = client().load_pending_journal(root).unwrap();
        let original = pending(&first, "one-key");
        let mut second = original.clone();
        second.body = Some("different randomized ciphertext".into());
        assert_eq!(first.admit_pending(&original).unwrap(), None);
        assert_eq!(
            sibling.admit_pending(&second).unwrap(),
            Some(original.clone())
        );
        first.resolve_pending(&original.key).unwrap();
        assert_eq!(sibling.admit_pending(&second).unwrap(), Some(original));
        assert!(sibling.pending_operations().is_empty());
        assert_eq!(row_count(sibling.pending_journal.as_ref().unwrap()), 1);
    }
}
