// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Writes that did not come through a hook.
//!
//! The hook can refuse an agent's edit tool. It cannot refuse `sed -i`, a build script or a person
//! with an editor, because nothing asks it first. What Lockyard can do is **notice**: every hook that
//! lets an edit through announces the path, a monitor watches the same paths for real changes, and a
//! change to a claimed path with no announcement behind it is reported to the holder.
//!
//! This is detection, not prevention, and the README says so. A write still happens; the holder finds
//! out that it did.
//!
//! The announcement journal is a plain append-only file rather than a table, because a hook appends to
//! it on the path whose latency budget is measured in milliseconds, and an append of one short line
//! costs a system call where opening the database costs a connection.

use crate::{DIR_NAME, Result, Store, fsio};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const JOURNAL: &str = "announced-writes.jsonl";
const JOURNAL_MODE: u32 = 0o600;

/// How long an announcement covers its path.
///
/// A hook runs before the edit, and the edit can wait for a person to approve the tool call, so this
/// has to be generous. The cost of being generous is the other way round: a real outside write to a
/// path some agent legitimately touched in the last few minutes is not reported.
pub const ANNOUNCE_WINDOW_MS: i64 = 5 * 60_000;

/// The holder is told about one path at most this often, however many times it is written.
pub const TELL_EVERY_MS: i64 = 15 * 60_000;

/// The journal is rewritten when it passes this, so a long session cannot grow it without end.
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;

/// A hook let `agent` write `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    pub at: i64,
    pub agent: String,
    pub path: String,
}

/// A change to a claimed path that no hook announced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unannounced {
    pub id: i64,
    pub path: String,
    /// The agent whose claim covers the path.
    pub holder: String,
    pub claim: i64,
    pub first_at: i64,
    pub last_at: i64,
    /// How many times the path changed without an announcement.
    pub hits: i64,
    /// When the holder was last told, if ever.
    pub told_at: Option<i64>,
}

fn journal(root: &Path) -> PathBuf {
    root.join(DIR_NAME).join(JOURNAL)
}

/// Records that a hook is about to let `agent` write `path`. Cheap enough for the hook path.
pub fn announce(root: &Path, agent: &str, path: &str, now: i64) -> Result<()> {
    let line = serde_json::to_string(&Announcement {
        at: now,
        agent: agent.to_string(),
        path: path.to_string(),
    })
    .map_err(|error| crate::Error::Invalid(error.to_string()))?;
    Ok(fsio::append_line(&journal(root), &line, JOURNAL_MODE)?)
}

/// Every announcement at or after `since`. A damaged line is skipped, never fatal.
pub fn announcements(root: &Path, since: i64) -> Result<Vec<Announcement>> {
    let text = match fs::read_to_string(journal(root)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str::<Announcement>(line).ok())
        .filter(|entry| entry.at >= since)
        .collect())
}

/// Drops announcements older than `keep_since`, if the journal has grown enough to matter.
pub fn compact(root: &Path, keep_since: i64) -> Result<()> {
    let path = journal(root);
    let size = match fs::metadata(&path) {
        Ok(data) => data.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if size < MAX_JOURNAL_BYTES {
        return Ok(());
    }
    let kept = announcements(root, keep_since)?;
    let mut text = String::new();
    for entry in kept {
        if let Ok(line) = serde_json::to_string(&entry) {
            text.push_str(&line);
            text.push('\n');
        }
    }
    Ok(fsio::replace(&path, text.as_bytes(), JOURNAL_MODE)?)
}

/// True when some hook announced a write to `path` inside the window ending at `now`.
pub fn was_announced(announced: &[Announcement], path: &str, now: i64) -> bool {
    announced
        .iter()
        .any(|entry| entry.path == path && now.saturating_sub(entry.at) <= ANNOUNCE_WINDOW_MS)
}

impl Store {
    /// Records one unannounced write, merging it with an earlier one for the same path and holder.
    pub fn record_unannounced(
        &mut self,
        path: &str,
        holder: &str,
        claim: i64,
        now: i64,
    ) -> Result<Unannounced> {
        let transaction = self.write()?;
        transaction.execute(
            "INSERT INTO unannounced_writes (path, holder, claim_id, first_at, last_at, hits)
             VALUES (?1, ?2, ?3, ?4, ?4, 1)
             ON CONFLICT(path, holder) DO UPDATE SET
                 last_at = excluded.last_at,
                 claim_id = excluded.claim_id,
                 hits = unannounced_writes.hits + 1",
            params![path, holder, claim, now],
        )?;
        transaction.commit()?;
        self.unannounced_for(path, holder)
    }

    fn unannounced_for(&self, path: &str, holder: &str) -> Result<Unannounced> {
        Ok(self.conn.query_row(
            "SELECT id, path, holder, claim_id, first_at, last_at, hits, told_at
             FROM unannounced_writes WHERE path = ?1 AND holder = ?2",
            params![path, holder],
            row_to_unannounced,
        )?)
    }

    /// Unannounced writes last seen at or after `since`, newest first.
    pub fn unannounced(&self, since: i64) -> Result<Vec<Unannounced>> {
        let mut statement = self.conn.prepare(
            "SELECT id, path, holder, claim_id, first_at, last_at, hits, told_at
             FROM unannounced_writes WHERE last_at >= ?1 ORDER BY last_at DESC, id DESC",
        )?;
        let rows = statement.query_map([since], row_to_unannounced)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// True when the holder has not been told about this record inside [`TELL_EVERY_MS`].
    pub fn should_tell(&self, id: i64, now: i64) -> Result<bool> {
        let told: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT told_at FROM unannounced_writes WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(match told.flatten() {
            Some(at) => now.saturating_sub(at) >= TELL_EVERY_MS,
            None => true,
        })
    }

    /// Marks that the holder has been told about this record.
    pub fn mark_told(&mut self, id: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE unannounced_writes SET told_at = ?2 WHERE id = ?1",
            params![id, now],
        )?;
        Ok(())
    }

    /// Removes records not seen since `before`.
    pub fn forget_unannounced(&mut self, before: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM unannounced_writes WHERE last_at < ?1",
            [before],
        )?)
    }
}

fn row_to_unannounced(row: &rusqlite::Row<'_>) -> rusqlite::Result<Unannounced> {
    Ok(Unannounced {
        id: row.get(0)?,
        path: row.get(1)?,
        holder: row.get(2)?,
        claim: row.get(3)?,
        first_at: row.get(4)?,
        last_at: row.get(5)?,
        hits: row.get(6)?,
        told_at: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;

    #[test]
    fn an_announcement_covers_its_path_for_the_window_and_no_longer() {
        let (dir, _store) = test_store();
        announce(dir.path(), "alice", "src/a.rs", 1_000).unwrap();
        let seen = announcements(dir.path(), 0).unwrap();
        assert_eq!(seen.len(), 1);
        assert!(was_announced(&seen, "src/a.rs", 1_000 + ANNOUNCE_WINDOW_MS));
        assert!(!was_announced(
            &seen,
            "src/a.rs",
            1_001 + ANNOUNCE_WINDOW_MS
        ));
        assert!(!was_announced(&seen, "src/b.rs", 1_000));
    }

    #[test]
    fn a_missing_or_damaged_journal_is_empty_rather_than_an_error() {
        let (dir, _store) = test_store();
        assert!(announcements(dir.path(), 0).unwrap().is_empty());
        announce(dir.path(), "alice", "src/a.rs", 1).unwrap();
        let path = journal(dir.path());
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("{not json\n");
        fs::write(&path, text).unwrap();
        assert_eq!(announcements(dir.path(), 0).unwrap().len(), 1);
    }

    #[test]
    fn a_since_filter_hides_older_entries() {
        let (dir, _store) = test_store();
        announce(dir.path(), "alice", "old.rs", 10).unwrap();
        announce(dir.path(), "alice", "new.rs", 20).unwrap();
        let seen = announcements(dir.path(), 20).unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "new.rs");
    }

    #[test]
    fn a_small_journal_is_left_alone_and_a_large_one_loses_its_old_entries() {
        let (dir, _store) = test_store();
        announce(dir.path(), "alice", "a.rs", 1).unwrap();
        compact(dir.path(), 1_000).unwrap();
        assert_eq!(announcements(dir.path(), 0).unwrap().len(), 1);
        let long = "x".repeat(200);
        for index in 0..6_000 {
            announce(dir.path(), "alice", &format!("{long}{index}.rs"), 1).unwrap();
        }
        announce(dir.path(), "alice", "fresh.rs", 5_000).unwrap();
        assert!(fs::metadata(journal(dir.path())).unwrap().len() > MAX_JOURNAL_BYTES);
        compact(dir.path(), 5_000).unwrap();
        let left = announcements(dir.path(), 0).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].path, "fresh.rs");
    }

    #[test]
    fn repeated_writes_to_one_path_merge_into_one_record() {
        let (_dir, mut store) = test_store();
        let first = store
            .record_unannounced("src/a.rs", "alice", 7, 100)
            .unwrap();
        assert_eq!((first.hits, first.first_at, first.last_at), (1, 100, 100));
        let again = store
            .record_unannounced("src/a.rs", "alice", 7, 200)
            .unwrap();
        assert_eq!(again.id, first.id);
        assert_eq!((again.hits, again.first_at, again.last_at), (2, 100, 200));
        assert_eq!(store.unannounced(0).unwrap().len(), 1);
    }

    #[test]
    fn the_holder_is_told_once_per_interval() {
        let (_dir, mut store) = test_store();
        let record = store
            .record_unannounced("src/a.rs", "alice", 7, 100)
            .unwrap();
        assert!(store.should_tell(record.id, 100).unwrap());
        store.mark_told(record.id, 100).unwrap();
        assert!(
            !store
                .should_tell(record.id, 100 + TELL_EVERY_MS - 1)
                .unwrap()
        );
        assert!(store.should_tell(record.id, 100 + TELL_EVERY_MS).unwrap());
    }

    #[test]
    fn old_records_are_forgotten_and_recent_ones_kept() {
        let (_dir, mut store) = test_store();
        store.record_unannounced("old.rs", "alice", 1, 100).unwrap();
        store.record_unannounced("new.rs", "alice", 1, 900).unwrap();
        assert_eq!(store.forget_unannounced(500).unwrap(), 1);
        let left = store.unannounced(0).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].path, "new.rs");
    }

    #[test]
    fn two_holders_of_one_path_are_two_records() {
        let (_dir, mut store) = test_store();
        store
            .record_unannounced("src/a.rs", "alice", 1, 100)
            .unwrap();
        store.record_unannounced("src/a.rs", "bob", 2, 100).unwrap();
        assert_eq!(store.unannounced(0).unwrap().len(), 2);
    }
}
