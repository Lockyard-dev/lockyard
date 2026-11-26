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

use crate::{DIR_NAME, Result, Store, fsio, paths::nfc_path};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

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
        path: nfc_path(path),
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
        .map(|mut entry| {
            entry.path = nfc_path(&entry.path);
            entry
        })
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

/// True when a hook announced a canonically equivalent path within the window before `at`.
pub fn was_announced(announced: &[Announcement], path: &str, at: i64) -> bool {
    let path = nfc_path(path);
    let window = at.saturating_sub(ANNOUNCE_WINDOW_MS)..=at;
    announced.iter().any(|entry| {
        window.contains(&entry.at)
            && (entry.path == path || (!entry.path.is_ascii() && entry.path.nfc().eq(path.chars())))
    })
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
        let path = nfc_path(path);
        let transaction = self.write()?;
        // Old writers could store multiple Unicode spellings for a holder. Repair those
        // rows on write, keeping the oldest ID and the latest notification timestamp.
        let mut matches = {
            let mut statement = transaction.prepare(
                "SELECT id, path, holder, claim_id, first_at, last_at, hits, told_at
                 FROM unannounced_writes WHERE holder = ?1
                 AND (path = ?2 OR length(path) != length(CAST(path AS BLOB))) ORDER BY id",
            )?;
            let mut matches = Vec::new();
            for row in statement.query_map(params![holder, path], row_to_unannounced)? {
                let row = row?;
                if row.path == path || row.path.nfc().eq(path.chars()) {
                    matches.push(row);
                }
            }
            matches.into_iter()
        };
        let record = if let Some(mut previous) = matches.next() {
            for duplicate in matches {
                transaction.execute(
                    "DELETE FROM unannounced_writes WHERE id = ?1",
                    [duplicate.id],
                )?;
                previous.first_at = previous.first_at.min(duplicate.first_at);
                previous.hits = previous.hits.saturating_add(duplicate.hits);
                previous.told_at = previous.told_at.max(duplicate.told_at);
            }
            transaction.query_row(
                "UPDATE unannounced_writes SET path = ?2, claim_id = ?3, first_at = ?4,
                     last_at = ?5, hits = ?6, told_at = ?7 WHERE id = ?1
                 RETURNING id, path, holder, claim_id, first_at, last_at, hits, told_at",
                params![
                    previous.id,
                    path,
                    claim,
                    previous.first_at,
                    now,
                    previous.hits.saturating_add(1),
                    previous.told_at
                ],
                row_to_unannounced,
            )?
        } else {
            transaction.query_row(
                "INSERT INTO unannounced_writes (path, holder, claim_id, first_at, last_at, hits)
                 VALUES (?1, ?2, ?3, ?4, ?4, 1)
                 RETURNING id, path, holder, claim_id, first_at, last_at, hits, told_at",
                params![path, holder, claim, now],
                row_to_unannounced,
            )?
        };
        transaction.commit()?;
        Ok(record)
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
        assert!(!was_announced(&seen, "src/a.rs", 999));
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
    fn journal_paths_use_nfc_on_write_and_when_reading_legacy_entries() {
        let (dir, mut store) = test_store();
        let nfc = "src/café.rs";
        let nfd = "src/cafe\u{301}.rs";
        announce(dir.path(), "alice", nfd, 1).unwrap();
        let path = journal(dir.path());
        let on_disk: Announcement =
            serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
        assert_eq!(on_disk.path, nfc);

        let legacy = Announcement {
            path: nfd.into(),
            ..on_disk
        };
        assert!(was_announced(std::slice::from_ref(&legacy), nfc, 1));
        fs::write(path, serde_json::to_string(&legacy).unwrap()).unwrap();
        let seen = announcements(dir.path(), 0).unwrap();
        assert!(was_announced(&seen, nfc, 1));
        assert!(was_announced(&seen, nfd, 1));
        assert!(!was_announced(&seen, "src/CAFÉ.rs", 1));

        let first = store.record_unannounced(nfd, "alice", 1, 1).unwrap();
        let second = store.record_unannounced(nfc, "alice", 1, 2).unwrap();
        assert_eq!(first.path, nfc);
        assert_eq!(second.id, first.id);
        assert_eq!(second.hits, 2);
    }

    #[test]
    fn a_legacy_nfd_write_keeps_its_id_and_notification_history() {
        let (_dir, mut store) = test_store();
        let nfd = "src/cafe\u{301}.rs";
        let nfc = "src/café.rs";
        store.conn.execute(
            "INSERT INTO unannounced_writes (path, holder, claim_id, first_at, last_at, hits, told_at)
             VALUES (?1, 'alice', 7, 100, 200, 3, 200)",
            [nfd],
        ).unwrap();
        let legacy_id = store.conn.last_insert_rowid();

        let record = store.record_unannounced(nfc, "alice", 8, 300).unwrap();
        assert_eq!(
            record.id, legacy_id,
            "the legacy row owns the canonical path"
        );
        assert_eq!(record.path, nfc);
        assert_eq!(record.claim, 8);
        assert_eq!(
            (record.first_at, record.last_at, record.hits),
            (100, 300, 4)
        );
        assert_eq!(record.told_at, Some(200));
        assert!(!store.should_tell(record.id, 300).unwrap());
        assert_eq!(store.unannounced(0).unwrap().len(), 1);
    }

    #[test]
    fn an_existing_nfc_duplicate_merges_into_the_oldest_record() {
        let (_dir, mut store) = test_store();
        store.conn.execute(
            "INSERT INTO unannounced_writes (path, holder, claim_id, first_at, last_at, hits, told_at)
             VALUES ('src/K', 'alice', 7, 200, 300, 3, 300), ('src/K', 'alice', 8, 100, 400, 2, 400)",
            [],
        ).unwrap();
        let other_holder = store.record_unannounced("src/K", "bob", 9, 500).unwrap();
        let other_case = store.record_unannounced("src/k", "alice", 10, 500).unwrap();
        let record = store.record_unannounced("src/K", "alice", 11, 500).unwrap();
        assert_eq!(
            (record.id, record.path.as_str(), record.hits),
            (1, "src/K", 6)
        );
        assert_eq!((record.first_at, record.told_at), (100, Some(400)));
        assert_eq!(
            store.unannounced(0).unwrap(),
            [other_case, other_holder, record]
        );
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
