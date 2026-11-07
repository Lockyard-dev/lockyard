// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! The durable write queue of the agent process.
//!
//! An entry is on disk before anyone hears it was accepted, and one sender thread drains the queue from
//! the head, so writes reach the server in the order they arrived. A crash after a send but before the
//! cursor moves sends the entry again under its idempotency key, which the server answers with the
//! first result.

use lockyard_cloud_client::{Call, ClientError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

const QUEUE_FILE: &str = "outbox.jsonl";
const CURSOR_FILE: &str = "outbox.cursor";
const REJECTED_FILE: &str = "outbox.rejected";
const DONE_FILE: &str = "outbox.done";
/// An outage this long must not fill the disk. Past it, a write fails for its caller to see.
const MAX_QUEUE_BYTES: u64 = 64 * 1024 * 1024;

pub type Outcome = Result<Value, ClientError>;

/// One queued write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub n: u64,
    pub call: Call,
}

struct Queue {
    file: File,
    bytes: u64,
    pending: VecDeque<Entry>,
    next: u64,
    waiters: HashMap<u64, Sender<Outcome>>,
    deferred: HashMap<u64, std::time::Instant>,
}

pub struct Outbox {
    dir: PathBuf,
    queue: Mutex<Queue>,
    ready: Condvar,
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

impl Outbox {
    /// Opens the queue in `dir` and restores what an earlier process left.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let mut file = private_options()
            .create(true)
            .read(true)
            .append(true)
            .open(dir.join(QUEUE_FILE))?;
        // sync_data on an appended entry cannot preserve a newly created directory entry.
        sync_directory(dir)?;
        let cursor = read_cursor(dir);
        let completed = read_completed(dir)?;
        let mut text = Vec::new();
        file.read_to_end(&mut text)?;
        let mut pending = VecDeque::new();
        // Older versions could truncate the queue before persisting the cursor. Completion
        // markers left by that interruption must never be reused for newly accepted writes.
        let mut last = completed.iter().copied().max().unwrap_or(0).max(cursor);
        let mut intact = 0_usize;
        for line in text.split_inclusive(|byte| *byte == b'\n') {
            // A crash can leave a torn last line. Nobody was told that write was accepted.
            let parsed = line
                .ends_with(b"\n")
                .then(|| serde_json::from_slice::<Entry>(line).ok())
                .flatten();
            let Some(entry) = parsed else { break };
            intact += line.len();
            last = last.max(entry.n);
            if entry.n > cursor && !completed.contains(&entry.n) {
                pending.push_back(entry);
            }
        }
        if intact != text.len() {
            file.set_len(intact as u64)?;
            file.sync_data()?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            queue: Mutex::new(Queue {
                file,
                bytes: intact as u64,
                pending,
                next: last + 1,
                waiters: HashMap::new(),
                deferred: HashMap::new(),
            }),
            ready: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues `call` durably. Returning means it will be sent, even after a crash.
    pub fn append(&self, call: Call) -> io::Result<u64> {
        let mut queue = self.lock();
        let n = store(&mut queue, call)?;
        self.ready.notify_all();
        Ok(n)
    }

    /// Queues `call` and also gives the caller a channel for its outcome.
    pub fn append_waiting(&self, call: Call) -> io::Result<(u64, Receiver<Outcome>)> {
        let (sender, receiver) = channel();
        let mut queue = self.lock();
        let n = store(&mut queue, call)?;
        queue.waiters.insert(n, sender);
        self.ready.notify_all();
        Ok((n, receiver))
    }

    /// The oldest eligible entry, left in place until [`Outbox::finish`]. Entries stay ordered
    /// within one session while a rate limited session backs off.
    pub fn head(&self, timeout: Duration) -> Option<Entry> {
        let until = std::time::Instant::now() + timeout;
        let mut queue = self.lock();
        loop {
            let now = std::time::Instant::now();
            let mut blocked = std::collections::HashSet::new();
            for entry in &queue.pending {
                let key = pair_key(entry);
                let ready_at = queue.deferred.get(&entry.n).copied();
                if !blocked.contains(&key) && ready_at.is_none_or(|at| at <= now) {
                    return Some(entry.clone());
                }
                blocked.insert(key);
            }
            let next = queue
                .deferred
                .values()
                .copied()
                .min()
                .unwrap_or(until)
                .min(until);
            let wait = next.saturating_duration_since(now);
            if wait.is_zero() {
                return None;
            }
            let (guard, _) = self
                .ready
                .wait_timeout(queue, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queue = guard;
            if std::time::Instant::now() >= until && queue.pending.is_empty() {
                return None;
            }
        }
    }

    pub fn defer(&self, n: u64, duration: Duration) {
        let mut queue = self.lock();
        queue
            .deferred
            .insert(n, std::time::Instant::now() + duration);
        self.ready.notify_all();
    }

    /// Tell a waiting caller the outcome is unknown without recording a final receipt.
    /// Its original call stays durable and remains the only operation eligible for replay.
    pub fn report_unknown(&self, n: u64, error: ClientError) {
        debug_assert!(matches!(error, ClientError::OutcomeUnknown(_)));
        if let Some(waiter) = self.lock().waiters.remove(&n) {
            let _ = waiter.send(Err(error));
        }
    }

    /// Removes the head after a final answer and tells whoever waits for it.
    pub fn finish(&self, n: u64, outcome: Outcome) -> io::Result<()> {
        let mut queue = self.lock();
        let Some(index) = queue.pending.iter().position(|entry| entry.n == n) else {
            return Ok(());
        };
        let mut done = private_options()
            .create(true)
            .append(true)
            .open(self.dir.join(DONE_FILE))?;
        let before = done.metadata()?.len();
        if let Err(error) = writeln!(done, "{n}")
            .and_then(|()| done.sync_data())
            .and_then(|()| sync_directory(&self.dir))
        {
            // A failed partial line must not fuse with the next completion number. Keep the
            // entry and its waiter until its completion has actually reached durable storage.
            if done.set_len(before).is_ok() {
                let _ = done.sync_data();
            }
            return Err(error);
        }
        let entry = queue.pending.remove(index).expect("entry index exists");
        queue.deferred.remove(&n);
        let waiter = queue.waiters.remove(&n);
        let truncated = if queue.pending.is_empty() {
            compact(&self.dir, &mut queue)
        } else {
            Ok(())
        };
        // A caller that stopped waiting cannot hear the outcome, so it goes to the log instead.
        let unheard = match waiter {
            Some(waiter) => waiter.send(outcome).err().map(|failed| failed.0),
            None => Some(outcome),
        };
        if let Some(outcome) = unheard {
            log_rejection(&self.dir, &entry, &outcome);
        }
        truncated
    }

    /// How many entries wait.
    pub fn len(&self) -> usize {
        self.lock().pending.len()
    }

    pub fn rejected(&self) -> usize {
        fs::read_to_string(self.dir.join(REJECTED_FILE))
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }
}

fn store(queue: &mut Queue, call: Call) -> io::Result<u64> {
    let entry = Entry {
        n: queue.next,
        call,
    };
    let mut line = serde_json::to_vec(&entry).map_err(io::Error::other)?;
    line.push(b'\n');
    let size = line.len() as u64;
    if queue.bytes + size > MAX_QUEUE_BYTES {
        return Err(io::Error::other("the outbox is full"));
    }
    let written = queue
        .file
        .write_all(&line)
        .and_then(|()| queue.file.sync_data());
    if let Err(error) = written {
        // Undo a partial line, or the next entry would fuse with it.
        let _ = queue.file.set_len(queue.bytes);
        return Err(error);
    }
    queue.bytes += size;
    queue.next += 1;
    queue.pending.push_back(entry);
    Ok(queue.next - 1)
}

fn read_cursor(dir: &Path) -> u64 {
    fs::read_to_string(dir.join(CURSOR_FILE))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

fn read_completed(dir: &Path) -> io::Result<HashSet<u64>> {
    let mut file = match private_options()
        .read(true)
        .write(true)
        .open(dir.join(DONE_FILE))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let mut completed = HashSet::new();
    let mut intact = 0;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let parsed = line
            .ends_with(b"\n")
            .then(|| {
                std::str::from_utf8(&line[..line.len() - 1])
                    .ok()?
                    .parse()
                    .ok()
            })
            .flatten();
        let Some(n) = parsed else { break };
        completed.insert(n);
        intact += line.len();
    }
    if intact != bytes.len() {
        // A crash during marker append can leave a fragment. Discard it before another
        // number is appended, or the two numbers could become an unrelated completed ID.
        file.set_len(intact as u64)?;
        file.sync_data()?;
    }
    Ok(completed)
}

fn save_cursor(dir: &Path, through: u64) -> io::Result<()> {
    let temporary = dir.join(format!(
        ".outbox.cursor-{}.tmp",
        lockyard_cloud_client::ulid()
    ));
    let saved = (|| {
        let mut file = private_options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        write!(file, "{through}")?;
        file.sync_all()?;
        fs::rename(&temporary, dir.join(CURSOR_FILE))?;
        sync_directory(dir)
    })();
    if saved.is_err() {
        let _ = fs::remove_file(temporary);
    }
    saved
}

fn compact(dir: &Path, queue: &mut Queue) -> io::Result<()> {
    // Commit the high-water mark before destroying either source of completion IDs.
    // Every interrupted stage then leaves a cursor, log, or marker that prevents reuse.
    save_cursor(dir, queue.next - 1)?;
    queue.file.set_len(0)?;
    queue.bytes = 0;
    queue.file.sync_data()?;
    fs::remove_file(dir.join(DONE_FILE))?;
    sync_directory(dir)
}

/// Keeps a write the server refused for good, because no caller is left to hear about it.
fn log_rejection(dir: &Path, entry: &Entry, outcome: &Outcome) {
    let Err(error) = outcome else { return };
    eprintln!(
        "lockyard agent: the server refused queued write {}: {error}",
        entry.n
    );
    let record = serde_json::json!({"n": entry.n, "call": entry.call, "error": error.to_string()});
    let file = private_options()
        .create(true)
        .append(true)
        .open(dir.join(REJECTED_FILE));
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{record}");
    }
}

fn pair_key(entry: &Entry) -> String {
    entry.call.session.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mail(text: &str) -> Call {
        Call::write(
            "s",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"body": text}),
        )
    }

    fn body(entry: &Entry) -> String {
        entry.call.body.as_ref().unwrap()["body"]
            .as_str()
            .unwrap()
            .to_string()
    }

    const NOW: Duration = Duration::from_millis(1);

    #[test]
    fn entries_survive_a_restart_in_order_with_their_keys() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let first = mail("one");
        let key = first.key.clone();
        outbox.append(first).unwrap();
        outbox.append(mail("two")).unwrap();
        drop(outbox);
        let again = Outbox::open(dir.path()).unwrap();
        assert_eq!(again.len(), 2);
        let head = again.head(NOW).unwrap();
        assert_eq!((body(&head).as_str(), head.call.key), ("one", key));
        again.finish(head.n, Ok(Value::Null)).unwrap();
        assert_eq!(body(&again.head(NOW).unwrap()), "two");
    }

    #[test]
    fn a_finished_entry_is_not_sent_again_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let first = outbox.append(mail("one")).unwrap();
        outbox.append(mail("two")).unwrap();
        outbox.finish(first, Ok(Value::Null)).unwrap();
        drop(outbox);
        let again = Outbox::open(dir.path()).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(body(&again.head(NOW).unwrap()), "two");
    }

    #[test]
    fn a_torn_last_line_is_cut_and_the_next_entry_stays_readable() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        outbox.append(mail("one")).unwrap();
        drop(outbox);
        let path = dir.path().join(QUEUE_FILE);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"n\":2,\"cal").unwrap();
        drop(file);
        let again = Outbox::open(dir.path()).unwrap();
        assert_eq!(again.len(), 1);
        again.append(mail("two")).unwrap();
        drop(again);
        let last = Outbox::open(dir.path()).unwrap();
        assert_eq!(last.len(), 2);
    }

    #[test]
    fn numbers_keep_rising_after_the_queue_empties() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let first = outbox.append(mail("one")).unwrap();
        outbox.finish(first, Ok(Value::Null)).unwrap();
        assert_eq!(fs::metadata(dir.path().join(QUEUE_FILE)).unwrap().len(), 0);
        drop(outbox);
        let again = Outbox::open(dir.path()).unwrap();
        let next = again.append(mail("two")).unwrap();
        assert!(next > first);
        drop(again);
        assert_eq!(
            Outbox::open(dir.path()).unwrap().len(),
            1,
            "the cursor must not hide a new entry"
        );
    }

    #[test]
    fn the_waiter_hears_the_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let (n, outcome) = outbox.append_waiting(mail("one")).unwrap();
        outbox.finish(n, Ok(json!({"id": 1}))).unwrap();
        assert_eq!(outcome.recv().unwrap().unwrap()["id"], 1);
    }

    #[test]
    fn a_refusal_nobody_waits_for_keeps_the_call_and_body() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let n = outbox.append(mail("one")).unwrap();
        outbox
            .finish(n, Err(ClientError::Invalid("no".into())))
            .unwrap();
        let kept = fs::read_to_string(dir.path().join(REJECTED_FILE)).unwrap();
        assert!(kept.contains("no"));
        assert!(kept.contains("\"call\""));
        assert!(kept.contains("one"));
        assert_eq!(outbox.rejected(), 1);
    }

    #[test]
    fn a_deferred_session_does_not_block_another_session() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let first = outbox.append(mail("one")).unwrap();
        let mut other = mail("two");
        other.session = "other".into();
        outbox.append(other).unwrap();
        outbox.defer(first, Duration::from_secs(10));
        assert_eq!(body(&outbox.head(NOW).unwrap()), "two");
    }

    #[test]
    fn a_later_completion_does_not_hide_earlier_work_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let first = outbox.append(mail("one")).unwrap();
        let second = outbox.append(mail("two")).unwrap();
        outbox.finish(second, Ok(Value::Null)).unwrap();
        drop(outbox);
        let reopened = Outbox::open(dir.path()).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.head(NOW).unwrap().n, first);
    }

    #[test]
    fn accepted_writes_survive_every_interrupted_compaction_stage() {
        // These are files left between the production finish steps, including the old
        // truncate-before-cursor order. No synthetic transport or I/O interception is used.
        for previous in [0, 9] {
            for stage in [
                "before_marker",
                "after_marker",
                "before_cursor_rename",
                "after_cursor",
                "after_truncate",
                "after_marker_removal",
                "legacy_after_truncate",
            ] {
                let dir = tempfile::tempdir().unwrap();
                let completed = previous + 1;
                let cursor_advanced = matches!(
                    stage,
                    "after_cursor" | "after_truncate" | "after_marker_removal"
                );
                fs::write(
                    dir.path().join(CURSOR_FILE),
                    if cursor_advanced { completed } else { previous }.to_string(),
                )
                .unwrap();
                let old = Entry {
                    n: completed,
                    call: mail("old"),
                };
                let old_line = format!("{}\n", serde_json::to_string(&old).unwrap());
                let truncated = matches!(
                    stage,
                    "after_truncate" | "after_marker_removal" | "legacy_after_truncate"
                );
                fs::write(
                    dir.path().join(QUEUE_FILE),
                    if truncated { "" } else { &old_line },
                )
                .unwrap();
                if !matches!(stage, "before_marker" | "after_marker_removal") {
                    fs::write(dir.path().join(DONE_FILE), format!("{completed}\n")).unwrap();
                }
                if stage == "before_cursor_rename" {
                    fs::write(
                        dir.path().join(".outbox.cursor-interrupted.tmp"),
                        completed.to_string(),
                    )
                    .unwrap();
                }
                let outbox = Outbox::open(dir.path()).unwrap();
                let call = mail("accepted after restart");
                let key = call.key.clone();
                let n = outbox.append(call).unwrap();
                assert!(n > completed, "reused completion ID: {previous}/{stage}");
                drop(outbox);
                let again = Outbox::open(dir.path()).unwrap();
                let pending = &again.lock().pending;
                assert_eq!(
                    pending.len(),
                    if stage == "before_marker" { 2 } else { 1 },
                    "{previous}/{stage}"
                );
                assert!(
                    pending
                        .iter()
                        .any(|entry| entry.n == n && entry.call.key == key),
                    "accepted write disappeared: {previous}/{stage}"
                );
            }
        }
    }

    #[test]
    fn a_legacy_compaction_without_a_cursor_does_not_reuse_its_completed_number() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(QUEUE_FILE), "").unwrap();
        fs::write(dir.path().join(DONE_FILE), "1\n").unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let n = outbox.append(mail("new")).unwrap();
        assert_eq!(n, 2);
        drop(outbox);
        let again = Outbox::open(dir.path()).unwrap();
        assert_eq!(again.head(NOW).unwrap().n, n);
    }

    #[test]
    fn an_empty_queue_without_completion_markers_retains_new_writes() {
        for cursor in [0, 9] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join(CURSOR_FILE), cursor.to_string()).unwrap();
            let outbox = Outbox::open(dir.path()).unwrap();
            let n = outbox.append(mail("new")).unwrap();
            assert_eq!(n, cursor + 1);
            drop(outbox);
            assert_eq!(Outbox::open(dir.path()).unwrap().head(NOW).unwrap().n, n);
        }
    }

    #[test]
    fn a_failed_completion_marker_preserves_the_entry_and_its_waiter() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let (n, waiter) = outbox.append_waiting(mail("one")).unwrap();
        outbox.defer(n, Duration::from_secs(1));
        fs::create_dir(dir.path().join(DONE_FILE)).unwrap();
        assert!(outbox.finish(n, Ok(json!({"id": 7}))).is_err());
        assert_eq!(outbox.len(), 1);
        assert!(outbox.lock().deferred.contains_key(&n));
        assert!(matches!(
            waiter.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        fs::remove_dir(dir.path().join(DONE_FILE)).unwrap();
        outbox.finish(n, Ok(json!({"id": 7}))).unwrap();
        assert_eq!(waiter.recv().unwrap().unwrap()["id"], 7);
        drop(outbox);
        assert_eq!(Outbox::open(dir.path()).unwrap().len(), 0);
    }

    #[test]
    fn compaction_failure_preserves_the_log_and_acknowledges_durable_completion() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let (n, waiter) = outbox.append_waiting(mail("one")).unwrap();
        // An ordinary filesystem error prevents atomic cursor replacement.
        fs::create_dir(dir.path().join(CURSOR_FILE)).unwrap();
        assert!(outbox.finish(n, Ok(json!({"id": 7}))).is_err());
        assert_eq!(waiter.recv().unwrap().unwrap()["id"], 7);
        assert_eq!(outbox.len(), 0);
        assert!(fs::metadata(dir.path().join(QUEUE_FILE)).unwrap().len() > 0);
        assert_eq!(
            fs::read_to_string(dir.path().join(DONE_FILE)).unwrap(),
            format!("{n}\n")
        );
        drop(outbox);
        fs::remove_dir(dir.path().join(CURSOR_FILE)).unwrap();
        let again = Outbox::open(dir.path()).unwrap();
        assert_eq!(again.len(), 0);
        let next = again.append(mail("two")).unwrap();
        assert!(next > n);
        drop(again);
        assert_eq!(Outbox::open(dir.path()).unwrap().head(NOW).unwrap().n, next);
    }

    #[test]
    fn a_torn_completion_line_cannot_fuse_with_the_next_completed_number() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let first = outbox.append(mail("one")).unwrap();
        let second = outbox.append(mail("two")).unwrap();
        let third = outbox.append(mail("three")).unwrap();
        drop(outbox);
        fs::write(dir.path().join(DONE_FILE), format!("{first}\n{second}")).unwrap();
        let again = Outbox::open(dir.path()).unwrap();
        assert_eq!(again.head(NOW).unwrap().n, second);
        again.finish(second, Ok(Value::Null)).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join(DONE_FILE)).unwrap(),
            format!("{first}\n{second}\n")
        );
        drop(again);
        let reopened = Outbox::open(dir.path()).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.head(NOW).unwrap().n, third);
    }

    #[test]
    fn unreadable_completion_storage_does_not_silently_replay_finished_entries() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(DONE_FILE)).unwrap();
        assert!(Outbox::open(dir.path()).is_err());
    }

    #[test]
    fn the_queue_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        Outbox::open(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(QUEUE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
