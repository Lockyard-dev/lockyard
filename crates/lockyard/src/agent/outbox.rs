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
use std::collections::{HashMap, VecDeque};
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
        let cursor = read_cursor(dir);
        let mut text = Vec::new();
        file.read_to_end(&mut text)?;
        let mut pending = VecDeque::new();
        let mut last = cursor;
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
            if entry.n > cursor {
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

    /// The oldest entry, left in place until [`Outbox::finish`]. Waits up to `timeout` for one.
    pub fn head(&self, timeout: Duration) -> Option<Entry> {
        let queue = self.lock();
        let (queue, _) = self
            .ready
            .wait_timeout_while(queue, timeout, |queue| queue.pending.is_empty())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queue.pending.front().cloned()
    }

    /// Removes the head after a final answer and tells whoever waits for it.
    pub fn finish(&self, n: u64, outcome: Outcome) -> io::Result<()> {
        let mut queue = self.lock();
        if queue.pending.front().is_none_or(|entry| entry.n != n) {
            return Ok(());
        }
        queue.pending.pop_front();
        let waiter = queue.waiters.remove(&n);
        // The cursor needs no fsync: a stale one sends again, and the key makes that harmless.
        let cursor = fs::write(self.dir.join(CURSOR_FILE), n.to_string());
        let truncated = if queue.pending.is_empty() {
            queue.bytes = 0;
            queue.file.set_len(0)
        } else {
            Ok(())
        };
        // A caller that stopped waiting cannot hear the outcome, so it goes to the log instead.
        let unheard = match waiter {
            Some(waiter) => waiter.send(outcome).err().map(|failed| failed.0),
            None => Some(outcome),
        };
        if let Some(outcome) = unheard {
            log_rejection(&self.dir, n, &outcome);
        }
        cursor.and(truncated)
    }

    /// How many entries wait.
    pub fn len(&self) -> usize {
        self.lock().pending.len()
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

/// Keeps a write the server refused for good, because no caller is left to hear about it.
fn log_rejection(dir: &Path, n: u64, outcome: &Outcome) {
    let Err(error) = outcome else { return };
    eprintln!("lockyard agent: the server refused queued write {n}: {error}");
    let record = serde_json::json!({"n": n, "error": error.to_string()});
    let file = private_options()
        .create(true)
        .append(true)
        .open(dir.join(REJECTED_FILE));
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{record}");
    }
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
    fn a_refusal_nobody_waits_for_is_kept_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::open(dir.path()).unwrap();
        let n = outbox.append(mail("one")).unwrap();
        outbox
            .finish(n, Err(ClientError::Invalid("no".into())))
            .unwrap();
        let kept = fs::read_to_string(dir.path().join(REJECTED_FILE)).unwrap();
        assert!(kept.contains("no"));
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
