// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Opt-in, bounded metadata only. This never transmits signed manifests or job content.
use crate::{
    Result,
    cloud::NodeCloudClient,
    executor::Executor,
    wire::{self, JobState},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CAPACITY: usize = 2000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const TOMBSTONE: u64 = 7 * DAY;
const MAX_BYTES: usize = 512 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    job_id: String,
    state: JobState,
    queued_at_ms: u64,
    delivered: bool,
    #[serde(default)]
    source_accounted: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    version: u8,
    certificate_sha256: String,
    enabled_at_ms: u64,
    active: bool,
    dropped: u64,
    expired: u64,
    entries: Vec<Entry>,
}
pub(crate) struct Outbox {
    directory: PathBuf,
    disk: Disk,
}
pub(crate) type SharedOutbox = Arc<Mutex<Outbox>>;

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn valid_pin(pin: &str) -> bool {
    pin.len() == 64
        && pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Outbox {
    pub(crate) fn open(directory: &Path, pin: &str, active: bool) -> Result<Self> {
        if !valid_pin(pin) {
            return Err("invalid notification certificate".into());
        }
        // A crash between temporary-file creation and rename must not accumulate
        // metadata files across restarts. Names are node-generated ULIDs only.
        let mut removed = false;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(id) = name
                .strip_prefix(".job-notifications-")
                .and_then(|name| name.strip_suffix(".tmp"))
                && wire::valid_ulid(id)
            {
                fs::remove_file(entry.path())?;
                removed = true;
            }
        }
        if removed {
            File::open(directory)?.sync_all()?;
        }
        let path = directory.join("job-notifications.json");
        let now = now_ms()?;
        let disk = match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = crate::local_files::read_private(&path, MAX_BYTES)?;
                let disk: Disk = serde_json::from_slice(&bytes)
                    .map_err(|_| "invalid job notification outbox")?;
                if disk.version != 1
                    || !valid_pin(&disk.certificate_sha256)
                    || disk.enabled_at_ms > now
                    || disk.entries.len() > CAPACITY
                    || disk.entries.iter().any(|e| {
                        !wire::valid_ulid(&e.job_id)
                            || !e.state.is_terminal()
                            || e.queued_at_ms > now
                    })
                {
                    return Err("invalid job notification outbox".into());
                }
                if disk.certificate_sha256 == pin {
                    disk
                } else {
                    // A replacement generation cannot authenticate the old pin's
                    // pending reports; account for them before dropping the queue.
                    let discarded =
                        disk.entries.iter().filter(|entry| !entry.delivered).count() as u64;
                    Disk {
                        version: 1,
                        certificate_sha256: pin.into(),
                        enabled_at_ms: now,
                        active,
                        dropped: disk.dropped.saturating_add(discarded),
                        expired: disk.expired,
                        entries: vec![],
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Disk {
                version: 1,
                certificate_sha256: pin.into(),
                enabled_at_ms: now,
                active,
                dropped: 0,
                expired: 0,
                entries: vec![],
            },
            Err(_) => return Err("cannot inspect job notification outbox".into()),
        };
        let mut outbox = Self {
            directory: directory.into(),
            disk,
        };
        if active && !outbox.disk.active {
            outbox.disk.enabled_at_ms = now;
        }
        if !active {
            for entry in &mut outbox.disk.entries {
                entry.delivered = true;
            }
            outbox.disk.entries.retain(|entry| !entry.source_accounted);
        }
        outbox.disk.active = active;
        outbox.persist()?;
        Ok(outbox)
    }
    fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.disk)?;
        if bytes.len() > MAX_BYTES {
            return Err("job notification outbox exceeds limit".into());
        }
        let temporary = self
            .directory
            .join(format!(".job-notifications-{}.tmp", wire::new_id()?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        let result = (|| -> Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, self.directory.join("job-notifications.json"))?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    pub(crate) fn capture(
        &mut self,
        job_id: &str,
        state: JobState,
        completed_at_ms: u64,
    ) -> Result<()> {
        let now = now_ms()?;
        self.expire(now);
        // Equal millisecond timestamps cannot prove completion followed consent.
        if completed_at_ms > self.disk.enabled_at_ms
            && !self
                .disk
                .entries
                .iter()
                .any(|entry| entry.job_id == job_id && entry.state == state)
        {
            if self.disk.entries.len() == CAPACITY {
                self.disk.dropped = self.disk.dropped.saturating_add(1);
            } else {
                self.disk.entries.push(Entry {
                    job_id: job_id.into(),
                    state,
                    queued_at_ms: now,
                    delivered: false,
                    source_accounted: false,
                });
            }
        }
        // This sync precedes the durable marker on the source job.
        self.persist()
    }
    fn expire(&mut self, now: u64) {
        for entry in &mut self.disk.entries {
            if !entry.delivered && now.saturating_sub(entry.queued_at_ms) >= DAY {
                entry.delivered = true;
                self.disk.expired = self.disk.expired.saturating_add(1);
            }
        }
        self.disk.entries.retain(|entry| {
            !(entry.delivered && entry.source_accounted)
                && now.saturating_sub(entry.queued_at_ms) < TOMBSTONE
        });
    }
    pub(crate) fn counts(&self) -> (usize, u64, u64) {
        (
            self.disk.entries.iter().filter(|e| !e.delivered).count(),
            self.disk.dropped,
            self.disk.expired,
        )
    }
    fn pending(&mut self) -> Result<Vec<(String, JobState)>> {
        self.expire(now_ms()?);
        self.persist()?;
        Ok(self
            .disk
            .entries
            .iter()
            .filter(|e| !e.delivered)
            .take(32)
            .map(|e| (e.job_id.clone(), e.state))
            .collect())
    }
    fn mark_delivered(&mut self, job_id: &str, state: JobState) -> Result<()> {
        if let Some(entry) = self
            .disk
            .entries
            .iter_mut()
            .find(|e| e.job_id == job_id && e.state == state)
        {
            entry.delivered = true;
        }
        self.disk
            .entries
            .retain(|entry| !(entry.delivered && entry.source_accounted));
        self.persist()
    }
    pub(crate) fn source_accounted(&mut self, job_id: &str, state: JobState) -> Result<()> {
        let Some(entry) = self
            .disk
            .entries
            .iter_mut()
            .find(|e| e.job_id == job_id && e.state == state)
        else {
            return Ok(());
        };
        if entry.source_accounted {
            return Ok(());
        }
        entry.source_accounted = true;
        self.disk
            .entries
            .retain(|entry| !(entry.delivered && entry.source_accounted));
        self.persist()
    }
}

pub(crate) async fn run(
    outbox: SharedOutbox,
    pin: String,
    executor: Executor,
    client: NodeCloudClient,
) {
    let mut cursor: Option<String> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let worker = executor.clone();
        let scan = tokio::task::spawn_blocking(move || {
            worker.notification_capture_page(cursor.as_deref())
        })
        .await;
        cursor = match scan {
            Ok(Ok(next)) => next,
            _ => {
                eprintln!("lockyard node: job notification maintenance unavailable");
                None
            }
        };
        let queue = outbox.clone();
        let pending = tokio::task::spawn_blocking(move || {
            queue
                .lock()
                .map_err(|_| "outbox unavailable")?
                .pending()
                .map_err(|_| "outbox unavailable")
        })
        .await;
        let Ok(Ok(pending)) = pending else {
            eprintln!("lockyard node: job notification outbox unavailable");
            continue;
        };
        for (job_id, state) in pending {
            if client
                .report_job_outcome(job_id.clone(), state, pin.clone())
                .await
                .is_err()
            {
                break;
            }
            let queue = outbox.clone();
            let result = tokio::task::spawn_blocking(move || {
                queue
                    .lock()
                    .map_err(|_| "outbox unavailable")?
                    .mark_delivered(&job_id, state)
                    .map_err(|_| "outbox unavailable")
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                eprintln!("lockyard node: job notification outbox unavailable");
                break;
            }
        }
    }
}

pub(crate) fn disable_if_present(directory: &Path, pin: &str) -> Result<()> {
    match fs::symlink_metadata(directory.join("job-notifications.json")) {
        Ok(_) => {
            Outbox::open(directory, pin, false)?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("cannot inspect job notification outbox".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delivered_entries_release_capacity_only_after_the_source_acknowledgement_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let pin = "b".repeat(64);
        let mut outbox = Outbox::open(dir.path(), &pin, true).unwrap();
        let activation = outbox.disk.enabled_at_ms;
        let crash_job = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        outbox
            .capture(crash_job, JobState::Cancelled, activation)
            .unwrap();
        assert!(outbox.disk.entries.is_empty());
        outbox
            .capture(crash_job, JobState::Cancelled, activation + 1)
            .unwrap();
        outbox
            .mark_delivered(crash_job, JobState::Cancelled)
            .unwrap();
        drop(outbox);
        let mut outbox = Outbox::open(dir.path(), &pin, true).unwrap();
        assert_eq!(outbox.disk.entries.len(), 1);
        assert!(!outbox.disk.entries[0].source_accounted);
        outbox
            .source_accounted(crash_job, JobState::Cancelled)
            .unwrap();
        assert!(outbox.disk.entries.is_empty());
        // A healthy destination must not consume the entire bounded queue merely
        // because more than 2,000 results completed during seven days.
        for index in 0..2001 {
            let id = format!("{:026}", index);
            outbox
                .capture(&id, JobState::Failed, activation + 1)
                .unwrap();
            outbox.source_accounted(&id, JobState::Failed).unwrap();
            outbox.mark_delivered(&id, JobState::Failed).unwrap();
        }
        assert_eq!(outbox.counts(), (0, 0, 0));
        assert!(outbox.disk.entries.is_empty());
    }
    #[test]
    fn bounded_durable_metadata_outbox_expires_and_withdrawal_discards_pending() {
        let dir = tempfile::tempdir().unwrap();
        let pin = "a".repeat(64);
        let job = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        let mut outbox = Outbox::open(dir.path(), &pin, true).unwrap();
        let activation = outbox.disk.enabled_at_ms;
        outbox
            .capture(job, JobState::Failed, activation + 1)
            .unwrap();
        outbox
            .capture(job, JobState::Failed, activation + 1)
            .unwrap();
        assert_eq!(outbox.counts(), (1, 0, 0));
        let saved = fs::read_to_string(dir.path().join("job-notifications.json")).unwrap();
        assert!(saved.contains(job));
        for private in [
            "prompt",
            "manifest",
            "workspace_key",
            "token",
            "log",
            "arguments",
        ] {
            assert!(!saved.contains(private));
        }
        drop(outbox);
        let mut restored = Outbox::open(dir.path(), &pin, true).unwrap();
        assert_eq!(restored.counts(), (1, 0, 0));
        restored.disk.entries[0].queued_at_ms = now_ms().unwrap().saturating_sub(DAY);
        restored.pending().unwrap();
        assert_eq!(restored.counts(), (0, 0, 1));
        for index in 0..CAPACITY {
            restored.disk.entries.push(Entry {
                job_id: format!("{:026}", index),
                state: JobState::Cancelled,
                queued_at_ms: now_ms().unwrap(),
                delivered: true,
                source_accounted: false,
            });
        }
        // One preexisting expired tombstone plus 2,000 entries is deliberately trimmed for the exact cap.
        restored.disk.entries.remove(0);
        restored
            .capture(
                "01ARZ3NDEKTSV4RRFFQ69G5FAW",
                JobState::Failed,
                activation + 1,
            )
            .unwrap();
        assert_eq!(restored.counts().1, 1);
        restored.disk.entries.clear();
        restored
            .capture(job, JobState::Failed, activation + 1)
            .unwrap();
        drop(restored);
        disable_if_present(dir.path(), &pin).unwrap();
        let reenabled = Outbox::open(dir.path(), &pin, true).unwrap();
        assert_eq!(reenabled.counts().0, 0);
        assert!(reenabled.disk.enabled_at_ms >= activation);
    }
}
