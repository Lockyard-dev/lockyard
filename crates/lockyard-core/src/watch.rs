// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Watching folders so a change is noticed when it happens instead of at the next poll.
//!
//! The file system is an **accelerator, never the source of truth**. FSEvents coalesces bursts and
//! drops events when a folder changes faster than the kernel reports it, inotify silently loses a
//! queue that overflows, and neither says anything when it does. So every watcher here also hands out
//! a [`Tick::Reconcile`] on a fixed interval, and callers are written to do the same full read on
//! either tick. A missed event then costs latency, never correctness.
//!
//! Nothing in here fails to construct: a machine that refuses the native backend falls back to
//! polling, and a machine that refuses both still reconciles. [`Watcher::backend`] says which, so
//! `doctor` can report "events" or "polling only" rather than quietly going slow.

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// The reconcile interval unless a caller asks for another one.
pub const RECONCILE: Duration = Duration::from_secs(10);

/// A burst of writes is one change. This is how long a tick waits for the rest of it.
const COALESCE: Duration = Duration::from_millis(20);

/// How often the fallback backend looks, when the native one is unavailable.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How the watcher hears about changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// FSEvents, inotify or ReadDirectoryChangesW.
    Native,
    /// Repeated directory scans, when the native backend is unavailable.
    Poll,
    /// Neither worked. Only [`Tick::Reconcile`] arrives.
    None,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Poll => "poll",
            Self::None => "none",
        }
    }
}

/// What [`Watcher::wait`] learned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// These paths changed. The list is a hint: read the store, do not trust the list.
    Changed(Vec<PathBuf>),
    /// The interval elapsed. Read everything, whatever the file system said.
    Reconcile,
    /// Nothing before the caller's deadline.
    Idle,
}

/// Watches folders and reconciles on a timer.
pub struct Watcher {
    events: Receiver<Vec<PathBuf>>,
    /// Dropping this stops the backend thread, so it is held even though it is never read.
    _inner: Option<Box<dyn notify::Watcher + Send>>,
    backend: Backend,
    reconcile: Duration,
    next_reconcile: Instant,
}

impl Watcher {
    /// Watches each of `roots` and its children. Missing folders are skipped, not an error: a
    /// project may create `.lockyard/` after the watcher starts.
    pub fn new(roots: &[PathBuf], reconcile: Duration) -> Self {
        let (sender, events) = channel();
        let sink = move |result: notify::Result<notify::Event>| {
            let Ok(event) = result else { return };
            if matches!(event.kind, EventKind::Access(_)) {
                return;
            }
            // The receiver is gone once the caller dropped the watcher; nothing to do about it.
            let _ = sender.send(event.paths);
        };
        let (inner, backend) = start(roots, sink);
        Self {
            events,
            _inner: inner,
            backend,
            reconcile,
            next_reconcile: Instant::now() + reconcile,
        }
    }

    /// Which backend is in use.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Waits up to `timeout` for a change, and never longer than the next reconcile.
    pub fn wait(&mut self, timeout: Duration) -> Tick {
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= self.next_reconcile {
                self.next_reconcile = now + self.reconcile;
                return Tick::Reconcile;
            }
            if now >= deadline {
                return Tick::Idle;
            }
            let until = deadline.min(self.next_reconcile);
            match self
                .events
                .recv_timeout(until.saturating_duration_since(now))
            {
                Ok(paths) => return Tick::Changed(self.coalesce(paths)),
                Err(RecvTimeoutError::Timeout) => continue,
                // The backend thread died. Reconcile is all that is left, and it still works.
                Err(RecvTimeoutError::Disconnected) => {
                    self.backend = Backend::None;
                    let wait = until.saturating_duration_since(Instant::now());
                    std::thread::sleep(wait);
                }
            }
        }
    }

    /// Collects the rest of a burst so one save is one tick.
    fn coalesce(&self, first: Vec<PathBuf>) -> Vec<PathBuf> {
        let mut paths = first;
        let until = Instant::now() + COALESCE;
        while let Ok(more) = self
            .events
            .recv_timeout(until.saturating_duration_since(Instant::now()))
        {
            paths.extend(more);
            if paths.len() > 4096 {
                break;
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }
}

type Sink = Box<dyn FnMut(notify::Result<notify::Event>) + Send>;

/// Starts the best backend that this machine allows.
fn start(
    roots: &[PathBuf],
    sink: impl FnMut(notify::Result<notify::Event>) + Send + Clone + 'static,
) -> (Option<Box<dyn notify::Watcher + Send>>, Backend) {
    let native = RecommendedWatcher::new(Box::new(sink.clone()) as Sink, Config::default())
        .ok()
        .and_then(|watcher| attach(Box::new(watcher), roots));
    if let Some(watcher) = native {
        return (Some(watcher), Backend::Native);
    }
    let polling = notify::PollWatcher::new(
        Box::new(sink) as Sink,
        Config::default().with_poll_interval(POLL_INTERVAL),
    )
    .ok()
    .and_then(|watcher| attach(Box::new(watcher), roots));
    match polling {
        Some(watcher) => (Some(watcher), Backend::Poll),
        None => (None, Backend::None),
    }
}

/// Adds every folder that exists. `None` when not one of them could be watched.
fn attach(
    mut watcher: Box<dyn notify::Watcher + Send>,
    roots: &[PathBuf],
) -> Option<Box<dyn notify::Watcher + Send>> {
    let mut attached = 0;
    for root in roots {
        if !root.exists() {
            continue;
        }
        if watcher.watch(root, RecursiveMode::Recursive).is_ok() {
            attached += 1;
        }
    }
    (attached > 0).then_some(watcher)
}

/// True when `path` is Lockyard's own state, which must never be read as project work.
pub fn is_internal(path: &Path) -> bool {
    path.components().any(|part| {
        let name = part.as_os_str();
        name == crate::DIR_NAME || name == ".git"
    })
}

/// Which backend this machine can construct, without watching any folder.
///
/// Used by `doctor`: attaching a recursive watcher to a real tree just to print a name can stall.
pub fn detect() -> Backend {
    let (sender, _receiver) = channel::<Vec<PathBuf>>();
    let sink = move |result: notify::Result<notify::Event>| {
        if let Ok(event) = result {
            let _ = sender.send(event.paths);
        }
    };
    if RecommendedWatcher::new(Box::new(sink.clone()) as Sink, Config::default()).is_ok() {
        return Backend::Native;
    }
    if notify::PollWatcher::new(
        Box::new(sink) as Sink,
        Config::default().with_poll_interval(POLL_INTERVAL),
    )
    .is_ok()
    {
        return Backend::Poll;
    }
    Backend::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn roots(dir: &Path) -> Vec<PathBuf> {
        vec![dir.to_path_buf()]
    }

    /// A controlled, silent event source: native watchers may emit startup events even when no
    /// test writes a file. Keep the sender alive so timer tests exercise recv_timeout, rather than
    /// the disconnected-backend fallback. Native writes are covered by the tests below.
    fn no_event_source(reconcile: Duration) -> (Watcher, std::sync::mpsc::Sender<Vec<PathBuf>>) {
        let (sender, events) = channel();
        (
            Watcher {
                events,
                _inner: None,
                backend: Backend::None,
                reconcile,
                next_reconcile: Instant::now() + reconcile,
            },
            sender,
        )
    }

    #[test]
    fn a_write_is_reported_before_the_reconcile_interval() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = Watcher::new(&roots(dir.path()), Duration::from_secs(600));
        if watcher.backend() == Backend::None {
            return; // A machine without any backend is tested by the degraded case below.
        }
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let tick = watcher.wait(Duration::from_secs(10));
        let Tick::Changed(paths) = tick else {
            panic!("expected a change, got {tick:?}");
        };
        assert!(
            paths.iter().any(|path| path.ends_with("a.txt")),
            "{paths:?}"
        );
    }

    #[test]
    fn a_burst_of_writes_becomes_one_tick() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = Watcher::new(&roots(dir.path()), Duration::from_secs(600));
        if watcher.backend() != Backend::Native {
            return; // Polling cannot see a burst; it sees the result of one.
        }
        for index in 0..5 {
            fs::write(dir.path().join(format!("{index}.txt")), "x").unwrap();
        }
        let tick = watcher.wait(Duration::from_secs(10));
        let Tick::Changed(paths) = tick else {
            panic!("expected a change, got {tick:?}");
        };
        assert!(paths.len() > 1, "a burst should coalesce: {paths:?}");
    }

    #[test]
    fn the_reconcile_arrives_with_no_file_system_event_at_all() {
        let (mut watcher, _source) = no_event_source(Duration::from_millis(50));
        assert_eq!(watcher.wait(Duration::from_secs(5)), Tick::Reconcile);
        // And it keeps coming, so a long-running monitor never stops checking.
        assert_eq!(watcher.wait(Duration::from_secs(5)), Tick::Reconcile);
    }

    #[test]
    fn a_deadline_shorter_than_the_interval_returns_idle() {
        let (mut watcher, _source) = no_event_source(Duration::from_secs(600));
        let started = Instant::now();
        assert_eq!(watcher.wait(Duration::from_millis(50)), Tick::Idle);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_folder_that_does_not_exist_still_reconciles() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-here");
        let mut watcher = Watcher::new(&[missing], Duration::from_millis(50));
        assert_eq!(watcher.backend(), Backend::None);
        assert_eq!(watcher.wait(Duration::from_secs(5)), Tick::Reconcile);
    }

    #[test]
    fn lockyard_state_and_git_are_not_project_work() {
        assert!(is_internal(Path::new("/p/.lockyard/lockyard.db")));
        assert!(is_internal(Path::new("/p/.git/index")));
        assert!(!is_internal(Path::new("/p/src/.gitignore")));
        assert!(!is_internal(Path::new("/p/src/a.rs")));
    }

    #[test]
    fn backend_names_are_stable_for_doctor_output() {
        assert_eq!(Backend::Native.as_str(), "native");
        assert_eq!(Backend::Poll.as_str(), "poll");
        assert_eq!(Backend::None.as_str(), "none");
    }

    #[test]
    fn detect_names_a_backend_without_watching_anything() {
        let name = detect().as_str();
        assert!(
            matches!(name, "native" | "poll" | "none"),
            "unexpected backend {name}"
        );
    }
}
