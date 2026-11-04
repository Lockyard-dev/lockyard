// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! `lockyard monitor`: one process per project that reacts to changes instead of waiting for them.
//!
//! Two jobs, both driven by the same ticks:
//!
//! * **Mail.** A message written by another agent reaches the screen as soon as the store changes,
//!   rather than at the next tool call. Reserve, print, then mark seen — the order the hook uses, so
//!   a monitor that dies between the print and the mark shows the message twice instead of losing it.
//! * **Writes nobody announced.** A change to a claimed path that no hook announced is recorded, the
//!   holder is mailed, and `status` and `doctor` show it. This is detection: by the time the event
//!   arrives the file is already written.
//!
//! The file system only decides **when** the work runs. Every tick re-reads the store, and a
//! reconcile tick runs the same work on a timer whether or not an event arrived, because FSEvents
//! coalesces and inotify overflows without telling anyone. Switch the events off entirely with
//! `LOCKYARD_WATCH=off` and the monitor still works, at the reconcile interval.

use lockyard_core::proto::{DirtyPath, InboxQuery, Message, SendRequest};
use lockyard_core::watch::{Backend as WatchBackend, Tick, Watcher};
use lockyard_core::{Backend, Error, Result, Store, ZonePath, outside, watch};
use serde_json::json;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Mail reserved per round. The rest arrives on the next one.
const MAIL_PER_ROUND: usize = 20;
/// How long one round holds the exclusive right to show a message.
const DELIVERY_LEASE_SECONDS: i64 = 60;
/// Unannounced-write records older than this are forgotten.
const KEEP_RECORDS_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// What the monitor was asked to do.
pub struct Settings {
    pub root: PathBuf,
    pub agent: String,
    pub reconcile: Duration,
    pub mail: bool,
    pub zones: bool,
    /// Stop as soon as anything has been reported.
    pub once: bool,
    /// Stop after this long, whatever happened.
    pub timeout: Option<Duration>,
    pub json: bool,
}

/// What a finished run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub delivered: usize,
    pub unannounced: usize,
    pub rounds: usize,
    pub backend: Option<&'static str>,
}

/// Everything the monitor needs from the outside world, so a test can supply it.
pub struct Ports<'a> {
    /// Mail, claims and dirty reports. Local store or cloud, as the project says.
    pub backend: &'a mut dyn Backend,
    /// The project's own store: it holds the unannounced-write records in either mode.
    pub store: Store,
    pub now: &'a dyn Fn() -> i64,
}

/// Runs until the deadline, the first report under `--once`, or forever.
pub fn run(settings: &Settings, ports: &mut Ports<'_>, out: &mut dyn Write) -> Result<Summary> {
    let mut watcher = watcher(settings);
    let mut summary = Summary {
        backend: Some(watcher.as_ref().map_or("off", |w| w.backend().as_str())),
        ..Summary::default()
    };
    let deadline = settings.timeout.map(|limit| Instant::now() + limit);
    // Seen paths whose claim and announcement were already judged in this round set.
    let mut pending: Vec<String> = Vec::new();
    loop {
        let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
        if left == Some(Duration::ZERO) {
            return Ok(summary);
        }
        let tick = match watcher.as_mut() {
            Some(watcher) => watcher.wait(left.unwrap_or(settings.reconcile)),
            // Without any watcher the reconcile interval is the whole mechanism.
            None => {
                std::thread::sleep(settings.reconcile.min(left.unwrap_or(settings.reconcile)));
                Tick::Reconcile
            }
        };
        let reconcile = matches!(tick, Tick::Reconcile);
        match &tick {
            Tick::Idle => return Ok(summary),
            Tick::Changed(paths) => pending.extend(project_paths(&settings.root, paths)),
            Tick::Reconcile => {}
        }
        summary.rounds += 1;
        let now = (ports.now)();
        if settings.mail {
            summary.delivered += deliver(settings, ports, now, out)?;
        }
        if settings.zones {
            let paths = std::mem::take(&mut pending);
            summary.unannounced += inspect(settings, ports, paths, reconcile, now, out)?;
        }
        if reconcile {
            let _ = outside::compact(&settings.root, now - outside::ANNOUNCE_WINDOW_MS);
            let _ = ports.store.forget_unannounced(now - KEEP_RECORDS_MS);
        }
        if settings.once && (summary.delivered > 0 || summary.unannounced > 0) {
            return Ok(summary);
        }
    }
}

/// `None` when the events are switched off; the monitor then runs on its timer alone.
fn watcher(settings: &Settings) -> Option<Watcher> {
    if std::env::var("LOCKYARD_WATCH").is_ok_and(|value| value == "off") {
        return None;
    }
    let roots = if settings.zones {
        vec![settings.root.clone()]
    } else {
        vec![settings.root.join(lockyard_core::DIR_NAME)]
    };
    Some(Watcher::new(&roots, settings.reconcile))
}

/// Turns the watcher's absolute paths into project paths, dropping Lockyard's own state.
fn project_paths(root: &Path, paths: &[PathBuf]) -> Vec<String> {
    let mut seen: Vec<String> = paths
        .iter()
        .filter(|path| !watch::is_internal(path))
        .filter_map(|path| path.strip_prefix(root).ok())
        .filter_map(|relative| relative.to_str())
        .filter(|relative| !relative.is_empty())
        .map(|relative| relative.replace(std::path::MAIN_SEPARATOR, "/"))
        .collect();
    seen.sort();
    seen.dedup();
    seen
}

/// Reserve, print, mark seen. A failure between the print and the mark repeats a message.
fn deliver(
    settings: &Settings,
    ports: &mut Ports<'_>,
    now: i64,
    out: &mut dyn Write,
) -> Result<usize> {
    let agent = &settings.agent;
    if ports.backend.unread(agent)? == 0 {
        return Ok(0);
    }
    let page = ports.backend.inbox(
        agent,
        InboxQuery {
            all: false,
            limit: MAIL_PER_ROUND,
        },
        now,
    )?;
    let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let channel = format!("monitor-{}", std::process::id());
    let granted = ports
        .backend
        .inbox_claim(agent, &channel, &ids, DELIVERY_LEASE_SECONDS, now)?;
    let mine: Vec<Message> = page
        .messages
        .into_iter()
        .filter(|message| granted.contains(&message.id))
        .collect();
    if mine.is_empty() {
        return Ok(0);
    }
    for message in &mine {
        let line = if settings.json {
            json!({"event": "mail", "id": message.id, "from": message.from, "body": message.body})
                .to_string()
        } else {
            format!(
                "M-{} from {}: {}",
                message.id,
                message.from,
                one_line(&message.body)
            )
        };
        writeln!(out, "{line}")?;
    }
    out.flush()?;
    let shown: Vec<i64> = mine.iter().map(|message| message.id).collect();
    ports.backend.inbox_seen(agent, &shown, now)?;
    Ok(shown.len())
}

/// Judges changed paths against the claims, and reports the ones nobody announced.
fn inspect(
    settings: &Settings,
    ports: &mut Ports<'_>,
    changed: Vec<String>,
    reconcile: bool,
    now: i64,
    out: &mut dyn Write,
) -> Result<usize> {
    let claims = ports
        .backend
        .claims(&lockyard_core::proto::ClaimQuery::default(), now)?;
    if claims.is_empty() {
        return Ok(0);
    }
    let mut paths = changed;
    if reconcile {
        // The fallback: the file system may have dropped events, so walk the claimed paths and
        // trust their modification times instead.
        paths.extend(rescan(&settings.root, &claims, now));
        paths.sort();
        paths.dedup();
    }
    if paths.is_empty() {
        return Ok(0);
    }
    let announced = outside::announcements(&settings.root, now - outside::ANNOUNCE_WINDOW_MS)?;
    let mut dirty: HashMap<String, Vec<DirtyPath>> = HashMap::new();
    let mut found = 0;
    for path in paths {
        let zone = ZonePath::stored(path.clone());
        let Some(claim) = claims.iter().find(|claim| covers(claim, &zone)) else {
            continue;
        };
        // Any change under a claim makes it dirty, announced or not: the holder has work in flight.
        dirty
            .entry(claim.session.clone())
            .or_default()
            .push(DirtyPath {
                path: path.clone(),
                owner_session: Some(claim.session.clone()),
                reason: Some("changed on disk while the zone was held".into()),
                task_id: None,
            });
        if outside::was_announced(&announced, &path, now) {
            continue;
        }
        found += 1;
        let record = ports
            .store
            .record_unannounced(&path, &claim.session, claim.id, now)?;
        let text = format!(
            "{path} changed without a hook, inside Z-{} held by {}",
            claim.id, claim.session
        );
        let line = if settings.json {
            json!({"event": "unannounced", "path": path, "holder": claim.session,
                   "claim": claim.id, "hits": record.hits})
            .to_string()
        } else {
            format!("! {text}")
        };
        writeln!(out, "{line}")?;
        if ports.store.should_tell(record.id, now)? && claim.session != settings.agent {
            let request = SendRequest {
                to: claim.session.clone(),
                body: format!(
                    "Lockyard noticed a write outside the hook: {text}. \
                     Lockyard cannot refuse those, only report them."
                ),
                ..SendRequest::default()
            };
            match ports.backend.send(&settings.agent, &request, now) {
                Ok(_) => ports.store.mark_told(record.id, now)?,
                // An unreachable bus must not stop the warning that is already on the screen.
                Err(error) => writeln!(out, "! could not mail {}: {error}", claim.session)?,
            }
        }
    }
    out.flush()?;
    for (session, paths) in dirty {
        // Local mode has no dirty tracking; the call says so and there is nothing to report.
        if let Err(error) = ports.backend.dirty_report(&session, &paths)
            && !matches!(error, Error::NeedsCloud(_))
        {
            writeln!(out, "! could not report dirty paths: {error}")?;
        }
    }
    Ok(found)
}

fn covers(claim: &lockyard_core::proto::Claim, path: &ZonePath) -> bool {
    let overlaps = |held: &String| ZonePath::stored(held.clone()).overlaps(path);
    let excluded = claim.excluded_paths.iter().any(|gap| {
        let gap = ZonePath::stored(gap.clone());
        gap.overlaps(path) && gap.as_str().len() <= path.as_str().len()
    });
    claim.paths.iter().any(overlaps) && !excluded
}

/// The fallback for dropped events: files under a claim modified since the claim began.
fn rescan(root: &Path, claims: &[lockyard_core::proto::Claim], now: i64) -> Vec<String> {
    let mut found = Vec::new();
    let since = now - i64::try_from(RESCAN_WINDOW.as_millis()).unwrap_or(i64::MAX);
    for claim in claims {
        for held in &claim.paths {
            let start = if held == "." {
                root.to_path_buf()
            } else {
                root.join(held)
            };
            walk(root, &start, since, 0, &mut found);
        }
    }
    found
}

/// How far back a rescan looks. Longer than the reconcile interval, so nothing falls between rounds.
const RESCAN_WINDOW: Duration = Duration::from_secs(60);
/// A rescan does not descend further than this, so one claim on `.` cannot stall a round.
const RESCAN_DEPTH: usize = 12;
/// Nor does it look at more files than this.
const RESCAN_FILES: usize = 20_000;

fn walk(root: &Path, at: &Path, since: i64, depth: usize, found: &mut Vec<String>) {
    if depth > RESCAN_DEPTH || found.len() >= RESCAN_FILES || watch::is_internal(at) {
        return;
    }
    let Ok(data) = at.symlink_metadata() else {
        return;
    };
    if data.is_dir() {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            walk(root, &entry.path(), since, depth + 1, found);
        }
        return;
    }
    if !data.is_file() {
        return;
    }
    let modified = data
        .modified()
        .ok()
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since_epoch| i64::try_from(since_epoch.as_millis()).ok());
    if modified.is_none_or(|at| at < since) {
        return;
    }
    if let Ok(relative) = at.strip_prefix(root)
        && let Some(text) = relative.to_str()
    {
        found.push(text.replace(std::path::MAIN_SEPARATOR, "/"));
    }
}

/// Keeps a message body on one line, so a monitor line cannot be forged into several.
fn one_line(body: &str) -> String {
    let flat: String = body
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    match flat.char_indices().nth(400) {
        Some((end, _)) => format!("{}… (see `lockyard msg inbox --all`)", &flat[..end]),
        None => flat,
    }
}

/// Names the watcher backend for `doctor`, without watching any folder.
pub fn backend_name(_root: &Path) -> &'static str {
    if std::env::var("LOCKYARD_WATCH").is_ok_and(|value| value == "off") {
        return "off";
    }
    watch::detect().as_str()
}

#[allow(dead_code)]
fn backend_is_native(backend: WatchBackend) -> bool {
    backend == WatchBackend::Native
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockyard_core::proto::ClaimQuery;

    struct Project {
        dir: tempfile::TempDir,
    }

    impl Project {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            Store::init(dir.path()).unwrap();
            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().canonicalize().unwrap()
        }

        fn store(&self) -> Store {
            Store::open(&self.root()).unwrap()
        }
    }

    fn settings(root: &Path, agent: &str) -> Settings {
        Settings {
            root: root.to_path_buf(),
            agent: agent.to_string(),
            reconcile: Duration::from_millis(100),
            mail: true,
            zones: true,
            once: true,
            timeout: Some(Duration::from_secs(10)),
            json: false,
        }
    }

    fn now_is(value: i64) -> impl Fn() -> i64 {
        move || value
    }

    #[test]
    fn mail_sent_while_the_monitor_waits_is_printed_and_marked_seen() {
        let project = Project::new();
        let root = project.root();
        let mut bus = project.store();
        Backend::touch_agent(&mut bus, "me", 0).unwrap();
        Backend::touch_agent(&mut bus, "bob", 0).unwrap();
        let sender = root.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let mut store = Store::open(&sender).unwrap();
            store.send("bob", "me", "the api is yours", 1).unwrap();
        });
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(2),
        };
        let mut out = Vec::new();
        let summary = run(&settings(&root, "me"), &mut ports, &mut out).unwrap();
        writer.join().unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("the api is yours"), "{text}");
        assert_eq!(summary.delivered, 1);
        assert_eq!(project.store().unread("me").unwrap(), 0);
    }

    #[test]
    fn an_announced_write_is_not_reported_and_an_unannounced_one_is() {
        let project = Project::new();
        let root = project.root();
        let mut store = project.store();
        Backend::touch_agent(&mut store, "alice", 0).unwrap();
        Backend::touch_agent(&mut store, "watcher", 0).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        store
            .claim("alice", &[ZonePath::stored("src".into())], "api", 30, 0)
            .unwrap();
        outside::announce(&root, "alice", "src/known.rs", 0).unwrap();
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1_000),
        };
        let mut out = Vec::new();
        let paths = vec!["src/known.rs".to_string(), "src/surprise.rs".to_string()];
        let found = inspect(
            &settings(&root, "watcher"),
            &mut ports,
            paths,
            false,
            1_000,
            &mut out,
        )
        .unwrap();
        assert_eq!(found, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("src/surprise.rs"), "{text}");
        assert!(!text.contains("src/known.rs"), "{text}");
        let records = project.store().unannounced(0).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].holder, "alice");
    }

    #[test]
    fn the_holder_is_mailed_once_about_a_path_however_often_it_changes() {
        let project = Project::new();
        let root = project.root();
        let mut store = project.store();
        Backend::touch_agent(&mut store, "alice", 0).unwrap();
        Backend::touch_agent(&mut store, "watcher", 0).unwrap();
        store
            .claim("alice", &[ZonePath::stored("src".into())], "", 30, 0)
            .unwrap();
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1_000),
        };
        for _ in 0..3 {
            inspect(
                &settings(&root, "watcher"),
                &mut ports,
                vec!["src/a.rs".to_string()],
                false,
                1_000,
                &mut Vec::new(),
            )
            .unwrap();
        }
        let inbox = Backend::inbox(
            &mut project.store(),
            "alice",
            InboxQuery {
                all: true,
                limit: 10,
            },
            1_000,
        )
        .unwrap();
        assert_eq!(inbox.messages.len(), 1, "{:?}", inbox.messages);
        assert!(inbox.messages[0].body.contains("src/a.rs"));
        assert!(inbox.messages[0].body.contains("only report them"));
    }

    #[test]
    fn a_change_outside_every_claim_is_ignored() {
        let project = Project::new();
        let root = project.root();
        let mut store = project.store();
        Backend::touch_agent(&mut store, "alice", 0).unwrap();
        store
            .claim("alice", &[ZonePath::stored("src".into())], "", 30, 0)
            .unwrap();
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1),
        };
        let found = inspect(
            &settings(&root, "watcher"),
            &mut ports,
            vec!["docs/readme.md".to_string()],
            false,
            1,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(found, 0);
        assert!(project.store().unannounced(0).unwrap().is_empty());
    }

    #[test]
    fn the_reconcile_finds_a_write_whose_event_never_arrived() {
        let project = Project::new();
        let root = project.root();
        let mut store = project.store();
        Backend::touch_agent(&mut store, "alice", 0).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/late.rs"), "fn main() {}").unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        // Claim at `now` so the lease is still live when inspect runs.
        store
            .claim("alice", &[ZonePath::stored("src".into())], "", 30, now)
            .unwrap();
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(now),
        };
        // No changed paths at all: only the rescan can find this one.
        let found = inspect(
            &settings(&root, "watcher"),
            &mut ports,
            Vec::new(),
            true,
            now,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(found, 1);
        assert_eq!(
            project.store().unannounced(0).unwrap()[0].path,
            "src/late.rs"
        );
    }

    #[test]
    fn lockyards_own_files_are_never_project_writes() {
        let root = Path::new("/p");
        let paths = vec![
            PathBuf::from("/p/.lockyard/lockyard.db-wal"),
            PathBuf::from("/p/.git/index"),
            PathBuf::from("/p/src/a.rs"),
        ];
        assert_eq!(project_paths(root, &paths), vec!["src/a.rs".to_string()]);
    }

    #[test]
    fn a_body_cannot_forge_a_second_monitor_line() {
        assert_eq!(one_line("one\ntwo"), "one two");
        let long = one_line(&"x".repeat(500));
        assert!(long.ends_with("msg inbox --all`)"));
        assert!(long.starts_with(&"x".repeat(400)));
        assert!(!long.starts_with(&"x".repeat(401)));
    }

    #[test]
    fn switching_the_events_off_leaves_a_working_timer() {
        let project = Project::new();
        let root = project.root();
        // SAFETY: single-threaded test; the variable is read once when the watcher starts.
        unsafe { std::env::set_var("LOCKYARD_WATCH", "off") };
        let mut settings = settings(&root, "me");
        settings.once = false;
        settings.timeout = Some(Duration::from_millis(250));
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1),
        };
        let summary = run(&settings, &mut ports, &mut Vec::new()).unwrap();
        unsafe { std::env::remove_var("LOCKYARD_WATCH") };
        assert_eq!(summary.backend, Some("off"));
        assert!(summary.rounds >= 1, "{summary:?}");
    }

    #[test]
    fn a_claim_with_a_hole_in_it_does_not_cover_the_hole() {
        let mut claim = lockyard_core::proto::Claim {
            id: 1,
            paths: vec!["src".into()],
            ..serde_json::from_value(json!({"id": 1})).unwrap()
        };
        assert!(covers(&claim, &ZonePath::stored("src/a.rs".into())));
        claim.excluded_paths = vec!["src/a.rs".into()];
        assert!(!covers(&claim, &ZonePath::stored("src/a.rs".into())));
        assert!(covers(&claim, &ZonePath::stored("src/b.rs".into())));
    }

    #[test]
    fn an_empty_board_of_claims_costs_nothing() {
        let project = Project::new();
        let root = project.root();
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1),
        };
        assert!(
            ports
                .backend
                .claims(&ClaimQuery::default(), 1)
                .unwrap()
                .is_empty()
        );
        let found = inspect(
            &settings(&root, "me"),
            &mut ports,
            vec!["src/a.rs".into()],
            true,
            1,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(found, 0);
    }

    /// Send → visible under the event watcher. Records the number so RESULT.md can cite it.
    #[test]
    fn send_to_visible_latency_under_event_watch() {
        let project = Project::new();
        let root = project.root();
        let mut bus = project.store();
        Backend::touch_agent(&mut bus, "me", 0).unwrap();
        Backend::touch_agent(&mut bus, "bob", 0).unwrap();
        let sender = root.clone();
        let started = Instant::now();
        let writer = std::thread::spawn(move || {
            // Give the monitor a moment to enter wait() before the write.
            std::thread::sleep(Duration::from_millis(80));
            let sent_at = Instant::now();
            let mut store = Store::open(&sender).unwrap();
            store.send("bob", "me", "event delivery", 1).unwrap();
            sent_at
        });
        let mut backend = project.store();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(2),
        };
        let mut settings = settings(&root, "me");
        settings.zones = false;
        // Reconcile is the safety net when the native watcher is unavailable; keep it short so the
        // test still finishes, and print which backend answered so RESULT.md can cite both cases.
        settings.reconcile = Duration::from_millis(400);
        settings.timeout = Some(Duration::from_secs(5));
        let mut out = Vec::new();
        let summary = run(&settings, &mut ports, &mut out).unwrap();
        let sent_at = writer.join().unwrap();
        let visible = Instant::now().saturating_duration_since(sent_at);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("event delivery"), "{text}");
        assert_eq!(summary.delivered, 1);
        assert!(
            visible < Duration::from_secs(2),
            "send→visible was {visible:?} (monitor up for {:?})",
            started.elapsed()
        );
        eprintln!(
            "lockyard monitor send→visible: {visible:?} via {}",
            summary.backend.unwrap_or("?")
        );
    }
}
