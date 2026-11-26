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

use lockyard_core::paths::{fold_path_component, nfc_path};
use lockyard_core::proto::{DirtyPath, InboxQuery, Message, SendRequest};
use lockyard_core::watch::{Backend as WatchBackend, Tick, Watcher};
use lockyard_core::{Backend, Error, Result, Store, ZonePath, outside, watch};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::io::{ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Mail reserved per round. The rest arrives on the next one.
const MAIL_PER_ROUND: usize = 20;
/// How long one round holds the exclusive right to show a message.
const DELIVERY_LEASE_SECONDS: i64 = 60;
/// Unannounced-write records older than this are forgotten.
const KEEP_RECORDS_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const RESCAN_STATUS_FILE: &str = "monitor-rescan-status";

/// What the monitor was asked to do.
pub struct Settings {
    pub root: PathBuf,
    pub agent: String,
    pub reconcile: Duration,
    pub mail: bool,
    pub zones: bool,
    /// Stop after the first mail or unannounced write.
    pub once: bool,
    /// Stop after this long, whatever happened.
    pub timeout: Option<Duration>,
    pub json: bool,
    /// Mark delivered mail read even when stdout is not a terminal.
    pub mark_read: bool,
}

/// What a finished run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub delivered: usize,
    pub unannounced: usize,
    pub rounds: usize,
    pub backend: Option<&'static str>,
    pub rescan_incomplete: bool,
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
    let started = Instant::now();
    let deadline = settings.timeout.map(|limit| started + limit);
    let mut next_reconcile = started + settings.reconcile;
    // Seen paths whose claim and announcement were already judged in this round set.
    let mut pending: Vec<String> = Vec::new();
    loop {
        if crate::shutdown::requested() {
            return Ok(summary);
        }
        let left = deadline.map(|at| at.saturating_duration_since(Instant::now()));
        if left == Some(Duration::ZERO) {
            return Ok(summary);
        }
        let wait = left
            .unwrap_or(settings.reconcile)
            .min(crate::shutdown::POLL_INTERVAL);
        let tick = match watcher.as_mut() {
            Some(watcher) => watcher.wait(wait),
            // Without any watcher the reconcile interval is the whole mechanism.
            None => {
                std::thread::sleep(
                    wait.min(next_reconcile.saturating_duration_since(Instant::now())),
                );
                let now = Instant::now();
                if now >= next_reconcile || deadline.is_some_and(|deadline| now >= deadline) {
                    next_reconcile = now + settings.reconcile;
                    Tick::Reconcile
                } else {
                    Tick::Idle
                }
            }
        };
        if crate::shutdown::requested() {
            return Ok(summary);
        }
        let reconcile = matches!(tick, Tick::Reconcile);
        match &tick {
            Tick::Idle => continue,
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
            let inspection = inspect(settings, ports, paths, reconcile, now, out)?;
            summary.unannounced += inspection.unannounced;
            summary.rescan_incomplete |= inspection.rescan_incomplete;
            if reconcile {
                save_rescan_status(&settings.root, inspection.rescan_incomplete);
            }
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

fn rescan_status_path(root: &Path) -> PathBuf {
    root.join(lockyard_core::DIR_NAME).join(RESCAN_STATUS_FILE)
}

/// Completeness of the last finished reconcile tick, when a monitor has recorded one.
pub(crate) fn read_rescan_status(root: &Path) -> Option<bool> {
    let path = rescan_status_path(root);
    if !path.symlink_metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(2)
        .read_to_end(&mut bytes)
        .ok()?;
    match bytes.as_slice() {
        b"0" => Some(false),
        b"1" => Some(true),
        _ => None,
    }
}

fn save_rescan_status(root: &Path, incomplete: bool) {
    if read_rescan_status(root) == Some(incomplete) {
        return;
    }
    let bytes = if incomplete { b"1" } else { b"0" };
    if let Err(error) = lockyard_core::fsio::replace(&rescan_status_path(root), bytes, 0o600) {
        eprintln!("warning: could not save monitor rescan status: {error}");
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
    let should_mark = settings.mark_read || std::io::stdout().is_terminal();
    if should_mark {
        ports.backend.inbox_seen(agent, &shown, now)?;
    }
    Ok(shown.len())
}

#[derive(Default)]
struct Inspection {
    unannounced: usize,
    rescan_incomplete: bool,
}

/// Judges changed paths against the claims, and reports the ones nobody announced.
fn inspect(
    settings: &Settings,
    ports: &mut Ports<'_>,
    changed: Vec<String>,
    reconcile: bool,
    now: i64,
    out: &mut dyn Write,
) -> Result<Inspection> {
    let claims = ports
        .backend
        .claims(&lockyard_core::proto::ClaimQuery::default(), now)?;
    if claims.is_empty() {
        return Ok(Inspection::default());
    }
    let scan = if reconcile {
        // The file system may have dropped events, so check modification times too.
        rescan(&settings.root, &claims, now)
    } else {
        ScanResult::default()
    };
    let mut inspection = Inspection {
        rescan_incomplete: !scan.incomplete.is_empty(),
        ..Inspection::default()
    };
    let causes = [
        (ScanIssues::ALIASES, "Unicode alias lookup budget"),
        (ScanIssues::ENTRIES, "directory entry budget"),
        (ScanIssues::DEPTH, "directory depth limit"),
        (ScanIssues::LISTING, "directory listing error"),
    ];
    for ((session, path), issues) in scan.incomplete {
        let reasons = causes
            .iter()
            .filter_map(|(issue, label)| (issues & issue != 0).then_some(*label))
            .collect::<Vec<_>>()
            .join(", ");
        let message = format!(
            "monitor rescan coverage is incomplete for {path:?} (session {session:?}): {reasons}"
        );
        eprintln!("warning: {message}");
        if settings.json {
            writeln!(
                out,
                "{}",
                json!({"event": "warning", "message": message, "session": session, "path": path})
            )?;
        }
    }
    let mut paths: Vec<_> = changed
        .into_iter()
        .chain(scan.paths)
        .map(|path| nfc_path(&path))
        .collect();
    paths.sort();
    paths.dedup();
    let announced = if paths.is_empty() {
        Vec::new()
    } else {
        outside::announcements(&settings.root, now - outside::ANNOUNCE_WINDOW_MS)?
    };
    let mut dirty: HashMap<String, Vec<DirtyPath>> = HashMap::new();
    for path in paths {
        let zone = ZonePath::stored(path.clone());
        let Some(claim) = claims.iter().find(|claim| claim.covers(&zone)) else {
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
        inspection.unannounced += 1;
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
                urgent: false,
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
    for (session, paths) in &dirty {
        // Local mode has no dirty tracking; the call says so and there is nothing to report.
        if let Err(error) = ports.backend.dirty_report(session, paths)
            && !matches!(error, Error::NeedsCloud(_))
        {
            writeln!(out, "! could not report dirty paths: {error}")?;
        }
    }
    Ok(inspection)
}

/// The fallback for dropped events: recently modified files under the active claims.
fn rescan<'a>(root: &Path, claims: &'a [lockyard_core::proto::Claim], now: i64) -> ScanResult<'a> {
    let since = now - i64::try_from(RESCAN_WINDOW.as_millis()).unwrap_or(i64::MAX);
    let mut scan = Rescan {
        root,
        since,
        remaining: 0,
        alias_remaining: RESCAN_ALIAS_ENTRIES,
        issues: 0,
        alias_listings: HashMap::new(),
        found: Vec::new(),
    };
    let mut result = ScanResult::default();
    let mut zones_left: usize = claims.iter().map(|claim| claim.paths.len()).sum();
    let mut remaining = RESCAN_ENTRIES;
    for (claim, held) in claims
        .iter()
        .flat_map(|claim| claim.paths.iter().map(move |held| (claim, held)))
    {
        // Reserve an equal share for later zones, passing unused entries forward. Resolve
        // every zone root even if there are more zones than directory entries in the budget.
        let budget = remaining.div_ceil(zones_left);
        zones_left -= 1;
        scan.remaining = budget;
        scan.issues = 0;
        if held == "." {
            scan.walk(root, 0);
        } else {
            let components: Vec<_> = held.split('/').collect();
            scan.walk_aliases(root, &components, claim.folds_path_case());
        }
        remaining -= budget - scan.remaining;
        if scan.issues != 0 {
            *result
                .incomplete
                .entry((claim.session.as_str(), nfc_path(held)))
                .or_default() |= scan.issues;
        }
    }
    result.paths = scan.found;
    result
}

#[derive(Default)]
struct ScanResult<'a> {
    paths: Vec<String>,
    // One warning per session and NFC path in this rescan, preserving case.
    incomplete: BTreeMap<(&'a str, String), u8>,
}

struct ScanIssues;

impl ScanIssues {
    const ENTRIES: u8 = 1;
    const ALIASES: u8 = 2;
    const DEPTH: u8 = 4;
    const LISTING: u8 = 8;
}

/// How far back a rescan looks. Longer than the reconcile interval, so nothing falls between rounds.
const RESCAN_WINDOW: Duration = Duration::from_secs(60);
/// A rescan does not descend further than this below a matched claim path.
const RESCAN_DEPTH: usize = 12;
/// Bound the walk through claimed subtrees independently of alias resolution.
const RESCAN_ENTRIES: usize = 20_000;
/// Bound the total number of directory entries indexed for Unicode alias lookups per rescan.
const RESCAN_ALIAS_ENTRIES: usize = 20_000;

fn list_directory(at: &Path, issues: &mut u8) -> Option<std::fs::ReadDir> {
    match std::fs::read_dir(at) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(_) => {
            *issues |= ScanIssues::LISTING;
            None
        }
    }
}

#[derive(Default)]
struct AliasDirectory {
    by_nfc: HashMap<String, Vec<PathBuf>>,
    by_d145: HashMap<String, Vec<PathBuf>>,
    issues: u8,
}

impl AliasDirectory {
    fn read(at: &Path, remaining: &mut usize) -> Self {
        let mut listing = Self::default();
        // Do not follow an intermediate symlink while resolving aliases.
        if !at.symlink_metadata().is_ok_and(|data| data.is_dir()) {
            return listing;
        }
        let Some(entries) = list_directory(at, &mut listing.issues) else {
            return listing;
        };
        for entry in entries {
            if *remaining == 0 {
                listing.issues |= ScanIssues::ALIASES;
                break;
            }
            *remaining -= 1;
            let Ok(entry) = entry else {
                listing.issues |= ScanIssues::LISTING;
                continue;
            };
            if let Some(name) = entry.file_name().to_str() {
                let path = entry.path();
                listing
                    .by_nfc
                    .entry(nfc_path(name))
                    .or_default()
                    .push(path.clone());
                listing
                    .by_d145
                    .entry(fold_path_component(name))
                    .or_default()
                    .push(path);
            }
        }
        listing
    }
}

struct Rescan<'a> {
    root: &'a Path,
    since: i64,
    remaining: usize,
    alias_remaining: usize,
    issues: u8,
    // Share each physical parent listing across both comparison policies.
    alias_listings: HashMap<PathBuf, AliasDirectory>,
    found: Vec<String>,
}

impl Rescan<'_> {
    fn walk_aliases(&mut self, at: &Path, components: &[&str], fold_case: bool) {
        let Some((component, rest)) = components.split_first() else {
            self.walk(at, 0);
            return;
        };
        if watch::is_internal(at) {
            return;
        }
        let listing = self
            .alias_listings
            .entry(at.to_path_buf())
            .or_insert_with(|| AliasDirectory::read(at, &mut self.alias_remaining));
        let matches = if fold_case {
            listing.by_d145.get(&fold_path_component(component))
        } else {
            listing.by_nfc.get(&nfc_path(component))
        }
        .cloned()
        .unwrap_or_default();
        self.issues |= listing.issues;
        for child in matches {
            self.walk_aliases(&child, rest, fold_case);
        }
    }

    fn walk(&mut self, at: &Path, depth: usize) {
        if watch::is_internal(at) {
            return;
        }
        let Ok(data) = at.symlink_metadata() else {
            return;
        };
        if data.is_dir() {
            let Some(entries) = list_directory(at, &mut self.issues) else {
                return;
            };
            for entry in entries {
                if depth == RESCAN_DEPTH {
                    self.issues |= ScanIssues::DEPTH;
                    break;
                }
                if self.remaining == 0 {
                    self.issues |= ScanIssues::ENTRIES;
                    break;
                }
                self.remaining -= 1;
                let Ok(entry) = entry else {
                    self.issues |= ScanIssues::LISTING;
                    continue;
                };
                self.walk(&entry.path(), depth + 1);
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
        if modified.is_none_or(|at| at < self.since) {
            return;
        }
        if let Ok(relative) = at.strip_prefix(self.root)
            && let Some(text) = relative.to_str()
        {
            self.found
                .push(text.replace(std::path::MAIN_SEPARATOR, "/"));
        }
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
            // Unit tests capture stdout; mark explicitly like `monitor --mark-read`.
            mark_read: true,
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
        assert_eq!(found.unannounced, 1);
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
        assert_eq!(found.unannounced, 0);
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
        assert_eq!(found.unannounced, 1);
        assert!(!found.rescan_incomplete);
        assert_eq!(
            project.store().unannounced(0).unwrap()[0].path,
            "src/late.rs"
        );
    }

    #[test]
    fn local_0100_r8_rescan_finds_late_zone_after_large_stale_zone() {
        let project = Project::new();
        let root = project.root();
        let stale = root.join("aaa-stale");
        std::fs::create_dir(&stale).unwrap();
        let times = std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH);
        for index in 0..=RESCAN_ENTRIES {
            std::fs::File::create(stale.join(format!("{index}.rs")))
                .unwrap()
                .set_times(times)
                .unwrap();
        }
        std::fs::create_dir(root.join("zzz-live")).unwrap();
        std::fs::write(root.join("zzz-live/changed.rs"), "changed").unwrap();
        let now = crate::now_ms();
        let mut backend = project.store();
        Backend::touch_agent(&mut backend, "alice", now).unwrap();
        backend
            .claim(
                "alice",
                &[
                    ZonePath::stored("aaa-stale".into()),
                    ZonePath::stored("zzz-live".into()),
                ],
                "",
                30,
                now,
            )
            .unwrap();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(now),
        };
        let mut out = Vec::new();
        let mut settings = settings(&root, "alice");
        settings.mail = false;
        settings.json = true;
        let _guard = lockyard_core::test_env_lock();
        unsafe { std::env::set_var("LOCKYARD_WATCH", "off") };
        let summary = run(&settings, &mut ports, &mut out);
        unsafe { std::env::remove_var("LOCKYARD_WATCH") };
        let summary = summary.unwrap();
        assert_eq!(
            summary.unannounced, 1,
            "the large stale zone must not starve zzz-live/changed.rs"
        );
        assert!(summary.rescan_incomplete);
        assert_eq!(
            ports.store.unannounced(0).unwrap()[0].path,
            "zzz-live/changed.rs"
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("directory entry budget"), "{out}");
    }

    struct RecordingCloud<'a> {
        paths: &'a [&'a str],
        reports: std::sync::Mutex<Vec<serde_json::Value>>,
    }

    impl lockyard_cloud_client::Transport for &RecordingCloud<'_> {
        fn call(
            &self,
            call: &lockyard_cloud_client::Call,
        ) -> std::result::Result<serde_json::Value, lockyard_cloud_client::ClientError> {
            match call.path.as_str() {
                "/api/v1/zones/claims" => Ok(json!([
                    {"id": 1, "session": "alice", "paths": self.paths}
                ])),
                "/api/v1/zones/dirty" => {
                    assert_eq!(call.session, "alice");
                    self.reports
                        .lock()
                        .unwrap()
                        .push(call.body.clone().unwrap());
                    Ok(json!({"stored": 1}))
                }
                path => panic!("unexpected cloud call: {path}"),
            }
        }
    }

    #[test]
    fn local_0100_r9_incomplete_cloud_rescan_reports_only_observed_writes() {
        let project = Project::new();
        let root = project.root();
        let mut deep = root.join("src");
        for _ in 0..RESCAN_DEPTH {
            deep.push("nested");
        }
        std::fs::create_dir_all(&deep).unwrap();
        let old_file = std::fs::File::create(deep.join("unchecked.rs")).unwrap();
        old_file
            .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
        let now = crate::now_ms();
        let cloud = RecordingCloud {
            paths: &["src", "live"],
            reports: Default::default(),
        };
        let mut backend = lockyard_cloud_client::CloudBackend::new(&cloud, "alice");
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(now),
        };
        let mut settings = settings(&root, "alice");
        settings.json = true;
        let mut out = Vec::new();
        let inspection = inspect(&settings, &mut ports, Vec::new(), true, now, &mut out).unwrap();
        assert_eq!(inspection.unannounced, 0);
        assert!(inspection.rescan_incomplete);
        let warning: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(warning["event"], "warning");
        assert!(
            warning["message"]
                .as_str()
                .unwrap()
                .contains("directory depth limit")
        );
        assert_eq!(
            cloud.reports.lock().unwrap().len(),
            0,
            "an unchanged tree with an incomplete scan must not produce a dirty report"
        );
        assert_eq!(warning["session"], "alice");
        assert_eq!(warning["path"], "src");

        std::fs::create_dir(root.join("live")).unwrap();
        std::fs::write(root.join("live/checked.rs"), "changed").unwrap();
        let inspection = inspect(&settings, &mut ports, Vec::new(), true, now, &mut out).unwrap();
        assert_eq!(inspection.unannounced, 1);
        assert!(inspection.rescan_incomplete);
        let reports = cloud.reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["paths"].as_array().unwrap().len(), 1);
        assert_eq!(reports[0]["paths"][0]["path"], "live/checked.rs");
    }

    #[cfg(unix)]
    #[test]
    fn local_0100_r10_unreadable_listing_marks_rescan_incomplete() {
        use std::os::unix::fs::PermissionsExt;

        let project = Project::new();
        let root = project.root();
        let parents = [root.join("src"), root.join("tree")];
        for parent in &parents {
            std::fs::create_dir(parent).unwrap();
            std::fs::write(parent.join("checked.rs"), "changed").unwrap();
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o311)).unwrap();
        }
        let cloud = RecordingCloud {
            paths: &["src/checked.rs", "tree", "missing/checked.rs"],
            reports: Default::default(),
        };
        let mut backend = lockyard_cloud_client::CloudBackend::new(&cloud, "alice");
        let now = crate::now_ms();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(now),
        };
        let mut settings = settings(&root, "alice");
        settings.json = true;
        let unreadable = parents.each_ref().map(|parent| {
            std::fs::read_dir(parent)
                .is_err_and(|error| error.kind() == ErrorKind::PermissionDenied)
        });
        let file_accessible = parents
            .iter()
            .all(|parent| parent.join("checked.rs").is_file());
        let mut out = Vec::new();
        let inspection = inspect(&settings, &mut ports, Vec::new(), true, now, &mut out);
        for parent in &parents {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        if !unreadable.into_iter().all(|denied| denied) {
            // Privileged users can list directories without read permission.
            return;
        }
        assert!(file_accessible);
        let inspection = inspection.unwrap();
        assert!(
            inspection.rescan_incomplete,
            "unreadable listings must mark the rescan incomplete"
        );
        assert_eq!(inspection.unannounced, 0);
        assert!(cloud.reports.lock().unwrap().is_empty());
        let warnings: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&out)
            .into_iter()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(warnings.len(), 2);
        for (warning, path) in warnings.iter().zip(["src/checked.rs", "tree"]) {
            assert_eq!(warning["event"], "warning");
            assert_eq!(warning["path"], path);
            assert!(
                warning["message"]
                    .as_str()
                    .unwrap()
                    .contains("directory listing error")
            );
        }

        out.clear();
        let inspection = inspect(&settings, &mut ports, Vec::new(), true, now, &mut out).unwrap();
        assert!(!inspection.rescan_incomplete);
        assert_eq!(inspection.unannounced, 2);
        let reports = cloud.reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        let paths = reports[0]["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0]["path"], "src/checked.rs");
        assert_eq!(paths[1]["path"], "tree/checked.rs");
    }

    #[test]
    fn local_0100_r9_alias_budget_does_not_trust_an_unlisted_literal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let parent = root.join("src");
        std::fs::create_dir_all(parent.join("a")).unwrap();
        std::fs::write(parent.join("a/changed.rs"), "changed").unwrap();
        // Exercise case-mismatched lookup on a case-insensitive volume. On a case-sensitive
        // volume, an existing exact spelling still proves that an unlisted literal is skipped.
        let requested = if parent.join("A").is_dir() { "A" } else { "a" };
        let mut scan = Rescan {
            root,
            since: 0,
            remaining: RESCAN_ENTRIES,
            alias_remaining: 0,
            issues: 0,
            alias_listings: HashMap::new(),
            found: Vec::new(),
        };
        scan.walk_aliases(&parent, &[requested], false);
        assert_eq!(scan.issues, ScanIssues::ALIASES);
        assert_eq!(
            scan.found,
            Vec::<String>::new(),
            "the exhausted alias budget must not turn an unlisted literal into a covered write"
        );

        scan.alias_listings.clear();
        scan.alias_remaining = 1;
        scan.issues = 0;
        scan.walk_aliases(&parent, &["A"], false);
        assert!(scan.found.is_empty());
        scan.walk_aliases(&parent, &["A"], true);
        assert_eq!(scan.found, ["src/a/changed.rs"]);
        assert_eq!(scan.issues, 0);
    }

    #[test]
    fn local_0100_r9_rescan_deduplicates_incomplete_zones_by_session_and_exact_nfc_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut deep = root.join("src/café");
        for _ in 0..=RESCAN_DEPTH {
            deep.push("nested");
        }
        std::fs::create_dir_all(deep).unwrap();
        let make_claim = |id, session, paths: &[&str], fold_case| {
            serde_json::from_value(json!({
                "id": id, "session": session, "paths": paths, "case_insensitive_paths": fold_case
            }))
            .unwrap()
        };
        let claims = [
            make_claim(
                1,
                "alice",
                &["src/café", "src/cafe\u{301}", "SRC/CAFÉ"],
                true,
            ),
            make_claim(2, "bob", &["src/café"], false),
        ];
        assert_eq!(
            rescan(root, &claims, 0).incomplete,
            BTreeMap::from([
                (("alice", "src/café".into()), ScanIssues::DEPTH),
                (("alice", "SRC/CAFÉ".into()), ScanIssues::DEPTH),
                (("bob", "src/café".into()), ScanIssues::DEPTH),
            ])
        );
    }

    #[test]
    fn local_0100_r5_rescan_walks_all_d145_spellings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src/STRASSE")).unwrap();
        std::fs::write(root.join("src/STRASSE/file.rs"), "changed").unwrap();
        let distinct = match std::fs::create_dir(root.join("src/straße")) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => panic!("{error}"),
        };
        std::fs::write(root.join("src/straße/other.rs"), "also changed").unwrap();
        std::fs::create_dir(root.join("src/STRASSE-sibling")).unwrap();
        std::fs::write(root.join("src/STRASSE-sibling/unrelated.rs"), "outside").unwrap();
        let mut claim: lockyard_core::proto::Claim = serde_json::from_value(json!({
            "id": 1, "paths": ["src/straße"], "case_insensitive_paths": true
        }))
        .unwrap();
        let mut scan = rescan(root, std::slice::from_ref(&claim), 0);
        assert!(scan.incomplete.is_empty());
        scan.paths.sort();
        let other = if distinct {
            "src/straße/other.rs"
        } else {
            "src/STRASSE/other.rs"
        };
        assert_eq!(scan.paths, ["src/STRASSE/file.rs", other]);
        if distinct {
            claim.case_insensitive_paths = Some(false);
            let claims = [claim];
            let scan = rescan(root, &claims, 0);
            assert_eq!(scan.paths, ["src/straße/other.rs"]);
            assert!(scan.incomplete.is_empty());
        }
    }

    #[test]
    fn case_sensitive_rescan_finds_the_on_disk_nfc_alias() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let nfc = "café";
        let nfd = "cafe\u{301}";
        std::fs::create_dir_all(root.join("src").join(nfd)).unwrap();
        std::fs::write(root.join("src").join(nfd).join("changed.rs"), "changed").unwrap();
        let name = std::fs::read_dir(root.join("src"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name();
        let on_disk = name.to_str().unwrap();
        // Use the other spelling even on file systems that resolve both names literally.
        let held = if on_disk == nfc { nfd } else { nfc };
        let claim = serde_json::from_value(json!({
            "id": 1, "paths": [format!("src/{held}")], "case_insensitive_paths": false
        }))
        .unwrap();
        let claims = [claim];
        let scan = rescan(root, &claims, 0);
        assert_eq!(scan.paths, [format!("src/{on_disk}/changed.rs")]);
        assert!(scan.incomplete.is_empty());
    }

    #[test]
    fn local_0100_r6_rescan_does_not_starve_after_missing_siblings() {
        let project = Project::new();
        let root = project.root();
        for i in 0..105 {
            std::fs::write(root.join(format!("unrelated-{i:03}")), "").unwrap();
        }
        std::fs::create_dir(root.join("zzz-live")).unwrap();
        std::fs::write(root.join("zzz-live/changed.rs"), "changed").unwrap();

        let mut paths: Vec<_> = (0..200).map(|i| format!("missing-{i:03}")).collect();
        paths.push("zzz-live".into());
        let mut backend = project.store();
        Backend::touch_agent(&mut backend, "alice", 0).unwrap();
        backend
            .claim(
                "alice",
                &paths.into_iter().map(ZonePath::stored).collect::<Vec<_>>(),
                "",
                30,
                1,
            )
            .unwrap();
        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1),
        };
        let mut settings = settings(&root, "alice");
        settings.mail = false;
        settings.timeout = Some(Duration::from_millis(500));
        let mut out = Vec::new();
        let _guard = lockyard_core::test_env_lock();
        // The monitor reads the variable once, at startup.
        unsafe { std::env::set_var("LOCKYARD_WATCH", "off") };
        let summary = run(&settings, &mut ports, &mut out);
        unsafe { std::env::remove_var("LOCKYARD_WATCH") };
        let summary = summary.unwrap();
        assert_eq!(summary.backend, Some("off"));
        assert_eq!(summary.unannounced, 1);
        assert_eq!(
            ports.store.unannounced(0).unwrap()[0].path,
            "zzz-live/changed.rs"
        );
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains("alias lookup budget")
        );
    }

    #[test]
    fn a_capped_alias_lookup_still_walks_verified_matches_from_the_shared_listing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/changed.rs"), "changed").unwrap();
        let mut listing = AliasDirectory::read(root, &mut 1);
        listing.issues = ScanIssues::ALIASES;
        let mut scan = Rescan {
            root,
            since: 0,
            remaining: 1,
            alias_remaining: 0,
            issues: 0,
            alias_listings: HashMap::from([(root.to_path_buf(), listing)]),
            found: Vec::new(),
        };
        scan.walk_aliases(root, &["missing"], true);
        scan.walk_aliases(root, &["src"], false);
        assert_eq!(scan.issues, ScanIssues::ALIASES);
        assert_eq!(
            scan.alias_listings.len(),
            1,
            "both requests share a parent listing"
        );
        assert_eq!(scan.found, ["src/changed.rs"]);
    }

    #[test]
    fn local_0100_r6_rescan_matches_nfc_announcement() {
        let project = Project::new();
        let root = project.root();
        let mut backend = project.store();
        Backend::touch_agent(&mut backend, "alice", 0).unwrap();
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(root.join("src/cafe\u{301}.rs"), "changed").unwrap();
        backend
            .claim("alice", &[ZonePath::stored("src".into())], "", 30, 1)
            .unwrap();
        outside::announce(&root, "alice", "src/café.rs", 1).unwrap();

        let mut ports = Ports {
            backend: &mut backend,
            store: project.store(),
            now: &now_is(1),
        };
        let found = inspect(
            &settings(&root, "alice"),
            &mut ports,
            Vec::new(),
            true,
            1,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            found.unannounced, 0,
            "the NFC announcement covers the rescanned file"
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
        let _guard = lockyard_core::test_env_lock();
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
        assert!(claim.covers(&ZonePath::stored("src/a.rs".into())));
        claim.excluded_paths = vec!["src/a.rs".into()];
        assert!(!claim.covers(&ZonePath::stored("src/a.rs".into())));
        assert!(claim.covers(&ZonePath::stored("src/b.rs".into())));
    }

    #[test]
    fn monitor_uses_case_policy_for_unicode_exclusions() {
        let mut claim: lockyard_core::proto::Claim = serde_json::from_value(json!({
            "id": 1,
            "paths": ["src"],
            "excluded_paths": ["src/ſ"],
            "case_insensitive_paths": true,
        }))
        .unwrap();
        let path = ZonePath::stored("src/s".into());
        assert!(!claim.covers(&path), "D145 matches the exclusion");
        claim.case_insensitive_paths = Some(false);
        assert!(claim.covers(&path), "case-sensitive exclusion is distinct");
    }

    #[test]
    fn monitor_uses_case_policy_for_held_paths() {
        let mut claim: lockyard_core::proto::Claim = serde_json::from_value(json!({
            "id": 1,
            "paths": ["src/ſ"],
            "case_insensitive_paths": false,
        }))
        .unwrap();
        let path = ZonePath::stored("src/s".into());
        assert!(!claim.covers(&path), "case-sensitive claim is distinct");
        claim.case_insensitive_paths = Some(true);
        assert!(claim.covers(&path), "D145 matches the held path");
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
        assert_eq!(found.unannounced, 0);
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
