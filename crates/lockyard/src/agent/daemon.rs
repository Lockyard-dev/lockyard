// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! The agent process.
//!
//! A view is trusted only while it is younger than [`Timing::fresh`] and no event has arrived that it
//! does not reflect. Each event bumps a generation, and a snapshot records the generation it started
//! from, so an event that lands during a snapshot leaves the view dirty. Age is measured on this
//! process's monotonic clock: leases are never compared with it, because a claim leaves the view only
//! when the server says so.

use super::outbox::Outbox;
use super::private_dir;
use super::wire::{AgentStatus, Envelope, Phase, Reply, Request, Source};
use lockyard_cloud_client::{Call, ClientError, CloudBackend, Transport, ulid};
use lockyard_core::proto::{
    ActivityRequest, BoardEntry, CheckStatus, Claim, ClaimMode, ClaimQuery, DirtyPath, EventPage,
    EventQuery, InboxQuery, Message, PathCheck, PresenceBeat, SessionActivity, SessionState, Stamp,
    Stream, rfc3339,
};
use lockyard_core::zones::Conflict;
use lockyard_core::{Backend, Error, ZonePath};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A request line longer than this is refused. Mail is limited to 8 KiB, with room for its envelope.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
/// A client that says nothing for this long loses its connection.
const IDLE_CONNECTION: Duration = Duration::from_secs(60);
/// A server's `Retry-After` delays the outbox by at most this long.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);
/// Longest pause of a failed event poll. A refresh can make the view look fresh again while the poll
/// still sleeps, and until it wakes the view does not hear about new claims.
const MAX_POLL_PAUSE: Duration = Duration::from_secs(2);

/// Every interval of the process. Tests shorten them.
#[derive(Debug, Clone)]
pub struct Timing {
    /// A view older than this is not answered from.
    pub fresh: Duration,
    /// Limit of the one server call made for a hook.
    pub deadline: Duration,
    pub poll_wait_seconds: u64,
    /// Pause between upkeep rounds.
    pub upkeep: Duration,
    /// Limit of one outbox send.
    pub send_limit: Duration,
    /// How long a sender of mail waits to hear the server's answer before getting `queued`.
    pub mail_wait: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
    /// A repeated identical heartbeat waits this long.
    pub beat_every: Duration,
    /// Claim activity goes out at most this often per claim.
    pub activity_every: Duration,
    /// A session unheard of for this long leaves the upkeep rounds.
    pub active_window: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            fresh: Duration::from_secs(30),
            deadline: Duration::from_millis(800),
            poll_wait_seconds: 25,
            upkeep: Duration::from_secs(5),
            send_limit: Duration::from_secs(10),
            mail_wait: Duration::from_secs(2),
            retry_min: Duration::from_millis(250),
            retry_max: Duration::from_secs(15),
            beat_every: Duration::from_secs(60),
            activity_every: Duration::from_secs(10),
            active_window: Duration::from_secs(30 * 60),
        }
    }
}

/// Where the process lives and what it serves.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub url: String,
    pub workspace: String,
    pub token_id: String,
    pub socket: PathBuf,
    pub state_root: PathBuf,
    pub timing: Timing,
}

#[derive(Default)]
struct UnreadCount {
    count: i64,
    generation: u64,
    clean: u64,
    at: Option<Instant>,
    wall_at: Option<SystemTime>,
}

impl UnreadCount {
    fn fresh(&self, limit: Duration) -> bool {
        self.generation == self.clean
            && self.at.is_some_and(|at| at.elapsed() < limit)
            && self
                .wall_at
                .is_some_and(|at| SystemTime::now().duration_since(at).unwrap_or_default() < limit)
    }
}

#[derive(Default)]
struct View {
    claims: Vec<Claim>,
    board: Vec<BoardEntry>,
    zones_generation: u64,
    zones_clean: u64,
    zones_at: Option<Instant>,
    zones_wall_at: Option<SystemTime>,
    board_generation: u64,
    board_clean: u64,
    board_at: Option<Instant>,
    board_wall_at: Option<SystemTime>,
    unread: HashMap<String, UnreadCount>,
}

impl View {
    fn fresh(&self, limit: Duration) -> bool {
        self.zones_generation == self.zones_clean
            && self.zones_at.is_some_and(|at| at.elapsed() < limit)
            && self
                .zones_wall_at
                .is_some_and(|at| SystemTime::now().duration_since(at).unwrap_or_default() < limit)
    }

    fn board_fresh(&self, limit: Duration) -> bool {
        self.board_generation == self.board_clean
            && self.board_at.is_some_and(|at| at.elapsed() < limit)
            && self
                .board_wall_at
                .is_some_and(|at| SystemTime::now().duration_since(at).unwrap_or_default() < limit)
    }

    /// A poll came back and everything it held is in the view: the view is current as of now.
    fn confirm(&mut self, at: Instant) {
        if self.zones_generation == self.zones_clean {
            self.zones_at = Some(at);
            self.zones_wall_at = Some(SystemTime::now());
        }
        if self.board_generation == self.board_clean {
            self.board_at = Some(at);
            self.board_wall_at = Some(SystemTime::now());
        }
    }

    /// Answers a check from memory.
    fn check(&self, session: &str, paths: &[String]) -> Vec<PathCheck> {
        paths
            .iter()
            .map(|path| self.check_path(session, path))
            .collect()
    }

    fn check_path(&self, session: &str, raw: &str) -> PathCheck {
        let path = ZonePath::stored(raw.to_string());
        // A claim of an unavailable session stops blocking, as it does on the server.
        let covering =
            |claim: &&Claim| claim.holder_available != Some(false) && covers(claim, &path);
        // Availability is about other sessions: a session that comes back still holds its own claims.
        let mine: Vec<&Claim> = self
            .claims
            .iter()
            .filter(|claim| claim.session == session && covers(claim, &path))
            .collect();
        let shares = mine.iter().any(|claim| claim.mode == ClaimMode::Shared);
        let holder = self
            .claims
            .iter()
            .filter(|claim| claim.session != session)
            .filter(covering)
            .find(|claim| !(shares && claim.mode == ClaimMode::Shared));
        match holder {
            Some(claim) => PathCheck {
                path: raw.to_string(),
                status: CheckStatus::Held,
                holder: Some(Conflict {
                    path: raw.to_string(),
                    held_path: claim
                        .paths
                        .iter()
                        .find(|held| ZonePath::stored((*held).clone()).overlaps(&path))
                        .cloned()
                        .unwrap_or_default(),
                    claim: claim.id,
                    agent: claim.session.clone(),
                    note: claim.note.clone(),
                    expires_at: claim.expires_at.clone(),
                }),
            },
            None => PathCheck {
                path: raw.to_string(),
                status: if mine.is_empty() {
                    CheckStatus::Free
                } else {
                    CheckStatus::Own
                },
                holder: None,
            },
        }
    }
}

fn covers(claim: &Claim, path: &ZonePath) -> bool {
    let inside = |list: &[String]| {
        list.iter()
            .any(|held| ZonePath::stored(held.clone()).overlaps(path))
    };
    let excluded = claim.excluded_paths.iter().any(|gap| {
        let gap = ZonePath::stored(gap.clone());
        gap.overlaps(path) && gap.as_str().len() <= path.as_str().len()
    });
    inside(&claim.paths) && !excluded
}

#[derive(Default)]
struct SessionTrack {
    heard: Option<Instant>,
    beat: Option<Instant>,
    tool_running: bool,
    client: String,
}

#[derive(Default)]
struct ClaimActivity {
    sent: Option<Instant>,
    paths: Vec<String>,
    reported: HashSet<String>,
    session: String,
}

#[derive(Default)]
struct SessionEvents {
    after: i64,
    last_poll: Option<Instant>,
    events: VecDeque<lockyard_core::proto::Event>,
}

const SESSION_EVENT_CACHE: usize = 256;

#[derive(Default)]
struct Signal {
    stop: bool,
    nudged: bool,
}

/// How a write travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteClass {
    /// Straight to the server, and it fails during an outage. Claims are here on purpose: a claim that
    /// arrives minutes late would take effect after its owner stopped caring.
    Direct,
    /// Through the outbox, with the caller waiting briefly for the answer.
    Mail,
    /// Through the outbox, with the caller moving on at once.
    Background,
}

fn write_class(call: &Call) -> WriteClass {
    if call.method != "POST" {
        return WriteClass::Direct;
    }
    let route = call.path.split('?').next().unwrap_or_default();
    let parts: Vec<&str> = route.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["api", "v1", "presence"]
        | ["api", "v1", "bus", "inbox", "seen"]
        | ["api", "v1", "zones", "dirty"]
        | ["api", "v1", "zones", "claims", _, "activity"] => WriteClass::Background,
        ["api", "v1", "bus", "messages"] | ["api", "v1", "bus", "messages", _, "reply" | "ack"] => {
            WriteClass::Mail
        }
        _ => WriteClass::Direct,
    }
}

struct Shared<T: Transport + 'static> {
    transport: Arc<T>,
    config: AgentConfig,
    session: String,
    state_dir: PathBuf,
    view: RwLock<View>,
    sessions: Mutex<HashMap<String, SessionTrack>>,
    activity: Mutex<HashMap<i64, ClaimActivity>>,
    outbox: Outbox,
    signal: Mutex<Signal>,
    wake: Condvar,
    coordination_seq: AtomicI64,
    registry_seq: AtomicI64,
    session_event_cursors: Mutex<HashMap<String, i64>>,
    session_events: Mutex<HashMap<String, SessionEvents>>,
}

fn now_ms() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
}

impl<T: Transport + 'static> Shared<T> {
    fn timing(&self) -> &Timing {
        &self.config.timing
    }

    fn backend(&self, session: &str) -> CloudBackend<Arc<T>> {
        CloudBackend::new(Arc::clone(&self.transport), session)
    }

    fn read_view(&self) -> std::sync::RwLockReadGuard<'_, View> {
        self.view.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_view(&self) -> std::sync::RwLockWriteGuard<'_, View> {
        self.view.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn signal(&self) -> MutexGuard<'_, Signal> {
        self.signal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<String, SessionTrack>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn activity(&self) -> MutexGuard<'_, HashMap<i64, ClaimActivity>> {
        self.activity.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stopped(&self) -> bool {
        self.signal().stop
    }

    fn stop(&self) {
        self.signal().stop = true;
        self.wake.notify_all();
    }

    /// Wakes the upkeep thread for work that should not wait for its next round.
    fn nudge(&self) {
        self.signal().nudged = true;
        self.wake.notify_all();
    }

    /// Sleeps for `span` or until the process stops.
    fn pause(&self, span: Duration) {
        let end = Instant::now() + span;
        let mut signal = self.signal();
        while !signal.stop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            signal = self
                .wake
                .wait_timeout(signal, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Runs `work` on its own thread and gives up at the deadline. The limit holds even where the
    /// transport cannot enforce it, such as a slow name lookup. The abandoned call ends by its own
    /// timeout, and everything run this way is safe to abandon.
    fn within_deadline<R: Send + 'static>(
        &self,
        work: impl FnOnce(CloudBackend<Arc<T>>) -> R + Send + 'static,
        session: &str,
    ) -> Option<R> {
        let backend = self.backend(session);
        let (sender, receiver) = channel();
        thread::spawn(move || {
            let _ = sender.send(work(backend));
        });
        receiver.recv_timeout(self.timing().deadline).ok()
    }

    fn check(&self, session: &str, paths: Vec<String>) -> Reply {
        {
            let view = self.read_view();
            if view.fresh(self.timing().fresh) {
                return Reply {
                    checks: Some(view.check(session, &paths)),
                    source: Some(Source::View),
                    ..Reply::default()
                };
            }
        }
        let wanted = paths.clone();
        let answer = self.within_deadline(
            {
                let session = session.to_string();
                move |backend| backend.check(&session, &wanted, None, 0)
            },
            session,
        );
        match answer {
            Some(Ok(checks)) => Reply {
                checks: Some(checks),
                source: Some(Source::Server),
                ..Reply::default()
            },
            _ => {
                let checks = paths
                    .into_iter()
                    .map(|path| PathCheck {
                        path,
                        status: CheckStatus::Unknown,
                        holder: None,
                    })
                    .collect();
                Reply {
                    checks: Some(checks),
                    source: Some(Source::None),
                    ..Reply::default()
                }
            }
        }
    }

    fn unread(&self, session: &str) -> Reply {
        let limit = self.timing().fresh;
        self.hear(session);
        let generation = {
            let mut view = self.write_view();
            let entry = view.unread.entry(session.to_string()).or_default();
            if entry.fresh(limit) {
                return Reply {
                    unread: Some(entry.count),
                    source: Some(Source::View),
                    ..Reply::default()
                };
            }
            entry.generation
        };
        let asked = session.to_string();
        let answer = self.within_deadline(move |backend| backend.unread(&asked), session);
        match answer {
            Some(Ok(count)) => {
                self.store_unread(session, generation, count);
                Reply {
                    unread: Some(count),
                    source: Some(Source::Server),
                    ..Reply::default()
                }
            }
            _ => Reply {
                source: Some(Source::None),
                ..Reply::default()
            },
        }
    }

    fn store_unread(&self, session: &str, generation: u64, count: i64) {
        let mut view = self.write_view();
        let entry = view.unread.entry(session.to_string()).or_default();
        entry.count = count;
        entry.clean = generation;
        entry.at = Some(Instant::now());
        entry.wall_at = Some(SystemTime::now());
    }

    fn take_mail(&self, session: &str, limit: usize, lease_seconds: i64) -> Reply {
        let asked = session.to_string();
        let answer = self.within_deadline(
            move |mut backend| -> Result<Vec<Message>, Error> {
                let page = backend.inbox(&asked, InboxQuery { all: false, limit }, 0)?;
                if page.messages.is_empty() {
                    return Ok(Vec::new());
                }
                let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
                let granted = backend.inbox_claim(&asked, "agent", &ids, lease_seconds, 0)?;
                Ok(page
                    .messages
                    .into_iter()
                    .filter(|message| granted.contains(&message.id))
                    .collect())
            },
            session,
        );
        match answer {
            Some(Ok(messages)) => Reply {
                messages: Some(messages),
                source: Some(Source::Server),
                ..Reply::default()
            },
            _ => Reply {
                source: Some(Source::None),
                ..Reply::default()
            },
        }
    }

    fn take_events(&self, session: &str) -> Reply {
        let after = self
            .session_event_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(session)
            .copied()
            .unwrap_or_default();
        let events = self
            .session_events
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let cached = events
            .get(session)
            .map(|entry| {
                entry
                    .events
                    .iter()
                    .filter(|event| event.seq > after)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Reply {
            events: Some(cached),
            ..Reply::default()
        }
    }

    fn ack_events(&self, session: &str, through: i64) -> Reply {
        let cursor_name = format!(
            "cursor-session-{}",
            lockyard_cloud_client::token_id(session)
        );
        let mut cursors = self
            .session_event_cursors
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = cursors
            .entry(session.to_string())
            .or_insert_with(|| load_seq(&self.state_dir, &cursor_name));
        if through > *current {
            let temporary = self.state_dir.join(format!("{cursor_name}.tmp"));
            let cursor = self.state_dir.join(cursor_name);
            if let Err(error) = fs::write(&temporary, through.to_string())
                .and_then(|()| fs::rename(&temporary, cursor))
            {
                return Reply::failed(ClientError::Transport(format!(
                    "cannot save event cursor: {error}"
                )));
            }
            *current = through;
        }
        if let Some(cache) = self
            .session_events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(session)
        {
            cache.events.retain(|event| event.seq > through);
        }
        Reply::default()
    }

    fn refresh_session_events(&self) {
        let active: Vec<String> = {
            let sessions = self.sessions();
            sessions
                .iter()
                .filter_map(|(session, track)| {
                    track
                        .heard
                        .filter(|heard| heard.elapsed() < self.timing().active_window)
                        .map(|_| session.clone())
                })
                .collect()
        };
        for session in active {
            let acked = {
                let cursor_name = format!(
                    "cursor-session-{}",
                    lockyard_cloud_client::token_id(&session)
                );
                let mut cursors = self
                    .session_event_cursors
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *cursors
                    .entry(session.clone())
                    .or_insert_with(|| load_seq(&self.state_dir, &cursor_name))
            };
            let after = {
                let mut caches = self
                    .session_events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let cache = caches.entry(session.clone()).or_default();
                if cache
                    .last_poll
                    .is_some_and(|at| at.elapsed() < self.timing().upkeep)
                {
                    continue;
                }
                cache.last_poll = Some(Instant::now());
                cache.after = cache.after.max(acked);
                cache
                    .after
                    .max(cache.events.back().map_or(0, |event| event.seq))
            };
            let query = EventQuery {
                stream: Stream::Coordination,
                after,
                wait_seconds: 0,
                session: Some(session.clone()),
                types: Vec::new(),
            };
            if let Ok(page) = self.backend(&session).events(&query) {
                let mut caches = self
                    .session_events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let cache = caches.entry(session).or_default();
                for event in page.events {
                    if event.seq > cache.after
                        && !cache
                            .events
                            .iter()
                            .any(|existing| existing.seq == event.seq)
                    {
                        cache.events.push_back(event);
                    }
                }
                while cache.events.len() > SESSION_EVENT_CACHE {
                    if let Some(event) = cache.events.pop_front() {
                        cache.after = cache.after.max(event.seq);
                    }
                }
            }
        }
    }

    fn hear(&self, session: &str) {
        self.sessions()
            .entry(session.to_string())
            .or_default()
            .heard = Some(Instant::now());
    }

    fn touch(&self, session: &str, client: &str, phase: Phase, write_paths: Vec<String>) -> Reply {
        let running = phase == Phase::Pre;
        let beat = {
            let mut sessions = self.sessions();
            let track = sessions.entry(session.to_string()).or_default();
            track.heard = Some(Instant::now());
            track.client = client.to_string();
            let changed = track.tool_running != running;
            let due = track
                .beat
                .is_none_or(|at| at.elapsed() >= self.timing().beat_every);
            let send = changed || due || phase == Phase::End;
            if send {
                track.beat = Some(Instant::now());
                track.tool_running = running;
            }
            send
        };
        if beat {
            let state = if phase == Phase::End {
                SessionState::Ended
            } else {
                SessionState::Working
            };
            let machine_config = lockyard_core::machine::MachineConfig::load_user();
            let machine = crate::guard::snapshot(&machine_config).ok();
            let meta = machine.map(|report| {
                let level = match report.level {
                    lockyard_core::machine::Level::Ok => "ok",
                    lockyard_core::machine::Level::Warn => "warn",
                    lockyard_core::machine::Level::Hold => "hold",
                    lockyard_core::machine::Level::Critical => "critical",
                };
                json!({"level": level, "memory_available": report.sample.memory_available,
                    "memory_total": report.sample.memory_total, "disk_free": report.sample.disk_free,
                    "temp_free": report.sample.temp_free, "swap_used": report.sample.swap_used,
                    "load": report.sample.load, "cpus": report.sample.cpus})
            });
            let beat = PresenceBeat {
                client: client.to_string(),
                version: Some(lockyard_core::VERSION.to_string()),
                activity: Some(SessionActivity {
                    tool_running: running,
                    tool_started_at: running.then(|| Stamp::Text(rfc3339(now_ms()))),
                    state: Some(state),
                    meta,
                }),
                ..PresenceBeat::default()
            };
            let body = serde_json::to_value(&beat).unwrap_or(Value::Null);
            self.enqueue(Call::write(
                session,
                "POST",
                "/api/v1/presence".into(),
                body,
            ));
        }
        if !write_paths.is_empty() {
            self.note_writes(session, write_paths);
        }
        Reply::default()
    }

    /// Collects written paths per claim. [`Shared::flush_activity`] sends them, spaced per claim.
    fn note_writes(&self, session: &str, paths: Vec<String>) {
        let matches: Vec<(i64, String)> = {
            let view = self.read_view();
            let own = view.claims.iter().filter(|claim| claim.session == session);
            own.flat_map(|claim| {
                paths
                    .iter()
                    .filter(|path| covers(claim, &ZonePath::stored((*path).clone())))
                    .map(|path| (claim.id, path.clone()))
            })
            .collect()
        };
        let dirty_paths = {
            let mut activity = self.activity();
            let mut fresh = Vec::new();
            for (claim, path) in &matches {
                let entry = activity.entry(*claim).or_default();
                entry.session = session.to_string();
                if !entry.paths.contains(path) {
                    entry.paths.push(path.clone());
                }
                if entry.reported.insert(path.clone()) {
                    fresh.push(path.clone());
                }
            }
            fresh.sort();
            fresh.dedup();
            fresh
        };
        if !dirty_paths.is_empty() {
            let report: Vec<DirtyPath> = dirty_paths
                .into_iter()
                .map(|path| DirtyPath {
                    path,
                    owner_session: Some(session.to_string()),
                    reason: Some("uncommitted changes reported by a tool hook".into()),
                    task_id: None,
                })
                .collect();
            let call = Call::write(
                session,
                "POST",
                "/api/v1/zones/dirty".into(),
                json!({"paths": report}),
            );
            if let Err(error) = self.outbox.append(call) {
                eprintln!("lockyard agent: could not queue dirty paths: {error}");
            }
        }
        self.flush_activity();
    }

    fn flush_activity(&self) {
        let limit = self.timing().activity_every;
        let due: Vec<(i64, String, Vec<String>)> = {
            let mut activity = self.activity();
            let ready = activity.iter_mut().filter(|(_, entry)| {
                !entry.paths.is_empty() && entry.sent.is_none_or(|at| at.elapsed() >= limit)
            });
            ready
                .map(|(claim, entry)| {
                    entry.sent = Some(Instant::now());
                    (
                        *claim,
                        entry.session.clone(),
                        std::mem::take(&mut entry.paths),
                    )
                })
                .collect()
        };
        for (claim, session, paths) in due {
            let request = ActivityRequest {
                write: true,
                paths,
                fence: None,
            };
            let body = serde_json::to_value(&request).unwrap_or(Value::Null);
            self.enqueue(Call::write(
                &session,
                "POST",
                format!("/api/v1/zones/claims/{claim}/activity"),
                body,
            ));
        }
    }

    fn enqueue(&self, call: Call) {
        if let Err(error) = self.outbox.append(call) {
            eprintln!("lockyard agent: cannot queue a write: {error}");
        }
    }

    fn forward(&self, mut call: Call) -> Reply {
        if call.method == "GET" && call.path == "/api/v1/bus/board" {
            let view = self.read_view();
            if view.board_fresh(self.timing().fresh) {
                return Reply {
                    value: Some(json!(view.board)),
                    source: Some(Source::View),
                    ..Reply::default()
                };
            }
        }
        let class = if call.is_write() {
            write_class(&call)
        } else {
            WriteClass::Direct
        };
        if class == WriteClass::Direct {
            let writes = call.is_write() && call.path.starts_with("/api/v1/zones/");
            return match self.transport.call(&call) {
                Ok(value) => {
                    if writes {
                        self.write_view().zones_generation += 1;
                        self.nudge();
                    }
                    Reply {
                        value: Some(value),
                        ..Reply::default()
                    }
                }
                Err(error) => Reply::failed(error),
            };
        }
        let key = call.key.get_or_insert_with(ulid).clone();
        let queued = json!({"queued": true, "key": key});
        let session = call.session.clone();
        let seen = call.path.starts_with("/api/v1/bus/inbox/seen");
        if class == WriteClass::Background {
            return match self.outbox.append(call) {
                Ok(_) => {
                    if seen {
                        self.mark_unread_dirty(&session);
                    }
                    Reply {
                        value: Some(queued),
                        ..Reply::default()
                    }
                }
                Err(error) => Reply::failed(ClientError::Transport(error.to_string())),
            };
        }
        match self.outbox.append_waiting(call) {
            Err(error) => Reply::failed(ClientError::Transport(error.to_string())),
            Ok((_, outcome)) => match outcome.recv_timeout(self.timing().mail_wait) {
                Ok(Ok(value)) => Reply {
                    value: Some(value),
                    ..Reply::default()
                },
                Ok(Err(error)) => Reply::failed(error),
                Err(_) => Reply {
                    value: Some(queued),
                    ..Reply::default()
                },
            },
        }
    }

    fn mark_unread_dirty(&self, session: &str) {
        let mut view = self.write_view();
        if let Some(entry) = view.unread.get_mut(session) {
            entry.generation += 1;
        }
        drop(view);
        self.nudge();
    }

    fn status(&self) -> AgentStatus {
        let view = self.read_view();
        AgentStatus {
            url: self.config.url.clone(),
            workspace: self.config.workspace.clone(),
            token_id: self.config.token_id.clone(),
            pid: std::process::id(),
            view_fresh: view.fresh(self.timing().fresh),
            view_age_ms: view
                .zones_at
                .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)),
            claims: view.claims.len(),
            board: view.board.len(),
            sessions: view.unread.len(),
            outbox: self.outbox.len(),
            rejected: self.outbox.rejected(),
            coordination_seq: self.coordination_seq.load(Ordering::Relaxed),
            registry_seq: self.registry_seq.load(Ordering::Relaxed),
        }
    }

    fn handle(&self, envelope: Envelope) -> Reply {
        if !matches!(envelope.request, Request::Ping) && envelope.workspace != self.config.workspace
        {
            let text = format!("this agent serves workspace {:?}", self.config.workspace);
            return Reply::failed(ClientError::Invalid(text));
        }
        match envelope.request {
            Request::Ping => Reply {
                status: Some(self.status()),
                ..Reply::default()
            },
            Request::Check { session, paths } => self.check(&session, paths),
            Request::Unread { session } => self.unread(&session),
            Request::TakeMail {
                session,
                limit,
                lease_seconds,
            } => self.take_mail(&session, limit, lease_seconds),
            Request::TakeEvents { session } => self.take_events(&session),
            Request::AckEvents { session, through } => self.ack_events(&session, through),
            Request::Touch {
                session,
                client,
                phase,
                write_paths,
            } => self.touch(&session, &client, phase, write_paths),
            Request::Call { call } => self.forward(call),
        }
    }

    fn apply_events(&self, page: &EventPage) {
        let mut touched = false;
        let mut view = self.write_view();
        for event in &page.events {
            if event.kind.starts_with("zone.") {
                view.zones_generation += 1;
                touched = true;
            } else if event.kind == "board.changed" {
                view.board_generation += 1;
                touched = true;
            } else if event.kind.starts_with("bus.") {
                let to = event.field("to").and_then(Value::as_str);
                match to {
                    Some(session) if session != "*" => {
                        if let Some(entry) = view.unread.get_mut(session) {
                            entry.generation += 1;
                            touched = true;
                        }
                    }
                    _ => {
                        for entry in view.unread.values_mut() {
                            entry.generation += 1;
                            touched = true;
                        }
                    }
                }
            }
        }
        view.confirm(Instant::now());
        drop(view);
        if touched {
            self.nudge();
        }
    }

    fn poll_stream(&self, stream: Stream, name: &str, seq: &AtomicI64) {
        let mut pause = self.timing().retry_min;
        let session = (stream == Stream::Coordination).then(|| self.session.clone());
        let backend = self.backend(&self.session);
        while !self.stopped() {
            let query = EventQuery {
                stream,
                after: seq.load(Ordering::Relaxed),
                wait_seconds: self.timing().poll_wait_seconds,
                session: session.clone(),
                types: Vec::new(),
            };
            let started = Instant::now();
            match backend.events(&query) {
                Ok(page) => {
                    pause = self.timing().retry_min;
                    // A server that answers an empty poll at once must not make this loop spin.
                    if page.events.is_empty() && started.elapsed() < pause {
                        self.pause(pause);
                    }
                    let last = page.last_seq(query.after);
                    if stream == Stream::Coordination {
                        self.apply_events(&page);
                    }
                    if last != query.after {
                        seq.store(last, Ordering::Relaxed);
                        let _ = fs::write(
                            self.state_dir.join(format!("cursor-{name}")),
                            last.to_string(),
                        );
                    }
                }
                Err(error) => {
                    if !matches!(error, Error::Unavailable(_)) {
                        eprintln!("lockyard agent: {name} events: {error}");
                    }
                    self.pause(pause);
                    pause = (pause * 2).min(self.timing().retry_max.min(MAX_POLL_PAUSE));
                }
            }
        }
    }

    fn refresh_zones(&self) {
        let (generation, started) = (self.read_view().zones_generation, Instant::now());
        if let Ok(claims) = self
            .backend(&self.session)
            .claims(&ClaimQuery::default(), 0)
        {
            let mut view = self.write_view();
            view.claims = claims;
            view.zones_clean = generation;
            view.zones_at = Some(started);
            view.zones_wall_at = Some(SystemTime::now());
        }
    }

    fn refresh_board(&self) {
        let (generation, started) = (self.read_view().board_generation, Instant::now());
        if let Ok(board) = self.backend(&self.session).board_list(None, 0) {
            let mut view = self.write_view();
            view.board = board;
            view.board_clean = generation;
            view.board_at = Some(started);
            view.board_wall_at = Some(SystemTime::now());
        }
    }

    fn refresh_unread(&self) {
        let window = self.timing().active_window;
        let live: HashSet<String> = {
            let mut sessions = self.sessions();
            sessions.retain(|_, track| track.heard.is_some_and(|at| at.elapsed() < window));
            sessions.keys().cloned().collect()
        };
        let limit = self.timing().fresh / 2;
        let wanted: Vec<(String, u64)> = {
            let mut view = self.write_view();
            view.unread.retain(|session, _| live.contains(session));
            let stale = view.unread.iter().filter(|(_, entry)| !entry.fresh(limit));
            stale
                .map(|(session, entry)| (session.clone(), entry.generation))
                .collect()
        };
        for (session, generation) in wanted {
            if let Ok(count) = self.backend(&session).unread(&session) {
                self.store_unread(&session, generation, count);
            }
        }
    }

    /// One thread keeps the view current, so a slow server delays nothing a hook waits for.
    fn upkeep(&self) {
        while !self.stopped() {
            let half = self.timing().fresh / 2;
            let (zones, board) = {
                let view = self.read_view();
                (
                    !view.fresh(half),
                    view.board_generation != view.board_clean
                        || view.board_at.is_none_or(|at| at.elapsed() >= half),
                )
            };
            if zones {
                self.refresh_zones();
            }
            if board {
                self.refresh_board();
            }
            self.refresh_unread();
            self.refresh_session_events();
            self.flush_activity();
            let mut signal = self.signal();
            if !signal.nudged && !signal.stop {
                signal = self
                    .wake
                    .wait_timeout(signal, self.timing().upkeep)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            signal.nudged = false;
        }
    }

    /// The only thread that sends outbox entries: one at a time, oldest first.
    fn drain(&self) {
        let mut pause = self.timing().retry_min;
        while !self.stopped() {
            let Some(entry) = self.outbox.head(self.timing().retry_max) else {
                continue;
            };
            let mut call = entry.call.clone();
            call.deadline_ms =
                Some(u64::try_from(self.timing().send_limit.as_millis()).unwrap_or(u64::MAX));
            match self.transport.call(&call) {
                Err(ClientError::RateLimited(error)) => {
                    let delay = error
                        .retry_after
                        .map(Duration::from_secs)
                        .unwrap_or(self.timing().retry_min)
                        .min(MAX_RETRY_AFTER);
                    self.outbox.defer(entry.n, delay);
                }
                Err(error) if error.is_outage() => {
                    let asked = error
                        .retry_after()
                        .map_or(Duration::ZERO, Duration::from_secs);
                    self.pause(pause.max(asked.min(MAX_RETRY_AFTER)));
                    pause = (pause * 2).min(self.timing().retry_max);
                }
                outcome => {
                    pause = self.timing().retry_min;
                    if let Err(error) = self.outbox.finish(entry.n, outcome) {
                        eprintln!("lockyard agent: cannot update the outbox: {error}");
                    }
                }
            }
        }
    }
}

fn answer<T: Transport + 'static>(shared: &Shared<T>, stream: UnixStream) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(IDLE_CONNECTION));
    let _ = stream.set_write_timeout(Some(IDLE_CONNECTION));
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take(MAX_REQUEST_BYTES)
            .read_line(&mut line)?;
        if read == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') {
            let error = ClientError::Invalid("request too long".into());
            write_reply(&mut writer, &Reply::failed(error))?;
            return Ok(());
        }
        let reply = match serde_json::from_str::<Envelope>(&line) {
            Ok(envelope) => shared.handle(envelope),
            Err(error) => Reply::failed(ClientError::Invalid(format!("bad request: {error}"))),
        };
        write_reply(&mut writer, &reply)?;
    }
}

fn write_reply(writer: &mut UnixStream, reply: &Reply) -> io::Result<()> {
    let mut line = serde_json::to_vec(reply).map_err(io::Error::other)?;
    line.push(b'\n');
    writer.write_all(&line)
}

fn load_seq(dir: &Path, name: &str) -> i64 {
    fs::read_to_string(dir.join(format!("cursor-{name}")))
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

fn state_folder(config: &AgentConfig) -> String {
    let identity = format!("{}\0{}", config.url, config.token_id);
    format!("target-{}", lockyard_cloud_client::token_id(&identity))
}

fn bind(path: &Path) -> io::Result<(File, UnixListener)> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("the socket has no folder"))?;
    private_dir(dir)?;
    // The lock decides who owns the socket. It dies with its process, so a crash leaves nothing to clean.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("agent.lock"))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another lockyard agent is running",
            ));
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok((lock, listener))
}

/// A running agent process.
pub struct Daemon<T: Transport + 'static> {
    shared: Arc<Shared<T>>,
    threads: Vec<JoinHandle<()>>,
    _lock: File,
}

impl<T: Transport + 'static> Daemon<T> {
    /// Binds the socket, restores the outbox and starts every thread.
    pub fn start(config: AgentConfig, transport: T) -> io::Result<Self> {
        let (lock, listener) = bind(&config.socket)?;
        private_dir(&config.state_root)?;
        let state_dir = config.state_root.join(state_folder(&config));
        private_dir(&state_dir)?;
        let outbox = Outbox::open(&state_dir)?;
        let shared = Arc::new(Shared {
            transport: Arc::new(transport),
            session: format!("lockyard-agent-{}", super::uid()),
            coordination_seq: AtomicI64::new(load_seq(&state_dir, "coordination")),
            registry_seq: AtomicI64::new(load_seq(&state_dir, "registry")),
            session_event_cursors: Mutex::new(HashMap::new()),
            session_events: Mutex::new(HashMap::new()),
            state_dir,
            config,
            view: RwLock::new(View {
                zones_generation: 1,
                board_generation: 1,
                ..View::default()
            }),
            sessions: Mutex::new(HashMap::new()),
            activity: Mutex::new(HashMap::new()),
            outbox,
            signal: Mutex::new(Signal::default()),
            wake: Condvar::new(),
        });
        let mut threads = Vec::new();
        let spawn = |name: &str, work: Box<dyn FnOnce() + Send>| {
            thread::Builder::new().name(name.to_string()).spawn(work)
        };
        let copy = Arc::clone(&shared);
        threads.push(spawn("upkeep", Box::new(move || copy.upkeep()))?);
        let copy = Arc::clone(&shared);
        threads.push(spawn(
            "machine-tick",
            Box::new(move || {
                while !copy.stopped() {
                    crate::guard::tick();
                    for _ in 0..50 {
                        if copy.stopped() {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }),
        )?);
        let copy = Arc::clone(&shared);
        threads.push(spawn("outbox", Box::new(move || copy.drain()))?);
        let copy = Arc::clone(&shared);
        threads.push(spawn(
            "coordination",
            Box::new(move || {
                copy.poll_stream(Stream::Coordination, "coordination", &copy.coordination_seq)
            }),
        )?);
        let copy = Arc::clone(&shared);
        threads.push(spawn(
            "registry",
            Box::new(move || copy.poll_stream(Stream::Registry, "registry", &copy.registry_seq)),
        )?);
        let copy = Arc::clone(&shared);
        threads.push(spawn(
            "accept",
            Box::new(move || {
                for stream in listener.incoming() {
                    if copy.stopped() {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let connection = Arc::clone(&copy);
                    thread::spawn(move || {
                        // A hook that told and left closes its end first. That is not a failure.
                        let _ = answer(&connection, stream);
                    });
                }
            }),
        )?);
        Ok(Self {
            shared,
            threads,
            _lock: lock,
        })
    }

    /// Runs until the process is killed. The outbox is on disk, so that needs no ceremony.
    pub fn wait(mut self) {
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
impl<T: Transport + 'static> Daemon<T> {
    /// Handles one request without a socket.
    fn handle(&self, request: Request) -> Reply {
        let workspace = self.shared.config.workspace.clone();
        self.shared.handle(Envelope { workspace, request })
    }
}

impl<T: Transport + 'static> Drop for Daemon<T> {
    fn drop(&mut self) {
        self.shared.stop();
        // Wake the accept loop, which sits in a blocking call.
        let _ = UnixStream::connect(&self.shared.config.socket);
        let _ = fs::remove_file(&self.shared.config.socket);
    }
}

#[cfg(test)]
mod tests {
    use super::super::socket::AgentSocket;
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    /// An in-memory server that can go down, hang or be made to refuse.
    #[derive(Default)]
    struct FakeServer {
        claims: Mutex<Vec<Value>>,
        unread: Mutex<i64>,
        events: Mutex<Vec<Value>>,
        writes: Mutex<Vec<Call>>,
        down: AtomicBool,
        /// Calls that are not long polls sleep this long, in milliseconds.
        hang_ms: AtomicUsize,
        /// Every request that is not an event poll.
        calls: Mutex<Vec<String>>,
        event_calls: AtomicUsize,
        refuse_with: Mutex<Option<u16>>,
    }

    impl FakeServer {
        fn writes_to(&self, tail: &str) -> Vec<Call> {
            self.writes
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.path.ends_with(tail))
                .cloned()
                .collect()
        }

        fn calls_to(&self, route: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.as_str() == route)
                .count()
        }

        fn claim(&self, id: i64, session: &str, path: &str) {
            let claim = json!({"id": id, "session": session, "paths": [path], "note": "busy"});
            self.claims.lock().unwrap().push(claim);
        }

        fn event(&self, kind: &str, to: Option<&str>) {
            let mut events = self.events.lock().unwrap();
            let seq = events.len() as i64 + 1;
            events.push(json!({"seq": seq, "type": kind, "payload": {"to": to}}));
        }
    }

    impl Transport for FakeServer {
        fn call(&self, call: &Call) -> Result<Value, ClientError> {
            let route = call.path.split('?').next().unwrap_or_default().to_string();
            if call.long_poll || route.ends_with("/events") {
                self.event_calls.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                if self.down.load(Ordering::SeqCst) {
                    return Err(ClientError::Transport("down".into()));
                }
                if route.contains("registry") {
                    return Ok(json!({"events": []}));
                }
                let after = call
                    .path
                    .split("after=")
                    .nth(1)
                    .and_then(|tail| tail.split('&').next());
                let after: i64 = after.and_then(|text| text.parse().ok()).unwrap_or(0);
                let events = self.events.lock().unwrap();
                let tail: Vec<Value> = events
                    .iter()
                    .filter(|event| event["seq"].as_i64() > Some(after))
                    .cloned()
                    .collect();
                return Ok(json!({"events": tail}));
            }
            self.calls.lock().unwrap().push(route.clone());
            let hang = self.hang_ms.load(Ordering::SeqCst);
            if hang > 0 {
                thread::sleep(Duration::from_millis(hang as u64));
            }
            if self.down.load(Ordering::SeqCst) {
                return Err(ClientError::Transport("down".into()));
            }
            let marked_bad = call.body.as_ref().is_some_and(|body| body["body"] == "bad");
            let refusal = if marked_bad {
                Some(404)
            } else {
                *self.refuse_with.lock().unwrap()
            };
            if let Some(status) = refusal {
                return Err(ClientError::from_api(lockyard_cloud_client::ApiError {
                    status,
                    ..Default::default()
                }));
            }
            match route.as_str() {
                "/api/v1/zones/claims" if call.method == "GET" => {
                    Ok(json!({"claims": *self.claims.lock().unwrap()}))
                }
                "/api/v1/zones/check" => Ok(json!({"paths": [{"path": "src", "status": "free"}]})),
                "/api/v1/bus/board" => Ok(json!([{"key": "k", "value": "v"}])),
                "/api/v1/bus/inbox" => {
                    let unread = *self.unread.lock().unwrap();
                    let messages: Vec<Value> = (1..=unread)
                        .map(|id| json!({"id": id, "body": "hi"}))
                        .collect();
                    Ok(json!({"messages": messages}))
                }
                "/api/v1/bus/inbox/claim" => {
                    self.writes.lock().unwrap().push(call.clone());
                    Ok(json!({"claimed": call.body.as_ref().unwrap()["ids"]}))
                }
                _ => {
                    self.writes.lock().unwrap().push(call.clone());
                    Ok(json!({"id": 1}))
                }
            }
        }
    }

    fn timing() -> Timing {
        Timing {
            fresh: Duration::from_millis(400),
            deadline: Duration::from_millis(150),
            poll_wait_seconds: 0,
            upkeep: Duration::from_millis(10),
            send_limit: Duration::from_millis(500),
            mail_wait: Duration::from_millis(100),
            retry_min: Duration::from_millis(5),
            retry_max: Duration::from_millis(20),
            beat_every: Duration::from_millis(60),
            activity_every: Duration::from_millis(60),
            active_window: Duration::from_secs(60),
        }
    }

    struct Rig {
        dir: tempfile::TempDir,
        server: Arc<FakeServer>,
        daemon: Daemon<Arc<FakeServer>>,
    }

    fn config(dir: &Path, timing: Timing) -> AgentConfig {
        AgentConfig {
            url: "https://example.test".into(),
            workspace: "team".into(),
            token_id: "t".into(),
            socket: dir.join("run/agent.sock"),
            state_root: dir.join("state"),
            timing,
        }
    }

    #[test]
    fn outbox_identity_separates_same_label_across_targets() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = config(dir.path(), timing());
        let mut second = first.clone();
        second.url = "https://other.test".into();
        let mut third = first.clone();
        third.token_id = "other-token".into();
        assert_ne!(state_folder(&first), state_folder(&second));
        assert_ne!(state_folder(&first), state_folder(&third));
        first.workspace = "different-label".into();
        assert_eq!(
            state_folder(&first),
            state_folder(&config(dir.path(), timing()))
        );
    }

    fn start_with(timing: Timing, prepare: impl FnOnce(&FakeServer)) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(FakeServer::default());
        prepare(&server);
        let daemon = Daemon::start(config(dir.path(), timing), Arc::clone(&server)).unwrap();
        Rig {
            dir,
            server,
            daemon,
        }
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < end, "timed out: {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn view_ready(rig: &Rig) {
        wait_for("a fresh view", || {
            rig.daemon
                .shared
                .read_view()
                .fresh(Duration::from_millis(200))
        });
    }

    fn check(session: &str, path: &str) -> Request {
        Request::Check {
            session: session.into(),
            paths: vec![path.into()],
        }
    }

    fn mail(body: &str) -> Request {
        Request::Call {
            call: Call::write(
                "me",
                "POST",
                "/api/v1/bus/messages".into(),
                json!({"to": "bob", "body": body}),
            ),
        }
    }

    fn claim_call() -> Request {
        Request::Call {
            call: Call::write(
                "me",
                "POST",
                "/api/v1/zones/claims".into(),
                json!({"paths": ["src"]}),
            ),
        }
    }

    fn bodies(calls: &[Call]) -> Vec<String> {
        calls
            .iter()
            .map(|call| {
                call.body.as_ref().unwrap()["body"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn a_fresh_view_answers_from_memory_in_under_5_ms_with_no_server_call() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |server| {
                server.claim(1, "bob", "src");
            },
        );
        view_ready(&rig);
        let before = rig.server.calls_to("/api/v1/zones/check");
        let socket = AgentSocket::connect(
            &rig.dir.path().join("run/agent.sock"),
            "https://example.test",
            "team",
            Duration::from_secs(1),
        )
        .unwrap();
        let mut times = Vec::new();
        for _ in 0..200 {
            let started = Instant::now();
            let held = socket.ask(&check("me", "src/a.rs")).unwrap();
            times.push(started.elapsed());
            assert_eq!(held.source, Some(Source::View));
            let found = held.checks.unwrap().remove(0);
            assert_eq!(found.status, CheckStatus::Held);
            assert_eq!(found.holder.unwrap().agent, "bob");
        }
        // One outlier on a busy machine says nothing about the code, so this reads the 95th percentile.
        times.sort();
        let usual = times[times.len() * 95 / 100];
        assert!(usual < Duration::from_millis(5), "p95 was {usual:?}");
        assert_eq!(rig.server.calls_to("/api/v1/zones/check"), before);
    }

    #[test]
    fn the_view_tells_free_own_held_and_honours_exclusions_and_sharing() {
        let view = View {
            claims: vec![
                serde_json::from_value(json!({"id": 1, "session": "bob", "paths": ["src"], "excluded_paths": ["src/mine"]})).unwrap(),
                serde_json::from_value(json!({"id": 2, "session": "me", "paths": ["src/mine"]})).unwrap(),
                serde_json::from_value(json!({"id": 3, "session": "bob", "paths": ["docs"], "mode": "shared"})).unwrap(),
                serde_json::from_value(json!({"id": 4, "session": "me", "paths": ["docs/a"], "mode": "shared"})).unwrap(),
            ],
            ..View::default()
        };
        let status = |path: &str| view.check("me", &[path.to_string()]).remove(0).status;
        assert_eq!(status("other"), CheckStatus::Free);
        assert_eq!(status("src/x"), CheckStatus::Held);
        assert_eq!(status("src/mine/a"), CheckStatus::Own);
        assert_eq!(status("docs/a"), CheckStatus::Own);
        assert_eq!(
            status("docs/b"),
            CheckStatus::Held,
            "no shared claim of mine covers it"
        );
    }

    #[test]
    fn a_view_that_aged_during_suspend_is_stale_after_wake() {
        let mut view = View {
            zones_at: Some(Instant::now()),
            zones_wall_at: Some(SystemTime::now() - Duration::from_secs(60)),
            ..View::default()
        };
        assert!(!view.fresh(Duration::from_secs(30)));
        view.confirm(Instant::now());
        assert!(view.fresh(Duration::from_secs(30)));
    }

    #[test]
    fn a_claim_of_an_unavailable_holder_stops_blocking_in_the_view() {
        let view = View {
            claims: vec![
                serde_json::from_value(
                    json!({"id": 1, "session": "bob", "paths": ["src"], "holder_available": false}),
                )
                .unwrap(),
                serde_json::from_value(
                    json!({"id": 2, "session": "bob", "paths": ["docs"], "holder_available": true}),
                )
                .unwrap(),
            ],
            ..View::default()
        };
        let status = |path: &str| view.check("me", &[path.to_string()]).remove(0).status;
        assert_eq!(status("src/a"), CheckStatus::Free);
        assert_eq!(status("docs/a"), CheckStatus::Held);
        assert_eq!(
            view.check("bob", &["src/a".to_string()]).remove(0).status,
            CheckStatus::Own,
            "a session that comes back still holds its own claim"
        );
    }

    #[test]
    fn unread_answers_from_memory_after_the_first_count_and_an_event_refreshes_it() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |server| {
                *server.unread.lock().unwrap() = 2;
            },
        );
        view_ready(&rig);
        let ask = || Request::Unread {
            session: "me".into(),
        };
        let first = rig.daemon.handle(ask());
        assert_eq!(
            (first.unread, first.source),
            (Some(2), Some(Source::Server))
        );
        let second = rig.daemon.handle(ask());
        assert_eq!(
            (second.unread, second.source),
            (Some(2), Some(Source::View))
        );
        *rig.server.unread.lock().unwrap() = 3;
        rig.server.event("bus.unread", Some("me"));
        wait_for("the new count", || {
            let reply = rig.daemon.handle(ask());
            reply.unread == Some(3) && reply.source == Some(Source::View)
        });
    }

    #[test]
    fn a_stale_view_makes_one_server_call_and_never_answers_from_memory() {
        let rig = start_with(timing(), |server| server.claim(1, "bob", "src"));
        view_ready(&rig);
        rig.daemon.shared.stop();
        // The upkeep threads are gone, so the view can only age.
        wait_for("the view to go stale", || {
            !rig.daemon.shared.read_view().fresh(timing().fresh)
        });
        let before = rig.server.calls_to("/api/v1/zones/check");
        let reply = rig.daemon.handle(check("me", "src"));
        assert_eq!(reply.source, Some(Source::Server));
        assert_eq!(
            reply.checks.unwrap()[0].status,
            CheckStatus::Free,
            "the server's word, not the old claim"
        );
        assert_eq!(rig.server.calls_to("/api/v1/zones/check"), before + 1);
    }

    #[test]
    fn an_event_that_the_view_has_not_absorbed_makes_it_stale_at_once() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |_| {},
        );
        view_ready(&rig);
        rig.daemon.shared.write_view().zones_generation += 1;
        assert!(!rig.daemon.shared.read_view().fresh(Duration::from_secs(30)));
    }

    #[test]
    fn a_snapshot_overtaken_by_an_event_stays_dirty() {
        let mut view = View {
            zones_generation: 2,
            zones_clean: 1,
            zones_at: Some(Instant::now()),
            ..View::default()
        };
        view.confirm(Instant::now());
        assert!(
            !view.fresh(Duration::from_secs(30)),
            "a poll must not bless a view with an unread event"
        );
        view.zones_clean = 2;
        view.confirm(Instant::now());
        assert!(view.fresh(Duration::from_secs(30)));
    }

    #[test]
    fn a_new_claim_elsewhere_reaches_the_view_through_an_event() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |_| {},
        );
        view_ready(&rig);
        let free = rig.daemon.handle(check("me", "src"));
        assert_eq!(free.checks.unwrap()[0].status, CheckStatus::Free);
        rig.server.claim(1, "bob", "src");
        rig.server.event("zone.claimed", None);
        wait_for("the claim to arrive", || {
            let reply = rig.daemon.handle(check("me", "src/x"));
            reply.source == Some(Source::View)
                && reply.checks.unwrap()[0].status == CheckStatus::Held
        });
    }

    #[test]
    fn a_hung_server_gives_unknown_at_the_deadline() {
        let rig = start_with(timing(), |_| {});
        view_ready(&rig);
        rig.daemon.shared.stop();
        wait_for("the view to go stale", || {
            !rig.daemon.shared.read_view().fresh(timing().fresh)
        });
        rig.server.hang_ms.store(2_000, Ordering::SeqCst);
        let started = Instant::now();
        let reply = rig.daemon.handle(check("me", "src"));
        let took = started.elapsed();
        assert_eq!(reply.source, Some(Source::None));
        assert_eq!(reply.checks.unwrap()[0].status, CheckStatus::Unknown);
        assert!(
            took >= timing().deadline && took < Duration::from_millis(600),
            "took {took:?}"
        );
        let unread = rig.daemon.handle(Request::Unread {
            session: "me".into(),
        });
        assert_eq!((unread.unread, unread.source), (None, Some(Source::None)));
    }

    #[test]
    fn the_default_limits_are_the_contract() {
        let timing = Timing::default();
        assert_eq!(timing.fresh, Duration::from_secs(30));
        assert_eq!(timing.deadline, Duration::from_millis(800));
        assert!(timing.poll_wait_seconds <= lockyard_cloud_client::MAX_POLL_WAIT_SECONDS);
    }

    #[test]
    fn during_an_outage_mail_is_queued_and_replays_in_order_with_heartbeats_and_activity() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |server| server.claim(7, "me", "src"),
        );
        view_ready(&rig);
        rig.server.down.store(true, Ordering::SeqCst);
        let first = rig.daemon.handle(mail("one"));
        assert_eq!(first.value.unwrap()["queued"], true);
        let touch = Request::Touch {
            session: "me".into(),
            client: "hook".into(),
            phase: Phase::Post,
            write_paths: vec!["src/a.rs".into()],
        };
        rig.daemon.handle(touch);
        rig.daemon.handle(mail("two"));
        let seen = Call::write(
            "me",
            "POST",
            "/api/v1/bus/inbox/seen".into(),
            json!({"ids": [4]}),
        );
        assert_eq!(
            rig.daemon
                .handle(Request::Call { call: seen })
                .value
                .unwrap()["queued"],
            true
        );
        rig.daemon.handle(mail("three"));
        assert!(rig.server.writes.lock().unwrap().is_empty());
        let queued = rig.daemon.shared.outbox.len();
        assert!(queued >= 5, "{queued}");

        rig.server.down.store(false, Ordering::SeqCst);
        wait_for("the queue to drain", || rig.daemon.shared.outbox.len() == 0);
        assert_eq!(
            bodies(&rig.server.writes_to("/bus/messages")),
            ["one", "two", "three"]
        );
        let order: Vec<String> = rig
            .server
            .writes
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.path.clone())
            .collect();
        let position = |tail: &str| order.iter().position(|path| path.ends_with(tail)).unwrap();
        assert!(position("/presence") < position("/activity"), "{order:?}");
        assert!(
            position("/activity") < position("/bus/inbox/seen"),
            "{order:?}"
        );
        assert!(
            order
                .iter()
                .filter(|path| path.ends_with("/bus/messages"))
                .count()
                == 3
        );
    }

    #[test]
    fn the_queue_survives_a_restart_and_keeps_its_keys_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(FakeServer::default());
        server.down.store(true, Ordering::SeqCst);
        let daemon = Daemon::start(config(dir.path(), timing()), Arc::clone(&server)).unwrap();
        let keep = Call::write(
            "me",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"body": "one"}),
        );
        let key = keep.key.clone();
        daemon.handle(Request::Call { call: keep });
        daemon.handle(mail("two"));
        drop(daemon);
        thread::sleep(Duration::from_millis(50));
        server.down.store(false, Ordering::SeqCst);
        let again = Daemon::start(config(dir.path(), timing()), Arc::clone(&server)).unwrap();
        wait_for("the queue to drain", || again.shared.outbox.len() == 0);
        let sent = server.writes_to("/bus/messages");
        assert_eq!(bodies(&sent), ["one", "two"]);
        assert_eq!(sent[0].key, key);
    }

    #[test]
    fn a_claim_during_an_outage_fails_now_and_is_never_sent_later() {
        let rig = start_with(timing(), |_| {});
        view_ready(&rig);
        rig.server.down.store(true, Ordering::SeqCst);
        let refused = rig.daemon.handle(claim_call());
        assert!(
            matches!(refused.error, Some(ClientError::Transport(_))),
            "{refused:?}"
        );
        assert_eq!(rig.daemon.shared.outbox.len(), 0);
        rig.server.down.store(false, Ordering::SeqCst);
        rig.daemon.handle(mail("after"));
        wait_for("the queue to drain", || rig.daemon.shared.outbox.len() == 0);
        assert!(
            rig.server.writes_to("/zones/claims").is_empty(),
            "the refused claim must stay refused"
        );
    }

    #[test]
    fn a_frozen_server_refuses_claims_and_holds_mail() {
        let rig = start_with(timing(), |_| {});
        view_ready(&rig);
        *rig.server.refuse_with.lock().unwrap() = Some(503);
        assert!(matches!(
            rig.daemon.handle(claim_call()).error,
            Some(ClientError::Frozen(_))
        ));
        assert_eq!(
            rig.daemon.handle(mail("wait")).value.unwrap()["queued"],
            true
        );
        *rig.server.refuse_with.lock().unwrap() = None;
        wait_for("the mail to go", || {
            rig.server.writes_to("/bus/messages").len() == 1
        });
    }

    #[test]
    fn mail_the_server_refuses_reaches_the_sender_and_leaves_the_queue() {
        let rig = start_with(
            Timing {
                mail_wait: Duration::from_secs(2),
                ..timing()
            },
            |_| {},
        );
        *rig.server.refuse_with.lock().unwrap() = Some(404);
        let reply = rig.daemon.handle(mail("typo"));
        assert!(
            matches!(reply.error, Some(ClientError::NotFound(_))),
            "{reply:?}"
        );
        assert_eq!(rig.daemon.shared.outbox.len(), 0);
    }

    #[test]
    fn a_refused_entry_does_not_block_the_ones_behind_it() {
        let rig = start_with(timing(), |server| server.down.store(true, Ordering::SeqCst));
        rig.daemon.handle(mail("bad"));
        rig.daemon.handle(mail("good"));
        rig.server.down.store(false, Ordering::SeqCst);
        wait_for("the queue to drain", || rig.daemon.shared.outbox.len() == 0);
        assert_eq!(bodies(&rig.server.writes_to("/bus/messages")), ["good"]);
    }

    #[test]
    fn mail_is_taken_under_a_delivery_claim_and_marked_only_by_a_later_seen() {
        let rig = start_with(timing(), |server| *server.unread.lock().unwrap() = 2);
        let taken = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 5,
            lease_seconds: 60,
        });
        assert_eq!(taken.messages.unwrap().len(), 2);
        let claims = rig.server.writes_to("/bus/inbox/claim");
        assert_eq!(
            claims[0].body.as_ref().unwrap(),
            &json!({"ids": [1, 2], "lease_seconds": 60})
        );
        assert!(claims[0].key.is_some());
        assert!(rig.server.writes_to("/bus/inbox/seen").is_empty());
    }

    #[test]
    fn taking_mail_during_an_outage_is_unknown_not_empty() {
        let rig = start_with(timing(), |server| server.down.store(true, Ordering::SeqCst));
        let taken = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 5,
            lease_seconds: 60,
        });
        assert_eq!((taken.messages, taken.source), (None, Some(Source::None)));
    }

    #[test]
    fn heartbeats_are_spaced_but_a_state_change_goes_at_once() {
        let rig = start_with(
            Timing {
                beat_every: Duration::from_secs(60),
                ..timing()
            },
            |_| {},
        );
        let touch = |phase| Request::Touch {
            session: "me".into(),
            client: "hook".into(),
            phase,
            write_paths: Vec::new(),
        };
        rig.daemon.handle(touch(Phase::Post));
        rig.daemon.handle(touch(Phase::Post));
        rig.daemon.handle(touch(Phase::Pre));
        rig.daemon.handle(touch(Phase::Pre));
        rig.daemon.handle(touch(Phase::End));
        wait_for("the beats", || rig.server.writes_to("/presence").len() == 3);
        let beats = rig.server.writes_to("/presence");
        assert_eq!(
            beats[1].body.as_ref().unwrap()["activity"]["tool_running"],
            true
        );
        assert_eq!(
            beats[2].body.as_ref().unwrap()["activity"]["state"],
            "ended"
        );
    }

    #[test]
    fn activity_is_batched_per_claim() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |server| server.claim(7, "me", "src"),
        );
        view_ready(&rig);
        let write = |path: &str| Request::Touch {
            session: "me".into(),
            client: "hook".into(),
            phase: Phase::Post,
            write_paths: vec![path.into()],
        };
        for path in ["src/a", "src/b", "src/c", "elsewhere"] {
            rig.daemon.handle(write(path));
        }
        for _ in 0..10 {
            rig.daemon.handle(write("src/a"));
        }
        wait_for("dirty path reporting", || {
            rig.server.writes_to("/zones/dirty").len() >= 3
        });
        let dirty = rig.server.writes_to("/zones/dirty");
        assert_eq!(
            dirty.len(),
            3,
            "unclaimed and repeated paths are not reported twice"
        );
        assert_eq!(dirty[0].body.as_ref().unwrap()["paths"][0]["path"], "src/a");
        assert_eq!(
            dirty[0].body.as_ref().unwrap()["paths"][0]["owner_session"],
            "me"
        );
        wait_for("both batches", || {
            rig.server.writes_to("/activity").len() == 2
        });
        let batches = rig.server.writes_to("/activity");
        assert_eq!(batches[0].body.as_ref().unwrap()["paths"], json!(["src/a"]));
        // Activity keeps counting repeated writes of src/a, which only the dirty report folds.
        let second = batches[1].body.as_ref().unwrap()["paths"].to_string();
        assert!(
            second.contains("src/b") && second.contains("src/c"),
            "{second}"
        );
        assert_eq!(batches[1].session, "me");
        rig.daemon.handle(write("src/a"));
        thread::sleep(Duration::from_millis(30));
        assert_eq!(rig.server.writes_to("/zones/dirty").len(), 3);
    }

    #[test]
    fn both_streams_are_followed_and_the_status_reports_them() {
        let rig = start_with(timing(), |server| server.event("board.changed", None));
        wait_for("the cursor", || {
            rig.daemon
                .handle(Request::Ping)
                .status
                .unwrap()
                .coordination_seq
                == 1
        });
        let status = rig.daemon.handle(Request::Ping).status.unwrap();
        assert_eq!(
            (status.workspace.as_str(), status.pid),
            ("team", std::process::id())
        );
        wait_for("the board", || {
            rig.daemon.handle(Request::Ping).status.unwrap().board == 1
        });
    }

    #[test]
    fn session_events_repeat_until_the_hook_acknowledges_written_output() {
        let rig = start_with(
            Timing {
                upkeep: Duration::from_secs(1),
                ..timing()
            },
            |server| server.event("zone.requested", Some("alice")),
        );
        let take = Request::TakeEvents {
            session: "alice".into(),
        };
        rig.daemon.handle(Request::Touch {
            session: "alice".into(),
            client: "test".into(),
            phase: Phase::Post,
            write_paths: Vec::new(),
        });
        wait_for("session event cache", || {
            rig.daemon
                .shared
                .session_events
                .lock()
                .unwrap()
                .get("alice")
                .is_some_and(|cache| !cache.events.is_empty())
        });
        let polls = rig.server.event_calls.load(Ordering::SeqCst);
        let first = rig.daemon.handle(take.clone()).events.unwrap();
        assert_eq!(
            rig.server.event_calls.load(Ordering::SeqCst),
            polls,
            "TakeEvents must read memory only"
        );
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, "zone.requested");
        assert_eq!(rig.daemon.handle(take.clone()).events.unwrap(), first);
        rig.daemon.handle(Request::AckEvents {
            session: "alice".into(),
            through: first[0].seq,
        });
        assert!(rig.daemon.handle(take).events.unwrap().is_empty());
    }

    #[test]
    fn a_board_read_answers_from_a_fresh_view() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |_| {},
        );
        wait_for("the board", || {
            rig.daemon.handle(Request::Ping).status.unwrap().board == 1
        });
        rig.server.down.store(true, Ordering::SeqCst);
        let call = Call::get("me", "/api/v1/bus/board".into());
        let reply = rig.daemon.handle(Request::Call { call });
        assert_eq!(reply.source, Some(Source::View));
        assert_eq!(reply.value.unwrap()[0]["key"], "k");
    }

    #[test]
    fn the_socket_is_0600_in_a_0700_folder_and_one_process_owns_it() {
        let rig = start_with(timing(), |_| {});
        let socket = rig.dir.path().join("run/agent.sock");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&socket), 0o600);
        assert_eq!(mode(socket.parent().unwrap()), 0o700);
        let folder = socket.parent().unwrap();
        fs::set_permissions(folder, fs::Permissions::from_mode(0o755)).unwrap();
        let open_folder = AgentSocket::connect(
            &socket,
            "https://example.test",
            "team",
            Duration::from_secs(1),
        );
        assert!(
            open_folder.is_none(),
            "a shared folder proves nothing about the socket"
        );
        fs::set_permissions(folder, fs::Permissions::from_mode(0o700)).unwrap();
        let second = Daemon::start(
            config(rig.dir.path(), timing()),
            Arc::new(FakeServer::default()),
        );
        assert_eq!(
            second.err().map(|error| error.kind()),
            Some(io::ErrorKind::AddrInUse)
        );
    }

    #[test]
    fn a_told_touch_is_processed_after_the_client_closes() {
        let rig = start_with(timing(), |_| {});
        let mut stream = UnixStream::connect(&rig.daemon.shared.config.socket).unwrap();
        let envelope = Envelope {
            workspace: "team".into(),
            request: Request::Touch {
                session: "alice".into(),
                client: "test".into(),
                phase: Phase::Prompt,
                write_paths: Vec::new(),
            },
        };
        serde_json::to_writer(&mut stream, &envelope).unwrap();
        stream.write_all(b"\n").unwrap();
        drop(stream);
        wait_for("closed tell heartbeat", || {
            rig.server.writes_to("/presence").len() == 1
        });
    }

    #[test]
    fn a_request_for_another_workspace_or_a_bad_line_is_refused() {
        let rig = start_with(timing(), |_| {});
        let path = rig.dir.path().join("run/agent.sock");
        assert!(
            AgentSocket::connect(
                &path,
                "https://example.test",
                "other",
                Duration::from_secs(1)
            )
            .is_none()
        );
        assert!(
            AgentSocket::connect(
                &path,
                "https://elsewhere.test",
                "team",
                Duration::from_secs(1)
            )
            .is_none()
        );
        let wrong = rig.daemon.shared.handle(Envelope {
            workspace: "other".into(),
            request: check("me", "src"),
        });
        assert!(matches!(wrong.error, Some(ClientError::Invalid(_))));
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.write_all(b"not json\n").unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let reply: Reply = serde_json::from_str(&line).unwrap();
        assert!(matches!(reply.error, Some(ClientError::Invalid(_))));
    }

    #[test]
    fn write_classes_put_only_mail_heartbeats_and_activity_in_the_outbox() {
        let class = |method: &str, path: &str| {
            write_class(&Call {
                method: method.into(),
                path: path.into(),
                ..Call::default()
            })
        };
        assert_eq!(class("POST", "/api/v1/bus/messages"), WriteClass::Mail);
        assert_eq!(
            class("POST", "/api/v1/bus/messages/3/reply"),
            WriteClass::Mail
        );
        assert_eq!(
            class("POST", "/api/v1/bus/messages/3/ack"),
            WriteClass::Mail
        );
        assert_eq!(
            class("POST", "/api/v1/bus/inbox/seen"),
            WriteClass::Background
        );
        assert_eq!(class("POST", "/api/v1/presence"), WriteClass::Background);
        assert_eq!(
            class("POST", "/api/v1/zones/claims/3/activity"),
            WriteClass::Background
        );
        assert_eq!(class("POST", "/api/v1/zones/dirty"), WriteClass::Background);
        for direct in [
            "/api/v1/zones/claims",
            "/api/v1/zones/claims/3/renew",
            "/api/v1/zones/claims/3/add-path",
            "/api/v1/zones/queue",
            "/api/v1/bus/inbox/claim",
            "/api/v1/bus/board",
            "/api/v1/bus/tasks",
        ] {
            assert_eq!(class("POST", direct), WriteClass::Direct, "{direct}");
        }
        assert_eq!(
            class("DELETE", "/api/v1/zones/claims/3"),
            WriteClass::Direct
        );
    }
}
