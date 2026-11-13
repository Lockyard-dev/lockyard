// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! The agent process.
//!
//! A view is trusted only while it is younger than [`Timing::fresh`] and no event has arrived that it
//! does not reflect. Each event bumps a generation, and a snapshot records the generation it started
//! from, so an event that lands during a snapshot leaves the view dirty. Age is measured on this
//! process's monotonic clock **and** wall clock (so a laptop sleep cannot keep a frozen view). Leases
//! are never compared with either clock: a claim leaves the view only when the server says so.
//!
//! **Fail closed:** a hook that asks a stale or missing view gets `Unknown`, and the hook refuses the
//! edit. The mirror accelerates path checks (target p95 ≤ 10 ms when fresh); it must never allow a
//! write the server would refuse. The written guarantee is `docs/cloud-mirror.md`.

use super::outbox::Outbox;
use super::private_dir;
use super::wire::{AgentStatus, Envelope, Phase, Reply, Request, Source};
use lockyard_cloud_client::{
    Call, Cancellation, ClientError, CloudBackend, RepositoryTransport, Transport, ulid,
};
use lockyard_core::proto::{
    AccessRecord, ActivityRequest, BoardEntry, CheckStatus, Claim, ClaimMode, ClaimQuery,
    DirtyPath, EventPage, EventQuery, InboxQuery, LostClaim, Message, PathCheck, PresenceBeat,
    QueueEntry, SessionActivity, SessionState, Stamp, Stream, rfc3339,
};
use lockyard_core::zones::Conflict;
use lockyard_core::{Backend, Error, ZonePath};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};

use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use lockyard_core::windows::ipc::{LocalListener as UnixListener, LocalStream as UnixStream};

/// A request line longer than this is refused. Mail is limited to 8 KiB, with room for its envelope.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
/// A client that says nothing for this long loses its connection.
const IDLE_CONNECTION: Duration = Duration::from_secs(60);
/// A server's `Retry-After` delays the outbox by at most this long.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);
/// Longest pause of a failed event poll. A refresh can make the view look fresh again while the poll
/// still sleeps, and until it wakes the view does not hear about new claims.
const MAX_POLL_PAUSE: Duration = Duration::from_secs(2);
const MAIL_BUFFER_LIMIT: usize = 10;
const MAIL_DELIVERY_LEASE: Duration = Duration::from_secs(60);
/// Bound a local aggregate, including admission queue wait, separately from the cold CLI deadline.
const STATUS_READ_LIMIT: Duration = Duration::from_millis(2600);
/// A blocked resolver must not accumulate an unbounded group of HTTP workers for every hook.
const MAX_STATUS_READS: usize = 3;
/// Tell credentialed callers to go direct only when an abandoned read occupies a generation AND no
/// generation is free: while one is free the agent still answers faster than a cold direct read.
fn abandoned_read_advisory(running: usize, any_abandoned: bool) -> Option<bool> {
    (any_abandoned && running >= MAX_STATUS_READS).then_some(true)
}
/// Peer EOF is checked between queue wakes, independently of the HTTP worker's lifetime.
const STATUS_PEER_CHECK: Duration = Duration::from_millis(5);
const STATUS_PEER_READ: Duration = Duration::from_millis(1);
/// Queue callers rather than sending an overflow herd to cold HTTP transports.
const MAX_STATUS_CALLERS: usize = 128;
/// A tiny collection window lets simultaneous identical calls share a *new* network generation.
const STATUS_COALESCE_WINDOW: Duration = Duration::from_millis(2);

#[derive(Default)]
struct StatusReads {
    running: usize,
    next: u64,
    pending: VecDeque<u64>,
    batches: HashMap<u64, StatusBatch>,
}

struct StatusBatch {
    session: String,
    repository: Option<String>,
    ready_at: Instant,
    deadline: Instant,
    waiters: usize,
    running: bool,
    reply: Option<Reply>,
    cancellation: Cancellation,
}

impl StatusReads {
    fn leave(&mut self, id: u64) {
        let remove = self.batches.get_mut(&id).is_some_and(|batch| {
            batch.waiters -= 1;
            if batch.waiters == 0 {
                batch.cancellation.cancel();
            }
            batch.waiters == 0 && !batch.running
        });
        if remove {
            self.batches.remove(&id);
            self.pending.retain(|queued| *queued != id);
        }
    }
}

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
struct LostMarks {
    marks: Vec<LostClaim>,
    generation: u64,
    clean: u64,
    at: Option<Instant>,
    wall_at: Option<SystemTime>,
}

struct MailBuffer {
    messages: VecDeque<Message>,
    reserved_at: Instant,
    lease_expires_at: Instant,
}

impl LostMarks {
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
    extras_stale: bool,
    queue: Vec<QueueEntry>,
    requests: Vec<AccessRecord>,
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
    mail: HashMap<String, MailBuffer>,
    lost: HashMap<String, LostMarks>,
    lost_refresh_generation: u64,
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
        let repository = lockyard_core::repository::split(raw).0;
        // The server uses .NET OrdinalIgnoreCase. ASCII folding cannot safely answer
        // Unicode comparisons, including exclusions and Unicode holders of ASCII paths.
        if self.claims.iter().any(|claim| {
            claim
                .case_insensitive_paths
                .unwrap_or(cfg!(any(target_os = "macos", windows)))
                && claim
                    .paths
                    .iter()
                    .any(|held| lockyard_core::repository::split(held).0 == repository)
                && (!raw.is_ascii()
                    || claim
                        .paths
                        .iter()
                        .chain(&claim.excluded_paths)
                        .any(|held| !held.is_ascii()))
        }) {
            return PathCheck {
                path: raw.to_string(),
                status: CheckStatus::Unknown,
                holder: None,
            };
        }
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
                        .find(|held| {
                            ZonePath::stored((*held).clone()).overlaps_with_case(
                                &path,
                                claim
                                    .case_insensitive_paths
                                    .unwrap_or(cfg!(any(target_os = "macos", windows))),
                            )
                        })
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
    let fold = claim
        .case_insensitive_paths
        .unwrap_or(cfg!(any(target_os = "macos", windows)));
    let inside = |list: &[String]| {
        list.iter()
            .any(|held| ZonePath::stored(held.clone()).overlaps_with_case(path, fold))
    };
    let excluded = claim.excluded_paths.iter().any(|gap| {
        let gap = ZonePath::stored(gap.clone());
        gap.overlaps_with_case(path, fold) && gap.as_str().len() <= path.as_str().len()
    });
    inside(&claim.paths) && !excluded
}

#[derive(Default)]
struct SessionTrack {
    /// Outstanding refreshes retain this identity across removal and re-registration.
    incarnation: Arc<()>,
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
    /// Successful namespace negotiations live only as long as this daemon instance.
    repository_capabilities: Mutex<HashSet<String>>,
    status_reads: Mutex<StatusReads>,
    status_ready: Condvar,
    status_pool_warm: Arc<AtomicBool>,
    /// Sessions whose caller-driven status read is on the network right now. That read fetches
    /// the unread count itself, so upkeep must not send a second inbox read for them.
    status_network_sessions: Mutex<HashMap<String, usize>>,
}

/// Marks one caller-driven status read as in flight for its session until dropped.
struct StatusNetworkMark<'a> {
    sessions: &'a Mutex<HashMap<String, usize>>,
    session: String,
}

impl<'a> StatusNetworkMark<'a> {
    fn new(sessions: &'a Mutex<HashMap<String, usize>>, session: &str) -> Self {
        *sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(session.to_string())
            .or_default() += 1;
        Self {
            sessions,
            session: session.to_string(),
        }
    }
}

impl Drop for StatusNetworkMark<'_> {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = sessions.get_mut(&self.session) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                sessions.remove(&self.session);
            }
        }
    }
}

/// A per-request read adapter. Only the harmless unread count may come from the daemon's view.
struct StatusTransport<T: Transport> {
    inner: Arc<T>,
    session: String,
    unread: Option<i64>,
    parallel: bool,
    pool_warm: Arc<AtomicBool>,
    cancellation: Cancellation,
}

impl<T: Transport> Transport for StatusTransport<T> {
    fn registry_auto_area(&self, session: &str) -> Result<bool, ClientError> {
        self.inner.registry_auto_area(session)
    }
    fn status_registry_assignee_supported(
        &self,
        deadline: Instant,
        _cancellation: Option<&Cancellation>,
    ) -> bool {
        self.inner
            .status_registry_assignee_supported(deadline, Some(&self.cancellation))
    }

    fn status_registry_call(
        &self,
        call: &Call,
    ) -> Result<lockyard_cloud_client::StatusRegistryPage, ClientError> {
        if self.cancellation.is_cancelled() {
            return Err(ClientError::Transport("status generation cancelled".into()));
        }
        let mut call = call.clone();
        call.cancellation = Some(self.cancellation.clone());
        self.inner.status_registry_call(&call)
    }

    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        if self.cancellation.is_cancelled() {
            return Err(ClientError::Transport("status generation cancelled".into()));
        }
        let mut call = call.clone();
        call.cancellation = Some(self.cancellation.clone());
        let result = self.inner.call(&call);
        if call.method == "GET"
            && call.path.split('?').next() == Some("/api/v1/zones/claims")
            && !call.path.contains("namespace_probe=1")
            && result.is_ok()
        {
            // One authoritative claims response proves the shared connection is usable. The
            // current cold aggregate still follows claims-first; a later aggregate may overlap
            // its reads even if this one's remaining cold connections hit their allocation.
            self.pool_warm.store(true, Ordering::Release);
        }
        result
    }

    fn server_time_upper_bound(&self) -> Option<i64> {
        self.inner.server_time_upper_bound()
    }

    fn verifies_repository_reads(&self) -> bool {
        self.inner.verifies_repository_reads()
    }

    fn status_reads_parallel(&self) -> bool {
        self.parallel
    }

    fn status_followups_parallel(&self) -> bool {
        // The agent's pool is long-lived: connections opened by one cold fan-out serve later reads.
        true
    }

    fn status_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    fn fast_unread(&self, session: &str) -> Option<Result<Option<i64>, ClientError>> {
        (session == self.session)
            .then_some(self.unread)
            .flatten()
            .map(|count| Ok(Some(count)))
    }
}

/// A cold/restarted daemon may spend its aggregate allocation warming connections. Let the CLI
/// use its reserved direct-read allocation for transport timeouts, but never multiply a 429 into
/// another HTTP attempt. The status backend wraps mandatory failures in `Unavailable`, so inspect
/// the underlying transport wording, not the generic "within deadline" wrapper on every failure.
fn status_failure(error: Error) -> Reply {
    let detail = error.to_string();
    let lower = detail.to_ascii_lowercase();
    let rate_limited = matches!(&error, Error::Cloud { code, status, .. }
        if code == "rate_limited" || *status == Some(429))
        || lower.contains("rate limiting")
        || lower.contains("rate_limited")
        || lower.contains("http 429");
    let transport_timeout = matches!(&error, Error::Unavailable(_))
        && !rate_limited
        && [
            "timed out",
            "timedout",
            "network error",
            "deadline elapsed",
            "deadline exceeded",
            "connection refused",
            "connection reset",
            "connection aborted",
            "dns error",
        ]
        .iter()
        .any(|cause| lower.contains(cause));
    if transport_timeout {
        return Reply::failed(ClientError::Transport(detail));
    }
    Reply::failed(ClientError::Protocol(lockyard_cloud_client::Problem {
        code: error.kind().to_string(),
        status: match &error {
            Error::Cloud { status, .. } => *status,
            _ => None,
        },
        details: match &error {
            Error::Cloud { details, .. } => details.clone(),
            _ => Value::Null,
        },
        detail,
    }))
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
        self.check_with_server(session, paths, |wanted| {
            let wanted = wanted.to_vec();
            self.within_deadline(
                {
                    let session = session.to_string();
                    move |backend| backend.check(&session, &wanted, None, 0)
                },
                session,
            )
        })
    }

    /// Keeps the cache/fallback decision separate from the bounded transport execution.
    fn check_with_server(
        &self,
        session: &str,
        paths: Vec<String>,
        server_check: impl FnOnce(&[String]) -> Option<lockyard_core::Result<Vec<PathCheck>>>,
    ) -> Reply {
        {
            let view = self.read_view();
            if view.fresh(self.timing().fresh) {
                let checks = view.check(session, &paths);
                if checks
                    .iter()
                    .all(|check| check.status != CheckStatus::Unknown)
                {
                    return Reply {
                        checks: Some(checks),
                        source: Some(Source::View),
                        ..Reply::default()
                    };
                }
            }
        }
        match server_check(&paths) {
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
        let registered = {
            let mut view = self.write_view();
            let registered = !view.unread.contains_key(session);
            let entry = view.unread.entry(session.to_string()).or_default();
            if entry.fresh(limit) {
                return Reply {
                    unread: Some(entry.count),
                    source: Some(Source::View),
                    ..Reply::default()
                };
            }
            registered
        };
        if registered {
            self.nudge();
        }
        Reply {
            unread: None,
            source: Some(Source::None),
            ..Reply::default()
        }
    }

    fn zone_snapshot(&self, session: &str) -> Reply {
        self.hear(session);
        let mut view = self.write_view();
        let age_ms = view
            .zones_at
            .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX));
        let board_age_ms = view
            .board_at
            .map(|at| u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX));
        // Board freshness is independent of claims, and this hook path never refreshes it.
        let board = view
            .board_fresh(self.timing().fresh)
            .then(|| view.board.clone());
        let board_source = if board.is_some() {
            Source::View
        } else {
            Source::None
        };
        let claims = view.claims.clone();
        let queue = view.queue.clone();
        let requests = view.requests.clone();
        let lost = view.lost.entry(session.to_string()).or_default();
        let lost = lost.at.map(|_| lost.marks.clone());
        Reply {
            claims: Some(claims),
            queue: Some(queue),
            requests: Some(requests),
            lost,
            source: Some(if age_ms.is_some() {
                Source::View
            } else {
                Source::None
            }),
            age_ms,
            board,
            board_source: Some(board_source),
            board_age_ms,
            ..Reply::default()
        }
    }

    /// Claims single-flight contract: only a queued, not-yet-dispatched generation may be joined.
    /// Dispatch removes it from `pending` before any HTTP read begins, so every member arrived
    /// before that generation's claims GET. Running and completed generations are never reused.
    /// Different sessions/repositories have separate generations; at most three run at once.
    fn status_read(
        self: &Arc<Self>,
        session: &str,
        repository: Option<&str>,
        deadline_ms: u64,
    ) -> Reply {
        self.status_read_with_peer(session, repository, deadline_ms, &mut || false)
    }

    fn status_read_with_peer(
        self: &Arc<Self>,
        session: &str,
        repository: Option<&str>,
        deadline_ms: u64,
        peer_gone: &mut dyn FnMut() -> bool,
    ) -> Reply {
        let arrived = Instant::now();
        let budget = Duration::from_millis(deadline_ms).min(STATUS_READ_LIMIT);
        let deadline = arrived + budget;
        let timed_out = || {
            Reply::failed(ClientError::Transport(
                "agent status deadline exceeded while waiting for an authoritative read".into(),
            ))
        };
        if budget.is_zero() {
            return timed_out();
        }
        let mut reads = self
            .status_reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if reads
            .batches
            .values()
            .map(|batch| batch.waiters)
            .sum::<usize>()
            >= MAX_STATUS_CALLERS
        {
            return Reply::failed(ClientError::Transport(
                "agent status bounded queue is full".into(),
            ));
        }
        let queued = reads.pending.iter().copied().find(|id| {
            let batch = &reads.batches[id];
            batch.session == session && batch.repository.as_deref() == repository
        });
        let id = if let Some(id) = queued {
            let batch = reads
                .batches
                .get_mut(&id)
                .expect("queued status batch exists");
            batch.waiters += 1;
            // Each member keeps its own deadline. A short-lived member must not shorten the
            // live members' network budget, including when that member disconnects.
            batch.deadline = batch.deadline.max(deadline);
            id
        } else {
            let id = reads.next;
            reads.next = reads.next.wrapping_add(1);
            reads.batches.insert(
                id,
                StatusBatch {
                    session: session.to_string(),
                    repository: repository.map(str::to_string),
                    ready_at: arrived + STATUS_COALESCE_WINDOW,
                    deadline,
                    waiters: 1,
                    running: false,
                    reply: None,
                    cancellation: Cancellation::new(),
                },
            );
            reads.pending.push_back(id);
            id
        };
        self.status_ready.notify_all();
        loop {
            // Never hold admission's mutex while probing a peer: all other callers can leave or
            // dispatch while this platform-neutral UnixStream/LocalStream read waits briefly.
            drop(reads);
            let disconnected = peer_gone();
            reads = self
                .status_reads
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            if disconnected || now >= deadline {
                reads.leave(id);
                self.status_ready.notify_all();
                return if disconnected {
                    Reply::failed(ClientError::Transport("status caller disconnected".into()))
                } else {
                    timed_out()
                };
            }
            if let Some(reply) = reads.batches[&id].reply.clone() {
                reads.leave(id);
                self.status_ready.notify_all();
                return reply;
            }
            let batch = &reads.batches[&id];
            let ready_at = batch.ready_at;
            if !batch.running
                && reads.running < MAX_STATUS_READS
                && reads.pending.front() == Some(&id)
                && ready_at <= now
            {
                let generation_deadline = batch.deadline;
                let cancellation = batch.cancellation.clone();
                let session = batch.session.clone();
                let repository = batch.repository.clone();
                reads.batches.get_mut(&id).unwrap().running = true;
                reads.running += 1;
                reads.pending.pop_front();
                // No request arriving from this point onward can join this generation. The
                // dispatcher is a waiter too: it keeps checking EOF while this worker runs.
                let shared = Arc::clone(self);
                thread::spawn(move || {
                    let reply = shared.status_read_network(
                        &session,
                        repository.as_deref(),
                        generation_deadline.saturating_duration_since(Instant::now()),
                        cancellation,
                    );
                    let mut reads = shared
                        .status_reads
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    reads.running -= 1;
                    if reads.batches[&id].waiters == 0 {
                        // Abandoned generations never publish a result (or become reusable).
                        reads.batches.remove(&id);
                    } else {
                        let batch = reads.batches.get_mut(&id).unwrap();
                        batch.running = false;
                        batch.reply = Some(reply);
                    }
                    shared.status_ready.notify_all();
                });
                self.status_ready.notify_all();
                continue;
            }
            let wake_at = if reads.running < MAX_STATUS_READS
                && reads.pending.front() == Some(&id)
                && ready_at > now
            {
                deadline.min(ready_at)
            } else {
                deadline
            };
            let (guard, _) = self
                .status_ready
                .wait_timeout(
                    reads,
                    wake_at
                        .saturating_duration_since(now)
                        .min(STATUS_PEER_CHECK),
                )
                .unwrap_or_else(PoisonError::into_inner);
            reads = guard;
        }
    }

    fn status_read_network(
        &self,
        session: &str,
        repository: Option<&str>,
        budget: Duration,
        cancellation: Cancellation,
    ) -> Reply {
        let deadline = Instant::now() + budget;
        if cancellation.is_cancelled() {
            return Reply::failed(ClientError::Transport(
                "status generation cancelled before dispatch".into(),
            ));
        }
        if budget.is_zero() {
            return Reply::failed(ClientError::Transport("status deadline exceeded".into()));
        }
        // Keep membership established before unread reconciliation can inspect this entry,
        // but do not launch redundant upkeep/polls ahead of the caller's own network reads.
        // The mark is taken before the unread entry exists, so upkeep never sees that entry
        // without also seeing that this read will fetch the count itself. It is released early
        // when the read reuses a cached count, and before nudging upkeep at the end.
        let mut in_flight = Some(StatusNetworkMark::new(
            &self.status_network_sessions,
            session,
        ));
        let registered_session = {
            let mut sessions = self.sessions();
            let registered = !sessions.contains_key(session);
            sessions.entry(session.to_string()).or_default().heard = Some(Instant::now());
            registered
        };
        let (cached_unread, unread_generation, registered) = {
            let mut view = self.write_view();
            let registered = !view.unread.contains_key(session);
            let entry = view.unread.entry(session.to_string()).or_default();
            let snapshot = entry.at.map(|_| {
                let age = entry.at.map(|at| at.elapsed()).unwrap_or_default().max(
                    entry
                        .wall_at
                        .and_then(|at| SystemTime::now().duration_since(at).ok())
                        .unwrap_or_default(),
                );
                (
                    entry.count,
                    age,
                    Instant::now(),
                    entry.fresh(self.timing().fresh),
                )
            });
            (snapshot, entry.generation, registered)
        };
        if cached_unread.is_some_and(|(_, _, _, fresh)| fresh) {
            // This read answers unread from the cache and sends no inbox request, so upkeep's
            // prefetch for this session is not repeated work.
            drop(in_flight.take());
        }
        // The zone mirror is deliberately not an authority for this request. An empty event poll
        // confirms a generation, but cannot give a server-time lease or prove there was no revoke
        // during a network gap. A fresh read also handles restart, sleep, handover and idle release.
        let transport = StatusTransport {
            inner: Arc::clone(&self.transport),
            session: session.to_string(),
            unread: cached_unread
                .filter(|(_, _, _, fresh)| *fresh)
                .map(|(count, _, _, _)| count),
            parallel: self.status_pool_warm.load(Ordering::Acquire),
            pool_warm: Arc::clone(&self.status_pool_warm),
            cancellation: cancellation.clone(),
        };
        let transport = match RepositoryTransport::new(transport, repository) {
            Ok(transport) => transport,
            Err(error) => return Reply::failed(error),
        };
        let backend = CloudBackend::new(transport, session);
        let left = deadline.saturating_duration_since(Instant::now());
        // Mail and mandatory reads share the entire HTTP allocation. Leave enough of the remaining
        // aggregate budget for folding optional failures, expiry checks, JSON serialization and
        // IPC. A 25 ms reserve races the caller's socket deadline when optional mail uses nearly
        // the whole network budget (warm status with a stalled inbox): the daemon finishes just
        // as the client times out, the CLI falls back to a direct read, and that direct read
        // waits on the same stall again.
        let reply_reserve = left
            .div_f64(10.0)
            .clamp(Duration::from_millis(25), Duration::from_millis(150));
        let network_budget = left.saturating_sub(reply_reserve);
        match backend.status_read(session, now_ms(), network_budget) {
            Ok(mut status) => {
                status.freshness["transport"] = json!("agent");
                let cached_unread = cached_unread.or_else(|| {
                    if status.unread.is_some() {
                        return None;
                    }
                    let view = self.read_view();
                    let entry = view.unread.get(session)?;
                    let age = entry.at?.elapsed().max(
                        entry
                            .wall_at
                            .and_then(|at| SystemTime::now().duration_since(at).ok())
                            .unwrap_or_default(),
                    );
                    Some((entry.count, age, Instant::now(), false))
                });
                if let Some((count, age, captured, was_fresh)) = cached_unread {
                    let mut age = age.saturating_add(captured.elapsed());
                    let mut count = count;
                    let metadata = &mut status.freshness["sections"]["unread"];
                    if was_fresh || status.unread.is_none() {
                        // An upkeep refresh may have learned a newer count while this network read
                        // failed. Preserve the last value actually known, even if older than 30s.
                        let view = self.read_view();
                        if let Some(entry) =
                            view.unread.get(session).filter(|entry| entry.at.is_some())
                        {
                            count = entry.count;
                            age = entry.at.unwrap().elapsed().max(
                                entry
                                    .wall_at
                                    .and_then(|at| SystemTime::now().duration_since(at).ok())
                                    .unwrap_or_default(),
                            );
                        }
                        // Staleness is explicit; an intervening event can only make it stale.
                        let still_fresh = was_fresh
                            && age < self.timing().fresh
                            && view
                                .unread
                                .get(session)
                                .is_some_and(|entry| entry.generation == unread_generation);
                        status.unread = Some(count);
                        metadata["age_ms"] = json!(age.as_millis());
                        metadata["available"] = json!(true);
                        metadata["stale"] = json!(!still_fresh);
                        metadata["source"] = json!(if still_fresh { "view" } else { "stale" });
                    } else if let Some(count) = status.unread {
                        self.store_unread(session, unread_generation, count);
                    }
                } else if let Some(count) = status.unread {
                    // Events arriving during the read keep the response dirty for the next call.
                    self.store_unread(session, unread_generation, count);
                }
                // The count is stored (or the inbox section failed): let the nudged upkeep pass
                // refresh this session immediately instead of skipping it as still in flight.
                drop(in_flight.take());
                if (registered_session || registered) && !cancellation.is_cancelled() {
                    self.nudge();
                }
                Reply {
                    status_read: Some(status),
                    source: Some(Source::Server),
                    ..Reply::default()
                }
            }
            Err(error) => status_failure(error),
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

    fn take_mail(&self, session: &str, limit: usize, _lease_seconds: i64) -> Reply {
        let mut view = self.write_view();
        let fresh = self.timing().fresh;
        // Reserved mail is good for its lease, whatever the age of the count.
        if !view.mail.contains_key(session)
            && !view
                .unread
                .get(session)
                .is_some_and(|entry| entry.fresh(fresh))
        {
            if !view.unread.contains_key(session) {
                view.unread.entry(session.to_string()).or_default();
                drop(view);
                self.nudge();
            }
            return Reply {
                source: Some(Source::None),
                ..Reply::default()
            };
        }
        let now = Instant::now();
        if view.mail.get(session).is_some_and(|buffer| {
            debug_assert!(buffer.lease_expires_at >= buffer.reserved_at);
            buffer.lease_expires_at.saturating_duration_since(now) < Duration::from_secs(10)
        }) {
            view.mail.remove(session);
        }
        let mut messages = Vec::new();
        if let Some(buffer) = view.mail.get_mut(session) {
            for _ in 0..limit {
                let Some(message) = buffer.messages.pop_front() else {
                    break;
                };
                messages.push(message);
            }
            if buffer.messages.is_empty() {
                view.mail.remove(session);
            }
        }
        if let Some(count) = view.unread.get_mut(session) {
            count.count = count.count.saturating_sub(messages.len() as i64).max(0);
            count.at = Some(now);
            count.wall_at = Some(SystemTime::now());
        }
        Reply {
            messages: Some(messages),
            source: Some(Source::View),
            ..Reply::default()
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
            #[cfg(unix)]
            let temporary = self.state_dir.join(format!("{cursor_name}.tmp"));
            let cursor = self.state_dir.join(cursor_name);
            #[cfg(unix)]
            let saved = fs::write(&temporary, through.to_string())
                .and_then(|()| lockyard_core::fsio::rename(&temporary, &cursor));
            #[cfg(windows)]
            let saved =
                lockyard_core::fsio::replace(&cursor, through.to_string().as_bytes(), 0o600);
            if let Err(error) = saved {
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
        let registered = {
            let mut sessions = self.sessions();
            let registered = !sessions.contains_key(session);
            sessions.entry(session.to_string()).or_default().heard = Some(Instant::now());
            registered
        };
        if registered {
            self.nudge();
        }
    }

    fn touch(&self, session: &str, client: &str, phase: Phase, write_paths: Vec<String>) -> Reply {
        let running = phase == Phase::Pre;
        let (beat, registered) = {
            let mut sessions = self.sessions();
            let registered = !sessions.contains_key(session);
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
            (send, registered)
        };
        if registered {
            self.nudge();
        }
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
        let repository_probe = call.method == "GET"
            && call.path.starts_with("/api/v1/zones/claims?")
            && call.path.ends_with("&namespace_probe=1")
            && call
                .repository
                .as_deref()
                .is_some_and(|repository| !repository.is_empty());
        if repository_probe
            && self
                .repository_capabilities
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(call.repository.as_deref().unwrap_or_default())
        {
            return Reply {
                value: Some(
                    json!({"repository_namespace_supported":true,"repository":call.repository}),
                ),
                source: Some(Source::View),
                ..Reply::default()
            };
        }
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
                    if repository_probe {
                        self.repository_capabilities
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(call.repository.clone().unwrap_or_default());
                        return Reply {
                            value: Some(
                                json!({"repository_namespace_supported":true,"repository":call.repository}),
                            ),
                            source: Some(Source::Server),
                            ..Reply::default()
                        };
                    }
                    if writes {
                        let mut view = self.write_view();
                        view.zones_generation += 1;
                        for marks in view.lost.values_mut() {
                            marks.generation += 1;
                        }
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
        let caller_budget = call.deadline_ms.map(Duration::from_millis);
        // Once a write enters the durable queue, the socket caller's patience no longer
        // bounds delivery. The outbox owns retries and keeps the entry until it can finish.
        call.deadline_ms = None;
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
            Ok((_, outcome)) => match outcome.recv_timeout(
                caller_budget.map_or(self.timing().mail_wait, |budget| {
                    budget.min(self.timing().mail_wait)
                }),
            ) {
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
        let status_read_abandoned = {
            let reads = self
                .status_reads
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            abandoned_read_advisory(
                reads.running,
                reads
                    .batches
                    .values()
                    .any(|batch| batch.running && batch.waiters == 0),
            )
        };
        let view = self.read_view();
        AgentStatus {
            url: self.config.url.clone(),
            workspace: self.config.workspace.clone(),
            token_id: self.config.token_id.clone(),
            catalog_expansion_v1: true,
            status_read_v1: true,
            status_read_abandoned,
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

    fn handle(self: &Arc<Self>, envelope: Envelope) -> Reply {
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
            Request::ZoneSnapshot { session } => self.zone_snapshot(&session),
            Request::StatusRead {
                session,
                repository,
                deadline_ms,
            } => self.status_read(&session, repository.as_deref(), deadline_ms),
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
            Request::ExpandCatalog { call, names } => {
                if call.method != "GET"
                    || call.path != "/api/v1/zones/catalog"
                    || call.body.is_some()
                    || call.key.is_some()
                {
                    return Reply::failed(ClientError::Invalid(
                        "catalog expansion requires a catalog read".into(),
                    ));
                }
                match self.transport.catalog_expand(&call, &names) {
                    Ok(paths) => Reply {
                        value: Some(json!(paths)),
                        ..Reply::default()
                    },
                    Err(error) => Reply::failed(error),
                }
            }
            Request::Call { call } => self.forward(call),
        }
    }

    fn apply_events(&self, page: &EventPage) {
        let mut touched = false;
        let mut view = self.write_view();
        for event in &page.events {
            if event.kind.starts_with("zone.") {
                view.zones_generation += 1;
                for marks in view.lost.values_mut() {
                    marks.generation += 1;
                }
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
                        #[cfg(unix)]
                        let _ = fs::write(
                            self.state_dir.join(format!("cursor-{name}")),
                            last.to_string(),
                        );
                        #[cfg(windows)]
                        let _ = lockyard_core::fsio::replace(
                            &self.state_dir.join(format!("cursor-{name}")),
                            last.to_string().as_bytes(),
                            0o600,
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
        let backend = self.backend(&self.session);
        let claims = backend.claims(&ClaimQuery::default(), 0);
        let queue = backend.queue_list(&self.session);
        let requests = backend.zone_requests(&self.session);
        let mut view = self.write_view();
        // Only claims decide a path check, so a failed queue or request read must not stale it.
        view.extras_stale = queue.is_err() || requests.is_err();
        if let Ok(queue) = queue {
            view.queue = queue;
        }
        if let Ok(requests) = requests {
            view.requests = requests;
        }
        if let Ok(claims) = claims {
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
        let limit = self.timing().fresh / 2;
        let wanted: Vec<(String, u64)> = {
            // Reconcile against membership under the same lock: an older snapshot must
            // not erase a count that an Unread request registered after TakeMail.
            let mut sessions = self.sessions();
            sessions.retain(|_, track| track.heard.is_some_and(|at| at.elapsed() < window));
            #[cfg(test)]
            tests::pause_unread_reconciliation();
            let mut view = self.write_view();
            view.unread
                .retain(|session, _| sessions.contains_key(session));
            view.mail
                .retain(|session, _| sessions.contains_key(session));
            let stale = view.unread.iter().filter(|(_, entry)| !entry.fresh(limit));
            stale
                .map(|(session, entry)| (session.clone(), entry.generation))
                .collect()
        };
        for (session, generation) in wanted {
            // A caller's status read for this session is already fetching the count; a second
            // inbox read would be repeated work, and that read stores the result when it ends.
            if self
                .status_network_sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&session)
            {
                continue;
            }
            // The snapshot above is older than this iteration: a status read may have stored a
            // fresh count while upkeep was busy with an earlier session.
            if self
                .read_view()
                .unread
                .get(&session)
                .is_none_or(|entry| entry.fresh(limit))
            {
                continue;
            }
            if let Ok(count) = self.backend(&session).unread(&session) {
                self.store_unread(&session, generation, count);
            }
        }
    }

    fn refresh_mail(&self) -> bool {
        let mut journal_busy = false;
        let now = Instant::now();
        let window = self.timing().active_window;
        let wanted: Vec<String> = {
            // Use the same sessions -> view lock order as unread/lost reconciliation.
            let mut sessions = self.sessions();
            sessions.retain(|_, track| track.heard.is_some_and(|at| at.elapsed() < window));
            let mut view = self.write_view();
            view.mail.retain(|_, buffer| buffer.lease_expires_at > now);
            view.unread
                .iter()
                .filter(|(session, entry)| {
                    entry.count > 0
                        && sessions.contains_key(*session)
                        && !view.mail.contains_key(*session)
                })
                .map(|(session, _)| session.clone())
                .collect()
        };
        for session in wanted {
            let mut backend = self.backend(&session);
            let page = match backend.inbox(
                &session,
                InboxQuery {
                    all: false,
                    limit: MAIL_BUFFER_LIMIT,
                },
                0,
            ) {
                Ok(page) => page,
                Err(_) => continue,
            };
            if page.messages.is_empty() {
                continue;
            }
            let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
            let reserved_at = Instant::now();
            let granted = match backend.inbox_claim(
                &session,
                "agent",
                &ids,
                i64::try_from(MAIL_DELIVERY_LEASE.as_secs()).unwrap_or(i64::MAX),
                0,
            ) {
                Ok(granted) => granted,
                // The heartbeat sender and mail reservation share one pending journal. A
                // busy journal is a local pre-send refusal, so retry it before the next
                // normal upkeep. Other failures keep their existing polling cadence.
                Err(Error::Unavailable(reason)) if reason == "pending journal is busy" => {
                    journal_busy = true;
                    continue;
                }
                Err(Error::Invalid(reason))
                    if reason == "pending journal unavailable: pending journal is busy" =>
                {
                    journal_busy = true;
                    continue;
                }
                Err(_) => continue,
            };
            let messages: VecDeque<Message> = page
                .messages
                .into_iter()
                .filter(|message| granted.contains(&message.id))
                .collect();
            if messages.is_empty() {
                continue;
            }
            // A claim is only a lease: if the agent dies before marking mail seen, the server
            // releases it at expiry and a later upkeep pass can deliver it again.
            let mut view = self.write_view();
            view.mail.entry(session).or_insert(MailBuffer {
                messages,
                reserved_at,
                lease_expires_at: reserved_at + MAIL_DELIVERY_LEASE,
            });
        }
        journal_busy
    }

    fn refresh_lost(&self) {
        let window = self.timing().active_window;
        let limit = self.timing().fresh / 2;
        let (refresh_generation, wanted) = {
            // Keep membership and its reconciliation atomic: a paused older live-set snapshot
            // must not recreate entries after a newer refresh has removed expired sessions.
            let mut sessions = self.sessions();
            sessions.retain(|_, track| track.heard.is_some_and(|at| at.elapsed() < window));
            let mut view = self.write_view();
            view.lost_refresh_generation += 1;
            view.lost
                .retain(|session, _| sessions.contains_key(session));
            for session in sessions.keys() {
                view.lost.entry(session.clone()).or_default();
            }
            let wanted: Vec<(String, u64, Arc<()>)> = view
                .lost
                .iter()
                .filter(|(_, marks)| !marks.fresh(limit))
                .map(|(session, marks)| {
                    (
                        session.clone(),
                        marks.generation,
                        Arc::clone(&sessions[session].incarnation),
                    )
                })
                .collect();
            (view.lost_refresh_generation, wanted)
        };
        for (session, generation, incarnation) in wanted {
            if let Ok(marks) = self.backend(&session).lost(&session) {
                // Unread/mail upkeep can also expire sessions without starting a lost refresh.
                // Hold the same lock order as preparation until publication is complete.
                let sessions = self.sessions();
                if !sessions.get(&session).is_some_and(|track| {
                    Arc::ptr_eq(&track.incarnation, &incarnation)
                        && track.heard.is_some_and(|at| at.elapsed() < window)
                }) {
                    continue;
                }
                let mut view = self.write_view();
                // A newer pass owns publication, including a remove/re-register of the same
                // session. Never let an in-flight response restore a removed entry.
                if view.lost_refresh_generation != refresh_generation {
                    continue;
                }
                let Some(entry) = view.lost.get_mut(&session) else {
                    continue;
                };
                // Events arriving during this read leave the entry dirty for the next pass.
                if entry.generation != generation {
                    continue;
                }
                entry.marks = marks;
                entry.clean = generation;
                entry.at = Some(Instant::now());
                entry.wall_at = Some(SystemTime::now());
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
                    !view.fresh(half) || view.extras_stale,
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
            let retry_mail = self.refresh_mail();
            self.refresh_lost();
            self.refresh_session_events();
            self.flush_activity();
            let mut signal = self.signal();
            if !signal.nudged && !signal.stop {
                signal = self
                    .wake
                    .wait_timeout(
                        signal,
                        if retry_mail {
                            self.timing().upkeep.min(self.timing().retry_min)
                        } else {
                            self.timing().upkeep
                        },
                    )
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
            // Outbox readiness has its own condvar, so Shared::stop cannot wake this wait.
            let Some(entry) = self
                .outbox
                .head(self.timing().retry_max.min(crate::shutdown::POLL_INTERVAL))
            else {
                continue;
            };
            if self.stopped() {
                break;
            }
            let mut call = entry.call.clone();
            call.defer_pending_ack = true;
            call.attempt_timeout_ms =
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
                Err(error @ ClientError::OutcomeUnknown(_)) => {
                    self.outbox.report_unknown(entry.n, error);
                    self.outbox.defer(entry.n, pause);
                    pause = (pause * 2).min(self.timing().retry_max);
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
                    let succeeded = outcome.is_ok();
                    if let Err(error) = self.outbox.finish(entry.n, outcome) {
                        eprintln!("lockyard agent: cannot update the outbox: {error}");
                    } else if succeeded && let Err(error) = self.transport.acknowledge_write(&call)
                    {
                        eprintln!(
                            "lockyard agent: cannot acknowledge the completed write: {error}"
                        );
                    }
                }
            }
        }
    }
}

fn answer<T: Transport + 'static>(shared: &Arc<Shared<T>>, stream: UnixStream) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(IDLE_CONNECTION));
    let _ = stream.set_write_timeout(Some(IDLE_CONNECTION));
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    // Preserve pipelined bytes read while checking a status peer, including older CLI traffic.
    let mut pending = Vec::new();
    loop {
        let mut line = String::new();
        let mut prefix = io::Cursor::new(&pending);
        let read = (&mut prefix)
            .chain(&mut reader)
            .take(MAX_REQUEST_BYTES)
            .read_line(&mut line)?;
        let consumed = prefix.position() as usize;
        pending.drain(..consumed);
        if read == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') {
            let error = ClientError::Invalid("request too long".into());
            write_reply(&mut writer, &Reply::failed(error))?;
            return Ok(());
        }
        let reply = match serde_json::from_str::<Envelope>(&line) {
            Ok(Envelope {
                workspace,
                request:
                    Request::StatusRead {
                        session,
                        repository,
                        deadline_ms,
                    },
            }) if workspace == shared.config.workspace => {
                reader.get_ref().set_read_timeout(Some(STATUS_PEER_READ))?;
                let mut disconnected = false;
                let reply = shared.status_read_with_peer(
                    &session,
                    repository.as_deref(),
                    deadline_ms,
                    &mut || {
                        if disconnected {
                            return true;
                        }
                        let mut bytes = [0u8; 1024];
                        match reader.read(&mut bytes) {
                            Ok(0) => disconnected = true,
                            Ok(count) => {
                                pending.extend_from_slice(&bytes[..count]);
                                disconnected = pending.len() > MAX_REQUEST_BYTES as usize;
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::WouldBlock
                                        | io::ErrorKind::TimedOut
                                        | io::ErrorKind::Interrupted
                                ) => {}
                            Err(_) => disconnected = true,
                        }
                        disconnected
                    },
                );
                if disconnected {
                    return Ok(());
                }
                reader.get_ref().set_read_timeout(Some(IDLE_CONNECTION))?;
                reply
            }
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
    #[cfg(unix)]
    let bytes = fs::read(dir.join(format!("cursor-{name}")));
    #[cfg(windows)]
    let bytes = lockyard_core::windows::read_private(&dir.join(format!("cursor-{name}")), 128);
    bytes
        .ok()
        .and_then(|bytes| {
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| text.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn state_folder(config: &AgentConfig) -> String {
    #[cfg(unix)]
    let identity = format!("{}\0{}", config.url, config.token_id);
    #[cfg(windows)]
    let identity = format!("{}\0{}\0{}", config.url, config.token_id, config.workspace);
    format!("target-{}", lockyard_cloud_client::token_id(&identity))
}

#[cfg(unix)]
fn bind(path: &Path) -> io::Result<(Option<File>, UnixListener)> {
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
    Ok((Some(lock), listener))
}

#[cfg(windows)]
fn bind(path: &Path) -> io::Result<(Option<File>, UnixListener)> {
    Ok((None, UnixListener::bind(path)?))
}

/// A running agent process.
pub struct Daemon<T: Transport + 'static> {
    shared: Arc<Shared<T>>,
    threads: Vec<JoinHandle<()>>,
    _lock: Option<File>,
    #[cfg(windows)]
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    #[cfg(windows)]
    listener_stop: lockyard_core::windows::ipc::ListenerStop,
}

impl<T: Transport + 'static> Daemon<T> {
    /// Binds the socket, restores the outbox and starts every thread.
    pub fn start(config: AgentConfig, transport: T) -> io::Result<Self> {
        #[cfg(windows)]
        private_dir(&config.state_root)?;
        let (lock, listener) = bind(&config.socket)?;
        #[cfg(windows)]
        let listener_stop = listener.stop_handle();
        private_dir(&config.state_root)?;
        let state_dir = config.state_root.join(state_folder(&config));
        private_dir(&state_dir)?;
        #[cfg(windows)]
        for entry in fs::read_dir(&state_dir)? {
            let path = entry?.path();
            lockyard_core::windows::require_private(&path)?;
        }
        let outbox = Outbox::open(&state_dir)?;
        let shared = Arc::new(Shared {
            transport: Arc::new(transport),
            // One name per token, not per machine: another key on this machine must not find it taken (D-3178).
            // Same rule as Client::service_session (first 8 hex of the token id).
            session: format!(
                "lockyard-agent-{}-{}",
                super::uid(),
                config.token_id.get(..8).unwrap_or(&config.token_id)
            ),
            coordination_seq: AtomicI64::new(load_seq(&state_dir, "coordination")),
            registry_seq: AtomicI64::new(load_seq(&state_dir, "registry")),
            session_event_cursors: Mutex::new(HashMap::new()),
            session_events: Mutex::new(HashMap::new()),
            repository_capabilities: Mutex::new(HashSet::new()),
            status_reads: Mutex::new(StatusReads::default()),
            status_ready: Condvar::new(),
            status_pool_warm: Arc::new(AtomicBool::new(false)),
            status_network_sessions: Mutex::new(HashMap::new()),
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
        #[cfg(windows)]
        let connections = Arc::new(Mutex::new(Vec::<JoinHandle<()>>::new()));
        #[cfg(windows)]
        let accepted = connections.clone();
        threads.push(spawn(
            "accept",
            Box::new(move || {
                for stream in listener.incoming() {
                    if copy.stopped() {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let connection = Arc::clone(&copy);
                    let worker = thread::spawn(move || {
                        // A hook that told and left closes its end first. That is not a failure.
                        let _ = answer(&connection, stream);
                    });
                    #[cfg(windows)]
                    {
                        let mut workers = accepted.lock().unwrap_or_else(PoisonError::into_inner);
                        workers.retain(|worker| !worker.is_finished());
                        workers.push(worker);
                    }
                    #[cfg(unix)]
                    let _ = worker;
                }
            }),
        )?);
        Ok(Self {
            shared,
            threads,
            _lock: lock,
            #[cfg(windows)]
            connections,
            #[cfg(windows)]
            listener_stop,
        })
    }

    /// Waits for a normal stop signal, then joins the bounded background operations.
    pub fn wait(mut self) {
        while !crate::shutdown::requested() && !self.shared.stopped() {
            thread::sleep(crate::shutdown::POLL_INTERVAL);
        }
        self.shutdown();
    }

    /// Stops the workers and waits for their current bounded transport operations to finish.
    fn shutdown(&mut self) {
        self.shared.stop();
        // Wake the accept loop, which sits in a blocking call. If the socket file is already gone (its folder
        // was removed), nothing can wake it: leave that one thread behind rather than wait for it forever.
        #[cfg(unix)]
        let woke = UnixStream::connect(&self.shared.config.socket).is_ok();
        #[cfg(unix)]
        let _ = fs::remove_file(&self.shared.config.socket);
        #[cfg(windows)]
        let woke = {
            self.listener_stop.stop();
            true
        };
        for thread in self.threads.drain(..) {
            if !woke && thread.thread().name() == Some("accept") {
                continue;
            }
            let _ = thread.join();
        }
        #[cfg(windows)]
        for connection in std::mem::take(
            &mut *self
                .connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        ) {
            let _ = connection.join();
        }
    }
}

#[cfg(test)]
impl<T: Transport + 'static> Daemon<T> {
    /// Stop and join background workers before a test inspects or seeds a stationary view.
    fn stop_workers(&mut self) {
        self.shared.stop();
        let _ = UnixStream::connect(&self.shared.config.socket);
        for worker in self.threads.drain(..) {
            worker.join().expect("agent worker panicked");
        }
    }

    /// Handles one request without a socket.
    fn handle(&self, request: Request) -> Reply {
        let workspace = self.shared.config.workspace.clone();
        self.shared.handle(Envelope { workspace, request })
    }
}

impl<T: Transport + 'static> Drop for Daemon<T> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(test)]
mod tests {
    use super::super::socket::AgentSocket;
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    #[cfg(windows)]
    include!("windows_tests.rs");

    /// An in-memory server that can go down, hang or be made to refuse.
    #[derive(Default)]
    struct FakeServer {
        claims: Mutex<Vec<Value>>,
        queue: Mutex<Vec<Value>>,
        requests: Mutex<Vec<Value>>,
        lost: Mutex<Vec<Value>>,
        board: Mutex<Option<Vec<Value>>>,
        lost_read_gate: Mutex<Option<LostReadGate>>,
        busy_mail_claim_gate: Mutex<Option<LostReadGate>>,
        unread: Mutex<i64>,
        events: Mutex<Vec<Value>>,
        writes: Mutex<Vec<Call>>,
        down: AtomicBool,
        /// Calls that are not long polls sleep this long, in milliseconds.
        hang_ms: AtomicUsize,
        /// Every request that is not an event poll.
        calls: Mutex<Vec<String>>,
        claims_started: Mutex<Vec<(String, Instant)>>,
        claim_failure: Mutex<Option<ClientError>>,
        claim_gate: Mutex<Option<LostReadGate>>,
        registry_failure: Mutex<Option<ClientError>>,
        event_calls: AtomicUsize,
        namespace_probes: AtomicUsize,
        namespace_unsupported: AtomicBool,
        refuse_with: Mutex<Option<u16>>,
        fail_queue: AtomicBool,
        fail_inbox_for: Mutex<Option<String>>,
    }

    struct LostReadGate {
        started: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    }

    thread_local! {
        // Only the refresh thread of the targeted test pauses; parallel daemons stay independent.
        static UNREAD_RECONCILE_GATE: std::cell::RefCell<Option<LostReadGate>> = const {
            std::cell::RefCell::new(None)
        };
    }

    pub(super) fn pause_unread_reconciliation() {
        let gate = UNREAD_RECONCILE_GATE.with(|gate| gate.borrow_mut().take());
        if let Some(gate) = gate {
            gate.started.send(()).unwrap();
            gate.resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }
    }

    impl FakeServer {
        /// Pause one response after capturing its payload, without blocking later reads.
        fn pause_next_lost_read(
            &self,
        ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
            let (started, observed) = channel();
            let (resume, paused) = channel();
            *self.lost_read_gate.lock().unwrap() = Some(LostReadGate {
                started,
                resume: paused,
            });
            (observed, resume)
        }

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
            if call.path.ends_with("&namespace_probe=1") {
                self.namespace_probes.fetch_add(1, Ordering::SeqCst);
                if self.namespace_unsupported.load(Ordering::SeqCst) {
                    return Err(ClientError::Invalid(
                        "repository namespaces unsupported".into(),
                    ));
                }
            }
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
            if route == "/api/v1/zones/claims" && call.method == "GET" {
                self.claims_started
                    .lock()
                    .unwrap()
                    .push((call.session.clone(), Instant::now()));
            }
            let hang = self.hang_ms.load(Ordering::SeqCst);
            if hang > 0 {
                thread::sleep(Duration::from_millis(hang as u64));
            }
            if self.down.load(Ordering::SeqCst) {
                return Err(ClientError::Transport("down".into()));
            }
            if route == "/api/v1/bus/inbox"
                && self
                    .fail_inbox_for
                    .lock()
                    .unwrap()
                    .as_deref()
                    .is_some_and(|session| session == call.session)
            {
                return Err(ClientError::Transport("inbox unavailable".into()));
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
            if route == "/api/v1/zones/queue"
                && call.method == "GET"
                && self.fail_queue.load(Ordering::SeqCst)
            {
                return Err(ClientError::Transport("queue unavailable".into()));
            }
            match route.as_str() {
                "/api/v1/zones/claims" if call.method == "GET" => {
                    if let Some(error) = self.claim_failure.lock().unwrap().clone() {
                        return Err(error);
                    }
                    let gate = self.claim_gate.lock().unwrap().take();
                    if let Some(gate) = gate {
                        gate.started.send(()).unwrap();
                        gate.resume.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    Ok(json!({"claims": *self.claims.lock().unwrap()}))
                }
                "/api/v1/zones/queue" if call.method == "GET" => {
                    Ok(json!({"queue": *self.queue.lock().unwrap()}))
                }
                "/api/v1/zones/requests" if call.method == "GET" => {
                    Ok(json!({"requests": *self.requests.lock().unwrap()}))
                }
                "/api/v1/zones/lost" if call.method == "GET" => {
                    let lost = self.lost.lock().unwrap().clone();
                    let gate = self.lost_read_gate.lock().unwrap().take();
                    if let Some(gate) = gate {
                        gate.started.send(()).unwrap();
                        gate.resume.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    Ok(json!({"lost": lost}))
                }
                "/api/v1/zones/check" => Ok(json!({"paths": [{"path": "src", "status": "free"}]})),
                "/api/v1/bus/board" => {
                    Ok(json!(self.board.lock().unwrap().clone().unwrap_or_else(
                        || vec![json!({"key": "k", "value": "v"})]
                    )))
                }
                "/api/v1/bus/tasks" if call.method == "GET" => Ok(json!({"tasks": []})),
                "/api/v1/registry/items" if call.method == "GET" => {
                    if let Some(error) = self.registry_failure.lock().unwrap().clone() {
                        return Err(error);
                    }
                    Ok(json!({"items": []}))
                }
                "/api/v1/bus/inbox" => {
                    let unread = *self.unread.lock().unwrap();
                    let messages: Vec<Value> = (1..=unread)
                        .map(|id| json!({"id": id, "body": "hi"}))
                        .collect();
                    Ok(json!({"messages": messages}))
                }
                "/api/v1/bus/inbox/claim" => {
                    let gate = self.busy_mail_claim_gate.lock().unwrap().take();
                    if let Some(gate) = gate {
                        gate.started.send(()).unwrap();
                        gate.resume.recv_timeout(Duration::from_secs(5)).unwrap();
                        return Err(ClientError::Transport("pending journal is busy".into()));
                    }
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

    // Fields drop in order: the daemon stops while its socket folder still exists.
    struct Rig {
        daemon: Daemon<Arc<FakeServer>>,
        server: Arc<FakeServer>,
        dir: tempfile::TempDir,
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

    #[cfg(unix)]
    #[test]
    fn new_client_038_keeps_037_task_frames_and_explains_rollback() {
        // Frozen serialized Call fields from 0.3.7. Its daemon forwards body as arbitrary JSON,
        // rather than decoding a task DTO that could silently discard the new paths field.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct CallV037 {
            session: String,
            method: String,
            path: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            repository: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            body: Option<Value>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            key: Option<String>,
            #[serde(default)]
            long_poll: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            deadline_ms: Option<u64>,
            #[serde(default)]
            defer_pending_ack: bool,
        }
        #[derive(serde::Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case")]
        enum RequestV037 {
            Ping,
            Call { call: CallV037 },
        }
        #[derive(serde::Deserialize)]
        struct EnvelopeV037 {
            workspace: String,
            #[serde(flatten)]
            request: RequestV037,
        }
        let paths_body = json!({"title":"new task","paths":["core/src/lib.rs"]});
        let legacy_body = json!({"title":"old task","area_id":"area-core"});
        let mut paths_call = Call::write(
            "worker",
            "POST",
            "/api/v1/registry/items".into(),
            paths_body.clone(),
        );
        paths_call.key = Some("01K00000000000000000000001".into());
        let mut legacy_call = Call::write(
            "worker",
            "POST",
            "/api/v1/registry/items".into(),
            legacy_body.clone(),
        );
        legacy_call.key = Some("01K00000000000000000000002".into());

        // Client 0.3.8 -> daemon 0.3.7: the old Call decoder and unchanged JSON forwarding
        // preserve paths and idempotency keys, and live discovery can both enable and disable them.
        let old_dir = tempfile::tempdir().unwrap();
        private_dir(old_dir.path()).unwrap();
        let old_path = old_dir.path().join("agent.sock");
        let listener = UnixListener::bind(&old_path).unwrap();
        let peer = thread::spawn(move || {
            let mut tasks = Vec::new();
            let mut protocol_reads = 0;
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let envelope: EnvelopeV037 = serde_json::from_str(&line).unwrap();
                assert_eq!(envelope.workspace, "team");
                let reply = match envelope.request {
                    RequestV037::Ping => json!({"status":{
                        "url":"https://example.test", "workspace":"team", "token_id":"t",
                        "pid":1, "view_fresh":false, "view_age_ms":null,
                        "claims":0, "board":0, "sessions":0, "outbox":0,
                        "coordination_seq":0, "registry_seq":0
                    }}),
                    RequestV037::Call { call } if call.path == "/api/v1/protocol" => {
                        protocol_reads += 1;
                        json!({"value":{"selected_protocol":2,"capabilities":
                            if protocol_reads == 2 {vec![]} else {vec!["registry_auto_area_v1"]}
                        }})
                    }
                    RequestV037::Call { call } => {
                        assert_eq!(call.method, "POST");
                        assert_eq!(call.path, "/api/v1/registry/items");
                        let paths = call
                            .body
                            .as_ref()
                            .and_then(|body| body.get("paths"))
                            .cloned();
                        tasks.push(serde_json::to_value(call).unwrap());
                        if tasks.len() == 3 {
                            // Frozen 0.3.7 error frame: the old daemon has no new SDK
                            // guidance and returns the server's missing-area refusal verbatim.
                            json!({"error":{"http":{
                                "status":422, "code":"validation_error",
                                "message":"area_id is required",
                                "details":{"area_id":["required"],"source":"legacy-daemon"},
                                "retry_after":null,
                            }}})
                        } else {
                            let mut reply = json!({"value":{"id":"CORE-1"}});
                            if let Some(paths) = paths {
                                reply["value"]["paths"] = paths;
                            }
                            reply
                        }
                    }
                };
                serde_json::to_writer(&mut stream, &reply).unwrap();
                stream.write_all(b"\n").unwrap();
            }
            tasks
        });
        let socket = AgentSocket::connect(
            &old_path,
            "https://example.test",
            "team",
            Duration::from_secs(2),
        )
        .expect("0.3.7 peer must accept the 0.3.8 Ping before task frames are exercised");
        assert!(socket.registry_auto_area("worker").unwrap());
        assert_eq!(
            socket.call(&paths_call).unwrap()["paths"],
            paths_body["paths"]
        );
        assert!(!socket.registry_auto_area("worker").unwrap());
        socket.call(&legacy_call).unwrap();
        let mut cloud = CloudBackend::new(socket, "worker");
        let error = cloud
            .add_task(
                "worker",
                &lockyard_core::tasks::TaskSpec {
                    title: "rollback task".into(),
                    paths: vec!["core/src/lib.rs".into()],
                    ..Default::default()
                },
                0,
            )
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("Повтори команду"), "{text}");
        assert_eq!(text.matches("Повтори команду").count(), 1, "{text}");
        assert!(text.contains("--area <область>"), "{text}");
        assert!(text.contains("area_id is required"), "{text}");
        match error {
            Error::Cloud {
                code,
                status,
                details,
                ..
            } => {
                assert_eq!(code, "validation_error");
                assert_eq!(status, Some(422));
                assert_eq!(
                    details,
                    json!({"area_id":["required"],"source":"legacy-daemon"})
                );
            }
            other => panic!("lost old-daemon refusal metadata: {other:?}"),
        }
        let forwarded = peer.join().unwrap();
        assert_eq!(forwarded[0]["body"], paths_body);
        assert_eq!(forwarded[0]["key"], paths_call.key.as_deref().unwrap());
        assert_eq!(forwarded[1]["body"], legacy_body);
        assert_eq!(forwarded[1]["key"], legacy_call.key.as_deref().unwrap());
        assert_eq!(
            forwarded.len(),
            3,
            "one write for the refused task, with no retry"
        );
        assert_eq!(forwarded[2]["body"]["title"], "rollback task");
        assert_eq!(forwarded[2]["body"]["paths"], paths_body["paths"]);
        assert!(forwarded[2]["body"].get("area_id").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn old_client_037_frames_keep_live_protocol_capabilities_on_daemon_038() {
        #[derive(serde::Deserialize)]
        struct ReplyV037 {
            #[serde(default)]
            error: Option<ClientError>,
            #[serde(default)]
            value: Option<Value>,
        }
        let legacy_body = json!({"title":"old task","area_id":"area-core"});
        struct HeaderServer {
            inner: FakeServer,
            supported: AtomicBool,
            cached_capability_reads: AtomicUsize,
        }
        impl Transport for HeaderServer {
            fn registry_auto_area(&self, _session: &str) -> Result<bool, ClientError> {
                self.cached_capability_reads.fetch_add(1, Ordering::SeqCst);
                // An old observation must never override a later live protocol response.
                Ok(true)
            }
            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                if call.path == "/api/v1/protocol" {
                    return Ok(json!({"selected_protocol":2,"capabilities":
                        if self.supported.load(Ordering::SeqCst) {
                            vec!["registry_auto_area_v1"]
                        } else {
                            vec![]
                        }
                    }));
                }
                self.inner.call(call)
            }
        }
        // Client 0.3.7 -> daemon 0.3.8: use the old serialized envelope over the real listener,
        // and the old reply reader. The daemon must forward exactly the live capabilities.
        let dir = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(
            config(dir.path(), timing()),
            HeaderServer {
                inner: FakeServer::default(),
                supported: AtomicBool::new(true),
                cached_capability_reads: AtomicUsize::new(0),
            },
        )
        .unwrap();
        let old_call = |call: Value| {
            let mut stream = UnixStream::connect(&daemon.shared.config.socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            serde_json::to_writer(
                &mut stream,
                &json!({
                    "workspace":"team", "op":"call", "call":call,
                }),
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
            let mut line = String::new();
            BufReader::new(stream).read_line(&mut line).unwrap();
            let reply: ReplyV037 = serde_json::from_str(&line).unwrap();
            assert!(reply.error.is_none(), "{:?}", reply.error);
            reply.value.unwrap()
        };
        let discovery = json!({
            "session":"worker", "method":"GET", "path":"/api/v1/protocol",
            "long_poll":false, "defer_pending_ack":false,
        });
        assert_eq!(
            old_call(discovery.clone())["capabilities"],
            json!(["registry_auto_area_v1"])
        );
        daemon
            .shared
            .transport
            .supported
            .store(false, Ordering::SeqCst);
        assert_eq!(old_call(discovery)["capabilities"], json!([]));
        assert_eq!(
            daemon
                .shared
                .transport
                .cached_capability_reads
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            old_call(json!({
                "session":"worker", "method":"POST", "path":"/api/v1/registry/items",
                "body":legacy_body, "key":"01K00000000000000000000003",
                "long_poll":false, "defer_pending_ack":false,
            }))["id"],
            1
        );
        let writes = daemon.shared.transport.inner.writes_to("/registry/items");
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].body.as_ref().unwrap(), &legacy_body);
        assert_eq!(writes[0].key.as_deref(), Some("01K00000000000000000000003"));
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
        #[cfg(unix)]
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

    // A safety net for conditions that must eventually hold, not a speed check: a stalled shared
    // CI machine once spent more than 5 s before a daemon's first refresh.
    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(30);
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

    fn status_read(session: &str, deadline_ms: u64) -> Request {
        Request::StatusRead {
            session: session.to_string(),
            repository: None,
            deadline_ms,
        }
    }

    #[test]
    fn status_read_never_serves_a_revoked_claim_from_any_cached_view() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        for condition in [
            "fresh",
            "monotonic_stale",
            "sleep",
            "event_dirty",
            "restart",
        ] {
            {
                let mut view = rig.daemon.shared.write_view();
                view.claims = vec![
                    serde_json::from_value(json!({
                        "id": 42, "session": "me", "paths": ["src"],
                        "expires_at": "2099-01-01T00:00:00Z"
                    }))
                    .unwrap(),
                ];
                view.zones_generation = 1;
                view.zones_clean = 1;
                view.zones_at = Some(Instant::now());
                view.zones_wall_at = Some(SystemTime::now());
                match condition {
                    "monotonic_stale" => {
                        view.zones_at = Some(Instant::now() - Duration::from_secs(60));
                    }
                    "sleep" => {
                        view.zones_wall_at = Some(SystemTime::now() - Duration::from_secs(60));
                    }
                    "event_dirty" => view.zones_generation += 1,
                    "restart" => {
                        view.zones_at = None;
                        view.zones_wall_at = None;
                    }
                    _ => {}
                }
            }
            // The authority revoked the cached claim. Event delivery and cache age do not matter.
            let before = rig.server.calls_to("/api/v1/zones/claims");
            let reply = rig.daemon.handle(status_read("me", 500));
            assert!(reply.error.is_none(), "{condition}: {:?}", reply.error);
            assert!(reply.status_read.unwrap().claims.is_empty(), "{condition}");
            assert_eq!(reply.source, Some(Source::Server));
            assert_eq!(rig.server.calls_to("/api/v1/zones/claims"), before + 1);
        }
    }

    #[test]
    fn status_read_cannot_turn_a_fresh_cached_claim_into_authority_during_an_outage() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        {
            let mut view = rig.daemon.shared.write_view();
            view.claims = vec![
                serde_json::from_value(json!({
                    "id": 42, "session": "me", "paths": ["src"],
                    "expires_at": "2099-01-01T00:00:00Z"
                }))
                .unwrap(),
            ];
            view.zones_at = Some(Instant::now());
            view.zones_wall_at = Some(SystemTime::now());
            view.zones_clean = view.zones_generation;
        }
        rig.server.down.store(true, Ordering::SeqCst);
        let reply = rig.daemon.handle(status_read("me", 100));
        assert!(reply.error.is_some());
        assert!(reply.status_read.is_none());
        assert!(reply.claims.is_none());
        assert_ne!(reply.source, Some(Source::View));
        assert_eq!(rig.daemon.shared.status_reads.lock().unwrap().running, 0);
    }

    #[test]
    fn status_read_cold_agent_transport_timeout_permits_direct_fallback_but_rate_limit_does_not() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        *rig.server.claim_failure.lock().unwrap() = Some(ClientError::Transport(
            "Network Error: timed out reading response".into(),
        ));
        let timeout = rig.daemon.handle(status_read("me", 500));
        assert!(
            matches!(timeout.error, Some(ClientError::Transport(ref detail))
            if detail.contains("timed out reading response"))
        );
        assert!(!rig.daemon.shared.status_pool_warm.load(Ordering::Acquire));
        *rig.server.claim_failure.lock().unwrap() =
            Some(ClientError::from_api(lockyard_cloud_client::ApiError {
                status: 429,
                code: "rate_limited".into(),
                message: "rate limiting test".into(),
                ..Default::default()
            }));
        let limited = rig.daemon.handle(status_read("me", 50));
        assert!(
            matches!(limited.error, Some(ClientError::Protocol(ref problem))
            if problem.detail.contains("rate limiting")),
            "unexpected rate-limit error: {:?}",
            limited.error
        );
        // Every required failure contains "within deadline". That alone must never enable
        // fallback for malformed data, an unprovable lease, or an authorization refusal.
        for detail in [
            "status claims unavailable within deadline: invalid claim payload",
            "status cannot validate expiry of claim Z-42",
            "status claims unavailable within deadline: access denied",
            "status claims unavailable within deadline: rate limiting (HTTP 429): timed out",
        ] {
            assert!(
                matches!(
                    status_failure(Error::Unavailable(detail.into())).error,
                    Some(ClientError::Protocol(_))
                ),
                "{detail}"
            );
        }
    }

    #[test]
    fn status_read_successful_claims_enable_warm_overlap_after_cold_task_timeout() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        *rig.server.registry_failure.lock().unwrap() = Some(ClientError::Transport(
            "Network Error: timed out reading response".into(),
        ));
        let cold = rig.daemon.handle(status_read("me", 500));
        assert!(
            matches!(cold.error, Some(ClientError::Transport(_))),
            "{:?}",
            cold.error
        );
        assert!(cold.status_read.is_none());
        assert!(
            rig.daemon.shared.status_pool_warm.load(Ordering::Acquire),
            "successful authoritative claims warm the route even when later tasks time out"
        );
        *rig.server.registry_failure.lock().unwrap() = None;
        let (started, observed) = channel();
        let (resume, paused) = channel();
        *rig.server.claim_gate.lock().unwrap() = Some(LostReadGate {
            started,
            resume: paused,
        });
        let before = rig.server.calls_to("/api/v1/registry/items");
        let shared = Arc::clone(&rig.daemon.shared);
        let warm = thread::spawn(move || shared.status_read("me", None, 1000));
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        // Hold this generation's claims response: assigned task reads must already overlap it.
        wait_for(
            "both assigned task reads while warm claims are in flight",
            || rig.server.calls_to("/api/v1/registry/items") >= before + 2,
        );
        resume.send(()).unwrap();
        let reply = warm.join().unwrap();
        assert!(reply.error.is_none(), "{:?}", reply.error);
        assert_eq!(reply.status_read.unwrap().freshness["claims_cached"], false);
    }

    #[test]
    fn status_read_queue_coalesces_ten_callers_only_before_claims_begin() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.server.calls.lock().unwrap().clear();
        rig.server.claims_started.lock().unwrap().clear();
        // Occupy admission so all ten arrivals deterministically join the same pending generation.
        rig.daemon.shared.status_reads.lock().unwrap().running = MAX_STATUS_READS;
        let barrier = Arc::new(std::sync::Barrier::new(11));
        let mut workers = Vec::new();
        for _ in 0..10 {
            let shared = Arc::clone(&rig.daemon.shared);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                let arrived = Instant::now();
                (arrived, shared.status_read("same", None, 1000))
            }));
        }
        barrier.wait();
        wait_for("all ten status callers to queue", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .map(|batch| batch.waiters)
                .sum::<usize>()
                == 10
        });
        {
            let mut reads = rig.daemon.shared.status_reads.lock().unwrap();
            assert_eq!(reads.pending.len(), 1);
            reads.running = 0;
        }
        rig.daemon.shared.status_ready.notify_all();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let starts = rig.server.claims_started.lock().unwrap().clone();
        assert_eq!(
            starts.len(),
            1,
            "identical queued callers share one new claims GET"
        );
        for (arrived, reply) in results {
            assert!(reply.error.is_none(), "{:?}", reply.error);
            let status = reply.status_read.unwrap();
            assert_eq!(status.freshness["claims_cached"], false);
            assert_eq!(status.freshness["sections"]["claims"]["source"], "network");
            assert!(
                starts[0].1 >= arrived,
                "claims GET must begin after this caller arrived"
            );
        }
        assert_eq!(rig.server.calls.lock().unwrap().len(), 5);
        let arrived = Instant::now();
        assert!(rig.daemon.handle(status_read("same", 500)).error.is_none());
        let starts = rig.server.claims_started.lock().unwrap();
        assert_eq!(
            starts.len(),
            2,
            "completed answers are never reused for a later caller"
        );
        assert!(starts[1].1 >= arrived);
        let reads = rig.daemon.shared.status_reads.lock().unwrap();
        assert_eq!(reads.running, 0);
        assert!(reads.pending.is_empty() && reads.batches.is_empty());
    }

    #[test]
    fn status_read_arrival_after_claims_begin_gets_a_new_generation() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.server.claims_started.lock().unwrap().clear();
        rig.server.hang_ms.store(80, Ordering::SeqCst);
        let shared = Arc::clone(&rig.daemon.shared);
        let first_arrived = Instant::now();
        let first = thread::spawn(move || shared.status_read("same", None, 1000));
        wait_for("first claims GET to begin", || {
            !rig.server.claims_started.lock().unwrap().is_empty()
        });
        let second_arrived = Instant::now();
        let second = rig.daemon.handle(status_read("same", 1000));
        assert!(first.join().unwrap().error.is_none());
        assert!(second.error.is_none(), "{:?}", second.error);
        let starts = rig.server.claims_started.lock().unwrap();
        assert_eq!(
            starts.len(),
            2,
            "in-flight claims that began before arrival cannot be joined"
        );
        assert!(starts[0].1 >= first_arrived && starts[0].1 < second_arrived);
        assert!(starts[1].1 >= second_arrived);
    }

    #[test]
    fn status_read_queue_serves_ten_distinct_sessions_with_three_active_generations() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.server.calls.lock().unwrap().clear();
        rig.server.claims_started.lock().unwrap().clear();
        rig.server.hang_ms.store(20, Ordering::SeqCst);
        let barrier = Arc::new(std::sync::Barrier::new(11));
        let mut workers = Vec::new();
        for index in 0..10 {
            let shared = Arc::clone(&rig.daemon.shared);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let session = format!("distinct-{index}");
                barrier.wait();
                let arrived = Instant::now();
                let reply = shared.status_read(&session, None, 1000);
                (session, arrived, reply)
            }));
        }
        barrier.wait();
        loop {
            assert!(rig.daemon.shared.status_reads.lock().unwrap().running <= MAX_STATUS_READS);
            if workers.iter().all(JoinHandle::is_finished) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let starts = rig.server.claims_started.lock().unwrap().clone();
        assert_eq!(starts.len(), 10);
        for worker in workers {
            let (session, arrived, reply) = worker.join().unwrap();
            assert!(reply.error.is_none(), "{session}: {:?}", reply.error);
            assert!(
                starts
                    .iter()
                    .any(|(name, start)| name == &session && *start >= arrived)
            );
        }
        assert_eq!(rig.server.calls.lock().unwrap().len(), 50);
        let reads = rig.daemon.shared.status_reads.lock().unwrap();
        assert_eq!(reads.running, 0);
        assert!(reads.pending.is_empty() && reads.batches.is_empty());
    }

    #[test]
    fn status_read_queue_deadline_removes_waiter_without_starting_http() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.daemon.shared.status_reads.lock().unwrap().running = MAX_STATUS_READS;
        let before = rig.server.calls.lock().unwrap().len();
        let started = Instant::now();
        let reply = rig.daemon.handle(status_read("me", 30));
        assert!(started.elapsed() >= Duration::from_millis(25));
        assert!(started.elapsed() < Duration::from_millis(150));
        assert!(reply.error.unwrap().to_string().contains("deadline"));
        assert_eq!(rig.server.calls.lock().unwrap().len(), before);
        {
            let mut reads = rig.daemon.shared.status_reads.lock().unwrap();
            assert!(reads.pending.is_empty() && reads.batches.is_empty());
            reads.running = 0;
        }
        let reply = rig.daemon.handle(Request::StatusRead {
            session: "me".into(),
            repository: Some("../invalid".into()),
            deadline_ms: 500,
        });
        assert!(reply.error.is_some());
        assert_eq!(rig.daemon.shared.status_reads.lock().unwrap().running, 0);
    }

    // Uses the same LocalStream alias on Windows; no Unix-only peek/poll API is needed.
    fn status_peer(
        rig: &Rig,
        name: &str,
        session: &str,
        deadline_ms: u64,
    ) -> (UnixStream, JoinHandle<()>) {
        let path = rig.dir.path().join(name);
        let listener = UnixListener::bind(&path).unwrap();
        let shared = Arc::clone(&rig.daemon.shared);
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = answer(&shared, stream);
        });
        let mut stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        writeln!(
            stream,
            "{}",
            serde_json::to_string(&Envelope {
                workspace: "team".into(),
                request: status_read(session, deadline_ms),
            })
            .unwrap()
        )
        .unwrap();
        (stream, worker)
    }

    fn status_peer_reply(stream: &mut UnixStream) -> Reply {
        let mut line = String::new();
        // Do not prefetch a second reply out of the caller's stream.
        let mut reader = BufReader::with_capacity(1, stream);
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn status_read_disconnected_queued_peer_frees_full_admission_without_deadline() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        {
            let mut reads = rig.daemon.shared.status_reads.lock().unwrap();
            reads.running = MAX_STATUS_READS;
            // Represent the other 127 admitted callers without spawning 127 fixture threads.
            reads.batches.insert(
                u64::MAX,
                StatusBatch {
                    session: "fillers".into(),
                    repository: None,
                    ready_at: Instant::now(),
                    deadline: Instant::now() + STATUS_READ_LIMIT,
                    waiters: MAX_STATUS_CALLERS - 1,
                    running: false,
                    reply: None,
                    cancellation: Cancellation::new(),
                },
            );
            reads.pending.push_back(u64::MAX);
        }
        let (dead, dead_worker) = status_peer(&rig, "q", "dead", 2600);
        wait_for("full status queue", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .map(|batch| batch.waiters)
                .sum::<usize>()
                == MAX_STATUS_CALLERS
        });
        assert!(
            rig.daemon
                .handle(status_read("overflow", 2600))
                .error
                .unwrap()
                .to_string()
                .contains("queue is full")
        );
        let departed = Instant::now();
        drop(dead);
        wait_for("EOF to remove the dead queued caller", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .map(|batch| batch.waiters)
                .sum::<usize>()
                == MAX_STATUS_CALLERS - 1
        });
        assert!(departed.elapsed() < Duration::from_millis(100));
        dead_worker.join().unwrap();
        let (mut live, live_worker) = status_peer(&rig, "n", "next", 2600);
        wait_for("replacement admitted before old deadline", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .map(|batch| batch.waiters)
                .sum::<usize>()
                == MAX_STATUS_CALLERS
        });
        assert!(departed.elapsed() < Duration::from_millis(200));
        {
            let mut reads = rig.daemon.shared.status_reads.lock().unwrap();
            reads.batches.remove(&u64::MAX);
            reads.pending.retain(|id| *id != u64::MAX);
            reads.running = 0;
        }
        rig.daemon.shared.status_ready.notify_all();
        assert!(status_peer_reply(&mut live).error.is_none());
        drop(live);
        live_worker.join().unwrap();
        assert!(
            !rig.server
                .claims_started
                .lock()
                .unwrap()
                .iter()
                .any(|(session, _)| session == "dead")
        );
    }

    #[test]
    fn status_read_twenty_soft_peer_disconnects_at_850ms_do_not_delay_next_hard() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.daemon.shared.status_reads.lock().unwrap().running = MAX_STATUS_READS;
        let peers = (0..20)
            .map(|index| status_peer(&rig, &format!("s{index}"), &format!("soft-{index}"), 2600))
            .collect::<Vec<_>>();
        wait_for("twenty soft callers queued", || {
            rig.daemon.shared.status_reads.lock().unwrap().pending.len() == 20
        });
        thread::sleep(Duration::from_millis(850));
        let departed = Instant::now();
        let mut workers = Vec::new();
        for (stream, worker) in peers {
            drop(stream);
            workers.push(worker);
        }
        wait_for("all disconnected soft callers to leave", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .is_empty()
        });
        assert!(departed.elapsed() < Duration::from_millis(100));
        for worker in workers {
            worker.join().unwrap();
        }
        rig.daemon.shared.status_reads.lock().unwrap().running = 0;
        rig.daemon.shared.status_ready.notify_all();
        rig.server.hang_ms.store(20, Ordering::SeqCst);
        let started = Instant::now();
        let (mut hard, worker) = status_peer(&rig, "h", "hard", 2600);
        assert!(status_peer_reply(&mut hard).error.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "hard caller waited for dead callers' 2600ms deadlines"
        );
        drop(hard);
        worker.join().unwrap();
        assert!(
            !rig.server
                .claims_started
                .lock()
                .unwrap()
                .iter()
                .any(|(session, _)| session.starts_with("soft-"))
        );
    }

    #[test]
    fn status_read_dead_running_peer_cancels_only_its_generation_and_drops_result() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        let (started, observed) = channel();
        let (resume, paused) = channel();
        *rig.server.claim_gate.lock().unwrap() = Some(LostReadGate {
            started,
            resume: paused,
        });
        rig.daemon.shared.signal().nudged = false;
        let (dead, worker) = status_peer(&rig, "d", "dead-running", 2600);
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(rig.daemon.shared.status().status_read_abandoned, None);
        let cancellation = rig
            .daemon
            .shared
            .status_reads
            .lock()
            .unwrap()
            .batches
            .values()
            .next()
            .unwrap()
            .cancellation
            .clone();
        drop(dead);
        wait_for("running generation cancellation on EOF", || {
            cancellation.is_cancelled()
        });
        worker.join().unwrap();
        // One abandoned generation with two still free: no advisory, the agent keeps answering
        // (the hard call below proves it). The advisory appears only with every generation taken.
        assert_eq!(rig.daemon.shared.status().status_read_abandoned, None);
        assert_eq!(abandoned_read_advisory(MAX_STATUS_READS - 1, true), None);
        assert_eq!(abandoned_read_advisory(MAX_STATUS_READS, false), None);
        assert_eq!(abandoned_read_advisory(MAX_STATUS_READS, true), Some(true));
        assert!(
            !rig.daemon.shared.signal().nudged,
            "a dead caller must not start redundant upkeep"
        );
        assert_eq!(
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .map(|batch| batch.waiters)
                .sum::<usize>(),
            0
        );
        let hard_started = Instant::now();
        let (mut hard, hard_worker) = status_peer(&rig, "h", "live-other", 2600);
        assert!(status_peer_reply(&mut hard).error.is_none());
        assert!(hard_started.elapsed() < Duration::from_millis(150));
        drop(hard);
        hard_worker.join().unwrap();
        // The fake transport cannot interrupt its held claims read; releasing it models ureq
        // returning headers/body. No later section of the abandoned generation may be sent.
        let before = rig.server.calls.lock().unwrap().len();
        resume.send(()).unwrap();
        wait_for("abandoned worker and result to be discarded", || {
            let reads = rig.daemon.shared.status_reads.lock().unwrap();
            reads.running == 0 && reads.batches.is_empty()
        });
        assert_eq!(rig.server.calls.lock().unwrap().len(), before);
        assert_eq!(rig.daemon.shared.status().status_read_abandoned, None);
    }

    #[test]
    fn status_read_dead_coalesced_member_does_not_cancel_live_member() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.daemon.shared.status_reads.lock().unwrap().running = MAX_STATUS_READS;
        let (dead, dead_worker) = status_peer(&rig, "d", "same", 500);
        let (mut live, live_worker) = status_peer(&rig, "l", "same", 2600);
        wait_for("two coalesced members", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .any(|batch| batch.waiters == 2)
        });
        let (started, observed) = channel();
        let (resume, paused) = channel();
        *rig.server.claim_gate.lock().unwrap() = Some(LostReadGate {
            started,
            resume: paused,
        });
        rig.daemon.shared.status_reads.lock().unwrap().running = 0;
        rig.daemon.shared.status_ready.notify_all();
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(dead);
        wait_for("dead member alone to leave", || {
            rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .any(|batch| batch.waiters == 1)
        });
        dead_worker.join().unwrap();
        assert_eq!(rig.daemon.shared.status().status_read_abandoned, None);
        assert!(
            !rig.daemon
                .shared
                .status_reads
                .lock()
                .unwrap()
                .batches
                .values()
                .next()
                .unwrap()
                .cancellation
                .is_cancelled()
        );
        // Cross the dead member's own deadline to prove it did not poison the live budget.
        thread::sleep(Duration::from_millis(550));
        resume.send(()).unwrap();
        let reply = status_peer_reply(&mut live);
        assert!(reply.error.is_none(), "{:?}", reply.error);
        drop(live);
        live_worker.join().unwrap();
        assert_eq!(
            rig.server
                .claims_started
                .lock()
                .unwrap()
                .iter()
                .filter(|(session, _)| session == "same")
                .count(),
            1
        );
    }

    #[test]
    fn status_read_peer_monitor_preserves_pipelined_requests() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.server.hang_ms.store(20, Ordering::SeqCst);
        let (mut stream, worker) = status_peer(&rig, "p", "same", 2600);
        writeln!(
            stream,
            "{}",
            serde_json::to_string(&Envelope {
                workspace: "team".into(),
                request: Request::Ping
            })
            .unwrap()
        )
        .unwrap();
        assert!(status_peer_reply(&mut stream).status_read.is_some());
        assert!(status_peer_reply(&mut stream).status.is_some());
        drop(stream);
        worker.join().unwrap();
    }

    #[test]
    fn status_read_registers_membership_but_defers_upkeep_until_live_answer() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.daemon.shared.signal().nudged = false;
        let (started, observed) = channel();
        let (resume, paused) = channel();
        *rig.server.claim_gate.lock().unwrap() = Some(LostReadGate {
            started,
            resume: paused,
        });
        let shared = Arc::clone(&rig.daemon.shared);
        let worker = thread::spawn(move || shared.status_read("new-status", None, 2600));
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(rig.daemon.shared.sessions().contains_key("new-status"));
        assert!(
            rig.daemon
                .shared
                .read_view()
                .unread
                .contains_key("new-status")
        );
        assert!(
            !rig.daemon.shared.signal().nudged,
            "status must not wake upkeep before its own reads"
        );
        // Reconciliation must retain the in-flight entry because membership already exists.
        rig.daemon.shared.refresh_unread();
        assert!(
            rig.daemon
                .shared
                .read_view()
                .unread
                .contains_key("new-status")
        );
        resume.send(()).unwrap();
        assert!(worker.join().unwrap().error.is_none());
        assert!(
            rig.daemon.shared.signal().nudged,
            "a successful live answer starts normal upkeep"
        );
    }

    #[test]
    fn status_read_uses_only_a_fresh_unread_cache_and_reports_its_age() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        *rig.server.unread.lock().unwrap() = 11;
        for condition in [
            "fresh",
            "monotonic_stale",
            "sleep",
            "event_dirty",
            "restart",
        ] {
            {
                let mut view = rig.daemon.shared.write_view();
                let mut unread = UnreadCount {
                    count: 7,
                    generation: 3,
                    clean: 3,
                    at: Some(Instant::now() - Duration::from_millis(20)),
                    wall_at: Some(SystemTime::now() - Duration::from_millis(25)),
                };
                match condition {
                    "monotonic_stale" => unread.at = Some(Instant::now() - Duration::from_secs(60)),
                    "sleep" => unread.wall_at = Some(SystemTime::now() - Duration::from_secs(60)),
                    "event_dirty" => unread.generation += 1,
                    "restart" => {
                        unread.at = None;
                        unread.wall_at = None;
                    }
                    _ => {}
                }
                view.unread.insert("me".into(), unread);
            }
            let before = rig.server.calls_to("/api/v1/bus/inbox");
            let reply = rig.daemon.handle(status_read("me", 500));
            assert!(reply.error.is_none(), "{condition}: {:?}", reply.error);
            let read = reply.status_read.unwrap();
            if condition == "fresh" {
                assert_eq!(read.unread, Some(7));
                assert_eq!(read.freshness["sections"]["unread"]["source"], "view");
                assert!(
                    read.freshness["sections"]["unread"]["age_ms"]
                        .as_u64()
                        .unwrap()
                        >= 25
                );
                assert_eq!(rig.server.calls_to("/api/v1/bus/inbox"), before);
            } else {
                assert_eq!(read.unread, Some(11), "{condition}");
                assert_eq!(read.freshness["sections"]["unread"]["source"], "network");
                assert_eq!(rig.server.calls_to("/api/v1/bus/inbox"), before + 1);
            }
        }
        let before = rig.server.calls_to("/api/v1/bus/inbox");
        let read = rig
            .daemon
            .handle(status_read("me", 500))
            .status_read
            .unwrap();
        assert_eq!(read.unread, Some(11));
        assert_eq!(read.freshness["sections"]["unread"]["source"], "view");
        assert_eq!(rig.server.calls_to("/api/v1/bus/inbox"), before);
    }

    #[test]
    fn status_read_preserves_an_unread_cache_that_expires_during_network_wait() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        {
            let mut view = rig.daemon.shared.write_view();
            view.unread.insert(
                "me".into(),
                UnreadCount {
                    count: 7,
                    at: Some(Instant::now() - Duration::from_millis(350)),
                    wall_at: Some(SystemTime::now() - Duration::from_millis(350)),
                    ..Default::default()
                },
            );
        }
        rig.server.hang_ms.store(100, Ordering::SeqCst);
        let before = rig.server.calls_to("/api/v1/bus/inbox");
        let read = rig
            .daemon
            .handle(status_read("me", 500))
            .status_read
            .unwrap();
        assert_eq!(read.unread, Some(7));
        assert_eq!(read.freshness["sections"]["unread"]["source"], "stale");
        assert_eq!(read.freshness["sections"]["unread"]["available"], true);
        assert_eq!(read.freshness["sections"]["unread"]["stale"], true);
        assert_eq!(rig.server.calls_to("/api/v1/bus/inbox"), before);
    }

    #[test]
    fn status_read_mail_failure_preserves_last_known_value_even_after_thirty_seconds() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        *rig.server.fail_inbox_for.lock().unwrap() = Some("me".into());
        rig.daemon.shared.write_view().unread.insert(
            "me".into(),
            UnreadCount {
                count: 7,
                at: Some(Instant::now() - Duration::from_secs(60)),
                wall_at: Some(SystemTime::now() - Duration::from_secs(60)),
                ..Default::default()
            },
        );
        let before = rig.server.calls_to("/api/v1/bus/inbox");
        let reply = rig.daemon.handle(status_read("me", 500));
        assert!(reply.error.is_none(), "{:?}", reply.error);
        let status = reply.status_read.unwrap();
        assert_eq!(status.unread, Some(7));
        let metadata = &status.freshness["sections"]["unread"];
        assert_eq!(metadata["source"], "stale");
        assert_eq!(metadata["stale"], true);
        assert_eq!(metadata["available"], true);
        assert!(metadata["age_ms"].as_u64().unwrap() >= 60_000);
        assert!(
            metadata["error"]
                .as_str()
                .unwrap()
                .contains("inbox unavailable")
        );
        assert_eq!(rig.server.calls_to("/api/v1/bus/inbox"), before + 1);
        rig.daemon.shared.write_view().unread.remove("me");
        let unknown = rig
            .daemon
            .handle(status_read("me", 500))
            .status_read
            .unwrap();
        assert_eq!(
            unknown.unread, None,
            "unknown mail is never invented as zero"
        );
        assert_eq!(unknown.freshness["sections"]["unread"]["available"], false);
        assert_eq!(unknown.freshness["sections"]["unread"]["source"], "unknown");
    }

    #[test]
    fn status_read_mail_failure_uses_a_count_first_learned_during_the_read() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        *rig.server.fail_inbox_for.lock().unwrap() = Some("me".into());
        rig.server.hang_ms.store(60, Ordering::SeqCst);
        let before = rig.server.calls_to("/api/v1/bus/inbox");
        let shared = Arc::clone(&rig.daemon.shared);
        let worker = thread::spawn(move || shared.status_read("me", None, 500));
        wait_for("mail GET to begin", || {
            rig.server.calls_to("/api/v1/bus/inbox") > before
        });
        rig.daemon.shared.store_unread("me", 0, 9);
        let status = worker.join().unwrap().status_read.unwrap();
        assert_eq!(status.unread, Some(9));
        assert_eq!(status.freshness["sections"]["unread"]["source"], "stale");
        assert_eq!(status.freshness["sections"]["unread"]["stale"], true);
    }

    #[test]
    fn status_read_cached_mail_uses_the_latest_count_learned_while_waiting() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        rig.daemon.shared.store_unread("me", 0, 7);
        rig.server.hang_ms.store(60, Ordering::SeqCst);
        let before = rig.server.calls_to("/api/v1/zones/claims");
        let shared = Arc::clone(&rig.daemon.shared);
        let worker = thread::spawn(move || shared.status_read("me", None, 500));
        wait_for("claims GET to begin", || {
            rig.server.calls_to("/api/v1/zones/claims") > before
        });
        rig.daemon.shared.store_unread("me", 0, 9);
        let status = worker.join().unwrap().status_read.unwrap();
        assert_eq!(status.unread, Some(9));
        assert_eq!(status.freshness["sections"]["unread"]["source"], "view");
        assert_eq!(status.freshness["sections"]["unread"]["stale"], false);
    }

    #[test]
    fn status_read_does_not_block_memory_requests_while_the_network_waits() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        // Hang ≫ 100 ms memory budget so a blocking defect stays visible (~100 ms margin).
        // Two hung network steps need headroom above the reply_reserve floor, so the status
        // deadline is 800 ms rather than 500 ms (test scope only — not a product change).
        rig.server.hang_ms.store(200, Ordering::SeqCst);
        let before = rig.server.calls_to("/api/v1/zones/claims");
        let shared = Arc::clone(&rig.daemon.shared);
        let worker = thread::spawn(move || shared.status_read("me", None, 800));
        wait_for("a status network request", || {
            rig.server.calls_to("/api/v1/zones/claims") > before
        });
        let started = Instant::now();
        let reply = rig.daemon.handle(Request::Ping);
        assert!(reply.status.unwrap().status_read_v1);
        let _ = rig.daemon.handle(Request::ZoneSnapshot {
            session: "me".into(),
        });
        assert!(started.elapsed() < Duration::from_millis(100));
        let finished = worker.join().unwrap();
        assert!(
            finished.error.is_none(),
            "status read must finish without holding memory requests: {:?}",
            finished.error
        );
    }

    #[test]
    fn status_read_tiny_budget_still_answers_instead_of_becoming_an_error() {
        // reply_reserve clamps to ≥25 ms. A 25 ms (or shorter) agent budget must not turn into a
        // hard protocol failure: either a status payload or a transport error that lets the CLI
        // take its direct-read path.
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        for deadline_ms in [25_u64, 10, 1] {
            let reply = rig.daemon.handle(status_read("me", deadline_ms));
            assert!(
                reply.status_read.is_some()
                    || matches!(reply.error, Some(ClientError::Transport(_))),
                "tiny status budget {deadline_ms} ms must stay answerable or direct-fallbackable, got {:?}",
                reply.error
            );
            assert!(
                !matches!(reply.error, Some(ClientError::Protocol(_))),
                "tiny status budget {deadline_ms} ms must not become a protocol error: {:?}",
                reply.error
            );
        }
    }

    #[test]
    fn status_read_preserves_repository_scope_on_the_shared_daemon_transport() {
        #[derive(Default)]
        struct ScopedAuthority {
            other: FakeServer,
            reads: Mutex<Vec<Call>>,
        }
        impl Transport for ScopedAuthority {
            fn verifies_repository_reads(&self) -> bool {
                // Model the real HTTP Client, which verifies the namespace echo on every read.
                true
            }

            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                if call.path.starts_with("/api/v1/zones/claims") && call.session == "alice" {
                    self.reads.lock().unwrap().push(call.clone());
                    let repository = call.repository.as_deref().unwrap_or_default();
                    if call.path.ends_with("&namespace_probe=1") {
                        return Ok(json!({
                            "repository_namespace_supported": true, "repository": repository,
                            "claims": [],
                        }));
                    }
                    return Ok(json!({"claims": [{
                        "id": if repository == "api" { 1 } else { 2 },
                        "session": "alice", "expires_at": "2099-01-01T00:00:00Z",
                        "paths": [format!(".lockyard-repository/{repository}/src/lib.rs")],
                    }]}));
                }
                self.other.call(call)
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let authority = Arc::new(ScopedAuthority::default());
        let mut daemon =
            Daemon::start(config(directory.path(), timing()), authority.clone()).unwrap();
        daemon.stop_workers();
        for (repository, claim_id) in [("api", 1), ("web", 2), ("api", 1)] {
            let reply = daemon.handle(Request::StatusRead {
                session: "alice".into(),
                repository: Some(repository.into()),
                deadline_ms: 500,
            });
            assert!(reply.error.is_none(), "{:?}", reply.error);
            let claims = reply.status_read.unwrap().claims;
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0].id, claim_id);
            assert_eq!(claims[0].paths, ["src/lib.rs"]);
        }
        let reads = authority.reads.lock().unwrap();
        assert_eq!(
            reads.len(),
            3,
            "scoped reads verify their own namespace without extra probes"
        );
        assert_eq!(reads[0].repository.as_deref(), Some("api"));
        assert_eq!(reads[1].repository.as_deref(), Some("web"));
        assert_eq!(reads[2].repository.as_deref(), Some("api"));
        assert!(
            reads
                .iter()
                .all(|read| !read.path.ends_with("&namespace_probe=1"))
        );
        drop(reads);
        let invalid = daemon.handle(Request::StatusRead {
            session: "alice".into(),
            repository: Some("../api".into()),
            deadline_ms: 500,
        });
        assert!(matches!(invalid.error, Some(ClientError::Invalid(_))));
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
        #[cfg(unix)]
        let socket = AgentSocket::connect(
            &rig.dir.path().join("run/agent.sock"),
            "https://example.test",
            "team",
            Duration::from_secs(1),
        )
        .unwrap();
        #[cfg(windows)]
        let socket = AgentSocket::connect_in_state(
            &rig.dir.path().join("run/agent.sock"),
            "https://example.test",
            "team",
            Duration::from_secs(1),
            &rig.dir.path().join("state"),
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
    fn cache_checks_keep_repository_roots_separate_and_follow_the_server_case_policy() {
        let view = View {
            claims: vec![
                serde_json::from_value(json!({"id": 1, "session": "bob", "paths": [".lockyard-repository/api/SRC"], "case_insensitive_paths": true})).unwrap(),
                serde_json::from_value(json!({"id": 2, "session": "carol", "paths": ["."], "case_insensitive_paths": false})).unwrap(),
            ],
            ..View::default()
        };
        let status = |path: &str| view.check("alice", &[path.to_string()]).remove(0).status;
        assert_eq!(
            status(".lockyard-repository/api/src/file"),
            CheckStatus::Held
        );
        assert_eq!(
            status(".lockyard-repository/web/src/file"),
            CheckStatus::Free
        );
        assert_eq!(status("src/file"), CheckStatus::Held);
    }

    #[test]
    fn insensitive_unicode_comparisons_require_the_authoritative_server() {
        for (held, requested, excluded) in [
            ("Ä", "ä/file", ""),
            ("Ж", "ж/file", ""),
            ("Ä", "ascii", ""),
            ("ascii", "Ä", ""),
            ("ascii", "ascii/file", "ascii/Ä"),
        ] {
            let held = format!(".lockyard-repository/api/{held}");
            let excluded =
                (!excluded.is_empty()).then(|| format!(".lockyard-repository/api/{excluded}"));
            let mut claim: Claim = serde_json::from_value(
                json!({"id":1,"session":"bob","paths":[held],"case_insensitive_paths":true}),
            )
            .unwrap();
            claim.excluded_paths = excluded.into_iter().collect();
            let mut view = View {
                claims: vec![claim],
                ..View::default()
            };
            let requested = format!(".lockyard-repository/api/{requested}");
            assert_eq!(
                view.check("alice", std::slice::from_ref(&requested))[0].status,
                CheckStatus::Unknown
            );
            assert_eq!(
                view.check("alice", &[".lockyard-repository/web/ascii".into()])[0].status,
                CheckStatus::Free
            );
            view.claims[0].case_insensitive_paths = Some(false);
            assert_ne!(
                view.check("alice", &[requested])[0].status,
                CheckStatus::Unknown
            );
        }
    }

    #[test]
    fn a_fresh_unicode_insensitive_view_falls_back_to_the_server() {
        let rig = start_with(timing(), |server| {
            server.claims.lock().unwrap().push(json!({"id":1,"session":"bob","paths":[".lockyard-repository/api/Ä"],"case_insensitive_paths":true}));
        });
        view_ready(&rig);
        let before = rig.server.calls_to("/api/v1/zones/check");
        let reply = rig
            .daemon
            .handle(check("alice", ".lockyard-repository/api/ä/file"));
        assert_eq!(reply.source, Some(Source::Server));
        assert_eq!(rig.server.calls_to("/api/v1/zones/check"), before + 1);
    }

    #[test]
    fn successful_namespace_probes_are_cached_per_daemon_but_failures_are_not() {
        let rig = start_with(timing(), |_| {});
        let probe = |repository: &str| {
            let mut call = Call::get(
                "me",
                format!(
                    "/api/v1/zones/claims?path={}&namespace_probe=1",
                    lockyard_cloud_client::encode(&format!(".lockyard-repository/{repository}"))
                ),
            );
            call.repository = Some(repository.to_string());
            Request::Call { call }
        };
        let first = rig.daemon.handle(probe("api"));
        assert_eq!(first.value.unwrap()["repository_namespace_supported"], true);
        let cached = rig.daemon.handle(probe("api"));
        assert_eq!(cached.source, Some(Source::View));
        assert_eq!(rig.server.namespace_probes.load(Ordering::SeqCst), 1);
        rig.server
            .namespace_unsupported
            .store(true, Ordering::SeqCst);
        assert!(rig.daemon.handle(probe("web")).error.is_some());
        rig.server
            .namespace_unsupported
            .store(false, Ordering::SeqCst);
        assert!(rig.daemon.handle(probe("web")).error.is_none());
        assert_eq!(rig.server.namespace_probes.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn unread_registers_unknown_then_upkeep_fills_it_and_events_refresh_it() {
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
        rig.server.hang_ms.store(80, Ordering::SeqCst);
        let ask = || Request::Unread {
            session: "me".into(),
        };
        let started = Instant::now();
        let first = rig.daemon.handle(ask());
        assert_eq!((first.unread, first.source), (None, Some(Source::None)));
        assert!(started.elapsed() < Duration::from_millis(20));
        wait_for("the first unread count", || {
            let reply = rig.daemon.handle(ask());
            reply.unread == Some(2) && reply.source == Some(Source::View)
        });
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

    fn board_entries() -> Vec<Value> {
        vec![
            json!({
                "key": "freeze", "value": {"reason": "release"}, "zone": "core",
                "session": "alice", "created_at": "2026-11-12T08:00:00Z",
                "updated_at": "2026-11-12T08:05:00Z",
                "expires_at": "2026-11-12T10:00:00Z"
            }),
            json!({
                "key": "notice", "value": "all zones", "zone": null,
                "session": "bob", "created_at": "2026-11-12T07:00:00Z",
                "updated_at": "2026-11-12T07:00:00Z", "expires_at": null
            }),
            json!({
                "key": "freeze", "value": "deploy", "zone": "cloud",
                "session": "carol", "created_at": "2026-11-12T09:00:00Z",
                "updated_at": "2026-11-12T09:00:00Z", "expires_at": null
            }),
        ]
    }

    fn board_snapshot(rig: &Rig) -> Value {
        serde_json::to_value(rig.daemon.handle(Request::ZoneSnapshot {
            session: "me".into(),
        }))
        .unwrap()
    }

    #[test]
    fn zone_snapshot_board_is_loaded_in_background_with_zone_and_global_metadata() {
        let entries = board_entries();
        let mut rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |server| *server.board.lock().unwrap() = Some(entries.clone()),
        );
        // No client request, including a board read, primes the background refresh.
        wait_for("background board initialization", || {
            rig.daemon
                .shared
                .read_view()
                .board_fresh(Duration::from_secs(30))
        });
        rig.daemon.stop_workers();
        assert!(rig.server.calls_to("/api/v1/bus/board") > 0);
        let reply = board_snapshot(&rig);
        assert_eq!(reply["board_source"], "view");
        assert_eq!(reply["board"], json!(entries));
        assert!(reply["board_age_ms"].is_u64());
    }

    #[test]
    fn zone_snapshot_board_fresh_empty_is_an_authoritative_array() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        {
            let mut view = rig.daemon.shared.write_view();
            view.board.clear();
            view.board_clean = view.board_generation;
            view.board_at = Some(Instant::now());
            view.board_wall_at = Some(SystemTime::now());
            // Board freshness is independent of the claims snapshot.
            view.zones_at = None;
        }
        let reply = board_snapshot(&rig);
        assert_eq!(reply["source"], "none");
        assert_eq!(reply["board_source"], "view");
        assert_eq!(reply["board"], json!([]));
        assert!(reply["board_age_ms"].is_u64());
    }

    #[test]
    fn zone_snapshot_board_stale_by_either_clock_or_event_omits_cached_entries() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        for stale in ["monotonic", "wall", "event"] {
            {
                let mut view = rig.daemon.shared.write_view();
                view.board = serde_json::from_value(json!(board_entries())).unwrap();
                view.board_at = Some(Instant::now() - Duration::from_millis(900));
                view.board_wall_at = Some(SystemTime::now());
                view.board_clean = view.board_generation;
                view.zones_at = Some(Instant::now());
                if stale != "monotonic" {
                    view.board_at = Some(Instant::now());
                }
                if stale == "wall" {
                    view.board_wall_at = Some(SystemTime::now() - Duration::from_millis(900));
                }
                if stale == "event" {
                    view.board_generation += 1;
                }
            }
            let reply = board_snapshot(&rig);
            assert_eq!(reply["source"], "view");
            assert_eq!(reply["board_source"], "none", "{stale}");
            assert!(reply.get("board").is_none(), "{stale}: {reply}");
            assert!(reply["board_age_ms"].is_u64(), "{stale}");
            if stale == "monotonic" {
                assert!(reply["board_age_ms"].as_u64().unwrap() >= 900);
            }
        }
    }

    #[test]
    fn zone_snapshot_board_uninitialized_is_unknown_without_an_age() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        *rig.daemon.shared.write_view() = View::default();
        let reply = board_snapshot(&rig);
        assert_eq!(reply["board_source"], "none");
        assert!(reply.get("board").is_none());
        assert!(reply.get("board_age_ms").is_none());
    }

    #[test]
    fn zone_snapshot_board_never_uses_transport_even_when_stale_or_uninitialized() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        let before = rig.server.calls.lock().unwrap().len();
        let polls_before = rig.server.event_calls.load(Ordering::SeqCst);
        for state in ["fresh", "stale", "uninitialized"] {
            {
                let mut view = rig.daemon.shared.write_view();
                *view = View::default();
                if state != "uninitialized" {
                    view.board = serde_json::from_value(json!(board_entries())).unwrap();
                    view.board_at = Some(Instant::now());
                    view.board_wall_at = Some(SystemTime::now());
                }
                if state == "stale" {
                    view.board_generation += 1;
                }
            }
            for down in [true, false] {
                rig.server.down.store(down, Ordering::SeqCst);
                rig.server.hang_ms.store(2_000, Ordering::SeqCst);
                let started = Instant::now();
                let reply = board_snapshot(&rig);
                assert!(
                    started.elapsed() < Duration::from_millis(40),
                    "{state}: {reply}"
                );
                assert_eq!(rig.server.calls.lock().unwrap().len(), before);
                assert_eq!(rig.server.event_calls.load(Ordering::SeqCst), polls_before);
                assert_eq!(
                    reply["board_source"],
                    if state == "fresh" { "view" } else { "none" }
                );
            }
        }
    }

    #[test]
    fn zone_snapshot_never_calls_the_backend_when_down_or_blocked() {
        let mut rig = start_with(timing(), |_| {});
        view_ready(&rig);
        rig.daemon.stop_workers();
        let before = rig.server.calls.lock().unwrap().len();
        let ask = || Request::ZoneSnapshot {
            session: "me".into(),
        };
        rig.server.down.store(true, Ordering::SeqCst);
        let down = rig.daemon.handle(ask());
        assert_eq!(down.source, Some(Source::View));
        rig.server.down.store(false, Ordering::SeqCst);
        rig.server.hang_ms.store(2_000, Ordering::SeqCst);
        let started = Instant::now();
        let blocked = rig.daemon.handle(ask());
        assert!(started.elapsed() < Duration::from_millis(20));
        assert_eq!(blocked.source, Some(Source::View));
        assert_eq!(rig.server.calls.lock().unwrap().len(), before);
    }

    #[test]
    fn a_zone_event_refreshes_claims_queue_and_requests_in_the_snapshot() {
        let rig = start_with(timing(), |_| {});
        view_ready(&rig);
        rig.server.claim(8, "holder", "src");
        *rig.server.queue.lock().unwrap() =
            vec![json!({"id": 2, "session": "waiter", "paths": ["src"]})];
        *rig.server.requests.lock().unwrap() =
            vec![json!({"id": 3, "from": "asker", "text": "help"})];
        rig.server.event("zone.claimed", None);
        wait_for("the changed zone snapshot", || {
            let reply = rig.daemon.handle(Request::ZoneSnapshot {
                session: "me".into(),
            });
            reply.claims.as_ref().is_some_and(|items| items.len() == 1)
                && reply.queue.as_ref().is_some_and(|items| items.len() == 1)
                && reply
                    .requests
                    .as_ref()
                    .is_some_and(|items| items.len() == 1)
        });
    }

    #[test]
    fn a_failed_queue_refresh_keeps_its_old_value_and_is_retried_while_claims_stay_fresh() {
        let rig = start_with(timing(), |server| {
            server.claim(1, "old", "old");
            *server.queue.lock().unwrap() =
                vec![json!({"id": 2, "session": "waiter", "paths": ["old"]})];
        });
        view_ready(&rig);
        rig.server.claim(3, "new", "new");
        *rig.server.queue.lock().unwrap() =
            vec![json!({"id": 4, "session": "waiter", "paths": ["new"]})];
        rig.server.fail_queue.store(true, Ordering::SeqCst);
        rig.daemon.shared.write_view().zones_generation += 1;
        rig.daemon.shared.refresh_zones();
        let view = rig.daemon.shared.read_view();
        assert_eq!(view.claims.last().unwrap().id, 3);
        assert_eq!(view.queue[0].id, 2);
        assert!(view.extras_stale);
        assert!(view.fresh(Duration::from_secs(30)));
    }

    #[test]
    fn idle_lost_marks_do_not_revoke_a_still_live_narrowed_claim() {
        let mut rig = start_with(timing(), |server| {
            server.claim(9, "me", "src/dirty");
            *server.lost.lock().unwrap() = vec![json!({
                "claim_id": 9, "session": "me", "paths": ["src"], "reason": "idle"
            })];
        });
        rig.daemon.stop_workers();
        rig.daemon.shared.refresh_zones();
        rig.daemon.handle(Request::ZoneSnapshot {
            session: "me".into(),
        });
        rig.daemon.shared.refresh_lost();
        let snapshot = rig.daemon.handle(Request::ZoneSnapshot {
            session: "me".into(),
        });
        assert_eq!(snapshot.lost.as_ref().unwrap()[0].claim_id, 9);
        let claims = snapshot.claims.as_ref().unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, 9);
        assert_eq!(claims[0].paths, ["src/dirty"]);
        // Lost marks are history, separate from the live ownership used by checks/activity.
        let view = rig.daemon.shared.read_view();
        assert_eq!(
            view.check_path("me", "src/dirty/file.rs").status,
            CheckStatus::Own
        );
        assert_eq!(
            view.check_path("other", "src/dirty/file.rs").status,
            CheckStatus::Held
        );
        assert_eq!(
            view.check_path("me", "src/clean/file.rs").status,
            CheckStatus::Free
        );
        assert!(rig.server.writes_to("/release").is_empty());
    }

    #[test]
    fn lost_marks_are_loaded_for_heard_sessions_and_expired_sessions_are_dropped() {
        let mut rig = start_with(timing(), |server| {
            *server.lost.lock().unwrap() =
                vec![json!({"claim_id": 9, "session": "me", "paths": ["src"]})];
        });
        rig.daemon.stop_workers();
        rig.daemon.handle(Request::ZoneSnapshot {
            session: "me".into(),
        });
        rig.daemon.shared.refresh_lost();
        let reply = rig.daemon.handle(Request::ZoneSnapshot {
            session: "me".into(),
        });
        assert_eq!(reply.lost.as_ref().unwrap()[0].claim_id, 9);
        rig.daemon.shared.sessions().get_mut("me").unwrap().heard =
            Some(Instant::now() - timing().active_window * 2);
        rig.daemon.shared.refresh_lost();
        assert!(!rig.daemon.shared.read_view().lost.contains_key("me"));
    }

    #[test]
    fn an_older_lost_refresh_cannot_restore_an_expired_session() {
        let mut rig = start_with(timing(), |server| {
            *server.lost.lock().unwrap() =
                vec![json!({"claim_id": 9, "session": "me", "paths": ["src"]})];
        });
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("me");
        let (started, resume) = rig.server.pause_next_lost_read();
        let shared = Arc::clone(&rig.daemon.shared);
        let older = thread::spawn(move || shared.refresh_lost());
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        rig.daemon.shared.sessions().get_mut("me").unwrap().heard =
            Some(Instant::now() - timing().active_window * 2);
        rig.daemon.shared.refresh_lost();
        assert!(!rig.daemon.shared.read_view().lost.contains_key("me"));
        resume.send(()).unwrap();
        older.join().unwrap();

        assert!(
            !rig.daemon.shared.read_view().lost.contains_key("me"),
            "an in-flight response must not recreate a session removed by a newer refresh"
        );
    }

    #[test]
    fn an_older_lost_refresh_cannot_overwrite_a_newer_response() {
        let mut rig = start_with(timing(), |server| {
            *server.lost.lock().unwrap() =
                vec![json!({"claim_id": 9, "session": "me", "paths": ["src"]})];
        });
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("me");
        let (started, resume) = rig.server.pause_next_lost_read();
        let shared = Arc::clone(&rig.daemon.shared);
        let older = thread::spawn(move || shared.refresh_lost());
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        *rig.server.lost.lock().unwrap() =
            vec![json!({"claim_id": 10, "session": "me", "paths": ["new"]})];
        rig.daemon.shared.refresh_lost();
        assert_eq!(
            rig.daemon.shared.read_view().lost["me"].marks[0].claim_id,
            10
        );
        resume.send(()).unwrap();
        older.join().unwrap();

        assert_eq!(
            rig.daemon.shared.read_view().lost["me"].marks[0].claim_id,
            10,
            "an older response must not replace the result of a newer refresh"
        );
    }

    #[test]
    fn an_older_lost_refresh_cannot_overwrite_a_reregistered_session() {
        let mut rig = start_with(timing(), |server| {
            *server.lost.lock().unwrap() =
                vec![json!({"claim_id": 9, "session": "me", "paths": ["src"]})];
        });
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("me");
        let (started, resume) = rig.server.pause_next_lost_read();
        let shared = Arc::clone(&rig.daemon.shared);
        let older = thread::spawn(move || shared.refresh_lost());
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        rig.daemon.shared.sessions().get_mut("me").unwrap().heard =
            Some(Instant::now() - timing().active_window * 2);
        rig.daemon.shared.refresh_lost();
        assert!(!rig.daemon.shared.read_view().lost.contains_key("me"));
        rig.daemon.shared.hear("me");
        *rig.server.lost.lock().unwrap() =
            vec![json!({"claim_id": 10, "session": "me", "paths": ["new"]})];
        rig.daemon.shared.refresh_lost();
        assert_eq!(
            rig.daemon.shared.read_view().lost["me"].marks[0].claim_id,
            10
        );
        resume.send(()).unwrap();
        older.join().unwrap();

        assert_eq!(
            rig.daemon.shared.read_view().lost["me"].marks[0].claim_id,
            10,
            "an old response must not match the default generation of a re-registered session"
        );
    }

    #[test]
    fn a_lost_refresh_cannot_publish_after_another_upkeep_expires_the_session() {
        for reregister in [false, true] {
            let mut rig = start_with(timing(), |server| {
                *server.lost.lock().unwrap() =
                    vec![json!({"claim_id": 9, "session": "me", "paths": ["src"]})];
            });
            rig.daemon.stop_workers();
            rig.daemon.shared.hear("me");
            let (started, resume) = rig.server.pause_next_lost_read();
            let shared = Arc::clone(&rig.daemon.shared);
            let older = thread::spawn(move || shared.refresh_lost());
            started.recv_timeout(Duration::from_secs(5)).unwrap();

            rig.daemon.shared.sessions().get_mut("me").unwrap().heard =
                Some(Instant::now() - timing().active_window * 2);
            rig.daemon.shared.refresh_unread();
            assert!(!rig.daemon.shared.sessions().contains_key("me"));
            if reregister {
                rig.daemon.shared.hear("me");
            }
            resume.send(()).unwrap();
            older.join().unwrap();

            let view = rig.daemon.shared.read_view();
            assert!(
                view.lost["me"].at.is_none(),
                "the old session response must be discarded (re-registered: {reregister})"
            );
            assert!(view.lost["me"].marks.is_empty());
        }
    }

    #[test]
    fn a_lost_refresh_overtaken_by_an_event_keeps_its_entry_dirty() {
        let mut rig = start_with(timing(), |server| {
            *server.lost.lock().unwrap() =
                vec![json!({"claim_id": 9, "session": "me", "paths": ["src"]})];
        });
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("me");
        let (started, resume) = rig.server.pause_next_lost_read();
        let shared = Arc::clone(&rig.daemon.shared);
        let older = thread::spawn(move || shared.refresh_lost());
        started.recv_timeout(Duration::from_secs(5)).unwrap();

        let page = serde_json::from_value(json!({
            "events": [{"seq": 1, "type": "zone.claimed"}]
        }))
        .unwrap();
        rig.daemon.shared.apply_events(&page);
        resume.send(()).unwrap();
        older.join().unwrap();

        {
            let view = rig.daemon.shared.read_view();
            let entry = &view.lost["me"];
            assert!(entry.marks.is_empty(), "the pre-event payload is obsolete");
            assert!(entry.at.is_none());
            assert_eq!(entry.generation, 1);
            assert_eq!(entry.clean, 0);
        }
        *rig.server.lost.lock().unwrap() =
            vec![json!({"claim_id": 10, "session": "me", "paths": ["new"]})];
        rig.daemon.shared.refresh_lost();
        let view = rig.daemon.shared.read_view();
        assert_eq!(view.lost["me"].marks[0].claim_id, 10);
        assert!(view.lost["me"].fresh(timing().fresh));
    }

    #[test]
    fn a_stale_view_makes_one_server_call_and_never_answers_from_memory() {
        let mut rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                ..timing()
            },
            |server| server.claim(1, "bob", "src"),
        );
        view_ready(&rig);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        // This test covers the cache/fallback decision, so run the fake server inline.
        // Thread scheduling and diagnostic I/O under parallel test load can exhaust
        // the real 150 ms deadline; the hung-server test covers that separate bound.
        let server_check =
            |paths: &[String]| Some(shared.backend("me").check("me", paths, None, 0));
        let before = rig.server.calls_to("/api/v1/zones/check");
        let cached = shared.check_with_server("me", vec!["src".into()], server_check);
        assert_eq!(cached.source, Some(Source::View));
        assert_eq!(cached.checks.unwrap()[0].status, CheckStatus::Held);
        assert_eq!(rig.server.calls_to("/api/v1/zones/check"), before);
        {
            let mut view = shared.write_view();
            let age = shared.timing().fresh * 2;
            view.zones_at = Some(Instant::now() - age);
            view.zones_wall_at = Some(SystemTime::now() - age);
        }
        assert!(!shared.read_view().fresh(shared.timing().fresh));
        let reply = shared.check_with_server("me", vec!["src".into()], server_check);
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
        let mut rig = start_with(timing(), |_| {});
        view_ready(&rig);
        rig.daemon.stop_workers();
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
    fn disconnected_write_survives_agent_restart_and_replays_exact_wire_operation() {
        unknown_wire_operation_survives_restart(false);
    }

    #[test]
    fn unrecognized_server_error_survives_agent_restart_and_keeps_original_operation() {
        unknown_wire_operation_survives_restart(true);
    }

    fn unknown_wire_operation_survives_restart(initial_server_error: bool) {
        use lockyard_cloud_client::{Client, WorkspaceKey};
        use std::net::TcpListener;

        // The server commits the first POST but drops its response. All subsequent POSTs
        // return that receipt: the request log proves that recovery uses the original nonce.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let writes = Arc::new(Mutex::new(
            Vec::<(String, String, String, String, String)>::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = Arc::clone(&writes);
        let stopped = Arc::clone(&stop);
        let server = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                };
                // Accepted socket flags differ by platform. Fixture reads are blocking with a deadline.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                let end = loop {
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break end + 4;
                    }
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    bytes.extend_from_slice(&buffer[..count]);
                };
                let headers = String::from_utf8(bytes[..end].to_vec()).unwrap();
                let mut lines = headers.split("\r\n");
                let request = lines.next().unwrap().split_whitespace().collect::<Vec<_>>();
                let headers = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
                    .collect::<HashMap<_, _>>();
                let length: usize = headers
                    .get("content-length")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                while bytes.len() < end + length {
                    let count = stream.read(&mut buffer).unwrap();
                    assert_ne!(count, 0);
                    bytes.extend_from_slice(&buffer[..count]);
                }
                let mut status = 200;
                let response = if request[0] == "POST" && request[1] == "/api/v1/bus/messages" {
                    let mut writes = recorded.lock().unwrap();
                    writes.push((
                        headers["idempotency-key"].clone(),
                        String::from_utf8(bytes[end..end + length].to_vec()).unwrap(),
                        headers["lockyard-protocol"].clone(),
                        request[0].to_owned(),
                        request[1].to_owned(),
                    ));
                    if writes.len() == 1 {
                        if !initial_server_error {
                            continue; // The entire POST arrived; its receipt is lost.
                        }
                        status = 503;
                        json!({"type":"urn:lockyard:problem:future_server_code", "title":"Unknown failure",
                            "status":503,"detail":"commit uncertain","instance":"urn:request:fixture",
                            "code":"future_server_code","details":{}})
                    } else {
                        json!({"id": 7})
                    }
                } else if request[1] == "/api/v1/protocol" {
                    json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":[]})
                } else if request[1].contains("/events") {
                    json!({"events":[]})
                } else {
                    json!({"claims":[],"queue":[],"requests":[],"lost":[],"messages":[]})
                }.to_string();
                let reply = format!(
                    "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nLockyard-Protocol: 2\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        #[cfg(windows)]
        lockyard_core::windows::private_dir(&root).unwrap();
        let make_client = || {
            Client::new(&url, "fixture-token".into())
                .unwrap()
                .with_content_encryption("team", Some(WorkspaceKey::from_entropy([71; 32])), true)
                .with_pending_journal(root.join("pending"))
                .unwrap()
        };
        let mut config = config(
            &root,
            Timing {
                retry_min: Duration::from_secs(1),
                retry_max: Duration::from_secs(1),
                mail_wait: Duration::from_secs(2),
                ..timing()
            },
        );
        config.url = url.clone();
        let call = Call::write(
            "me",
            "POST",
            "/api/v1/bus/messages".into(),
            json!({"to":"other","body":"must keep the encrypted nonce"}),
        );
        let key = call.key.clone().unwrap();
        let client = Arc::new(make_client());
        let mut daemon = Daemon::start(config.clone(), Arc::clone(&client)).unwrap();
        let reply = daemon.handle(Request::Call { call: call.clone() });
        assert_eq!(
            reply.error.as_ref().and_then(ClientError::code),
            Some("outcome_unknown")
        );
        daemon.stop_workers();
        assert_eq!(daemon.shared.outbox.len(), 1, "unknown is still queued");
        assert_eq!(
            daemon.shared.outbox.rejected(),
            0,
            "unknown is not a final refusal"
        );
        let pending = client.pending_operation(&key).unwrap();
        assert_eq!(writes.lock().unwrap().len(), 1);
        assert_eq!(
            pending.body.as_deref(),
            Some(writes.lock().unwrap()[0].1.as_str())
        );
        drop(daemon);
        drop(client);

        let restored = Arc::new(make_client());
        assert_eq!(restored.pending_operation(&key).unwrap().body, pending.body);
        let again = Daemon::start(config, Arc::clone(&restored)).unwrap();
        wait_for("exact pending replay after restart", || {
            again.shared.outbox.len() == 0
        });
        let sent = writes.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "one initial POST and one exact replay");
        assert_eq!(
            sent[0], sent[1],
            "key, ciphertext bytes, protocol, method and path must be identical"
        );
        assert_eq!(sent[0].0, key);
        assert!(!sent[0].1.contains("must keep the encrypted nonce"));
        wait_for(
            "durable outbox completion to release the pending journal",
            || restored.pending_operation(&key).is_none(),
        );
        assert_eq!(again.shared.outbox.rejected(), 0);
        drop(again);
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
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
    fn registering_unread_during_reconciliation_keeps_mail_deliverable() {
        let mut rig = start_with(timing(), |server| *server.unread.lock().unwrap() = 1);
        rig.daemon.stop_workers();
        let shared = &rig.daemon.shared;
        // TakeMail registers an unknown count before Unread supplies the active session.
        assert_eq!(shared.take_mail("me", 1, 60).source, Some(Source::None));
        assert!(!shared.sessions().contains_key("me"));

        let (started, observed) = channel();
        let (resume, paused) = channel();
        let refresh = Arc::clone(shared);
        let worker = thread::spawn(move || {
            UNREAD_RECONCILE_GATE.with(|gate| {
                *gate.borrow_mut() = Some(LostReadGate {
                    started,
                    resume: paused,
                });
            });
            refresh.refresh_unread();
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        // A deterministic scheduler: if membership is unlocked, complete the real Unread
        // request before the older reconciliation. Otherwise it must legally follow it.
        let register_before_reconciliation = match shared.sessions.try_lock() {
            Ok(sessions) => {
                drop(sessions);
                true
            }
            Err(std::sync::TryLockError::WouldBlock) => false,
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("session membership was poisoned"),
        };
        if register_before_reconciliation {
            assert_eq!(shared.unread("me").source, Some(Source::None));
        }
        resume.send(()).unwrap();
        worker.join().unwrap();
        if !register_before_reconciliation {
            assert_eq!(shared.unread("me").source, Some(Source::None));
        }

        // The next upkeep must fetch this active session's count and reserve its mail.
        shared.refresh_unread();
        shared.refresh_mail();
        let delivered = shared.take_mail("me", 1, 60);
        assert_eq!(
            delivered.messages.as_ref().map(Vec::len),
            Some(1),
            "an older membership snapshot discarded a newly registered unread count"
        );
        assert_eq!(rig.server.writes_to("/bus/inbox/claim").len(), 1);
        assert!(rig.server.writes_to("/bus/inbox/seen").is_empty());
    }

    #[test]
    fn mail_is_taken_under_a_delivery_claim_and_marked_only_by_a_later_seen() {
        let rig = start_with(timing(), |server| *server.unread.lock().unwrap() = 2);
        let unknown = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 5,
            lease_seconds: 60,
        });
        assert_eq!(
            (unknown.messages, unknown.source),
            (None, Some(Source::None))
        );
        rig.daemon.handle(Request::Unread {
            session: "me".into(),
        });
        wait_for("mail to be reserved", || {
            rig.daemon.shared.read_view().mail.contains_key("me")
        });
        let taken = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 1,
            lease_seconds: 60,
        });
        assert_eq!(taken.messages.unwrap().len(), 1);
        assert_eq!(
            rig.daemon
                .handle(Request::Unread {
                    session: "me".into()
                })
                .unread,
            Some(1)
        );
        let remaining = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 1,
            lease_seconds: 60,
        });
        assert_eq!(remaining.messages.unwrap().len(), 1);
        let claims = rig.server.writes_to("/bus/inbox/claim");
        assert_eq!(
            claims[0].body.as_ref().unwrap(),
            &json!({"ids": [1, 2], "lease_seconds": 60})
        );
        assert!(claims[0].key.is_some());
        assert!(rig.server.writes_to("/bus/inbox/seen").is_empty());
    }

    #[test]
    fn a_busy_local_journal_retries_mail_before_the_normal_upkeep() {
        let rig = start_with(
            Timing {
                fresh: Duration::from_secs(30),
                // The normal pass is a minute away, so only the 250 ms retry can deliver mail
                // inside the 10 s wait below: the order is proven without a tight stopwatch.
                upkeep: Duration::from_secs(60),
                retry_min: Duration::from_millis(250),
                ..timing()
            },
            |server| *server.unread.lock().unwrap() = 1,
        );
        let (started, observed) = channel();
        let (resume, paused) = channel();
        *rig.server.busy_mail_claim_gate.lock().unwrap() = Some(LostReadGate {
            started,
            resume: paused,
        });
        rig.daemon.handle(Request::Unread {
            session: "me".into(),
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        // Registration has completed while the first reserve is paused. Consume its pending
        // nudge so the next pass must be scheduled by the retry, rather than by registration.
        rig.daemon.shared.signal().nudged = false;
        resume.send(()).unwrap();
        let end = Instant::now() + Duration::from_secs(10);
        while !rig.daemon.shared.read_view().mail.contains_key("me") {
            assert!(
                Instant::now() < end,
                "local journal contention postponed mail until the normal 60 s upkeep"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let taken = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 1,
            lease_seconds: 60,
        });
        assert_eq!(taken.messages.unwrap().len(), 1);
        assert_eq!(rig.server.writes_to("/bus/inbox/claim").len(), 1);
        assert!(rig.server.writes_to("/bus/inbox/seen").is_empty());
    }

    #[test]
    fn taking_mail_uses_no_backend_calls_when_down_or_hung() {
        let mut rig = start_with(timing(), |server| *server.unread.lock().unwrap() = 1);
        rig.daemon.handle(Request::Unread {
            session: "me".into(),
        });
        wait_for("mail to be reserved", || {
            rig.daemon.shared.read_view().mail.contains_key("me")
        });
        rig.daemon.stop_workers();
        let before = rig.server.calls.lock().unwrap().len();
        rig.server.down.store(true, Ordering::SeqCst);
        let taken = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 5,
            lease_seconds: 60,
        });
        assert_eq!(taken.messages.unwrap().len(), 1);
        assert_eq!(rig.server.calls.lock().unwrap().len(), before);
        rig.server.down.store(false, Ordering::SeqCst);
        rig.server.hang_ms.store(500, Ordering::SeqCst);
        let empty = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 5,
            lease_seconds: 5,
        });
        assert_eq!(
            (empty.messages, empty.source),
            (Some(Vec::new()), Some(Source::View))
        );
        assert_eq!(rig.server.calls.lock().unwrap().len(), before);
    }

    #[test]
    fn take_mail_is_atomic_across_two_hundred_concurrent_rounds() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        for id in 1..=200 {
            {
                let mut view = rig.daemon.shared.write_view();
                view.unread.insert(
                    "me".into(),
                    UnreadCount {
                        count: 1,
                        generation: 0,
                        clean: 0,
                        at: Some(Instant::now()),
                        wall_at: Some(SystemTime::now()),
                    },
                );
                let reserved_at = Instant::now();
                view.mail.insert(
                    "me".into(),
                    MailBuffer {
                        messages: VecDeque::from([serde_json::from_value(json!({
                            "id": id, "body": "only once"
                        }))
                        .unwrap()]),
                        reserved_at,
                        lease_expires_at: reserved_at + MAIL_DELIVERY_LEASE,
                    },
                );
            }
            let (left, right) = thread::scope(|scope| {
                let left = scope.spawn(|| {
                    rig.daemon.handle(Request::TakeMail {
                        session: "me".into(),
                        limit: 5,
                        lease_seconds: 60,
                    })
                });
                let right = scope.spawn(|| {
                    rig.daemon.handle(Request::TakeMail {
                        session: "me".into(),
                        limit: 5,
                        lease_seconds: 60,
                    })
                });
                (left.join().unwrap(), right.join().unwrap())
            });
            assert_eq!(
                left.messages.unwrap_or_default().len() + right.messages.unwrap_or_default().len(),
                1,
                "round {id}"
            );
        }
    }

    #[test]
    fn a_mail_buffer_with_less_than_ten_seconds_of_lease_is_dropped() {
        let mut rig = start_with(timing(), |_| {});
        rig.daemon.stop_workers();
        let mut view = rig.daemon.shared.write_view();
        let reserved_at = Instant::now();
        view.unread.insert(
            "me".into(),
            UnreadCount {
                count: 1,
                generation: 0,
                clean: 0,
                at: Some(reserved_at),
                wall_at: Some(SystemTime::now()),
            },
        );
        view.mail.insert(
            "me".into(),
            MailBuffer {
                messages: VecDeque::from([serde_json::from_value(
                    json!({"id": 1, "body": "lease"}),
                )
                .unwrap()]),
                reserved_at,
                lease_expires_at: reserved_at + Duration::from_secs(9),
            },
        );
        drop(view);
        let taken = rig.daemon.handle(Request::TakeMail {
            session: "me".into(),
            limit: 5,
            lease_seconds: 60,
        });
        assert_eq!(
            (taken.messages, taken.source),
            (Some(Vec::new()), Some(Source::View))
        );
    }

    #[test]
    fn upkeep_reserves_mail_for_each_session_even_if_another_session_fails() {
        let mut rig = start_with(timing(), |server| *server.unread.lock().unwrap() = 1);
        rig.daemon.stop_workers();
        rig.daemon.shared.hear("fails");
        rig.daemon.shared.hear("works");
        rig.daemon.shared.store_unread("fails", 0, 1);
        rig.daemon.shared.store_unread("works", 0, 1);
        *rig.server.fail_inbox_for.lock().unwrap() = Some("fails".into());
        rig.daemon.shared.refresh_mail();
        assert!(!rig.daemon.shared.read_view().mail.contains_key("fails"));
        assert!(rig.daemon.shared.read_view().mail.contains_key("works"));
        assert_eq!(rig.server.writes_to("/bus/inbox/claim").len(), 1);
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
                activity_every: Duration::from_secs(30),
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
        // Advance the batching deadline explicitly: fsync and scheduler delays
        // must not decide how many flush windows the test crosses.
        let flush_due = || {
            rig.daemon.shared.activity().get_mut(&7).unwrap().sent =
                Some(Instant::now() - rig.daemon.shared.timing().activity_every);
            rig.daemon.shared.flush_activity();
        };
        assert_eq!(rig.server.writes_to("/activity").len(), 1);
        flush_due();
        let later = || -> String {
            rig.server.writes_to("/activity")[1..]
                .iter()
                .map(|batch| batch.body.as_ref().unwrap()["paths"].to_string())
                .collect()
        };
        wait_for("the later batches", || {
            rig.server.writes_to("/activity").len() >= 2
                && later().contains("src/b")
                && later().contains("src/c")
        });
        let batches = rig.server.writes_to("/activity");
        assert_eq!(batches[0].body.as_ref().unwrap()["paths"], json!(["src/a"]));
        assert_eq!(batches.len(), 2, "pending writes form one later batch");
        let mut paths: Vec<String> =
            serde_json::from_value(batches[1].body.as_ref().unwrap()["paths"].clone()).unwrap();
        paths.sort();
        assert_eq!(paths, ["src/a", "src/b", "src/c"]);
        assert!(batches.iter().all(|batch| batch.session == "me"));
        assert!(!later().contains("elsewhere"), "{}", later());
        // Activity keeps counting repeated writes of src/a, which only the dirty report folds.
        let before = batches.len();
        rig.daemon.handle(write("src/a"));
        flush_due();
        wait_for("the next activity batch", || {
            rig.server.writes_to("/activity").len() == before + 1
        });
        assert_eq!(rig.server.writes_to("/zones/dirty").len(), 3);
        assert_eq!(
            rig.server.writes_to("/activity")[before]
                .body
                .as_ref()
                .unwrap()["paths"],
            json!(["src/a"])
        );
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
        let mut rig = start_with(
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
        // Join the background polls before counting: only TakeEvents may affect
        // the assertion below, not an unrelated stream refresh in this rig.
        rig.daemon.stop_workers();
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

    #[cfg(unix)]
    #[test]
    #[cfg(unix)]
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
