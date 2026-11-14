// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A status read is one deadline, including discovery, retries and every registry page.
//! Claims are deliberately never answered from a daemon snapshot: its event cursor is not an
//! authoritative freshness barrier for revocation, expiry, handover or idle release.

use crate::{Call, CloudBackend, StatusRegistryPage, Transport, encode};
use lockyard_core::proto::{Claim, Stamp, WorkTask, parse_rfc3339};
use lockyard_core::{Error, Result, StatusRead, tasks};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// In the absence of server time, shorten leases by 30 seconds to cover ordinary clock lag.
/// This is explicit provenance, not a proof against unbounded client/server clock skew.
const LOCAL_CLOCK_SAFETY_MARGIN_MS: i64 = 30_000;

fn request<T: Transport>(
    transport: &T,
    session: &str,
    path: String,
    deadline: Instant,
) -> Result<Value> {
    request_page(transport, session, path, deadline)?
        .value
        .map_err(Into::into)
}

fn request_page<T: Transport>(
    transport: &T,
    session: &str,
    path: String,
    deadline: Instant,
) -> Result<StatusRegistryPage> {
    let mut retried_rate_limit = false;
    loop {
        if transport.status_cancelled() {
            return Err(Error::Unavailable("local status read cancelled".into()));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Unavailable("status deadline elapsed".into()));
        }
        let mut call = Call::get(session, path.clone());
        call.deadline_ms = Some(left.as_millis().min(u128::from(u64::MAX)) as u64);
        let response = if call.path.starts_with("/api/v1/registry/") {
            transport.status_registry_call(&call)
        } else {
            transport.call(&call).map(|value| StatusRegistryPage {
                value: Ok(value),
                assignee_session_supported: false,
            })
        };
        let (result, confirmed) = match response {
            Ok(page) => (page.value, page.assignee_session_supported),
            // No response metadata: preserve the ordinary error/retry policy.
            Err(error) => (Err(error), true),
        };
        let unconfirmed_filter = path.contains("&assignee_session=") && !confirmed;
        match result {
            Ok(value) => {
                return Ok(StatusRegistryPage {
                    value: Ok(value),
                    assignee_session_supported: confirmed,
                });
            }
            Err(error) if error.code() == Some("rate_limited") => {
                // Status GETs get one safe retry without changing the ordinary command policy.
                // Honor the complete server Retry-After, and reserve a full request estimate.
                let wait = error
                    .retry_after()
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_millis(100));
                let left = deadline.saturating_duration_since(Instant::now());
                if !retried_rate_limit
                    && wait.saturating_add(crate::RETRY_ROUND_TRIP_ESTIMATE) <= left
                {
                    retried_rate_limit = true;
                    let retry_at = Instant::now() + wait;
                    while Instant::now() < retry_at {
                        if transport.status_cancelled() {
                            return Err(Error::Unavailable("local status read cancelled".into()));
                        }
                        std::thread::sleep(
                            retry_at
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(10)),
                        );
                    }
                    if unconfirmed_filter {
                        return Ok(StatusRegistryPage {
                            value: Err(error),
                            assignee_session_supported: false,
                        });
                    }
                    continue;
                }
                return Err(Error::Unavailable(format!(
                    "rate limiting (HTTP 429; retry cannot fit status deadline): {error}"
                )));
            }
            Err(error) if unconfirmed_filter => {
                return Ok(StatusRegistryPage {
                    value: Err(error),
                    assignee_session_supported: false,
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
}

struct Assigned {
    tasks: Vec<tasks::Task>,
    server_filter: bool,
}

const CAPABILITY_UNKNOWN: u8 = 0;
const CAPABILITY_PRESENT: u8 = 1;
const CAPABILITY_REJECTED: u8 = 2;

fn assigned<T: Transport>(
    transport: &T,
    session: &str,
    status: &str,
    deadline: Instant,
    capability: &AtomicU8,
) -> Result<Assigned> {
    let mut tasks: Vec<tasks::Task> = Vec::new();
    let mut cursor: Option<String> = None;
    // Decide once before the first page, using only existing negotiation or headers from this
    // aggregate. A header learned mid-chain never changes that chain's filters/cursor domain.
    let known = capability.load(Ordering::Acquire);
    let mut server_filter = !session.trim().is_empty()
        && known != CAPABILITY_REJECTED
        && (known == CAPABILITY_PRESENT
            || transport.status_registry_assignee_supported(deadline, None));
    loop {
        // `actor` classifies a task; it is not an assignee. Unknown servers get the exact old path.
        let mut path = format!("/api/v1/registry/items?status={status}&limit=200");
        if server_filter {
            path.push_str("&assignee_session=");
            path.push_str(&encode(session));
        }
        if let Some(cursor) = &cursor {
            path.push_str("&cursor=");
            path.push_str(&encode(cursor));
        }
        let response = request_page(transport, session, path, deadline)?;
        if response.assignee_session_supported {
            // A missing confirmation on any filtered response wins over later announcements.
            let _ = capability.compare_exchange(
                CAPABILITY_UNKNOWN,
                CAPABILITY_PRESENT,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        let restart = server_filter && !response.assignee_session_supported;
        if restart {
            capability.store(CAPABILITY_REJECTED, Ordering::Release);
            server_filter = false;
        }
        let page = match response.value {
            Ok(page) => page,
            Err(_) if restart => {
                cursor = None;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let items = page
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Protocol("status registry response has no items array".into()))?;
        for item in items {
            let task = crate::backend::task_from(item)?;
            let current = item
                .get("assignment")
                .is_some_and(|assignment| assignment.get("released_at").is_none_or(Value::is_null));
            if current && task.assignee.as_deref() == Some(session) {
                if let Some(previous) = tasks.iter_mut().find(|previous| previous.id == task.id) {
                    *previous = task;
                } else {
                    tasks.push(task);
                }
            }
        }
        if restart {
            // Retain every observed matching item, but never reuse a cursor with changed filters.
            // Replay ALL unfiltered pages, even when the unconfirmed response had cursor=null.
            cursor = None;
            continue;
        }
        match page.get("cursor").and_then(Value::as_str) {
            Some(next) if cursor.as_deref() != Some(next) => cursor = Some(next.into()),
            Some(_) => {
                return Err(Error::Protocol(
                    "status registry cursor did not advance".into(),
                ));
            }
            None => {
                return Ok(Assigned {
                    tasks,
                    server_filter,
                });
            }
        }
    }
}

struct Observed<T> {
    value: Result<T>,
    started: Instant,
    finished: Instant,
}

fn observed<T>(operation: impl FnOnce() -> Result<T>) -> Observed<T> {
    let started = Instant::now();
    let value = operation();
    Observed {
        value,
        started,
        finished: Instant::now(),
    }
}

fn section<T>(value: &Observed<T>) -> Value {
    let mut metadata = json!({
        "source": if value.value.is_ok() { "network" } else { "unknown" },
        "available": value.value.is_ok(),
        // The response could have been observed at any point during the request. Report the
        // conservative age from its start, never an invented zero-age synchronization barrier.
        "age_ms": value.started.elapsed().as_millis(),
        "elapsed_ms": value.finished.duration_since(value.started).as_millis(),
    });
    if let Err(error) = &value.value {
        metadata["error"] = json!(error.to_string());
    }
    metadata
}

pub(crate) fn read<T: Transport>(
    backend: &CloudBackend<T>,
    session: &str,
    now: i64,
    budget: Duration,
) -> Result<StatusRead> {
    let started = Instant::now();
    let deadline = started
        .checked_add(budget)
        .ok_or_else(|| Error::Invalid("invalid status deadline".into()))?;
    if budget.is_zero() {
        return Err(Error::Unavailable(
            "status deadline elapsed before reads".into(),
        ));
    }
    let transport = &backend.transport;
    let capability = AtomicU8::new(CAPABILITY_UNKNOWN);
    let read_claims = || {
        observed(|| {
            let value = request(
                transport,
                session,
                format!("/api/v1/zones/claims?session={}", encode(session)),
                deadline,
            )?;
            crate::backend::list::<Claim>(value, &["claims", "items"]).map_err(Into::into)
        })
    };
    // A cold/direct route establishes discovery and one pooled connection before fan-out. Only
    // an explicitly warm daemon transport may overlap claims, preserving its one-round-trip path.
    let cold_claims = (!transport.status_reads_parallel()).then(read_claims);
    if let Some(claims) = &cold_claims
        && let Err(error) = &claims.value
    {
        return Err(Error::Unavailable(format!(
            "status claims unavailable within deadline: {error}"
        )));
    }
    let read_active = || observed(|| assigned(transport, session, "active", deadline, &capability));
    let read_review = || observed(|| assigned(transport, session, "review", deadline, &capability));
    let read_unread = || {
        observed(|| {
            // A daemon may provide a session-scoped synchronized mail count. Unknown or failed
            // snapshots fall back to the bounded network read; claims and tasks never use it.
            if let Some(Ok(Some(count))) = transport.fast_unread(session) {
                return Ok(count);
            }
            let value = request(transport, session, "/api/v1/bus/inbox".into(), deadline)?;
            let page = crate::backend::inbox_page(value)?;
            Ok(i64::try_from(page.messages.len())
                .unwrap_or(i64::MAX)
                .saturating_add(page.skipped))
        })
    };
    let read_work = || {
        observed(|| {
            let value = request(transport, session, "/api/v1/bus/tasks".into(), deadline)?;
            crate::backend::list::<WorkTask>(value, &["tasks", "items"]).map_err(Into::into)
        })
    };
    let (claims, unread, work, active, review) =
        if cold_claims.is_some() && !transport.status_followups_parallel() {
            // One-shot direct route: the pool holds exactly one connection after the claims read. Parallel
            // follow-ups cannot share it, so each would pay its own connection set-up; read them one
            // after another on that connection instead. Stop needs both task chains: they go first,
            // before optional mail and work can use up the deadline.
            let active = read_active();
            let review = read_review();
            let unread = read_unread();
            let work = read_work();
            (None, Ok(unread), Ok(work), Ok(active), Ok(review))
        } else {
            std::thread::scope(|scope| {
                let claims = cold_claims.is_none().then(|| scope.spawn(read_claims));
                // Stop requires both task chains. Launch them immediately, before optional work/mail
                // can occupy the shared HTTP worker allowance.
                let active = scope.spawn(read_active);
                let review = scope.spawn(read_review);
                let unread = scope.spawn(read_unread);
                let work = scope.spawn(read_work);
                // Scoped workers finish before returning. ureq bounds TLS/read/body by the deadline, but
                // its fixed TCP-connect cap and blocking OS resolver cannot be cancelled per request.
                // The CLI process watchdog and daemon admission limit cover those library limitations.
                (
                    claims.map(|worker| worker.join()),
                    unread.join(),
                    work.join(),
                    active.join(),
                    review.join(),
                )
            })
        };
    let panic = || Error::Unavailable("status read worker failed".into());
    let (claims, unread, work, active, review) = (
        match cold_claims {
            Some(claims) => claims,
            None => claims
                .expect("parallel claims worker")
                .map_err(|_| panic())?,
        },
        unread.map_err(|_| panic())?,
        work.map_err(|_| panic())?,
        active.map_err(|_| panic())?,
        review.map_err(|_| panic())?,
    );
    let server_clock = transport.server_time_upper_bound();
    let upper = server_clock.unwrap_or_else(|| {
        now.saturating_add(i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX))
            .saturating_add(LOCAL_CLOCK_SAFETY_MARGIN_MS)
    });
    let freshness = json!({
        "source": "network", "claims_cached": false,
        "claims_server_time_upper_ms": upper,
        "claims_clock_source": if server_clock.is_some() { "http_date" } else { "local_fallback" },
        "claims_local_safety_margin_ms": if server_clock.is_some() { 0 } else { LOCAL_CLOCK_SAFETY_MARGIN_MS },
        "elapsed_ms": started.elapsed().as_millis(),
        "sections": {"claims": section(&claims), "unread": section(&unread),
            "work": section(&work), "tasks_active": section(&active), "tasks_review": section(&review)},
        "assignment_filter": if active.value.as_ref().is_ok_and(|chain| chain.server_filter)
            && review.value.as_ref().is_ok_and(|chain| chain.server_filter) {
            "server"
        } else { "client_fallback" },
    });
    let required = |name: &str, error: Error| {
        Error::Unavailable(format!(
            "status {name} unavailable within deadline: {error}"
        ))
    };
    let mut claims = claims.value.map_err(|error| required("claims", error))?;
    expire_claims(&mut claims, upper)?;
    let mut tasks = active
        .value
        .map_err(|error| required("assigned tasks", error))?
        .tasks;
    tasks.extend(
        review
            .value
            .map_err(|error| required("assigned tasks", error))?
            .tasks,
    );
    Ok(StatusRead {
        claims,
        unread: unread.value.ok(),
        work: work.value.unwrap_or_default(),
        tasks,
        freshness,
        open_mail: None,
    })
}

/// Expiry and idle release are checked for every answer, after all independent reads finish.
/// An opaque lease timestamp cannot prove ownership and therefore fails closed.
fn expire_claims(claims: &mut Vec<Claim>, upper: i64) -> Result<()> {
    fn millis(stamp: &Stamp) -> Option<i64> {
        match stamp {
            Stamp::Millis(value) => Some(*value),
            Stamp::Text(value) => parse_rfc3339(value),
        }
    }
    for claim in claims.iter() {
        if millis(&claim.expires_at).is_none()
            || claim
                .idle_release_at
                .as_ref()
                .is_some_and(|stamp| millis(stamp).is_none())
        {
            return Err(Error::Unavailable(format!(
                "status cannot validate expiry of claim Z-{}",
                claim.id
            )));
        }
    }
    claims.retain(|claim| {
        claim.holder_available != Some(false)
            && millis(&claim.expires_at).is_some_and(|expiry| expiry > upper)
            && claim
                .idle_release_at
                .as_ref()
                .is_none_or(|stamp| millis(stamp).is_some_and(|expiry| expiry > upper))
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientError;
    use lockyard_core::Backend;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct Mock {
        calls: Mutex<Vec<Call>>,
        claims: Mutex<Vec<Claim>>,
        active: AtomicUsize,
        peak: AtomicUsize,
        claims_completed: AtomicBool,
        premature_followups: AtomicUsize,
        delay: Duration,
        fail_optional: bool,
        server_upper: Option<i64>,
        protocol_capability: bool,
        registry_capability: bool,
        ignore_assignee_filter: bool,
        omit_filtered_header_on: Option<&'static str>,
        filtered_paged: bool,
        sequential: bool,
        executor: Option<String>,
    }

    impl Transport for Mock {
        fn status_registry_assignee_supported(
            &self,
            _deadline: Instant,
            _cancellation: Option<&crate::Cancellation>,
        ) -> bool {
            self.protocol_capability
        }
        fn status_followups_parallel(&self) -> bool {
            !self.sequential
        }
        fn status_registry_call(
            &self,
            call: &Call,
        ) -> std::result::Result<StatusRegistryPage, ClientError> {
            let value = self.call(call)?;
            let omitted = call.path.contains("assignee_session=")
                && self.omit_filtered_header_on.is_some_and(|page| {
                    page == "all" || (page == "last" && call.path.contains("cursor="))
                });
            Ok(StatusRegistryPage {
                value: Ok(value),
                assignee_session_supported: self.registry_capability && !omitted,
            })
        }
        fn server_time_upper_bound(&self) -> Option<i64> {
            self.server_upper
        }
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            self.calls.lock().unwrap().push(call.clone());
            if !call.path.starts_with("/api/v1/zones/claims")
                && !self.claims_completed.load(Ordering::SeqCst)
            {
                self.premature_followups.fetch_add(1, Ordering::SeqCst);
            }
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            let budget = call
                .deadline_ms
                .map(Duration::from_millis)
                .unwrap_or(Duration::MAX);
            std::thread::sleep(self.delay.min(budget));
            self.active.fetch_sub(1, Ordering::SeqCst);
            if self.delay >= budget {
                return Err(ClientError::Transport("mock deadline elapsed".into()));
            }
            if call.path.starts_with("/api/v1/zones/claims") {
                self.claims_completed.store(true, Ordering::SeqCst);
                return Ok(json!({"claims": self.claims.lock().unwrap().clone()}));
            }
            if call.path == "/api/v1/bus/inbox" {
                return if self.fail_optional {
                    Err(ClientError::Transport("mail unavailable".into()))
                } else {
                    Ok(json!({"messages": [], "skipped": 0}))
                };
            }
            if call.path == "/api/v1/bus/tasks" {
                return if self.fail_optional {
                    Err(ClientError::Transport("work unavailable".into()))
                } else {
                    Ok(json!({"tasks": []}))
                };
            }
            if call.path.starts_with("/api/v1/registry/items?status=") {
                let status = if call.path.contains("status=active") {
                    "active"
                } else {
                    "review"
                };
                let (id, cursor) = if call.path.contains("cursor=") {
                    ("D-2", Value::Null)
                } else {
                    ("D-1", json!("next/page"))
                };
                let assignment = |id: &str, executor: &str| {
                    json!({"id": id, "status": status,
                    "assignment": {"executor": executor, "session":"misleading"}})
                };
                let executor = self.executor.as_deref().unwrap_or("token:ab:me");
                if call.path.contains("assignee_session=") && !self.ignore_assignee_filter {
                    let items = if self.filtered_paged {
                        vec![assignment(id, executor)]
                    } else {
                        vec![assignment("D-1", executor), assignment("D-2", executor)]
                    };
                    return Ok(json!({"items":items,
                        "cursor":if self.filtered_paged { cursor } else { Value::Null }}));
                }
                let mut items = vec![
                    assignment(id, executor),
                    json!({"id":"D-98", "status":status}),
                    json!({"id":"D-97", "status":status,
                        "assignment":{"executor":executor,"released_at":"2026-11-12T00:00:00Z"}}),
                ];
                items.extend(
                    (100..232).map(|number| assignment(&format!("D-{number}"), "token:ab:other")),
                );
                return Ok(json!({"items":items,"cursor":cursor}));
            }
            Err(ClientError::Invalid(format!(
                "unexpected mock route {}",
                call.path
            )))
        }
    }

    fn claim(expiry: i64) -> Claim {
        serde_json::from_value(json!({"id":1,"session":"me","paths":["src"],"expires_at":expiry}))
            .unwrap()
    }

    #[test]
    fn status_reads_overlap_and_filter_every_assignment_page() {
        let cloud = CloudBackend::new(
            Mock {
                delay: Duration::from_millis(40),
                ..Mock::default()
            },
            "me",
        );
        let read = cloud
            .status_read("me", 1000, Duration::from_secs(1))
            .unwrap();
        assert_eq!(cloud.transport.peak.load(Ordering::SeqCst), 4);
        assert_eq!(
            cloud.transport.premature_followups.load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            read.tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            ["D-1", "D-2", "D-1", "D-2"]
        );
        assert!(
            read.tasks
                .iter()
                .all(|task| task.assignee.as_deref() == Some("me"))
        );
        let calls = cloud.transport.calls.lock().unwrap();
        assert_eq!(read.freshness["assignment_filter"], "client_fallback");
        assert!(
            calls
                .iter()
                .all(|call| !call.path.contains("assignee_session="))
        );
        assert!(calls[0].path.starts_with("/api/v1/zones/claims"));
        let registry: Vec<_> = calls
            .iter()
            .filter(|call| call.path.contains("/registry/"))
            .collect();
        assert_eq!(registry.len(), 4);
        assert!(
            registry
                .iter()
                .all(|call| call.path.contains("limit=200") && !call.path.contains("actor="))
        );
        assert_eq!(
            registry
                .iter()
                .filter(|call| call.path.contains("cursor=next%2Fpage"))
                .count(),
            2
        );
        assert!(
            calls
                .iter()
                .all(|call| call.deadline_ms.is_some_and(|budget| budget <= 1000))
        );
    }

    #[test]
    fn status_announced_assignee_filter_reads_two_single_page_chains() {
        let cloud = CloudBackend::new(
            Mock {
                protocol_capability: true,
                registry_capability: true,
                ..Mock::default()
            },
            "me",
        );
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(read.freshness["assignment_filter"], "server");
        assert_eq!(read.tasks.len(), 4);
        let calls = cloud.transport.calls.lock().unwrap();
        let registry: Vec<_> = calls
            .iter()
            .filter(|call| call.path.contains("/registry/"))
            .collect();
        assert_eq!(registry.len(), 2);
        assert!(registry.iter().all(
            |call| call.path.contains("&assignee_session=me") && !call.path.contains("cursor=")
        ));
    }

    #[test]
    fn status_unannounced_server_keeps_exact_sequential_fallback_paths() {
        let cloud = CloudBackend::new(
            Mock {
                sequential: true,
                ..Mock::default()
            },
            "me",
        );
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(read.freshness["assignment_filter"], "client_fallback");
        let calls = cloud.transport.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .map(|call| call.path.as_str())
                .collect::<Vec<_>>(),
            [
                "/api/v1/zones/claims?session=me",
                "/api/v1/registry/items?status=active&limit=200",
                "/api/v1/registry/items?status=active&limit=200&cursor=next%2Fpage",
                "/api/v1/registry/items?status=review&limit=200",
                "/api/v1/registry/items?status=review&limit=200&cursor=next%2Fpage",
                "/api/v1/bus/inbox",
                "/api/v1/bus/tasks",
            ]
        );
        assert!(
            calls
                .iter()
                .all(|call| !call.path.contains("assignee_session="))
        );
        assert_eq!(read.tasks.len(), 4);
    }

    #[test]
    fn status_registry_header_only_applies_before_next_chain_not_mid_page_chain() {
        let cloud = CloudBackend::new(
            Mock {
                sequential: true,
                registry_capability: true,
                ..Mock::default()
            },
            "me",
        );
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(read.tasks.len(), 4);
        assert_eq!(read.freshness["assignment_filter"], "client_fallback");
        let calls = cloud.transport.calls.lock().unwrap();
        let registry: Vec<_> = calls
            .iter()
            .filter(|call| call.path.contains("/registry/"))
            .map(|call| call.path.as_str())
            .collect();
        assert_eq!(
            registry,
            [
                "/api/v1/registry/items?status=active&limit=200",
                "/api/v1/registry/items?status=active&limit=200&cursor=next%2Fpage",
                "/api/v1/registry/items?status=review&limit=200&assignee_session=me",
            ]
        );
    }

    #[test]
    fn status_missing_filtered_header_replays_every_old_page_without_losing_tasks() {
        for (omitted, paged) in [("all", false), ("last", true)] {
            let cloud = CloudBackend::new(
                Mock {
                    sequential: true,
                    protocol_capability: true,
                    registry_capability: true,
                    omit_filtered_header_on: Some(omitted),
                    filtered_paged: paged,
                    ..Mock::default()
                },
                "me",
            );
            let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
            assert_eq!(
                read.tasks
                    .iter()
                    .map(|task| task.id.as_str())
                    .collect::<Vec<_>>(),
                ["D-1", "D-2", "D-1", "D-2"]
            );
            assert_eq!(read.freshness["assignment_filter"], "client_fallback");
            let calls = cloud.transport.calls.lock().unwrap();
            let registry: Vec<_> = calls
                .iter()
                .filter(|call| call.path.contains("/registry/"))
                .map(|call| call.path.as_str())
                .collect();
            let filtered_pages = if paged { 2 } else { 1 };
            assert_eq!(registry.len(), filtered_pages + 4);
            assert!(
                registry[..filtered_pages]
                    .iter()
                    .all(|path| path.contains("assignee_session="))
            );
            assert_eq!(
                &registry[filtered_pages..],
                [
                    "/api/v1/registry/items?status=active&limit=200",
                    "/api/v1/registry/items?status=active&limit=200&cursor=next%2Fpage",
                    "/api/v1/registry/items?status=review&limit=200",
                    "/api/v1/registry/items?status=review&limit=200&cursor=next%2Fpage",
                ]
            );
        }
    }

    #[test]
    fn status_announced_but_ignored_filter_still_filters_locally_and_pages_fully() {
        let cloud = CloudBackend::new(
            Mock {
                protocol_capability: true,
                registry_capability: true,
                ignore_assignee_filter: true,
                ..Mock::default()
            },
            "me",
        );
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(read.freshness["assignment_filter"], "server");
        assert_eq!(read.tasks.len(), 4);
        assert!(
            read.tasks
                .iter()
                .all(|task| task.assignee.as_deref() == Some("me"))
        );
        assert_eq!(
            cloud
                .transport
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.path.contains("assignee_session="))
                .count(),
            4
        );
    }

    #[test]
    fn status_assignment_executor_colons_and_encoded_session_are_exact() {
        for (executor, session) in [
            ("plain", "plain"),
            ("worker:part", "worker:part"),
            ("person:id:worker", "worker"),
            ("token:id:worker:part", "worker:part"),
            ("token:id:worker /?&+", "worker /?&+"),
        ] {
            for filter in [false, true] {
                let cloud = CloudBackend::new(
                    Mock {
                        protocol_capability: filter,
                        registry_capability: filter,
                        executor: Some(executor.into()),
                        ..Mock::default()
                    },
                    session,
                );
                let read = cloud
                    .status_read(session, 0, Duration::from_secs(1))
                    .unwrap();
                assert_eq!(read.tasks.len(), 4, "{executor}, filter={filter}");
                assert!(
                    read.tasks
                        .iter()
                        .all(|task| task.assignee.as_deref() == Some(session))
                );
                let expected = format!("assignee_session={}", encode(session));
                assert!(
                    cloud
                        .transport
                        .calls
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|call| call.path.contains("/registry/"))
                        .all(|call| call.path.contains(&expected) == filter)
                );
            }
        }
    }

    #[test]
    fn status_deadline_bounds_all_reads_and_pages() {
        let cloud = CloudBackend::new(
            Mock {
                delay: Duration::from_secs(2),
                ..Mock::default()
            },
            "me",
        );
        let start = Instant::now();
        let error = cloud
            .status_read("me", 1000, Duration::from_millis(80))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("status claims unavailable within deadline")
        );
        assert!(start.elapsed() < Duration::from_millis(300));
        assert_eq!(cloud.transport.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn status_optional_failures_are_explicit_but_tasks_are_mandatory() {
        let cloud = CloudBackend::new(
            Mock {
                fail_optional: true,
                ..Mock::default()
            },
            "me",
        );
        let read = cloud
            .status_read("me", 1000, Duration::from_secs(1))
            .unwrap();
        assert_eq!(read.unread, None);
        assert!(read.work.is_empty());
        assert_eq!(read.freshness["sections"]["unread"]["available"], false);
        assert_eq!(read.freshness["sections"]["unread"]["source"], "unknown");
        assert_eq!(read.freshness["sections"]["work"]["available"], false);
        assert!(!read.tasks.is_empty());
        let cloud = CloudBackend::new(
            Mock {
                delay: Duration::from_millis(45),
                ..Mock::default()
            },
            "me",
        );
        let error = cloud
            .status_read("me", 1000, Duration::from_millis(75))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("status assigned tasks unavailable within deadline")
        );
        let calls = cloud.transport.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .filter(|call| call.path.contains("cursor="))
                .all(|call| call.deadline_ms.unwrap() < 45)
        );
    }

    #[test]
    fn status_mail_uses_the_whole_remaining_deadline() {
        struct SlowMail(Mock);
        impl Transport for SlowMail {
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                if call.path == "/api/v1/bus/inbox" {
                    assert!(call.deadline_ms.unwrap() > 500);
                    std::thread::sleep(Duration::from_millis(600));
                    return Ok(json!({"messages": [], "skipped": 3}));
                }
                self.0.call(call)
            }
        }
        let cloud = CloudBackend::new(SlowMail(Mock::default()), "me");
        let read = cloud.status_read("me", 0, Duration::from_secs(2)).unwrap();
        assert_eq!(read.unread, Some(3));
        assert_eq!(read.freshness["sections"]["unread"]["available"], true);
        assert!(
            read.freshness["sections"]["unread"]["elapsed_ms"]
                .as_u64()
                .unwrap()
                >= 600
        );
    }

    #[test]
    fn status_cancellation_interrupts_retry_after_before_another_network_read() {
        struct RateLimited {
            cancellation: crate::Cancellation,
            called: AtomicUsize,
        }
        impl Transport for RateLimited {
            fn status_cancelled(&self) -> bool {
                self.cancellation.is_cancelled()
            }

            fn call(&self, _: &Call) -> std::result::Result<Value, ClientError> {
                self.called.fetch_add(1, Ordering::SeqCst);
                Err(ClientError::RateLimited(crate::ApiError {
                    status: 429,
                    code: "rate_limited".into(),
                    retry_after: Some(1),
                    ..crate::ApiError::default()
                }))
            }
        }
        let cloud = CloudBackend::new(
            RateLimited {
                cancellation: crate::Cancellation::new(),
                called: AtomicUsize::new(0),
            },
            "me",
        );
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| cloud.status_read("me", 0, Duration::from_millis(2600)));
            let started = Instant::now();
            while cloud.transport.called.load(Ordering::SeqCst) == 0 {
                assert!(started.elapsed() < Duration::from_secs(1));
                std::thread::sleep(Duration::from_millis(1));
            }
            let cancelled = Instant::now();
            cloud.transport.cancellation.cancel();
            let error = worker.join().unwrap().unwrap_err();
            assert!(error.to_string().contains("cancelled"));
            assert!(cancelled.elapsed() < Duration::from_millis(100));
        });
        assert_eq!(cloud.transport.called.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn status_warm_transport_overlaps_claims_with_all_other_reads() {
        struct Warm(Mock);
        impl Transport for Warm {
            fn status_reads_parallel(&self) -> bool {
                true
            }
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                self.0.call(call)
            }
        }
        let cloud = CloudBackend::new(
            Warm(Mock {
                delay: Duration::from_millis(40),
                ..Mock::default()
            }),
            "me",
        );
        cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(cloud.transport.0.peak.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn status_one_shot_transport_reads_sections_in_sequence_after_claims() {
        struct OneShot(Mock);
        impl Transport for OneShot {
            fn status_followups_parallel(&self) -> bool {
                false
            }
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                self.0.call(call)
            }
        }
        let cloud = CloudBackend::new(
            OneShot(Mock {
                delay: Duration::from_millis(10),
                ..Mock::default()
            }),
            "me",
        );
        let read = cloud
            .status_read("me", 1000, Duration::from_secs(2))
            .unwrap();
        // One connection's worth of work at a time: nothing overlaps, claims still go first and
        // both task chains precede optional mail and work.
        assert_eq!(cloud.transport.0.peak.load(Ordering::SeqCst), 1);
        assert_eq!(read.tasks.len(), 4);
        let calls = cloud.transport.0.calls.lock().unwrap();
        assert!(calls[0].path.starts_with("/api/v1/zones/claims"));
        let first_optional = calls
            .iter()
            .position(|call| call.path.starts_with("/api/v1/bus/"))
            .unwrap();
        let last_registry = calls
            .iter()
            .rposition(|call| call.path.contains("/registry/"))
            .unwrap();
        assert!(last_registry < first_optional);
    }

    #[test]
    fn status_local_clock_fallback_shortens_lease_by_safety_margin() {
        let transport = Mock::default();
        *transport.claims.lock().unwrap() = vec![claim(10_000), claim(100_000)];
        let cloud = CloudBackend::new(transport, "me");
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(read.claims.len(), 1);
        assert_eq!(read.claims[0].expires_at, Stamp::Millis(100_000));
        assert_eq!(read.freshness["claims_clock_source"], "local_fallback");
        assert_eq!(read.freshness["claims_local_safety_margin_ms"], 30_000);
        assert!(
            read.freshness["claims_server_time_upper_ms"]
                .as_i64()
                .unwrap()
                >= 30_000
        );
    }

    #[test]
    fn status_lower_server_date_cannot_resurrect_an_expired_claim() {
        struct Clocked {
            clock: crate::Client,
            responses: Mock,
        }
        impl Transport for Clocked {
            fn server_time_upper_bound(&self) -> Option<i64> {
                self.clock.server_time_upper_bound()
            }
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                self.responses.call(call)
            }
        }
        let clock = crate::Client::new("http://127.0.0.1:1", "fixture".into()).unwrap();
        clock.observe_server_time(5000);
        let responses = Mock::default();
        responses.claims.lock().unwrap().push(claim(4000));
        let cloud = CloudBackend::new(Clocked { clock, responses }, "me");
        assert!(
            cloud
                .status_read("me", 0, Duration::from_secs(1))
                .unwrap()
                .claims
                .is_empty()
        );
        // Model a racing worker/error/edge response carrying an older HTTP Date.
        cloud.transport.clock.observe_server_time(1000);
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert!(read.claims.is_empty());
        assert!(
            read.freshness["claims_server_time_upper_ms"]
                .as_i64()
                .unwrap()
                >= 5000
        );
    }

    #[test]
    fn status_never_reuses_revoked_claims_and_rechecks_expiry_and_idle() {
        let cloud = CloudBackend::new(
            Mock {
                server_upper: Some(5000),
                ..Mock::default()
            },
            "me",
        );
        cloud.transport.claims.lock().unwrap().push(claim(10000));
        assert_eq!(
            cloud
                .status_read("me", 0, Duration::from_secs(1))
                .unwrap()
                .claims
                .len(),
            1
        );
        cloud.transport.claims.lock().unwrap().clear();
        assert!(
            cloud
                .status_read("me", 0, Duration::from_secs(1))
                .unwrap()
                .claims
                .is_empty()
        );
        let mut idle = claim(10000);
        idle.idle_release_at = Some(Stamp::Millis(5000));
        let mut unavailable = claim(10000);
        unavailable.holder_available = Some(false);
        *cloud.transport.claims.lock().unwrap() = vec![claim(5000), idle, unavailable];
        assert!(
            cloud
                .status_read("me", 0, Duration::from_secs(1))
                .unwrap()
                .claims
                .is_empty()
        );
        let read = cloud.status_read("me", 0, Duration::from_secs(1)).unwrap();
        assert_eq!(read.freshness["claims_cached"], false);
        assert_eq!(read.freshness["claims_clock_source"], "http_date");
        assert_eq!(read.freshness["claims_server_time_upper_ms"], 5000);
    }

    #[test]
    fn status_opaque_claim_expiry_fails_closed() {
        let mut invalid = claim(10000);
        invalid.expires_at = Stamp::Text("opaque".into());
        let mut claims = vec![invalid];
        assert!(expire_claims(&mut claims, 1000).is_err());
    }

    #[test]
    fn status_claim_expiring_during_other_reads_is_removed_at_answer_time() {
        struct Temporal {
            inner: Mock,
            started: Instant,
        }
        impl Transport for Temporal {
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                if call.path.contains("/registry/") {
                    std::thread::sleep(Duration::from_millis(40));
                }
                self.inner.call(call)
            }
            fn server_time_upper_bound(&self) -> Option<i64> {
                Some(1000 + self.started.elapsed().as_millis() as i64)
            }
        }
        let inner = Mock::default();
        inner.claims.lock().unwrap().push(claim(1050));
        let cloud = CloudBackend::new(
            Temporal {
                inner,
                started: Instant::now(),
            },
            "me",
        );
        let read = cloud
            .status_read("me", 1000, Duration::from_secs(1))
            .unwrap();
        assert!(read.claims.is_empty());
        assert!(
            read.freshness["claims_server_time_upper_ms"]
                .as_i64()
                .unwrap()
                >= 1080
        );
    }
}
