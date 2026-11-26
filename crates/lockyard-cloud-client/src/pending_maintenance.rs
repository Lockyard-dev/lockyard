// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Reconcile exact wire operations; elapsed time is not evidence of an outcome.
use super::*;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

const RECONCILE_BUDGET: Duration = Duration::from_secs(2);
const WAITER_RECEIPT_TTL: Duration = Duration::from_secs(60);
pub(super) const ENCRYPTION_MISMATCH: &str = "pending_encryption_mismatch";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    Durable,
    Coordination,
    SignedResult,
    ReadState(&'static str),
    TokenIssue,
    Unknown,
}

// Server contract at cloud d4b95dc. Source paths below are relative to cloud/src.
// Method + route -> server deduplication -> recovery. Only these exact method
// and segment patterns opt in. Query parameters stay in the frozen request.
fn recovery(pending: &PendingWrite) -> Recovery {
    use Recovery::*;
    let path = pending.path.split('?').next().unwrap_or(&pending.path);
    let Some(path) = path.strip_prefix("/api/v1/") else {
        return Unknown;
    };
    let parts: Vec<_> = path.split('/').collect();
    if parts.iter().any(|part| {
        part.is_empty()
            || matches!(*part, "." | "..")
            || part.contains(['\\', '#'])
            || part.chars().any(char::is_control)
            || part.as_bytes().windows(3).any(|escape| {
                [b"%2e", b"%2f", b"%5c"]
                    .iter()
                    .any(|encoded| escape.eq_ignore_ascii_case(*encoded))
            })
    }) {
        return Unknown;
    }
    match (pending.method.as_str(), parts.as_slice()) {
        // Durable Idempotency-Key -> replay. TaskRegistry/RegistryService.cs:1131-1168.
        ("POST", ["registry", "items"]) => Durable, // :69, also durable client_key
        ("POST", ["registry", "items", "batch-transition"]) => Durable, // :405
        ("POST", ["registry", "items", _, "triage"]) => Durable, // :255
        ("POST", ["registry", "items", _, "plan"]) => Durable, // :514
        ("POST", ["registry", "items", _, "review"]) => Durable, // :383
        ("POST", ["registry", "items", _, "transition"]) => Durable, // :281
        ("POST", ["registry", "items", _, "owner-close"]) => Durable, // :481
        ("POST", ["registry", "items", _, "claim"]) => Durable, // :727
        ("POST", ["registry", "items", _, "heartbeat" | "release"]) => Durable, // :783-787,1104
        ("POST", ["registry", "items", _, "evidence"]) => Durable, // :790
        ("POST", ["registry", "items", _, "links"]) => Durable, // :810
        ("POST", ["registry", "import"]) => Durable, // :978
        // Durable Idempotency-Key, pinned to original instance -> replay.
        // Lockyard.Api/OperationsEndpoints.cs:133-138, OperationsAdmission.cs:178-207.
        ("POST", ["admin", "drain"]) => Durable,
        // Coordination receipts are eligible for cleanup after 30 days.
        // Coordination/CoordinationService.cs:311-352, CoordinationZones.cs:2063.
        ("POST", ["presence"]) => Coordination, // CoordinationZones.cs:1798
        ("POST", ["zones", "catalog"]) => Coordination, // CoordinationCatalog.cs:112
        ("POST", ["zones", "claims"]) => Coordination, // CoordinationZones.cs:442
        ("DELETE", ["zones", "claims"]) => Coordination, // CoordinationZones.cs:1184
        ("DELETE", ["zones", "claims", _]) => Coordination, // CoordinationZones.cs:1126
        ("POST", ["zones", "claims", _, "add-path"]) => Coordination, // CoordinationZones.cs:603
        ("POST", ["zones", "claims", _, "renew"]) => Coordination, // CoordinationZones.cs:667
        ("POST", ["zones", "claims", _, "narrow"]) => Coordination, // CoordinationZones.cs:718
        ("POST", ["zones", "claims", _, "activity"]) => Coordination, // CoordinationZones.cs:773
        ("POST", ["zones", "claims", _, "meta"]) => Coordination, // CoordinationZones.cs:805
        ("POST", ["zones", "claims", _, "handover"]) => Coordination, // CoordinationZones.cs:847
        ("POST", ["zones", "claims", _, "accept"])
        | ("POST", ["zones", "claims", _, "handover", "accept"]) => Coordination, // CoordinationZones.cs:924
        ("POST", ["zones", "claims", _, "takeover"]) => Coordination, // CoordinationZones.cs:972
        ("POST", ["zones", "dirty"]) => Coordination,                 // CoordinationZones.cs:1685
        ("POST", ["zones", "dirty", "disown" | "adopt"]) => Coordination, // CoordinationZones.cs:1742
        ("POST", ["zones", "queue"]) => Coordination, // CoordinationZones.cs:1365
        ("DELETE", ["zones", "queue", _]) => Coordination, // CoordinationZones.cs:1403
        ("POST", ["zones", "requests"]) => Coordination, // CoordinationZones.cs:1542
        ("POST", ["zones", "requests", _, "answer"]) => Coordination, // CoordinationZones.cs:1627
        ("POST", ["bus", "messages"]) => Coordination, // CoordinationBus.cs:71
        ("POST", ["bus", "messages", _, "reply"]) => Coordination, // CoordinationBus.cs:236
        ("POST", ["bus", "messages", _, "ack"]) => Coordination, // CoordinationBus.cs:280
        ("POST", ["messages", _, "receipt"]) => Coordination, // CoordinationReceipts.cs:25
        ("POST", ["bus", "inbox", "seen"]) => Coordination, // CoordinationBus.cs:410
        ("POST", ["bus", "inbox", "handled"]) => Coordination, // CoordinationBus.cs:442
        ("POST", ["bus", "inbox", "claim"]) => Coordination, // CoordinationBus.cs:475
        ("POST", ["bus", "board"]) => Coordination,   // CoordinationBus.cs:586
        ("DELETE", ["bus", "board", _]) => Coordination, // CoordinationBus.cs:606
        ("POST", ["bus", "tasks"]) => Coordination,   // CoordinationBus.cs:657
        (
            "POST",
            [
                "bus",
                "tasks",
                _,
                "claim" | "beat" | "done" | "accept" | "reject" | "fail" | "cancel" | "handoff"
                | "take" | "decline",
            ],
        ) => Coordination, // Lockyard.Api/CoordinationRoutes.cs:16,250; CoordinationBus.cs:745
        ("POST", ["import", "zones"]) => Coordination, // CoordinationService.cs:761
        ("POST", ["import", "bus"]) => Coordination,  // CoordinationService.cs:783
        ("POST", ["admin", "freeze"]) => Coordination, // CoordinationService.cs:403
        ("POST", ["admin", "sessions", _, "release"]) => Coordination, // CoordinationService.cs:231
        ("POST", ["admin", "sessions", _, "end"]) => Coordination, // CoordinationService.cs:264
        // No header deduplication; immutable workspace/node/job identity, job ULID + 365
        // days. Only the EP-09 worker can replay. Lockyard.Api/NodeSignedResults.cs:195-222,284.
        ("PUT", ["nodes", _, "jobs", _, "signed-result"])
            if crate::signed_results::is_result_path(&pending.path) =>
        {
            SignedResult
        }
        // No Idempotency-Key deduplication -> read current state; retain exact outcome as unknown.
        ("POST", ["registry", "areas"]) => ReadState("/api/v1/registry/areas"), // TaskRegistry/RegistryService.cs:540-578
        ("POST", ["registry", "tokens", _, "revoke"]) => ReadState("/api/v1/registry/tokens"), // TaskRegistry/RegistryService.cs:684-718
        ("POST", ["workspace", "encryption"]) => ReadState("/api/v1/workspace/encryption"), // Lockyard.Api/CoordinationRoutes.cs:50-84
        // Token creation has no Idempotency-Key deduplication or unique request ID in
        // the metadata-only list. A name/time match cannot prove who issued it.
        ("POST", ["registry", "tokens"]) => TokenIssue, // TaskRegistry/RegistryService.cs:655-681,1918
        // No server contract established; retain the unknown outcome without replay.
        _ => Unknown,
    }
}

pub(super) fn eligible_for_recovery(pending: &PendingWrite) -> bool {
    matches!(
        recovery(pending),
        Recovery::Durable | Recovery::Coordination | Recovery::SignedResult
    )
}

pub(super) fn waiter_receipt_allowed(pending: &PendingWrite) -> bool {
    // A direct success proves the outcome even on routes without server replay.
    // Token issuance returns the raw credential, which must stay in memory.
    recovery(pending) != Recovery::TokenIssue
}

pub(super) fn unreplayed_detail(pending: &PendingWrite) -> &'static str {
    if recovery(pending) == Recovery::TokenIssue {
        "token issuance outcome is unknown; request retained without replay. Inspect metadata with `lockyard cloud token list`."
    } else {
        "mutation outcome is unknown; request retained without replay"
    }
}

const REPLAY_MARGIN_SECS: u64 = 60;

pub(super) fn unix_now() -> Result<u64, ClientError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(journal_error)?
        .as_secs())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplayWindow {
    Open,
    Unverified,
    Closed,
}

fn replay_deadline(pending: &PendingWrite) -> Option<u64> {
    let first = pending.first_sent_server_secs?;
    match recovery(pending) {
        Recovery::Coordination => Some(first.saturating_add(PENDING_RETENTION_SECS)),
        Recovery::SignedResult => Some(
            first
                .saturating_add(365 * 86400)
                .min(crate::signed_results::replay_deadline_secs(&pending.path)?),
        ),
        _ => None,
    }
}

fn window(pending: &PendingWrite, date: Option<u64>) -> ReplayWindow {
    use ReplayWindow::*;
    if pending.replay_stopped {
        return Closed;
    }
    if recovery(pending) == Recovery::Durable {
        return Open;
    }
    let Some(deadline) = replay_deadline(pending) else {
        return Closed;
    };
    match date {
        Some(date) if date >= deadline.saturating_sub(REPLAY_MARGIN_SECS) => Closed,
        Some(date)
            if date.saturating_add(REPLAY_MARGIN_SECS)
                >= pending.first_sent_server_secs.unwrap() =>
        {
            Open
        }
        _ => Unverified,
    }
}

pub(super) fn uses_replay_budget(pending: &PendingWrite) -> bool {
    !pending.replay_paused
        && window(pending, None) != ReplayWindow::Closed
        && !(recovery(pending) == Recovery::SignedResult
            && Client::result_permanently_refused(pending))
}

pub(super) fn outcome_unproven(error: &ClientError) -> bool {
    matches!(
        error.code(),
        Some(
            "session_name_bound"
                | "drain_instance_mismatch"
                | "protocol_unsupported"
                | "conflict"
                | "idempotency_conflict"
                | "idempotency_key_unknown"
                | "idempotency_key_expired"
                | "idempotency_expired"
        )
    ) || matches!(error.status(), Some(401 | 403 | 408 | 429))
        || pre_execution_refusal(error)
}

fn connection_unavailable(error: &ClientError) -> bool {
    // Malformed JSON came from an individual response. An interrupted HTTP body
    // is already classified as Transport by the response decoder.
    error.is_outage() && !matches!(error, ClientError::Decode(_))
}

fn expiry_reason<'a>(pending: &PendingWrite, error: &'a ClientError) -> Option<&'a str> {
    let api = error.api_error()?;
    let unsafe_key = matches!(
        recovery(pending),
        Recovery::Coordination | Recovery::SignedResult
    ) || api.details["replay_safe"] == false
        || api.details["retry_safe"] == false;
    (unsafe_key
        && matches!(
            api.code.as_str(),
            "idempotency_key_unknown" | "idempotency_key_expired" | "idempotency_expired"
        ))
    .then_some(api.code.as_str())
}

fn matching_state(route: &str, pending: &PendingWrite, value: Value) -> Option<Value> {
    if route == "/api/v1/registry/tokens" {
        let id = pending
            .path
            .split('?')
            .next()?
            .strip_prefix("/api/v1/registry/tokens/")?
            .strip_suffix("/revoke")?;
        return value
            .as_array()?
            .iter()
            .find(|token| {
                token["id"]
                    .as_str()
                    .is_some_and(|found| found.eq_ignore_ascii_case(id))
                    && token["revoked_at"].is_string()
            })
            .cloned();
    }
    let body: Value = serde_json::from_str(pending.body.as_deref()?).ok()?;
    if route == "/api/v1/workspace/encryption" {
        return (matches!(body["encryption"].as_str(), Some("off" | "required"))
            && body["encryption"] == value["encryption"]
            && body["key_id"] == value["key_id"])
            .then_some(value);
    }
    let key = body["key"].as_str()?.trim().to_lowercase();
    let name = body["name"].as_str()?.trim();
    value
        .as_array()?
        .iter()
        .find(|area| {
            area["key"].as_str() == Some(key.as_str())
                && area["name"].as_str() == Some(name)
                && area["prefix"].as_str() == Some(body["prefix"].as_str().unwrap_or("D").trim())
                && area["pad"].as_i64() == Some(body["pad"].as_i64().unwrap_or(4))
                && (body["path_roots"].is_null() || body["path_roots"] == area["path_roots"])
        })
        .cloned()
}

#[derive(Debug, Default, Serialize)]
pub struct PendingRepair {
    pub applied: usize,
    pub rejected: usize,
    pub quarantined: usize,
    /// Unresolved records still charged to the active replay budget.
    pub remaining: usize,
    /// Retained unresolved records outside the replay budget.
    pub outcome_unknown: usize,
    /// Retained records whose requested state was visible during a read-only check.
    pub state_observed: usize,
    pub network_required: bool,
    pub unknown_ids: Vec<String>,
    pub drain_instance_mismatch: Vec<String>,
}

/// Keep the raw response and frozen request until the original caller consumes its
/// receipt. An outbox must still persist its own completion before acknowledging.
#[derive(Serialize, Deserialize)]
struct SettledWrite {
    pending: PendingWrite,
    value: Option<Value>,
    error: Option<Problem>,
    #[serde(default)]
    consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<ReceiptEncryption>,
}

fn waiter_receipt_path(directory: &Path, key: &str) -> PathBuf {
    journal_path(directory, key).with_extension("waiter.settled")
}

fn is_waiter_receipt(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".waiter.settled"))
}

fn waiter_receipt_age(path: &Path) -> std::io::Result<Duration> {
    Ok(std::fs::symlink_metadata(path)?
        .modified()?
        .elapsed()
        .unwrap_or_default())
}

/// Public inputs to the operation's frozen encryption fingerprint.
#[derive(Serialize, Deserialize)]
struct ReceiptEncryption {
    workspace: Option<String>,
    key_id: Option<String>,
    enabled: bool,
}

impl ReceiptEncryption {
    fn matches(&self, client: &Client, frozen: Option<&str>) -> bool {
        frozen.is_some_and(|frozen| {
            frozen
                == client.encryption_context_for(
                    self.workspace.as_deref(),
                    self.key_id.as_deref(),
                    self.enabled,
                )
        })
    }
}

impl Client {
    /// Recheck signed results that were parked when blind replay stopped.
    pub fn maintain_stopped_signed_results(&self) -> Result<(), ClientError> {
        let stopped = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .values()
            .any(|row| {
                row.replay_paused && !row.replay_stopped && recovery(row) == Recovery::SignedResult
            });
        if stopped {
            self.maintain_pending_journal()?;
        }
        Ok(())
    }

    pub(crate) fn first_send_server_secs(&self) -> Option<u64> {
        u64::try_from(crate::Transport::server_time_upper_bound(self)?)
            .ok()
            .map(|ms| ms.div_ceil(1000))
    }

    fn replay_date(
        &self,
        pending: &PendingWrite,
        budget: Duration,
        cancellation: Option<&crate::Cancellation>,
    ) -> Result<Option<u64>, ClientError> {
        let session = if recovery(pending) == Recovery::SignedResult {
            pending.session.clone()
        } else {
            self.service_session("lockyard-pending-clock")
        };
        let mut probe = Call::get(&session, DISCOVERY.into());
        probe.cancellation = cancellation.cloned();
        let mut date = None;
        self.attempt_with_date(
            &probe,
            None,
            Some(budget),
            &pending.protocol,
            None,
            None,
            false,
            Some(&mut date),
            None,
        )
        .map_err(failure_error)?;
        Ok(date)
    }

    pub(super) fn park_pending(
        &self,
        pending: &PendingWrite,
        stop: bool,
    ) -> Result<(), ClientError> {
        if !pending.replay_paused || (stop && !pending.replay_stopped) {
            let mut parked = pending.clone();
            parked.replay_paused = true;
            parked.replay_stopped |= stop;
            self.update_pending(pending, parked)?;
        }
        Ok(())
    }

    pub(super) fn park_incompatible_pending(
        &self,
        pending: &PendingWrite,
    ) -> Result<ClientError, ClientError> {
        let mut parked = pending.clone();
        parked.replay_paused = true;
        parked.cause_code = ENCRYPTION_MISMATCH.into();
        parked.cause_status = None;
        if parked != *pending
            || (self
                .pending_journal
                .as_ref()
                .is_some_and(|directory| journal_path(directory, &pending.key).is_file()))
        {
            self.update_pending(pending, parked.clone())?;
        }
        Ok(ClientError::OutcomeUnknown(Box::new(parked)))
    }

    pub(crate) fn explicit_expiry(
        &self,
        pending: &PendingWrite,
        error: &ClientError,
    ) -> Result<bool, ClientError> {
        if expiry_reason(pending, error).is_some() {
            self.park_pending(pending, true)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn can_replay_pending(
        &self,
        pending: &PendingWrite,
        guard: &mut PendingSendGuard<'_>,
        budget: Option<Duration>,
        cancellation: Option<&crate::Cancellation>,
    ) -> Result<bool, ClientError> {
        let mut decision = window(pending, None);
        if decision == ReplayWindow::Unverified {
            let date = guard
                .exchange_with_budget(budget, cancellation, || {
                    self.replay_date(
                        pending,
                        budget.unwrap_or(RECONCILE_BUDGET).min(RECONCILE_BUDGET),
                        cancellation,
                    )
                })?
                .ok()
                .flatten();
            decision = window(pending, date);
        }
        if decision != ReplayWindow::Open {
            self.park_pending(pending, decision == ReplayWindow::Closed)?;
        }
        Ok(decision == ReplayWindow::Open)
    }

    fn summarize_pending(&self, report: &mut PendingRepair) {
        let state = self
            .protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        report.unknown_ids.clear();
        report.drain_instance_mismatch.clear();
        report.remaining = 0;
        for pending in state.pending.values() {
            if uses_replay_budget(pending) {
                report.remaining += 1;
            } else {
                report.unknown_ids.push(pending.key.clone());
                if pending.cause_code == "drain_instance_mismatch" {
                    report.drain_instance_mismatch.push(pending.key.clone());
                }
            }
        }
        report.outcome_unknown = report.unknown_ids.len();
    }

    pub fn repair_pending(&self) -> Result<PendingRepair, ClientError> {
        self.repair_pending_with_age(0, RECONCILE_BUDGET, true, None)
    }

    pub(crate) fn maintain_pending_journal(&self) -> Result<PendingRepair, ClientError> {
        self.repair_pending_with_age(60, RECONCILE_BUDGET, false, None)
    }

    pub(super) fn repair_pending_for_capacity(
        &self,
        deadline: Instant,
    ) -> Result<PendingRepair, ClientError> {
        let budget = deadline.saturating_duration_since(Instant::now());
        self.repair_pending_with_age(0, budget, false, Some(deadline))
    }

    fn repair_pending_with_age(
        &self,
        minimum_age: u64,
        pass_budget: Duration,
        explicit_repair: bool,
        admission_deadline: Option<Instant>,
    ) -> Result<PendingRepair, ClientError> {
        let Some(directory) = &self.pending_journal else {
            return Ok(PendingRepair::default());
        };
        let cursor_path = directory.join(".repair-cursor");
        let now = unix_now()?;
        let (mut rows, cursor, _repair, probe_policy) = {
            let _journal = PendingSendGuard::lock_journal(directory)?;
            let lock_path = directory.join(REPAIR_LOCK);
            // Avoid scanning over another pass and creating a sidecar for
            // journals that never need repair.
            let mut repair = if lock_path.try_exists().map_err(journal_error)? {
                Some(PendingSendGuard::lock_operation(&lock_path)?)
            } else {
                None
            };
            if directory
                .join(LONG_POLL_MAINTENANCE)
                .try_exists()
                .map_err(journal_error)?
            {
                self.retire_completed_pending(directory)?;
            }
            self.reload_pending(true)?;
            let rows = self.pending_operations();
            if rows.is_empty() {
                return Ok(PendingRepair::default());
            }
            // Keep pass ownership when the journal is released for HTTP.
            if repair.is_none() {
                repair = Some(PendingSendGuard::lock_operation(&lock_path)?);
            }
            let cursor = read_private_json::<String>(&cursor_path).ok();
            let mut probe_policy = false;
            if explicit_repair && self.check_pending_encryption_policy {
                for row in rows.iter().filter(|row| {
                    uses_replay_budget(row)
                        && matches!(recovery(row), Recovery::Durable | Recovery::Coordination)
                }) {
                    if self.settled_write(&row.key)?.is_none() {
                        probe_policy = true;
                        break;
                    }
                }
            }
            (rows, cursor, repair, probe_policy)
        };
        if let Some(cursor) = cursor {
            let next = rows.partition_point(|row| row.key <= cursor);
            rows.rotate_left(next);
        }
        let pass_started = Instant::now();
        let mut uncharged = Duration::ZERO;
        let mut slow_rows = 0;
        let mut reviewed = 0;
        let mut report = PendingRepair::default();
        // Report unavailable policy for an explicit online repair even if local
        // housekeeping uses the pass budget before it reaches a replayable row.
        if probe_policy {
            let policy = self.live_replay_encryption(self, pass_budget, None);
            report.network_required = policy.as_ref().err().is_some_and(connection_unavailable);
        }
        let admission_left = || {
            admission_deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
        };
        for pending in rows {
            // Avoid starting a row in the last scheduling slice of foreground admission.
            if admission_left().is_some_and(|left| left < Duration::from_millis(25)) {
                break;
            }
            if pending.replay_paused && pending.replay_stopped {
                continue;
            }
            if minimum_age > 0
                && uses_replay_budget(&pending)
                && pending
                    .first_sent_unix_secs
                    .and_then(|first| now.checked_sub(first))
                    .is_some_and(|age| age < minimum_age)
            {
                continue;
            }
            // Charge at most a fraction of the pass to an individual network exchange.
            // Bound repeated slow exchanges separately and resume past them on the next pass.
            if reviewed >= 2
                && (slow_rows >= 2
                    || pass_started.elapsed().saturating_sub(uncharged) >= pass_budget)
            {
                break;
            }
            let mut guard = match self.reserve_pending_key(&pending.key) {
                Ok(guard) => guard,
                Err(error) if journal_busy(&error) => continue,
                Err(error) => return Err(error),
            };
            // Contention on the shared journal says nothing about this row.
            // Wait for a concurrent scan to finish before examining the key.
            guard.wait_for_journal_with_budget(
                admission_left().unwrap_or(crate::MAX_RETRY_WAIT),
                None,
            )?;
            if !self.pending_snapshot_matches(directory, &pending)? {
                continue;
            }
            match guard.acquire_operation() {
                Ok(()) => {}
                Err(error) if journal_busy(&error) => continue,
                Err(error) => return Err(error),
            }
            lockyard_core::fsio::replace(
                &cursor_path,
                &serde_json::to_vec(&pending.key).map_err(journal_error)?,
                0o600,
            )
            .map_err(journal_error)?;
            reviewed += 1;
            if self.settled_write(&pending.key)?.is_some() {
                self.resolve_pending(&pending.key)?;
                continue;
            }
            let mut pending = pending;
            let recovery = recovery(&pending);
            let decision = window(&pending, None);
            if decision == ReplayWindow::Closed && !matches!(recovery, Recovery::ReadState(_)) {
                self.park_pending(&pending, true)?;
                continue;
            }
            if recovery == Recovery::SignedResult && Client::result_permanently_refused(&pending) {
                self.park_pending(&pending, true)?;
                continue;
            }
            // Keep per-key ownership across the HTTP exchange, including the probe and
            // replica retry. A concurrent writer can use the journal for any other key.
            guard.release_journal()?;
            let started = Instant::now();
            let left = || {
                let row_budget = RECONCILE_BUDGET.saturating_sub(started.elapsed());
                admission_left().map_or(row_budget, |remaining| remaining.min(row_budget))
            };
            let mut window_status = decision;
            let mut observed = false;
            let refused = pending.pre_execution_rejected;
            let mut incompatible_encryption = false;
            let mut receipt_encryption = None;
            let result = if left().is_zero() {
                None
            } else if let Recovery::ReadState(route) = recovery {
                let read = Call::get(&pending.session, route.into());
                match self.attempt_observed(
                    &read,
                    None,
                    Some(left()),
                    &pending.protocol,
                    None,
                    None,
                    false,
                ) {
                    Ok(value) => {
                        let matched = matching_state(route, &pending, value);
                        observed = matched.is_some();
                        matched.map(Ok)
                    }
                    Err(failure) => {
                        report.network_required |= connection_unavailable(&failure_error(failure));
                        None
                    }
                }
            } else {
                if window_status == ReplayWindow::Unverified {
                    match self.replay_date(&pending, left(), None) {
                        Ok(date) => window_status = window(&pending, date),
                        Err(error) => report.network_required |= connection_unavailable(&error),
                    }
                }
                // The signed-result worker owns the binary send and its acknowledgement.
                if window_status != ReplayWindow::Open
                    || recovery == Recovery::SignedResult
                    || left().is_zero()
                {
                    None
                } else {
                    match self.check_replay_encryption(self, &pending, left(), None) {
                        Ok(Some(encryption)) => {
                            let context = ReceiptEncryption {
                                workspace: encryption.workspace,
                                key_id: encryption.key.as_ref().map(crate::WorkspaceKey::key_id),
                                enabled: encryption.enabled,
                            };
                            if context.matches(self, pending.encryption_context.as_deref()) {
                                receipt_encryption = Some(context);
                            }
                            if refused {
                                guard.wait_for_journal_with_budget(
                                    admission_left().unwrap_or(crate::MAX_RETRY_WAIT),
                                    None,
                                )?;
                                let previous = pending.clone();
                                pending.pre_execution_rejected = false;
                                self.update_pending(&previous, pending.clone())?;
                                guard.release_journal()?;
                            }
                            let mut wire = Call::get(&pending.session, pending.path.clone());
                            wire.method = pending.method.clone();
                            wire.repository = pending.repository.clone();
                            wire.key = Some(pending.key.clone());
                            Some(self.reconcile_wire(&wire, &pending, left))
                        }
                        Ok(None) => {
                            incompatible_encryption = true;
                            None
                        }
                        Err(error) => {
                            report.network_required |= connection_unavailable(&error);
                            None
                        }
                    }
                }
            };
            let excess = started.elapsed().saturating_sub(Duration::from_millis(250));
            uncharged += excess;
            slow_rows += usize::from(!excess.is_zero());
            guard.wait_for_journal_with_budget(
                admission_left().unwrap_or(crate::MAX_RETRY_WAIT),
                None,
            )?;
            if !self.pending_snapshot_matches(directory, &pending)? {
                continue;
            }
            if incompatible_encryption
                || matches!(&result, Some(Err(error)) if error.code() == Some(ENCRYPTION_MISMATCH))
            {
                self.park_incompatible_pending(&pending)?;
                continue;
            }
            let (value, error) = match result {
                Some(Ok(value)) => (Some(value), None),
                Some(Err(error)) => {
                    if self.explicit_expiry(&pending, &error)? {
                        continue;
                    }
                    if error.code() == Some("drain_instance_mismatch") {
                        let _ = self.unknown(
                            pending.clone(),
                            "drain_instance_mismatch",
                            error.status(),
                        );
                        if let Some(updated) = self.pending_operation(&pending.key) {
                            self.park_pending(&updated, false)?;
                        }
                        continue;
                    }
                    // Admission and validation can run before receipt lookup. A
                    // retry's 4xx only settles rejection if earlier sends were
                    // proven not to have executed and this refusal is definitive.
                    if refused && replay_refusal(&error) {
                        self.retain_refusal(pending, &error)?;
                        continue;
                    }
                    let unavailable = connection_unavailable(&error);
                    if !refused || outcome_unproven(&error) || unavailable {
                        if outcome_unproven(&error) || error.status().is_some_and(|s| s < 500) {
                            let cause = error.code().unwrap_or("outcome_unknown");
                            let _ = self.unknown(pending, cause, error.status());
                        }
                        report.network_required |= unavailable;
                        continue;
                    }
                    if let Some(problem) = error
                        .problem()
                        .filter(|_| error.status().is_some_and(|status| status < 500))
                    {
                        (None, Some(problem))
                    } else {
                        continue;
                    }
                }
                None => {
                    if window_status != ReplayWindow::Open {
                        self.park_pending(
                            &pending,
                            window_status == ReplayWindow::Closed
                                && !matches!(recovery, Recovery::ReadState(_)),
                        )?;
                    }
                    continue;
                }
            };
            let settled = SettledWrite {
                pending: pending.clone(),
                value,
                error,
                consumed: false,
                encryption: receipt_encryption,
            };
            let path = journal_path(directory, &pending.key).with_extension("settled");
            lockyard_core::fsio::replace(
                &path,
                &serde_json::to_vec(&settled).map_err(journal_error)?,
                0o600,
            )
            .map_err(journal_error)?;
            self.resolve_pending(&pending.key)?;
            if settled.error.is_some() {
                report.rejected += 1;
            } else {
                report.applied += 1;
                report.state_observed += usize::from(observed);
            }
        }
        if let Ok(_journal) = PendingSendGuard::lock_journal(directory) {
            self.reload_pending(true)?;
        }
        self.summarize_pending(&mut report);
        Ok(report)
    }

    pub(crate) fn verify_pending_replay_encryption(
        &self,
        pending: &PendingWrite,
        guard: &mut PendingSendGuard<'_>,
        budget: Option<Duration>,
        cancellation: Option<&crate::Cancellation>,
    ) -> Result<ContentEncryption, ClientError> {
        match guard.exchange_with_budget(budget, cancellation, || {
            self.check_replay_encryption(
                self,
                pending,
                budget.unwrap_or(RECONCILE_BUDGET).min(RECONCILE_BUDGET),
                cancellation,
            )
        })? {
            Ok(Some(encryption)) => Ok(encryption),
            Ok(None) => Err(self.park_incompatible_pending(pending)?),
            Err(_) => Err(ClientError::OutcomeUnknown(Box::new(pending.clone()))),
        }
    }

    pub(crate) fn live_replay_encryption(
        &self,
        server: &Client,
        budget: Duration,
        cancellation: Option<&crate::Cancellation>,
    ) -> Result<Option<WorkspaceEncryption>, ClientError> {
        if self.check_pending_encryption_policy || self.expected_e2ee_workspace.is_some() {
            let mut call = Call::get(
                &self.service_session("lockyard-pending-policy"),
                crate::ENCRYPTION_PATH.into(),
            );
            call.deadline_ms = Some(budget.as_millis() as u64);
            call.cancellation = cancellation.cloned();
            match crate::Transport::call(server, &call) {
                Ok(value) => {
                    let setting: WorkspaceEncryption = serde_json::from_value(value)
                        .map_err(|error| ClientError::Decode(error.to_string()))?;
                    self.validate_encryption_setting(&setting)?;
                    if self.check_live_write_encryption_policy && std::ptr::eq(self, server) {
                        *self
                            .live_encryption
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(setting.clone());
                    }
                    return Ok(Some(setting));
                }
                // Only an unconfigured legacy client can fall back when the endpoint is absent.
                Err(ClientError::NotFound(_))
                    if self.workspace.is_none()
                        && self.expected_e2ee_workspace.is_none()
                        && self.live_encryption_setting().is_none() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    pub(crate) fn attest_frozen_body(
        &self,
        server: &Client,
        pending: &PendingWrite,
        budget: Option<Duration>,
        cancellation: Option<&crate::Cancellation>,
    ) -> Result<(), ClientError> {
        if self
            .check_replay_encryption(
                server,
                pending,
                budget.unwrap_or(RECONCILE_BUDGET).min(RECONCILE_BUDGET),
                cancellation,
            )?
            .is_some()
        {
            return Ok(());
        }
        Err(local(
            ENCRYPTION_MISMATCH,
            "pending encryption context changed",
        ))
    }

    fn check_replay_encryption(
        &self,
        server: &Client,
        pending: &PendingWrite,
        budget: Duration,
        cancellation: Option<&crate::Cancellation>,
    ) -> Result<Option<ContentEncryption>, ClientError> {
        let frozen = pending.encryption_context.as_deref();
        let encryption =
            if let Some(setting) = self.live_replay_encryption(server, budget, cancellation)? {
                let required = self.validate_encryption_setting(&setting)?;
                // A required server key id is enough to rule out an incompatible wire
                // context, including when the local workspace key is unavailable.
                if required
                    && let Some(key_id) = setting.key_id.as_deref()
                    && frozen
                        != Some(
                            self.encryption_context_for(
                                Some(&setting.workspace_id),
                                Some(key_id),
                                required,
                            )
                            .as_str(),
                        )
                {
                    return Ok(None);
                }
                let (key, _) = self.validate_content_encryption(&setting)?;
                ContentEncryption {
                    enabled: required,
                    workspace: Some(setting.workspace_id),
                    key,
                }
            } else {
                ContentEncryption {
                    enabled: self.encryption_enabled,
                    workspace: self.workspace.clone(),
                    key: self.content_key.clone(),
                }
            };
        if encryption.enabled && encryption.key.is_none() {
            return Err(ClientError::Invalid(
                "pending replay needs a workspace key".into(),
            ));
        }
        let key_id = encryption.key.as_ref().map(crate::WorkspaceKey::key_id);
        let context = self.encryption_context_for(
            encryption.workspace.as_deref(),
            key_id.as_deref(),
            encryption.enabled,
        );
        let compatible = frozen == Some(context.as_str())
            || (!encryption.enabled
                && (frozen.is_none()
                    || frozen == Some(self.encryption_context_for(None, None, false).as_str())));
        Ok(compatible.then_some(encryption))
    }

    fn pending_snapshot_matches(
        &self,
        directory: &Path,
        pending: &PendingWrite,
    ) -> Result<bool, ClientError> {
        let path = self.existing_pending_path(directory, &pending.key)?;
        let matches = match read_private_json::<PendingWrite>(&path) {
            Ok(current) => current == *pending,
            Err(_) if !path.try_exists().map_err(journal_error)? => false,
            Err(error) => return Err(error),
        };
        if matches {
            self.protocol_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending
                .insert(pending.key.clone(), pending.clone());
        }
        Ok(matches)
    }

    pub(super) fn reconcile_wire(
        &self,
        wire: &Call,
        pending: &PendingWrite,
        left: impl Fn() -> Duration,
    ) -> Result<Value, ClientError> {
        let send = |client: &Client| {
            let budget = left();
            if budget.is_zero() {
                return Err(ClientError::Transport(
                    "pending reconciliation deadline elapsed".into(),
                ));
            }
            client
                .attempt_frozen(self, wire, pending, Some(budget), None, false)
                .map_err(failure_error)
        };
        let result = send(self);
        if pending.path == "/api/v1/admin/drain"
            && let Err(error) = &result
            && error.code() == Some("drain_instance_mismatch")
            && let Some(details) = error.api_error().map(|api| &api.details)
            && let Some(replica) = self.resolve_drain_replica(pending, details)
            && replica != self.base_url
        {
            // The original request keeps its instance_id. The target must validate it
            // before looking up the receipt. Client::new disables HTTP redirects.
            let replica = Client::new(&replica, self.token.clone())?;
            return send(&replica);
        }
        result
    }

    fn resolve_drain_replica(&self, pending: &PendingWrite, details: &Value) -> Option<String> {
        let body: Value = serde_json::from_str(pending.body.as_deref()?).ok()?;
        let expected = body["instance_id"].as_str()?;
        let id = [
            "original_instance_id",
            "requested_instance_id",
            "instance_id",
        ]
        .into_iter()
        .find_map(|key| details[key].as_str());
        if id.is_some_and(|id| !id.eq_ignore_ascii_case(expected)) {
            return None;
        }
        let hint = [
            "original_instance_url",
            "instance_url",
            "instance_origin",
            "replica_url",
            "origin",
        ]
        .into_iter()
        .find_map(|key| details[key].as_str());
        let candidate = (self.trusted_replica)(id, hint)?;
        let origin = url::Url::parse(&candidate).ok()?;
        (origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.username().is_empty()
            && origin.password().is_none())
        .then(|| candidate.trim_end_matches('/').to_owned())
    }

    pub(crate) fn durable_parked_write(&self, call: &Call) -> bool {
        let (Some(directory), Some(key)) = (&self.pending_journal, &call.key) else {
            return false;
        };
        let path = journal_path(directory, key);
        // A parked record is evidence of an unresolved call regardless of current policy.
        let record = read_private_json::<PendingWrite>(&path.with_extension("unknown"))
            .or_else(|_| read_private_json(&path.with_extension("quarantine")));
        record.is_ok_and(|row| {
            row.key == *key
                && row.origin == self.base_url
                && row.credential_scope == crate::credential_fingerprint(&self.token)
                && row.method == call.method
                && row.request_path == call.path
                && row
                    .request_digest
                    .as_ref()
                    .is_none_or(|digest| *digest == crate::request_identity(call))
        })
    }

    /// Forget explicitly selected unknown operations under the scoped journal lock.
    pub fn forget_unknown_journal(
        mut self,
        directory: impl AsRef<Path>,
        selection: &str,
    ) -> Result<usize, ClientError> {
        self.attach_pending_journal(directory.as_ref())?;
        let directory = self.pending_journal.as_ref().unwrap();
        let _journal = PendingSendGuard::lock_journal(directory)?;
        self.reload_pending(true)?;
        let mut records = Vec::new();
        let mut locks = Vec::new();
        for row in self.pending_operations() {
            if !uses_replay_budget(&row) && (selection == "--all" || selection == row.key) {
                let path = self.existing_pending_path(directory, &row.key)?;
                let inflight = path.with_extension("inflight");
                if inflight.try_exists().map_err(journal_error)? {
                    locks.push(PendingSendGuard::lock_operation(&inflight)?);
                }
                records.push((path, row));
            }
        }
        if selection != "--all" && records.is_empty() {
            return Err(local(
                "not_found",
                "unknown operation not found in this credential's journal",
            ));
        }
        self.archive_unknown(&records, unix_now()?, "operator_forgot_unknown")?;
        Ok(records.len())
    }

    pub(super) fn unconsumed_settled_operations(&self) -> Result<Vec<PendingWrite>, ClientError> {
        let Some(directory) = &self.pending_journal else {
            return Ok(Vec::new());
        };
        let mut operations = Vec::new();
        for entry in std::fs::read_dir(directory).map_err(journal_error)? {
            let path = entry.map_err(journal_error)?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("settled")
                || is_waiter_receipt(&path)
            {
                continue;
            }
            let settled: SettledWrite = read_private_json(&path)?;
            if !settled.consumed && self.settled_write(&settled.pending.key)?.is_some() {
                operations.push(settled.pending);
            }
        }
        Ok(operations)
    }

    pub(crate) fn consume_settled(&self, call: &Call) -> Result<(), ClientError> {
        let Some(key) = &call.key else {
            return Ok(());
        };
        let Some(mut settled) = self.settled_write(key)? else {
            return Ok(());
        };
        if settled.pending.request_digest.as_deref() != Some(crate::request_identity(call).as_str())
        {
            return Err(local(
                "idempotency_conflict",
                "acknowledgement does not match settled operation",
            ));
        }
        if !settled.consumed {
            settled.consumed = true;
            let path =
                journal_path(self.pending_journal.as_ref().unwrap(), key).with_extension("settled");
            lockyard_core::fsio::replace(
                &path,
                &serde_json::to_vec(&settled).map_err(journal_error)?,
                0o600,
            )
            .map_err(journal_error)?;
        }
        Ok(())
    }

    pub(super) fn settled_response_key_exists(&self, key: &str) -> Result<bool, ClientError> {
        self.settled_write(key).map(|value| value.is_some())
    }

    /// Publish a verified direct reply before removing its pending record. An ordinary
    /// response is already acknowledged and does not become an outbox recovery item.
    pub(super) fn publish_waiter_receipt(
        &self,
        pending: &PendingWrite,
        value: Value,
        encryption: &ContentEncryption,
    ) -> Result<(), ClientError> {
        let directory = self
            .pending_journal
            .as_ref()
            .expect("waiter receipt journal");
        let settled = SettledWrite {
            pending: pending.clone(),
            value: Some(value),
            error: None,
            consumed: true,
            encryption: Some(ReceiptEncryption {
                workspace: encryption.workspace.clone(),
                key_id: encryption.key.as_ref().map(crate::WorkspaceKey::key_id),
                enabled: encryption.enabled,
            }),
        };
        let bytes = serde_json::to_vec(&settled).map_err(journal_error)?;
        if bytes.len() as u64 > MAX_PENDING_BYTES {
            return Err(journal_error(
                "settled response exceeds journal record budget",
            ));
        }
        lockyard_core::fsio::replace(&waiter_receipt_path(directory, &pending.key), &bytes, 0o600)
            .map_err(journal_error)
    }

    fn settled_path(&self, key: &str) -> Result<Option<PathBuf>, ClientError> {
        let Some(directory) = &self.pending_journal else {
            return Ok(None);
        };
        let path = journal_path(directory, key).with_extension("settled");
        if path.try_exists().map_err(journal_error)? {
            return Ok(Some(path));
        }
        let path = waiter_receipt_path(directory, key);
        match waiter_receipt_age(&path) {
            Ok(age) => Ok((age < WAITER_RECEIPT_TTL).then_some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(journal_error(error)),
        }
    }

    fn settled_write(&self, key: &str) -> Result<Option<SettledWrite>, ClientError> {
        self.settled_path(key)?
            .map(|path| self.read_settled_write(key, &path))
            .transpose()
    }

    fn read_settled_write(&self, key: &str, path: &Path) -> Result<SettledWrite, ClientError> {
        let settled: SettledWrite = read_private_json(path)?;
        if settled.pending.key != key
            || settled.pending.origin != self.base_url
            || settled.pending.credential_scope != crate::credential_fingerprint(&self.token)
        {
            return Err(journal_error(
                "settled receipt does not match its origin or credential",
            ));
        }
        Ok(settled)
    }

    fn local_receipt_keys(
        &self,
        workspace: Option<&str>,
    ) -> impl Iterator<Item = crate::WorkspaceKey> {
        self.content_key
            .clone()
            .filter(|_| self.workspace.as_deref() == workspace)
            .into_iter()
            .chain(
                std::iter::once_with(move || {
                    crate::WorkspaceKey::load_for_workspace(workspace?).ok()?
                })
                .flatten(),
            )
    }

    fn settled_encryption(
        &self,
        frozen: Option<&str>,
        recorded: Option<ReceiptEncryption>,
    ) -> Option<ContentEncryption> {
        if let Some(context) = recorded {
            if !context.matches(self, frozen) {
                return None;
            }
            let key = context.key_id.as_deref().and_then(|id| {
                self.local_receipt_keys(context.workspace.as_deref())
                    .find(|key| key.key_id() == id)
            });
            return (!context.enabled || key.is_some()).then_some(ContentEncryption {
                enabled: context.enabled,
                workspace: context.workspace,
                key,
            });
        }

        // Older receipts only have the fingerprint. Try both modes with the local
        // workspace and keys, and use only the combination that matches the operation.
        let frozen = frozen?;
        let live = self.live_encryption_setting();
        for workspace in [None, self.workspace.as_deref()].into_iter().chain(
            live.as_ref()
                .map(|setting| Some(setting.workspace_id.as_str())),
        ) {
            for key in std::iter::once(None).chain(self.local_receipt_keys(workspace).map(Some)) {
                let key_id = key.as_ref().map(crate::WorkspaceKey::key_id);
                if let Some(enabled) = [false, true].into_iter().find(|&enabled| {
                    frozen == self.encryption_context_for(workspace, key_id.as_deref(), enabled)
                }) {
                    return Some(ContentEncryption {
                        enabled,
                        workspace: workspace.map(str::to_owned),
                        key,
                    });
                }
            }
        }
        None
    }

    pub(super) fn settled_response(
        &self,
        call: &Call,
        guard: &mut PendingSendGuard<'_>,
        remaining: &dyn Fn() -> Option<Duration>,
    ) -> Result<Option<Value>, ClientError> {
        let Some(key) = &call.key else {
            return Ok(None);
        };
        let Some(path) = self.settled_path(key)? else {
            return Ok(None);
        };
        let settled = self.read_settled_write(key, &path)?;
        let pending = settled.pending;
        let verified_route = if is_waiter_receipt(&path) {
            waiter_receipt_allowed(&pending)
        } else {
            eligible_for_recovery(&pending)
        };
        if !verified_route
            || pending.request_digest.as_deref() != Some(crate::request_identity(call).as_str())
        {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        let frozen = pending.encryption_context.as_deref();
        let legacy_receipt = settled.encryption.is_none();
        let mut encryption = self.settled_encryption(frozen, settled.encryption);
        if encryption.is_none()
            && legacy_receipt
            && frozen.is_some()
            && self.check_live_write_encryption_policy
        {
            // Old receipts carry only a fingerprint. If the agent started without
            // a workspace, one live lookup can identify the key to verify it with.
            let budget = remaining();
            let policy = guard.exchange_with_budget(budget, call.cancellation.as_ref(), || {
                self.live_replay_encryption(
                    self,
                    budget.unwrap_or(RECONCILE_BUDGET).min(RECONCILE_BUDGET),
                    call.cancellation.as_ref(),
                )
            })?;
            if matches!(policy, Ok(Some(_))) {
                encryption = self.settled_encryption(frozen, None);
            }
        }
        let Some(encryption) = encryption else {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        };
        if let Some(error) = settled.error {
            if !call.defer_pending_ack {
                self.consume_settled(call)?;
            }
            return Err(ClientError::Protocol(error));
        }
        let mut value = settled
            .value
            .ok_or_else(|| journal_error("settled receipt missing response"))?;
        if let Err(error) =
            self.decode_pending_response(call, &pending, &mut value, Some(&encryption))
        {
            // decode_pending_response durably restored the original pending bytes.
            if self.pending_operation(key).is_some() {
                std::fs::remove_file(path).map_err(journal_error)?;
                lockyard_core::fsio::sync_dir(self.pending_journal.as_ref().unwrap())
                    .map_err(journal_error)?;
            }
            return Err(error);
        }
        self.resolve_pending(key)?;
        if !call.defer_pending_ack {
            self.consume_settled(call)?;
        }
        Ok(Some(value))
    }

    /// Loading is read-only with respect to unknown outcomes. Quarantine decisions
    /// and HTTP reconciliation require the journal lock and an online repair pass.
    pub(super) fn reload_pending(&self, retire: bool) -> Result<PendingRepair, ClientError> {
        let Some(directory) = &self.pending_journal else {
            return Ok(PendingRepair::default());
        };
        let mut pending = BTreeMap::new();
        let mut maintenance = false;
        for entry in std::fs::read_dir(directory).map_err(journal_error)? {
            let path = entry.map_err(journal_error)?.path();
            match path.extension().and_then(|s| s.to_str()) {
                Some("settled") if retire && is_waiter_receipt(&path) => {
                    if waiter_receipt_age(&path).is_ok_and(|age| age >= WAITER_RECEIPT_TTL) {
                        // Expiry is also checked on lookup. A cleanup failure can be retried.
                        let _ = std::fs::remove_file(path);
                    }
                    continue;
                }
                Some("inflight" | "completed") => {
                    maintenance = true;
                    continue;
                }
                Some("json" | "unknown") => {}
                _ => continue,
            }
            let operation: PendingWrite = match read_private_json(&path) {
                Ok(operation) => operation,
                Err(_) if !retire && !path.try_exists().map_err(journal_error)? => continue,
                Err(error) => return Err(error),
            };
            if operation.origin != self.base_url
                || operation.credential_scope != crate::credential_fingerprint(&self.token)
                || !matches!(operation.protocol.selected, 1 | 2)
                || operation.code != "outcome_unknown"
                || operation.key.is_empty()
                || operation.path.starts_with("//")
                || !operation.path.starts_with('/')
                || matches!(operation.method.as_str(), "GET" | "HEAD" | "")
                || (recovery(&operation) == Recovery::SignedResult
                    && operation.result_expires_at.is_none())
                || path.with_extension("json") != journal_path(directory, &operation.key)
            {
                return Err(journal_error(
                    "pending journal operation does not match its origin or credential",
                ));
            }
            pending.insert(operation.key.clone(), operation);
        }
        if retire && maintenance {
            private_directory(&directory.join(LONG_POLL_MAINTENANCE))?;
        }
        let remaining = pending
            .values()
            .filter(|row| uses_replay_budget(row))
            .count();
        let outcome_unknown = pending.len() - remaining;
        self.protocol_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending = pending;
        Ok(PendingRepair {
            remaining,
            outcome_unknown,
            ..Default::default()
        })
    }

    fn archive_unknown(
        &self,
        records: &[(PathBuf, PendingWrite)],
        now: u64,
        reason: &str,
    ) -> Result<(), ClientError> {
        let Some((first, _)) = records.first() else {
            return Ok(());
        };
        let directory = first.parent().expect("journal record has a parent");
        let mut options = StateOpenOptions::new();
        options.write(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut log = options
            .open(directory.join("quarantine.log"))
            .map_err(journal_error)?;
        private_file(&log.metadata().map_err(journal_error)?)?;
        for (path, pending) in records {
            let entry = json!({"at_unix_secs":now,"reason":reason,
                "record":path.with_extension("quarantine").file_name().unwrap().to_string_lossy(),
                "first_sent_unix_secs":pending.first_sent_unix_secs,
                "outcome":"unknown"});
            writeln!(log, "{entry}").map_err(journal_error)?;
        }
        // Sync the complete quarantine intent before moving any original bytes.
        // One log/directory sync per sweep avoids holding all writers behind
        // hundreds of individual fsyncs after an API outage.
        log.sync_all().map_err(journal_error)?;
        for (path, _) in records {
            lockyard_core::fsio::rename(path, path.with_extension("quarantine"))
                .map_err(journal_error)?;
        }
        lockyard_core::fsio::sync_dir(directory).map_err(journal_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Transport;
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    const REPLICA_A: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const REPLICA_B: &str = "00112233-4455-6677-8899-aabbccddeeee";
    const ENCRYPTION_WORKSPACE: &str = "00000000-0000-0000-0000-000000000015";
    type Requests = Arc<Mutex<Vec<(String, String, String)>>>;
    struct Server {
        url: String,
        requests: Requests,
        offline: Arc<AtomicBool>,
        date: Arc<Mutex<Option<&'static str>>>,
        drain_replica_a: Arc<AtomicBool>,
        drain_hint: Arc<Mutex<Value>>,
        encryption_key_id: Arc<Mutex<Option<String>>>,
        catalog_policy_required: Arc<AtomicBool>,
        catalog_receipt: Arc<Mutex<Option<String>>>,
        stop: Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<()>>,
    }
    impl Server {
        fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests: Requests = Arc::default();
            let offline = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let date = Arc::new(Mutex::new(None));
            let drain_replica_a = Arc::new(AtomicBool::new(false));
            let (clock, replica_a) = (date.clone(), drain_replica_a.clone());
            let drain_hint = Arc::new(Mutex::new(Value::Null));
            let hint = drain_hint.clone();
            let encryption_key_id = Arc::new(Mutex::new(None::<String>));
            let policy_key_id = encryption_key_id.clone();
            let catalog_policy_required = Arc::new(AtomicBool::new(false));
            let catalog_receipt = Arc::new(Mutex::new(None));
            let (catalog_required, catalog_saved) =
                (catalog_policy_required.clone(), catalog_receipt.clone());
            let (seen, down, done) = (requests.clone(), offline.clone(), stop.clone());
            let worker = std::thread::spawn(move || {
                'accept: while !done.load(Ordering::SeqCst) {
                    let (stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() || line.is_empty() {
                        continue;
                    }
                    let path = line.split_whitespace().nth(1).unwrap().to_owned();
                    let mut key = String::new();
                    let mut session = String::new();
                    let mut length = 0;
                    loop {
                        line.clear();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => continue 'accept,
                            Ok(_) => {}
                        }
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse().unwrap();
                            }
                            if name.eq_ignore_ascii_case("x-lockyard-session") {
                                session = value.trim().into();
                            }
                            if name.eq_ignore_ascii_case("idempotency-key") {
                                key = value.trim().into();
                            }
                        }
                    }
                    let mut body = vec![0; length];
                    if reader.read_exact(&mut body).is_err() {
                        continue;
                    }
                    let body = String::from_utf8(body).unwrap();
                    seen.lock()
                        .unwrap()
                        .push((path.clone(), key.clone(), body.clone()));
                    if path == "/api/v1/zones/claims" && key == "a-queued" {
                        let stream = reader.into_inner();
                        std::thread::spawn(move || {
                            std::thread::sleep(RECONCILE_BUDGET + Duration::from_millis(500));
                            drop(stream);
                        });
                        continue;
                    }
                    let (status, body) = if down.load(Ordering::SeqCst) {
                        (
                            503,
                            json!({"error":{"code":"unavailable","message":"offline"}}),
                        )
                    } else if path == DISCOVERY {
                        (
                            200,
                            json!({"selected_protocol":2,"min_protocol":1,"max_protocol":2,"capabilities":[]}),
                        )
                    } else if path == crate::ENCRYPTION_PATH {
                        let key_id = policy_key_id.lock().unwrap().clone();
                        (
                            200,
                            json!({
                                "encryption": if key_id.is_some() { "required" } else { "off" },
                                "key_id": key_id,
                                "workspace_id": ENCRYPTION_WORKSPACE,
                            }),
                        )
                    } else if path == "/api/v1/registry/tokens" && key.is_empty() {
                        (
                            200,
                            json!([{"id":"00112233-4455-6677-8899-aabbccddeeff","revoked_at":"2026-11-18T00:00:00Z"}]),
                        )
                    } else if path == "/api/v1/import/zones" {
                        if catalog_required.load(Ordering::SeqCst) {
                            // The server enforces the new policy before looking up the receipt.
                            (
                                422,
                                json!({"error":{"code":"catalog_legacy_forbidden","message":"legacy catalog rejected"}}),
                            )
                        } else {
                            let mut receipt = catalog_saved.lock().unwrap();
                            if receipt.is_none() {
                                *receipt = Some(key);
                                // Commit the import and lose the response.
                                continue;
                            }
                            assert_eq!(receipt.as_deref(), Some(key.as_str()));
                            (200, json!({"stored":true}))
                        }
                    } else if session == "bound-elsewhere" {
                        (
                            403,
                            json!({"error":{"code":"session_name_bound","message":"different session owner"}}),
                        )
                    } else if path == "/api/v1/admin/drain" {
                        let instance = if replica_a.load(Ordering::SeqCst) {
                            REPLICA_A
                        } else {
                            REPLICA_B
                        };
                        let request: Value = serde_json::from_str(&body).unwrap();
                        if request["instance_id"] == instance {
                            (
                                200,
                                json!({"id":"original-drain","state":"drained","instance_id":instance}),
                            )
                        } else {
                            (
                                409,
                                json!({"error":{"code":"drain_instance_mismatch","message":"use original replica","details":hint.lock().unwrap().clone()}}),
                            )
                        }
                    } else if key == "unsafe-unknown" {
                        (
                            409,
                            json!({"error":{"code":"idempotency_key_unknown","message":"replay unsafe","details":{"replay_safe":false}}}),
                        )
                    } else if key == "unknown" {
                        (
                            409,
                            json!({"error":{"code":"idempotency_key_unknown","message":"key unknown; replay unsafe"}}),
                        )
                    } else if key == "denied" {
                        (
                            422,
                            json!({"error":{"code":"invalid","message":"proven refusal"}}),
                        )
                    } else if key == "frozen-now" {
                        (503, json!({"error":{"code":"frozen","message":"frozen"}}))
                    } else {
                        (200, json!({"id":"FE-1","saved":true}))
                    };
                    let body = body.to_string();
                    let date_header = clock
                        .lock()
                        .unwrap()
                        .map_or_else(String::new, |date| format!("Date: {date}\r\n"));
                    let _ = write!(
                        reader.get_mut(),
                        "HTTP/1.1 {status} reply\r\nContent-Type: application/json\r\nLockyard-Protocol: 2\r\n{date_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
            });
            Self {
                url,
                requests,
                offline,
                date,
                drain_replica_a,
                drain_hint,
                encryption_key_id,
                catalog_policy_required,
                catalog_receipt,
                stop,
                worker: Some(worker),
            }
        }
        fn client(&self, root: &Path) -> Client {
            client_at(&self.url, root)
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Err(error) = self.worker.take().unwrap().join()
                && !std::thread::panicking()
            {
                std::panic::resume_unwind(error);
            }
        }
    }
    fn client_at(url: &str, root: &Path) -> Client {
        Client::new(url, "pending-fixture".into())
            .unwrap()
            .with_pending_journal(root.canonicalize().unwrap())
            .unwrap()
    }

    #[test]
    fn ordinary_waiter_receipt_expires_and_is_not_an_outbox_item() {
        let root = tempfile::tempdir().unwrap();
        let client = client_at("http://127.0.0.1:1", root.path());
        let mut row = pending(&client, "waited", false);
        row.path = "/api/v1/registry/areas".into();
        assert!(!eligible_for_recovery(&row));
        assert!(waiter_receipt_allowed(&row));
        let encryption = client.current_content_encryption().unwrap();
        let reply = json!({"id": "area-1"});
        client
            .publish_waiter_receipt(&row, reply.clone(), &encryption)
            .unwrap();
        assert_eq!(
            client.settled_write(&row.key).unwrap().unwrap().value,
            Some(reply)
        );
        assert!(client.unconsumed_settled_operations().unwrap().is_empty());

        let directory = client.pending_journal.as_ref().unwrap();
        let path = waiter_receipt_path(directory, &row.key);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(UNIX_EPOCH)
            .unwrap();
        assert!(client.settled_write(&row.key).unwrap().is_none());
        let _journal = PendingSendGuard::lock_journal(directory).unwrap();
        client.reload_pending(true).unwrap();
        assert!(!path.exists());
    }

    fn pending(client: &Client, key: &str, old: bool) -> PendingWrite {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut call = Call::write(
            "fixture",
            "POST",
            "/api/v1/registry/items/FE-1/evidence".into(),
            json!({"evidence":"sha:path"}),
        );
        call.key = Some(key.into());
        PendingWrite {
            code: "outcome_unknown".into(),
            cause_code: "transport".into(),
            cause_status: None,
            diagnostic: None,
            protocol: NegotiatedProtocol::candidate(2),
            method: call.method.clone(),
            path: call.path.clone(),
            request_path: call.path.clone(),
            body: Some(call.body.as_ref().unwrap().to_string()),
            key: key.into(),
            repository: None,
            session: call.session.clone(),
            origin: client.base_url.clone(),
            credential_scope: crate::credential_fingerprint(&client.token),
            request_digest: Some(crate::request_identity(&call)),
            first_sent_unix_secs: Some(if old { now - 31 * 86400 } else { now }),
            first_sent_server_secs: None,
            replay_stopped: false,
            replay_paused: false,
            pre_execution_rejected: false,
            encryption_context: Some(client.encryption_context()),
            result_expires_at: None,
            result_retry_at: None,
        }
    }
    fn save(client: &Client, pending: &PendingWrite) {
        lockyard_core::fsio::replace(
            &journal_path(client.pending_journal.as_ref().unwrap(), &pending.key),
            &serde_json::to_vec(pending).unwrap(),
            0o600,
        )
        .unwrap();
    }
    fn call_for(pending: &PendingWrite) -> Call {
        let mut call = Call::write(
            &pending.session,
            &pending.method,
            pending.request_path.clone(),
            serde_json::from_str(pending.body.as_deref().unwrap()).unwrap(),
        );
        call.key = Some(pending.key.clone());
        call
    }

    #[test]
    fn settled_mail_without_encryption_metadata_is_decoded_offline() {
        let server = Server::new();
        server.offline.store(true, Ordering::SeqCst);
        let root = tempfile::tempdir().unwrap();
        let key = crate::WorkspaceKey::from_entropy([19; 32]);
        for enabled in [false, true] {
            let client = server
                .client(root.path())
                .with_content_encryption(ENCRYPTION_WORKSPACE, Some(key.clone()), !enabled)
                .with_live_write_encryption_policy();
            let mut row = pending(&client, &format!("settled-{enabled}"), false);
            row.path = "/api/v1/bus/messages".into();
            row.request_path = row.path.clone();
            row.body = Some(json!({"to":"bob","body":"hello"}).to_string());
            let call = call_for(&row);
            row.request_digest = Some(crate::request_identity(&call));
            row.encryption_context = Some(client.encryption_context_for(
                Some(ENCRYPTION_WORKSPACE),
                Some(&key.key_id()),
                enabled,
            ));
            let wire_body = if enabled {
                key.encrypt(ENCRYPTION_WORKSPACE, "body", "hello").unwrap()
            } else {
                "hello".into()
            };
            let receipt = SettledWrite {
                pending: row.clone(),
                value: Some(json!({"id":42,"to":"bob","from_session":"fixture","body":wire_body})),
                error: None,
                consumed: false,
                encryption: None,
            };
            let path = journal_path(client.pending_journal.as_ref().unwrap(), &row.key);
            lockyard_core::fsio::replace(
                &path.with_extension("settled"),
                &serde_json::to_vec(&receipt).unwrap(),
                0o600,
            )
            .unwrap();
            // A crash can leave the original record beside the already-synced receipt.
            save(&client, &row);
            let report = client.repair_pending().unwrap();
            assert_eq!(report.remaining, 0);
            assert!(!report.network_required);
            assert!(!path.exists());
            assert_eq!(client.call(&call).unwrap()["body"], "hello");
            assert!(client.settled_write(&row.key).unwrap().unwrap().consumed);
        }
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn offline_started_client_can_read_an_older_encrypted_receipt() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server
            .client(root.path())
            .with_live_write_encryption_policy();
        let key = crate::WorkspaceKey::from_entropy([29; 32]);
        key.store_for_workspace(ENCRYPTION_WORKSPACE).unwrap();
        *server.encryption_key_id.lock().unwrap() = Some(key.key_id());

        let mut row = pending(&client, "legacy-encrypted", false);
        row.path = "/api/v1/bus/messages".into();
        row.request_path = row.path.clone();
        row.body = Some(json!({"to":"bob","body":"hello"}).to_string());
        let call = call_for(&row);
        row.request_digest = Some(crate::request_identity(&call));
        row.encryption_context = Some(client.encryption_context_for(
            Some(ENCRYPTION_WORKSPACE),
            Some(&key.key_id()),
            true,
        ));
        let body = key.encrypt(ENCRYPTION_WORKSPACE, "body", "hello").unwrap();
        let receipt = SettledWrite {
            pending: row,
            value: Some(json!({"id":42,"to":"bob","from_session":"fixture","body":body})),
            error: None,
            consumed: false,
            encryption: None,
        };
        let path = journal_path(
            client.pending_journal.as_ref().unwrap(),
            &receipt.pending.key,
        )
        .with_extension("settled");
        lockyard_core::fsio::replace(&path, &serde_json::to_vec(&receipt).unwrap(), 0o600).unwrap();

        let recovered = client.call(&call);
        std::fs::remove_file(crate::WorkspaceKey::storage_path(ENCRYPTION_WORKSPACE).unwrap())
            .unwrap();
        assert_eq!(recovered.unwrap()["body"], "hello");
        let seen = server.requests.lock().unwrap();
        assert!(
            seen.iter()
                .any(|(path, _, _)| path == crate::ENCRYPTION_PATH)
        );
        assert!(seen.iter().all(|(_, key, _)| key.is_empty()), "{seen:?}");
    }

    fn drain(client: &Client) -> PendingRepair {
        let end = Instant::now() + Duration::from_secs(20);
        let mut result = PendingRepair::default();
        loop {
            let report = client.repair_pending().unwrap();
            result.applied += report.applied;
            result.rejected += report.rejected;
            result.quarantined += report.quarantined;
            result.remaining = report.remaining;
            if result.remaining == 0 {
                return result;
            }
            assert!(Instant::now() < end, "reconciliation stalled: {report:?}");
        }
    }
    #[test]
    fn ly0030_old_registry_evidence_reconciles_saved_result_and_caller_consumes_receipt() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let record = pending(&client, "evidence", true);
        save(&client, &record);
        let restored = server.client(root.path());
        assert!(restored.pending_operations().is_empty());
        assert!(
            !journal_path(restored.pending_journal.as_ref().unwrap(), "evidence")
                .with_extension("quarantine")
                .exists()
        );
        assert_eq!(restored.call(&call_for(&record)).unwrap()["saved"], true);
        let seen = server.requests.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, record.key);
        assert_eq!(Some(seen[0].2.as_str()), record.body.as_deref());
    }
    #[test]
    fn ly0030_old_registry_create_client_key_and_frozen_refusal_replay_exact_bytes() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        for key in ["create", "frozen"] {
            let mut record = pending(&client, key, true);
            if key == "create" {
                record.path = "/api/v1/registry/items".into();
                record.request_path = record.path.clone();
                record.body = Some(json!({"client_key":crate::ulid()}).to_string());
            } else {
                record.pre_execution_rejected = true;
                record.cause_code = "frozen".into();
                record.cause_status = Some(503);
            }
            save(&client, &record);
        }
        let report = drain(&client);
        assert_eq!(
            (report.applied, report.quarantined, report.remaining),
            (2, 0, 0)
        );
        assert_eq!(server.requests.lock().unwrap().len(), 2);
    }
    #[test]
    fn ly0030_unanchored_operation_is_retained_and_rejection_closes() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let mut unknown = pending(&client, "unknown", false);
        unknown.path = "/api/v1/presence".into();
        unknown.request_path = unknown.path.clone();
        save(&client, &unknown);
        let mut denied = pending(&client, "denied", false);
        denied.pre_execution_rejected = true;
        denied.cause_code = "frozen".into();
        denied.cause_status = Some(503);
        save(&client, &denied);
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.quarantined, report.rejected, report.remaining),
            (0, 1, 0)
        );
        assert!(
            journal_path(client.pending_journal.as_ref().unwrap(), "unknown")
                .with_extension("unknown")
                .exists()
        );
    }

    #[test]
    fn r14_catalog_policy_refusal_before_receipt_preserves_committed_import() {
        let server = Server::new();
        *server.date.lock().unwrap() = Some("Thu, 12 Nov 2026 10:20:00 GMT");
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let call = Call::write(
            "fixture",
            "POST",
            "/api/v1/import/zones".into(),
            json!({"catalog":{"r14-fixture":["src"]}}),
        );
        let key = call.key.as_deref().unwrap();
        assert!(matches!(
            client.call(&call),
            Err(ClientError::OutcomeUnknown(_))
        ));
        assert_eq!(server.catalog_receipt.lock().unwrap().as_deref(), Some(key));

        server.catalog_policy_required.store(true, Ordering::SeqCst);
        let client = Client::new(&server.url, "pending-fixture".into())
            .unwrap()
            .load_pending_journal(root.path().canonicalize().unwrap())
            .unwrap();
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.applied, report.rejected, report.remaining),
            (0, 0, 1)
        );
        let retained = client.pending_operation(key).unwrap();
        assert_eq!(retained.cause_code, "catalog_legacy_forbidden");
        assert!(client.settled_write(key).unwrap().is_none());

        server
            .catalog_policy_required
            .store(false, Ordering::SeqCst);
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.applied, report.rejected, report.remaining),
            (1, 0, 0)
        );
        assert_eq!(
            client.settled_write(key).unwrap().unwrap().value,
            Some(json!({"stored":true}))
        );
        assert_eq!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, sent, _)| sent == key)
                .count(),
            3
        );
    }
    #[test]
    fn ly0030_durable_route_parks_explicitly_unsafe_unknown_key() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let record = pending(&client, "unsafe-unknown", true);
        save(&client, &record);
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.quarantined, report.rejected, report.remaining),
            (0, 0, 0)
        );
        assert_eq!(report.unknown_ids, [record.key]);
    }

    #[test]
    fn recovered_commit_evidence_warns_only_for_encrypted_requests() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let key = crate::WorkspaceKey::from_entropy([19; 32]);
        let evidence = "abcdef0:src/file";
        for enabled in [true, false] {
            let client = server.client(root.path()).with_content_encryption(
                ENCRYPTION_WORKSPACE,
                Some(key.clone()),
                !enabled,
            );
            let mut row = pending(&client, &format!("settled-evidence-{enabled}"), false);
            row.body = Some(json!({"kind":"commit","value":evidence}).to_string());
            let call = call_for(&row);
            row.request_digest = Some(crate::request_identity(&call));
            row.encryption_context = Some(client.encryption_context_for(
                Some(ENCRYPTION_WORKSPACE),
                Some(&key.key_id()),
                enabled,
            ));
            if enabled {
                let ciphertext = key
                    .encrypt(ENCRYPTION_WORKSPACE, "value", evidence)
                    .unwrap();
                row.body = Some(json!({"kind":"commit","value":ciphertext}).to_string());
            }
            let receipt = SettledWrite {
                pending: row.clone(),
                value: Some(json!({"id":"FE-1","status":"review"})),
                error: None,
                consumed: false,
                encryption: None,
            };
            let path = journal_path(client.pending_journal.as_ref().unwrap(), &row.key);
            lockyard_core::fsio::replace(
                &path.with_extension("settled"),
                &serde_json::to_vec(&receipt).unwrap(),
                0o600,
            )
            .unwrap();
            let response = client.call(&call).unwrap();
            assert_eq!(response.get("warnings").is_some(), enabled);
        }
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn ly0030_reconciled_create_reuses_client_key_until_caller_consumes_receipt() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let mut record = pending(&client, "create-receipt", true);
        let mut call = Call::write(
            "fixture",
            "POST",
            "/api/v1/registry/items".into(),
            json!({
                "title":"work",
                "client_key":crate::ulid(),
                "evidence":[{
                    "kind":"commit",
                    "value":"abcdef0:src/file",
                    "observed_at":"old timestamp",
                    "commit_sha":"abcdef0123456789abcdef0123456789abcdef01"
                }]
            }),
        );
        call.key = Some(record.key.clone());
        record.path = call.path.clone();
        record.request_path = call.path.clone();
        record.body = Some(call.body.as_ref().unwrap().to_string());
        record.request_digest = Some(crate::request_identity(&call));
        save(&client, &record);
        let restored = server.client(root.path());
        let mut candidate = call.clone();
        candidate.key = Some(crate::ulid());
        candidate.body.as_mut().unwrap()["client_key"] = json!(crate::ulid());
        candidate.body.as_mut().unwrap()["evidence"][0]["commit_sha"] =
            json!("abcdef0987654321abcdef0987654321abcdef09");
        let recovered = restored.pending_task_create(&candidate, false).unwrap();
        assert_eq!(recovered.key, call.key, "retry chose a different HTTP key");
        assert_eq!(recovered.body, call.body);
        assert_eq!(restored.call(&recovered).unwrap()["saved"], true);
        // A subsequent intentional create with the same title uses its own key.
        assert_eq!(
            restored.pending_task_create(&candidate, false).unwrap().key,
            candidate.key
        );
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1, call.key.unwrap());
        assert_eq!(requests[0].2, call.body.unwrap().to_string());
    }

    #[test]
    fn ly0030_background_receipt_remains_unconsumed_until_outbox_ack() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let record = pending(&client, "deferred", true);
        save(&client, &record);
        let restored = server.client(root.path());
        let mut call = call_for(&record);
        call.defer_pending_ack = true;
        assert_eq!(restored.call(&call).unwrap()["saved"], true);
        assert!(
            !restored
                .settled_write("deferred")
                .unwrap()
                .unwrap()
                .consumed
        );
        restored.acknowledge_write(&call).unwrap();
        assert!(
            restored
                .settled_write("deferred")
                .unwrap()
                .unwrap()
                .consumed
        );
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn ly0030_live_full_journal_reconciles_before_admission() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        for i in 0..140 {
            save(&client, &pending(&client, &format!("old-{i}"), true));
        }
        let mut guard = client.claim_pending_send("new").unwrap();
        client
            .repair_before_admission(&mut guard, 1024, Duration::from_secs(5))
            .unwrap();
        client
            .retain_pending(pending(&client, "new", false))
            .unwrap();
        drop(guard);
        assert!(client.pending_operations().len() <= MAX_PENDING);
        assert!(!server.requests.lock().unwrap().is_empty());
        drain(&client);
        assert_eq!(server.requests.lock().unwrap().len(), 141);
    }
    #[test]
    fn admission_reconciliation_respects_the_call_deadline() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let date = "Thu, 12 Nov 2026 10:21:00 GMT";
        *server.date.lock().unwrap() = Some(date);
        let mut claim = pending(&client, "a-queued", false);
        claim.path = "/api/v1/zones/claims".into();
        claim.request_path = claim.path.clone();
        claim.body = Some(json!({"paths":["src"],"queue_wait_seconds":30}).to_string());
        claim.first_sent_server_secs = Some(crate::http_date_ms(date).unwrap() as u64 / 1000);
        save(&client, &claim);
        for index in 0..MAX_PENDING {
            save(&client, &pending(&client, &format!("old-{index}"), true));
        }
        let mut call = Call::write(
            "fixture",
            "POST",
            "/api/v1/registry/items".into(),
            json!({"title":"new"}),
        );
        call.deadline_ms = Some(500);
        let started = Instant::now();
        assert!(client.call(&call).is_err());
        assert!(
            started.elapsed() < Duration::from_millis(1_100),
            "admission reconcile exceeded the original call deadline: {:?}",
            started.elapsed()
        );
        let requests = server.requests.lock().unwrap();
        let writes: Vec<_> = requests
            .iter()
            .filter(|(_, key, _)| !key.is_empty())
            .collect();
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert_eq!(writes[0].1, "a-queued");
    }

    #[test]
    fn ly0030_network_unavailable_preserves_bytes_and_reports_repair() {
        let server = Server::new();
        server.offline.store(true, Ordering::SeqCst);
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        for i in 0..140 {
            save(&client, &pending(&client, &format!("old-{i}"), true));
        }
        let mut finite = pending(&client, "finite", true);
        finite.path = "/api/v1/presence".into();
        finite.request_path = finite.path.clone();
        save(&client, &finite);
        let original_path = journal_path(client.pending_journal.as_ref().unwrap(), "old-0");
        let original_bytes = std::fs::read(&original_path).unwrap();
        let report = client.repair_pending().unwrap();
        assert!(report.network_required);
        assert_eq!(
            (report.remaining, report.outcome_unknown, report.quarantined),
            (140, 1, 0)
        );
        let _guard = client.claim_pending_send("new").unwrap();
        let error = client
            .retain_pending(pending(&client, "new", false))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("lockyard doctor --repair-pending")
                && error.contains("network required"),
            "{error}"
        );
        assert_eq!(client.pending_operations().len(), 141);
        let disk: PendingWrite = read_private_json(&journal_path(
            client.pending_journal.as_ref().unwrap(),
            "old-0",
        ))
        .unwrap();
        assert_eq!(disk.body, pending(&client, "old-0", true).body);
        assert_eq!(disk.cause_code, "transport");
        assert_eq!(std::fs::read(original_path).unwrap(), original_bytes);
    }
    #[test]
    fn ly0030_legacy_finite_window_stays_unknown_without_a_server_anchor() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let mut record = pending(&client, "finite", true);
        record.path = "/api/v1/presence".into();
        record.request_path = record.path.clone();
        // On a 0.3.15 client a one-hour wall-clock rollback could make a
        // receipt beyond 30 days look younger than its retention window.
        record.first_sent_unix_secs = Some(unix_now().unwrap() - PENDING_RETENTION_SECS + 3600);
        save(&client, &record);
        *server.date.lock().unwrap() = Some("Thu, 12 Nov 2026 10:21:00 GMT");
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.quarantined, report.remaining, report.outcome_unknown),
            (0, 0, 1)
        );
        let saved = client.pending_operation("finite").unwrap();
        assert!(saved.replay_stopped);
        assert_eq!(saved.body, record.body);
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn pending_coordination_uses_server_clock_without_discarding_expired_replay() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let deadline = u64::try_from(crate::http_date_ms("Thu, 12 Nov 2026 10:21:00 GMT").unwrap())
            .unwrap()
            / 1000;
        // Local age exceeds 30 days. The server still has this exact receipt.
        let mut record = pending(&client, "receipt-before-cutoff", true);
        record.path = "/api/v1/presence".into();
        record.request_path = record.path.clone();
        record.first_sent_server_secs = Some(deadline - PENDING_RETENTION_SECS);
        save(&client, &record);
        *server.date.lock().unwrap() = Some("Thu, 12 Nov 2026 10:19:59 GMT");
        let report = client.repair_pending().unwrap();
        assert_eq!((report.applied, report.quarantined), (1, 0));
        let receipt = client.settled_write(&record.key).unwrap().unwrap();
        assert_eq!(receipt.value.unwrap()["saved"], true);

        // Local age is near zero. The server has reached its no-blind-replay window.
        record.key = "elapsed-according-to-server".into();
        record.first_sent_unix_secs = Some(unix_now().unwrap());
        save(&client, &record);
        *server.date.lock().unwrap() = Some("Thu, 12 Nov 2026 10:20:00 GMT");
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.quarantined, report.remaining, report.outcome_unknown),
            (0, 0, 1)
        );
        assert!(
            client
                .pending_operation(&record.key)
                .unwrap()
                .replay_stopped
        );
        assert!(
            !server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(_, key, _)| key == &record.key)
        );

        *server.date.lock().unwrap() = Some("Thu, 12 Nov 2026 10:21:59 GMT");
        let report = client.repair_pending().unwrap();
        assert_eq!((report.quarantined, report.outcome_unknown), (0, 1));
        // Keep the same result if the endpoint is reachable but omits Date.
        *server.date.lock().unwrap() = None;
        assert_eq!(client.repair_pending().unwrap().outcome_unknown, 1);

        *server.date.lock().unwrap() = Some("Thu, 12 Nov 2026 10:22:00 GMT");
        let report = client.repair_pending().unwrap();
        assert_eq!((report.quarantined, report.outcome_unknown), (0, 1));
        let retained = client.pending_operation(&record.key).unwrap();
        assert_eq!(retained.body, record.body);
        assert!(retained.replay_stopped);
        assert!(client.settled_write(&record.key).unwrap().is_none());
        let new = Call::write("fixture", "POST", "/api/v1/presence".into(), json!({}));
        assert_eq!(client.call(&new).unwrap()["saved"], true);
    }

    #[test]
    fn pending_closed_replay_windows_leave_capacity_for_new_writes() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        for index in 0..MAX_PENDING {
            let mut row = pending(&client, &format!("closed-{index}"), false);
            row.path = "/api/v1/presence".into();
            row.request_path = row.path.clone();
            row.replay_stopped = true;
            save(&client, &row);
        }
        let _guard = client.claim_pending_send("new-after-cutoff").unwrap();
        client
            .retain_pending(pending(&client, "new-after-cutoff", false))
            .unwrap();
        let mut report = PendingRepair::default();
        client.summarize_pending(&mut report);
        assert_eq!((report.remaining, report.outcome_unknown), (1, MAX_PENDING));
        assert!(server.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn pending_incompatible_encryption_releases_a_full_active_budget() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let plain = server.client(root.path());
        let rows: Vec<_> = (0..MAX_PENDING)
            .map(|index| pending(&plain, &format!("plaintext-{index:03}"), false))
            .collect();
        for row in &rows {
            save(&plain, row);
        }
        assert_eq!(plain.reload_pending(false).unwrap().remaining, MAX_PENDING);

        let key = crate::WorkspaceKey::from_entropy([15; 32]);
        let key_id = key.key_id();
        *server.encryption_key_id.lock().unwrap() = Some(key_id.clone());
        let mut encrypted = plain
            .with_pending_encryption_policy()
            .with_content_encryption(ENCRYPTION_WORKSPACE, Some(key), true);
        encrypted.expected_key_id = Some(key_id);
        let new = Call::write(
            "fixture",
            "POST",
            "/api/v1/registry/items".into(),
            json!({"title":"new encrypted title"}),
        );
        // Admission itself must free space, without an earlier doctor run.
        assert_eq!(encrypted.call(&new).unwrap()["saved"], true);
        assert_eq!(drain(&encrypted).remaining, 0);
        let directory = encrypted.pending_journal.as_ref().unwrap();
        for row in rows {
            let path = journal_path(directory, &row.key);
            assert!(!path.exists());
            let parked: PendingWrite = read_private_json(&path.with_extension("unknown")).unwrap();
            assert_eq!(parked.cause_code, ENCRYPTION_MISMATCH);
            assert_eq!(parked.body, row.body);
        }
        let requests = server.requests.lock().unwrap();
        let writes: Vec<_> = requests
            .iter()
            .filter(|(_, key, _)| !key.is_empty())
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(Some(&writes[0].1), new.key.as_ref());
        assert!(!writes[0].2.contains("new encrypted title"));
    }

    #[test]
    fn pending_ordinary_retry_rechecks_encryption_and_can_recover_when_policy_matches() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path()).with_pending_encryption_policy();
        let row = pending(&client, "policy-change", false);
        save(&client, &row);
        let call = call_for(&row);
        *server.encryption_key_id.lock().unwrap() = Some("required-fixture-key".into());
        assert!(matches!(
            client.call(&call),
            Err(ClientError::OutcomeUnknown(parked))
                if parked.cause_code == ENCRYPTION_MISMATCH
                    && parked.body == row.body
                    && parked.replay_paused
                    && !parked.replay_stopped
        ));
        assert!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|(_, key, _)| key.is_empty())
        );

        *server.encryption_key_id.lock().unwrap() = None;
        let report = client.repair_pending().unwrap();
        assert_eq!(
            (report.applied, report.remaining, report.outcome_unknown),
            (1, 0, 0)
        );
        let requests = server.requests.lock().unwrap();
        let writes: Vec<_> = requests
            .iter()
            .filter(|(_, key, _)| !key.is_empty())
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].1, row.key);
        assert_eq!(Some(writes[0].2.as_str()), row.body.as_deref());
    }

    #[test]
    fn pending_full_journal_continues_past_one_session_refusal() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let mut bad = pending(&client, "oldest", true);
        bad.session = "bound-elsewhere".into();
        save(&client, &bad);
        for index in 1..MAX_PENDING {
            let mut row = pending(&client, &format!("remaining-{index}"), false);
            row.session = format!("session-{index}");
            save(&client, &row);
        }
        let report = client
            .repair_pending_for_capacity(Instant::now() + Duration::from_secs(10))
            .unwrap();
        assert_eq!(report.applied, MAX_PENDING - 1);
        assert_eq!(
            (report.remaining, report.rejected, report.network_required),
            (1, 0, false)
        );
        let saved = client.pending_operation(&bad.key).unwrap();
        assert_eq!(saved.cause_code, "session_name_bound");
        assert_eq!(saved.cause_status, Some(403));
        assert_eq!(saved.body, bad.body);
    }

    #[test]
    fn pending_drain_reconciles_only_at_the_trusted_original_replica() {
        for hint_with_url in [true, false] {
            let original = Server::new();
            original.drain_replica_a.store(true, Ordering::SeqCst);
            let load_balancer = Server::new();
            let root = tempfile::tempdir().unwrap();
            let client = load_balancer.client(root.path());
            let mut row = pending(&client, "drain", true);
            row.path = "/api/v1/admin/drain".into();
            row.request_path = row.path.clone();
            row.body = Some(json!({"scope":"workspace","instance_id":REPLICA_A}).to_string());
            save(&client, &row);
            let mut hint = json!({"original_instance_id":REPLICA_A});
            if hint_with_url {
                hint["original_instance_url"] = json!(original.url);
            }
            *load_balancer.drain_hint.lock().unwrap() = hint;

            // The supplied URL alone is not authority to transmit a credential.
            let report = client.repair_pending().unwrap();
            assert_eq!(
                (report.remaining, report.rejected, report.outcome_unknown),
                (0, 0, 1)
            );
            assert_eq!(report.drain_instance_mismatch, [row.key.clone()]);
            assert!(client.settled_write(&row.key).unwrap().is_none());
            assert!(original.requests.lock().unwrap().is_empty());

            let trusted = original.url.clone();
            let client = client.with_trusted_replica(move |id, address| {
                (id == Some(REPLICA_A) && address.is_none_or(|url| url == trusted))
                    .then(|| trusted.clone())
            });
            let report = client.repair_pending().unwrap();
            assert_eq!(
                (report.applied, report.rejected, report.outcome_unknown),
                (1, 0, 0)
            );
            let receipt = client
                .settled_write(&row.key)
                .unwrap()
                .unwrap()
                .value
                .unwrap();
            assert_eq!(receipt["id"], "original-drain");
            assert_eq!(receipt["instance_id"], REPLICA_A);
            let seen = original.requests.lock().unwrap();
            assert_eq!(seen.as_slice(), &[(row.path, row.key, row.body.unwrap())]);
        }
    }

    #[test]
    fn queued_claim_reconciliation_releases_the_journal_and_advances_the_cursor() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let date = "Thu, 12 Nov 2026 10:21:00 GMT";
        *server.date.lock().unwrap() = Some(date);
        let mut claim = pending(&client, "a-queued", false);
        claim.path = "/api/v1/zones/claims".into();
        claim.request_path = claim.path.clone();
        claim.body = Some(json!({"paths":["src"],"queue_wait_seconds":30}).to_string());
        claim.first_sent_server_secs = Some(crate::http_date_ms(date).unwrap() as u64 / 1000);
        save(&client, &claim);
        save(&client, &pending(&client, "b-other", false));
        save(&client, &pending(&client, "c-next", false));

        std::thread::scope(|scope| {
            let repair = scope.spawn(|| {
                client
                    .repair_pending_with_age(0, Duration::from_millis(50), false, None)
                    .unwrap()
            });
            let limit = Instant::now() + Duration::from_secs(3);
            while !server
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|(_, key, _)| key == "a-queued")
            {
                assert!(
                    Instant::now() < limit,
                    "queued reconciliation never reached the server"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let sibling = server.client(root.path());
            let _sibling_guard = sibling.claim_pending_send("independent").unwrap();
            assert!(
                !repair.is_finished(),
                "journal must be available during the queued request"
            );
            drop(_sibling_guard);
            assert_eq!(repair.join().unwrap().applied, 1);
        });
        assert!(client.settled_write("b-other").unwrap().is_some());
        assert!(client.settled_write("c-next").unwrap().is_none());
        assert_eq!(
            client
                .repair_pending_with_age(0, Duration::ZERO, false, None)
                .unwrap()
                .applied,
            1
        );
        assert!(client.settled_write("c-next").unwrap().is_some());
        let requests = server.requests.lock().unwrap();
        let order: Vec<_> = requests
            .iter()
            .filter(|(_, key, _)| !key.is_empty())
            .map(|(_, key, _)| key.as_str())
            .collect();
        assert_eq!(order, ["a-queued", "b-other", "c-next", "a-queued"]);
    }

    #[test]
    fn ly0030_running_client_reloads_after_sibling_repair_without_restart() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let running = server.client(root.path());
        running
            .retain_pending(pending(&running, "live", true))
            .unwrap();
        let _sibling = server.client(root.path());
        assert!(running.pending_operation("live").is_some());
        let _guard = running.claim_pending_send("next").unwrap();
        assert!(running.pending_operation("live").is_none());
    }
    #[test]
    fn ly0030_maintenance_keeps_an_active_long_poll_until_its_owner_releases() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let mut guard = client.claim_pending_send("active").unwrap();
        client
            .retain_pending(pending(&client, "active", false))
            .unwrap();
        guard.release_journal().unwrap();
        assert_eq!(client.repair_pending().unwrap().remaining, 1);
        assert!(server.requests.lock().unwrap().is_empty());
        drop(guard);
        assert_eq!(client.repair_pending().unwrap().applied, 1);
    }
    #[test]
    fn ly0030_two_processes_repair_and_write_without_lost_records() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let parent = server.client(root.path());
        for i in 0..140 {
            save(&parent, &pending(&parent, &format!("old-{i}"), true));
        }
        let held =
            PendingSendGuard::lock_journal(parent.pending_journal.as_ref().unwrap()).unwrap();
        let mut children = Vec::new();
        for key in ["child-a", "child-b"] {
            children.push(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "protocol::maintenance::tests::ly0030_repair_child",
                        "--nocapture",
                    ])
                    .env("LY0030_TEST_ROOT", root.path())
                    .env("LY0030_TEST_URL", &server.url)
                    .env("LY0030_TEST_KEY", key)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
        for child in children {
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        let restored = server.client(root.path());
        drain(&restored);
        let requests = server.requests.lock().unwrap();
        for i in 0..140 {
            assert_eq!(
                requests
                    .iter()
                    .filter(|(_, key, _)| key == &format!("old-{i}"))
                    .count(),
                1
            );
        }
        for key in ["child-a", "child-b"] {
            assert!(requests.iter().any(|(_, k, _)| k == key));
        }
    }
    #[test]
    fn ly0030_repair_child() {
        let Some(root) = std::env::var_os("LY0030_TEST_ROOT") else {
            return;
        };
        let client = client_at(&std::env::var("LY0030_TEST_URL").unwrap(), Path::new(&root));
        let key = std::env::var("LY0030_TEST_KEY").unwrap();
        let end = Instant::now() + Duration::from_secs(8);
        loop {
            match client.repair_pending() {
                Ok(_) => break,
                Err(ClientError::JournalBusy) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
        loop {
            match client.claim_pending_send(&key) {
                Ok(_guard) => {
                    client
                        .retain_pending(pending(&client, &key, false))
                        .unwrap();
                    break;
                }
                Err(ClientError::JournalBusy) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
    }
    #[test]
    fn ly0030_signed_results_use_server_clock_for_their_separate_replay_window() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let deadline = u64::try_from(crate::http_date_ms("Thu, 12 Nov 2026 10:21:00 GMT").unwrap())
            .unwrap()
            / 1000;
        let mut created_ms = (deadline - 365 * 86400) * 1000;
        let mut timestamp = [b'0'; 10];
        for byte in timestamp.iter_mut().rev() {
            *byte = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(created_ms & 31) as usize];
            created_ms >>= 5;
        }
        let job = format!(
            "{}0000000000000000",
            std::str::from_utf8(&timestamp).unwrap()
        );
        let mut row = pending(&client, "near-expiry", false);
        row.method = "PUT".into();
        row.path = format!("/api/v1/nodes/node/jobs/{job}/signed-result");
        row.request_path = row.path.clone();
        row.result_expires_at = Some("2026-11-12T10:21:00Z".into());
        row.first_sent_server_secs = Some(deadline - 364 * 86400);
        save(&client, &row);
        for (date, expected) in [
            ("Thu, 12 Nov 2026 10:19:59 GMT", (0, false)),
            ("Thu, 12 Nov 2026 10:20:00 GMT", (0, true)),
            ("Thu, 12 Nov 2026 10:21:59 GMT", (0, true)),
            ("Thu, 12 Nov 2026 10:22:00 GMT", (0, true)),
        ] {
            *server.date.lock().unwrap() = Some(date);
            let report = client.repair_pending().unwrap();
            assert_eq!(
                (
                    report.quarantined,
                    client
                        .pending_operation(&row.key)
                        .is_some_and(|row| row.replay_stopped)
                ),
                expected
            );
        }
        assert!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|(path, _, _)| path == DISCOVERY)
        );
    }
    #[test]
    fn ly0030_unlisted_routes_stay_unknown_and_do_not_fill_replay_budget() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        for index in 0..=MAX_PENDING {
            let mut record = pending(&client, &format!("unlisted-{index}"), true);
            match index % 3 {
                0 => record.path = "/api/v1/registry/items/FE-1/new-operation".into(),
                1 => record.path = "/api/v1/zones/checkpoint".into(),
                // The same URL with a different method is a different contract.
                _ => record.method = "DELETE".into(),
            }
            record.request_path = record.path.clone();
            record.pre_execution_rejected = true;
            record.request_digest = Some(crate::request_identity(&call_for(&record)));
            save(&client, &record);
        }
        let client = server.client(root.path());
        for index in 0..3 {
            let record = client
                .pending_operation(&format!("unlisted-{index}"))
                .unwrap();
            let call = call_for(&record);
            assert!(call.is_write());
            assert!(matches!(
                client.call(&call),
                Err(ClientError::OutcomeUnknown(_))
            ));
        }
        let report = client.repair_pending().unwrap();
        assert_eq!(report.outcome_unknown, MAX_PENDING + 1);
        assert_eq!((report.remaining, report.quarantined), (0, 0));
        assert!(server.requests.lock().unwrap().is_empty());

        let call = Call::write("fixture", "POST", "/api/v1/presence".into(), json!({}));
        assert_eq!(client.call(&call).unwrap()["saved"], true);
    }

    #[test]
    fn ly0030_token_revoke_confirms_state_with_get() {
        let server = Server::new();
        let root = tempfile::tempdir().unwrap();
        let client = server.client(root.path());
        let mut record = pending(&client, "lost-revoke", true);
        record.path = "/api/v1/registry/tokens/00112233-4455-6677-8899-aabbccddeeff/revoke".into();
        record.request_path = record.path.clone();
        save(&client, &record);
        let report = client.repair_pending().unwrap();
        assert_eq!((report.outcome_unknown, report.state_observed), (0, 1));
        assert_eq!(report.applied, 1);
        assert!(client.pending_operation(&record.key).is_none());
        assert_eq!(
            client
                .settled_write(&record.key)
                .unwrap()
                .unwrap()
                .value
                .unwrap()["id"],
            "00112233-4455-6677-8899-aabbccddeeff"
        );
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0],
            (
                "/api/v1/registry/tokens".into(),
                String::new(),
                String::new()
            )
        );
    }
}
