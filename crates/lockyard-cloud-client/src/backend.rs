// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! [`Backend`] over the cloud protocol.
//!
//! The protocol names the fields of a record but not the envelope of a response, so a list reads
//! either as a bare array or under its plural name, and a record either bare or under its singular name.

use crate::{Call, ClientError, MAX_POLL_WAIT_SECONDS, Transport, encode, ulid};
use lockyard_core::proto::{
    AccessAnswer, AccessRecord, AccessRequest, ActivityRequest, AgentSeen, BoardEntry, BoardWrite,
    CheckStatus, Claim, ClaimQuery, ClaimRequest, DirtyPath, EventPage, EventQuery, Freeze,
    InboxPage, InboxQuery, LostClaim, Message, PathCheck, Presence, PresenceBeat, QueueEntry,
    QueueRequest, ReleaseRequest, RenewRequest, SendRequest, Stream, TokenRequest, Undelivered,
    WorkAction, WorkOffer, WorkStep, WorkTask, parse_rfc3339, rfc3339,
};
use lockyard_core::zones::Conflict;
use lockyard_core::{Backend, Error, Result, bus, tasks};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const ITEMS: &str = "/api/v1/registry/items";
const TOKENS: &str = "/api/v1/registry/tokens";
const AREAS: &str = "/api/v1/registry/areas";
const MAX_REGISTRY_TEXT_BYTES: usize = 8 * 1024;
const MAX_EVIDENCE_BYTES: usize = 1024;
const MAX_EVIDENCE_COUNT: usize = 4;
const ITEM_PAGE: usize = 200;
const DEFAULT_PRIORITY: &str = "P2";
const DEFAULT_TARGET: &str = "code_accepted";
/// The area a workspace gets when the first item needs one.
const DEFAULT_AREA: &str = "general";
/// The server keeps at most this many unread messages per addressee and refuses a larger page.
const INBOX_PAGE: usize = 50;
pub(crate) const UNREAD_TRUNCATED: &str = "unread count unknown: inbox truncated";
/// The protocol requires a lifetime on every board value.
const DEFAULT_BOARD_MINUTES: i64 = 24 * 60;
/// The kind of a message that names none: mail stays seven days, as it does in local mode.
const DEFAULT_KIND: &str = "ask";
/// `who` lists sessions seen in this window, the time mail is kept.
const WHO_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

fn compatibility_error(error: String) -> ClientError {
    if matches!(
        error.as_str(),
        "invalid_task_id"
            | "invalid_request"
            | "legacy_input_removed"
            | "legacy_task_id_unrepresentable"
    ) {
        crate::protocol::local(&error, "wire compatibility input rejected")
    } else {
        ClientError::Decode(error)
    }
}

/// Reads only the endpoint-selected list wrappers, then projects its known DTO schema.
pub fn list<T: DeserializeOwned>(
    value: Value,
    names: &[&str],
) -> std::result::Result<Vec<T>, ClientError> {
    let items = lockyard_compat::LegacyCompatibilityV1::wire_list(
        value,
        names,
        lockyard_compat::Source::Sdk,
        2,
    )
    .map_err(compatibility_error)?;
    let records = items
        .as_array()
        .expect("wire_list returns array")
        .iter()
        .map(|value| {
            lockyard_compat::LegacyCompatibilityV1::wire_schema(
                value.clone(),
                std::any::type_name::<T>(),
                lockyard_compat::Source::Sdk,
                2,
            )
            .map_err(compatibility_error)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    serde_json::from_value(Value::Array(records))
        .map_err(|error| ClientError::Decode(error.to_string()))
}

/// Reads only this record wrapper and schema; no field aliases live in domain serde models.
pub fn one<T: DeserializeOwned>(value: Value, name: &str) -> std::result::Result<T, ClientError> {
    let record = lockyard_compat::LegacyCompatibilityV1::wire_record(
        value,
        name,
        lockyard_compat::Source::Sdk,
        2,
    )
    .map_err(compatibility_error)?;
    let canonical = lockyard_compat::LegacyCompatibilityV1::wire_schema(
        record,
        std::any::type_name::<T>(),
        lockyard_compat::Source::Sdk,
        2,
    )
    .map_err(compatibility_error)?;
    serde_json::from_value(canonical).map_err(|error| ClientError::Decode(error.to_string()))
}

/// Reads the answer of `zones/check`: for each path, free, own, or the holder.
pub fn checks(value: Value) -> std::result::Result<Vec<PathCheck>, ClientError> {
    let items: Vec<Value> = list(value, &["paths", "results", "checks"])?;
    items.into_iter().map(check_item).collect()
}

fn check_item(item: Value) -> std::result::Result<PathCheck, ClientError> {
    let path = item
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let holder = match item.get("holder") {
        None | Some(Value::Null) => None,
        Some(Value::String(session)) => Some(Conflict {
            path: path.clone(),
            held_path: String::new(),
            claim: 0,
            agent: session.clone(),
            note: String::new(),
            expires_at: Default::default(),
            mode: None,
            dirty: None,
        }),
        Some(object) => {
            let mut conflict: Conflict = serde_json::from_value(object.clone())
                .map_err(|error| ClientError::Decode(error.to_string()))?;
            if conflict.path.is_empty() {
                conflict.path.clone_from(&path);
            }
            Some(conflict)
        }
    };
    // An answer this client cannot read must never count as free.
    let status = match item.get("status").and_then(Value::as_str) {
        Some("own") => CheckStatus::Own,
        Some("held") => CheckStatus::Held,
        Some("free") => CheckStatus::Free,
        other => {
            return Err(ClientError::Decode(format!(
                "a zone check for {path} has status {other:?}"
            )));
        }
    };
    Ok(PathCheck {
        path,
        status,
        holder,
        mode: serde_json::from_value(item.get("mode").cloned().unwrap_or(Value::Null))
            .map_err(|error| ClientError::Decode(error.to_string()))?,
        auto_grantable: serde_json::from_value(
            item.get("auto_grantable").cloned().unwrap_or(Value::Null),
        )
        .map_err(|error| ClientError::Decode(error.to_string()))?,
    })
}

/// [`Backend`] on a [`Transport`]. The `agent` of each call is its session.
pub struct CloudBackend<T: Transport> {
    zone_stream_allowed: bool,
    pub(crate) transport: T,
    pub(crate) session: String,
    write_idempotency_key: Option<String>,
}

impl<T: Transport> CloudBackend<T> {
    /// `session` names calls that carry no agent, such as listing claims.
    pub fn new(transport: T, session: &str) -> Self {
        Self {
            transport,
            session: session.to_string(),
            write_idempotency_key: None,
            zone_stream_allowed: true,
        }
    }

    pub(crate) fn call_cloud(&self, call: &Call) -> std::result::Result<Value, ClientError> {
        self.transport.call(call)
    }

    pub fn with_zone_stream_allowed(mut self, allowed: bool) -> Self {
        self.zone_stream_allowed = allowed;
        self
    }

    fn zone_is_free(&self, agent: &str, path: &str, budget: std::time::Duration) -> Result<bool> {
        let mut call = Call::write(
            agent,
            "POST",
            "/api/v1/zones/check".into(),
            json!({"paths":[path],"mode":"exclusive"}),
        );
        call.key = None; // check is a read, despite its POST verb.
        let ms = budget.as_millis().max(1).min(u64::MAX as u128) as u64;
        call.deadline_ms = Some(ms);
        call.attempt_timeout_ms = Some(ms);
        let rows = checks(self.call_cloud(&call)?)?;
        match rows.as_slice() {
            [row] => match row.status {
                CheckStatus::Free | CheckStatus::Own => Ok(true),
                CheckStatus::Held => Ok(false),
                CheckStatus::Unknown => Err(Error::Unavailable("zone state is unknown".into())),
            },
            _ => Err(Error::Unavailable(
                "zone check returned no unique answer".into(),
            )),
        }
    }

    fn wait_zone_stream(
        &self,
        agent: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<bool> {
        self.wait_zone_stream_with_clock(agent, path, timeout, std::time::Instant::now)
    }

    fn wait_zone_stream_with_clock(
        &self,
        agent: &str,
        path: &str,
        timeout: std::time::Duration,
        now: impl Fn() -> std::time::Instant + Sync,
    ) -> Result<bool> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;
        let deadline = now()
            .checked_add(timeout)
            .ok_or_else(|| Error::Invalid("zone wait timeout is too large".into()))?;
        if timeout.is_zero() {
            return self.zone_is_free(agent, path, timeout);
        }
        if !self.zone_stream_allowed
            || self.transport.owns_event_stream()
            || !self.transport.mail_push_v1(agent)?
        {
            if self.zone_is_free(agent, path, deadline.saturating_duration_since(now()))? {
                return Ok(true);
            }
            loop {
                let left = deadline.saturating_duration_since(now());
                if left.is_zero() {
                    return Ok(false);
                }
                std::thread::sleep(left.min(Duration::from_secs(60)));
                let left = deadline.saturating_duration_since(now());
                if left.is_zero() {
                    return Ok(false);
                }
                if self.zone_is_free(agent, path, left)? {
                    return Ok(true);
                }
            }
        }
        // Walk the JSON feed to its current visible head before subscribing. JSON reads do
        // not replace an existing stream; replay preceding this head is irrelevant to a wait.
        let mut after = 0;
        loop {
            let left = deadline.saturating_duration_since(now());
            if left.is_zero() {
                return Ok(false);
            }
            let mut call = Call::get(
                agent,
                format!("/api/v1/events?after={after}&session={}", encode(agent)),
            );
            call.deadline_ms = Some(left.as_millis().max(1).min(u64::MAX as u128) as u64);
            let value = self.call_cloud(&call)?;
            let events: Vec<lockyard_core::proto::Event> = list(value, &["events", "items"])?;
            let head = events.iter().map(|event| event.seq).max().unwrap_or(after);
            if head <= after {
                break;
            }
            after = head;
        }
        let interrupt = Arc::new(AtomicBool::new(false));
        let (done, completion) = mpsc::channel::<()>();
        let now = &now;
        std::thread::scope(|scope| {
            let stop = interrupt.clone();
            scope.spawn(move || {
                if completion
                    .recv_timeout(deadline.saturating_duration_since(now()))
                    .is_err()
                {
                    stop.store(true, Ordering::Release);
                }
            });
            let result = (|| {
                let mut stream = self.transport.event_stream_sessions(
                    agent,
                    &[agent.to_string()],
                    after,
                    interrupt.clone(),
                )?;
                let stream_stop = stream.interrupt_handle();
                let (frames, receive) = mpsc::sync_channel(1);
                let stop = interrupt.clone();
                scope.spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let next = stream.next_frame();
                        let ended = !matches!(next, Ok(Some(_)));
                        if frames.send(next).is_err() || ended {
                            break;
                        }
                    }
                });
                let result = (|| {
                    let mut ready = false;
                    loop {
                        let current = now();
                        if current >= deadline {
                            return Ok(false);
                        }
                        let next = match receive
                            .recv_timeout(deadline.saturating_duration_since(now()))
                        {
                            Ok(next) => next,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(_) => {
                                return Err(Error::Unavailable("zone event reader stopped".into()));
                            }
                        };
                        let frame = match next {
                            Ok(Some(frame)) => frame,
                            Ok(None) => {
                                return Err(Error::Unavailable(
                                    "zone event stream disconnected".into(),
                                ));
                            }
                            Err(error) => {
                                return Err(Error::Unavailable(format!(
                                    "zone event stream: {error}"
                                )));
                            }
                        };
                        if frame.event == "replaced" {
                            return Err(Error::Unavailable(
                                "zone event stream was replaced; use the local daemon".into(),
                            ));
                        }
                        if frame.event == "ready" {
                            ready = true;
                        } else if !ready {
                            continue;
                        }
                        let changed = frame.event == "ready"
                            || frame.event.starts_with("zone.")
                            || frame
                                .decode()?
                                .is_some_and(|event| event.kind.starts_with("zone."));
                        if changed
                            && self.zone_is_free(
                                agent,
                                path,
                                deadline.saturating_duration_since(now()),
                            )?
                        {
                            return Ok(true);
                        }
                    }
                })();
                interrupt.store(true, Ordering::Release);
                stream_stop.store(true, Ordering::Release);
                drop(receive);
                result
            })();
            let _ = done.send(());
            if result.is_err() && now() >= deadline {
                Ok(false)
            } else {
                result
            }
        })
    }

    fn get(&self, session: &str, path: String) -> Result<Value> {
        self.get_with_timeout(session, path, None)
    }

    fn get_with_timeout(
        &self,
        session: &str,
        path: String,
        timeout: Option<std::time::Duration>,
    ) -> Result<Value> {
        let mut call = Call::get(session, path);
        if let Some(limit) = timeout {
            let ms = u64::try_from(limit.as_millis()).unwrap_or(u64::MAX);
            if ms == 0 {
                return Err(Error::Unavailable("open-mail call deadline elapsed".into()));
            }
            call.attempt_timeout_ms = Some(ms);
        }
        Ok(self.call_cloud(&call)?)
    }

    fn post(&self, session: &str, path: String, body: &impl Serialize) -> Result<Value> {
        self.write(session, "POST", path, body)
    }

    fn zone_request_body(&self, agent: &str, request: &impl Serialize) -> Result<Value> {
        let mut body =
            serde_json::to_value(request).map_err(|error| Error::Invalid(error.to_string()))?;
        // An unknown capability (ping/protocol failure) is not a confirmed server default.
        if body.get("mode").is_none() && !self.transport.soft_zones_v1(agent).unwrap_or(false) {
            // Safe before Request::Call crosses even a 0.3.12 agent socket.
            body["mode"] = json!("exclusive");
        }
        Ok(body)
    }

    fn claim_error(&self, agent: &str, id: i64, error: Error) -> Error {
        if error.kind() != "not_found"
            && !matches!(
                &error,
                Error::Cloud {
                    status: Some(403 | 404 | 409),
                    ..
                }
            )
            && !matches!(&error, Error::Denied(_) | Error::Contended(_))
        {
            return error;
        }
        let tail = query(&[("session", Some(agent.to_string()))]);
        let lost = self
            .get_with_timeout(
                agent,
                format!("/api/v1/zones/lost{tail}"),
                Some(std::time::Duration::from_millis(500)),
            )
            .ok()
            .and_then(|value| list::<LostClaim>(value, &["lost", "claims", "items"]).ok())
            .and_then(|items| {
                items.into_iter().find(|claim| {
                    claim.claim_id == id && (claim.session.is_empty() || claim.session == agent)
                })
            });
        // A refusal alone does not prove a loss (e.g. a hold/version conflict).
        // Preserve it unless the loss feed confirms this specific session and claim.
        if lost.is_none()
            && error.kind() != "not_found"
            && !matches!(
                &error,
                Error::Cloud {
                    status: Some(404),
                    ..
                }
            )
        {
            return error;
        }
        let detail = match lost {
            Some(claim) => {
                let reason = claim.reason.as_deref().unwrap_or("expired or released");
                let takeover = matches!(
                    &error,
                    Error::Denied(_)
                        | Error::Cloud {
                            status: Some(403),
                            ..
                        }
                ) || reason == "taken"
                    || reason.starts_with("taken:");
                let action = if takeover {
                    let owner = self
                        .get_with_timeout(
                            agent,
                            "/api/v1/zones/claims".into(),
                            Some(std::time::Duration::from_millis(500)),
                        )
                        .ok()
                        .and_then(|value| list::<Claim>(value, &["claims", "items"]).ok())
                        .and_then(|claims| {
                            claims
                                .into_iter()
                                .find(|c| c.id == id && c.session != agent)
                        })
                        .map(|c| c.session)
                        .unwrap_or_else(|| "другим агентом".into());
                    format!("перехвачена {owner}")
                } else {
                    match reason {
                        "expired" | "ttl" => "истекла по ttl".into(),
                        "idle" | "idle_released" => "истекла по простою".into(),
                        _ => "потеряна".into(),
                    }
                };
                let at = claim.lost_at.map(|at| match at {
                    lockyard_core::proto::Stamp::Millis(ms) => lockyard_core::proto::rfc3339(ms),
                    lockyard_core::proto::Stamp::Text(text) => text,
                });
                let time = at
                    .as_deref()
                    .map(|at| format!(" в {}", at.get(11..16).unwrap_or(at)))
                    .unwrap_or_default();
                format!(
                    "{action}{time} ({reason}{})",
                    at.map(|at| format!(" at {at}")).unwrap_or_default()
                )
            }
            None => match &error {
                Error::Cloud { details, .. } if details.get("reason").is_some() => format!(
                    "{}{}",
                    details["reason"].as_str().unwrap_or("expired or released"),
                    details
                        .get("lost_at")
                        .map(|at| format!(" at {at}"))
                        .unwrap_or_default()
                ),
                _ => "expired or released (истекла или снята)".into(),
            },
        };
        let message = format!("claim Z-{id} is gone: {detail}; check status --lost");
        match error {
            Error::Cloud {
                code,
                status,
                details,
                ..
            } => Error::Cloud {
                code,
                status,
                details,
                message,
            },
            Error::Denied(_) => Error::Denied(message),
            Error::Contended(_) => Error::Contended(message),
            _ => Error::NotFound(message),
        }
    }

    fn item(&self, session: &str, id: &str) -> Result<Value> {
        self.get(session, format!("{ITEMS}/{}", id))
    }

    /// Tells the server how far a message got, for the sender's `lockyard msg sent`.
    ///
    /// Only ever called from a path that already writes. Reading the inbox stays a read — hooks
    /// run it on every edit, and a frozen or read-only server must not turn that into a refusal
    /// — so `delivered` is the server's own observation of what its inbox endpoint handed out.
    ///
    /// Best effort by design: a receipt is a courtesy to the sender, and a server that has not
    /// shipped the endpoint must not stop the recipient marking mail read. A receipt can never
    /// move backwards, which the contract makes the server's job.
    fn report_receipts(&self, agent: &str, ids: &[i64], status: &str) {
        for id in ids {
            let _ = self.post(
                agent,
                format!("/api/v1/messages/{id}/receipt"),
                &json!({"status": status}),
            );
        }
    }

    /// One registry operation on an item, at the version the caller read.
    fn item_step(
        &self,
        agent: &str,
        id: &str,
        operation: &str,
        body: Value,
        item: &Value,
    ) -> Result<tasks::Task> {
        task_from(&self.item_step_response(agent, id, operation, body, item)?)
    }

    /// Preserve the exact mutation response when callers need its authoritative assignment.
    fn item_step_response(
        &self,
        agent: &str,
        id: &str,
        operation: &str,
        mut body: Value,
        item: &Value,
    ) -> Result<Value> {
        body["expected_version"] = item["version"].clone();
        let route = format!("{ITEMS}/{}/{operation}", id);
        self.post(agent, route, &body)
    }

    /// Select by explicit area, then prefix. With neither, use the first area; an empty registry
    /// gets its default area on first use where the role allows.
    fn area_id(
        &self,
        agent: &str,
        wanted: Option<&str>,
        prefix: Option<&str>,
        pad: Option<u8>,
    ) -> Result<String> {
        let value = self.get(agent, AREAS.into())?;
        let areas: Vec<Value> = list(value, &["areas", "items"])?;
        let found = match wanted {
            Some(key) => areas.iter().find(|area| {
                text(area, "key").eq_ignore_ascii_case(key)
                    || text(area, "prefix").eq_ignore_ascii_case(key)
            }),
            None => match prefix {
                Some(prefix) => areas
                    .iter()
                    .find(|area| text(area, "prefix").eq_ignore_ascii_case(prefix)),
                None => areas.first(),
            },
        };
        // A prefix can configure the default area in an empty registry. In an existing registry,
        // it must select a matching area rather than silently writing into the first one.
        match (found, wanted.or(prefix.filter(|_| !areas.is_empty()))) {
            (Some(area), _) => Ok(text(area, "id").to_string()),
            (None, Some(key)) => Err(Error::NotFound(format!("no area {key:?}"))),
            (None, None) => {
                let mut body = json!({"key": DEFAULT_AREA, "name": "General"});
                if let Some(prefix) = prefix {
                    body["prefix"] = json!(prefix);
                }
                if let Some(pad) = pad {
                    body["pad"] = json!(pad);
                }
                Ok(text(&self.post(agent, AREAS.into(), &body)?, "id").to_string())
            }
        }
    }

    /// Resolve a triage area, active areas only: a GUID matches ids, otherwise an exact key, then
    /// a prefix that must match exactly one area. Never creates an area. Where the registry's
    /// matching (Guid.TryParse, OrdinalIgnoreCase) could pick a different area than ASCII
    /// matching, the selector is refused instead of guessed: the UUID sent is the only thing
    /// the server sees, so a wrong guess would move the task silently.
    fn triage_area(&self, agent: &str, selector: &str) -> Result<String> {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err(Error::Invalid(
                "--area is empty; pass an area id, key or prefix".into(),
            ));
        }
        let unsure = || {
            Error::Invalid(format!(
                "area {selector:?} cannot be matched safely; pass the hyphenated area id or the exact key"
            ))
        };
        let guid = guid_canon(selector);
        if guid.is_none()
            && (selector.contains(['{', '(']) || selector.to_ascii_lowercase().contains("0x"))
        {
            return Err(unsure());
        }
        let value = self.get(agent, AREAS.into())?;
        let areas: Vec<Value> = list(value, &["areas", "items"])?;
        let active: Vec<&Value> = areas
            .iter()
            .filter(|area| area["is_active"].as_bool().unwrap_or(true))
            .collect();
        let mut matches: Vec<&Value> = match guid {
            Some(guid) => active
                .iter()
                .copied()
                .filter(|area| guid_canon(text(area, "id")).as_deref() == Some(guid.as_str()))
                .collect(),
            None => {
                // ASCII case folding agrees with OrdinalIgnoreCase only when both sides are ASCII.
                // A non-ASCII key of the same UTF-16 length could still fold onto the selector
                // on the server, so it makes the choice unsafe.
                let width = selector.encode_utf16().count();
                let unsafe_key = active.iter().any(|area| {
                    let key = text(area, "key");
                    key != selector
                        && !(key.is_ascii() && selector.is_ascii())
                        && key.encode_utf16().count() == width
                });
                if unsafe_key {
                    return Err(unsure());
                }
                active
                    .iter()
                    .copied()
                    .filter(|area| text(area, "key").eq_ignore_ascii_case(selector))
                    .collect()
            }
        };
        if matches.is_empty() {
            if !selector.is_ascii() || active.iter().any(|area| !text(area, "prefix").is_ascii()) {
                return Err(unsure());
            }
            matches = active
                .iter()
                .copied()
                .filter(|area| {
                    let prefix = text(area, "prefix").as_bytes();
                    prefix.len() >= selector.len()
                        && prefix[..selector.len()].eq_ignore_ascii_case(selector.as_bytes())
                })
                .collect();
        }
        match matches.as_slice() {
            [] => Err(Error::NotFound(format!("no active area {selector:?}"))),
            [area] => Ok(text(area, "id").to_string()),
            _ => Err(Error::Invalid(format!(
                "area prefix {selector:?} is ambiguous; use the area id or key"
            ))),
        }
    }

    fn write(
        &self,
        session: &str,
        method: &str,
        path: String,
        body: &impl Serialize,
    ) -> Result<Value> {
        let body = serde_json::to_value(body).map_err(|error| Error::Invalid(error.to_string()))?;
        let mut call = Call::write(session, method, path, body);
        if let Some(key) = &self.write_idempotency_key {
            call.key = Some(key.clone());
        }
        let result = self.call_cloud(&call);
        let result = match result {
            Err(ClientError::OutcomeUnknown(_))
                if call.method == "POST"
                    && call.path == ITEMS
                    && call
                        .body
                        .as_ref()
                        .is_some_and(|body| body["client_key"].is_string()) =>
            {
                self.call_cloud(&call)
            }
            result => result,
        };
        Ok(result.map_err(|mut error| {
            error.explain_task_create_refusal(&call);
            error
        })?)
    }
}

/// Canonical lowercase 32-hex form of a GUID written the ways Guid.TryParse accepts most often:
/// plain hex, hyphenated, or hyphenated in braces or parentheses. Anything else is not a GUID.
fn guid_canon(value: &str) -> Option<String> {
    let value = value.trim();
    let inner = match (value.chars().next(), value.chars().last()) {
        (Some('{'), Some('}')) | (Some('('), Some(')')) if value.len() >= 2 => {
            &value[1..value.len() - 1]
        }
        _ => value,
    };
    let hex = match inner.len() {
        32 => inner.to_string(),
        36 if [8, 13, 18, 23].iter().all(|&i| inner.as_bytes()[i] == b'-') => {
            inner.replace('-', "")
        }
        _ => return None,
    };
    // A braced form is only valid with hyphens, like the server's "B" and "P" formats.
    if inner.len() == 32 && inner.len() != value.len() {
        return None;
    }
    (hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| hex.to_lowercase())
}

fn query(pairs: &[(&str, Option<String>)]) -> String {
    let mut text = String::new();
    for (name, value) in pairs {
        if let Some(value) = value {
            text.push(if text.is_empty() { '?' } else { '&' });
            text.push_str(name);
            text.push('=');
            text.push_str(&encode(value));
        }
    }
    text
}

fn count(value: &Value, names: &[&str], fallback: usize) -> usize {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_u64))
        .and_then(|found| usize::try_from(found).ok())
        .unwrap_or(fallback)
}

pub(crate) fn inbox_page(value: Value) -> std::result::Result<InboxPage, ClientError> {
    if value.is_array() {
        return Ok(InboxPage {
            messages: list(value, &[])?,
            skipped: 0,
        });
    }
    let skipped = value.get("skipped").and_then(Value::as_i64).unwrap_or(0);
    Ok(InboxPage {
        messages: list(value, &["messages", "items"])?,
        skipped,
    })
}

fn selected_inbox_page(mut value: Value, all: bool) -> std::result::Result<InboxPage, ClientError> {
    // Keep default reads new-only even while talking to a server that still
    // returns seen mail. Explicit all/open reads preserve the complete selection.
    if !all {
        let messages = if value.is_array() {
            value.as_array_mut()
        } else if value.get("messages").is_some() {
            value.get_mut("messages").and_then(Value::as_array_mut)
        } else {
            value.get_mut("items").and_then(Value::as_array_mut)
        };
        if let Some(messages) = messages {
            messages.retain(|message| {
                !matches!(message["reader_state"].as_str(), Some("seen" | "handled"))
                    && ["seen_at", "acked_at", "replied_at"]
                        .iter()
                        .all(|field| message[*field].is_null())
            });
        }
    }
    inbox_page(value)
}

/// Exact new-mail count only when all retained rows can be classified.
pub(crate) fn new_mail_count(value: Value) -> Result<i64> {
    let page = selected_inbox_page(value, false)?;
    // Server 2ca693e skips rows before projecting reader marks, including seen mail.
    // Those omitted rows cannot be classified or paged back through this endpoint.
    if page.skipped > 0 {
        return Err(Error::Unavailable(UNREAD_TRUNCATED.into()));
    }
    Ok(i64::try_from(page.messages.len()).unwrap_or(i64::MAX))
}

/// Reads one line of `msg sent` from the server.
///
/// An unknown status is reported as it came rather than being rounded down to `sent`: a sender
/// deciding whether to nudge is worse off with a confident wrong answer than with a strange one.
fn receipt_from(value: &Value) -> bus::Receipt {
    let stamp = |name: &str| value[name].as_i64().or_else(|| millis(value, name));
    let status = value.get("status").and_then(Value::as_str).unwrap_or("");
    let reply_to = value
        .get("reply_to")
        .or_else(|| value.get("in_reply_to"))
        .and_then(Value::as_i64);
    bus::Receipt {
        id: value.get("id").and_then(Value::as_i64).unwrap_or_default(),
        to: value
            .get("to")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        body: if status == "failed" {
            String::new()
        } else {
            text(value, "body").to_owned()
        },
        created_at: stamp("created_at").unwrap_or_default(),
        reply_to,
        status: match status {
            "replied" => bus::Delivery::Replied,
            "read" => bus::Delivery::Read,
            "delivered" => bus::Delivery::Delivered,
            "failed" => bus::Delivery::Failed,
            _ => bus::Delivery::Sent,
        },
        delivered_at: stamp("delivered_at"),
        read_at: stamp("read_at"),
        replied_at: stamp("replied_at"),
    }
}

fn message(value: Value) -> Result<Message> {
    if value.get("queued").and_then(Value::as_bool) == Some(true) && value.get("id").is_none() {
        return Ok(Message {
            urgent: false,
            replied_at: None,
            id: 0,
            thread_id: None,
            reply_to: None,
            kind: None,
            from: String::new(),
            from_alias: None,
            address: None,
            role: None,
            from_client: None,
            to: String::new(),
            zone: None,
            re: None,
            status: None,
            needs: None,
            body: String::new(),
            key: value.get("key").and_then(Value::as_str).map(str::to_string),
            expires_at: None,
            created_at: Default::default(),
            deduplicated: false,
            queued: true,
        });
    }
    Ok(one(value, "message")?)
}

fn canonical_sdk_task(raw: &str) -> Result<String> {
    lockyard_compat::LegacyCompatibilityV1::task_id(
        &json!(raw),
        lockyard_compat::TaskDomain::Registry,
        lockyard_compat::Source::Sdk,
        2,
    )
    .map_err(|code| Error::Cloud {
        code: code.clone(),
        status: None,
        details: Value::Null,
        message: code,
    })
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn millis(value: &Value, key: &str) -> Option<i64> {
    parse_rfc3339(value.get(key)?.as_str()?)
}

fn validate_registry_text(field: &str, value: &str) -> Result<()> {
    if value.len() > MAX_REGISTRY_TEXT_BYTES {
        return Err(Error::Invalid(format!(
            "registry {field} exceeds {MAX_REGISTRY_TEXT_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

fn validate_title(value: &str) -> Result<()> {
    if value.chars().count() > 200 {
        return Err(Error::Invalid(
            "registry title exceeds 200 characters".into(),
        ));
    }
    Ok(())
}

/// `<7-64 hex>:<relative/path>`. A bare object id is not a file in that commit.
fn commit_names_file(value: &str) -> bool {
    let Some((revision, path)) = value.split_once(':') else {
        return false;
    };
    if !(7..=64).contains(&revision.len()) || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') || path.contains('\\') {
        return false;
    }
    path.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn require_commit_file(target: &str, value: &str) -> Result<()> {
    if target != "ci_passed" && !commit_names_file(value) {
        return Err(Error::Invalid(
            "commit evidence must name a file in git as <rev>:<path>".into(),
        ));
    }
    if commit_names_file(value)
        && let Ok(cwd) = std::env::current_dir()
    {
        refuse_if_file_missing(&cwd, value)?;
    }
    Ok(())
}

/// When `revision` is an object in the git repository that contains `repo`, the path must be in
/// that tree. A revision this repository does not have is not judged: the server has no checkout,
/// and the proof may name another repository.
pub(crate) fn refuse_if_file_missing(repo: &std::path::Path, value: &str) -> Result<()> {
    let Some((revision, path)) = value.split_once(':') else {
        return Ok(());
    };
    let object = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &format!("{revision}^{{commit}}")])
        .output();
    let Ok(object) = object else {
        return Ok(());
    };
    if !object.status.success() {
        return Ok(());
    }
    let file = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &format!("{revision}:{path}")])
        .status();
    match file {
        Ok(status) if status.success() => Ok(()),
        Ok(_) => Err(Error::Invalid(format!(
            "file {path} is not in revision {revision}"
        ))),
        Err(_) => Ok(()),
    }
}

fn validate_evidence(values: &[String]) -> Result<()> {
    if values.len() > MAX_EVIDENCE_COUNT {
        return Err(Error::Invalid(format!(
            "registry items allow at most {MAX_EVIDENCE_COUNT} evidence records"
        )));
    }
    for value in values {
        if value.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::Invalid(format!(
                "registry evidence value exceeds {MAX_EVIDENCE_BYTES} UTF-8 bytes"
            )));
        }
    }
    Ok(())
}

fn validate_registry_import(dump: &Value) -> Result<()> {
    let Some(items) = dump.get("items").and_then(Value::as_array) else {
        return Ok(());
    };
    for item in items {
        if let Some(title) = item.get("title").and_then(Value::as_str) {
            validate_title(title)?;
        }
        for field in ["body", "acceptance", "legacy_raw"] {
            if let Some(value) = item.get(field).and_then(Value::as_str) {
                validate_registry_text(field, value)?;
            }
        }
        if let Some(evidence) = item.get("evidence").and_then(Value::as_array) {
            if evidence.len() > MAX_EVIDENCE_COUNT {
                return Err(Error::Invalid(format!(
                    "registry items allow at most {MAX_EVIDENCE_COUNT} evidence records"
                )));
            }
            let values: Vec<String> = evidence
                .iter()
                .filter_map(|entry| entry.get("value").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            validate_evidence(&values)?;
        }
    }
    Ok(())
}

/// The session inside an identity `token:<id>:<session>`.
fn session_of(identity: &str) -> String {
    identity
        .splitn(3, ':')
        .nth(2)
        .unwrap_or(identity)
        .to_string()
}

fn reason_or<'a>(reason: &'a str, fallback: &'a str) -> &'a str {
    if reason.trim().is_empty() {
        fallback
    } else {
        reason
    }
}

/// Evidence for a code or CI target. A deploy target also needs a probe, which `task` does not record.
fn evidence_body(agent: &str, target: &str, value: &str, now: i64) -> Value {
    json!({
        "kind": if target == "ci_passed" { "ci_run" } else { "commit" },
        "environment": "local",
        "value": value,
        "observed_at": rfc3339(now),
        "verifier": agent,
    })
}

fn task_status(status: &str) -> tasks::Status {
    match status {
        "active" => tasks::Status::Claimed,
        "review" => tasks::Status::Review,
        "done" => tasks::Status::Accepted,
        "cancelled" => tasks::Status::Cancelled,
        _ => tasks::Status::Open,
    }
}

fn priority_rank(priority: Option<&str>) -> u8 {
    match priority.unwrap_or_default().to_ascii_uppercase().as_str() {
        "P0" => 0,
        "P1" => 1,
        "P2" => 2,
        "P3" => 3,
        _ => 4,
    }
}

fn stage_rank(stage: Option<&str>) -> u8 {
    match stage.unwrap_or_default() {
        "ready" => 0,
        "intake" => 1,
        "active" => 2,
        "blocked" => 3,
        "review" => 4,
        _ => 5,
    }
}

/// A backlog item in the shape of a task. Open covers `ready`, `blocked` and `intake`.
pub(crate) fn task_from(item: &Value) -> Result<tasks::Task> {
    let id = text(item, "id");
    lockyard_core::task_id::TaskId::parse(id)?;
    let assignment = item.get("assignment").filter(|found| found.is_object());
    let evidence: Vec<&str> = item
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|entry| text(entry, "value"))
        .collect();
    Ok(tasks::Task {
        id: lockyard_core::task_id::TaskId::parse(id)?,
        title: text(item, "title").to_string(),
        body: text(item, "body").to_string(),
        status: task_status(text(item, "status")),
        raw_status: Some(text(item, "status").to_string()),
        author: session_of(text(item, "created_by")),
        assignee: assignment.map(|found| session_of(text(found, "executor"))),
        lease_until: assignment.and_then(|found| millis(found, "lease_expires_at")),
        evidence: (!evidence.is_empty()).then(|| evidence.join(", ")),
        created_at: millis(item, "created_at").unwrap_or(0),
        updated_at: millis(item, "updated_at").unwrap_or(0),
        priority: item
            .get("priority")
            .and_then(Value::as_str)
            .map(str::to_string),
        acceptance: item
            .get("acceptance")
            .and_then(Value::as_str)
            .map(str::to_string),
        stage: item
            .get("status")
            .and_then(Value::as_str)
            .map(str::to_string),
        target: item
            .get("target")
            .and_then(Value::as_str)
            .map(str::to_string),
        links: item
            .get("links")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        registry_evidence: item
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        paths: item
            .get("paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    })
}

impl<T: Transport> Backend for CloudBackend<T> {
    fn registry_auto_area(&self) -> Result<bool> {
        Ok(self.transport.registry_auto_area(&self.session)?)
    }
    fn mail_open_v1(&self, timeout: std::time::Duration) -> Result<bool> {
        Ok(self.transport.mail_open_v1_within(&self.session, timeout)?)
    }
    fn peek_open_inbox_within(
        &self,
        agent: &str,
        limit: usize,
        _now: i64,
        timeout: std::time::Duration,
    ) -> Result<InboxPage> {
        let tail = query(&[
            ("open", Some("true".to_string())),
            (
                "limit",
                (limit > 0).then(|| limit.min(INBOX_PAGE).to_string()),
            ),
        ]);
        Ok(inbox_page(self.get_with_timeout(
            agent,
            format!("/api/v1/bus/inbox{tail}"),
            Some(timeout),
        )?)?)
    }
    fn status_read(
        &self,
        session: &str,
        now: i64,
        budget: std::time::Duration,
    ) -> Result<lockyard_core::StatusRead> {
        crate::status::read(self, session, now, budget)
    }
    fn set_write_idempotency_key(&mut self, key: Option<String>) {
        self.write_idempotency_key = key;
    }

    fn registry_search(&self, query: &Value) -> Result<Value> {
        crate::registry::search(self, query, false)
    }
    fn registry_ready(&self, query: &Value) -> Result<Value> {
        crate::registry::search(self, query, true)
    }

    fn registry_item_by_id(&self, id: &str) -> Result<Value> {
        crate::registry::item_by_id(self, id, false)
    }
    fn registry_blockers_by_id(&self, id: &str) -> Result<Value> {
        crate::registry::item_by_id(self, id, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn registry_link_by_id(
        &mut self,
        agent: &str,
        id: &str,
        to: &str,
        kind: &str,
        version: i64,
        key: &str,
    ) -> Result<Value> {
        crate::registry::link_by_id(self, agent, id, to, kind, version, key)
    }

    fn is_cloud(&self) -> bool {
        true
    }

    fn touch_agent(&mut self, _agent: &str, _now: i64) -> Result<()> {
        // Presence is reported through heartbeats. A read must not write in cloud mode.
        Ok(())
    }

    fn agents(&self) -> Result<Vec<AgentSeen>> {
        Ok(self
            .presence(WHO_WINDOW_SECONDS, 0)?
            .into_iter()
            .map(|entry| AgentSeen {
                id: entry.session,
                first_seen: entry.last_seen.clone(),
                last_seen: entry.last_seen,
            })
            .collect())
    }

    fn claim(&mut self, agent: &str, request: &ClaimRequest, now: i64) -> Result<Claim> {
        self.claim_with_creation_status(agent, request, now)
            .map(|(claim, _)| claim)
    }

    fn soft_zones_v1(&self) -> Result<bool> {
        Ok(self.transport.soft_zones_v1(&self.session)?)
    }

    fn claim_with_creation_status(
        &mut self,
        agent: &str,
        request: &ClaimRequest,
        _now: i64,
    ) -> Result<(Claim, Option<bool>)> {
        let body = self.zone_request_body(agent, request)?;
        let mut call = Call::write(agent, "POST", "/api/v1/zones/claims".into(), body);
        if let Some(key) = &self.write_idempotency_key {
            call.key = Some(key.clone());
        }
        // With a short wait the server holds the answer until the zone frees up.
        call.long_poll = request
            .queue_wait_seconds
            .is_some_and(|seconds| seconds > 0);
        let reply = self.call_cloud(&call)?;
        // Only the POST outcome is evidence. Stored meta and GET snapshots cannot
        // distinguish concurrent same-session reuse from a newly created lease.
        let created = reply.get("created").and_then(Value::as_bool);
        Ok((one(reply, "claim")?, created))
    }

    fn renew(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &RenewRequest,
        now: i64,
    ) -> Result<usize> {
        if !(1..=240).contains(&request.ttl_minutes) {
            return Err(Error::Invalid("ttl must be 1 to 240 minutes".into()));
        }
        let owned = if request.fence.is_none() || id.is_none() {
            self.claims(
                &ClaimQuery {
                    session: Some(agent.to_string()),
                    path: None,
                },
                now,
            )?
            .into_iter()
            .filter(|claim| claim.session == agent)
            .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let ids = match id {
            Some(id) => vec![id],
            None => owned.iter().map(|claim| claim.id).collect(),
        };
        for id in &ids {
            let mut request = request.clone();
            if request.fence.is_none() {
                request.fence = Some(
                    owned
                        .iter()
                        .find(|claim| claim.id == *id)
                        .map(|claim| claim.fence)
                        .ok_or_else(|| {
                            self.claim_error(
                                agent,
                                *id,
                                Error::NotFound("claim is not yours or no longer active".into()),
                            )
                        })?,
                );
            }
            self.post(agent, format!("/api/v1/zones/claims/{id}/renew"), &request)
                .map_err(|error| self.claim_error(agent, *id, error))?;
        }
        Ok(ids.len())
    }

    fn release(
        &mut self,
        agent: &str,
        id: Option<i64>,
        request: &ReleaseRequest,
        _now: i64,
    ) -> Result<usize> {
        match id {
            Some(id) => {
                let value = self
                    .write(
                        agent,
                        "DELETE",
                        format!("/api/v1/zones/claims/{id}"),
                        request,
                    )
                    .map_err(|error| self.claim_error(agent, id, error))?;
                Ok(count(&value, &["released", "count"], 1))
            }
            None => {
                if request.fence.is_some() {
                    let claims = self.claims(
                        &ClaimQuery {
                            session: Some(agent.to_string()),
                            ..ClaimQuery::default()
                        },
                        _now,
                    )?;
                    if claims.len() != 1 {
                        return Err(Error::Invalid(
                            "a release fence requires exactly one live claim".into(),
                        ));
                    }
                }
                let route = format!(
                    "/api/v1/zones/claims{}",
                    query(&[("session", Some(agent.to_string()))])
                );
                let value = self.write(agent, "DELETE", route, request)?;
                Ok(count(&value, &["released", "count"], 0))
            }
        }
    }

    fn claims(&self, filter: &ClaimQuery, _now: i64) -> Result<Vec<Claim>> {
        let tail = query(&[
            ("session", filter.session.clone()),
            ("path", filter.path.clone()),
        ]);
        let value = self.get(&self.session, format!("/api/v1/zones/claims{tail}"))?;
        Ok(list(value, &["claims", "items"])?)
    }

    fn check(
        &self,
        agent: &str,
        paths: &[String],
        fence: Option<i64>,
        _now: i64,
    ) -> Result<Vec<PathCheck>> {
        if fence.is_none()
            && let Some(answer) = self.transport.fast_check(agent, paths)
        {
            return Ok(answer?);
        }
        let mut call = Call {
            session: agent.to_string(),
            method: "POST".into(),
            path: "/api/v1/zones/check".into(),
            body: Some(json!({"paths": paths})),
            ..Call::default()
        };
        if let (Some(fence), Some(body)) = (fence, call.body.as_mut()) {
            body["fence"] = json!(fence);
        }
        Ok(checks(self.call_cloud(&call)?)?)
    }

    fn queue_add(&mut self, agent: &str, request: &QueueRequest) -> Result<QueueEntry> {
        let body = self.zone_request_body(agent, request)?;
        let value = self.post(agent, "/api/v1/zones/queue".into(), &body)?;
        Ok(one(value, "entry")?)
    }

    fn queue_list(&self, agent: &str) -> Result<Vec<QueueEntry>> {
        let value = self.get(agent, "/api/v1/zones/queue".into())?;
        Ok(list(value, &["queue", "entries", "items"])?)
    }

    fn queue_cancel(&mut self, agent: &str, id: i64) -> Result<()> {
        self.write(
            agent,
            "DELETE",
            format!("/api/v1/zones/queue/{id}"),
            &json!({}),
        )?;
        Ok(())
    }

    fn zone_request(&mut self, agent: &str, request: &AccessRequest) -> Result<AccessRecord> {
        let value = self.post(agent, "/api/v1/zones/requests".into(), request)?;
        Ok(one(value, "request")?)
    }

    fn zone_requests(&self, agent: &str) -> Result<Vec<AccessRecord>> {
        self.zone_requests_within(agent, std::time::Duration::from_secs(40))
    }

    fn zone_requests_within(
        &self,
        agent: &str,
        timeout: std::time::Duration,
    ) -> Result<Vec<AccessRecord>> {
        let value = self.get_with_timeout(agent, "/api/v1/zones/requests".into(), Some(timeout))?;
        Ok(list(value, &["requests", "items"])?)
    }

    fn zone_answer(&mut self, agent: &str, id: i64, answer: &AccessAnswer) -> Result<AccessRecord> {
        let value = self.post(agent, format!("/api/v1/zones/requests/{id}/answer"), answer)?;
        Ok(one(value, "request")?)
    }

    fn partial_zone(
        &mut self,
        agent: &str,
        id: i64,
        operation: &str,
        body: &Value,
    ) -> Result<Value> {
        if !matches!(operation, "narrow" | "handover" | "takeover" | "release") {
            return Err(Error::Invalid("unsupported partial zone mutation".into()));
        }
        let (method, path) = if operation == "release" {
            ("DELETE", format!("/api/v1/zones/claims/{id}"))
        } else {
            ("POST", format!("/api/v1/zones/claims/{id}/{operation}"))
        };
        self.write(agent, method, path, body)
            .map_err(|error| self.claim_error(agent, id, error))
    }

    fn handover(&mut self, agent: &str, id: i64, to: &str, fence: Option<i64>) -> Result<Value> {
        let mut body = json!({"to": to});
        if let Some(fence) = fence {
            body["fence"] = json!(fence);
        }
        self.post(agent, format!("/api/v1/zones/claims/{id}/handover"), &body)
    }

    fn handover_accept(&mut self, agent: &str, id: i64) -> Result<Claim> {
        let value = self.post(
            agent,
            format!("/api/v1/zones/claims/{id}/accept"),
            &json!({}),
        )?;
        Ok(one(value, "claim")?)
    }

    fn takeover(&mut self, agent: &str, id: i64, reason: &str) -> Result<Claim> {
        if reason.trim().is_empty() {
            return Err(Error::Invalid("a takeover needs a reason".into()));
        }
        let value = self.post(
            agent,
            format!("/api/v1/zones/claims/{id}/takeover"),
            &json!({"reason": reason}),
        )?;
        Ok(one(value, "claim")?)
    }

    fn narrow(
        &mut self,
        agent: &str,
        id: i64,
        paths: &[String],
        fence: Option<i64>,
    ) -> Result<Claim> {
        let mut body = json!({"paths": paths});
        if let Some(fence) = fence {
            body["fence"] = json!(fence);
        }
        let value = self.post(agent, format!("/api/v1/zones/claims/{id}/narrow"), &body)?;
        Ok(one(value, "claim")?)
    }

    fn add_path(&mut self, agent: &str, id: i64, path: &str, fence: Option<i64>) -> Result<Claim> {
        let mut body = json!({"path": path});
        if let Some(fence) = fence {
            body["fence"] = json!(fence);
        }
        let value = self.post(agent, format!("/api/v1/zones/claims/{id}/add-path"), &body)?;
        if value.get("queued") == Some(&Value::Bool(true)) {
            let queue = value
                .get("priority_of")
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    Error::Unavailable(format!(
                        "add-path {path} queued without an id; inspect Z-{id} before retrying"
                    ))
                })?;
            if let Err(error) = self.queue_cancel(agent, queue) {
                if error.kind() == "not_found"
                    || matches!(
                        error,
                        Error::Cloud {
                            status: Some(404),
                            ..
                        }
                    )
                {
                    return Err(Error::Cloud {
                        code: "add_path_queue_consumed".into(),
                        status: Some(404),
                        details: json!({"queue_id":queue,"claim_id":id,"path":path}),
                        message: format!(
                            "Q-{queue} consumed before cancellation; reconcile Z-{id}"
                        ),
                    });
                }
                return Err(Error::Unavailable(format!(
                    "add-path {path} queued as Q-{queue}; cancellation unconfirmed: {error}; inspect queue before retrying"
                )));
            }
            return Err(Error::Contended(format!(
                "add-path {path} queued as Q-{queue}; queue cancelled; path not added"
            )));
        }
        Ok(one(value, "claim")?)
    }

    fn activity(&mut self, agent: &str, id: i64, request: &ActivityRequest) -> Result<()> {
        self.post(
            agent,
            format!("/api/v1/zones/claims/{id}/activity"),
            request,
        )?;
        Ok(())
    }

    fn dirty_report(&mut self, agent: &str, paths: &[DirtyPath]) -> Result<()> {
        self.post(
            agent,
            "/api/v1/zones/dirty".into(),
            &json!({"paths": paths}),
        )?;
        Ok(())
    }

    fn dirty_list(&self, agent: &str, path: Option<&str>) -> Result<Vec<DirtyPath>> {
        let tail = query(&[("path", path.map(str::to_string))]);
        let value = self.get(agent, format!("/api/v1/zones/dirty{tail}"))?;
        Ok(list(value, &["paths", "dirty", "items"])?)
    }

    fn dirty_disown(&mut self, agent: &str, paths: &[String]) -> Result<()> {
        self.post(
            agent,
            "/api/v1/zones/dirty/disown".into(),
            &json!({"paths": paths}),
        )?;
        Ok(())
    }

    fn dirty_adopt(&mut self, agent: &str, paths: &[String], reason: &str) -> Result<()> {
        self.post(
            agent,
            "/api/v1/zones/dirty/adopt".into(),
            &json!({"paths": paths, "reason": reason}),
        )?;
        Ok(())
    }

    fn lost_within(&self, agent: &str, budget: std::time::Duration) -> Result<Vec<LostClaim>> {
        let tail = query(&[("session", Some(agent.to_string()))]);
        let value =
            self.get_with_timeout(agent, format!("/api/v1/zones/lost{tail}"), Some(budget))?;
        Ok(list(value, &["lost", "claims", "items"])?)
    }
    fn lost(&self, agent: &str) -> Result<Vec<LostClaim>> {
        let tail = query(&[("session", Some(agent.to_string()))]);
        let value = self.get(agent, format!("/api/v1/zones/lost{tail}"))?;
        Ok(list(value, &["lost", "claims", "items"])?)
    }

    fn catalog(&self) -> Result<Value> {
        self.get(&self.session, "/api/v1/zones/catalog".into())
    }

    fn catalog_expand(&self, names: &[String]) -> Result<Vec<String>> {
        Ok(self.transport.catalog_expand(
            &Call::get(&self.session, "/api/v1/zones/catalog".into()),
            names,
        )?)
    }
    fn catalog_put(
        &mut self,
        agent: &str,
        catalog: &Value,
        expected_revision: u64,
        key: &str,
    ) -> Result<Value> {
        let plaintext = lockyard_core::catalog::ZoneCatalogV1::from_json(&catalog.to_string())
            .map_err(|e| Error::Cloud {
                code: e.code().into(),
                status: None,
                details: Value::Null,
                message: e.to_string(),
            })?;
        let mut call = Call::write(
            agent,
            "POST",
            "/api/v1/zones/catalog".into(),
            json!({"catalog":plaintext,"expected_revision":expected_revision}),
        );
        call.key = Some(key.into());
        Ok(self.call_cloud(&call)?)
    }
    fn cloud_protocol(&self) -> Result<Value> {
        self.get(&self.session, "/api/v1/protocol".into())
    }
    fn cloud_drain(&mut self, agent: &str, request: &Value, key: &str) -> Result<Value> {
        let mut call = Call::write(agent, "POST", "/api/v1/admin/drain".into(), request.clone());
        call.key = Some(key.into());
        Ok(self.call_cloud(&call)?)
    }
    fn cloud_drain_status(&self, id: &str) -> Result<Value> {
        self.get(&self.session, format!("/api/v1/admin/drain/{}", encode(id)))
    }

    fn send(&mut self, agent: &str, request: &SendRequest, _now: i64) -> Result<Message> {
        let mut request = request.clone();
        if lockyard_core::proto::is_mail_address(&request.to) || request.urgent {
            let push = self.transport.mail_push_v1(agent)?;
            request.to = lockyard_core::proto::mail_address(&request.to, push)?;
            if request.urgent && !push {
                return Err(Error::Invalid(
                    "сервер не поддерживает urgent: требуется mail_push_v1".into(),
                ));
            }
        }
        request.kind.get_or_insert_with(|| DEFAULT_KIND.to_string());
        message(self.post(agent, "/api/v1/bus/messages".into(), &request)?)
    }

    fn reply(&mut self, agent: &str, id: i64, body: &str, _now: i64) -> Result<Message> {
        message(self.post(
            agent,
            format!("/api/v1/bus/messages/{id}/reply"),
            &json!({"body": body}),
        )?)
    }

    fn reply_with_client(
        &mut self,
        agent: &str,
        id: i64,
        body: &str,
        client: &str,
        _now: i64,
    ) -> Result<Message> {
        message(self.post(
            agent,
            format!("/api/v1/bus/messages/{id}/reply"),
            &json!({"body":body,"from_client":client}),
        )?)
    }

    fn ack(&mut self, agent: &str, id: i64) -> Result<()> {
        self.post(agent, format!("/api/v1/bus/messages/{id}/ack"), &json!({}))?;
        Ok(())
    }

    fn validate_handled(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() || ids.iter().any(|id| *id <= 0) {
            return Err(Error::Invalid(
                "handled message ids must be positive integers".into(),
            ));
        }
        let protocol = self.cloud_protocol()?;
        if !protocol["capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|cap| cap == "mail_handled_v1"))
        {
            return Err(Error::Invalid("marking mail handled requires server capability mail_handled_v1; no read receipts were changed".into()));
        }
        Ok(())
    }

    fn mark_handled(&mut self, agent: &str, ids: &[i64]) -> Result<usize> {
        self.validate_handled(ids)?;
        let reply = self.post(
            agent,
            "/api/v1/bus/inbox/handled".into(),
            &json!({"ids": ids}),
        )?;
        Ok(count(&reply, &["handled", "count"], 0))
    }

    fn wait_zone_free(
        &self,
        agent: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<bool> {
        if std::time::Instant::now().checked_add(timeout).is_none() {
            return Err(Error::Invalid("zone wait timeout is too large".into()));
        }
        if let Some(result) = self.transport.wait_zone_free(agent, path, timeout) {
            return Ok(result?);
        }
        self.wait_zone_stream(agent, path, timeout)
    }

    fn task_by_client_key(&self, key: &str) -> Result<Option<tasks::Task>> {
        let reply = self.get(
            &self.session,
            format!("{ITEMS}{}", query(&[("client_key", Some(key.to_owned()))])),
        )?;
        let items: Vec<Value> = list(reply, &["items", "tasks"])?;
        let matching: Vec<_> = items
            .iter()
            .filter(|item| item["client_key"].as_str() == Some(key))
            .collect();
        match matching.as_slice() {
            [item] => task_from(item).map(Some),
            _ => Ok(None),
        }
    }

    fn inbox(&mut self, agent: &str, filter: InboxQuery, now: i64) -> Result<InboxPage> {
        self.peek_inbox(agent, filter, now)
    }

    fn peek_inbox(&self, agent: &str, filter: InboxQuery, _now: i64) -> Result<InboxPage> {
        let tail = query(&[
            ("all", filter.all.then(|| "true".to_string())),
            (
                "limit",
                (filter.limit > 0).then(|| filter.limit.min(INBOX_PAGE).to_string()),
            ),
        ]);
        Ok(selected_inbox_page(
            self.get(agent, format!("/api/v1/bus/inbox{tail}"))?,
            filter.all,
        )?)
    }

    fn peek_inbox_within(
        &self,
        agent: &str,
        filter: InboxQuery,
        _now: i64,
        timeout: std::time::Duration,
    ) -> Result<InboxPage> {
        let tail = query(&[
            ("all", filter.all.then(|| "true".to_string())),
            (
                "limit",
                (filter.limit > 0).then(|| filter.limit.min(INBOX_PAGE).to_string()),
            ),
        ]);
        Ok(selected_inbox_page(
            self.get_with_timeout(agent, format!("/api/v1/bus/inbox{tail}"), Some(timeout))?,
            filter.all,
        )?)
    }

    fn unread(&self, agent: &str) -> Result<i64> {
        if let Some(answer) = self.transport.fast_unread(agent) {
            return answer?.ok_or_else(|| Error::Unavailable("unread count unknown".into()));
        }
        new_mail_count(self.get(agent, "/api/v1/bus/inbox".into())?)
    }

    fn inbox_seen(&mut self, agent: &str, ids: &[i64], _now: i64) -> Result<usize> {
        let value = self.post(agent, "/api/v1/bus/inbox/seen".into(), &json!({"ids": ids}))?;
        self.report_receipts(agent, ids, "read");
        if let Some(marked) = value.get("seen").and_then(Value::as_array) {
            return Ok(marked.len());
        }
        Ok(count(&value, &["seen", "marked", "count"], ids.len()))
    }

    /// The protocol ties a delivery claim to the call, not to a named channel, so `channel` stays local.
    fn inbox_claim(
        &mut self,
        agent: &str,
        _channel: &str,
        ids: &[i64],
        lease_seconds: i64,
        _now: i64,
    ) -> Result<Vec<i64>> {
        let body = json!({"ids": ids, "lease_seconds": lease_seconds});
        let value = self.post(agent, "/api/v1/bus/inbox/claim".into(), &body)?;
        Ok(claimed_ids(value, ids)?)
    }

    fn thread(&self, agent: &str, id: i64) -> Result<Vec<Message>> {
        let value = self.get(agent, format!("/api/v1/bus/threads/{id}"))?;
        Ok(list(value, &["messages", "items"])?)
    }

    fn overdue(&self, agent: &str) -> Result<Vec<Message>> {
        let value = self.get(agent, "/api/v1/bus/overdue".into())?;
        Ok(list(value, &["messages", "items"])?)
    }

    fn undelivered(&self, agent: &str, older_than_seconds: i64) -> Result<Vec<Undelivered>> {
        let tail = query(&[("older_than_seconds", Some(older_than_seconds.to_string()))]);
        let value = self.get(agent, format!("/api/v1/bus/undelivered{tail}"))?;
        Ok(list(value, &["messages", "undelivered", "items"])?)
    }

    fn sent(&self, agent: &str, limit: usize) -> Result<Vec<bus::Receipt>> {
        let tail = query(&[("limit", (limit > 0).then(|| limit.to_string()))]);
        let value = self.get(agent, format!("/api/v1/bus/sent{tail}"))?;
        let items = value
            .get("messages")
            .or_else(|| value.get("items"))
            .unwrap_or(&value);
        let empty = Vec::new();
        Ok(items
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(receipt_from)
            .collect())
    }

    fn sent_within(
        &self,
        agent: &str,
        limit: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<bus::Receipt>> {
        let tail = query(&[("limit", (limit > 0).then(|| limit.to_string()))]);
        let value =
            self.get_with_timeout(agent, format!("/api/v1/bus/sent{tail}"), Some(timeout))?;
        let items = value
            .get("messages")
            .or_else(|| value.get("items"))
            .unwrap_or(&value);
        let empty = Vec::new();
        Ok(items
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(receipt_from)
            .collect())
    }

    fn tasks(
        &self,
        status: Option<tasks::Status>,
        include_final: bool,
    ) -> Result<Vec<tasks::Task>> {
        let mut found = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let tail = query(&[
                ("limit", Some(ITEM_PAGE.to_string())),
                ("cursor", cursor.clone()),
            ]);
            let page = self.get(&self.session, format!("{ITEMS}{tail}"))?;
            let items = page.get("items").and_then(Value::as_array);
            for item in items.into_iter().flatten() {
                found.push(task_from(item)?);
            }
            match page.get("cursor").and_then(Value::as_str) {
                Some(next) => cursor = Some(next.to_string()),
                None => break,
            }
        }
        found.retain(|task| match status {
            Some(wanted) => task.status == wanted,
            None => include_final || !task.status.is_final(),
        });
        Ok(found)
    }

    fn assigned_tasks(&self, session: &str) -> Result<Vec<tasks::Task>> {
        let mut found = Vec::new();
        // Claiming creates an active assignment; submitting for review preserves it. The server
        // releases the assignment on every other transition, including blocked, so those states
        // cannot contribute to status. Keep each cursor scoped to its server-side status filter.
        for status in ["active", "review"] {
            let mut cursor: Option<String> = None;
            loop {
                let tail = query(&[
                    ("status", Some(status.to_string())),
                    ("limit", Some(ITEM_PAGE.to_string())),
                    ("cursor", cursor.clone()),
                ]);
                let page = self.get(&self.session, format!("{ITEMS}{tail}"))?;
                let items = page.get("items").and_then(Value::as_array);
                for item in items.into_iter().flatten() {
                    let task = task_from(item)?;
                    if task.assignee.as_deref() == Some(session) {
                        found.push(task);
                    }
                }
                match page.get("cursor").and_then(Value::as_str) {
                    Some(next) => cursor = Some(next.to_string()),
                    None => break,
                }
            }
        }
        Ok(found)
    }

    fn ready_tasks(&self, area: Option<&str>) -> Result<Vec<tasks::Task>> {
        let tail = query(&[
            ("area", area.map(str::to_string)),
            ("limit", Some("100".into())),
        ]);
        let value = self.get(&self.session, format!("/api/v1/registry/ready{tail}"))?;
        let rows: Vec<Value> = list(value, &["items", "tasks"])?;
        let mut found: Vec<tasks::Task> = rows.iter().map(task_from).collect::<Result<_>>()?;
        found.sort_by(|a, b| {
            priority_rank(a.priority.as_deref())
                .cmp(&priority_rank(b.priority.as_deref()))
                .then_with(|| stage_rank(a.stage.as_deref()).cmp(&stage_rank(b.stage.as_deref())))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(found)
    }

    fn block_task(
        &mut self,
        agent: &str,
        id: &str,
        blocked: bool,
        reason: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let body = json!({"to": if blocked {"blocked"} else {"ready"}, "reason": reason_or(reason, if blocked {"blocked"} else {"unblocked"})});
        self.item_step(agent, id, "transition", body, &item)
    }

    fn task(&self, id: &str) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        task_from(&self.item(&self.session, id)?)
    }

    fn task_history(&self, id: &str) -> Result<Vec<tasks::TaskEvent>> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let value = self.get(&self.session, format!("{ITEMS}/{}/history", id))?;
        let rows: Vec<Value> = list(value, &["events", "items"])?;
        Ok(rows
            .iter()
            .map(|row| tasks::TaskEvent {
                agent: session_of(text(row, "actor")),
                action: text(row, "op").to_string(),
                note: text(row, "reason").to_string(),
                at: millis(row, "at").unwrap_or(0),
            })
            .collect())
    }

    fn add_task(&mut self, author: &str, spec: &tasks::TaskSpec, now: i64) -> Result<tasks::Task> {
        validate_title(&spec.title)?;
        let categories = [
            "player_money",
            "security_breach",
            "prod_outage",
            "cert_slip",
        ];
        if spec.priority.as_deref() == Some("P0") && spec.p0_category.is_none() {
            return Err(Error::Invalid(
                "P0 requires p0_category: player_money, security_breach, prod_outage, cert_slip"
                    .into(),
            ));
        }
        if spec
            .p0_category
            .as_deref()
            .is_some_and(|value| !categories.contains(&value))
        {
            return Err(Error::Invalid(
                "invalid p0_category: player_money, security_breach, prod_outage, cert_slip".into(),
            ));
        }
        validate_registry_text("body", &spec.body)?;
        validate_registry_text(
            "acceptance",
            spec.acceptance.as_deref().unwrap_or(&spec.title),
        )?;
        validate_evidence(&spec.evidence.iter().cloned().collect::<Vec<_>>())?;
        let target = spec.target.as_deref().unwrap_or(DEFAULT_TARGET);
        if !matches!(target, "code_accepted" | "ci_passed") {
            return Err(Error::Invalid(format!(
                "task target {target:?} needs evidence this client cannot provide; use code_accepted or ci_passed"
            )));
        }
        if target != "ci_passed"
            && let Some(value) = spec.evidence.as_deref()
        {
            require_commit_file(target, value)?;
        }
        let evidence: Vec<Value> = spec
            .evidence
            .iter()
            .map(|value| evidence_body(author, target, value, now))
            .collect();
        let auto_area = self.registry_auto_area()?;
        if auto_area && spec.paths.is_empty() {
            return Err(Error::Invalid(
                crate::task_area_error(&crate::ApiError {
                    code: "task_paths_required".into(),
                    ..crate::ApiError::default()
                })
                .expect("known task error"),
            ));
        }
        let mut body = json!({
            "client_key": spec.client_key.clone().unwrap_or_else(ulid),
            "title": spec.title,
            "body": spec.body,
            "acceptance": spec.acceptance.as_deref().unwrap_or(&spec.title),
            "type": spec.kind.as_deref().unwrap_or("code"),
            "actor": "agent",
            "priority": spec.priority.as_deref().unwrap_or(DEFAULT_PRIORITY),
            "p0_category": spec.p0_category,
            "due_at": spec.due_at,
            "target": target,
            "verification": spec.verification.as_deref().unwrap_or("auto"),
            "audience": [],
            "evidence": evidence,
        });
        if auto_area {
            body["paths"] = json!(spec.paths);
            if let Some(area) = &spec.area {
                body["area"] = json!(area);
            }
        } else {
            body["area_id"] = json!(self.area_id(
                author,
                spec.area.as_deref(),
                spec.prefix.as_deref(),
                spec.pad
            )?);
        }
        if let Some(key) = &spec.client_key
            && (key.is_empty() || key.len() > 256 || !key.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(Error::Invalid(
                "client_key must be 1 to 256 visible ASCII bytes".into(),
            ));
        }
        // Keep the exact HTTP key as well as the logical creation key for reconciliation.
        let mut call = Call::write(author, "POST", ITEMS.into(), body.clone());
        if let Some(key) = &self.write_idempotency_key {
            call.key = Some(key.clone());
        }
        let call = self
            .transport
            .prepare_task_create(&call, spec.client_key.is_some())?;
        body = call.body.clone().expect("task creation body");
        let attempt = || {
            self.call_cloud(&call).and_then(|reply| {
                task_from(&reply).map_err(|error| ClientError::Decode(error.to_string()))
            })
        };
        let mut result = attempt();
        // A lost daemon reply is a Transport error rather than OutcomeUnknown; a
        // malformed success response can also follow a committed registry write.
        let uncertain = matches!(
            result,
            Err(ClientError::OutcomeUnknown(_)
                | ClientError::Transport(_)
                | ClientError::Decode(_))
        );
        if uncertain {
            result = attempt();
        }
        match result {
            Ok(task) => Ok(task),
            Err(error) => {
                if uncertain {
                    let key = body["client_key"].as_str().expect("creation key");
                    if let Ok(Some(task)) = self.task_by_client_key(key) {
                        // A key match proves this pending write completed; a title never does.
                        self.transport.acknowledge_write(&call)?;
                        return Ok(task);
                    }
                    return Err(Error::Cloud {
                        code: "task_create_unconfirmed".into(),
                        status: None,
                        details: json!({"client_key":key,"idempotency_key":call.key}),
                        message: format!(
                            "task creation could not be confirmed after retry and lookup; client_key={key}; repeat task_add with client_key={key} or CLI task add --client-key {key} and the same arguments: {error}"
                        ),
                    });
                }
                let mut error = error;
                error.explain_task_create_refusal(&call);
                Err(error.into())
            }
        }
    }

    fn plan_task(&mut self, agent: &str, id: &str, plan: &tasks::TaskPlan) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let body = json!({
            "priority": plan.priority.as_deref().map_or(item["priority"].clone(), |p| json!(p)),
            "p0_category": plan.p0_category.as_deref().map_or(item["p0_category"].clone(), |p| json!(p)),
            "due_at": plan.due_at.as_deref().map_or(item["due_at"].clone(), |p| json!(p)),
            "revisit_after": item["revisit_after"],
            "revisit_on": item["revisit_on"],
            "expected_version": item["version"],
        });
        let category = body["p0_category"].as_str();
        let allowed = [
            "player_money",
            "security_breach",
            "prod_outage",
            "cert_slip",
        ];
        if body["priority"] == "P0"
            && category.is_none()
            && (plan.p0_category.is_some() || item["priority"] != "P0")
        {
            return Err(Error::Invalid(
                "P0 requires p0_category: player_money, security_breach, prod_outage, cert_slip"
                    .into(),
            ));
        }
        if category.is_some_and(|value| !allowed.contains(&value)) {
            return Err(Error::Invalid(
                "invalid p0_category: player_money, security_breach, prod_outage, cert_slip".into(),
            ));
        }
        task_from(&self.post(agent, format!("{ITEMS}/{}/plan", id), &body)?)
    }

    /// Intake → ready. A flag wins, then the item's own value, then the documented default.
    /// The area flag accepts an id, key or unique prefix of an active area; without it the
    /// item's area stays, and an item without an area is refused instead of guessed.
    fn triage_task(
        &mut self,
        agent: &str,
        id: &str,
        triage: &tasks::TaskTriage,
    ) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        if item["status"] != "intake" {
            return Err(Error::Invalid(format!(
                "{id} is {}, triage works only from intake",
                item["status"].as_str().unwrap_or("unknown")
            )));
        }
        let pick = |flag: &Option<String>, field: &str, default: &str| -> Value {
            match flag {
                Some(value) => json!(value),
                None if !item[field].is_null() => item[field].clone(),
                None => json!(default),
            }
        };
        let priority = pick(&triage.priority, "priority", "P2");
        let p0_category = triage
            .p0_category
            .as_deref()
            .map_or(item["p0_category"].clone(), |p| json!(p));
        if priority == "P0" && p0_category.is_null() {
            return Err(Error::Invalid(
                "P0 requires p0_category: player_money, security_breach, prod_outage, cert_slip"
                    .into(),
            ));
        }
        let area_id = match triage.area.as_deref() {
            Some(area) => json!(self.triage_area(agent, area)?),
            None if !item["area_id"].is_null() => item["area_id"].clone(),
            None => {
                return Err(Error::Invalid(format!(
                    "{id} has no area; pass --area with an area id, key or prefix"
                )));
            }
        };
        let body = json!({
            "type": pick(&triage.kind, "type", "code"),
            "actor": pick(&triage.actor, "actor", "agent"),
            "area_id": area_id,
            "priority": priority,
            "p0_category": p0_category,
            "due_at": item["due_at"],
            "revisit_after": item["revisit_after"],
            "revisit_on": item["revisit_on"],
            "target": pick(&triage.target, "target", "code_accepted"),
            "verification": pick(&triage.verification, "verification", "none"),
            "verify_by": item["verify_by"],
            "expected_version": item["version"],
        });
        task_from(&self.post(agent, format!("{ITEMS}/{}/triage", id), &body)?)
    }

    /// The registry leases an item for two hours, so `ttl` has no meaning here.
    fn claim_task(&mut self, agent: &str, id: &str, _ttl: i64, _now: i64) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        self.item_step(agent, id, "claim", json!({"session": agent}), &item)
    }

    fn claim_task_receipt_by_id(
        &mut self,
        agent: &str,
        id: &str,
        _ttl: i64,
        _now: i64,
    ) -> Result<Value> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let claimed =
            self.item_step_response(agent, id, "claim", json!({"session": agent}), &item)?;
        // Use the mutation's identity and assignment verbatim. The workflow verifies both;
        // substituting the requested ID could hide an unrelated successful mutation.
        let mut result = serde_json::to_value(task_from(&claimed)?)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        result["registry_assignment"] = claimed["assignment"].clone();
        result["registry_assignment_source"] = json!("claim_response");
        Ok(result)
    }

    fn renew_task(&mut self, agent: &str, id: &str, _ttl: i64, _now: i64) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        self.item_step(agent, id, "heartbeat", json!({}), &item)
    }

    fn release_task(
        &mut self,
        agent: &str,
        id: &str,
        _note: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        self.item_step(agent, id, "release", json!({}), &item)
    }

    fn submit_task(
        &mut self,
        agent: &str,
        id: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        validate_evidence(&[evidence.to_string()])?;
        let item = self.item(agent, id)?;
        let target = item["target"].as_str().unwrap_or(DEFAULT_TARGET);
        require_commit_file(target, evidence)?;
        let body = evidence_body(agent, target, evidence, now);
        let proved = self.item_step(agent, id, "evidence", body, &item);
        proved?;
        let item = self.item(agent, id)?;
        let body = json!({"to": "review", "reason": "submitted for review"});
        self.item_step(agent, id, "transition", body, &item)
    }

    fn accept_task(&mut self, agent: &str, id: &str, note: &str, _now: i64) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let body =
            json!({"to": "done", "resolution": "completed", "reason": reason_or(note, "accepted")});
        self.item_step(agent, id, "transition", body, &item)
    }

    fn review_task(
        &mut self,
        agent: &str,
        id: &str,
        decision: &str,
        reason: &str,
        _now: i64,
    ) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let body = json!({"decision": decision, "reason": reason});
        self.item_step(agent, id, "review", body, &item)
    }

    fn reject_task(
        &mut self,
        agent: &str,
        id: &str,
        reason: &str,
        evidence: &str,
        now: i64,
    ) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let mut body = json!({"to": "ready", "reason": reason_or(reason, "rejected")});
        if item["status"].as_str() == Some("done") {
            if evidence.trim().is_empty() {
                return Err(Error::Invalid(
                    "revoking accepted work needs new evidence".into(),
                ));
            }
            let target = item["target"].as_str().unwrap_or(DEFAULT_TARGET);
            require_commit_file(target, evidence)?;
            body["evidence"] = evidence_body(agent, target, evidence, now);
        }
        self.item_step(agent, id, "transition", body, &item)
    }

    fn cancel_task(&mut self, agent: &str, id: &str, note: &str, _now: i64) -> Result<tasks::Task> {
        let canonical = canonical_sdk_task(id)?;
        let id = canonical.as_str();
        let item = self.item(agent, id)?;
        let body = json!({
            "to": "cancelled",
            "resolution": "wont_do",
            "reason": reason_or(note, "cancelled"),
        });
        self.item_step(agent, id, "transition", body, &item)
    }

    fn batch_close_tasks(
        &mut self,
        agent: &str,
        ids: &[String],
        evidence: &str,
        now: i64,
    ) -> Result<Value> {
        if ids.is_empty() || ids.len() > 100 {
            return Err(Error::Invalid(
                "batch close requires 1 to 100 task ids".into(),
            ));
        }
        let mut results = Vec::with_capacity(ids.len());
        let mut pending = Vec::new();
        let mut targets = Vec::new();
        for id in ids {
            match self.task(id) {
                Ok(task)
                    if matches!(
                        task.status,
                        tasks::Status::Accepted | tasks::Status::Cancelled
                    ) =>
                {
                    results.push(json!({"id": id, "changed": false, "error": null, "item": task}));
                }
                Ok(task) => {
                    targets.push(task.target);
                    pending.push(id.clone());
                }
                Err(error) => results.push(
                    json!({"id": id, "changed": false, "error": error.to_string(), "item": null}),
                ),
            }
        }
        if pending.is_empty() {
            return Ok(json!({"results": results}));
        }
        let evidence_kind = if targets
            .iter()
            .all(|target| target.as_deref() == Some("ci_passed"))
        {
            "ci_run"
        } else {
            "commit"
        };
        let payload = json!({
            "ids": pending,
            "to": "done",
            "resolution": "completed",
            "reason": reason_or(evidence, "owner decision"),
            "evidence": {
                "kind": evidence_kind,
                "environment": "local",
                "value": evidence,
                "observed_at": rfc3339(now),
                "verifier": agent,
                "expected_version": null
            }
        });
        let response = self.post(agent, format!("{ITEMS}/batch-transition"), &payload)?;
        results.extend(
            response
                .get("results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        Ok(json!({"results": results}))
    }

    fn board_set(&mut self, agent: &str, write: &BoardWrite, _now: i64) -> Result<BoardEntry> {
        let mut write = write.clone();
        write.ttl_minutes.get_or_insert(DEFAULT_BOARD_MINUTES);
        let value = self.post(agent, "/api/v1/bus/board".into(), &write)?;
        Ok(one(value, "entry")?)
    }

    fn board_get(&self, key: &str, now: i64) -> Result<Option<BoardEntry>> {
        Ok(self
            .board_list(None, now)?
            .into_iter()
            .find(|entry| entry.key == key))
    }

    fn board_remove(&mut self, agent: &str, key: &str) -> Result<bool> {
        match self.write(
            agent,
            "DELETE",
            format!("/api/v1/bus/board/{}", encode(key)),
            &json!({}),
        ) {
            Ok(_) => Ok(true),
            Err(
                Error::NotFound(_)
                | Error::Cloud {
                    status: Some(404), ..
                },
            ) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn board_list(&self, zone: Option<&str>, _now: i64) -> Result<Vec<BoardEntry>> {
        let tail = query(&[("zone", zone.map(str::to_string))]);
        let value = self.get(&self.session, format!("/api/v1/bus/board{tail}"))?;
        Ok(list(value, &["board", "entries", "items"])?)
    }

    fn work_offer(&mut self, agent: &str, offer: &WorkOffer) -> Result<WorkTask> {
        let value = self.post(agent, "/api/v1/bus/tasks".into(), offer)?;
        Ok(one(value, "task")?)
    }

    fn work_list(&self, agent: &str) -> Result<Vec<WorkTask>> {
        let value = self.get(agent, "/api/v1/bus/tasks".into())?;
        Ok(list(value, &["tasks", "items"])?)
    }

    fn work_get(&self, agent: &str, id: &str) -> Result<WorkTask> {
        let canonical = lockyard_compat::LegacyCompatibilityV1::task_id(
            &json!(id),
            lockyard_compat::TaskDomain::Bus,
            lockyard_compat::Source::Sdk,
            2,
        )
        .map_err(compatibility_error)?;
        let id = canonical.as_str();
        let value = self.get(agent, format!("/api/v1/bus/tasks/{id}"))?;
        Ok(one(value, "task")?)
    }

    fn work_step(
        &mut self,
        agent: &str,
        id: &str,
        action: WorkAction,
        step: &WorkStep,
    ) -> Result<WorkTask> {
        let canonical = lockyard_compat::LegacyCompatibilityV1::task_id(
            &json!(id),
            lockyard_compat::TaskDomain::Bus,
            lockyard_compat::Source::Sdk,
            2,
        )
        .map_err(compatibility_error)?;
        let id = canonical.as_str();
        if action == WorkAction::Take && step.version.is_none() {
            return Err(Error::Invalid("take needs the task's version".into()));
        }
        let tail = query(&[("version", step.version.map(|version| version.to_string()))]);
        let value = self.post(
            agent,
            format!("/api/v1/bus/tasks/{id}/{}{tail}", action.as_str()),
            step,
        )?;
        Ok(one(value, "task")?)
    }

    fn heartbeat(&mut self, agent: &str, beat: &PresenceBeat, _now: i64) -> Result<()> {
        let mut beat = beat.clone();
        beat.dnd_until = beat.dnd_until.map(|stamp| stamp.on_the_wire());
        if let Some(activity) = beat.activity.as_mut() {
            activity.tool_started_at = activity
                .tool_started_at
                .take()
                .map(|stamp| stamp.on_the_wire());
        }
        self.post(agent, "/api/v1/presence".into(), &beat)?;
        Ok(())
    }

    fn presence(&self, active_within_seconds: i64, _now: i64) -> Result<Vec<Presence>> {
        let tail = query(&[("active_within", Some(active_within_seconds.to_string()))]);
        let value = self.get(&self.session, format!("/api/v1/presence{tail}"))?;
        Ok(list(value, &["sessions", "presence", "items"])?)
    }

    fn events(&self, request: &EventQuery) -> Result<EventPage> {
        if request.wait_seconds > MAX_POLL_WAIT_SECONDS {
            return Err(Error::Invalid(format!(
                "wait is at most {MAX_POLL_WAIT_SECONDS} seconds"
            )));
        }
        let mut call = Call::get(&self.session, event_route(request));
        call.long_poll = request.wait_seconds > 0;
        let value = self.call_cloud(&call)?;
        Ok(crate::decode_events(value)?)
    }

    fn export(&self) -> Result<Value> {
        self.get(&self.session, "/api/v1/export/coordination".into())
    }

    fn freeze(&mut self, agent: &str, freeze: &Freeze) -> Result<Value> {
        self.post(agent, "/api/v1/admin/freeze".into(), freeze)
    }

    fn release_session(&mut self, agent: &str, session: &str) -> Result<Value> {
        self.post(
            agent,
            format!("/api/v1/admin/sessions/{}/release", encode(session)),
            &json!({}),
        )
    }

    fn import_zones(&mut self, agent: &str, catalog: &Value) -> Result<Value> {
        self.post(
            agent,
            "/api/v1/import/zones".into(),
            &json!({"catalog": catalog}),
        )
    }

    fn import_bus(&mut self, agent: &str, dump: &Value) -> Result<Value> {
        self.post(agent, "/api/v1/import/bus".into(), dump)
    }

    fn registry_import(&mut self, agent: &str, dump: &Value) -> Result<Value> {
        validate_registry_import(dump)?;
        const CHUNK_BYTES: usize = 900 * 1024;
        let Some(items) = dump.get("items").and_then(Value::as_array) else {
            return self.post(agent, "/api/v1/registry/import".into(), dump);
        };
        if serde_json::to_vec(dump).map_or(0, |bytes| bytes.len()) <= CHUNK_BYTES {
            return self.post(agent, "/api/v1/registry/import".into(), dump);
        }
        let mut chunks: Vec<Vec<Value>> = Vec::new();
        let mut current = Vec::new();
        let mut size = 32usize;
        for item in items {
            let item_size = serde_json::to_vec(item)
                .map_err(|error| Error::Invalid(error.to_string()))?
                .len();
            if !current.is_empty() && size + item_size > CHUNK_BYTES {
                chunks.push(std::mem::take(&mut current));
                size = 32;
            }
            current.push(item.clone());
            size += item_size;
        }
        if !current.is_empty() {
            chunks.push(current);
        }
        let mut results = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let mut payload = dump.clone();
            payload["items"] = json!(chunk);
            results.push(self.post(agent, "/api/v1/registry/import".into(), &payload)?);
        }
        Ok(json!({"chunks": results.len(), "results": results}))
    }

    fn area_list(&self, agent: &str) -> Result<Value> {
        self.get(agent, AREAS.into())
    }

    fn area_create(&mut self, agent: &str, request: &Value) -> Result<Value> {
        self.post(agent, AREAS.into(), request)
    }

    fn area_update(&mut self, agent: &str, key: &str, request: &Value) -> Result<Value> {
        let areas: Vec<Value> = list(self.get(agent, AREAS.into())?, &["areas", "items"])?;
        let area = areas
            .iter()
            .find(|area| text(area, "key").eq_ignore_ascii_case(key))
            .ok_or_else(|| Error::NotFound(format!("no area {key:?}")))?;
        let body = json!({
            "key": key,
            "name": request.get("name").and_then(Value::as_str).unwrap_or_else(|| text(area, "name")),
            "prefix": request.get("prefix").and_then(Value::as_str).unwrap_or_else(|| text(area, "prefix")),
            "pad": request.get("pad").and_then(Value::as_u64).unwrap_or_else(|| area.get("pad").and_then(Value::as_u64).unwrap_or(4)),
        });
        self.post(agent, AREAS.into(), &body)
    }

    fn tokens(&self) -> Result<Value> {
        self.get(&self.session, TOKENS.into())
    }

    fn token_create(&mut self, agent: &str, request: &TokenRequest) -> Result<Value> {
        self.post(agent, TOKENS.into(), request)
    }

    fn token_revoke(&mut self, agent: &str, id: &str) -> Result<Value> {
        self.post(agent, format!("{TOKENS}/{}/revoke", encode(id)), &json!({}))
    }
}

/// Route of one event poll. `seq` is per stream, so each stream keeps its own cursor.
pub fn event_route(request: &EventQuery) -> String {
    let wait = (request.wait_seconds > 0).then(|| request.wait_seconds.to_string());
    match request.stream {
        Stream::Coordination => {
            let types = (!request.types.is_empty()).then(|| request.types.join(","));
            let tail = query(&[
                ("after", Some(request.after.to_string())),
                ("wait", wait),
                ("session", request.session.clone()),
                ("types", types),
            ]);
            format!("/api/v1/events{tail}")
        }
        Stream::Registry => {
            let tail = query(&[("after", Some(request.after.to_string())), ("wait", wait)]);
            format!("/api/v1/registry/events{tail}")
        }
    }
}

/// Ids a delivery claim granted. An answer without a list grants everything asked: a duplicate over a loss.
pub fn claimed_ids(value: Value, asked: &[i64]) -> std::result::Result<Vec<i64>, ClientError> {
    if value.is_array()
        || value.get("claimed").is_some_and(Value::is_array)
        || value.get("ids").is_some_and(Value::is_array)
    {
        return list(value, &["claimed", "ids"]);
    }
    Ok(asked.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use crate::Transport;
    use crate::fake::{FakeServer, Reply, Seen};
    use lockyard_core::proto::{ClaimMode, Purpose, SessionActivity, SessionState, WorkStatus};
    use std::collections::HashSet;

    #[test]
    fn survey_r4_check_and_granted_request_preserve_server_modes() {
        let checks = checks(
            json!([{"path":"src/a.rs","status":"held","mode":"shared","auto_grantable":false,
            "holder":{"session":"other","path":"src/a.rs","mode":"exclusive","dirty":true}}]),
        )
        .unwrap();
        let output = serde_json::to_value(checks).unwrap();
        assert_eq!(output[0]["mode"], "shared");
        assert_eq!(output[0]["auto_grantable"], false);
        assert_eq!(output[0]["holder"]["mode"], "exclusive");
        assert_eq!(output[0]["holder"]["dirty"], true);
        let record: AccessRecord = one(json!({"id":4,"granted":true,"claim":{"id":7,"session":"me","mode":"shared","held":false,
            "foreign_dirty_paths":[{"path":"src/a.rs","task_id":12}]}}), "request").unwrap();
        let output = serde_json::to_value(record).unwrap();
        assert_eq!(output["claim"]["mode"], "shared");
        assert_eq!(output["granted"], true);
        assert_eq!(output["claim"]["foreign_dirty_paths"][0]["task_id"], "D-12");
    }

    #[test]
    fn legacy_nested_and_bare_task_fields_are_normalized_once() {
        for wire in [
            json!([{"path":"a","task_id":12}]),
            json!({"paths":[{"path":"a","task_id":12}]}),
        ] {
            let paths: Vec<DirtyPath> = list(wire, &["paths", "dirty", "items"]).unwrap();
            assert_eq!(paths[0].task_id.as_ref().unwrap().as_str(), "D-12");
        }
        let claim: Claim = one(
            json!({"id":1,"session":"me","foreign_dirty_paths":[{"path":"a","task_id":12}]}),
            "claim",
        )
        .unwrap();
        assert_eq!(
            claim.foreign_dirty_paths[0]
                .task_id
                .as_ref()
                .unwrap()
                .as_str(),
            "D-12"
        );
        let work: Vec<WorkTask> =
            list(json!([{"id":12,"status":"offered"}]), &["tasks", "items"]).unwrap();
        assert_eq!(work[0].id.as_str(), "BT-12");
    }

    #[test]
    fn session_wire_aliases_are_canonicalized_at_one_boundary() {
        let claim: Claim = one(json!({"id":1,"agent":"me"}), "claim").unwrap();
        assert_eq!(serde_json::to_value(claim).unwrap()["session"], "me");
        let queue: QueueEntry = one(json!({"id":1,"agent":"me"}), "entry").unwrap();
        assert_eq!(serde_json::to_value(queue).unwrap()["session"], "me");
        let presence: Presence = one(json!({"agent":"me"}), "presence").unwrap();
        assert_eq!(serde_json::to_value(presence).unwrap()["session"], "me");
    }

    fn backend(script: Vec<Value>) -> (FakeServer, CloudBackend<Client>) {
        let replies = script
            .into_iter()
            .map(|body| Reply::json(200, body))
            .collect();
        let server = FakeServer::start(replies);
        let client = Client::new(&server.url(), "token".into()).unwrap();
        (server, CloudBackend::new(client, "me"))
    }

    fn sees(server: &FakeServer, routes: &[(&str, &str)]) -> Vec<Seen> {
        let seen = server.requests();
        let actual: Vec<(&str, &str)> = seen
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect();
        assert_eq!(actual, routes);
        let mut keys = HashSet::new();
        for request in &seen {
            let is_read = request.method == "GET" || request.path == "/api/v1/zones/check";
            let key = request.header("idempotency-key");
            if is_read {
                assert_eq!(key, None, "{}", request.path);
            } else {
                assert!(
                    keys.insert(key.expect("every write has a key").to_string()),
                    "keys are unique"
                );
            }
            assert_eq!(request.header("x-lockyard-session"), Some("me"));
        }
        seen
    }

    fn claim_json(id: i64) -> Value {
        json!({"id": id, "session": "me", "paths": ["src"], "fence": 2})
    }

    #[test]
    fn claim_creation_status_is_transient_and_does_not_change_submitted_status() {
        for (field, expected) in [
            (None, None),
            (Some(Value::Null), None),
            (Some(json!("true")), None),
            (Some(json!(1)), None),
            (Some(json!(true)), Some(true)),
            (Some(json!(false)), Some(false)),
        ] {
            let mut reply = claim_json(7);
            if let Some(field) = field {
                reply["created"] = field;
            }
            let (server, mut cloud) = backend(vec![json!([]), reply]);
            let request = ClaimRequest {
                paths: vec!["src".into()],
                ..ClaimRequest::default()
            };
            let (claim, created) =
                lockyard_core::claim_or_reuse_with_creation_status(&mut cloud, "me", &request, 0)
                    .unwrap();
            assert_eq!(created, expected);
            assert!(
                serde_json::to_value(claim)
                    .unwrap()
                    .get("created")
                    .is_none()
            );
            sees(
                &server,
                &[
                    ("GET", "/api/v1/zones/claims?session=me"),
                    ("POST", "/api/v1/zones/claims"),
                ],
            );
        }
        let mut reply = claim_json(7);
        reply["created"] = json!(false);
        let (_server, mut cloud) = backend(vec![json!([]), reply]);
        let (_, submitted) = lockyard_core::claim_or_reuse_with_status(
            &mut cloud,
            "me",
            &ClaimRequest {
                paths: vec!["src".into()],
                ..ClaimRequest::default()
            },
            0,
        )
        .unwrap();
        assert!(submitted, "server-side reuse still submits a POST");
    }

    #[test]
    fn claim_reuse_does_not_treat_an_incoming_handover_as_owned() {
        let mut offered = claim_json(7);
        offered["session"] = json!("bob");
        offered["handover_to"] = json!("me");
        offered["offered_to_you"] = json!(true);
        let (server, mut cloud) = backend(vec![json!([offered]), claim_json(8)]);
        let request = ClaimRequest {
            paths: vec!["src/file.rs".into()],
            ..ClaimRequest::default()
        };
        let claim = lockyard_core::claim_or_reuse(&mut cloud, "me", &request, 0).unwrap();
        assert_eq!(claim.id, 8, "an offered claim must still be acquired");
        assert_eq!(claim.session, "me");
        sees(
            &server,
            &[
                ("GET", "/api/v1/zones/claims?session=me"),
                ("POST", "/api/v1/zones/claims"),
            ],
        );
    }

    #[test]
    fn claim_reuse_does_not_cover_excluded_paths_or_their_parents() {
        for requested in ["src/private/file.rs", "src/private", "src"] {
            let mut held = claim_json(7);
            held["excluded_paths"] = json!(["src/private"]);
            let (server, mut cloud) = backend(vec![json!([held]), claim_json(8)]);
            let request = ClaimRequest {
                paths: vec![requested.into()],
                ..ClaimRequest::default()
            };
            let claim = lockyard_core::claim_or_reuse(&mut cloud, "me", &request, 0).unwrap();
            assert_eq!(claim.id, 8, "excluded coverage was reused for {requested}");
            sees(
                &server,
                &[
                    ("GET", "/api/v1/zones/claims?session=me"),
                    ("POST", "/api/v1/zones/claims"),
                ],
            );
        }
    }

    #[test]
    fn claim_reuse_respects_the_server_case_sensitive_repository_policy() {
        let mut held = claim_json(7);
        held["paths"] = json!(["SRC"]);
        held["case_insensitive_paths"] = json!(false);
        let (server, mut cloud) = backend(vec![json!([held]), claim_json(8)]);
        let request = ClaimRequest {
            paths: vec!["src/file.rs".into()],
            ..ClaimRequest::default()
        };
        let claim = lockyard_core::claim_or_reuse(&mut cloud, "me", &request, 0).unwrap();
        assert_eq!(claim.id, 8, "SRC does not hold src in this repository");
        sees(
            &server,
            &[
                ("GET", "/api/v1/zones/claims?session=me"),
                ("POST", "/api/v1/zones/claims"),
            ],
        );
    }

    #[test]
    fn claim_reuse_keeps_owned_coverage_under_the_server_case_policy() {
        for case_policy in [None, Some(true), Some(false)] {
            let mut held = claim_json(7);
            held["paths"] = json!(["SRC"]);
            held["excluded_paths"] = json!(["SRC/private"]);
            if let Some(fold_case) = case_policy {
                held["case_insensitive_paths"] = json!(fold_case);
            }
            let (server, mut cloud) = backend(vec![json!([held])]);
            let request = ClaimRequest {
                paths: vec![if case_policy == Some(false) {
                    "SRC/public/file.rs".into()
                } else {
                    "src/public/file.rs".into()
                }],
                ..ClaimRequest::default()
            };
            let claim = lockyard_core::claim_or_reuse(&mut cloud, "me", &request, 0).unwrap();
            assert_eq!(claim.id, 7);
            sees(&server, &[("GET", "/api/v1/zones/claims?session=me")]);
        }
    }

    #[test]
    fn claim_reuse_with_hold_preserves_acquisition_conflicts() {
        let mut receipt = claim_json(8);
        receipt["excluded_paths"] = json!(["src/private"]);
        receipt["conflicts"] = json!([{"path":"src/private","session":"bob"}]);
        receipt["created"] = json!(true);
        let mut held = receipt.clone();
        held.as_object_mut().unwrap().remove("conflicts");
        held["hold_reason"] = json!("build");
        held["hold_until"] = json!("2099-11-11T21:20:00Z");
        let (server, mut cloud) = backend(vec![json!([]), receipt, json!({}), json!([held])]);
        let (claim, created) = lockyard_core::claim_or_reuse_with_hold(
            &mut cloud,
            "me",
            &ClaimRequest {
                paths: vec!["src".into()],
                ttl_minutes: 60,
                ..ClaimRequest::default()
            },
            Some("build".into()),
            Some("2099-11-11T21:20:00Z".into()),
            0,
        )
        .unwrap();
        assert_eq!(created, Some(true));
        assert!(
            claim
                .excluded_paths_warning()
                .unwrap()
                .contains("держатель: bob")
        );
        sees(
            &server,
            &[
                ("GET", "/api/v1/zones/claims?session=me"),
                ("POST", "/api/v1/zones/claims"),
                ("POST", "/api/v1/zones/claims/8/renew"),
                ("GET", "/api/v1/zones/claims?session=me"),
            ],
        );
    }

    #[test]
    fn claim_reuse_rejects_an_acquisition_receipt_with_unexplained_missing_coverage() {
        let mut foreign = claim_json(8);
        foreign["session"] = json!("bob");
        let mut missing = claim_json(8);
        missing["paths"] = json!(["other"]);
        missing["excluded_paths"] = json!(["src/private"]);
        let mut different_case = claim_json(8);
        different_case["paths"] = json!(["SRC"]);
        different_case["case_insensitive_paths"] = json!(false);
        for receipt in [foreign, missing, different_case] {
            let (server, mut cloud) = backend(vec![json!([]), receipt.clone()]);
            let request = ClaimRequest {
                paths: vec!["src".into()],
                ..ClaimRequest::default()
            };
            assert!(
                lockyard_core::claim_or_reuse(&mut cloud, "me", &request, 0).is_err(),
                "invalid acquisition receipt accepted: {receipt}"
            );
            sees(
                &server,
                &[
                    ("GET", "/api/v1/zones/claims?session=me"),
                    ("POST", "/api/v1/zones/claims"),
                ],
            );
        }
    }

    #[test]
    fn claims_carry_lazy_mode_purpose_meta_and_short_waits() {
        let (server, mut cloud) = backend(vec![json!({"claim": claim_json(1)}), claim_json(2)]);
        let request = ClaimRequest {
            paths: vec!["src".into()],
            note: "n".into(),
            ttl_minutes: 30,
            mode: Some(ClaimMode::Shared),
            purpose: Purpose::Deploy,
            lazy: true,
            zone: Some("api".into()),
            zones: vec!["api".into(), "web".into()],
            queue_wait_seconds: Some(60),
            meta: Some(json!({"change": "abc"})),
        };
        assert_eq!(cloud.claim("me", &request, 0).unwrap().id, 1);
        assert_eq!(
            cloud
                .claim("me", &ClaimRequest::default(), 0)
                .unwrap()
                .fence,
            2
        );
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/claims"),
                ("POST", "/api/v1/zones/claims"),
            ],
        );
        let body = &seen[0].body;
        assert_eq!(body["mode"], "shared");
        assert_eq!(body["purpose"], "deploy");
        assert_eq!(body["lazy"], true);
        assert_eq!(body["queue_wait_seconds"], 60);
        assert_eq!(body["meta"]["change"], "abc");
        assert_eq!(body["zones"], json!(["api", "web"]));
    }

    #[test]
    fn claim_lifecycle_routes_and_fences() {
        let (server, mut cloud) = backend(vec![
            claim_json(5),
            claim_json(5),
            json!({"pending": true}),
            claim_json(5),
            claim_json(5),
            json!({}),
            json!({}),
            json!({}),
            json!([claim_json(5), claim_json(6)]),
            json!({}),
            json!({}),
            json!({"released": 2}),
        ]);
        cloud.add_path("me", 5, "docs", Some(7)).unwrap();
        cloud
            .narrow("me", 5, &["src".to_string()], Some(7))
            .unwrap();
        cloud.handover("me", 5, "bob", Some(7)).unwrap();
        cloud.handover_accept("me", 5).unwrap();
        cloud.takeover("me", 5, "holder is gone").unwrap();
        cloud
            .activity(
                "me",
                5,
                &ActivityRequest {
                    write: true,
                    paths: vec!["src".into()],
                    fence: Some(7),
                },
            )
            .unwrap();
        let renew = RenewRequest {
            ttl_minutes: 10,
            fence: Some(7),
            ..RenewRequest::default()
        };
        assert_eq!(cloud.renew("me", Some(5), &renew, 0).unwrap(), 1);
        let release = ReleaseRequest {
            note: Some("done".into()),
            leave_dirty: true,
            fence: Some(7),
        };
        assert_eq!(cloud.release("me", Some(5), &release, 0).unwrap(), 1);
        let renew_all = RenewRequest {
            ttl_minutes: 10,
            ..RenewRequest::default()
        };
        assert_eq!(cloud.renew("me", None, &renew_all, 0).unwrap(), 2);
        assert_eq!(
            cloud
                .release("me", None, &ReleaseRequest::default(), 0)
                .unwrap(),
            2
        );
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/claims/5/add-path"),
                ("POST", "/api/v1/zones/claims/5/narrow"),
                ("POST", "/api/v1/zones/claims/5/handover"),
                ("POST", "/api/v1/zones/claims/5/accept"),
                ("POST", "/api/v1/zones/claims/5/takeover"),
                ("POST", "/api/v1/zones/claims/5/activity"),
                ("POST", "/api/v1/zones/claims/5/renew"),
                ("DELETE", "/api/v1/zones/claims/5"),
                ("GET", "/api/v1/zones/claims?session=me"),
                ("POST", "/api/v1/zones/claims/5/renew"),
                ("POST", "/api/v1/zones/claims/6/renew"),
                ("DELETE", "/api/v1/zones/claims?session=me"),
            ],
        );
        assert_eq!(seen[0].body, json!({"path": "docs", "fence": 7}));
        assert_eq!(seen[1].body, json!({"paths": ["src"], "fence": 7}));
        assert_eq!(seen[2].body, json!({"to": "bob", "fence": 7}));
        assert_eq!(seen[4].body, json!({"reason": "holder is gone"}));
        assert_eq!(
            seen[5].body,
            json!({"write": true, "paths": ["src"], "fence": 7})
        );
        assert_eq!(seen[6].body["fence"], 7);
        assert_eq!(
            seen[7].body,
            json!({"note": "done", "leave_dirty": true, "fence": 7})
        );
    }

    #[test]
    fn bulk_release_sends_options_in_the_delete_body_and_fences_only_one_live_claim() {
        let (server, mut cloud) = backend(vec![
            json!([claim_json(5)]),
            json!({"released": 1}),
            json!([claim_json(5), claim_json(6)]),
        ]);
        let request = ReleaseRequest {
            note: Some("finished".into()),
            leave_dirty: true,
            fence: Some(9),
        };
        assert_eq!(cloud.release("me", None, &request, 0).unwrap(), 1);
        assert!(matches!(
            cloud.release("me", None, &request, 0),
            Err(Error::Invalid(_))
        ));
        let seen = server.requests();
        assert_eq!(seen[1].method, "DELETE");
        assert_eq!(seen[1].path, "/api/v1/zones/claims?session=me");
        assert_eq!(
            seen[1].body,
            json!({"note": "finished", "leave_dirty": true, "fence": 9})
        );
        assert_eq!(
            seen.len(),
            3,
            "a multi-claim fence must be rejected before DELETE"
        );
    }

    #[test]
    fn seen_returns_only_ids_the_server_marked() {
        let (_server, mut cloud) = backend(vec![json!({"seen": [7]})]);
        assert_eq!(cloud.inbox_seen("me", &[7, 8], 0).unwrap(), 1);
    }

    #[test]
    fn a_takeover_needs_a_reason_before_any_request() {
        let (server, mut cloud) = backend(vec![]);
        assert!(matches!(
            cloud.takeover("me", 1, "  "),
            Err(Error::Invalid(_))
        ));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn claim_listing_and_check_read_free_own_and_holder() {
        let (server, cloud) = backend(vec![
            json!({"claims": [claim_json(1)]}),
            json!({"paths": [
                {"path": "a", "status": "free"},
                {"path": "b", "status": "own"},
                {"path": "c", "status": "held", "holder": {"session": "bob", "claim_id": 9, "note": "n"}},
                {"path": "d", "status": "held", "holder": "carol"}
            ]}),
        ]);
        let filter = ClaimQuery {
            session: Some("me".into()),
            path: Some("src/a b".into()),
        };
        assert_eq!(cloud.claims(&filter, 0).unwrap()[0].id, 1);
        let paths: Vec<String> = ["a", "b", "c", "d"].iter().map(|p| p.to_string()).collect();
        let found = cloud.check("me", &paths, Some(4), 0).unwrap();
        let statuses: Vec<_> = found.iter().map(|check| check.status).collect();
        assert_eq!(
            statuses,
            [
                CheckStatus::Free,
                CheckStatus::Own,
                CheckStatus::Held,
                CheckStatus::Held
            ]
        );
        assert_eq!(found[2].holder.as_ref().unwrap().agent, "bob");
        assert_eq!(found[3].holder.as_ref().unwrap().agent, "carol");
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/zones/claims?session=me&path=src%2Fa%20b"),
                ("POST", "/api/v1/zones/check"),
            ],
        );
        assert_eq!(
            seen[1].body,
            json!({"paths": ["a", "b", "c", "d"], "fence": 4})
        );
    }

    #[test]
    fn queue_routes() {
        let (server, mut cloud) = backend(vec![
            json!({"id": 3, "session": "me", "paths": ["src"]}),
            json!([{"id": 3, "session": "me"}]),
            Value::Null,
        ]);
        let request = QueueRequest {
            paths: vec!["src".into()],
            ttl_minutes: 60,
            zones: vec!["api".into()],
            ..QueueRequest::default()
        };
        assert_eq!(cloud.queue_add("me", &request).unwrap().id, 3);
        assert_eq!(cloud.queue_list("me").unwrap().len(), 1);
        cloud.queue_cancel("me", 3).unwrap();
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/queue"),
                ("GET", "/api/v1/zones/queue"),
                ("DELETE", "/api/v1/zones/queue/3"),
            ],
        );
        assert_eq!(seen[0].body["ttl_minutes"], 60);
        assert_eq!(seen[0].body["zones"], json!(["api"]));
    }

    #[test]
    fn request_routes() {
        let (server, mut cloud) = backend(vec![
            json!({"id": 4, "session": "me", "paths": ["src"], "text": "please"}),
            json!({"request": {"id": 4, "reply": "soon"}}),
        ]);
        let request = AccessRequest {
            paths: vec!["src".into()],
            text: "please".into(),
            urgent: true,
            need_by: Some("soon".into()),
        };
        assert_eq!(cloud.zone_request("me", &request).unwrap().from, "me");
        let answer = AccessAnswer {
            reply: Some("soon".into()),
            eta: Some("10m".into()),
        };
        assert_eq!(
            cloud
                .zone_answer("me", 4, &answer)
                .unwrap()
                .reply
                .as_deref(),
            Some("soon")
        );
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/requests"),
                ("POST", "/api/v1/zones/requests/4/answer"),
            ],
        );
        assert_eq!(seen[0].body["urgent"], true);
        assert_eq!(seen[1].body, json!({"reply": "soon", "eta": "10m"}));
    }

    #[test]
    fn dirty_routes_disown_and_adopt() {
        let (server, mut cloud) = backend(vec![
            json!({}),
            json!({"paths": [{"path": "a", "owner_session": "bob", "task_id": 2}]}),
            json!({}),
            json!({}),
        ]);
        let report = DirtyPath {
            path: "a".into(),
            owner_session: Some("bob".into()),
            reason: None,
            task_id: Some(lockyard_core::task_id::TaskId::parse("D-2").unwrap()),
        };
        cloud
            .dirty_report("me", std::slice::from_ref(&report))
            .unwrap();
        assert_eq!(cloud.dirty_list("me", Some("a")).unwrap(), [report]);
        cloud.dirty_disown("me", &["a".to_string()]).unwrap();
        cloud
            .dirty_adopt("me", &["a".to_string()], "left behind")
            .unwrap();
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/zones/dirty"),
                ("GET", "/api/v1/zones/dirty?path=a"),
                ("POST", "/api/v1/zones/dirty/disown"),
                ("POST", "/api/v1/zones/dirty/adopt"),
            ],
        );
        assert_eq!(seen[0].body["paths"][0]["owner_session"], "bob");
        assert_eq!(
            seen[3].body,
            json!({"paths": ["a"], "reason": "left behind"})
        );
    }

    #[test]
    fn lost_claims_and_the_catalog() {
        let (server, cloud) = backend(vec![
            json!([{"claim_id": 8, "session": "me", "paths": ["src"], "reason": "unavailable"}]),
            json!({"zones": {"api": ["src"]}}),
        ]);
        assert_eq!(cloud.lost("me").unwrap()[0].claim_id, 8);
        assert_eq!(cloud.catalog().unwrap()["zones"]["api"][0], "src");
        sees(
            &server,
            &[
                ("GET", "/api/v1/zones/lost?session=me"),
                ("GET", "/api/v1/zones/catalog"),
            ],
        );
    }

    #[test]
    fn mail_is_two_phase_with_delivery_claims() {
        let (server, mut cloud) = backend(vec![
            json!({"id": 10, "thread_id": 10, "from_session": "me", "to": "bob", "body": "x", "deduplicated": true}),
            json!({"id": 11, "thread_id": 10, "in_reply_to": 10, "from_session": "me", "to": "bob", "body": "y"}),
            json!({}),
            json!({"messages": [{"id": 12, "from_session": "bob", "to": "me", "body": "z"}], "skipped": 3}),
            json!({"messages": [{"id": 12}], "skipped": 3}),
            json!({"claimed": [12]}),
            json!({"seen": 1}),
            json!({}),
        ]);
        let send = SendRequest {
            urgent: false,
            to: "bob".into(),
            body: "x".into(),
            kind: Some("ask".into()),
            needs: Some("reply".into()),
            key: Some("k".into()),
            ..SendRequest::default()
        };
        assert!(cloud.send("me", &send, 0).unwrap().deduplicated);
        assert_eq!(cloud.reply("me", 10, "y", 0).unwrap().reply_to, Some(10));
        cloud.ack("me", 10).unwrap();
        let page = cloud
            .inbox(
                "me",
                InboxQuery {
                    all: true,
                    limit: 20,
                },
                0,
            )
            .unwrap();
        assert_eq!((page.messages[0].id, page.skipped), (12, 3));
        assert!(matches!(cloud.unread("me"), Err(Error::Unavailable(_))));
        assert_eq!(
            cloud.inbox_claim("me", "hook", &[12, 13], 60, 0).unwrap(),
            [12]
        );
        assert_eq!(cloud.inbox_seen("me", &[12], 0).unwrap(), 1);
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/bus/messages"),
                ("POST", "/api/v1/bus/messages/10/reply"),
                ("POST", "/api/v1/bus/messages/10/ack"),
                ("GET", "/api/v1/bus/inbox?all=true&limit=20"),
                ("GET", "/api/v1/bus/inbox"),
                ("POST", "/api/v1/bus/inbox/claim"),
                ("POST", "/api/v1/bus/inbox/seen"),
                // Marking mail read tells the sender so, through the endpoint in the contract.
                ("POST", "/api/v1/messages/12/receipt"),
            ],
        );
        assert_eq!(seen[0].body["needs"], "reply");
        assert_eq!(seen[5].body, json!({"ids": [12, 13], "lease_seconds": 60}));
        assert_eq!(seen[6].body, json!({"ids": [12]}));
        assert_eq!(seen[7].body, json!({"status": "read"}));
    }

    #[test]
    fn sent_mail_comes_back_with_the_status_the_server_gave_each_message() {
        let (server, cloud) = backend(vec![json!({"messages": [
            {"id": 7, "to": "bob", "body": "take src/api", "created_at": 10,
             "status": "replied", "delivered_at": 20, "read_at": 30, "replied_at": 40},
            {"id": 8, "to": "bob", "body": "and this", "created_at": 11, "status": "sent"},
            {"id": 9, "to": "gone", "body": "discard this", "created_at": 12, "status": "failed"},
            {"id": 10, "to": "bob", "body": "?", "created_at": 13, "status": "something new"}
        ]})]);
        let receipts = cloud.sent("me", 20).unwrap();
        let statuses: Vec<bus::Delivery> = receipts.iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [
                bus::Delivery::Replied,
                bus::Delivery::Sent,
                bus::Delivery::Failed,
                bus::Delivery::Sent
            ]
        );
        assert_eq!(receipts[0].delivered_at, Some(20));
        assert_eq!(receipts[0].created_at, 10);
        assert_eq!(receipts[0].read_at, Some(30));
        assert_eq!(receipts[0].replied_at, Some(40));
        assert_eq!(receipts[0].to, "bob");
        assert!(receipts[2].body.is_empty());
        let seen = server.requests();
        assert_eq!(seen[0].method, "GET");
        assert_eq!(seen[0].path, "/api/v1/bus/sent?limit=20");
    }

    #[test]
    fn sent_mail_decodes_rfc3339_receipt_timestamps() {
        let response = serde_json::from_str(r#"{"messages":[{"id":1042,"to":"bob","body":"reply",
            "created_at":"2026-11-19T10:21:00.123456+00:00","status":"replied",
            "delivered_at":"2026-11-19T10:21:01.234+00:00","read_at":"2026-11-19T10:21:02+00:00",
            "replied_at":"2026-11-19T15:21:03.456+05:00","in_reply_to":42},
            {"id":1043,"to":"*","body":"broadcast","created_at":"2026-11-19T10:21:02+00:00",
            "status":"sent","delivered_at":null,"read_at":null,"replied_at":null,"in_reply_to":null}]}"#)
            .unwrap();
        let (_server, cloud) = backend(vec![response]);
        let receipts = cloud.sent("me", 20).unwrap();
        assert_eq!(receipts[0].created_at, 1_795_083_660_123);
        assert_eq!(receipts[0].delivered_at, Some(1_795_083_661_234));
        assert_eq!(receipts[0].read_at, Some(1_795_083_662_000));
        assert_eq!(receipts[0].replied_at, Some(1_795_083_663_456));
        assert_eq!(receipts[0].reply_to, Some(42));
        assert_eq!(receipts[1].created_at, 1_795_083_662_000);
        assert_eq!(receipts[1].delivered_at, None);
        assert_eq!(receipts[1].read_at, None);
        assert_eq!(receipts[1].replied_at, None);
    }

    #[test]
    fn sent_mail_decrypts_direct_broadcast_and_labeled_reply_bodies() {
        const WORKSPACE: &str = "00000000-0000-0000-0000-000000000001";
        let key = crate::WorkspaceKey::from_entropy([19; 32]);
        let direct = key.encrypt(WORKSPACE, "body", "direct").unwrap();
        let broadcast = key.encrypt(WORKSPACE, "body", "broadcast").unwrap();
        let reply = key
            .encrypt(
                WORKSPACE,
                "body",
                r#"$lockyard_mail_v1:{"body":"reply","from_client":"sender-chat parent_pid=123"}"#,
            )
            .unwrap();
        let response = json!({"messages": [
            {"id":1,"to":"bob","body":direct,"created_at":"2026-11-19T10:21:00Z","status":"delivered",
             "delivered_at":"2026-11-19T10:21:01Z","read_at":null,"replied_at":null,"in_reply_to":null},
            {"id":2,"to":"*","body":broadcast,"created_at":1795083660000_i64,"status":"sent",
             "delivered_at":null,"read_at":null,"replied_at":null,"in_reply_to":null},
            {"id":3,"to":"bob","body":reply,"created_at":"2026-11-19T10:21:00Z","status":"sent",
             "delivered_at":null,"read_at":null,"replied_at":null,"in_reply_to":42},
            {"id":4,"to":"gone","body":"","created_at":"2026-11-19T10:21:00Z","status":"failed",
             "delivered_at":null,"read_at":null,"replied_at":null,"in_reply_to":null}
        ]});
        let server = FakeServer::start(vec![
            Reply::json(200, response.clone()),
            Reply::json(200, response),
        ]);
        for strict in [false, true] {
            let client = Client::new(&server.url(), "token".into())
                .unwrap()
                .with_content_encryption(WORKSPACE, Some(key.clone()), true);
            let client = if strict {
                client.require_e2ee_for(WORKSPACE).unwrap()
            } else {
                client
            };
            let cloud = CloudBackend::new(client, "me");
            let receipts = cloud.sent("me", 20).unwrap();
            assert_eq!(
                receipts
                    .iter()
                    .map(|row| row.body.as_str())
                    .collect::<Vec<_>>(),
                ["direct", "broadcast", "reply", ""]
            );
            assert_eq!(receipts[1].to, "*");
            assert_eq!(receipts[2].reply_to, Some(42));
            assert_eq!(receipts[3].status, bus::Delivery::Failed);
        }
    }

    #[test]
    fn a_read_of_the_inbox_never_writes() {
        let (server, mut cloud) = backend(vec![json!({"messages": []})]);
        cloud.inbox("me", InboxQuery::default(), 0).unwrap();
        assert_eq!(server.requests().len(), 1);
        assert_eq!(server.requests()[0].method, "GET");
    }

    #[test]
    fn an_answer_without_a_list_grants_what_was_asked() {
        assert_eq!(claimed_ids(json!({}), &[1, 2]).unwrap(), [1, 2]);
        assert_eq!(claimed_ids(json!({"ids": [2]}), &[1, 2]).unwrap(), [2]);
        assert_eq!(claimed_ids(json!([]), &[1, 2]).unwrap(), Vec::<i64>::new());
    }

    #[test]
    fn threads_overdue_and_undelivered() {
        let (server, cloud) = backend(vec![
            json!({"messages": [{"id": 1}]}),
            json!([{"id": 2, "needs": "ack"}]),
            json!([{"message_id": 3, "to": "bob", "age_seconds": 70}]),
        ]);
        assert_eq!(cloud.thread("me", 1).unwrap().len(), 1);
        assert_eq!(cloud.overdue("me").unwrap()[0].id, 2);
        assert_eq!(cloud.undelivered("me", 60).unwrap()[0].to, "bob");
        sees(
            &server,
            &[
                ("GET", "/api/v1/bus/threads/1"),
                ("GET", "/api/v1/bus/overdue"),
                ("GET", "/api/v1/bus/undelivered?older_than_seconds=60"),
            ],
        );
    }

    #[test]
    fn board_routes() {
        let (server, mut cloud) = backend(vec![
            json!({"key": "a/b", "value": "v"}),
            json!([{"key": "a/b", "value": "v", "zone": "api"}]),
            json!([{"key": "a/b", "value": 3}]),
            json!({}),
        ]);
        let write = BoardWrite {
            key: "a/b".into(),
            value: "v".into(),
            zone: Some("api".into()),
            ttl_minutes: Some(5),
        };
        assert_eq!(cloud.board_set("me", &write, 0).unwrap().text(), "v");
        assert_eq!(cloud.board_list(Some("api"), 0).unwrap().len(), 1);
        assert_eq!(cloud.board_get("a/b", 0).unwrap().unwrap().text(), "3");
        assert!(cloud.board_remove("me", "a/b").unwrap());
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/bus/board"),
                ("GET", "/api/v1/bus/board?zone=api"),
                ("GET", "/api/v1/bus/board"),
                ("DELETE", "/api/v1/bus/board/a%2Fb"),
            ],
        );
        assert_eq!(seen[0].body["ttl_minutes"], 5);
    }

    #[test]
    fn removing_an_absent_board_key_reads_as_false() {
        let server = FakeServer::start(vec![Reply::json(
            404,
            json!({"error": {"code":"not_found", "message": "no"}}),
        )]);
        let client = Client::new(&server.url(), "t".into()).unwrap();
        assert!(
            !CloudBackend::new(client, "me")
                .board_remove("me", "k")
                .unwrap()
        );
    }

    #[test]
    fn work_tasks_walk_every_transition() {
        let task = |status: &str, version: i64| json!({"id": 6, "status": status, "version": version, "to": "bob", "title": "t"});
        let actions = [
            (WorkAction::Claim, "claimed"),
            (WorkAction::Beat, "claimed"),
            (WorkAction::Done, "review"),
            (WorkAction::Reject, "claimed"),
            (WorkAction::Handoff, "offered"),
            (WorkAction::Take, "claimed"),
            (WorkAction::Done, "review"),
            (WorkAction::Accept, "accepted"),
            (WorkAction::Fail, "failed"),
            (WorkAction::Cancel, "cancelled"),
            (WorkAction::Decline, "offered"),
        ];
        let mut script = vec![task("offered", 1)];
        script.extend(
            actions
                .iter()
                .enumerate()
                .map(|(index, (_, status))| task(status, index as i64 + 2)),
        );
        script.push(json!([task("offered", 1)]));
        script.push(task("offered", 1));
        let (server, mut cloud) = backend(script);
        let offer = WorkOffer {
            title: "t".into(),
            to: "bob".into(),
            accept: "tests pass".into(),
            re: Some("D-1".into()),
            zone: Some("api".into()),
            brief: Some("b".into()),
        };
        assert_eq!(
            cloud.work_offer("me", &offer).unwrap().status,
            WorkStatus::Offered
        );
        let mut routes: Vec<String> = vec!["/api/v1/bus/tasks".into()];
        for (action, _) in actions {
            let step = WorkStep {
                version: (action == WorkAction::Take).then_some(4),
                to: (action == WorkAction::Handoff).then(|| "carol".to_string()),
                report: (action == WorkAction::Done).then(|| "done".to_string()),
                reason: (action == WorkAction::Reject).then(|| "no".to_string()),
                commits: if action == WorkAction::Done {
                    vec!["abc".into()]
                } else {
                    Vec::new()
                },
            };
            cloud.work_step("me", "BT-6", action, &step).unwrap();
            let tail = if action == WorkAction::Take {
                "?version=4"
            } else {
                ""
            };
            routes.push(format!("/api/v1/bus/tasks/BT-6/{}{tail}", action.as_str()));
        }
        assert_eq!(cloud.work_list("me").unwrap().len(), 1);
        assert_eq!(cloud.work_get("me", "BT-6").unwrap().title, "t");
        routes.push("/api/v1/bus/tasks".into());
        routes.push("/api/v1/bus/tasks/BT-6".into());
        let expected: Vec<(&str, &str)> = routes
            .iter()
            .enumerate()
            .map(|(index, route)| {
                (
                    if index + 2 >= routes.len() {
                        "GET"
                    } else {
                        "POST"
                    },
                    route.as_str(),
                )
            })
            .collect();
        let seen = sees(&server, &expected);
        assert_eq!(seen[3].body, json!({"report": "done", "commits": ["abc"]}));
        assert_eq!(seen[5].body, json!({"to": "carol"}));
        assert_eq!(seen[4].body, json!({"reason": "no"}));
    }

    #[test]
    fn take_refuses_to_go_without_a_version() {
        let (server, mut cloud) = backend(vec![]);
        assert!(
            cloud
                .work_step("me", "BT-1", WorkAction::Take, &WorkStep::default())
                .is_err()
        );
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_stale_version_is_a_conflict_that_names_it() {
        let body = json!({"error": {"code": "version_conflict", "message": "stale", "details": {"version": 9}}});
        let server = FakeServer::start(vec![Reply::json(409, body)]);
        let client = Client::new(&server.url(), "t".into()).unwrap();
        let mut cloud = CloudBackend::new(client, "me");
        let step = WorkStep {
            version: Some(1),
            ..WorkStep::default()
        };
        let error = cloud
            .work_step("me", "BT-1", WorkAction::Claim, &step)
            .unwrap_err();
        assert!(
            matches!(&error, Error::Cloud { code,status:Some(409),message,.. } if code=="version_conflict" && message.contains("version 9"))
        );
    }

    #[test]
    fn presence_carries_activity() {
        let (server, mut cloud) = backend(vec![
            json!({"server_time": 5}),
            json!({"sessions": [{"session": "me", "client": "cli", "last_seen": "t", "activity": {"tool_running": true, "state": "working"}}]}),
            json!([{"session": "bob"}]),
        ]);
        let beat = PresenceBeat {
            client: "cli".into(),
            model: Some("m".into()),
            activity: Some(SessionActivity {
                tool_running: true,
                tool_started_at: None,
                state: Some(SessionState::ApiFailure),
                meta: Some(json!({"pid": 1})),
            }),
            ..PresenceBeat::default()
        };
        cloud.heartbeat("me", &beat, 0).unwrap();
        let live = cloud.presence(60, 0).unwrap();
        assert_eq!(
            live[0].activity.as_ref().unwrap().state,
            Some(SessionState::Working)
        );
        assert_eq!(cloud.agents().unwrap()[0].id, "bob");
        let seen = sees(
            &server,
            &[
                ("POST", "/api/v1/presence"),
                ("GET", "/api/v1/presence?active_within=60"),
                ("GET", "/api/v1/presence?active_within=604800"),
            ],
        );
        assert_eq!(seen[0].body["activity"]["state"], "api_failure");
        assert_eq!(seen[0].body["activity"]["meta"]["pid"], 1);
    }

    #[test]
    fn both_event_streams_poll_with_their_own_routes() {
        let (server, cloud) = backend(vec![
            json!({"events": [{"seq": 9, "type": "zone.claimed", "payload": {"claim_id": 1}}]}),
            json!([{"seq": 3, "type": "registry.item", "payload": {}}]),
        ]);
        let coordination = EventQuery {
            after: 4,
            wait_seconds: 25,
            session: Some("me".into()),
            types: vec!["zone.claimed".into(), "bus.message".into()],
            ..EventQuery::default()
        };
        let page = cloud.events(&coordination).unwrap();
        assert_eq!(page.last_seq(4), 9);
        assert_eq!(page.events[0].field("claim_id"), Some(&json!(1)));
        let registry = EventQuery {
            stream: Stream::Registry,
            after: 2,
            ..EventQuery::default()
        };
        assert_eq!(cloud.events(&registry).unwrap().last_seq(2), 3);
        sees(
            &server,
            &[
                (
                    "GET",
                    "/api/v1/events?after=4&wait=25&session=me&types=zone.claimed%2Cbus.message",
                ),
                ("GET", "/api/v1/registry/events?after=2"),
            ],
        );
    }

    #[test]
    fn a_wait_past_the_protocol_limit_is_refused() {
        let (server, cloud) = backend(vec![]);
        let query = EventQuery {
            wait_seconds: 26,
            ..EventQuery::default()
        };
        assert!(matches!(cloud.events(&query), Err(Error::Invalid(_))));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn release_session_posts_to_the_encoded_name() {
        let (server, mut cloud) = backend(vec![json!({"session": "a/b", "released": true})]);
        let answer = cloud.release_session("me", "a/b").unwrap();
        assert_eq!(answer["released"], json!(true));
        sees(&server, &[("POST", "/api/v1/admin/sessions/a%2Fb/release")]);
    }

    #[test]
    fn export_freeze_and_import() {
        let (server, mut cloud) = backend(vec![
            json!({"claims": [], "messages": [{"id": 4, "seen_by": ["alice"]}], "board": [{"key": "k", "expires_at": "2027-01-01T00:00:00Z"}]}),
            json!({"frozen": true}),
            json!({"ok": true}),
            json!({"ok": true}),
        ]);
        let exported = cloud.export().unwrap();
        assert_eq!(exported["messages"][0]["seen_by"], json!(["alice"]));
        assert_eq!(exported["board"][0]["expires_at"], "2027-01-01T00:00:00Z");
        cloud
            .freeze(
                "me",
                &Freeze {
                    on: true,
                    reason: "switch".into(),
                },
            )
            .unwrap();
        cloud.import_zones("me", &json!({"zones": {}})).unwrap();
        let bus_dump = json!({"messages": [{"id": 4, "seen_by": ["alice"]}], "board": [{"key": "k", "expires_at": "2027-01-01T00:00:00Z"}]});
        cloud.import_bus("me", &bus_dump).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/export/coordination"),
                ("POST", "/api/v1/admin/freeze"),
                ("POST", "/api/v1/import/zones"),
                ("POST", "/api/v1/import/bus"),
            ],
        );
        assert_eq!(seen[1].body, json!({"on": true, "reason": "switch"}));
        assert_eq!(seen[2].body["catalog"], json!({"zones": {}}));
        assert_eq!(
            seen[3].body, bus_dump,
            "import must retain seen_by and board expiry"
        );
    }

    #[test]
    fn registry_create_and_import_limits_are_checked_before_requests() {
        let (server, mut cloud) = backend(vec![json!([])]);
        let too_long = tasks::TaskSpec {
            title: "t".into(),
            body: "é".repeat(4097),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &too_long, 0),
            Err(Error::Invalid(_))
        ));
        let too_long_evidence = tasks::TaskSpec {
            title: "t".into(),
            evidence: Some("x".repeat(1025)),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &too_long_evidence, 0),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            cloud.registry_import("me", &json!({"items": [{"legacy_raw": "x".repeat(8193)}]})),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            cloud.registry_import(
                "me",
                &json!({"items": [{"evidence": [{"value": "x".repeat(1025)}]}]})
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(cloud.registry_import("me", &json!({"items": [{"evidence": [{"value": "1"}, {"value": "2"}, {"value": "3"}, {"value": "4"}, {"value": "5"}]}]})), Err(Error::Invalid(_))));
        assert!(server.requests().is_empty());
    }

    #[test]
    fn triage_fills_ready_fields_from_flags_item_and_defaults() {
        let mut intake = item("intake", 3);
        intake["id"] = json!("D-7");
        intake["type"] = Value::Null;
        intake["target"] = Value::Null;
        intake["area_id"] = json!(AREA_ONE);
        let mut ready = intake.clone();
        ready["status"] = json!("ready");
        let (server, mut cloud) = backend(vec![intake, ready]);
        let triage = tasks::TaskTriage {
            kind: Some("housekeeping".into()),
            ..tasks::TaskTriage::default()
        };
        cloud.triage_task("me", "D-7", &triage).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/D-7"),
                ("POST", "/api/v1/registry/items/D-7/triage"),
            ],
        );
        let body = &seen[1].body;
        assert_eq!(body["type"], "housekeeping");
        assert_eq!(body["actor"], "agent");
        assert_eq!(body["area_id"], AREA_ONE);
        assert_eq!(body["priority"], "P1");
        assert_eq!(body["target"], "code_accepted");
        assert_eq!(body["verification"], "none");
        assert_eq!(body["expected_version"], 3);
    }

    const AREA_ONE: &str = "6f1c2a8e-0000-4000-8000-000000000001";
    const AREA_TWO: &str = "6f1c2a8e-0000-4000-8000-000000000002";

    fn legacy_areas() -> Value {
        json!({"areas": [
            {"id": AREA_ONE, "key": "legacy-one", "name": "One", "is_active": true, "prefix": "D"},
            {"id": AREA_TWO, "key": "legacy-two", "name": "Two", "is_active": true, "prefix": "D"},
            {"id": "6f1c2a8e-0000-4000-8000-000000000003", "key": "old", "name": "Old",
             "is_active": false, "prefix": "OLD"}
        ]})
    }

    fn intake_without_area() -> Value {
        let mut intake = item("intake", 4);
        intake["id"] = json!("D-8");
        intake["area_id"] = Value::Null;
        intake
    }

    #[test]
    fn triage_area_key_beats_a_shared_prefix_and_sends_its_uuid() {
        let mut ready = intake_without_area();
        ready["status"] = json!("ready");
        let (server, mut cloud) = backend(vec![intake_without_area(), legacy_areas(), ready]);
        let triage = tasks::TaskTriage {
            area: Some("legacy-two".into()),
            ..Default::default()
        };
        cloud.triage_task("me", "D-8", &triage).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/D-8"),
                ("GET", "/api/v1/registry/areas"),
                ("POST", "/api/v1/registry/items/D-8/triage"),
            ],
        );
        assert_eq!(seen[2].body["area_id"], AREA_TWO);
    }

    #[test]
    fn triage_refuses_an_ambiguous_or_inactive_area_without_writing() {
        for selector in ["D", "OLD"] {
            let (server, mut cloud) = backend(vec![intake_without_area(), legacy_areas()]);
            let triage = tasks::TaskTriage {
                area: Some(selector.into()),
                ..Default::default()
            };
            assert!(
                cloud.triage_task("me", "D-8", &triage).is_err(),
                "{selector}"
            );
            sees(
                &server,
                &[
                    ("GET", "/api/v1/registry/items/D-8"),
                    ("GET", "/api/v1/registry/areas"),
                ],
            );
        }
    }

    #[test]
    fn triage_refuses_a_blank_area_before_listing_areas() {
        for selector in ["", "   "] {
            let (server, mut cloud) = backend(vec![intake_without_area()]);
            let triage = tasks::TaskTriage {
                area: Some(selector.into()),
                ..Default::default()
            };
            let error = cloud.triage_task("me", "D-8", &triage).unwrap_err();
            assert!(matches!(error, Error::Invalid(_)), "{selector:?}");
            sees(&server, &[("GET", "/api/v1/registry/items/D-8")]);
        }
    }

    #[test]
    fn triage_area_matches_guid_forms_and_keys_like_the_registry() {
        let areas = json!({"areas": [
            {"id": AREA_ONE, "key": "платежи", "name": "One", "is_active": true, "prefix": "PAY"},
            {"id": AREA_TWO, "key": AREA_ONE, "name": "Two", "is_active": true, "prefix": "PLX"}
        ]});
        let cases = [
            ("6F1C2A8E000040008000000000000001", AREA_ONE),
            ("{6f1c2a8e-0000-4000-8000-000000000001}", AREA_ONE),
            ("платежи", AREA_ONE),
            ("PL", AREA_TWO),
        ];
        for (selector, expected) in cases {
            let mut ready = intake_without_area();
            ready["status"] = json!("ready");
            let (server, mut cloud) = backend(vec![intake_without_area(), areas.clone(), ready]);
            let triage = tasks::TaskTriage {
                area: Some(selector.into()),
                ..Default::default()
            };
            cloud.triage_task("me", "D-8", &triage).unwrap();
            let seen = sees(
                &server,
                &[
                    ("GET", "/api/v1/registry/items/D-8"),
                    ("GET", "/api/v1/registry/areas"),
                    ("POST", "/api/v1/registry/items/D-8/triage"),
                ],
            );
            assert_eq!(seen[2].body["area_id"], expected, "{selector}");
        }
        assert_eq!(guid_canon("{6F1C2A8E000040008000000000000001}"), None);
        assert_eq!(guid_canon("D"), None);
    }

    #[test]
    fn triage_area_keeps_unicode_folding_apart_and_uses_the_prefix_like_the_registry() {
        // OrdinalIgnoreCase keeps "straße" and "STRASSE" apart, so the prefix decides.
        let areas = json!({"areas": [
            {"id": AREA_ONE, "key": "straße", "name": "One", "is_active": true, "prefix": "GER"},
            {"id": AREA_TWO, "key": "roads", "name": "Two", "is_active": true, "prefix": "STRASSE"}
        ]});
        let mut ready = intake_without_area();
        ready["status"] = json!("ready");
        let (server, mut cloud) = backend(vec![intake_without_area(), areas, ready]);
        let triage = tasks::TaskTriage {
            area: Some("STRASSE".into()),
            ..Default::default()
        };
        cloud.triage_task("me", "D-8", &triage).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/D-8"),
                ("GET", "/api/v1/registry/areas"),
                ("POST", "/api/v1/registry/items/D-8/triage"),
            ],
        );
        assert_eq!(seen[2].body["area_id"], AREA_TWO);
    }

    #[test]
    fn triage_refuses_selectors_the_registry_could_read_differently() {
        let areas = json!({"areas": [
            {"id": AREA_ONE, "key": "платежи", "name": "One", "is_active": true, "prefix": "PAY"},
            {"id": AREA_TWO, "key": "ſtop", "name": "Two", "is_active": true, "prefix": "STP"}
        ]});
        // Upper-case Cyrillic and a long s fold onto keys only on the server.
        for selector in ["ПЛАТЕЖИ", "STOP"] {
            let (server, mut cloud) = backend(vec![intake_without_area(), areas.clone()]);
            let triage = tasks::TaskTriage {
                area: Some(selector.into()),
                ..Default::default()
            };
            let error = cloud.triage_task("me", "D-8", &triage).unwrap_err();
            assert!(matches!(error, Error::Invalid(_)), "{selector}");
            sees(
                &server,
                &[
                    ("GET", "/api/v1/registry/items/D-8"),
                    ("GET", "/api/v1/registry/areas"),
                ],
            );
        }
        // Guid.TryParse reads the X format; it is refused before areas are listed.
        let x = "{0x6f1c2a8e,0x0000,0x4000,{0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x01}}";
        let (server, mut cloud) = backend(vec![intake_without_area()]);
        let triage = tasks::TaskTriage {
            area: Some(x.into()),
            ..Default::default()
        };
        let error = cloud.triage_task("me", "D-8", &triage).unwrap_err();
        assert!(matches!(error, Error::Invalid(_)));
        sees(&server, &[("GET", "/api/v1/registry/items/D-8")]);
    }

    #[test]
    fn triage_never_guesses_or_creates_an_area_and_checks_p0_first() {
        let (server, mut cloud) = backend(vec![intake_without_area()]);
        let error = cloud
            .triage_task("me", "D-8", &tasks::TaskTriage::default())
            .unwrap_err();
        assert!(matches!(error, Error::Invalid(_)));
        sees(&server, &[("GET", "/api/v1/registry/items/D-8")]);

        let (server, mut cloud) = backend(vec![intake_without_area()]);
        let triage = tasks::TaskTriage {
            priority: Some("P0".into()),
            area: Some("legacy-one".into()),
            ..Default::default()
        };
        let error = cloud.triage_task("me", "D-8", &triage).unwrap_err();
        assert!(matches!(error, Error::Invalid(_)));
        sees(&server, &[("GET", "/api/v1/registry/items/D-8")]);
    }

    #[test]
    fn triage_refuses_items_that_left_intake_without_writing() {
        let (server, mut cloud) = backend(vec![item("ready", 2)]);
        let error = cloud
            .triage_task("me", "G-SG-0012", &tasks::TaskTriage::default())
            .unwrap_err();
        assert!(matches!(error, Error::Invalid(_)));
        sees(&server, &[("GET", "/api/v1/registry/items/G-SG-0012")]);
    }

    #[test]
    fn requests_for_the_active_session_use_the_new_list_route() {
        let (server, cloud) = backend(vec![
            json!({"requests": [{"id": 4, "from": "me", "text": "please"}]}),
        ]);
        assert_eq!(cloud.zone_requests("me").unwrap()[0].id, 4);
        let seen = sees(&server, &[("GET", "/api/v1/zones/requests")]);
        assert_eq!(seen[0].header("x-lockyard-session"), Some("me"));
    }

    fn item_target(status: &str, version: i64, target: &str) -> Value {
        let mut value = item(status, version);
        value["target"] = json!(target);
        value
    }

    fn item(status: &str, version: i64) -> Value {
        json!({
            "id": "G-SG-0012", "title": "t", "body": "b", "status": status, "priority": "P1", "version": version,
            "target": "ci_passed", "created_by": "token:ab:writer",
            "created_at": "2026-11-02T10:00:00+00:00", "updated_at": "2026-11-02T10:00:00+00:00",
            "assignment": {"executor": "token:ab:s:1", "lease_expires_at": "2026-11-02T12:00:00+00:00"},
            "evidence": [{"value": "run 5"}],
        })
    }

    #[test]
    fn status_assigned_tasks_only_queries_assignment_statuses_when_empty() {
        let (server, cloud) = backend(vec![
            json!({"items": [], "cursor": null}),
            json!({"items": [], "cursor": null}),
        ]);
        assert!(cloud.assigned_tasks("me").unwrap().is_empty());
        sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items?status=active&limit=200"),
                ("GET", "/api/v1/registry/items?status=review&limit=200"),
            ],
        );
    }

    #[test]
    fn status_assigned_tasks_filters_foreign_and_unassigned_items() {
        let assigned = |id: &str, status: &str, session: &str| {
            let mut value = item(status, 1);
            value["id"] = json!(id);
            value["assignment"]["executor"] = json!(format!("token:ab:{session}"));
            value
        };
        let mut unassigned = item("active", 1);
        unassigned["assignment"] = Value::Null;
        let (server, cloud) = backend(vec![
            json!({"items": [
                assigned("D-1", "active", "me"),
                assigned("D-2", "active", "other"),
                unassigned,
            ]}),
            json!({"items": [
                assigned("D-3", "review", "other"),
                assigned("D-4", "review", "me"),
            ]}),
        ]);
        let tasks = cloud.assigned_tasks("me").unwrap();
        assert_eq!(
            tasks
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            ["D-1", "D-4"]
        );
        assert_eq!(tasks[0].status, tasks::Status::Claimed);
        assert_eq!(tasks[1].status, tasks::Status::Review);
        assert!(
            tasks
                .iter()
                .all(|task| task.assignee.as_deref() == Some("me"))
        );
        sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items?status=active&limit=200"),
                ("GET", "/api/v1/registry/items?status=review&limit=200"),
            ],
        );
    }

    #[test]
    fn status_assigned_tasks_follows_each_filtered_status_cursor() {
        let assigned = |id: &str, status: &str| {
            let mut value = item(status, 1);
            value["id"] = json!(id);
            value["assignment"]["executor"] = json!("token:ab:me");
            value
        };
        let (server, cloud) = backend(vec![
            json!({"items": [assigned("D-1", "active")], "cursor": "active/next"}),
            json!({"items": [assigned("D-2", "active")], "cursor": null}),
            json!({"items": [assigned("D-3", "review")], "cursor": "review/next"}),
            json!({"items": [assigned("D-4", "review")], "cursor": null}),
        ]);
        assert_eq!(
            cloud
                .assigned_tasks("me")
                .unwrap()
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            ["D-1", "D-2", "D-3", "D-4"]
        );
        sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items?status=active&limit=200"),
                (
                    "GET",
                    "/api/v1/registry/items?status=active&limit=200&cursor=active%2Fnext",
                ),
                ("GET", "/api/v1/registry/items?status=review&limit=200"),
                (
                    "GET",
                    "/api/v1/registry/items?status=review&limit=200&cursor=review%2Fnext",
                ),
            ],
        );
    }

    #[test]
    fn cloud_task_numeric_alias_preserves_all_explicit_area_prefixes() {
        let cases = [
            ("12", "D-12"),
            ("0012", "D-12"),
            ("D-12", "D-12"),
            ("FE-0319", "FE-0319"),
            ("PA-0001", "PA-0001"),
            ("G-SG-0012", "G-SG-0012"),
        ];
        let replies = cases
            .iter()
            .map(|(_, id)| {
                let mut value = item("ready", 1);
                value["id"] = json!(id);
                value
            })
            .collect();
        let (server, cloud) = backend(replies);
        for (requested, canonical) in cases {
            assert_eq!(cloud.task(requested).unwrap().id, canonical);
        }
        sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/D-12"),
                ("GET", "/api/v1/registry/items/D-12"),
                ("GET", "/api/v1/registry/items/D-12"),
                ("GET", "/api/v1/registry/items/FE-0319"),
                ("GET", "/api/v1/registry/items/PA-0001"),
                ("GET", "/api/v1/registry/items/G-SG-0012"),
            ],
        );
    }

    #[test]
    fn workflow_claim_receipt_keeps_the_mutation_assignment_and_legacy_numeric_id() {
        let mut before = item("ready", 3);
        before["id"] = json!("D-12");
        let mut claimed = item("active", 4);
        claimed["id"] = json!("D-12");
        claimed["assignment"] = json!({
            "executor": "token:ab:me",
            "session": "me",
            "claimed_at": "2026-11-02T10:00:00+00:00",
            "lease_expires_at": "2026-11-02T12:00:00+00:00",
            "lease_active": true,
        });
        let assignment = claimed["assignment"].clone();
        let (server, mut cloud) = backend(vec![before, claimed]);
        let receipt = cloud.claim_task_receipt_by_id("me", "D-12", 60, 0).unwrap();
        assert_eq!(receipt["id"], "D-12");
        assert_eq!(receipt["raw_status"], "active");
        assert_eq!(receipt["registry_assignment"], assignment);
        assert_eq!(receipt["registry_assignment_source"], "claim_response");
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/D-12"),
                ("POST", "/api/v1/registry/items/D-12/claim"),
            ],
        );
        assert_eq!(seen[1].body["expected_version"], 3);
    }

    #[test]
    fn workflow_string_claim_receipt_preserves_area_identity_and_mutation_assignment() {
        let mut before = item("ready", 7);
        before["id"] = json!("FE-0319");
        let mut claimed = item("active", 8);
        claimed["id"] = json!("FE-0319");
        claimed["assignment"] = json!({
            "executor": "token:ab:me",
            "session": "me",
            "claimed_at": "2026-11-02T10:00:00+00:00",
            "lease_expires_at": "2026-11-02T12:00:00+00:00",
            "lease_active": true,
        });
        let assignment = claimed["assignment"].clone();
        let (server, mut cloud) = backend(vec![before, claimed]);
        let receipt = cloud
            .claim_task_receipt_by_id("me", "FE-0319", 60, 0)
            .unwrap();
        assert_eq!(receipt["id"], "FE-0319");
        assert_eq!(receipt["raw_status"], "active");
        assert_eq!(receipt["registry_assignment"], assignment);
        assert_eq!(receipt["registry_assignment_source"], "claim_response");
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/FE-0319"),
                ("POST", "/api/v1/registry/items/FE-0319/claim"),
            ],
        );
        assert_eq!(seen[1].body["expected_version"], 7);
    }

    #[test]
    fn workflow_string_claim_receipt_keeps_an_unrelated_mutation_identity_visible() {
        let mut before = item("ready", 7);
        before["id"] = json!("FE-0319");
        let mut claimed = item("active", 8);
        claimed["id"] = json!("PA-0001");
        let (_server, mut cloud) = backend(vec![before, claimed]);
        let receipt = cloud
            .claim_task_receipt_by_id("me", "FE-0319", 60, 0)
            .unwrap();
        assert_eq!(receipt["id"], "PA-0001");
    }

    #[test]
    fn workflow_claim_receipt_does_not_hide_an_unrelated_mutation_result() {
        let mut before = item("ready", 3);
        before["id"] = json!("D-12");
        let mut claimed = item("active", 4);
        claimed["id"] = json!("D-13");
        let (_server, mut cloud) = backend(vec![before, claimed]);
        let receipt = cloud.claim_task_receipt_by_id("me", "D-12", 60, 0).unwrap();
        assert_eq!(receipt["id"], "D-13");
    }

    #[test]
    fn ready_registry_listing_filters_by_area_and_preserves_details_in_priority_stage_order() {
        let mut ready = item("ready", 1);
        ready["acceptance"] = json!("tests pass");
        ready["links"] = json!([{"kind": "blocks", "to": "FE-0002"}]);
        ready["evidence"] = json!([{"kind": "ci_run", "value": "green"}]);
        let (server, cloud) = backend(vec![json!([ready])]);
        let tasks = cloud.ready_tasks(Some("flexengine")).unwrap();
        assert_eq!(tasks[0].acceptance.as_deref(), Some("tests pass"));
        assert_eq!(tasks[0].links[0]["to"], "FE-0002");
        assert_eq!(tasks[0].registry_evidence[0]["value"], "green");
        sees(
            &server,
            &[("GET", "/api/v1/registry/ready?area=flexengine&limit=100")],
        );
    }

    #[test]
    fn registry_batch_close_uses_the_server_batch_route_and_shared_evidence() {
        let (server, mut cloud) = backend(vec![
            item("ready", 1),
            item("ready", 1),
            json!({"results": [{"id": "FE-1", "changed": true}, {"id": "FE-2", "changed": true}]}),
        ]);
        cloud
            .batch_close_tasks("me", &["FE-1".into(), "FE-2".into()], "owner decision", 0)
            .unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/FE-1"),
                ("GET", "/api/v1/registry/items/FE-2"),
                ("POST", "/api/v1/registry/items/batch-transition"),
            ],
        );
        assert_eq!(seen[2].body["ids"], json!(["FE-1", "FE-2"]));
        assert_eq!(seen[2].body["to"], "done");
        assert_eq!(seen[2].body["evidence"]["value"], "owner decision");
        assert_eq!(seen[2].body["evidence"]["expected_version"], Value::Null);
    }

    #[test]
    fn repeating_a_registry_batch_close_reports_final_items_without_a_second_transition() {
        let mut done = item("done", 5);
        done["id"] = json!("FE-1");
        let (server, mut cloud) = backend(vec![done]);
        let result = cloud
            .batch_close_tasks("me", &["FE-1".into()], "already completed", 0)
            .unwrap();
        assert_eq!(result["results"][0]["changed"], false);
        assert_eq!(result["results"][0]["id"], "FE-1");
        sees(&server, &[("GET", "/api/v1/registry/items/FE-1")]);
    }

    #[test]
    fn registry_block_and_unblock_use_versioned_transition_routes() {
        let (server, mut cloud) = backend(vec![
            item("active", 3),
            item("blocked", 4),
            item("blocked", 4),
            item("ready", 5),
        ]);
        cloud
            .block_task("me", "G-SG-0012", true, "waiting", 0)
            .unwrap();
        cloud
            .block_task("me", "G-SG-0012", false, "resolved", 0)
            .unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/G-SG-0012"),
                ("POST", "/api/v1/registry/items/G-SG-0012/transition"),
                ("GET", "/api/v1/registry/items/G-SG-0012"),
                ("POST", "/api/v1/registry/items/G-SG-0012/transition"),
            ],
        );
        assert_eq!(seen[1].body["to"], "blocked");
        assert_eq!(seen[1].body["expected_version"], 3);
        assert_eq!(seen[3].body["to"], "ready");
        assert_eq!(seen[3].body["expected_version"], 4);
    }

    #[test]
    fn area_update_uses_the_existing_post_upsert_route() {
        let (server, mut cloud) = backend(vec![
            json!([{"id": "a1", "key": "flexengine", "name": "Flex", "prefix": "FE", "pad": 4}]),
            json!({"key": "flexengine", "name": "FLEX Engine", "prefix": "FE", "pad": 4}),
        ]);
        cloud
            .area_update("me", "flexengine", &json!({"name": "FLEX Engine"}))
            .unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/areas"),
                ("POST", "/api/v1/registry/areas"),
            ],
        );
        assert_eq!(seen[1].body["name"], "FLEX Engine");
        assert_eq!(seen[1].body["prefix"], "FE");
    }

    #[test]
    fn a_new_item_sets_its_urgency_and_finds_an_area() {
        let (server, mut cloud) = backend(vec![
            json!([{"id": "a1", "key": "api"}, {"id": "a2", "key": "web"}]),
            item("ready", 1),
        ]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            priority: Some("P1".into()),
            area: Some("web".into()),
            ..tasks::TaskSpec::default()
        };
        let task = cloud.add_task("me", &spec, 0).unwrap();
        assert_eq!(
            (task.id.as_str(), task.priority.as_deref()),
            ("G-SG-0012", Some("P1"))
        );
        assert_eq!(task.status, tasks::Status::Open);
        assert_eq!(task.author, "writer");
        assert_eq!(task.assignee.as_deref(), Some("s:1"));
        assert_eq!(task.evidence.as_deref(), Some("run 5"));
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/areas"),
                ("POST", "/api/v1/registry/items"),
            ],
        );
        let body = &seen[1].body;
        assert_eq!(body["area_id"], "a2");
        assert_eq!(body["priority"], "P1");
        assert_eq!(body["type"], "code");
        assert_eq!(body["target"], "code_accepted");
        assert_eq!(body["client_key"].as_str().unwrap().len(), 26);
    }

    #[test]
    fn legacy_task_creation_omits_paths_and_preserves_area_lookup() {
        let (server, mut cloud) =
            backend(vec![json!([{"id":"a1", "key":"web"}]), item("ready", 1)]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            area: Some("web".into()),
            paths: vec!["web/src/main.rs".into()],
            ..tasks::TaskSpec::default()
        };
        assert!(!cloud.registry_auto_area().unwrap());
        cloud.add_task("me", &spec, 0).unwrap();
        let seen = sees(
            &server,
            &[("GET", "/api/v1/registry/areas"), ("POST", ITEMS)],
        );
        assert_eq!(seen[1].body["area_id"], "a1");
        assert!(seen[1].body.get("paths").is_none());
        assert!(seen[1].body.get("area").is_none());
    }

    #[test]
    fn task_paths_are_retained_when_returned_and_absent_for_legacy_tasks() {
        let mut row = item("ready", 1);
        row["paths"] = json!(["web/src/main.rs", "web/tests"]);
        let task = task_from(&row).unwrap();
        assert_eq!(task.paths, ["web/src/main.rs", "web/tests"]);
        assert_eq!(serde_json::to_value(task).unwrap()["paths"], row["paths"]);
        assert!(
            serde_json::to_value(task_from(&item("ready", 1)).unwrap())
                .unwrap()
                .get("paths")
                .is_none()
        );
    }

    #[test]
    fn a_new_item_can_select_an_existing_area_by_prefix() {
        let (server, mut cloud) = backend(vec![
            json!([{"id": "a1", "key": "flexengine", "prefix": "FE"},
                  {"id": "a2", "key": "platform", "prefix": "PA"}]),
            item("ready", 1),
        ]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            area: Some("PA".into()),
            prefix: Some("PA".into()),
            ..tasks::TaskSpec::default()
        };
        cloud.add_task("me", &spec, 0).unwrap();
        let seen = server.requests();
        assert_eq!(seen[1].body["area_id"], "a2");
        assert_eq!(
            seen.len(),
            2,
            "an existing area should not be created again"
        );
    }

    #[test]
    fn a_new_item_with_only_prefix_selects_the_matching_area_not_the_first() {
        let (server, mut cloud) = backend(vec![
            json!([{"id":"a1", "key":"flexengine", "prefix":"FE"},
                {"id":"a2", "key":"platform", "prefix":"PA"}]),
            item("ready", 1),
        ]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            prefix: Some("pa".into()),
            ..tasks::TaskSpec::default()
        };
        cloud.add_task("me", &spec, 0).unwrap();
        let seen = server.requests();
        assert_eq!(seen.len(), 2, "an existing area must not be created again");
        assert_eq!(seen[1].body["area_id"], "a2");
    }

    #[test]
    fn a_new_item_with_unknown_prefix_does_not_fall_back_to_another_area() {
        let (server, mut cloud) = backend(vec![
            json!([{"id":"a1", "key":"flexengine", "prefix":"FE"}]),
        ]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            prefix: Some("PA".into()),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &spec, 0),
            Err(Error::NotFound(_))
        ));
        assert_eq!(
            server.requests().len(),
            1,
            "an unknown prefix must not create a task in another area"
        );
    }

    #[test]
    fn a_new_item_explicit_area_takes_precedence_over_prefix() {
        let (server, mut cloud) = backend(vec![
            json!([{"id":"a1", "key":"flexengine", "prefix":"FE"},
                {"id":"a2", "key":"platform", "prefix":"PA"}]),
            item("ready", 1),
        ]);
        let spec = tasks::TaskSpec {
            title: "t".into(),
            area: Some("flexengine".into()),
            prefix: Some("PA".into()),
            ..tasks::TaskSpec::default()
        };
        cloud.add_task("me", &spec, 0).unwrap();
        assert_eq!(server.requests()[1].body["area_id"], "a1");
    }

    #[test]
    fn a_new_item_refuses_targets_the_client_cannot_prove_before_sending_it() {
        struct UnexpectedTransport;
        impl Transport for UnexpectedTransport {
            fn call(&self, _: &Call) -> std::result::Result<Value, ClientError> {
                panic!("unsupported targets must be rejected before any server call")
            }
        }
        let mut cloud = CloudBackend::new(UnexpectedTransport, "me");
        for target in [
            "deployed_staging",
            "deployed_prod",
            "verified_prod",
            "owner_decision",
            "external_confirmation",
        ] {
            let spec = tasks::TaskSpec {
                title: "t".into(),
                target: Some(target.into()),
                ..tasks::TaskSpec::default()
            };
            assert!(matches!(
                cloud.add_task("me", &spec, 0),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn an_unknown_area_is_refused_and_a_workspace_without_one_gets_the_default() {
        let (_server, mut cloud) = backend(vec![json!([])]);
        let named = tasks::TaskSpec {
            title: "t".into(),
            area: Some("nope".into()),
            ..tasks::TaskSpec::default()
        };
        assert!(matches!(
            cloud.add_task("me", &named, 0),
            Err(Error::NotFound(_))
        ));
        let (server, mut cloud) = backend(vec![json!([]), json!({"id": "new"}), item("ready", 1)]);
        let plain = tasks::TaskSpec {
            title: "t".into(),
            prefix: Some("FE".into()),
            pad: Some(4),
            ..tasks::TaskSpec::default()
        };
        cloud.add_task("me", &plain, 0).unwrap();
        let seen = server.requests();
        assert_eq!(seen[1].body["key"], "general");
        assert_eq!(seen[1].body["prefix"], "FE");
        assert_eq!(seen[1].body["pad"], 4);
        assert_eq!(seen[2].body["area_id"], "new");
    }

    #[test]
    fn a_submission_proves_first_and_each_step_carries_the_version_it_read() {
        let (server, mut cloud) = backend(vec![
            item("active", 3),
            item("active", 4),
            item("active", 4),
            item("review", 5),
        ]);
        cloud.submit_task("me", "G-SG-0012", "run 5", 0).unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/items/G-SG-0012"),
                ("POST", "/api/v1/registry/items/G-SG-0012/evidence"),
                ("GET", "/api/v1/registry/items/G-SG-0012"),
                ("POST", "/api/v1/registry/items/G-SG-0012/transition"),
            ],
        );
        assert_eq!(seen[1].body["expected_version"], 3);
        assert_eq!(seen[1].body["kind"], "ci_run");
        assert_eq!(
            seen[3].body,
            json!({"to": "review", "reason": "submitted for review", "expected_version": 4})
        );
    }

    #[test]
    fn a_bare_commit_is_refused_before_accept_and_revoking_done_sends_the_new_file() {
        let (server, mut cloud) = backend(vec![item_target("active", 3, "code_accepted")]);
        assert!(matches!(
            cloud.submit_task("me", "G-SG-0012", "25fb94b", 0),
            Err(Error::Invalid(_))
        ));
        assert!(server.requests().iter().all(|call| call.method == "GET"));

        let (server, mut cloud) = backend(vec![item_target("done", 7, "code_accepted")]);
        assert!(
            cloud
                .reject_task("me", "G-SG-0012", "empty commit", "", 0)
                .is_err()
        );
        assert!(server.requests().iter().all(|call| call.method == "GET"));

        let (server, mut cloud) = backend(vec![
            item_target("done", 7, "code_accepted"),
            item_target("ready", 8, "code_accepted"),
        ]);
        cloud
            .reject_task("me", "G-SG-0012", "empty commit", "48bbf9a:src/Game.cs", 0)
            .unwrap();
        let seen = server.requests();
        let transition = seen
            .iter()
            .find(|call| call.method == "POST" && call.path.ends_with("/transition"))
            .expect("revoke posts a transition");
        assert_eq!(transition.body["to"], "ready");
        assert_eq!(transition.body["reason"], "empty commit");
        assert_eq!(transition.body["evidence"]["value"], "48bbf9a:src/Game.cs");
        assert_eq!(transition.body["evidence"]["kind"], "commit");
    }

    #[test]
    fn listing_walks_every_page_and_hides_final_items() {
        let (server, cloud) = backend(vec![
            json!({"items": [item("ready", 1)], "cursor": "7"}),
            json!({"items": [item("done", 1)], "cursor": null}),
        ]);
        assert_eq!(cloud.tasks(None, false).unwrap().len(), 1);
        let seen = server.requests();
        assert_eq!(seen[1].path, "/api/v1/registry/items?limit=200&cursor=7");
    }

    #[test]
    fn a_file_missing_from_a_known_revision_is_refused() {
        let dir = std::env::temp_dir().join(format!("ly-evidence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success(), "{args:?}");
        };
        git(&["init"]);
        git(&["config", "user.email", "dev@example.com"]);
        git(&["config", "user.name", "dev"]);
        std::fs::write(dir.join("kept.txt"), "ok").unwrap();
        git(&["add", "kept.txt"]);
        git(&["commit", "-m", "keep"]);
        let rev = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let short = &rev.trim()[..7];
        assert!(refuse_if_file_missing(&dir, &format!("{short}:kept.txt")).is_ok());
        let missing = refuse_if_file_missing(&dir, &format!("{short}:gone.txt")).unwrap_err();
        assert!(missing.to_string().contains("not in revision"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_reads_the_session_out_of_the_identity() {
        let (_server, cloud) = backend(vec![json!([
            {"actor": "token:ab:bob", "op": "claimed", "reason": null, "at": "2026-11-02T10:00:00+00:00"}
        ])]);
        let history = cloud.task_history("G-SG-0012").unwrap();
        assert_eq!(
            (history[0].agent.as_str(), history[0].action.as_str()),
            ("bob", "claimed")
        );
    }

    #[test]
    fn tokens_use_the_registry_routes() {
        let (server, mut cloud) = backend(vec![json!([]), json!({"raw": "x"}), json!({})]);
        cloud.tokens().unwrap();
        let request = TokenRequest {
            name: "n".into(),
            role: "agent".into(),
            expires_at: "2027-01-01T00:00:00.000Z".into(),
        };
        assert_eq!(cloud.token_create("me", &request).unwrap()["raw"], "x");
        cloud.token_revoke("me", "abc").unwrap();
        let seen = sees(
            &server,
            &[
                ("GET", "/api/v1/registry/tokens"),
                ("POST", "/api/v1/registry/tokens"),
                ("POST", "/api/v1/registry/tokens/abc/revoke"),
            ],
        );
        assert_eq!(seen[1].body["role"], "agent");
    }

    #[derive(Default)]
    struct CreationFaults {
        calls: std::sync::Mutex<Vec<Call>>,
        found: bool,
        retry_succeeds: bool,
        socket_loss: bool,
        acknowledged: std::sync::atomic::AtomicBool,
    }
    impl Transport for CreationFaults {
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(call.clone());
            if call.path == AREAS {
                return Ok(json!([{"id":"area","key":"web"}]));
            }
            let creates: Vec<_> = calls.iter().filter(|c| c.method == "POST").collect();
            if call.path == ITEMS {
                if self.retry_succeeds && creates.len() == 2 {
                    return Ok(item("ready", 1));
                }
                if self.socket_loss {
                    return Err(ClientError::Transport("agent socket reply lost".into()));
                }
                let pending = serde_json::from_value(json!({
                    "code":"outcome_unknown","cause_code":"connection_lost_after_commit",
                    "cause_status":null,"protocol":{"selected":2,"capabilities":[]},
                    "method":call.method,"path":call.path,"request_path":call.path,
                    "body":call.body.as_ref().map(Value::to_string),"key":call.key,
                    "repository":null,"session":call.session,"origin":"http://fixture",
                    "credential_scope":"fixture"
                }))
                .unwrap();
                return Err(ClientError::OutcomeUnknown(Box::new(pending)));
            }
            let key = creates[0].body.as_ref().unwrap()["client_key"].clone();
            assert_eq!(
                call.path,
                format!("{ITEMS}?client_key={}", key.as_str().unwrap())
            );
            let mut row = item("ready", 1);
            row["client_key"] = if self.found {
                key
            } else {
                json!("unrelated-key")
            };
            Ok(json!({"items":[row]}))
        }
        fn acknowledge_write(&self, call: &Call) -> std::result::Result<(), ClientError> {
            assert_eq!(
                call.key,
                self.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|c| c.method == "POST")
                    .unwrap()
                    .key
            );
            self.acknowledged
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn task_creation_retries_exact_request_then_reconciles_by_client_key() {
        for (found, retry_succeeds, socket_loss) in [
            (true, false, false),
            (false, false, false),
            (false, true, false),
            (true, false, true),
        ] {
            let transport = std::sync::Arc::new(CreationFaults {
                found,
                retry_succeeds,
                socket_loss,
                ..Default::default()
            });
            let mut cloud = CloudBackend::new(transport.clone(), "alice");
            let result = cloud.add_task(
                "alice",
                &tasks::TaskSpec {
                    title: "same title".into(),
                    area: Some("web".into()),
                    ..Default::default()
                },
                0,
            );
            if found || retry_succeeds {
                assert_eq!(result.unwrap().id.as_str(), "G-SG-0012");
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), "task_create_unconfirmed");
                assert!(!error.to_string().contains("created=unknown"));
                assert!(error.to_string().contains("client_key="));
            }
            let calls = transport.calls.lock().unwrap();
            let posts: Vec<_> = calls.iter().filter(|c| c.method == "POST").collect();
            assert_eq!(posts.len(), 2);
            assert_eq!(posts[0], posts[1]);
            assert!(posts[0].key.is_some());
            assert_eq!(
                calls
                    .iter()
                    .filter(|c| c.path.contains("?client_key="))
                    .count(),
                usize::from(!retry_succeeds)
            );
            assert_eq!(
                transport
                    .acknowledged
                    .load(std::sync::atomic::Ordering::SeqCst),
                found
            );
        }
    }

    struct ZoneEvents {
        push: bool,
        states: std::sync::Mutex<std::collections::VecDeque<&'static str>>,
        calls: std::sync::Mutex<Vec<Call>>,
    }
    impl Transport for ZoneEvents {
        fn mail_push_v1(&self, _: &str) -> std::result::Result<bool, ClientError> {
            Ok(self.push)
        }
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            if call.path.starts_with("/api/v1/events?") {
                self.calls.lock().unwrap().push(call.clone());
                return if call.path.contains("after=0&") {
                    Ok(json!({"events":[{"seq":42,"type":"zone.taken","payload":{}}]}))
                } else {
                    Ok(json!({"events":[]}))
                };
            }
            assert_eq!(call.path, "/api/v1/zones/check");
            assert_eq!(
                call.body.as_ref().unwrap()["mode"],
                "exclusive",
                "shared checks can permit a foreign holder"
            );
            self.calls.lock().unwrap().push(call.clone());
            let state = self.states.lock().unwrap().pop_front().unwrap_or("held");
            Ok(json!({"paths":[{"path":"src","status":state}]}))
        }
        fn event_stream_sessions(
            &self,
            _: &str,
            _: &[String],
            after: i64,
            _: std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) -> std::result::Result<crate::sse::EventStream, ClientError> {
            assert!(self.push);
            assert_eq!(after, 42);
            assert_eq!(self.calls.lock().unwrap().len(), 2, "no check before ready");
            let bytes =
                b"id: 42\nevent: ready\ndata: {\"head\":42}\n\nid: 1\nevent: zone.taken\ndata: {}\n\nid: 2\nevent: zone.released\ndata: {}\n\n"
                    .to_vec();
            Ok(crate::sse::EventStream::new(Box::new(
                std::io::Cursor::new(bytes),
            )))
        }
    }
    #[test]
    fn zone_wait_free_uses_events_and_old_server_does_not_poll_before_ten_seconds() {
        use std::time::Duration;
        let cloud = CloudBackend::new(
            ZoneEvents {
                push: true,
                states: std::sync::Mutex::new(["held", "held", "free"].into()),
                calls: Default::default(),
            },
            "alice",
        );
        assert!(
            cloud
                .wait_zone_free("alice", "src", Duration::from_secs(1))
                .unwrap()
        );
        assert_eq!(cloud.transport.calls.lock().unwrap().len(), 5);
        let cloud = CloudBackend::new(
            ZoneEvents {
                push: false,
                states: Default::default(),
                calls: Default::default(),
            },
            "alice",
        );
        assert!(
            !cloud
                .wait_zone_free("alice", "src", Duration::from_millis(20))
                .unwrap()
        );
        assert_eq!(cloud.transport.calls.lock().unwrap().len(), 1);
        let cloud = CloudBackend::new(
            ZoneEvents {
                push: true,
                states: std::sync::Mutex::new(["own"].into()),
                calls: Default::default(),
            },
            "alice",
        );
        assert!(
            cloud
                .wait_zone_free("alice", "src", Duration::ZERO)
                .unwrap()
        );
    }

    #[test]
    fn zone_wait_free_quiet_sse_five_controlled_minutes_never_polls_and_stops_reader() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        };
        use std::time::{Duration, Instant};
        struct Quiet {
            stopped: Arc<AtomicBool>,
            seconds: Arc<AtomicU64>,
            ready: std::io::Cursor<Vec<u8>>,
        }
        impl std::io::Read for Quiet {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let count = std::io::Read::read(&mut self.ready, out)?;
                if count > 0 {
                    return Ok(count);
                }
                if self.stopped.load(Ordering::Acquire) {
                    return Ok(0);
                }
                self.seconds.fetch_add(5, Ordering::SeqCst);
                let heartbeat = b": quiet\n\n";
                out[..heartbeat.len()].copy_from_slice(heartbeat);
                Ok(heartbeat.len())
            }
        }
        struct QuietZone {
            checks: AtomicUsize,
            seconds: Arc<AtomicU64>,
        }
        impl Transport for QuietZone {
            fn mail_push_v1(&self, _: &str) -> std::result::Result<bool, ClientError> {
                Ok(true)
            }
            fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
                if call.path.starts_with("/api/v1/events?") {
                    return Ok(json!({"events":[]}));
                }
                assert_eq!(call.path, "/api/v1/zones/check");
                self.checks.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"paths":[{"path":"src","status":"held"}]}))
            }
            fn event_stream_sessions(
                &self,
                _: &str,
                _: &[String],
                _: i64,
                interrupt: Arc<AtomicBool>,
            ) -> std::result::Result<crate::sse::EventStream, ClientError> {
                Ok(crate::sse::EventStream::new(Box::new(Quiet {
                    stopped: interrupt,
                    seconds: self.seconds.clone(),
                    ready: std::io::Cursor::new(
                        b"id: 0\nevent: ready\ndata: {\"head\":0}\n\n".to_vec(),
                    ),
                })))
            }
        }
        let seconds = Arc::new(AtomicU64::new(0));
        let cloud = CloudBackend::new(
            QuietZone {
                checks: AtomicUsize::new(0),
                seconds: seconds.clone(),
            },
            "alice",
        );
        let start = Instant::now();
        assert!(
            !cloud
                .wait_zone_stream_with_clock("alice", "src", Duration::from_secs(300), || start
                    + Duration::from_secs(seconds.load(Ordering::SeqCst)))
                .unwrap()
        );
        assert!(seconds.load(Ordering::SeqCst) >= 300);
        assert_eq!(
            cloud.transport.checks.load(Ordering::SeqCst),
            1,
            "only ready may check; five quiet minutes add zero checks"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "reader did not stop"
        );
    }

    /// Keeps the calls it is given, for what HTTP does not show.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<Call>>);

    impl Transport for Recorder {
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            self.0.lock().unwrap().push(call.clone());
            Ok(claim_json(1))
        }
    }

    #[test]
    fn a_claim_that_waits_uses_the_long_read_limit() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let mut cloud = CloudBackend::new(std::sync::Arc::clone(&recorder), "me");
        let waiting = ClaimRequest {
            queue_wait_seconds: Some(25),
            ..ClaimRequest::default()
        };
        cloud.claim("me", &ClaimRequest::default(), 0).unwrap();
        cloud.claim("me", &waiting, 0).unwrap();
        let calls = recorder.0.lock().unwrap();
        assert!(!calls[0].long_poll);
        assert!(calls[1].long_poll);
    }

    #[test]
    fn undelivered_mail_names_its_addressee() {
        let (_server, cloud) = backend(vec![
            json!([{"id": 3, "addressee": "bob", "age_seconds": 7}]),
        ]);
        assert_eq!(cloud.undelivered("me", 0).unwrap()[0].to, "bob");
    }

    #[test]
    fn a_check_without_a_status_is_refused_and_never_reads_as_free() {
        assert!(checks(json!([{"path": "a", "state": "held"}])).is_err());
    }

    #[test]
    fn a_large_inbox_page_is_cut_to_what_the_server_takes() {
        let (server, mut cloud) = backend(vec![json!({"messages": []})]);
        let filter = InboxQuery {
            all: false,
            limit: 200,
        };
        cloud.inbox("me", filter, 0).unwrap();
        assert_eq!(server.requests()[0].path, "/api/v1/bus/inbox?limit=50");
    }

    #[test]
    fn plain_mail_names_a_kind_and_a_plain_board_value_a_lifetime() {
        let (server, mut cloud) =
            backend(vec![json!({"id": 1}), json!({"key": "k", "value": "v"})]);
        let send = SendRequest {
            urgent: false,
            to: "bob".into(),
            body: "x".into(),
            ..SendRequest::default()
        };
        cloud.send("me", &send, 0).unwrap();
        let write = BoardWrite {
            key: "k".into(),
            value: "v".into(),
            ..BoardWrite::default()
        };
        cloud.board_set("me", &write, 0).unwrap();
        let seen = server.requests();
        assert_eq!(seen[0].body["kind"], "ask");
        assert_eq!(seen[1].body["ttl_minutes"], 1440);
    }

    #[test]
    fn a_heartbeat_writes_its_times_as_text() {
        let (server, mut cloud) = backend(vec![json!({})]);
        let beat = PresenceBeat {
            client: "cli".into(),
            dnd_until: Some(lockyard_core::proto::Stamp::Millis(0)),
            activity: Some(SessionActivity {
                tool_running: true,
                tool_started_at: Some(lockyard_core::proto::Stamp::Millis(0)),
                state: None,
                meta: None,
            }),
            ..PresenceBeat::default()
        };
        cloud.heartbeat("me", &beat, 0).unwrap();
        let body = &server.requests()[0].body;
        assert_eq!(body["dnd_until"], "1970-01-01T00:00:00.000Z");
        assert_eq!(
            body["activity"]["tool_started_at"],
            "1970-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn a_body_that_is_not_a_list_is_a_decode_error() {
        let (_server, cloud) = backend(vec![json!({"nope": 1})]);
        assert!(matches!(
            cloud.claims(&ClaimQuery::default(), 0),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn a_message_queued_by_the_agent_process_reads_as_queued() {
        let message = message(json!({"queued": true, "key": "k"})).unwrap();
        assert!(message.queued);
        assert_eq!(message.key.as_deref(), Some("k"));
    }

    fn open_inbox_reply(body: serde_json::Value, announce: bool) -> Reply {
        let mut reply = Reply::json(200, body).header("Lockyard-Protocol", "2");
        if announce {
            reply = reply.header("Lockyard-Capabilities", "mail_open_v1");
        }
        reply
    }

    fn seed_mail_open(client: &Client) {
        let protocol = crate::NegotiatedProtocol {
            selected: 2,
            capabilities: std::collections::BTreeSet::from([crate::MAIL_OPEN_V1.to_string()]),
            legacy: false,
        };
        client.protocol_state.lock().unwrap().cached = Some(crate::protocol::CachedProtocol {
            value: protocol,
            obtained: std::time::Instant::now(),
        });
        client
            .mail_open_v1_observed
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn revocations_header_does_not_clear_mail_open_observation() {
        let server = FakeServer::start(vec![
            Reply::json(200, json!({"claims": []}))
                .header("Lockyard-Capabilities", "mail_open_v1")
                .header("Lockyard-Protocol", "2"),
            Reply::json(200, json!({"items": [], "epoch": 0, "next_since": 0}))
                .header("Lockyard-Capabilities", "revocations_v1")
                .header("Lockyard-Protocol", "2"),
        ]);
        let client = Client::new(&server.url(), "fixture".into()).unwrap();
        client
            .call(&crate::Call::get("me", "/api/v1/zones/claims".into()))
            .unwrap();
        assert!(client.mail_open_v1("me").unwrap());
        client
            .call(&crate::Call::get(
                "me",
                "/api/v1/revocations?since=0&nonce=test".into(),
            ))
            .unwrap();
        assert!(
            client.mail_open_v1("me").unwrap(),
            "revocations Lockyard-Capabilities must not clear mail_open_v1_observed"
        );
    }

    #[test]
    fn unread_is_unknown_when_legacy_skipped_may_contain_seen_mail() {
        for unseen in [false, true] {
            let mut messages: Vec<Value> = (1..=50)
                .map(|id| {
                    json!({
                        "id":id,"body":"shown","reader_state":"seen","seen_at":123
                    })
                })
                .collect();
            if unseen {
                messages[0] = json!({"id":1,"body":"new","reader_state":"new"});
            }
            let (_server, cloud) = backend(vec![json!({"messages":messages,"skipped":1})]);
            assert!(matches!(cloud.unread("me"), Err(Error::Unavailable(_))));
        }
        let (_server, cloud) = backend(vec![json!({"messages":[
            {"id":1,"reader_state":"seen","seen_at":123}
        ],"skipped":0})]);
        assert_eq!(cloud.unread("me").unwrap(), 0);
    }

    #[test]
    fn default_inbox_excludes_seen_while_explicit_all_keeps_it() {
        let body = json!({"messages":[
            {"id":1,"body":"new","reader_state":"new"},
            {"id":2,"body":"shown","reader_state":"seen","seen_at":123},
            {"id":3,"body":"closed","reader_state":"handled"}
        ],"skipped":0});
        let server =
            FakeServer::start(vec![Reply::json(200, body.clone()), Reply::json(200, body)]);
        let client = Client::new(&server.url(), "fixture".into()).unwrap();
        let mut cloud = CloudBackend::new(client, "me");
        let page = cloud
            .inbox(
                "me",
                InboxQuery {
                    all: false,
                    limit: 50,
                },
                0,
            )
            .unwrap();
        assert_eq!(
            page.messages.iter().map(|mail| mail.id).collect::<Vec<_>>(),
            vec![1]
        );
        let page = cloud
            .peek_inbox(
                "me",
                InboxQuery {
                    all: true,
                    limit: 50,
                },
                0,
            )
            .unwrap();
        assert_eq!(page.messages.len(), 3);
        assert!(server.requests()[1].path.contains("all=true"));
    }

    #[test]
    fn peek_open_inbox_uses_open_true_without_all() {
        let open = open_inbox_reply(
            json!({
                "messages": [{
                    "id": 7,
                    "from_session": "bob",
                    "to": "me",
                    "body": "need a path",
                    "kind": "ask",
                    "reader_state": "seen",
                    "seen_at": "2026-11-14T12:00:00Z"
                }],
                "skipped": 2
            }),
            true,
        );
        let server = FakeServer::start(vec![open]);
        let client = Client::new(&server.url(), "fixture".into()).unwrap();
        seed_mail_open(&client);
        assert!(client.mail_open_v1("me").unwrap());
        assert!(
            server.requests().is_empty(),
            "capability read must not hit the network"
        );
        let cloud = CloudBackend::new(client, "service");
        let page = cloud
            .peek_open_inbox_within("me", 50, 0, std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(page.messages[0].id, 7);
        assert_eq!(page.skipped, 2);
        let paths: Vec<_> = server
            .requests()
            .into_iter()
            .map(|seen| seen.path)
            .collect();
        assert_eq!(
            paths,
            vec!["/api/v1/bus/inbox?open=true&limit=50".to_string()]
        );
    }

    #[test]
    fn mail_open_v1_reads_only_fresh_cache_without_discovery() {
        let server = FakeServer::start(vec![]);
        let client = Client::new(&server.url(), "fixture".into()).unwrap();
        assert!(!client.mail_open_v1("me").unwrap());
        assert!(
            server.requests().is_empty(),
            "cold mail_open_v1 must not hit the network"
        );
    }

    #[test]
    fn open_inbox_without_capability_header_is_rejected() {
        let open = open_inbox_reply(
            json!({"messages": [{"id": 1, "from_session": "bob", "to": "me", "body": "x"}], "skipped": 0}),
            false,
        );
        let server = FakeServer::start(vec![open]);
        let client = Client::new(&server.url(), "fixture".into()).unwrap();
        seed_mail_open(&client);
        let cloud = CloudBackend::new(client, "service");
        let err = cloud
            .peek_open_inbox_within("me", 50, 0, std::time::Duration::from_secs(2))
            .unwrap_err();
        let text = format!("{err:?}");
        assert!(
            text.contains("mail_open_v1") || text.contains("feature_unsupported"),
            "{text}"
        );
    }
}
