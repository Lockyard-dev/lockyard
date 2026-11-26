// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// Paths named on the command line plus those of named zones. The server knows paths only.
/// Relative paths are anchored at the workspace root, not the process cwd (LY-0015).
pub(super) fn with_zones(
    opened: &Opened,
    cwd: &Path,
    raw: &[String],
    zones: &[String],
) -> Result<Vec<String>> {
    let mut paths = opened.workspace_zone_paths(cwd, raw)?;
    if !zones.is_empty() {
        match opened.backend.catalog_expand(zones) {
            Ok(expanded) => crate::open::merge_catalog_paths(&mut paths, expanded),
            Err(error)
                if error.to_string().contains("zone_unknown") || error.kind() == "zone_unknown" =>
            {
                let message = format!(
                    "{error}; zones are catalog names; pass workspace-root paths as positional paths instead of --zone"
                );
                return Err(match error {
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
                    _ => Error::Invalid(message),
                });
            }
            Err(error) => return Err(error),
        }
    }
    validate_claim_path_count(paths.len())?;
    Ok(paths)
}

pub(super) fn zone_label(zones: &[String]) -> Option<String> {
    match zones {
        [one] => Some(one.clone()),
        _ => None,
    }
}

pub(super) fn claim_request(
    paths: Vec<String>,
    note: String,
    ttl: i64,
    style: &ClaimStyle,
) -> ClaimRequest {
    ClaimRequest {
        paths,
        note,
        ttl_minutes: ttl,
        mode: style.mode(),
        purpose: style.purpose(),
        zone: zone_label(&style.zones),
        zones: if style.zones.len() > 1 {
            style.zones.clone()
        } else {
            Vec::new()
        },
        ..ClaimRequest::default()
    }
}

/// Attach the session label when the backend stores claim meta (cloud only).
pub(super) fn with_session_meta(mut request: ClaimRequest, cloud: bool) -> Result<ClaimRequest> {
    if cloud {
        request.meta = Some(crate::session_label::merge_session_meta(
            request.meta.take(),
        )?);
    }
    Ok(request)
}

/// Resolve an omitted id before releasing, so another process's claims need explicit consent.
pub(super) fn release_claims(
    backend: &mut dyn Backend,
    agent: &str,
    id: Option<i64>,
    all: bool,
    request: &ReleaseRequest,
    now: i64,
) -> Result<usize> {
    if id.is_some() && all {
        return Err(Error::Invalid(
            "provide either id or --all, not both".into(),
        ));
    }
    let id = match id {
        Some(id) => Some(id),
        None => {
            let ids: Vec<_> = backend
                .claims(
                    &ClaimQuery {
                        session: Some(agent.to_string()),
                        path: None,
                    },
                    now,
                )?
                .into_iter()
                .filter(|claim| claim.session == agent)
                .map(|claim| claim.id)
                .collect();
            match ids.as_slice() {
                [] => return Ok(0),
                [id] => Some(*id),
                _ if all => None,
                _ => {
                    return Err(Error::Invalid(format!(
                        "you own multiple claims: {}; provide id or --all",
                        ids.iter()
                            .map(|id| format!("Z-{id}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
        }
    };
    backend.release(agent, id, request, now)
}

/// Keeps asking for a claim until it is granted or the wait ends. Each try is its own write, because a
/// repeat under one key would only repeat the first refusal.
pub(crate) fn wait_for_claim(
    backend: &mut dyn Backend,
    agent: &str,
    mut request: ClaimRequest,
    seconds: u64,
) -> Result<Claim> {
    if seconds > MAX_SHORT_WAIT_SECONDS {
        return Err(Error::Invalid(format!(
            "a short wait is at most {MAX_SHORT_WAIT_SECONDS} seconds, use zone queue"
        )));
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let slice = left.as_secs().min(WAIT_SLICE_SECONDS);
        request.queue_wait_seconds = Some(i64::try_from(slice).unwrap_or(0));
        match backend.claim(agent, &request, now_ms()) {
            Err(Error::Conflict(_) | Error::Contended(_)) if !left.is_zero() => {
                std::thread::sleep(WAIT_RETRY.min(left));
            }
            other => return other,
        }
    }
}

pub(super) fn run_zone(
    mut opened: Opened,
    command: ZoneCommand,
    agent: Option<&String>,
    cwd: &Path,
) -> Result<Output> {
    let now = now_ms();
    let lease = clock(&opened);
    match command {
        ZoneCommand::WaitFree { path, timeout } => {
            let path = opened.workspace_zone_path(cwd, &path)?;
            let free = opened.backend.wait_zone_free(
                &resolve_agent(agent)?,
                &path,
                Duration::from_secs(timeout),
            )?;
            let mut answer = output(
                &json!({"path":path,"free":free,"timed_out":!free}),
                if free { "free" } else { "timed out" },
            )?;
            answer.exit = if free { 0 } else { 1 };
            Ok(answer)
        }
        ZoneCommand::Claim {
            paths,
            paths_file,
            note,
            ttl,
            hold_reason,
            hold_until,
            hold_for,
            lazy,
            style,
            meta,
        } => {
            let agent = resolve_agent(agent)?;
            let mut paths = paths;
            if let Some(file) = paths_file {
                paths.extend(read_lines_file(&file)?);
            }
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let hold_until = match (hold_until, hold_for) {
                (Some(until), None) => Some(until),
                (None, Some(minutes)) => Some(hold_until_from_minutes(minutes, now)?),
                (None, None) => None,
                (Some(_), Some(_)) => {
                    return Err(Error::Invalid(
                        "use either --hold-until or --hold-for, not both".into(),
                    ));
                }
            };
            let cloud = opened.backend.is_cloud();
            let mut request = claim_request(paths, note, ttl.ttl, &style);
            request.lazy = lazy;
            request.meta = meta;
            let request = with_session_meta(request, cloud)?;
            let (claim, _) = lockyard_core::claim_or_reuse_with_hold(
                opened.backend.as_mut(),
                &agent,
                &request,
                hold_reason,
                hold_until,
                now,
            )?;
            let text = claim_line(&claim, lease);
            let mut out = output(&claim, text)?;
            if let Some(warning) = claim.excluded_paths_warning() {
                out.json["warning"] = json!(warning);
            }
            Ok(out)
        }
        ZoneCommand::Wait {
            paths,
            note,
            ttl,
            seconds,
            style,
        } => {
            let agent = resolve_agent(agent)?;
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let request = with_session_meta(
                claim_request(paths, note, ttl.ttl, &style),
                opened.backend.is_cloud(),
            )?;
            let claim = wait_for_claim(opened.backend.as_mut(), &agent, request, seconds)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Queue {
            paths,
            note,
            ttl,
            style,
        } => {
            let agent = resolve_agent(agent)?;
            if paths.is_empty() && style.zones.is_empty() {
                let entries = opened.backend.queue_list(&agent)?;
                let line = |entry: &lockyard_core::proto::QueueEntry| {
                    format!("Q-{}  {}", entry.id, entry.paths.join(" "))
                };
                let text = join(&entries, line, "nothing queued");
                return output(&entries, text);
            }
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let request = QueueRequest {
                paths,
                note,
                ttl_minutes: ttl,
                mode: style.mode(),
                purpose: style.purpose(),
                zones: style.zones.clone(),
            };
            let entry = opened.backend.queue_add(&agent, &request)?;
            let verb = if entry.granted { "granted" } else { "queued" };
            output(&entry, format!("{verb} Q-{}", entry.id))
        }
        ZoneCommand::Unwait { id } => {
            opened.backend.queue_cancel(&resolve_agent(agent)?, id)?;
            output(&json!({"cancelled": id}), format!("left the queue: Q-{id}"))
        }
        ZoneCommand::Request {
            paths,
            text,
            urgent,
            need_by,
        } => {
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            let request = AccessRequest {
                paths,
                text,
                urgent,
                need_by,
            };
            let record = opened
                .backend
                .zone_request(&resolve_agent(agent)?, &request)?;
            output(&record, format!("requested as R-{}", record.id))
        }
        ZoneCommand::Requests => {
            let records = opened.backend.zone_requests(&resolve_agent(agent)?)?;
            output(&records, format!("{} active requests", records.len()))
        }
        ZoneCommand::Answer { id, reply, eta } => {
            let record = opened.backend.zone_answer(
                &resolve_agent(agent)?,
                id,
                &AccessAnswer { reply, eta },
            )?;
            output(&record, format!("answered R-{}", record.id))
        }
        ZoneCommand::Handover {
            id,
            to,
            fence,
            paths,
        } => {
            if !paths.is_empty() {
                let paths = opened.workspace_zone_paths(cwd, &paths)?;
                let record = opened.backend.partial_zone(
                    &resolve_agent(agent)?,
                    id,
                    "handover",
                    &json!({"to":to,"paths":paths,"fence":fence}),
                )?;
                return output(&record, format!("Z-{id} paths offered to {to}"));
            }
            let record = opened
                .backend
                .handover(&resolve_agent(agent)?, id, &to, fence)?;
            output(&record, format!("Z-{id} offered to {to}"))
        }
        ZoneCommand::Accept { id } => {
            let claim = opened.backend.handover_accept(&resolve_agent(agent)?, id)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Narrow {
            id,
            paths,
            fence,
            except,
        } => {
            if !except.is_empty() {
                let except = opened.workspace_zone_paths(cwd, &except)?;
                let record = opened.backend.partial_zone(
                    &resolve_agent(agent)?,
                    id,
                    "narrow",
                    &json!({"except":except,"fence":fence}),
                )?;
                return output(&record, format!("Z-{id} excluded subpaths"));
            }
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            let claim = opened
                .backend
                .narrow(&resolve_agent(agent)?, id, &paths, fence)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::AddPath { id, paths, fence } => {
            let agent = resolve_agent(agent)?;
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            let claim = add_paths_atomic(opened.backend.as_mut(), &agent, id, &paths, fence)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Takeover { id, reason, paths } => {
            if !paths.is_empty() {
                let paths = opened.workspace_zone_paths(cwd, &paths)?;
                let record = opened.backend.partial_zone(
                    &resolve_agent(agent)?,
                    id,
                    "takeover",
                    &json!({"paths":paths,"reason":reason}),
                )?;
                return output(&record, format!("Z-{id} paths taken"));
            }
            let claim = opened
                .backend
                .takeover(&resolve_agent(agent)?, id, &reason)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Dirty(command) => run_dirty(opened, command, agent, cwd),
        ZoneCommand::Activity {
            id,
            paths,
            write,
            fence,
        } => {
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            let request = ActivityRequest {
                write,
                paths,
                fence,
            };
            let agent = resolve_agent(agent)?;
            opened.backend.activity(&agent, id, &request)?;
            let incoming = match opened
                .backend
                .zone_requests_within(&agent, Duration::from_millis(300))
            {
                Ok(records) => IncomingFetch::Known(incoming_path_requests(records, &agent)),
                Err(_) => IncomingFetch::Unknown,
            };
            let mut lines = vec![format!("reported Z-{id}")];
            let mut data = json!({ "reported": id });
            attach_incoming(&mut data, &mut lines, incoming);
            output(&data, lines.join("\n"))
        }
        ZoneCommand::Lost => {
            let lost = opened.backend.lost(&resolve_agent(agent)?)?;
            let line = |claim: &lockyard_core::proto::LostClaim| {
                format!("Z-{}  {}", claim.claim_id, claim.paths.join(" "))
            };
            let text = join(&lost, line, "no lost claims");
            output(&lost, text)
        }
        ZoneCommand::Catalog => {
            let catalog = opened.backend.catalog()?;
            let text = catalog.to_string();
            output(&catalog, text)
        }
        ZoneCommand::Renew {
            id,
            ttl,
            hold_reason,
            hold_until,
            hold_for,
            fence,
        } => {
            let agent = resolve_agent(agent)?;
            if !(1..=240).contains(&ttl.ttl) {
                return Err(Error::Invalid(format!(
                    "ttl must be 1 to 240 minutes (got {}); seconds are not accepted — use minutes",
                    ttl.ttl
                )));
            }
            let hold_until = match (hold_until, hold_for) {
                (Some(until), None) => Some(until),
                (None, Some(minutes)) => Some(hold_until_from_minutes(minutes, now)?),
                (None, None) if hold_reason.is_some() => Some(hold_until_from_minutes(240, now)?),
                (None, None) => None,
                (Some(_), Some(_)) => {
                    return Err(Error::Invalid(
                        "use either --hold-until or --hold-for, not both".into(),
                    ));
                }
            };
            let request = RenewRequest {
                ttl_minutes: ttl.ttl,
                hold_reason,
                hold_until,
                fence,
            };
            let renewed = opened.backend.renew(&agent, id, &request, now)?;
            let incoming = match opened
                .backend
                .zone_requests_within(&agent, Duration::from_millis(300))
            {
                Ok(records) => IncomingFetch::Known(incoming_path_requests(records, &agent)),
                Err(_) => IncomingFetch::Unknown,
            };
            let mut data = json!({ "renewed": renewed });
            let mut lines = vec![format!("renewed {renewed}")];
            attach_incoming(&mut data, &mut lines, incoming);
            if let Some(snap) = crate::open_mail::open_mail_within(
                opened.backend.as_ref(),
                &agent,
                now,
                crate::open_mail::RENEW_BUDGET,
            ) {
                data["open_mail_count"] = json!(snap.items.len());
                data["open_mail"] = json!(snap.items);
                lines.push(format!("open mail: {}", snap.items.len()));
                lines.extend(crate::open_mail::open_mail_lines(&snap.items));
                if snap.truncated {
                    data["open_mail_truncated"] = json!(true);
                }
            } else {
                data["open_mail_unknown"] = json!(true);
                lines.push("почта: неизвестно".into());
            }
            output(&data, lines.join("\n"))
        }
        ZoneCommand::Release {
            id,
            paths,
            all,
            note,
            leave_dirty,
            fence,
        } => {
            let agent = resolve_agent(agent)?;
            let request = ReleaseRequest {
                note,
                leave_dirty,
                fence,
            };
            if !paths.is_empty() {
                let paths = opened.workspace_zone_paths(cwd, &paths)?;
                let id = id.ok_or_else(|| Error::Invalid("partial release requires id".into()))?;
                let mut body =
                    serde_json::to_value(&request).map_err(|e| Error::Invalid(e.to_string()))?;
                body["paths"] = json!(paths);
                let record = opened.backend.partial_zone(&agent, id, "release", &body)?;
                return output(&record, format!("Z-{id} paths released"));
            }
            let released = release_claims(opened.backend.as_mut(), &agent, id, all, &request, now)?;
            output(
                &json!({ "released": released }),
                format!("released {released}"),
            )
        }
        ZoneCommand::List { session, path } => {
            let path = path
                .map(|raw| opened.workspace_zone_path(cwd, &raw))
                .transpose()?;
            let claims = opened.backend.claims(&ClaimQuery { session, path }, now)?;
            let text = join(
                &claims,
                |claim| claim_line(claim, lease),
                "no active claims",
            );
            output(&claims, text)
        }
        ZoneCommand::Check { path } => {
            let agent = resolve_agent(agent)?;
            let path = opened.workspace_zone_path(cwd, &path)?;
            let mut checks =
                opened
                    .backend
                    .check(&agent, std::slice::from_ref(&path), None, now)?;
            let found = (!checks.is_empty()).then(|| checks.remove(0));
            match found {
                None => output(&json!({ "free": true }), "free"),
                Some(check) => match check.status {
                    CheckStatus::Held => match check.holder {
                        Some(holder) => Err(Error::Conflict(vec![holder])),
                        None => Err(Error::Contended(format!("{path} is held"))),
                    },
                    CheckStatus::Own => output(&json!({ "free": true, "own": true }), "own"),
                    CheckStatus::Free => output(&json!({ "free": true }), "free"),
                    CheckStatus::Unknown => {
                        let mut out = output(&json!({ "unknown": true }), "unknown")?;
                        out.exit = EXIT_UNKNOWN;
                        Ok(out)
                    }
                },
            }
        }
    }
}

pub(super) fn run_dirty(
    mut opened: Opened,
    command: DirtyCommand,
    agent: Option<&String>,
    cwd: &Path,
) -> Result<Output> {
    let agent = resolve_agent(agent)?;
    match command {
        DirtyCommand::Report {
            paths,
            owner,
            reason,
            task,
        } => {
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            let task = task
                .as_deref()
                .map(lockyard_core::task_id::TaskId::parse)
                .transpose()?;
            let report: Vec<DirtyPath> = paths
                .into_iter()
                .map(|path| DirtyPath {
                    path,
                    owner_session: owner.clone(),
                    reason: reason.clone(),
                    task_id: task.clone(),
                })
                .collect();
            opened.backend.dirty_report(&agent, &report)?;
            output(&report, format!("reported {}", report.len()))
        }
        DirtyCommand::List { path } => {
            let path = path
                .map(|raw| opened.workspace_zone_path(cwd, &raw))
                .transpose()?;
            let list = opened.backend.dirty_list(&agent, path.as_deref())?;
            let line = |entry: &DirtyPath| {
                format!(
                    "{}  {}",
                    entry.path,
                    entry.owner_session.as_deref().unwrap_or("-")
                )
            };
            let text = join(&list, line, "nothing dirty");
            output(&list, text)
        }
        DirtyCommand::Disown { paths } => {
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            opened.backend.dirty_disown(&agent, &paths)?;
            output(
                &json!({"disowned": paths}),
                format!("disowned {}", paths.len()),
            )
        }
        DirtyCommand::Adopt { paths, reason } => {
            let paths = opened.workspace_zone_paths(cwd, &paths)?;
            opened.backend.dirty_adopt(&agent, &paths, &reason)?;
            output(
                &json!({"adopted": paths}),
                format!("adopted {}", paths.len()),
            )
        }
    }
}

/// The server's add-path endpoint is singular. Restore original roots on a later rejection.
pub(crate) fn add_paths_atomic(
    backend: &mut dyn Backend,
    agent: &str,
    id: i64,
    paths: &[String],
    fence: Option<i64>,
) -> Result<Claim> {
    if paths.is_empty() {
        return Err(Error::Invalid("add-path needs at least one path".into()));
    }
    if paths.len() == 1 {
        return backend.add_path(agent, id, &paths[0], fence);
    }
    let original = backend
        .claims(
            &ClaimQuery {
                session: Some(agent.into()),
                path: None,
            },
            now_ms(),
        )?
        .into_iter()
        .find(|claim| claim.id == id && claim.session == agent)
        .ok_or_else(|| Error::NotFound(format!("claim Z-{id} is not yours")))?;
    let mut current = original.clone();
    let mut next_fence = fence.or(Some(current.fence));
    let mut added = Vec::new();
    for path in paths {
        match backend.add_path(agent, id, path, next_fence) {
            Ok(claim) => {
                current = claim;
                next_fence = Some(current.fence);
                added.push(path.clone());
            }
            Err(error) => {
                if error.kind() == "add_path_queue_consumed" {
                    current = backend
                        .claims(
                            &ClaimQuery {
                                session: Some(agent.into()),
                                path: None,
                            },
                            now_ms(),
                        )
                        .map_err(|read| {
                            Error::Unavailable(format!(
                                "{error}; reconciliation failed: {read}; added {}; inspect Z-{id}",
                                added.join(", ")
                            ))
                        })?
                        .into_iter()
                        .find(|claim| claim.id == id && claim.session == agent)
                        .ok_or_else(|| {
                            Error::NotFound(format!(
                                "{error}; Z-{id} no longer owned; added {}",
                                added.join(", ")
                            ))
                        })?;
                    added.push(path.clone());
                }
                if added.is_empty() {
                    return Err(error);
                }
                if error.kind().contains("unknown") || error.kind() == "unavailable" {
                    return Err(Error::Invalid(format!(
                        "{error}; added {}; outcome unknown, inspect Z-{id} before retrying",
                        added.join(", ")
                    )));
                }
                let restored = backend.narrow(agent, id, &original.paths, Some(current.fence));
                return Err(Error::Invalid(match restored {
                    Ok(_) => format!(
                        "{error}; added {}; rolled back to original paths",
                        added.join(", ")
                    ),
                    Err(rollback) => format!(
                        "{error}; added {}; rollback failed: {rollback}; inspect Z-{id} before retrying",
                        added.join(", ")
                    ),
                }));
            }
        }
    }
    Ok(current)
}
