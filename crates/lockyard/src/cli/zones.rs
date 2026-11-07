// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// Paths named on the command line plus those of named zones. The server knows paths only.
pub(super) fn with_zones(
    opened: &Opened,
    cwd: &Path,
    raw: &[String],
    zones: &[String],
) -> Result<Vec<String>> {
    let mut paths = opened.zone_paths(cwd, raw)?;
    if !zones.is_empty() {
        for path in expand_zones(&opened.backend.catalog()?, zones)? {
            if !paths.contains(&path) {
                paths.push(path);
            }
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
        ZoneCommand::Claim {
            paths,
            note,
            ttl,
            lazy,
            style,
            meta,
        } => {
            let agent = resolve_agent(agent)?;
            let paths = with_zones(&opened, cwd, &paths, &style.zones)?;
            let mut request = claim_request(paths, note, ttl.ttl, &style);
            request.lazy = lazy;
            request.meta = meta;
            let claim =
                lockyard_core::claim_or_reuse(opened.backend.as_mut(), &agent, &request, now)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
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
            let request = claim_request(paths, note, ttl.ttl, &style);
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
            let paths = opened.zone_paths(cwd, &paths)?;
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
        ZoneCommand::Handover { id, to, fence } => {
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
        ZoneCommand::Narrow { id, paths, fence } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            let claim = opened
                .backend
                .narrow(&resolve_agent(agent)?, id, &paths, fence)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::AddPath { id, path, fence } => {
            let path = opened.zone_path(cwd, &path)?;
            let claim = opened
                .backend
                .add_path(&resolve_agent(agent)?, id, &path, fence)?;
            let text = claim_line(&claim, lease);
            output(&claim, text)
        }
        ZoneCommand::Takeover { id, reason } => {
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
            let paths = opened.zone_paths(cwd, &paths)?;
            let request = ActivityRequest {
                write,
                paths,
                fence,
            };
            opened
                .backend
                .activity(&resolve_agent(agent)?, id, &request)?;
            output(&json!({"reported": id}), format!("reported Z-{id}"))
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
            fence,
        } => {
            let agent = resolve_agent(agent)?;
            let request = RenewRequest {
                ttl_minutes: ttl.ttl,
                hold_reason,
                hold_until,
                fence,
            };
            let renewed = opened.backend.renew(&agent, id, &request, now)?;
            output(&json!({ "renewed": renewed }), format!("renewed {renewed}"))
        }
        ZoneCommand::Release {
            id,
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
            let released = opened.backend.release(&agent, id, &request, now)?;
            output(
                &json!({ "released": released }),
                format!("released {released}"),
            )
        }
        ZoneCommand::List { session, path } => {
            let path = path.map(|raw| opened.zone_path(cwd, &raw)).transpose()?;
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
            let path = opened.zone_path(cwd, &path)?;
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
            let paths = opened.zone_paths(cwd, &paths)?;
            let report: Vec<DirtyPath> = paths
                .into_iter()
                .map(|path| DirtyPath {
                    path,
                    owner_session: owner.clone(),
                    reason: reason.clone(),
                    task_id: task,
                })
                .collect();
            opened.backend.dirty_report(&agent, &report)?;
            output(&report, format!("reported {}", report.len()))
        }
        DirtyCommand::List { path } => {
            let path = path.map(|raw| opened.zone_path(cwd, &raw)).transpose()?;
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
            let paths = opened.zone_paths(cwd, &paths)?;
            opened.backend.dirty_disown(&agent, &paths)?;
            output(
                &json!({"disowned": paths}),
                format!("disowned {}", paths.len()),
            )
        }
        DirtyCommand::Adopt { paths, reason } => {
            let paths = opened.zone_paths(cwd, &paths)?;
            opened.backend.dirty_adopt(&agent, &paths, &reason)?;
            output(
                &json!({"adopted": paths}),
                format!("adopted {}", paths.len()),
            )
        }
    }
}
