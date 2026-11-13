// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use lockyard_core::StatusRead;

/// Includes config, socket probing, DNS/TLS, retries, paging and local decoration. A process-level
/// wait also covers blocking OS resolvers and filesystem calls that cannot honor transport limits.
const DEFAULT_STATUS_DEADLINE_MS: u64 = 6_000;
const MAX_STATUS_DEADLINE_MS: u64 = 60_000;

fn status_limit_from(value: Option<&str>) -> Result<Duration> {
    let invalid = || {
        Error::Invalid(format!(
            "LOCKYARD_STATUS_DEADLINE_MS must be an integer in the range 1..={MAX_STATUS_DEADLINE_MS} milliseconds (or empty for the default)"
        ))
    };
    let millis = match value.filter(|value| !value.is_empty()) {
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|ms| (1..=MAX_STATUS_DEADLINE_MS).contains(ms))
            .ok_or_else(invalid)?,
        None => DEFAULT_STATUS_DEADLINE_MS,
    };
    let limit = Duration::from_millis(millis);
    Instant::now().checked_add(limit).ok_or_else(invalid)?;
    Ok(limit)
}

fn status_limit() -> Result<Duration> {
    status_limit_from(std::env::var("LOCKYARD_STATUS_DEADLINE_MS").ok().as_deref())
}

// Reserve one percent for the bounded 50 ms local decoration and output at the default budget.
fn status_read_limit(limit: Duration) -> Duration {
    limit.mul_f64(0.99)
}

pub(super) fn run_status_command(cwd: &Path, agent: Option<&String>) -> Result<Output> {
    let started = Instant::now();
    let limit = status_limit()?;
    let read_limit = status_read_limit(limit);
    let cwd = cwd.to_path_buf();
    let agent = agent.cloned().or_else(env_agent);
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("status".into())
        .spawn(move || {
            let session = agent.as_deref().unwrap_or("lockyard-cli");
            let result = open::status_read(&cwd, session, started + read_limit)
                .and_then(|(root, cloud, read)| {
                    render_status(&root, cloud, agent.as_deref(), read, started)
                })
                // Output's post-delivery closure is intentionally not Send. Status has no such action.
                .map(|out| (out.json, out.text));
            let _ = send.send(result);
        })
        .map_err(Error::Io)?;
    let remaining = limit.saturating_sub(started.elapsed());
    match receive.recv_timeout(remaining) {
        Ok(result) => result.and_then(|(data, text)| output(&data, text)),
        Err(_) => Err(Error::Unavailable(format!(
            "status deadline exceeded ({} ms); claims and assigned tasks could not be confirmed",
            limit.as_millis()
        ))),
    }
}

#[cfg(test)]
pub(super) fn run_status(opened: &Opened, agent: Option<&String>) -> Result<Output> {
    let started = Instant::now();
    let agent = agent.cloned().or_else(env_agent);
    let session = agent.as_deref().unwrap_or("lockyard-cli");
    let read = opened
        .backend
        .status_read(session, now_ms(), status_read_limit(status_limit()?))?;
    render_status(
        &opened.root,
        opened.backend.is_cloud(),
        agent.as_deref(),
        read,
        started,
    )
}

fn render_status(
    root: &Path,
    cloud: bool,
    agent: Option<&str>,
    mut read: StatusRead,
    started: Instant,
) -> Result<Output> {
    let _span = lockyard_core::perf::Span::new("status.render");
    let session = agent.unwrap_or("lockyard-cli");
    let mut lines = Vec::new();
    // Machine pressure is informational here. Its shared flock and SQLite's busy timeout must
    // never delay mandatory claims/tasks. Use the existing nonblocking machine sampling path.
    let root_owned = root.to_path_buf();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let machine = {
            let _span = lockyard_core::perf::Span::new("status.machine");
            guard::cached_level(&guard::project_config(&root_owned)).ok()
        };
        let records = {
            let _span = lockyard_core::perf::Span::new("status.local_store");
            Store::open(&root_owned)
                .ok()
                .and_then(|store| store.unannounced(now_ms().saturating_sub(DAY_MS)).ok())
        };
        let _ = send.send((machine, records));
    });
    let decoration = receive.recv_timeout(Duration::from_millis(50));
    let decoration_available = decoration.is_ok();
    let (machine, records) = decoration.unwrap_or_default();
    let machine_available = machine.is_some();
    let records_available = records.is_some();
    let machine_level = machine.map(|level| match level {
        lockyard_core::machine::Level::Ok => "ok",
        lockyard_core::machine::Level::Warn => "warn",
        lockyard_core::machine::Level::Hold => "hold",
        lockyard_core::machine::Level::Critical => "critical",
    });
    if let Some(level) = machine_level {
        lines.push(format!("machine: {level}"));
    }
    let unread = agent.and(read.unread);
    if let Some(unread) = unread {
        lines.push(format!("unread mail: {unread}"));
    }
    let unannounced: Vec<_> = records
        .unwrap_or_default()
        .into_iter()
        .filter(|record| record.holder == session)
        .collect();
    if !unannounced.is_empty() {
        lines.push(format!(
            "writes outside the hook: {} (detection only — Lockyard cannot refuse a shell write)",
            unannounced.len()
        ));
        for record in unannounced.iter().take(5) {
            lines.push(format!(
                "  ! {} held by {} ({} hits)",
                record.path, record.holder, record.hits
            ));
        }
    }
    // Re-evaluate expiry after ALL network reads and local work. The HTTP Date bound is in the
    // server's clock domain; adding the full command age is conservative across the IPC hop.
    let elapsed_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    let upper = read.freshness["claims_server_time_upper_ms"]
        .as_i64()
        .map(|server| server.saturating_add(elapsed_ms))
        .unwrap_or_else(now_ms);
    read.claims.retain(|claim| {
        let stamp = |value: &Stamp| match value {
            Stamp::Millis(ms) => Some(*ms),
            Stamp::Text(text) => lockyard_core::proto::parse_rfc3339(text),
        };
        stamp(&claim.expires_at).is_some_and(|expires| expires > upper)
            && claim
                .idle_release_at
                .as_ref()
                .is_none_or(|at| stamp(at).is_some_and(|expires| expires > upper))
    });
    if cloud {
        read.freshness["age_ms"] = json!(elapsed_ms);
        read.freshness["local_decoration_available"] = json!(decoration_available);
        read.freshness["sections"]["machine_level"] =
            json!({"source": "local", "available": machine_available});
        read.freshness["sections"]["unannounced"] =
            json!({"source": "local", "available": records_available});
        // Account for IPC and decoration conservatively in each section's age.
        if let Some(sections) = read.freshness["sections"].as_object_mut() {
            for metadata in sections.values_mut() {
                if let Some(age) = metadata["age_ms"].as_u64() {
                    metadata["age_ms"] = json!(age.saturating_add(elapsed_ms as u64));
                }
            }
        }
    }
    let (claims, incoming): (Vec<_>, Vec<_>) = read
        .claims
        .into_iter()
        .partition(|claim| claim.session == session);
    let lease = if cloud { None } else { Some(now_ms()) };
    lines.push(join(
        &claims,
        |claim| claim_line(claim, lease),
        "no active claims",
    ));
    let offers: Vec<_> = incoming
        .iter()
        .map(|claim| {
            lines.push(format!(
                "Z-{} offered to you by {}: {}  {}",
                claim.id,
                claim.session,
                claim.paths.join(" "),
                claim.note
            ));
            json!({"id": claim.id, "from": claim.session, "paths": claim.paths, "note": claim.note})
        })
        .collect();
    read.tasks.truncate(20);
    lines.push(join(&read.tasks, task_line, "no tasks"));
    let mut data = json!({"unread": unread, "claims": claims, "tasks": read.tasks,
        "machine_level": machine_level, "unannounced": unannounced});
    if cloud {
        let mut work = mcp::visible_work(Some(session), read.work);
        work.truncate(10);
        lines.push(join(&work, work_line, "no work tasks"));
        data["work"] = json!(
            work.into_iter()
                .map(|item| json!({"id": item.id, "title": item.title,
            "status": item.status, "assignee": item.assignee, "to": item.to}))
                .collect::<Vec<_>>()
        );
        data["offers"] = json!(offers);
        data["freshness"] = read.freshness;
    }
    output(&data, lines.join("\n"))
}

pub(super) fn run_monitor(
    args: MonitorArgs,
    agent: Option<&String>,
    cwd: &Path,
    json: bool,
) -> Result<Output> {
    let name = resolve_agent(agent)?;
    let _shutdown = crate::shutdown::Guard::new(cwd)?;
    let mut opened = open::open(cwd, Some(&name))?;
    let store = Store::open(&opened.root)?;
    let settings = monitor::Settings {
        root: opened.root.clone(),
        agent: name,
        reconcile: Duration::from_secs(args.reconcile.max(1)),
        mail: !args.no_mail,
        zones: !args.no_zones,
        once: args.once,
        timeout: args.timeout.map(Duration::from_secs),
        json,
    };
    let now = || now_ms();
    let mut ports = monitor::Ports {
        backend: opened.backend.as_mut(),
        store,
        now: &now,
    };
    // The monitor writes its own lines as events arrive; the command's Output is only a summary.
    let mut sink = std::io::stdout();
    let summary = monitor::run(&settings, &mut ports, &mut sink)?;
    let text = if json {
        String::new()
    } else {
        format!(
            "monitor stopped: {} mail, {} outside writes, {} rounds ({})",
            summary.delivered,
            summary.unannounced,
            summary.rounds,
            summary.backend.unwrap_or("off")
        )
    };
    output(
        &json!({
            "delivered": summary.delivered,
            "unannounced": summary.unannounced,
            "rounds": summary.rounds,
            "backend": summary.backend,
        }),
        text,
    )
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn status_deadline_defaults_to_six_seconds_and_honors_override() {
        let default = status_limit_from(None).unwrap();
        assert_eq!(default, Duration::from_millis(6000));
        assert_eq!(status_limit_from(Some("")).unwrap(), default);
        assert_eq!(status_read_limit(default), Duration::from_millis(5940));
        assert_eq!(
            status_limit_from(Some("850")).unwrap(),
            Duration::from_millis(850)
        );
    }

    #[test]
    fn status_deadline_accepts_both_range_boundaries() {
        for millis in [1, MAX_STATUS_DEADLINE_MS] {
            assert_eq!(
                status_limit_from(Some(&millis.to_string())).unwrap(),
                Duration::from_millis(millis)
            );
        }
    }

    #[test]
    fn status_deadline_rejects_invalid_values_with_variable_and_range() {
        for invalid in [
            "0",
            "-1",
            " ",
            "abc",
            "60001",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            let error = status_limit_from(Some(invalid)).unwrap_err().to_string();
            assert!(
                error.contains("LOCKYARD_STATUS_DEADLINE_MS"),
                "{invalid}: {error}"
            );
            assert!(
                error.contains("1..=60000 milliseconds"),
                "{invalid}: {error}"
            );
        }
    }
}
