// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_status(opened: &Opened, agent: Option<&String>) -> Result<Output> {
    let now = now_ms();
    let lease = clock(opened);
    let backend = opened.backend.as_ref();
    let agent = agent.cloned().or_else(env_agent);
    let session = agent.as_deref().unwrap_or("lockyard-cli");
    let claims = backend.claims(
        &ClaimQuery {
            session: Some(session.to_string()),
            path: None,
        },
        now,
    )?;
    let (claims, incoming): (Vec<Claim>, Vec<Claim>) = claims
        .into_iter()
        .partition(|claim| claim.session == session);
    let offers: Vec<Value> = incoming
        .iter()
        .map(|claim| {
            json!({"id": claim.id, "from": claim.session,
            "paths": claim.paths, "note": claim.note})
        })
        .collect();
    let unread = agent
        .as_deref()
        .map(|name| backend.unread(name))
        .transpose()?;
    let mut lines = Vec::new();
    let machine_config = guard::project_config(&std::env::current_dir().unwrap_or_default());
    let machine_level = guard::snapshot(&machine_config).ok().map(|report| {
        let name = match report.level {
            lockyard_core::machine::Level::Ok => "ok",
            lockyard_core::machine::Level::Warn => "warn",
            lockyard_core::machine::Level::Hold => "hold",
            lockyard_core::machine::Level::Critical => "critical",
        };
        lines.push(format!("machine: {name}"));
        name
    });
    if let Some(unread) = unread {
        lines.push(format!("unread mail: {unread}"));
    }
    lines.push(join(
        &claims,
        |claim| claim_line(claim, lease),
        "no active claims",
    ));
    for claim in &incoming {
        lines.push(format!(
            "Z-{} offered to you by {}: {}  {}",
            claim.id,
            claim.session,
            claim.paths.join(" "),
            claim.note
        ));
    }
    // Outside-hook writes live in the local store in both modes; they are detection, not a lock.
    let unannounced = Store::open(&opened.root)
        .ok()
        .and_then(|store| {
            store
                .unannounced(now.saturating_sub(24 * 60 * 60 * 1000))
                .ok()
        })
        .unwrap_or_default()
        .into_iter()
        .filter(|record| record.holder == session)
        .collect::<Vec<_>>();
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
    if backend.is_cloud() {
        let mut work = mcp::visible_work(Some(session), backend.work_list(session)?);
        work.truncate(10);
        lines.push(join(&work, work_line, "no work tasks"));
        let work: Vec<Value> = work
            .into_iter()
            .map(|item| {
                json!({"id": item.id, "title": item.title, "status": item.status,
                "assignee": item.assignee, "to": item.to})
            })
            .collect();
        let backlog = backend.tasks(None, false)?;
        let mut tasks = backlog.clone();
        tasks.retain(|task| task.assignee.as_deref() == Some(session));
        tasks.truncate(20);
        lines.push(join(&tasks, task_line, "no tasks"));
        let data = json!({
            "unread": unread,
            "claims": claims,
            "offers": offers,
            "work": work,
            "tasks": tasks,
            "backlog": backlog,
            "machine_level": machine_level,
            "unannounced": unannounced,
        });
        return output(&data, lines.join("\n"));
    }
    let mut tasks = backend.tasks(None, false)?;
    tasks.retain(|task| task.assignee.as_deref() == Some(session));
    tasks.truncate(20);
    lines.push(join(&tasks, task_line, "no tasks"));
    let data = json!({
        "unread": unread,
        "claims": claims,
        "tasks": tasks,
        "machine_level": machine_level,
        "unannounced": unannounced,
    });
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
