// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_task(
    mut opened: Opened,
    command: TaskCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let now = now_ms();
    let mut command = command;
    if let TaskCommand::Add {
        paths,
        body,
        body_file,
        acceptance,
        acceptance_file,
        ..
    } = &mut command
    {
        *paths = opened.task_paths(paths)?;
        if let Some(file) = body_file.take() {
            *body = read_text_file(&file)?;
        }
        if let Some(file) = acceptance_file.take() {
            *acceptance = Some(read_text_file(&file)?);
        }
        if opened.backend.is_cloud() && !paths.is_empty() && !opened.backend.registry_auto_area()? {
            eprintln!(
                "warning: this server does not support task paths (registry_auto_area_v1) yet; --path values will not be sent"
            );
        }
    }
    if !opened.backend.is_cloud() {
        let canonicalize = |id: &mut String| -> Result<()> {
            *id = lockyard_compat::LegacyCompatibilityV1::task_id(
                &json!(id),
                lockyard_compat::TaskDomain::LegacyLocal,
                lockyard_compat::Source::Cli,
                2,
            )
            .map_err(|code| Error::Cloud {
                code,
                status: None,
                details: Value::Null,
                message: "invalid local task id".into(),
            })?;
            Ok(())
        };
        match &mut command {
            TaskCommand::WhyBlocked { id }
            | TaskCommand::Links { id }
            | TaskCommand::Show { id }
            | TaskCommand::Plan { id, .. }
            | TaskCommand::Claim { id, .. }
            | TaskCommand::Renew { id, .. }
            | TaskCommand::Release { id, .. }
            | TaskCommand::Submit { id, .. }
            | TaskCommand::Review { id, .. }
            | TaskCommand::Accept { id, .. }
            | TaskCommand::Reject { id, .. }
            | TaskCommand::Cancel { id, .. } => canonicalize(id)?,
            TaskCommand::Link { id, to, .. } => {
                canonicalize(id)?;
                canonicalize(to)?;
            }
            _ => {}
        }
    }
    let store = opened.backend.as_mut();
    let changed = match command {
        TaskCommand::Ready {
            actor,
            area,
            kind,
            limit,
        } => {
            let data = store
                .registry_ready(&json!({"actor":actor,"area":area,"type":kind,"limit":limit}))?;
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::Search {
            query,
            status,
            actor,
            area,
            kind,
            priority,
            limit,
            cursor,
        } => {
            let data = store.registry_search(&json!({"q":query,"status":status,"actor":actor,"area":area,"type":kind,"priority":priority,"limit":limit,"cursor":cursor}))?;
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::WhyBlocked { id } => {
            let data = store.registry_blockers_by_id(&id)?;
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::Links { id } => {
            let item = store.registry_item_by_id(&id)?;
            let data = json!({"id":item["id"],"status":item["status"],"version":item["version"],"links":item["links"]});
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::Link {
            id,
            to,
            kind,
            if_version,
            key,
        } => {
            let key = key.unwrap_or_else(lockyard_cloud_client::ulid);
            let item = store.registry_link_by_id(
                &resolve_agent(agent)?,
                &id,
                &to,
                &kind,
                if_version,
                &key,
            )?;
            let data = json!({"idempotency_key":key,"item":item});
            return output(
                &data,
                serde_json::to_string_pretty(&data).unwrap_or_default(),
            );
        }
        TaskCommand::List { all, status, ready } => {
            if ready && (all || status.is_some()) {
                return Err(Error::Invalid(
                    "task list --ready does not take --all or --status".into(),
                ));
            }
            let tasks = if ready {
                store.ready_tasks(None)?
            } else {
                store.tasks(status, all)?
            };
            let text = join(&tasks, task_line, "no tasks");
            return output(&tasks, text);
        }
        TaskCommand::Show { id } => {
            let task = store.task(&id).map_err(|error| {
                if error.kind() == "not_found" {
                    Error::NotFound(format!("task {id:?} was not found"))
                } else {
                    error
                }
            })?;
            let history = store.task_history(&id)?;
            let mut lines = vec![task_line(&task)];
            if !task.paths.is_empty() {
                lines.push(format!("paths: {}", task.paths.join(", ")));
            }
            if !task.body.is_empty() {
                lines.push(task.body.clone());
            }
            if let Some(evidence) = &task.evidence {
                lines.push(format!("evidence: {evidence}"));
            }
            lines.extend(history.iter().map(|event| {
                format!("{} {} {}", event.agent, event.action, event.note)
                    .trim_end()
                    .to_string()
            }));
            let data = json!({ "task": task, "history": history });
            return output(&data, lines.join("\n"));
        }
        TaskCommand::Add {
            title,
            paths,
            body,
            acceptance,
            priority,
            p0_category,
            kind,
            target,
            verification,
            area,
            prefix,
            pad,
            due,
            evidence,
            ..
        } => store.add_task(
            &resolve_agent(agent)?,
            &TaskSpec {
                title,
                paths,
                body,
                acceptance,
                priority,
                p0_category,
                kind,
                target,
                verification,
                area,
                prefix,
                pad,
                due_at: due,
                evidence,
            },
            now,
        )?,
        TaskCommand::Plan {
            id,
            priority,
            p0_category,
            due,
        } => store.plan_task(
            &resolve_agent(agent)?,
            &id,
            &TaskPlan {
                priority,
                p0_category,
                due_at: due,
            },
        )?,
        TaskCommand::Claim { id, ttl } => {
            store.claim_task(&resolve_agent(agent)?, &id, ttl.ttl, now)?
        }
        TaskCommand::Renew { id, ttl } => {
            store.renew_task(&resolve_agent(agent)?, &id, ttl.ttl, now)?
        }
        TaskCommand::Release { id, note } => {
            store.release_task(&resolve_agent(agent)?, &id, &note, now)?
        }
        TaskCommand::Submit { id, evidence } => {
            store.submit_task(&resolve_agent(agent)?, &id, &evidence, now)?
        }
        TaskCommand::Review {
            id,
            decision,
            reason,
        } => store.review_task(&resolve_agent(agent)?, &id, &decision, &reason, now)?,
        TaskCommand::Accept { id, note } => {
            store.accept_task(&resolve_agent(agent)?, &id, &note, now)?
        }
        TaskCommand::Reject {
            id,
            reason,
            evidence,
        } => store.reject_task(&resolve_agent(agent)?, &id, &reason, &evidence, now)?,
        TaskCommand::Cancel { id, note } => {
            store.cancel_task(&resolve_agent(agent)?, &id, &note, now)?
        }
    };
    output(&changed, task_line(&changed))
}

pub(super) fn work_step(reference: &WorkRef) -> WorkStep {
    WorkStep {
        version: reference.if_version,
        ..WorkStep::default()
    }
}

pub(super) fn run_work(
    mut opened: Opened,
    command: WorkCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let agent = resolve_agent(agent)?;
    let backend = opened.backend.as_mut();
    let (id, action, step) = match command {
        WorkCommand::Offer {
            title,
            to,
            accept,
            brief,
            re,
            zone,
        } => {
            let task = backend.work_offer(
                &agent,
                &WorkOffer {
                    title,
                    to,
                    accept,
                    re,
                    zone,
                    brief,
                },
            )?;
            return output(&task, work_line(&task));
        }
        WorkCommand::List => {
            let tasks = backend.work_list(&agent)?;
            let text = join(&tasks, work_line, "no work tasks");
            return output(&tasks, text);
        }
        WorkCommand::Show { id } => {
            let task = backend.work_get(&agent, &id)?;
            return output(&task, work_line(&task));
        }
        WorkCommand::Claim(task) => (task.id.clone(), WorkAction::Claim, work_step(&task)),
        WorkCommand::Beat(task) => (task.id.clone(), WorkAction::Beat, work_step(&task)),
        WorkCommand::Accept(task) => (task.id.clone(), WorkAction::Accept, work_step(&task)),
        WorkCommand::Done {
            task,
            report,
            commits,
        } => (
            task.id.clone(),
            WorkAction::Done,
            WorkStep {
                report,
                commits,
                ..work_step(&task)
            },
        ),
        WorkCommand::Reject { task, reason } => (
            task.id.clone(),
            WorkAction::Reject,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Fail { task, reason } => (
            task.id.clone(),
            WorkAction::Fail,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Cancel { task, reason } => (
            task.id.clone(),
            WorkAction::Cancel,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Decline { task, reason } => (
            task.id.clone(),
            WorkAction::Decline,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Handoff {
            task,
            to,
            report,
            commits,
        } => (
            task.id.clone(),
            WorkAction::Handoff,
            WorkStep {
                to: Some(to),
                report,
                commits,
                ..work_step(&task)
            },
        ),
        WorkCommand::Take { id, if_version } => (
            id,
            WorkAction::Take,
            WorkStep {
                version: Some(if_version),
                ..WorkStep::default()
            },
        ),
    };
    let task = backend.work_step(&agent, &id, action, &step)?;
    output(&task, work_line(&task))
}
