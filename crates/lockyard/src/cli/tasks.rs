// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_task(
    mut opened: Opened,
    command: TaskCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let now = now_ms();
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
        } => store.add_task(
            &resolve_agent(agent)?,
            &TaskSpec {
                title,
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
            let task = backend.work_get(&agent, id)?;
            return output(&task, work_line(&task));
        }
        WorkCommand::Claim(task) => (task.id, WorkAction::Claim, work_step(&task)),
        WorkCommand::Beat(task) => (task.id, WorkAction::Beat, work_step(&task)),
        WorkCommand::Accept(task) => (task.id, WorkAction::Accept, work_step(&task)),
        WorkCommand::Done {
            task,
            report,
            commits,
        } => (
            task.id,
            WorkAction::Done,
            WorkStep {
                report,
                commits,
                ..work_step(&task)
            },
        ),
        WorkCommand::Reject { task, reason } => (
            task.id,
            WorkAction::Reject,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Fail { task, reason } => (
            task.id,
            WorkAction::Fail,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Cancel { task, reason } => (
            task.id,
            WorkAction::Cancel,
            WorkStep {
                reason,
                ..work_step(&task)
            },
        ),
        WorkCommand::Decline { task, reason } => (
            task.id,
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
            task.id,
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
    let task = backend.work_step(&agent, id, action, &step)?;
    output(&task, work_line(&task))
}
