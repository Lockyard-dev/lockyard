// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_tool(
    name: &str,
    args: Args<'_>,
    agent: Option<&str>,
    cwd: &Path,
    client: Option<&str>,
    surface: Surface,
    after: &mut Option<After>,
) -> Result<Value> {
    let handler = tool_registry()
        .handler(name)
        .ok_or_else(|| Error::Invalid(format!("unknown tool {name:?}")))?;
    let name = match &handler {
        ToolHandler::Composite(name) => {
            return run_composite(name, args, agent, cwd, client, after);
        }
        ToolHandler::Primitive(name) => name.as_str(),
    };
    if uses_node_transport(name) {
        return node_tool(name, args);
    }
    let now = crate::now_ms();
    let mut opened = open(cwd, agent)?;
    let me = || {
        agent.ok_or_else(|| {
            Error::Invalid(
                "this tool needs an agent name: set LOCKYARD_AGENT or pass --agent".into(),
            )
        })
    };
    let is_cloud = opened.backend.is_cloud();
    let work = |action: WorkAction, opened: &mut Opened| -> Result<Value> {
        encode(
            &opened
                .backend
                .work_step(me()?, &args.bus_key()?, action, &args.step()?)?,
        )
    };
    match name {
        "cloud_protocol" => opened.backend.cloud_protocol(),
        "cloud_drain" => {
            let request = json!({"scope":args.text("scope")?,"instance_id":args.text("instance_id")?,"timeout_seconds":args.some_int("timeout_seconds")?.unwrap_or(30)});
            opened
                .backend
                .cloud_drain(me()?, &request, args.text("idempotency_key")?)
        }
        "cloud_drain_status" => opened.backend.cloud_drain_status(args.text("id")?),
        "zone_catalog_put" => {
            let revision = args.int("expected_revision").and_then(|value| {
                u64::try_from(value)
                    .map_err(|_| wrong_type("expected_revision", "a nonnegative integer"))
            })?;
            opened.backend.catalog_put(
                me()?,
                &args.required_object("catalog")?,
                revision,
                args.text("idempotency_key")?,
            )
        }
        "tasks" => {
            let backend = &mut opened.backend;
            let action = args.some_text("action")?.ok_or_else(|| Error::Invalid(
                "action must be a string; allowed actions: list, show, claim, submit, block, unblock, review, accept, reject, cancel, close".into(),
            ))?;
            match action.as_str() {
                "list" => {
                    let area = args.some_text("area")?;
                    let prefix = args.some_text("prefix")?;
                    let selector = area.as_deref().or(prefix.as_deref());
                    let tasks = backend.ready_tasks(selector)?;
                    encode(&tasks)
                }
                "show" => {
                    let id = args.task_key_for(is_cloud)?;
                    Ok(json!({"task": backend.task(&id)?, "history": backend.task_history(&id)?}))
                }
                "claim" => encode(&backend.claim_task(
                    me()?,
                    &args.task_key_for(is_cloud)?,
                    args.ttl()?,
                    now,
                )?),
                "submit" => {
                    let evidence = executor_evidence(args.text("evidence")?);
                    encode(&backend.submit_task(
                        me()?,
                        &args.task_key_for(is_cloud)?,
                        &evidence,
                        now,
                    )?)
                }
                "block" | "unblock" => encode(&backend.block_task(
                    me()?,
                    &args.task_key_for(is_cloud)?,
                    args.text("action")? == "block",
                    args.optional_text("reason")?,
                    now,
                )?),
                "review" => encode(&backend.review_task(
                    me()?,
                    &args.task_key_for(is_cloud)?,
                    args.text("decision")?,
                    args.optional_text("reason")?,
                    now,
                )?),
                "accept" => encode(&backend.accept_task(
                    me()?,
                    &args.task_key_for(is_cloud)?,
                    args.optional_text("note")?,
                    now,
                )?),
                "reject" => encode(&backend.reject_task(
                    me()?,
                    &args.task_key_for(is_cloud)?,
                    args.text("reason")?,
                    args.optional_text("evidence")?,
                    now,
                )?),
                "cancel" | "close" => encode(&backend.cancel_task(
                    me()?,
                    &args.task_key_for(is_cloud)?,
                    args.optional_text("note")?,
                    now,
                )?),
                other => Err(Error::Invalid(format!("unknown tasks action {other:?}"))),
            }
        }
        "task_bulk" => {
            let ids = args.task_keys("ids")?;
            let evidence = args.optional_text("evidence")?;
            let note = if evidence.is_empty() {
                args.optional_text("note")?
            } else {
                evidence
            };
            if note.trim().is_empty() {
                return Err(Error::Invalid(
                    "bulk close needs evidence of the owner decision".into(),
                ));
            }
            opened.backend.batch_close_tasks(me()?, &ids, note, now)
        }
        "registry_import" => opened
            .backend
            .registry_import(me()?, &args.required_object("dump")?),
        "area_list" => opened.backend.area_list(agent.unwrap_or("lockyard-cli")),
        "area_create" => {
            let request = json!({
                "key": args.text("key")?,
                "name": args.text("name")?,
                "prefix": args.text("prefix")?,
                "pad": args.some_int("pad")?,
            });
            opened.backend.area_create(me()?, &request)
        }
        "area_update" => {
            let key = args.text("key")?;
            let mut request = json!({});
            for field in ["name", "prefix"] {
                if let Some(value) = args.some_text(field)? {
                    request[field] = json!(value);
                }
            }
            if let Some(pad) = args.some_int("pad")? {
                request["pad"] = json!(pad);
            }
            opened.backend.area_update(me()?, key, &request)
        }
        "workflow_run" => crate::workflow::run_with_source(
            &opened.root,
            opened.backend.as_mut(),
            me()?,
            now,
            args.text("operation_id")?,
            args.get("plan")
                .ok_or_else(|| Error::Invalid("plan is required".into()))?,
            lockyard_compat::Source::Mcp,
        ),
        "workflow_inspect" => crate::workflow::inspect(&opened.root, args.text("operation_id")?),
        "context" => crate::context::snapshot(
            opened.backend.as_mut(),
            me()?,
            now,
            &crate::context::ContextOptions {
                limit: usize::try_from(args.some_int("limit")?.unwrap_or(20))
                    .map_err(|_| Error::Invalid("limit must be positive".into()))?,
                max_bytes: usize::try_from(args.some_int("max_bytes")?.unwrap_or(8192))
                    .map_err(|_| Error::Invalid("max_bytes must be positive".into()))?,
                cursor: args.some_text("cursor")?,
            },
        ),
        "task_ready" => opened.backend.registry_ready(args.0),
        "task_search" => opened.backend.registry_search(args.0),
        "task_why_blocked" => opened
            .backend
            .registry_blockers_by_id(&args.task_key("id")?),
        "task_links" => {
            let item = opened.backend.registry_item_by_id(&args.task_key("id")?)?;
            Ok(
                json!({"id":item["id"],"status":item["status"],"version":item["version"],"links":item["links"]}),
            )
        }
        "task_link" => opened.backend.registry_link_by_id(
            me()?,
            &args.task_key("id")?,
            &args.task_key("to")?,
            args.text("kind")?,
            args.int("if_version")?,
            args.text("key")?,
        ),
        "who" => encode(&opened.backend.agents()?),
        "status" => {
            let backend = opened.backend.as_mut();
            let unread = agent.map(|name| backend.unread(name)).transpose()?;
            let claims = backend.claims(
                &ClaimQuery {
                    session: agent.map(str::to_string),
                    path: None,
                },
                now,
            )?;
            if backend.is_cloud() {
                let work = visible_work(agent, backend.work_list(agent.unwrap_or("lockyard-cli"))?);
                let mut work = work;
                work.truncate(10);
                let work: Vec<Value> = work
                    .into_iter()
                    .map(|item| json!({"id": item.id, "title": item.title, "status": item.status, "assignee": item.assignee, "to": item.to}))
                    .collect();
                let (claims, offers) = match agent {
                    Some(name) => split_handover_offers(name, claims),
                    None => (claims, Vec::new()),
                };
                let mut tasks = backend.assigned_tasks(agent.unwrap_or("lockyard-cli"))?;
                tasks.truncate(20);
                return Ok(
                    json!({"unread": unread, "claims": claims, "work": work, "offers": offers, "tasks": tasks}),
                );
            }
            let mut tasks = backend.tasks(None, false)?;
            tasks.retain(|task| task.assignee.as_deref() == agent);
            tasks.truncate(20);
            let tasks: Vec<Value> = tasks
                .into_iter()
                .map(|task| {
                    json!({
                        "id": task.id, "title": task.title, "status": task.status,
                        "priority": task.priority, "assignee": task.assignee
                    })
                })
                .collect();
            Ok(json!({"unread": unread, "claims": claims, "tasks": tasks}))
        }
        "zone_claim" => {
            let request = claim_request(&opened, args, cwd)?;
            let claim =
                lockyard_core::claim_or_reuse(opened.backend.as_mut(), me()?, &request, now)?;
            encode(&claim)
        }
        "zone_wait" => {
            let request = claim_request(&opened, args, cwd)?;
            let seconds = args.some_int("seconds")?.unwrap_or(DEFAULT_WAIT_SECONDS);
            let seconds =
                u64::try_from(seconds).map_err(|_| wrong_type("seconds", "not negative"))?;
            encode(&crate::wait_for_claim(
                opened.backend.as_mut(),
                me()?,
                request,
                seconds,
            )?)
        }
        "zone_queue" => {
            let (paths, zones) = claim_paths(&opened, args, cwd)?;
            if paths.is_empty() {
                return encode(&opened.backend.queue_list(me()?)?);
            }
            let request = QueueRequest {
                paths,
                note: args.optional_text("note")?.to_string(),
                ttl_minutes: args.some_int("ttl")?.unwrap_or(DEFAULT_QUEUE_MINUTES),
                mode: args.mode()?,
                purpose: args.purpose()?,
                zones,
            };
            encode(&opened.backend.queue_add(me()?, &request)?)
        }
        "zone_unwait" => {
            let id = args.id()?;
            opened.backend.queue_cancel(me()?, id)?;
            Ok(json!({"cancelled": id}))
        }
        "zone_request" => {
            let request = AccessRequest {
                paths: opened.zone_paths(cwd, &args.strings("paths")?)?,
                text: args.text("text")?.to_string(),
                urgent: args.flag("urgent")?,
                need_by: args.some_text("need_by")?,
            };
            encode(&opened.backend.zone_request(me()?, &request)?)
        }
        "zone_answer" => {
            let answer = AccessAnswer {
                reply: args.some_text("reply")?,
                eta: args.some_text("eta")?,
            };
            encode(&opened.backend.zone_answer(me()?, args.id()?, &answer)?)
        }
        "zone_handover" => {
            opened
                .backend
                .handover(me()?, args.id()?, args.text("to")?, args.some_int("fence")?)
        }
        "zone_accept" => encode(&opened.backend.handover_accept(me()?, args.id()?)?),
        "zone_narrow" => {
            let paths = opened.zone_paths(cwd, &args.strings("paths")?)?;
            encode(
                &opened
                    .backend
                    .narrow(me()?, args.id()?, &paths, args.some_int("fence")?)?,
            )
        }
        "zone_add_path" => {
            let path = opened.zone_path(cwd, args.text("path")?)?;
            encode(
                &opened
                    .backend
                    .add_path(me()?, args.id()?, &path, args.some_int("fence")?)?,
            )
        }
        "zone_takeover" => encode(&opened.backend.takeover(
            me()?,
            args.id()?,
            args.text("reason")?,
        )?),
        "zone_dirty" => {
            let (owner, reason) = (args.some_text("owner")?, args.some_text("reason")?);
            let task = args
                .some_task_id("task")?
                .map(|id| lockyard_core::task_id::TaskId::parse(&id))
                .transpose()?;
            let paths = opened.zone_paths(cwd, &args.strings("paths")?)?;
            let report: Vec<DirtyPath> = paths
                .into_iter()
                .map(|path| DirtyPath {
                    path,
                    owner_session: owner.clone(),
                    reason: reason.clone(),
                    task_id: task.clone(),
                })
                .collect();
            opened.backend.dirty_report(me()?, &report)?;
            encode(&report)
        }
        "zone_dirty_list" => {
            let path = args
                .some_text("path")?
                .map(|raw| opened.zone_path(cwd, &raw))
                .transpose()?;
            encode(&opened.backend.dirty_list(me()?, path.as_deref())?)
        }
        "zone_dirty_disown" => {
            let paths = opened.zone_paths(cwd, &args.strings("paths")?)?;
            opened.backend.dirty_disown(me()?, &paths)?;
            Ok(json!({"disowned": paths}))
        }
        "zone_dirty_adopt" => {
            let paths = opened.zone_paths(cwd, &args.strings("paths")?)?;
            opened
                .backend
                .dirty_adopt(me()?, &paths, args.text("reason")?)?;
            Ok(json!({"adopted": paths}))
        }
        "zone_activity" => {
            let id = args.id()?;
            let request = ActivityRequest {
                write: args.flag("write")?,
                paths: opened.zone_paths(cwd, &args.strings("paths")?)?,
                fence: args.some_int("fence")?,
            };
            opened.backend.activity(me()?, id, &request)?;
            Ok(json!({"reported": id}))
        }
        "zone_lost" => encode(&opened.backend.lost(me()?)?),
        "zone_catalog" => opened.backend.catalog(),
        "zone_renew" => {
            let fence = args.some_int("fence")?;
            if surface == Surface::Compact && is_cloud && fence.is_none() {
                return Err(Error::Invalid("fence is required in cloud mode".into()));
            }
            let request = RenewRequest {
                ttl_minutes: args.ttl()?,
                hold_reason: args.some_text("hold_reason")?,
                hold_until: args.some_text("hold_until")?,
                fence: if surface == Surface::Compact && !is_cloud {
                    None
                } else {
                    fence
                },
            };
            let renewed = opened
                .backend
                .renew(me()?, args.optional_id()?, &request, now)?;
            Ok(json!({"renewed": renewed}))
        }
        "zone_release" => {
            let request = ReleaseRequest {
                note: args.some_text("note")?,
                leave_dirty: args.flag("leave_dirty")?,
                fence: args.some_int("fence")?,
            };
            let released = opened
                .backend
                .release(me()?, args.optional_id()?, &request, now)?;
            Ok(json!({"released": released}))
        }
        "zone_list" => {
            let path = args
                .some_text("path")?
                .map(|raw| opened.zone_path(cwd, &raw))
                .transpose()?;
            let query = ClaimQuery {
                session: args.some_text("session")?,
                path,
            };
            encode(&opened.backend.claims(&query, now)?)
        }
        "zone_check" => {
            let path = opened.zone_path(cwd, args.text("path")?)?;
            let mut checks = opened
                .backend
                .check(me()?, std::slice::from_ref(&path), None, now)?;
            let found = (!checks.is_empty()).then(|| checks.remove(0));
            match found {
                Some(check) if check.status == CheckStatus::Held => {
                    Ok(json!({"free": false, "holder": check.holder}))
                }
                Some(check) if check.status == CheckStatus::Unknown => Ok(json!({"unknown": true})),
                Some(check) if check.status == CheckStatus::Own => {
                    Ok(json!({"free": false, "own": true, "holder": "you"}))
                }
                Some(check) if check.status == CheckStatus::Free => {
                    let own = opened.backend.claims(
                        &ClaimQuery {
                            session: Some(me()?.to_string()),
                            path: Some(path.clone()),
                        },
                        now,
                    )?;
                    let held_by_me = own.iter().any(|claim| {
                        claim.paths.iter().any(|held| {
                            lockyard_core::ZonePath::stored(held.clone())
                                .contains(&lockyard_core::ZonePath::stored(path.clone()))
                        })
                    });
                    if !held_by_me {
                        Ok(json!({"free": true}))
                    } else {
                        Ok(json!({"free": false, "own": true, "holder": "you"}))
                    }
                }
                _ => Ok(json!({"free": true})),
            }
        }
        "msg_send" => {
            let to = resolve_target(cwd, agent, args.text("to")?)?;
            if me()? == to {
                return Err(Error::Invalid("cannot send a message to yourself".into()));
            }
            let request = SendRequest {
                to,
                body: args.text("body")?.to_string(),
                from_client: client.map(str::to_string),
                kind: args.some_text("kind")?,
                needs: args.some_text("needs")?,
                zone: args.some_text("zone")?,
                re: args.some_text("re")?,
                key: args.some_text("key")?,
                ttl_minutes: args.some_int("ttl")?,
            };
            let mut message = opened.backend.send(me()?, &request, now)?;
            message.body = escape_bidi_controls(&message.body);
            encode(&message)
        }
        "msg_reply" => {
            let mut message = opened
                .backend
                .reply(me()?, args.id()?, args.text("body")?, now)?;
            message.body = escape_bidi_controls(&message.body);
            encode(&message)
        }
        "msg_inbox" => {
            let (all, peek) = (args.flag("all")?, args.flag("peek")?);
            let reader = me()?.to_string();
            let page = opened.backend.inbox(
                &reader,
                InboxQuery {
                    all,
                    limit: INBOX_LIMIT,
                },
                now,
            )?;
            let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
            let answer = encode(&safe_messages(page.messages))?;
            if !peek && !ids.is_empty() {
                let mut backend = opened.backend;
                *after = Some(Box::new(move || {
                    backend
                        .inbox_seen(&reader, &ids, crate::now_ms())
                        .map(|_| ())
                }));
            }
            Ok(answer)
        }
        "msg_unread" => Ok(json!({"unread": opened.backend.unread(me()?)?})),
        "msg_ack" => {
            let id = args.id()?;
            opened.backend.ack(me()?, id)?;
            Ok(json!({"acked": id}))
        }
        "msg_thread" => encode(&safe_messages(opened.backend.thread(me()?, args.id()?)?)),
        "msg_overdue" => encode(&safe_messages(opened.backend.overdue(me()?)?)),
        "msg_undelivered" => encode(
            &opened
                .backend
                .undelivered(me()?, args.some_int("older_than")?.unwrap_or(0))?,
        ),
        "msg_sent" => {
            let limit = args.some_int("limit")?.unwrap_or(20).clamp(1, 200);
            encode(&safe_receipts(opened.backend.sent(me()?, limit as usize)?))
        }
        "task_add" => {
            let spec = TaskSpec {
                title: args.text("title")?.to_string(),
                body: args.optional_text("body")?.to_string(),
                acceptance: args.some_text("acceptance")?,
                priority: args.some_text("priority")?,
                p0_category: args.some_text("p0_category")?,
                kind: args.some_text("type")?,
                target: args.some_text("target")?,
                verification: args.some_text("verification")?,
                area: args.some_text("area")?,
                prefix: args.some_text("prefix")?,
                pad: args
                    .some_int("pad")?
                    .map(|value| {
                        u8::try_from(value)
                            .map_err(|_| Error::Invalid("pad must be 0 to 255".into()))
                    })
                    .transpose()?,
                due_at: args.some_text("due")?,
                evidence: args.some_text("evidence")?,
            };
            encode(&opened.backend.add_task(me()?, &spec, now)?)
        }
        "task_plan" => {
            let plan = TaskPlan {
                priority: args.some_text("priority")?,
                p0_category: args.some_text("p0_category")?,
                due_at: args.some_text("due")?,
            };
            encode(
                &opened
                    .backend
                    .plan_task(me()?, &args.task_key_for(is_cloud)?, &plan)?,
            )
        }
        "task_list" => {
            let area = args.some_text("area")?;
            let prefix = args.some_text("prefix")?;
            let selector = area.as_deref().or(prefix.as_deref());
            let requested_status = args.some_text("status")?;
            if requested_status.as_deref() == Some("ready")
                || (selector.is_some() && requested_status.is_none())
            {
                return encode(&opened.backend.ready_tasks(selector)?);
            }
            if selector.is_some() {
                return Err(Error::Invalid(
                    "area and prefix filters require status ready (or no status)".into(),
                ));
            }
            let status = args
                .get("status")
                .map(|_| {
                    let text = args.text("status")?;
                    Status::parse(text)
                        .ok_or_else(|| Error::Invalid(format!("unknown task status {text:?}")))
                })
                .transpose()?;
            encode(&opened.backend.tasks(status, args.flag("all")?)?)
        }
        "task_show" => {
            let id = args.task_key_for(is_cloud)?;
            let task = opened.backend.task(&id)?;
            let history = opened.backend.task_history(&id)?;
            Ok(json!({"task": task, "history": history}))
        }
        "task_claim" => encode(&opened.backend.claim_task(
            me()?,
            &args.task_key_for(is_cloud)?,
            args.ttl()?,
            now,
        )?),
        "task_renew" => encode(&opened.backend.renew_task(
            me()?,
            &args.task_key_for(is_cloud)?,
            args.ttl()?,
            now,
        )?),
        "task_release" => {
            let note = args.optional_text("note")?;
            encode(
                &opened
                    .backend
                    .release_task(me()?, &args.task_key_for(is_cloud)?, note, now)?,
            )
        }
        "task_submit" => {
            let evidence = executor_evidence(args.text("evidence")?);
            encode(&opened.backend.submit_task(
                me()?,
                &args.task_key_for(is_cloud)?,
                &evidence,
                now,
            )?)
        }
        "task_review" => encode(&opened.backend.review_task(
            me()?,
            &args.task_key_for(is_cloud)?,
            args.text("decision")?,
            args.optional_text("reason")?,
            now,
        )?),
        "task_accept" => {
            let note = args.optional_text("note")?;
            encode(
                &opened
                    .backend
                    .accept_task(me()?, &args.task_key_for(is_cloud)?, note, now)?,
            )
        }
        "task_reject" => {
            let reason = args.text("reason")?;
            let evidence = args.optional_text("evidence")?;
            encode(&opened.backend.reject_task(
                me()?,
                &args.task_key_for(is_cloud)?,
                reason,
                evidence,
                now,
            )?)
        }
        "task_cancel" => {
            let note = args.optional_text("note")?;
            encode(
                &opened
                    .backend
                    .cancel_task(me()?, &args.task_key_for(is_cloud)?, note, now)?,
            )
        }
        "board_set" => {
            let write = BoardWrite {
                key: args.text("key")?.to_string(),
                value: args.text("value")?.to_string(),
                zone: args.some_text("zone")?,
                ttl_minutes: args.some_int("ttl")?,
            };
            encode(
                &opened
                    .backend
                    .board_set(agent.unwrap_or("lockyard-cli"), &write, now)?,
            )
        }
        "board_get" => encode(&opened.backend.board_get(args.text("key")?, now)?),
        "board_remove" => {
            let removed = opened
                .backend
                .board_remove(agent.unwrap_or("lockyard-cli"), args.text("key")?)?;
            Ok(json!({"removed": removed}))
        }
        "board_list" => {
            let zone = args.some_text("zone")?;
            encode(&opened.backend.board_list(zone.as_deref(), now)?)
        }
        "work_offer" => {
            let offer = WorkOffer {
                title: args.text("title")?.to_string(),
                to: args.text("to")?.to_string(),
                accept: args.text("accept")?.to_string(),
                re: args.some_text("re")?,
                zone: args.some_text("zone")?,
                brief: args.some_text("brief")?,
            };
            encode(&opened.backend.work_offer(me()?, &offer)?)
        }
        "work_list" => encode(&opened.backend.work_list(me()?)?),
        "work_show" => encode(&opened.backend.work_get(me()?, &args.bus_key()?)?),
        "work_claim" => work(WorkAction::Claim, &mut opened),
        "work_beat" => work(WorkAction::Beat, &mut opened),
        "work_done" => work(WorkAction::Done, &mut opened),
        "work_accept" => work(WorkAction::Accept, &mut opened),
        "work_reject" => work(WorkAction::Reject, &mut opened),
        "work_fail" => work(WorkAction::Fail, &mut opened),
        "work_cancel" => work(WorkAction::Cancel, &mut opened),
        "work_decline" => work(WorkAction::Decline, &mut opened),
        "work_handoff" => work(WorkAction::Handoff, &mut opened),
        "work_take" => work(WorkAction::Take, &mut opened),
        "events" => {
            let query = EventQuery {
                stream: stream(args)?,
                after: args.some_int("after")?.unwrap_or(0),
                wait_seconds: u64::try_from(args.some_int("wait")?.unwrap_or(0)).unwrap_or(0),
                session: agent.map(str::to_string),
                types: args.strings("types")?,
            };
            encode(&opened.backend.events(&query)?.events)
        }
        "presence" => {
            let within = args
                .some_int("active_within")?
                .unwrap_or(DEFAULT_ACTIVE_SECONDS);
            encode(&opened.backend.presence(within, now)?)
        }
        "presence_beat" => {
            let tool_running = args.flag("tool_running")?;
            let state = session_state(args.some_text("state")?)?;
            let meta = args.get("meta").cloned();
            let activity =
                (tool_running || state.is_some() || meta.is_some()).then(|| SessionActivity {
                    tool_running,
                    tool_started_at: tool_running.then_some(Stamp::Millis(now)),
                    state,
                    meta,
                });
            let beat = PresenceBeat {
                client: args
                    .some_text("client")?
                    .unwrap_or_else(|| "mcp".to_string()),
                model: args.some_text("model")?,
                role: args.some_text("role")?,
                version: Some(lockyard_core::VERSION.to_string()),
                cwd: args.some_text("cwd")?,
                dnd_until: None,
                activity,
            };
            opened.backend.heartbeat(me()?, &beat, now)?;
            Ok(json!({"beat": true}))
        }
        "cloud_export" => opened.backend.export(),
        "cloud_freeze" => {
            let freeze = Freeze {
                on: args.flag("on")?,
                reason: args.optional_text("reason")?.to_string(),
            };
            opened.backend.freeze(me()?, &freeze)
        }
        _ => Err(Error::Invalid(format!("unknown tool {name:?}"))),
    }
}
