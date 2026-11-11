// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// Runs one composite tool as the full tools it stands for, in order.
///
/// Each step is the same call an agent on the full surface would make, so a conflict is still a
/// refusal. `start_work` undoes its own claim when the task it was asked for cannot be taken:
/// a zone held for work that never started is exactly the stuck lease leases exist to prevent.
pub(super) fn run_composite(
    name: &str,
    args: Args<'_>,
    agent: Option<&str>,
    cwd: &Path,
    client: Option<&str>,
    after: &mut Option<After>,
) -> Result<Value> {
    let step = |tool: &str, arguments: Value, after: &mut Option<After>| {
        run_tool(
            tool,
            Args(&arguments),
            agent,
            cwd,
            client,
            Surface::Full,
            after,
        )
    };
    match name {
        "start_work" => {
            let paths = args.strings("paths")?;
            let hold_reason = args.some_text("hold_reason")?;
            let hold_until = args.some_text("hold_until")?;
            lockyard_core::validate_hold(hold_reason.as_deref(), hold_until.as_deref())?;
            if let Some(id) = args.some_int("handover_id")? {
                if hold_reason.is_some() {
                    return Err(Error::Invalid(
                        "a hold needs paths or zones; renew an accepted handover with zone_renew"
                            .into(),
                    ));
                }
                return Ok(json!({"accepted": step("zone_accept", json!({"id": id}), after)?}));
            }
            // Reject malformed task arguments before creating any lease.
            let task = args.some_task_id("task")?;
            if args.get("task").is_some() && paths.is_empty() && args.strings("zones")?.is_empty() {
                if hold_reason.is_some() {
                    return Err(Error::Invalid("a hold needs a path or zone claim".into()));
                }
                // A registry task claim does not need a path claim.
                let id = task.expect("checked above");
                return Ok(json!({"task": step("task_claim", json!({"id": id}), after)?}));
            }
            let zones = args.strings("zones")?;
            if paths.is_empty() && zones.is_empty() {
                return Err(Error::Invalid(
                    "start_work needs paths or zones (or handover_id to accept an offer)".into(),
                ));
            }
            let arguments = json!({
                "paths": paths,
                "note": args.optional_text("note")?,
                "ttl": args.get("ttl").cloned(),
                "shared": args.flag("shared")?,
                "zones": zones,
            });
            let (claim, rollback) = {
                let me =
                    agent.ok_or_else(|| Error::Invalid("this write needs an agent name".into()))?;
                let mut opened = open(cwd, agent)?;
                let mut request = claim_request(&opened, Args(&arguments), cwd)?;
                let cloud = opened.backend.is_cloud();
                let nonce = (cloud && (task.is_some() || hold_reason.is_some()))
                    .then(lockyard_cloud_client::ulid);
                if let Some(nonce) = nonce.as_ref() {
                    request.meta = Some(json!({"lockyard_start_work_nonce": nonce}));
                }
                let (claim, created) = lockyard_core::claim_or_reuse_with_hold(
                    opened.backend.as_mut(),
                    me,
                    &request,
                    hold_reason,
                    hold_until,
                    crate::now_ms(),
                )?;
                // Unknown legacy responses preserve the lease. Ownership and a
                // matching fence alone do not prove creation within one session.
                let rollback = (created == Some(true)
                    && (!cloud || (claim.id > 0 && claim.fence > 0)))
                    .then_some((claim.id, cloud.then_some(claim.fence)));
                (encode(&claim)?, rollback)
            };
            let mut answer = json!({"claim": claim});
            if let Some(id) = task {
                match step("task_claim", json!({"id": id}), after) {
                    Ok(task) => answer["task"] = task,
                    Err(failure) => {
                        if let Some((id, fence)) = rollback {
                            let mut release = json!({"id": id});
                            if let Some(fence) = fence {
                                release["fence"] = json!(fence);
                            }
                            let _ = step("zone_release", release, after);
                        }
                        return Err(failure);
                    }
                }
            }
            if let Some(name) = agent {
                answer["unread"] = step("msg_unread", json!({}), after)?["unread"].clone();
                answer["agent"] = json!(name);
            }
            Ok(answer)
        }
        "update" => {
            let mut answer = json!({});
            if let (Some(to), Some(body)) = (args.some_text("to")?, args.some_text("body")?) {
                let to = resolve_target(cwd, agent, &to)?;
                answer["sent"] = step("msg_send", json!({"to": to, "body": body}), after)?;
            } else if args.get("to").is_some() || args.get("body").is_some() {
                return Err(Error::Invalid(
                    "sending a note needs both to and body".into(),
                ));
            }
            answer["mail"] = step(
                "msg_inbox",
                json!({"peek": args.flag("peek")?, "all": args.flag("all")?}),
                after,
            )?;
            Ok(answer)
        }
        "handover" => {
            let note = args.optional_text("note")?;
            // Only the cloud can offer a claim to a named agent; locally the honest move is to
            // let it go and say so, rather than pretend the other agent now holds it.
            let cloud = open(cwd, agent)?.backend.is_cloud();
            let id = if cloud {
                match args.optional_id()? {
                    Some(id) => {
                        let claims = open(cwd, agent)?.backend.claims(
                            &ClaimQuery {
                                session: agent.map(str::to_string),
                                path: None,
                            },
                            crate::now_ms(),
                        )?;
                        validate_handover_claim(id, &claims)?;
                        id
                    }
                    None => {
                        let claims = open(cwd, agent)?.backend.claims(
                            &ClaimQuery {
                                session: agent.map(str::to_string),
                                path: None,
                            },
                            crate::now_ms(),
                        )?;
                        match claims.as_slice() {
                            [claim] => claim.id,
                            [] => {
                                return Err(Error::Invalid(
                                    "you have no claim to hand over".into(),
                                ));
                            }
                            many => {
                                return Err(Error::Invalid(format!(
                                    "choose a claim id: {}",
                                    many.iter()
                                        .map(|c| c.id.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )));
                            }
                        }
                    }
                }
            } else {
                let selected = args.optional_id()?;
                let ids = if selected.is_none() {
                    owned_claim_ids(
                        agent,
                        open(cwd, agent)?.backend.claims(
                            &ClaimQuery {
                                session: agent.map(str::to_string),
                                path: None,
                            },
                            crate::now_ms(),
                        )?,
                    )
                } else {
                    Vec::new()
                };
                if ids.len() > 1 {
                    return Err(Error::Invalid(format!(
                        "choose a claim id: {}",
                        ids.iter()
                            .map(i64::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                release_target(selected, false, &ids)?.unwrap_or_default()
            };
            let to = resolve_target(cwd, agent, args.text("to")?)?;
            let body = if cloud {
                // The sender is this agent; `to` is the receiver reading the letter.
                format!(
                    "Lockyard: zone Z-{id} offered to you by {}; accept it with start_work({{\"handover_id\": {id}}}). {}",
                    agent.unwrap_or("another agent"),
                    note
                )
            } else {
                format!("Lockyard: claim released for you to take. {}", note)
            };
            let mut answer = if cloud {
                json!({"mode": "offered", "claim": step("zone_handover", json!({"id": id, "to": to}), after)?})
            } else {
                let released = if id == 0 && args.optional_id()?.is_none() {
                    json!({"released": 0})
                } else {
                    step("zone_release", json!({"id": id, "note": note}), after)?
                };
                json!({"mode": "released", "released": released["released"].clone()})
            };
            answer["message"] = if cloud {
                step(
                    "msg_send",
                    json!({"to": to, "body": body, "kind": "ask", "needs": "reply", "zone": format!("Z-{id}")}),
                    after,
                )?
            } else {
                step("msg_send", json!({"to": to, "body": body}), after)?
            };
            Ok(answer)
        }
        "finish_work" => {
            let mut answer = json!({});
            let id = args.optional_claim_id()?;
            let all = args.flag("all")?;
            if id.is_some() && all {
                return Err(Error::Invalid("pass id or all: true, not both".into()));
            }
            let released_ids = match id {
                Some(id) => vec![id],
                None => owned_claim_ids(
                    agent,
                    open(cwd, agent)?.backend.claims(
                        &ClaimQuery {
                            session: agent.map(str::to_string),
                            path: None,
                        },
                        crate::now_ms(),
                    )?,
                ),
            };
            // Resolve ambiguity before task_submit: a refusal must leave the task untouched.
            let target = release_target(id, all, &released_ids)?;
            let note = args.optional_text("note")?;
            if let Some(id) = args.some_task_id("task")? {
                let evidence = args.some_text("evidence")?.ok_or_else(|| {
                    Error::Invalid("finishing a task needs evidence of the work".into())
                })?;
                let evidence = executor_evidence(&evidence);
                answer["task"] = step(
                    "task_submit",
                    json!({"id": id, "evidence": evidence}),
                    after,
                )?;
            }
            let release = match target {
                Some(id) => json!({"id": id, "note": note}),
                None => json!({"note": note, "all": true}),
            };
            let released = if released_ids.is_empty() {
                json!(0)
            } else {
                step("zone_release", release, after)?["released"].clone()
            };
            answer["released"] = released.clone();
            answer["released_ids"] = json!(released_ids);
            Ok(answer)
        }
        _ => Err(Error::Invalid(format!("unknown tool {name:?}"))),
    }
}

fn release_target(id: Option<i64>, all: bool, owned: &[i64]) -> Result<Option<i64>> {
    if id.is_some() && all {
        return Err(Error::Invalid("pass id or all: true, not both".into()));
    }
    if let Some(id) = id {
        return Ok(Some(id));
    }
    match owned {
        [] => Ok(None),
        [id] => Ok(Some(*id)),
        _ if all => Ok(None),
        many => Err(Error::Invalid(format!(
            "multiple claims: {}; pass id or all: true",
            many.iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

pub(super) fn owned_claim_ids(agent: Option<&str>, claims: Vec<Claim>) -> Vec<i64> {
    claims
        .into_iter()
        .filter(|claim| Some(claim.session.as_str()) == agent)
        .map(|claim| claim.id)
        .collect()
}

pub(super) fn resolve_target(cwd: &Path, agent: Option<&str>, target: &str) -> Result<String> {
    let backend = open(cwd, agent)?;
    let presence = backend.backend.presence(24 * 60 * 60, crate::now_ms())?;
    resolve_presence_target(&presence, target)
}

pub(super) fn resolve_presence_target(
    presence: &[lockyard_core::proto::Presence],
    target: &str,
) -> Result<String> {
    if presence.iter().any(|person| person.session == target) {
        return Ok(target.to_string());
    }
    if target.is_empty() {
        return Err(Error::Invalid("an agent name must not be empty".into()));
    }
    let exact_aliases: Vec<_> = presence
        .iter()
        .filter(|person| {
            person
                .alias
                .as_deref()
                .is_some_and(|alias| alias.eq_ignore_ascii_case(target))
        })
        .collect();
    let candidates = if exact_aliases.is_empty() {
        presence
            .iter()
            .filter(|person| {
                person.session.starts_with(target)
                    || person.alias.as_deref().is_some_and(|alias| {
                        alias.to_lowercase().starts_with(&target.to_lowercase())
                    })
                    || person.client == target
                    || person.client.starts_with(target)
            })
            .collect::<Vec<_>>()
    } else {
        exact_aliases
    };
    let sessions: std::collections::BTreeSet<_> = candidates
        .iter()
        .map(|person| person.session.as_str())
        .collect();
    match sessions.len() {
        0 => Ok(target.to_string()), // The server also resolves aliases outside this presence snapshot.
        1 => Ok(sessions.into_iter().next().unwrap().to_string()),
        _ => Err(Error::Invalid(format!(
            "agent {target:?} is ambiguous; use an exact session name or alias: {}",
            sessions.into_iter().collect::<Vec<_>>().join(", ")
        ))),
    }
}
