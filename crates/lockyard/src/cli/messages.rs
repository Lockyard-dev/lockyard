// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn inbox_text(page: &InboxPage) -> String {
    let mut text = join(&page.messages, message_line, "no new mail");
    if page.skipped > 0 {
        text.push_str(&format!("\n{} older messages skipped", page.skipped));
    }
    text
}

pub(super) fn run_msg(
    opened: Opened,
    command: MsgCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let now = now_ms();
    let agent = resolve_agent(agent)?;
    let mut backend = opened.backend;
    match command {
        MsgCommand::Send {
            to,
            body,
            kind,
            needs,
            zone,
            re,
            key,
            ttl,
        } => {
            if to == agent {
                return Err(Error::Invalid("cannot send a message to yourself".into()));
            }
            let request = SendRequest {
                to,
                body,
                kind,
                needs,
                zone,
                re,
                key,
                ttl_minutes: ttl,
                from_client: None,
            };
            let message = backend.send(&agent, &request, now)?;
            let text = sent_line(&message);
            output(&safe_message(message), text)
        }
        MsgCommand::Reply { id, body } => {
            let message = backend.reply(&agent, id, &body, now)?;
            let text = sent_line(&message);
            output(&safe_message(message), text)
        }
        MsgCommand::Inbox { all, peek } => {
            let page = backend.inbox(
                &agent,
                InboxQuery {
                    all,
                    limit: INBOX_LIMIT,
                },
                now,
            )?;
            let text = inbox_text(&page);
            let ids: Vec<i64> = page.messages.iter().map(|message| message.id).collect();
            let mut out = output(&safe_messages(page.messages.clone()), text)?;
            if !peek && !ids.is_empty() {
                // Marked only after the mail is on screen: a duplicate over a loss.
                out.after = Some(Box::new(move || {
                    backend.inbox_seen(&agent, &ids, now_ms()).map(|_| ())
                }));
            }
            Ok(out)
        }
        MsgCommand::Unread => {
            let unread = backend.unread(&agent)?;
            output(&json!({"unread": unread}), format!("unread mail: {unread}"))
        }
        MsgCommand::Ack { id } => {
            backend.ack(&agent, id)?;
            output(&json!({"acked": id}), format!("acked M-{id}"))
        }
        MsgCommand::Thread { id } => {
            let messages = backend.thread(&agent, id)?;
            let text = join(&messages, message_line, "empty thread");
            output(&safe_messages(messages), text)
        }
        MsgCommand::Overdue => {
            let messages = backend.overdue(&agent)?;
            let text = join(&messages, message_line, "nothing overdue");
            output(&safe_messages(messages), text)
        }
        MsgCommand::Sent { limit } => {
            let receipts = backend.sent(&agent, limit)?;
            let line = |receipt: &lockyard_core::bus::Receipt| {
                let first = receipt.body.lines().next().unwrap_or_default();
                format!(
                    "M-{:<5} to {:<12} {:<10} {}",
                    receipt.id,
                    receipt.to,
                    receipt.status.as_str(),
                    escape_controls(first)
                )
            };
            let text = join(&receipts, line, "nothing sent yet");
            output(&safe_receipts(receipts), text)
        }
        MsgCommand::Undelivered { older_than } => {
            let list = backend.undelivered(&agent, older_than)?;
            let line = |entry: &lockyard_core::proto::Undelivered| {
                format!(
                    "M-{}  to {}  {} s old",
                    entry.id, entry.to, entry.age_seconds
                )
            };
            let text = join(&list, line, "nothing undelivered");
            output(&list, text)
        }
    }
}
