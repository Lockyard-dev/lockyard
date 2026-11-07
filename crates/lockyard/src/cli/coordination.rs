// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn run_board(
    mut opened: Opened,
    command: BoardCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let now = now_ms();
    let backend = opened.backend.as_mut();
    match command {
        BoardCommand::Set {
            key,
            value,
            zone,
            ttl,
        } => {
            let write = BoardWrite {
                key,
                value,
                zone,
                ttl_minutes: ttl,
            };
            let entry = backend.board_set(&resolve_agent(agent)?, &write, now)?;
            output(&entry, board_line(&entry))
        }
        BoardCommand::Get { key } => match backend.board_get(&key, now)? {
            Some(entry) => output(&entry, board_line(&entry)),
            None => Err(Error::NotFound(format!("board key {key:?} not found"))),
        },
        BoardCommand::Rm { key } => {
            let removed = backend.board_remove(&resolve_agent(agent)?, &key)?;
            output(
                &json!({"removed": removed}),
                if removed { "removed" } else { "no such key" },
            )
        }
        BoardCommand::List { zone } => {
            let entries = backend.board_list(zone.as_deref(), now)?;
            let text = join(&entries, board_line, "the board is empty");
            output(&entries, text)
        }
    }
}

pub(super) fn run_events(
    opened: &Opened,
    args: EventsArgs,
    agent: Option<&String>,
) -> Result<Output> {
    let stream = match args.stream {
        StreamName::Coordination => Stream::Coordination,
        StreamName::Registry => Stream::Registry,
    };
    let query = EventQuery {
        stream,
        after: args.after,
        wait_seconds: args.wait,
        session: agent.cloned().or_else(env_agent),
        types: args.types,
    };
    let page = opened.backend.events(&query)?;
    let line = |event: &lockyard_core::proto::Event| format!("{}  {}", event.seq, event.kind);
    let text = join(&page.events, line, "no events");
    output(&page.events, text)
}

pub(super) fn run_presence(
    mut opened: Opened,
    command: PresenceCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let now = now_ms();
    match command {
        PresenceCommand::List { active_within } => {
            let live = opened.backend.presence(active_within, now)?;
            let line = |entry: &lockyard_core::proto::Presence| {
                format!("{}  {}  {}", entry.session, entry.client, entry.last_seen)
            };
            let text = join(&live, line, "nobody active");
            output(&live, text)
        }
        PresenceCommand::Beat {
            client,
            role,
            model,
            cwd,
            dnd_until,
            tool_running,
            state,
            meta,
        } => {
            let state = state.map(|name| match name {
                StateName::Working => SessionState::Working,
                StateName::Idle => SessionState::Idle,
                StateName::Ended => SessionState::Ended,
                StateName::ApiFailure => SessionState::ApiFailure,
            });
            let activity =
                (tool_running || state.is_some() || meta.is_some()).then(|| SessionActivity {
                    tool_running,
                    tool_started_at: tool_running.then_some(Stamp::Millis(now)),
                    state,
                    meta,
                });
            let beat = PresenceBeat {
                client,
                model,
                role,
                version: Some(lockyard_core::VERSION.to_string()),
                cwd,
                dnd_until: dnd_until.map(Stamp::Millis),
                activity,
            };
            opened
                .backend
                .heartbeat(&resolve_agent(agent)?, &beat, now)?;
            output(&json!({"beat": true}), "beat")
        }
    }
}
