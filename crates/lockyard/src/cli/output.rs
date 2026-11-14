// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// Output of one command: the data for `--json` and the lines for a person.
pub(super) struct Output {
    pub(super) json: Value,
    pub(super) text: String,
    pub(super) after: Option<After>,
    pub(super) exit: u8,
}

pub(super) fn output(data: &impl Serialize, text: impl Into<String>) -> Result<Output> {
    let json = serde_json::to_value(data)
        .map_err(|error| Error::Invalid(format!("cannot encode output: {error}")))?;
    Ok(Output {
        json,
        text: text.into(),
        after: None,
        exit: 0,
    })
}

pub(super) fn minutes_left(expires_at: i64, now: i64) -> i64 {
    ((expires_at - now).max(0) + 59_999) / 60_000
}

/// Local leases count down on the local clock. A cloud lease is shown as the server stated it.
pub(super) fn claim_line(claim: &Claim, clock: Option<i64>) -> String {
    let left = match (&claim.expires_at, clock) {
        (Stamp::Millis(expires_at), Some(now)) => {
            format!("{} min left", minutes_left(*expires_at, now))
        }
        (stamp, _) => format!("until {stamp}"),
    };
    let mut line = format!(
        "Z-{}  {}  {}  {left}",
        claim.id,
        claim.session,
        claim.paths.join(" ")
    );
    if !claim.note.is_empty() {
        line.push_str("  ");
        line.push_str(&claim.note);
    }
    for dirty in &claim.foreign_dirty_paths {
        let path = serde_json::to_string(&dirty.path).unwrap_or_else(|_| "\"?\"".into());
        let owner = dirty
            .owner_session
            .as_deref()
            .map(|owner| serde_json::to_string(owner).unwrap_or_else(|_| "\"?\"".into()))
            .unwrap_or_else(|| "unknown owner".into());
        line.push_str(&format!(
            "\nForeign uncommitted work: {path} (owner: {owner})"
        ));
    }
    line
}

pub(super) fn message_line(message: &Message) -> String {
    let scope = if message.to == BROADCAST {
        " to all"
    } else {
        ""
    };
    format!(
        "M-{}  {}{}: {}",
        message.id,
        message.from,
        scope,
        escape_controls(&message.body)
    )
}

pub(super) fn escape_controls(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            ch if ch.is_control() || is_bidi_control(ch) => format!("\\u{{{:x}}}", ch as u32),
            ch => ch.to_string(),
        })
        .collect()
}

pub(super) fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch as u32,
        0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
    )
}

pub(super) fn safe_message(mut message: Message) -> Message {
    message.body = escape_controls(&message.body);
    message
}

pub(super) fn safe_messages(mut messages: Vec<Message>) -> Vec<Message> {
    for message in &mut messages {
        message.body = escape_controls(&message.body);
    }
    messages
}

pub(super) fn safe_receipts(
    mut receipts: Vec<lockyard_core::bus::Receipt>,
) -> Vec<lockyard_core::bus::Receipt> {
    for receipt in &mut receipts {
        receipt.body = escape_controls(&receipt.body);
    }
    receipts
}

pub(super) fn sent_line(message: &Message) -> String {
    match (message.queued, message.deduplicated) {
        (true, _) => "queued: the server is out of reach, the agent will send it".to_string(),
        (_, true) => format!("already sent as M-{}", message.id),
        _ => format!("sent M-{}", message.id),
    }
}

pub(super) fn task_line(task: &Task) -> String {
    let assignee = task.assignee.as_deref().unwrap_or("-");
    format!(
        "{}  {}  {}  {}",
        task.id,
        task.raw_status.as_deref().unwrap_or(task.status.as_str()),
        assignee,
        task.title
    )
}

pub(super) fn work_line(task: &WorkTask) -> String {
    let status = serde_json::to_value(task.status).ok();
    let status = status.as_ref().and_then(Value::as_str).unwrap_or_default();
    let assignee = task
        .assignee
        .as_deref()
        .or(task.to.as_deref())
        .unwrap_or("-");
    format!(
        "W-{}  {status}  {assignee}  v{}  {}",
        task.id, task.version, task.title
    )
}

pub(super) fn board_line(entry: &BoardEntry) -> String {
    format!("{} = {}", entry.key, entry.text())
}

pub(super) fn join<T>(items: &[T], line: impl Fn(&T) -> String, empty: &str) -> String {
    if items.is_empty() {
        return empty.to_string();
    }
    items.iter().map(line).collect::<Vec<_>>().join("\n")
}

/// The clock to count local leases on. Cloud leases are not counted at all.
pub(super) fn clock(opened: &Opened) -> Option<i64> {
    (!opened.backend.is_cloud()).then(now_ms)
}

/// Max non-empty path lines accepted from `--paths-file`.
pub(super) const PATHS_FILE_MAX_LINES: usize = 1000;
/// Max bytes for `--body-file` / `--acceptance-file`.
pub(super) const BODY_FILE_MAX_BYTES: u64 = 64 * 1024;

fn read_regular_bytes(path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| Error::Invalid(format!("cannot read {}: {error}", path.display())))?;
    if !meta.file_type().is_file() {
        return Err(Error::Invalid(format!(
            "{} must be a regular file (not a directory or symlink)",
            path.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(Error::Invalid(format!(
            "{} exceeds the {} byte limit",
            path.display(),
            max_bytes
        )));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| Error::Invalid(format!("cannot read {}: {error}", path.display())))?;
    if bytes.contains(&0) {
        return Err(Error::Invalid(format!(
            "{} must not contain NUL bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

pub(super) fn read_lines_file(path: &std::path::Path) -> Result<Vec<String>> {
    // Bound by line count; allow a generous byte ceiling so huge lines still fail clearly.
    let text = String::from_utf8(read_regular_bytes(path, 1024 * 1024)?).map_err(|error| {
        Error::Invalid(format!("{} is not valid UTF-8: {error}", path.display()))
    })?;
    let paths: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    if paths.len() > PATHS_FILE_MAX_LINES {
        return Err(Error::Invalid(format!(
            "{} has more than {PATHS_FILE_MAX_LINES} paths",
            path.display()
        )));
    }
    Ok(paths)
}

pub(super) fn read_text_file(path: &std::path::Path) -> Result<String> {
    String::from_utf8(read_regular_bytes(path, BODY_FILE_MAX_BYTES)?)
        .map_err(|error| Error::Invalid(format!("{} is not valid UTF-8: {error}", path.display())))
}

/// Absolute RFC 3339 hold deadline for --hold-for minutes (1..=240).
pub(super) fn hold_until_from_minutes(minutes: i64, now_ms: i64) -> Result<String> {
    if !(1..=240).contains(&minutes) {
        return Err(Error::Invalid(
            "hold-for must be between 1 and 240 minutes".into(),
        ));
    }
    let until = now_ms.saturating_add(minutes.saturating_mul(60_000));
    Ok(lockyard_core::proto::rfc3339(until))
}
