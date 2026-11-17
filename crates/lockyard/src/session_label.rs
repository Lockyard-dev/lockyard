// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Session label visible to neighbours on claims and mail (LY-0017).

use serde_json::{Value, json};

/// Label for this process: chat/session name and parent PID when known.
/// Prefers explicit `LOCKYARD_SESSION_LABEL`, then common host env vars.
pub fn session_label() -> Value {
    let name = std::env::var("LOCKYARD_SESSION_LABEL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("CLAUDE_CODE_SESSION_ID").ok())
        .or_else(|| std::env::var("CURSOR_SESSION_ID").ok())
        .or_else(|| std::env::var("TERM_SESSION_ID").ok())
        .or_else(|| std::env::var("LOCKYARD_AGENT").ok())
        .map(|name| safe_label(&name))
        .filter(|name| !name.trim().is_empty());
    json!({
        "session_label": name,
        "parent_pid": parent_pid(),
        "pid": std::process::id(),
    })
}

fn safe_label(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || " _-.:@/".contains(*ch))
        .take(64)
        .collect()
}

fn parent_pid() -> u32 {
    #[cfg(unix)]
    {
        std::os::unix::process::parent_id()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Sender label in the existing mail protocol field.
pub fn mail_label() -> String {
    mail_label_for_client(None)
}

pub fn mail_label_for_client(client: Option<&str>) -> String {
    let label = session_label();
    format!(
        "{}{} (parent_pid={})",
        client
            .map(safe_label)
            .filter(|name| !name.is_empty())
            .map(|name| format!("{name}: "))
            .unwrap_or_default(),
        label["session_label"].as_str().unwrap_or("lockyard"),
        parent_pid()
    )
}

/// Merge identity into claim meta, preserving unrelated caller fields.
pub fn merge_session_meta(existing: Option<Value>) -> lockyard_core::Result<Value> {
    let mut label = session_label();
    if let Some(existing) = existing {
        let Value::Object(map) = existing else {
            return Err(lockyard_core::Error::Invalid(
                "meta must be an object".into(),
            ));
        };
        let object = label.as_object_mut().expect("session label is an object");
        for (key, value) in map {
            object.insert(key, value);
        }
    }
    if label.to_string().len() > 4096 {
        return Err(lockyard_core::Error::Invalid(
            "claim meta must be at most 4 KiB".into(),
        ));
    }
    Ok(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_caller_fields_and_adds_pid() {
        let merged = merge_session_meta(Some(json!({"note":"x"}))).unwrap();
        assert_eq!(merged["note"], "x");
        assert!(merged["pid"].as_u64().is_some());
        assert!(merged["parent_pid"].as_u64().is_some());
    }

    #[test]
    fn merge_preserves_explicit_session_label_and_pid() {
        let merged = merge_session_meta(Some(json!({"session_label":"caller", "pid":17}))).unwrap();
        assert_eq!(merged["session_label"], "caller");
        assert_eq!(merged["pid"], 17);
    }

    #[test]
    fn long_client_name_also_fits_mail_sender_limit() {
        let sender = mail_label_for_client(Some(&"client\n\u{202e}".repeat(1000)));
        assert!(sender.len() <= 256 && sender.is_ascii());
        assert!(!sender.chars().any(char::is_control));
    }
}
