// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Merging Lockyard's entries into files another program owns.
//!
//! Every function here takes the current text and returns the text to write, so a caller can show
//! a plan without touching the disk and can tell "already correct" from "needs a write". A file
//! that cannot be parsed is an error: a configuration Lockyard does not understand is never
//! rewritten from scratch, because that would throw away the user's other servers.

use lockyard_core::{Error, Result};
use serde_json::{Map, Value, json};

/// Opening marker of the instruction block Lockyard owns.
pub const BLOCK_START: &str = "<!-- lockyard:start -->";
/// Closing marker of the instruction block Lockyard owns.
pub const BLOCK_END: &str = "<!-- lockyard:end -->";

fn parse_object(path: &str, text: &str) -> Result<Map<String, Value>> {
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::Invalid(format!(
            "{path} is JSON but not an object; Lockyard will not rewrite it"
        ))),
        Err(error) => Err(Error::Invalid(format!(
            "{path} is not valid JSON ({error}); fix it or move it aside, Lockyard will not rewrite it"
        ))),
    }
}

fn render(map: &Map<String, Value>) -> Result<String> {
    let mut text = serde_json::to_string_pretty(&Value::Object(map.clone()))
        .map_err(|error| Error::Invalid(format!("cannot write JSON: {error}")))?;
    text.push('\n');
    Ok(text)
}

/// The server entry every MCP client gets.
pub fn server_entry() -> Value {
    json!({"command": "lockyard", "args": ["mcp"]})
}

/// Adds or refreshes `mcpServers.lockyard`, leaving every other server and key alone.
pub fn mcp_set(path: &str, current: Option<&str>, entry: &Value) -> Result<String> {
    let mut map = parse_object(path, current.unwrap_or(""))?;
    let servers = map
        .entry("mcpServers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(servers) = servers.as_object_mut() else {
        return Err(Error::Invalid(format!(
            "{path} has an mcpServers that is not an object; Lockyard will not rewrite it"
        )));
    };
    servers.insert("lockyard".to_string(), entry.clone());
    render(&map)
}

/// Removes only Lockyard's entry. `None` means the file held nothing else and can go.
pub fn mcp_remove(path: &str, current: &str) -> Result<Option<String>> {
    let mut map = parse_object(path, current)?;
    let Some(servers) = map.get_mut("mcpServers").and_then(Value::as_object_mut) else {
        return Ok(Some(current.to_string()));
    };
    servers.remove("lockyard");
    if servers.is_empty() {
        map.remove("mcpServers");
    }
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(render(&map)?))
}

/// Whether `mcpServers.lockyard` is present.
pub fn mcp_present(current: &str) -> bool {
    serde_json::from_str::<Value>(current)
        .ok()
        .and_then(|value| value.pointer("/mcpServers/lockyard").cloned())
        .is_some()
}

/// The events Lockyard's Claude Code hook answers, with the tools each one matches.
pub const CLAUDE_HOOK_EVENTS: [(&str, Option<&str>); 4] = [
    ("PreToolUse", Some("Edit|Write|MultiEdit|NotebookEdit|Bash")),
    ("PostToolUse", None),
    ("UserPromptSubmit", None),
    ("SessionEnd", None),
];

/// The command Claude Code runs for every one of those events.
pub const CLAUDE_HOOK_COMMAND: &str = "lockyard hook claude";

fn hook_runs(entry: &Value, command: &str) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks
                .iter()
                .any(|hook| hook.get("command").and_then(Value::as_str) == Some(command))
        })
}

/// Adds Lockyard's hook to each event it answers without disturbing hooks already there.
pub fn claude_hooks_set(path: &str, current: Option<&str>) -> Result<String> {
    let mut map = parse_object(path, current.unwrap_or(""))?;
    let hooks = map
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(hooks) = hooks.as_object_mut() else {
        return Err(Error::Invalid(format!(
            "{path} has a hooks key that is not an object; Lockyard will not rewrite it"
        )));
    };
    for (event, matcher) in CLAUDE_HOOK_EVENTS {
        let list = hooks
            .entry(event.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let Some(list) = list.as_array_mut() else {
            return Err(Error::Invalid(format!(
                "{path} has a {event} that is not an array; Lockyard will not rewrite it"
            )));
        };
        if list
            .iter()
            .any(|entry| hook_runs(entry, CLAUDE_HOOK_COMMAND))
        {
            continue;
        }
        let mut entry = Map::new();
        if let Some(matcher) = matcher {
            entry.insert("matcher".to_string(), json!(matcher));
        }
        entry.insert(
            "hooks".to_string(),
            json!([{"type": "command", "command": CLAUDE_HOOK_COMMAND}]),
        );
        list.push(Value::Object(entry));
    }
    render(&map)
}

/// Removes Lockyard's hook from every event, keeping any hook the user added beside it.
pub fn claude_hooks_remove(path: &str, current: &str) -> Result<Option<String>> {
    let mut map = parse_object(path, current)?;
    let Some(hooks) = map.get_mut("hooks").and_then(Value::as_object_mut) else {
        return Ok(Some(current.to_string()));
    };
    for (event, _) in CLAUDE_HOOK_EVENTS {
        let Some(list) = hooks.get_mut(event).and_then(Value::as_array_mut) else {
            continue;
        };
        for entry in list.iter_mut() {
            if let Some(inner) = entry.get_mut("hooks").and_then(Value::as_array_mut) {
                inner.retain(|hook| {
                    hook.get("command").and_then(Value::as_str) != Some(CLAUDE_HOOK_COMMAND)
                });
            }
        }
        // An entry whose only hook was Lockyard's would otherwise stay as an empty matcher.
        list.retain(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .is_none_or(|hooks| !hooks.is_empty())
        });
        if list.is_empty() {
            hooks.remove(event);
        }
    }
    if hooks.is_empty() {
        map.remove("hooks");
    }
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(render(&map)?))
}

/// Whether Lockyard's hook is wired for every event it answers.
pub fn claude_hooks_present(current: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(current) else {
        return false;
    };
    CLAUDE_HOOK_EVENTS.iter().all(|(event, _)| {
        value
            .pointer(&format!("/hooks/{event}"))
            .and_then(Value::as_array)
            .is_some_and(|list| {
                list.iter()
                    .any(|entry| hook_runs(entry, CLAUDE_HOOK_COMMAND))
            })
    })
}

/// Finds the half-open range of the Lockyard block, markers included.
fn block_range(current: &str) -> Option<(usize, usize)> {
    let start = current.find(BLOCK_START)?;
    let end = current[start..].find(BLOCK_END)? + start + BLOCK_END.len();
    Some((start, end))
}

/// Replaces the Lockyard block, or appends it when the file has none.
pub fn block_set(current: &str, block: &str) -> String {
    let block = block.trim_end();
    match block_range(current) {
        Some((start, end)) => format!("{}{block}{}", &current[..start], &current[end..]),
        None if current.trim().is_empty() => format!("{block}\n"),
        None => {
            let separator = if current.ends_with("\n\n") {
                ""
            } else if current.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            format!("{current}{separator}{block}\n")
        }
    }
}

/// Removes the Lockyard block. `None` means nothing but the block was in the file.
pub fn block_remove(current: &str) -> Option<String> {
    let Some((start, end)) = block_range(current) else {
        return Some(current.to_string());
    };
    let mut text = format!(
        "{}{}",
        &current[..start],
        current[end..].trim_start_matches('\n')
    );
    while text.ends_with("\n\n") {
        text.pop();
    }
    if text.trim().is_empty() {
        return None;
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Some(text)
}

pub fn block_present(current: &str) -> bool {
    block_range(current).is_some()
}

/// Line range of a TOML table header and its body, up to the next header or the end.
fn toml_table_range(current: &str, header: &str) -> Option<(usize, usize)> {
    let needle = format!("[{header}]");
    let lines: Vec<&str> = current.lines().collect();
    let start = lines.iter().position(|line| line.trim() == needle)?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some((start, end))
}

/// Writes one TOML table, replacing it in place when it is already there.
///
/// Lines rather than a parsed document: re-serializing the file would drop the comments and the
/// ordering of a configuration Lockyard does not own.
pub fn toml_table_set(current: &str, header: &str, body: &[String]) -> String {
    let mut table = vec![format!("[{header}]")];
    table.extend(body.iter().cloned());
    let mut lines: Vec<String> = current.lines().map(str::to_string).collect();
    match toml_table_range(current, header) {
        Some((start, end)) => {
            lines.splice(start..end, table);
        }
        None => {
            if lines.last().is_some_and(|line| !line.trim().is_empty()) {
                lines.push(String::new());
            }
            lines.extend(table);
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// Removes one TOML table. `None` means the file held nothing else and can go.
pub fn toml_table_remove(current: &str, header: &str) -> Option<String> {
    let Some((start, end)) = toml_table_range(current, header) else {
        return Some(current.to_string());
    };
    let mut lines: Vec<String> = current.lines().map(str::to_string).collect();
    lines.drain(start..end);
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    if lines.is_empty() {
        return None;
    }
    let mut text = lines.join("\n");
    text.push('\n');
    Some(text)
}

pub fn toml_table_present(current: &str, header: &str) -> bool {
    toml_table_range(current, header).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_mcp_entry_joins_other_servers_and_keeps_other_keys() {
        let existing = r#"{"theme":"dark","mcpServers":{"other":{"command":"x"}}}"#;
        let written = mcp_set("m.json", Some(existing), &server_entry()).unwrap();
        let value: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(value["theme"], "dark");
        assert_eq!(value["mcpServers"]["other"]["command"], "x");
        assert_eq!(value["mcpServers"]["lockyard"]["args"][0], "mcp");
        assert!(mcp_present(&written));
        // Writing twice changes nothing more.
        assert_eq!(
            mcp_set("m.json", Some(&written), &server_entry()).unwrap(),
            written
        );
    }

    #[test]
    fn removing_an_mcp_entry_leaves_the_neighbours_and_deletes_an_empty_file() {
        let shared = mcp_set(
            "m.json",
            Some(r#"{"mcpServers":{"other":{}}}"#),
            &server_entry(),
        )
        .unwrap();
        let left = mcp_remove("m.json", &shared).unwrap().unwrap();
        assert!(!mcp_present(&left));
        assert!(left.contains("other"));
        let only_ours = mcp_set("m.json", None, &server_entry()).unwrap();
        assert_eq!(mcp_remove("m.json", &only_ours).unwrap(), None);
    }

    #[test]
    fn a_file_that_is_not_an_object_or_not_json_is_refused_rather_than_rewritten() {
        assert!(mcp_set("m.json", Some("[1,2]"), &server_entry()).is_err());
        assert!(mcp_set("m.json", Some("{oops"), &server_entry()).is_err());
        assert!(mcp_set("m.json", Some(r#"{"mcpServers":7}"#), &server_entry()).is_err());
    }

    #[test]
    fn claude_hooks_are_added_once_and_keep_the_hooks_already_there() {
        let existing = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"mine"}]}]}}"#;
        let written = claude_hooks_set("s.json", Some(existing)).unwrap();
        assert!(claude_hooks_present(&written));
        let value: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(value["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "mine"
        );
        assert_eq!(
            claude_hooks_set("s.json", Some(&written)).unwrap(),
            written,
            "a second run adds nothing"
        );
        let left = claude_hooks_remove("s.json", &written).unwrap().unwrap();
        assert!(!claude_hooks_present(&left));
        assert!(left.contains("mine"));
    }

    #[test]
    fn removing_claude_hooks_from_a_file_we_created_deletes_it() {
        let written = claude_hooks_set("s.json", None).unwrap();
        assert_eq!(claude_hooks_remove("s.json", &written).unwrap(), None);
    }

    #[test]
    fn a_block_is_appended_replaced_and_removed_without_touching_the_rest() {
        let doc = "# Project\n\nRules here.\n";
        let added = block_set(doc, &format!("{BLOCK_START}\nclaim first\n{BLOCK_END}"));
        assert!(added.starts_with("# Project\n\nRules here.\n\n"));
        assert!(block_present(&added));
        let changed = block_set(
            &added,
            &format!("{BLOCK_START}\nclaim first, then edit\n{BLOCK_END}"),
        );
        assert!(changed.contains("then edit"));
        assert_eq!(changed.matches(BLOCK_START).count(), 1);
        assert_eq!(block_remove(&changed).unwrap(), doc);
    }

    #[test]
    fn a_file_holding_only_the_block_is_deleted_on_removal() {
        let only = block_set("", &format!("{BLOCK_START}\nx\n{BLOCK_END}"));
        assert_eq!(block_remove(&only), None);
    }

    #[test]
    fn a_toml_table_is_replaced_in_place_and_leaves_its_neighbours() {
        let existing = "# comment\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n";
        let body = vec![
            "command = \"lockyard\"".to_string(),
            "args = [\"mcp\"]".to_string(),
        ];
        let written = toml_table_set(existing, "mcp_servers.lockyard", &body);
        assert!(written.contains("# comment"));
        assert!(written.contains("[mcp_servers.other]"));
        assert!(toml_table_present(&written, "mcp_servers.lockyard"));
        toml::from_str::<toml::Value>(&written).expect("still valid TOML");
        let again = toml_table_set(&written, "mcp_servers.lockyard", &body);
        assert_eq!(again, written);

        let changed = toml_table_set(
            &written,
            "mcp_servers.lockyard",
            &["command = \"ly\"".into()],
        );
        assert!(!changed.contains("args = [\"mcp\"]"));
        assert!(changed.contains("[mcp_servers.other]"));

        let left = toml_table_remove(&written, "mcp_servers.lockyard").unwrap();
        assert!(!toml_table_present(&left, "mcp_servers.lockyard"));
        assert!(left.contains("[mcp_servers.other]"));
        assert_eq!(
            toml_table_remove(&left, "mcp_servers.lockyard"),
            Some(left.clone()),
            "a table that is not there leaves the file exactly as it was"
        );
    }

    #[test]
    fn a_toml_file_holding_only_our_table_is_deleted_on_removal() {
        let written = toml_table_set(
            "",
            "mcp_servers.lockyard",
            &["command = \"lockyard\"".into()],
        );
        assert_eq!(toml_table_remove(&written, "mcp_servers.lockyard"), None);
    }
}
