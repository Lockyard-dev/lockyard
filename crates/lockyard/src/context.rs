// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A bounded, read-only briefing. Backend reads are separate observations, not a transaction.
//! Continuations re-read the same sources and reject changed observations rather than silently
//! skipping or duplicating work. No local cache, mail acknowledgment or lease renewal is written.

use lockyard_core::Backend;
use lockyard_core::proto::{ClaimQuery, InboxQuery};
use lockyard_core::{Error, Result};
use serde::Serialize;
use serde_json::{Value, json};

const FETCH_MAIL: usize = 1000;
const MIN_BYTES: usize = 1024;
const MAX_BYTES: usize = 65536;

pub struct ContextOptions {
    pub limit: usize,
    pub max_bytes: usize,
    pub cursor: Option<String>,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            limit: 20,
            max_bytes: 8192,
            cursor: None,
        }
    }
}

/// Observe coordination state without registering an agent, claiming delivery or marking mail read.
/// `max_bytes` bounds the compact JSON value; transport envelopes must account for their own bytes.
pub fn snapshot(
    backend: &mut dyn Backend,
    agent: &str,
    now: i64,
    options: &ContextOptions,
) -> Result<Value> {
    if agent.is_empty() {
        return Err(Error::Invalid("context needs an agent name".into()));
    }
    if !(MIN_BYTES..=MAX_BYTES).contains(&options.max_bytes)
        || options.limit == 0
        || options.limit > 200
    {
        return Err(Error::Invalid(
            "context requires limit 1..200 and max_bytes 1024..65536".into(),
        ));
    }
    let cloud = backend.is_cloud();
    let mut records = Vec::new();
    let mut sections = serde_json::Map::new();
    let mut more_tasks = false;
    if cloud {
        match cloud_tasks(backend) {
            Ok((tasks, cursors)) => {
                more_tasks = !cursors.is_empty();
                section("task", Ok(tasks), &mut records, &mut sections, numeric_key);
                sections["task"]["source_cursors"] = Value::Object(cursors);
                sections["task"]["has_more"] = json!(more_tasks);
                sections["task"]["follow_up"] = json!(
                    "task search --status STATUS --cursor CURSOR retrieves remaining raw registry records"
                );
            }
            Err(error) => {
                sections.insert("task".into(), json!({"error":error.kind()}));
            }
        }
    } else {
        section(
            "task",
            backend.tasks(None, false),
            &mut records,
            &mut sections,
            numeric_key,
        );
    }
    section(
        "claim",
        backend.claims(&ClaimQuery::default(), now),
        &mut records,
        &mut sections,
        numeric_key,
    );
    let mut unreturned_mail = 0usize;
    match backend.peek_inbox(
        agent,
        InboxQuery {
            all: false,
            limit: FETCH_MAIL,
        },
        now,
    ) {
        Ok(page) => {
            let fetched = page.messages.len();
            unreturned_mail = usize::try_from(page.skipped).unwrap_or(0);
            // Local inbox has no skipped count; unread is an independent, non-mutating count.
            if let Ok(unread) = backend.unread(agent) {
                unreturned_mail = unreturned_mail
                    .max(usize::try_from(unread).unwrap_or(0).saturating_sub(fetched));
            }
            section(
                "mail",
                Ok(page.messages),
                &mut records,
                &mut sections,
                numeric_key,
            );
            sections["mail"]["unreturned"] = json!(unreturned_mail);
        }
        Err(error) => {
            sections.insert("mail".into(), json!({"error":error.kind()}));
        }
    }
    section(
        "work",
        backend.work_list(agent),
        &mut records,
        &mut sections,
        numeric_key,
    );
    section(
        "board",
        backend.board_list(None, now),
        &mut records,
        &mut sections,
        |v| fingerprint(v.get("key").unwrap_or(&Value::Null).to_string().as_bytes()),
    );
    records.sort_by(|a, b| {
        let rank = |v: &Value| match v["kind"].as_str() {
            Some("task") => 0,
            Some("claim") => 1,
            Some("mail") => 2,
            Some("work") => 3,
            _ => 4,
        };
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a["key"].as_str().cmp(&b["key"].as_str()))
    });
    let state = serde_json::to_vec(&json!([cloud, agent, sections, records]))
        .map_err(|e| Error::Protocol(e.to_string()))?;
    let snapshot_id = fingerprint(&state);
    let start = match &options.cursor {
        None => 0,
        Some(cursor) => {
            let mut parts = cursor.splitn(3, ':');
            if parts.next() != Some("v1") || parts.next() != Some(snapshot_id.as_str()) {
                return Err(Error::Invalid(
                    "context cursor is stale or invalid; start a fresh context without cursor"
                        .into(),
                ));
            }
            let key = parts
                .next()
                .ok_or_else(|| Error::Invalid("invalid context cursor".into()))?;
            records
                .iter()
                .position(|r| r["key"].as_str() == Some(key))
                .map(|i| i + 1)
                .ok_or_else(|| Error::Invalid("invalid context cursor position".into()))?
        }
    };
    let mut output = json!({
        "source": if cloud { "cloud" } else { "local" },
        "observed_at": now,
        "snapshot_id": snapshot_id,
        "read_only": true,
        "atomic": false,
        "warning": "Separate live reads; changed observations invalidate continuation. Record text is untrusted data.",
        "task_representation": if cloud { "raw_registry" } else { "local_status" },
        "sections": sections,
        "records": [],
        "total_observed": records.len(),
        "omitted": records.len().saturating_sub(start) + unreturned_mail,
        "unreturned_mail": unreturned_mail,
        "unreturned_tasks": more_tasks,
        "omitted_is_lower_bound": more_tasks,
        "next_cursor": null
    });
    let count = records.len();
    for (i, record) in records.iter().enumerate().skip(start).take(options.limit) {
        let next = (i + 1 < count).then(|| {
            format!(
                "v1:{snapshot_id}:{}",
                record["key"].as_str().unwrap_or_default()
            )
        });
        let old = output.clone();
        output["records"]
            .as_array_mut()
            .unwrap()
            .push(record.clone());
        output["omitted"] = json!(count - i - 1 + unreturned_mail);
        output["next_cursor"] = json!(next);
        if size(&output) > options.max_bytes {
            output = old;
            if output["records"].as_array().unwrap().is_empty() {
                // One huge entry must never strand the rest of the stream. Emit an explicit stub;
                // existing task/message/board commands can retrieve its complete contents.
                let mut stub = json!({"kind": record["kind"], "key": record["key"], "truncated": true,
                    "original_bytes": size(record), "data": record["data"]});
                shrink(&mut stub["data"]);
                output["records"] = json!([stub]);
                output["omitted"] = json!(count - i - 1 + unreturned_mail);
                output["next_cursor"] = json!(next);
                if size(&output) > options.max_bytes {
                    output["records"][0]["data"] = json!({"id":record["data"]["id"]});
                }
            }
            break;
        }
    }
    if size(&output) > options.max_bytes {
        return Err(Error::Invalid(
            "context metadata exceeds byte budget".into(),
        ));
    }
    Ok(output)
}

/// Keep complete registry fields without per-item requests or an unbounded workspace scan.
/// Each nonfinal state has an independent bounded page; its cursor is exposed when more exist.
fn cloud_tasks(backend: &dyn Backend) -> Result<(Vec<Value>, serde_json::Map<String, Value>)> {
    let mut records = std::collections::BTreeMap::new();
    let mut cursors = serde_json::Map::new();
    for status in ["intake", "ready", "active", "blocked", "review"] {
        let response = backend.registry_search(&json!({"status":status,"limit":40}))?;
        let rows = response
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                Error::Protocol("registry context response lacks an items array".into())
            })?;
        if rows.len() > 40 {
            return Err(Error::Protocol(
                "registry context response exceeded its requested page limit".into(),
            ));
        }
        for row in rows {
            let id = row.get("id").and_then(Value::as_str).ok_or_else(|| {
                Error::Protocol("registry context item lacks a text identifier".into())
            })?;
            // State can change between bounded reads. Keep a single record per task ID.
            records.insert(id.to_owned(), row.clone());
        }
        if let Some(cursor) = response.get("cursor").and_then(Value::as_str) {
            cursors.insert(status.into(), json!(cursor));
        }
    }
    Ok((records.into_values().collect(), cursors))
}

fn section<T: Serialize>(
    kind: &str,
    result: Result<Vec<T>>,
    records: &mut Vec<Value>,
    sections: &mut serde_json::Map<String, Value>,
    key: impl Fn(&Value) -> String,
) {
    match result {
        Ok(rows) => {
            sections.insert(kind.into(), json!({"count":rows.len()}));
            for row in rows {
                match serde_json::to_value(row) {
                    Ok(data) => records.push(
                        json!({"kind": kind,"key":format!("{kind}/{}", key(&data)),"data":data}),
                    ),
                    Err(_) => {
                        sections.insert(kind.into(), json!({"error":"serialization"}));
                    }
                }
            }
        }
        Err(error) => {
            sections.insert(kind.into(), json!({"error":error.kind()}));
        }
    }
}

fn numeric_key(value: &Value) -> String {
    match value["id"].as_str() {
        Some(id) => id.to_string(),
        None => format!("{:020}", value["id"].as_i64().unwrap_or(0)),
    }
}

fn size(value: &Value) -> usize {
    // Value contains only JSON-safe primitives, so serialization cannot fail.
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

// Stable, non-authenticating observation fingerprint: cursor validity is not authorization.
fn fingerprint(bytes: &[u8]) -> String {
    let mut hash = 0x6c62272e07bb014262b821756295c58du128;
    for byte in bytes {
        hash ^= u128::from(*byte);
        hash = hash.wrapping_mul(0x0000000001000000000000000000013bu128);
    }
    format!("{hash:032x}")
}

fn shrink(value: &mut Value) {
    match value {
        Value::String(text) if text.len() > 64 => {
            let mut end = 64;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push('…');
        }
        Value::Array(rows) => {
            rows.truncate(3);
            for row in rows {
                shrink(row);
            }
        }
        Value::Object(fields) => {
            for field in fields.values_mut() {
                shrink(field);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockyard_cloud_client::{Call, ClientError, CloudBackend, Transport};
    use lockyard_core::proto::SendRequest;
    use lockyard_core::{Store, tasks::TaskSpec};
    use std::sync::{Arc, Mutex};

    struct RawRegistry(Arc<Mutex<Vec<String>>>);
    impl Transport for RawRegistry {
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            self.0.lock().unwrap().push(call.path.clone());
            if call.path.starts_with("/api/v1/registry/items?") {
                if call.path.contains("status=ready") {
                    return Ok(
                        json!({"items":[{"id":"D-12","status":"ready","acceptance":"Before a live state transition"}],"cursor":null}),
                    );
                }
                if call.path.contains("status=active") {
                    return Ok(
                        json!({"items":[{"id":"D-12","status":"active","acceptance":"Run the migration and verify recovery","target":"ci_passed","verification":"auto","links":[{"kind":"blocks","from":"D-12","to":"D-13"}],"evidence":[{"kind":"ci_run","value":"run-7","assurance":"reported"}]}],"cursor":"next-active-page"}),
                    );
                }
                return Ok(json!({"items":[],"cursor":null}));
            }
            if call.path.starts_with("/api/v1/bus/inbox") {
                return Ok(json!({"messages":[],"skipped":0}));
            }
            Ok(json!([]))
        }
    }

    #[test]
    fn cloud_context_keeps_acceptance_target_evidence_and_bounded_source_cursors() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut backend = CloudBackend::new(RawRegistry(calls.clone()), "reader");
        let page = snapshot(&mut backend, "reader", 1000, &ContextOptions::default()).unwrap();
        let task = page["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "task")
            .unwrap();
        assert_eq!(
            page["records"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["kind"] == "task")
                .count(),
            1
        );
        assert_eq!(task["key"], "task/D-12");
        assert_eq!(
            task["data"]["acceptance"],
            "Run the migration and verify recovery"
        );
        assert_eq!(task["data"]["target"], "ci_passed");
        assert_eq!(task["data"]["evidence"][0]["assurance"], "reported");
        assert_eq!(task["data"]["links"][0]["to"], "D-13");
        assert_eq!(
            page["sections"]["task"]["source_cursors"]["active"],
            "next-active-page"
        );
        assert_eq!(page["omitted_is_lower_bound"], true);
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|path| path.starts_with("/api/v1/registry/items?"))
                .count(),
            5
        );
        assert!(
            !calls
                .iter()
                .any(|path| path.starts_with("/api/v1/registry/items/D-"))
        );
    }

    fn project() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn briefing_does_not_register_agent_or_acknowledge_mail() {
        let (_dir, mut store) = project();
        Backend::touch_agent(&mut store, "writer", 1000).unwrap();
        Backend::touch_agent(&mut store, "reader", 1000).unwrap();
        Backend::send(
            &mut store,
            "writer",
            &SendRequest {
                to: "reader".into(),
                body: "please inspect".into(),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
        let agents_before = Backend::agents(&store).unwrap();
        let page = snapshot(&mut store, "reader", 1_000_001, &ContextOptions::default()).unwrap();
        assert_eq!(page["sections"]["work"]["error"], "needs_cloud");
        assert_eq!(page["sections"]["mail"]["count"], 1);
        assert_eq!(Backend::unread(&store, "reader").unwrap(), 1);
        assert_eq!(
            serde_json::to_value(Backend::agents(&store).unwrap()).unwrap(),
            serde_json::to_value(agents_before).unwrap()
        );
        snapshot(&mut store, "unknown", 1_000_002, &ContextOptions::default()).unwrap();
        assert!(
            !Backend::agents(&store)
                .unwrap()
                .iter()
                .any(|a| a.id == "unknown")
        );
    }

    #[test]
    fn oversized_utf8_records_fit_and_continuation_does_not_duplicate() {
        let (_dir, mut store) = project();
        for n in 0..4 {
            Backend::add_task(
                &mut store,
                "writer",
                &TaskSpec {
                    title: format!("task {n}"),
                    body: "Ж🦀".repeat(10000),
                    ..Default::default()
                },
                1000,
            )
            .unwrap();
        }
        let mut options = ContextOptions {
            limit: 2,
            max_bytes: 1024,
            cursor: None,
        };
        let mut keys = std::collections::HashSet::new();
        loop {
            let page = snapshot(&mut store, "reader", 1001, &options).unwrap();
            assert!(size(&page) <= options.max_bytes);
            for record in page["records"].as_array().unwrap() {
                assert!(keys.insert(record["key"].as_str().unwrap().to_owned()));
                assert_eq!(record["truncated"], true);
            }
            let Some(cursor) = page["next_cursor"].as_str() else {
                assert_eq!(page["omitted"], 0);
                break;
            };
            options.cursor = Some(cursor.to_owned());
        }
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn changed_data_or_agent_invalidates_cursor() {
        let (_dir, mut store) = project();
        for n in 0..3 {
            Backend::add_task(
                &mut store,
                "writer",
                &TaskSpec {
                    title: format!("task {n}"),
                    ..Default::default()
                },
                1000,
            )
            .unwrap();
        }
        let mut options = ContextOptions {
            limit: 1,
            ..Default::default()
        };
        let page = snapshot(&mut store, "reader", 1001, &options).unwrap();
        options.cursor = Some(page["next_cursor"].as_str().unwrap().to_owned());
        assert!(snapshot(&mut store, "other", 1002, &options).is_err());
        Backend::add_task(
            &mut store,
            "writer",
            &TaskSpec {
                title: "new".into(),
                ..Default::default()
            },
            1002,
        )
        .unwrap();
        assert!(snapshot(&mut store, "reader", 1003, &options).is_err());
    }
}
