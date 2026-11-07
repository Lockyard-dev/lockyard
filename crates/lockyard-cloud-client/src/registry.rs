// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Lossless registry operations shared by CLI and MCP. Server DTOs are returned unchanged.
use crate::{Call, CloudBackend, Transport, encode};
use lockyard_core::{Error, Result};
use serde_json::{Value, json};

fn checked_string_id(id: &str) -> Result<String> {
    lockyard_compat::LegacyCompatibilityV1::task_id(
        &json!(id),
        lockyard_compat::TaskDomain::Registry,
        lockyard_compat::Source::Sdk,
        2,
    )
    .map_err(|code| Error::Cloud {
        code: code.clone(),
        status: None,
        details: Value::Null,
        message: code,
    })
}

pub(crate) fn search<T: Transport>(
    backend: &CloudBackend<T>,
    query: &Value,
    ready: bool,
) -> Result<Value> {
    let allowed: &[&str] = if ready {
        &["actor", "area", "type", "limit"]
    } else {
        &[
            "status", "type", "area", "priority", "actor", "q", "limit", "cursor",
        ]
    };
    let object = query
        .as_object()
        .ok_or_else(|| Error::Invalid("registry query must be an object".into()))?;
    let mut pairs = Vec::new();
    for (name, value) in object {
        if !allowed.contains(&name.as_str()) {
            return Err(Error::Invalid(format!(
                "unsupported registry query field {name:?}"
            )));
        }
        if value.is_null() {
            continue;
        }
        let value = if name == "limit" {
            let limit = value
                .as_u64()
                .filter(|limit| (1..=200).contains(limit))
                .ok_or_else(|| Error::Invalid("registry limit must be between 1 and 200".into()))?;
            limit.to_string()
        } else {
            value
                .as_str()
                .ok_or_else(|| Error::Invalid(format!("{name} must be text")))?
                .to_string()
        };
        pairs.push(format!("{name}={}", encode(&value)));
    }
    let route = if ready { "ready" } else { "items" };
    let tail = if pairs.is_empty() {
        String::new()
    } else {
        format!("?{}", pairs.join("&"))
    };
    Ok(backend.transport.call(&Call::get(
        &backend.session,
        format!("/api/v1/registry/{route}{tail}"),
    ))?)
}

pub(crate) fn item_by_id<T: Transport>(
    backend: &CloudBackend<T>,
    id: &str,
    blockers: bool,
) -> Result<Value> {
    let tail = if blockers { "/blockers" } else { "" };
    Ok(backend.transport.call(&Call::get(
        &backend.session,
        format!("/api/v1/registry/items/{}{tail}", checked_string_id(id)?),
    ))?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn link_by_id<T: Transport>(
    backend: &CloudBackend<T>,
    agent: &str,
    id: &str,
    to: &str,
    kind: &str,
    version: i64,
    key: &str,
) -> Result<Value> {
    validate_link(kind, version, key)?;
    let mut call = Call::write(
        agent,
        "POST",
        format!("/api/v1/registry/items/{}/links", checked_string_id(id)?),
        json!({"kind": kind, "to_item_id": checked_string_id(to)?, "expected_version": version}),
    );
    call.key = Some(key.to_string());
    Ok(backend.transport.call(&call)?)
}

fn validate_link(kind: &str, version: i64, key: &str) -> Result<()> {
    if !["blocks", "parent_of", "duplicate_of", "relates_to"].contains(&kind) {
        return Err(Error::Invalid(
            "link kind must be blocks, parent_of, duplicate_of or relates_to".into(),
        ));
    }
    if version <= 0
        || key.len() != 26
        || !key
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
    {
        return Err(Error::Invalid(
            "link requires positive expected version and a 26-character ULID idempotency key"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientError;
    use lockyard_core::Backend;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording(Mutex<Vec<Call>>);
    impl Transport for Recording {
        fn call(&self, call: &Call) -> std::result::Result<Value, ClientError> {
            self.0.lock().unwrap().push(call.clone());
            Ok(
                json!({"items":[{"id":"D-1","status":"blocked","links":[{"kind":"blocks","to":"D-2"}]}],"cursor":"next","encrypted_fields_not_searched":true}),
            )
        }
    }
    #[test]
    fn search_keeps_raw_dto_and_encodes_cursor_and_query() {
        let backend = CloudBackend::new(Recording::default(), "agent");
        let answer = search(
            &backend,
            &json!({"q":"x & y", "cursor":"a/b", "limit":2}),
            false,
        )
        .unwrap();
        assert_eq!(answer["items"][0]["status"], "blocked");
        assert_eq!(answer["items"][0]["links"][0]["to"], "D-2");
        assert_eq!(answer["encrypted_fields_not_searched"], true);
        let calls = backend.transport.0.lock().unwrap();
        assert!(calls[0].path.contains("q=x%20%26%20y"));
        assert!(calls[0].path.contains("cursor=a%2Fb"));
    }
    #[test]
    fn bad_queries_do_not_call_transport() {
        let backend = CloudBackend::new(Recording::default(), "agent");
        assert!(search(&backend, &json!({"limit":201}), false).is_err());
        assert!(search(&backend, &json!({"q":"x"}), true).is_err());
        assert!(backend.transport.0.lock().unwrap().is_empty());
    }
    #[test]
    fn string_registry_reads_preserve_area_prefixes_and_canonicalize_numeric_aliases() {
        let backend = CloudBackend::new(Recording::default(), "agent");
        item_by_id(&backend, "FE-0319", false).unwrap();
        item_by_id(&backend, "G-SG-0012", true).unwrap();
        item_by_id(&backend, "0012", false).unwrap();
        item_by_id(&backend, "D-0012", false).unwrap();
        let calls = backend.transport.0.lock().unwrap();
        assert_eq!(calls[0].path, "/api/v1/registry/items/FE-0319");
        assert_eq!(calls[1].path, "/api/v1/registry/items/G-SG-0012/blockers");
        assert_eq!(calls[2].path, "/api/v1/registry/items/D-12");
        assert_eq!(calls[3].path, "/api/v1/registry/items/D-0012");
    }

    #[test]
    fn area_prefixed_link_preserves_both_identities_idempotency_and_version() {
        let mut backend = CloudBackend::new(Recording::default(), "agent");
        let key = "01K00000000000000000000000";
        backend
            .registry_link_by_id("me", "FE-0319", "G-SG-0012", "blocks", 4, key)
            .unwrap();
        let calls = backend.transport.0.lock().unwrap();
        assert_eq!(calls[0].path, "/api/v1/registry/items/FE-0319/links");
        assert_eq!(calls[0].key.as_deref(), Some(key));
        assert_eq!(calls[0].body.as_ref().unwrap()["to_item_id"], "G-SG-0012");
        assert_eq!(calls[0].body.as_ref().unwrap()["expected_version"], 4);
    }

    #[test]
    fn invalid_string_ids_never_reach_the_transport() {
        let backend = CloudBackend::new(Recording::default(), "agent");
        for id in ["", "0", "FE-0000", "fe-1", "FE-1/path", "../D-1", "G--SG-1"] {
            assert!(item_by_id(&backend, id, false).is_err(), "{id}");
        }
        assert!(backend.transport.0.lock().unwrap().is_empty());
    }

    #[test]
    fn link_preserves_idempotency_and_version() {
        let backend = CloudBackend::new(Recording::default(), "agent");
        let key = "01K00000000000000000000000";
        link_by_id(&backend, "me", "D-1", "D-2", "blocks", 4, key).unwrap();
        let calls = backend.transport.0.lock().unwrap();
        assert_eq!(calls[0].key.as_deref(), Some(key));
        assert_eq!(calls[0].body.as_ref().unwrap()["expected_version"], 4);
    }
}
