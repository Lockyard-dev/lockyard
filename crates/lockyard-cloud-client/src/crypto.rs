//! Client-side content encryption. Coordination fields deliberately stay clear.
use ring::{
    aead, digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use serde_json::Value;
const LABEL: &[u8] = b"lockyard-cloud-key-id-v1";
const WORDS: &str = include_str!("english.txt");
const PREFIX: &str = "lyenc1.";
const FIELDS: &str = include_str!("../content-fields.json");
const OPENAPI: &str = include_str!("../tests/fixtures/openapi.json");
#[derive(Debug, Clone, Deserialize)]
struct Field {
    schema: String,
    property: String,
    name: String,
}
#[derive(Debug, Deserialize)]
struct FieldMap {
    fields: Vec<Field>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRule {
    pub method: &'static str,
    pub route: &'static str,
    pub pointer: &'static str,
    pub name: &'static str,
}
// Compatibility metadata; transformations below are driven by OpenAPI schemas and content-fields.json.
pub const CONTENT_FIELDS: &[FieldRule] = &[];
pub fn route_matches(pattern: &str, route: &str) -> bool {
    let a = pattern.split('/').collect::<Vec<_>>();
    let b = route
        .split('?')
        .next()
        .unwrap_or(route)
        .split('/')
        .collect::<Vec<_>>();
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| *x == "*" || *x == y)
}
/// The table and the document are embedded, so they are parsed once and shared.
fn parsed() -> Result<&'static (FieldMap, Value), String> {
    static PARSED: std::sync::OnceLock<Result<(FieldMap, Value), String>> =
        std::sync::OnceLock::new();
    PARSED
        .get_or_init(|| {
            let map: FieldMap = serde_json::from_str(FIELDS).map_err(|e| e.to_string())?;
            let api: Value = serde_json::from_str(OPENAPI).map_err(|e| e.to_string())?;
            Ok((map, api))
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub fn transform_fields(
    value: &mut Value,
    method: &str,
    route: &str,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    encrypt: bool,
) -> Result<(), String> {
    transform_fields_policy(value, method, route, workspace, key, encrypt, false)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn transform_fields_policy(
    value: &mut Value,
    method: &str,
    route: &str,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    encrypt: bool,
    require_encrypted: bool,
) -> Result<(), String> {
    let (map, api) = parsed()?;
    let normalized = route.split('?').next().unwrap_or(route);
    let mut schemas = Vec::new();
    let mut matched = false;
    for (path, ops) in api["paths"].as_object().ok_or("bad OpenAPI paths")? {
        if !openapi_path_matches(path, normalized) {
            continue;
        }
        let Some(op) = ops.get(method.to_ascii_lowercase()) else {
            continue;
        };
        matched = true;
        if encrypt {
            let node = op
                .get("requestBody")
                .and_then(|x| x.get("content"))
                .and_then(|x| x.get("application/json"))
                .and_then(|x| x.get("schema"));
            if let Some(n) = node {
                collect_refs(n, &mut schemas)
            }
        } else {
            let node = op
                .get("responses")
                .and_then(Value::as_object)
                .and_then(|r| {
                    r.iter()
                        .find(|(code, _)| code.starts_with('2'))
                        .map(|(_, v)| v)
                })
                .and_then(|x| x.get("content"))
                .and_then(|x| x.get("application/json"))
                .and_then(|x| x.get("schema"));
            if let Some(n) = node {
                collect_refs(n, &mut schemas)
            }
        }
    }
    if require_encrypted && !matched {
        return Err("required node encryption does not support this API operation".into());
    }
    if require_encrypted && encrypt {
        if schemas.is_empty() && !value.is_null() && value != &serde_json::json!({}) {
            return Err("required node encryption does not support this request body".into());
        }
        for schema in &schemas {
            validate_request_shape(
                value,
                &api["components"]["schemas"][schema],
                &api["components"]["schemas"],
            )?;
        }
    }
    let mut touched = Vec::new();
    for schema in schemas {
        visit(
            value,
            &schema,
            &api["components"]["schemas"],
            &map.fields,
            workspace,
            key,
            encrypt,
            require_encrypted,
            &mut touched,
        )?;
    }
    Ok(())
}
fn openapi_path_matches(template: &str, path: &str) -> bool {
    let a = template.split('/').collect::<Vec<_>>();
    let b = path.split('/').collect::<Vec<_>>();
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.starts_with('{') && x.ends_with('}') || *x == y)
}
#[allow(clippy::collapsible_if)]
fn collect_refs(v: &Value, out: &mut Vec<String>) {
    if let Some(r) = v.get("$ref").and_then(Value::as_str) {
        if let Some(s) = r.strip_prefix("#/components/schemas/") {
            out.push(s.into())
        }
    }
    if let Some(i) = v.get("items") {
        collect_refs(i, out)
    }
    if let Some(a) = v.get("allOf").and_then(Value::as_array) {
        for x in a {
            collect_refs(x, out)
        }
    }
}
#[allow(clippy::collapsible_if, clippy::too_many_arguments)]
fn visit(
    v: &mut Value,
    schema: &str,
    schemas: &Value,
    fields: &[Field],
    workspace: &str,
    key: Option<&WorkspaceKey>,
    enc: bool,
    require_encrypted: bool,
    touched: &mut Vec<String>,
) -> Result<(), String> {
    let Some(def) = schemas.get(schema) else {
        return Ok(());
    };
    if let Some(values) = v.as_array_mut() {
        for value in values {
            visit(
                value,
                schema,
                schemas,
                fields,
                workspace,
                key,
                enc,
                require_encrypted,
                touched,
            )?;
        }
        return Ok(());
    }
    if !enc && matches!(schema, "CoordinationEvent" | "RegistryEventDto") {
        visit_event(
            v,
            schema,
            schemas,
            fields,
            workspace,
            key,
            require_encrypted,
            touched,
        )?;
    }
    if !enc
        && schema == "CoordinationLostEvent"
        && let Some(reason) = v.get_mut("reason")
        && reason.as_str() != Some("taken")
    {
        decrypt_event_field(reason, "reason", workspace, key, require_encrypted)?;
    }
    if let (Some(obj), Some(props)) = (
        v.as_object_mut(),
        def.get("properties").and_then(Value::as_object),
    ) {
        for (p, sch) in props {
            if let Some(slot) = obj.get_mut(p) {
                if !enc
                    && ((schema == "CoordinationCheckResult" && p == "holder")
                        || (schema == "CoordinationClaim" && p == "conflicts"))
                {
                    if p == "holder" {
                        transform_conflict_entry(slot, workspace, key, require_encrypted)?;
                    } else {
                        transform_conflict_array(slot, workspace, key, require_encrypted)?;
                    }
                    continue;
                }
                let content_name = fields
                    .iter()
                    .find(|f| f.schema == schema && f.property == *p)
                    .map(|f| f.name.as_str())
                    .or_else(|| {
                        require_encrypted
                            .then(|| additional_node_content(schema, p))
                            .flatten()
                    });
                if let Some(content_name) = content_name {
                    if let Some(s) = slot.as_str() {
                        if enc && s.starts_with(PREFIX) && require_encrypted {
                            key.ok_or("required node encryption key is unavailable")?
                                .decrypt(workspace, content_name, s)
                                .map_err(
                                    |_| "required node content envelope failed authentication",
                                )?;
                        } else if enc && !s.starts_with(PREFIX) {
                            let k = key.ok_or_else(|| {
                                format!("workspace encryption is required but no local key is available; import the key with `lockyard cloud key import` before writing content ({schema}.{p})")
                            })?;
                            *slot = Value::String(k.encrypt(workspace, content_name, s)?);
                            touched.push(format!("{schema}.{p}"));
                        } else if !enc && require_encrypted {
                            if !s.is_empty() {
                                if !s.starts_with(PREFIX) {
                                    return Err(
                                        "required node content response contains plaintext".into(),
                                    );
                                }
                                let key = key.ok_or("required node response key is unavailable")?;
                                *slot = Value::String(
                                    key.decrypt(workspace, content_name, s).map_err(
                                        |_| "required node content response failed authentication",
                                    )?,
                                );
                            }
                        } else if !enc && s.starts_with(PREFIX) {
                            *slot = Value::String(match key {
                                None => "[locked]".into(),
                                Some(k) => k
                                    .decrypt(workspace, content_name, s)
                                    .unwrap_or_else(|_| "[cannot decrypt]".into()),
                            });
                        }
                    } else if require_encrypted && !slot.is_null() {
                        return Err("required node content must be text; structured content must be serialized locally".into());
                    }
                }
                if let Some(r) = sch
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.strip_prefix("#/components/schemas/"))
                {
                    visit(
                        slot,
                        r,
                        schemas,
                        fields,
                        workspace,
                        key,
                        enc,
                        require_encrypted,
                        touched,
                    )?;
                }
                if let Some(items) = sch.get("items") {
                    if let Some(r) = items
                        .get("$ref")
                        .and_then(Value::as_str)
                        .and_then(|r| r.strip_prefix("#/components/schemas/"))
                    {
                        if let Some(a) = slot.as_array_mut() {
                            for item in a {
                                visit(
                                    item,
                                    r,
                                    schemas,
                                    fields,
                                    workspace,
                                    key,
                                    enc,
                                    require_encrypted,
                                    touched,
                                )?
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Conflict holders are compatibility JSON in the published contract, but their
/// note is the original encrypted claim note. Never treat that slot as metadata.
fn transform_conflict_entry(
    value: &mut Value,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    required: bool,
) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let Some(object) = value.as_object_mut() else {
        return if required {
            Err("required node conflict holder must be an object".into())
        } else {
            Ok(())
        };
    };
    if required {
        for (name, slot) in object.iter() {
            let valid = match name.as_str() {
                "note" => slot.is_null() || slot.is_string(),
                "paths" => {
                    slot.is_null()
                        || slot
                            .as_array()
                            .is_some_and(|values| values.iter().all(Value::is_string))
                }
                "claim_id" | "priority_of" => {
                    slot.is_null() || slot.is_string() || slot.is_number()
                }
                "path" | "held_path" | "session" | "mode" | "purpose" | "expires_at" => {
                    slot.is_null() || slot.is_string()
                }
                _ => false,
            };
            if !valid {
                return Err("required node conflict contains unclassified content".into());
            }
        }
    }
    if let Some(note) = object.get_mut("note") {
        decrypt_event_field(note, "note", workspace, key, required)?;
    }
    Ok(())
}
fn transform_conflict_array(
    value: &mut Value,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    required: bool,
) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let Some(values) = value.as_array_mut() else {
        return if required {
            Err("required node conflicts must be an array".into())
        } else {
            Ok(())
        };
    };
    for value in values {
        transform_conflict_entry(value, workspace, key, required)?;
    }
    Ok(())
}

pub(crate) fn transform_error_details(
    value: &mut Value,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    required: bool,
) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let Some(object) = value.as_object_mut() else {
        return if required {
            Err("required node error details must be classified metadata".into())
        } else {
            Ok(())
        };
    };
    for (name, slot) in object {
        match name.as_str() {
            "conflicts" => transform_conflict_array(slot, workspace, key, required)?,
            "priority_of" if slot.is_null() || slot.as_u64().is_some() => {}
            "reason" => decrypt_event_field(slot, "reason", workspace, key, required)?,
            "path" | "fence" | "current_fence" | "expected_version" | "current_version"
            | "actual_version" | "version" | "retry_after" | "until" | "expires_at" | "session"
            | "owner_session" | "owner" | "id" | "key" | "status" | "available" | "repository"
                if slot.is_null() || slot.is_string() || slot.is_number() || slot.is_boolean() => {}
            "paths" | "holders"
                if slot.is_null()
                    || slot
                        .as_array()
                        .is_some_and(|values| values.iter().all(Value::is_string)) => {}
            _ if required => return Err("required node error contains unclassified details".into()),
            _ => {}
        }
    }
    Ok(())
}

fn additional_node_content(schema: &str, property: &str) -> Option<&'static str> {
    match (schema, property) {
        ("CoordinationRenewWrite" | "CoordinationClaim", "hold_reason") => Some("hold_reason"),
        (
            "CoordinationTakeoverWrite"
            | "CoordinationDirtyPathsWrite"
            | "CoordinationFreezeWrite"
            | "CoordinationFreezeResult"
            | "CoordinationDirtyPathReply"
            | "CoordinationDirtyPath",
            "reason",
        ) => Some("reason"),
        ("CoordinationClaim", "takeover_reason") => Some("reason"),
        ("CoordinationBoardHistory", "value") => Some("value"),
        ("CoordinationLostEvent", "note") => Some("note"),
        ("RegistryItemDto", "legacy_raw") => Some("legacy_raw"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_event(
    value: &mut Value,
    schema: &str,
    schemas: &Value,
    fields: &[Field],
    workspace: &str,
    key: Option<&WorkspaceKey>,
    required: bool,
    touched: &mut Vec<String>,
) -> Result<(), String> {
    let kind = value[if schema == "RegistryEventDto" {
        "op"
    } else {
        "type"
    }]
    .as_str()
    .unwrap_or_default()
    .to_string();
    if schema == "RegistryEventDto" {
        if let Some(reason) = value.get_mut("reason") {
            let system_reason = match kind.as_str() {
                "lease_expired" => Some("assignment lease expired"),
                "verify_expired" => Some("verify_by expired"),
                "legacy_verdict_expired" => Some("14 days without verdict"),
                _ => None,
            };
            if !reason.is_null()
                && !system_reason.is_some_and(|expected| reason.as_str() == Some(expected))
            {
                decrypt_event_field(
                    reason,
                    if kind == "owner_closed" {
                        "value"
                    } else {
                        "reason"
                    },
                    workspace,
                    key,
                    required,
                )?;
            }
        }
        if let Some(payload) = value.get_mut("payload") {
            visit(
                payload,
                "RegistryItemDto",
                schemas,
                fields,
                workspace,
                key,
                false,
                required,
                touched,
            )?;
        }
        return Ok(());
    }
    let payload_schema = match kind.as_str() {
        "task.offered" | "task.claim" | "task.beat" | "task.done" | "task.accept"
        | "task.reject" | "task.fail" | "task.cancel" | "task.handoff" | "task.take"
        | "task.decline" | "task.expired" => Some("CoordinationTask"),
        "board.changed" => Some("CoordinationBoardValue"),
        "zone.requested" | "zone.answered" => Some("CoordinationRequest"),
        "zone.queued" | "zone.dequeued" => Some("CoordinationQueueEntry"),
        "zone.claimed" | "zone.released" | "zone.expired" | "zone.lost" | "zone.granted"
        | "zone.handover" | "zone.takeover" => Some("CoordinationClaim"),
        "admin.freeze" => Some("CoordinationFreezeResult"),
        "bus.message" | "bus.ack" => Some("CoordinationMessage"),
        "bus.unread"
        | "bus.seen"
        | "bus.delivery_claimed"
        | "bus.imported"
        | "presence.activity"
        | "presence.heartbeat"
        | "presence.unavailable"
        | "zone.catalog"
        | "zone.dirty"
        | "zone.dirty_adopted"
        | "zone.dirty_disowned"
        | "integration.github" => None,
        _ if required => {
            return Err("required node encryption does not support this event payload type".into());
        }
        _ => None,
    };
    if let Some(payload) = value.get_mut("payload") {
        if let Some(payload_schema) = payload_schema {
            visit(
                payload,
                payload_schema,
                schemas,
                fields,
                workspace,
                key,
                false,
                required,
                touched,
            )?;
            // The server's request event copies the already-encrypted text into its note alias.
            if matches!(kind.as_str(), "zone.requested" | "zone.answered")
                && let Some(note) = payload.get_mut("note")
            {
                decrypt_event_field(note, "text", workspace, key, required)?;
            }
            if kind.starts_with("zone.")
                && let Some(reason) = payload.get_mut("reason")
            {
                let is_system = matches!(
                    (kind.as_str(), reason.as_str().unwrap_or_default()),
                    (
                        "zone.claimed",
                        "claimed" | "add_path" | "renewed" | "meta_updated"
                    ) | (
                        "zone.released",
                        "narrowed" | "released" | "idle" | "expired" | "unused_grant"
                    ) | ("zone.lost", "taken")
                        | ("zone.granted", "granted")
                        | ("zone.handover", "offered" | "accepted" | "returned")
                        | ("zone.expired", "expired" | "unused_grant")
                        | ("zone.queued", "short_wait" | "add_path" | "queued")
                        | (
                            "zone.dequeued",
                            "left_queue" | "claim_ended" | "already_held" | "expired"
                        )
                        | ("zone.requested", "requested")
                        | ("zone.answered", "answered")
                );
                if !is_system {
                    decrypt_event_field(reason, "reason", workspace, key, required)?;
                }
            }
        } else if required {
            reject_unclassified_event_content(payload)?;
        }
    }
    Ok(())
}

fn decrypt_event_field(
    value: &mut Value,
    name: &str,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    required: bool,
) -> Result<(), String> {
    if value.is_null() || value.as_str() == Some("") {
        return Ok(());
    }
    let Some(text) = value.as_str() else {
        return if required {
            Err("required node event content must be text".into())
        } else {
            Ok(())
        };
    };
    if text.starts_with(PREFIX) {
        *value = Value::String(match key {
            Some(key) => match key.decrypt(workspace, name, text) {
                Ok(plain) => plain,
                Err(_) if required => {
                    return Err("required node event content failed authentication".into());
                }
                Err(_) => "[cannot decrypt]".into(),
            },
            None if required => return Err("required node event key is unavailable".into()),
            None => "[locked]".into(),
        });
    } else if required {
        return Err("required node event content contains plaintext".into());
    }
    Ok(())
}

fn reject_unclassified_event_content(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(object) => {
            for (name, value) in object {
                if matches!(
                    name.as_str(),
                    "body"
                        | "title"
                        | "brief"
                        | "report"
                        | "text"
                        | "reply"
                        | "value"
                        | "note"
                        | "accept"
                ) && !value.is_null()
                    && value.as_str() != Some("")
                {
                    return Err("required node event contains unclassified content".into());
                }
                reject_unclassified_event_content(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_unclassified_event_content(value)?;
            }
        }
        Value::String(text) if text.starts_with(PREFIX) => {
            return Err("required node event contains an unclassified envelope".into());
        }
        _ => (),
    }
    Ok(())
}

/// Fail closed when a newer endpoint or an unclassified arbitrary JSON slot could bypass
/// the embedded content map. Ordinary coordination identifiers remain routing metadata.
fn validate_request_shape(
    value: &Value,
    definition: &Value,
    schemas: &Value,
) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    if definition.get("format").and_then(Value::as_str) == Some("date-time")
        && !safe_timestamp(value)
    {
        return Err(
            "required node timestamps must be canonical UTC text or bounded epoch milliseconds"
                .into(),
        );
    }
    if let Some(name) = definition
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.strip_prefix("#/components/schemas/"))
    {
        return validate_request_shape(value, &schemas[name], schemas);
    }
    if let Some(variants) = definition
        .get("oneOf")
        .or_else(|| definition.get("anyOf"))
        .and_then(Value::as_array)
    {
        return if variants
            .iter()
            .any(|variant| validate_request_shape(value, variant, schemas).is_ok())
        {
            Ok(())
        } else {
            Err("required node request has an unsupported field type".into())
        };
    }
    if let Some(variants) = definition.get("enum").and_then(Value::as_array) {
        return if variants.contains(value) {
            Ok(())
        } else {
            Err("required node request has an unsupported enum value".into())
        };
    }
    if let Some(items) = definition.get("items") {
        let values = value
            .as_array()
            .ok_or("required node request has an unsupported field type")?;
        for item in values {
            validate_request_shape(item, items, schemas)?;
        }
        return Ok(());
    }
    if let Some(properties) = definition.get("properties").and_then(Value::as_object) {
        let object = value
            .as_object()
            .ok_or("required node request must be an object")?;
        for (name, item) in object {
            let child = properties
                .get(name)
                .ok_or("required node request contains an unclassified field")?;
            if matches!(name.as_str(), "meta" | "hold_until_ref" | "legacy_raw") && !item.is_null()
            {
                return Err("required node request cannot send unclassified metadata".into());
            }
            if name == "sealed" {
                if !item.is_null() && !item.is_boolean() {
                    return Err("required node request sealed flag must be boolean".into());
                }
                continue;
            }
            if name == "value" {
                if !item.is_null() && !item.is_string() {
                    return Err("required node content must be serialized to text locally".into());
                }
                continue;
            }
            // This legacy DTO models activity as arbitrary JSON. Only the fixed public
            // liveness fields are valid in a node job; tool arguments and metadata aren't.
            if name == "activity" && !item.is_null() {
                let object = item
                    .as_object()
                    .ok_or("required node activity must be an approved liveness object")?;
                if object.iter().any(|(key, value)| match key.as_str() {
                    "tool_running" => !value.is_boolean(),
                    "tool_started_at" => !safe_timestamp(value),
                    "state" => {
                        !value.is_null()
                            && !matches!(
                                value.as_str(),
                                Some("working" | "idle" | "ended" | "api_failure")
                            )
                    }
                    "meta" => !safe_activity_meta(value),
                    _ => true,
                }) {
                    return Err(
                        "required node request cannot send arbitrary activity metadata".into(),
                    );
                }
            } else {
                validate_request_shape(item, child, schemas)?;
            }
        }
    } else {
        let supported_type = |kind: &str| match kind {
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            _ => false,
        };
        let valid = definition.get("type").is_some_and(|kind| {
            kind.as_str().is_some_and(supported_type)
                || kind
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().filter_map(Value::as_str).any(supported_type))
        });
        if !valid {
            return Err("required node request cannot send unclassified metadata or an unsupported field type".into());
        }
    }
    Ok(())
}

fn safe_timestamp(value: &Value) -> bool {
    const MAX: i64 = 253_402_300_799_999;
    value.is_null()
        || value
            .as_i64()
            .is_some_and(|stamp| (0..=MAX).contains(&stamp))
        || value.as_str().is_some_and(|text| {
            text.len() <= 24
                && lockyard_core::proto::parse_rfc3339(text).is_some_and(|stamp| {
                    (0..=MAX).contains(&stamp) && lockyard_core::proto::rfc3339(stamp) == text
                })
        })
}

fn safe_activity_meta(value: &Value) -> bool {
    value.is_null()
        || value.as_object().is_some_and(|object| {
            object.iter().all(|(key, value)| match key.as_str() {
                "level" => matches!(value.as_str(), Some("ok" | "warn" | "hold" | "critical")),
                "memory_available" | "memory_total" | "disk_free" | "temp_free" | "swap_used"
                | "cpus" => value.is_null() || value.as_u64().is_some(),
                "load" => value
                    .as_f64()
                    .is_some_and(|load| load.is_finite() && load >= 0.0),
                _ => false,
            })
        })
}

pub(crate) fn validate_required_route(method: &str, route: &str) -> Result<(), String> {
    let (_, api) = parsed()?;
    let (normalized, query) = route.split_once('?').unwrap_or((route, ""));
    // Legacy bulk imports contain untyped JSON/legacy_raw outside the content table.
    // A remote job must use the typed, encrypted operations instead.
    if normalized.starts_with("/api/v1/import/") || normalized == "/api/v1/registry/import" {
        return Err("required node encryption does not support legacy bulk imports".into());
    }
    let operation = api["paths"]
        .as_object()
        .ok_or("bad OpenAPI paths")?
        .iter()
        .filter(|(path, _)| openapi_path_matches(path, normalized))
        .find_map(|(_, operations)| operations.get(method.to_ascii_lowercase()))
        .ok_or("required node encryption does not support this API operation")?;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let name = pair.split('=').next().unwrap_or_default();
        if name == "q" {
            return Err("required node encryption forbids sending full-text searches to the cloud; filter decrypted items locally".into());
        }
        if !operation
            .get("parameters")
            .and_then(Value::as_array)
            .is_some_and(|params| {
                params
                    .iter()
                    .any(|parameter| parameter["in"] == "query" && parameter["name"] == name)
            })
        {
            return Err("required node request contains an unclassified query parameter".into());
        }
    }
    Ok(())
}
#[derive(Clone)]
pub struct WorkspaceKey([u8; 32]);
impl WorkspaceKey {
    pub fn from_entropy(e: [u8; 32]) -> Self {
        Self(e)
    }
    pub fn generate() -> Result<(Self, String), String> {
        let mut e = [0; 32];
        SystemRandom::new()
            .fill(&mut e)
            .map_err(|_| "system random source failed")?;
        let k = Self(e);
        let p = k.phrase();
        Ok((k, p))
    }
    pub fn from_phrase(p: &str) -> Result<Self, String> {
        let words = WORDS.lines().collect::<Vec<_>>();
        let parts = p
            .to_ascii_lowercase()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if parts.len() != 24 {
            return Err("the recovery phrase must contain 24 words".into());
        }
        let mut bits = Vec::new();
        for w in parts {
            let n = words
                .iter()
                .position(|x| **x == w)
                .ok_or("unknown recovery word")?;
            for b in (0..11).rev() {
                bits.push(((n >> b) & 1) as u8)
            }
        }
        let mut e = [0; 32];
        for (i, b) in bits[..256].iter().enumerate() {
            e[i / 8] |= b << (7 - i % 8)
        }
        let sum = digest::digest(&digest::SHA256, &e);
        for i in 0..8 {
            if bits[256 + i] != (sum.as_ref()[i / 8] >> (7 - i % 8)) & 1 {
                return Err("recovery phrase checksum is invalid".into());
            }
        }
        Ok(Self(e))
    }
    pub fn phrase(&self) -> String {
        entropy_to_phrase(&self.0)
    }
    pub fn store_for_workspace(&self, workspace: &str) -> Result<(), String> {
        use std::fs;
        let destination = Self::storage_path(workspace)?;
        let directory = destination.parent().ok_or("invalid key directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .map_err(|_| "cannot create key directory")?;
            for path in [
                directory.parent().ok_or("invalid key directory")?,
                directory,
            ] {
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| "cannot inspect key directory")?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || fs::canonicalize(path).map_err(|_| "cannot inspect key directory")? != path
                {
                    return Err(
                        "key directory must be owned and cannot contain symbolic links".into(),
                    );
                }
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "cannot secure key directory")?;
            }
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            fs::create_dir_all(directory).map_err(|_| "cannot create key directory")?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|_| "cannot create workspace key")?;
            file.write_all(&self.0)
                .and_then(|()| file.sync_all())
                .map_err(|_| "cannot write workspace key")
        }
        #[cfg(unix)]
        self.copy_to_private(&destination)
    }
    /// Location of the current workspace key; no key bytes or recovery words are returned.
    pub fn storage_path(workspace: &str) -> Result<std::path::PathBuf, String> {
        use std::path::PathBuf;
        if workspace.is_empty()
            || !workspace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invalid workspace id for local key storage".into());
        }
        let base = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?).join(".config"),
        };
        if !base.is_absolute() {
            return Err("workspace key directory must be absolute".into());
        }
        Ok(base.join("lockyard/keys").join(format!("{workspace}.key")))
    }
    pub fn load_for_workspace(workspace: &str) -> Result<Option<Self>, String> {
        Self::load_private(&Self::storage_path(workspace)?)
    }
    /// Bounded file-descriptor validation prevents symlink, FIFO and metadata replacement races.
    pub fn load_private(path: &std::path::Path) -> Result<Option<Self>, String> {
        use std::{fs, io::Read};
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("cannot read workspace key".into()),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect workspace key")?;
        if !metadata.is_file() {
            return Err("workspace key must be a regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } {
                return Err("workspace key must be owned by this user with mode 0600".into());
            }
        }
        let mut bytes = Vec::with_capacity(33);
        file.take(33)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read workspace key")?;
        if bytes.len() != 32 {
            return Err("workspace key file has an invalid length".into());
        }
        let mut raw = [0; 32];
        raw.copy_from_slice(&bytes);
        bytes.fill(0);
        Ok(Some(Self(raw)))
    }

    /// Stage a key for an explicitly authorized endpoint in a caller-created private directory.
    /// The key is never returned as text, and an existing destination is never replaced.
    #[cfg(unix)]
    pub fn copy_to_private(&self, destination: &std::path::Path) -> Result<(), String> {
        use std::{
            fs,
            io::Write,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        if !destination.is_absolute() {
            return Err("key destination must be absolute".into());
        }
        let parent = destination.parent().ok_or("invalid key destination")?;
        let metadata =
            fs::symlink_metadata(parent).map_err(|_| "key staging directory unavailable")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("key staging directory must be private and owned".into());
        }
        let mut nonce = [0; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "key staging random source unavailable")?;
        let staged = parent.join(format!(".lykey-stage-{}", base64url(&nonce)));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged)
            .map_err(|_| "cannot create private key copy")?;
        let result: Result<(), String> = (|| {
            file.write_all(&self.0)
                .map_err(|_| "cannot write private key copy")?;
            file.sync_all()
                .map_err(|_| "cannot sync private key copy")?;
            // Only a complete, fsynced file can become the final name. link is atomic
            // and create-only: another key at the destination is never overwritten.
            fs::hard_link(&staged, destination).map_err(|_| "cannot publish private key copy")?;
            fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "cannot sync key staging directory")?;
            Ok(())
        })();
        // A crash before publication can leave only a private, ignored temporary.
        // After publication, even a directory-sync failure must retain the complete key.
        let removed = fs::remove_file(&staged);
        let synced = fs::File::open(parent).and_then(|dir| dir.sync_all());
        result?;
        removed.map_err(|_| "cannot remove private key staging file")?;
        synced.map_err(|_| "cannot sync key staging directory")?;
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn copy_to_private(&self, _: &std::path::Path) -> Result<(), String> {
        Err("private key staging requires Unix ownership checks".into())
    }
    pub fn key_id(&self) -> String {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        base64url(&hmac::sign(&k, LABEL).as_ref()[..8])
    }
    /// Derive a purpose-bound child key without exposing master key bytes.
    /// High-rate protocols must give every encrypted record its own unique context.
    pub fn derive_context(&self, domain: &[u8], context: &[u8]) -> Result<Self, String> {
        struct KeyLength;
        impl ring::hkdf::KeyType for KeyLength {
            fn len(&self) -> usize {
                32
            }
        }
        if domain.is_empty() || domain.len() > 128 || context.len() > 64 * 1024 {
            return Err("invalid key derivation context".into());
        }
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, domain);
        let prk = salt.extract(&self.0);
        let info = [context];
        let expanded = prk
            .expand(&info, KeyLength)
            .map_err(|_| "key derivation failed")?;
        let mut key = [0; 32];
        expanded
            .fill(&mut key)
            .map_err(|_| "key derivation failed")?;
        Ok(Self(key))
    }
    pub fn encrypt(&self, w: &str, f: &str, p: &str) -> Result<String, String> {
        let mut n = [0; 12];
        SystemRandom::new()
            .fill(&mut n)
            .map_err(|_| "system random source failed")?;
        let k = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).map_err(|_| "invalid key")?,
        );
        let mut b = p.as_bytes().to_vec();
        k.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(n),
            aead::Aad::from(aad(w, f)),
            &mut b,
        )
        .map_err(|_| "encryption failed")?;
        let mut x = n.to_vec();
        x.extend(b);
        Ok(format!("{PREFIX}{}.{}", self.key_id(), base64url(&x)))
    }
    pub fn decrypt(&self, w: &str, f: &str, v: &str) -> Result<String, String> {
        let x = v.strip_prefix(PREFIX).ok_or("not encrypted")?;
        let (id, b) = x.split_once('.').ok_or("invalid envelope")?;
        if id != self.key_id() {
            return Err("wrong encryption key".into());
        }
        let mut b = unbase64url(b)?;
        if b.len() < 28 {
            return Err("invalid envelope".into());
        }
        let n: [u8; 12] = b[..12].try_into().map_err(|_| "invalid nonce")?;
        let k = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).map_err(|_| "invalid key")?,
        );
        let o = k
            .open_in_place(
                aead::Nonce::assume_unique_for_key(n),
                aead::Aad::from(aad(w, f)),
                &mut b[12..],
            )
            .map_err(|_| "cannot decrypt")?;
        String::from_utf8(o.to_vec()).map_err(|_| "invalid utf8".into())
    }
}
fn aad(w: &str, f: &str) -> Vec<u8> {
    [w.as_bytes(), &[0], f.as_bytes()].concat()
}
fn entropy_to_phrase(e: &[u8; 32]) -> String {
    let w = WORDS.lines().collect::<Vec<_>>();
    let c = digest::digest(&digest::SHA256, e);
    (0..24)
        .map(|i| {
            let mut n = 0;
            for j in 0..11 {
                let p = i * 11 + j;
                let b = if p < 256 {
                    (e[p / 8] >> (7 - p % 8)) & 1
                } else {
                    (c.as_ref()[(p - 256) / 8] >> (7 - (p - 256) % 8)) & 1
                };
                n = (n << 1) | b as usize
            }
            w[n]
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn base64url(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((*c.get(1).unwrap_or(&0) as u32) << 8)
            | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[((n >> 18) & 63) as usize] as char);
        o.push(T[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 {
            o.push(T[((n >> 6) & 63) as usize] as char)
        }
        if c.len() > 2 {
            o.push(T[(n & 63) as usize] as char)
        }
    }
    o
}
fn unbase64url(s: &str) -> Result<Vec<u8>, String> {
    let mut o = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err("bad base64".into()),
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            o.push((acc >> bits) as u8)
        }
    }
    if base64url(&o) != s {
        return Err("noncanonical base64".into());
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn current_key_read_is_bounded_private_and_uses_opened_descriptor() {
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        };
        let directory = std::env::temp_dir().join(format!("lockyard-key-read-{}", crate::ulid()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("key");
        WorkspaceKey::from_entropy([91; 32])
            .copy_to_private(&path)
            .unwrap();
        assert_eq!(
            WorkspaceKey::load_private(&path).unwrap().unwrap().key_id(),
            WorkspaceKey::from_entropy([91; 32]).key_id()
        );
        // A crash between final create-only link and temporary unlink must remain readable.
        let orphan = directory.join("orphan");
        fs::hard_link(&path, &orphan).unwrap();
        assert!(WorkspaceKey::load_private(&path).unwrap().is_some());
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        assert!(WorkspaceKey::load_private(&link).is_err());
        assert!(WorkspaceKey::load_private(&directory).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(WorkspaceKey::load_private(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, [1; 33]).unwrap();
        assert!(WorkspaceKey::load_private(&path).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn key_copy_publishes_complete_bytes_once_and_ignores_interrupted_temporary() {
        use std::{
            fs,
            os::unix::fs::{DirBuilderExt, PermissionsExt},
        };
        let directory =
            std::env::temp_dir().join(format!("lockyard-key-publish-{}", crate::ulid()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let orphan = directory.join(".lykey-stage-interrupted-fixture");
        fs::write(&orphan, [1; 16]).unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
        let destination = directory.join("fixture-workspace.key");
        let left = destination.clone();
        let right = destination.clone();
        let first =
            std::thread::spawn(move || WorkspaceKey::from_entropy([94; 32]).copy_to_private(&left));
        let second = std::thread::spawn(move || {
            WorkspaceKey::from_entropy([95; 32]).copy_to_private(&right)
        });
        let (first, second) = (first.join().unwrap(), second.join().unwrap());
        assert_ne!(first.is_ok(), second.is_ok());
        let actual = fs::read(&destination).unwrap();
        assert!(actual == [94; 32] || actual == [95; 32]);
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            WorkspaceKey::from_entropy([96; 32])
                .copy_to_private(&destination)
                .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), actual);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn encrypted_envelopes_reject_alternate_unused_base64_bits() {
        let key = WorkspaceKey::from_entropy([93; 32]);
        let envelope = key.encrypt("fixture-workspace", "body", "a").unwrap();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut altered = envelope.as_bytes().to_vec();
        let last = altered.last_mut().unwrap();
        let index = alphabet
            .iter()
            .position(|character| character == last)
            .unwrap();
        *last = alphabet[index | 1];
        assert_ne!(altered, envelope.as_bytes());
        assert_eq!(
            key.decrypt("fixture-workspace", "body", &envelope).unwrap(),
            "a"
        );
        assert!(
            key.decrypt(
                "fixture-workspace",
                "body",
                &String::from_utf8(altered).unwrap()
            )
            .is_err()
        );
        assert!(unbase64url("A").is_err());
        assert!(unbase64url("AB").is_err());
    }
    #[test]
    fn content_table_entries_exist_and_free_text_is_explicit() {
        let api: Value = serde_json::from_str(OPENAPI).unwrap();
        let table: Value = serde_json::from_str(FIELDS).unwrap();
        let schemas = api["components"]["schemas"].as_object().unwrap();
        let fields = table["fields"].as_array().unwrap();
        let clear = table["clear"].as_array().unwrap();
        for entry in fields.iter().chain(clear) {
            let schema = entry["schema"].as_str().unwrap();
            let prop = entry["property"].as_str().unwrap();
            assert!(
                schemas
                    .get(schema)
                    .is_some_and(|s| s["properties"].get(prop).is_some()),
                "missing {schema}.{prop}"
            );
        }
        let covered = fields
            .iter()
            .chain(clear)
            .map(|e| {
                (
                    e["schema"].as_str().unwrap(),
                    e["property"].as_str().unwrap(),
                )
            })
            .collect::<std::collections::HashSet<_>>();
        let likely_free = [
            "body",
            "text",
            "reply",
            "brief",
            "report",
            "reason",
            "accept",
            "acceptance",
            "title",
            "value",
            "resolution",
            "purpose",
            "comment",
        ];
        for (schema, def) in schemas {
            if let Some(props) = def["properties"].as_object() {
                for (prop, spec) in props {
                    let stringy = spec["type"] == "string"
                        || spec["type"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|x| x == "string"));
                    if stringy && likely_free.contains(&prop.as_str()) {
                        assert!(
                            covered.contains(&(schema.as_str(), prop.as_str())),
                            "unclassified free text {schema}.{prop}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn schema_response_and_request_walks_use_web_aad_names() {
        let key = WorkspaceKey::from_entropy([9; 32]);
        let mut req = serde_json::json!({"body":"hello"});
        transform_fields(
            &mut req,
            "POST",
            "/api/v1/bus/messages",
            "w",
            Some(&key),
            true,
        )
        .unwrap();
        assert!(req["body"].as_str().unwrap().starts_with(PREFIX));
        let mut res = serde_json::json!({"messages":[{"body":req["body"].clone()}]});
        transform_fields(&mut res, "GET", "/api/v1/bus/inbox", "w", Some(&key), false).unwrap();
        assert_eq!(res["messages"][0]["body"], "hello");
    }
    #[test]
    fn enabled_encryption_errors_without_key() {
        let mut v = serde_json::json!({"body":"plain"});
        assert!(transform_fields(&mut v, "POST", "/api/v1/bus/messages", "w", None, true).is_err());
        assert_eq!(v["body"], "plain");
    }
}
