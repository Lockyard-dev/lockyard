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
        use std::{fs, io::Write, path::PathBuf};
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
        let dir = base.join("lockyard/keys");
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create key directory: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                dir.parent().ok_or("invalid key directory")?,
                fs::Permissions::from_mode(0o700),
            )
            .map_err(|e| format!("cannot secure key directory: {e}"))?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot secure key directory: {e}"))?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(dir.join(format!("{workspace}.key")))
            .map_err(|e| format!("cannot create workspace key: {e}"))?;
        f.write_all(&self.0)
            .map_err(|e| format!("cannot write workspace key: {e}"))
    }
    pub fn load_for_workspace(workspace: &str) -> Result<Option<Self>, String> {
        use std::{fs, path::PathBuf};
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
        let path = base.join("lockyard/keys").join(format!("{workspace}.key"));
        let b = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read workspace key: {e}")),
        };
        if b.len() != 32 {
            return Err("workspace key file has an invalid length".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path)
                .map_err(|e| format!("cannot inspect workspace key: {e}"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o600 {
                return Err("workspace key file must have mode 0600".into());
            }
        }
        let mut raw = [0; 32];
        raw.copy_from_slice(&b);
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
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(destination)
            .map_err(|_| "cannot create private key copy")?;
        let result = (|| {
            file.write_all(&self.0)
                .map_err(|_| "cannot write private key copy")?;
            file.sync_all()
                .map_err(|_| "cannot sync private key copy")?;
            fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| "cannot sync key staging directory")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(destination);
        }
        result
    }

    #[cfg(not(unix))]
    pub fn copy_to_private(&self, _: &std::path::Path) -> Result<(), String> {
        Err("private key staging requires Unix ownership checks".into())
    }
    pub fn key_id(&self) -> String {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        base64url(&hmac::sign(&k, LABEL).as_ref()[..8])
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
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;
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
