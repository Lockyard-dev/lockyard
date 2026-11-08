// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! The only numeric-task and historical owner-decision boundary.
use lockyard_core::task_id::{BusTaskId, TaskId};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

const MAX_ORDINAL: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug)]
pub enum Source {
    Cli,
    Mcp,
    Sdk,
    Http,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Mcp => "mcp",
            Self::Sdk => "sdk",
            Self::Http => "http",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TaskDomain {
    Registry,
    Local,
    /// Only a local ingress explicitly permits the former T-n syntax.
    LegacyLocal,
    Bus,
}

static COUNTERS: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();

/// Process diagnostics can be read without cloud connectivity. Values contain no task IDs.
pub fn counters() -> BTreeMap<String, u64> {
    COUNTERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn diagnostics_dir() -> Option<PathBuf> {
    if let Some(directory) = std::env::var_os("LOCKYARD_DIAGNOSTICS_DIR") {
        return Some(directory.into());
    }
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            lockyard_core::paths::home_dir().map(|home| PathBuf::from(home).join(".local/state"))
        })
        .map(|path| path.join("lockyard/diagnostics"))
}

fn count(metric: &str, source: Source, kind: Option<&str>, protocol: Option<u8>) {
    let labels = match (kind, protocol) {
        (Some(kind), Some(protocol)) => format!(
            "{metric}{{kind={kind},source={},protocol={protocol}}}",
            source.as_str()
        ),
        _ => format!("{metric}{{source={}}}", source.as_str()),
    };
    *COUNTERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(labels)
        .or_default() += 1;
    // A diagnostics filesystem failure cannot change a successful decode into a new write/retry.
    if let Some(directory) = diagnostics_dir() {
        let _ = (|| -> std::io::Result<()> {
            fs::create_dir_all(&directory)?;
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let mut output = options.open(directory.join("compat.jsonl"))?;
            let mut entry = serde_json::to_vec(&json!({"metric":metric,"source":source.as_str(),"kind":kind,"protocol":protocol,"delta":1}))
                .map_err(std::io::Error::other)?;
            entry.push(b'\n');
            output.write_all(&entry)
        })();
    }
}

pub struct LegacyCompatibilityV1;

impl LegacyCompatibilityV1 {
    /// Exactly one conversion per field; strict canonical validation never normalizes prefixes.
    pub fn task_id(
        raw: &Value,
        domain: TaskDomain,
        source: Source,
        protocol: u8,
    ) -> Result<String, String> {
        let text = match raw {
            Value::String(text) => text.clone(),
            Value::Number(number) => {
                let ordinal = number
                    .as_u64()
                    .filter(|n| (1..=MAX_ORDINAL).contains(n))
                    .ok_or_else(|| "invalid_task_id".to_string())?;
                if protocol >= 3 {
                    return Err("legacy_input_removed".into());
                }
                count(
                    "lockyard_compat_conversions_total",
                    source,
                    Some("legacy_task_id"),
                    Some(protocol),
                );
                return Ok(format!(
                    "{}-{ordinal}",
                    if matches!(domain, TaskDomain::Bus) {
                        "BT"
                    } else {
                        "D"
                    }
                ));
            }
            _ => return Err("invalid_task_id".into()),
        };
        let digits = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
        let local_alias = matches!(domain, TaskDomain::LegacyLocal) && text.starts_with("T-");
        if digits || local_alias {
            if protocol >= 3 {
                return Err("legacy_input_removed".into());
            }
            let suffix = if local_alias {
                &text[2..]
            } else {
                text.as_str()
            };
            let ordinal = suffix
                .parse::<u64>()
                .ok()
                .filter(|n| (1..=MAX_ORDINAL).contains(n))
                .filter(|_| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
                .ok_or_else(|| "invalid_task_id".to_string())?;
            count(
                "lockyard_compat_conversions_total",
                source,
                Some("legacy_task_id"),
                Some(protocol),
            );
            return Ok(format!(
                "{}-{ordinal}",
                if matches!(domain, TaskDomain::Bus) {
                    "BT"
                } else {
                    "D"
                }
            ));
        }
        let valid = if matches!(domain, TaskDomain::Bus) {
            BusTaskId::parse(&text).map(|_| ())
        } else {
            TaskId::parse(&text).map(|_| ())
        };
        valid.map_err(|_| "invalid_task_id".to_string())?;
        Ok(text)
    }

    /// Schema-selected DTO projection; unknown schemas and unrelated fields are untouched.
    pub fn wire_schema(
        mut value: Value,
        schema: &str,
        source: Source,
        protocol: u8,
    ) -> Result<Value, String> {
        let Some(object) = value.as_object_mut() else {
            return Ok(value);
        };
        match schema {
            "lockyard_core::proto::Claim"
            | "lockyard_core::proto::QueueEntry"
            | "lockyard_core::proto::Presence" => {
                if let Some(alias) = object.get("agent").cloned() {
                    if protocol >= 3 {
                        return Err("legacy_input_removed".into());
                    }
                    if !alias.is_string()
                        || object
                            .get("session")
                            .is_some_and(|canonical| canonical != &alias)
                    {
                        return Err("invalid_request".into());
                    }
                    object.remove("agent");
                    object.insert("session".into(), alias);
                    count(
                        "lockyard_compat_conversions_total",
                        source,
                        Some("legacy_wire_shape"),
                        Some(protocol),
                    );
                }
                if schema == "lockyard_core::proto::Claim"
                    && let Some(entries) = object
                        .get_mut("foreign_dirty_paths")
                        .and_then(Value::as_array_mut)
                {
                    for entry in entries {
                        *entry = Self::wire_schema(
                            entry.clone(),
                            "lockyard_core::proto::DirtyPath",
                            source,
                            protocol,
                        )?;
                    }
                }
            }
            "lockyard_core::proto::DirtyPath" => {
                if let Some(id) = object.get_mut("task_id").filter(|id| !id.is_null()) {
                    *id = Value::String(Self::task_id(id, TaskDomain::Registry, source, protocol)?);
                }
            }
            "lockyard_core::proto::WorkTask" => {
                if let Some(id) = object.get_mut("id") {
                    *id = Value::String(Self::task_id(id, TaskDomain::Bus, source, protocol)?);
                }
            }
            _ => {}
        }
        Ok(value)
    }

    /// Endpoint supplies its exact accepted wrapper names; no recursive JSON heuristics.
    pub fn wire_list(
        value: Value,
        names: &[&str],
        source: Source,
        protocol: u8,
    ) -> Result<Value, String> {
        let result = match value {
            Value::Array(_) => return Ok(value),
            Value::Null => Value::Array(Vec::new()),
            other => names
                .iter()
                .find_map(|name| other.get(*name).filter(|field| field.is_array()).cloned())
                .ok_or_else(|| format!("expected a list under {names:?}"))?,
        };
        if protocol >= 3 {
            return Err("legacy_input_removed".into());
        }
        count(
            "lockyard_compat_conversions_total",
            source,
            Some("legacy_wire_shape"),
            Some(protocol),
        );
        Ok(result)
    }

    pub fn wire_record(
        value: Value,
        name: &str,
        source: Source,
        protocol: u8,
    ) -> Result<Value, String> {
        if let Some(record) = value.get(name).filter(|inner| inner.is_object()) {
            if protocol >= 3 {
                return Err("legacy_input_removed".into());
            }
            count(
                "lockyard_compat_conversions_total",
                source,
                Some("legacy_wire_shape"),
                Some(protocol),
            );
            Ok(record.clone())
        } else {
            Ok(value)
        }
    }

    /// Protocol-one numeric projection is available only when the canonical ID round-trips.
    pub fn task_receipt(
        id: &str,
        domain: TaskDomain,
        source: Source,
        protocol: u8,
    ) -> Result<Value, String> {
        if matches!(domain, TaskDomain::Bus) {
            BusTaskId::parse(id).map(|_| ())
        } else {
            TaskId::parse(id).map(|_| ())
        }
        .map_err(|_| "invalid_task_id".to_string())?;
        if protocol >= 2 {
            return Ok(Value::String(id.into()));
        }
        let prefix = if matches!(domain, TaskDomain::Bus) {
            "BT-"
        } else {
            "D-"
        };
        let suffix = id
            .strip_prefix(prefix)
            .ok_or_else(|| "legacy_task_id_unrepresentable".to_string())?;
        let number = suffix
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=MAX_ORDINAL).contains(n))
            .filter(|n| n.to_string() == suffix)
            .ok_or_else(|| "legacy_task_id_unrepresentable".to_string())?;
        count(
            "lockyard_compat_conversions_total",
            source,
            Some("legacy_task_receipt"),
            Some(protocol),
        );
        Ok(json!(number))
    }
}

/// Invoke only after the caller has established an owner-close schema/context.
pub struct OwnerDecisionV1Reader;

impl OwnerDecisionV1Reader {
    pub fn read(
        source: Source,
        mut decrypt: impl FnMut(&str) -> Result<String, String>,
    ) -> Result<String, String> {
        match decrypt("owner_word") {
            Ok(plaintext) => Ok(plaintext),
            Err(error) if error == "content_authentication_failed" => {
                let plaintext = decrypt("value")?;
                count("lockyard_compat_aad_value_reads_total", source, None, None);
                Ok(plaintext)
            }
            Err(error) => Err(error),
        }
    }
}
