// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

/// Tool arguments. A value of the wrong type is an error, never treated as absent: `zone_release`
/// with a bad id must not release every claim.
#[derive(Clone, Copy)]
pub(super) struct Args<'a>(pub(super) &'a Value);

impl<'a> Args<'a> {
    pub(super) fn get(self, key: &str) -> Option<&'a Value> {
        self.0.get(key).filter(|value| !value.is_null())
    }

    pub(super) fn text(self, key: &str) -> Result<&'a str> {
        self.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| wrong_type(key, "a string"))
    }

    pub(super) fn optional_text(self, key: &str) -> Result<&'a str> {
        self.get(key).map_or(Ok(""), |_| self.text(key))
    }

    pub(super) fn some_text(self, key: &str) -> Result<Option<String>> {
        self.get(key)
            .map(|_| self.text(key).map(str::to_string))
            .transpose()
    }

    pub(super) fn required_object(self, key: &str) -> Result<Value> {
        self.get(key)
            .filter(|value| value.is_object())
            .cloned()
            .ok_or_else(|| wrong_type(key, "an object"))
    }

    pub(super) fn flag(self, key: &str) -> Result<bool> {
        self.get(key).map_or(Ok(false), |value| {
            value.as_bool().ok_or_else(|| wrong_type(key, "a boolean"))
        })
    }

    pub(super) fn int(self, key: &str) -> Result<i64> {
        self.get(key)
            .and_then(Value::as_i64)
            .ok_or_else(|| wrong_type(key, "an integer"))
    }

    pub(super) fn some_int(self, key: &str) -> Result<Option<i64>> {
        self.get(key).map(|_| self.int(key)).transpose()
    }

    pub(super) fn id(self) -> Result<i64> {
        self.int("id")
    }

    pub(super) fn task_key(self, key: &str) -> Result<String> {
        self.task_value(key, lockyard_compat::TaskDomain::Registry)
    }

    fn task_value(self, key: &str, domain: lockyard_compat::TaskDomain) -> Result<String> {
        lockyard_compat::LegacyCompatibilityV1::task_id(
            self.get(key).ok_or_else(|| wrong_type(key, "a task id"))?,
            domain,
            lockyard_compat::Source::Mcp,
            2,
        )
        .map_err(|code| Error::Cloud {
            code,
            status: None,
            details: Value::Null,
            message: format!("invalid {key}"),
        })
    }

    pub(super) fn task_key_for(self, cloud: bool) -> Result<String> {
        self.task_value(
            "id",
            if cloud {
                lockyard_compat::TaskDomain::Registry
            } else {
                lockyard_compat::TaskDomain::LegacyLocal
            },
        )
    }

    pub(super) fn some_task_id(self, key: &str) -> Result<Option<String>> {
        self.get(key).map(|_| self.task_key(key)).transpose()
    }

    pub(super) fn bus_key(self) -> Result<String> {
        self.task_value("id", lockyard_compat::TaskDomain::Bus)
    }

    pub(super) fn optional_id(self) -> Result<Option<i64>> {
        self.some_int("id")
    }

    pub(super) fn optional_claim_id(self) -> Result<Option<i64>> {
        self.get("id")
            .map(|value| {
                let raw = match value {
                    Value::Number(number) => number.to_string(),
                    Value::String(text) => text
                        .strip_prefix("Z-")
                        .or_else(|| text.strip_prefix("z-"))
                        .unwrap_or(text)
                        .to_string(),
                    _ => return Err(wrong_type("id", "a claim id such as Z-392 or 392")),
                };
                raw.parse::<i64>().map_err(|_| {
                    Error::Invalid("id must be a claim id such as Z-392 or 392".into())
                })
            })
            .transpose()
    }

    pub(super) fn ttl(self) -> Result<i64> {
        self.get("ttl")
            .map_or(Ok(DEFAULT_TTL_MINUTES), |_| self.int("ttl"))
    }

    pub(super) fn strings(self, key: &str) -> Result<Vec<String>> {
        let Some(value) = self.get(key) else {
            return Ok(Vec::new());
        };
        let items = value
            .as_array()
            .ok_or_else(|| wrong_type(key, "an array of strings"))?;
        items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| wrong_type(key, "an array of strings"))
            })
            .collect()
    }

    pub(super) fn task_keys(self, key: &str) -> Result<Vec<String>> {
        let values = self
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| wrong_type(key, "an array of task ids"))?;
        values
            .iter()
            .map(|raw| {
                lockyard_compat::LegacyCompatibilityV1::task_id(
                    raw,
                    lockyard_compat::TaskDomain::Registry,
                    lockyard_compat::Source::Mcp,
                    2,
                )
                .map_err(|code| Error::Cloud {
                    code,
                    status: None,
                    details: Value::Null,
                    message: format!("invalid {key}"),
                })
            })
            .collect()
    }

    pub(super) fn step(self) -> Result<WorkStep> {
        Ok(WorkStep {
            to: self.some_text("to")?,
            report: self.some_text("report")?,
            reason: self.some_text("reason")?,
            commits: self.strings("commits")?,
            version: self.some_int("if_version")?,
        })
    }

    pub(super) fn mode(self) -> Result<ClaimMode> {
        Ok(if self.flag("shared")? {
            ClaimMode::Shared
        } else {
            ClaimMode::Exclusive
        })
    }

    pub(super) fn purpose(self) -> Result<Purpose> {
        Ok(if self.flag("deploy")? {
            Purpose::Deploy
        } else {
            Purpose::Work
        })
    }
}

pub(super) fn wrong_type(key: &str, expected: &str) -> Error {
    Error::Invalid(format!("{key} must be {expected}"))
}

pub(super) fn encode(value: &impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| Error::Invalid(format!("cannot encode: {error}")))
}

pub(super) fn escape_bidi_controls(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if matches!(
                ch as u32,
                0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
            ) {
                format!("\\u{{{:x}}}", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
}

pub(super) fn safe_messages(
    mut messages: Vec<lockyard_core::proto::Message>,
) -> Vec<lockyard_core::proto::Message> {
    for message in &mut messages {
        message.body = escape_bidi_controls(&message.body);
    }
    messages
}

pub(super) fn safe_receipts(
    mut receipts: Vec<lockyard_core::bus::Receipt>,
) -> Vec<lockyard_core::bus::Receipt> {
    for receipt in &mut receipts {
        receipt.body = escape_bidi_controls(&receipt.body);
    }
    receipts
}

/// Paths of a tool call, plus those of the zones it names.
pub(super) fn claim_paths(
    opened: &Opened,
    args: Args<'_>,
    cwd: &Path,
) -> Result<(Vec<String>, Vec<String>)> {
    let zones = args.strings("zones")?;
    let mut paths = opened.zone_paths(cwd, &args.strings("paths")?)?;
    if !zones.is_empty() {
        let expanded = opened
            .backend
            .catalog_expand(&zones)
            .map_err(|error| match error {
                Error::NeedsCloud(_) => Error::Invalid(format!(
                    "unknown zone {}; catalog: unavailable in local mode",
                    zones.join(", ")
                )),
                other => other,
            })?;
        for path in expanded {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    validate_claim_path_count(paths.len())?;
    Ok((paths, zones))
}

pub(super) fn claim_request(opened: &Opened, args: Args<'_>, cwd: &Path) -> Result<ClaimRequest> {
    let (paths, zones) = claim_paths(opened, args, cwd)?;
    Ok(ClaimRequest {
        paths,
        note: args.optional_text("note")?.to_string(),
        ttl_minutes: args.ttl()?,
        mode: args.mode()?,
        purpose: args.purpose()?,
        lazy: args.flag("lazy")?,
        zone: if let [one] = zones.as_slice() {
            Some(one.clone())
        } else {
            None
        },
        zones: if zones.len() > 1 { zones } else { Vec::new() },
        queue_wait_seconds: None,
        meta: args.get("meta").cloned(),
    })
}

pub(super) fn stream(args: Args<'_>) -> Result<Stream> {
    match args
        .get("stream")
        .map(|_| args.text("stream"))
        .transpose()?
    {
        None | Some("coordination") => Ok(Stream::Coordination),
        Some("registry") => Ok(Stream::Registry),
        Some(other) => Err(Error::Invalid(format!("unknown stream {other:?}"))),
    }
}

pub(super) fn session_state(text: Option<String>) -> Result<Option<SessionState>> {
    text.map(|name| {
        serde_json::from_value(json!(name))
            .map_err(|_| Error::Invalid(format!("unknown session state {name:?}")))
    })
    .transpose()
}
