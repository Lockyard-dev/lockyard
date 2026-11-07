// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Canonical task identities. Compatibility conversion belongs at the wire boundary.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{fmt, ops::Deref, str::FromStr};

const MAX_ORDINAL: u64 = 9_007_199_254_740_991;

fn valid(value: &str, bus: bool) -> bool {
    if value.len() > 32 || !value.is_ascii() {
        return false;
    }
    let Some((prefix, suffix)) = value.rsplit_once('-') else {
        return false;
    };
    if prefix.len() > 16 || prefix.is_empty() || (bus && prefix != "BT") {
        return false;
    }
    if !prefix.split('-').all(|part| {
        part.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
            && part
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    }) {
        return false;
    }
    !suffix.is_empty()
        && suffix.bytes().all(|b| b.is_ascii_digit())
        && suffix
            .parse::<u64>()
            .is_ok_and(|n| (1..=MAX_ORDINAL).contains(&n))
}

macro_rules! identity {
    ($name:ident, $bus:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn parse(value: &str) -> Result<Self> {
                if valid(value, $bus) {
                    Ok(Self(value.into()))
                } else {
                    Err(Error::Cloud {
                        code: "invalid_task_id".into(),
                        status: None,
                        details: serde_json::Value::Null,
                        message: "invalid task id".into(),
                    })
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }
        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }
        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other
            }
        }
        impl PartialEq<$name> for serde_json::Value {
            fn eq(&self, other: &$name) -> bool {
                self.as_str() == Some(other.as_str())
            }
        }
        impl TryFrom<String> for $name {
            type Error = Error;
            fn try_from(s: String) -> Result<Self> {
                Self::parse(&s)
            }
        }
        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }
        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::parse(s)
            }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
        impl Deref for $name {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
identity!(TaskId, false);
identity!(BusTaskId, true);
