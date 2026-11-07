// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Strict EP-07 plaintext and wire records. Only the SDK may authenticate a wire record.
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, MapAccess, Visitor},
};
use std::{collections::BTreeMap, fmt};

pub const CATALOG_FORMAT: &str = "lockyard.zone_catalog.v1";
pub const MAX_CATALOG_REVISION: u64 = 9_007_199_254_740_991;
pub const MAX_CATALOG_PLAINTEXT: usize = 512 * 1024;
pub const MAX_CATALOG_WIRE: usize = 720 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError(&'static str);
impl CatalogError {
    pub fn new(code: &'static str) -> Self {
        Self(code)
    }
    pub fn code(&self) -> &'static str {
        self.0
    }
}
impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CatalogError {}
fn invalid() -> CatalogError {
    CatalogError::new("catalog_invalid")
}

/// The plaintext never crosses the cloud transport. Maps reject repeated names during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneCatalogV1 {
    pub version: u8,
    #[serde(deserialize_with = "unique_names")]
    pub zones: BTreeMap<String, Vec<String>>,
    #[serde(default, deserialize_with = "unique_names")]
    pub groups: BTreeMap<String, Vec<String>>,
}
fn unique_names<'de, D: Deserializer<'de>>(
    reader: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    struct Names;
    impl<'de> Visitor<'de> for Names {
        type Value = BTreeMap<String, Vec<String>>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("unique catalog names")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut names = BTreeMap::new();
            while let Some((name, entries)) = map.next_entry::<String, Vec<String>>()? {
                if names.insert(name, entries).is_some() {
                    return Err(de::Error::custom("duplicate catalog name"));
                }
            }
            Ok(names)
        }
    }
    reader.deserialize_map(Names)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control)
}
impl ZoneCatalogV1 {
    pub fn from_json(raw: &str) -> Result<Self, CatalogError> {
        if raw.len() > MAX_CATALOG_PLAINTEXT {
            return Err(invalid());
        }
        let catalog: Self = serde_json::from_str(raw).map_err(|_| invalid())?;
        catalog.validate()?;
        Ok(catalog)
    }
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.version != 1
            || self.zones.len() > 1024
            || self.groups.len() > 1024
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > MAX_CATALOG_PLAINTEXT
        {
            return Err(invalid());
        }
        let mut count = 0;
        for (name, paths) in &self.zones {
            if !valid_name(name) || paths.is_empty() || paths.len() > 256 {
                return Err(invalid());
            }
            count += paths.len();
            for path in paths {
                if path.len() > 1024
                    || path.chars().any(char::is_control)
                    || path.as_bytes().get(1) == Some(&b':')
                        && path.as_bytes()[0].is_ascii_alphabetic()
                    || crate::repository::qualify(None, path).is_err()
                {
                    return Err(invalid());
                }
            }
        }
        if count > 4096 {
            return Err(invalid());
        }
        for (name, members) in &self.groups {
            if !valid_name(name)
                || self.zones.contains_key(name)
                || members.is_empty()
                || members
                    .iter()
                    .any(|member| !self.zones.contains_key(member))
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    /// First-seen paths follow requested-name, group-member and zone-path order.
    pub fn expand(&self, names: &[String]) -> Result<Vec<String>, CatalogError> {
        self.validate()?;
        let mut paths = Vec::new();
        for name in names {
            let members = self
                .groups
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or(std::slice::from_ref(name));
            for member in members {
                let entries = self
                    .zones
                    .get(member)
                    .ok_or_else(|| CatalogError::new("zone_unknown"))?;
                for path in entries {
                    if !paths.contains(path) {
                        paths.push(path.clone());
                    }
                    if paths.len() > 256 {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(paths)
    }
}

pub fn canonical_workspace_id(workspace: &str) -> bool {
    workspace.len() == 36
        && workspace.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
pub fn validate_catalog_scope(workspace: &str, repository: &str) -> Result<(), CatalogError> {
    if !canonical_workspace_id(workspace)
        || !repository.is_empty() && crate::repository::validate_id(repository).is_err()
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationZoneCatalog {
    pub format: String,
    pub workspace_id: String,
    pub repository: String,
    pub revision: u64,
    pub key_id: String,
    pub case_insensitive_paths: bool,
    pub content_sha256: String,
    pub content: String,
    pub metadata_hmac: String,
}
impl CoordinationZoneCatalog {
    pub fn from_json(raw: &str) -> Result<Self, CatalogError> {
        if raw.len() > MAX_CATALOG_WIRE {
            return Err(invalid());
        }
        let wire: Self = serde_json::from_str(raw).map_err(|_| invalid())?;
        wire.validate()?;
        Ok(wire)
    }
    pub fn validate(&self) -> Result<(), CatalogError> {
        validate_catalog_scope(&self.workspace_id, &self.repository)?;
        let base64 = |text: &str| {
            text.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        };
        if self.format != CATALOG_FORMAT
            || !(1..=MAX_CATALOG_REVISION).contains(&self.revision)
            || self.key_id.is_empty()
            || self.key_id.len() > 128
            || !base64(&self.key_id)
            || self.content_sha256.len() != 64
            || !self
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.metadata_hmac.len() != 43
            || !base64(&self.metadata_hmac)
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > MAX_CATALOG_WIRE
        {
            return Err(invalid());
        }
        let (key_id, bytes) = self
            .content
            .strip_prefix("lyenc1.")
            .and_then(|rest| rest.split_once('.'))
            .ok_or_else(invalid)?;
        if key_id != self.key_id || bytes.len() < 38 || !base64(bytes) {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinationZoneCatalogWrite {
    pub expected_revision: u64,
    pub catalog: CoordinationZoneCatalog,
}
impl CoordinationZoneCatalogWrite {
    pub fn validate(&self) -> Result<(), CatalogError> {
        self.catalog.validate()?;
        if self.expected_revision >= MAX_CATALOG_REVISION
            || self.catalog.revision != self.expected_revision + 1
        {
            return Err(invalid());
        }
        Ok(())
    }
}
