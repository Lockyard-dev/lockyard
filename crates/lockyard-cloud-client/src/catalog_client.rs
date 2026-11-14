// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Typed catalog preparation and verified local projection at the HTTP boundary.
use crate::{
    Call, Client, ClientError,
    catalog::{CatalogStore, seal_catalog},
};
use lockyard_core::catalog::{
    CoordinationZoneCatalog, CoordinationZoneCatalogWrite, ZoneCatalogV1, validate_catalog_scope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;

const ROUTE: &str = "/api/v1/zones/catalog";
fn catalog_call(call: &Call) -> bool {
    call.path.split('?').next() == Some(ROUTE)
}
fn local(error: impl std::fmt::Display) -> ClientError {
    let code = error.to_string();
    crate::protocol::local(&code, &code)
}
fn default_case() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextWrite {
    expected_revision: u64,
    catalog: ZoneCatalogV1,
    #[serde(default = "default_case")]
    case_insensitive_paths: bool,
}

/// Optional plaintext compatibility uses the same stable errors for every transport.
pub(crate) fn expand_legacy_catalog(
    catalog: &Value,
    names: &[String],
) -> Result<Vec<String>, ClientError> {
    lockyard_core::proto::expand_zones(catalog, names).map_err(|error| {
        let (code, message) = match error {
            lockyard_core::Error::NotFound(_) => {
                ("zone_unknown", "named zone is absent from the catalog")
            }
            _ => ("catalog_invalid", "catalog cannot be expanded"),
        };
        crate::protocol::local(code, message)
    })
}

impl Client {
    /// Named claims always perform an online GET first (with the explicit offline-read policy),
    /// then expand through the verified SDK capability rather than a serialized marker.
    pub(crate) fn expand_catalog_call(
        &self,
        call: &Call,
        names: &[String],
    ) -> Result<Vec<String>, ClientError> {
        if call.method != "GET" || !catalog_call(call) {
            return Err(local("catalog_invalid"));
        }
        let value = crate::Transport::call(self, call)?;
        if self.encryption_enabled
            || self.expected_e2ee_workspace.is_some()
            || value.get("format").is_some()
        {
            let workspace = self
                .workspace
                .as_deref()
                .ok_or_else(|| local("catalog_key_unavailable"))?;
            let held = self.resolved_content_key()?;
            let key = held
                .as_ref()
                .ok_or_else(|| local("catalog_key_unavailable"))?;
            let repository = call.repository.as_deref().unwrap_or_default();
            return self
                .catalog_store(workspace, repository)?
                .offline(key, workspace, repository)
                .map_err(local)?
                .expand(names)
                .map_err(local);
        }
        expand_legacy_catalog(&value, names)
    }
    /// Select a private cache root, primarily for embedding and isolated client instances.
    pub fn with_catalog_cache_dir(mut self, directory: PathBuf) -> Self {
        self.catalog_cache_root = Some(directory);
        self
    }
    fn catalog_store(
        &self,
        workspace: &str,
        repository: &str,
    ) -> Result<CatalogStore, ClientError> {
        validate_catalog_scope(workspace, repository).map_err(local)?;
        match &self.catalog_cache_root {
            None => CatalogStore::for_scope(workspace, repository).map_err(local),
            Some(root) => {
                let path = if repository.is_empty() {
                    root.join(workspace).join("legacy/catalog.json")
                } else {
                    root.join(workspace)
                        .join("repositories")
                        .join(format!("{repository}.json"))
                };
                Ok(CatalogStore::new(path))
            }
        }
    }
    /// Runs only after capability negotiation and before serialization. All retry attempts share it.
    pub(crate) fn prepare_catalog_call(&self, call: &Call) -> Result<Call, ClientError> {
        if !catalog_call(call) {
            return Ok(call.clone());
        }
        let mut prepared = call.clone();
        // An absent repository is the explicitly selected legacy namespace, never aggregate.
        prepared.repository = Some(call.repository.clone().unwrap_or_default());
        if call.method != "POST" {
            return Ok(prepared);
        }
        let workspace = self
            .workspace
            .as_deref()
            .ok_or_else(|| local("catalog_key_unavailable"))?;
        let held = self.resolved_content_key()?;
        let key = held
            .as_ref()
            .ok_or_else(|| local("catalog_key_unavailable"))?;
        let repository = prepared.repository.as_deref().expect("set repository");
        let body = call.body.as_ref().ok_or_else(|| local("catalog_invalid"))?;
        if body.pointer("/catalog/format").is_some() {
            let wire: CoordinationZoneCatalogWrite =
                serde_json::from_value(body.clone()).map_err(|_| local("catalog_invalid"))?;
            wire.validate().map_err(local)?;
            crate::catalog::verify_catalog(key, workspace, repository, &wire.catalog, None)
                .map_err(local)?;
        } else {
            let raw: PlaintextWrite =
                serde_json::from_value(body.clone()).map_err(|_| local("catalog_invalid"))?;
            let wire = seal_catalog(
                key,
                workspace,
                repository,
                raw.expected_revision,
                raw.case_insensitive_paths,
                &raw.catalog,
            )
            .map_err(local)?;
            prepared.body = Some(serde_json::to_value(wire).map_err(|_| local("catalog_invalid"))?);
        }
        Ok(prepared)
    }
    /// Publish only authenticated plaintext to SDK/CLI/MCP callers after durable highwater update.
    pub(crate) fn finish_catalog_call(
        &self,
        call: &Call,
        value: &mut Value,
    ) -> Result<(), ClientError> {
        if !catalog_call(call) {
            return Ok(());
        }
        if value.get("format").is_none()
            && !self.encryption_enabled
            && self.expected_e2ee_workspace.is_none()
            && call.method == "GET"
        {
            return Ok(());
        }
        let workspace = self
            .workspace
            .as_deref()
            .ok_or_else(|| local("catalog_key_unavailable"))?;
        let held = self.resolved_content_key()?;
        let key = held
            .as_ref()
            .ok_or_else(|| local("catalog_key_unavailable"))?;
        let repository = call.repository.as_deref().unwrap_or_default();
        let wire = CoordinationZoneCatalog::from_json(&value.to_string()).map_err(local)?;
        let verified = self
            .catalog_store(workspace, repository)?
            .accept(key, workspace, repository, &wire)
            .map_err(local)?;
        *value = if call.method == "POST" {
            json!({"stored":true,"repository":repository,"revision":verified.wire().revision,"verified":true})
        } else {
            verified.read_json()
        };
        Ok(())
    }
    /// The caller invokes this only for a genuine transport failure of a read/discovery.
    pub(crate) fn catalog_offline_call(&self, call: &Call) -> Result<Option<Value>, ClientError> {
        if !catalog_call(call) || call.method != "GET" {
            return Ok(None);
        }
        let held = self.resolved_content_key()?;
        if held.is_none() && self.expected_e2ee_workspace.is_none() && !self.encryption_enabled {
            return Ok(None);
        }
        let workspace = self
            .workspace
            .as_deref()
            .ok_or_else(|| local("catalog_key_unavailable"))?;
        let key = held
            .as_ref()
            .ok_or_else(|| local("catalog_key_unavailable"))?;
        let repository = call.repository.as_deref().unwrap_or_default();
        self.catalog_store(workspace, repository)?
            .offline(key, workspace, repository)
            .map(|catalog| Some(catalog.read_json()))
            .map_err(local)
    }
}
