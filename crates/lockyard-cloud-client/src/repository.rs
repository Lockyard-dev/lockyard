// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! A repository-aware view over the workspace transport. The daemon itself remains aggregate.

use crate::{Call, ClientError, Transport, encode};
use lockyard_core::proto::PathCheck;
use lockyard_core::repository::{qualify, relative, validate_id};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct RepositoryTransport<T> {
    inner: T,
    repository: Option<String>,
    verified: AtomicBool,
}

impl<T> RepositoryTransport<T> {
    pub fn new(inner: T, repository: Option<&str>) -> Result<Self, ClientError> {
        if let Some(id) = repository {
            validate_id(id).map_err(|e| ClientError::Invalid(e.to_string()))?;
        }
        Ok(Self {
            inner,
            repository: repository.map(str::to_string),
            verified: AtomicBool::new(false),
        })
    }

    fn path(&self, path: &str) -> Result<String, ClientError> {
        qualify(self.repository.as_deref(), path).map_err(|e| ClientError::Invalid(e.to_string()))
    }

    fn transform(&self, value: &mut Value, outgoing: bool) -> Result<(), ClientError> {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    if matches!(key.as_str(), "path" | "held_path") {
                        if let Some(text) = child.as_str().filter(|text| !text.is_empty()) {
                            *child = Value::String(if outgoing {
                                self.path(text)?
                            } else {
                                relative(self.repository.as_deref(), text)
                                    .unwrap_or(text)
                                    .to_string()
                            });
                        }
                    } else if matches!(
                        key.as_str(),
                        "paths" | "excluded_paths" | "write_paths" | "adopted" | "disowned"
                    ) {
                        if let Some(paths) = child.as_array_mut() {
                            for path in paths {
                                if let Some(text) = path.as_str() {
                                    *path = Value::String(if outgoing {
                                        self.path(text)?
                                    } else {
                                        relative(self.repository.as_deref(), text)
                                            .unwrap_or(text)
                                            .to_string()
                                    });
                                } else {
                                    self.transform(path, outgoing)?;
                                }
                            }
                        }
                    } else if key == "meta" { /* Application metadata is opaque. */
                    } else {
                        self.transform(child, outgoing)?;
                    }
                }
            }
            Value::Array(array) => {
                for child in array {
                    self.transform(child, outgoing)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn catalog(&self, value: &mut Value, outgoing: bool) -> Result<(), ClientError> {
        let catalog = if value.get("catalog").is_some() {
            value.get_mut("catalog").expect("checked catalog")
        } else {
            value
        };
        if let Some(zones) = catalog.get_mut("zones").and_then(Value::as_object_mut) {
            for zone in zones.values_mut() {
                let paths = if zone.is_array() {
                    Some(zone)
                } else {
                    zone.get_mut("paths")
                };
                if let Some(paths) = paths.and_then(Value::as_array_mut) {
                    for path in paths {
                        if let Some(text) = path.as_str() {
                            *path = Value::String(if outgoing {
                                self.path(text)?
                            } else {
                                relative(self.repository.as_deref(), text)
                                    .unwrap_or(text)
                                    .to_string()
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<T: Transport> Transport for RepositoryTransport<T> {
    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        let zones = call.path.starts_with("/api/v1/zones/")
            || call.path.starts_with("/api/v1/import/zones");
        let catalog = call.path.starts_with("/api/v1/zones/catalog")
            || call.path.starts_with("/api/v1/import/zones");
        let events = call.path.starts_with("/api/v1/events");
        let mut qualified = call.clone();
        if zones {
            qualified.repository = Some(self.repository.clone().unwrap_or_default());
            if self.repository.is_some() && !self.verified.load(Ordering::Acquire) {
                // Negotiate through a read before a write can acquire a zone on an older server.
                let mut probe = Call::get(
                    &call.session,
                    format!(
                        "/api/v1/zones/claims?path={}&namespace_probe=1",
                        encode(&self.path(".")?)
                    ),
                );
                probe.repository = self.repository.clone();
                self.inner.call(&probe)?;
                self.verified.store(true, Ordering::Release);
            }
            if let Some(body) = qualified.body.as_mut() {
                if catalog {
                    self.catalog(body, true)?;
                } else {
                    self.transform(body, true)?;
                }
            }
            if let Some((route, query)) = qualified.path.split_once('?') {
                let pairs = query
                    .split('&')
                    .map(|pair| {
                        if let Some(encoded) = pair.strip_prefix("path=") {
                            let decoded = decode(encoded)?;
                            Ok(format!("path={}", encode(&self.path(&decoded)?)))
                        } else {
                            Ok(pair.to_string())
                        }
                    })
                    .collect::<Result<Vec<_>, ClientError>>()?;
                qualified.path = format!("{route}?{}", pairs.join("&"));
            }
        }
        let answer = self.inner.call(&qualified);
        let mut answer = match answer {
            Err(ClientError::Conflict(mut error)) => {
                self.transform(&mut error.details, false)?;
                return Err(ClientError::Conflict(error));
            }
            other => other?,
        };
        if catalog {
            self.catalog(&mut answer, false)?;
        } else if zones || events {
            self.transform(&mut answer, false)?;
        }
        Ok(answer)
    }

    fn fast_check(
        &self,
        session: &str,
        paths: &[String],
    ) -> Option<Result<Vec<PathCheck>, ClientError>> {
        // A legacy server cannot interpret these addresses. Do not trust a local cache until
        // the server has explicitly advertised support for repository namespaces.
        if self.repository.is_some() && !self.verified.load(Ordering::Acquire) {
            return None;
        }
        let qualified = match paths
            .iter()
            .map(|path| self.path(path))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(paths) => paths,
            Err(error) => return Some(Err(error)),
        };
        self.inner.fast_check(session, &qualified).map(|answer| {
            answer.map(|mut checks| {
                for check in &mut checks {
                    check.path = relative(self.repository.as_deref(), &check.path)
                        .unwrap_or(&check.path)
                        .to_string();
                    if let Some(holder) = check.holder.as_mut() {
                        holder.path = relative(self.repository.as_deref(), &holder.path)
                            .unwrap_or(&holder.path)
                            .to_string();
                        holder.held_path = relative(self.repository.as_deref(), &holder.held_path)
                            .unwrap_or(&holder.held_path)
                            .to_string();
                    }
                }
                checks
            })
        })
    }

    fn fast_unread(&self, session: &str) -> Option<Result<Option<i64>, ClientError>> {
        self.inner.fast_unread(session)
    }
}

fn decode(encoded: &str) -> Result<String, ClientError> {
    let mut bytes = Vec::new();
    let mut source = encoded.as_bytes().iter().copied();
    while let Some(byte) = source.next() {
        bytes.push(if byte == b'%' {
            let high = source.next().and_then(|c| (c as char).to_digit(16));
            let low = source.next().and_then(|c| (c as char).to_digit(16));
            match (high, low) {
                (Some(high), Some(low)) => (high * 16 + low) as u8,
                _ => return Err(ClientError::Invalid("invalid encoded path".into())),
            }
        } else if byte == b'+' {
            b' '
        } else {
            byte
        });
    }
    String::from_utf8(bytes).map_err(|_| ClientError::Invalid("path is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeServer, Reply};
    use crate::{Client, CloudBackend, WorkspaceKey};
    use lockyard_core::Backend;
    use lockyard_core::proto::{ClaimRequest, DirtyPath};
    use serde_json::json;

    const REQUIRED_WORKSPACE: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn required_client(server: &FakeServer, key: WorkspaceKey) -> Client {
        Client::new(&server.url(), "fixture-token".into())
            .unwrap()
            .require_e2ee_for(REQUIRED_WORKSPACE)
            .unwrap()
            .with_content_encryption(REQUIRED_WORKSPACE, Some(key), true)
    }

    #[test]
    fn required_repository_claim_negotiates_before_encrypted_literal_path_write() {
        let key = WorkspaceKey::from_entropy([53; 32]);
        let encrypted = key
            .encrypt(REQUIRED_WORKSPACE, "note", "private claim note")
            .unwrap();
        let response = |body| Reply::json(200, body).header("X-Lockyard-Repository", "api");
        let server = FakeServer::start(vec![
            response(json!([])),
            response(
                json!({"id":1,"session":"alice","paths":[".lockyard-repository/api/src"],"note":encrypted,"repository":"api"}),
            ),
        ]);
        let transport =
            RepositoryTransport::new(required_client(&server, key.clone()), Some("api")).unwrap();
        let mut backend = CloudBackend::new(transport, "alice");
        let claim = backend
            .claim(
                "alice",
                &ClaimRequest {
                    paths: vec!["src".into()],
                    note: "private claim note".into(),
                    ttl_minutes: 10,
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        assert_eq!(claim.paths, ["src"]);
        assert_eq!(claim.note, "private claim note");
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(
            requests[0].path,
            "/api/v1/zones/claims?path=.lockyard-repository%2Fapi&namespace_probe=1"
        );
        assert_eq!(requests[0].header("x-lockyard-repository"), Some("api"));
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].body["paths"][0], ".lockyard-repository/api/src");
        let wire_note = requests[1].body["note"].as_str().unwrap();
        assert!(wire_note.starts_with("lyenc1."));
        assert_eq!(
            key.decrypt(REQUIRED_WORKSPACE, "note", wire_note).unwrap(),
            "private claim note"
        );
        assert!(!requests[1].body.to_string().contains("private claim note"));
    }

    #[test]
    fn required_repository_probe_rejects_missing_namespace_header_before_write() {
        let server = FakeServer::start(vec![Reply::json(200, json!([]))]);
        let transport = RepositoryTransport::new(
            required_client(&server, WorkspaceKey::from_entropy([54; 32])),
            Some("api"),
        )
        .unwrap();
        let mut backend = CloudBackend::new(transport, "alice");
        let error = backend
            .claim(
                "alice",
                &ClaimRequest {
                    paths: vec!["src".into()],
                    ..Default::default()
                },
                0,
            )
            .unwrap_err();
        assert!(error.to_string().contains("namespace support"));
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
    }

    #[test]
    fn required_repository_rejects_malformed_probe_queries_before_http() {
        let server = FakeServer::start(vec![]);
        let client = required_client(&server, WorkspaceKey::from_entropy([55; 32]));
        for path in [
            "/api/v1/zones/claims?path=src&namespace_probe=0",
            "/api/v1/zones/claims?path=src&namespace_probe=1&namespace_probe=1",
            "/api/v1/zones/claims?path=src&namespace_probe=1&unknown=private",
            "/api/v1/zones/claims?path=src&namespace_probe=1%0Aprivate",
            "/api/v1/bus/inbox?namespace_probe=1",
        ] {
            let mut call = Call::get("alice", path.into());
            call.repository = Some("api".into());
            assert!(client.call(&call).is_err(), "{path}");
        }
        let mut wrong_method = Call::write(
            "alice",
            "POST",
            "/api/v1/zones/claims?namespace_probe=1".into(),
            json!({"paths":["src"],"note":"private"}),
        );
        wrong_method.repository = Some("api".into());
        assert!(client.call(&wrong_method).is_err());
        assert!(server.requests().is_empty());
    }

    #[test]
    fn an_older_server_is_rejected_by_a_read_before_a_namespace_write_can_happen() {
        let server = FakeServer::start(vec![Reply::json(200, json!([]))]);
        let transport = RepositoryTransport::new(
            Client::new(&server.url(), "token".into()).unwrap(),
            Some("api"),
        )
        .unwrap();
        let mut backend = CloudBackend::new(transport, "alice");
        let error = backend
            .claim(
                "alice",
                &ClaimRequest {
                    paths: vec!["src".into()],
                    ..Default::default()
                },
                0,
            )
            .unwrap_err();
        assert!(error.to_string().contains("namespace support"));
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].header("x-lockyard-repository"), Some("api"));
    }

    #[test]
    fn http_negotiates_namespace_and_preserves_nested_dirty_paths_and_local_root_in_results() {
        let response = |body| Reply::json(200, body).header("X-Lockyard-Repository", "api");
        let server = FakeServer::start(vec![
            response(json!([])),
            response(
                json!({"id":1,"session":"alice","paths":[".lockyard-repository/api"],"repository":"api"}),
            ),
            response(json!({"stored":1})),
            response(json!({"zones":{"code":[".lockyard-repository/api/src"]}})),
        ]);
        let transport = RepositoryTransport::new(
            Client::new(&server.url(), "token".into()).unwrap(),
            Some("api"),
        )
        .unwrap();
        let mut backend = CloudBackend::new(transport, "alice");
        let claim = backend
            .claim(
                "alice",
                &ClaimRequest {
                    paths: vec![".".into()],
                    ..Default::default()
                },
                0,
            )
            .unwrap();
        assert_eq!(claim.paths, ["."]);
        let dirty: DirtyPath = serde_json::from_value(
            json!({"path":"src/file","owner_session":"alice","reason":"work"}),
        )
        .unwrap();
        backend.dirty_report("alice", &[dirty]).unwrap();
        assert_eq!(backend.catalog().unwrap()["zones"]["code"][0], "src");
        let requests = server.requests();
        assert_eq!(requests[1].body["paths"][0], ".lockyard-repository/api");
        assert_eq!(
            requests[2].body["paths"][0]["path"],
            ".lockyard-repository/api/src/file"
        );
        assert_eq!(
            requests.len(),
            4,
            "the capability read is reused for this transport"
        );
    }

    #[test]
    fn transforming_events_never_dequalifies_another_repository_and_leaves_application_metadata_opaque()
     {
        struct Events;
        impl Transport for Events {
            fn call(&self, _: &Call) -> Result<Value, ClientError> {
                Ok(
                    json!([{"seq":1,"payload":{"paths":[".lockyard-repository/web/src"],"repository":"web","meta":{"path":"user metadata"}}},
                    {"seq":2,"payload":{"paths":[".lockyard-repository/api/src"],"repository":"api"}}]),
                )
            }
        }
        let transport = RepositoryTransport::new(Events, Some("api")).unwrap();
        let events = transport
            .call(&Call::get("alice", "/api/v1/events".into()))
            .unwrap();
        assert_eq!(
            events[0]["payload"]["paths"][0],
            ".lockyard-repository/web/src"
        );
        assert_eq!(events[0]["payload"]["meta"]["path"], "user metadata");
        assert_eq!(events[1]["payload"]["paths"][0], "src");
        assert_eq!(events[1]["seq"], 2);
    }

    #[test]
    fn fast_checks_use_the_same_qualified_addresses_as_http_and_return_checkout_relative_holders() {
        struct Cache;
        impl Transport for Cache {
            fn call(&self, _: &Call) -> Result<Value, ClientError> {
                panic!("cache must not make an HTTP call")
            }
            fn fast_check(
                &self,
                session: &str,
                paths: &[String],
            ) -> Option<Result<Vec<PathCheck>, ClientError>> {
                assert_eq!(session, "alice");
                assert_eq!(paths, &[".lockyard-repository/api/src/file"]);
                Some(Ok(vec![serde_json::from_value(json!({"path":paths[0],"status":"held", "holder":{
                    "claim":1,"agent":"bob","path":paths[0],"held_path":".lockyard-repository/api/src","note":"work","expires_at":0
                }})).unwrap()]))
            }
        }
        let transport = RepositoryTransport::new(Cache, Some("api")).unwrap();
        assert!(
            transport
                .fast_check("alice", &["src/file".into()])
                .is_none()
        );
        transport.verified.store(true, Ordering::Release);
        let checks = transport
            .fast_check("alice", &["src/file".into()])
            .unwrap()
            .unwrap();
        assert_eq!(checks[0].path, "src/file");
        assert_eq!(checks[0].holder.as_ref().unwrap().held_path, "src");
    }
}
