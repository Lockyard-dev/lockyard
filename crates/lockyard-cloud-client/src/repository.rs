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
        // Typed plaintext is local input; typed wire metadata is authenticated; both stay relative.
        if catalog.get("format").is_some()
            || catalog.get("version") == Some(&Value::from(1))
            || catalog.get("verified") == Some(&Value::Bool(true))
        {
            return Ok(());
        }
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

    /// Apply the same pure scope transformation to sends and their durable acknowledgements.
    fn qualified_call(&self, call: &Call) -> Result<Call, ClientError> {
        let mut qualified = call.clone();
        if call.path.starts_with("/api/v1/zones/") || call.path.starts_with("/api/v1/import/zones")
        {
            qualified.repository = Some(self.repository.clone().unwrap_or_default());
            if let Some(body) = qualified.body.as_mut() {
                if call.path.starts_with("/api/v1/zones/catalog")
                    || call.path.starts_with("/api/v1/import/zones")
                {
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
        Ok(qualified)
    }
}

impl<T: Transport> Transport for RepositoryTransport<T> {
    fn status_registry_assignee_supported(
        &self,
        deadline: std::time::Instant,
        cancellation: Option<&crate::Cancellation>,
    ) -> bool {
        self.inner
            .status_registry_assignee_supported(deadline, cancellation)
    }

    fn status_registry_call(&self, call: &Call) -> Result<crate::StatusRegistryPage, ClientError> {
        // Registry items are workspace-scoped, with no zone path transformation.
        self.inner.status_registry_call(call)
    }

    fn status_reads_parallel(&self) -> bool {
        self.inner.status_reads_parallel()
    }

    fn status_followups_parallel(&self) -> bool {
        self.inner.status_followups_parallel()
    }

    fn status_cancelled(&self) -> bool {
        self.inner.status_cancelled()
    }

    fn server_time_upper_bound(&self) -> Option<i64> {
        self.inner.server_time_upper_bound()
    }

    fn call(&self, call: &Call) -> Result<Value, ClientError> {
        let started = std::time::Instant::now();
        let zones = call.path.starts_with("/api/v1/zones/")
            || call.path.starts_with("/api/v1/import/zones");
        let catalog = call.path.starts_with("/api/v1/zones/catalog")
            || call.path.starts_with("/api/v1/import/zones");
        let events = call.path.starts_with("/api/v1/events");
        if zones
            && (call.is_write() || !self.inner.verifies_repository_reads())
            && self.repository.is_some()
            && !self.verified.load(Ordering::Acquire)
        {
            // Negotiate through a read before a write can acquire a zone on an older server.
            let mut probe = Call::get(
                &call.session,
                format!(
                    "/api/v1/zones/claims?path={}&namespace_probe=1",
                    encode(&self.path(".")?)
                ),
            );
            probe.repository = self.repository.clone();
            probe.deadline_ms = call.deadline_ms;
            self.inner.call(&probe)?;
            self.verified.store(true, Ordering::Release);
        }
        let mut qualified = self.qualified_call(call)?;
        if let Some(limit) = call.deadline_ms {
            let remaining =
                std::time::Duration::from_millis(limit).saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(ClientError::Transport(
                    "call deadline elapsed during repository verification".into(),
                ));
            }
            qualified.deadline_ms = Some(remaining.as_millis().min(u128::from(u64::MAX)) as u64);
        }
        let answer = self.inner.call(&qualified);
        let mut answer = match answer {
            Err(ClientError::Conflict(mut error)) => {
                self.transform(&mut error.details, false)?;
                return Err(ClientError::Conflict(error));
            }
            other => other?,
        };
        // A successful scoped read through Client verifies the echo at the HTTP boundary.
        // Legacy socket transports must first succeed at the explicit capability probe above.
        if zones && self.repository.is_some() {
            self.verified.store(true, Ordering::Release);
        }
        if catalog {
            self.catalog(&mut answer, false)?;
        } else if zones || events {
            self.transform(&mut answer, false)?;
        }
        Ok(answer)
    }

    fn acknowledge_write(&self, call: &Call) -> Result<(), ClientError> {
        self.inner.acknowledge_write(&self.qualified_call(call)?)
    }

    fn catalog_expand(&self, call: &Call, names: &[String]) -> Result<Vec<String>, ClientError> {
        let mut scoped = call.clone();
        scoped.repository = Some(self.repository.clone().unwrap_or_default());
        self.inner.catalog_expand(&scoped, names)
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
    use std::sync::Mutex;

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
    fn status_repository_read_verifies_namespace_without_an_extra_probe() {
        let server = FakeServer::start(vec![
            Reply::json(
                200,
                json!([{"id":1,"session":"alice","paths":[".lockyard-repository/api/src"]}]),
            )
            .header("X-Lockyard-Repository", "api"),
        ]);
        let client = Client::new(&server.url(), "fixture-token".into()).unwrap();
        let transport = RepositoryTransport::new(client, Some("api")).unwrap();
        let value = transport
            .call(&Call::get(
                "alice",
                "/api/v1/zones/claims?session=alice".into(),
            ))
            .unwrap();
        assert_eq!(value[0]["paths"][0], "src");
        assert!(transport.verified.load(Ordering::Acquire));
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path, "/api/v1/zones/claims?session=alice");
        assert_eq!(requests[0].header("x-lockyard-repository"), Some("api"));
    }

    #[test]
    fn status_repository_read_via_legacy_socket_still_requires_namespace_probe() {
        struct Unsupported(Mutex<Vec<Call>>);
        impl Transport for Unsupported {
            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                self.0.lock().unwrap().push(call.clone());
                if call.path.contains("namespace_probe=1") {
                    Err(ClientError::Invalid(
                        "upgrade agent: repository namespace unsupported".into(),
                    ))
                } else {
                    Ok(json!([]))
                }
            }
        }
        let transport =
            RepositoryTransport::new(Unsupported(Mutex::new(Vec::new())), Some("api")).unwrap();
        let error = transport
            .call(&Call::get(
                "alice",
                "/api/v1/zones/claims?session=alice".into(),
            ))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repository namespace unsupported")
        );
        assert!(!transport.verified.load(Ordering::Acquire));
        let calls = transport.inner.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].path.contains("namespace_probe=1"));
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
    fn acknowledging_a_repository_write_uses_the_same_qualified_operation_without_a_probe() {
        #[derive(Default)]
        struct Recorder(std::sync::Mutex<Vec<Call>>);
        impl Transport for Recorder {
            fn call(&self, call: &Call) -> Result<Value, ClientError> {
                self.0.lock().unwrap().push(call.clone());
                Ok(Value::Null)
            }
            fn acknowledge_write(&self, call: &Call) -> Result<(), ClientError> {
                assert_eq!(
                    call,
                    self.0.lock().unwrap().last().unwrap(),
                    "acknowledgement must identify exactly the operation sent to the inner transport"
                );
                Ok(())
            }
        }
        for repository in [Some("api"), None] {
            let recorder = std::sync::Arc::new(Recorder::default());
            let transport = RepositoryTransport::new(recorder.clone(), repository).unwrap();
            let call = Call::write(
                "alice",
                "POST",
                "/api/v1/zones/claims?path=src%2Ffile".into(),
                json!({"paths":["src/file"],"note":"private"}),
            );
            transport.call(&call).unwrap();
            let calls_before = recorder.0.lock().unwrap().len();
            transport.acknowledge_write(&call).unwrap();
            assert_eq!(
                recorder.0.lock().unwrap().len(),
                calls_before,
                "acknowledgement must not issue a network probe"
            );
        }
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
