// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Direct revocation control and an HTTP refresh loop independent of relay transport liveness.
use super::*;
use crate::revocations::{RevocationManager, SignedDocument};
impl Host {
    pub(super) fn requires_protected_direct(&self) -> bool {
        self.revocations
            .as_ref()
            .is_some_and(|state| state.config().required)
    }
    pub(super) fn known_revoked_direct_target(&self, target_pin: Option<&str>) -> bool {
        self.revocations.as_ref().is_some_and(|state| {
            std::iter::once(self.certificate_sha256.as_str())
                .chain(target_pin)
                .any(|pin| {
                    state
                        .authorize_pin(pin)
                        .is_err_and(|error| error.to_string() == "revoked")
                })
        })
    }
    pub(super) fn announce_direct_capabilities(
        &self,
        operation: Operation,
        mut payload: Value,
    ) -> Value {
        if operation == Operation::NodePing {
            if !payload.is_object() {
                payload = json!({});
            }
            let object = payload.as_object_mut().expect("ping payload is an object");
            object.insert("capabilities".into(), json!(self.revocation_capabilities()));
            object.insert(
                "revocations_enforced".into(),
                json!(self.requires_protected_direct()),
            );
        }
        payload
    }
    fn protected_peer_claim(&self, value: &Value) -> bool {
        value
            .get("capabilities")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|v| v.as_str() == Some("revocations_v1")))
            && (!self.requires_protected_direct()
                || value.get("revocations_enforced").and_then(Value::as_bool) == Some(true))
    }
    pub(super) async fn direct_rpc(
        &self,
        connection: &quic::DirectConnection,
        request: &RpcFrame,
    ) -> Result<RpcReply<Value>> {
        if request.operation != Operation::NodePing
            && (self.requires_protected_direct()
                || request.operation == Operation::RevocationsApply)
            && !connection.revocations_negotiated()
        {
            let peer = connection.peer();
            let mut ping = RpcFrame {
                v: wire::PROTOCOL_VERSION,
                kind: FrameKind::Request,
                id: wire::new_id()?,
                source: self.config.node_id.clone(),
                target: peer.node_id.clone(),
                operation: Operation::NodePing,
                in_reply_to: None,
                source_certificate_sha256: Some(self.certificate_sha256.clone()),
                target_certificate_sha256: Some(peer.certificate_sha256.to_ascii_lowercase()),
                retention: None,
                payload: String::new(),
            };
            self.codec.encode(
                &mut ping,
                &self.announce_direct_capabilities(Operation::NodePing, json!({})),
            )?;
            let response = connection.rpc(&ping).await?;
            let reply = self.decode_response(&ping, &response)?;
            if !reply.ok
                || !reply
                    .result
                    .as_ref()
                    .is_some_and(|value| self.protected_peer_claim(value))
            {
                if let Some(state) = &self.revocations {
                    state.record_legacy_peer(&peer.node_id)?;
                }
                return Ok(RpcReply::failure(
                    "feature_unsupported",
                    "Peer does not enforce revocations_v1.",
                ));
            }
            connection.mark_revocations_negotiated();
        }
        let response = connection.rpc(request).await?;
        let reply = self.decode_response(request, &response)?;
        if request.operation == Operation::NodePing
            && reply.ok
            && reply
                .result
                .as_ref()
                .is_some_and(|value| self.protected_peer_claim(value))
        {
            connection.mark_revocations_negotiated();
        }
        Ok(reply)
    }
    pub(super) fn direct_frame_gate(
        &self,
        connection: &quic::DirectConnection,
        request: &RpcFrame,
    ) -> Result<Option<RpcFrame>> {
        // TLS source/operation checks run in RpcStream::recv before this AEAD-bound announcement.
        let peer = connection.peer();
        if request.kind != FrameKind::Request
            || request.source != peer.node_id
            || request.target != self.config.node_id
        {
            return Err("invalid direct request".into());
        }
        if request
            .source_certificate_sha256
            .as_deref()
            .is_some_and(|pin| !pin.eq_ignore_ascii_case(&peer.certificate_sha256))
            || request
                .target_certificate_sha256
                .as_deref()
                .is_some_and(|pin| !pin.eq_ignore_ascii_case(&self.certificate_sha256))
        {
            return Err("node incarnation mismatch".into());
        }
        let payload: Value = self.codec.decode(request)?;
        if request.operation == Operation::NodePing {
            if self.protected_peer_claim(&payload) {
                connection.mark_revocations_negotiated();
            }
            return Ok(None);
        }
        if !self.requires_protected_direct() || connection.revocations_negotiated() {
            return Ok(None);
        }
        if let Some(state) = &self.revocations {
            state.record_legacy_peer(&peer.node_id)?;
        }
        let mut response = RpcFrame {
            v: request.v,
            kind: FrameKind::Response,
            id: wire::new_id()?,
            source: self.config.node_id.clone(),
            target: request.source.clone(),
            operation: request.operation,
            in_reply_to: Some(request.id.clone()),
            source_certificate_sha256: request.target_certificate_sha256.clone(),
            target_certificate_sha256: request.source_certificate_sha256.clone(),
            retention: None,
            payload: String::new(),
        };
        self.codec.encode(
            &mut response,
            &RpcReply::<Value>::failure(
                "feature_unsupported",
                "Peer must negotiate enforced revocations_v1 before direct RPC.",
            ),
        )?;
        Ok(Some(response))
    }
    pub(super) fn revocation_capabilities(&self) -> Vec<&'static str> {
        if self.revocations.is_some() {
            vec!["revocations_v1"]
        } else {
            vec![]
        }
    }
    pub(super) fn apply_revocation_payload(&self, payload: Value) -> RpcReply<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Apply {
            document: SignedDocument,
        }
        let Some(state) = &self.revocations else {
            return RpcReply::failure(
                "revocation_protocol_unavailable",
                "Revocation enforcement is not configured.",
            );
        };
        let request: Apply = match serde_json::from_value(payload) {
            Ok(value) => value,
            Err(_) => {
                return RpcReply::failure("invalid_revocation_request", "Invalid revocation page.");
            }
        };
        match state.apply_additive(&request.document) {
            Ok(()) => match state.snapshot() {
                Ok(status) => RpcReply::success(
                    json!({"observed_epoch":status.observed_epoch,"complete_epoch":status.complete_epoch,"applied":true}),
                ),
                Err(_) => RpcReply::failure(
                    "revocation_state_unavailable",
                    "Revocation state unavailable.",
                ),
            },
            Err(error) => RpcReply::failure(
                revocation_code(&error.to_string()),
                "Revocation page rejected.",
            ),
        }
    }
    pub(super) async fn propagate_revocations(
        &self,
        documents: Vec<SignedDocument>,
    ) -> Result<Value> {
        if documents.is_empty() || documents.len() > 4096 {
            return Err("invalid_revocation_request".into());
        }
        let state = self
            .revocations
            .as_ref()
            .ok_or("revocation_signer_untrusted")?;
        // Validate every page before producing a local or remote application receipt.
        for document in &documents {
            lockyard_cloud_client::revocations::verify_document(
                document,
                state.trust(),
                &state.trust().server_origin,
            )?;
        }
        for document in &documents {
            state.apply_additive(document)?;
        }
        state.wake();
        let mut acked = Vec::new();
        let mut pending = Vec::new();
        for peer in &self.config.peers {
            let applied = async {
                let pong = self
                    .direct_control(peer, Operation::NodePing, json!({}))
                    .await?;
                if !pong.ok
                    || !pong
                        .result
                        .as_ref()
                        .and_then(|r| r.get("capabilities"))
                        .and_then(Value::as_array)
                        .is_some_and(|values| {
                            values.iter().any(|v| v.as_str() == Some("revocations_v1"))
                        })
                {
                    state.record_legacy_peer(&peer.node_id)?;
                    return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                        "revocation_protocol_unavailable".into(),
                    );
                }
                for document in &documents {
                    let reply = self
                        .direct_control(
                            peer,
                            Operation::RevocationsApply,
                            json!({"document":document}),
                        )
                        .await?;
                    if !reply.ok
                        || reply
                            .result
                            .as_ref()
                            .and_then(|r| r.get("applied"))
                            .and_then(Value::as_bool)
                            != Some(true)
                    {
                        return Err("revocation_state_unavailable".into());
                    }
                }
                Ok(())
            }
            .await;
            if applied.is_ok() {
                acked.push(peer.node_id.clone());
            } else {
                pending.push(peer.node_id.clone());
            }
        }
        Ok(json!({"local_applied":true,"direct":{"acked":acked,"pending":pending}}))
    }
    async fn direct_control(
        &self,
        peer: &PeerConfig,
        operation: Operation,
        payload: Value,
    ) -> Result<RpcReply<Value>> {
        let direct = self.direct.as_ref().ok_or("direct transport unavailable")?;
        let address = peer.address.ok_or("direct peer unavailable")?;
        if self.known_revoked_direct_target(Some(&peer.certificate_sha256)) {
            return Ok(RpcReply::failure(
                "revoked",
                "Access to this identity has been revoked.",
            ));
        }
        let payload = self.announce_direct_capabilities(operation, payload);
        let mut frame = RpcFrame {
            v: wire::PROTOCOL_VERSION,
            kind: FrameKind::Request,
            id: wire::new_id()?,
            source: self.config.node_id.clone(),
            target: peer.node_id.clone(),
            operation,
            in_reply_to: None,
            source_certificate_sha256: Some(self.certificate_sha256.clone()),
            target_certificate_sha256: Some(peer.certificate_sha256.clone()),
            retention: None,
            payload: String::new(),
        };
        self.codec.encode(&mut frame, &payload)?;
        tokio::time::timeout(
            Duration::from_secs(self.config.rpc_timeout_seconds.min(5)),
            async {
                let connection = direct
                    .connect(address, &peer.tls_name, peer.policy())
                    .await?;
                self.direct_rpc(&connection, &frame).await
            },
        )
        .await?
    }
}
fn revocation_code(code: &str) -> &'static str {
    match code {
        "revocation_signer_untrusted" => "revocation_signer_untrusted",
        "revocation_clock_skew" => "revocation_clock_skew",
        "revocations_stale" => "revocations_stale",
        _ => "invalid_revocation_request",
    }
}
pub(super) async fn refresh_once(
    config: &NodeConfig,
    state: &Arc<RevocationManager>,
) -> Result<()> {
    if !state.retry_delay(false)?.is_zero() {
        return Err("rate_limited".into());
    }
    let client = crate::cloud::NodeCloudClient::for_revocations(config)?.revocation_client()?;
    let since = state.refresh_from_epoch()?;
    let trust = state.trust().clone();
    let node = config.node_id.clone();
    let started = Instant::now();
    let applying = state.clone();
    let documents = tokio::task::spawn_blocking(move || {
        client.revocation_refresh_documents_with_apply(&node, since, &trust, |document| {
            applying.apply_additive(document).map_err(|_| {
                lockyard_cloud_client::revocations::RevocationError {
                    code: "revocation_state_unavailable".into(),
                    commit_unknown: false,
                    retry_after: None,
                }
            })
        })
    })
    .await?;
    let documents = match documents {
        Ok(documents) => documents,
        Err(error) => {
            state.record_http_failure(false, &error)?;
            if error.code() == "revocation_clock_skew" {
                state.reject_clock_skew()?;
            }
            return Err(error.into());
        }
    };
    let first = documents.first().ok_or("invalid_revocation_request")?;
    let page = lockyard_cloud_client::revocations::verify_document(
        first,
        state.trust(),
        &state.trust().server_origin,
    )?;
    state.refresh(&documents, &page.nonce, wall_ms()?, started)
}
pub(super) async fn monitor(host: std::sync::Weak<Host>) {
    let Some(initial) = host.upgrade() else {
        return;
    };
    let Some(state) = initial.revocations.clone() else {
        return;
    };
    let config = initial.config.clone();
    drop(initial);
    let mut timer = tokio::time::interval(Duration::from_secs(state.config().poll_seconds));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    timer.tick().await;
    struct Child(tokio::task::JoinHandle<()>);
    impl Drop for Child {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let event_state = state.clone();
    let event_config = config.clone();
    let event_host = host.clone();
    let _events = Child(tokio::spawn(async move {
        while event_host.strong_count() > 0 {
            let wait = event_state
                .retry_delay(true)
                .unwrap_or(Duration::from_secs(60));
            if !wait.is_zero() {
                tokio::time::sleep(wait.min(Duration::from_secs(60))).await;
                continue;
            }
            if let Ok(client) = crate::cloud::NodeCloudClient::for_revocations(&event_config)
                .and_then(|c| c.revocation_client())
            {
                let _ = event_state.record_notify_reconnect();
                let node = event_config.node_id.clone();
                let epoch = event_state
                    .snapshot()
                    .map(|s| s.observed_epoch)
                    .unwrap_or(0);
                match tokio::task::spawn_blocking(move || {
                    client.revocation_events_hint(&node, epoch)
                })
                .await
                {
                    Ok(Ok(true)) => event_state.wake(),
                    Ok(Err(error)) => {
                        let _ = event_state.record_http_failure(true, &error);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    _ => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }));
    loop {
        tokio::select! {_=timer.tick()=>{},_=state.notified()=>{}}
        if host.strong_count() == 0 {
            break;
        }
        let _ = refresh_once(&config, &state).await;
    }
}
