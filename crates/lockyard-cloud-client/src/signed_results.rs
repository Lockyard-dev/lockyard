// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! EP-09 binary storage. A cloud ACK confirms storage, never result authenticity.
use crate::{Call, Client, ClientError, NegotiatedProtocol, PendingWrite, protocol};
use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BYTES: u64 = 262_144;
const YEAR_MS: u64 = 365 * 24 * 60 * 60 * 1000;

pub(crate) fn is_result_path(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    matches!(parts.as_slice(), ["", "api", "v1", "nodes", node, "jobs", job, "signed-result"] if route(node, job).is_ok())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn route(node: &str, job: &str) -> Result<(String, u64), ClientError> {
    if node.is_empty()
        || node.len() > 64
        || !node
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || job.len() != 26
        || job.as_bytes()[0] > b'7'
        || !job
            .bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
    {
        return Err(protocol::local(
            "invalid_request",
            "invalid signed result identity",
        ));
    }
    let mut timestamp = 0_u64;
    for b in job.bytes().take(10) {
        timestamp = (timestamp << 5)
            | b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
                .iter()
                .position(|v| *v == b)
                .unwrap() as u64;
    }
    Ok((
        format!("/api/v1/nodes/{node}/jobs/{job}/signed-result"),
        timestamp,
    ))
}
fn read_bounded(response: ureq::Response) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            protocol::local(
                "protocol_response_invalid",
                "incomplete signed result response",
            )
        })?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(protocol::local(
            "protocol_response_invalid",
            "signed result response exceeds limit",
        ));
    }
    Ok(bytes)
}
impl Client {
    /// Choose a stable cloud deadline without extending the job's content retention.
    pub fn signed_result_expiry(
        node: &str,
        job: &str,
        retention_deadline_ms: u64,
    ) -> Result<u64, ClientError> {
        let (_, created) = route(node, job)?;
        Ok(retention_deadline_ms.min(created.saturating_add(YEAR_MS)))
    }
    fn result_context(&self) -> Result<(&str, crate::WorkspaceKey), ClientError> {
        let workspace = self.workspace.as_deref().ok_or_else(|| {
            protocol::local("content_encryption_required", "workspace key required")
        })?;
        if workspace.len() != 36
            || !workspace.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            || self
                .expected_e2ee_workspace
                .as_deref()
                .is_some_and(|expected| expected != workspace)
        {
            return Err(protocol::local(
                "content_encryption_required",
                "canonical workspace identity required",
            ));
        }
        let key = self.resolved_content_key()?.ok_or_else(|| {
            protocol::local("content_encryption_required", "workspace key required")
        })?;
        Ok((workspace, key))
    }
    fn result_protocol(&self, session: &str) -> Result<NegotiatedProtocol, ClientError> {
        let protocol = self.negotiated_protocol(session)?;
        if !protocol.capabilities.contains("signed_results_v1") {
            return Err(protocol::local(
                "feature_unsupported",
                "server does not confirm signed_results_v1",
            ));
        }
        Ok(protocol)
    }
    fn result_call(
        session: &str,
        node: &str,
        job: &str,
        document: &[u8],
        expires_at_ms: u64,
    ) -> Result<Call, ClientError> {
        let (path, _) = route(node, job)?;
        let document = std::str::from_utf8(document)
            .map_err(|_| protocol::local("invalid_request", "result document must be UTF-8"))?;
        if document.is_empty() || document.len() > 64 * 1024 || expires_at_ms > 253_402_300_799_999
        {
            return Err(protocol::local(
                "invalid_request",
                "invalid result document or expiry",
            ));
        }
        Ok(Call {
            session: session.into(),
            method: "PUT".into(),
            key: Some(crate::credential_fingerprint(&path)),
            path,
            body: Some(serde_json::json!({"document":document,"expires_at_ms":expires_at_ms})),
            defer_pending_ack: true,
            ..Call::default()
        })
    }
    fn result_response(
        &self,
        result: Result<ureq::Response, ureq::Error>,
        protocol: &NegotiatedProtocol,
    ) -> Result<ureq::Response, ClientError> {
        match result {
            Ok(response) => {
                protocol::verify_echo(&response, protocol)?;
                Ok(response)
            }
            Err(ureq::Error::Status(status, response)) => {
                let echo = protocol::verify_echo(&response, protocol);
                let retry = response.header("Retry-After").and_then(|s| s.parse().ok());
                let bytes = read_bounded(response)?;
                let body = std::str::from_utf8(&bytes).map_err(|_| {
                    protocol::local("protocol_response_invalid", "invalid error response")
                })?;
                let mut error = protocol::parse_api_error(status, body, retry)?;
                if error.code.is_empty() {
                    return Err(protocol::local(
                        "protocol_response_invalid",
                        "error response omits stable code",
                    ));
                }
                if !matches!(
                    error.code.as_str(),
                    "protocol_invalid" | "protocol_unsupported"
                ) {
                    echo?;
                }
                error.message = format!("Cloud request failed with HTTP {status}");
                Err(ClientError::from_api(error))
            }
            Err(_) => Err(ClientError::Transport(
                "signed result transport unavailable".into(),
            )),
        }
    }
    fn result_request(
        &self,
        method: &str,
        path: &str,
        session: &str,
        protocol: &NegotiatedProtocol,
    ) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{path}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("X-Lockyard-Session", session)
            .set("Lockyard-Protocol", &protocol.selected.to_string())
            .set("Accept", "application/octet-stream")
    }
    /// Encrypt the original saved UTF-8 document once. Keep its W4 journal until the caller
    /// durably records the 204 receipt and calls `acknowledge_signed_result`.
    pub fn put_signed_result(
        &self,
        session: &str,
        node: &str,
        job: &str,
        document: &[u8],
        expires_at_ms: u64,
    ) -> Result<(), ClientError> {
        if session != node {
            return Err(protocol::local(
                "invalid_request",
                "upload requires the node session",
            ));
        }
        let call = Self::result_call(session, node, job, document, expires_at_ms)?;
        let key = call.key.as_deref().unwrap();
        let _guard = self.claim_pending_send(key)?;
        let (workspace, content_key) = self.result_context()?;
        let (_, job_time) = route(node, job)?;
        let now = now_ms();
        let expiry = lockyard_core::proto::rfc3339(expires_at_ms as i64);
        let pending = if let Some(pending) = self.pending_operation(key) {
            if now >= job_time.saturating_add(YEAR_MS).saturating_sub(60_000)
                || pending.method != "PUT"
                || pending.path != call.path
                || pending.request_path != call.path
                || pending.session != session
                || pending.origin != self.base_url
                || pending.credential_scope != crate::credential_fingerprint(&self.token)
                || pending.encryption_context.as_deref() != Some(self.encryption_context().as_str())
                || pending.result_expires_at.as_deref() != Some(expiry.as_str())
                || pending.request_digest.as_deref()
                    != Some(crate::request_identity(&call).as_str())
            {
                return Err(ClientError::OutcomeUnknown(Box::new(pending)));
            }
            pending
        } else {
            if expires_at_ms <= now
                || expires_at_ms > job_time.saturating_add(YEAR_MS)
                || expires_at_ms > now.saturating_add(YEAR_MS)
                || job_time > now.saturating_add(300_000)
            {
                return Err(protocol::local("invalid_request", "invalid result expiry"));
            }
            let protocol = self.result_protocol(session)?;
            let body = content_key
                .encrypt(
                    workspace,
                    &format!("node-result/{node}/{job}"),
                    std::str::from_utf8(document).unwrap(),
                )
                .map_err(|_| {
                    protocol::local("content_authentication_failed", "result encryption failed")
                })?;
            if body.len() as u64 > MAX_BYTES {
                return Err(protocol::local("too_large", "result exceeds limit"));
            }
            let pending = PendingWrite {
                code: "outcome_unknown".into(),
                cause_code: "outcome_unknown".into(),
                cause_status: None,
                protocol,
                method: "PUT".into(),
                path: call.path.clone(),
                request_path: call.path.clone(),
                body: Some(body),
                key: key.into(),
                repository: None,
                session: session.into(),
                origin: self.base_url.clone(),
                credential_scope: crate::credential_fingerprint(&self.token),
                request_digest: Some(crate::request_identity(&call)),
                first_sent_unix_secs: Some(now / 1000),
                pre_execution_rejected: false,
                encryption_context: Some(self.encryption_context()),
                result_expires_at: Some(expiry),
                result_retry_at: None,
            };
            self.retain_pending(pending.clone())?;
            pending
        };
        self.send_signed_result(pending)
    }
    fn send_signed_result(&self, mut pending: PendingWrite) -> Result<(), ClientError> {
        if !Self::result_retry_ready(&pending) {
            return Err(ClientError::from_api(crate::ApiError {
                status: pending.cause_status.unwrap_or(503),
                code: pending.cause_code.clone(),
                message: "signed result publication is suspended".into(),
                ..Default::default()
            }));
        }
        if matches!(
            (pending.cause_status, pending.cause_code.as_str()),
            (Some(400), "protocol_unsupported") | (Some(503), "server_draining")
        ) {
            // A proven refusal permits fresh discovery at the configured origin.
            // Only the protocol header changes; ciphertext, key, path and expiry stay frozen.
            self.refresh_protocol(&pending.session)?;
            let previous = pending.clone();
            pending.protocol = self.result_protocol(&pending.session)?;
            self.update_pending(&previous, pending.clone())?;
        }
        let request = self
            .result_request("PUT", &pending.path, &pending.session, &pending.protocol)
            .set("Content-Type", "application/octet-stream")
            .set(
                "Lockyard-Result-Expires-At",
                pending.result_expires_at.as_deref().unwrap(),
            );
        let response = self.result_response(
            request.send_bytes(pending.body.as_ref().unwrap().as_bytes()),
            &pending.protocol,
        );
        match response {
            Ok(response) if response.status() == 204 => {
                if !read_bounded(response)?.is_empty() {
                    return Err(self.unknown(pending, "protocol_response_invalid", None));
                }
                Ok(())
            }
            Ok(_) => Err(self.unknown(pending, "protocol_response_invalid", None)),
            Err(error) => {
                let previous = pending.clone();
                let mut pending = pending;
                pending.cause_code = error.code().unwrap_or("outcome_unknown").to_owned();
                pending.cause_status = error.status();
                pending.result_retry_at = error
                    .retry_after()
                    .map(|seconds| (now_ms().saturating_add(999) / 1000).saturating_add(seconds));
                self.update_pending(&previous, pending.clone())?;
                if error.status().is_some_and(|status| {
                    status < 500
                        || (status == 503
                            && matches!(
                                error.code(),
                                Some("server_draining" | "frozen" | "temporarily_unavailable")
                            ))
                }) {
                    Err(error)
                } else {
                    let cause = pending.cause_code.clone();
                    Err(self.unknown(pending, &cause, error.status()))
                }
            }
        }
    }
    /// The worker respects refusal codes and Retry-After across restarts.
    pub fn result_retry_ready(pending: &PendingWrite) -> bool {
        pending
            .result_retry_at
            .is_none_or(|time| now_ms() / 1000 >= time)
            && matches!(
                (pending.cause_status, pending.cause_code.as_str()),
                (None, _)
                    | (Some(429), "rate_limited")
                    | (
                        Some(503),
                        "server_draining" | "frozen" | "temporarily_unavailable"
                    )
                    | (Some(400), "protocol_unsupported")
            )
    }
    pub fn result_permanently_refused(pending: &PendingWrite) -> bool {
        pending.cause_status.is_some_and(|status| status < 500)
            && !matches!(
                (pending.cause_status, pending.cause_code.as_str()),
                (Some(429), "rate_limited" | "relay_budget_exceeded")
                    | (Some(400), "protocol_unsupported")
            )
    }
    pub fn result_replay_expired(pending: &PendingWrite) -> bool {
        let parts = pending.path.split('/').collect::<Vec<_>>();
        match parts.as_slice() {
            ["", "api", "v1", "nodes", node, "jobs", job, "signed-result"] => route(node, job)
                .is_ok_and(|(_, time)| {
                    now_ms() >= time.saturating_add(YEAR_MS).saturating_sub(60_000)
                }),
            _ => false,
        }
    }
    pub fn signed_result_pending(&self, node: &str, job: &str) -> Option<PendingWrite> {
        let (path, _) = route(node, job).ok()?;
        self.pending_operation(&crate::credential_fingerprint(&path))
    }
    /// Replay from the private W4 journal after the original job content has expired. No
    /// document serialization, encryption or expiry generation occurs here. Discovery changes
    /// only after a proven replica refusal.
    pub fn replay_signed_result(&self, key: &str) -> Result<(), ClientError> {
        let _guard = self.claim_pending_send(key)?;
        self.send_signed_result(self.result_for_replay(key)?)
    }
    /// Explicitly resume a quota-refused operation after budget relief. This only schedules
    /// exact replay: the saved Retry-After still applies, and a durable receipt is still needed
    /// before acknowledgement. Automatic workers never make this decision themselves.
    pub fn resume_signed_result(&self, key: &str) -> Result<(), ClientError> {
        let _guard = self.claim_pending_send(key)?;
        let mut pending = self.result_for_replay(key)?;
        if pending.cause_status != Some(429) || pending.cause_code != "relay_budget_exceeded" {
            return Err(protocol::local(
                "invalid_request",
                "result is not quota suspended",
            ));
        }
        let previous = pending.clone();
        pending.cause_code = "outcome_unknown".into();
        pending.cause_status = None;
        self.update_pending(&previous, pending)
    }
    fn result_for_replay(&self, key: &str) -> Result<PendingWrite, ClientError> {
        self.result_context()?;
        let pending = self
            .pending_operation(key)
            .ok_or_else(|| protocol::local("invalid_request", "pending result missing"))?;
        let parts = pending.path.split('/').collect::<Vec<_>>();
        let valid = match parts.as_slice() {
            ["", "api", "v1", "nodes", node, "jobs", job, "signed-result"] => {
                route(node, job).is_ok_and(|(_, timestamp)| {
                    now_ms() < timestamp.saturating_add(YEAR_MS).saturating_sub(60_000)
                }) && pending.session == *node
            }
            _ => false,
        };
        if !valid
            || pending.method != "PUT"
            || pending.request_path != pending.path
            || pending.origin != self.base_url
            || pending.credential_scope != crate::credential_fingerprint(&self.token)
            || pending.encryption_context.as_deref() != Some(self.encryption_context().as_str())
            || pending.result_expires_at.is_none()
            || pending.body.is_none()
        {
            return Err(ClientError::OutcomeUnknown(Box::new(pending)));
        }
        Ok(pending)
    }
    /// Release frozen bytes only after a durable local publication receipt exists.
    pub fn acknowledge_signed_result(
        &self,
        session: &str,
        node: &str,
        job: &str,
        document: &[u8],
        expires_at_ms: u64,
    ) -> Result<(), ClientError> {
        use crate::Transport;
        self.acknowledge_write(&Self::result_call(
            session,
            node,
            job,
            document,
            expires_at_ms,
        )?)
    }
    /// Return original authenticated document bytes. The caller must still verify the node's
    /// pinned signature and complete job context before accepting the result as evidence.
    pub fn get_signed_result(
        &self,
        session: &str,
        node: &str,
        job: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let (path, _) = route(node, job)?;
        let (workspace, key) = self.result_context()?;
        let protocol = self.result_protocol(session)?;
        let response = self.result_response(
            self.result_request("GET", &path, session, &protocol).call(),
            &protocol,
        )?;
        if response.status() != 200
            || response.content_type() != "application/octet-stream"
            || response.all("Lockyard-Result-Expires-At").len() != 1
            || response
                .header("Lockyard-Result-Expires-At")
                .and_then(lockyard_core::proto::parse_rfc3339)
                .is_none_or(|time| time <= now_ms() as i64)
        {
            return Err(protocol::local(
                "protocol_response_invalid",
                "invalid signed result response",
            ));
        }
        let bytes = read_bounded(response)?;
        let envelope = std::str::from_utf8(&bytes).map_err(|_| {
            protocol::local(
                "content_authentication_failed",
                "result authentication failed",
            )
        })?;
        let document = key
            .decrypt(workspace, &format!("node-result/{node}/{job}"), envelope)
            .map_err(|_| {
                protocol::local(
                    "content_authentication_failed",
                    "result authentication failed",
                )
            })?;
        if document.is_empty() || document.len() > 64 * 1024 {
            return Err(protocol::local(
                "content_authentication_failed",
                "invalid result document",
            ));
        }
        Ok(document.into_bytes())
    }
}
