// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use super::*;
use crate::Client;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    io::{BufRead, BufReader, Read},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationKey {
    pub workspace_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}
impl Client {
    /// Inject the node's already configured TLS roots and bounded resolver without weakening TLS.
    pub fn with_revocation_agent(mut self, agent: ureq::Agent) -> Self {
        self.agent = agent.clone();
        self.poll_agent = agent;
        self
    }
    fn revocation_request(&self, session: &str, path: &str, method: &str) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{path}", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("X-Lockyard-Session", session)
            .set(
                "User-Agent",
                concat!("lockyard/", env!("CARGO_PKG_VERSION")),
            )
            .timeout(Duration::from_secs(15))
    }
    /// Owner bootstrap is explicit trust provisioning over the configured authenticated HTTPS origin.
    /// Subsequent calls compare metadata to the independently stored pin, never replace that pin.
    pub fn revocation_key(&self, session: &str) -> Result<RevocationTrust, RevocationError> {
        let response = self
            .revocation_request(session, "/api/v1/revocations/key", "GET")
            .call();
        let response = response_result(response, false)?;
        check_capability(&response)?;
        let key: RevocationKey = read_json(response)?;
        if key.algorithm != "Ed25519" {
            return Err(error("revocation_signer_untrusted"));
        }
        let trust = RevocationTrust {
            workspace_id: key.workspace_id,
            key_id: key.key_id,
            public_key: key.public_key,
            server_origin: canonical_origin(&self.base_url)?,
        };
        trust.validate()?;
        Ok(trust)
    }
    pub fn revocation_confirm_trust(
        &self,
        session: &str,
        trust: &RevocationTrust,
    ) -> Result<(), RevocationError> {
        trust.validate()?;
        if trust.server_origin != canonical_origin(&self.base_url)?
            || self.revocation_key(session)? != *trust
        {
            return Err(error("revocation_signer_untrusted"));
        }
        Ok(())
    }
    /// One complete challenge-bound fixed snapshot. Cursor expiry restarts with a fresh nonce once;
    /// all other failures preserve callers' complete epoch and monotonic freshness.
    pub fn revocation_refresh_documents(
        &self,
        session: &str,
        since: u64,
        trust: &RevocationTrust,
    ) -> Result<Vec<SignedDocument>, RevocationError> {
        self.revocation_refresh_documents_with_apply(session, since, trust, |_| Ok(()))
    }
    /// Publish every validated page immediately, even when a later page or cursor expires.
    /// The callback is additive only; the returned complete snapshot establishes freshness.
    pub fn revocation_refresh_documents_with_apply(
        &self,
        session: &str,
        since: u64,
        trust: &RevocationTrust,
        mut apply: impl FnMut(&SignedDocument) -> Result<(), RevocationError>,
    ) -> Result<Vec<SignedDocument>, RevocationError> {
        trust.validate()?;
        if trust.server_origin != canonical_origin(&self.base_url)? || since > MAX_EPOCH {
            return Err(error("revocation_signer_untrusted"));
        }
        for attempt in 0..2 {
            match self.revocation_snapshot(session, since, trust, &mut apply) {
                Err(e) if e.code == "revocation_cursor_expired" && attempt == 0 => continue,
                result => return result,
            }
        }
        Err(error("revocation_cursor_expired"))
    }
    fn revocation_snapshot(
        &self,
        session: &str,
        since: u64,
        trust: &RevocationTrust,
        apply: &mut impl FnMut(&SignedDocument) -> Result<(), RevocationError>,
    ) -> Result<Vec<SignedDocument>, RevocationError> {
        let started = Instant::now();
        let started_wall = now_ms();
        let mut random = [0; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| error("revocation_state_unavailable"))?;
        let nonce = hex(&random);
        let mut cursor = None;
        let mut documents = Vec::new();
        let mut first: Option<RevocationPage> = None;
        let mut last_entry: Option<(u64, u32)> = None;
        loop {
            if started.elapsed() > Duration::from_secs(60) || documents.len() >= 4096 {
                return Err(error("revocation_state_unavailable"));
            }
            let mut path = format!("/api/v1/revocations?since={since}&nonce={nonce}");
            if let Some(c) = cursor.as_deref() {
                path.push_str("&cursor=");
                path.push_str(&crate::encode(c));
            }
            let response =
                response_result(self.revocation_request(session, &path, "GET").call(), false)?;
            check_capability(&response)?;
            let document: SignedDocument = read_json(response)?;
            let page = verify_document(&document, trust, &self.base_url)?;
            let now = now_ms();
            validate_refresh_times(
                page.issued_at_ms,
                page.valid_until_ms,
                started_wall,
                now,
                started.elapsed(),
            )?;
            if page.nonce != nonce
                || page.from_epoch != since
                || page.page_index as usize != documents.len()
            {
                return Err(error("invalid_revocation_request"));
            }
            if let Some(f) = &first
                && (f.epoch != page.epoch
                    || f.snapshot_id != page.snapshot_id
                    || f.issued_at_ms != page.issued_at_ms
                    || f.valid_until_ms != page.valid_until_ms)
            {
                return Err(error("invalid_revocation_request"));
            }
            for entry in &page.entries {
                if let Some((epoch, ordinal)) = last_entry {
                    if entry.epoch < epoch
                        || (entry.epoch == epoch && ordinal.checked_add(1) != Some(entry.ordinal))
                        || (entry.epoch > epoch
                            && (epoch.checked_add(1) != Some(entry.epoch) || entry.ordinal != 0))
                    {
                        return Err(error("invalid_revocation_request"));
                    }
                } else if entry.ordinal != 0 || since.checked_add(1) != Some(entry.epoch) {
                    return Err(error("invalid_revocation_request"));
                }
                last_entry = Some((entry.epoch, entry.ordinal));
            }
            apply(&document)?;
            cursor = page.next_cursor.clone();
            first.get_or_insert(page);
            documents.push(document);
            if cursor.is_none() {
                if last_entry.map(|(epoch, _)| epoch).unwrap_or(since)
                    != first.as_ref().expect("first page recorded").epoch
                {
                    return Err(error("invalid_revocation_request"));
                }
                return Ok(documents);
            }
        }
    }
    /// Sends exactly one POST. The caller persists key and exact body before this call and decides
    /// whether a second send is safe. Never retry a revoked credential or a write with unknown retention.
    pub fn revocation_post(
        &self,
        session: &str,
        target: &RevocationTarget,
        key: &str,
        trust: &RevocationTrust,
    ) -> Result<RevocationReceipt, RevocationError> {
        target.validate()?;
        if !valid_ulid(key) {
            return Err(error("invalid_revocation_request"));
        }
        self.revocation_confirm_trust(session, trust)?;
        let body = serde_json::to_string(
            &serde_json::json!({"target":target,"reason_code":"owner_request"}),
        )
        .map_err(|_| error("invalid_revocation_request"))?;
        let response = response_result(
            self.revocation_request(session, "/api/v1/revocations", "POST")
                .set("Idempotency-Key", key)
                .set("Content-Type", "application/json")
                .send_string(&body),
            true,
        )?;
        // A malformed successful write response may follow a committed transaction.
        let result = (|| {
            check_capability(&response)?;
            let receipt: RevocationReceipt = read_json(response)?;
            verify_receipt(&receipt, target, trust, &self.base_url)?;
            Ok(receipt)
        })();
        result.map_err(|mut e: RevocationError| {
            e.commit_unknown = true;
            e
        })
    }
    /// SSE is an untrusted wake-up hint. Every wake is followed by a new signed challenge refresh.
    pub fn revocation_events_hint(
        &self,
        session: &str,
        last_epoch: u64,
    ) -> Result<bool, RevocationError> {
        let response = response_result(
            self.revocation_request(session, "/api/v1/revocations/events", "GET")
                .set("Accept", "text/event-stream")
                .set("Last-Event-ID", &last_epoch.to_string())
                .call(),
            false,
        )?;
        check_capability(&response)?;
        if !response
            .header("Content-Type")
            .is_some_and(|v| v.starts_with("text/event-stream"))
        {
            return Err(error("revocation_protocol_unavailable"));
        }
        let started = Instant::now();
        let mut reader = BufReader::new(response.into_reader().take(65_537));
        let mut line = String::new();
        let mut changed = false;
        loop {
            if started.elapsed() >= Duration::from_secs(15) {
                return Ok(false);
            }
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|_| error("temporarily_unavailable"))?;
            if n == 0 {
                return Ok(false);
            }
            if line.len() > 4096 {
                return Err(error("too_large"));
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() && changed {
                return Ok(true);
            }
            if line == "event: revocations_changed" {
                changed = true;
            }
            if changed && line.starts_with("data:") {
                let data: serde_json::Value = serde_json::from_str(line[5..].trim())
                    .map_err(|_| error("invalid_revocation_request"))?;
                if data
                    .get("epoch")
                    .and_then(serde_json::Value::as_u64)
                    .is_none()
                {
                    return Err(error("invalid_revocation_request"));
                }
            }
        }
    }
}
fn valid_ulid(s: &str) -> bool {
    s.len() == 26
        && s.as_bytes()[0] <= b'7'
        && s.bytes()
            .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
fn check_capability(response: &ureq::Response) -> Result<(), RevocationError> {
    if response
        .header("Lockyard-Capabilities")
        .is_some_and(|c| c.split([',', ' ']).any(|v| v == "revocations_v1"))
    {
        Ok(())
    } else {
        Err(error("revocation_protocol_unavailable"))
    }
}
fn read_json<T: for<'de> Deserialize<'de>>(response: ureq::Response) -> Result<T, RevocationError> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| error("temporarily_unavailable"))?;
    if bytes.len() > 65_536 {
        return Err(error("too_large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error("protocol_response_invalid"))
}
fn response_result(
    response: Result<ureq::Response, ureq::Error>,
    write: bool,
) -> Result<ureq::Response, RevocationError> {
    match response {
        Ok(r) if r.status() == 200 => Ok(r),
        Ok(_) => Err(RevocationError {
            code: if write {
                "revocation_commit_unknown"
            } else {
                "protocol_response_invalid"
            }
            .into(),
            commit_unknown: write,
            retry_after: None,
        }),
        Err(ureq::Error::Transport(_)) => Err(RevocationError {
            code: if write {
                "revocation_commit_unknown"
            } else {
                "temporarily_unavailable"
            }
            .into(),
            commit_unknown: write,
            retry_after: None,
        }),
        Err(ureq::Error::Status(status, r)) => {
            let retry_after = r.header("Retry-After").and_then(|v| v.parse().ok());
            let mut bytes = Vec::new();
            let _ = r.into_reader().take(65_537).read_to_end(&mut bytes);
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let code = body
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(if status == 404 {
                    "revocation_protocol_unavailable"
                } else {
                    "protocol_response_invalid"
                });
            let contradictory = (body.get("status").and_then(serde_json::Value::as_u64)
                != Some(status as u64)
                && !(status == 404 && body.get("code").is_none()))
                || code.is_empty()
                || code.len() > 128
                || !code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            Err(RevocationError {
                code: if contradictory {
                    "protocol_response_invalid".into()
                } else {
                    code.into()
                },
                commit_unknown: write
                    && (contradictory
                        || code == "protocol_response_invalid"
                        || status >= 500
                            && !matches!(
                                code,
                                "revocation_state_unavailable" | "revocation_signer_unavailable"
                            )),
                retry_after,
            })
        }
    }
}

/// An old later page is still fresh until its fixed expiry. Clock skew is measured against the
/// challenge's first request and monotonic elapsed time, rather than time since issuance per page.
pub fn validate_refresh_times(
    issued: u64,
    expires: u64,
    started_wall: u64,
    received_wall: u64,
    elapsed: Duration,
) -> Result<(), RevocationError> {
    let expected = started_wall.saturating_add(elapsed.as_millis().min(u64::MAX as u128) as u64);
    if issued.saturating_add(30_000) < started_wall
        || issued > received_wall.saturating_add(30_000)
        || received_wall.abs_diff(expected) > 30_000
    {
        return Err(error("revocation_clock_skew"));
    }
    if received_wall >= expires {
        return Err(error("revocations_stale"));
    }
    Ok(())
}
