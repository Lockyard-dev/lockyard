// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Signed revocations use a dedicated, independently provisioned server key.
//! A POST proof and an additive push never establish snapshot freshness.
mod http;
pub use http::{RevocationKey, validate_refresh_times};
use ring::{digest, signature};
use serde::{Deserialize, Serialize};

pub const MAX_EPOCH: u64 = 9_007_199_254_740_991;
pub const DOMAIN: &[u8] = b"lockyard-revocations-v1\0";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationTarget {
    Token {
        token_id: String,
    },
    Machine {
        node_id: String,
        credential_id: String,
        certificate_sha256: String,
    },
    CertPin {
        certificate_sha256: String,
    },
    SsoSession {
        token_id: String,
    },
}
impl RevocationTarget {
    pub fn validate(&self) -> Result<(), RevocationError> {
        let valid = match self {
            Self::Token { token_id } | Self::SsoSession { token_id } => uuid(token_id),
            Self::CertPin { certificate_sha256 } => hex_value(certificate_sha256, 64),
            Self::Machine {
                node_id,
                credential_id,
                certificate_sha256,
            } => valid_name(node_id) && uuid(credential_id) && hex_value(certificate_sha256, 64),
        };
        if valid {
            Ok(())
        } else {
            Err(error("invalid_revocation_request"))
        }
    }
    pub fn pin(&self) -> Option<&str> {
        match self {
            Self::Machine {
                certificate_sha256, ..
            }
            | Self::CertPin { certificate_sha256 } => Some(certificate_sha256),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    pub epoch: u64,
    pub ordinal: u32,
    pub target: RevocationTarget,
    pub revoked_at_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPage {
    pub schema: u8,
    pub workspace_id: String,
    pub from_epoch: u64,
    pub epoch: u64,
    pub snapshot_id: String,
    pub issued_at_ms: u64,
    pub valid_until_ms: u64,
    pub nonce: String,
    pub page_index: u32,
    pub next_cursor: Option<String>,
    pub entries: Vec<RevocationEntry>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDocument {
    pub version: u8,
    pub algorithm: String,
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationReceipt {
    pub epoch: u64,
    pub already_revoked: bool,
    pub document: SignedDocument,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTrust {
    pub workspace_id: String,
    pub key_id: String,
    pub public_key: String,
    pub server_origin: String,
}
impl RevocationTrust {
    pub fn validate(&self) -> Result<(), RevocationError> {
        if !uuid(&self.workspace_id)
            || !hex_value(&self.public_key, 64)
            || !hex_value(&self.key_id, 64)
            || canonical_origin(&self.server_origin).ok().as_deref()
                != Some(self.server_origin.as_str())
            || hex(digest::digest(&digest::SHA256, &unhex(&self.public_key)?).as_ref())
                != self.key_id
        {
            return Err(error("revocation_signer_untrusted"));
        }
        Ok(())
    }
}
/// Carries a stable server code verbatim. A possible write is never reported as a definite failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationError {
    pub code: String,
    pub commit_unknown: bool,
    pub retry_after: Option<u64>,
}
impl RevocationError {
    pub fn code(&self) -> &str {
        &self.code
    }
}
impl std::fmt::Display for RevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code)
    }
}
impl std::error::Error for RevocationError {}
pub(crate) fn error(code: &str) -> RevocationError {
    RevocationError {
        code: code.into(),
        commit_unknown: false,
        retry_after: None,
    }
}

/// Verify the exact signed bytes before parsing. Re-encoding enforces the canonical field order,
/// canonical integers, no unknown/duplicate fields, and unescaped ASCII values.
pub fn verify_document(
    document: &SignedDocument,
    trust: &RevocationTrust,
    origin: &str,
) -> Result<RevocationPage, RevocationError> {
    trust.validate()?;
    if canonical_origin(origin)? != trust.server_origin
        || document.version != 1
        || document.algorithm != "Ed25519"
        || document.key_id != trust.key_id
    {
        return Err(error("revocation_signer_untrusted"));
    }
    if serde_json::to_vec(document)
        .map_err(|_| error("invalid_revocation_request"))?
        .len()
        > 65_536
    {
        return Err(error("too_large"));
    }
    let bytes = unbase64(&document.payload)?;
    let sig = unbase64(&document.signature)?;
    if bytes.len() > 32_768 || !bytes.is_ascii() || sig.len() != 64 {
        return Err(error("invalid_revocation_request"));
    }
    let mut framed = DOMAIN.to_vec();
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(&bytes);
    signature::UnparsedPublicKey::new(&signature::ED25519, unhex(&trust.public_key)?)
        .verify(&framed, &sig)
        .map_err(|_| error("revocation_signer_untrusted"))?;
    let page: RevocationPage =
        serde_json::from_slice(&bytes).map_err(|_| error("invalid_revocation_request"))?;
    if serde_json::to_vec(&page).map_err(|_| error("invalid_revocation_request"))? != bytes {
        return Err(error("invalid_revocation_request"));
    }
    if page.workspace_id != trust.workspace_id {
        return Err(error("revocation_signer_untrusted"));
    }
    if page.schema != 1
        || !uuid(&page.snapshot_id)
        || page.from_epoch > page.epoch
        || page.epoch > MAX_EPOCH
        || page.valid_until_ms < page.issued_at_ms
        || page.valid_until_ms - page.issued_at_ms > 60_000
        || (!page.nonce.is_empty() && !hex_value(&page.nonce, 64))
        || page.next_cursor.as_deref().is_some_and(|c| {
            c.is_empty()
                || c.len() > 4096
                || !c
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(error("invalid_revocation_request"));
    }
    let mut previous = None;
    for entry in &page.entries {
        entry.target.validate()?;
        if entry.epoch == 0
            || entry.epoch <= page.from_epoch
            || entry.epoch > page.epoch
            || entry.revoked_at_ms > page.issued_at_ms
            || previous.is_some_and(|p| p >= (entry.epoch, entry.ordinal))
        {
            return Err(error("invalid_revocation_request"));
        }
        previous = Some((entry.epoch, entry.ordinal));
    }
    Ok(page)
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_value(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unhex(s: &str) -> Result<Vec<u8>, RevocationError> {
    if !hex_value(s, 64) {
        return Err(error("revocation_signer_untrusted"));
    }
    (0..s.len())
        .step_by(2)
        .map(|n| {
            u8::from_str_radix(&s[n..n + 2], 16).map_err(|_| error("revocation_signer_untrusted"))
        })
        .collect()
}
fn uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn base64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let x = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | (c.get(2).copied().unwrap_or(0) as u32);
        for shift in [18, 12, 6, 0] {
            out.push(T[((x >> shift) & 63) as usize] as char);
        }
        if c.len() < 3 {
            out.truncate(out.len() - (3 - c.len()));
            for _ in 0..3 - c.len() {
                out.push('=');
            }
        }
    }
    out
}
fn unbase64(s: &str) -> Result<Vec<u8>, RevocationError> {
    if s.len() > 45_000 || !s.len().is_multiple_of(4) {
        return Err(error("invalid_revocation_request"));
    }
    let mut out = Vec::new();
    for c in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for &b in c {
            let value = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 0,
                _ => return Err(error("invalid_revocation_request")),
            };
            n = (n << 6) | value as u32;
        }
        out.push((n >> 16) as u8);
        if c[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if c[3] != b'=' {
            out.push(n as u8);
        }
    }
    if base64(&out) != s {
        return Err(error("invalid_revocation_request"));
    }
    Ok(out)
}

/// A durable POST receipt proves only its requested target, never the materialized direct closure.
pub fn verify_receipt(
    receipt: &RevocationReceipt,
    target: &RevocationTarget,
    trust: &RevocationTrust,
    origin: &str,
) -> Result<RevocationPage, RevocationError> {
    let page = verify_document(&receipt.document, trust, origin)?;
    if receipt.epoch == 0
        || receipt.epoch > MAX_EPOCH
        || page.epoch != receipt.epoch
        || !page.nonce.is_empty()
        || page.page_index != 0
        || page.next_cursor.is_some()
        || page.entries.len() != 1
        || page.entries[0].target != *target
        || page.entries[0].epoch != receipt.epoch
    {
        return Err(error("protocol_response_invalid"));
    }
    Ok(page)
}

/// Canonicalize the configured server scope before selecting any persistent trust or operation.
/// URL normalization preserves paths while removing equivalent host case, default ports and slashes.
pub fn canonical_origin(raw: &str) -> Result<String, RevocationError> {
    let mut url = url::Url::parse(raw).map_err(|_| error("revocation_signer_untrusted"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || !crate::allowed_url(url.as_str())
    {
        return Err(error("revocation_signer_untrusted"));
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}
