// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
// Envelope decoder extracted from crates/lockyard-cloud-client/src/crypto.rs.
// Identical in 0.3.14 (f00f98a96b0a) and 0.3.15 (1d57b99fa278).

use ring::{aead, hmac};
const LABEL: &[u8] = b"lockyard-cloud-key-id-v1";
const PREFIX: &str = "lyenc1.";

pub struct WorkspaceKey([u8; 32]);
impl WorkspaceKey {
    pub fn from_entropy(e: [u8; 32]) -> Self {
        Self(e)
    }
    pub fn key_id(&self) -> String {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        base64url(&hmac::sign(&k, LABEL).as_ref()[..8])
    }
    pub fn decrypt(&self, w: &str, f: &str, v: &str) -> Result<String, String> {
        let x = v.strip_prefix(PREFIX).ok_or("not encrypted")?;
        let (id, b) = x.split_once('.').ok_or("invalid envelope")?;
        if id != self.key_id() {
            return Err("wrong encryption key".into());
        }
        let mut b = unbase64url(b)?;
        if b.len() < 28 {
            return Err("invalid envelope".into());
        }
        let n: [u8; 12] = b[..12].try_into().map_err(|_| "invalid nonce")?;
        let k = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).map_err(|_| "invalid key")?,
        );
        let o = k
            .open_in_place(
                aead::Nonce::assume_unique_for_key(n),
                aead::Aad::from(aad(w, f)),
                &mut b[12..],
            )
            .map_err(|_| "cannot decrypt")?;
        String::from_utf8(o.to_vec()).map_err(|_| "invalid utf8".into())
    }
}
fn aad(w: &str, f: &str) -> Vec<u8> {
    [w.as_bytes(), &[0], f.as_bytes()].concat()
}
fn base64url(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((*c.get(1).unwrap_or(&0) as u32) << 8)
            | *c.get(2).unwrap_or(&0) as u32;
        o.push(T[((n >> 18) & 63) as usize] as char);
        o.push(T[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 {
            o.push(T[((n >> 6) & 63) as usize] as char)
        }
        if c.len() > 2 {
            o.push(T[(n & 63) as usize] as char)
        }
    }
    o
}
fn unbase64url(s: &str) -> Result<Vec<u8>, String> {
    let mut o = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err("bad base64".into()),
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            o.push((acc >> bits) as u8)
        }
    }
    if base64url(&o) != s {
        return Err("noncanonical base64".into());
    }
    Ok(o)
}
