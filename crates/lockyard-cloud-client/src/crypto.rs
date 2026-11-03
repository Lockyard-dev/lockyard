//! Client-side content encryption. Coordination fields deliberately stay clear.
use ring::{
    aead, digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use serde_json::Value;
const LABEL: &[u8] = b"lockyard-cloud-key-id-v1";
const WORDS: &str = include_str!("english.txt");
const PREFIX: &str = "lyenc1.";
const FIELDS: &str = include_str!("../content-fields.json");
const OPENAPI: &str = include_str!("../tests/fixtures/openapi.json");
#[derive(Debug, Clone, Deserialize)]
struct Field {
    schema: String,
    property: String,
    name: String,
}
#[derive(Debug, Deserialize)]
struct FieldMap {
    fields: Vec<Field>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldRule {
    pub method: &'static str,
    pub route: &'static str,
    pub pointer: &'static str,
    pub name: &'static str,
}
// Compatibility metadata; transformations below are driven by OpenAPI schemas and content-fields.json.
pub const CONTENT_FIELDS: &[FieldRule] = &[];
pub fn route_matches(pattern: &str, route: &str) -> bool {
    let a = pattern.split('/').collect::<Vec<_>>();
    let b = route
        .split('?')
        .next()
        .unwrap_or(route)
        .split('/')
        .collect::<Vec<_>>();
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| *x == "*" || *x == y)
}
/// The table and the document are embedded, so they are parsed once and shared.
fn parsed() -> Result<&'static (FieldMap, Value), String> {
    static PARSED: std::sync::OnceLock<Result<(FieldMap, Value), String>> =
        std::sync::OnceLock::new();
    PARSED
        .get_or_init(|| {
            let map: FieldMap = serde_json::from_str(FIELDS).map_err(|e| e.to_string())?;
            let api: Value = serde_json::from_str(OPENAPI).map_err(|e| e.to_string())?;
            Ok((map, api))
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub fn transform_fields(
    value: &mut Value,
    method: &str,
    route: &str,
    workspace: &str,
    key: Option<&WorkspaceKey>,
    encrypt: bool,
) -> Result<(), String> {
    let (map, api) = parsed()?;
    let normalized = route.split('?').next().unwrap_or(route);
    let mut schemas = Vec::new();
    for (path, ops) in api["paths"].as_object().ok_or("bad OpenAPI paths")? {
        if !openapi_path_matches(path, normalized) {
            continue;
        }
        let Some(op) = ops.get(method.to_ascii_lowercase()) else {
            continue;
        };
        if encrypt {
            let node = op
                .get("requestBody")
                .and_then(|x| x.get("content"))
                .and_then(|x| x.get("application/json"))
                .and_then(|x| x.get("schema"));
            if let Some(n) = node {
                collect_refs(n, &mut schemas)
            }
        } else {
            let node = op
                .get("responses")
                .and_then(Value::as_object)
                .and_then(|r| {
                    r.iter()
                        .find(|(code, _)| code.starts_with('2'))
                        .map(|(_, v)| v)
                })
                .and_then(|x| x.get("content"))
                .and_then(|x| x.get("application/json"))
                .and_then(|x| x.get("schema"));
            if let Some(n) = node {
                collect_refs(n, &mut schemas)
            }
        }
    }
    let mut touched = Vec::new();
    for schema in schemas {
        visit(
            value,
            &schema,
            &api["components"]["schemas"],
            &map.fields,
            workspace,
            key,
            encrypt,
            &mut touched,
        )?;
    }
    Ok(())
}
fn openapi_path_matches(template: &str, path: &str) -> bool {
    let a = template.split('/').collect::<Vec<_>>();
    let b = path.split('/').collect::<Vec<_>>();
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.starts_with('{') && x.ends_with('}') || *x == y)
}
#[allow(clippy::collapsible_if)]
fn collect_refs(v: &Value, out: &mut Vec<String>) {
    if let Some(r) = v.get("$ref").and_then(Value::as_str) {
        if let Some(s) = r.strip_prefix("#/components/schemas/") {
            out.push(s.into())
        }
    }
    if let Some(i) = v.get("items") {
        collect_refs(i, out)
    }
    if let Some(a) = v.get("allOf").and_then(Value::as_array) {
        for x in a {
            collect_refs(x, out)
        }
    }
}
#[allow(clippy::collapsible_if, clippy::too_many_arguments)]
fn visit(
    v: &mut Value,
    schema: &str,
    schemas: &Value,
    fields: &[Field],
    workspace: &str,
    key: Option<&WorkspaceKey>,
    enc: bool,
    touched: &mut Vec<String>,
) -> Result<(), String> {
    let Some(def) = schemas.get(schema) else {
        return Ok(());
    };
    if let (Some(obj), Some(props)) = (
        v.as_object_mut(),
        def.get("properties").and_then(Value::as_object),
    ) {
        for (p, sch) in props {
            if let Some(slot) = obj.get_mut(p) {
                if let Some(rule) = fields
                    .iter()
                    .find(|f| f.schema == schema && f.property == *p)
                {
                    if let Some(s) = slot.as_str() {
                        if enc && !s.starts_with(PREFIX) {
                            let k = key.ok_or_else(|| {
                                format!("workspace encryption is required but no local key is available; import the key with `lockyard cloud key import` before writing content ({schema}.{p})")
                            })?;
                            *slot = Value::String(k.encrypt(workspace, &rule.name, s)?);
                            touched.push(format!("{schema}.{p}"));
                        } else if !enc && s.starts_with(PREFIX) {
                            *slot = Value::String(match key {
                                None => "[locked]".into(),
                                Some(k) => k
                                    .decrypt(workspace, &rule.name, s)
                                    .unwrap_or_else(|_| "[cannot decrypt]".into()),
                            });
                        }
                    }
                }
                if let Some(r) = sch
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| r.strip_prefix("#/components/schemas/"))
                {
                    visit(slot, r, schemas, fields, workspace, key, enc, touched)?;
                }
                if let Some(items) = sch.get("items") {
                    if let Some(r) = items
                        .get("$ref")
                        .and_then(Value::as_str)
                        .and_then(|r| r.strip_prefix("#/components/schemas/"))
                    {
                        if let Some(a) = slot.as_array_mut() {
                            for item in a {
                                visit(item, r, schemas, fields, workspace, key, enc, touched)?
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
#[derive(Clone)]
pub struct WorkspaceKey([u8; 32]);
impl WorkspaceKey {
    pub fn from_entropy(e: [u8; 32]) -> Self {
        Self(e)
    }
    pub fn generate() -> Result<(Self, String), String> {
        let mut e = [0; 32];
        SystemRandom::new()
            .fill(&mut e)
            .map_err(|_| "system random source failed")?;
        let k = Self(e);
        let p = k.phrase();
        Ok((k, p))
    }
    pub fn from_phrase(p: &str) -> Result<Self, String> {
        let words = WORDS.lines().collect::<Vec<_>>();
        let parts = p
            .to_ascii_lowercase()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if parts.len() != 24 {
            return Err("the recovery phrase must contain 24 words".into());
        }
        let mut bits = Vec::new();
        for w in parts {
            let n = words
                .iter()
                .position(|x| **x == w)
                .ok_or("unknown recovery word")?;
            for b in (0..11).rev() {
                bits.push(((n >> b) & 1) as u8)
            }
        }
        let mut e = [0; 32];
        for (i, b) in bits[..256].iter().enumerate() {
            e[i / 8] |= b << (7 - i % 8)
        }
        let sum = digest::digest(&digest::SHA256, &e);
        for i in 0..8 {
            if bits[256 + i] != (sum.as_ref()[i / 8] >> (7 - i % 8)) & 1 {
                return Err("recovery phrase checksum is invalid".into());
            }
        }
        Ok(Self(e))
    }
    pub fn phrase(&self) -> String {
        entropy_to_phrase(&self.0)
    }
    pub fn store_for_workspace(&self, workspace: &str) -> Result<(), String> {
        use std::{fs, io::Write, path::PathBuf};
        if workspace.is_empty()
            || !workspace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invalid workspace id for local key storage".into());
        }
        let base = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?).join(".config"),
        };
        let dir = base.join("lockyard/keys");
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create key directory: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                dir.parent().ok_or("invalid key directory")?,
                fs::Permissions::from_mode(0o700),
            )
            .map_err(|e| format!("cannot secure key directory: {e}"))?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot secure key directory: {e}"))?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(dir.join(format!("{workspace}.key")))
            .map_err(|e| format!("cannot create workspace key: {e}"))?;
        f.write_all(&self.0)
            .map_err(|e| format!("cannot write workspace key: {e}"))
    }
    pub fn load_for_workspace(workspace: &str) -> Result<Option<Self>, String> {
        use std::{fs, path::PathBuf};
        if workspace.is_empty()
            || !workspace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("invalid workspace id for local key storage".into());
        }
        let base = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?).join(".config"),
        };
        let path = base.join("lockyard/keys").join(format!("{workspace}.key"));
        let b = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read workspace key: {e}")),
        };
        if b.len() != 32 {
            return Err("workspace key file has an invalid length".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path)
                .map_err(|e| format!("cannot inspect workspace key: {e}"))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o600 {
                return Err("workspace key file must have mode 0600".into());
            }
        }
        let mut raw = [0; 32];
        raw.copy_from_slice(&b);
        Ok(Some(Self(raw)))
    }
    pub fn key_id(&self) -> String {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        base64url(&hmac::sign(&k, LABEL).as_ref()[..8])
    }
    pub fn encrypt(&self, w: &str, f: &str, p: &str) -> Result<String, String> {
        let mut n = [0; 12];
        SystemRandom::new()
            .fill(&mut n)
            .map_err(|_| "system random source failed")?;
        let k = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0).map_err(|_| "invalid key")?,
        );
        let mut b = p.as_bytes().to_vec();
        k.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(n),
            aead::Aad::from(aad(w, f)),
            &mut b,
        )
        .map_err(|_| "encryption failed")?;
        let mut x = n.to_vec();
        x.extend(b);
        Ok(format!("{PREFIX}{}.{}", self.key_id(), base64url(&x)))
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
fn entropy_to_phrase(e: &[u8; 32]) -> String {
    let w = WORDS.lines().collect::<Vec<_>>();
    let c = digest::digest(&digest::SHA256, e);
    (0..24)
        .map(|i| {
            let mut n = 0;
            for j in 0..11 {
                let p = i * 11 + j;
                let b = if p < 256 {
                    (e[p / 8] >> (7 - p % 8)) & 1
                } else {
                    (c.as_ref()[(p - 256) / 8] >> (7 - (p - 256) % 8)) & 1
                };
                n = (n << 1) | b as usize
            }
            w[n]
        })
        .collect::<Vec<_>>()
        .join(" ")
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
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn content_table_entries_exist_and_free_text_is_explicit() {
        let api: Value = serde_json::from_str(OPENAPI).unwrap();
        let table: Value = serde_json::from_str(FIELDS).unwrap();
        let schemas = api["components"]["schemas"].as_object().unwrap();
        let fields = table["fields"].as_array().unwrap();
        let clear = table["clear"].as_array().unwrap();
        for entry in fields.iter().chain(clear) {
            let schema = entry["schema"].as_str().unwrap();
            let prop = entry["property"].as_str().unwrap();
            assert!(
                schemas
                    .get(schema)
                    .is_some_and(|s| s["properties"].get(prop).is_some()),
                "missing {schema}.{prop}"
            );
        }
        let covered = fields
            .iter()
            .chain(clear)
            .map(|e| {
                (
                    e["schema"].as_str().unwrap(),
                    e["property"].as_str().unwrap(),
                )
            })
            .collect::<std::collections::HashSet<_>>();
        let likely_free = [
            "body",
            "text",
            "reply",
            "brief",
            "report",
            "reason",
            "accept",
            "acceptance",
            "title",
            "value",
            "resolution",
            "purpose",
            "comment",
        ];
        for (schema, def) in schemas {
            if let Some(props) = def["properties"].as_object() {
                for (prop, spec) in props {
                    let stringy = spec["type"] == "string"
                        || spec["type"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|x| x == "string"));
                    if stringy && likely_free.contains(&prop.as_str()) {
                        assert!(
                            covered.contains(&(schema.as_str(), prop.as_str())),
                            "unclassified free text {schema}.{prop}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn schema_response_and_request_walks_use_web_aad_names() {
        let key = WorkspaceKey::from_entropy([9; 32]);
        let mut req = serde_json::json!({"body":"hello"});
        transform_fields(
            &mut req,
            "POST",
            "/api/v1/bus/messages",
            "w",
            Some(&key),
            true,
        )
        .unwrap();
        assert!(req["body"].as_str().unwrap().starts_with(PREFIX));
        let mut res = serde_json::json!({"messages":[{"body":req["body"].clone()}]});
        transform_fields(&mut res, "GET", "/api/v1/bus/inbox", "w", Some(&key), false).unwrap();
        assert_eq!(res["messages"][0]["body"], "hello");
    }
    #[test]
    fn enabled_encryption_errors_without_key() {
        let mut v = serde_json::json!({"body":"plain"});
        assert!(transform_fields(&mut v, "POST", "/api/v1/bus/messages", "w", None, true).is_err());
        assert_eq!(v["body"], "plain");
    }
}
