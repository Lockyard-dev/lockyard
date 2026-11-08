// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Node-side secret references. Plaintext values never implement Debug or Serialize.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::fs;

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: u64 = 128 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBinding {
    pub name: String,
    pub environment: Option<String>,
    pub source: SecretSource,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretSource {
    LocalFile {
        path: PathBuf,
    },
    VaultKvV2 {
        identity: VaultIdentity,
        mount: String,
        path: String,
        field: String,
    },
    VaultTransit {
        identity: VaultIdentity,
        mount: String,
        key: String,
        ciphertext_file: PathBuf,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultIdentity {
    pub url: String,
    /// A customer Vault agent may renew/replace this private node-side token file.
    pub token_file: PathBuf,
    #[serde(default)]
    pub tls_roots: Vec<PathBuf>,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretError(pub &'static str);
impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for SecretError {}
type Result<T> = std::result::Result<T, SecretError>;

/// A local plaintext value. Keep its lifetime limited to the admitted workload.
pub struct ResolvedSecret {
    pub name: String,
    pub environment: Option<String>,
    value: Vec<u8>,
}
impl ResolvedSecret {
    pub fn bytes(&self) -> &[u8] {
        &self.value
    }
}

fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn vault_path(value: &str) -> bool {
    value.len() <= 1024 && value.split('/').all(component)
}

impl SecretBinding {
    pub fn validate(&self) -> Result<()> {
        if !component(&self.name) || self.name.len() > 64 {
            return Err(SecretError("invalid_secret_reference"));
        }
        if self
            .environment
            .as_deref()
            .is_some_and(|name| !safe_environment_name(name))
        {
            return Err(SecretError("invalid_secret_environment_name"));
        }
        match &self.source {
            SecretSource::LocalFile { path } => {
                if !path.is_absolute() {
                    return Err(SecretError("secret_path_must_be_absolute"));
                }
            }
            SecretSource::VaultKvV2 {
                identity,
                mount,
                path,
                field,
            } => {
                identity.validate()?;
                if !component(mount) || !vault_path(path) || !component(field) {
                    return Err(SecretError("invalid_vault_reference"));
                }
            }
            SecretSource::VaultTransit {
                identity,
                mount,
                key,
                ciphertext_file,
            } => {
                identity.validate()?;
                if !component(mount) || !component(key) || !ciphertext_file.is_absolute() {
                    return Err(SecretError("invalid_vault_reference"));
                }
            }
        }
        Ok(())
    }
}

fn safe_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.as_bytes()[0].is_ascii_digit()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && ![
            "LOCKYARD_",
            "XDG_",
            "DOCKER_",
            "PODMAN_",
            "CONTAINER_",
            "LD_",
            "DYLD_",
            "GIT_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
        && ![
            "HOME",
            "PATH",
            "TMPDIR",
            "ENV",
            "BASH_ENV",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PYTHONHOME",
            "RUBYOPT",
            "PERL5OPT",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ]
        .contains(&name)
}

impl VaultIdentity {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.url).map_err(|_| SecretError("invalid_vault_endpoint"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || !self.token_file.is_absolute()
            || self.tls_roots.len() > 16
            || self.tls_roots.iter().any(|p| !p.is_absolute())
            || self.namespace.as_ref().is_some_and(|n| !vault_path(n))
        {
            return Err(SecretError("invalid_vault_endpoint"));
        }
        Ok(())
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Value> {
        check_budget(deadline, cancelled)?;
        self.validate()?;
        let token = read_private(&self.token_file, 4096)?;
        let token = std::str::from_utf8(&token)
            .map_err(|_| SecretError("invalid_vault_identity"))?
            .trim();
        if token.is_empty() || token.bytes().any(|b| b.is_ascii_control()) {
            return Err(SecretError("invalid_vault_identity"));
        }
        let roots = self
            .tls_roots
            .iter()
            .map(|path| {
                #[cfg(unix)]
                use std::os::unix::fs::OpenOptionsExt;
                check_budget(deadline, cancelled)?;
                #[cfg(unix)]
                let file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                    .open(path)
                    .map_err(|_| SecretError("vault_trust_unavailable"))?;
                #[cfg(windows)]
                let file = lockyard_core::windows::open_public(path)
                    .map_err(|_| SecretError("vault_trust_unavailable"))?;
                let metadata = file
                    .metadata()
                    .map_err(|_| SecretError("vault_trust_unavailable"))?;
                if !metadata.is_file() || metadata.len() > 64 * 1024 {
                    return Err(SecretError("vault_trust_unavailable"));
                }
                let mut bytes = Vec::new();
                file.take(64 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| SecretError("vault_trust_unavailable"))?;
                check_budget(deadline, cancelled)?;
                if bytes.len() > 64 * 1024 {
                    return Err(SecretError("vault_trust_unavailable"));
                }
                Ok(bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut url =
            url::Url::parse(&self.url).map_err(|_| SecretError("invalid_vault_endpoint"))?;
        url.set_path(path);
        let tls = crate::relay::tls(&roots).map_err(|_| SecretError("vault_trust_unavailable"))?;
        check_budget(deadline, cancelled)?;
        let dns_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
        let client = ureq::AgentBuilder::new()
            .resolver(move |netloc: &str| crate::bounded_dns::resolve(netloc, dns_deadline))
            .try_proxy_from_env(!crate::relay::bypass_proxy(&url))
            .redirects(0)
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .timeout_write(Duration::from_secs(10))
            .tls_config(tls)
            .build();
        let remaining = check_budget(deadline, cancelled)?;
        let mut request = client
            .request(method, url.as_str())
            .timeout(remaining.min(Duration::from_secs(10)))
            .set("X-Vault-Token", token)
            .set("Accept", "application/json");
        if let Some(namespace) = &self.namespace {
            request = request.set("X-Vault-Namespace", namespace);
        }
        check_budget(deadline, cancelled)?;
        let response = match body {
            Some(value) => request
                .set("Content-Type", "application/json")
                .send_string(&value.to_string()),
            None => request.call(),
        };
        check_budget(deadline, cancelled)?;
        let response = response.map_err(|_| SecretError("vault_request_failed"))?;
        if response.status() != 200 {
            return Err(SecretError("vault_request_failed"));
        }
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SecretError("vault_response_unavailable"))?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(SecretError("vault_response_too_large"));
        }
        check_budget(deadline, cancelled)?;
        serde_json::from_slice(&bytes).map_err(|_| SecretError("invalid_vault_response"))
    }
}

pub fn resolve(bindings: &[SecretBinding]) -> Result<Vec<ResolvedSecret>> {
    resolve_with_budget(
        bindings,
        Instant::now() + Duration::from_secs(30),
        &AtomicBool::new(false),
    )
}

fn check_budget(deadline: Instant, cancelled: &AtomicBool) -> Result<Duration> {
    if cancelled.load(Ordering::SeqCst) {
        return Err(SecretError("secret_fetch_cancelled"));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SecretError("secret_fetch_timed_out"));
    }
    Ok(remaining)
}

pub fn resolve_with_budget(
    bindings: &[SecretBinding],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<ResolvedSecret>> {
    check_budget(deadline, cancelled)?;
    if bindings.len() > 64 {
        return Err(SecretError("too_many_secret_references"));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut environments = std::collections::BTreeSet::new();
    // Check every reference before the first credential-bearing network request.
    for binding in bindings {
        check_budget(deadline, cancelled)?;
        binding.validate()?;
        if !names.insert(&binding.name) {
            return Err(SecretError("duplicate_secret_reference"));
        }
        if let Some(name) = &binding.environment
            && !environments.insert(name)
        {
            return Err(SecretError("duplicate_secret_environment"));
        }
    }
    bindings
        .iter()
        .map(|binding| {
            check_budget(deadline, cancelled)?;
            let value = match &binding.source {
                SecretSource::LocalFile { path } => read_private(path, MAX_SECRET_BYTES)?,
                SecretSource::VaultKvV2 {
                    identity,
                    mount,
                    path,
                    field,
                } => {
                    let response = identity.request(
                        "GET",
                        &format!("/v1/{mount}/data/{path}"),
                        None,
                        deadline,
                        cancelled,
                    )?;
                    response
                        .get("data")
                        .and_then(|d| d.get("data"))
                        .and_then(|d| d.get(field))
                        .and_then(Value::as_str)
                        .ok_or(SecretError("invalid_vault_secret"))?
                        .as_bytes()
                        .to_vec()
                }
                SecretSource::VaultTransit {
                    identity,
                    mount,
                    key,
                    ciphertext_file,
                } => {
                    let ciphertext = read_private(ciphertext_file, MAX_SECRET_BYTES)?;
                    let ciphertext = std::str::from_utf8(&ciphertext)
                        .map_err(|_| SecretError("invalid_kms_ciphertext"))?
                        .trim();
                    if !valid_transit_ciphertext(ciphertext) {
                        return Err(SecretError("invalid_kms_ciphertext"));
                    }
                    let response = identity.request(
                        "POST",
                        &format!("/v1/{mount}/decrypt/{key}"),
                        Some(json!({"ciphertext":ciphertext})),
                        deadline,
                        cancelled,
                    )?;
                    let plaintext = response
                        .get("data")
                        .and_then(|d| d.get("plaintext"))
                        .and_then(Value::as_str)
                        .ok_or(SecretError("invalid_kms_response"))?;
                    STANDARD
                        .decode(plaintext)
                        .map_err(|_| SecretError("invalid_kms_response"))?
                }
            };
            check_budget(deadline, cancelled)?;
            if value.is_empty() || value.len() > MAX_SECRET_BYTES {
                return Err(SecretError("secret_size_invalid"));
            }
            if binding.environment.is_some()
                && (std::str::from_utf8(&value).is_err()
                    || value.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')))
            {
                return Err(SecretError("secret_environment_must_be_one_utf8_line"));
            }
            Ok(ResolvedSecret {
                name: binding.name.clone(),
                environment: binding.environment.clone(),
                value,
            })
        })
        .collect()
}

fn valid_transit_ciphertext(value: &str) -> bool {
    let Some((version, encoded)) = value
        .strip_prefix("vault:v")
        .and_then(|v| v.split_once(':'))
    else {
        return false;
    };
    value.len() <= MAX_SECRET_BYTES
        && version.parse::<u32>().is_ok_and(|version| version > 0)
        && STANDARD
            .decode(encoded)
            .is_ok_and(|bytes| !bytes.is_empty() && STANDARD.encode(bytes) == encoded)
}

/// Stage only configured references. The caller supplies all node identity/key paths
/// that may never be delegated as a workload secret, including canonical aliases.
pub fn stage(
    job_dir: &Path,
    bindings: &[SecretBinding],
    forbidden: &[PathBuf],
) -> Result<Vec<ResolvedSecret>> {
    stage_with_budget(
        job_dir,
        bindings,
        forbidden,
        Instant::now() + Duration::from_secs(30),
        &AtomicBool::new(false),
    )
}

pub fn stage_with_budget(
    job_dir: &Path,
    bindings: &[SecretBinding],
    forbidden: &[PathBuf],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<ResolvedSecret>> {
    check_budget(deadline, cancelled)?;
    check_protected_references(bindings, forbidden)?;
    let resolved = resolve_with_budget(bindings, deadline, cancelled)?;
    if resolved.is_empty() {
        return Ok(resolved);
    }
    let directory = job_dir.join("runtime-secrets");
    stage_resolved(job_dir, directory, resolved, deadline, cancelled)
}

/// Validate references without reading any secret value or contacting a provider.
pub fn check_protected_references(bindings: &[SecretBinding], forbidden: &[PathBuf]) -> Result<()> {
    if bindings.is_empty() {
        return Ok(());
    }
    if bindings.len() > 64 {
        return Err(SecretError("too_many_secret_references"));
    }
    let protected = forbidden
        .iter()
        .map(|path| canonical_reservation(path))
        .collect::<Result<Vec<_>>>()?;
    for binding in bindings {
        binding.validate()?;
        let paths: Vec<&Path> = match &binding.source {
            SecretSource::LocalFile { path } => vec![path],
            SecretSource::VaultKvV2 { identity, .. } => vec![&identity.token_file],
            SecretSource::VaultTransit {
                identity,
                ciphertext_file,
                ..
            } => vec![&identity.token_file, ciphertext_file],
        };
        for path in paths {
            let canonical = path
                .canonicalize()
                .map_err(|_| SecretError("secret_file_unavailable"))?;
            if protected.iter().any(|protected| {
                canonical == *protected || protected.is_dir() && canonical.starts_with(protected)
            }) {
                return Err(SecretError("protected_identity_cannot_be_delegated"));
            }
        }
    }
    Ok(())
}

/// Future rotation/control files are reserved before they exist. Resolve their
/// nearest existing ancestor so a missing journal neither disables secrets nor
/// silently drops a protected identity reservation.
fn canonical_reservation(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(SecretError("protected_identity_unavailable"));
    }
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    ancestor
                        .file_name()
                        .ok_or(SecretError("protected_identity_unavailable"))?
                        .to_os_string(),
                );
                ancestor = ancestor
                    .parent()
                    .ok_or(SecretError("protected_identity_unavailable"))?;
            }
            Err(_) => return Err(SecretError("protected_identity_unavailable")),
        }
    }
}

pub(crate) fn check_private_reference(path: &Path, forbidden: &[PathBuf]) -> Result<()> {
    check_protected_references(
        &[SecretBinding {
            name: "private_reference".into(),
            environment: None,
            source: SecretSource::LocalFile { path: path.into() },
        }],
        forbidden,
    )
}

fn stage_resolved(
    job_dir: &Path,
    directory: PathBuf,
    resolved: Vec<ResolvedSecret>,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<ResolvedSecret>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| SecretError("secret_staging_failed"))?;
        lockyard_core::fsio::sync_path(job_dir)
            .map_err(|_| SecretError("secret_staging_failed"))?;
        for secret in &resolved {
            check_budget(deadline, cancelled)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(directory.join(&secret.name))
                .map_err(|_| SecretError("secret_staging_failed"))?;
            file.write_all(secret.bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| SecretError("secret_staging_failed"))?;
        }
        let environment: Vec<_> = resolved
            .iter()
            .filter_map(|secret| secret.environment.as_ref().map(|name| (name, secret)))
            .collect();
        if !environment.is_empty() {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(directory.join(".environment"))
                .map_err(|_| SecretError("secret_staging_failed"))?;
            for (name, secret) in environment {
                file.write_all(name.as_bytes())
                    .and_then(|_| file.write_all(b"="))
                    .and_then(|_| file.write_all(secret.bytes()))
                    .and_then(|_| file.write_all(b"\n"))
                    .map_err(|_| SecretError("secret_staging_failed"))?;
            }
            file.sync_all()
                .map_err(|_| SecretError("secret_staging_failed"))?;
        }
        lockyard_core::fsio::sync_path(&directory)
            .map_err(|_| SecretError("secret_staging_failed"))?;
        Ok(resolved)
    }
    #[cfg(windows)]
    {
        let _ = job_dir;
        lockyard_core::windows::private_dir(&directory)
            .map_err(|_| SecretError("secret_staging_failed"))?;
        for secret in &resolved {
            check_budget(deadline, cancelled)?;
            let mut file = lockyard_core::windows::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(&secret.name))
                .map_err(|_| SecretError("secret_staging_failed"))?;
            file.write_all(secret.bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| SecretError("secret_staging_failed"))?;
        }
        let environment: Vec<_> = resolved
            .iter()
            .filter_map(|secret| secret.environment.as_ref().map(|name| (name, secret)))
            .collect();
        if !environment.is_empty() {
            let mut file = lockyard_core::windows::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join(".environment"))
                .map_err(|_| SecretError("secret_staging_failed"))?;
            for (name, secret) in environment {
                file.write_all(name.as_bytes())
                    .and_then(|()| file.write_all(b"="))
                    .and_then(|()| file.write_all(secret.bytes()))
                    .and_then(|()| file.write_all(b"\n"))
                    .map_err(|_| SecretError("secret_staging_failed"))?;
            }
            file.sync_all()
                .map_err(|_| SecretError("secret_staging_failed"))?;
        }
        Ok(resolved)
    }
}

#[cfg(unix)]
fn read_private(path: &Path, max: usize) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !path.is_absolute() {
        return Err(SecretError("secret_path_must_be_absolute"));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| SecretError("secret_file_unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| SecretError("secret_file_unavailable"))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > max as u64
    {
        return Err(SecretError("secret_file_not_private"));
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretError("secret_file_unavailable"))?;
    if bytes.len() > max {
        return Err(SecretError("secret_size_invalid"));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_private(path: &Path, max: usize) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(SecretError("secret_path_must_be_absolute"));
    }
    lockyard_core::windows::read_private(path, max as u64)
        .map_err(|_| SecretError("secret_file_not_private"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    fn tls_fixture(
        status: u16,
        response: Value,
    ) -> (
        VaultIdentity,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        std::thread::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        use std::{
            io::{BufRead, BufReader},
            net::TcpListener,
            os::unix::fs::PermissionsExt,
            sync::{Arc, Mutex},
        };
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("vault-token");
        fs::write(&token, b"synthetic-vault-credential").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root = directory.path().join("root.der");
        fs::write(&root, cert.der()).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(Arc::new(config)).unwrap(),
                socket,
            );
            let mut reader = BufReader::new(&mut stream);
            let mut request = String::new();
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) if line == "\r\n" => break,
                    Ok(_) => request.push_str(&line),
                }
            }
            let length = request
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            request.push_str(&String::from_utf8(body).unwrap());
            seen.lock().unwrap().push(request);
            let body = response.to_string();
            write!(stream,"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            stream.flush().unwrap();
        });
        (
            VaultIdentity {
                url: format!("https://localhost:{port}"),
                token_file: token,
                tls_roots: vec![root],
                namespace: Some("team".into()),
            },
            requests,
            server,
            directory,
        )
    }

    #[cfg(unix)]
    #[test]
    fn vault_trust_fifo_is_rejected_within_budget_before_any_provider_contact() {
        use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
        let root = tempfile::tempdir().unwrap();
        let token = root.path().join("vault.token");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token)
            .unwrap()
            .write_all(b"synthetic")
            .unwrap();
        let fifo = root.path().join("trust.fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let binding = SecretBinding {
            name: "secret".into(),
            environment: None,
            source: SecretSource::VaultKvV2 {
                identity: VaultIdentity {
                    url: format!(
                        "https://localhost:{}",
                        listener.local_addr().unwrap().port()
                    ),
                    token_file: token,
                    tls_roots: vec![fifo],
                    namespace: None,
                },
                mount: "secret".into(),
                path: "project".into(),
                field: "value".into(),
            },
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = resolve_with_budget(
                &[binding],
                Instant::now() + Duration::from_millis(100),
                &AtomicBool::new(false),
            );
            let _ = tx.send(result.err().unwrap().0);
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "vault_trust_unavailable"
        );
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    #[cfg(unix)]
    fn nonexistent_control_reservations_do_not_disable_other_secret_profiles() {
        use std::os::unix::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let secret = root.path().join("customer.secret");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&secret)
            .unwrap()
            .write_all(b"synthetic")
            .unwrap();
        let reserved = root.path().join("future-control/nested/pending.json");
        check_private_reference(&secret, std::slice::from_ref(&reserved)).unwrap();
        fs::create_dir_all(reserved.parent().unwrap()).unwrap();
        fs::write(&reserved, b"future-identity").unwrap();
        assert_eq!(
            check_private_reference(&reserved, std::slice::from_ref(&reserved))
                .unwrap_err()
                .0,
            "protected_identity_cannot_be_delegated"
        );
    }

    #[test]
    #[cfg(unix)]
    fn vault_kv_and_transit_use_verified_tls_and_node_local_credentials() {
        let (identity, requests, server, _directory) = tls_fixture(
            200,
            json!({"data":{"data":{"provider_key":"synthetic-provider-secret"}}}),
        );
        let secrets = resolve(&[SecretBinding {
            name: "provider".into(),
            environment: None,
            source: SecretSource::VaultKvV2 {
                identity,
                mount: "customer".into(),
                path: "project/provider".into(),
                field: "provider_key".into(),
            },
        }])
        .unwrap();
        server.join().unwrap();
        assert_eq!(secrets[0].bytes(), b"synthetic-provider-secret");
        let request = requests.lock().unwrap()[0].to_ascii_lowercase();
        assert!(request.starts_with("get /v1/customer/data/project/provider "));
        assert!(request.contains("x-vault-token: synthetic-vault-credential"));
        assert!(request.contains("x-vault-namespace: team"));
        let (identity, requests, server, directory) = tls_fixture(
            200,
            json!({"data":{"plaintext":STANDARD.encode(b"synthetic-kms-secret")}}),
        );
        use std::os::unix::fs::PermissionsExt;
        let wrapped = directory.path().join("wrapped");
        fs::write(&wrapped, "vault:v1:c3ludGhldGlj").unwrap();
        fs::set_permissions(&wrapped, fs::Permissions::from_mode(0o600)).unwrap();
        let secrets = resolve(&[SecretBinding {
            name: "provider".into(),
            environment: None,
            source: SecretSource::VaultTransit {
                identity,
                mount: "transit".into(),
                key: "project".into(),
                ciphertext_file: wrapped,
            },
        }])
        .unwrap();
        server.join().unwrap();
        assert_eq!(secrets[0].bytes(), b"synthetic-kms-secret");
        let request = &requests.lock().unwrap()[0];
        assert!(request.starts_with("POST /v1/transit/decrypt/project "));
        assert!(request.contains("vault:v1:c3ludGhldGlj"));
        assert!(!request.contains("synthetic-kms-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn vault_refuses_untrusted_tls_before_transmitting_credential() {
        let (mut identity, requests, server, _directory) =
            tls_fixture(200, json!({"data":{"data":{"provider_key":"synthetic"}}}));
        identity.tls_roots.clear();
        let result = resolve(&[SecretBinding {
            name: "provider".into(),
            environment: None,
            source: SecretSource::VaultKvV2 {
                identity,
                mount: "customer".into(),
                path: "project/provider".into(),
                field: "provider_key".into(),
            },
        }]);
        assert!(result.is_err());
        server.join().unwrap();
        assert!(requests.lock().unwrap().is_empty());
    }
    #[test]
    fn vault_reference_and_ciphertext_are_bounded_and_structured() {
        let directory = tempfile::tempdir().unwrap();
        let mut identity = VaultIdentity {
            url: "https://vault.example".into(),
            token_file: directory.path().canonicalize().unwrap().join("vault-token"),
            tls_roots: vec![],
            namespace: None,
        };
        assert!(identity.validate().is_ok());
        for endpoint in [
            "http://vault.example",
            "https://user:secret@vault.example",
            "https://vault.example?token=hidden",
            "https://vault.example/#hidden",
            "https://vault.example/unconfigured-prefix",
        ] {
            identity.url = endpoint.into();
            assert!(identity.validate().is_err());
        }
        assert!(valid_transit_ciphertext("vault:v1:c3ludGhldGlj"));
        for value in [
            "vault:vsecret",
            "vault:v0:c3ludGhldGlj",
            "vault:v1:raw plaintext",
            "vault:v1:",
            "vault:v1:c3ludGhldGlj\n",
        ] {
            assert!(!valid_transit_ciphertext(value));
        }
        assert!(!vault_path("../secrets"));
        assert!(!vault_path("safe//secrets"));
    }

    #[cfg(unix)]
    #[test]
    fn local_files_stage_privately_and_refuse_links_duplicates_and_identity_aliases() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("customer-secret");
        fs::write(&secret, b"synthetic-private-value").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let binding = SecretBinding {
            name: "provider-key".into(),
            environment: Some("OPENAI_API_KEY".into()),
            source: SecretSource::LocalFile {
                path: secret.clone(),
            },
        };
        let job = directory.path().join("job");
        fs::create_dir(&job).unwrap();
        let staged = stage(&job, std::slice::from_ref(&binding), &[]).unwrap();
        assert_eq!(staged[0].bytes(), b"synthetic-private-value");
        assert_eq!(
            fs::read(job.join("runtime-secrets/.environment")).unwrap(),
            b"OPENAI_API_KEY=synthetic-private-value\n"
        );
        assert_eq!(
            fs::metadata(job.join("runtime-secrets/provider-key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            stage(
                &job,
                std::slice::from_ref(&binding),
                std::slice::from_ref(&secret)
            )
            .is_err()
        );
        assert!(resolve(&[binding.clone(), binding.clone()]).is_err());
        let linked = directory.path().join("linked");
        symlink(&secret, &linked).unwrap();
        assert!(read_private(&linked, MAX_SECRET_BYTES).is_err());
        fs::remove_file(&linked).unwrap();
        fs::hard_link(&secret, &linked).unwrap();
        assert!(read_private(&secret, MAX_SECRET_BYTES).is_err());
        fs::remove_file(&linked).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(resolve(&[binding]).is_err());
    }

    #[test]
    fn cancelled_or_expired_fetch_refuses_before_reading_and_reserved_environment_is_rejected() {
        let reference = SecretBinding {
            name: "fixture".into(),
            environment: None,
            source: SecretSource::LocalFile {
                path: "/does-not-exist/fixture".into(),
            },
        };
        assert_eq!(
            resolve_with_budget(
                std::slice::from_ref(&reference),
                Instant::now() + Duration::from_secs(30),
                &AtomicBool::new(true)
            )
            .err()
            .unwrap()
            .0,
            "secret_fetch_cancelled"
        );
        assert_eq!(
            resolve_with_budget(
                &[reference],
                Instant::now() - Duration::from_secs(1),
                &AtomicBool::new(false)
            )
            .err()
            .unwrap()
            .0,
            "secret_fetch_timed_out"
        );
        assert!(safe_environment_name("OPENAI_API_KEY"));
        for name in [
            "PATH",
            "LD_PRELOAD",
            "LOCKYARD_TOKEN",
            "HTTP_PROXY",
            "NODE_OPTIONS",
            "KEY=value",
            "lowercase",
            "1KEY",
        ] {
            assert!(!safe_environment_name(name));
        }
    }

    #[cfg(unix)]
    #[test]
    fn fifo_secret_reference_is_rejected_without_blocking_open() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fifo");
        let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(read_private(&path, MAX_SECRET_BYTES).is_err())
                .unwrap()
        });
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
    }
}
