// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Monotonic server-signed access denial. Trust is provisioned separately from received pages.
use crate::Result;
use lockyard_cloud_client::revocations::verify_document;
pub use lockyard_cloud_client::revocations::{
    RevocationEntry, RevocationPage, RevocationTarget, RevocationTrust, SignedDocument,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn required() -> bool {
    true
}
fn poll() -> u64 {
    30
}
fn offline() -> u64 {
    600
}
#[cfg(unix)]
#[cfg(windows)]
use std::fs::File;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationConfig {
    #[serde(default = "required")]
    pub required: bool,
    #[serde(default = "poll")]
    pub poll_seconds: u64,
    #[serde(default = "offline")]
    pub max_offline_seconds: u64,
    pub trust: RevocationTrust,
}
impl RevocationConfig {
    pub fn validate(&self) -> Result<()> {
        if !(1..=30).contains(&self.poll_seconds)
            || !(60..=86_400).contains(&self.max_offline_seconds)
        {
            return Err("invalid_revocation_request".into());
        }
        self.trust.validate().map_err(|e| e.into())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationSnapshot {
    pub complete_epoch: u64,
    pub observed_epoch: u64,
    pub revocations_enforced: bool,
    pub key_id: String,
    pub age_seconds: Option<u64>,
    pub stale: bool,
    pub refresh_failures_total: BTreeMap<String, u64>,
    pub notify_reconnects_total: u64,
    pub quic_close_seconds: f64,
    pub legacy_direct_peers: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Persisted {
    trust: RevocationTrust,
    #[serde(default)]
    previous_trust: Vec<RevocationTrust>,
    complete_epoch: u64,
    observed_epoch: u64,
    documents: Vec<SignedDocument>,
}
type CachePruner = Box<dyn Fn(&BTreeSet<String>) + Send + Sync>;
struct State {
    complete_epoch: u64,
    observed_epoch: u64,
    deny_set: BTreeSet<String>,
    documents: Vec<SignedDocument>,
    last_fresh_monotonic: Option<Instant>,
    clock_skew: bool,
    nonces: VecDeque<String>,
    needs_full_snapshot: bool,
    previous_trust: Vec<RevocationTrust>,
    retry_refresh: Option<Option<Instant>>,
    retry_events: Option<Option<Instant>>,
    refresh_failures_total: BTreeMap<String, u64>,
    notify_reconnects_total: u64,
    quic_close_seconds: f64,
    legacy_peers: BTreeSet<String>,
    connections: Vec<(String, String, String, quinn::Connection)>,
    cache_pruners: Vec<CachePruner>,
}
pub struct RevocationManager {
    config: RevocationConfig,
    path: PathBuf,
    state: Mutex<State>,
    wake: tokio::sync::Notify,
}
impl RevocationManager {
    pub fn open(config: RevocationConfig, state_dir: &Path) -> Result<Arc<Self>> {
        config.validate()?;
        #[cfg(windows)]
        lockyard_core::windows::private_dir(state_dir)?;
        if !state_dir.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(state_dir)?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(state_dir)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
            {
                return Err("revocation_state_unavailable".into());
            }
        }
        let path = state_dir.join("revocations.json");
        let mut state = State {
            complete_epoch: 0,
            observed_epoch: 0,
            deny_set: BTreeSet::new(),
            documents: Vec::new(),
            last_fresh_monotonic: None,
            clock_skew: false,
            nonces: VecDeque::new(),
            needs_full_snapshot: true,
            previous_trust: Vec::new(),
            retry_refresh: None,
            retry_events: None,
            refresh_failures_total: BTreeMap::new(),
            notify_reconnects_total: 0,
            quic_close_seconds: 0.0,
            legacy_peers: BTreeSet::new(),
            connections: Vec::new(),
            cache_pruners: Vec::new(),
        };
        match crate::local_files::read_private(&path, 32 * 1024 * 1024) {
            Ok(bytes) => {
                let mut saved: Persisted = serde_json::from_slice(&bytes)?;
                // Only the private owner-provisioned config can select a new active key. Retain
                // prior local pins exclusively for old durable deny evidence, never network input.
                if saved.trust.workspace_id != config.trust.workspace_id
                    || saved.trust.server_origin != config.trust.server_origin
                {
                    return Err("revocation_signer_untrusted".into());
                }
                if saved.trust != config.trust && !saved.previous_trust.contains(&saved.trust) {
                    saved.previous_trust.push(saved.trust.clone());
                }
                for prior in &saved.previous_trust {
                    prior.validate()?;
                    if prior.workspace_id != config.trust.workspace_id
                        || prior.server_origin != config.trust.server_origin
                    {
                        return Err("revocation_signer_untrusted".into());
                    }
                }
                state.previous_trust = saved.previous_trust;
                for document in &saved.documents {
                    let key = std::iter::once(&config.trust)
                        .chain(state.previous_trust.iter())
                        .find(|key| key.key_id == document.key_id)
                        .ok_or("revocation_signer_untrusted")?;
                    let page = verify_document(document, key, &key.server_origin)?;
                    add_pins(&mut state, &page);
                }
                if saved.complete_epoch > saved.observed_epoch
                    || saved.observed_epoch != state.observed_epoch
                {
                    return Err("invalid_revocation_request".into());
                }
                state.complete_epoch = saved.complete_epoch;
                state.documents = saved.documents;
            }
            Err(_) if !path.exists() => {}
            Err(error) => return Err(error),
        }
        let manager = Arc::new(Self {
            config,
            path,
            state: Mutex::new(state),
            wake: tokio::sync::Notify::new(),
        });
        {
            let state = manager
                .state
                .lock()
                .map_err(|_| "revocation_state_unavailable")?;
            manager.persist(&state)?;
        }
        Ok(manager)
    }
    pub fn wake(&self) {
        self.wake.notify_one();
    }
    pub async fn notified(&self) {
        self.wake.notified().await;
    }
    pub fn reject_clock_skew(&self) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?
            .clock_skew = true;
        Ok(())
    }
    pub fn trust(&self) -> &RevocationTrust {
        &self.config.trust
    }
    pub fn config(&self) -> &RevocationConfig {
        &self.config
    }
    pub fn snapshot(&self) -> Result<RevocationSnapshot> {
        let state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        Ok(RevocationSnapshot {
            complete_epoch: state.complete_epoch,
            observed_epoch: state.observed_epoch,
            revocations_enforced: self.config.required,
            key_id: self.config.trust.key_id.clone(),
            age_seconds: state.last_fresh_monotonic.map(|t| t.elapsed().as_secs()),
            stale: state.last_fresh_monotonic.is_none_or(|t| {
                t.elapsed() >= Duration::from_secs(self.config.max_offline_seconds)
            }),
            refresh_failures_total: state.refresh_failures_total.clone(),
            notify_reconnects_total: state.notify_reconnects_total,
            quic_close_seconds: state.quic_close_seconds,
            legacy_direct_peers: state.legacy_peers.len(),
        })
    }
    fn authorize_locked(&self, state: &State, pin: &str) -> Result<()> {
        if state.deny_set.contains(pin) {
            return Err("revoked".into());
        }
        if self.config.required {
            if state.clock_skew {
                return Err("revocation_clock_skew".into());
            }
            if state.last_fresh_monotonic.is_none_or(|fresh| {
                fresh.elapsed() >= Duration::from_secs(self.config.max_offline_seconds)
            }) {
                return Err("revocations_stale".into());
            }
        }
        Ok(())
    }
    pub fn authorize_pin(&self, pin: &str) -> Result<()> {
        {
            let state = self
                .state
                .lock()
                .map_err(|_| "revocation_state_unavailable")?;
            // Legacy peer configuration accepts uppercase hex; certificate identity is byte based.
            self.authorize_locked(&state, &pin.to_ascii_lowercase())
        }
    }
    pub(crate) fn register(
        &self,
        pin: String,
        local_pin: String,
        node_id: String,
        connection: quinn::Connection,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        if let Err(error) = self
            .authorize_locked(&state, &pin)
            .and_then(|()| self.authorize_locked(&state, &local_pin))
        {
            let code = if error.to_string() == "revoked" {
                0x105u32
            } else {
                1u32
            };
            connection.close(code.into(), error.to_string().as_bytes());
            return Err(error);
        }
        state
            .connections
            .retain(|(_, _, _, conn)| conn.close_reason().is_none());
        if !state
            .connections
            .iter()
            .any(|(_, _, _, conn)| conn.stable_id() == connection.stable_id())
        {
            state
                .connections
                .push((pin, local_pin, node_id, connection));
        }
        Ok(())
    }
    pub(crate) fn register_cache_pruner(&self, pruner: CachePruner) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?
            .cache_pruners
            .push(pruner);
        Ok(())
    }
    pub fn apply_additive(&self, document: &SignedDocument) -> Result<()> {
        let received = Instant::now();
        let page = verify_document(
            document,
            &self.config.trust,
            &self.config.trust.server_origin,
        )?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        let changed = page.epoch > state.observed_epoch
            || page
                .entries
                .iter()
                .filter_map(|e| e.target.pin())
                .any(|pin| !state.deny_set.contains(pin));
        add_pins(&mut state, &page);
        if changed && !state.documents.contains(document) {
            state.documents.push(document.clone());
        }
        // Publish under the same gate used by registration before closing live handles.
        let deny = state.deny_set.clone();
        state
            .connections
            .retain(|(pin, local_pin, _node_id, conn)| {
                if deny.contains(pin) || deny.contains(local_pin) {
                    conn.close(0x105u32.into(), b"revoked");
                    false
                } else {
                    conn.close_reason().is_none()
                }
            });
        for prune in &state.cache_pruners {
            prune(&deny);
        }
        state.quic_close_seconds = received.elapsed().as_secs_f64();
        self.persist(&state)
    }
    pub fn refresh(
        &self,
        documents: &[SignedDocument],
        nonce: &str,
        now_ms: u64,
        started: Instant,
    ) -> Result<()> {
        if nonce.len() != 64
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || documents.is_empty()
        {
            return Err("invalid_revocation_request".into());
        }
        let pages = documents
            .iter()
            .map(|doc| verify_document(doc, &self.config.trust, &self.config.trust.server_origin))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let first = &pages[0];
        let mut state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        if first.issued_at_ms > now_ms.saturating_add(30_000) {
            state.clock_skew = true;
            return Err("revocation_clock_skew".into());
        }
        if (state.needs_full_snapshot && first.from_epoch != 0)
            || state.nonces.iter().any(|used| used == nonce)
            || started > Instant::now()
        {
            return Err("invalid_revocation_request".into());
        }
        if now_ms >= first.valid_until_ms
            || first.epoch < state.observed_epoch
            || (first.from_epoch != 0 && first.from_epoch != state.complete_epoch)
        {
            return Err("invalid_revocation_request".into());
        }
        let mut previous: Option<(u64, u32)> = None;
        for (index, page) in pages.iter().enumerate() {
            if page.nonce != nonce
                || page.page_index as usize != index
                || page.snapshot_id != first.snapshot_id
                || page.from_epoch != first.from_epoch
                || page.epoch != first.epoch
                || page.issued_at_ms != first.issued_at_ms
                || page.valid_until_ms != first.valid_until_ms
                || page.next_cursor.is_some() != (index + 1 < pages.len())
            {
                return Err("invalid_revocation_request".into());
            }
            for entry in &page.entries {
                match previous {
                    Some((epoch, ordinal))
                        if entry.epoch == epoch
                            && ordinal.checked_add(1) == Some(entry.ordinal) => {}
                    Some((epoch, _))
                        if epoch.checked_add(1) == Some(entry.epoch) && entry.ordinal == 0 => {}
                    None if entry.epoch == first.from_epoch + 1 && entry.ordinal == 0 => {}
                    _ => return Err("invalid_revocation_request".into()),
                }
                previous = Some((entry.epoch, entry.ordinal));
            }
        }
        if previous.map(|(epoch, _)| epoch).unwrap_or(first.from_epoch) != first.epoch {
            return Err("invalid_revocation_request".into());
        }
        for (page, document) in pages.iter().zip(documents) {
            let changed = page.epoch > state.observed_epoch
                || page
                    .entries
                    .iter()
                    .filter_map(|e| e.target.pin())
                    .any(|pin| !state.deny_set.contains(pin));
            add_pins(&mut state, page);
            if changed && !state.documents.contains(document) {
                state.documents.push(document.clone());
            }
        }
        let previous_complete = state.complete_epoch;
        state.complete_epoch = first.epoch;
        state.observed_epoch = state.observed_epoch.max(first.epoch);
        let deny = state.deny_set.clone();
        state
            .connections
            .retain(|(pin, local_pin, _node_id, conn)| {
                if deny.contains(pin) || deny.contains(local_pin) {
                    conn.close(0x105u32.into(), b"revoked");
                    false
                } else {
                    conn.close_reason().is_none()
                }
            });
        for prune in &state.cache_pruners {
            prune(&deny);
        }
        if let Err(error) = self.persist(&state) {
            state.complete_epoch = previous_complete;
            return Err(error);
        }
        state.last_fresh_monotonic = Some(started);
        state.clock_skew = false;
        state.needs_full_snapshot = false;
        state.nonces.push_back(nonce.to_owned());
        if state.nonces.len() > 4096 {
            state.nonces.pop_front();
        }
        Ok(())
    }
    pub fn refresh_from_epoch(&self) -> Result<u64> {
        let state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        Ok(if state.needs_full_snapshot {
            0
        } else {
            state.complete_epoch
        })
    }
    pub fn retry_delay(&self, events: bool) -> Result<Duration> {
        let state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        Ok(
            match if events {
                state.retry_events
            } else {
                state.retry_refresh
            } {
                None => Duration::ZERO,
                Some(None) => Duration::MAX,
                Some(Some(until)) => until.saturating_duration_since(Instant::now()),
            },
        )
    }
    pub fn record_http_failure(
        &self,
        events: bool,
        error: &lockyard_cloud_client::revocations::RevocationError,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?;
        let code = match error.code() {
            "rate_limited"
            | "revocation_state_unavailable"
            | "revocation_signer_unavailable"
            | "revocation_protocol_unavailable"
            | "revocation_signer_untrusted"
            | "revocation_clock_skew"
            | "revocations_stale"
            | "invalid_revocation_request"
            | "credential_revoked"
            | "sso_session_revoked"
            | "unauthorized"
            | "forbidden"
            | "machine_scope"
            | "temporarily_unavailable"
            | "server_draining" => error.code(),
            _ => "unknown",
        };
        if !events {
            *state.refresh_failures_total.entry(code.into()).or_default() += 1;
        }
        if matches!(
            error.code(),
            "credential_revoked" | "sso_session_revoked" | "unauthorized"
        ) {
            state.retry_refresh = Some(None);
            state.retry_events = Some(None);
        } else if let Some(seconds) = error.retry_after {
            let deadline = Some(Instant::now().checked_add(Duration::from_secs(seconds)));
            if events {
                state.retry_events = deadline;
            } else {
                state.retry_refresh = deadline;
            }
        }
        Ok(())
    }
    pub fn record_notify_reconnect(&self) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?
            .notify_reconnects_total += 1;
        Ok(())
    }
    pub fn record_legacy_peer(&self, node: &str) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| "revocation_state_unavailable")?
            .legacy_peers
            .insert(node.into());
        Ok(())
    }
    fn persist(&self, state: &State) -> Result<()> {
        let bytes = serde_json::to_vec(&Persisted {
            trust: self.config.trust.clone(),
            previous_trust: state.previous_trust.clone(),
            complete_epoch: state.complete_epoch,
            observed_epoch: state.observed_epoch,
            documents: state.documents.clone(),
        })?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err("revocation_state_unavailable".into());
        }
        let temp = self.path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        lockyard_core::fsio::rename(&temp, &self.path)?;
        lockyard_core::fsio::sync_path(self.path.parent().ok_or("revocation_state_unavailable")?)?;
        Ok(())
    }
}
fn add_pins(state: &mut State, page: &RevocationPage) {
    state.observed_epoch = state.observed_epoch.max(page.epoch);
    for entry in &page.entries {
        if let RevocationTarget::Machine {
            certificate_sha256, ..
        }
        | RevocationTarget::CertPin { certificate_sha256 } = &entry.target
        {
            state.deny_set.insert(certificate_sha256.clone());
        }
    }
}

#[cfg(windows)]
use lockyard_core::windows::OpenOptions;
#[cfg(unix)]
use std::fs::OpenOptions;
