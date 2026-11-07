// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! A workload receives a dedicated RPC capability, never the operator control socket.
use crate::Result;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

pub trait DelegationProvider: Send + Sync {
    fn prepare(&self, parent_job_id: &str, job_dir: &Path) -> Result<DelegationLease>;
}

/// The executor keeps this lease alive only while its main workload can delegate.
/// The directory is read-only in that workload and is never mounted in Git helpers.
pub struct DelegationLease {
    pub directory: PathBuf,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}
impl DelegationLease {
    pub(crate) fn new(directory: PathBuf, cleanup: impl FnOnce() + Send + 'static) -> Self {
        Self {
            directory,
            cleanup: Some(Box::new(cleanup)),
        }
    }
}
impl Drop for DelegationLease {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

/// Queue recovery may begin before Host's Arc is constructed. Hold delegation
/// preparation at a bounded, fail-closed startup barrier until its weak adapter is ready.
#[derive(Default)]
pub struct DeferredDelegation {
    provider: Mutex<Option<Arc<dyn DelegationProvider>>>,
    changed: Condvar,
}
impl DeferredDelegation {
    pub fn bind(&self, provider: Arc<dyn DelegationProvider>) -> Result<()> {
        let mut slot = self
            .provider
            .lock()
            .map_err(|_| "delegation startup unavailable")?;
        if slot.is_some() {
            return Err("delegation startup was already bound".into());
        }
        *slot = Some(provider);
        self.changed.notify_all();
        Ok(())
    }
}
impl DelegationProvider for DeferredDelegation {
    fn prepare(&self, parent_job_id: &str, job_dir: &Path) -> Result<DelegationLease> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut slot = self
            .provider
            .lock()
            .map_err(|_| "delegation startup unavailable")?;
        let provider = loop {
            if let Some(provider) = slot.as_ref() {
                break provider.clone();
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("delegation startup timed out")?;
            let (next, wait) = self
                .changed
                .wait_timeout(slot, remaining)
                .map_err(|_| "delegation startup unavailable")?;
            slot = next;
            if wait.timed_out() && slot.is_none() {
                return Err("delegation startup timed out".into());
            }
        };
        drop(slot);
        provider.prepare(parent_job_id, job_dir)
    }
}
