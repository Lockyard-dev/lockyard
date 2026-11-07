// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Authenticated node protocol and bounded persistent transports.
pub mod approvals;
pub mod archive;
mod bounded_dns;
pub mod cloud;
pub mod crypto;
pub mod delegation;
pub mod executor;
pub mod host;
pub mod incarnation;
pub mod invites;
mod job_notifications;
mod local_files;
pub mod provenance;
pub mod quic;
pub mod relay;
pub mod retention;
pub mod rotation;
pub mod rotation_install;
pub mod scheduler;
pub mod secrets;
pub mod supply_chain;
pub mod updates;
pub mod wire;
pub mod workflow;

/// Transport failures do not establish whether an already sent request executed.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
