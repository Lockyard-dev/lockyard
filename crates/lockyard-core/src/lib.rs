// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Core of Lockyard: work zones, a message bus and tasks, all in one SQLite file under `.lockyard/`.
//!
//! Every write is one immediate transaction, so concurrent agents on one machine see a single order of
//! events. Time is passed in as milliseconds since the epoch, which keeps leases testable.

mod admission;
mod backend;
pub mod bus;
pub mod catalog;
pub mod config;
pub mod coordination;
pub mod credentials;
mod error;
pub mod fsio;
pub mod machine;
pub mod outside;
pub mod paths;
pub mod proto;
pub mod repository;
mod store;
pub mod task_id;
pub mod tasks;
pub mod watch;
pub mod zones;

pub use backend::{
    Backend, claim_or_reuse, claim_or_reuse_with_creation_status, claim_or_reuse_with_status,
};
pub use error::{Error, Result};
pub use paths::ZonePath;
pub use store::{Agent, DIR_NAME, Store, validate_agent};

/// Version of this build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Full source revision, or `unknown` when building a source archive without Git.
pub const GIT_SHA: &str = env!("LOCKYARD_GIT_SHA");

/// Build time as Unix seconds; SOURCE_DATE_EPOCH can pin it for reproducible builds.
pub const BUILD_TIME: &str = env!("LOCKYARD_BUILD_TIME");

/// Human-readable semantic version and source/build identity.
pub const BUILD_VERSION: &str = env!("LOCKYARD_BUILD_VERSION");

/// Shared build identity for diagnostic surfaces.
pub fn build_info() -> serde_json::Value {
    serde_json::json!({"semver": VERSION, "git_sha": GIT_SHA, "built_at_unix": BUILD_TIME})
}

/// Home of the project.
pub const HOMEPAGE: &str = "https://lockyard.dev";

/// One line about the product.
pub const SUMMARY: &str = "Coordination for coding agents: a shared bus, work zones and tasks.";

/// Text of `lockyard about`.
pub fn about() -> String {
    format!("Lockyard {BUILD_VERSION}\n{SUMMARY}\n{HOMEPAGE}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn about_names_the_version_and_the_homepage() {
        let text = about();
        assert!(text.contains(VERSION));
        assert!(text.contains(HOMEPAGE));
    }
}
