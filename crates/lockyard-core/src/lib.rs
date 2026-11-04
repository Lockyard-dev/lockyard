// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Core of Lockyard: work zones, a message bus and tasks, all in one SQLite file under `.lockyard/`.
//!
//! Every write is one immediate transaction, so concurrent agents on one machine see a single order of
//! events. Time is passed in as milliseconds since the epoch, which keeps leases testable.

mod backend;
pub mod bus;
pub mod config;
pub mod coordination;
mod error;
pub mod machine;
pub mod paths;
pub mod proto;
mod store;
pub mod tasks;
pub mod zones;

pub use backend::Backend;
pub use error::{Error, Result};
pub use paths::ZonePath;
pub use store::{Agent, DIR_NAME, Store, validate_agent};

/// Version of this build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Home of the project.
pub const HOMEPAGE: &str = "https://lockyard.dev";

/// One line about the product.
pub const SUMMARY: &str = "Coordination for coding agents: a shared bus, work zones and tasks.";

/// Text of `lockyard about`.
pub fn about() -> String {
    format!("Lockyard {VERSION}\n{SUMMARY}\n{HOMEPAGE}")
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
