// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use crate::zones::Conflict;
use std::fmt;

/// Result of every fallible operation in the core.
pub type Result<T> = std::result::Result<T, Error>;

/// Why an operation did not happen.
#[derive(Debug)]
pub enum Error {
    /// No `.lockyard` directory in this folder or above it.
    NoProject,
    /// The input cannot be used as given.
    Invalid(String),
    /// The record does not exist or has expired.
    NotFound(String),
    /// The record exists, but this agent cannot act on it in its current state.
    Denied(String),
    /// Another agent holds at least one of the requested paths.
    Conflict(Vec<Conflict>),
    /// The server refused with a conflict that names no holder: a version mismatch or a reserved zone.
    Contended(String),
    /// The caller's fencing token is out of date: it no longer owns the claim.
    StaleFence(String),
    /// Coordination writes are frozen on the server for now.
    Frozen(String),
    /// The server could not be reached, or did not answer in time.
    Unavailable(String),
    /// The server answered with something this client cannot read.
    Protocol(String),
    /// This feature exists only in cloud mode.
    NeedsCloud(String),
    /// This feature exists only in local mode.
    NeedsLocal(String),
    /// The file system refused.
    Io(std::io::Error),
    /// SQLite refused.
    Db(rusqlite::Error),
}

impl Error {
    /// Refuses a feature that local mode does not have.
    pub fn needs_cloud(feature: &str) -> Self {
        Self::NeedsCloud(feature.to_string())
    }

    /// A stable name for the failure, for `--json` output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoProject => "no_project",
            Self::Invalid(_) => "invalid",
            Self::NotFound(_) => "not_found",
            Self::Denied(_) => "denied",
            Self::Conflict(_) | Self::Contended(_) => "conflict",
            Self::StaleFence(_) => "stale_fence",
            Self::Frozen(_) => "frozen",
            Self::Unavailable(_) => "unavailable",
            Self::Protocol(_) => "protocol",
            Self::NeedsCloud(_) => "needs_cloud",
            Self::NeedsLocal(_) => "needs_local",
            Self::Io(_) => "io",
            Self::Db(_) => "database",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProject => write!(f, "no Lockyard project here, run `lockyard init`"),
            Self::Invalid(text)
            | Self::NotFound(text)
            | Self::Denied(text)
            | Self::Contended(text)
            | Self::Protocol(text) => f.write_str(text),
            Self::StaleFence(text) => write!(f, "stale fence: {text}"),
            Self::Frozen(text) => write!(f, "coordination is frozen: {text}"),
            Self::Unavailable(text) => write!(f, "cloud unavailable: {text}"),
            Self::NeedsCloud(feature) => write!(
                f,
                "{feature} needs cloud mode: set mode = \"cloud\" in .lockyard/config.toml"
            ),
            Self::NeedsLocal(feature) => write!(f, "{feature} needs local mode"),
            Self::Conflict(conflicts) => {
                for (index, conflict) in conflicts.iter().enumerate() {
                    if index > 0 {
                        writeln!(f)?;
                    }
                    write!(f, "{conflict}")?;
                }
                Ok(())
            }
            Self::Io(error) => write!(f, "file system: {error}"),
            Self::Db(error) => write!(f, "database: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cloud_only_feature_says_how_to_get_it() {
        let text = Error::needs_cloud("zone queue").to_string();
        assert!(text.contains("zone queue needs cloud mode"));
        assert_eq!(Error::needs_cloud("x").kind(), "needs_cloud");
    }
}
