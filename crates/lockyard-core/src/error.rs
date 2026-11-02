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
    /// The file system refused.
    Io(std::io::Error),
    /// SQLite refused.
    Db(rusqlite::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProject => write!(f, "no Lockyard project here, run `lockyard init`"),
            Self::Invalid(text) | Self::NotFound(text) | Self::Denied(text) => f.write_str(text),
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
