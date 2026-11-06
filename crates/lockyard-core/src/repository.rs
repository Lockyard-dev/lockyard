// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Stable repository namespaces shared by HTTP clients and the local agent cache.
//! The prefix is a protocol address, never a filesystem path or an authorization boundary.

use crate::{Error, Result};

pub const PREFIX: &str = ".lockyard-repository/";

pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id.as_bytes()[0].is_ascii_lowercase() && !id.as_bytes()[0].is_ascii_digit()
        || !id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
    {
        return Err(Error::Invalid("repository must be 1–64 lowercase ASCII letters, digits, '.', '_' or '-', starting with a letter or digit".into()));
    }
    Ok(())
}

/// Returns the explicit repository ID and path within it, or legacy namespace and its path.
pub fn split(path: &str) -> (Option<&str>, &str) {
    match path.strip_prefix(PREFIX) {
        Some(rest) => {
            let (id, path) = rest.split_once('/').unwrap_or((rest, "."));
            (Some(id), path)
        }
        None => (None, path),
    }
}

pub fn qualify(repository: Option<&str>, path: &str) -> Result<String> {
    if path == ".lockyard-repository" || path.starts_with(PREFIX) {
        return Err(Error::Invalid(
            ".lockyard-repository is reserved for repository addresses".into(),
        ));
    }
    if path != "."
        && (path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path.split('/').any(|part| matches!(part, "" | "." | "..")))
    {
        return Err(Error::Invalid(
            "repository paths must be normalized relative paths".into(),
        ));
    }
    match repository {
        None => Ok(path.to_string()),
        Some(id) => {
            validate_id(id)?;
            let root = format!("{PREFIX}{id}");
            Ok(if path == "." {
                root
            } else {
                format!("{root}/{path}")
            })
        }
    }
}

pub fn relative<'a>(repository: Option<&str>, path: &'a str) -> Option<&'a str> {
    let (actual, relative) = split(path);
    (actual == repository).then_some(relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_and_roots_are_independent_of_checkout_locations() {
        assert_eq!(
            qualify(Some("api"), ".").unwrap(),
            ".lockyard-repository/api"
        );
        assert_eq!(
            qualify(Some("api"), "src/a").unwrap(),
            qualify(Some("api"), "src/a").unwrap()
        );
        assert_ne!(
            qualify(Some("api"), "src/a").unwrap(),
            qualify(Some("web"), "src/a").unwrap()
        );
        assert_eq!(relative(Some("api"), ".lockyard-repository/api"), Some("."));
        assert_eq!(relative(None, ".lockyard-repository/api/src/a"), None);
        assert!(qualify(Some("api"), "../web").is_err());
        assert!(qualify(None, ".lockyard-repository/api").is_err());
        for invalid in ["", ".", "..", "Api", "api/web", "-", "api\nweb"] {
            assert!(validate_id(invalid).is_err());
        }
    }
}
