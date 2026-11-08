// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Paths inside a project. Two agents must get the same text for the same file, whatever folder they
//! run from and however they spell it, because overlap is decided on that text.

use crate::store::DIR_NAME;
use crate::{Error, Result};
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

/// The project root in zone form.
const ROOT: &str = ".";

/// A path relative to the project root, with `/` separators and no `.` or `..` parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZonePath(String);

impl ZonePath {
    /// Resolves `raw` from `cwd`. Returns `None` when the path lies outside the project at `root`.
    ///
    /// `root` must be canonical. Symlinks are followed as far as the path exists, so a file that is
    /// about to be created resolves the same way as its existing siblings.
    pub fn resolve(root: &Path, cwd: &Path, raw: &str) -> Result<Option<Self>> {
        if raw.is_empty() {
            return Err(Error::Invalid("path is empty".into()));
        }
        let absolute = canonical_prefix(&lexical(&cwd.join(raw)));
        let Ok(relative) = absolute.strip_prefix(root) else {
            return Ok(None);
        };
        let mut parts = Vec::new();
        for component in relative.components() {
            let Some(part) = component.as_os_str().to_str() else {
                return Err(Error::Invalid(format!("path is not UTF-8: {raw:?}")));
            };
            // One stored form on every OS and on the server (D-3124): NFC, original case kept.
            // Case is folded only when comparing, so a Mac and a Linux client name `src/Auth` alike.
            parts.push(part.nfc().collect::<String>());
        }
        if parts.first().map(String::as_str) == Some(".lockyard-repository") {
            return Err(Error::Invalid(
                ".lockyard-repository is reserved for repository protocol addresses".into(),
            ));
        }
        if parts.is_empty() {
            return Ok(Some(Self(ROOT.into())));
        }
        Ok(Some(Self(parts.join("/"))))
    }

    /// Wraps a path already stored in zone form.
    pub fn stored(text: String) -> Self {
        Self(text)
    }

    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when one path is the other or contains it.
    pub fn overlaps(&self, other: &Self) -> bool {
        // Always case-insensitive, on every OS, like the server's default (D-3124): one workspace can mix
        // a Mac with a Linux host, and a lock that misses `src/Auth` vs `src/auth` is worse than a spare
        // conflict between two names that differ only in case.
        overlaps(self.as_str(), other.as_str(), true)
    }

    /// True when this path is the requested path or one of its parent directories.
    pub fn contains(&self, other: &Self) -> bool {
        self.contains_with_case(other, true)
    }

    /// Coverage under the repository path policy, independent of this machine's OS.
    pub fn contains_with_case(&self, other: &Self, fold_case: bool) -> bool {
        let (repository_outer, outer) = crate::repository::split(self.as_str());
        let (repository_inner, inner) = crate::repository::split(other.as_str());
        if repository_outer != repository_inner {
            return false;
        }
        let outer = comparable(outer, fold_case);
        let inner = comparable(inner, fold_case);
        outer == ROOT || inner == outer || is_inside(&inner, &outer)
    }

    /// Cloud caches use the repository policy returned by the server, rather than this machine's OS.
    pub fn overlaps_with_case(&self, other: &Self, fold_case: bool) -> bool {
        overlaps(self.as_str(), other.as_str(), fold_case)
    }
}

fn overlaps(a: &str, b: &str, fold_case: bool) -> bool {
    let (repository_a, a) = crate::repository::split(a);
    let (repository_b, b) = crate::repository::split(b);
    if repository_a != repository_b {
        return false;
    }
    overlaps_exact(&comparable(a, fold_case), &comparable(b, fold_case))
}

/// The form two zones are compared in: NFC, and lower case when the file system ignores case.
/// NFC here also matches zones stored by older clients in NFD.
fn comparable(path: &str, fold_case: bool) -> String {
    let composed = path.nfc().collect::<String>();
    if fold_case {
        composed.to_lowercase()
    } else {
        composed
    }
}

fn overlaps_exact(a: &str, b: &str) -> bool {
    a == ROOT || b == ROOT || a == b || is_inside(a, b) || is_inside(b, a)
}

/// Finds the project that contains `start`.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    let _span = crate::perf::Span::new("project.discovery");
    let start = start.canonicalize().ok()?;
    start
        .ancestors()
        .find(|dir| dir.join(DIR_NAME).is_dir())
        .map(Path::to_path_buf)
}

fn is_inside(inner: &str, outer: &str) -> bool {
    inner
        .strip_prefix(outer)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Removes `.` and `..` without touching the disk.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Canonicalizes the longest part of `path` that exists and keeps the rest as written.
fn canonical_prefix(path: &Path) -> PathBuf {
    for existing in path.ancestors() {
        if let Ok(canonical) = existing.canonicalize() {
            let rest = path.strip_prefix(existing).unwrap_or(Path::new(""));
            return canonical.join(rest);
        }
    }
    path.to_path_buf()
}

/// User home, including native Windows profiles when HOME is not provided.
pub fn home_dir() -> Option<std::ffi::OsString> {
    let home = std::env::var_os("HOME");
    #[cfg(windows)]
    {
        home.or_else(|| std::env::var_os("USERPROFILE"))
    }
    #[cfg(unix)]
    {
        home
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn project() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir_all(root.join("src/deep")).unwrap();
        (dir, root)
    }

    #[test]
    fn physical_paths_cannot_impersonate_virtual_repository_addresses() {
        let (_dir, root) = project();
        fs::create_dir_all(root.join(".lockyard-repository/api/src")).unwrap();
        assert!(matches!(
            ZonePath::resolve(&root, &root, ".lockyard-repository/api/src"),
            Err(Error::Invalid(_))
        ));
        // Wire records still need this representation in the aggregate daemon cache.
        let stored = ZonePath::stored(".lockyard-repository/api/src".into());
        assert_eq!(stored.as_str(), ".lockyard-repository/api/src");
    }

    #[test]
    fn path_overlap_can_fold_ascii_case_on_any_platform() {
        assert!(!overlaps("SRC", "src/file.rs", false));
        assert!(overlaps("SRC", "src/file.rs", true));
        assert!(!overlaps("Src", "src/file.rs", false));
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn path_overlap_folds_unicode_case_on_case_insensitive_platforms() {
        assert!(overlaps("src/É", "src/é/file", true));
    }

    #[test]
    fn repository_roots_and_legacy_root_are_separate_even_when_comparing_without_case() {
        let api = ".lockyard-repository/api";
        let web = ".lockyard-repository/web";
        assert!(overlaps(api, &format!("{api}/src/file"), false));
        assert!(!overlaps(api, &format!("{web}/src/file"), false));
        assert!(!overlaps(".", &format!("{api}/src/file"), false));
        assert!(!overlaps(api, "src/file", true));
        assert!(overlaps(
            &format!("{api}/SRC"),
            &format!("{api}/src/file"),
            true
        ));
        assert!(!overlaps(
            &format!("{api}/SRC"),
            &format!("{api}/src/file"),
            false
        ));
    }

    #[test]
    fn repository_namespaces_preserve_unicode_aliases_and_containment_boundaries() {
        let path = |text: &str| ZonePath::stored(text.into());
        let root = path(".lockyard-repository/api");
        let directory = path(".lockyard-repository/api/src/Cafe\u{0301}");
        let file = path(".lockyard-repository/api/src/CAF\u{00c9}/file.rs");
        assert!(directory.overlaps_with_case(&file, true));
        assert!(!directory.overlaps_with_case(&file, false));
        assert!(directory.contains(&file));
        assert!(!file.contains(&directory));
        assert!(root.contains(&file));
        assert!(!path(".").contains(&file));
        assert!(!root.contains(&path(".lockyard-repository/web/src/file.rs")));
        assert!(!root.contains(&path("src/file.rs")));
        assert!(!directory.overlaps(&path(".lockyard-repository/web/src/CAF\u{00c9}")));
    }

    fn zone(root: &Path, cwd: &Path, raw: &str) -> String {
        ZonePath::resolve(root, cwd, raw)
            .unwrap()
            .unwrap()
            .as_str()
            .to_string()
    }

    #[test]
    fn spellings_of_one_path_agree() {
        let (_dir, root) = project();
        let deep = root.join("src/deep");
        assert_eq!(zone(&root, &root, "src/a.rs"), "src/a.rs");
        assert_eq!(zone(&root, &root, "./src//a.rs"), "src/a.rs");
        assert_eq!(zone(&root, &deep, "../a.rs"), "src/a.rs");
        assert_eq!(
            zone(&root, &deep, root.join("src/a.rs").to_str().unwrap()),
            "src/a.rs"
        );
    }

    #[test]
    fn the_root_and_trailing_slashes_normalize() {
        let (_dir, root) = project();
        assert_eq!(zone(&root, &root, "."), ".");
        assert_eq!(zone(&root, &root, "src/"), "src");
    }

    #[test]
    fn a_path_outside_the_project_is_not_a_zone() {
        let (_dir, root) = project();
        assert!(ZonePath::resolve(&root, &root, "../x").unwrap().is_none());
        assert!(
            ZonePath::resolve(&root, &root, "/etc/hosts")
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_resolves_to_its_target_even_for_a_new_file() {
        let (_dir, root) = project();
        std::os::unix::fs::symlink(root.join("src"), root.join("link")).unwrap();
        assert_eq!(zone(&root, &root, "link/new.rs"), "src/new.rs");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unicode_spellings_of_a_new_file_resolve_to_one_zone() {
        let (_dir, root) = project();
        let composed = ZonePath::resolve(&root, &root, "src/caf\u{00e9}.rs")
            .unwrap()
            .unwrap();
        let decomposed = ZonePath::resolve(&root, &root, "src/cafe\u{0301}.rs")
            .unwrap()
            .unwrap();
        let case_alias = ZonePath::resolve(&root, &root, "src/CAF\u{00c9}.rs")
            .unwrap()
            .unwrap();

        assert_eq!(composed, decomposed);
        assert!(composed.overlaps(&case_alias));
    }

    #[test]
    fn a_zone_is_stored_in_nfc_with_its_case_kept() {
        let (_dir, root) = project();
        assert_eq!(
            zone(&root, &root, "src/Cafe\u{0301}.rs"),
            "src/Caf\u{00e9}.rs"
        );
        assert_eq!(zone(&root, &root, "src/Auth"), "src/Auth");
    }

    #[test]
    fn shared_vectors_agree_with_the_server() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("path-overlap-vectors.json")).unwrap();
        let (_dir, root) = project();
        for row in vectors["normalize"].as_array().unwrap() {
            let (raw, stored) = (
                row["raw"].as_str().unwrap(),
                row["stored"].as_str().unwrap(),
            );
            assert_eq!(zone(&root, &root, raw), stored, "normalize {raw:?}");
        }
        for row in vectors["overlap"].as_array().unwrap() {
            let (a, b) = (row["a"].as_str().unwrap(), row["b"].as_str().unwrap());
            let expected = row["overlap"].as_bool().unwrap();
            let path = |text: &str| ZonePath::stored(text.into());
            assert_eq!(path(a).overlaps(&path(b)), expected, "{a:?} vs {b:?}");
            assert_eq!(path(b).overlaps(&path(a)), expected, "{b:?} vs {a:?}");
        }
    }

    #[test]
    fn overlap_matches_zones_stored_in_nfd_by_older_clients() {
        assert!(overlaps("src/cafe\u{0301}", "src/caf\u{00e9}/a.rs", false));
        assert!(overlaps("src/cafe\u{0301}", "src/CAF\u{00c9}/a.rs", true));
    }

    #[test]
    fn overlap_respects_path_components() {
        let path = |text: &str| ZonePath::stored(text.into());
        assert!(path("src").overlaps(&path("src/a.rs")));
        assert!(path("src/a.rs").overlaps(&path("src")));
        assert!(path("src/a.rs").overlaps(&path("src/a.rs")));
        assert!(path(".").overlaps(&path("anything")));
        assert!(!path("src").overlaps(&path("src2/a.rs")));
        assert!(!path("src/a").overlaps(&path("src/b")));
    }

    #[test]
    fn contains_requires_the_existing_claim_to_cover_the_requested_path() {
        let directory = ZonePath::stored("Auth".into());
        let file = ZonePath::stored("auth/a.cs".into());
        assert!(directory.contains(&file));
        assert!(!file.contains(&directory));
    }

    #[test]
    fn find_root_walks_up() {
        let (_dir, root) = project();
        fs::create_dir(root.join(DIR_NAME)).unwrap();
        assert_eq!(find_root(&root.join("src/deep")), Some(root));
    }
}
