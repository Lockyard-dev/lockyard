// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Paths inside a project. Two agents must get the same text for the same file, whatever folder they
//! run from and however they spell it, because overlap is decided on that text.

use crate::store::DIR_NAME;
use crate::{Error, Result};
use std::path::{Component, Path, PathBuf};

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
            parts.push(part);
        }
        if parts.is_empty() {
            return Ok(Some(Self(ROOT.into())));
        }
        Ok(Some(Self(parts.join("/"))))
    }

    /// Wraps a path already stored in zone form.
    pub(crate) fn stored(text: String) -> Self {
        Self(text)
    }

    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when one path is the other or contains it.
    pub fn overlaps(&self, other: &Self) -> bool {
        overlaps(
            self.as_str(),
            other.as_str(),
            cfg!(any(target_os = "macos", windows)),
        )
    }
}

fn overlaps(a: &str, b: &str, fold_ascii_case: bool) -> bool {
    if fold_ascii_case {
        let a = a.to_ascii_lowercase();
        let b = b.to_ascii_lowercase();
        return overlaps_exact(&a, &b);
    }
    overlaps_exact(a, b)
}

fn overlaps_exact(a: &str, b: &str) -> bool {
    a == ROOT || b == ROOT || a == b || is_inside(a, b) || is_inside(b, a)
}

/// Finds the project that contains `start`.
pub fn find_root(start: &Path) -> Option<PathBuf> {
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
    fn path_overlap_can_fold_ascii_case_on_any_platform() {
        assert!(!overlaps("SRC", "src/file.rs", false));
        assert!(overlaps("SRC", "src/file.rs", true));
        assert!(!overlaps("Src", "src/file.rs", false));
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
    fn find_root_walks_up() {
        let (_dir, root) = project();
        fs::create_dir(root.join(DIR_NAME)).unwrap();
        assert_eq!(find_root(&root.join("src/deep")), Some(root));
    }
}
