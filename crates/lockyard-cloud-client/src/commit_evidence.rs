// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_core::{Error, Result, ZonePath, paths::find_root};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

/// `<7-64 hex>:<relative/path>`. A bare object id is not a file in that commit.
pub fn commit_names_file(value: &str) -> bool {
    let Some((revision, path)) = value.split_once(':') else {
        return false;
    };
    (7..=64).contains(&revision.len())
        && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn git(directory: &Path) -> Command {
    let mut git = Command::new("git");
    git.arg("-C")
        .arg(directory)
        .env_remove("GIT_DIR")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "");
    git
}

fn toplevel(path: &Path) -> Option<PathBuf> {
    let directory = path.ancestors().find(|path| path.is_dir())?;
    let result = git(directory)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !result.status.success() {
        return None;
    }
    Path::new(
        std::str::from_utf8(&result.stdout)
            .ok()?
            .trim_end_matches(['\r', '\n']),
    )
    .canonicalize()
    .ok()
}

// Task paths are workspace-relative, including when invoked from another checkout in it.
pub(crate) fn task_repository(
    cwd: &Path,
    paths: impl IntoIterator<Item = impl AsRef<str>>,
) -> Option<PathBuf> {
    let mut paths = paths.into_iter().peekable();
    let workspace = find_root(cwd);
    if paths.peek().is_none() {
        return toplevel(workspace.as_deref().unwrap_or(cwd));
    }
    let root = workspace.as_deref()?;
    let mut repositories = paths.map(|path| {
        let relative = ZonePath::resolve(root, root, path.as_ref()).ok()??;
        toplevel(&root.join(relative.as_str())).filter(|repo| repo.starts_with(root))
    });
    let first = repositories.next()??;
    repositories
        .all(|repo| repo.as_ref() == Some(&first))
        .then_some(first)
}

pub(crate) fn full_commit_sha(repository: Option<&Path>, value: &str) -> Option<String> {
    if !commit_names_file(value) {
        return None;
    }
    let (revision, _) = value.split_once(':')?;
    if revision.len() == 40 {
        return Some(revision.to_ascii_lowercase());
    }
    if revision.len() > 40 {
        return None;
    }
    let output = git(repository?)
        .args(["rev-parse", "--verify", &format!("{revision}^{{commit}}")])
        .output()
        .ok()?;
    let sha = std::str::from_utf8(&output.stdout).ok()?.trim();
    (output.status.success() && sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| sha.to_ascii_lowercase())
}

/// A revision missing locally may name a commit the server can still verify.
pub(crate) fn refuse_if_file_missing(repo: &Path, value: &str) -> Result<()> {
    let Some((revision, path)) = value.split_once(':') else {
        return Ok(());
    };
    if git(repo)
        .args(["cat-file", "-e", &format!("{revision}^{{commit}}")])
        .output()
        .is_ok_and(|output| output.status.success())
        && git(repo)
            .args(["cat-file", "-e", &format!("{revision}:{path}")])
            .output()
            .is_ok_and(|output| !output.status.success())
    {
        return Err(Error::Invalid(format!(
            "file {path} is not in revision {revision}"
        )));
    }
    Ok(())
}

pub(crate) fn warn_if_sha_missing(route: &str, body: &Value, response: &mut Value) {
    let missing_sha = |entry: &Value| {
        entry["kind"] == "commit"
            && entry["commit_sha"].is_null()
            && entry["value"].as_str().is_some_and(commit_names_file)
    };
    let missing = match route.strip_prefix("/api/v1/registry/items") {
        Some("") => body["evidence"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(missing_sha)),
        Some(item) if item.ends_with("/evidence") => missing_sha(body),
        Some(item) if item.ends_with("/transition") => missing_sha(&body["evidence"]),
        _ => false,
    };
    if missing && response.is_object() {
        let warning = json!(
            "Не удалось развернуть SHA коммита. Приёмка в шифрованном workspace откажет. Пересдайте задачу с полным 40-символьным SHA."
        );
        if let Some(warnings) = response["warnings"].as_array_mut() {
            warnings.push(warning);
        } else {
            response["warnings"] = json!([warning]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_response_schema_accepts_single_and_batch_warnings_as_clear_metadata() {
        let item = json!({"id":"D-1", "status":"review", "warnings":["check dev"]});
        for (route, response) in [
            ("/api/v1/registry/items/D-1/transition", item.clone()),
            (
                "/api/v1/registry/items/batch-transition",
                json!({"results":[{"id":"D-1", "changed":true, "item":item}]}),
            ),
        ] {
            let mut decoded = response.clone();
            crate::crypto::transform_fields_policy(
                &mut decoded,
                "POST",
                route,
                "fixture",
                None,
                false,
                true,
            )
            .unwrap();
            assert_eq!(decoded, response);
        }
    }
}
