// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use crate::Call;
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
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"GIT_") {
            git.env_remove(name);
        }
    }
    git.arg("-C")
        .arg(directory)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
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

fn checkout_contains_path(repo: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(repo) else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return true;
    };
    // Query from the first component so the index also reports gitlink ancestors.
    let relative = relative.as_os_str().as_encoded_bytes();
    git(repo)
        .args(["--literal-pathspecs", "ls-files", "--stage", "-z", "--"])
        .arg(first.as_os_str())
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && !output.stdout.split(|&byte| byte == 0).any(|entry| {
                    entry.starts_with(b"160000 ")
                        && entry
                            .splitn(2, |&byte| byte == b'\t')
                            .nth(1)
                            .and_then(|gitlink| relative.strip_prefix(gitlink))
                            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(b"/"))
                })
        })
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
        let path = root.join(relative.as_str());
        toplevel(&path).filter(|repo| repo.starts_with(root) && checkout_contains_path(repo, &path))
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
    local_commit_oid(repository?, revision).filter(|sha| sha.len() == 40)
}

fn local_commit_oid(repository: &Path, revision: &str) -> Option<String> {
    let output = git(repository)
        .args(["rev-parse", &format!("--disambiguate={revision}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut candidates = std::str::from_utf8(&output.stdout).ok()?.lines();
    let sha = candidates.next()?;
    if candidates.next().is_some()
        || !matches!(sha.len(), 40 | 64)
        || !sha.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let object = git(repository)
        .args(["cat-file", "-t", sha])
        .output()
        .ok()?;
    (object.status.success() && object.stdout == b"commit\n").then(|| sha.to_ascii_lowercase())
}

/// Refuse only when the local commit tree proves the path is absent.
pub(crate) fn refuse_if_file_missing(repo: &Path, value: &str) -> Result<()> {
    let Some((input_revision, path)) = value.split_once(':') else {
        return Ok(());
    };
    let Some(revision) = local_commit_oid(repo, input_revision) else {
        return Ok(());
    };
    if git(repo)
        .args([
            "--literal-pathspecs",
            "ls-tree",
            "--name-only",
            "-z",
            &revision,
            "--",
            path,
        ])
        .output()
        .is_ok_and(|output| {
            output.status.success() && output.stdout.is_empty() && output.stderr.is_empty()
        })
    {
        return Err(Error::Invalid(format!(
            "file {path} is not in revision {input_revision}"
        )));
    }
    Ok(())
}

pub(crate) fn warn_if_sha_missing(call: &Call, encryption_enabled: bool, response: &mut Value) {
    let Some(body) = &call.body else {
        return;
    };
    if !encryption_enabled || call.method != "POST" {
        return;
    }
    let route = call.path.split('?').next().unwrap_or(&call.path);
    let missing_sha = |entry: &Value| {
        entry["kind"] == "commit"
            && entry["commit_sha"].is_null()
            && entry["value"].as_str().is_some_and(commit_names_file)
    };
    let missing = match route.strip_prefix("/api/v1/registry/items") {
        Some("") => body["evidence"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(missing_sha)),
        Some("/batch-transition") => {
            if missing_sha(&body["evidence"])
                && let Some(results) = response.get_mut("results").and_then(Value::as_array_mut)
            {
                for result in results {
                    if let Some(item) = result.get_mut("item") {
                        add_missing_sha_warning(item);
                    }
                }
            }
            return;
        }
        Some(item) if item.ends_with("/evidence") => missing_sha(body),
        Some(item) if item.ends_with("/transition") => missing_sha(&body["evidence"]),
        _ => false,
    };
    if missing {
        add_missing_sha_warning(response);
    }
}

fn add_missing_sha_warning(response: &mut Value) {
    if response.is_object() {
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
