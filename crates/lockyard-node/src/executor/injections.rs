// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn valid_blob_id(oid: &str) -> bool {
    [40, 64].contains(&oid.len()) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}
pub(super) fn record_injected_paths(
    job_dir: &Path,
    worktree: &Path,
    paths: Vec<String>,
) -> Result<()> {
    let mut injections = Vec::new();
    for path in paths {
        let output = git(&job_dir.join("repository.git"))
            .args(["hash-object", "--no-filters", "--"])
            .arg(worktree.join(&path))
            .output()
            .map_err(io_error)?;
        let blob = String::from_utf8(output.stdout)
            .map_err(|_| ExecutorError("injection_manifest_failed"))?
            .trim()
            .to_string();
        if !output.status.success() || !valid_blob_id(&blob) {
            return Err(ExecutorError("injection_manifest_failed"));
        }
        injections.push(InjectedPath { path, blob });
    }
    let mut file = private_open(&job_dir.join("injected-paths.json"), true)?;
    file.write_all(
        &serde_json::to_vec(&injections).map_err(|_| ExecutorError("injection_manifest_failed"))?,
    )
    .map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    File::open(job_dir)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)?;
    Ok(())
}
pub(super) fn load_injected_paths(job_dir: &Path) -> Result<Vec<InjectedPath>> {
    let path = job_dir.join("injected-paths.json");
    let mut file = match private_open_existing(&path) {
        Ok(file) => file,
        Err(_) if !path.exists() => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > 4096 {
        return Err(ExecutorError("invalid_injection_manifest"));
    }
    let injections: Vec<InjectedPath> =
        serde_json::from_slice(&bytes).map_err(|_| ExecutorError("invalid_injection_manifest"))?;
    if injections.len() > 1
        || injections
            .iter()
            .any(|item| item.path != ".lockyard/config.toml" || !valid_blob_id(&item.blob))
    {
        return Err(ExecutorError("invalid_injection_manifest"));
    }
    Ok(injections)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_injected_paths(
    profile: &ContainerProfile,
    job_dir: &Path,
    worktree: &Path,
    name: &str,
    git_args: &[String],
    injections: &[InjectedPath],
    budget: &PatchBudget<'_>,
) -> Result<()> {
    for injection in injections {
        let run = |suffix: &str, arguments: &[&str]| -> Result<Vec<u8>> {
            let args: Vec<_> = arguments.iter().map(OsString::from).collect();
            patch_git_output(
                profile,
                job_dir,
                worktree,
                &format!("{name}-injection-{suffix}"),
                git_args,
                &args,
                4096,
                budget,
            )
            .map_err(|error| {
                if matches!(
                    error.0,
                    "patch_container_stop_unconfirmed"
                        | "patch_collection_cancelled"
                        | "patch_collection_timeout"
                ) {
                    error
                } else {
                    ExecutorError("patch_injected_file_changed")
                }
            })
        };
        run("stage", &["add", "-f", "--", &injection.path])?;
        let index = run(
            "type",
            &["ls-files", "--stage", "-z", "--", &injection.path],
        )?;
        let expected = format!("100644 {} 0\t{}\0", injection.blob, injection.path);
        if index != expected.as_bytes() {
            return Err(ExecutorError("patch_injected_file_changed"));
        }
        let hash = run(
            "raw",
            &["hash-object", "--no-filters", "--", &injection.path],
        )?;
        if std::str::from_utf8(&hash).ok().map(str::trim) != Some(injection.blob.as_str()) {
            return Err(ExecutorError("patch_injected_file_changed"));
        }
        run(
            "remove",
            &["update-index", "--force-remove", "--", &injection.path],
        )?;
    }
    Ok(())
}
