// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn legitimate_lockyard_source_is_included_in_patch() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    fs::create_dir_all(worktree.join(".lockyard")).unwrap();
    fs::write(
        worktree.join(".lockyard/library.rs"),
        b"pub fn legitimate() {}\n",
    )
    .unwrap();
    fs::write(
        worktree.join(".lockyard/tracked.rs"),
        b"// changed legitimate code\n",
    )
    .unwrap();
    let cloud = CloudConfig {
        url: "https://example.invalid".into(),
        workspace: "team".into(),
        repository: "repo".into(),
        token_file: None,
    };
    let injected = write_cloud_config(&worktree, &cloud).unwrap().unwrap();
    record_injected_paths(&job, &worktree, vec![injected]).unwrap();
    collect_patch(&profile, &job, &worktree, &revision, "fixture", 4096, &[]).unwrap();
    let patch = fs::read_to_string(job.join("result.patch")).unwrap();
    assert!(
        patch.contains(".lockyard/library.rs"),
        "legitimate project code was dropped"
    );
    assert!(patch.contains(".lockyard/tracked.rs"));
    assert!(!patch.contains(".lockyard/config.toml"));
}

#[test]
fn preexisting_cloud_config_is_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".lockyard")).unwrap();
    let path = dir.path().join(".lockyard/config.toml");
    fs::write(&path, b"# project-owned content\n").unwrap();
    let cloud = CloudConfig {
        url: "https://example.invalid".into(),
        workspace: "team".into(),
        repository: "repo".into(),
        token_file: None,
    };
    assert!(write_cloud_config(dir.path(), &cloud).is_err());
    assert_eq!(fs::read(path).unwrap(), b"# project-owned content\n");
}

#[test]
fn changed_or_deleted_injected_config_is_an_explicit_incomplete_patch() {
    for deleted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        let cloud = CloudConfig {
            url: "https://example.invalid".into(),
            workspace: "team".into(),
            repository: "repo".into(),
            token_file: None,
        };
        let injected = write_cloud_config(&worktree, &cloud).unwrap().unwrap();
        record_injected_paths(&job, &worktree, vec![injected]).unwrap();
        let path = worktree.join(".lockyard/config.toml");
        if deleted {
            fs::remove_file(path).unwrap();
        } else {
            fs::write(path, b"# legitimate job edit\n").unwrap();
        }
        assert_eq!(
            collect_patch(&profile, &job, &worktree, &revision, "fixture", 4096, &[])
                .unwrap_err()
                .0,
            "patch_injected_file_changed"
        );
    }
}

#[test]
fn clean_filter_cannot_hide_its_mutation_of_injected_config() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    let cloud = CloudConfig {
        url: "https://example.invalid".into(),
        workspace: "team".into(),
        repository: "repo".into(),
        token_file: None,
    };
    let injected = write_cloud_config(&worktree, &cloud).unwrap().unwrap();
    record_injected_paths(&job, &worktree, vec![injected]).unwrap();
    fs::copy(
        worktree.join(".lockyard/config.toml"),
        worktree.join(".lockyard/original.txt"),
    )
    .unwrap();
    fs::write(worktree.join(".lockyard/filter.py"), b"import sys,pathlib\nsys.stdin.buffer.read()\noriginal=pathlib.Path('.lockyard/original.txt').read_bytes()\npathlib.Path('.lockyard/config.toml').write_bytes(b'# filter mutation\\n')\nsys.stdout.buffer.write(original)\n").unwrap();
    fs::write(
        worktree.join(".gitattributes"),
        b".lockyard/config.toml filter=fixture\n",
    )
    .unwrap();
    git_ok(
        &job.join("repository.git"),
        &[
            "config",
            "filter.fixture.clean",
            "/usr/bin/python3 .lockyard/filter.py",
        ],
    );
    assert_eq!(
        collect_patch(&profile, &job, &worktree, &revision, "fixture", 16384, &[])
            .unwrap_err()
            .0,
        "patch_injected_file_changed"
    );
}

#[test]
fn binary_patch_cannot_serialize_a_known_forwarded_credential() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    let token = b"fixture-known-sensitive-token".to_vec();
    let mut bytes = vec![0];
    bytes.extend_from_slice(&token);
    bytes.extend_from_slice(b"\0binary tail");
    fs::write(worktree.join("artifact.bin"), bytes).unwrap();
    assert_eq!(
        collect_patch(
            &profile,
            &job,
            &worktree,
            &revision,
            "fixture",
            4096,
            &[token]
        )
        .unwrap_err()
        .0,
        "patch_contains_forwarded_credential"
    );
}

#[test]
fn benign_binary_patch_with_forwarded_credential_still_applies() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    let bytes = b"\0benign\0binary tail";
    fs::write(worktree.join("artifact.bin"), bytes).unwrap();
    collect_patch(
        &profile,
        &job,
        &worktree,
        &revision,
        "fixture",
        4096,
        &[b"fixture-known-sensitive-token".to_vec()],
    )
    .unwrap();
    let patch = job.join("result.patch");
    fs::remove_file(worktree.join("artifact.bin")).unwrap();
    assert!(
        git(&worktree)
            .arg("apply")
            .arg(&patch)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(worktree.join("artifact.bin")).unwrap(), bytes);
}

#[test]
fn serialized_patch_is_refused_instead_of_rewritten_when_syntax_matches_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    fs::write(worktree.join("artifact.bin"), b"\0benign\0binary tail").unwrap();
    // "literal" occurs in Git's binary patch syntax rather than in the source blob.
    assert_eq!(
        collect_patch(
            &profile,
            &job,
            &worktree,
            &revision,
            "fixture",
            4096,
            &[b"literal".to_vec()]
        )
        .unwrap_err()
        .0,
        "patch_contains_forwarded_credential"
    );
    assert!(
        !fs::read_to_string(job.join("result.patch"))
            .unwrap()
            .contains("[REDACTED]")
    );
}

#[test]
fn credential_scan_rejects_secret_paths_and_symlink_targets_before_encoding() {
    for symlink in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, revision) = patch_fixture(dir.path());
        let token = b"fixture-known-sensitive-token".to_vec();
        if symlink {
            std::os::unix::fs::symlink(std::str::from_utf8(&token).unwrap(), worktree.join("link"))
                .unwrap();
        } else {
            fs::write(
                worktree.join(std::str::from_utf8(&token).unwrap()),
                b"benign",
            )
            .unwrap();
        }
        assert_eq!(
            collect_patch(
                &profile,
                &job,
                &worktree,
                &revision,
                "fixture",
                4096,
                &[token]
            )
            .unwrap_err()
            .0,
            "patch_contains_forwarded_credential"
        );
    }
}

#[test]
fn credential_scan_has_explicit_entry_and_collection_time_bounds() {
    let cancel = AtomicBool::new(false);
    let budget = PatchBudget {
        deadline: Instant::now() - Duration::from_millis(1),
        cancel: &cancel,
    };
    assert_eq!(
        budget.remaining().unwrap_err().0,
        "patch_collection_timeout"
    );
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(
        budget.remaining().unwrap_err().0,
        "patch_collection_cancelled"
    );
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    for index in 0..MAX_PATCH_SCAN_ENTRIES / 2 + 1 {
        fs::write(
            worktree.join(format!("file-{index}")),
            format!("unique content {index}\n"),
        )
        .unwrap();
    }
    assert_eq!(
        collect_patch(
            &profile,
            &job,
            &worktree,
            &revision,
            "fixture",
            1024 * 1024,
            &[b"fixture-known-sensitive-token".to_vec()]
        )
        .unwrap_err()
        .0,
        "patch_credential_scan_entries"
    );
}

#[test]
fn cancellation_interrupts_patch_helpers_and_confirms_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, revision) = patch_fixture(dir.path());
    fs::write(&profile.runtime_program, b"#!/usr/bin/python3\nimport sys,time\na=sys.argv[1:]\nif 'container' in a and 'rm' in a: sys.exit(0)\ntime.sleep(300)\n").unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let started = Instant::now();
    let worker = thread::spawn(move || {
        collect_patch_bounded(
            &profile,
            &job,
            &worktree,
            &revision,
            "fixture",
            4096,
            &[],
            &worker_cancel,
        )
    });
    thread::sleep(Duration::from_millis(100));
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(
        worker.join().unwrap().unwrap_err().0,
        "patch_collection_cancelled"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}
