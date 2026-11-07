// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[test]
fn runtime_identity_preserves_private_file_access_without_capabilities() {
    for rootless in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (profile, job, worktree, _) = patch_fixture(dir.path());
        fs::remove_file(job.join("runtime-user")).unwrap();
        fs::write(
            &profile.runtime_program,
            format!(
                r#"#!/usr/bin/python3
import sys
a=sys.argv[1:]
if 'image' in a: print('null')
elif any('SecurityOptions' in item for item in a): print('{}')
else: print('true true true')
"#,
                if rootless {
                    "[\"name=rootless\"]"
                } else {
                    "[]"
                }
            ),
        )
        .unwrap();
        verify_runtime_limits(&profile, &job).unwrap();
        let command = container_command(
            &profile,
            &job,
            &worktree,
            &profile.git_program,
            "fixture",
            false,
        )
        .unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let identity = if rootless {
            "0:0".into()
        } else {
            host_container_identity()
        };
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--user" && pair[1] == identity)
        );
        assert!(args.iter().any(|arg| arg == "--cap-drop=ALL"));
    }
}

#[test]
fn runtime_workspace_key_copy_is_private_scoped_and_helpers_cannot_mount_it() {
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, _) = patch_fixture(dir.path());
    let key = WorkspaceKey::from_entropy([73; 32]);
    let context = WorkspaceKeyContext {
        workspace: "actual-workspace-id".into(),
        key,
    };
    assert_eq!(create_runtime_key(&job, &context).unwrap(), vec![73; 32]);
    let key_file = job.join("runtime-key/lockyard/keys/actual-workspace-id.key");
    assert_eq!(
        fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(key_file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let main = container_command(
        &profile,
        &job,
        &worktree,
        &profile.git_program,
        "fixture",
        false,
    )
    .unwrap();
    let main: Vec<_> = main
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(
        main.iter()
            .any(|arg| arg.ends_with("dst=/run/lockyard-config,readonly"))
    );
    assert!(
        main.iter()
            .any(|arg| arg == "XDG_CONFIG_HOME=/run/lockyard-config")
    );
    assert!(
        !main
            .iter()
            .any(|arg| arg.contains("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII"))
    );
    let patch = container_command(
        &profile,
        &job,
        &worktree,
        &profile.git_program,
        "fixture",
        true,
    )
    .unwrap();
    let patch: Vec<_> = patch
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(
        !patch
            .iter()
            .any(|arg| arg.contains("runtime-key") || arg.contains("XDG_CONFIG_HOME"))
    );
    assert!(
        patch
            .iter()
            .any(|arg| arg.ends_with(&format!("dst={},readonly", worktree.display())))
    );
    remove_runtime_key(&job).unwrap();
    assert!(!key_file.exists());
}

#[test]
fn arbitrary_forwarded_environment_names_are_private_and_redacted() {
    let root = tempfile::tempdir().unwrap();
    let (profile, job, worktree, _) = patch_fixture(root.path());
    let mut secrets = Vec::new();
    stage_forwarded_environment(
        &job,
        vec![
            ("AUTH".into(), "unique-auth-value".into()),
            ("DATABASE_URL".into(), "unique-database-value".into()),
        ],
        &mut secrets,
    )
    .unwrap();
    assert_eq!(
        secrets,
        vec![
            b"unique-auth-value".to_vec(),
            b"unique-database-value".to_vec()
        ]
    );
    let command = container_command(
        &profile,
        &job,
        &worktree,
        &profile.git_program,
        "main",
        false,
    )
    .unwrap();
    assert!(command.get_args().any(|arg| arg == "--env-file"));
    assert!(
        command
            .get_args()
            .all(|arg| !arg.to_string_lossy().contains("unique-"))
    );
    assert!(command.get_envs().all(|(_, value)| {
        !value.is_some_and(|value| value.to_string_lossy().contains("unique-"))
    }));
    let spool = Arc::new(Mutex::new(Spool {
        file: Vec::new(),
        bytes: 0,
        truncated: false,
        limit: 4096,
        error: None,
        credential_tail: Vec::new(),
    }));
    let raw = b"AUTH unique-auth-value DB unique-database-value";
    drain(
        std::io::Cursor::new(raw),
        spool.clone(),
        secrets.clone(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let spool = spool.lock().unwrap();
    for secret in &secrets {
        assert!(
            !spool
                .file
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }
    assert_eq!(
        scan_credential_stream(std::io::Cursor::new(raw), &secrets, 4096)
            .unwrap_err()
            .0,
        "patch_contains_forwarded_credential"
    );
}
#[test]
fn forwarded_environment_rejects_unsupported_values_without_staging_any_prefix() {
    use std::os::unix::ffi::OsStringExt;
    for invalid in [
        std::ffi::OsString::from_vec(vec![255]),
        "bad\nline".into(),
        "bad\rline".into(),
        "bad\0line".into(),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut secrets = Vec::new();
        assert!(
            stage_forwarded_environment(
                root.path(),
                vec![
                    ("AUTH".into(), "valid-first".into()),
                    ("DATABASE_URL".into(), invalid)
                ],
                &mut secrets
            )
            .is_err()
        );
        assert!(!root.path().join("runtime-secrets").exists());
        assert!(secrets.is_empty());
    }
}

#[test]
fn oversized_padded_cloud_token_cannot_be_silently_truncated() {
    use std::os::unix::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let token = root.path().join("token");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&token)
        .unwrap();
    file.write_all(b"synthetic").unwrap();
    file.write_all(&vec![b' '; 16385]).unwrap();
    file.sync_all().unwrap();
    assert_eq!(
        read_private_token(&token).unwrap_err().0,
        "invalid_token_file"
    );
}

#[test]
fn hardlinked_protected_node_token_cannot_be_forwarded_as_project_cloud_token() {
    use std::os::unix::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let protected = root.path().join("node-relay.token");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&protected)
        .unwrap();
    file.write_all(b"synthetic-private-node-identity").unwrap();
    file.sync_all().unwrap();
    let alias = root.path().join("project-cloud.token");
    fs::hard_link(&protected, &alias).unwrap();
    assert_eq!(
        read_private_token(&alias).unwrap_err().0,
        "token_file_has_aliases"
    );
}

#[test]
fn project_cloud_token_fifo_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("token.fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_private_token(&fifo).is_err());
    });
    assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
}

#[test]
fn source_checkout_cannot_include_node_identity_or_other_job_state() {
    let (root, mut config, executor) = retention_fixture();
    drop(executor);
    let checkout = root.path().join("checkout");
    private_dir_new(&checkout).unwrap();
    config.repositories.insert(
        "repo".into(),
        RepositoryConfig {
            checkout: checkout.clone(),
            cloud: None,
            retention: Some(crate::retention::RetentionPolicy {
                content_ttl_seconds: 60,
            }),
        },
    );
    check_execution_identity_paths(&config).unwrap();
    let identity = checkout.join("node-identity.key");
    fs::write(&identity, [7; 32]).unwrap();
    config.protected_identity_files = vec![identity];
    assert_eq!(
        check_execution_identity_paths(&config).unwrap_err().0,
        "identity_must_be_outside_execution_mounts"
    );
    config.protected_identity_files.clear();
    config.repositories.get_mut("repo").unwrap().checkout = config.state_dir.join("jobs");
    assert_eq!(
        check_execution_identity_paths(&config).unwrap_err().0,
        "identity_must_be_outside_execution_mounts"
    );
}

#[test]
fn workload_credentials_and_context_are_readonly_main_only_and_cleaned() {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (profile, job, worktree, _) = patch_fixture(dir.path());
    let secret_file = dir.path().join("customer.secret");
    let mut source = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&secret_file)
        .unwrap();
    source
        .write_all(b"private-customer-value-sentinel")
        .unwrap();
    source.sync_all().unwrap();
    let refs = vec![crate::secrets::SecretBinding {
        name: "customer_api".into(),
        environment: Some("CUSTOMER_API_TOKEN".into()),
        source: crate::secrets::SecretSource::LocalFile { path: secret_file },
    }];
    let resolved = crate::secrets::stage_with_budget(
        &job,
        &refs,
        &[],
        Instant::now() + Duration::from_secs(2),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(resolved[0].bytes(), b"private-customer-value-sentinel");
    for name in ["runtime-context", "runtime-delegation"] {
        private_dir_new(&job.join(name)).unwrap();
    }
    fs::write(job.join("runtime-context/workflow-inputs.json"), b"{}").unwrap();
    fs::write(
        job.join("runtime-delegation/node.toml"),
        b"private-delegation-config",
    )
    .unwrap();
    let main = container_command(
        &profile,
        &job,
        &worktree,
        &profile.git_program,
        "main",
        false,
    )
    .unwrap();
    let main = main
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    for path in [
        "/run/lockyard-secrets",
        "/run/lockyard-context",
        "/run/lockyard-delegation",
    ] {
        assert!(
            main.iter()
                .any(|arg| arg.ends_with(&format!("dst={path},readonly")))
        );
    }
    assert!(
        main.iter()
            .any(|arg| arg == "LOCKYARD_NODE_CONFIG=/run/lockyard-delegation/node.toml")
    );
    assert!(main.iter().any(
        |arg| arg == "LOCKYARD_WORKFLOW_INPUTS_FILE=/run/lockyard-context/workflow-inputs.json"
    ));
    assert!(
        main.windows(2).any(
            |pair| pair[0] == "--env-file" && pair[1].ends_with("runtime-secrets/.environment")
        )
    );
    assert!(
        main.iter()
            .all(|arg| !arg.contains("private-customer-value-sentinel"))
    );
    assert!(main.iter().all(|arg| !arg.contains("CUSTOMER_API_TOKEN=")));
    assert!(main.iter().all(|arg| !arg.contains("operator.sock")));
    let helper = container_command(
        &profile,
        &job,
        &worktree,
        &profile.git_program,
        "helper",
        true,
    )
    .unwrap();
    assert!(
        helper
            .get_args()
            .all(|arg| !arg.to_string_lossy().contains("runtime-secrets")
                && !arg.to_string_lossy().contains("runtime-delegation")
                && !arg.to_string_lossy().contains("runtime-context"))
    );
    remove_runtime_key(&job).unwrap();
    assert!(!job.join("runtime-secrets").exists());
}
