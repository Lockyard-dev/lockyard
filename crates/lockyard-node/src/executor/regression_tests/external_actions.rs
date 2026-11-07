// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;
use crate::approvals::{self, ApprovalExpectation, ManagedAction};
use serde_json::json;

fn external_fixture(
    network: bool,
    credential: u8,
) -> (tempfile::TempDir, SigningKey, Executor, JobSpec) {
    let (root, _, mut executor) = retention_fixture();
    let key_file = root.path().join("owner.pk8");
    let key = SigningKey::generate(&key_file).unwrap();
    let config = &mut Arc::get_mut(&mut executor.inner).unwrap().config;
    config.provenance = Some(ResultSigningConfig {
        workspace: "workspace".into(),
        key_file,
        public_key: key.trusted_key().public_key.clone(),
    });
    config.node_certificate_sha256 = Some("b".repeat(64));
    let mut runner: RunnerProfile = serde_json::from_value(json!({
        "program":"/usr/bin/compute", "owner_approval_authorities":[key.trusted_key()],
        "container":{"runtime":"docker","runtime_program":root.path().join("no-runtime"),
            "image":format!("sha256:{}", "a".repeat(64)), "memory_mb":128,"cpu_millis":1000,
            "pids_limit":64,"network":if network { "bridge" } else { "none" }}
    }))
    .unwrap();
    if credential == 1 {
        runner.env_passthrough.push("EXTERNAL_TOKEN".into());
    } else if credential == 2 {
        runner.secrets = serde_json::from_value(json!([{
            "name":"publish", "source":{"kind":"local_file", "path":root.path().join("credential")}, "environment":"PUBLISH_TOKEN"
        }])).unwrap();
    }
    runner.credential_repositories.push("repo".into());
    config.runners.insert("runner".into(), runner);
    config.repositories.insert(
        "repo".into(),
        RepositoryConfig {
            checkout: root.path().join("source"),
            cloud: if credential == 3 {
                Some(CloudConfig {
                    url: "https://broker.example.invalid".into(),
                    workspace: "workspace".into(),
                    repository: "remote".into(),
                    token_file: Some(root.path().join("cloud-token")),
                })
            } else {
                None
            },
            retention: Some(RetentionPolicy {
                content_ttl_seconds: 3600,
            }),
        },
    );
    let spec = serde_json::from_value(json!({
        "id":"01ARZ3NDEKTSV4RRFFQ69G5FAV", "repository":"repo", "revision":"HEAD",
        "runner":"runner", "arguments":["https://destination.example.invalid/release"]
    }))
    .unwrap();
    (root, key, executor, spec)
}

fn sign(executor: &Executor, key: &SigningKey, spec: &mut JobSpec) {
    sign_revision(executor, key, spec, &"c".repeat(40));
}

fn sign_revision(executor: &Executor, key: &SigningKey, spec: &mut JobSpec, revision: &str) {
    let current = now_ms();
    spec.owner_approval = Some(
        approvals::prepare(
            &ApprovalExpectation {
                workspace: "workspace",
                node_id: "worker",
                node_certificate_sha256: &"b".repeat(64),
                spec,
                resolved_revision: revision,
                runner: &executor.inner.config.runners["runner"],
                repository_cloud: executor.inner.config.repositories["repo"].cloud.as_ref(),
            },
            current - 1000,
            current + 60_000,
        )
        .unwrap()
        .sign(key)
        .unwrap(),
    );
}

fn set_policy(executor: &mut Executor, policy: &str) {
    let mut config = serde_json::to_value(&executor.inner.config).unwrap();
    config["external_actions"] = json!(policy);
    let mut config: ExecutorConfig = serde_json::from_value(config).unwrap();
    // Host-only fields are deliberately not accepted from configuration.
    config.node_certificate_sha256 = executor.inner.config.node_certificate_sha256.clone();
    Arc::get_mut(&mut executor.inner).unwrap().config = config;
}

#[test]
fn ep06_workspace_policy_is_explicit_defaulted_and_closed() {
    let (_root, _, executor) = retention_fixture();
    let encoded = serde_json::to_value(&executor.inner.config).unwrap();
    assert_eq!(encoded["external_actions"], "require_approval");
    let mut omitted = encoded.clone();
    omitted.as_object_mut().unwrap().remove("external_actions");
    let defaulted: ExecutorConfig = serde_json::from_value(omitted).unwrap();
    assert_eq!(
        serde_json::to_value(defaulted).unwrap()["external_actions"],
        "require_approval"
    );
    for policy in ["require_approval", "deny"] {
        let mut configured = encoded.clone();
        configured["external_actions"] = json!(policy);
        assert!(serde_json::from_value::<ExecutorConfig>(configured).is_ok());
    }
    let mut invalid = encoded;
    invalid["external_actions"] = json!("allow");
    assert!(serde_json::from_value::<ExecutorConfig>(invalid).is_err());
}

#[test]
fn ep06_network_credentials_policy_matrix_requires_exact_owner_approval() {
    for network in [true, false] {
        for credential in [0, 1, 2, 3] {
            for policy in ["require_approval", "deny"] {
                let (_root, key, mut executor, mut spec) = external_fixture(network, credential);
                // Test the default behavior before parsing the explicit policy on old code.
                let unsigned = executor.verify_owner_approval(&spec, &"c".repeat(40));
                if network || credential != 0 {
                    assert_eq!(unsigned.unwrap_err().0, "owner_approval_required");
                } else {
                    unsigned.unwrap();
                }
                set_policy(&mut executor, policy);
                let forbidden = policy == "deny" && network && credential != 0;
                if network || credential != 0 {
                    sign(&executor, &key, &mut spec);
                    let approved = executor.verify_owner_approval(&spec, &"c".repeat(40));
                    if forbidden {
                        assert_eq!(approved.unwrap_err().0, "external_actions_denied");
                    } else {
                        approved.unwrap();
                    }
                    spec.owner_approval = None;
                    assert_eq!(
                        executor
                            .verify_owner_approval(&spec, &"c".repeat(40))
                            .unwrap_err()
                            .0,
                        if forbidden {
                            "external_actions_denied"
                        } else {
                            "owner_approval_required"
                        }
                    );
                } else {
                    executor
                        .verify_owner_approval(&spec, &"c".repeat(40))
                        .unwrap();
                    // Managed profiles retain their independent owner requirement.
                    Arc::get_mut(&mut executor.inner)
                        .unwrap()
                        .config
                        .runners
                        .get_mut("runner")
                        .unwrap()
                        .action = ManagedAction::Deploy;
                    assert_eq!(
                        executor
                            .verify_owner_approval(&spec, &"c".repeat(40))
                            .unwrap_err()
                            .0,
                        "owner_approval_required"
                    );
                    sign(&executor, &key, &mut spec);
                    executor
                        .verify_owner_approval(&spec, &"c".repeat(40))
                        .unwrap();
                }
            }
        }
    }
}

#[test]
fn ep06_compute_signature_rejects_changed_spec_digest_and_destination() {
    let (_root, key, mut executor, mut spec) = external_fixture(true, 1);
    sign(&executor, &key, &mut spec);
    executor
        .verify_owner_approval(&spec, &"c".repeat(40))
        .unwrap();
    for field in 0..12 {
        let mut changed = spec.clone();
        let original = executor.inner.config.runners["runner"].clone();
        match field {
            0 => changed
                .arguments
                .push("https://other.example.invalid".into()),
            1 => {
                Arc::get_mut(&mut executor.inner)
                    .unwrap()
                    .config
                    .runners
                    .get_mut("runner")
                    .unwrap()
                    .program = "/usr/bin/changed".into()
            }
            2 => {
                Arc::get_mut(&mut executor.inner)
                    .unwrap()
                    .config
                    .runners
                    .get_mut("runner")
                    .unwrap()
                    .container
                    .image = format!("sha256:{}", "d".repeat(64))
            }
            3 => {
                Arc::get_mut(&mut executor.inner)
                    .unwrap()
                    .config
                    .runners
                    .get_mut("runner")
                    .unwrap()
                    .container
                    .network = ContainerNetwork::None
            }
            4 => Arc::get_mut(&mut executor.inner)
                .unwrap()
                .config
                .runners
                .get_mut("runner")
                .unwrap()
                .env_passthrough
                .push("OTHER_TOKEN".into()),
            5 => Arc::get_mut(&mut executor.inner)
                .unwrap()
                .config
                .runners
                .get_mut("runner")
                .unwrap()
                .credential_repositories
                .push("other".into()),
            6 => {
                Arc::get_mut(&mut executor.inner)
                    .unwrap()
                    .config
                    .node_certificate_sha256 = Some("d".repeat(64))
            }
            7 => changed.id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into(),
            9 => Arc::get_mut(&mut executor.inner).unwrap().config.runners.get_mut("runner").unwrap().secrets = serde_json::from_value(json!([{
                "name":"other", "source":{"kind":"local_file", "path":"/private/changed-credential"}, "environment":"OTHER_TOKEN"
            }])).unwrap(),
            10 => Arc::get_mut(&mut executor.inner).unwrap().config.runners.get_mut("runner").unwrap().fixed_args.push("--changed-command".into()),
            11 => changed.owner_approval.as_mut().unwrap().signature = "A".repeat(88),
            _ => {
                let mut claim = approvals::prepare(
                    &ApprovalExpectation {
                        workspace: "workspace",
                        node_id: "worker",
                        node_certificate_sha256: &"b".repeat(64),
                        spec: &changed,
                        resolved_revision: &"c".repeat(40),
                        runner: &original,
                        repository_cloud: None,
                    },
                    1,
                    2,
                )
                .unwrap();
                claim.expires_at_ms = 3;
                changed.owner_approval = Some(claim.sign(&key).unwrap());
            }
        }
        assert_eq!(
            executor
                .verify_owner_approval(&changed, &"c".repeat(40))
                .unwrap_err()
                .0,
            "owner_approval_required"
        );
        let config = &mut Arc::get_mut(&mut executor.inner).unwrap().config;
        config.runners.insert("runner".into(), original);
        config.node_certificate_sha256 = Some("b".repeat(64));
    }
    Arc::get_mut(&mut executor.inner).unwrap().config.provenance = None;
    assert_eq!(
        executor
            .verify_owner_approval(&spec, &"c".repeat(40))
            .unwrap_err()
            .0,
        "owner_approval_required"
    );
}

#[test]
fn ep06_compute_admission_refuses_before_journal_clone_and_runtime() {
    let (root, _key, executor, spec) = external_fixture(true, 0);
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    git_ok(&source, &["init", "-q"]);
    git_ok(&source, &["config", "user.email", "test@example.invalid"]);
    git_ok(&source, &["config", "user.name", "Test"]);
    fs::write(source.join("base"), "base").unwrap();
    git_ok(&source, &["add", "base"]);
    git_ok(&source, &["commit", "-qm", "base"]);
    let result = executor.submit(
        spec.clone(),
        &Caller {
            node_id: "controller".into(),
            local_operator: true,
            certificate_sha256: None,
        },
    );
    assert_eq!(result.unwrap_err().0, "owner_approval_required");
    assert!(
        !executor
            .inner
            .config
            .state_dir
            .join("jobs")
            .join(&spec.id)
            .exists()
    );
    assert!(executor.list().unwrap().is_empty());
}

#[test]
fn ep06_deny_submit_returns_policy_code_before_journal_and_runtime() {
    let (root, key, mut executor, mut spec) = external_fixture(true, 1);
    let runtime = root.path().join("no-runtime");
    fs::write(&runtime, "#!/bin/sh\n: > \"$0.called\"\nexit 1\n").unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    git_ok(&source, &["init", "-q"]);
    git_ok(&source, &["config", "user.email", "test@example.invalid"]);
    git_ok(&source, &["config", "user.name", "Test"]);
    fs::write(source.join("base"), "base").unwrap();
    git_ok(&source, &["add", "base"]);
    git_ok(&source, &["commit", "-qm", "base"]);
    let revision = String::from_utf8(git_ok(&source, &["rev-parse", "HEAD"]))
        .unwrap()
        .trim()
        .to_owned();
    sign_revision(&executor, &key, &mut spec, &revision);
    executor.verify_owner_approval(&spec, &revision).unwrap();
    set_policy(&mut executor, "deny");
    for approved in [true, false] {
        if !approved {
            spec.owner_approval = None;
        }
        let result = executor.submit(
            spec.clone(),
            &Caller {
                node_id: "controller".into(),
                local_operator: true,
                certificate_sha256: None,
            },
        );
        assert_eq!(result.unwrap_err().0, "external_actions_denied");
        assert!(
            !executor
                .inner
                .config
                .state_dir
                .join("jobs")
                .join(&spec.id)
                .exists()
        );
        assert!(executor.list().unwrap().is_empty());
        assert!(!root.path().join("no-runtime.called").exists());
    }
}

#[test]
fn ep06_implicit_cloud_credentials_and_destinations_are_approval_bound() {
    let (_root, key, mut executor, mut spec) = external_fixture(false, 3);
    assert_eq!(
        executor
            .verify_owner_approval(&spec, &"c".repeat(40))
            .unwrap_err()
            .0,
        "owner_approval_required"
    );
    sign(&executor, &key, &mut spec);
    executor
        .verify_owner_approval(&spec, &"c".repeat(40))
        .unwrap();
    for field in 0..4 {
        let original = executor.inner.config.repositories["repo"].clone();
        let cloud = Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .repositories
            .get_mut("repo")
            .unwrap()
            .cloud
            .as_mut()
            .unwrap();
        match field {
            0 => cloud.url = "https://other.example.invalid".into(),
            1 => cloud.token_file = Some(PathBuf::from("/private/other-credential")),
            2 => cloud.workspace = "other".into(),
            _ => cloud.repository = "other".into(),
        }
        assert_eq!(
            executor
                .verify_owner_approval(&spec, &"c".repeat(40))
                .unwrap_err()
                .0,
            "owner_approval_required"
        );
        Arc::get_mut(&mut executor.inner)
            .unwrap()
            .config
            .repositories
            .insert("repo".into(), original);
    }
}
