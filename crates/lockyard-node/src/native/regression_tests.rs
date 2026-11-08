// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

#[cfg(unix)]
use super::*;

#[cfg(unix)]
#[test]
fn native_limit_metadata_rejects_symlink_and_oversized_files() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let name = "lockyard-worker-fixed-job";
    let output = root
        .path()
        .join(format!("native-events-{}.json", identity(name)));
    let foreign = root.path().join("foreign-events.json");
    fs::write(&foreign, br#"{"oom_kill":1}"#).unwrap();
    symlink(&foreign, &output).unwrap();
    assert_eq!(
        limit_error(root.path(), name),
        None,
        "do not follow a substituted events file"
    );
    fs::remove_file(&output).unwrap();
    let mut events = std::collections::BTreeMap::new();
    events.insert("oom_kill".to_owned(), 1u64);
    for index in 0..1024 {
        events.insert(format!("unexpected-{index:04}-{}", "x".repeat(128)), 0);
    }
    fs::write(&output, serde_json::to_vec(&events).unwrap()).unwrap();
    assert_eq!(
        limit_error(root.path(), name),
        None,
        "kernel event metadata is bounded; oversized persisted data is corrupt"
    );
}

#[cfg(unix)]
#[test]
fn native_stop_absent_group_rejects_seeded_torn_and_unbound_receipts() {
    use std::os::unix::fs::PermissionsExt;
    // Exercise the exact production cleanup-receipt parser without pretending to enforce cgroups.
    // It is parser/recovery evidence, not a positive cgroup enforcement test.
    let root = tempfile::tempdir().unwrap();
    let delegated = root.path().join("delegated");
    fs::create_dir(&delegated).unwrap();
    let name = "lockyard-worker-fixed-job";
    let output = root
        .path()
        .join(format!("native-events-{}.json", identity(name)));
    let mut seed = 0x5bfa_1d49_cca0_173du64;
    let expected = delegated.join("expected-group");
    let valid = CleanupReceipt {
        version: 1,
        identity: identity(name),
        cgroup: expected.clone(),
        stopped: true,
        events: std::collections::BTreeMap::new(),
    };
    fs::write(&output, serde_json::to_vec(&valid).unwrap()).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(cleanup_receipt(root.path(), name, Some(&expected)).is_some());
    assert!(cleanup_receipt(root.path(), "another-command", Some(&expected)).is_none());
    assert!(cleanup_receipt(root.path(), name, Some(&delegated.join("wrong-group"))).is_none());
    let mut cases = vec![
        Vec::new(),
        b"{".to_vec(),
        b"{}".to_vec(),
        br#"{"oom":0,"pids_max":0}"#.to_vec(),
        br#"{"job_id":"another-job","populated":0}"#.to_vec(),
    ];
    for _ in 0..64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let bytes = serde_json::to_vec(&serde_json::json!({"unbound": seed, "oom": 0})).unwrap();
        let length = (seed as usize) % bytes.len();
        cases.push(bytes[..length].to_vec());
    }
    for (index, bytes) in cases.iter().enumerate() {
        fs::write(&output, bytes).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            cleanup_receipt(root.path(), name, Some(&delegated.join("expected-group"))).is_none(),
            "unproven cleanup accepted seed case {index}: {bytes:?}"
        );
    }
}
