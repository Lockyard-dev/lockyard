// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#![cfg(windows)]
use lockyard_cloud_client::WorkspaceKey;
#[test]
fn workspace_key_copy_is_private_create_only_and_reloadable() {
    let directory = tempfile::tempdir().unwrap();
    lockyard_core::windows::private_dir(directory.path()).unwrap();
    let path = directory.path().join("workspace.key");
    let key = WorkspaceKey::from_entropy([17; 32]);
    key.copy_to_private(&path).unwrap();
    lockyard_core::windows::require_private(&path).unwrap();
    assert_eq!(
        WorkspaceKey::load_private(&path).unwrap().unwrap().key_id(),
        key.key_id()
    );
    assert!(
        WorkspaceKey::from_entropy([18; 32])
            .copy_to_private(&path)
            .is_err()
    );
    assert_eq!(
        WorkspaceKey::load_private(&path).unwrap().unwrap().key_id(),
        key.key_id()
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
