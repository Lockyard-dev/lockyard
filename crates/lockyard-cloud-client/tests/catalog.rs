// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use lockyard_cloud_client::{
    WorkspaceKey,
    catalog::{CatalogStore, seal_catalog, verify_catalog},
};
use lockyard_core::catalog::{CoordinationZoneCatalog, ZoneCatalogV1};
use serde_json::json;
const WS: &str = "00000000-0000-0000-0000-000000000001";

fn plaintext() -> ZoneCatalogV1 {
    ZoneCatalogV1::from_json(
        r#"{"version":1,"zones":{"code":["src","tests"]},"groups":{"all":["code"]}}"#,
    )
    .unwrap()
}
fn key() -> WorkspaceKey {
    WorkspaceKey::from_entropy(std::array::from_fn(|n| n as u8))
}
fn golden() -> CoordinationZoneCatalog {
    serde_json::from_value(json!({
        "format":"lockyard.zone_catalog.v1","workspace_id":WS,"repository":"api","revision":7,
        "key_id":"j6z8qD7bdq8","case_insensitive_paths":true,
        "content":"lyenc1.j6z8qD7bdq8.AAECAwQFBgcICQoLPCCgfreWq3TjY626ncsCAu2z9BbKAH0fVwOApycyIsFzc4zQjbV36wDXXbD1qwpfnDYV_Sn0maEd9kZ1OtmuzJNToh_xjFsc_xQ5EklvKBNpv3vTx0xQFg",
        "content_sha256":"c102e5636aa065f410bd13e797e36f470ff6c95fbefa053586c1ad51680faf76",
        "metadata_hmac":"2btIRyoC9s76oOyAaB4B1XuIUujZiBFxK4MEn3zQO7M"
    })).unwrap()
}

#[test]
fn zone_catalog_hmac_and_aad_vectors() {
    // Independently generated using Python hashlib/hmac HKDF and cryptography AESGCM.
    let wire = golden();
    let verified = verify_catalog(&key(), WS, "api", &wire, None).unwrap();
    assert_eq!(verified.expand(&["all".into()]).unwrap(), ["src", "tests"]);
    assert_eq!(
        verified.highwater().authenticated_fingerprint,
        "d4a96eeec7e5ed8fa12e06dadfdee203ffaca7484745bc0bbef0cfaef054e9b7"
    );
    assert_eq!(
        key()
            .decrypt(WS, "zone_catalog_content", &wire.content)
            .unwrap(),
        serde_json::to_string(&plaintext()).unwrap()
    );
    assert!(key().decrypt(WS, "owner_word", &wire.content).is_err());
    assert!(
        key()
            .decrypt(
                "00000000-0000-0000-0000-000000000002",
                "zone_catalog_content",
                &wire.content
            )
            .is_err()
    );
    for (field, value) in [
        ("format", json!("lockyard.zone_catalog.v2")),
        (
            "workspace_id",
            json!("00000000-0000-0000-0000-000000000002"),
        ),
        ("repository", json!("web")),
        ("revision", json!(8)),
        ("key_id", json!("other")),
        ("case_insensitive_paths", json!(false)),
        ("content_sha256", json!("0".repeat(64))),
        ("content", json!(wire.content.clone() + "A")),
        ("metadata_hmac", json!("A".repeat(43))),
    ] {
        let mut changed = serde_json::to_value(&wire).unwrap();
        changed[field] = value;
        let changed: CoordinationZoneCatalog = serde_json::from_value(changed).unwrap();
        assert!(
            verify_catalog(&key(), WS, "api", &changed, None).is_err(),
            "{field}"
        );
    }
    assert!(verify_catalog(&key(), WS, "web", &wire, None).is_err());
    assert_eq!(
        verify_catalog(&WorkspaceKey::from_entropy([9; 32]), WS, "api", &wire, None)
            .unwrap_err()
            .code(),
        "catalog_key_unavailable"
    );
}

#[test]
fn zone_catalog_transform_preserves_authenticated_wire_and_rejects_metadata_changes() {
    let mut value = serde_json::to_value(golden()).unwrap();
    let original = value.clone();
    lockyard_cloud_client::transform_fields(
        &mut value,
        "GET",
        "/api/v1/zones/catalog",
        WS,
        Some(&key()),
        false,
    )
    .unwrap();
    assert_eq!(
        value, original,
        "generic transform must preserve signed ciphertext byte for byte"
    );
    value["revision"] = json!(8);
    assert!(
        lockyard_cloud_client::transform_fields(
            &mut value,
            "GET",
            "/api/v1/zones/catalog",
            WS,
            Some(&key()),
            false
        )
        .is_err()
    );
}

#[test]
fn zone_catalog_seal_uses_relative_paths_and_checked_cas() {
    let first = seal_catalog(&key(), WS, "api", 0, true, &plaintext()).unwrap();
    assert_eq!(first.expected_revision, 0);
    assert_eq!(first.catalog.revision, 1);
    let verified = verify_catalog(&key(), WS, "api", &first.catalog, None).unwrap();
    assert_eq!(verified.read_json()["verified"], true);
    assert_eq!(verified.read_json()["zones"]["code"][0], "src");
    let second = seal_catalog(&key(), WS, "api", 0, true, &plaintext()).unwrap();
    assert_ne!(first.catalog.content, second.catalog.content);
    assert!(!serde_json::to_string(&first).unwrap().contains("tests"));
    assert_eq!(
        seal_catalog(&key(), WS, "api", 9_007_199_254_740_991, true, &plaintext())
            .unwrap_err()
            .code(),
        "catalog_invalid"
    );
    assert!(seal_catalog(&key(), WS, "-", 0, true, &plaintext()).is_err());
    assert!(
        seal_catalog(
            &key(),
            "00000000-0000-0000-0000-00000000000A",
            "api",
            0,
            true,
            &plaintext()
        )
        .is_err()
    );
}

#[test]
fn zone_catalog_replay_highwater_survives_restart_and_rotation() {
    let directory = std::env::temp_dir().join(format!("ly-catalog-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let path = directory.join("catalog");
    let store = CatalogStore::new(path.clone());
    store.accept(&key(), WS, "api", &golden()).unwrap();
    let store = CatalogStore::new(path);
    assert_eq!(
        store.offline(&key(), WS, "api").unwrap().read_json()["offline"],
        true
    );
    let old = seal_catalog(&key(), WS, "api", 5, true, &plaintext())
        .unwrap()
        .catalog;
    assert_eq!(
        store.accept(&key(), WS, "api", &old).unwrap_err().code(),
        "catalog_replay_detected"
    );
    for case in [true, false] {
        let changed = seal_catalog(&key(), WS, "api", 6, case, &plaintext())
            .unwrap()
            .catalog;
        assert_eq!(
            store
                .accept(&key(), WS, "api", &changed)
                .unwrap_err()
                .code(),
            "catalog_replay_detected"
        );
    }
    // Same exact ciphertext and revision with another valid MAC-bound case policy is a replay.
    let mut changed_policy = golden();
    changed_policy.case_insensitive_paths = false;
    let child = key()
        .derive_context(
            b"lockyard-zone-catalog-metadata-hmac-v1",
            &serde_json::to_vec(&[WS, "api"]).unwrap(),
        )
        .unwrap();
    changed_policy.metadata_hmac = child.sign_hmac(
        &serde_json::to_vec(&json!([
            changed_policy.format,
            changed_policy.workspace_id,
            changed_policy.repository,
            changed_policy.revision,
            changed_policy.key_id,
            changed_policy.case_insensitive_paths,
            changed_policy.content_sha256
        ]))
        .unwrap(),
    );
    assert_eq!(
        store
            .accept(&key(), WS, "api", &changed_policy)
            .unwrap_err()
            .code(),
        "catalog_replay_detected"
    );
    let mut invalid = seal_catalog(&key(), WS, "api", 99, true, &plaintext())
        .unwrap()
        .catalog;
    invalid.metadata_hmac = "A".repeat(43);
    assert!(store.accept(&key(), WS, "api", &invalid).is_err());
    assert_eq!(store.offline(&key(), WS, "api").unwrap().wire().revision, 7);
    let rotated = WorkspaceKey::from_entropy([8; 32]);
    let next = seal_catalog(&rotated, WS, "api", 7, true, &plaintext())
        .unwrap()
        .catalog;
    store.accept(&rotated, WS, "api", &next).unwrap();
    assert_eq!(
        store
            .accept(&key(), WS, "api", &golden())
            .unwrap_err()
            .code(),
        "catalog_replay_detected"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn zone_catalog_wire_rejects_unknown_duplicate_or_unsafe_metadata() {
    let wire = golden();
    let encoded = serde_json::to_string(&wire).unwrap();
    assert!(
        CoordinationZoneCatalog::from_json(
            &encoded.replace("\"revision\":7", "\"revision\":7,\"revision\":7")
        )
        .is_err()
    );
    let mut unknown = serde_json::to_value(&wire).unwrap();
    unknown["future"] = json!(true);
    assert!(CoordinationZoneCatalog::from_json(&unknown.to_string()).is_err());
    for invalid in [0, 9_007_199_254_740_992u64] {
        let mut value = serde_json::to_value(&wire).unwrap();
        value["revision"] = json!(invalid);
        assert!(CoordinationZoneCatalog::from_json(&value.to_string()).is_err());
    }
}

#[test]
fn zone_catalog_offline_cache_is_private_and_rejects_substitution() {
    let directory = std::env::temp_dir().join(format!("ly-catalog-private-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let path = directory.join("catalog");
    let store = CatalogStore::new(path.clone());
    assert_eq!(
        store.offline(&key(), WS, "api").unwrap_err().code(),
        "catalog_offline_unavailable"
    );
    store.accept(&key(), WS, "api", &golden()).unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains("tests"));
    assert!(store.offline(&key(), WS, "web").is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let outside = directory.join("outside");
        std::fs::rename(&path, &outside).unwrap();
        symlink(&outside, &path).unwrap();
        assert!(store.offline(&key(), WS, "api").is_err());
        assert!(store.accept(&key(), WS, "api", &golden()).is_err());
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn zone_catalog_cache_rejects_symlink_ancestors_before_creating_storage() {
    use std::os::unix::fs::{DirBuilderExt, symlink};
    let directory = std::env::temp_dir().join(format!("ly-catalog-parent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let actual = directory.join("actual");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&actual)
        .unwrap();
    symlink(&actual, directory.join("alias")).unwrap();
    let store = CatalogStore::new(directory.join("alias/nested/catalog"));
    assert!(
        store.accept(&key(), WS, "api", &golden()).is_err(),
        "a substituted ancestor must fail before a cache is created"
    );
    assert!(!actual.join("nested").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn zone_catalog_default_cache_partition_is_workspace_and_namespace_specific() {
    let first = format!("{:?}", CatalogStore::for_scope(WS, "api").unwrap());
    let second = format!(
        "{:?}",
        CatalogStore::for_scope("00000000-0000-0000-0000-000000000002", "api").unwrap()
    );
    assert_ne!(
        first, second,
        "catalog highwater must not collide between workspaces"
    );
    assert_ne!(
        format!("{:?}", CatalogStore::for_scope(WS, "").unwrap()),
        format!("{:?}", CatalogStore::for_scope(WS, "legacy").unwrap())
    );
}
