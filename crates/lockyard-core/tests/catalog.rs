// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use lockyard_core::catalog::ZoneCatalogV1;
use serde_json::json;

#[test]
fn zone_catalog_typed_plaintext_rejects_legacy_and_invalid_groups() {
    for input in [
        r#"{"zones":{"code":["src"]}}"#,
        r#"{"version":1,"zones":{"code":{"paths":["src"]}}}"#,
        r#"{"version":1,"zones":{"code":["src",7]}}"#,
        r#"{"version":1,"zones":{"code":[]}}"#,
        r#"{"version":1,"zones":{"code":["src"]},"groups":{"all":[]}}"#,
        r#"{"version":1,"zones":{"code":["src"]},"groups":{"all":["absent"]}}"#,
        r#"{"version":1,"zones":{"code":["src"]},"groups":{"code":["code"]}}"#,
        r#"{"version":1,"zones":{"code":["src"]},"groups":{"a":["b"],"b":["code"]}}"#,
        r#"{"version":1,"zones":{"code":["src"]},"future":true}"#,
        r#"{"version":1,"version":1,"zones":{}}"#,
        r#"{"version":1,"zones":{"code":["src"],"code":["tests"]}}"#,
        r#"{"version":1,"zones":{},"groups":{"all":["code"],"all":["code"]}}"#,
        r#"{"version":2,"zones":{}}"#,
        r#"[]"#,
    ] {
        assert_eq!(
            ZoneCatalogV1::from_json(input).unwrap_err().code(),
            "catalog_invalid",
            "{input}"
        );
    }
    for path in [
        "",
        "/src",
        "../src",
        "src//x",
        "src/./x",
        "src/../x",
        "src\\x",
        ".lockyard-repository",
        ".lockyard-repository/api/src",
    ] {
        assert!(
            ZoneCatalogV1::from_json(&json!({"version":1,"zones":{"code":[path]}}).to_string())
                .is_err(),
            "{path}"
        );
    }
    for name in ["".to_string(), "a".repeat(129), "a\nb".to_string()] {
        assert!(
            ZoneCatalogV1::from_json(&json!({"version":1,"zones":{name:["src"]}}).to_string())
                .is_err()
        );
    }
}

#[test]
fn zone_catalog_expansion_preserves_declared_order_and_rejects_whole_unknown_request() {
    let catalog = ZoneCatalogV1::from_json(r#"{"version":1,"zones":{"code":["src","shared"],"tests":["tests","shared"]},"groups":{"all":["tests","code"]}}"#).unwrap();
    assert_eq!(
        catalog.expand(&["all".into(), "code".into()]).unwrap(),
        ["tests", "shared", "src"]
    );
    assert_eq!(
        catalog
            .expand(&["code".into(), "absent".into()])
            .unwrap_err()
            .code(),
        "zone_unknown"
    );
    assert_eq!(
        ZoneCatalogV1::from_json(r#"{"version":1,"zones":{"root":["."]}}"#)
            .unwrap()
            .expand(&["root".into()])
            .unwrap(),
        ["."]
    );
}

#[test]
fn zone_catalog_limits_apply_before_expansion() {
    let paths = (0..257).map(|n| format!("src/{n}")).collect::<Vec<_>>();
    assert!(
        ZoneCatalogV1::from_json(&json!({"version":1,"zones":{"code":paths}}).to_string()).is_err()
    );
    assert!(
        ZoneCatalogV1::from_json(
            &json!({"version":1,"zones":{"code":["x".repeat(1025)]}}).to_string()
        )
        .is_err()
    );
    let zones = (0..1025)
        .map(|n| (format!("z{n}"), json!(["src"])))
        .collect::<serde_json::Map<_, _>>();
    assert!(ZoneCatalogV1::from_json(&json!({"version":1,"zones":zones}).to_string()).is_err());
    let first = (0..256).map(|n| format!("a/{n}")).collect::<Vec<_>>();
    let catalog =
        ZoneCatalogV1::from_json(&json!({"version":1,"zones":{"a":first,"b":["b"]}}).to_string())
            .unwrap();
    assert_eq!(
        catalog
            .expand(&["a".into(), "b".into()])
            .unwrap_err()
            .code(),
        "catalog_invalid"
    );
    assert!(ZoneCatalogV1::from_json(&" ".repeat(512 * 1024 + 1)).is_err());
    let groups = (0..1025)
        .map(|n| (format!("g{n}"), json!(["code"])))
        .collect::<serde_json::Map<_, _>>();
    assert!(
        ZoneCatalogV1::from_json(
            &json!({"version":1,"zones":{"code":["src"]},"groups":groups}).to_string()
        )
        .is_err()
    );
    let mut zones = (0..16)
        .map(|n| {
            (
                format!("z{n}"),
                json!((0..256).map(|p| format!("src/{n}/{p}")).collect::<Vec<_>>()),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    zones.insert("extra".into(), json!(["extra"]));
    assert!(ZoneCatalogV1::from_json(&json!({"version":1,"zones":zones}).to_string()).is_err());
}
