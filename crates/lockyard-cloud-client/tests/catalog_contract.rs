// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use serde_json::{Value, json};
const MANIFEST: &str = include_str!("../content-fields.json");
const OPENAPI: &str = include_str!("fixtures/openapi.json");

#[test]
fn zone_catalog_contract_has_one_content_field_and_explicit_clear_metadata() {
    let table: Value = serde_json::from_str(MANIFEST).unwrap();
    let fields = table["fields"].as_array().unwrap();
    let catalog = fields
        .iter()
        .filter(|entry| entry["schema"] == "CoordinationZoneCatalog")
        .collect::<Vec<_>>();
    assert_eq!(
        catalog,
        vec![
            &json!({"schema":"CoordinationZoneCatalog","property":"content","name":"zone_catalog_content"})
        ]
    );
    let clear = table["clear"].as_array().unwrap();
    for name in [
        "format",
        "workspace_id",
        "repository",
        "revision",
        "key_id",
        "case_insensitive_paths",
        "content_sha256",
        "metadata_hmac",
    ] {
        assert_eq!(
            clear
                .iter()
                .filter(|entry| entry["schema"] == "CoordinationZoneCatalog"
                    && entry["property"] == name)
                .count(),
            1,
            "unclassified catalog metadata {name}"
        );
    }
    assert!(clear.contains(
        &json!({"schema":"CoordinationZoneCatalogWrite","property":"expected_revision"})
    ));
}

#[test]
fn zone_catalog_contract_has_closed_wire_and_cas_schemas_and_referenced_routes() {
    let api: Value = serde_json::from_str(OPENAPI).unwrap();
    let schemas = &api["components"]["schemas"];
    let wire = &schemas["CoordinationZoneCatalog"];
    assert_eq!(wire["type"], "object");
    assert_eq!(wire["additionalProperties"], false);
    let fields = [
        ("format", "string"),
        ("workspace_id", "string"),
        ("repository", "string"),
        ("revision", "integer"),
        ("key_id", "string"),
        ("case_insensitive_paths", "boolean"),
        ("content_sha256", "string"),
        ("content", "string"),
        ("metadata_hmac", "string"),
    ];
    assert_eq!(wire["properties"].as_object().unwrap().len(), fields.len());
    assert_eq!(wire["required"].as_array().unwrap().len(), fields.len());
    for (name, kind) in fields {
        assert_eq!(wire["properties"][name]["type"], kind);
        assert!(wire["required"].as_array().unwrap().contains(&json!(name)));
    }
    assert_eq!(
        wire["properties"]["format"]["const"],
        "lockyard.zone_catalog.v1"
    );
    assert_eq!(wire["properties"]["revision"]["minimum"], 1);
    assert_eq!(
        wire["properties"]["revision"]["maximum"],
        9_007_199_254_740_991u64
    );
    let write = &schemas["CoordinationZoneCatalogWrite"];
    assert_eq!(write["additionalProperties"], false);
    assert_eq!(write["required"], json!(["expected_revision", "catalog"]));
    assert_eq!(write["properties"]["expected_revision"]["type"], "integer");
    assert_eq!(write["properties"]["expected_revision"]["minimum"], 0);
    assert_eq!(
        write["properties"]["catalog"]["$ref"],
        "#/components/schemas/CoordinationZoneCatalog"
    );
    let route = &api["paths"]["/api/v1/zones/catalog"];
    for method in ["get", "post"] {
        let operation = &route[method];
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/CoordinationZoneCatalog"
        );
        assert_eq!(
            operation["responses"]["200"]["headers"]["Cache-Control"]["schema"]["const"],
            "no-store"
        );
        for status in ["400", "401", "403", "409", "413", "422", "429", "503"] {
            assert_eq!(
                operation["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"],
                "#/components/schemas/ApiProblem",
                "{method} {status}"
            );
        }
    }
    assert_eq!(
        route["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CoordinationZoneCatalogWrite"
    );
}

#[test]
fn full_server_contract_includes_protocol_drain_and_protocol_headers() {
    let api: Value = serde_json::from_str(OPENAPI).unwrap();
    for (path, method, schema) in [
        ("/api/v1/protocol", "get", "ProtocolDescription"),
        ("/api/v1/admin/drain", "post", "DrainStatus"),
        ("/api/v1/admin/drain/{id}", "get", "DrainStatus"),
    ] {
        let operation = &api["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{schema}")
        );
    }
    let signed_result = &api["paths"]["/api/v1/nodes/{node_id}/jobs/{job_id}/signed-result"];
    assert_eq!(
        signed_result["put"]["requestBody"]["content"]["application/octet-stream"]["schema"]["format"],
        "binary"
    );
    assert_eq!(
        signed_result["get"]["responses"]["200"]["content"]["application/octet-stream"]["schema"]["format"],
        "binary"
    );
    assert!(signed_result["put"]["responses"]["204"].is_object());
    assert!(
        signed_result["put"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|parameter| {
                parameter["in"] == "header"
                    && parameter["name"] == "Lockyard-Result-Expires-At"
                    && parameter["required"] == true
            })
    );
    assert!(
        signed_result["get"]["responses"]["200"]["headers"]["Lockyard-Result-Expires-At"]
            .is_object()
    );
    for (path, operations) in api["paths"].as_object().unwrap() {
        // EP-10 negotiates the versioned API; public health/auth routes are separate.
        if !path.starts_with("/api/v1/") {
            continue;
        }
        for method in ["get", "post", "put", "patch", "delete"] {
            let Some(operation) = operations.get(method) else {
                continue;
            };
            assert!(
                operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|parameter| {
                        parameter["in"] == "header" && parameter["name"] == "Lockyard-Protocol"
                    }),
                "missing protocol request header on {method} {path}"
            );
            for (status, response) in operation["responses"].as_object().unwrap() {
                for header in [
                    "Lockyard-Protocol",
                    "Lockyard-Protocol-Min",
                    "Lockyard-Protocol-Max",
                ] {
                    assert!(
                        response["headers"][header].is_object(),
                        "missing {header} on {method} {path} {status}"
                    );
                }
            }
        }
    }
}

#[test]
fn owner_word_manifest_declares_versioned_contextual_selectors() {
    let table: Value = serde_json::from_str(MANIFEST).unwrap();
    assert_eq!(table["version"], 2);
    assert_eq!(table["protocol_min"], 2);
    assert_eq!(
        table["selectors"],
        json!([
            {"schema":"RegistryEvidenceDto","property":"value","name":"owner_word","when":{"kind":["decision"],"source":["direct_owner","relayed_owner"]}},
            {"schema":"RegistryEventDto","property":"reason","name":"owner_word","when":{"op":["owner_closed"]}}
        ])
    );
}
