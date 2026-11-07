// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use lockyard_cloud_client::{ApiError, ClientError};
use serde_json::json;

#[test]
fn authentication_errors_stop_outbox_retries_until_explicit_authentication() {
    for code in ["unauthorized", "credential_revoked", "sso_session_revoked"] {
        let error = ClientError::from_api(ApiError {
            status: 401,
            code: code.into(),
            ..ApiError::default()
        });
        assert!(
            !error.is_outage(),
            "{code} requires explicit authentication"
        );
    }
}

#[test]
fn problem_and_legacy_error_envelopes_preserve_identical_fields() {
    let details = json!({"min_protocol":2});
    let modern = json!({"type":"urn:lockyard:problem:upgrade_required","status":400,"code":"upgrade_required","detail":"upgrade","details":details});
    let legacy = json!({"error":{"code":"upgrade_required","message":"upgrade","details":details}});
    let modern = ApiError::parse(400, &modern.to_string(), Some(3));
    let legacy = ApiError::parse(400, &legacy.to_string(), Some(3));
    assert_eq!(modern, legacy);
}

#[test]
fn duplicate_problem_code_is_rejected_even_when_last_code_looks_valid() {
    let error = ApiError::parse(
        400,
        r#"{"status":400,"code":"upgrade_required","code":"feature_unsupported","detail":"x","details":{}}"#,
        None,
    );
    assert_eq!(error.code, "protocol_response_invalid");
}

#[test]
fn contradictory_problem_http_status_is_rejected() {
    let error = ApiError::parse(
        403,
        r#"{"status":400,"code":"forbidden","detail":"x","details":{}}"#,
        None,
    );
    assert_eq!(error.code, "protocol_response_invalid");
}

#[test]
fn unknown_problem_code_is_preserved_without_an_outage_retry() {
    let api = ApiError::parse(
        503,
        r#"{"status":503,"code":"future_server_code","detail":"x","details":{"safe":true}}"#,
        None,
    );
    assert_eq!(api.code, "future_server_code");
    assert_eq!(api.details, json!({"safe":true}));
    assert!(!ClientError::from_api(api).is_outage());
}

#[test]
fn workspace_encryption_policy_rejects_unnegotiated_fields() {
    let decoded = serde_json::from_value::<lockyard_cloud_client::WorkspaceEncryption>(json!({
        "encryption":"off", "key_id":null, "workspace_id":"w", "future_required_policy":"unsupported"
    }));
    assert!(decoded.is_err());
}
