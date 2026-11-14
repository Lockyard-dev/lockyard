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

fn task_error_text(code: &str, status: u16, details: serde_json::Value) -> String {
    let api = ApiError {
        code: code.into(),
        status,
        message: "server fixture".into(),
        details: details.clone(),
        ..ApiError::default()
    };
    let displayed = api.to_string();
    let error = lockyard_core::Error::from(ClientError::from_api(api));
    match &error {
        lockyard_core::Error::Cloud {
            code: actual,
            status: actual_status,
            details: actual_details,
            message,
        } => {
            assert_eq!(actual, code);
            assert_eq!(*actual_status, Some(status));
            assert_eq!(actual_details, &details);
            assert_eq!(message, &displayed);
        }
        _ => panic!("stable cloud failure lost: {error:?}"),
    }
    displayed
}

#[test]
fn task_paths_required_explains_cli_and_mcp_input_forms() {
    let text = task_error_text("task_paths_required", 422, json!({}));
    assert!(
        text.contains("--path <путь>") && text.contains("paths: [\"репозиторий/файл\"]"),
        "{text}"
    );
    assert!(text.contains("относительно корня рабочего места"), "{text}");
}

#[test]
fn task_paths_span_repositories_lists_roots_and_separate_task_instruction() {
    let text = task_error_text(
        "task_paths_span_repositories",
        422,
        json!({"roots":["games/game-foo", "web"]}),
    );
    assert!(
        text.contains("games/game-foo") && text.contains("web"),
        "{text}"
    );
    assert!(
        text.contains("заведи по одной задаче на репозиторий"),
        "{text}"
    );
}

#[test]
fn task_area_mismatch_names_the_derived_area_and_how_to_fix_it() {
    let text = task_error_text("area_mismatch", 422, json!({"derived":"web"}));
    assert!(
        text.contains("web") && text.contains("Убери --area / area"),
        "{text}"
    );
}

#[test]
fn task_area_closed_explains_that_new_tasks_need_an_open_area() {
    let text = task_error_text("area_closed", 422, json!({}));
    assert!(
        text.contains("закрыта для новых задач") && text.contains("открытую область"),
        "{text}"
    );
}

#[test]
fn task_area_template_conflict_names_the_root_prefix_existing_area_and_lead_action() {
    let text = task_error_text(
        "area_template_conflict",
        409,
        json!({"root":"web", "prefix":"W", "existing_area":"website"}),
    );
    for part in ["web", "W", "website", "Ведущий", "добавить корень"] {
        assert!(text.contains(part), "{text}");
    }
}
