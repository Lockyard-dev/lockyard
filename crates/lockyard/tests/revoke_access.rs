#![cfg(unix)]
use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
fn revoke_cli_accepts_all_contract_target_forms() {
    let output = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["revoke", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    for name in ["identity", "token", "cert-pin", "sso-session"] {
        assert!(help.contains(name), "{name}: {help}");
    }
}
#[test]
fn revoke_mcp_full_and_compact_use_same_tool_schema() {
    let mut schemas = Vec::new();
    for surface in ["compact", "full"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lockyard"))
            .args(["mcp", "--tools", surface])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        let tools = response
            .pointer("/result/tools")
            .unwrap()
            .as_array()
            .unwrap();
        let tool = tools
            .iter()
            .find(|t| t["name"] == "revoke_access")
            .expect("revoke_access must be listed");
        schemas.push(tool["inputSchema"].clone());
    }
    assert_eq!(schemas[0], schemas[1]);
}
mod revoke_support;
use revoke_support::{Mode, Server, invoke, project};
fn assert_missing_trust_refuses_without_bootstrap(surface: Option<&str>) {
    let server = Server::start(Mode::Normal);
    let root = revoke_support::project_without_trust(&server.url);
    let trust_path = revoke_support::trust_path(root.path(), &server.url);
    assert!(!trust_path.exists());
    let (exit, result) = revoke_support::invoke_surface(root.path(), &server.url, surface);
    let outcome = if surface.is_some() {
        assert_eq!(result["isError"], true);
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            result["structuredContent"]
        );
        &result["structuredContent"]
    } else {
        &result
    };
    let requests = server.requests.lock().unwrap().clone();
    assert!(
        outcome["code"] == "revocation_signer_untrusted"
            && outcome["cloud_committed"] == false
            && outcome["local_applied"] == false
            && outcome["hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("lockyard node revocation-trust"))
            && !trust_path.exists()
            && !root.path().join(".lockyard/private-revocations").exists()
            && requests.is_empty()
            && server.posts.lock().unwrap().is_empty()
            && (surface.is_some() || exit == 1),
        "surface={surface:?}, exit={exit}, outcome={outcome}, trust_exists={}, requests={requests:?}",
        trust_path.exists(),
    );
}

#[test]
fn missing_trust_cli_refuses_without_bootstrap() {
    assert_missing_trust_refuses_without_bootstrap(None);
}

#[test]
fn missing_trust_compact_mcp_refuses_without_bootstrap() {
    assert_missing_trust_refuses_without_bootstrap(Some("compact"));
}

#[test]
fn missing_trust_full_mcp_refuses_without_bootstrap() {
    assert_missing_trust_refuses_without_bootstrap(Some("full"));
}

fn assert_legacy_node_config_refuses_without_bootstrap(surface: Option<&str>) {
    for cached_trust in [false, true] {
        let server = Server::start(Mode::Normal);
        let root = if cached_trust {
            project(&server.url)
        } else {
            revoke_support::project_without_trust(&server.url)
        };
        let trust_path = revoke_support::trust_path(root.path(), &server.url);
        let before = std::fs::read(&trust_path).ok();
        let node_config = revoke_support::legacy_node_config(root.path());
        let (exit, result) = revoke_support::invoke_with_node_config(
            root.path(),
            &server.url,
            surface,
            Some(&node_config),
        );
        let outcome = if surface.is_some() {
            assert_eq!(result["isError"], true);
            &result["structuredContent"]
        } else {
            assert_eq!(exit, 1);
            &result
        };
        assert_eq!(outcome["code"], "revocation_signer_untrusted", "{result}");
        assert_eq!(outcome["cloud_committed"], false);
        assert!(
            outcome["hint"]
                .as_str()
                .unwrap()
                .contains("lockyard node revocation-trust")
        );
        assert_eq!(std::fs::read(&trust_path).ok(), before);
        assert!(server.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn legacy_node_config_cli_refuses_without_bootstrap() {
    assert_legacy_node_config_refuses_without_bootstrap(None);
}

#[test]
fn legacy_node_config_compact_mcp_refuses_without_bootstrap() {
    assert_legacy_node_config_refuses_without_bootstrap(Some("compact"));
}

#[test]
fn legacy_node_config_full_mcp_refuses_without_bootstrap() {
    assert_legacy_node_config_refuses_without_bootstrap(Some("full"));
}

#[test]
fn malformed_persisted_trust_cli_refuses_without_network() {
    let server = Server::start(Mode::Normal);
    let root = project(&server.url);
    let trust_path = revoke_support::trust_path(root.path(), &server.url);
    std::fs::write(&trust_path, b"malformed json").unwrap();
    let (exit, outcome) = invoke(root.path(), &server.url, false);
    assert_eq!(exit, 1);
    assert_eq!(outcome["code"], "revocation_signer_untrusted");
    assert_eq!(outcome["cloud_committed"], false);
    assert!(outcome["hint"].is_string());
    assert_eq!(std::fs::read(&trust_path).unwrap(), b"malformed json");
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn invalid_persisted_trust_mcp_refuses_without_network() {
    for surface in ["compact", "full"] {
        let server = Server::start(Mode::Normal);
        let root = project(&server.url);
        let trust_path = revoke_support::trust_path(root.path(), &server.url);
        let mut trust: Value =
            serde_json::from_slice(&std::fs::read(&trust_path).unwrap()).unwrap();
        trust["public_key"] = Value::String("0".repeat(64));
        let before = serde_json::to_vec(&trust).unwrap();
        std::fs::write(&trust_path, &before).unwrap();
        let (_, result) = revoke_support::invoke_surface(root.path(), &server.url, Some(surface));
        assert_eq!(result["isError"], true);
        let outcome = &result["structuredContent"];
        assert_eq!(outcome["code"], "revocation_signer_untrusted");
        assert_eq!(outcome["cloud_committed"], false);
        assert!(outcome["hint"].is_string());
        assert_eq!(std::fs::read(&trust_path).unwrap(), before);
        assert!(server.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn cloud_commit_closure_partial_cli_and_mcp_have_identical_structured_outcome() {
    let server = Server::start(Mode::Normal);
    let cli_root = project(&server.url);
    let mcp_root = project(&server.url);
    let (exit, cli) = invoke(cli_root.path(), &server.url, false);
    assert_eq!(exit, 2);
    assert_eq!(cli["cloud_committed"], true);
    assert_eq!(cli["local_applied"], false);
    assert_eq!(cli["propagation_complete"], false);
    let (_, mcp) = invoke(mcp_root.path(), &server.url, true);
    assert_eq!(mcp["isError"], true);
    assert_eq!(mcp["structuredContent"], cli);
    assert_eq!(
        serde_json::from_str::<Value>(mcp["content"][0]["text"].as_str().unwrap()).unwrap(),
        cli
    );
}
#[test]
fn lost_reply_reuses_exact_key_and_body_and_resume_never_posts_new_mutation() {
    let server = Server::start(Mode::LostReply);
    let root = project(&server.url);
    let (exit, result) = invoke(root.path(), &server.url, false);
    assert_eq!(exit, 2);
    assert_eq!(result["cloud_committed"], true);
    let posts = server.posts.lock().unwrap().clone();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
    assert_eq!(posts[0].0.len(), 26);
    let (_, resumed) = invoke(root.path(), &server.url, false);
    assert_eq!(resumed["cloud_committed"], true);
    assert_eq!(server.posts.lock().unwrap().len(), 2);
}
#[test]
fn unknown_commit_persists_pending_and_restart_does_not_generate_another_write() {
    let server = Server::start(Mode::Unknown);
    let root = project(&server.url);
    let (exit, result) = invoke(root.path(), &server.url, false);
    assert_eq!(exit, 1);
    assert!(result["cloud_committed"].is_null());
    assert_eq!(result["code"], "revocation_commit_unknown");
    let posts = server.posts.lock().unwrap().clone();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0], posts[1]);
    let (_, resumed) = invoke(root.path(), &server.url, false);
    assert_eq!(resumed["code"], "revocation_commit_unknown");
    assert_eq!(server.posts.lock().unwrap().len(), 2);
    let files = std::fs::read_dir(root.path().join(".lockyard/private-revocations")).unwrap();
    for file in files {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            file.unwrap().metadata().unwrap().permissions().mode() & 0o077,
            0
        );
    }
}
#[test]
fn closure_failure_keeps_commit_true_and_legacy_cloud_never_receives_post() {
    let server = Server::start(Mode::ClosureUnavailable);
    let root = project(&server.url);
    let (exit, result) = invoke(root.path(), &server.url, false);
    assert_eq!(exit, 2);
    assert_eq!(result["cloud_committed"], true);
    assert_eq!(result["code"], "revocation_state_unavailable");
    let legacy = Server::start(Mode::Legacy);
    let root = project(&legacy.url);
    let (exit, result) = invoke(root.path(), &legacy.url, false);
    assert_eq!(exit, 1);
    assert_eq!(result["cloud_committed"], false);
    assert_eq!(result["code"], "revocation_protocol_unavailable");
    assert!(legacy.posts.lock().unwrap().is_empty());
}

#[test]
fn definite_http_failure_survives_pending_state_write_failure_for_cli_and_mcp() {
    use std::os::unix::fs::PermissionsExt;
    for mcp in [false, true] {
        let server = Server::start(Mode::DeniedStateFailure);
        let root = project(&server.url);
        let directory = root.path().join(".lockyard/private-revocations");
        *server.fail_state.lock().unwrap() = Some(directory.clone());
        let (exit, result) = invoke(root.path(), &server.url, mcp);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let outcome = if mcp {
            assert_eq!(result["isError"], true);
            &result["structuredContent"]
        } else {
            assert_eq!(exit, 1);
            &result
        };
        assert_eq!(outcome["cloud_committed"], false);
        assert_eq!(outcome["code"], "forbidden");
        assert_eq!(server.posts.lock().unwrap().len(), 1);
    }
}

#[test]
fn signed_older_or_omitted_target_closure_never_claims_direct_application() {
    for mode in [Mode::StaleClosure, Mode::OmittedTarget] {
        let server = Server::start(mode);
        let root = project(&server.url);
        let (exit, result) = invoke(root.path(), &server.url, false);
        assert_eq!(exit, 2);
        assert_eq!(result["cloud_committed"], true);
        assert_eq!(result["epoch"], 1);
        assert_eq!(result["code"], "protocol_response_invalid");
        assert_eq!(result["local_applied"], false);
        assert_eq!(result["propagation_complete"], false);
    }
}

#[test]
fn confirmed_commit_survives_receipt_persistence_failure_for_cli_and_mcp() {
    use std::os::unix::fs::PermissionsExt;
    for mcp in [false, true] {
        let server = Server::start(Mode::CommittedStateFailure);
        let root = project(&server.url);
        let directory = root.path().join(".lockyard/private-revocations");
        *server.fail_state.lock().unwrap() = Some(directory.clone());
        let (exit, result) = invoke(root.path(), &server.url, mcp);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let outcome = if mcp {
            assert_eq!(result["isError"], true);
            &result["structuredContent"]
        } else {
            assert_eq!(exit, 2);
            &result
        };
        assert_eq!(outcome["cloud_committed"], true);
        assert_eq!(outcome["epoch"], 1);
        assert_eq!(outcome["code"], "revocation_state_unavailable");
        assert_eq!(server.posts.lock().unwrap().len(), 1);
    }
}

#[test]
fn equivalent_trailing_slash_url_cannot_bootstrap_a_rotated_signer() {
    let server = Server::start(Mode::Normal);
    let root = project(&server.url);
    let (_, first) = invoke(root.path(), &server.url, false);
    assert_eq!(first["cloud_committed"], true);
    server
        .signer_seed
        .store(8, std::sync::atomic::Ordering::SeqCst);
    std::fs::write(
        root.path().join(".lockyard/config.toml"),
        format!("mode='cloud'\nurl='{}/'\nworkspace='team'\n", server.url),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .current_dir(root.path())
        .env("LOCKYARD_URL", &server.url)
        .env("LOCKYARD_TOKEN", "fixture-token")
        .env("XDG_STATE_HOME", root.path().join("private-command-state"))
        .env_remove("LOCKYARD_REQUIRE_E2EE")
        .env_remove("LOCKYARD_E2EE_WORKSPACE_ID")
        .args([
            "revoke",
            "token",
            "44444444-4444-4444-8444-444444444444",
            "--json",
        ])
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(result["code"], "revocation_signer_untrusted");
    assert_eq!(result["cloud_committed"], false);
    assert_eq!(server.posts.lock().unwrap().len(), 1);
}
