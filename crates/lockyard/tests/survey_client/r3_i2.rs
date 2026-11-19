// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

#[test]
fn survey1118_i2_partial_claim_warns_in_mcp_and_cli_without_losing_the_lease() {
    for (held, excluded, conflicts) in [
        (
            json!(["src", "docs"]),
            json!(["docs"]),
            json!([
                {"path":"docs","session":"bob","claim_id":7}
            ]),
        ),
        (json!(["src"]), json!(["docs"]), Value::Null),
        (
            json!(["src"]),
            json!(["docs"]),
            json!([
                {"paths":["docs"],"session":"bob","claim_id":7}
            ]),
        ),
        (
            json!(["src", "docs"]),
            json!(["src/private", "docs"]),
            json!([
                {"path":"src/private","session":"bob","claim_id":7},
                {"held_path":"docs","session":"carol","claim_id":8}
            ]),
        ),
    ] {
        for surface in ["mcp", "cli-json", "cli-text"] {
            let server = Server::start();
            let claim = json!({"id":1190,"session":"alice","paths":held,
                "excluded_paths":excluded,"conflicts":conflicts,"mode":"exclusive",
                "fence":2712,"expires_at":HOLD_EXPIRES_AT,
                "idle_release_at":"2099-11-11T21:20:00Z"});
            server.state.lock().unwrap().claim_reused_on_post = Some(claim);
            server.state.lock().unwrap().claim_created = Some(json!(true));
            let dir = cloud_project(&server);
            let runtime = tempfile::tempdir().unwrap();
            let (text, data) = if surface == "mcp" {
                let answers = mcp_calls(
                    dir.path(),
                    runtime.path(),
                    "compact",
                    &[("start_work", json!({"paths":["src", "docs"]}))],
                );
                assert_eq!(answers[0]["isError"], false, "{answers:?}");
                let answer = &answers[0]["structuredContent"];
                assert!(answer["notice"].as_str().unwrap().contains("21:20 UTC"));
                (
                    answers[0]["content"][0]["text"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    Some(answer.clone()),
                )
            } else {
                let args = if surface == "cli-json" {
                    vec!["--json", "zone", "claim", "src", "docs"]
                } else {
                    vec!["zone", "claim", "src", "docs"]
                };
                let out = cli(dir.path(), runtime.path(), &args);
                assert!(
                    out.status.success(),
                    "{surface}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                let text = String::from_utf8(out.stdout).unwrap();
                let data =
                    (surface == "cli-json").then(|| serde_json::from_str::<Value>(&text).unwrap());
                (text, data)
            };
            assert!(!text.contains("upgrade Lockyard"), "{surface}: {text}");
            let warning = data
                .as_ref()
                .map(|data| data["warning"].as_str().unwrap())
                .unwrap_or(&text);
            assert!(
                warning.contains("Заявка Z-1190 создана с исключениями"),
                "{surface}: {text}"
            );
            assert!(
                warning.contains("Эти пути не твои — подожди или напиши держателю"),
                "{surface}: {text}"
            );
            for path in excluded.as_array().unwrap() {
                assert!(
                    warning.contains(path.as_str().unwrap()),
                    "{surface}: {text}"
                );
            }
            if let Some(conflicts) = conflicts.as_array() {
                for conflict in conflicts {
                    assert!(
                        warning.contains(&format!(
                            "держатель: {}",
                            conflict["session"].as_str().unwrap()
                        )),
                        "{surface}: {text}"
                    );
                }
            }
            if let Some(data) = data {
                assert!(
                    data["warning"]
                        .as_str()
                        .unwrap()
                        .contains("Эти пути не твои")
                );
                let claim = if surface == "mcp" {
                    &data["claim"]
                } else {
                    &data
                };
                assert_eq!(claim["id"], 1190);
                assert_eq!(claim["fence"], 2712);
                assert_eq!(claim["excluded_paths"], excluded);
                if conflicts.is_array() {
                    assert_eq!(claim["conflicts"], conflicts);
                }
            }
            assert_eq!(server.seen("POST", "/api/v1/zones/claims").len(), 1);
            assert_eq!(server.state.lock().unwrap().claims.len(), 1);
            assert!(
                server
                    .state
                    .lock()
                    .unwrap()
                    .seen
                    .iter()
                    .all(|r| r.method != "DELETE")
            );
        }
    }
}

#[test]
fn survey1118_i2_actual_protocol_mismatch_still_suggests_upgrade() {
    for bad_claim in [
        json!({"session":"bob","paths":["src", "docs"],"excluded_paths":["docs"]}),
        json!({"session":"alice","paths":["other"],"excluded_paths":["docs"]}),
        json!({"session":"alice","paths":["src"],"excluded_paths":["docs/private"]}),
        json!({"session":"alice","paths":["src", "docs"],"mode":"shared"}),
    ] {
        for surface in ["mcp", "cli"] {
            let server = Server::start();
            let mut claim = bad_claim.clone();
            claim["id"] = json!(1190);
            claim["fence"] = json!(2712);
            claim["expires_at"] = json!(HOLD_EXPIRES_AT);
            server.state.lock().unwrap().claim_reused_on_post = Some(claim);
            let dir = cloud_project(&server);
            let runtime = tempfile::tempdir().unwrap();
            let text = if surface == "mcp" {
                let answers = mcp_calls(
                    dir.path(),
                    runtime.path(),
                    "compact",
                    &[(
                        "start_work",
                        json!({"paths":["src", "docs"],"shared":false}),
                    )],
                );
                assert_eq!(answers[0]["isError"], true, "{bad_claim}: {answers:?}");
                answers[0]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            } else {
                let out = cli(
                    dir.path(),
                    runtime.path(),
                    &["zone", "claim", "src", "docs", "--exclusive"],
                );
                assert!(
                    !out.status.success(),
                    "{bad_claim}: {}",
                    String::from_utf8_lossy(&out.stdout)
                );
                String::from_utf8(out.stderr).unwrap()
            };
            assert!(text.contains("upgrade Lockyard"), "{surface}: {text}");
        }
    }
}
