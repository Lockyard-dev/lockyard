// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Opt-in diagnostics, separate from the uninstrumented pass/fail latency budgets.
use lockyard_core::{Store, ZonePath};
use std::{
    collections::BTreeMap,
    io::Write,
    process::{Command, Stdio},
    time::Instant,
};

const SAMPLES: usize = 80;

#[test]
#[ignore = "opt-in hot-path diagnostics; run in release with --ignored --nocapture"]
fn profile_cli_hot_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut store = Store::init(&root).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    store.touch("alice", now).unwrap();
    store.touch("bob", now).unwrap();
    std::fs::create_dir(root.join("src")).unwrap();
    store
        .claim("bob", &[ZonePath::stored("src".into())], "profile", 30, now)
        .unwrap();
    let event = serde_json::json!({"hook_event_name":"PreToolUse","session_id":"alice","cwd":root,"tool_name":"Edit","tool_input":{"file_path":root.join("src/a.rs")}}).to_string();
    for case in ["about", "hook", "send", "send_due"] {
        let mut wall = Vec::new();
        let mut spans: BTreeMap<String, Vec<(u128, usize)>> = BTreeMap::new();
        for index in 0..SAMPLES {
            let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
            command
                .current_dir(&root)
                .env_remove("LOCKYARD_AGENT")
                .env_remove("CLAUDE_CODE_SESSION_ID")
                .env("LOCKYARD_PERF_TRACE", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let sender = if case == "send_due" {
                format!("fresh-{index}")
            } else {
                "alice".into()
            };
            match case {
                "about" => {
                    command.arg("about");
                }
                "hook" => {
                    command.args(["hook", "claude"]);
                }
                _ => {
                    command.args(["--agent", &sender, "msg", "send", "bob", "profile"]);
                }
            }
            let started = Instant::now();
            let mut child = command.spawn().unwrap();
            if case == "hook" {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(event.as_bytes())
                    .unwrap();
            }
            let output = child.wait_with_output().unwrap();
            wall.push(started.elapsed().as_micros());
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if case == "hook" {
                assert!(String::from_utf8_lossy(&output.stdout).contains("permissionDecision"));
            }
            let mut per_process: BTreeMap<String, (u128, usize)> = BTreeMap::new();
            for line in String::from_utf8_lossy(&output.stderr).lines() {
                if let Some((label, value)) = line
                    .strip_prefix("perf_span ")
                    .and_then(|line| line.split_once(" us="))
                {
                    let entry = per_process.entry(label.into()).or_default();
                    entry.0 += value.parse::<u128>().unwrap();
                    entry.1 += 1;
                }
            }
            assert!(
                per_process.contains_key("process.main"),
                "diagnostic spans missing"
            );
            for (label, value) in per_process {
                spans.entry(label).or_default().push(value);
            }
        }
        wall.sort_unstable();
        eprintln!(
            "perf_profile case={case} samples={SAMPLES} wall_p50_us={} wall_p95_us={}",
            wall[SAMPLES / 2],
            wall[SAMPLES * 95 / 100]
        );
        for (label, values) in spans {
            let mut us: Vec<_> = values.iter().map(|v| v.0).collect();
            us.sort_unstable();
            let mut calls: Vec<_> = values.iter().map(|v| v.1).collect();
            calls.sort_unstable();
            eprintln!(
                "perf_profile case={case} span={label} samples={} p50_us={} p95_us={} calls_p50={} calls_p95={}",
                us.len(),
                us[us.len() / 2],
                us[us.len() * 95 / 100],
                calls[calls.len() / 2],
                calls[calls.len() * 95 / 100]
            );
        }
    }
}
