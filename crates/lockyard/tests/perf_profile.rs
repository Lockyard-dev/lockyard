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
const TAIL_SAMPLES: usize = 8;

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
        let mut io_stats: BTreeMap<String, Vec<(u128, u128)>> = BTreeMap::new();
        let mut samples = Vec::new();
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
            let wall_us = started.elapsed().as_micros();
            wall.push(wall_us);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if case == "hook" {
                assert!(String::from_utf8_lossy(&output.stdout).contains("permissionDecision"));
            }
            let mut per_process: BTreeMap<String, (u128, usize)> = BTreeMap::new();
            let mut per_process_io: BTreeMap<String, (usize, u128, u128)> = BTreeMap::new();
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stderr.lines() {
                if let Some((label, value)) = line
                    .strip_prefix("perf_span ")
                    .and_then(|line| line.split_once(" us="))
                {
                    let entry = per_process.entry(label.into()).or_default();
                    entry.0 += value.parse::<u128>().unwrap();
                    entry.1 += 1;
                }
                if let Some((label, values)) = line
                    .strip_prefix("perf_io ")
                    .and_then(|line| line.split_once(" calls="))
                {
                    let (calls, values) = values.split_once(" max_us=").unwrap();
                    let (max_us, requested_ms) = values.split_once(" requested_ms=").unwrap();
                    per_process_io.insert(
                        label.into(),
                        (
                            calls.parse().unwrap(),
                            max_us.parse().unwrap(),
                            requested_ms.parse().unwrap(),
                        ),
                    );
                }
            }
            // A perf_io line summarizes many forwarded calls; the corresponding perf_span
            // line is emitted once. Report the actual syscall count instead of that one line.
            for (label, (calls, max_us, requested_ms)) in &per_process_io {
                per_process.get_mut(label).unwrap().1 = *calls;
                io_stats
                    .entry(label.clone())
                    .or_default()
                    .push((*max_us, *requested_ms));
            }
            assert!(
                per_process.contains_key("process.main"),
                "diagnostic spans missing"
            );
            #[cfg(windows)]
            {
                assert!(
                    stderr.lines().any(|line| {
                        line == "perf_diag windows.sqlite_syscalls installed=8 requested=8"
                    }),
                    "Windows SQLite forwarding probes incomplete: {stderr}"
                );
                if matches!(case, "send" | "send_due") {
                    assert!(
                        per_process_io
                            .get("windows.sqlite.flush_file_buffers")
                            .is_some_and(|(calls, _, _)| *calls > 0),
                        "Windows durable-send flush probe did not execute: {stderr}"
                    );
                    for label in [
                        "message.touch_sender",
                        "message.recipient_lookup",
                        "message.retention",
                        "message.insert",
                        "sqlite.begin_immediate",
                    ] {
                        assert!(
                            per_process.contains_key(label),
                            "Windows send diagnostic span missing: {label}"
                        );
                    }
                }
            }
            for (label, value) in &per_process {
                spans.entry(label.clone()).or_default().push(*value);
            }
            samples.push((index, wall_us, per_process, per_process_io));
        }
        wall.sort_unstable();
        eprintln!(
            "perf_profile case={case} samples={SAMPLES} wall_p50_us={} wall_p95_us={} wall_max_us={}",
            wall[SAMPLES / 2],
            wall[SAMPLES * 95 / 100],
            wall[SAMPLES - 1]
        );
        for (label, values) in spans {
            let mut us: Vec<_> = values.iter().map(|v| v.0).collect();
            us.sort_unstable();
            let mut calls: Vec<_> = values.iter().map(|v| v.1).collect();
            calls.sort_unstable();
            eprintln!(
                "perf_profile case={case} span={label} samples={} p50_us={} p95_us={} max_us={} calls_p50={} calls_p95={}",
                us.len(),
                us[us.len() / 2],
                us[us.len() * 95 / 100],
                us[us.len() - 1],
                calls[calls.len() / 2],
                calls[calls.len() * 95 / 100]
            );
        }
        for (label, values) in io_stats {
            let mut max_us: Vec<_> = values.iter().map(|v| v.0).collect();
            max_us.sort_unstable();
            let mut requested_ms: Vec<_> = values.iter().map(|v| v.1).collect();
            requested_ms.sort_unstable();
            eprintln!(
                "perf_profile_io case={case} span={label} samples={} call_max_p95_us={} call_max_us={} requested_p95_ms={} requested_max_ms={}",
                max_us.len(),
                max_us[max_us.len() * 95 / 100],
                max_us[max_us.len() - 1],
                requested_ms[requested_ms.len() * 95 / 100],
                requested_ms[requested_ms.len() - 1],
            );
        }
        // Independent p95 values can describe different processes. Keep the complete span map
        // for the same eight slowest subprocesses so a CI tail can be attributed accurately.
        samples.sort_unstable_by_key(|(index, wall_us, _, _)| (*wall_us, *index));
        for (index, wall_us, per_process, per_process_io) in samples.iter().rev().take(TAIL_SAMPLES)
        {
            let main_us = per_process["process.main"].0;
            eprintln!(
                "perf_profile_tail case={case} sample={index} wall_us={wall_us} wall_minus_main_us={} spans_us_calls={} io_calls_max_us_requested_ms={}",
                wall_us.saturating_sub(main_us),
                serde_json::to_string(per_process).unwrap(),
                serde_json::to_string(per_process_io).unwrap(),
            );
        }
    }
}
