// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Performance budget (no network). CI fails when the local hook decision or a local
//! `msg send` regresses past the documented p95 ceilings.
//! Windows and macOS CI run these same raw subprocess budgets serially with the release binary.
//!
//! Budgets are deliberately looser than a quiet laptop (owner baseline: hook ~4 ms p95,
//! msg send ~4 ms) so a shared CI runner does not flake, and tight enough to catch a
//! multi-hundred-millisecond regression.

use lockyard_core::proto::InboxQuery;
use lockyard_core::{Backend, Store, ZonePath};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const SAMPLES: usize = 80;
// Every OS uses one attempt and raw subprocess timings; diagnostics run separately.
const HOOK_P95: Duration = Duration::from_millis(15);
// Owner decision 2026-11-08: Windows send p95 <= 35 ms. SQLite synchronous=FULL
// pays FlushFileBuffers (p50 4.7 ms / p95 ~10 ms) plus 7-8 ms process startup.
// CI run 42504694714: raw send p95 22.0/29.1 ms; profiled p95 18.8-19.6 ms,
// max ~40 ms. Keep durability and one attempt; no best-of-three acceptance.
#[cfg(windows)]
const SEND_P95: Duration = Duration::from_millis(35);
#[cfg(not(windows))]
const SEND_P95: Duration = Duration::from_millis(20);

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lockyard"));
    command.env_remove("LOCKYARD_AGENT");
    command.env_remove("LOCKYARD_PERF_TRACE");
    command
}

fn p95(samples: &mut [Duration]) -> Duration {
    samples.sort_unstable();
    samples[samples.len() * 95 / 100]
}

fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    Store::init(dir.path()).unwrap();
    dir
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

#[test]
fn hook_decision_p95_stays_within_budget() {
    let dir = project();
    let root = dir.path().canonicalize().unwrap();
    let mut store = Store::open(&root).unwrap();
    let now = now_ms();
    Backend::touch_agent(&mut store, "alice", now).unwrap();
    Backend::touch_agent(&mut store, "bob", now).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    store
        .claim("bob", &[ZonePath::stored("src".into())], "held", 30, now)
        .unwrap();

    let event = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "alice",
        "cwd": root,
        "tool_name": "Edit",
        "tool_input": {"file_path": root.join("src/a.rs")},
    })
    .to_string();

    let mut times = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let output = binary()
            .args(["hook", "claude"])
            .current_dir(&root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(event.as_bytes())?;
                child.wait_with_output()
            })
            .unwrap();
        times.push(started.elapsed());
        assert!(output.status.success(), "hook failed: {output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("deny") || text.contains("permissionDecision"),
            "expected a deny decision, got stdout={text} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let usual = p95(&mut times);
    eprintln!(
        "perf_budget hook_decision samples={SAMPLES} p50_us={} p95_us={} budget_us={}",
        times[SAMPLES / 2].as_micros(),
        usual.as_micros(),
        HOOK_P95.as_micros()
    );
    assert!(
        usual <= HOOK_P95,
        "hook decision p95 was {usual:?}, budget is {HOOK_P95:?}"
    );
}

#[test]
fn msg_send_p95_stays_within_budget() {
    let dir = project();
    let root = dir.path();
    warm_agents(root);

    let mut times = Vec::with_capacity(SAMPLES);
    for index in 0..SAMPLES {
        let started = Instant::now();
        let output = binary()
            .args([
                "--agent",
                "alice",
                "msg",
                "send",
                "bob",
                &format!("budget-{index}"),
            ])
            .current_dir(root)
            .output()
            .unwrap();
        times.push(started.elapsed());
        assert!(
            output.status.success(),
            "msg send failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let usual = p95(&mut times);
    eprintln!(
        "perf_budget msg_send samples={SAMPLES} p50_us={} p95_us={} budget_us={}",
        times[SAMPLES / 2].as_micros(),
        usual.as_micros(),
        SEND_P95.as_micros()
    );
    assert!(
        usual <= SEND_P95,
        "msg send p95 was {usual:?}, budget is {SEND_P95:?}"
    );

    let mut store = Store::open(root).unwrap();
    let inbox = Backend::inbox(
        &mut store,
        "bob",
        InboxQuery {
            all: true,
            limit: 200,
        },
        1,
    )
    .unwrap();
    assert!(inbox.messages.len() >= SAMPLES);
}

fn warm_agents(root: &Path) {
    let mut store = Store::open(root).unwrap();
    Backend::touch_agent(&mut store, "alice", 0).unwrap();
    Backend::touch_agent(&mut store, "bob", 0).unwrap();
    // One send through the library so the first CLI spawn is not paying init alone.
    store.send("alice", "bob", "warm", 0).unwrap();
}
