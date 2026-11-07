// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use lockyard_compat::{OwnerDecisionV1Reader, Source, counters};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, process::Command};

const METRIC: &str = "lockyard_compat_aad_value_reads_total";
const CANARY: &str = "private owner text / ciphertext / workspace / session / task FE-0001";
const CHILD: &str = "LOCKYARD_COMPAT_OWNER_COUNTER_TEST_CHILD";

fn assert_counter_boundary() {
    for source in [Source::Cli, Source::Mcp, Source::Sdk, Source::Http] {
        let before = counters();
        let mut attempts = Vec::new();
        let canonical = OwnerDecisionV1Reader::read(source, |field| {
            attempts.push(field.to_string());
            Ok(CANARY.to_string())
        })
        .unwrap();
        assert_eq!(canonical, CANARY);
        assert_eq!(attempts, ["owner_word"]);
        assert_eq!(
            counters(),
            before,
            "canonical reads are not legacy conversions"
        );

        attempts.clear();
        let failed = OwnerDecisionV1Reader::read(source, |field| {
            attempts.push(field.to_string());
            Err("content_authentication_failed".to_string())
        });
        assert_eq!(failed.unwrap_err(), "content_authentication_failed");
        assert_eq!(attempts, ["owner_word", "value"]);
        assert_eq!(counters(), before, "failed legacy reads must not increment");

        attempts.clear();
        let unavailable = OwnerDecisionV1Reader::read(source, |field| {
            attempts.push(field.to_string());
            Err("key_unavailable".to_string())
        });
        assert_eq!(unavailable.unwrap_err(), "key_unavailable");
        assert_eq!(attempts, ["owner_word"]);
        assert_eq!(counters(), before);

        attempts.clear();
        let legacy = OwnerDecisionV1Reader::read(source, |field| {
            attempts.push(field.to_string());
            match field {
                "owner_word" => Err("content_authentication_failed".to_string()),
                "value" => Ok(CANARY.to_string()),
                _ => panic!("unexpected AAD"),
            }
        })
        .unwrap();
        assert_eq!(legacy, CANARY);
        assert_eq!(attempts, ["owner_word", "value"]);
        let label = format!("{METRIC}{{source={}}}", source.as_str());
        let mut expected = before;
        *expected.entry(label).or_default() += 1;
        assert_eq!(
            counters(),
            expected,
            "one increment for one successful legacy read"
        );
    }
    let metrics = counters();
    assert_eq!(metrics.len(), 4);
    for source in ["cli", "mcp", "sdk", "http"] {
        assert_eq!(metrics[&format!("{METRIC}{{source={source}}}")], 1);
    }
    assert!(metrics.keys().all(|label| !label.contains(CANARY)));
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn owner_decision_metrics_count_only_successful_legacy_reads_with_fixed_labels() {
    if std::env::var_os(CHILD).is_some() {
        assert_counter_boundary();
        return;
    }
    // A child isolates process counters and diagnostics environment without changing global
    // environment variables while Rust's test runner may have other threads running.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("ly-owner-counters-{}-{unique}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).unwrap();
    let scratch = Scratch(directory);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "owner_decision_metrics_count_only_successful_legacy_reads_with_fixed_labels",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("LOCKYARD_DIAGNOSTICS_DIR", &scratch.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let diagnostics = fs::read_to_string(scratch.0.join("compat.jsonl")).unwrap();
    let records = diagnostics
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        records.len(),
        4,
        "canonical and failed reads emit no legacy event"
    );
    for (record, source) in records.iter().zip(["cli", "mcp", "sdk", "http"]) {
        assert_eq!(
            record,
            &json!({"metric":METRIC,"source":source,"kind":null,"protocol":null,"delta":1})
        );
    }
    assert!(!diagnostics.contains(CANARY));
}
