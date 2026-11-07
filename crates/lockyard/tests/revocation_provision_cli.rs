// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use std::process::Command;

#[test]
fn explicit_revocation_trust_provisioning_requires_separate_output_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_lockyard"))
        .args(["node", "revocation-trust", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--output"));
    assert!(help.contains("--config"));
}
