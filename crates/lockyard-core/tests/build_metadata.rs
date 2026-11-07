// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Proves source archives without Git still build and respect reproducible build time.
use std::{path::Path, process::Command};

#[test]
fn build_script_without_git_records_unknown_and_source_date_epoch() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join(if cfg!(windows) {
        "build-script.exe"
    } else {
        "build-script"
    });
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs");
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .env("PATH", root.path().join("no-tools"))
        .env("CARGO_MANIFEST_DIR", root.path())
        .env("CARGO_PKG_VERSION", "9.8.7")
        .env("SOURCE_DATE_EPOCH", "1234567890")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(
        output.contains("cargo:rustc-env=LOCKYARD_GIT_SHA=unknown"),
        "{output}"
    );
    assert!(
        output.contains("cargo:rustc-env=LOCKYARD_BUILD_TIME=1234567890"),
        "{output}"
    );
    assert!(
        output.contains("9.8.7 (git=unknown built=1234567890)"),
        "{output}"
    );
}
