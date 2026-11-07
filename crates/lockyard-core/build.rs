// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn git(root: &Path, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-changed=build.rs");
    // A source edit in any product crate changes the identity of the shared binary build.
    println!("cargo:rerun-if-changed=..");
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| ".".into()));
    for name in ["HEAD", "refs", "packed-refs"] {
        if let Some(path) = git(&root, &["rev-parse", "--git-path", name]) {
            let path = PathBuf::from(path);
            let path = if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    let sha = git(&root, &["rev-parse", "--verify", "HEAD"])
        .filter(|value| {
            matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .unwrap_or_else(|| "unknown".into());
    let timestamp = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=LOCKYARD_GIT_SHA={sha}");
    println!("cargo:rustc-env=LOCKYARD_BUILD_TIME={timestamp}");
    println!("cargo:rustc-env=LOCKYARD_BUILD_VERSION={version} (git={sha} built={timestamp})");
}
