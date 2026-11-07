// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
use lockyard_node::executor::ContainerProfile;

#[test]
fn native_is_the_default_runtime_and_accepts_delegated_cgroup_configuration() {
    let profile: ContainerProfile = serde_json::from_value(serde_json::json!({
        "runtime_program": "/usr/bin/lockyard-sandbox", "image": "native@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "memory_mb": 64, "cpu_millis": 1000, "pids_limit": 16,
        "cgroup_root": "/sys/fs/cgroup/lockyard"
    })).expect("native capability configuration must be accepted before execution");
    assert_eq!(serde_json::to_value(profile.runtime).unwrap(), "native");
}
