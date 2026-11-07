#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
set -eu
test "$(uname -s)" = Linux || { echo 'Linux is required' >&2; exit 1; }
test "$(id -u)" != 0 || { echo 'Run this acceptance suite as an unprivileged user' >&2; exit 1; }
: "${LOCKYARD_NATIVE_ROOTFS:?set the provisioned immutable rootfs path}"
: "${LOCKYARD_NATIVE_SANDBOX_BINARY:?set the root-owned AppArmor-profiled helper path}"
if [ "${1:-}" != --delegated ]; then
    exec systemd-run --user --scope -p Delegate=yes sh "$0" --delegated
fi
scope="/sys/fs/cgroup$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
mkdir "$scope/manager" "$scope/jobs"
printf '%s\n' "$$" > "$scope/manager/cgroup.procs"
printf '+cpu +memory +pids\n' > "$scope/cgroup.subtree_control"
export LOCKYARD_NATIVE_CGROUP_ROOT="$scope/jobs"
export LOCKYARD_REQUIRE_NATIVE_TESTS=1
export CARGO_INCREMENTAL=0
cargo test --locked -p lockyard-node --test executor -- --include-ignored --test-threads=1 --nocapture
cargo test --locked -p lockyard-node native_stop_absent_group_rejects --lib -- --nocapture
