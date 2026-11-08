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
if mkdir "$scope/manager" "$scope/jobs" \
    && printf '%s\n' "$$" > "$scope/manager/cgroup.procs" \
    && printf '+cpu +memory +pids\n' > "$scope/cgroup.subtree_control"; then
    :
elif [ "${LOCKYARD_NATIVE_ALLOW_REFUSAL:-0}" = 1 ]; then
    echo 'Cgroup preparation was denied; the capability test must prove executor refusal with a reason.' >&2
else
    exit 1
fi
export LOCKYARD_NATIVE_CGROUP_ROOT="$scope/jobs"
export LOCKYARD_REQUIRE_NATIVE_TESTS=1
export CARGO_INCREMENTAL=0
exec sh "$(dirname "$0")/run-native-executor-tests.sh"
