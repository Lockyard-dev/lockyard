#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
# Called inside the delegated scope prepared by test-native-executor.sh.
set -eu
if [ "${LOCKYARD_NATIVE_ALLOW_REFUSAL:-0}" = 1 ]; then
    # Hosted machines may deny kernel enforcement. Verify a real executor refusal;
    # a missing marker, an assertion failure or an unknown result is never a skip.
    gate_log=$(mktemp)
    trap 'rm -f "$gate_log"' EXIT HUP INT TERM
    if ! cargo test --locked -p lockyard-node --test executor runtime_resource_capability_report_is_respected -- --exact --include-ignored --test-threads=1 --nocapture > "$gate_log" 2>&1; then
        cat "$gate_log"
        exit 1
    fi
    cat "$gate_log"
    result=$(sed -n 's/^LOCKYARD_NATIVE_ACCEPTANCE=//p' "$gate_log")
    case "$result" in
        available) ;;
        refused)
            echo 'Native enforcement is unavailable: verified executor refusal with the reason above; full native acceptance has not run.'
            exit 0
            ;;
        *) echo 'Native capability gate did not prove exactly one available/refused outcome' >&2; exit 1 ;;
    esac
    unset LOCKYARD_NATIVE_ALLOW_REFUSAL
fi
cargo test --locked -p lockyard-node --test executor -- --include-ignored --test-threads=1 --nocapture
cargo test --locked -p lockyard-node native_stop_absent_group_rejects --lib -- --nocapture
