#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
set -eu
# Shared hosted macOS runners exceed the production budgets in the debug profile.
# Measure the shipped profile; keep the same raw subprocess timings and ceilings.
catalog=$(cargo test --locked --release -p lockyard --test perf_budget -- --list)
listed=$(printf '%s\n' "$catalog" | sed -n 's/: test$//p' | LC_ALL=C sort)
expected=$(printf '%s\n' hook_decision_p95_stays_within_budget msg_send_p95_stays_within_budget)
if [ "$listed" != "$expected" ]; then
    printf '%s\n' 'Expected exactly the hook decision and msg send performance budget tests' >&2
    printf '%s\n' "$catalog" >&2
    exit 1
fi
# Hosted runners are noisy (owner decision 2026-11-08): up to three attempts with the
# unchanged ceilings; a real regression fails all three. Every attempt prints its p95.
attempt=1
while :; do
    echo "perf gate attempt $attempt of 3"
    if cargo test --locked --release -p lockyard --test perf_budget -- --test-threads=1 --nocapture; then
        exit 0
    else
        status=$?
    fi
    if [ "$attempt" -ge 3 ]; then
        exit "$status"
    fi
    attempt=$((attempt + 1))
done
