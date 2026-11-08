#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
set -eu
export CARGO_INCREMENTAL=0
# Shared hosted macOS runners exceed the production budgets in the debug profile.
# Measure the shipped profile: raw subprocess p95 hook <= 15 ms, send <= 20 ms.
# Emit hot-path spans before the strict gate, even when that gate exceeds its budget.
cargo test --locked --release -p lockyard --test perf_profile -- --ignored --test-threads=1 --nocapture
catalog=$(cargo test --locked --release -p lockyard --test perf_budget -- --list)
listed=$(printf '%s\n' "$catalog" | sed -n 's/: test$//p' | LC_ALL=C sort)
expected=$(printf '%s\n' hook_decision_p95_stays_within_budget msg_send_p95_stays_within_budget)
if [ "$listed" != "$expected" ]; then
    printf '%s\n' 'Expected exactly the hook decision and msg send performance budget tests' >&2
    printf '%s\n' "$catalog" >&2
    exit 1
fi
# Keep the first run's result: a later successful run must not hide an overrun.
exec cargo test --locked --release -p lockyard --test perf_budget -- --test-threads=1 --nocapture
