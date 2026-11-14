#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
set -eu
export CARGO_INCREMENTAL=0
# Shared hosted macOS runners exceed the production budgets in the debug profile.
# Measure the shipped profile: raw subprocess p95 hook <= 15 ms, send <= 20 ms.
# Emit hot-path spans before the strict gate, even when that gate exceeds its budget.
cargo test --locked --release -p lockyard --test perf_profile -- --ignored --test-threads=1 --nocapture
# Owner decision 2026-11-13: best of five attempts for each hosted budget (Linux/macOS/Windows).
# Share Windows' classifier: only an explicit p95 overrun may be retried.
script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
exec python3 "$script_dir/perf-budget-gate.py" macos
