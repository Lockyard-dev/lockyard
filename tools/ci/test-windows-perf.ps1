# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
$ErrorActionPreference = 'Stop'
$env:CARGO_INCREMENTAL = '0'
# Require this Windows-only regression by exact name: a successful zero-test run is not proof.
# Keep it in this step's log alongside the performance diagnostics, even when the budget fails.
$recovery = 'store::tests::windows_database_releases_the_rollback_journal_pin_before_hot_recovery'
$recoveryCatalog = cargo test --locked --release -p lockyard-core --lib -- --list
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (@($recoveryCatalog | Where-Object { $_ -ceq "${recovery}: test" }).Count -ne 1) {
    throw "Missing or duplicate Windows hot-journal regression: $recovery"
}
cargo test --locked --release -p lockyard-core --lib $recovery -- --exact --nocapture
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Windows debug validation overhead exceeded the production latency budgets.
# Measure the shipped profile: raw subprocess p95 hook <= 15 ms, send <= 35 ms.
# Owner decision 2026-11-08; see docs/performance.md for the Windows FULL-sync evidence.
# Emit hot-path and authenticated-pipe spans before the strict budget gate.
cargo test --locked --release -p lockyard --test perf_profile -- --ignored --test-threads=1 --nocapture
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo test --locked --release -p lockyard-core --lib windows::tests::profile_authenticated_pipe_connect_80_samples -- --ignored --exact --nocapture
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$tests = @('hook_decision_p95_stays_within_budget', 'msg_send_p95_stays_within_budget')
$catalog = cargo test --locked --release -p lockyard --test perf_budget -- --list
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$listed = @($catalog | Where-Object { $_ -match ': test$' })
if ($listed.Count -ne $tests.Count) { throw 'Expected exactly two performance budget tests' }
foreach ($test in $tests) {
    if (-not ($listed -contains "${test}: test")) { throw "Missing performance budget: $test" }
}
# Keep the first run's result: a later successful run must not hide an overrun.
cargo test --locked --release -p lockyard --test perf_budget -- --test-threads=1 --nocapture
exit $LASTEXITCODE
