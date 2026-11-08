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
# Measure the shipped profile: hook <= 15 ms once; best of three send p95s <= 35 ms.
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
# Hooks have no retry allowance on any OS. Both Windows jobs use this gate.
$hookOutput = @(cargo test --locked --release -p lockyard --test perf_budget hook_decision_p95_stays_within_budget -- --exact --test-threads=1 --nocapture 2>&1)
$hookStatus = $LASTEXITCODE
$hookLines = @($hookOutput | ForEach-Object { "$_" })
$hookLines | Write-Output
if ($hookStatus -ne 0) { exit $hookStatus }
$hookMeasurements = @($hookLines | Where-Object { $_ -match '^(?:test hook_decision_p95_stays_within_budget \.\.\. )?perf_budget hook_decision samples=80 p50_us=[0-9]+ p95_us=([0-9]+) budget_us=15000$' })
if ($hookMeasurements.Count -ne 1) { throw 'Expected exactly one hook decision p95 measurement' }

# Owner decision 2026-11-08: hosted Windows send latency gets exactly three attempts.
# Only the explicit p95 assertion may fail between attempts; a product/build failure
# must fail immediately, even when a previous attempt was within budget.
$bestP95 = [long]::MaxValue
$anySendPassed = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Output "Windows msg_send attempt ${attempt}/3"
    $output = @(cargo test --locked --release -p lockyard --test perf_budget msg_send_p95_stays_within_budget -- --exact --test-threads=1 --nocapture 2>&1)
    $status = $LASTEXITCODE
    $lines = @($output | ForEach-Object { "$_" })
    $lines | Write-Output
    $measurements = @($lines | Where-Object { $_ -match '^(?:test msg_send_p95_stays_within_budget \.\.\. )?perf_budget msg_send samples=80 p50_us=[0-9]+ p95_us=([0-9]+) budget_us=35000$' })
    if ($measurements.Count -ne 1) {
        if ($status -ne 0) { exit $status }
        throw "Expected exactly one Windows msg_send p95 measurement in attempt $attempt"
    }
    $null = $measurements[0] -match 'p95_us=([0-9]+) budget_us=35000$'
    $p95 = [long]$Matches[1]
    Write-Output "Windows msg_send attempt ${attempt}/3 p95_us=$p95 budget_us=35000"
    if ($status -ne 0) {
        $budgetFailure = @($lines | Where-Object { $_ -match '^msg send p95 was .+, budget is 35ms$' })
        if ($status -ne 101 -or $p95 -lt 35000 -or $budgetFailure.Count -ne 1) { exit $status }
    } else {
        if ($p95 -gt 35000) { throw 'Windows msg_send succeeded despite exceeding its p95 budget' }
        $anySendPassed = $true
    }
    $bestP95 = [Math]::Min($bestP95, $p95)
}
Write-Output "Windows msg_send best_of=3 p95_us=$bestP95 budget_us=35000"
# as_micros() truncates: 35 ms plus a fraction of a microsecond still fails in Rust.
# Acceptance follows a successful assertion, never the rounded diagnostic alone.
if (-not $anySendPassed) { exit 101 }
exit 0
