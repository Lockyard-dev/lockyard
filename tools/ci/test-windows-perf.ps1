# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
$ErrorActionPreference = 'Stop'
# Windows debug validation overhead exceeded the production latency budgets.
# Measure the shipped profile; keep the same raw subprocess timings and ceilings.
$tests = @('hook_decision_p95_stays_within_budget', 'msg_send_p95_stays_within_budget')
$catalog = cargo test --locked --release -p lockyard --test perf_budget -- --list
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$listed = @($catalog | Where-Object { $_ -match ': test$' })
if ($listed.Count -ne $tests.Count) { throw 'Expected exactly two performance budget tests' }
foreach ($test in $tests) {
    if (-not ($listed -contains "${test}: test")) { throw "Missing performance budget: $test" }
}
# Hosted runners are noisy (owner decision 2026-11-08): up to three attempts with the
# unchanged ceilings; a real regression fails all three. Every attempt prints its p95.
$status = 1
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Output "perf gate attempt $attempt of 3"
    cargo test --locked --release -p lockyard --test perf_budget -- --test-threads=1 --nocapture
    $status = $LASTEXITCODE
    if ($status -eq 0) { exit 0 }
}
exit $status
