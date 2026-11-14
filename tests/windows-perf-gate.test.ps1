# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('lockyard-windows-perf-gate-' + [guid]::NewGuid().ToString('N'))
$engine = (Get-Process -Id $PID).Path
$saved = @{}
foreach ($name in @('PATH', 'CARGO_INCREMENTAL', 'WINDOWS_PERF_ENGINE', 'WINDOWS_PERF_MOCK', 'WINDOWS_PERF_COMMANDS', 'WINDOWS_PERF_CASE')) {
    $saved[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $bin = New-Item -ItemType Directory -Path (Join-Path $fixture 'bin')
    $mock = Join-Path $fixture 'cargo-mock.ps1'
    @'
$ErrorActionPreference = 'Stop'
$command = $args -join ' '
[System.IO.File]::AppendAllText($env:WINDOWS_PERF_COMMANDS, $command + [System.Environment]::NewLine)
if ($env:CARGO_INCREMENTAL -ne '0') {
    Write-Error 'performance gate must disable incremental compilation'
    exit 2
}
switch ($command) {
    'test --locked --release -p lockyard-core --lib -- --list' {
        $recovery = 'store::tests::windows_database_releases_the_rollback_journal_pin_before_hot_recovery: test'
        switch ($env:WINDOWS_PERF_CASE) {
            'recovery_missing' { Write-Output 'store::tests::other: test' }
            'recovery_duplicate' { Write-Output $recovery, $recovery }
            'recovery_list_failed' { exit 101 }
            default { Write-Output $recovery, '', '1 test, 0 benchmarks' }
        }
    }
    'test --locked --release -p lockyard-core --lib store::tests::windows_database_releases_the_rollback_journal_pin_before_hot_recovery -- --exact --nocapture' {
        if ($env:WINDOWS_PERF_CASE -eq 'recovery_failed') { exit 101 }
    }
    'test --locked --release -p lockyard --test perf_profile -- --ignored --test-threads=1 --nocapture' {
        if ($env:WINDOWS_PERF_CASE -eq 'profile_failed') { exit 101 }
    }
    'test --locked --release -p lockyard-core --lib windows::tests::profile_authenticated_pipe_connect_80_samples -- --ignored --exact --nocapture' {
        if ($env:WINDOWS_PERF_CASE -eq 'pipe_profile_failed') { exit 101 }
    }
    'test --locked --release -p lockyard --test perf_budget -- --list' {
        switch ($env:WINDOWS_PERF_CASE) {
            'missing' { Write-Output 'hook_decision_p95_stays_within_budget: test' }
            'unknown' { Write-Output 'hook_decision_p95_stays_within_budget: test', 'other: test' }
            'duplicate' { Write-Output 'hook_decision_p95_stays_within_budget: test', 'hook_decision_p95_stays_within_budget: test', 'msg_send_p95_stays_within_budget: test' }
            'list_failed' { exit 101 }
            default { Write-Output 'msg_send_p95_stays_within_budget: test', 'hook_decision_p95_stays_within_budget: test', '', '2 tests, 0 benchmarks' }
        }
    }
    'test --locked --release -p lockyard --test perf_budget hook_decision_p95_stays_within_budget -- --exact --test-threads=1 --nocapture' {
        if ($env:WINDOWS_PERF_CASE -eq 'hook_missing_metric') { exit 0 }
        [Console]::Error.WriteLine('perf_budget hook_decision samples=80 p50_us=4000 p95_us=5000 budget_us=15000')
        if ($env:WINDOWS_PERF_CASE -in @('hook_failed', 'hook_flaky')) {
            $runs = @(Get-Content -LiteralPath $env:WINDOWS_PERF_COMMANDS | Where-Object { $_ -ceq $command }).Count
            if ($env:WINDOWS_PERF_CASE -eq 'hook_failed' -or $runs -eq 1) { exit 101 }
        }
    }
    'test --locked --release -p lockyard --test perf_budget msg_send_p95_stays_within_budget -- --exact --test-threads=1 --nocapture' {
        $runs = @(Get-Content -LiteralPath $env:WINDOWS_PERF_COMMANDS | Where-Object { $_ -ceq $command }).Count
        if ($env:WINDOWS_PERF_CASE -eq 'send_product_failed') { exit 101 }
        if ($env:WINDOWS_PERF_CASE -eq 'send_non_test_failure') { exit 2 }
        if ($env:WINDOWS_PERF_CASE -eq 'send_missing_metric') { exit 0 }
        $p95 = 22000
        switch ($env:WINDOWS_PERF_CASE) {
            'send_recover_second' { $p95 = @(64000, 29000, 64000, 64000, 64000)[$runs - 1] }
            'send_recover_third' { $p95 = @(64000, 134000, 35000, 64000, 64000)[$runs - 1] }
            'send_early_pass' { $p95 = @(22000, 64000, 134000, 64000, 64000)[$runs - 1] }
            'send_all_over_budget' { $p95 = 64000 }
            'send_truncated_overruns' { $p95 = 35000 }
            'send_truncated_then_pass' { $p95 = 35000 }
            'send_budget_missing_panic' { $p95 = 64000 }
            'send_duplicate_panic' { $p95 = 64000 }
            'send_success_over_budget' { $p95 = 64000 }
            'send_product_after_pass' { if ($runs -eq 2) { $p95 = 64000 } }
        }
        if ($env:WINDOWS_PERF_CASE -eq 'send_wrong_budget') {
            Write-Output 'perf_budget msg_send samples=80 p50_us=16000 p95_us=22000 budget_us=20000'
            exit 0
        }
        # Cargo's test-prefix stdout and the stderr metric may share a line.
        $prefix = ''
        if ($env:WINDOWS_PERF_CASE -eq 'send_inline_metric') { $prefix = 'test msg_send_p95_stays_within_budget ... ' }
        $metric = "${prefix}perf_budget msg_send samples=80 p50_us=16000 p95_us=$p95 budget_us=35000"
        if ($env:WINDOWS_PERF_CASE -eq 'send_stderr_metric') {
            [Console]::Error.WriteLine($metric)
        } else {
            Write-Output $metric
        }
        if ($env:WINDOWS_PERF_CASE -eq 'send_duplicate_metric') {
            Write-Output "perf_budget msg_send samples=80 p50_us=16000 p95_us=$p95 budget_us=35000"
            exit 0
        }
        if ($env:WINDOWS_PERF_CASE -eq 'send_product_after_metric' -or ($env:WINDOWS_PERF_CASE -eq 'send_product_after_pass' -and $runs -eq 2)) {
            [Console]::Error.WriteLine('msg send failed: product failure must not be retried')
            exit 101
        }
        if ($env:WINDOWS_PERF_CASE -eq 'send_success_over_budget') { exit 0 }
        if ($env:WINDOWS_PERF_CASE -eq 'send_truncated_overruns' -or ($env:WINDOWS_PERF_CASE -eq 'send_truncated_then_pass' -and $runs -lt 3)) {
            [Console]::Error.WriteLine('msg send p95 was 35.0005ms, budget is 35ms')
            exit 101
        }
        if ($p95 -gt 35000) {
            if ($env:WINDOWS_PERF_CASE -ne 'send_budget_missing_panic') {
                [Console]::Error.WriteLine("msg send p95 was ${p95}us, budget is 35ms")
            }
            if ($env:WINDOWS_PERF_CASE -eq 'send_duplicate_panic') {
                [Console]::Error.WriteLine("msg send p95 was ${p95}us, budget is 35ms")
            }
            exit 101
        }
    }
    default { Write-Error "unexpected cargo arguments: $command"; exit 2 }
}
exit 0
'@ | Set-Content -LiteralPath $mock
    if ($IsWindows) {
        @'
@echo off
"%WINDOWS_PERF_ENGINE%" -NoProfile -File "%WINDOWS_PERF_MOCK%" %*
exit /b %ERRORLEVEL%
'@ | Set-Content -LiteralPath (Join-Path $bin.FullName 'cargo.cmd')
    } else {
        $shim = Join-Path $bin.FullName 'cargo'
        @'
#!/bin/sh
exec "$WINDOWS_PERF_ENGINE" -NoProfile -File "$WINDOWS_PERF_MOCK" "$@"
'@ | Set-Content -LiteralPath $shim
        [System.IO.File]::SetUnixFileMode($shim, [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite -bor [System.IO.UnixFileMode]::UserExecute)
    }
    $env:WINDOWS_PERF_ENGINE = $engine
    $env:WINDOWS_PERF_MOCK = $mock
    $env:WINDOWS_PERF_COMMANDS = Join-Path $fixture 'commands'
    $env:PATH = $bin.FullName + [System.IO.Path]::PathSeparator + $env:PATH
    foreach ($scenario in @('recovery_missing', 'recovery_duplicate', 'recovery_list_failed', 'recovery_failed', 'profile_failed', 'pipe_profile_failed', 'missing', 'unknown', 'duplicate', 'list_failed', 'hook_failed', 'hook_flaky', 'hook_missing_metric', 'send_truncated_overruns', 'send_truncated_then_pass', 'send_product_failed', 'send_non_test_failure', 'send_product_after_metric', 'send_product_after_pass', 'send_budget_missing_panic', 'send_duplicate_panic', 'send_missing_metric', 'send_duplicate_metric', 'send_wrong_budget', 'send_success_over_budget', 'send_all_over_budget', 'send_recover_second', 'send_recover_third', 'send_early_pass', 'send_inline_metric', 'send_stderr_metric', 'valid')) {
        [System.IO.File]::WriteAllText($env:WINDOWS_PERF_COMMANDS, '')
        $env:WINDOWS_PERF_CASE = $scenario
        $env:CARGO_INCREMENTAL = '1'
        $stdout = Join-Path $fixture 'stdout'
        $stderr = Join-Path $fixture 'stderr'
        $gate = Join-Path $repo 'tools/ci/test-windows-perf.ps1'
        $process = Start-Process -FilePath $engine -ArgumentList @('-NoProfile', '-File', ('"' + $gate + '"')) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $status = $process.ExitCode
        $expected = 1
        $calls = 5
        $attempts = 0
        $bestP95 = $null
        switch ($scenario) {
            'valid' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 22000 }
            'send_inline_metric' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 22000 }
            'send_stderr_metric' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 22000 }
            'send_recover_second' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 29000 }
            'send_recover_third' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 35000 }
            'send_early_pass' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 22000 }
            'send_all_over_budget' { $expected = 101; $calls = 15; $attempts = 5; $bestP95 = 64000 }
            'hook_failed' { $expected = 101; $calls = 6 }
            'hook_flaky' { $expected = 101; $calls = 6 }
            'hook_missing_metric' { $calls = 6 }
            'send_truncated_overruns' { $expected = 101; $calls = 15; $attempts = 5; $bestP95 = 35000 }
            'send_truncated_then_pass' { $expected = 0; $calls = 15; $attempts = 5; $bestP95 = 35000 }
            'send_product_failed' { $expected = 101; $calls = 11 }
            'send_non_test_failure' { $expected = 2; $calls = 11 }
            'send_product_after_metric' { $expected = 101; $calls = 11; $attempts = 1 }
            'send_product_after_pass' { $expected = 101; $calls = 12; $attempts = 2 }
            'send_budget_missing_panic' { $expected = 101; $calls = 11; $attempts = 1 }
            'send_duplicate_panic' { $expected = 101; $calls = 11; $attempts = 1 }
            'send_missing_metric' { $calls = 11 }
            'send_duplicate_metric' { $calls = 11 }
            'send_wrong_budget' { $calls = 11 }
            'send_success_over_budget' { $calls = 11; $attempts = 1 }
            'recovery_missing' { $calls = 1 }
            'recovery_duplicate' { $calls = 1 }
            'recovery_list_failed' { $expected = 101; $calls = 1 }
            'recovery_failed' { $expected = 101; $calls = 2 }
            'profile_failed' { $expected = 101; $calls = 3 }
            'pipe_profile_failed' { $expected = 101; $calls = 4 }
            'list_failed' { $expected = 101 }
        }
        $actualCalls = @(Get-Content -LiteralPath $env:WINDOWS_PERF_COMMANDS).Count
        if ($status -ne $expected -or $actualCalls -ne $calls) {
            Get-Content -LiteralPath $stdout, $stderr | Write-Output
            throw "${scenario}: status=$status (expected $expected), cargo calls=$actualCalls (expected $calls)"
        }
        $output = @(Get-Content -LiteralPath $stdout)
        $actualAttempts = @($output | Where-Object { $_ -match '^Windows msg_send attempt [1-5]/5 p95_us=[0-9]+ budget_us=35000$' }).Count
        if ($actualAttempts -ne $attempts) { throw "${scenario}: printed $actualAttempts attempt p95s (expected $attempts)" }
        if ($null -ne $bestP95 -and -not ($output -contains "Windows msg_send best_of=5 p95_us=$bestP95 budget_us=35000")) {
            throw "${scenario}: missing best p95 $bestP95"
        }
        Write-Output "Windows perf gate ${scenario}: passed"
    }
}
finally {
    foreach ($name in $saved.Keys) {
        [System.Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
    }
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
