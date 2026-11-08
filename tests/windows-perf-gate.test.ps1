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
    'test --locked --release -p lockyard --test perf_budget -- --test-threads=1 --nocapture' {
        if ($env:WINDOWS_PERF_CASE -eq 'budget_failed') { exit 101 }
        if ($env:WINDOWS_PERF_CASE -eq 'flaky') {
            $runs = @(Get-Content -LiteralPath $env:WINDOWS_PERF_COMMANDS | Where-Object { $_ -match '--test perf_budget -- --test-threads=1 --nocapture$' }).Count
            if ($runs -lt 2) { exit 101 }
        }
    }
    default { Write-Error "unexpected cargo arguments: $command"; exit 2 }
}
exit 0
'@ | Set-Content -LiteralPath $mock
    @'
@echo off
"%WINDOWS_PERF_ENGINE%" -NoProfile -File "%WINDOWS_PERF_MOCK%" %*
exit /b %ERRORLEVEL%
'@ | Set-Content -LiteralPath (Join-Path $bin.FullName 'cargo.cmd')
    $env:WINDOWS_PERF_ENGINE = $engine
    $env:WINDOWS_PERF_MOCK = $mock
    $env:WINDOWS_PERF_COMMANDS = Join-Path $fixture 'commands'
    $env:PATH = $bin.FullName + [System.IO.Path]::PathSeparator + $env:PATH
    foreach ($scenario in @('profile_failed', 'pipe_profile_failed', 'missing', 'unknown', 'duplicate', 'list_failed', 'flaky', 'budget_failed', 'valid')) {
        [System.IO.File]::WriteAllText($env:WINDOWS_PERF_COMMANDS, '')
        $env:WINDOWS_PERF_CASE = $scenario
        $env:CARGO_INCREMENTAL = '1'
        $stdout = Join-Path $fixture 'stdout'
        $stderr = Join-Path $fixture 'stderr'
        $gate = Join-Path $repo 'tools/ci/test-windows-perf.ps1'
        $process = Start-Process -FilePath $engine -ArgumentList @('-NoProfile', '-File', ('"' + $gate + '"')) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $status = $process.ExitCode
        $expected = 1
        $calls = 3
        switch ($scenario) {
            'valid' { $expected = 0; $calls = 4 }
            'profile_failed' { $expected = 101; $calls = 1 }
            'pipe_profile_failed' { $expected = 101; $calls = 2 }
            'list_failed' { $expected = 101 }
            'flaky' { $expected = 101; $calls = 4 }
            'budget_failed' { $expected = 101; $calls = 4 }
        }
        $actualCalls = @(Get-Content -LiteralPath $env:WINDOWS_PERF_COMMANDS).Count
        if ($status -ne $expected -or $actualCalls -ne $calls) {
            Get-Content -LiteralPath $stdout, $stderr | Write-Output
            throw "${scenario}: status=$status (expected $expected), cargo calls=$actualCalls (expected $calls)"
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
