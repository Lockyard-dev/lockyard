<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Local CLI performance budgets

`crates/lockyard/tests/perf_budget.rs` measures 80 raw subprocess samples per test,
including process startup and durable SQLite writes. Hook decision gets one attempt
on every OS; macOS/Linux message send also gets one attempt. Only Windows message
send gets three attempts, and the best p95 must meet its budget. Each attempt prints
its own raw p95; samples are never filtered. Product, build and fixture failures stop
the gate immediately. Diagnostic runs never replace a budget result.

| Platform | Hook decision p95 | Message send p95 |
| --- | --- | --- |
| macOS | ≤ 15 ms | ≤ 20 ms |
| Linux | ≤ 15 ms | ≤ 20 ms |
| Windows | ≤ 15 ms | ≤ 35 ms |

The Windows send threshold follows the owner's 2026-11-08 decision. In
[CI run 42504694714](https://github.com/lockyard-dev/lockyard/actions/runs/42504694714),
raw send gate p95 was 22.0/29.1 ms; diagnostic send p95 was 18.8–19.6 ms with
maximum about 40 ms. SQLite `synchronous=FULL` commits tracked `FlushFileBuffers`
(p50 4.7 ms, p95 about 10 ms), while process startup cost 7–8 ms. The previous
120 ms tail did not recur in the normal send profile. The 35 ms budget preserves FULL durability;
it is a p95 ceiling, not a maximum-latency guarantee. Across four hosted runs the
worst send p95s were approximately 22/29/64/134 ms, including 63.5 ms in
[CI run 42508801763](https://github.com/lockyard-dev/lockyard/actions/runs/42508801763).
The owner therefore approved best-of-three acceptance for Windows send only on
2026-11-08. Hook decision stays at one attempt; FULL durability is unchanged.

The send gate warms both agents before sampling. The separate diagnostic
`send_due` case creates a new sender per sample and also commits its heartbeat;
the Windows job recorded p95 44.2 ms and maximum 163.9 ms for that case. It is
not the warm-sender acceptance fixture, and the budget does not bound its latency.

Windows and macOS CI enforce the release binary serially through
`tools/ci/test-windows-perf.ps1` and `tools/ci/test-macos-perf.sh`; Linux runs the
same budget tests serially. Both Windows jobs invoke the same PowerShell gate,
which runs the hook exactly once and all three send attempts. It fails the send
budget only when all three p95s exceed 35 ms; any failure other than the explicit
send p95 assertion fails immediately. Gate mocks cover early and late send passes,
three overruns, strict hook failure, and non-budget failures. macOS gate mocks keep
the first-failure scenario strict. All CI builds disable incremental compilation.

Both Windows jobs also require exactly one catalog entry and a successful exact
run of `store::tests::windows_database_releases_the_rollback_journal_pin_before_hot_recovery`
before profiling or budget acceptance. This test passed in both the workspace
and release steps of `windows` and `rust (windows-latest)` in run 42504694714.

Profiling is for CI/tests and is off by default in the product. Only
`LOCKYARD_PERF_TRACE=1` enables wall-time spans and Windows SQLite syscall probes;
without it, no VFS callbacks are replaced and no per-syscall timers, counters or
diagnostic output run. The ignored `perf_profile` test explicitly enables it in
child processes; budget children explicitly remove it, even if inherited by the
test harness. No CI configuration enables tracing for normal product commands.
