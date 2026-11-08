<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Local CLI performance budgets

`crates/lockyard/tests/perf_budget.rs` measures 80 raw subprocess samples per test,
including process startup and durable SQLite writes. Each gate makes one attempt;
an overrun fails immediately. There are no retries, best-of-three selection or
sample filtering. Diagnostic runs never replace a failed budget result.

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
it is a p95 ceiling, not a maximum-latency guarantee.

The send gate warms both agents before sampling. The separate diagnostic
`send_due` case creates a new sender per sample and also commits its heartbeat;
the Windows job recorded p95 44.2 ms and maximum 163.9 ms for that case. It is
not the warm-sender acceptance fixture, and the budget does not bound its latency.

Windows and macOS CI enforce the release binary serially through
`tools/ci/test-windows-perf.ps1` and `tools/ci/test-macos-perf.sh`; Linux runs the
same budget tests serially. Gate mocks include a first-failure scenario that would
pass on a second attempt and must still fail. All CI builds disable incremental
compilation.

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
