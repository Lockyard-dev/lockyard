<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->
# Local CLI performance budgets

`crates/lockyard/tests/perf_budget.rs` measures 80 raw subprocess samples per test,
including process startup and durable SQLite writes. Since the owner's 2026-11-13
decision every hosted CI platform measures the release binary and takes the best of
five attempts independently for hook decision and message send; the ceilings did not
change. All five configured attempts run even after an early pass, and each
measured attempt prints its own raw p95; samples are never filtered. Product,
build and fixture failures stop the gate immediately. Diagnostic runs never replace
a budget result.

| CI platform | Hook decision p95 | Message send p95 |
| --- | --- | --- |
| GitHub-hosted macOS | ≤ 15 ms, best of five | ≤ 20 ms, best of five |
| Linux | ≤ 15 ms, best of five | ≤ 20 ms, best of five |
| Windows | ≤ 15 ms, best of five | ≤ 35 ms, best of five |

Linux previously ran each budget once on the debug profile; it now runs the same
release gate as macOS and Windows (`python3 tools/ci/perf-budget-gate.py linux`), so
all three platforms measure the shipped binary.

On hosted Windows, send p95 was 58–152 ms in all six attempts of two runs on
2026-11-13 (p50 17–22 ms), well above the earlier 22–29 ms. That is treated as an
open product investigation, not noise: the 35 ms ceiling stays, and by the owner's
2026-11-13 decision a red Windows send budget alone does not block a merge while
Linux and macOS are green.

The earlier macOS attempt policy followed the owner's 2026-11-09 decision. In
[CI run 42517683446](https://github.com/lockyard-dev/lockyard/actions/runs/42517683446),
the hosted macOS hook p95 was 18.5 ms in its single attempt, versus 5.8 ms in earlier
hosted runs. The hook/send ceilings remain 15/20 ms.

The Windows send threshold follows the owner's 2026-11-08 decision. In
[CI run 42504694714](https://github.com/lockyard-dev/lockyard/actions/runs/42504694714),
raw send gate p95 was 22.0/29.1 ms; diagnostic send p95 was 18.8–19.6 ms with
maximum about 40 ms. SQLite `synchronous=FULL` commits tracked `FlushFileBuffers`
(p50 4.7 ms, p95 about 10 ms), while process startup cost 7–8 ms. The previous
120 ms tail did not recur in the normal send profile. The 35 ms budget preserves FULL durability;
it is a p95 ceiling, not a maximum-latency guarantee. Across four hosted runs the
worst send p95s were approximately 22/29/64/134 ms, including 63.5 ms in
[CI run 42508801763](https://github.com/lockyard-dev/lockyard/actions/runs/42508801763).
The owner therefore approved best-of-three acceptance for Windows send on
2026-11-08 (now best of five for both tests); FULL durability is unchanged.

The send gate warms both agents before sampling. The separate diagnostic
`send_due` case creates a new sender per sample and also commits its heartbeat;
the Windows job recorded p95 44.2 ms and maximum 163.9 ms for that case. It is
not the warm-sender acceptance fixture, and the budget does not bound its latency.

Windows and macOS CI enforce the release binary serially through
`tools/ci/test-windows-perf.ps1` and `tools/ci/test-macos-perf.sh`; Linux calls
`tools/ci/perf-budget-gate.py linux` directly. All of them use that gate for the
attempt policy, including the macOS gate invoked by `rust (macos-15)`.
A test fails its budget only when all five p95s exceed its ceiling.
Only that test's explicit p95 assertion permits another attempt; every other
failure stops immediately, even after an earlier passing attempt. Acceptance uses
the Rust assertion result, not the microsecond-truncated diagnostic p95.
Gate mocks cover early and late passes, five overruns, hook overrun retries,
the Linux policy, and immediate product/build failures. All CI builds disable incremental compilation.

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
