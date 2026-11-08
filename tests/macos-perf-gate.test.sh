#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
set -eu
repo=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir "$fixture/bin"
cat > "$fixture/bin/cargo" <<'MOCK'
#!/bin/sh
set -eu
command=$*
printf '%s\n' "$command" >> "$PERF_COMMANDS"
if [ "${CARGO_INCREMENTAL:-}" != 0 ]; then
    echo 'performance gate must disable incremental compilation' >&2
    exit 2
fi
case "$command" in
    'test --locked --release -p lockyard --test perf_profile -- --ignored --test-threads=1 --nocapture')
        if [ "$PERF_CASE" = profile_failed ]; then exit 101; fi
        exit 0
        ;;
    'test --locked --release -p lockyard --test perf_budget -- --list')
        hook='hook_decision_p95_stays_within_budget: test'
        send='msg_send_p95_stays_within_budget: test'
        case "$PERF_CASE" in
            missing_hook) printf '%s\n' "$send" ;;
            missing_send) printf '%s\n' "$hook" ;;
            unknown) printf '%s\n' "$hook" 'other: test' ;;
            duplicate_hook) printf '%s\n' "$hook" "$hook" "$send" ;;
            duplicate_send) printf '%s\n' "$hook" "$send" "$send" ;;
            empty) : ;;
            list_failed) exit 101 ;;
            *) printf '%s\n' "$send" "$hook" '' '2 tests, 0 benchmarks' ;;
        esac
        exit 0
        ;;
    'test --locked --release -p lockyard --test perf_budget hook_decision_p95_stays_within_budget -- --exact --test-threads=1 --nocapture')
        target=hook
        metric=hook_decision
        test=hook_decision_p95_stays_within_budget
        assertion='hook decision'
        budget=15000
        p95=5000
        ;;
    'test --locked --release -p lockyard --test perf_budget msg_send_p95_stays_within_budget -- --exact --test-threads=1 --nocapture')
        target=send
        metric=msg_send
        test=msg_send_p95_stays_within_budget
        assertion='msg send'
        budget=20000
        p95=6000
        if [ "$PERF_PLATFORM" = windows ]; then budget=35000; p95=22000; fi
        ;;
    *) echo "unexpected cargo arguments: $command" >&2; exit 2 ;;
esac
runs=$(grep -F -x -c "$command" "$PERF_COMMANDS")
mode=valid
case "$PERF_CASE" in "$target"_*) mode=${PERF_CASE#"$target"_} ;; esac
if [ "$PERF_CASE" = independent_minima ]; then
    case "$target:$runs" in
        hook:1) p95=4000 ;; hook:2) p95=7000 ;; hook:3) p95=9000 ;;
        send:1) p95=9000 ;; send:2) p95=8000 ;; send:3) p95=6000 ;;
    esac
fi
over=$((budget + 10000))
pass=$((budget - 1000))
case "$mode" in
    recover_second) case "$runs" in 2) p95=$pass ;; *) p95=$over ;; esac ;;
    recover_third) case "$runs" in 3) p95=$budget ;; *) p95=$over ;; esac ;;
    early_pass) case "$runs" in 1) p95=$pass ;; *) p95=$over ;; esac ;;
    all_over|missing_panic|duplicate_panic|exit2_overrun|success_over_budget|product_after_metric|build_after_metric)
        p95=$over ;;
    truncated_all|truncated_then_pass) p95=$budget ;;
    product_before_metric) echo 'product command failed before measurement' >&2; exit 101 ;;
    build_before_metric) echo 'error: mock compilation failed before measurement' >&2; exit 101 ;;
    product_after_pass|build_after_pass)
        if [ "$runs" -eq 2 ]; then p95=$over; fi ;;
    missing_metric) exit 0 ;;
esac
samples=80
printed_budget=$budget
printed_metric=$metric
prefix=''
case "$mode" in
    wrong_samples) samples=79 ;;
    wrong_budget) printed_budget=$((budget + 1000)) ;;
    wrong_metric) printed_metric=other ;;
    inline_metric) prefix="test $test ... " ;;
esac
line="${prefix}perf_budget $printed_metric samples=$samples p50_us=4000 p95_us=$p95 budget_us=$printed_budget"
if [ "$mode" = stderr_metric ]; then printf '%s\n' "$line" >&2; else printf '%s\n' "$line"; fi
case "$mode" in
    duplicate_metric) printf '%s\n' "$line"; exit 0 ;;
    wrong_samples|wrong_budget|wrong_metric) exit 0 ;;
    product_after_metric) echo 'product command failed after measurement' >&2; exit 101 ;;
    build_after_metric) echo 'error: mock compilation failed after measurement' >&2; exit 101 ;;
    product_after_pass|build_after_pass)
        if [ "$runs" -eq 2 ]; then echo "$mode must stop immediately" >&2; exit 101; fi ;;
    success_over_budget) exit 0 ;;
    truncated_all|truncated_then_pass)
        if [ "$mode" = truncated_all ] || [ "$runs" -lt 3 ]; then
            printf '%s\n' "$assertion p95 was $((budget / 1000)).0005ms, budget is $((budget / 1000))ms" >&2
            exit 101
        fi
        ;;
esac
if [ "$p95" -gt "$budget" ]; then
    if [ "$mode" != missing_panic ]; then
        printf '%s\n' "$assertion p95 was ${p95}us, budget is $((budget / 1000))ms" >&2
    fi
    if [ "$mode" = duplicate_panic ]; then
        printf '%s\n' "$assertion p95 was ${p95}us, budget is $((budget / 1000))ms" >&2
    fi
    if [ "$mode" = exit2_overrun ]; then exit 2; fi
    exit 101
fi
MOCK
chmod +x "$fixture/bin/cargo"
export PERF_COMMANDS="$fixture/commands"
export PATH="$fixture/bin:$PATH"

fail() {
    cat "$fixture/output"
    echo "$PERF_PLATFORM $PERF_CASE: $*" >&2
    exit 1
}

count() {
    grep -E -c "$1" "$2" || true
}

# Parameters: platform, scenario, status, total calls, hook/send calls,
# hook/send printed attempt p95 counts, hook/send final best p95 (or '-').
run_case() {
    PERF_PLATFORM=$1
    PERF_CASE=$2
    expected=$3
    calls=$4
    hook_calls=$5
    send_calls=$6
    hook_prints=$7
    send_prints=$8
    hook_best=$9
    shift 9
    send_best=$1
    export PERF_PLATFORM PERF_CASE
    : > "$PERF_COMMANDS"
    if [ "$PERF_PLATFORM" = macos ]; then
        label=macOS
        hook_attempts=3
        send_budget=20000
        if CARGO_INCREMENTAL=1 sh "$repo/tools/ci/test-macos-perf.sh" > "$fixture/output" 2>&1; then status=0; else status=$?; fi
    else
        label=Windows
        hook_attempts=1
        send_budget=35000
        if CARGO_INCREMENTAL=1 python3 "$repo/tools/ci/perf-budget-gate.py" windows > "$fixture/output" 2>&1; then status=0; else status=$?; fi
    fi
    actual_calls=$(wc -l < "$PERF_COMMANDS" | tr -d ' ')
    [ "$status" = "$expected" ] || fail "status=$status (expected $expected)"
    [ "$actual_calls" = "$calls" ] || fail "cargo calls=$actual_calls (expected $calls)"
    actual_hook_calls=$(count ' --test perf_budget hook_decision_p95_stays_within_budget ' "$PERF_COMMANDS")
    actual_send_calls=$(count ' --test perf_budget msg_send_p95_stays_within_budget ' "$PERF_COMMANDS")
    [ "$actual_hook_calls" = "$hook_calls" ] || fail "hook calls=$actual_hook_calls (expected $hook_calls)"
    [ "$actual_send_calls" = "$send_calls" ] || fail "send calls=$actual_send_calls (expected $send_calls)"
    actual_hook_prints=$(count "^$label hook_decision attempt [123]/$hook_attempts p95_us=[0-9]+ budget_us=15000$" "$fixture/output")
    actual_send_prints=$(count "^$label msg_send attempt [123]/3 p95_us=[0-9]+ budget_us=$send_budget$" "$fixture/output")
    [ "$actual_hook_prints" = "$hook_prints" ] || fail "hook p95 prints=$actual_hook_prints (expected $hook_prints)"
    [ "$actual_send_prints" = "$send_prints" ] || fail "send p95 prints=$actual_send_prints (expected $send_prints)"
    for metric in hook_decision msg_send; do
        if [ "$metric" = hook_decision ]; then best=$hook_best; budget=15000; else best=$send_best; budget=$send_budget; fi
        actual_best=$(count "^$label $metric best_of=" "$fixture/output")
        if [ "$best" = - ]; then
            [ "$actual_best" = 0 ] || fail "unexpected $metric best p95"
        else
            [ "$actual_best" = 1 ] || fail "expected one $metric best p95 (got $actual_best)"
            grep -F -x -q "$label $metric best_of=3 p95_us=$best budget_us=$budget" "$fixture/output" || fail "wrong $metric best p95 (expected $best)"
        fi
    done
    echo "$label perf gate $PERF_CASE: passed"
}

run_case macos profile_failed 101 1 0 0 0 0 - -
for scenario in missing_hook missing_send unknown duplicate_hook duplicate_send empty list_failed; do
    expected=1
    if [ "$scenario" = list_failed ]; then expected=101; fi
    run_case macos "$scenario" "$expected" 2 0 0 0 0 - -
done
run_case macos valid 0 8 3 3 3 3 5000 6000
run_case macos independent_minima 0 8 3 3 3 3 4000 6000

for target in hook send; do
    if [ "$target" = hook ]; then
        policy_budget=15000
        full_hook_best=14000
        full_send_best=6000
    else
        policy_budget=20000
        full_hook_best=5000
        full_send_best=19000
    fi
    for scenario in recover_second early_pass; do
        run_case macos "${target}_$scenario" 0 8 3 3 3 3 "$full_hook_best" "$full_send_best"
    done
    if [ "$target" = hook ]; then full_hook_best=$policy_budget; else full_send_best=$policy_budget; fi
    for scenario in recover_third truncated_then_pass; do
        run_case macos "${target}_$scenario" 0 8 3 3 3 3 "$full_hook_best" "$full_send_best"
    done
    if [ "$target" = hook ]; then
        run_case macos hook_all_over 101 5 3 0 3 0 25000 -
        run_case macos hook_truncated_all 101 5 3 0 3 0 15000 -
    else
        run_case macos send_all_over 101 8 3 3 3 3 5000 30000
        run_case macos send_truncated_all 101 8 3 3 3 3 5000 20000
    fi
    for scenario in inline_metric stderr_metric; do
        run_case macos "${target}_$scenario" 0 8 3 3 3 3 5000 6000
    done
    for scenario in product_before_metric build_before_metric product_after_metric build_after_metric product_after_pass build_after_pass missing_metric duplicate_metric wrong_metric wrong_budget wrong_samples missing_panic duplicate_panic exit2_overrun success_over_budget; do
        expected=101
        printed=1
        attempts=1
        case "$scenario" in
            product_before_metric|build_before_metric) printed=0 ;;
            missing_metric|duplicate_metric|wrong_metric|wrong_budget|wrong_samples) expected=1; printed=0 ;;
            product_after_pass|build_after_pass) printed=2; attempts=2 ;;
            exit2_overrun) expected=2 ;;
            success_over_budget) expected=1 ;;
        esac
        if [ "$target" = hook ]; then
            run_case macos "${target}_$scenario" "$expected" "$((2 + attempts))" "$attempts" 0 "$printed" 0 - -
        else
            run_case macos "${target}_$scenario" "$expected" "$((5 + attempts))" 3 "$attempts" 3 "$printed" 5000 -
        fi
    done
done

# Run the same helper directly so its Windows policy is verified without pwsh.
# Hook has one attempt, send has all three, and the ceilings stay 15/35 ms.
run_case windows valid 0 5 1 3 1 3 - 22000
run_case windows hook_recover_second 101 2 1 0 1 0 - -
run_case windows send_recover_second 0 5 1 3 1 3 - 34000
run_case windows send_recover_third 0 5 1 3 1 3 - 35000
run_case windows send_early_pass 0 5 1 3 1 3 - 34000
run_case windows send_all_over 101 5 1 3 1 3 - 45000
run_case windows send_truncated_all 101 5 1 3 1 3 - 35000
run_case windows send_truncated_then_pass 0 5 1 3 1 3 - 35000
run_case windows send_product_after_pass 101 4 1 2 1 2 - -
