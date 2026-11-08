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
printf '%s\n' "$*" >> "$MACOS_PERF_COMMANDS"
case "$*" in
    'test --locked --release -p lockyard --test perf_budget -- --list')
        case "$MACOS_PERF_CASE" in
            missing) echo 'hook_decision_p95_stays_within_budget: test' ;;
            unknown) printf 'hook_decision_p95_stays_within_budget: test\nother: test\n' ;;
            duplicate) printf 'hook_decision_p95_stays_within_budget: test\nhook_decision_p95_stays_within_budget: test\nmsg_send_p95_stays_within_budget: test\n' ;;
            list_failed) exit 101 ;;
            *) printf 'msg_send_p95_stays_within_budget: test\nhook_decision_p95_stays_within_budget: test\n\n2 tests, 0 benchmarks\n' ;;
        esac
        ;;
    'test --locked --release -p lockyard --test perf_budget -- --test-threads=1 --nocapture')
        if [ "$MACOS_PERF_CASE" = budget_failed ]; then exit 101; fi
        if [ "$MACOS_PERF_CASE" = flaky ]; then
            runs=$(grep -c -- '--nocapture' "$MACOS_PERF_COMMANDS")
            if [ "$runs" -lt 2 ]; then exit 101; fi
        fi
        ;;
    *) echo "unexpected cargo arguments: $*" >&2; exit 2 ;;
esac
MOCK
chmod +x "$fixture/bin/cargo"
export MACOS_PERF_COMMANDS="$fixture/commands"
export PATH="$fixture/bin:$PATH"
for scenario in missing unknown duplicate list_failed budget_failed flaky valid; do
    : > "$MACOS_PERF_COMMANDS"
    if MACOS_PERF_CASE=$scenario sh "$repo/tools/ci/test-macos-perf.sh" > "$fixture/output" 2>&1; then status=0; else status=$?; fi
    case "$scenario" in
        valid) expected=0; calls=2 ;;
        list_failed) expected=101; calls=1 ;;
        budget_failed) expected=101; calls=4 ;;
        flaky) expected=0; calls=3 ;;
        *) expected=1; calls=1 ;;
    esac
    actual_calls=$(wc -l < "$MACOS_PERF_COMMANDS" | tr -d ' ')
    if [ "$status" != "$expected" ] || [ "$actual_calls" != "$calls" ]; then
        cat "$fixture/output"
        echo "$scenario: status=$status (expected $expected), cargo calls=$actual_calls (expected $calls)" >&2
        exit 1
    fi
    echo "macOS perf gate $scenario: passed"
done
