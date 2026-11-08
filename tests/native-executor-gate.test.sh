#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
set -eu
repo=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
test_runner=${NATIVE_EXECUTOR_TEST_RUNNER:-$repo/tools/ci/run-native-executor-tests.sh}
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
mkdir "$fixture/bin"
cat > "$fixture/bin/cargo" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$NATIVE_GATE_COMMANDS"
case "$*" in
    *runtime_resource_capability_report_is_respected*)
        case "$NATIVE_GATE_CASE" in
            available|refused) printf 'LOCKYARD_NATIVE_ACCEPTANCE=%s\n' "$NATIVE_GATE_CASE" ;;
            missing) echo '0 tests passed' ;;
            unknown) echo 'LOCKYARD_NATIVE_ACCEPTANCE=unknown' ;;
            duplicate) printf 'LOCKYARD_NATIVE_ACCEPTANCE=available\nLOCKYARD_NATIVE_ACCEPTANCE=refused\n' ;;
            failed) echo 'LOCKYARD_NATIVE_ACCEPTANCE=refused'; exit 101 ;;
        esac
        ;;
esac
MOCK
chmod +x "$fixture/bin/cargo"
export NATIVE_GATE_COMMANDS="$fixture/commands"
export PATH="$fixture/bin:$PATH"
for scenario in missing unknown duplicate failed available refused strict; do
    : > "$NATIVE_GATE_COMMANDS"
    if [ "$scenario" = strict ]; then allow=0; else allow=1; fi
    if NATIVE_GATE_CASE=$scenario LOCKYARD_NATIVE_ALLOW_REFUSAL=$allow sh "$test_runner" > "$fixture/output" 2>&1; then status=0; else status=$?; fi
    case "$scenario" in
        available) expected=0; calls=3 ;;
        refused) expected=0; calls=1 ;;
        strict) expected=0; calls=2 ;;
        *) expected=1; calls=1 ;;
    esac
    actual_calls=$(wc -l < "$NATIVE_GATE_COMMANDS" | tr -d ' ')
    if [ "$status" != "$expected" ] || [ "$actual_calls" != "$calls" ]; then
        cat "$fixture/output"
        echo "$scenario: status=$status (expected $expected), cargo calls=$actual_calls (expected $calls)" >&2
        exit 1
    fi
    if [ "$scenario" = refused ]; then
        grep -Fq 'full native acceptance has not run' "$fixture/output"
    fi
    echo "native gate $scenario: passed"
done
