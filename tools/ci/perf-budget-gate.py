# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Apply the hosted macOS/Windows attempt policy to the raw release p95 tests."""

import argparse
import os
import re
import shutil
import subprocess
import sys


CARGO = ["cargo", "test", "--locked", "--release", "-p", "lockyard", "--test", "perf_budget"]
TESTS = (
    ("hook_decision_p95_stays_within_budget", "hook_decision", "hook decision"),
    ("msg_send_p95_stays_within_budget", "msg_send", "msg send"),
)


def run_cargo(arguments):
    """Stream combined output while retaining the lines needed to verify the gate."""
    lines = []
    try:
        with subprocess.Popen(
            [shutil.which(CARGO[0]) or CARGO[0], *CARGO[1:], *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        ) as process:
            for line in process.stdout:
                print(line, end="", flush=True)
                lines.append(line.rstrip("\r\n"))
            status = process.wait()
    except OSError as error:
        print(f"Could not run cargo: {error}", file=sys.stderr, flush=True)
        return 1, lines
    # Preserve failures caused by a signal as a conventional nonzero shell status.
    return status if status >= 0 else 128 - status, lines


def enforce_test(platform, test, metric, assertion, attempts, budget_us):
    measurement = re.compile(
        rf"(?:test {re.escape(test)} \.\.\. )?"
        rf"perf_budget {metric} samples=80 p50_us=[0-9]+ "
        rf"p95_us=([0-9]+) budget_us={budget_us}"
    )
    budget_failure = re.compile(
        rf"{assertion} p95 was .+, budget is {budget_us // 1000}ms"
    )
    best_p95 = None
    any_passed = False
    for attempt in range(1, attempts + 1):
        label = f"{platform} {metric} attempt {attempt}/{attempts}"
        print(label, flush=True)
        status, lines = run_cargo(
            [test, "--", "--exact", "--test-threads=1", "--nocapture"]
        )
        measurements = [match for line in lines if (match := measurement.fullmatch(line))]
        if len(measurements) != 1:
            print(f"Expected exactly one {metric} p95 measurement", file=sys.stderr, flush=True)
            return status or 1
        p95 = int(measurements[0].group(1))
        print(f"{label} p95_us={p95} budget_us={budget_us}", flush=True)
        failures = [line for line in lines if budget_failure.fullmatch(line)]
        if status:
            # Only this test's explicit p95 assertion permits another attempt.
            if status != 101 or p95 < budget_us or len(failures) != 1:
                return status
        else:
            if p95 > budget_us or failures:
                print(f"{metric} succeeded despite an inconsistent p95 result", file=sys.stderr, flush=True)
                return 1
            any_passed = True
        best_p95 = p95 if best_p95 is None else min(best_p95, p95)
    if attempts > 1:
        print(f"{platform} {metric} best_of={attempts} p95_us={best_p95} budget_us={budget_us}", flush=True)
    # as_micros() truncates: acceptance requires an actual successful assertion.
    return 0 if any_passed else 101


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=("macos", "windows"))
    options = parser.parse_args()
    os.environ["CARGO_INCREMENTAL"] = "0"
    status, catalog = run_cargo(["--", "--list"])
    if status:
        return status
    listed = sorted(line[:-6] for line in catalog if line.endswith(": test"))
    if listed != sorted(test for test, _, _ in TESTS):
        print("Expected exactly the hook decision and msg send performance budget tests", file=sys.stderr, flush=True)
        return 1
    if options.platform == "macos":
        platform, policies = "macOS", ((3, 15000), (3, 20000))
    else:
        platform, policies = "Windows", ((1, 15000), (3, 35000))
    for (test, metric, assertion), (attempts, budget_us) in zip(TESTS, policies):
        status = enforce_test(platform, test, metric, assertion, attempts, budget_us)
        if status:
            return status
    return 0


if __name__ == "__main__":
    sys.exit(main())
