#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#
# Proves check-versions.sh refuses each way a release can disagree with itself, by making a
# throwaway copy of the manifests and breaking one at a time.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
script="$repo/scripts/check-versions.sh"
passed=0

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

fresh() {
	rm -rf "$work/repo"
	mkdir -p "$work/repo/packages/npm" "$work/repo/packages/pypi"
	printf 'version = "9.9.9"\n' >"$work/repo/Cargo.toml"
	printf '{\n  "name": "lockyard",\n  "version": "9.9.9"\n}\n' >"$work/repo/packages/npm/package.json"
	printf 'version = "9.9.9"\n' >"$work/repo/packages/pypi/pyproject.toml"
	printf '{\n  "name": "x",\n  "version": "9.9.9"\n}\n' >"$work/repo/server.json"
	printf '## [9.9.9] - 2026-01-01\n' >"$work/repo/CHANGELOG.md"
}

check() {
	passed=$((passed + 1))
	if [ "$1" = "pass" ]; then
		if ! sh "$script" 9.9.9 "$work/repo" >/dev/null 2>&1; then
			echo "FAIL: $2 should have been accepted" >&2
			exit 1
		fi
	elif sh "$script" 9.9.9 "$work/repo" >/dev/null 2>&1; then
		echo "FAIL: $2 should have been refused" >&2
		exit 1
	fi
}

fresh
check pass "manifests that all agree"

# The tag carrying a leading v is the normal shape of a release ref.
passed=$((passed + 1))
sh "$script" v9.9.9 "$work/repo" >/dev/null || {
	echo "FAIL: a v-prefixed tag should be accepted" >&2
	exit 1
}

fresh
printf 'version = "9.9.8"\n' >"$work/repo/Cargo.toml"
check fail "a stale Cargo.toml"

fresh
printf '{\n  "name": "lockyard",\n  "version": "9.9.8"\n}\n' >"$work/repo/packages/npm/package.json"
check fail "a stale npm package"

fresh
printf 'version = "9.9.8"\n' >"$work/repo/packages/pypi/pyproject.toml"
check fail "a stale PyPI package"

fresh
printf '{\n  "name": "x",\n  "version": "9.9.8"\n}\n' >"$work/repo/server.json"
check fail "a stale MCP registry entry"

fresh
printf '## [9.9.8] - 2026-01-01\n' >"$work/repo/CHANGELOG.md"
check fail "a changelog with no section for the release"

fresh
printf '## [9.9.90] - 2026-01-01\n' >"$work/repo/CHANGELOG.md"
check fail "a changelog section for a different version that starts the same"

# And the real repository must pass at its own version, or the next tag cannot be cut.
passed=$((passed + 1))
real=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo/Cargo.toml" | head -1)
if ! sh "$script" "$real" "$repo" >/dev/null; then
	echo "FAIL: this repository disagrees with its own version $real" >&2
	sh "$script" "$real" "$repo" || true
	exit 1
fi

echo "check-versions.sh: $passed checks passed"
