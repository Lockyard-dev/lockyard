#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#
# Two agents, one repository, one contested folder. Everything here is real: a throwaway project
# in a temporary folder, two names, and the `lockyard` on your PATH.
#
#   sh examples/two-agents/run.sh            show the transcript
#   sh examples/two-agents/run.sh --check    the same, and fail if any step behaves differently
#
# --check is what CI runs, so the transcript in README.md cannot drift away from the binary.

set -eu

check=no
[ "${1:-}" = "--check" ] && check=yes

if ! command -v lockyard >/dev/null 2>&1; then
	echo "lockyard is not on PATH: cargo build --release -p lockyard && export PATH=\"\$PWD/target/release:\$PATH\"" >&2
	exit 1
fi

project=$(mktemp -d)
trap 'rm -rf "$project"' EXIT INT TERM
cd "$project"

failures=0
alice() { LOCKYARD_AGENT=alice lockyard "$@"; }
bob() { LOCKYARD_AGENT=bob lockyard "$@"; }

say() {
	printf '\n\033[1m%s\033[0m\n' "$1" 2>/dev/null || printf '\n%s\n' "$1"
}

# Runs a command, prints what it printed, and in --check mode insists on an exit code.
expect() {
	wanted=$1
	shift
	printf '$ %s\n' "$*"
	set +e
	output=$("$@" 2>&1)
	code=$?
	set -e
	[ -n "$output" ] && printf '%s\n' "$output"
	if [ "$check" = yes ] && [ "$code" != "$wanted" ]; then
		echo "FAIL: expected exit $wanted, got $code" >&2
		failures=$((failures + 1))
	fi
	last=$output
}

contains() {
	[ "$check" = yes ] || return 0
	case "$last" in
	*"$1"*) ;;
	*)
		echo "FAIL: the output does not mention '$1'" >&2
		failures=$((failures + 1))
		;;
	esac
}

say "A new project"
expect 0 lockyard init

say "Alice takes src/api"
expect 0 alice zone claim src/api --note "rewrite the routes"
contains "alice"

say "Bob wants a file inside it, and is refused"
# Exit 3 is the refusal: a file under a claimed folder belongs to whoever holds the folder.
expect 3 bob zone claim src/api/routes.rs --note "fix the 500 on POST"
contains "held by alice"

say "Bob asks whether he may touch it at all"
expect 3 bob zone check src/api/routes.rs

say "So Bob asks Alice for it, instead of editing behind her back"
expect 0 bob msg send alice "I need src/api/routes.rs for a 500 on POST, how long will you be?"

say "Alice reads her mail"
expect 0 alice msg inbox
contains "500 on POST"

say "Alice answers, finishes, and lets go"
expect 0 alice msg send bob "about 10 minutes, I will release src/api when the routes compile"
expect 0 alice zone release Z-1

say "Bob reads the answer"
expect 0 bob msg inbox
contains "10 minutes"

say "Alice can see her message arrived and was read"
expect 0 alice msg sent
contains "read"

say "Now Bob gets the file"
expect 0 bob zone claim src/api/routes.rs --note "fix the 500 on POST"
contains "bob"

say "And the project knows who holds what"
expect 0 lockyard zone list
contains "src/api/routes.rs"

if [ "$check" = yes ]; then
	if [ "$failures" -ne 0 ]; then
		printf '\n%s step(s) behaved differently from the README\n' "$failures" >&2
		exit 1
	fi
	printf '\nthe two-agent example behaved exactly as the README says\n'
fi
