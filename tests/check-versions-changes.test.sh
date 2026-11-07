#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
# Proves source changes require their crate's version to advance from the CI base.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../scripts/check-versions.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/lockyard-version-changes.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/repo/crates/one/src" "$work/repo/crates/two/src"
cd "$work/repo"
printf '[workspace.package]\nversion = "1.2.3"\n' > Cargo.toml
printf '[package]\nname = "one"\nversion.workspace = true\n' > crates/one/Cargo.toml
printf '[package]\nname = "two"\nversion = "2.0.0"\n' > crates/two/Cargo.toml
printf 'pub fn one() {}\n' > crates/one/src/lib.rs
printf 'pub fn two() {}\n' > crates/two/src/lib.rs
printf 'documentation\n' > README.md
git init -q
git add .
git -c user.name=VersionTest -c user.email=version-test@example.invalid commit -qm baseline
base=$(git rev-parse HEAD)
passed=0
check() {
    passed=$((passed + 1))
    if sh "$script" --changed "$base" "$work/repo" > "$work/result" 2>&1; then
        actual=pass
    else
        actual=fail
    fi
    if [ "$actual" != "$1" ]; then
        echo "FAIL: $2 expected $1, got $actual" >&2
        cat "$work/result" >&2
        exit 1
    fi
}
check pass 'an unchanged source tree'
printf 'documentation only\n' > README.md
check pass 'a documentation-only change'
printf 'pub fn changed() {}\n' > crates/one/src/lib.rs
check fail 'changed workspace-versioned crate without a bump'
printf '[workspace.package]\nversion = "1.2.4"\n' > Cargo.toml
check pass 'a workspace version bump for its changed crate'
printf '[workspace.package]\nversion = "1.2.2"\n' > Cargo.toml
check fail 'a version rollback'
printf '[workspace.package]\nversion = "1.2.4"\n' > Cargo.toml
printf 'pub fn changed_two() {}\n' > crates/two/src/lib.rs
check fail 'a changed separately versioned crate without its own bump'
printf '[package]\nname = "two"\nversion = "2.0.1"\n' > crates/two/Cargo.toml
check pass 'both changed crates have advanced versions'
printf '[workspace.package]\nversion = "1.2.3"\n' > Cargo.toml
cp crates/one/src/lib.rs "$work/modified-one"
git show "$base:crates/one/src/lib.rs" > crates/one/src/lib.rs
printf 'fn main() {}\n' > crates/one/build.rs
git add crates/one/build.rs
check fail 'a new tracked build script without a version bump'
printf '[workspace.package]\nversion = "1.2.4"\n' > Cargo.toml
check pass 'a build script change with a version bump'
# A cross-crate rename removes production code from the source crate as well as adding it
# to the destination. Git's normal name-only rename output contains only the destination.
git rm -f crates/one/build.rs >/dev/null
printf '[workspace.package]\nversion = "1.2.3"\n' > Cargo.toml
git mv crates/one/src/lib.rs crates/two/src/moved.rs
check fail 'a cross-crate rename requires the source crate version to advance too'
printf '[workspace.package]\nversion = "1.2.4"\n' > Cargo.toml
check pass 'a cross-crate rename with both crate versions advanced'
echo "check-versions changed crates: $passed checks passed"
