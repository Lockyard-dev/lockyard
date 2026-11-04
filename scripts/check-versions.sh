#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#
# Refuses a release whose manifests disagree with its tag.
#
# A release that ships Cargo at 0.2.0 and npm at 0.1.0 cannot be undone: both numbers are taken
# for ever. So this runs before anything is built, not after something is published.
#
# Usage: check-versions.sh <version-without-v> [repository-root]

set -eu

version="${1:?usage: check-versions.sh <version> [root]}"
version="${version#v}"
root="${2:-.}"
cd "$root"

failed=0
check() {
	if [ "$2" != "$version" ]; then
		echo "$1 says $2, the release is $version" >&2
		failed=1
	fi
}

toml_version() {
	# The first bare `version = "..."` of the file, which is the package's own.
	sed -n 's/^version = "\(.*\)"$/\1/p' "$1" | head -1
}

json_version() {
	# Without a JSON parser to depend on: the first "version" at the top level of the file.
	sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -1
}

check Cargo.toml "$(toml_version Cargo.toml)"
check packages/npm/package.json "$(json_version packages/npm/package.json)"
check packages/pypi/pyproject.toml "$(toml_version packages/pypi/pyproject.toml)"
check server.json "$(json_version server.json)"

if ! grep -q "^## \[$version\]" CHANGELOG.md; then
	echo "CHANGELOG.md has no section for $version" >&2
	failed=1
fi

if [ "$failed" -ne 0 ]; then
	echo "release $version refused" >&2
	exit 1
fi

echo "release $version: 4 manifests and the changelog agree"
