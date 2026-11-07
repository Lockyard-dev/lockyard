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

# CI mode compares each changed product crate with the event's base commit. It also works
# on a tracked working tree for a local preflight; release/tag consistency remains below.
if [ "${1:-}" = "--changed" ]; then
    base="${2:?usage: check-versions.sh --changed <base-commit> [root]}"
    root="${3:-.}"
    cd "$root"
    python3 - "$base" <<'PYCODE'
import pathlib
import re
import subprocess
import sys

base = sys.argv[1]

def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.STDOUT).decode("utf-8")

def section(text, name):
    match = re.search(r"^\[" + re.escape(name) + r"\]\s*\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
    return match.group(1) if match else ""

def package_version(text, workspace):
    package = section(text, "package")
    inherited = re.search(r"^version\.workspace\s*=\s*true\s*(?:#.*)?$", package, re.M)
    content = section(workspace, "workspace.package") if inherited else package
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.M)
    if not match:
        raise ValueError("package version missing or unsupported")
    value = match.group(1)
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("version must be a numeric three-part semver")
    return tuple(map(int, value.split("."))), value

try:
    git("rev-parse", "--verify", base + "^{commit}")
    changed = git("diff", "--no-renames", "--name-only", "-z", base, "--", "crates/").split("\0")
    crates = set()
    for path in changed:
        parts = pathlib.PurePosixPath(path).parts
        if len(parts) >= 4 and parts[2] == "src" or len(parts) == 3 and parts[2] in {"build.rs", "Cargo.toml"}:
            crates.add("/".join(parts[:2]))
    old_workspace = git("show", base + ":Cargo.toml")
    workspace = pathlib.Path("Cargo.toml").read_text()
    failures = []
    for crate in sorted(crates):
        manifest = crate + "/Cargo.toml"
        if not pathlib.Path(manifest).is_file():
            continue  # Removed crates have no release to version.
        exists = subprocess.run(["git", "cat-file", "-e", base + ":" + manifest], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exists.returncode:
            continue  # A new crate establishes its initial version.
        old, old_text = package_version(git("show", base + ":" + manifest), old_workspace)
        current, current_text = package_version(pathlib.Path(manifest).read_text(), workspace)
        if current <= old:
            failures.append(f"{crate}: code changed, bump version above {old_text} (current {current_text})")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        sys.exit(1)
    print(f"changed crate versions: {len(crates)} checked against {base}")
except (OSError, ValueError, subprocess.CalledProcessError) as error:
    print(f"crate version check unavailable: {error}", file=sys.stderr)
    sys.exit(1)
PYCODE
    exit $?
fi

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
# Reported by `import lockyard; lockyard.__version__`, so it is part of the release too.
check packages/pypi/src/lockyard/__init__.py \
	"$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' packages/pypi/src/lockyard/__init__.py | head -1)"

if ! grep -q "^## \[$version\]" CHANGELOG.md; then
	echo "CHANGELOG.md has no section for $version" >&2
	failed=1
fi

if [ "$failed" -ne 0 ]; then
	echo "release $version refused" >&2
	exit 1
fi

echo "release $version: 5 manifests and the changelog agree"
