#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#
# Installs the Lockyard executable from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/lockyard-dev/lockyard/main/install.sh | sh
#
# It downloads one archive, checks it against the release SHA256SUMS file and unpacks the
# executable into ~/.local/bin. It asks for no privileges, installs nothing else and sends
# no telemetry. Windows is not covered: use npm or cargo (see the README).
#
# Settings, all optional:
#   LOCKYARD_VERSION      tag to install, "latest" by default
#   LOCKYARD_INSTALL_DIR  where the executable lands, ~/.local/bin by default
#   LOCKYARD_REPO         owner/name of the GitHub repository

set -eu

REPO="${LOCKYARD_REPO:-lockyard-dev/lockyard}"
VERSION="${LOCKYARD_VERSION:-latest}"
INSTALL_DIR="${LOCKYARD_INSTALL_DIR:-$HOME/.local/bin}"
CHECKSUMS_NAME="SHA256SUMS"

say() { printf '%s\n' "$*"; }
fail() { printf 'lockyard install: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || fail "$1 is required but was not found on PATH"
}

# macOS arm64/x64 and Linux x64/arm64 are the released targets; anything else is told where to go.
detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Darwin) os_name=darwin ;;
        Linux) os_name=linux ;;
        *)
            fail "no prebuilt binary for $os. Install with \`cargo install lockyard\` or \`npm install -g lockyard\`."
            ;;
    esac
    case "$arch" in
        arm64 | aarch64) arch_name=arm64 ;;
        x86_64 | amd64) arch_name=x64 ;;
        *)
            fail "no prebuilt binary for $os $arch. Install with \`cargo install lockyard\`."
            ;;
    esac
    printf '%s-%s' "$os_name" "$arch_name"
}

download() {
    url="$1"
    output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$output" "$url" ||
            fail "could not download $url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$output" "$url" || fail "could not download $url"
    else
        fail "curl or wget is required"
    fi
}

# Prints the SHA-256 of a file as lowercase hex, using whichever tool this system has.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/.*= *//'
    else
        fail "no SHA-256 tool found: install sha256sum, shasum or openssl"
    fi
}

need uname
need tar

target="$(detect_target)"
asset="lockyard-$target.tar.gz"

if [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi

work="$(mktemp -d)"
# A failed install leaves nothing behind, including on an interrupt.
trap 'rm -rf "$work"' EXIT INT TERM

say "Downloading $asset from $base"
download "$base/$asset" "$work/$asset"
download "$base/$CHECKSUMS_NAME" "$work/$CHECKSUMS_NAME"

expected="$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1 }' "$work/$CHECKSUMS_NAME")"
[ -n "$expected" ] || fail "$CHECKSUMS_NAME of this release does not list $asset"
actual="$(sha256_of "$work/$asset")"
if [ "$expected" != "$actual" ]; then
    fail "checksum mismatch for $asset: expected $expected, got $actual"
fi
say "Checksum verified."

tar -xzf "$work/$asset" -C "$work" || fail "could not unpack $asset"
[ -f "$work/lockyard" ] || fail "$asset does not contain a lockyard executable"

mkdir -p "$INSTALL_DIR" || fail "could not create $INSTALL_DIR"
# Replace by rename so a running Lockyard is never a half-written file.
cp "$work/lockyard" "$INSTALL_DIR/lockyard.new" || fail "could not write to $INSTALL_DIR"
chmod 755 "$INSTALL_DIR/lockyard.new"
mv "$INSTALL_DIR/lockyard.new" "$INSTALL_DIR/lockyard"

say ""
say "Installed $("$INSTALL_DIR/lockyard" --version) to $INSTALL_DIR/lockyard"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "Add it to PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
say ""
say "Next: cd into your project and run"
say "  lockyard init && lockyard setup"
