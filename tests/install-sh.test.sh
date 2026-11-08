#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
#
# Tests install.sh against a fake release served from a folder. A stub `curl` on PATH answers
# the downloads, and a stub `uname` names the platform, so every supported target is exercised
# on one machine. Nothing leaves the temporary folder and nothing reaches the network.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../install.sh"
[ -f "$script" ] || { echo "install.sh not found next to tests/" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/lockyard-install-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT INT TERM
failures=0
checks=0

fail() {
    echo "FAIL: $1" >&2
    failures=$((failures + 1))
}

ok() {
    checks=$((checks + 1))
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Builds a release folder holding one archive per target plus a SHA256SUMS file.
build_release() {
    release="$work/release"
    rm -rf "$release"
    mkdir -p "$release/stage"
    printf '#!/bin/sh\necho "lockyard 0.1.0"\n' > "$release/stage/lockyard"
    chmod 755 "$release/stage/lockyard"
    for target in darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
        tar -czf "$release/lockyard-$target.tar.gz" -C "$release/stage" lockyard
    done
    (
        cd "$release"
        for archive in lockyard-*.tar.gz; do
            printf '%s  %s\n' "$(sha256 "$archive")" "$archive"
        done
    ) > "$release/SHA256SUMS"
    for archive in "$release"/lockyard-*.tar.gz; do
        : > "$archive.sig"
        : > "$archive.pem"
    done
}

# Stubs curl and uname so install.sh runs offline on any machine.
build_stubs() {
    stub_os="$1"
    stub_arch="$2"
    bin="$work/stub-bin"
    rm -rf "$bin"
    mkdir -p "$bin"
    cat > "$bin/curl" <<EOF
#!/bin/sh
# Answers only the two URLs install.sh asks for, from the fake release folder.
out=""
url=""
while [ \$# -gt 0 ]; do
    case "\$1" in
        -o) out="\$2"; shift 2 ;;
        -*) shift ;;
        *) url="\$1"; shift ;;
    esac
done
name="\${url##*/}"
[ -f "$work/release/\$name" ] || exit 22
cp "$work/release/\$name" "\$out"
EOF
    cat > "$bin/uname" <<EOF
#!/bin/sh
case "\$1" in
    -s) echo "$stub_os" ;;
    -m) echo "$stub_arch" ;;
    *) echo "$stub_os" ;;
esac
EOF
    cat > "$bin/cosign" <<'EOF'
#!/bin/sh
[ "$1" = verify-blob ] || exit 1
exit 0
EOF
    # wget must not be picked up instead of the stubbed curl.
    chmod 755 "$bin/curl" "$bin/uname" "$bin/cosign"
}

run_install() {
    target_dir="$1"
    PATH="$work/stub-bin:/usr/bin:/bin" \
    LOCKYARD_INSTALL_DIR="$target_dir" \
    LOCKYARD_VERSION="v0.1.0" \
        sh "$script" 2>&1
}

build_release

# Every supported platform resolves to the archive built for it.
for pair in "Darwin arm64 darwin-arm64" "Darwin x86_64 darwin-x64" \
            "Linux x86_64 linux-x64" "Linux aarch64 linux-arm64"; do
    # Splitting the triple into three arguments is the point here.
    # shellcheck disable=SC2086
    set -- $pair
    build_stubs "$1" "$2"
    dest="$work/dest-$3"
    if output="$(run_install "$dest")" && [ -x "$dest/lockyard" ]; then
        case "$output" in
            *"lockyard-$3.tar.gz"*) ok ;;
            *) fail "$1 $2 did not download lockyard-$3.tar.gz: $output" ;;
        esac
        case "$output" in
            *"Checksum verified."*) ok ;;
            *) fail "$1 $2 did not report a verified checksum" ;;
        esac
        # Signature verification is required after the checksum check.
        case "$output" in
            *"Signature verified (cosign)."*) ok ;;
            *) fail "$1 $2 said nothing about signature verification: $output" ;;
        esac
    else
        fail "$1 $2 did not install: $output"
    fi
done

# The destination temp name is exclusive and unpredictable; a pre-created symlink is not followed.
build_release
build_stubs "Darwin" "arm64"
dest="$work/dest-symlink"
mkdir -p "$dest"
printf 'keep me\n' > "$work/victim"
ln -s "$work/victim" "$dest/lockyard.new"
if output="$(run_install "$dest")" && [ -x "$dest/lockyard" ]; then
    if [ "$(cat "$work/victim")" = "keep me" ]; then
        ok
    else
        fail "installer wrote through a symlink in its destination"
    fi
else
    fail "installer could not replace a symlink safely: $output"
fi

# A checksum served beside the archive is not enough when the publisher identity cannot be checked.
build_release
build_stubs "Darwin" "arm64"
mv "$work/stub-bin/cosign" "$work/cosign.stub"
if output="$(PATH="$work/stub-bin:/usr/bin:/bin" LOCKYARD_INSTALL_DIR="$work/dest-no-cosign" \
    LOCKYARD_VERSION="v0.1.0" sh "$script" 2>&1)"; then
    fail "installer accepted an unsigned release without cosign"
else
    case "$output" in
        *"cosign is required"*) ok ;;
        *) fail "missing cosign failed for the wrong reason: $output" ;;
    esac
fi

# If cosign is installed, a release without a signature is refused.
build_release
build_stubs "Darwin" "arm64"
rm "$work/release/lockyard-darwin-arm64.tar.gz.sig" "$work/release/lockyard-darwin-arm64.tar.gz.pem"
cat > "$work/stub-bin/cosign" <<'EOF'
#!/bin/sh
if [ "$1" = verify-blob ]; then
    exit 0
fi
exit 1
EOF
chmod 755 "$work/stub-bin/cosign"
dest="$work/dest-missing-signature"
if output="$(PATH="$work/stub-bin:$PATH" LOCKYARD_INSTALL_DIR="$dest" \
    LOCKYARD_VERSION="v0.1.0" sh "$script" 2>&1)"; then
    fail "cosign accepted a release with no signature"
else
    case "$output" in
        *"release signature is missing"*) ok ;;
        *) fail "missing signature failed for the wrong reason: $output" ;;
    esac
fi
if [ ! -e "$dest/lockyard" ]; then
    ok
else
    fail "unsigned release left an executable behind"
fi

# With both signature files present, cosign must run before the archive is installed.
: > "$work/release/lockyard-darwin-arm64.tar.gz.sig"
: > "$work/release/lockyard-darwin-arm64.tar.gz.pem"
dest="$work/dest-signed"
if output="$(run_install "$dest")" && [ -x "$dest/lockyard" ]; then
    case "$output" in
        *"Signature verified (cosign)."*) ok ;;
        *) fail "cosign did not report signature verification: $output" ;;
    esac
else
    fail "a signed release did not install: $output"
fi

# An unsupported platform refuses and names the other install channels.
build_stubs "Linux" "riscv64"
if output="$(run_install "$work/dest-riscv" 2>&1)"; then
    fail "an unsupported architecture installed something"
else
    case "$output" in
        *"cargo install lockyard"*) ok ;;
        *) fail "the refusal does not name another channel: $output" ;;
    esac
fi

build_stubs "Darwin" "arm64"

# A tampered archive is refused and nothing is installed.
printf 'tampered' >> "$work/release/lockyard-darwin-arm64.tar.gz"
dest="$work/dest-tampered"
if output="$(run_install "$dest" 2>&1)"; then
    fail "a tampered archive was installed"
else
    case "$output" in
        *"checksum mismatch"*) ok ;;
        *) fail "a tampered archive failed for the wrong reason: $output" ;;
    esac
fi
if [ -e "$dest/lockyard" ]; then
    fail "a tampered archive left an executable behind"
else
    ok
fi

# A release whose checksums file does not list this asset is refused too.
build_release
grep -v 'lockyard-darwin-arm64' "$work/release/SHA256SUMS" > "$work/trimmed"
mv "$work/trimmed" "$work/release/SHA256SUMS"
if output="$(run_install "$work/dest-unlisted" 2>&1)"; then
    fail "an unlisted asset was installed"
else
    case "$output" in
        *"does not list"*) ok ;;
        *) fail "an unlisted asset failed for the wrong reason: $output" ;;
    esac
fi

if [ "$failures" -eq 0 ]; then
    echo "install.sh: $checks checks passed"
else
    echo "install.sh: $failures of $((checks + failures)) checks failed" >&2
    exit 1
fi
