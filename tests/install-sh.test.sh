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

work="$(mktemp -d)"
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
    # wget must not be picked up instead of the stubbed curl.
    chmod 755 "$bin/curl" "$bin/uname"
}

run_install() {
    target_dir="$1"
    PATH="$work/stub-bin:$PATH" \
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
        # Cosign is optional: without signatures on the fake release the script must still install.
        case "$output" in
            *"Signature verified"*|*"checksum alone was checked"*) ok ;;
            *) fail "$1 $2 said nothing about signature verification: $output" ;;
        esac
    else
        fail "$1 $2 did not install: $output"
    fi
done

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
