#!/bin/sh
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
# Administrator provisioning, never called by the node or its jobs.
set -eu
rootfs=${1:?usage: prepare-native-rootfs.sh /absolute/new/rootfs}
test "$(id -u)" = 0 || { echo 'root is required to provision an image' >&2; exit 1; }
case "$rootfs" in /*) ;; *) echo 'rootfs must be absolute' >&2; exit 1 ;; esac
test ! -e "$rootfs" && test ! -L "$rootfs" || { echo 'destination already exists; refusing to change it' >&2; exit 1; }
command -v debootstrap >/dev/null
# Refuse debootstrap's HTTPS-only fallback when the host's archive keyring is missing.
debootstrap --force-check-gpg --variant=minbase --include=python3,git,ca-certificates bookworm "$rootfs" https://deb.debian.org/debian
# Only immutable regular files/directories/symlinks belong in the measured image.
# These are freshly provisioned image paths, never directories on the running host.
for name in dev proc sys run tmp; do
    rm -rf -- "${rootfs:?}/$name"
    mkdir -m 755 -- "${rootfs:?}/$name"
done
rm -f -- "$rootfs/etc/resolv.conf"
printf 'nameserver 10.0.2.3\n' > "$rootfs/etc/resolv.conf"
chmod -R a+rX -- "$rootfs"
chmod -R go-w -- "$rootfs"
echo "Prepared immutable native test rootfs: $rootfs"
