# Native Linux execution

Linux runner profiles default to `runtime: native`. There is no unconfined execution fallback.
macOS refuses with `container_limits_unavailable`; Docker/Podman remain explicit optional backends.
The same backend isolates the workload and every credential-free Git/patch helper.

## Configuration and trust

The existing `container` configuration owns resource limits for every backend. A native profile uses:

```json
{
  "runtime": "native",
  "runtime_program": "/usr/local/bin/lockyard",
  "cgroup_root": "/sys/fs/cgroup/DELEGATED_SCOPE/jobs",
  "native_rootfs": "/var/lib/lockyard/executor-rootfs",
  "image": "native@sha256:REPLACE_WITH_MEASURED_ROOTFS_DIGEST",
  "supply_chain": "USE_THE_EXISTING_CUSTOMER_PINNED_ATTESTATION_SBOM_AND_SCAN_POLICY_OBJECT",
  "git_program": "/usr/bin/git",
  "memory_mb": 512,
  "cpu_millis": 1000,
  "pids_limit": 128,
  "network": "none"
}
```

`supply_chain` above is an explanatory placeholder: use the complete policy object from
[node-executor.md](node-executor.md). Signing remains mandatory. Provision a dedicated immutable
rootfs containing the runner, Git, its libraries and optionally Lockyard/Codex. Never select `/` or
mount a live host distribution as an image. The node hashes sorted paths, entry type, permission
bits, file lengths/content and symlink targets before admission. Both signed `image_digest` and
`image_config_digest` must equal this rootfs digest. The existing trusted attestation, SBOM and
vulnerability report bind this native image; no synthetic admission is created in production.

`lockyard node native-image-digest --rootfs /var/lib/lockyard/executor-rootfs` prints the identity to
use when preparing the signed attestation. Updates require a newly measured, scanned and signed
image. No group/world writable entries, special files or nested mount points are allowed. Symlinks
are hashed without following them; regular files use nofollow reads. Host administrators remain
trusted: keep the provisioned image immutable while the node runs. The node/control keys and state
must stay outside every image/checkout. The whole host home, host `/etc`, `/proc`, `/sys`, container
sockets and node state are never mounted into a job.

The released `lockyard` executable contains the fresh-process sandbox entry. A separately built
`lockyard-sandbox` is also supported. `runtime_program` is the absolute installed path to either.
The daemon never performs namespace setup in a multithreaded `pre_exec` closure.

## Kernel enforcement

Configure an empty delegated cgroup v2 subtree with `cpu`, `memory` and `pids`. Before running any
job code, the helper creates its per-command child, applies/read-verifies `memory.max`,
`memory.swap.max=0`, `memory.oom.group=1`, `cpu.max`, `pids.max`, and migrates itself into that child.
The daemon should run in a sibling manager leaf. Domain controllers cannot be enabled in a populated
parent. `systemd-run --user --scope -p Delegate=yes` or an administrator-delegated slice is required.
Delegation must cover the common ancestor used when moving a helper from its manager leaf.

Every command gets new user, mount, PID, network, IPC and UTS namespaces, private mount propagation,
a fresh PID-local proc, an ephemeral root, readonly system image mounts and only its private copied
checkout/Git metadata. The private repository is cloned without hardlinks. Patch helpers mount the
worktree readonly and receive no job credentials. `/dev` contains only null/zero/random/urandom and
`/dev/fd`; only those device binds permit device access. Mounts are nonrecursive; image submounts
are rejected before hashing so hidden underlying content cannot escape measurement.

The namespace's PID 1 reaps descendants. Outside-root file descriptors are closed, all effective,
permitted/inheritable and bounding capabilities are dropped, `no_new_privs` is set, and a classic BPF
seccomp profile is installed before workload fork/exec. The profile checks the syscall architecture,
rejects x32 and denies these syscall families with EPERM:

- mount/umount/pivot_root/chroot/unshare/setns and the new mount API;
- ptrace/process_vm_readv/process_vm_writev, bpf/perf_event_open;
- keyctl/add_key/request_key, kexec_load/init_module/finit_module/delete_module/reboot;
- open_by_handle_at, userfaultfd, io_uring_setup;
- clone with namespace flags. clone3 returns ENOSYS so ordinary libc threads can use safe clone.

Supported native syscall ABIs are x86_64 and aarch64. A missing control, namespace, migration,
tmpfs/proc/chroot, descriptor closing, capability operation or seccomp profile fails the startup
probe. `lockyard doctor --node-config /path/node.toml --json` gives the failed stage and remedies,
including `kernel.apparmor_restrict_unprivileged_userns=1` and the exact helper attachment.

Memory events produce signed `limit_exceeded:memory` results; PID exhaustion events produce signed
`limit_exceeded:pids`, even when the command catches EAGAIN. CPU is throttled by quota, not killed.
Cancellation and all stop paths use `cgroup.kill` and require `cgroup.events: populated 0`. Kernel
events and a bounded, identity-bound private cleanup receipt are fsynced before removing the group.
Every new invocation invalidates an old receipt. A missing proof remains `interrupted_unknown`;
restart never kills/replays an old numeric PID. Credentials are removed only after confirmed stop.

`network: none` always has a disconnected network namespace. `bridge` also uses a private network
namespace; configure `native_network_program: /usr/bin/slirp4netns` for rootless egress. The trusted
supervisor waits for slirp readiness, uses its sandbox/seccomp flags and disables host loopback.
Missing/failed networking refuses; the job never inherits the host network. The rootfs must contain
a regular `/etc/resolv.conf` (overlaid with the private resolver). External network/credentials keep
the existing exact owner-approval policy. Patch helpers always use disconnected networking.

## AppArmor and Linux acceptance

Ubuntu 24.04 may restrict unprivileged user namespaces. An administrator installs precise literal
binary attachments from `packaging/apparmor/lockyard`:

```sh
sudo /usr/local/bin/lockyard node install --apparmor \
  --sandbox-binary /usr/local/libexec/lockyard-sandbox
# Or use --sandbox-binary /usr/local/bin/lockyard for the single released binary.
```

This explicit command requires root, root-owned immutable binaries/ancestors and a trusted parser.
It validates before atomic publication and refuses replacing a different administrator profile.
The profile grants userns creation; the cgroup/namespace/seccomp policies enforce isolation.

On an unprivileged Linux account, after administrator provisioning:

```sh
cargo build --locked -p lockyard -p lockyard-node --bin lockyard --bin lockyard-sandbox
sudo install -m 755 target/debug/lockyard /usr/local/bin/lockyard
sudo install -D -m 755 target/debug/lockyard-sandbox /usr/local/libexec/lockyard-sandbox
sudo sh tools/ci/prepare-native-rootfs.sh /var/lib/lockyard-test-rootfs
sudo /usr/local/bin/lockyard node install --apparmor --sandbox-binary /usr/local/libexec/lockyard-sandbox
LOCKYARD_NATIVE_ROOTFS=/var/lib/lockyard-test-rootfs \
LOCKYARD_NATIVE_SANDBOX_BINARY=/usr/local/libexec/lockyard-sandbox \
  sh tools/ci/test-native-executor.sh
```

The script creates a delegated systemd user scope, moves its shell to the manager leaf, and requires
real enforcement (`LOCKYARD_REQUIRE_NATIVE_TESTS=1` makes missing prerequisites fail). Tests use
synthetic explicitly trusted attestations only for their fixture rootfs. They cover real command and
agent processes, namespace/capability/seccomp checks, memory/PID limits, CPU throttling, literal argv,
patch download, detached-child cancellation, seven legacy runtime cases, two-step signed workflow
result consumption and actual HTTPS/WebSocket broker outage with offline restart/outbox recovery, and an exact owner-approved
slirp bridge HTTP transfer in a distinct network namespace.
Default Linux runs print an explicit skip when rootfs/delegation is absent; CI's native job requires
all prerequisites. macOS cross-check/clippy establish compilation, not successful Linux execution.

Kernel semantics: [cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[unshare](https://man7.org/linux/man-pages/man2/unshare.2.html),
[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html),
[slirp4netns flags](https://github.com/rootless-containers/slirp4netns/blob/master/slirp4netns.1.md).
