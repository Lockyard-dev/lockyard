# Explicit offline signed managed updates

The node CLI provides opt-in signed executable maintenance. It does not download releases, execute a candidate, restart a daemon, change a service unit, resume admission or update this environment automatically. The operator supplies local artifacts and explicitly approves the reviewed digest. Normal system-package installations remain under their package manager.

A managed installation uses a dedicated canonical executable in an existing private directory owned by the operator. The executable must be an owned regular file, have an owner execute bit, have no extra hardlinks and be inaccessible to writes by other users. Symlinked paths and directory aliases are rejected. A create-only owner binding prevents a second node state from adopting the same managed installation. Workload mounts cannot contain node state or these protected identity/update files.

Release signing trust is pinned independently. An Ed25519 signature binds a typed canonical statement in a separate update domain: release ID, numeric three-part version, monotonic release sequence, Linux architecture/libc platform, minimum current version, compatible state schema, binary size and SHA-256, and issue/expiry times. Supported binaries are bounded to 256 MiB and checked for the declared 64-bit Linux ELF architecture. Prerelease/build version strings and state-schema transitions are rejected by this implementation; it performs no automatic data migration. Signature trust authenticates the release owner's statement and bytes, not the safety of arbitrary signed code.

Before opting in, run the intended private executable and obtain a signed baseline statement for those exact bytes and actual compiled version. The initial baseline is verified as strictly as an update, so an unsigned bootstrap never becomes an automatic rollback target. A release statement can be signed locally without publishing:

```sh
/private/node-bin/lockyard node update sign --statement /private/releases/release.json --key-file /private/release-signing.pk8 --output /private/releases/release.signed.json
```

The signer must control the trusted release key; this command grants no permission to publish or deploy. Example statement shape (hash and size must describe the actual build):

```json
{
  "format": 1,
  "release_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "version": "1.2.3",
  "sequence": 42,
  "platform": "linux-x86_64-gnu",
  "minimum_current_version": "1.2.0",
  "state_schema_version": 1,
  "binary_sha256": "<64 lowercase hexadecimal characters>",
  "binary_bytes": 12345678,
  "issued_at_ms": 1794024000000,
  "expires_at_ms": 1794110400000
}
```

Drain through the private local operator socket, wait for all local jobs and workflows to become confirmed terminal, reconcile outbound/remote children, then stop the daemon. Queued, active, starting, interrupted-unknown and unresolved outbound work block maintenance. An offline installer never constructs Executor, runs recovery jobs, kills a guessed PID or assumes an unavailable remote job did not run.

```sh
/private/node-bin/lockyard node drain --config /private/node.toml
/private/node-bin/lockyard node drain-status --config /private/node.toml
# Stop the drained foreground daemon or its operator-managed service explicitly.
/private/node-bin/lockyard node update init --binary /private/node-bin/lockyard --public-key TRUSTED_RELEASE_PUBLIC_KEY --baseline /private/releases/baseline.signed.json --config /private/node.toml
/private/node-bin/lockyard node update prepare --release /private/releases/next.signed.json --binary /private/releases/next-binary --config /private/node.toml
```

Preparation verifies and privately stages the signed candidate, returning an exact `approval_sha256` and preparation path. Review those concrete values and the release metadata. Apply requires that digest, the unchanged base generation and an unchanged signature/policy/binary. Every action rechecks drain, host/executor/workflow/outbound locks, workspace rotation state and global binding. Running managed daemons retain a shared installation lock for their lifetime, so replacement cannot proceed while that installation is in use.

```sh
/private/node-bin/lockyard node update apply --prepared /private/node-state/managed-updates/staged/RELEASE_HASH/prepared.json --approval-sha256 REVIEWED_DIGEST --config /private/node.toml
/private/node-bin/lockyard node update status --config /private/node.toml
```

A durable pending journal precedes atomic executable replacement. Directory syncs and an atomic installed-state write make interruption explicit; any pending, unsafe or corrupt marker blocks daemon and standalone executor startup. Recovery verifies the original signed transition and approval, accepts only its exact old/new binary hashes, and completes forward. It never overwrites an unrelated or corrupted replacement. Authorization expiry is checked when the update is admitted; recovery may complete an already-approved transaction after that window without admitting a new update.

```sh
/private/node-bin/lockyard node update recover --approval-sha256 ORIGINAL_REVIEWED_DIGEST --config /private/node.toml
```

The operator can also invoke the independently verified retained previous binary as an explicit recovery tool if the candidate cannot start. `status` reports its private path and the rollback digest. The product never invokes it automatically. Only the exact previous verified image is eligible for rollback; the release high-water sequence remains unchanged, so a rollback does not reopen older versions as fresh updates. Installation generation changes make each reviewed rollback digest one use. A running daemon verifies that its actual managed executable and compiled version match the signed installed image before recovery or job admission.

```sh
/private/verified-previous/lockyard node update rollback --approval-sha256 REVIEWED_ROLLBACK_DIGEST --config /private/node.toml
```

Only current/previous signed binary artifacts remain after a completed transaction. Earlier preparations become stale and are pruned; at most eight candidates may be staged, each bounded to 256 MiB. Unpublished files use an installation-specific, managed-update temporary namespace. Shared node/executable directories are cleaned only for that installation’s exact policy/owner/binary destinations; unrelated private files and another installation’s stages are preserved. Product staging directories are ownership checked and cleaned under the maintenance locks. Untagged files from unpublished development formats are left for explicit operator review, not guessed and deleted. Explicit resume and daemon/service start remain separate operator actions.

Synthetic tests cover signatures, hashes, platform/minimum-version/sequence rejection, wrong approvals, every journal crash phase, interrupted publication, exact rollback, unknown replacement refusal, unsafe paths, drain and active/unknown work, and running installation locks. Tiny ELF-shaped test files are never executed and do not prove a real release rollout. A source-specific real CLI proof separately verified an actual 0.0.1 → 0.0.2 update, explicit new daemon start, running-daemon denial, exact rollback and explicit old daemon start in a private synthetic installation, with zero executed jobs. Subsequent lifecycle-review fixes require their own final-source retest; adversarial review and target infrastructure qualification remain production acceptance gates. The existing resource-capable container execution gate remains unchanged.
