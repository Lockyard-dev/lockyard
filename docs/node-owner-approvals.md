# Owner authorization for managed external actions

E5 adds offline owner authorization for explicitly managed runner profiles. A profile's `action` is `compute` (the compatibility default), `git_push`, `publish` or `deploy`. Every workspace member can continue to dispatch permitted compute profiles. A managed external profile requires an Ed25519 owner signature in `JobSpec.owner_approval`, even for the local operator. An unapproved job fails before its journal/worktree is created, before clone or runtime inspection, and before any workload credentials are fetched. The executor rechecks authorization immediately before preparing a worktree, staging credentials and spawning the workload.

This is an administrative profile boundary. Lockyard does not classify arbitrary shell commands, inspect every network request or provide universal DLP. Ordinary networked compute with sufficiently privileged credentials can perform external actions; the selected network policy permits either no network or ordinary network access. Trusted node administrators must classify profiles, restrict their programs and arguments, and grant credentials appropriate to their purpose. A member who controls the node administrator account can change these policies; the agreed trust model includes execution hosts and administrators. Do not give a compute profile publishing/deployment credentials and expect the managed-action approval gate to control them.

The owner authority is independent of workspace encryption and machine identity. Workspace members share the workspace decryption key; possession of that key does not grant owner-signing authority. An administrator pins the customer owner's public key in each managed profile, using an independently authenticated channel:

```toml
[executor.runners.production-release]
action = "deploy"
# The remaining normal runner/container/supply-chain configuration is required.

[[executor.runners.production-release.owner_approval_authorities]]
public_key = "PINNED_64_LOWERCASE_HEX_OWNER_PUBLIC_KEY"
```

No key included in an approval establishes trust. Profiles accept at most 32 distinct configured owner keys; missing pins, malformed keys or a missing authenticated destination certificate fail startup for an external-action profile. The node host derives its destination certificate SHA-256 from its loaded TLS identity before opening the executor journal. This incarnation field cannot be supplied in node TOML.

The signed claim binds the workspace, destination node and certificate incarnation, stable job ID, repository/profile aliases, canonical request SHA-256, exact resolved Git commit, complete runner configuration digest, immutable image reference and digest, external-action kind, and exact validity interval. The request hash covers arguments, prompt, timeouts, priority, workflow inputs and the expected runner digest. Only the approval field itself is excluded to avoid circular hashing. The runner digest includes its pinned owner authorities, credentials references, program, arguments, network and resource policy. Owner signatures use a separate domain from result manifests and image attestations; those signatures cannot be substituted for an approval. Strict typed JSON rejects unknown fields and noncanonical signed payloads.

Validity windows must be nonempty, start after the Unix epoch and span at most 24 hours. Admission and actual start must occur at or after `not_before_ms` and before `expires_at_ms`, according to the trusted node's wall clock. Work queued past the deadline fails; work already running after an authorized start continues through broker outages and through the end of the window. Resource enforcement, supply-chain checks, project credential scope and all normal execution limits remain mandatory.

The stable job ID is the one-use identity. A durable admitted record consumes it: an identical authenticated retry returns its existing state without executing again, including after approval expiry or daemon restart. A changed request or submitter conflicts; copying the token to another job ID or node incarnation fails its binding. After content retention, the separate durable tombstone still prevents readmission. An uncertain outcome requires explicit local reconciliation and is never an automatic retry. Losing the node's durable state is not a supported way to obtain replay protection; restore never runs exported journals automatically.

The CLI performs the whole approval preparation/signature/verification flow offline. Owner private keys live only below the protected global directory `$XDG_CONFIG_HOME/lockyard/keys/owner-approvals` (or `$HOME/.config/lockyard/keys/owner-approvals`). The key command creates a new owned private key without overwrite; signing rejects valid keys copied outside that directory. Key loading rejects symlinks, hardlinks, nonregular files and unsafe permissions. The daemon protects its own selected global keys directory from workload-secret delegation and execution checkouts. A separate owner machine may select another `XDG_CONFIG_HOME`; the owner must independently keep that location outside every executor checkout. The approval CLI rejects detected Git worktree/metadata ancestry, including symlinked config roots, before generating or loading an owner key. It cannot prevent a future administrator from copying that file or creating a new repository around it. The executor never loads an owner's private key, and no private key enters a cloud request, approval, argv or container mount.

```sh
# Owner workstation, isolated private key custody. Receipt contains only a public key and path.
lockyard node approval key --name customer-owner --json

# Prepare on the owner workstation from the exact JSON JobSpec and reviewed JSON RunnerProfile.
# Resolve and independently review the destination incarnation and immutable commit first.
lockyard node approval prepare --request request.json --runner-config runner.json \
  --workspace WORKSPACE --node WORKER --certificate-sha256 DESTINATION_CERT_SHA256 \
  --revision EXACT_COMMIT --not-before-ms START_MS --expires-at-ms END_MS \
  --output claim.json --json

# Review the actual request, runner, destination, action and claim before this explicit signature.
lockyard node approval sign --input claim.json --request request.json --runner-config runner.json \
  --key-file /private/config/lockyard/keys/owner-approvals/customer-owner.pk8 \
  --output approval.json --json

# Verify independently and produce an exact complete request without sending it.
lockyard node approval verify --request request.json --runner-config runner.json \
  --workspace WORKSPACE --node WORKER --certificate-sha256 DESTINATION_CERT_SHA256 \
  --revision EXACT_COMMIT --approval approval.json --public-key PINNED_OWNER_PUBLIC_KEY \
  --output-request authorized-request.json --json
```

The signature command recomputes the request/profile bindings and requires its key to be present in the reviewed profile's independently configured authority list. Verification requires an independently supplied public key and exact expected context; it never trusts the claim to select those values. All output files are private, created without overwrite and synced. `job submit-spec TARGET --input authorized-request.json` sends that exact typed request when separately authorized to perform the external action. The ordinary `job submit` also accepts `--owner-approval approval.json` when its other flags reproduce the exact approved request. JSON submission avoids accidentally changing workflow inputs or expected profile hashes between approval and dispatch. The standard encrypted transport and stable submission receipts still apply.

These commands do not themselves publish or deploy. No actual push, publication or deployment was performed during implementation. Focused tests prove cryptographic/context rejection, offline CLI key custody and durable negative-runtime replay behavior. They do not prove a successful external action or resource-enforced container execution: the current managed Docker daemon still lacks the required CPU, RAM and PID enforcement. That infrastructure gate remains open for production acceptance.
