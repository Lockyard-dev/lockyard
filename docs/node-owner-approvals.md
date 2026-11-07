# Owner authorization for external job specifications

EP-06 requires an offline Ed25519 owner signature in `JobSpec.owner_approval` whenever the declared runner network is not `none` **or** the workload receives credentials. Credentials include runner secret references, every explicitly forwarded environment variable, and injected repository cloud credentials and workspace keys. This applies to `compute` as well as the explicitly managed `git_push`, `publish` and `deploy` profiles. Offline compute without credentials remains available to every permitted workspace member. Managed profiles keep their owner requirement even when offline and without credentials.

The workspace policy belongs to its trusted node executor configuration:

```toml
[executor]
external_actions = "require_approval" # default; the only other value is "deny"
```

`require_approval` requires an owner signature for any network or credentials. `deny` additionally rejects any job combining network access and credentials, even with a valid signature (`external_actions_denied`, HTTP projection 403). The SDK stops the job without automatic retry or policy changes; approval cannot override this policy. Network without credentials and offline credentials still require approval under either policy. Missing, invalid, expired or mismatched approval for an external compute specification returns `owner_approval_required`. Unapproved jobs are refused before journal/worktree creation, clone, runtime inspection or credential retrieval. Authorization is checked again before worktree preparation, credential staging and process spawn. The normal managed-profile signature diagnostics remain available.

The signature covers the **declared job specification**, including image, command, arguments, network, credential references and declared destinations. It does not authorize or inspect each dynamic action performed by that command, classify arbitrary shell commands or inspect every network request. Secret values are resolved only after authorization; signatures bind their configured references, not the current bytes of renewable credentials. Execution hosts and their administrators remain trusted. Administrators must restrict programs, arguments, network policy and credential scope appropriately.

The owner authority is independent of workspace encryption and machine identity. Workspace members share the workspace decryption key; possession of that key does not grant owner-signing authority. An administrator pins the customer owner's public key in each external-capable profile, using an independently authenticated channel:

```toml
[executor.runners.production-release]
action = "deploy"
# The remaining normal runner/container/supply-chain configuration is required.

[[executor.runners.production-release.owner_approval_authorities]]
public_key = "PINNED_64_LOWERCASE_HEX_OWNER_PUBLIC_KEY"
```

No key included in an approval establishes trust. Profiles accept at most 32 distinct configured owner keys; missing pins, malformed keys or a missing authenticated destination certificate fail startup for a managed external-action profile. External compute without usable owner pins or a destination certificate is rejected at admission with `owner_approval_required`. The node host derives its destination certificate SHA-256 from its loaded TLS identity before opening the executor journal. This incarnation field cannot be supplied in node TOML.

The signed claim binds the workspace, destination node and certificate incarnation, stable job ID, repository/profile aliases, canonical request SHA-256, exact resolved Git commit, complete runner configuration digest, immutable image reference and digest, external-action kind, and exact validity interval. The request hash covers arguments, prompt, timeouts, priority, workflow inputs and the expected runner digest. Only the approval field itself is excluded to avoid circular hashing. The runner digest includes its pinned owner authorities, credential references, program, arguments, network and resource policy. When a repository injects cloud credentials, the additional `repository_cloud_sha256` binds its broker URL, workspace/repository destination and token-file reference; changing any of them requires a new owner signature. Owner signatures use a separate domain from result manifests and image attestations; those signatures cannot be substituted for an approval. Strict typed JSON rejects unknown fields and noncanonical signed payloads.

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

For a repository with injected cloud credentials, add `--repository-config repository.json` (the independently reviewed JSON `RepositoryConfig`) to **prepare, sign and verify**, and to `sign-materialized` for a frozen workflow request. Omitting or changing that context invalidates the signature. Workflow placement advertises external approval requirements and the repository cloud digest, freezes them in its durable owner checkpoint, and waits for the same owner approval flow used by managed profiles before dispatching external compute.

The signature command recomputes the request/profile/repository bindings and requires its key to be present in the reviewed profile's independently configured authority list. Verification requires an independently supplied public key and exact expected context; it never trusts the claim to select those values. All output files are private, created without overwrite and synced. `job submit-spec TARGET --input authorized-request.json` sends that exact typed request when separately authorized to perform the external action. The ordinary `job submit` also accepts `--owner-approval approval.json` when its other flags reproduce the exact approved request. JSON submission avoids accidentally changing workflow inputs or expected profile hashes between approval and dispatch. The standard encrypted transport and stable submission receipts still apply.

These commands do not themselves publish or deploy. No actual push, publication or deployment was performed during implementation. Focused tests prove cryptographic/context rejection, offline CLI key custody and durable negative-runtime replay behavior. They do not prove a successful external action or resource-enforced container execution: the current managed Docker daemon still lacks the required CPU, RAM and PID enforcement. That infrastructure gate remains open for production acceptance.
