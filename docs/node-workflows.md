# Distributed workflows, placement and admission

The local node daemon can own a durable DAG and dispatch its steps over the existing pinned, end-to-end encrypted node transports. The Cloud routes encrypted RPCs; it does not receive workflow definitions, prompts, runner catalogs, labels, revision responses, logs or patches in plaintext. The execution hosts and their administrators remain trusted. Independently pin each executor's result-signing public key in the controller's `result_trust` configuration.

Enable the controller explicitly in its private node configuration:

```toml
[workflow]
max_workflows = 128
max_steps = 128
max_parallel_per_workflow = 16
max_active_steps = 32
poll_interval_ms = 1000

[project_retention.repo]
content_ttl_seconds = 3600

[result_trust.worker]
public_key = "<independently authenticated 32-byte Ed25519 public key as lowercase hex>"
```

An executor declares an administrator-reserved resource budget. This is a configured scheduling budget, not a claim that physical resources are idle or that the runtime passed its resource-enforcement gate:

```toml
[executor.scheduling]
capacity = { cpu_millis = 8000, memory_mb = 16384 }

[executor.scheduling.labels]
os = "linux"
region = "eu"

[executor.scheduling.queue]
max_pending_per_submitter = 32
max_pending_per_project = 128
max_running_per_submitter = 1
max_running_per_project = 16
aging_interval_ms = 1000

[executor.scheduling.queue.projects.repo]
max_pending = 64
max_running = 4
```

Automatic placement requires a declared budget. An explicit node may operate without one; its configured concurrency and container limits still apply. Placement matches project aliases, runner profiles, labels, minimum allocated profile resources and an optional image digest. It prefers immediately available capacity, then normalized queue load, with deterministic ties. The destination enforces resource reservations and caller/project quotas atomically. Caller quotas include its certificate generation. These are per-executor quotas; they are not a consensus-backed, cluster-global spending limit. Priorities range from -20 to 20; aging lets old work outrank newly arriving high-priority work. The best eligible resource waiter reserves the next capacity release so a large job cannot starve behind continuously arriving smaller jobs.

A minimal definition uses an explicit stable ULID. Retain it when a response is lost:

```json
{
  "version": 1,
  "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "max_parallel": 2,
  "steps": [
    {
      "key": "build",
      "needs": [],
      "placement": {"labels": {"os": "linux"}},
      "job": {"repository": "repo", "revision": "main", "runner": "build", "arguments": [], "prompt": null, "timeout_seconds": 600, "priority": 0}
    },
    {
      "key": "review",
      "needs": ["build"],
      "placement": {"node": "worker"},
      "job": {"repository": "repo", "revision": "main", "runner": "review", "arguments": [], "prompt": "Inspect the verified predecessor result", "timeout_seconds": 600}
    }
  ]
}
```

Use `lockyard node workflow submit --file flow.json --config node.toml`, then `status FLOW_ID`, `list` or `cancel FLOW_ID` below `node workflow`. JSON and TOML definition files are supported. MCP provides `flow_submit`, `flow_status`, `flow_list`, `flow_cancel`, `node_describe` and `workflow_inputs`; node operations do not require opening a local coordination project.

Before first submit, the controller fsyncs a deterministic step job ID, exact node/certificate incarnation, configured image, runner configuration hash and full request. Its private journal survives daemon restart. A committed dispatch never automatically chooses a replacement node, renews its prompt, submits a new job ID or replays an uncertain execution. The controller reconciles the original ID at the original incarnation. A changed controller certificate pauses unfinished workflows. Read-only capability discovery has a bounded total budget, individual probe deadlines and rotation across candidates; browser controllers are excluded from execution placement.

Dependencies release only after an independently pinned Ed25519 result verifies the exact node, workspace, job, request hash, immutable resolved revision, image and outcome. Complete, error-free patches are required by default; a step can explicitly set `require_complete_patch: false` when it needs only the signed outcome. Downstream input files contain typed artifact references and hashes, not code bytes or workspace keys. Agents fetch and verify referenced artifacts explicitly. The controller never applies a patch, pushes a branch or publishes a result.

## Managed external actions and owner approval

A profile classified `git_push`, `publish` or `deploy` requires a separately pinned owner authority. An ordinary compute profile with credentials/network can also cause side effects; profile classification and credential scoping remain an administrator responsibility. This mechanism does not classify arbitrary shell behavior.

For an external-action DAG step, the controller first verifies predecessor outcomes, fixes the destination certificate/profile/image, resolves the requested Git revision through a pinned read-only RPC, and replaces the mutable ref with that exact commit. It persists this complete request and enters `awaiting_owner`. No JobSubmit or sticky submission binding is created by materialization. The owner decision is outside the immutable original definition hash.

Export and review that exact request:

```sh
lockyard node workflow status FLOW_ID --config node.toml
lockyard node workflow approval-request FLOW_ID STEP --output request.json --config node.toml
lockyard node approval sign-materialized --input request.json --runner-config independently-reviewed-profile.json --workspace WORKSPACE --node WORKER --certificate-sha256 INDEPENDENT_PIN --key-file /private-config/lockyard/keys/owner-approvals/release-owner.pk8 --not-before-ms START_MS --expires-at-ms END_MS --output approval.json
lockyard node workflow approval-attach FLOW_ID STEP --definition-sha256 DEFINITION_HASH --approval approval.json --config node.toml
```

Authenticate the workspace and destination certificate independently, and inspect the full frozen request, referenced predecessor evidence and independently reviewed runner profile. A worker's authenticated public catalog is not evidence that the owner inspected its configuration. The signing command checks the full reviewed profile hash, exact image/reference, action and owner pins against the exported binding. The exported request contains no private runner paths, executable configuration or secret references. Owner private keys must remain in the protected global `lockyard/keys/owner-approvals` directory; copied keys outside that chosen directory and detected Git checkout/metadata ancestry are rejected. On a separate owner machine, independently review `XDG_CONFIG_HOME` and keep it outside all execution checkouts; the daemon can protect only the config roots it knows. Future copying/tracking by an administrator is outside that check.

MCP exposes `flow_approval_request` and `flow_approval_attach`; it does not expose an owner signing key. An attached approval must verify against the frozen target/profile/spec/inputs/revision and its current validity window. Expiry before first dispatch returns the step to `awaiting_owner`; it does not attempt an unsigned submit or mutate an already submitted job. After durable dispatch commitment, the approval and request cannot be replaced. An identical attachment retry only returns the existing state. The destination independently enforces the approval again at admission and before starting the workload.

## Cancellation, uncertainty and maintenance

`cancel` is a request. A step with `dispatch_committed: true` may already be in flight, including the conservative crash gap before the first bytes leave the controller. Cancellation at that point cannot promise that an approved external action will not execute. Its summary remains running/uncertain until signed outcome reconciliation. A late cancellation that stops no step does not relabel successful work as cancelled. Steps awaiting owner approval have no committed submit and can be cancelled locally without executing.

Drain stops new workflow dispatches and new job admissions while existing work reconciles. Drain status includes `workflow_active_steps` and `outbound_unresolved`. Offline key rotation and managed updates also inspect all private workflow journals under the same controller lock and reject any incomplete workflow. They separately require every outbound operator/workflow/delegated submit to have a verified terminal receipt or an explicit maintenance review.

Use `node dispatch pending` to inspect unresolved exact job, source certificate, destination certificate, opaque binding, delivery state and earliest manual-review time. A signed matching terminal result can settle the binding immediately. A `not_found`, missing signature, expired content or lost response cannot by itself settle a remote dispatch. Manual `node dispatch review TARGET JOB_ID --certificate-sha256 PIN --source-certificate-sha256 ORIGINAL_SOURCE_PIN --binding BINDING --confirm-no-active-execution` requires the operator independently to verify/stop surviving execution. For a versioned prepared binding, review atomically fences the first delivery before it can begin. For an already claimed remote frame, review requires its immutable original delivery deadline plus clock-skew margin to have elapsed. For a claimed local admission, review holds the same lock as the admission and checks both the local executor state and its durable journal, rejecting queued, running, unknown or incompletely persisted execution. Legacy bindings with unknown delivery deadlines require actual signed terminal evidence. A definitive local queue-quota rejection is recorded separately as never admitted, allowing maintenance without asserting a signed outcome. Review sends no RPC, creates no signed success, releases no dependency and retries no work.

If a workflow remains uncertain after remote execution is independently stopped, first settle its exact outbound bindings separately. Then drain and use `node workflow abandon FLOW_ID --definition-sha256 HASH --controller-certificate-sha256 ORIGINAL_CONTROLLER_PIN --confirm-no-active-execution`. The daemon holds the round barrier, checks local queued/running/unknown work and settled outbound bindings, and records a distinct abandonment. Unfinished steps become failed/skipped. Abandonment never creates success, releases descendants, changes another DAG or retries an execution. Both review protocols are bound to the current local daemon certificate and are unavailable to workload delegation sockets.

Terminal graph content uses the minimum explicit retention policy of its projects, snapshotted at admission. Terminal expiry removes definitions/prompts/arguments/references after a durable minimal workflow-ID/definition-hash tombstone. The same workflow ID cannot be revived or refresh its TTL on retry. Active and unknown execution are retained for explicit reconciliation; they cannot be erased safely as if they had completed. Outbound bindings retain minimal deduplication/maintenance metadata and have an explicit bounded capacity.

## Delegation inside a workload

The host gives each main workload its own read-only mounted client configuration and scoped RPC socket at `/run/lockyard-delegation`, plus `LOCKYARD_NODE_CONFIG`. The operator socket, node TLS private key and broker machine credential are not mounted. Git/export helpers receive no delegation mount. The bridge permits bounded ordinary node/job RPCs, public encrypted discovery, and cancellation only of children whose immutable local origin matches that parent job. It rejects drain, workflow controls, approval attachment, identity/update operations and unknown-outcome resolution. All team agents can use configured approved runner/project profiles; secret-bearing profiles still enforce their explicit project scopes at the executor.

A live lease is retained if stopping the parent is uncertain. Restart loses the old daemon's listener and does not automatically restore delegation for an unknown parent; surviving authorized compute may continue, while further nested delegation is unavailable until explicit reconciliation. Accepted children retain their own job identities and are never automatically resubmitted or reassigned.

## Evidence boundary

The repository tests include pure scheduling/DAG crash and signature checks, real private Unix bridge boundary checks, and a real CLI/MCP + two-daemon pinned encrypted QUIC test. The latter deliberately uses `/bin/false` as an unavailable runtime and verifies signed failures before any container executes, including the real owner materialization/sign/attach path. It is control-plane and negative-runtime evidence, not successful resource-enforced execution. The managed environment's real Docker also lacks enforceable CPU/RAM/PID limits; production positive-container acceptance remains a separate infrastructure gate.
