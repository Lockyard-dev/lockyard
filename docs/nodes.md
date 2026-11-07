# Remote nodes and jobs

A node is a long-running service that accepts authorized requests from other workspace members. Every member that participates must import the same workspace encryption key. Node messages are end-to-end encrypted and transport connections use TLS. Direct connections also require manually exchanged, pinned peer certificates. A trusted peer needs explicit permission for each operation. Only configured container runners can execute jobs; the operator chooses an image pinned by digest and Docker or Podman, and configures CPU, memory and process limits. There is no host-execution mode.

Import the existing workspace key using the documented `lockyard cloud key` workflow on every node. Then create a private node identity and configuration:

```sh
lockyard node init --config /private/node.toml --state-dir /private/node-state \
  --node-id laptop --workspace WORKSPACE_ID --tls-name laptop.example
```

The configuration and state directory must not already exist. Save the reported certificate fingerprint and verify it independently with each peer. The node must have the workspace key available when it runs. `node init` does not generate a workspace key or upload it. Edit the private TOML to configure a direct listener, trusted peers, relay and optional executor. All configured file paths must be absolute; permissions on the configuration, identity and token files must remain private. See [node-executor.md](node-executor.md) for repository and container runner fields and operational limits.

A direct peer entry has this form, with the peer's verified DER certificate copied through a trusted channel:

```toml
listen = "0.0.0.0:4400"
trust_anchors = ["/private/worker-cert.der"]

[[peers]]
node_id = "worker"
address = "192.0.2.10:4400"
tls_name = "worker.example"
certificate = "/private/worker-cert.der"
certificate_sha256 = "verified-peer-sha256"
allowed_operations = ["node.ping", "job.submit", "job.status", "job.cancel", "job.log", "job.patch", "job.resolve_unknown"]
```

Configure reciprocal peer policies on the worker, granting only the operations intended for the requesting node. For a relay, configure `[relay]` with `url` and `token_file` and, if needed, `tls_roots`; the relay requires authenticated workspace credentials. Use a TLS URL. Node configuration is local; exchanging and verifying certificates and setting peer policy are operator actions.

Run `lockyard node serve --config /private/node.toml` in a supervised process. Other commands use `--config` or `LOCKYARD_NODE_CONFIG` to connect to the private control socket. `node status`, `node list`, and `node ping TARGET` inspect the service and discover nodes.

```sh
lockyard job submit worker --repository repo --runner codex --prompt-file ./prompt.txt
lockyard job status worker JOB_ID
lockyard job logs worker JOB_ID --offset 0 --limit 16384
lockyard job patch worker JOB_ID --output ./review.patch
```

Use `--prompt-file -` to read a prompt from standard input. Submission prints the job ID even if its outcome is uncertain. Record it and reconcile with `job status`; to retry, use `--id` with the same ID and identical specification. A new ID represents a new job and can execute again. The checkout is configured on the worker, the revision defaults to `HEAD`, and each job uses a separate detached worktree. Review downloaded patches before applying them. Lockyard never automatically applies a patch or pushes commits. Patch downloads create a new private file and reject truncated or inconsistent chunks.

`job cancel` requests cancellation. A job in `interrupted_unknown` needs operator investigation before `job resolve-unknown` can clear it; do not assume it never ran. Logs and patches are retained on the worker subject to configured limits. The MCP tools `node_status`, `node_list`, `node_ping`, `job_submit`, `job_status`, `job_logs`, `job_cancel`, `job_patch`, and `job_resolve_unknown` use the same local service. Set `LOCKYARD_NODE_CONFIG` in the MCP environment or provide `config` in each call. MCP submissions require a caller-supplied ULID so callers can retain it before dispatch.

Before sending a submission, the client stores a private, synced receipt under the node's `state_dir/submissions`. It records the job ID, target, a keyed fingerprint of the complete specification, and `dispatching` status; it does not contain the prompt or arguments. If the client is killed before it prints a result, run `lockyard job receipts --config /private/node.toml` to recover the ID, or `lockyard job receipt JOB_ID --config /private/node.toml` to inspect it. A `dispatching` receipt means the outcome needs reconciliation, including when the client was interrupted before dispatch. The list reports an unreadable or damaged receipt individually so other IDs remain visible. Reusing an ID with a different target or specification is refused. MCP also exposes `job_receipts` and `job_receipt`.

When a relay is configured, `node list` queries the authenticated Cloud node directory and labels the result `cloud`. Without a relay it lists local configured peers with source `configured_peers`. A directory entry is discovery metadata; independently verify the certificate before trusting it.

To revoke a direct QUIC peer certificate, stop the node daemon and verify that its process has exited. Remove the peer entry and its certificate pin from the private TOML on each node that must deny that certificate. Also remove the certificate from `trust_anchors` when it is not needed by another peer. Restart the service and confirm the revoked peer cannot connect. Existing direct sessions persist until the daemon is stopped. Revoking a Cloud token does not automatically revoke a separately configured QUIC certificate; perform both operations when both paths must be revoked.

The maximum accepted patch is 128 MiB. A truncated patch or one exceeding that limit is rejected rather than saved as a complete result.

Distributed DAGs, automatic placement, per-executor quotas, scoped workload delegation and frozen owner approvals are described in [node-workflows.md](node-workflows.md). That guide also defines the durable dispatch commitment point, uncertain cancellation and the separate outbound/workflow maintenance fences.

## Optional job metadata notifications

Job IDs and outcomes normally remain inside encrypted application messages. A
node administrator can explicitly allow the node to disclose opaque terminal
job IDs and states to its configured Lockyard broker by adding this top-level
field to its private node TOML and restarting the node:

```toml
metadata_notifications = true
```

The default is `false`; the option requires both an executor and relay. Only
locally verified, signed terminal outcomes completed while the option is active
are eligible. The metadata report contains the job ID, terminal state and the
node's current registration certificate fingerprint. It contains no code,
prompt, logs, result manifest, configuration or workspace key. Cloud records it
as an authenticated node report, and workspace owners separately approve
webhook destinations and outcome kinds. Application RPCs remain end-to-end
encrypted. Setting the option to `false` and restarting stops sending, discards
pending sends, and fences jobs completed while disabled.
Completion timestamps have millisecond precision; a result completed in the
same millisecond as opt-in is omitted because its ordering cannot be established.

The private metadata outbox holds at most 2,000 entries, retries queued outcomes
for up to 24 hours, and keeps unresolved duplicate tombstones for up to seven days. A
per-job durable marker prevents announcing the same retained result again after
that tombstone expires; delivered entries release capacity as soon as that
marker is durable. `node status` reports pending, dropped (queue full),
expired and capture-failure counts. Dropped and expired outcomes require operator
attention; the channel is not a guarantee of eventual delivery during prolonged
outages or saturation. The cloud feed retains at most 2,000 events per workspace and rolls out old
history that has no pending webhook delivery. It exposes truncation and eviction
indicators. If pending webhooks pin all slots, or the cloud's separate bounded
deduplication capacity is exhausted, retries can expire even when the network is
healthy. A storage failure during content expiry can prevent
metadata capture; content is still purged on schedule, the running node records a
capture-failure count, and the outcome cannot be reconstructed by this channel.
The capture-failure count is process-local if the outbox itself is unwritable.
This mechanism never retries job execution.
