# Node-side customer secrets

Secret profiles are trusted node-admin configuration. A runner with secret references or environment passthrough must explicitly list its permitted project aliases in `credential_repositories`. The executor checks that scope before reading a value or contacting a provider, and rejects queued work if its admitted runner or repository configuration changed.

Supported sources are a private local file, customer Vault KV v2, and customer Vault Transit unwrap. Vault Transit is the supported customer KMS integration; native AWS/GCP/Azure KMS adapters are not implemented. Vault uses HTTPS with certificate verification, optional customer CA roots, a private node-side token file, no redirects, bounded requests/responses and bounded DNS workers. Customer Vault Agent may replace the token file for renewal. No Vault identity, secret value or workspace key is sent to the Lockyard broker.

Example runner configuration fragment:

```toml
credential_repositories = ["payments"]

[[executor.runners.build.secrets]]
name = "customer_api"
environment = "CUSTOMER_API_TOKEN"
[executor.runners.build.secrets.source]
kind = "local_file"
path = "/srv/customer-secrets/api-token"
```

Use the fragment inside the matching runner table; `credential_repositories` belongs to that runner. Files must be owned by the daemon user, regular, unlinked elsewhere, mode0600, and at most16KiB. Symlinks and FIFOs fail closed. Secret references cannot address node control state, TLS private keys, signing keys or the workspace key store. Source checkouts must not enclose those protected paths or sit inside executor state.

Only the admitted main container receives a read-only `/run/lockyard-secrets` mount. Named values are available as files and, when requested, through a private Docker/Podman environment file. Values are absent from runtime-client argv and environment. Git/export helper containers receive no secret, workspace-key or delegation mount. Runtime directories are removed after a confirmed stop; an uncertain stop retains containment state for explicit reconciliation. The mandatory CPU/RAM/PID capability gate remains in effect.

Exact credential bytes are redacted from logs and checked against raw Git content before patch serialization. Screening runs in the node daemon, so its memory use grows with the number and length of configured credential values and is outside the workload container limits; size the host and concurrency accordingly. Failed/truncated artifacts cannot be downloaded through the verified patch path or the encrypted archive. Credential-bearing job exports contain signed sanitized results only, excluding the worktree, Git objects and raw job journal.

Customer hosts/admins and workspace members are trusted as selected. Arbitrary permitted code with an ordinary network profile can intentionally transform or transmit a granted credential; exact-byte redaction is not a general information-flow or data-loss-prevention guarantee. Use a `none` network profile and least-privilege customer-issued credentials where required. No host execution fallback is provided.
