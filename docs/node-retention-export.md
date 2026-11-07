# Project content retention and explicit encrypted export

This is an unpublished node protocol extension. Upgrade the client, executor and broker together before enabling remote jobs. Normal legacy `node.ping` remains compatible; mutation frames require authenticated retention and certificate-incarnation metadata and fail closed when it is absent. No automatic backup or automatic archive import is provided.

Every executor repository and every dispatch-only project requires an explicit `content_ttl_seconds` policy. There is no global default. Supported values are 60 seconds through 365 days; choose a value appropriate for the project rather than copying the example blindly:

```toml
[project_retention.example]
content_ttl_seconds = 604800

[executor.repositories.example.retention]
content_ttl_seconds = 604800
```

The executor snapshots the smaller sender and receiver policy at first admission. A confirmed terminal job starts one immutable artifact deadline; subsequent reads, signing, retries, restart and export never extend it. Private execution copies of code and Git metadata, prompts, arguments, logs, patches and locally generated exports are removed after this deadline. The user’s original checkout is not managed or removed by this job policy. A maintenance sweep runs at startup and every 30 seconds; content reads fail at the deadline even before the next sweep. Filesystem errors surface as unhealthy retention cleanup and block new admission until a successful sweep.

Queued, starting, running and `interrupted_unknown` jobs are preserved. An unknown execution must be reconciled locally before its content can expire. This prevents a cleanup action from erasing the evidence needed to distinguish execution from an uncertain delivery. Per-job artifact locks prevent a sweep from deleting files while provenance signing, export or a read is in progress.

A submit frame has a separate immutable delivery deadline. Before receiver admission, only the explicitly selected sender policy is known; the receiver's shorter artifact policy cannot be promised for a copy that has not reached it. The broker also imposes its stricter 24-hour delivery cap. A delivery deadline does not cancel work already authorized and running. Status, log, patch and archive responses get a new per-copy deadline, clamped to the admitted policy and terminal artifact deadline. Local relay queues and response caches logically erase their ciphertext bodies at expiry while retaining only the minimum routing and conflict evidence. An identical known job ID is reconciled through pinned status; it does not create a new prompt copy or a fresh mutating delivery deadline.

Before private job files are erased, the executor durably publishes an immutable tombstone containing the job ID, submitter incarnation, typed request digest, final state, expiry and erasure time, and any existing signed hash statement. This evidence contains no prompt, command arguments, code, log or patch body and prevents a purged job ID from executing again. The tombstone timestamp records the erasure commitment. Separate durable completion evidence is published only after private files and exports have been removed and their directories synced; an expired status response distinguishes committed/pending from completed erasure without returning project content. Source-name reuse does not inherit an older certificate's submit/cancel authority. Origin relay write correlation has a bounded 100,000-entry durable history budget; admission stops when this budget is exhausted, rather than dropping non-replay evidence.

Erasure means logical filesystem removal. It does not guarantee physical secure erasure on snapshots, SSDs or storage replicas and cannot remove copies already received by trusted workspace members. The cloud receives ciphertext and authenticated routing/expiry metadata, never the workspace key or plaintext project content.

## Explicit export and offline restore

A confirmed terminal job with durably signed result provenance can be exported on demand:

```sh
lockyard job archive worker JOB_ULID --output /private/review/job.lyarchive --config /private/node.toml
lockyard job restore-archive worker --archive /private/review/job.lyarchive --output /private/review/restored --config /private/node.toml
```

Pin the worker's result-signing public key in `result_trust.worker` independently before downloading or restoring. Restore verifies this exact node identity and the signature over every exported path, byte length and SHA-256 digest, in addition to workspace-bound AEAD authentication, record ordering, completion and EOF. A workspace key alone cannot forge a different node's archive signature. The workspace key must be available locally. To restore an old archive after an explicitly authorized retain-history rotation, pass `--key-file /private/history/old-workspace.key`; this reads a private key file locally and never installs it as the active key. A discard-history policy intentionally makes old ciphertext unavailable unless another authorized copy already exists.

The signed manifest declares `full_project` or `results_only`. Jobs admitted without runtime credential injection can include the job record, logs, patch, worktree files and private Git data. A job using profile secrets, environment passthrough or project cloud context is permanently restricted to `results_only`: sanitized signed result/retention metadata, log and patch, with no raw journal, prompt, worktree or private Git. Legacy records default to this restriction. The CLI reports the authenticated scope rather than claiming a full backup. Injected runtime keys, runtime secrets, daemon configuration and signing keys are always excluded. This reduces accidental credential copies; it is not a guarantee against a malicious workload encoding secrets into allowed output. Archives are streamed in bounded encrypted records; filenames and the manifest are encrypted. Limits are 4,096 files, 128 MiB per file, 512 MiB total plaintext and 1 GiB downloaded encrypted archive. Symlinks, hardlinks, special files, duplicate paths, absolute paths and traversal are rejected. Concurrent source changes abort the export. Existing output files are never overwritten.

The executor publishes a completed archive cache only after writing and syncing the complete encrypted stream. At startup it discards recognized cached exports and interrupted export temporaries, including caches from older versions; a download interrupted by restart must begin again at offset zero. Previously downloaded user-controlled copies are unaffected.

The job restore command requires the archive's `export-metadata.json`, verifies its independently signed result for the pinned node, workspace and job, and compares each included top-level log or patch to that result's signed hash, length and completeness flags. A previous job archive with missing, invalid or inconsistent result metadata is rejected; restore does not treat a separately signed archive manifest as proof of consistency with an earlier signed result. The report's `result_provenance_verified` field distinguishes that check from archive integrity. The generic archive library can restore archives without job metadata and reports this field as false; recognizable job metadata is checked when present. Job metadata is bounded to 128 KiB. The generic library permits a larger file at the same name as ordinary archive content and makes no result provenance claim for it.

Restore creates only a fresh private directory with non-executable files under `files/`. Its immediate parent must be owned by the invoking user and private from group and other users. Restore currently supports Linux only: it retains an open parent directory descriptor and uses it for output and cleanup even if an ancestor is renamed, and requires `/proc/self/fd`. Other platforms fail closed until equivalent descriptor-anchored traversal is implemented and tested. Restore verifies the full archive before success, removes its partial destination on verification failure, and does not import an executor journal, schedule work, run Git hooks, apply a patch, publish or push anything. The downloaded archive is a user-requested copy outside daemon retention; the user controls its later deletion.

## Local drain

```sh
lockyard node drain --config /private/node.toml
lockyard node drain-status --config /private/node.toml
lockyard node resume --config /private/node.toml
```

Drain state is durable. It gates new job IDs under the admission lock while preserving existing-ID reconciliation and allowing queued/running work to finish. Only the private local operator control socket exposes it. Rotation also requires a stopped/drained boundary and rejects active or unknown work; remote workload RPCs cannot grant local-operator authority.

Validation uses synthetic private journal/crypto/path fixtures and real local transport regression tests. These prove the covered invariants, not resource-enforced container execution: the managed runtime still lacks CPU/RAM/PID enforcement, so the positive production execution gate remains open.

Downloads require an output directory owned by the invoking user and without group/world write permission. For a shared location such as `/tmp`, create an owned mode0700 subdirectory first. Patch/archive downloads retain one exclusive no-follow file descriptor through streaming and verification, publish without replacing an existing destination, and never reopen a writable temporary by pathname.

Expired terminal jobs retain a minimal, separately signed terminal receipt for dispatch reconciliation. It binds the target node and workspace, original request digest, submitting node and certificate, terminal state, and completion time. It carries no logs, patch, prompt, or claim that artifacts remain available. The receipt can release the outbound maintenance fence, but an expired status remains an error and cannot release workflow dependencies. Content deletion does not wait for receipt signing; if signing or receipt storage fails, the private immutable tombstone permits a later signing attempt. Until a valid receipt is available, the dispatch remains unresolved.

A legacy tombstone with a valid signed result can also settle the dispatch. An older unsigned tombstone with no recorded completion time first uses the automatic evidence reconciliation below. Unresolved evidence, or a legacy outbound dispatch without the original request digest/source certificate, still requires explicit operator reconciliation; it never justifies re-executing a job or recovering expired content.

Content reads are refused at the retention deadline. Logical deletion runs on startup and during the next available maintenance pass (normally every 30 seconds); it is not an exact wall-clock erasure guarantee while the daemon or storage is unavailable. This process cannot erase previously downloaded copies, backups, filesystem snapshots, or physical storage remnants.


Legacy tombstones without `completed_at_ms` are reconciled before content cleanup. A verified retained
signed result (pinned node/workspace/job/request/outcome) or the matching private node journal supplies
the completion time. Conflicting, corrupt or absent evidence produces `status: needs_review` and the
durable `tombstone_reconciliation_required` diagnostic; surviving content is preserved. An immutable
tombstone and its existing purge hash are never rewritten: a bounded private `.reconciliation` sidecar
binds the recovered timestamp to the tombstone digest. Receipt generation uses that recovered time.
The current broker stores metadata notifications, not signed manifests; it cannot yet supply a missing
signed result. This release verifies retained signed results and does not invent a cloud retrieval API.
