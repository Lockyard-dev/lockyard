# Container execution on a remote node

Managed `git_push`, `publish` and `deploy` profiles additionally require [offline owner authorization](node-owner-approvals.md). Compute profiles retain all-member dispatch; trusted administrators must classify profiles and scope credentials.

The node executes only locally configured runner profiles. Every job runs in a Docker or Podman
container; a missing runtime or image fails the job. There is no host execution fallback. Install an
image containing the selected program and Git before enabling a profile. Images are never pulled by
the executor. A Codex image also needs Codex, Lockyard, and its explicitly configured model credential.
The runtime must advertise memory, CPU, and PID controls; unavailable controls fail closed with
`container_limits_unavailable`. Images declaring Docker volumes are rejected so image defaults cannot
add writable mounts. Image health checks are disabled.

The execution part of a node configuration has this shape (paths and image are examples):

```json
{
  "node_id": "build-server",
  "state_dir": "/srv/lockyard/node-state",
  "provenance": {
    "workspace": "ACTUAL_WORKSPACE_ID",
    "key_file": "/srv/lockyard/result-signing.pk8",
    "public_key": "REPLACE_WITH_PINNED_64_HEX_PUBLIC_KEY"
  },
  "repositories": {
    "application": {
      "checkout": "/srv/checkouts/application",
      "retention": {"content_ttl_seconds": 604800},
      "cloud": {
        "url": "https://lockyard.example.com",
        "workspace": "team",
        "repository": "application",
        "token_file": "/srv/lockyard/credentials/team-token"
      }
    }
  },
  "runners": {
    "python": {
      "container": {
        "runtime": "docker",
        "runtime_program": "/usr/bin/docker",
        "image": "your-registry/executor@sha256:REPLACE_WITH_IMAGE_DIGEST",
        "supply_chain": {
          "attestation_file": "/srv/lockyard/policy/image-attestation.json",
          "sbom_file": "/srv/lockyard/policy/sbom.json",
          "vulnerability_report_file": "/srv/lockyard/policy/vulnerabilities.json",
          "trusted_signers": [{"public_key": "REPLACE_WITH_TRUSTED_ATTESTER_64_HEX_PUBLIC_KEY"}],
          "max_attestation_age_seconds": 86400,
          "max_report_age_seconds": 86400,
          "max_database_age_seconds": 86400,
          "max_critical": 0,
          "max_high": 0,
          "max_medium": 20,
          "max_low": 100,
          "max_unknown": 0,
          "denied_vulnerability_ids": []
        },
        "git_program": "/usr/bin/git",
        "memory_mb": 512,
        "cpu_millis": 1000,
        "pids_limit": 128,
        "network": "none"
      },
      "program": "/usr/bin/python3",
      "kind": "command",
      "fixed_args": ["-c"],
      "env_passthrough": []
    }
  },
  "limits": {
    "max_concurrency": 2,
    "max_pending_jobs": 128,
    "max_timeout_seconds": 1800,
    "max_log_bytes": 8388608,
    "max_patch_bytes": 8388608
  }
}
```

Signing identity and image admission policy are mandatory for executable profiles. Replace the example digest/key placeholders with actual immutable image identity and independently trusted public keys. The workspace in `provenance` must equal the node workspace ID. Keep the private signing key outside every checkout and job mount. See [node-provenance.md](node-provenance.md) for evidence/signature contracts and result verification.

`runtime` is `docker` or `podman`; `network` is `none` or `bridge`. Runtime flags, image, mounts,
resource limits, and the executable are operator configuration. RPC callers select a repository ID,
runner ID, locally available Git revision, argument array, optional prompt, timeout, and stable ULID.
Arguments and prompts become individual argv entries. A shell runs only when a profile explicitly
chooses a shell executable. All authenticated workspace participants may submit work; a caller can
cancel its own jobs. Resolving an unknown execution requires a local operator.

Each job receives an independent private bare repository copied from the configured local checkout
without hard links, then a detached worktree at the commit resolved when submission was accepted.
The main container mounts that worktree and private Git metadata as writable. Patch helpers mount
the worktree read-only and private metadata writable. Runtime identity maps to the daemon user on
rootful runtimes and container root on a same-user rootless runtime, preserving private-file access
without adding capabilities. It receives a read-only
root filesystem, a small temporary filesystem, no Linux capabilities, no new privileges, and limits
on memory, CPU, and process count. It receives no host home, config directory, Docker socket, source
checkout, or source object directory. The original checkout's dirty files and refs remain untouched.
Execution hosts and their administrators remain trusted; containers do not hide workspace content
from their host administrator.

Cloud endpoint metadata is written inside the private worktree's `.lockyard/config.toml`.
An existing file is never overwritten: an exact match remains project-owned; conflicting content
fails setup with `worktree_cloud_config_conflict`. Only a newly injected config path and its trusted
blob identity are recorded in the private injection manifest. Before excluding it, a credential-free
helper verifies its content and regular-file type. Changed/deleted injected files produce an explicit
incomplete patch; other tracked and new `.lockyard` project files remain in the Git result.
`LOCKYARD_AGENT` is derived from the configured node ID and job ULID. A configured private token file
is read by the daemon and passed to the container as `LOCKYARD_TOKEN` through an environment name,
never through a command-line value or host credential mount. Environment variables reach containers
only through the configured `env_passthrough` list and this scoped Cloud context. The job and model
can read credentials needed for their work. Known forwarded credential values are redacted from logs.
Cloud-enabled jobs also require the workspace key already imported by the node host. The executor
copies it to a fresh private per-job key directory and mounts only that copy read-only at
`/run/lockyard-config`, with `XDG_CONFIG_HOME` fixed to that path. The key uses the actual node
workspace ID, independently of the repository configuration label. No original host keystore is
mounted, and patch helpers receive neither the copy nor credentials. A confirmed stopped job removes
the copy before patch collection; unknown execution retains it until explicit operator reconciliation.
`XDG_CONFIG_HOME` cannot be supplied through runner passthrough. Every job launched by a key-bearing node host receives
`LOCKYARD_REQUIRE_E2EE=1` and `LOCKYARD_E2EE_WORKSPACE_ID` fixed to the actual node workspace.
These variables cannot be overridden by passthrough. A job without explicit Cloud configuration
receives no key copy, so a packaged MCP client using an incidental project configuration fails closed
on a missing key. Configure the scoped Cloud context to enable coordination. The Cloud client requires verified workspace
metadata and the imported key, binds resolved workspace IDs, encrypts despite a legacy setting being
off, and refuses unverifiable metadata or plaintext coordination content.
Before patch serialization, the executor scans raw changed paths, old/new index blobs, and unfiltered
changed file bytes inside containers. Known credentials and unverifiable entries refuse the patch;
Git binary encoding cannot bypass this raw-content check. A final streamed scan also refuses a
serialized patch containing a literal known credential; patch bytes are never redacted or rewritten. Arbitrary secrets created or transformed by
job code still require review before sharing. This check does not prevent a malicious authorized job
from encoding or exfiltrating its necessary credential.

For Codex, set `kind` to `codex`, `program` to its path inside the image, `fixed_args` to
`["exec", "--json", "--sandbox", "workspace-write"]`, and `mcp_program` to Lockyard's path inside the
image. The executor adds per-invocation MCP configuration and forwards the names `LOCKYARD_AGENT`,
`LOCKYARD_URL`, `LOCKYARD_TOKEN_FILE`, `LOCKYARD_TOKEN`, `XDG_CONFIG_HOME`,
`LOCKYARD_REQUIRE_E2EE`, and `LOCKYARD_E2EE_WORKSPACE_ID`. It adds an argv terminator before the prompt.
It never edits the operator's Codex configuration. Configure bridge networking and an explicit model
credential allowlist if that image needs an Internet model provider. Ordinary `agent` profiles receive
the same literal arguments and scoped environment without Codex-specific flags.

The private journal is fsynced before launch. Retrying the same job ID and identical specification
returns the recorded job. Reusing an ID for different work is a conflict. One process exclusively
locks a state directory. Queued jobs can continue after restart; jobs that were starting or running
become `interrupted_unknown`. They block new starts until an operator reviews surviving containers
and explicitly resolves the unknown result. Historical PID numbers are never killed or replayed.
Cancel and timeout kill the named container, which stops its process namespace; failure to confirm
that stop produces an unknown result. Containers are retained until explicit non-force removal or
inspection establishes that they stopped; automatic `--rm` cannot erase the evidence first. This rule
also applies to patch helpers. Ambiguous errors or unsettled creation remain unknown. Pre-journal
directories containing only an optional torn first temporary journal are quarantined so submission
can be retried. Corrupt committed journals or unexplained execution artifacts still fail startup.

Logs are spooled to a capped file while excess output is drained. Completed jobs also expose a
bounded binary Git patch, including new files allowed by Gitignore and excluding only injected files.
Patch generation runs in fresh containers with no job credentials and uses a separate Git index.
It has a 30-second aggregate budget and honors cancellation; bounded stop confirmation can add
cleanup time. Credential scanning permits 1 MiB of changed-entry metadata, 1024 combined path/object
entries, and the configured patch limit in raw scanned bytes. Unreadable/out-of-container symlink
targets and unsupported entries fail closed. The configured patch maximum is 128 MiB, matching the
client download contract. Large/compressed changes can exceed a raw scan bound before the patch size
bound and then report an explicit patch error.
The response reports truncation and artifact errors. A truncated patch is incomplete. Read, write,
synchronization, or stream-thread failures mark logs incomplete with `log_error` and refuse incomplete
patches. Excess pipe data continues to drain after spool write failure. Successful commands with
incomplete results are recorded as failed rather than complete successes.
Logs and patches are downloaded in chunks of at most 32 KiB so their encrypted JSON envelopes fit the transport frame limit. Nothing applies a patch or pushes a ref.
Retained worktrees and artifacts require operator retention and cleanup.

The meaningful execution tests require a preinstalled fixture image with `/usr/bin/python3` and
`/usr/bin/git` and permission to use the local Docker socket:

```sh
LOCKYARD_NODE_EXECUTOR_RUNTIME=/usr/bin/docker \
LOCKYARD_NODE_EXECUTOR_IMAGE=lockyard-executor-fixture:local \
  cargo test -p lockyard-node --test executor -- --include-ignored --test-threads=1
```

The container integration cases are explicitly ignored in the default test run; `--include-ignored`
requires the image variable and a resource-capable runtime. `LOCKYARD_NODE_EXECUTOR_RUNTIME` selects
the test runtime path; otherwise tests find Docker on `PATH`. Configuration and authority checks
still run by default. The suite includes a real daemon-process crash, private Git isolation, literal
argument handling, duplicate submission, bounded logs, timeout, cancellation, and Codex MCP argv
construction. A resource-capable case inspects the actual running container and effective cgroup
memory/CPU/PID settings, verifies private mounts and hardening, then exercises bounded process and
memory attempts against the configured limits. It permits at most 32 child processes or 256 MiB of
touched memory even if the runtime is broken. CPU enforcement is checked through the effective
quota rather than timing. These cases make no model calls. Merely compiling the tests or passing
the unavailable-resource rejection case does not establish successful resource-enforced execution.
