<!-- Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0. -->

# Security

## Reporting a vulnerability

Please report security issues privately to **hello@lockyard.dev**. Do not open a public GitHub
issue for a vulnerability that could be used against people who already run Lockyard.

Include the affected version (or commit), what you observed, and a minimal way to reproduce it when
you can. We aim to acknowledge within a few business days and to ship a fix or a clear mitigation
before any public write-up.

## What Lockyard protects

- In local mode, a cooperating agent that goes through the edit hook cannot write a path another
  agent holds.
- In cloud mode, the same check runs against a local mirror of the server's zone state; a stale or
  missing mirror refuses the edit (fail closed). See [docs/threat-model.md](docs/threat-model.md).

## What Lockyard does not protect

- Agent names are not authenticated. An agent can claim to be another one.
- Writes that never ask the hook (`sed -i`, an editor, a build script) are not refused. The monitor
  can notice them and mail the holder; that is detection, not prevention.
- Local mode stores everything under `.lockyard/` on disk. Anyone with that filesystem can read it.

## Supply chain

Release archives are published with `SHA256SUMS` and Sigstore cosign signatures (keyless, GitHub
OIDC). `install.sh` checks the checksum always, and the signature when `cosign` is on `PATH`. npm
publishes with provenance; PyPI uses Trusted Publishing. CI runs `cargo deny` for licenses and
advisories.
