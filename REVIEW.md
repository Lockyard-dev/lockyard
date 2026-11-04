# Core review — 04.11.2026

Baseline: `e484b55`; brief: `../BRIEF-core-2.md` plus inherited lock/setup rules in `../BRIEF-core.md`.

## Completeness

| # | Status | Evidence |
|---|---|---|
| 1 Event mail | Done | Native watcher plus 10 s reconcile: `crates/lockyard-core/src/watch.rs:20-27,71-125`; monitor loop: `crates/lockyard/src/monitor.rs:68-110`. Send→visible measured 334 ms via poll fallback. |
| 2 Cloud mirror | Done | Fresh checks from memory and stale checks use bounded server fallback: `crates/lockyard/src/agent/daemon.rs:429-456`; refresh/fencing: `1117-1137,1273-1295`; guarantee: `docs/cloud-mirror.md:10-36`. |
| 3 Outside edits | Done | Claimed paths are reported, mailed and documented as detection only: `crates/lockyard/src/monitor.rs:199-285`; `README.md:214-218`. |
| 4 Dirty events | Done | Changed paths are grouped and sent to `dirty_report`: `crates/lockyard/src/monitor.rs:225-285`; cloud event tracking: `crates/lockyard/src/agent/daemon.rs:804-852`. |
| 5 Perf CI | Done | No-network p95 checks (80 samples; 15 ms hook / 20 ms send): `crates/lockyard/tests/perf_budget.rs:3-29`; CI job: `.github/workflows/ci.yml:40-47`. Both passed. |
| 6 Supply chain | Done | Release checksums, cosign signatures, CycloneDX, npm provenance and PyPI OIDC: `.github/workflows/release.yml:129-167,219-235`; installer signature enforcement: `install.sh:119-136`; `cargo deny`: `.github/workflows/ci.yml:30-38`. |
| 7 Hardening | Done | Disclosure: `SECURITY.md`; threat/privacy/JSON docs: `docs/threat-model.md`, `docs/privacy.md`, `docs/json-schemas.md`; fsync/rename: `crates/lockyard-core/src/fsio.rs:35-99`. |

## Bugs

| Severity | Finding | Resolution |
|---|---|---|
| Medium | Invalid project config let edit hooks fail open (`crates/lockyard/src/hook.rs:321-326`). | Fixed in working tree; regression at `hook.rs:1480-1510`. |
| Medium | Setup overwrote backup files with default permissions; uninstall did not restore original bytes (`crates/lockyard/src/setup/mod.rs:435-518`). | Fixed in working tree; private/non-clobbering backup and safe restore tests in `setup/tests.rs:107-199`. |
| Medium | Installer accepted unsigned release when cosign was installed (`install.sh:119-134`). | Fixed in working tree; `tests/install-sh.test.sh:124-158`. |
| Medium | README said stale/no-agent cloud hooks allowed edits, contrary to fail-closed code (`README.md:227-235`). | Fixed in working tree; cloud test now asserts denial (`crates/lockyard/tests/cloud.rs:514-526`). |
| Low | A recent hook announcement can mask an unrelated write to the same path for up to five minutes; the trade-off is documented in `crates/lockyard-core/src/outside.rs:26-31,114-119`. | Open. |

## Checks

- `cargo fmt --check` — passed.
- `CARGO_HOME="$PWD/.cargo-home" cargo clippy --all-targets -- -D warnings` — passed.
- `XDG_STATE_HOME="$PWD/.codex-tmp/state" CARGO_HOME="$PWD/.cargo-home" cargo test` — passed: 149 unit, 22 CLI, 13 cloud, 1 e2e, 2 perf, 86 cloud-client, 110 core; doc tests 0.
- `TMPDIR="$PWD/.codex-tmp" sh tests/install-sh.test.sh` — passed, 18 checks.
- `TMPDIR="$PWD/.codex-tmp" sh tests/check-versions.test.sh` — passed, 10 checks.
- `node --test packages/npm/test/*.test.js` — passed, 4 tests. `PYTHONPATH=packages/pypi/src python3 -m unittest discover -s packages/pypi/tests` — passed, 4 run / 1 skipped.
- `git diff --check` — passed. Native FSEvents latency was not measured; the observed monitor backend was `poll`.

## For the lead

Cross-check the cloud server against `../CONTRACT-device-login.md`; it is outside this working copy. Changes remain uncommitted: `git commit` could not create `.git/index.lock` (`Operation not permitted`) because `.git` is read-only in this sandbox. Commit each review fix after moving to a writable Git checkout.
