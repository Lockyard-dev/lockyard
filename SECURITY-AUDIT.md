# Lockyard security audit — 2026-11-04

Scope: `core` working tree versus `e6e8b68`, plus touched security paths. Contract: `../CONTRACT-device-login.md`.
No push, deploy, or secret access. Fixes below are in the working tree; commits could not be created because `.git` is read-only here.

| Finding · severity | Exploit scenario | Fix commit or open | Residual risk |
|---|---|---|---|
| Setup followed symlinks when writing settings · MEDIUM | A crafted checkout links `.mcp.json` to another writable user file; running `lockyard setup` overwrote that target. | Open — atomic replacement in setup; regression `setup_replaces_a_symlink_without_writing_through_to_its_target`. | Parent-directory symlinks remain subject to the user's filesystem layout. |
| Shared atomic writer used a predictable, truncating temp path · MEDIUM | An attacker able to pre-create `.name.<pid>.tmp` as a symlink could redirect a credential/config replacement to another file. | Open — exclusive `create_new` temp allocation; regression `a_precreated_temporary_symlink_is_never_truncated`. | Same-user local attackers who can modify the destination directory can still deny writes. |
| Edit hook skipped checks for pathless edit events · MEDIUM | A client emitted `MultiEdit` without `file_path`; the hook returned allow while another agent held the edited zone. | Open — deny pathless known edit tools; regression `a_pathless_edit_tool_is_denied_instead_of_skipping_the_zone_check`. | Shell commands and tools outside the recognized edit-hook protocol can write files without this check. |
| Edit hook failed open without config, project root, or session identity · MEDIUM | A malformed project config or event missing `session_id` made the hook return allow while another agent held the target. | Open — deny edits when these inputs are unavailable; regressions cover config, missing identity, and missing root. | Denials require repairing project configuration or restarting the client session. |
| macOS Unicode aliases could name one new file as two zones · MEDIUM | Two agents claimed composed and decomposed spellings of the same not-yet-created filename, then both wrote it on a normalization-insensitive volume. | Open — normalize macOS zone keys with NFD and lowercase; regression `unicode_spellings_of_a_new_file_resolve_to_one_zone`. | Unicode behavior varies by filesystem; Windows and Linux continue using their platform path rules. |
| Device flow opened server-supplied verification links · MEDIUM | A malicious/compromised endpoint returned an attacker URL or redirect query; CLI displayed and opened it with the user code. | Open — restrict link to the chosen server's `/device` page and expected code query; two device-link regressions. | Cloud `/device` page behavior and server implementation were outside this `core` audit. |
| Installer treated same-origin checksum as sufficient authenticity · MEDIUM | An attacker able to replace release assets could replace both archive and `SHA256SUMS`; clients without cosign installed the malicious binary. | Open — cosign now required, identity checked, HTTPS-only redirects, exclusive destination temp; installer regression checks. | Bootstrap shell script authenticity still depends on the HTTPS source the user invokes. |
| GitHub Actions used mutable refs · MEDIUM | A tag/branch owner or compromise could change action code before a release job with publish permissions runs. | Open — CI and release actions pinned to full commit SHAs. | Recheck pins and action advisories before future releases. |
| Cloud authorization controls not verifiable from this checkout · OPEN | A workspace member could attempt an IDOR by changing resource IDs, impersonate an agent name to release its lease, or submit another recipient's receipt; server-side checks decide whether these succeed. | Open — requires review/fixes in cloud server; no server mutation made from `core`. | GitHub OAuth state/PKCE/redirect/cookies, device brute-force and enumeration limits, invite/token roles, receipts, workspace isolation, CSP/XSS/SSRF, and encrypted-body logging also require cloud/site review. |

## Verification

- Passed: `cargo test --offline -p lockyard-core fsio::tests` (5 tests).
- Passed: `cargo test --offline -p lockyard-core paths::tests` (9 tests, including macOS Unicode cases).
- Passed: `cargo test --offline -p lockyard setup::tests` (19 tests).
- Passed: `cargo test --offline -p lockyard-cloud-client device::tests` (18 tests).
- Passed: `cargo test --offline -p lockyard hook::tests` (28 tests).
- Passed: `sh tests/install-sh.test.sh` (21 checks) and `sh tests/check-versions.test.sh` (10 checks).
- Passed: `cargo fmt --all -- --check` and `git diff --check`.
- `cargo test --workspace --offline`: the `lockyard` suite had 149 passes and 2 unrelated failures (`take_mail_is_atomic_across_two_hundred_concurrent_rounds` under contention; process signaling denied by the sandbox in `recovery_resumes_a_group_only_when_its_start_time_matches`); Cargo stopped before the other workspace crates. Targeted changed-path tests passed.
- `cargo deny check --all-features` unavailable: `cargo-deny` is not installed. `pnpm audit --prod` unavailable without a `pnpm-lock.yaml`; no .NET project exists here.
