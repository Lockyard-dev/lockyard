# Publishing

Rust goes first because `lockyard` depends on `lockyard-core` and `lockyard-cloud-client`, then the GitHub release
with the binaries, then npm, then PyPI. The release workflow builds the five supported native targets before
publishing anything. The version in `Cargo.toml`, `packages/npm/package.json`, `packages/pypi/pyproject.toml` and
`server.json` must be the same as the tag, and `CHANGELOG.md` must already have a section for it: the `versions` job
checks all five and stops the release before a single artifact is built.

## What the release workflow does

The workflow runs for tags named `v*` and only for them. In order:

1. `versions` — tag, manifests and changelog agree.
2. `build` — one job per target, each one running the binary it just built.
3. `publish-release` — packs `lockyard-<target>.tar.gz` (a `.zip` for Windows), writes `SHA256SUMS`, attaches a
   CycloneDX SBOM, signs every asset with Sigstore cosign (keyless via GitHub OIDC), runs the installer's own test
   suite against those files, and creates the GitHub release with the archives, checksums, signatures, SBOM and
   `install.sh`. The one-line installer reads this release, so it is published before the registries.
4. `publish-crates`, then `publish-npm` (with `--provenance` / Trusted Publishing OIDC), then `publish-pypi`
   (Trusted Publishing OIDC — configure the GitHub environment on PyPI; no long-lived token).

Secrets: `CARGO_REGISTRY_TOKEN`. npm and PyPI use OIDC Trusted Publishing; configure the repository on each
registry before the first release.

## By hand

```sh
cargo publish -p lockyard-core
cargo publish -p lockyard-cloud-client
cargo publish -p lockyard
cp LICENSE README.md packages/npm/
node packages/npm/scripts/build-platform-packages.js <built-binaries-folder>
(cd packages/npm && for package in ./dist/*; do npm publish "$package" --access public; done && npm publish --access public)
cp LICENSE README.md packages/pypi/
(cd packages/pypi && LOCKYARD_BINARY=<built-binary> LOCKYARD_PLATFORM_TAG=<wheel-platform-tag> python3 -m build --wheel)
python3 -m twine upload packages/pypi/dist/*
```

Each PyPI build sets `LOCKYARD_BINARY` and `LOCKYARD_PLATFORM_TAG` for one platform wheel.

## MCP registries

`server.json` is the entry for the official MCP registry and `glama.json` the one for Glama. Both are at the root of
the repository, which is where those registries look.

The official registry authenticates a `io.github.<owner>/<name>` entry against the GitHub account that owns the
repository, so publishing is done from a machine signed in as `lockyard-dev`:

```sh
mcp-publisher login github
mcp-publisher publish
```

`server.json` names both the npm and the PyPI package, each launched as `lockyard mcp`. Its `version` is part of the
`versions` check, so the registry entry cannot quietly fall behind a release. Glama reads `glama.json` from the
default branch; it has no publish step.
