# Publishing

Rust goes first because `lockyard` depends on `lockyard-core`, `lockyard-cloud-client` and, on Unix, `lockyard-node`, then npm, then PyPI. The release workflow builds the five
supported native targets and requires the reusable CI workflow before publishing. CI includes the real-container executor tests on a resource-capable Linux runner. Versions in `Cargo.toml`, `packages/npm/package.json` and `packages/pypi`
stay equal at `0.0.1` until an intentional version change.

```sh
cargo publish --locked -p lockyard-core
cargo publish --locked -p lockyard-cloud-client
cargo publish --locked -p lockyard-node
cargo publish --locked -p lockyard
cp LICENSE README.md packages/npm/
node packages/npm/scripts/build-platform-packages.js <built-binaries-folder>
(cd packages/npm && for package in ./dist/*; do npm publish "$package" --access public; done && npm publish --access public)
cp LICENSE README.md packages/pypi/
(cd packages/pypi && LOCKYARD_BINARY=<built-binary> LOCKYARD_PLATFORM_TAG=<wheel-platform-tag> python3 -m build --wheel)
python3 -m twine upload packages/pypi/dist/*
```

The release workflow runs for tags named `v*`. It needs `CARGO_REGISTRY_TOKEN`, `NPM_TOKEN` and `PYPI_TOKEN` repository
secrets. Each PyPI build sets `LOCKYARD_BINARY` and `LOCKYARD_PLATFORM_TAG` for one platform wheel.

Remote node and job commands currently require Unix. The Windows package continues to provide the existing coordination commands; its MCP node tools return an unsupported-platform error. Native Windows CI builds that package and runs its `about` command.
