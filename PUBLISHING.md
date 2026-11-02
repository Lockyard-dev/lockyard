# Publishing

Rust goes first because `lockyard` depends on `lockyard-core`, then npm, then PyPI. The release workflow builds the five
supported native targets before publishing. Versions in `Cargo.toml`, `packages/npm/package.json` and `packages/pypi`
stay equal at `0.0.1` until an intentional version change.

```sh
cargo publish -p lockyard-core
cargo publish -p lockyard
cp LICENSE README.md packages/npm/
node packages/npm/scripts/build-platform-packages.js <built-binaries-folder>
(cd packages/npm && for package in ./dist/*; do npm publish "$package" --access public; done && npm publish --access public)
cp LICENSE README.md packages/pypi/
(cd packages/pypi && LOCKYARD_BINARY=<built-binary> LOCKYARD_PLATFORM_TAG=<wheel-platform-tag> python3 -m build --wheel)
python3 -m twine upload packages/pypi/dist/*
```

The release workflow runs for tags named `v*`. It needs `CARGO_REGISTRY_TOKEN`, `NPM_TOKEN` and `PYPI_TOKEN` repository
secrets. Each PyPI build sets `LOCKYARD_BINARY` and `LOCKYARD_PLATFORM_TAG` for one platform wheel.
