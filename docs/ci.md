# Continuous integration

Pull requests and pushes to `main` or `dev` run the Rust checks, package launcher tests and a native Windows build. Cargo checks use the committed lockfile. The release workflow calls the same CI workflow and waits for it before publishing crates.

Linux CI also runs `tools/ci/required-e2ee-mcp.py` against the actual built MCP executable. Isolated synthetic fixtures verify that a node's required-encryption context cannot silently use plaintext when legacy workspace encryption is off, the local key is missing, or workspace policy cannot be verified.

The `node-containers` job uses a local Docker socket on a Linux runner. It first requires memory, CPU quota and PID limit support. It then builds the disposable Git/Python fixture in `tools/ci/node-executor.Dockerfile`, passes its immutable local image ID to the executor tests, and runs every integration case with `--include-ignored --test-threads=1`.

To run the container cases on a suitable local Linux machine:

```sh
docker build -f tools/ci/node-executor.Dockerfile -t lockyard-node-ci:fixture tools/ci
export LOCKYARD_NODE_EXECUTOR_IMAGE="$(docker image inspect lockyard-node-ci:fixture --format '{{.Id}}')"
export LOCKYARD_NODE_EXECUTOR_RUNTIME="$(command -v docker)"
cargo test --locked -p lockyard-node --test executor -- --include-ignored --test-threads=1
```

The live resource test inspects the actual executor container and its effective cgroup limits, verifies private mounts and isolation settings, then exercises bounded memory and process exhaustion. A daemon without the required controls fails the CI preflight. A passing negative test that rejects such a daemon does not establish successful resource-enforced execution.

Node orchestration currently uses Unix control sockets and private-file permission checks. Windows CI preserves the existing coordination CLI; Windows node hosting and dispatch are not supported by this implementation.
