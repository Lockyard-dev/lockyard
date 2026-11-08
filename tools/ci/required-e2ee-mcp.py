# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Actual MCP subprocess proof, synthetic local fixture only; no container claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import tempfile
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, required=True)
parser.add_argument("--report", type=Path)
options = parser.parse_args()
ROOT = Path(tempfile.mkdtemp(prefix="ly-mcp-e2ee-"))
BINARY = options.binary.resolve(strict=True)
WORKSPACE = "123e4567-e89b-12d3-a456-426614174000"
results = []


def run_case(name, has_key=True, server_workspace=WORKSPACE, force_workspace=WORKSPACE,
             malformed_discovery=False):
    root = ROOT / name
    root.mkdir(mode=0o700, exist_ok=True)
    project = root / "project"
    (project / ".lockyard").mkdir(mode=0o700, parents=True, exist_ok=True)
    config = root / "config"
    keys = config / "lockyard" / "keys"
    keys.mkdir(mode=0o700, parents=True, exist_ok=True)
    keys.parent.chmod(0o700)
    if has_key:
        key_file = keys / (WORKSPACE + ".key")
        key_file.write_bytes(bytes([83]) * 32)
        key_file.chmod(0o600)
    token = secrets.token_urlsafe(32)
    requests = []
    unexpected_routes = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def answer(self, status, value):
            encoded = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/problem+json"
                             if status >= 400 and "type" in value else "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
            requests.append({"method": "GET", "path": self.path})
            assert self.headers.get("Authorization") == "Bearer " + token
            if self.path == "/api/v1/protocol":
                # EP-10: only a well-formed 404/405 followed by the typed encryption
                # probe establishes legacy protocol 1. Pre-negotiation errors use
                # Problem Details with a matching legacy extension (ERRORS.md).
                if malformed_discovery:
                    self.answer(404, {"error": "unexpected fixture route"})
                else:
                    self.answer(404, {"type": "urn:lockyard:problem:not_found",
                                      "title": "Not Found", "status": 404,
                                      "detail": "Legacy server has no discovery endpoint",
                                      "instance": "urn:lockyard:fixture:discovery",
                                      "code": "not_found", "details": None,
                                      "error": {"code": "not_found", "message": "Not Found",
                                                "details": None}})
            elif self.path == "/api/v1/workspace/encryption":
                self.answer(200, {"workspace_id": server_workspace, "encryption": "off", "key_id": None})
            elif self.path.split("?", 1)[0] == "/api/v1/presence":
                # The production MCP registers its session before the first coordination call.
                # This session is already present, so no unrelated heartbeat write is needed.
                self.answer(200, [{"session": "node-fixture"}])
            else:
                unexpected_routes.append(self.path)
                self.answer(404, {"error": {"code": "not_found", "message": "Unexpected route"}})

        def do_POST(self):
            if self.path != "/api/v1/bus/messages":
                unexpected_routes.append(self.path)
                self.answer(404, {"error": {"code": "not_found", "message": "Unexpected route"}})
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers.get("Authorization") == "Bearer " + token
            private = body.get("body", "")
            requests.append({"method": "POST", "path": self.path,
                             "encrypted": isinstance(private, str) and private.startswith("lyenc1."),
                             "plaintext_absent": "MCP-PRIVATE-SENTINEL" not in json.dumps(body)})
            self.answer(200, {"id": 1, "body": private, "to": "teammate",
                              "from_session": "node-fixture", "created_at": "2026-11-07T00:00:00.000Z"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"
    (project / ".lockyard" / "config.toml").write_text(
        f'mode="cloud"\nurl="{url}"\nworkspace="fixture-label"\n')
    runtime_directory = tempfile.TemporaryDirectory(prefix="ly-mcp-")
    runtime = Path(runtime_directory.name) / "lockyard"
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    legacy = socket.socket(socket.AF_UNIX)
    legacy.bind(str(runtime / "agent.sock"))
    legacy.listen()
    legacy.settimeout(0.05)
    legacy_connections = []
    stop = threading.Event()

    def legacy_fixture():
        while not stop.is_set():
            try:
                connection, _ = legacy.accept()
            except socket.timeout:
                continue
            legacy_connections.append(True)
            connection.close()

    thread = threading.Thread(target=legacy_fixture)
    thread.start()
    env = os.environ.copy()
    for key in ["LOCKYARD_TOKEN", "LOCKYARD_TOKEN_FILE", "LOCKYARD_NODE_CONFIG", "CLAUDE_CODE_SESSION_ID"]:
        env.pop(key, None)
    env.update({"LOCKYARD_URL": url, "LOCKYARD_TOKEN": token, "LOCKYARD_AGENT": "node-fixture",
                "LOCKYARD_REQUIRE_E2EE": "1", "LOCKYARD_E2EE_WORKSPACE_ID": force_workspace,
                "XDG_CONFIG_HOME": str(config), "XDG_RUNTIME_DIR": str(runtime.parent),
                "XDG_STATE_HOME": str(root / "state")})
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "msg_send", "arguments": {"to": "teammate", "body": "MCP-PRIVATE-SENTINEL"}}}
    result = subprocess.run([str(BINARY), "mcp"], input=json.dumps(call) + "\n", text=True,
                            capture_output=True, env=env, cwd=project, timeout=20)
    stop.set()
    thread.join(timeout=1)
    legacy.close()
    runtime_directory.cleanup()
    server.shutdown()
    response = json.loads(result.stdout.splitlines()[-1])
    is_error = response.get("result", {}).get("isError", False) or "error" in response
    posts = [request for request in requests if request["method"] == "POST"]
    expected_success = (has_key and server_workspace == force_workspace == WORKSPACE
                        and not malformed_discovery)
    assert bool(is_error) != expected_success, (name, response)
    assert not unexpected_routes, (name, unexpected_routes)
    if malformed_discovery:
        assert response["result"]["structuredContent"]["code"] == "protocol_response_invalid", response
        assert requests == [{"method": "GET", "path": "/api/v1/protocol"}], requests
    assert not legacy_connections, "forced node context contacted an unverified legacy agent"
    if expected_success:
        assert requests[:2] == [{"method": "GET", "path": "/api/v1/protocol"},
                               {"method": "GET", "path": "/api/v1/workspace/encryption"}], requests
        assert len(posts) == 1 and posts[0]["encrypted"] and posts[0]["plaintext_absent"]
        assert "MCP-PRIVATE-SENTINEL" in json.dumps(response), "local reply was not decrypted"
    else:
        assert not posts, "refused node context transmitted a content write"
    return {"case": name, "passed": True, "http": requests,
            "legacy_agent_connections": len(legacy_connections), "local_reply_decrypted": expected_success}


for name, case_options in [("legacy-off-forced-encrypted", {}), ("missing-key", {"has_key": False}),
                      ("wrong-workspace", {"server_workspace": "different-workspace"}),
                      ("missing-workspace-policy", {"force_workspace": ""}),
                      ("malformed-discovery-refused", {"malformed_discovery": True})]:
    results.append(run_case(name, **case_options))
report = {"binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
          "scope": "actual MCP child + synthetic HTTP fixture; no resource-enforced container or model call", "cases": results}
if options.report:
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(json.dumps(report, indent=2) + "\n")
shutil.rmtree(ROOT)
print(json.dumps(report, indent=2))
