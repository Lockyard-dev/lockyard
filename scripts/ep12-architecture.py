#!/usr/bin/env python3
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Check compatibility dependency direction and structural duplicate paths."""
import argparse
import importlib.util
import re
import sys
import tomllib
from pathlib import Path

spec = importlib.util.spec_from_file_location("ep12_scan", Path(__file__).with_name("ep12-production-scan.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def architecture(repo):
    failures = []
    source_files = scan.sources(repo)
    for path, tree in source_files:
        relative = path.relative_to(repo).as_posix()
        if relative in scan.ALLOWLIST:
            # The compatibility crate contains adapters, never business handlers.
            for node in scan.production_nodes(tree.root_node):
                if node.type == "impl_item" and node.child_by_field_name("trait"):
                    failures.append(f"{relative}:{node.start_point.row + 1}: compatibility cannot implement a domain trait")
            continue
        domain = relative.startswith(("crates/lockyard-core/src/", "crates/lockyard-node/src/"))
        for node in scan.production_nodes(tree.root_node):
            if domain and node.type in {"use_declaration", "extern_crate_declaration", "scoped_identifier", "scoped_type_identifier"}:
                if re.search(r"\b(lockyard_compat|legacy_v1|LegacyCompatibilityV1|OwnerDecisionV1Reader)\b", node.text.decode()):
                    failures.append(f"{relative}:{node.start_point.row + 1}: domain depends on a compatibility boundary")
            if domain and node.type == "struct_item" and node.child_by_field_name("name").text.decode() in {"Claim", "QueueEntry", "Presence"}:
                if re.search(r'alias\s*=\s*"agent"|serialize\s*=\s*"agent"', node.text.decode()):
                    failures.append(f"{relative}:{node.start_point.row + 1}: session alias belongs in the wire codec")
            if node.type not in {"function_item", "function_signature_item"}:
                continue
            name = node.child_by_field_name("name").text.decode()
            signature = node.text[:node.child_by_field_name("body").start_byte - node.start_byte].decode() if node.child_by_field_name("body") else node.text.decode()
            literals = [child.text.decode() for child in scan.walk(node) if child.type in {"string_literal", "raw_string_literal"}]
            identifiers = {child.text.decode() for child in scan.walk(node) if child.type in {"identifier", "field_identifier"}}
            # Detect a renamed numeric normalizer, rather than relying on a blacklist name.
            numeric_reader = bool(identifiers & {"as_i64", "as_u64"})
            strips_prefix = bool(identifiers & {"rsplit", "rsplit_once", "trim_start_matches", "strip_prefix"})
            numeric_parse = "parse" in identifiers and bool(re.search(r"\b[ui](?:32|64|size)\b", node.text.decode()))
            constructs_id = any(child.type == "macro_invocation" and re.search(r'format!\s*\(\s*"(?:D|BT)-', child.text.decode()) for child in scan.walk(node))
            string_input = "&str" in signature or "Value" in signature
            if string_input and ((numeric_reader and constructs_id) or (numeric_parse and ("task" in name and strips_prefix or bool(identifiers & {"rsplit", "rsplit_once"}) and "->" in signature and "i64" in signature))):
                failures.append(f"{relative}:{node.start_point.row + 1}: numeric task conversion outside the one adapter")
            legacy_aad_call = any(child.type == "call_expression" and child.child_by_field_name("function") is not None and "decrypt" in child.child_by_field_name("function").text.decode() and '"value"' in child.child_by_field_name("arguments").text.decode() for child in scan.walk(node))
            decrypt_calls = [child for child in scan.walk(node) if child.type == "call_expression" and child.child_by_field_name("function") is not None and "decrypt" in child.child_by_field_name("function").text.decode()]
            if "or_else" in identifiers and (legacy_aad_call or "decrypt" in name and len(decrypt_calls) >= 2):
                failures.append(f"{relative}:{node.start_point.row + 1}: owner AAD fallback outside the historical reader")
            if '"X-Registry-Session"' in literals:
                failures.append(f"{relative}:{node.start_point.row + 1}: session alias outside the one adapter")
            # General bare/wrapped fallbacks are a second policy even when renamed.
            if "Value" in signature and "DeserializeOwned" in signature and "get" in identifiers and ("clone" in identifiers or "cloned" in identifiers):
                failures.append(f"{relative}:{node.start_point.row + 1}: generic legacy response shape decoder outside adapter")
    for manifest in (repo / "crates").glob("*/Cargo.toml"):
        if manifest.parent.name not in {"lockyard-core", "lockyard-node"}:
            continue
        data = tomllib.loads(manifest.read_text())
        for kind in ("dependencies", "build-dependencies"):
            dependencies = data.get(kind, {})
            if "lockyard-compat" in dependencies or any(isinstance(value, dict) and value.get("package") == "lockyard-compat" for value in dependencies.values()):
                failures.append(f"{manifest.relative_to(repo)}: domain dependency on lockyard-compat")
    registry = repo / "crates/lockyard/src/mcp/registry.rs"
    if registry.exists():
        text = registry.read_text()
        if not re.search(r"\bstruct\s+ToolRegistry\b", text):
            failures.append("crates/lockyard/src/mcp/registry.rs: missing single ToolRegistry")
        declarations = [node for path, tree in source_files if path == registry for node in scan.production_nodes(tree.root_node)]
        for node in declarations:
            if node.type == "match_arm" and "Surface::Compact" in node.text.decode():
                if any(child.type in {"call_expression", "macro_invocation"} for child in scan.walk(node)):
                    failures.append(f"crates/lockyard/src/mcp/registry.rs:{node.start_point.row + 1}: compact reconstructs definitions")
    return sorted(set(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    try:
        failures = architecture(args.repo.resolve())
    except (ValueError, OSError, tomllib.TOMLDecodeError) as error:
        print(error, file=sys.stderr)
        return 2
    for failure in failures:
        print(failure)
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
