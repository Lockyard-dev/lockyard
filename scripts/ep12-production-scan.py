#!/usr/bin/env python3
# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""AST production inventory for the exact EP-12 grep gate.

Install scripts/requirements-ep12.txt first. Parse failures and an empty Rust
production scope fail closed with exit 2; grep, not this inventory, selects the
contract's forbidden symbol names. The allowlist is an exact repository path.
"""
import argparse
import itertools
import re
import sys
from pathlib import Path

try:
    from tree_sitter import Language, Parser
    import tree_sitter_rust
except ImportError as error:
    raise SystemExit("EP-12 parser unavailable; install scripts/requirements-ep12.txt") from error

ALLOWLIST = frozenset({"crates/lockyard-compat/src/legacy_v1.rs"})
DECLARATIONS = frozenset({
    "function_item", "function_signature_item", "struct_item", "enum_item",
    "union_item", "type_item", "trait_item", "const_item", "static_item",
})
PARSER = Parser(Language(tree_sitter_rust.language()))


def cfg_values(text):
    """Possible cfg values in production: test=false, all other flags unknown."""
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z_0-9]*|[(),=]', text)
    cursor = 0

    def expression():
        nonlocal cursor
        if cursor >= len(tokens):
            raise ValueError("invalid cfg expression")
        name = tokens[cursor]
        cursor += 1
        if cursor < len(tokens) and tokens[cursor] == "=":
            cursor += 2
            return {False, True}
        if cursor >= len(tokens) or tokens[cursor] != "(":
            return {False} if name == "test" else {False, True}
        cursor += 1
        arguments = []
        while cursor < len(tokens) and tokens[cursor] != ")":
            arguments.append(expression())
            if cursor < len(tokens) and tokens[cursor] == ",":
                cursor += 1
            elif cursor < len(tokens) and tokens[cursor] != ")":
                raise ValueError("invalid cfg separator")
        if cursor >= len(tokens):
            raise ValueError("unterminated cfg")
        cursor += 1
        if name == "not" and len(arguments) == 1:
            return {not value for value in arguments[0]}
        if name in {"all", "any"}:
            operation = all if name == "all" else any
            return {operation(values) for values in itertools.product(*arguments)}
        return {False, True}

    return expression()


def test_only(attributes):
    for attribute in attributes:
        match = re.fullmatch(r"#\s*!?\s*\[\s*cfg\s*\((.*)\)\s*\]", attribute.text.decode(), re.S)
        if match and cfg_values(match[1]) == {False}:
            return True
    return False


def production_nodes(node):
    """Retain production siblings when a file also contains cfg(test) items."""
    if test_only([child for child in node.named_children if child.type == "inner_attribute_item"]):
        return
    attributes = []
    for child in node.named_children:
        if child.type in {"line_comment", "block_comment"}:
            continue
        if child.type == "attribute_item":
            attributes.append(child)
            continue
        excluded = test_only(attributes)
        pending_attributes = attributes
        attributes = []
        if excluded:
            continue
        for attribute in pending_attributes:
            if not re.match(r"#\s*!?\s*\[\s*doc\b", attribute.text.decode()):
                yield attribute
                yield from production_nodes(attribute)
        yield child
        yield from production_nodes(child)


def sources(repo):
    paths = sorted((repo / "crates").glob("*/src/**/*.rs"))
    paths = [path for path in paths if not any(
        part in {"tests", "__tests__"} or ".test." in part or ".spec." in part
        for part in path.relative_to(repo).parts
    )]
    if not paths:
        raise ValueError("empty production scope: expected crates/*/src/**/*.rs")
    parsed = {}
    excluded = set()
    module_edges = {}
    for path in paths:
        body = path.read_bytes()
        # Grammar 0.24.2 supports Rust 2024 except explicit safe foreign functions.
        # Mask that keyword only, retaining byte offsets; validate its extern scope.
        safe_keywords = list(re.finditer(rb"\bsafe(?=\s+fn\b)", body))
        normalized = re.sub(rb"\bsafe(?=\s+fn\b)", b"    ", body)
        tree = PARSER.parse(normalized)
        for keyword in safe_keywords:
            ancestor = tree.root_node.descendant_for_byte_range(keyword.start(), keyword.end())
            while ancestor and ancestor.type not in {"foreign_mod_item", "line_comment", "block_comment", "string_literal", "raw_string_literal"}:
                ancestor = ancestor.parent
            if ancestor is None:
                raise ValueError(f"{path.relative_to(repo)}: safe fn outside extern block")
        if tree.root_node.has_error:
            errors = [node for node in walk(tree.root_node) if node.type == "ERROR" or node.is_missing]
            line = errors[0].start_point.row + 1 if errors else 1
            raise ValueError(f"{path.relative_to(repo)}:{line}: Rust parse error")
        parsed[path] = tree
        if test_only([node for node in tree.root_node.named_children if node.type == "inner_attribute_item"]):
            excluded.add(path)
        # Out-of-line #[cfg(test)] modules are not production files, even tests.rs.
        for parent in walk(tree.root_node):
            attributes = []
            for node in parent.named_children:
                if node.type in {"line_comment", "block_comment"}:
                    continue
                if node.type == "attribute_item":
                    attributes.append(node)
                    continue
                if node.type == "mod_item" and node.child_by_field_name("body") is None:
                    name = node.child_by_field_name("name").text.decode()
                    explicit = next((re.search(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]', a.text.decode()) for a in attributes if "path" in a.text.decode()), None)
                    if explicit:
                        targets = {path.parent / explicit[1]}
                    else:
                        directory = path.parent if path.stem in {"lib", "main", "mod"} else path.parent / path.stem
                        targets = {directory / f"{name}.rs", directory / name / "mod.rs"}
                    module_edges.setdefault(path, set()).update(targets)
                    if test_only(attributes):
                        excluded.update(targets)
                attributes = []
    pending = list(excluded)
    while pending:
        for child in module_edges.get(pending.pop(), set()):
            if child not in excluded:
                excluded.add(child)
                pending.append(child)
    return [(path, parsed[path]) for path in paths if path not in excluded]


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def inventory(repo):
    result = []
    for path, tree in sources(repo):
        relative = path.relative_to(repo).as_posix()
        if relative in ALLOWLIST:
            continue
        for node in production_nodes(tree.root_node):
            if node.type in DECLARATIONS:
                name = node.child_by_field_name("name")
                if name:
                    result.append(f"{relative}:{name.start_point.row + 1}: {name.text.decode()}")
            elif node.type in {"string_literal", "raw_string_literal"}:
                if "X-Registry-Session" in node.text.decode():
                    result.append(f"{relative}:{node.start_point.row + 1}: X-Registry-Session")
    return result


def main():
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--repo", type=Path, required=True)
    arguments.add_argument("--out", type=Path, required=True)
    args = arguments.parse_args()
    try:
        lines = inventory(args.repo.resolve())
        args.out.write_text("\n".join(lines) + "\n")
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
