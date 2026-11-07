# Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
"""Golden production-scope and negative-copy fixtures for both EP-12 gates."""
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


scan = module("ep12_scan", "ep12-production-scan.py")
arch = module("ep12_arch", "ep12-architecture.py")
FORBIDDEN = re.compile(r"\b(task_number|parse_task_id|item_id|registry_id|task_id_for|compact_tools|full_tools|COMPOSITES|LegacyTaskIdV1|OwnerDecisionV1Reader|LegacySessionHeaderV1|LegacyWireShapeV1|BindSessionTokenAsync|BindSessionTokenCoreAsync)\b|X-Registry-Session")


class Gates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lockyard-ep12-")
        self.repo = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def write(self, path, source):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        return target

    def matches(self):
        return [line for line in scan.inventory(self.repo) if FORBIDDEN.search(line)]

    def test_docs_external_inline_tests_and_dto_fields_are_not_production_declarations(self):
        self.write("docs/contracts.rs", "fn task_number() {}")
        self.write("crates/sample/tests/integration.rs", "fn task_number() {}")
        self.write("crates/sample/src/sub/tests/inline.rs", "fn task_number() {}")
        self.write("crates/sample/src/lib.rs", '''
            /// fn registry_id() {}
            // X-Registry-Session
            struct Request { item_id: String }
            fn legitimate() { BindSessionTokenAsync(); }
            #[cfg(test)] mod tests { fn task_number() {} }
            #[cfg(all(test, unix))] fn registry_id() {}
            #[cfg(test)] mod separate;
            fn production() {}
        ''')
        self.write("crates/sample/src/separate.rs", 'fn compact_tools() {} mod nested;')
        self.write("crates/sample/src/separate/nested.rs", 'fn full_tools() {}')
        self.assertEqual(self.matches(), [])

    def test_first_exact_compatibility_path_passes_but_production_copy_fails(self):
        source = 'struct LegacyTaskIdV1; fn item_id() { let header = "X-Registry-Session"; }'
        self.write("crates/lockyard-compat/src/legacy_v1.rs", source)
        self.assertEqual(self.matches(), [])
        self.write("crates/sample/src/legacy_v1.rs", source)
        self.assertEqual(len(self.matches()), 3)
        self.assertTrue(all("crates/sample/src/legacy_v1.rs" in line for line in self.matches()))

    def test_inline_test_does_not_hide_production_sibling_and_cfg_not_test_remains(self):
        self.write("crates/sample/src/lib.rs", '''
            #[cfg(test)] mod tests { fn item_id() {} }
            #[cfg(not(test))] fn registry_id() {}
            fn task_number() {}
        ''')
        self.assertEqual(len(self.matches()), 2)

    def test_production_attribute_literals_are_scanned_but_docs_and_inner_test_cfg_are_not(self):
        self.write("crates/sample/src/lib.rs", '#[doc="X-Registry-Session"] fn docs() {}\n#[custom("X-Registry-Session")] fn header() {}')
        self.write("crates/sample/src/isolated.rs", '#![cfg(test)] fn item_id() {}')
        self.assertEqual(self.matches(), ["crates/sample/src/lib.rs:2: X-Registry-Session"])

    def test_parse_error_and_empty_scope_fail_closed(self):
        with self.assertRaises(ValueError):
            scan.inventory(self.repo)
        self.write("crates/sample/src/lib.rs", "fn broken( {")
        with self.assertRaisesRegex(ValueError, "parse error"):
            scan.inventory(self.repo)

    def test_safe_foreign_functions_keep_source_coordinates(self):
        self.write("crates/sample/src/lib.rs", 'unsafe extern "C" { safe fn item_id() -> u32; }')
        self.assertEqual(self.matches(), ["crates/sample/src/lib.rs:1: item_id"])
        self.write("crates/sample/src/lib.rs", 'safe fn item_id() {}')
        with self.assertRaises(ValueError):
            scan.inventory(self.repo)

    def test_domain_cannot_import_renamed_compatibility_dependency(self):
        self.write("crates/lockyard-core/src/lib.rs", "use lockyard_compat as innocent; fn run() {}")
        self.assertTrue(arch.architecture(self.repo))
        self.write("crates/lockyard-core/src/lib.rs", "fn run() {}")
        self.write("crates/lockyard-core/Cargo.toml", '[dependencies]\nlockyard-compat = { path="../lockyard-compat" }')
        self.assertTrue(arch.architecture(self.repo))
        self.write("crates/lockyard-core/Cargo.toml", '[dependencies]\ninnocent = { package="lockyard-compat", path="../lockyard-compat" }')
        self.assertTrue(arch.architecture(self.repo))

    def test_session_aliases_cannot_move_back_into_domain_models(self):
        self.write("crates/lockyard-core/src/lib.rs", 'struct Claim { #[serde(alias="agent")] session: String }')
        self.assertTrue(arch.architecture(self.repo))

    def test_renamed_numeric_aad_and_wire_policy_copies_are_rejected(self):
        for source in [
            'fn innocent(value: &serde_json::Value) -> String { format!("D-{}", value.as_i64().unwrap()) }',
            'fn innocent(id: &str) -> i64 { id.rsplit_once("-").unwrap().1.parse::<i64>().unwrap() }',
            'fn innocent() { decrypt("owner_word").or_else(|_| decrypt("value")); }',
            'fn innocent<T: DeserializeOwned>(value: Value, name: &str) { value.get(name).cloned(); }',
        ]:
            with self.subTest(source=source):
                self.write("crates/sample/src/lib.rs", source)
                self.assertTrue(arch.architecture(self.repo))

    def test_compatibility_cannot_become_a_business_backend(self):
        self.write("crates/lockyard-compat/src/legacy_v1.rs", "struct Adapter; impl Backend for Adapter { fn claim() {} }")
        self.assertTrue(arch.architecture(self.repo))


if __name__ == "__main__":
    unittest.main()
