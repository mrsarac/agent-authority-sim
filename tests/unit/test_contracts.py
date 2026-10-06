from __future__ import annotations

import copy
import inspect
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "spec" / "v0.1.0"
SCHEMA = SPEC / "contracts.schema.json"
VALID = SPEC / "valid-contracts.json"
INVALID = SPEC / "invalid-vectors.json"
CONTRACTS_SOURCE = ROOT / "src" / "authority_sim" / "contracts.py"
EXPECTED_KINDS = {
    "authority_lease",
    "task_envelope",
    "capability_claim",
    "artifact_manifest",
    "execution_receipt",
    "promotion_proposal",
    "promotion_decision",
    "authority_event",
}


def _valid_documents() -> list[dict]:
    return json.loads(VALID.read_text(encoding="utf-8"))["documents"]


def _vectors() -> list[dict]:
    return json.loads(INVALID.read_text(encoding="utf-8"))["vectors"]


def _apply_operations(base: dict, operations: list[dict]) -> dict:
    document = copy.deepcopy(base)
    for operation in operations:
        parts = [part.replace("~1", "/").replace("~0", "~") for part in operation["path"].split("/")[1:]]
        parent = document
        for part in parts[:-1]:
            parent = parent[int(part)] if type(parent) is list else parent[part]
        final = parts[-1]
        if operation["op"] == "remove":
            if type(parent) is list:
                del parent[int(final)]
            else:
                del parent[final]
        elif operation["op"] in ("add", "replace"):
            if type(parent) is list:
                parent[int(final)] = operation["value"]
            else:
                parent[final] = operation["value"]
        else:
            raise AssertionError("unexpected fixture operation")
    return document


class HostileDict(dict):
    calls = 0

    def __iter__(self):
        type(self).calls += 1
        raise RuntimeError("HOSTILE_MAPPING_SENTINEL")

    def items(self):
        type(self).calls += 1
        raise RuntimeError("HOSTILE_MAPPING_SENTINEL")

    def keys(self):
        type(self).calls += 1
        raise RuntimeError("HOSTILE_MAPPING_SENTINEL")


class HostileString(str):
    pass


class TestStrictContractLoader(unittest.TestCase):
    def test_schema_is_loaded_only_from_the_pinned_relative_bundle(self):
        from authority_sim.contracts import load_schema

        self.assertEqual(tuple(inspect.signature(load_schema).parameters), ())
        self.assertTrue(SCHEMA.is_file())
        self.assertFalse(SCHEMA.is_symlink())
        schema = load_schema()
        self.assertEqual(schema["$id"], "urn:agent-authority-sim:contracts:0.1.0")
        self.assertEqual(len(schema["oneOf"]), 8)

    def test_caller_schema_mutation_cannot_self_bless_later_validation(self):
        from authority_sim.contracts import load_schema, validate_document

        poisoned = load_schema()
        poisoned["oneOf"].clear()
        poisoned["$defs"].clear()
        valid = _valid_documents()[0]
        validate_document(valid)
        fresh = load_schema()
        self.assertEqual(len(fresh["oneOf"]), 8)
        self.assertIn("authorityLease", fresh["$defs"])

    def test_exact_eight_valid_documents_and_kinds_validate(self):
        from authority_sim.contracts import validate_document

        documents = _valid_documents()
        self.assertEqual(len(documents), 8)
        self.assertEqual({document["kind"] for document in documents}, EXPECTED_KINDS)
        for document in documents:
            with self.subTest(kind=document["kind"]):
                self.assertIsNone(validate_document(document))

    def test_exact_s01_through_s13_schema_vectors_all_reject(self):
        from authority_sim.contracts import SchemaInvalidError, validate_document

        documents = {document["kind"]: document for document in _valid_documents()}
        schema_vectors = [vector for vector in _vectors() if vector["layer"] == "schema"]
        self.assertEqual(
            {vector["vector_id"] for vector in schema_vectors},
            {f"S{number:02d}" for number in range(1, 14)},
        )
        rejected = 0
        for vector in schema_vectors:
            mutated = _apply_operations(
                documents[vector["base_kind"]],
                vector["operations"],
            )
            with self.subTest(vector_id=vector["vector_id"]):
                with self.assertRaisesRegex(SchemaInvalidError, "^SCHEMA_INVALID$"):
                    validate_document(mutated)
                rejected += 1
        self.assertEqual(rejected, 13)

    def test_x01_x02_x03_are_exactly_deferred_not_schema_rejection_proof(self):
        deferred = [vector for vector in _vectors() if vector["layer"] != "schema"]
        self.assertEqual(
            {vector["vector_id"] for vector in deferred},
            {"X01", "X02", "X03"},
        )
        self.assertEqual(
            {vector["layer"] for vector in deferred},
            {"cross_document", "state_model"},
        )
        self.assertTrue(all(vector["operations"] == [] for vector in deferred))

    def test_bool_as_integer_unknown_fields_and_bad_format_reject(self):
        from authority_sim.contracts import SchemaInvalidError, validate_document

        documents = {document["kind"]: document for document in _valid_documents()}
        mutations = []
        authority = copy.deepcopy(documents["authority_lease"])
        authority["authority_epoch"] = True
        mutations.append(authority)
        task = copy.deepcopy(documents["task_envelope"])
        task["audience"]["unexpected"] = "forbidden"
        mutations.append(task)
        manifest = copy.deepcopy(documents["artifact_manifest"])
        manifest["created_at"] = "2026-02-31T00:00:00Z"
        mutations.append(manifest)
        for mutation in mutations:
            with self.subTest(kind=mutation["kind"]):
                with self.assertRaisesRegex(SchemaInvalidError, "^SCHEMA_INVALID$"):
                    validate_document(mutation)

    def test_date_time_checker_is_effective_and_does_not_mutate_global_registry(self):
        from jsonschema import FormatChecker
        from authority_sim.contracts import _format_checker

        before = dict(FormatChecker().checkers)
        checker = _format_checker()
        self.assertIn("date-time", checker.checkers)
        self.assertFalse(checker.conforms("2026-02-31T00:00:00Z", "date-time"))
        self.assertEqual(dict(FormatChecker().checkers), before)

    def test_hostile_mapping_and_subclass_values_fail_before_dispatch(self):
        from authority_sim.contracts import SchemaInvalidError, validate_document

        HostileDict.calls = 0
        hostile_mapping = HostileDict(_valid_documents()[0])
        with self.assertRaisesRegex(SchemaInvalidError, "^SCHEMA_INVALID$") as caught:
            validate_document(hostile_mapping)
        self.assertEqual(HostileDict.calls, 0)
        self.assertNotIn("HOSTILE_MAPPING_SENTINEL", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

        hostile_value = copy.deepcopy(_valid_documents()[0])
        hostile_value["operator_id"] = HostileString("SECRET_CLASS_SENTINEL")
        with self.assertRaisesRegex(SchemaInvalidError, "^SCHEMA_INVALID$") as caught:
            validate_document(hostile_value)
        self.assertNotIn("SECRET_CLASS_SENTINEL", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_public_errors_are_fixed_generic_and_unchained(self):
        from authority_sim.contracts import SchemaInvalidError, validate_document

        for value in (None, [], "SECRET_SCHEMA_SENTINEL"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(SchemaInvalidError, "^SCHEMA_INVALID$") as caught:
                    validate_document(value)
                self.assertEqual(str(caught.exception), "SCHEMA_INVALID")
                self.assertNotIn("SECRET_SCHEMA_SENTINEL", repr(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)

    def test_source_has_no_mutable_validator_or_ambient_schema_path(self):
        self.assertTrue(CONTRACTS_SOURCE.is_file())
        source = CONTRACTS_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("_VALIDATOR", source)
        self.assertNotIn("Path.home", source)
        self.assertNotIn("expanduser", source)
        self.assertNotIn("/Users/", source)
        self.assertNotIn("os.environ", source)


if __name__ == "__main__":
    unittest.main()
