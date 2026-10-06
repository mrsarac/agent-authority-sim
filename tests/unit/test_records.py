from __future__ import annotations

import copy
import inspect
import json
import unittest
from dataclasses import FrozenInstanceError, fields, is_dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "spec" / "v0.1.0" / "valid-contracts.json"
INVALID = ROOT / "spec" / "v0.1.0" / "invalid-vectors.json"
RECORDS_SOURCE = ROOT / "src" / "authority_sim" / "records.py"
EXPECTED_CLASSES = {
    "authority_lease": "AuthorityLeaseRecord",
    "task_envelope": "TaskEnvelopeRecord",
    "capability_claim": "CapabilityClaimRecord",
    "artifact_manifest": "ArtifactManifestRecord",
    "execution_receipt": "ExecutionReceiptRecord",
    "promotion_proposal": "PromotionProposalRecord",
    "promotion_decision": "PromotionDecisionRecord",
    "authority_event": "AuthorityEventRecord",
}


def _documents() -> list[dict]:
    return json.loads(VALID.read_text(encoding="utf-8"))["documents"]


def _by_kind() -> dict[str, dict]:
    return {document["kind"]: document for document in _documents()}


def _kwargs(record) -> dict:
    return {field.name: getattr(record, field.name) for field in fields(record)}


class StringSubclass(str):
    pass


class IntSubclass(int):
    pass


class DatetimeSubclass(datetime):
    pass


class HostileIterable:
    calls = 0

    def __iter__(self):
        type(self).calls += 1
        raise RuntimeError("HOSTILE_ITERABLE_SENTINEL")


class HostileMapping(dict):
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


class HostileTimezone(tzinfo):
    def utcoffset(self, dt):
        raise RuntimeError("HOSTILE_TIMEZONE_SENTINEL")

    def dst(self, dt):
        return timedelta(0)


class HostileOffset(timedelta):
    comparisons = 0

    def __eq__(self, other):
        type(self).comparisons += 1
        raise RuntimeError("HOSTILE_OFFSET_SENTINEL")

    def __ne__(self, other):
        type(self).comparisons += 1
        raise RuntimeError("HOSTILE_OFFSET_SENTINEL")


class HostileOffsetTimezone(tzinfo):
    def utcoffset(self, dt):
        return HostileOffset(0)

    def dst(self, dt):
        return timedelta(0)


class TestImmutableRecords(unittest.TestCase):
    def setUp(self):
        from authority_sim.records import create_record

        self.documents = _documents()
        self.records = {document["kind"]: create_record(document) for document in self.documents}

    def test_exact_eight_documents_create_exact_record_classes(self):
        self.assertEqual(set(self.records), set(EXPECTED_CLASSES))
        self.assertEqual(len(self.records), 8)
        for kind, record in self.records.items():
            with self.subTest(kind=kind):
                self.assertEqual(type(record).__name__, EXPECTED_CLASSES[kind])
                self.assertTrue(is_dataclass(record))
                self.assertTrue(type(record).__dataclass_params__.frozen)
                self.assertFalse(hasattr(record, "__dict__"))
                self.assertIsInstance(hash(record), int)

    def test_closed_enums_and_datetime_fields_have_exact_runtime_types(self):
        from authority_sim.records import (
            Classification,
            ContractKind,
            FrozenObject,
            LeaseAction,
            ProducerRecord,
            Provenance,
            TrustClass,
        )

        lease = self.records["authority_lease"]
        self.assertIs(lease.kind, ContractKind.AUTHORITY_LEASE)
        self.assertIs(lease.lease_action, LeaseAction.RENEW)
        for name in ("issued_at", "valid_from", "expires_at"):
            self.assertIs(type(getattr(lease, name)), datetime)
            self.assertEqual(getattr(lease, name).utcoffset(), timedelta(0))

        manifest = self.records["artifact_manifest"]
        self.assertIs(type(manifest.producer), ProducerRecord)
        self.assertIs(manifest.classification, Classification.INTERNAL)
        self.assertIs(manifest.provenance, Provenance.GOVERNOR_OBSERVED)
        self.assertIs(type(manifest.parent_artifact_ids), tuple)

        task = self.records["task_envelope"]
        self.assertIs(type(task.audience), FrozenObject)
        self.assertIs(type(task.input_refs), tuple)
        self.assertIs(type(task.input_refs[0]), FrozenObject)
        self.assertIs(
            task.input_refs[0].get("classification"),
            Classification.INTERNAL,
        )
        self.assertIs(
            task.acceptance_checks[0].get("minimum_trust_class"),
            TrustClass.GOVERNOR_OBSERVED,
        )

        receipt = self.records["execution_receipt"]
        self.assertIs(
            receipt.observations[0].get("trust_class"),
            TrustClass.GOVERNOR_OBSERVED,
        )

    def test_every_record_field_is_deeply_immutable_and_hashable(self):
        from authority_sim.records import FrozenObject, ProducerRecord

        def assert_immutable(value):
            self.assertNotIsInstance(value, (list, dict, set, bytearray))
            if type(value) is tuple:
                for item in value:
                    assert_immutable(item)
            elif type(value) is FrozenObject:
                self.assertFalse(hasattr(value, "__dict__"))
                for key, item in value.entries:
                    self.assertIs(type(key), str)
                    assert_immutable(item)
            elif type(value) is ProducerRecord:
                self.assertFalse(hasattr(value, "__dict__"))
                for field in fields(value):
                    assert_immutable(getattr(value, field.name))

        for record in self.records.values():
            for field in fields(record):
                assert_immutable(getattr(record, field.name))
            with self.assertRaises(FrozenInstanceError):
                record.schema_version = "9.9.9"

    def test_caller_and_returned_document_mutation_cannot_change_records(self):
        from authority_sim.records import create_record

        documents = copy.deepcopy(self.documents)
        records = [create_record(document) for document in documents]
        snapshots = [record.to_document() for record in records]
        hashes = [hash(record) for record in records]

        documents[1]["required_actions"].append("secret_use")
        documents[3]["producer"]["node_id"] = "node:mutated"
        documents[3]["parent_artifact_ids"].append("artifact_02mutated")
        documents[4]["observations"][0]["status"] = "fail"
        returned = records[1].to_document()
        returned["audience"]["node_id"] = "node:mutated"

        self.assertEqual([record.to_document() for record in records], snapshots)
        self.assertEqual([hash(record) for record in records], hashes)

    def test_direct_reconstruction_validates_full_exact_keyset(self):
        from authority_sim.records import RecordError

        for record in self.records.values():
            record_type = type(record)
            kwargs = _kwargs(record)
            with self.subTest(record_type=record_type.__name__):
                self.assertEqual(record_type(**kwargs), record)
                missing = dict(kwargs)
                missing.pop(next(iter(missing)))
                with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
                    record_type(**missing)
                unknown = dict(kwargs)
                unknown["SECRET_UNKNOWN_FIELD"] = "SECRET_VALUE"
                with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$") as caught:
                    record_type(**unknown)
                self.assertNotIn("SECRET_UNKNOWN_FIELD", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)

    def test_raw_string_enums_and_cross_enum_substitution_reject(self):
        from authority_sim.records import (
            AuthorityLeaseRecord,
            ArtifactManifestRecord,
            RecordError,
            TrustClass,
        )

        lease_kwargs = _kwargs(self.records["authority_lease"])
        for field_name, raw in (("kind", "authority_lease"), ("lease_action", "renew")):
            mutated = dict(lease_kwargs)
            mutated[field_name] = raw
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
                    AuthorityLeaseRecord(**mutated)

        manifest_kwargs = _kwargs(self.records["artifact_manifest"])
        for field_name, raw in (
            ("classification", "internal"),
            ("provenance", "governor_observed"),
            ("provenance", TrustClass.GOVERNOR_OBSERVED),
        ):
            mutated = dict(manifest_kwargs)
            mutated[field_name] = raw
            with self.subTest(field_name=field_name, raw_type=type(raw).__name__):
                with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
                    ArtifactManifestRecord(**mutated)

    def test_exact_scalar_types_bool_as_int_and_datetime_strings_reject(self):
        from authority_sim.records import AuthorityLeaseRecord, RecordError

        base = _kwargs(self.records["authority_lease"])
        mutations = {
            "operator_id": StringSubclass(base["operator_id"]),
            "authority_epoch": IntSubclass(base["authority_epoch"]),
            "lease_generation": True,
            "issued_at": "2026-08-15T13:59:59Z",
            "valid_from": DatetimeSubclass(2026, 8, 15, 14, 0, tzinfo=timezone.utc),
        }
        for field_name, value in mutations.items():
            mutated = dict(base)
            mutated[field_name] = value
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
                    AuthorityLeaseRecord(**mutated)

    def test_hostile_iterable_mapping_and_timezone_do_not_dispatch_or_leak(self):
        from authority_sim.records import (
            AuthorityLeaseRecord,
            RecordError,
            TaskEnvelopeRecord,
            create_record,
        )

        task_kwargs = _kwargs(self.records["task_envelope"])
        HostileIterable.calls = 0
        task_kwargs["required_actions"] = HostileIterable()
        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$") as caught:
            TaskEnvelopeRecord(**task_kwargs)
        self.assertEqual(HostileIterable.calls, 0)
        self.assertNotIn("HOSTILE_ITERABLE_SENTINEL", str(caught.exception))

        HostileMapping.calls = 0
        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$") as caught:
            create_record(HostileMapping(self.documents[0]))
        self.assertEqual(HostileMapping.calls, 0)
        self.assertNotIn("HOSTILE_MAPPING_SENTINEL", str(caught.exception))

        nested = copy.deepcopy(_by_kind()["artifact_manifest"])
        nested["producer"] = HostileMapping(nested["producer"])
        HostileMapping.calls = 0
        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
            create_record(nested)
        self.assertEqual(HostileMapping.calls, 0)

        lease_kwargs = _kwargs(self.records["authority_lease"])
        hostile_times = (
            datetime(2026, 8, 15, 14, 0, tzinfo=HostileTimezone()),
            datetime(2026, 8, 15, 14, 0, tzinfo=HostileOffsetTimezone()),
        )
        for hostile_time in hostile_times:
            mutated = dict(lease_kwargs)
            mutated["issued_at"] = hostile_time
            HostileOffset.comparisons = 0
            with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$") as caught:
                AuthorityLeaseRecord(**mutated)
            self.assertEqual(HostileOffset.comparisons, 0)
            self.assertNotIn("HOSTILE_", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)

    def test_duplicate_tuples_and_mutable_nested_values_reject(self):
        from authority_sim.records import FrozenObject, RecordError, TaskEnvelopeRecord

        task_kwargs = _kwargs(self.records["task_envelope"])
        task_kwargs["required_actions"] = ("read_artifact", "read_artifact")
        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
            TaskEnvelopeRecord(**task_kwargs)

        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
            FrozenObject((("safe", ["mutable"]),))
        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
            FrozenObject((("duplicate", "one"), ("duplicate", "two")))

    def test_producer_is_exact_frozen_record_not_dict(self):
        from authority_sim.records import ArtifactManifestRecord, ProducerRecord, RecordError

        manifest = self.records["artifact_manifest"]
        producer = manifest.producer
        self.assertIs(type(producer), ProducerRecord)
        self.assertFalse(hasattr(producer, "__dict__"))
        self.assertEqual(ProducerRecord(**_kwargs(producer)), producer)

        manifest_kwargs = _kwargs(manifest)
        manifest_kwargs["producer"] = producer.to_document()
        with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$"):
            ArtifactManifestRecord(**manifest_kwargs)

    def test_producer_direct_constructor_enforces_exact_identifier_patterns(self):
        from authority_sim.records import ProducerRecord, RecordError

        valid = {
            "node_id": "node:abc",
            "adapter_id": "adapter:abc",
            "process_id": "process:Abc_1",
        }
        self.assertEqual(ProducerRecord(**valid).to_document(), valid)
        invalid = (
            ("node_id", "x"),
            ("node_id", "node:Abc"),
            ("adapter_id", "adapter:ab"),
            ("adapter_id", " adapter:abc"),
            ("process_id", "process:ab"),
            ("process_id", StringSubclass("process:Abc_1")),
        )
        for field_name, value in invalid:
            kwargs = dict(valid)
            kwargs[field_name] = value
            with self.subTest(field_name=field_name, value_type=type(value).__name__):
                with self.assertRaisesRegex(RecordError, "^RECORD_INVALID$") as caught:
                    ProducerRecord(**kwargs)
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)

    def test_x_vectors_remain_individually_schema_valid_and_deferred(self):
        from authority_sim.records import create_record

        self.assertEqual(tuple(inspect.signature(create_record).parameters), ("document",))
        documents = _by_kind()
        vectors = json.loads(INVALID.read_text(encoding="utf-8"))["vectors"]
        deferred = [vector for vector in vectors if vector["layer"] != "schema"]
        self.assertEqual({vector["vector_id"] for vector in deferred}, {"X01", "X02", "X03"})
        for vector in deferred:
            with self.subTest(vector_id=vector["vector_id"]):
                record = create_record(documents[vector["base_kind"]])
                self.assertEqual(record.to_document(), documents[vector["base_kind"]])

    def test_source_has_no_any_deepcopy_isinstance_or_layer_shortcut(self):
        self.assertTrue(RECORDS_SOURCE.is_file())
        source = RECORDS_SOURCE.read_text(encoding="utf-8")
        for forbidden in ("Any", "deepcopy", "isinstance(", "layer !=", "_VALIDATOR"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
