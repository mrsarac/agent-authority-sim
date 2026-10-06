from __future__ import annotations

import ast
import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from authority_sim.canonical import canonical_bytes, sha256_digest


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "spec" / "v0.1.0" / "valid-contracts.json"
LOG_SOURCE = ROOT / "src" / "authority_sim" / "authority_log.py"


def _base_event() -> dict:
    documents = json.loads(VALID.read_text(encoding="utf-8"))["documents"]
    return copy.deepcopy(
        next(document for document in documents if document["kind"] == "authority_event"),
    )


def _event_bytes(
    sequence: int,
    previous_digest: str | None,
    observed_at: str,
    *,
    event_id: str | None = None,
    idempotency_key: str | None = None,
) -> bytes:
    document = _base_event()
    document["sequence"] = sequence
    document["previous_event_digest"] = previous_digest
    document["observed_at"] = observed_at
    document["event_id"] = event_id or f"event_{sequence:08d}"
    document["idempotency_key"] = idempotency_key or f"event.append:{sequence:08d}"
    document["event_digest"] = "sha256:" + ("0" * 64)
    body = dict(document)
    body.pop("event_digest")
    document["event_digest"] = sha256_digest(canonical_bytes(body))
    return canonical_bytes(document)


def _declared_digest(raw: bytes) -> str:
    return json.loads(raw.decode("utf-8"))["event_digest"]


class BytesSubclass(bytes):
    pass


class TupleSubclass(tuple):
    pass


class TestAtomicAuthorityLog(unittest.TestCase):
    def test_genesis_and_two_event_batch_publish_exact_bytes_once(self):
        from authority_sim.authority_log import InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        before = log.snapshot()
        self.assertIsNone(before.head)
        self.assertEqual(before.accepted_event_bytes, ())

        first = _event_bytes(1, None, "2026-08-16T12:00:00Z")
        first_digest = _declared_digest(first)
        second = _event_bytes(2, first_digest, "2026-08-16T12:00:01Z")
        result = log.compare_and_append(
            expected_head=None,
            event_bytes=(first, second),
        )

        after = log.snapshot()
        self.assertEqual(result.prior_head, None)
        self.assertEqual(result.resulting_head, _declared_digest(second))
        self.assertEqual((result.first_sequence, result.last_sequence), (1, 2))
        self.assertEqual(after.head, result.resulting_head)
        self.assertEqual(after.accepted_event_bytes, (first, second))
        self.assertNotEqual(after.projection_bytes, before.projection_bytes)

    def test_stale_expected_head_rejects_without_state_change(self):
        from authority_sim.authority_log import AuthorityLogError, InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        first = _event_bytes(1, None, "2026-08-16T12:00:00Z")
        log.compare_and_append(expected_head=None, event_bytes=(first,))
        before = log.snapshot()
        second = _event_bytes(
            2,
            before.head,
            "2026-08-16T12:00:01Z",
        )
        with self.assertRaisesRegex(AuthorityLogError, "^EXPECTED_HEAD_MISMATCH$"):
            log.compare_and_append(expected_head=None, event_bytes=(second,))
        self.assertEqual(log.snapshot(), before)

    def test_broken_previous_digest_and_sequence_gap_fail_closed(self):
        from authority_sim.authority_log import AuthorityLogError, InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        first = _event_bytes(1, None, "2026-08-16T12:00:00Z")
        log.compare_and_append(expected_head=None, event_bytes=(first,))
        before = log.snapshot()
        mutations = (
            _event_bytes(2, "sha256:" + ("f" * 64), "2026-08-16T12:00:01Z"),
            _event_bytes(3, before.head, "2026-08-16T12:00:01Z"),
        )
        for mutation in mutations:
            with self.subTest(sequence=json.loads(mutation)["sequence"]):
                with self.assertRaisesRegex(AuthorityLogError, "^AUTHORITY_LOG_INVALID$"):
                    log.compare_and_append(
                        expected_head=before.head,
                        event_bytes=(mutation,),
                    )
                self.assertEqual(log.snapshot(), before)

    def test_backward_observed_time_rejects_without_hostile_clock_fallback(self):
        from authority_sim.authority_log import AuthorityLogError, InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        first = _event_bytes(1, None, "2026-08-16T12:00:02Z")
        log.compare_and_append(expected_head=None, event_bytes=(first,))
        before = log.snapshot()
        backward = _event_bytes(2, before.head, "2026-08-16T12:00:01Z")
        with self.assertRaisesRegex(AuthorityLogError, "^AUTHORITY_LOG_INVALID$"):
            log.compare_and_append(
                expected_head=before.head,
                event_bytes=(backward,),
            )
        self.assertEqual(log.snapshot(), before)

    def test_submicrosecond_backward_observed_time_is_not_truncated(self):
        from authority_sim.authority_log import AuthorityLogError, InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        first = _event_bytes(1, None, "2026-08-16T12:00:00.000000900Z")
        log.compare_and_append(expected_head=None, event_bytes=(first,))
        before = log.snapshot()
        backward = _event_bytes(
            2,
            before.head,
            "2026-08-16T12:00:00.000000800Z",
        )
        with self.assertRaisesRegex(AuthorityLogError, "^AUTHORITY_LOG_INVALID$"):
            log.compare_and_append(
                expected_head=before.head,
                event_bytes=(backward,),
            )
        self.assertEqual(log.snapshot(), before)

    def test_pre_swap_faults_leave_head_bytes_and_projection_identical(self):
        from authority_sim.authority_log import (
            AuthorityLogError,
            FaultPoint,
            InMemoryAuthorityLog,
        )

        for fault in (FaultPoint.BEFORE_STAGE, FaultPoint.BETWEEN_STAGE_RECORDS):
            log = InMemoryAuthorityLog()
            first = _event_bytes(1, None, "2026-08-16T12:00:00Z")
            log.compare_and_append(expected_head=None, event_bytes=(first,))
            before = log.snapshot()
            second = _event_bytes(2, before.head, "2026-08-16T12:00:01Z")
            third = _event_bytes(
                3,
                _declared_digest(second),
                "2026-08-16T12:00:02Z",
            )
            with self.subTest(fault=fault.name):
                with self.assertRaisesRegex(AuthorityLogError, "^FAULT_INJECTED$"):
                    log.compare_and_append(
                        expected_head=before.head,
                        event_bytes=(second, third),
                        fault=fault,
                    )
                self.assertEqual(log.snapshot(), before)
                self.assertEqual(log.snapshot().head, before.head)
                self.assertEqual(
                    log.snapshot().accepted_event_bytes,
                    before.accepted_event_bytes,
                )
                self.assertIs(log.snapshot().projection_bytes, before.projection_bytes)

    def test_after_swap_fault_publishes_whole_batch_and_replay_is_idempotent(self):
        from authority_sim.authority_log import (
            AuthorityLogError,
            FaultPoint,
            InMemoryAuthorityLog,
        )

        log = InMemoryAuthorityLog()
        first = _event_bytes(1, None, "2026-08-16T12:00:00Z")
        second = _event_bytes(
            2,
            _declared_digest(first),
            "2026-08-16T12:00:01Z",
        )
        with self.assertRaisesRegex(AuthorityLogError, "^FAULT_INJECTED$"):
            log.compare_and_append(
                expected_head=None,
                event_bytes=(first, second),
                fault=FaultPoint.AFTER_SWAP,
            )
        accepted = log.snapshot()
        self.assertEqual(accepted.accepted_event_bytes, (first, second))
        replay_result = log.compare_and_append(
            expected_head=None,
            event_bytes=(first, second),
        )
        self.assertEqual(replay_result.resulting_head, accepted.head)
        self.assertEqual(log.snapshot(), accepted)

    def test_byte_different_replay_under_same_id_or_key_rejects(self):
        from authority_sim.authority_log import AuthorityLogError, InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        first = _event_bytes(1, None, "2026-08-16T12:00:00Z")
        log.compare_and_append(expected_head=None, event_bytes=(first,))
        before = log.snapshot()
        original = json.loads(first)
        conflicts = (
            (
                _event_bytes(
                    2,
                    before.head,
                    "2026-08-16T12:00:01Z",
                    event_id=original["event_id"],
                ),
                before.head,
            ),
            (
                _event_bytes(
                    2,
                    before.head,
                    "2026-08-16T12:00:01Z",
                    idempotency_key=original["idempotency_key"],
                ),
                before.head,
            ),
            (
                _event_bytes(
                    2,
                    before.head,
                    "2026-08-16T12:00:01Z",
                    event_id=original["event_id"],
                    idempotency_key=original["idempotency_key"],
                ),
                None,
            ),
        )
        for conflict, replay_expected_head in conflicts:
            with self.subTest(conflict=json.loads(conflict)["event_id"]):
                with self.assertRaisesRegex(AuthorityLogError, "^REPLAY_DETECTED$"):
                    log.compare_and_append(
                        expected_head=replay_expected_head,
                        event_bytes=(conflict,),
                    )
                self.assertEqual(log.snapshot(), before)

    def test_invalid_digest_noncanonical_bytes_and_exact_input_types_reject_generically(self):
        from authority_sim.authority_log import AuthorityLogError, InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        canonical = _event_bytes(1, None, "2026-08-16T12:00:00Z")
        bad_digest_document = json.loads(canonical)
        bad_digest_document["event_digest"] = "sha256:" + ("f" * 64)
        bad_digest = canonical_bytes(bad_digest_document)
        noncanonical = json.dumps(json.loads(canonical), ensure_ascii=False).encode("utf-8")
        cases = (
            {"expected_head": None, "event_bytes": ()},
            {"expected_head": None, "event_bytes": [canonical]},
            {"expected_head": None, "event_bytes": TupleSubclass((canonical,))},
            {"expected_head": None, "event_bytes": (BytesSubclass(canonical),)},
            {"expected_head": None, "event_bytes": (bad_digest,)},
            {"expected_head": None, "event_bytes": (noncanonical,)},
            {"expected_head": "SECRET_HEAD_SENTINEL", "event_bytes": (canonical,)},
        )
        for kwargs in cases:
            with self.subTest(event_bytes_type=type(kwargs["event_bytes"]).__name__):
                with self.assertRaisesRegex(
                    AuthorityLogError,
                    "^AUTHORITY_LOG_INVALID$",
                ) as caught:
                    log.compare_and_append(**kwargs)
                self.assertNotIn("SECRET_HEAD_SENTINEL", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertIsNone(log.snapshot().head)

    def test_snapshot_is_frozen_redacted_and_has_no_mutation_surface(self):
        from authority_sim.authority_log import InMemoryAuthorityLog

        log = InMemoryAuthorityLog()
        snapshot = log.snapshot()
        self.assertFalse(hasattr(log, "__dict__"))
        self.assertFalse(hasattr(snapshot, "__dict__"))
        self.assertEqual(repr(snapshot), "AuthorityLogSnapshot(...)")
        with self.assertRaises(FrozenInstanceError):
            snapshot.head = "sha256:" + ("a" * 64)
        for name in (
            "append",
            "compare_and_append",
            "promote",
            "renew_lease",
            "recover",
            "store",
        ):
            self.assertFalse(hasattr(snapshot, name))

    def test_source_uses_one_private_swap_and_no_ambient_capabilities(self):
        self.assertTrue(LOG_SOURCE.is_file())
        source = LOG_SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imported_roots.isdisjoint(
                {"os", "pathlib", "random", "socket", "subprocess", "time"},
            ),
        )
        for forbidden in (
            "datetime.now",
            "datetime.utcnow",
            "time.time",
            "os.environ",
            "open(",
            "Path(",
        ):
            self.assertNotIn(forbidden, source)

        compare_method = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "compare_and_append"
        )
        swaps = [
            node
            for node in ast.walk(compare_method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "object"
            and node.func.attr == "__setattr__"
        ]
        self.assertEqual(len(swaps), 1)


if __name__ == "__main__":
    unittest.main()
