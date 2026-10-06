from __future__ import annotations

import ast
import unittest
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLOCK_SOURCE = ROOT / "src" / "authority_sim" / "clock.py"
STORE_SOURCE = ROOT / "src" / "authority_sim" / "stores.py"


class HostileTimezone(tzinfo):
    def utcoffset(self, dt):
        raise RuntimeError("HOSTILE_TIME_SENTINEL")

    def dst(self, dt):
        return timedelta(0)


class DatetimeSubclass(datetime):
    pass


class TimedeltaSubclass(timedelta):
    pass


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


class StatefulTimezone(tzinfo):
    calls = 0

    def utcoffset(self, dt):
        type(self).calls += 1
        if type(self).calls == 1:
            return timedelta(0)
        raise RuntimeError("STATEFUL_TIMEZONE_SENTINEL")

    def dst(self, dt):
        return timedelta(0)


class StringSubclass(str):
    pass


class BytesSubclass(bytes):
    pass


class BytearraySubclass(bytearray):
    pass


class TestFakeClock(unittest.TestCase):
    def setUp(self):
        from authority_sim.clock import FakeClock

        self.initial = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
        self.clock = FakeClock(self.initial)

    def test_explicit_authority_time_and_worker_default(self):
        self.assertEqual(self.clock.authority_as_of(), self.initial)
        self.assertEqual(self.clock.worker_time("worker:one"), self.initial)

    def test_authority_advance_is_monotonic(self):
        self.clock.advance_authority(timedelta(seconds=30))
        self.assertEqual(
            self.clock.authority_as_of(),
            self.initial + timedelta(seconds=30),
        )
        with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$"):
            self.clock.advance_authority(timedelta(microseconds=-1))

    def test_worker_skew_never_mutates_authority_or_other_workers(self):
        self.clock.skew_worker("worker:one", timedelta(seconds=7))
        self.assertEqual(
            self.clock.worker_time("worker:one"),
            self.initial + timedelta(seconds=7),
        )
        self.assertEqual(self.clock.worker_time("worker:two"), self.initial)
        self.assertEqual(self.clock.authority_as_of(), self.initial)

    def test_initial_time_requires_exact_aware_utc_datetime(self):
        from authority_sim.clock import FakeClock

        invalid = [
            datetime(2026, 8, 16, 12, 0),
            datetime(2026, 8, 16, 12, 0, tzinfo=timezone(timedelta(hours=1))),
            DatetimeSubclass(2026, 8, 16, 12, 0, tzinfo=timezone.utc),
        ]
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$"):
                    FakeClock(value)

    def test_hostile_timezone_is_generic_and_unchained(self):
        from authority_sim.clock import FakeClock

        hostile = datetime(2026, 8, 16, 12, 0, tzinfo=HostileTimezone())
        with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$") as caught:
            FakeClock(hostile)
        self.assertNotIn("HOSTILE_TIME_SENTINEL", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_hostile_offset_subclass_is_rejected_before_comparison(self):
        from authority_sim.clock import FakeClock

        hostile = datetime(2026, 8, 16, 12, 0, tzinfo=HostileOffsetTimezone())
        HostileOffset.comparisons = 0
        with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$") as caught:
            FakeClock(hostile)
        self.assertEqual(HostileOffset.comparisons, 0)
        self.assertNotIn("HOSTILE_OFFSET_SENTINEL", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_validated_timezone_object_is_not_retained_in_authority_state(self):
        from authority_sim.clock import FakeClock

        StatefulTimezone.calls = 0
        initial = datetime(2026, 8, 16, 12, 0, tzinfo=StatefulTimezone())
        clock = FakeClock(initial)
        authority_time = clock.authority_as_of()
        self.assertIs(authority_time.tzinfo, timezone.utc)
        self.assertEqual(authority_time, self.initial)
        self.assertEqual(clock.worker_time("worker:one"), self.initial)
        self.assertEqual(StatefulTimezone.calls, 1)

    def test_delta_and_worker_ids_require_exact_types(self):
        with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$"):
            self.clock.advance_authority(TimedeltaSubclass(seconds=1))
        with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$"):
            self.clock.skew_worker("worker:one", TimedeltaSubclass(seconds=1))
        for worker_id in ("", " worker:one", "worker:one ", StringSubclass("worker:one")):
            with self.subTest(worker_id_type=type(worker_id).__name__):
                with self.assertRaisesRegex(ValueError, "^CLOCK_INVALID$"):
                    self.clock.worker_time(worker_id)

    def test_instance_has_no_public_time_mutation_surface(self):
        self.assertFalse(hasattr(self.clock, "__dict__"))
        for name in ("set_time", "reset", "now", "reload"):
            self.assertFalse(hasattr(self.clock, name))

    def test_source_has_no_ambient_time_or_environment_access(self):
        self.assertTrue(CLOCK_SOURCE.is_file())
        source = CLOCK_SOURCE.read_text(encoding="utf-8")
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
        self.assertTrue(imported_roots.isdisjoint({"os", "time", "pathlib", "subprocess"}))
        for forbidden in ("datetime.now", "datetime.utcnow", "time.time"):
            self.assertNotIn(forbidden, source)


class TestImmutableStore(unittest.TestCase):
    def setUp(self):
        from authority_sim.stores import ImmutableStore

        self.store = ImmutableStore()

    def test_caller_bytearray_mutation_cannot_change_stored_bytes(self):
        original = bytearray(b"original")
        self.store.store("artifact:one", original)
        original[:] = b"mutated!"
        self.assertEqual(self.store.get("artifact:one"), b"original")
        self.assertIsInstance(self.store.get("artifact:one"), bytes)

    def test_identical_replay_is_idempotent_before_and_after_acceptance(self):
        self.store.store("artifact:one", b"stable")
        self.store.store("artifact:one", b"stable")
        self.store.store_canonical("artifact:one", b"stable")
        self.store.store_canonical("artifact:one", b"stable")
        self.store.store("artifact:one", b"stable")
        self.assertEqual(self.store.get("artifact:one"), b"stable")

    def test_different_untrusted_bytes_are_a_closed_conflict_without_overwrite(self):
        from authority_sim.stores import UntrustedConflict

        self.store.store("artifact:one", b"first")
        with self.assertRaisesRegex(UntrustedConflict, "^UNTRUSTED_CONFLICT$"):
            self.store.store("artifact:one", b"second")
        self.assertEqual(self.store.get("artifact:one"), b"first")

    def test_canonicalizing_different_untrusted_bytes_is_not_accepted_corruption(self):
        from authority_sim.stores import UntrustedConflict

        self.store.store("artifact:one", b"first")
        with self.assertRaisesRegex(UntrustedConflict, "^UNTRUSTED_CONFLICT$"):
            self.store.store_canonical("artifact:one", b"second")
        self.assertEqual(self.store.get("artifact:one"), b"first")
        self.store.store_canonical("artifact:one", b"first")
        self.assertEqual(self.store.get("artifact:one"), b"first")

    def test_different_bytes_against_canonical_are_a_distinct_contradiction(self):
        from authority_sim.stores import AcceptedContradiction

        self.store.store_canonical("artifact:one", b"accepted")
        with self.assertRaisesRegex(
            AcceptedContradiction,
            "^ACCEPTED_CONTRADICTION$",
        ):
            self.store.store("artifact:one", b"different")
        self.assertEqual(self.store.get("artifact:one"), b"accepted")

    def test_inputs_require_exact_types_and_strict_stable_ids(self):
        invalid_data = (
            BytesSubclass(b"x"),
            BytearraySubclass(b"x"),
            [120],
            1,
            "x",
        )
        for data in invalid_data:
            with self.subTest(data_type=type(data).__name__):
                with self.assertRaisesRegex(ValueError, "^STORE_INVALID$"):
                    self.store.store("artifact:one", data)
        for store_id in ("", " artifact:one", "artifact:one ", StringSubclass("artifact:one")):
            with self.subTest(store_id_type=type(store_id).__name__):
                with self.assertRaisesRegex(ValueError, "^STORE_INVALID$"):
                    self.store.store(store_id, b"x")

    def test_errors_and_missing_reads_never_echo_hostile_ids_or_bytes(self):
        from authority_sim.stores import StoreMissing

        hostile = StringSubclass("SECRET_PATH_DIGEST_SENTINEL")
        with self.assertRaisesRegex(ValueError, "^STORE_INVALID$") as invalid:
            self.store.get(hostile)
        self.assertNotIn("SECRET_PATH_DIGEST_SENTINEL", str(invalid.exception))
        with self.assertRaisesRegex(StoreMissing, "^STORE_MISSING$") as missing:
            self.store.get("SECRET_PATH_DIGEST_SENTINEL")
        self.assertNotIn("SECRET_PATH_DIGEST_SENTINEL", str(missing.exception))

    def test_internal_state_is_slot_held_and_structurally_immutable(self):
        self.store.store("artifact:one", b"stable")
        self.assertFalse(hasattr(self.store, "__dict__"))
        self.assertFalse(hasattr(self.store, "_untrusted_storage"))
        self.assertFalse(hasattr(self.store, "_canonical_storage"))
        untrusted = object.__getattribute__(
            self.store,
            "_ImmutableStore__untrusted",
        )
        self.assertIsInstance(untrusted, tuple)
        with self.assertRaises(TypeError):
            untrusted[0] = ("artifact:one", b"mutated")
        with self.assertRaises(AttributeError):
            self.store._ImmutableStore__untrusted = ()
        self.assertEqual(self.store.get("artifact:one"), b"stable")

    def test_store_has_no_public_reset_update_or_raw_mapping_surface(self):
        for name in ("reset", "update", "reload", "save", "raw", "mapping"):
            self.assertFalse(hasattr(self.store, name))

    def test_source_has_no_filesystem_network_or_process_access(self):
        self.assertTrue(STORE_SOURCE.is_file())
        source = STORE_SOURCE.read_text(encoding="utf-8")
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
                {"os", "pathlib", "subprocess", "socket", "urllib"},
            ),
        )


if __name__ == "__main__":
    unittest.main()
