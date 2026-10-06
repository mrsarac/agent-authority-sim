from __future__ import annotations

import ast
import inspect
import unittest
from datetime import timedelta

import authority_sim.authority_core as authority_core
from authority_sim.authority_core import (
    AuthorityBinding,
    AuthorityCore,
    AuthorityVerifierPort,
    OperatorRecoveryPort,
)
from authority_sim.canonical import canonical_bytes
from authority_sim.errors import ReasonCode
from authority_sim.transitions import (
    AuthorityState,
    AuthorityTransitionEvent,
    TransitionDecision,
    authority_transition,
)
from tests.unit.test_authority_leases import (
    BASE_TIME,
    initialized_core,
    lease_bytes,
)


def binding_for(snapshot) -> AuthorityBinding:
    if (
        type(snapshot.authority_epoch) is not int
        or type(snapshot.lease_generation) is not int
        or type(snapshot.writer_id) is not str
        or type(snapshot.lease_id) is not str
        or type(snapshot.policy_digest) is not str
    ):
        raise AssertionError("authority snapshot is not bound")
    return AuthorityBinding(
        authority_epoch=snapshot.authority_epoch,
        lease_generation=snapshot.lease_generation,
        writer_id=snapshot.writer_id,
        lease_id=snapshot.lease_id,
        policy_digest=snapshot.policy_digest,
    )


def core_at_epoch_two_generation_two():
    core, initial = initialized_core()
    initial_binding = binding_for(initial)
    contradiction = AuthorityVerifierPort().verify_contradiction(
        "evidence:p01:authority-conflict",
        canonical_bytes({"case": "P01", "conflict": "two-active-writers"}),
    )
    recovery_required = core.record_contradiction(
        contradiction,
        expected_head=initial.authority_head,
        as_of=BASE_TIME + timedelta(minutes=1),
    )
    if not recovery_required.accepted:
        raise AssertionError("failed to enter recovery")

    recovery_time = BASE_TIME + timedelta(minutes=2)
    recovery_ref = "operator-decision:sim/P01/recovery"
    restore_ref = "restore-evidence:P01:verified"
    restore_bytes = canonical_bytes(
        {"case": "P01", "recovery_epoch": 2, "status": "verified"},
    )
    recovery_authorization = OperatorRecoveryPort().authorize_recovery(
        recovery_ref,
        recovery_epoch=2,
        restore_evidence_ref=restore_ref,
        restore_evidence_bytes=restore_bytes,
    )
    recovered = core.recover(
        lease_bytes(
            lease_record_id="lease-record_p01recovery02",
            lease_id="lease_p01recovery02",
            authority_epoch=2,
            lease_generation=1,
            writer_id="authority:writer-b",
            lease_action="recovery",
            authorization_ref=recovery_ref,
            expected_authority_state="RECOVERY_REQUIRED",
            issued_at=recovery_time - timedelta(seconds=1),
            valid_from=recovery_time,
            expires_at=BASE_TIME + timedelta(minutes=30),
            prior_authority_head=recovery_required.snapshot.authority_head,
            previous_lease_record_id=recovery_required.snapshot.latest_lease_record_id,
            nonce_suffix="p01recovery02",
        ),
        recovery_authorization,
        expected_head=recovery_required.snapshot.authority_head,
        as_of=recovery_time,
    )
    if not recovered.accepted:
        raise AssertionError("failed recovery")

    reissue_time = BASE_TIME + timedelta(minutes=3)
    reissued = core.reissue(
        lease_bytes(
            lease_record_id="lease-record_p01reissue02",
            lease_id="lease_p01reissue02",
            authority_epoch=2,
            lease_generation=2,
            writer_id="authority:writer-b",
            lease_action="reissue",
            authorization_ref="policy-decision:sim/P01/reissue",
            expected_authority_state="ACTIVE",
            issued_at=reissue_time - timedelta(seconds=1),
            valid_from=reissue_time,
            expires_at=BASE_TIME + timedelta(minutes=30),
            prior_authority_head=recovered.snapshot.authority_head,
            previous_lease_record_id=recovered.snapshot.latest_lease_record_id,
            nonce_suffix="p01reissue02",
        ),
        expected_head=recovered.snapshot.authority_head,
        as_of=reissue_time,
    )
    if not reissued.accepted:
        raise AssertionError("failed reissue")
    return core, initial_binding, reissued.snapshot, reissue_time


class TestP01AuthorityFencing(unittest.TestCase):
    def test_only_latest_epoch_generation_writer_and_lease_is_promotion_eligible(self):
        core, stale_writer_a, current, as_of = core_at_epoch_two_generation_two()
        before = core.snapshot(as_of=as_of)

        old_decision = core.check_promotion(
            stale_writer_a,
            expected_head=current.authority_head,
            as_of=as_of,
        )
        current_decision = core.check_promotion(
            binding_for(current),
            expected_head=current.authority_head,
            as_of=as_of,
        )

        self.assertFalse(old_decision.accepted)
        self.assertIs(old_decision.reason, ReasonCode.AUTHORITY_STALE)
        self.assertTrue(current_decision.accepted)
        self.assertEqual(sum(item.accepted for item in (old_decision, current_decision)), 1)
        self.assertEqual(old_decision.snapshot, before)
        self.assertEqual(current_decision.snapshot, before)
        self.assertEqual(core.snapshot(as_of=as_of), before)
        print("P01 authority fencing: eligible=1 denied=1 state_change=0")

    def test_every_emitted_authority_event_matches_the_closed_transition_matrix(self):
        core, _, current, _ = core_at_epoch_two_generation_two()
        event_map = {
            "authority_initialized": AuthorityTransitionEvent.AUTHORITY_INITIALIZED,
            "lease_acquired": AuthorityTransitionEvent.LEASE_ACQUIRED,
            "lease_renewed": AuthorityTransitionEvent.LEASE_RENEWED,
            "lease_released": AuthorityTransitionEvent.LEASE_RELEASED,
            "recovery_started": AuthorityTransitionEvent.RECOVERY_STARTED,
            "restore_verified": AuthorityTransitionEvent.RESTORE_VERIFIED,
            "authority_halted": AuthorityTransitionEvent.AUTHORITY_HALTED,
        }

        for raw_event in current.accepted_event_bytes:
            document = __import__("json").loads(raw_event)
            event_type = document["event_type"]
            with self.subTest(sequence=document["sequence"], event_type=event_type):
                semantic_event = event_map[event_type]
                expected = AuthorityState(document["transition"]["expected_state"])
                result = authority_transition(expected, semantic_event)
                self.assertIsInstance(result, TransitionDecision)
                self.assertTrue(result.allowed)
                self.assertEqual(
                    result.resulting_state.value,
                    document["transition"]["resulting_state"],
                )


class TestP02AuthorityPredicateTable(unittest.TestCase):
    def test_every_mismatched_authority_predicate_denies_without_state_change(self):
        core, _, current, active_as_of = core_at_epoch_two_generation_two()
        valid = binding_for(current)
        if current.expires_at is None:
            raise AssertionError("current lease lacks expiry")

        cases = (
            (
                "lower_epoch",
                AuthorityBinding(
                    current.authority_epoch - 1,
                    current.lease_generation,
                    current.writer_id,
                    current.lease_id,
                    current.policy_digest,
                ),
                current.authority_head,
                active_as_of,
                ReasonCode.AUTHORITY_STALE,
            ),
            (
                "lower_generation",
                AuthorityBinding(
                    current.authority_epoch,
                    current.lease_generation - 1,
                    current.writer_id,
                    current.lease_id,
                    current.policy_digest,
                ),
                current.authority_head,
                active_as_of,
                ReasonCode.AUTHORITY_STALE,
            ),
            (
                "writer_mismatch",
                AuthorityBinding(
                    current.authority_epoch,
                    current.lease_generation,
                    "authority:writer-z",
                    current.lease_id,
                    current.policy_digest,
                ),
                current.authority_head,
                active_as_of,
                ReasonCode.AUTHORITY_STALE,
            ),
            (
                "lease_mismatch",
                AuthorityBinding(
                    current.authority_epoch,
                    current.lease_generation,
                    current.writer_id,
                    "lease_mismatch0001",
                    current.policy_digest,
                ),
                current.authority_head,
                active_as_of,
                ReasonCode.AUTHORITY_STALE,
            ),
            (
                "policy_mismatch",
                AuthorityBinding(
                    current.authority_epoch,
                    current.lease_generation,
                    current.writer_id,
                    current.lease_id,
                    "sha256:" + ("d" * 64),
                ),
                current.authority_head,
                active_as_of,
                ReasonCode.POLICY_MISMATCH,
            ),
            (
                "expired",
                valid,
                current.authority_head,
                current.expires_at,
                ReasonCode.LEASE_EXPIRED,
            ),
            (
                "stale_expected_head",
                valid,
                "sha256:" + ("0" * 64),
                active_as_of,
                ReasonCode.EXPECTED_HEAD_MISMATCH,
            ),
        )

        for case_id, binding, expected_head, as_of, expected_reason in cases:
            with self.subTest(case_id=case_id):
                before = core.snapshot(as_of=as_of)
                denied = core.check_promotion(
                    binding,
                    expected_head=expected_head,
                    as_of=as_of,
                )
                after = core.snapshot(as_of=as_of)

                self.assertFalse(denied.accepted)
                self.assertIs(denied.reason, expected_reason)
                self.assertEqual(denied.snapshot, before)
                self.assertEqual(after, before)
                self.assertEqual(after.authority_head, before.authority_head)
                self.assertEqual(after.accepted_event_bytes, before.accepted_event_bytes)
                self.assertEqual(after.lease_record_bytes, before.lease_record_bytes)
                self.assertEqual(after.canonical_object_bytes, before.canonical_object_bytes)
                self.assertEqual(after.log_projection_bytes, before.log_projection_bytes)
                self.assertEqual(repr(denied), "AuthorityDecision(...)")
        print("P02 authority predicate cases=7 denied=7 state_change=0")


class _Hostile:
    __slots__ = ("calls",)

    def __init__(self) -> None:
        self.calls = 0

    def __eq__(self, other):
        self.calls += 1
        raise AssertionError("hostile equality called")

    def __hash__(self):
        self.calls += 1
        raise AssertionError("hostile hash called")

    def __repr__(self):
        self.calls += 1
        raise AssertionError("hostile repr called")

    def __str__(self):
        self.calls += 1
        raise AssertionError("hostile str called")


class TestAuthorityCoreBoundaries(unittest.TestCase):
    def test_hostile_and_cross_type_inputs_deny_before_dispatch_without_echo(self):
        core, _, current, as_of = core_at_epoch_two_generation_two()
        hostile = _Hostile()
        result = core.check_promotion(
            hostile,
            expected_head=current.authority_head,
            as_of=as_of,
        )

        self.assertFalse(result.accepted)
        self.assertIs(result.reason, ReasonCode.AUTHORITY_STALE)
        self.assertEqual(hostile.calls, 0)
        self.assertEqual(repr(result), "AuthorityDecision(...)")
        self.assertNotIn("hostile", repr(result).lower())

    def test_core_has_no_public_append_store_or_ambient_capability(self):
        core = AuthorityCore("operator:surface-audit")
        public_callables = {
            name
            for name in dir(core)
            if not name.startswith("_") and callable(getattr(core, name))
        }
        self.assertEqual(
            public_callables,
            {
                "acquire",
                "check_promotion",
                "halt",
                "initialize",
                "record_contradiction",
                "recover",
                "reissue",
                "release",
                "renew",
                "snapshot",
            },
        )
        for forbidden in (
            "append",
            "compare_and_append",
            "log",
            "store",
            "authority_log",
            "object_store",
        ):
            self.assertFalse(hasattr(core, forbidden))

        source = inspect.getsource(authority_core)
        tree = ast.parse(source)
        forbidden_imports = {
            "asyncio",
            "http",
            "os",
            "pathlib",
            "random",
            "secrets",
            "shutil",
            "socket",
            "subprocess",
            "time",
            "urllib",
        }
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertFalse(imported_roots & forbidden_imports)

        forbidden_calls = {"eval", "exec", "input", "open"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, forbidden_calls)
            if isinstance(node, ast.Attribute) and node.attr in {
                "now",
                "sleep",
                "system",
                "time",
                "urandom",
            }:
                self.fail(f"ambient attribute found: {node.attr}")

        public_mutables = {
            name: value
            for name, value in vars(authority_core).items()
            if not name.startswith("_")
            and isinstance(value, (bytearray, dict, list, set))
        }
        self.assertEqual(public_mutables, {})


if __name__ == "__main__":
    unittest.main()
