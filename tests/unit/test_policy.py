from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from authority_sim.canonical import canonical_bytes
from authority_sim.errors import ReasonCode
from authority_sim.transitions import AuthorityState, PolicyState


def _policy_bytes(version: int, label: str) -> bytes:
    return canonical_bytes(
        {
            "policy_key": "policy:sim-proof",
            "policy_version": version,
            "ruleset": label,
        },
    )


class TestPolicyFloor(unittest.TestCase):
    def test_standard_activation_rejects_foreign_policy_lineage(self):
        from authority_sim.policy import OperatorPolicyPort, PolicyActor, PolicyFloor, PolicyStub

        floor = PolicyFloor()
        port = OperatorPolicyPort()
        auth = port.authorize_activation(
            "policy-decision:sim/policy/lineage",
            authority_epoch=1,
        )
        first = floor.apply(
            PolicyStub.from_bytes(_policy_bytes(1, "alpha")),
            actor=PolicyActor.OPERATOR,
            authorization=auth,
        )
        foreign = PolicyStub.from_bytes(
            canonical_bytes(
                {
                    "policy_key": "policy:foreign",
                    "policy_version": 2,
                    "ruleset": "beta",
                }
            )
        )
        denied = floor.apply(
            foreign,
            actor=PolicyActor.OPERATOR,
            authorization=auth,
        )

        self.assertTrue(first.accepted)
        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.POLICY_MISMATCH)
        self.assertEqual(denied.snapshot, first.snapshot)

    def test_activation_is_monotonic_and_same_bytes_replay_is_idempotent(self):
        from authority_sim.policy import OperatorPolicyPort, PolicyActor, PolicyFloor, PolicyStub

        floor = PolicyFloor()
        port = OperatorPolicyPort()
        policy_v1 = PolicyStub.from_bytes(_policy_bytes(1, "alpha"))
        policy_v2 = PolicyStub.from_bytes(_policy_bytes(2, "beta"))
        same_version_different_digest = PolicyStub.from_bytes(_policy_bytes(2, "beta-alt"))
        auth = port.authorize_activation("policy-decision:sim/policy/01", authority_epoch=1)

        first = floor.apply(policy_v1, actor=PolicyActor.OPERATOR, authorization=auth)
        replay = floor.apply(policy_v1, actor=PolicyActor.OPERATOR, authorization=auth)
        second = floor.apply(policy_v2, actor=PolicyActor.OPERATOR, authorization=auth)
        lower = floor.apply(policy_v1, actor=PolicyActor.OPERATOR, authorization=auth)
        conflict = floor.apply(
            same_version_different_digest,
            actor=PolicyActor.OPERATOR,
            authorization=auth,
        )

        self.assertTrue(first.accepted)
        self.assertTrue(replay.accepted)
        self.assertTrue(second.accepted)
        self.assertIs(first.snapshot.state, PolicyState.ACTIVE)
        self.assertEqual(first.snapshot.active_version, 1)
        self.assertEqual(second.snapshot.active_version, 2)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertFalse(lower.accepted)
        self.assertFalse(conflict.accepted)
        self.assertIs(lower.reason, ReasonCode.POLICY_MISMATCH)
        self.assertIs(conflict.reason, ReasonCode.POLICY_MISMATCH)

    def test_only_verified_higher_epoch_recovery_authorization_may_cross_the_floor(self):
        from authority_sim.policy import OperatorPolicyPort, PolicyActor, PolicyFloor, PolicyStub

        floor = PolicyFloor()
        port = OperatorPolicyPort()
        policy_v1 = PolicyStub.from_bytes(_policy_bytes(1, "alpha"))
        policy_v2 = PolicyStub.from_bytes(_policy_bytes(2, "beta"))
        activate = port.authorize_activation("policy-decision:sim/policy/02", authority_epoch=1)
        entered = floor.apply(policy_v2, actor=PolicyActor.OPERATOR, authorization=activate)
        self.assertTrue(entered.accepted)
        before = entered.snapshot

        for actor in (
            PolicyActor.WORKER,
            PolicyActor.COORDINATOR,
            PolicyActor.RESTORE,
            PolicyActor.REPLAY,
        ):
            with self.subTest(actor=actor.name):
                denied = floor.apply(policy_v1, actor=actor, authorization=activate)
                self.assertFalse(denied.accepted)
                self.assertIs(denied.reason, ReasonCode.POLICY_MISMATCH)
                self.assertEqual(denied.snapshot, before)

        raw_denied = floor.apply(policy_v1, actor=PolicyActor.OPERATOR, authorization="recover policy please")
        self.assertFalse(raw_denied.accepted)
        self.assertIs(raw_denied.reason, ReasonCode.SCHEMA_INVALID)

        recovery = port.authorize_recovery("policy-decision:sim/policy-recovery/02", authority_epoch=2)
        foreign_policy = PolicyStub.from_bytes(
            canonical_bytes(
                {
                    "policy_key": "policy:foreign",
                    "policy_version": 1,
                    "ruleset": "foreign",
                }
            )
        )
        foreign_denied = floor.apply(
            foreign_policy,
            actor=PolicyActor.OPERATOR,
            authorization=recovery,
        )
        self.assertFalse(foreign_denied.accepted)
        self.assertIs(foreign_denied.reason, ReasonCode.POLICY_MISMATCH)
        self.assertEqual(foreign_denied.snapshot, before)

        recovered = floor.apply(policy_v1, actor=PolicyActor.OPERATOR, authorization=recovery)
        self.assertTrue(recovered.accepted)
        self.assertEqual(recovered.snapshot.active_version, 1)
        self.assertEqual(recovered.snapshot.authority_epoch, 2)

    def test_public_surface_is_frozen_and_exact_enum_safe(self):
        from authority_sim.policy import OperatorPolicyPort, PolicyFloor, PolicyStub

        floor = PolicyFloor()
        port = OperatorPolicyPort()
        policy = PolicyStub.from_bytes(_policy_bytes(1, "alpha"))
        accepted = floor.apply(
            policy,
            actor=AuthorityState.ACTIVE,
            authorization=port.authorize_activation(
                "policy-decision:sim/policy/03",
                authority_epoch=1,
            ),
        )
        self.assertFalse(accepted.accepted)
        self.assertIs(accepted.reason, ReasonCode.SCHEMA_INVALID)

        first = floor.apply(
            policy,
            actor=__import__("authority_sim.policy", fromlist=["PolicyActor"]).PolicyActor.OPERATOR,
            authorization=port.authorize_activation(
                "policy-decision:sim/policy/04",
                authority_epoch=1,
            ),
        )
        self.assertTrue(first.accepted)
        self.assertFalse(hasattr(first, "__dict__"))
        self.assertFalse(hasattr(first.snapshot, "__dict__"))
        self.assertFalse(hasattr(policy, "__dict__"))
        self.assertEqual(repr(first), "PolicyDecision(...)")
        self.assertEqual(repr(first.snapshot), "PolicySnapshot(...)")
        self.assertEqual(repr(policy), "PolicyStub(...)")
        with self.assertRaises(FrozenInstanceError):
            first.snapshot.active_version = 9


if __name__ == "__main__":
    unittest.main()
