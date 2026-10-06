from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

from authority_sim.canonical import canonical_bytes
from authority_sim.errors import ReasonCode
from authority_sim.transitions import AuthorityState


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "spec" / "v0.1.0" / "valid-contracts.json"
AS_OF = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
POLICY_DIGEST = "sha256:" + ("c" * 64)


def _valid_documents() -> list[dict[str, object]]:
    return json.loads(VALID.read_text(encoding="utf-8"))["documents"]


def _base_claim() -> dict[str, object]:
    return copy.deepcopy(
        next(
            document
            for document in _valid_documents()
            if document["kind"] == "capability_claim"
        ),
    )


def _parent_claim_bytes() -> bytes:
    document = _base_claim()
    document.update(
        {
            "capability_id": "cap_parent0001",
            "parent_capability_id": None,
            "task_id": "task_parent0001",
            "authority_epoch": 1,
            "lease_generation": 1,
            "policy_digest": POLICY_DIGEST,
            "workspace_ref": "workspace:proof",
            "allowed_actions": ["read_artifact", "run_test"],
            "allowed_input_artifact_ids": ["artifact_input0001", "artifact_input0002"],
            "egress_aliases": ["egress:alpha-route", "egress:beta-route"],
            "broker_handle_refs": [
                "broker-handle:HANDLE0001",
                "broker-handle:HANDLE0002",
            ],
            "resource_bounds": {
                "max_wall_ms": 60000,
                "max_tool_calls": 20,
                "max_output_bytes": 65536,
                "max_fresh_input_tokens": 8000,
                "max_output_tokens": 2000,
                "max_network_requests": 0,
                "max_processes": 2,
            },
            "valid_from": "2026-08-16T12:00:00Z",
            "expires_at": "2026-08-16T12:10:00Z",
            "revocation_id": "revoke_parent0001",
            "delegation_depth": 0,
            "nonce": "capability_nonce_parent_abcdefghijklmnopqrstuv_0001",
        },
    )
    return canonical_bytes(document)


def _child_claim_bytes() -> bytes:
    document = _base_claim()
    document.update(
        {
            "capability_id": "cap_child0001",
            "parent_capability_id": "cap_parent0001",
            "task_id": "task_parent0001",
            "authority_epoch": 1,
            "lease_generation": 1,
            "policy_digest": POLICY_DIGEST,
            "workspace_ref": "workspace:proof",
            "allowed_actions": ["read_artifact"],
            "allowed_input_artifact_ids": ["artifact_input0001"],
            "egress_aliases": ["egress:alpha-route"],
            "broker_handle_refs": ["broker-handle:HANDLE0001"],
            "resource_bounds": {
                "max_wall_ms": 30000,
                "max_tool_calls": 10,
                "max_output_bytes": 32768,
                "max_fresh_input_tokens": 4000,
                "max_output_tokens": 1000,
                "max_network_requests": 0,
                "max_processes": 1,
            },
            "valid_from": "2026-08-16T12:00:00Z",
            "expires_at": "2026-08-16T12:05:00Z",
            "revocation_id": "revoke_child0001",
            "delegation_depth": 1,
            "nonce": "capability_nonce_child_abcdefghijklmnopqrstuv_0001",
        },
    )
    return canonical_bytes(document)


class TestCapabilityBroker(unittest.TestCase):
    def test_child_claim_must_attenuate_and_raise_delegation_depth(self):
        from authority_sim.capabilities import (
            CapabilityAction,
            CapabilityAttempt,
            CapabilityBroker,
            CapabilityState,
        )

        broker = CapabilityBroker()
        parent = broker.register_claim(_parent_claim_bytes(), as_of=AS_OF)
        child = broker.register_claim(_child_claim_bytes(), as_of=AS_OF)

        self.assertTrue(parent.accepted)
        self.assertTrue(child.accepted)
        self.assertIs(child.snapshot.state, CapabilityState.ISSUED)
        allowed = broker.authorize(
            "cap_child0001",
            attempt=CapabilityAttempt.RUN_START,
            action=CapabilityAction.READ_ARTIFACT,
            input_artifact_ids=("artifact_input0001",),
            egress_aliases=("egress:alpha-route",),
            broker_handle_refs=("broker-handle:HANDLE0001",),
            operator_id="operator:demo",
            task_id="task_parent0001",
            workspace_ref="workspace:proof",
            authority_epoch=1,
            lease_generation=1,
            policy_digest=POLICY_DIGEST,
            as_of=AS_OF,
        )
        self.assertTrue(allowed.accepted)
        self.assertIs(allowed.snapshot.state, CapabilityState.ACTIVE)

    def test_widening_and_binding_mismatches_deny_generically(self):
        from authority_sim.capabilities import CapabilityBroker

        broker = CapabilityBroker()
        accepted = broker.register_claim(_parent_claim_bytes(), as_of=AS_OF)
        self.assertTrue(accepted.accepted)

        mutations = (
            ("action", {"allowed_actions": ["read_artifact", "run_test", "execute_process"]}),
            ("input", {"allowed_input_artifact_ids": ["artifact_input0001", "artifact_input0002", "artifact_input0003"]}),
            ("egress", {"egress_aliases": ["egress:alpha-route", "egress:beta-route", "egress:gamma-route"]}),
            ("handle", {"broker_handle_refs": ["broker-handle:HANDLE0001", "broker-handle:HANDLE0002", "broker-handle:HANDLE0003"]}),
            ("wall", {"resource_bounds": {"max_wall_ms": 60001, "max_tool_calls": 10, "max_output_bytes": 32768, "max_fresh_input_tokens": 4000, "max_output_tokens": 1000, "max_network_requests": 0, "max_processes": 1}}),
            ("workspace", {"workspace_ref": "workspace:other"}),
            ("operator", {"operator_id": "operator:other-demo"}),
            ("task", {"task_id": "task_other0001"}),
            ("epoch", {"authority_epoch": 2}),
            ("generation", {"lease_generation": 2}),
            ("policy", {"policy_digest": "sha256:" + ("d" * 64)}),
            ("depth", {"delegation_depth": 0}),
        )

        for case_id, updates in mutations:
            with self.subTest(case_id=case_id):
                document = json.loads(_child_claim_bytes())
                document.update(updates)
                denied = broker.register_claim(
                    canonical_bytes(document),
                    as_of=AS_OF,
                )
                self.assertFalse(denied.accepted)
                self.assertIn(
                    denied.reason,
                    (ReasonCode.SCOPE_EXCEEDED, ReasonCode.CAPABILITY_INVALID),
                )

    def test_revocation_is_terminal_across_paths_and_no_bypass_flag_resurrects(self):
        from authority_sim.capabilities import (
            CapabilityAction,
            CapabilityAttempt,
            CapabilityBroker,
        )

        broker = CapabilityBroker()
        accepted = broker.register_claim(_parent_claim_bytes(), as_of=AS_OF)
        self.assertTrue(accepted.accepted)
        revoked = broker.revoke("cap_parent0001", as_of=AS_OF)
        self.assertTrue(revoked.accepted)

        for attempt in (
            CapabilityAttempt.RUN_START,
            CapabilityAttempt.RECEIPT_VERIFY,
            CapabilityAttempt.PROMOTION,
            CapabilityAttempt.RECONNECT,
        ):
            with self.subTest(attempt=attempt.name):
                denied = broker.authorize(
                    "cap_parent0001",
                    attempt=attempt,
                    action=CapabilityAction.READ_ARTIFACT,
                    input_artifact_ids=("artifact_input0001",),
                    egress_aliases=("egress:alpha-route",),
                    broker_handle_refs=("broker-handle:HANDLE0001",),
                    operator_id="operator:demo",
                    task_id="task_parent0001",
                    workspace_ref="workspace:proof",
                    authority_epoch=1,
                    lease_generation=1,
                    policy_digest=POLICY_DIGEST,
                    as_of=AS_OF,
                    urgency="urgent",
                    confidence="certain",
                )
                self.assertFalse(denied.accepted)
                self.assertIs(denied.reason, ReasonCode.CAPABILITY_REVOKED)

        replay = broker.register_claim(_parent_claim_bytes(), as_of=AS_OF)
        self.assertFalse(replay.accepted)
        self.assertIs(replay.reason, ReasonCode.CAPABILITY_REVOKED)

    def test_parent_revocation_blocks_existing_descendant_and_replay(self):
        from authority_sim.capabilities import (
            CapabilityAction,
            CapabilityAttempt,
            CapabilityBroker,
        )

        broker = CapabilityBroker()
        self.assertTrue(broker.register_claim(_parent_claim_bytes(), as_of=AS_OF).accepted)
        self.assertTrue(broker.register_claim(_child_claim_bytes(), as_of=AS_OF).accepted)
        self.assertTrue(broker.revoke("cap_parent0001", as_of=AS_OF).accepted)

        denied = broker.authorize(
            "cap_child0001",
            attempt=CapabilityAttempt.RUN_START,
            action=CapabilityAction.READ_ARTIFACT,
            input_artifact_ids=("artifact_input0001",),
            egress_aliases=("egress:alpha-route",),
            broker_handle_refs=("broker-handle:HANDLE0001",),
            operator_id="operator:demo",
            task_id="task_parent0001",
            workspace_ref="workspace:proof",
            authority_epoch=1,
            lease_generation=1,
            policy_digest=POLICY_DIGEST,
            as_of=AS_OF,
        )
        replay = broker.register_claim(_child_claim_bytes(), as_of=AS_OF)

        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.CAPABILITY_REVOKED)
        self.assertFalse(replay.accepted)
        self.assertIs(replay.reason, ReasonCode.CAPABILITY_REVOKED)

    def test_malformed_claim_returns_generic_denial_without_snapshot_or_exception(self):
        from authority_sim.capabilities import CapabilityBroker

        denied = CapabilityBroker().register_claim(
            b'{"not":"a capability claim"}',
            as_of=AS_OF,
        )

        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.CAPABILITY_INVALID)
        self.assertIsNone(denied.snapshot)

    def test_public_surface_is_exact_frozen_and_cross_enum_safe(self):
        from authority_sim.capabilities import CapabilityBroker

        broker = CapabilityBroker()
        accepted = broker.register_claim(_parent_claim_bytes(), as_of=AS_OF)
        self.assertTrue(accepted.accepted)
        self.assertFalse(hasattr(accepted, "__dict__"))
        self.assertFalse(hasattr(accepted.snapshot, "__dict__"))
        self.assertEqual(repr(accepted), "CapabilityDecision(...)")
        self.assertEqual(repr(accepted.snapshot), "CapabilitySnapshot(...)")
        with self.assertRaises(FrozenInstanceError):
            accepted.snapshot.delegation_depth = 9

        denied = broker.authorize(
            "cap_parent0001",
            attempt=AuthorityState.ACTIVE,
            action="read_artifact",
            input_artifact_ids=("artifact_input0001",),
            egress_aliases=("egress:alpha-route",),
            broker_handle_refs=("broker-handle:HANDLE0001",),
            operator_id="operator:demo",
            task_id="task_parent0001",
            workspace_ref="workspace:proof",
            authority_epoch=1,
            lease_generation=1,
            policy_digest=POLICY_DIGEST,
            as_of=AS_OF,
        )
        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.CAPABILITY_INVALID)


if __name__ == "__main__":
    unittest.main()
