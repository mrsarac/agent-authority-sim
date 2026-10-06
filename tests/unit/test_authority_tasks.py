from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.errors import ReasonCode
from authority_sim.transitions import AuthorityState

from tests.unit.test_authority_leases import BASE_TIME, initialized_core


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "spec" / "v0.1.0" / "valid-contracts.json"


def _valid_documents() -> list[dict[str, object]]:
    return json.loads(VALID.read_text(encoding="utf-8"))["documents"]


def _base_task_document() -> dict[str, object]:
    return copy.deepcopy(
        next(
            document
            for document in _valid_documents()
            if document["kind"] == "task_envelope"
        ),
    )


def _base_claim_document() -> dict[str, object]:
    return copy.deepcopy(
        next(
            document
            for document in _valid_documents()
            if document["kind"] == "capability_claim"
        ),
    )


def _task_and_claim_bytes(authority_head: str) -> tuple[bytes, bytes]:
    task = _base_task_document()
    claim = _base_claim_document()

    task.update(
        {
            "authority_epoch": 1,
            "lease_generation": 1,
            "issued_at": "2026-08-16T12:00:00Z",
            "expires_at": "2026-08-16T12:05:00Z",
            "expected_authority_head": authority_head,
            "task_id": "task_issued0001",
            "capability_id": "cap_issued0001",
            "idempotency_key": "task.issue:issued0001",
            "nonce": "task_nonce_abcdefghijklmnopqrstuvwxyz_issued0001",
        },
    )
    claim.update(
        {
            "capability_id": "cap_issued0001",
            "parent_capability_id": None,
            "task_id": "task_issued0001",
            "authority_epoch": 1,
            "lease_generation": 1,
            "issuer_id": "authority:writer-a",
            "valid_from": "2026-08-16T12:00:00Z",
            "expires_at": "2026-08-16T12:05:00Z",
            "delegation_depth": 0,
            "revocation_id": "revoke_issued0001",
            "nonce": "capability_nonce_abcdefghijklmnopqrstuv_issued0001",
        },
    )
    return canonical_bytes(task), canonical_bytes(claim)


class TestAtomicTaskIssuance(unittest.TestCase):
    def test_initial_capability_is_bound_to_current_writer_and_task_plan(self):
        from authority_sim.authority_core import AuthorityTaskPort

        mutations = (
            ("issuer", {"issuer_id": "authority:forged-writer"}),
            (
                "action",
                {"allowed_actions": ["read_artifact", "network_egress"]},
            ),
            (
                "input",
                {
                    "allowed_input_artifact_ids": [
                        "artifact_01fixture",
                        "artifact_02foreign",
                    ]
                },
            ),
            ("egress", {"egress_aliases": ["egress:foreign-route"]}),
            ("handle", {"broker_handle_refs": ["broker-handle:FOREIGN0001"]}),
            (
                "budget",
                {
                    "resource_bounds": {
                        "max_wall_ms": 60000,
                        "max_tool_calls": 21,
                        "max_output_bytes": 65536,
                        "max_fresh_input_tokens": 8000,
                        "max_output_tokens": 2000,
                        "max_network_requests": 0,
                        "max_processes": 2,
                    }
                },
            ),
        )

        for case_id, update in mutations:
            with self.subTest(case_id=case_id):
                core, before = initialized_core()
                task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
                claim = json.loads(claim_bytes)
                claim.update(update)

                decision = AuthorityTaskPort().issue_task(
                    core,
                    task_bytes,
                    canonical_bytes(claim),
                    expected_head=before.authority_head,
                    as_of=BASE_TIME,
                )

                self.assertFalse(decision.accepted)
                self.assertIn(
                    decision.reason,
                    (ReasonCode.AUTHORITY_STALE, ReasonCode.SCOPE_EXCEEDED),
                )
                self.assertEqual(decision.snapshot, before)

    def test_issue_task_commits_task_and_initial_capability_in_one_batch(self):
        from authority_sim.authority_core import AuthorityRestoreVerifierPort, AuthorityTaskPort

        core, before = initialized_core()
        task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
        port = AuthorityTaskPort()

        result = port.issue_task(
            core,
            task_bytes,
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
        )

        self.assertTrue(result.accepted)
        self.assertFalse(result.fault_reported)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.ACTIVE)
        self.assertEqual(
            after.accepted_event_bytes[-2:],
            result.accepted_event_bytes,
        )
        self.assertEqual(
            dict(after.canonical_object_bytes)["task_issued0001"],
            task_bytes,
        )
        self.assertEqual(
            dict(after.canonical_object_bytes)["cap_issued0001"],
            claim_bytes,
        )
        task_event = json.loads(result.accepted_event_bytes[0])
        claim_event = json.loads(result.accepted_event_bytes[1])
        self.assertEqual(task_event["event_type"], "task_issued")
        self.assertEqual(claim_event["event_type"], "capability_issued")
        self.assertEqual(claim_event["previous_event_digest"], task_event["event_digest"])

        restore = AuthorityRestoreVerifierPort().verify_restore_state(
            canonical_object_bytes=after.canonical_object_bytes,
            accepted_event_bytes=after.accepted_event_bytes,
        )
        self.assertTrue(restore.accepted)
        self.assertFalse(restore.append_attempted)

    def test_pre_swap_faults_publish_neither_object_nor_event(self):
        from authority_sim.authority_log import FaultPoint
        from authority_sim.authority_core import AuthorityTaskPort

        for fault in (FaultPoint.BEFORE_STAGE, FaultPoint.BETWEEN_STAGE_RECORDS):
            core, before = initialized_core()
            task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
            port = AuthorityTaskPort()

            with self.subTest(fault=fault.name):
                result = port.issue_task(
                    core,
                    task_bytes,
                    claim_bytes,
                    expected_head=before.authority_head,
                    as_of=BASE_TIME,
                    fault=fault,
                )

                self.assertFalse(result.accepted)
                self.assertTrue(result.fault_reported)
                self.assertIs(result.reason, ReasonCode.ACCEPTANCE_FAILED)
                self.assertEqual(result.snapshot, before)

    def test_after_swap_fault_reports_fault_but_both_events_are_accepted(self):
        from authority_sim.authority_log import FaultPoint
        from authority_sim.authority_core import AuthorityTaskPort

        core, before = initialized_core()
        task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
        port = AuthorityTaskPort()

        reported = port.issue_task(
            core,
            task_bytes,
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
            fault=FaultPoint.AFTER_SWAP,
        )

        self.assertTrue(reported.accepted)
        self.assertTrue(reported.fault_reported)
        self.assertEqual(len(reported.accepted_event_bytes), 2)
        accepted = reported.snapshot
        self.assertEqual(
            accepted.accepted_event_bytes[-2:],
            reported.accepted_event_bytes,
        )
        self.assertEqual(
            dict(accepted.canonical_object_bytes)["task_issued0001"],
            task_bytes,
        )
        self.assertEqual(
            dict(accepted.canonical_object_bytes)["cap_issued0001"],
            claim_bytes,
        )

        replay = port.issue_task(
            core,
            task_bytes,
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
        )
        self.assertTrue(replay.accepted)
        self.assertFalse(replay.fault_reported)
        self.assertEqual(replay.snapshot, accepted)

    def test_byte_different_same_identity_or_key_denies_without_state_change(self):
        from authority_sim.authority_core import AuthorityTaskPort

        core, before = initialized_core()
        task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
        port = AuthorityTaskPort()
        first = port.issue_task(
            core,
            task_bytes,
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
        )
        self.assertTrue(first.accepted)
        accepted = first.snapshot

        mutated_task = json.loads(task_bytes)
        mutated_task["goal"] = "Different bytes, same task identity."
        denied = port.issue_task(
            core,
            canonical_bytes(mutated_task),
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
        )

        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.REPLAY_DETECTED)
        self.assertEqual(denied.snapshot, accepted)

    def test_restore_verifier_classifies_an_accepted_orphan_half_as_recovery_required(self):
        from authority_sim.authority_core import AuthorityRestoreVerifierPort, AuthorityTaskPort

        core, before = initialized_core()
        task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
        result = AuthorityTaskPort().issue_task(
            core,
            task_bytes,
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
        )
        self.assertTrue(result.accepted)
        accepted = result.snapshot
        orphan_objects = tuple(
            entry
            for entry in accepted.canonical_object_bytes
            if entry[0] != "cap_issued0001"
        )
        orphan_events = accepted.accepted_event_bytes[:-1]

        verdict = AuthorityRestoreVerifierPort().verify_restore_state(
            canonical_object_bytes=orphan_objects,
            accepted_event_bytes=orphan_events,
        )

        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.append_attempted)
        self.assertIs(verdict.reason, ReasonCode.RECOVERY_REQUIRED)

    def test_restore_verifier_classifies_digest_consistent_schema_corruption_as_recovery(self):
        from authority_sim.authority_core import AuthorityRestoreVerifierPort, AuthorityTaskPort

        core, before = initialized_core()
        task_bytes, claim_bytes = _task_and_claim_bytes(before.authority_head)
        result = AuthorityTaskPort().issue_task(
            core,
            task_bytes,
            claim_bytes,
            expected_head=before.authority_head,
            as_of=BASE_TIME,
        )
        self.assertTrue(result.accepted)

        corrupted_task = canonical_bytes({"kind": "task_envelope"})
        objects = list(result.snapshot.canonical_object_bytes)
        objects[-2] = (objects[-2][0], corrupted_task)
        events = [json.loads(raw) for raw in result.snapshot.accepted_event_bytes]
        task_event_index = len(events) - 2
        events[task_event_index]["object_digest"] = sha256_digest(corrupted_task)
        task_event_body = dict(events[task_event_index])
        task_event_body.pop("event_digest")
        events[task_event_index]["event_digest"] = sha256_digest(
            canonical_bytes(task_event_body)
        )
        events[task_event_index + 1]["previous_event_digest"] = events[
            task_event_index
        ]["event_digest"]
        claim_event_body = dict(events[task_event_index + 1])
        claim_event_body.pop("event_digest")
        events[task_event_index + 1]["event_digest"] = sha256_digest(
            canonical_bytes(claim_event_body)
        )

        verdict = AuthorityRestoreVerifierPort().verify_restore_state(
            canonical_object_bytes=tuple(objects),
            accepted_event_bytes=tuple(canonical_bytes(event) for event in events),
        )

        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.append_attempted)
        self.assertIs(verdict.reason, ReasonCode.RECOVERY_REQUIRED)


if __name__ == "__main__":
    unittest.main()
