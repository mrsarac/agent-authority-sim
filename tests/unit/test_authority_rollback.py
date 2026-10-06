from __future__ import annotations

import json
import unittest
from datetime import timedelta

from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.errors import ReasonCode
from authority_sim.transitions import AuthorityState

from tests.unit.test_authority_leases import BASE_TIME, initialized_core, lease_bytes


def _restamp_event(raw: bytes, observed_at: str) -> bytes:
    document = json.loads(raw)
    document["observed_at"] = observed_at
    document["event_digest"] = "sha256:" + ("0" * 64)
    body = dict(document)
    body.pop("event_digest")
    document["event_digest"] = sha256_digest(canonical_bytes(body))
    return canonical_bytes(document)


class TestAuthorityRollback(unittest.TestCase):
    def test_backward_accepted_observed_at_classifies_restore_as_recovery_required(self):
        from authority_sim.authority_core import AuthorityRestoreVerifierPort

        core, accepted = initialized_core()
        backward_second = _restamp_event(
            accepted.accepted_event_bytes[1],
            "2026-08-16T11:59:59Z",
        )

        verdict = AuthorityRestoreVerifierPort().verify_restore_state(
            canonical_object_bytes=accepted.canonical_object_bytes,
            accepted_event_bytes=(
                accepted.accepted_event_bytes[0],
                backward_second,
            ),
        )

        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.append_attempted)
        self.assertIs(verdict.reason, ReasonCode.RECOVERY_REQUIRED)
        self.assertEqual(core.snapshot(as_of=BASE_TIME), accepted)

    def test_digest_consistent_schema_corrupt_lease_requires_recovery(self):
        from authority_sim.authority_core import AuthorityRestoreVerifierPort

        _core, accepted = initialized_core()
        lease_record_id = accepted.latest_lease_record_id
        if type(lease_record_id) is not str:
            raise AssertionError("initialized snapshot has no lease record")
        corrupt = canonical_bytes({"kind": "authority_lease"})
        objects = list(accepted.canonical_object_bytes)
        object_index = next(
            index
            for index, (object_ref, _object_bytes) in enumerate(objects)
            if object_ref == lease_record_id
        )
        objects[object_index] = (lease_record_id, corrupt)

        events = [json.loads(raw) for raw in accepted.accepted_event_bytes]
        event_index = next(
            index
            for index, event in enumerate(events)
            if event["object_ref"] == lease_record_id
        )
        events[event_index]["object_digest"] = sha256_digest(corrupt)
        body = dict(events[event_index])
        body.pop("event_digest")
        events[event_index]["event_digest"] = sha256_digest(canonical_bytes(body))

        verdict = AuthorityRestoreVerifierPort().verify_restore_state(
            canonical_object_bytes=tuple(objects),
            accepted_event_bytes=tuple(canonical_bytes(event) for event in events),
        )

        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.append_attempted)
        self.assertIs(verdict.reason, ReasonCode.RECOVERY_REQUIRED)

    def test_release_blocks_promotion_until_higher_epoch_verified_acquisition(self):
        from authority_sim.authority_core import AuthorityBinding, OperatorRecoveryPort

        core, initial = initialized_core()
        binding = AuthorityBinding(
            authority_epoch=initial.authority_epoch,
            lease_generation=initial.lease_generation,
            writer_id=initial.writer_id,
            lease_id=initial.lease_id,
            policy_digest=initial.policy_digest,
        )
        released = core.release(
            binding,
            expected_head=initial.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertTrue(released.accepted)
        after_release = released.snapshot
        self.assertIs(after_release.state, AuthorityState.NO_WRITER)

        denied = core.check_promotion(
            binding,
            expected_head=after_release.authority_head,
            as_of=BASE_TIME + timedelta(minutes=2),
        )
        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.AUTHORITY_STALE)
        self.assertIs(denied.snapshot.state, AuthorityState.NO_WRITER)

        port = OperatorRecoveryPort()
        wrong_epoch = core.acquire(
            lease_bytes(
                lease_record_id="lease-record_acquire-same01",
                lease_id="lease_acquire-same01",
                authority_epoch=1,
                lease_generation=1,
                writer_id="authority:writer-b",
                lease_action="acquire",
                authorization_ref="operator-decision:sim/acquire/same01",
                expected_authority_state="NO_WRITER",
                issued_at=BASE_TIME + timedelta(minutes=1),
                valid_from=BASE_TIME + timedelta(minutes=2),
                expires_at=BASE_TIME + timedelta(minutes=20),
                prior_authority_head=after_release.authority_head,
                previous_lease_record_id=after_release.latest_lease_record_id,
                nonce_suffix="acquiresame01",
            ),
            port.authorize_acquisition(
                "operator-decision:sim/acquire/same01",
                authority_epoch=1,
            ),
            expected_head=after_release.authority_head,
            as_of=BASE_TIME + timedelta(minutes=2),
        )
        self.assertFalse(wrong_epoch.accepted)
        self.assertIs(wrong_epoch.reason, ReasonCode.AUTHORITY_STALE)
        self.assertEqual(wrong_epoch.snapshot, after_release)

        recovered = core.acquire(
            lease_bytes(
                lease_record_id="lease-record_acquire-high01",
                lease_id="lease_acquire-high01",
                authority_epoch=2,
                lease_generation=1,
                writer_id="authority:writer-b",
                lease_action="acquire",
                authorization_ref="operator-decision:sim/acquire/high01",
                expected_authority_state="NO_WRITER",
                issued_at=BASE_TIME + timedelta(minutes=1),
                valid_from=BASE_TIME + timedelta(minutes=2),
                expires_at=BASE_TIME + timedelta(minutes=20),
                prior_authority_head=after_release.authority_head,
                previous_lease_record_id=after_release.latest_lease_record_id,
                nonce_suffix="acquirehigh01",
            ),
            port.authorize_acquisition(
                "operator-decision:sim/acquire/high01",
                authority_epoch=2,
            ),
            expected_head=after_release.authority_head,
            as_of=BASE_TIME + timedelta(minutes=2),
        )
        self.assertTrue(recovered.accepted)
        self.assertEqual(recovered.snapshot.authority_epoch, 2)
        self.assertIs(recovered.snapshot.state, AuthorityState.ACTIVE)


if __name__ == "__main__":
    unittest.main()
