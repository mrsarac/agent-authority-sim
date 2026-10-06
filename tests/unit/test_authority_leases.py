from __future__ import annotations

import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.transitions import AuthorityState


OPERATOR_ID = "operator:demo"
POLICY_DIGEST = "sha256:" + ("c" * 64)
BASE_TIME = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def lease_bytes(
    *,
    lease_record_id: str,
    lease_id: str,
    authority_epoch: int,
    lease_generation: int,
    writer_id: str,
    lease_action: str,
    authorization_ref: str,
    expected_authority_state: str,
    issued_at: datetime,
    valid_from: datetime,
    expires_at: datetime,
    prior_authority_head: str | None,
    previous_lease_record_id: str | None,
    nonce_suffix: str,
    policy_digest: str = POLICY_DIGEST,
    operator_id: str = OPERATOR_ID,
) -> bytes:
    def stamp(value: datetime) -> str:
        if value.microsecond:
            return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    return canonical_bytes(
        {
            "kind": "authority_lease",
            "schema_version": "0.1.0",
            "operator_id": operator_id,
            "lease_record_id": lease_record_id,
            "lease_id": lease_id,
            "authority_epoch": authority_epoch,
            "lease_generation": lease_generation,
            "writer_id": writer_id,
            "lease_action": lease_action,
            "authorization_ref": authorization_ref,
            "expected_authority_state": expected_authority_state,
            "issued_at": stamp(issued_at),
            "valid_from": stamp(valid_from),
            "expires_at": stamp(expires_at),
            "policy_digest": policy_digest,
            "prior_authority_head": prior_authority_head,
            "previous_lease_record_id": previous_lease_record_id,
            "projection": "governor_only",
            "encoding_profile": "simulation_unsigned_v1",
            "nonce": f"lease_nonce_abcdefghijklmnopqrstuvwxyz_{nonce_suffix}",
        },
    )


def initial_lease_bytes(
    authorization_ref: str = "operator-decision:sim/initialize/01",
    *,
    operator_id: str = OPERATOR_ID,
) -> bytes:
    return lease_bytes(
        lease_record_id="lease-record_initialize01",
        lease_id="lease_initialize01",
        authority_epoch=1,
        lease_generation=1,
        writer_id="authority:writer-a",
        lease_action="acquire",
        authorization_ref=authorization_ref,
        expected_authority_state="UNINITIALIZED",
        issued_at=BASE_TIME - timedelta(seconds=1),
        valid_from=BASE_TIME,
        expires_at=BASE_TIME + timedelta(minutes=10),
        prior_authority_head=None,
        previous_lease_record_id=None,
        nonce_suffix="initialize01",
        operator_id=operator_id,
    )


def initialized_core():
    from authority_sim.authority_core import AuthorityCore, OperatorRecoveryPort

    core = AuthorityCore(OPERATOR_ID)
    authorization = OperatorRecoveryPort().authorize_initialization(
        "operator-decision:sim/initialize/01",
    )
    result = core.initialize(
        initial_lease_bytes(),
        authorization,
        expected_head=None,
        as_of=BASE_TIME,
    )
    if not result.accepted:
        raise AssertionError("test bootstrap failed")
    return core, result.snapshot


class TestAuthorityInitialization(unittest.TestCase):
    def test_schema_valid_nonzero_nanoseconds_deny_in_microsecond_clock_profile(self):
        from authority_sim.authority_core import AuthorityCore, OperatorRecoveryPort
        from authority_sim.contracts import validate_document
        from authority_sim.errors import ReasonCode

        document = json.loads(initial_lease_bytes())
        document["expires_at"] = "2026-08-16T12:10:00.000000001Z"
        validate_document(document)
        core = AuthorityCore(OPERATOR_ID)
        authorization = OperatorRecoveryPort().authorize_initialization(
            "operator-decision:sim/initialize/01",
        )

        denied = core.initialize(
            canonical_bytes(document),
            authorization,
            expected_head=None,
            as_of=BASE_TIME,
        )

        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.SCHEMA_INVALID)
        self.assertIs(denied.snapshot.state, AuthorityState.UNINITIALIZED)
        self.assertEqual(denied.snapshot.accepted_event_bytes, ())
        self.assertEqual(denied.snapshot.lease_record_bytes, ())

    def test_event_operator_is_bound_to_the_core_not_a_fixture_constant(self):
        from authority_sim.authority_core import AuthorityCore, OperatorRecoveryPort

        operator_id = "operator:alternate-demo"
        core = AuthorityCore(operator_id)
        authorization = OperatorRecoveryPort().authorize_initialization(
            "operator-decision:sim/initialize/01",
        )
        result = core.initialize(
            initial_lease_bytes(operator_id=operator_id),
            authorization,
            expected_head=None,
            as_of=BASE_TIME,
        )

        self.assertTrue(result.accepted)
        self.assertEqual(result.snapshot.operator_id, operator_id)
        for raw_event in result.snapshot.accepted_event_bytes:
            self.assertEqual(json.loads(raw_event)["operator_id"], operator_id)

    def test_verified_bootstrap_creates_epoch_one_lease_and_atomic_event_binding(self):
        from authority_sim.authority_core import AuthorityCore, OperatorRecoveryPort

        core = AuthorityCore(OPERATOR_ID)
        port = OperatorRecoveryPort()
        authorization = port.authorize_initialization(
            "operator-decision:sim/initialize/01",
        )
        raw_lease = initial_lease_bytes()

        result = core.initialize(
            raw_lease,
            authorization,
            expected_head=None,
            as_of=BASE_TIME,
        )

        self.assertTrue(result.accepted)
        self.assertIsNone(result.reason)
        snapshot = result.snapshot
        self.assertIs(snapshot.state, AuthorityState.ACTIVE)
        self.assertEqual(snapshot.authority_epoch, 1)
        self.assertEqual(snapshot.lease_generation, 1)
        self.assertEqual(snapshot.writer_id, "authority:writer-a")
        self.assertEqual(snapshot.lease_id, "lease_initialize01")
        self.assertEqual(snapshot.latest_lease_record_id, "lease-record_initialize01")
        self.assertEqual(snapshot.policy_digest, POLICY_DIGEST)
        self.assertEqual(snapshot.expires_at, BASE_TIME + timedelta(minutes=10))
        self.assertTrue(snapshot.promotion_eligible)
        self.assertEqual(snapshot.lease_record_bytes, (raw_lease,))
        self.assertEqual(len(snapshot.accepted_event_bytes), 2)

        first, second = tuple(json.loads(raw) for raw in snapshot.accepted_event_bytes)
        self.assertEqual(first["event_type"], "authority_initialized")
        self.assertEqual(first["sequence"], 1)
        self.assertIsNone(first["previous_event_digest"])
        self.assertEqual(first["transition"], {
            "state_machine": "authority",
            "expected_state": "UNINITIALIZED",
            "resulting_state": "ACTIVE",
        })
        self.assertEqual(second["event_type"], "lease_acquired")
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(second["previous_event_digest"], first["event_digest"])
        self.assertEqual(second["object_kind"], "authority_lease")
        self.assertEqual(second["object_ref"], "lease-record_initialize01")
        self.assertEqual(second["object_digest"], sha256_digest(raw_lease))
        self.assertEqual(second["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "ACTIVE",
        })
        self.assertEqual(snapshot.authority_head, second["event_digest"])

    def test_bootstrap_capability_and_public_results_are_frozen_and_redacted(self):
        from authority_sim.authority_core import AuthorityCore, OperatorRecoveryPort

        port = OperatorRecoveryPort()
        authorization = port.authorize_initialization(
            "operator-decision:sim/initialize/01",
        )
        core = AuthorityCore(OPERATOR_ID)
        result = core.initialize(
            initial_lease_bytes(),
            authorization,
            expected_head=None,
            as_of=BASE_TIME,
        )

        for value, expected_repr in (
            (authorization, "VerifiedOperatorAuthorization(...)"),
            (result, "AuthorityDecision(...)"),
            (result.snapshot, "AuthoritySnapshot(...)"),
        ):
            self.assertFalse(hasattr(value, "__dict__"))
            self.assertEqual(repr(value), expected_repr)
            self.assertIsInstance(hash(value), int)
        with self.assertRaises(FrozenInstanceError):
            result.snapshot.authority_epoch = 99
        self.assertFalse(hasattr(core, "__dict__"))
        for name in ("log", "store", "renew_lease_for_worker", "recover_from_string"):
            self.assertFalse(hasattr(core, name))


class TestAuthorityRenewal(unittest.TestCase):
    def test_same_term_renewal_extends_expiry_with_new_record_and_one_event(self):
        core, before = initialized_core()
        as_of = BASE_TIME + timedelta(minutes=5)
        raw_renewal = lease_bytes(
            lease_record_id="lease-record_renewal0001",
            lease_id=before.lease_id,
            authority_epoch=before.authority_epoch,
            lease_generation=before.lease_generation,
            writer_id=before.writer_id,
            lease_action="renew",
            authorization_ref="policy-decision:sim/renewal/01",
            expected_authority_state="ACTIVE",
            issued_at=as_of - timedelta(seconds=1),
            valid_from=as_of,
            expires_at=BASE_TIME + timedelta(minutes=20),
            prior_authority_head=before.authority_head,
            previous_lease_record_id=before.latest_lease_record_id,
            nonce_suffix="renewal0001",
        )

        result = core.renew(
            raw_renewal,
            expected_head=before.authority_head,
            as_of=as_of,
        )

        self.assertTrue(result.accepted)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.ACTIVE)
        self.assertEqual(after.authority_epoch, before.authority_epoch)
        self.assertEqual(after.lease_generation, before.lease_generation)
        self.assertEqual(after.writer_id, before.writer_id)
        self.assertEqual(after.lease_id, before.lease_id)
        self.assertEqual(after.policy_digest, before.policy_digest)
        self.assertEqual(after.latest_lease_record_id, "lease-record_renewal0001")
        self.assertEqual(after.expires_at, BASE_TIME + timedelta(minutes=20))
        self.assertEqual(after.lease_record_bytes, before.lease_record_bytes + (raw_renewal,))
        self.assertEqual(len(after.accepted_event_bytes), len(before.accepted_event_bytes) + 1)
        event = json.loads(after.accepted_event_bytes[-1])
        self.assertEqual(event["event_type"], "lease_renewed")
        self.assertEqual(event["object_ref"], "lease-record_renewal0001")
        self.assertEqual(event["object_digest"], sha256_digest(raw_renewal))
        self.assertEqual(event["previous_event_digest"], before.authority_head)
        self.assertEqual(event["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "ACTIVE",
        })
        self.assertEqual(after.authority_head, event["event_digest"])
        self.assertTrue(after.promotion_eligible)

    def test_renewal_stable_field_mutations_deny_without_changing_any_snapshot_byte(self):
        mutations = (
            ("writer", {"writer_id": "authority:writer-b"}),
            ("lease_id", {"lease_id": "lease_changed0001"}),
            ("epoch", {"authority_epoch": 2}),
            ("generation", {"lease_generation": 2}),
            ("policy", {"policy_digest": "sha256:" + ("d" * 64)}),
            ("previous_record", {"previous_lease_record_id": "lease-record_unknown01"}),
            ("prior_head", {"prior_authority_head": "sha256:" + ("0" * 64)}),
            ("expected_state", {"expected_authority_state": "NO_WRITER"}),
            ("record_replay", {"lease_record_id": "lease-record_initialize01"}),
            (
                "nonce_replay",
                {"nonce": "lease_nonce_abcdefghijklmnopqrstuvwxyz_initialize01"},
            ),
        )

        for case_id, updates in mutations:
            with self.subTest(case_id=case_id):
                core, initialized = initialized_core()
                as_of = BASE_TIME + timedelta(minutes=5)
                before = core.snapshot(as_of=as_of)
                raw = lease_bytes(
                    lease_record_id="lease-record_renewal0002",
                    lease_id=initialized.lease_id,
                    authority_epoch=initialized.authority_epoch,
                    lease_generation=initialized.lease_generation,
                    writer_id=initialized.writer_id,
                    lease_action="renew",
                    authorization_ref="policy-decision:sim/renewal/02",
                    expected_authority_state="ACTIVE",
                    issued_at=as_of - timedelta(seconds=1),
                    valid_from=as_of,
                    expires_at=BASE_TIME + timedelta(minutes=20),
                    prior_authority_head=initialized.authority_head,
                    previous_lease_record_id=initialized.latest_lease_record_id,
                    nonce_suffix="renewal0002",
                )
                document = json.loads(raw)
                document.update(updates)

                denied = core.renew(
                    canonical_bytes(document),
                    expected_head=initialized.authority_head,
                    as_of=as_of,
                )

                self.assertFalse(denied.accepted)
                self.assertEqual(denied.snapshot, before)
                self.assertEqual(repr(denied), "AuthorityDecision(...)")

        core, initialized = initialized_core()
        as_of = BASE_TIME + timedelta(minutes=5)
        before = core.snapshot(as_of=as_of)
        raw = lease_bytes(
            lease_record_id="lease-record_renewal0003",
            lease_id=initialized.lease_id,
            authority_epoch=initialized.authority_epoch,
            lease_generation=initialized.lease_generation,
            writer_id=initialized.writer_id,
            lease_action="renew",
            authorization_ref="policy-decision:sim/renewal/03",
            expected_authority_state="ACTIVE",
            issued_at=as_of - timedelta(seconds=1),
            valid_from=as_of,
            expires_at=BASE_TIME + timedelta(minutes=20),
            prior_authority_head=initialized.authority_head,
            previous_lease_record_id=initialized.latest_lease_record_id,
            nonce_suffix="renewal0003",
        )
        document = json.loads(raw)
        document["expires_at"] = json.loads(initialized.lease_record_bytes[-1])["expires_at"]
        denied = core.renew(
            canonical_bytes(document),
            expected_head=initialized.authority_head,
            as_of=as_of,
        )
        self.assertFalse(denied.accepted)
        self.assertEqual(denied.snapshot, before)


class TestAuthorityReissue(unittest.TestCase):
    def test_reissue_uses_new_lease_id_higher_generation_and_may_replace_writer(self):
        core, before = initialized_core()
        as_of = BASE_TIME + timedelta(minutes=2)
        raw_reissue = lease_bytes(
            lease_record_id="lease-record_reissue0001",
            lease_id="lease_reissue0001",
            authority_epoch=before.authority_epoch,
            lease_generation=before.lease_generation + 1,
            writer_id="authority:writer-b",
            lease_action="reissue",
            authorization_ref="policy-decision:sim/reissue/01",
            expected_authority_state="ACTIVE",
            issued_at=as_of - timedelta(seconds=1),
            valid_from=as_of,
            expires_at=BASE_TIME + timedelta(minutes=15),
            prior_authority_head=before.authority_head,
            previous_lease_record_id=before.latest_lease_record_id,
            nonce_suffix="reissue0001",
        )

        result = core.reissue(
            raw_reissue,
            expected_head=before.authority_head,
            as_of=as_of,
        )

        self.assertTrue(result.accepted)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.ACTIVE)
        self.assertEqual(after.authority_epoch, before.authority_epoch)
        self.assertEqual(after.lease_generation, before.lease_generation + 1)
        self.assertEqual(after.writer_id, "authority:writer-b")
        self.assertEqual(after.lease_id, "lease_reissue0001")
        self.assertEqual(after.latest_lease_record_id, "lease-record_reissue0001")
        self.assertEqual(after.policy_digest, before.policy_digest)
        event = json.loads(after.accepted_event_bytes[-1])
        self.assertEqual(event["event_type"], "lease_acquired")
        self.assertEqual(event["object_ref"], "lease-record_reissue0001")
        self.assertEqual(event["object_digest"], sha256_digest(raw_reissue))
        self.assertEqual(event["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "ACTIVE",
        })

    def test_reissue_term_mutations_and_expired_term_deny_without_state_change(self):
        mutations = (
            ("same_generation", {"lease_generation": 1}),
            ("skipped_generation", {"lease_generation": 3}),
            ("same_lease_id", {"lease_id": "lease_initialize01"}),
            ("changed_epoch", {"authority_epoch": 2}),
            ("changed_policy", {"policy_digest": "sha256:" + ("d" * 64)}),
            (
                "wrong_previous_record",
                {"previous_lease_record_id": "lease-record_unknown02"},
            ),
        )
        for case_id, updates in mutations:
            with self.subTest(case_id=case_id):
                core, initialized = initialized_core()
                as_of = BASE_TIME + timedelta(minutes=2)
                before = core.snapshot(as_of=as_of)
                raw = lease_bytes(
                    lease_record_id="lease-record_reissue0004",
                    lease_id="lease_reissue0004",
                    authority_epoch=1,
                    lease_generation=2,
                    writer_id="authority:writer-b",
                    lease_action="reissue",
                    authorization_ref="policy-decision:sim/reissue/04",
                    expected_authority_state="ACTIVE",
                    issued_at=as_of - timedelta(seconds=1),
                    valid_from=as_of,
                    expires_at=BASE_TIME + timedelta(minutes=15),
                    prior_authority_head=initialized.authority_head,
                    previous_lease_record_id=initialized.latest_lease_record_id,
                    nonce_suffix="reissue0004",
                )
                document = json.loads(raw)
                document.update(updates)
                denied = core.reissue(
                    canonical_bytes(document),
                    expected_head=initialized.authority_head,
                    as_of=as_of,
                )
                self.assertFalse(denied.accepted)
                self.assertEqual(denied.snapshot, before)

        core, initialized = initialized_core()
        expires_at = initialized.expires_at
        self.assertIsNotNone(expires_at)
        before = core.snapshot(as_of=expires_at)
        raw = lease_bytes(
            lease_record_id="lease-record_reissue0005",
            lease_id="lease_reissue0005",
            authority_epoch=1,
            lease_generation=2,
            writer_id="authority:writer-b",
            lease_action="reissue",
            authorization_ref="policy-decision:sim/reissue/05",
            expected_authority_state="ACTIVE",
            issued_at=expires_at - timedelta(seconds=1),
            valid_from=expires_at,
            expires_at=expires_at + timedelta(minutes=10),
            prior_authority_head=initialized.authority_head,
            previous_lease_record_id=initialized.latest_lease_record_id,
            nonce_suffix="reissue0005",
        )
        denied = core.reissue(
            raw,
            expected_head=initialized.authority_head,
            as_of=expires_at,
        )
        self.assertFalse(denied.accepted)
        self.assertEqual(denied.snapshot, before)


class TestAuthorityRelease(unittest.TestCase):
    def test_current_binding_release_enters_no_writer_without_new_lease_record(self):
        from authority_sim.authority_core import AuthorityBinding

        core, before = initialized_core()
        binding = AuthorityBinding(
            authority_epoch=before.authority_epoch,
            lease_generation=before.lease_generation,
            writer_id=before.writer_id,
            lease_id=before.lease_id,
            policy_digest=before.policy_digest,
        )
        as_of = BASE_TIME + timedelta(minutes=2)

        result = core.release(
            binding,
            expected_head=before.authority_head,
            as_of=as_of,
        )

        self.assertTrue(result.accepted)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.NO_WRITER)
        self.assertFalse(after.promotion_eligible)
        self.assertEqual(after.authority_epoch, before.authority_epoch)
        self.assertEqual(after.lease_generation, before.lease_generation)
        self.assertEqual(after.lease_record_bytes, before.lease_record_bytes)
        self.assertEqual(after.latest_lease_record_id, before.latest_lease_record_id)
        self.assertEqual(len(after.accepted_event_bytes), len(before.accepted_event_bytes) + 1)
        event = json.loads(after.accepted_event_bytes[-1])
        self.assertEqual(event["event_type"], "lease_released")
        self.assertEqual(event["object_ref"], before.latest_lease_record_id)
        self.assertEqual(event["object_digest"], sha256_digest(before.lease_record_bytes[-1]))
        self.assertEqual(event["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "NO_WRITER",
        })


class TestAuthorityAcquisition(unittest.TestCase):
    def test_verified_acquisition_after_release_uses_higher_epoch_generation_one(self):
        from authority_sim.authority_core import AuthorityBinding, OperatorRecoveryPort
        from authority_sim.errors import ReasonCode

        core, initial = initialized_core()
        binding = AuthorityBinding(
            authority_epoch=initial.authority_epoch,
            lease_generation=initial.lease_generation,
            writer_id=initial.writer_id,
            lease_id=initial.lease_id,
            policy_digest=initial.policy_digest,
        )
        release = core.release(
            binding,
            expected_head=initial.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertTrue(release.accepted)
        before = release.snapshot
        as_of = BASE_TIME + timedelta(minutes=2)
        authorization_ref = "operator-decision:sim/acquire/02"
        authorization = OperatorRecoveryPort().authorize_acquisition(
            authorization_ref,
            authority_epoch=2,
        )
        raw_acquisition = lease_bytes(
            lease_record_id="lease-record_acquire0002",
            lease_id="lease_acquire0002",
            authority_epoch=2,
            lease_generation=1,
            writer_id="authority:writer-b",
            lease_action="acquire",
            authorization_ref=authorization_ref,
            expected_authority_state="NO_WRITER",
            issued_at=as_of - timedelta(seconds=1),
            valid_from=as_of,
            expires_at=BASE_TIME + timedelta(minutes=20),
            prior_authority_head=before.authority_head,
            previous_lease_record_id=before.latest_lease_record_id,
            nonce_suffix="acquire0002",
        )

        raw_denial = core.acquire(
            raw_acquisition,
            authorization_ref,
            expected_head=before.authority_head,
            as_of=as_of,
        )
        self.assertFalse(raw_denial.accepted)
        self.assertIs(raw_denial.reason, ReasonCode.AUTHORITY_STALE)
        self.assertEqual(raw_denial.snapshot, before)

        result = core.acquire(
            raw_acquisition,
            authorization,
            expected_head=before.authority_head,
            as_of=as_of,
        )

        self.assertTrue(result.accepted)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.ACTIVE)
        self.assertEqual(after.authority_epoch, 2)
        self.assertEqual(after.lease_generation, 1)
        self.assertEqual(after.writer_id, "authority:writer-b")
        self.assertEqual(after.lease_id, "lease_acquire0002")
        event = json.loads(after.accepted_event_bytes[-1])
        self.assertEqual(event["event_type"], "lease_acquired")
        self.assertEqual(event["object_digest"], sha256_digest(raw_acquisition))
        self.assertEqual(event["transition"], {
            "state_machine": "authority",
            "expected_state": "NO_WRITER",
            "resulting_state": "ACTIVE",
        })


class TestAuthorityExpiry(unittest.TestCase):
    def test_exact_expiry_is_no_writer_without_synthetic_append(self):
        from authority_sim.authority_core import AuthorityBinding
        from authority_sim.errors import ReasonCode

        core, before = initialized_core()
        binding = AuthorityBinding(
            authority_epoch=before.authority_epoch,
            lease_generation=before.lease_generation,
            writer_id=before.writer_id,
            lease_id=before.lease_id,
            policy_digest=before.policy_digest,
        )
        expires_at = before.expires_at
        self.assertIsNotNone(expires_at)

        eligible = core.check_promotion(
            binding,
            expected_head=before.authority_head,
            as_of=expires_at - timedelta(microseconds=1),
        )
        expired = core.check_promotion(
            binding,
            expected_head=before.authority_head,
            as_of=expires_at,
        )

        self.assertTrue(eligible.accepted)
        self.assertIs(eligible.snapshot.state, AuthorityState.ACTIVE)
        self.assertFalse(expired.accepted)
        self.assertIs(expired.reason, ReasonCode.LEASE_EXPIRED)
        self.assertIs(expired.snapshot.state, AuthorityState.NO_WRITER)
        for snapshot in (eligible.snapshot, expired.snapshot):
            self.assertEqual(snapshot.authority_head, before.authority_head)
            self.assertEqual(snapshot.accepted_event_bytes, before.accepted_event_bytes)
            self.assertEqual(snapshot.lease_record_bytes, before.lease_record_bytes)
            self.assertEqual(snapshot.log_projection_bytes, before.log_projection_bytes)


class TestAuthorityRecovery(unittest.TestCase):
    def test_only_verified_contradiction_can_enter_recovery_required(self):
        from authority_sim.authority_core import AuthorityVerifierPort
        from authority_sim.errors import ReasonCode

        evidence_ref = "evidence:authority-contradiction:01"
        evidence_bytes = canonical_bytes(
            {
                "class": "authority_tuple_conflict",
                "left": "sha256:" + ("1" * 64),
                "right": "sha256:" + ("2" * 64),
            },
        )

        raw_core, raw_before = initialized_core()
        raw_result = raw_core.record_contradiction(
            evidence_bytes,
            expected_head=raw_before.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertFalse(raw_result.accepted)
        self.assertIs(raw_result.reason, ReasonCode.AUTHORITY_STALE)
        self.assertEqual(raw_result.snapshot, raw_before)

        core, before = initialized_core()
        verified = AuthorityVerifierPort().verify_contradiction(
            evidence_ref,
            evidence_bytes,
        )
        result = core.record_contradiction(
            verified,
            expected_head=before.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )

        self.assertTrue(result.accepted)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.RECOVERY_REQUIRED)
        self.assertFalse(after.promotion_eligible)
        self.assertEqual(after.lease_record_bytes, before.lease_record_bytes)
        event = json.loads(after.accepted_event_bytes[-1])
        self.assertEqual(event["event_type"], "recovery_started")
        self.assertEqual(event["object_kind"], "authority")
        self.assertEqual(event["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "RECOVERY_REQUIRED",
        })
        object_map = dict(after.canonical_object_bytes)
        authority_object = object_map[event["object_ref"]]
        self.assertEqual(event["object_digest"], sha256_digest(authority_object))
        self.assertEqual(
            json.loads(authority_object)["evidence_digest"],
            sha256_digest(evidence_bytes),
        )

    def test_raw_recovery_ref_denies_and_verified_recovery_binds_evidence_and_lease(self):
        from authority_sim.authority_core import AuthorityVerifierPort, OperatorRecoveryPort
        from authority_sim.errors import ReasonCode

        contradiction_bytes = canonical_bytes({"conflict": "verified"})
        core, initial = initialized_core()
        contradiction = AuthorityVerifierPort().verify_contradiction(
            "evidence:authority-contradiction:02",
            contradiction_bytes,
        )
        entered = core.record_contradiction(
            contradiction,
            expected_head=initial.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertTrue(entered.accepted)
        before = entered.snapshot
        as_of = BASE_TIME + timedelta(minutes=2)
        authorization_ref = "operator-decision:sim/recovery/02"
        restore_ref = "restore-evidence:verified:02"
        restore_bytes = canonical_bytes(
            {
                "authorization_ref": authorization_ref,
                "recovery_epoch": 2,
                "verification": "complete",
            },
        )
        raw_recovery_lease = lease_bytes(
            lease_record_id="lease-record_recovery0002",
            lease_id="lease_recovery0002",
            authority_epoch=2,
            lease_generation=1,
            writer_id="authority:writer-b",
            lease_action="recovery",
            authorization_ref=authorization_ref,
            expected_authority_state="RECOVERY_REQUIRED",
            issued_at=as_of - timedelta(seconds=1),
            valid_from=as_of,
            expires_at=BASE_TIME + timedelta(minutes=20),
            prior_authority_head=before.authority_head,
            previous_lease_record_id=before.latest_lease_record_id,
            nonce_suffix="recovery0002",
        )

        raw_denial = core.recover(
            raw_recovery_lease,
            authorization_ref,
            expected_head=before.authority_head,
            as_of=as_of,
        )
        self.assertFalse(raw_denial.accepted)
        self.assertIs(raw_denial.reason, ReasonCode.AUTHORITY_STALE)
        self.assertEqual(raw_denial.snapshot, before)

        authorization = OperatorRecoveryPort().authorize_recovery(
            authorization_ref,
            recovery_epoch=2,
            restore_evidence_ref=restore_ref,
            restore_evidence_bytes=restore_bytes,
        )
        result = core.recover(
            raw_recovery_lease,
            authorization,
            expected_head=before.authority_head,
            as_of=as_of,
        )

        self.assertTrue(result.accepted)
        after = result.snapshot
        self.assertIs(after.state, AuthorityState.ACTIVE)
        self.assertEqual(after.authority_epoch, 2)
        self.assertEqual(after.lease_generation, 1)
        self.assertEqual(after.writer_id, "authority:writer-b")
        self.assertEqual(after.lease_id, "lease_recovery0002")
        self.assertEqual(after.lease_record_bytes, before.lease_record_bytes + (raw_recovery_lease,))
        first, second = tuple(json.loads(raw) for raw in after.accepted_event_bytes[-2:])
        self.assertEqual(first["event_type"], "restore_verified")
        self.assertEqual(first["object_ref"], restore_ref)
        self.assertEqual(first["object_digest"], sha256_digest(restore_bytes))
        self.assertEqual(first["transition"], {
            "state_machine": "authority",
            "expected_state": "RECOVERY_REQUIRED",
            "resulting_state": "ACTIVE",
        })
        self.assertEqual(second["event_type"], "lease_acquired")
        self.assertEqual(second["previous_event_digest"], first["event_digest"])
        self.assertEqual(second["object_digest"], sha256_digest(raw_recovery_lease))
        self.assertEqual(second["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "ACTIVE",
        })


class TestAuthorityHalt(unittest.TestCase):
    def test_verified_operator_halt_is_terminal_for_promotion_until_restore(self):
        from authority_sim.authority_core import AuthorityBinding, OperatorRecoveryPort
        from authority_sim.errors import ReasonCode

        core, before = initialized_core()
        authorization_ref = "operator-decision:sim/halt/01"
        authorization = OperatorRecoveryPort().authorize_halt(
            authorization_ref,
            authority_epoch=before.authority_epoch,
        )

        raw_denial = core.halt(
            authorization_ref,
            expected_head=before.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertFalse(raw_denial.accepted)
        self.assertIs(raw_denial.reason, ReasonCode.AUTHORITY_STALE)
        self.assertEqual(raw_denial.snapshot, before)

        result = core.halt(
            authorization,
            expected_head=before.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )

        self.assertTrue(result.accepted)
        halted = result.snapshot
        self.assertIs(halted.state, AuthorityState.HALTED)
        self.assertFalse(halted.promotion_eligible)
        event = json.loads(halted.accepted_event_bytes[-1])
        self.assertEqual(event["event_type"], "authority_halted")
        self.assertEqual(event["object_kind"], "authority")
        self.assertEqual(event["transition"], {
            "state_machine": "authority",
            "expected_state": "ACTIVE",
            "resulting_state": "HALTED",
        })

        binding = AuthorityBinding(
            authority_epoch=halted.authority_epoch,
            lease_generation=halted.lease_generation,
            writer_id=halted.writer_id,
            lease_id=halted.lease_id,
            policy_digest=halted.policy_digest,
        )
        denied = core.check_promotion(
            binding,
            expected_head=halted.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertFalse(denied.accepted)
        self.assertIs(denied.reason, ReasonCode.RECOVERY_REQUIRED)
        self.assertEqual(denied.snapshot, halted)

    def test_verified_restore_recovers_from_halted_with_higher_epoch_lease(self):
        from authority_sim.authority_core import OperatorRecoveryPort

        core, initial = initialized_core()
        port = OperatorRecoveryPort()
        halted_result = core.halt(
            port.authorize_halt(
                "operator-decision:sim/halt/02",
                authority_epoch=1,
            ),
            expected_head=initial.authority_head,
            as_of=BASE_TIME + timedelta(minutes=1),
        )
        self.assertTrue(halted_result.accepted)
        halted = halted_result.snapshot
        as_of = BASE_TIME + timedelta(minutes=2)
        authorization_ref = "operator-decision:sim/recovery/03"
        restore_ref = "restore-evidence:verified:03"
        restore_bytes = canonical_bytes({"halt_restore": "verified"})
        authorization = port.authorize_recovery(
            authorization_ref,
            recovery_epoch=2,
            restore_evidence_ref=restore_ref,
            restore_evidence_bytes=restore_bytes,
        )
        raw_lease = lease_bytes(
            lease_record_id="lease-record_recovery0003",
            lease_id="lease_recovery0003",
            authority_epoch=2,
            lease_generation=1,
            writer_id="authority:writer-c",
            lease_action="recovery",
            authorization_ref=authorization_ref,
            expected_authority_state="HALTED",
            issued_at=as_of - timedelta(seconds=1),
            valid_from=as_of,
            expires_at=BASE_TIME + timedelta(minutes=20),
            prior_authority_head=halted.authority_head,
            previous_lease_record_id=halted.latest_lease_record_id,
            nonce_suffix="recovery0003",
        )

        recovered = core.recover(
            raw_lease,
            authorization,
            expected_head=halted.authority_head,
            as_of=as_of,
        )

        self.assertTrue(recovered.accepted)
        self.assertIs(recovered.snapshot.state, AuthorityState.ACTIVE)
        self.assertEqual(recovered.snapshot.authority_epoch, 2)
        first, second = tuple(
            json.loads(raw) for raw in recovered.snapshot.accepted_event_bytes[-2:]
        )
        self.assertEqual(first["event_type"], "restore_verified")
        self.assertEqual(first["transition"]["expected_state"], "HALTED")
        self.assertEqual(first["transition"]["resulting_state"], "ACTIVE")
        self.assertEqual(second["event_type"], "lease_acquired")
        self.assertEqual(second["previous_event_digest"], first["event_digest"])


if __name__ == "__main__":
    unittest.main()
