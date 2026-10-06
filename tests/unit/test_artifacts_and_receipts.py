from __future__ import annotations

import ast
import copy
import json
import unittest
from dataclasses import FrozenInstanceError, fields
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "spec" / "v0.1.0" / "valid-contracts.json"
ARTIFACTS_SOURCE = ROOT / "src" / "authority_sim" / "artifacts.py"
RECEIPTS_SOURCE = ROOT / "src" / "authority_sim" / "receipts.py"


def _documents() -> dict[str, dict]:
    documents = json.loads(VALID.read_text(encoding="utf-8"))["documents"]
    return {document["kind"]: copy.deepcopy(document) for document in documents}


def _records():
    from authority_sim.records import create_record

    return {
        kind: create_record(document)
        for kind, document in _documents().items()
    }


def _artifact_bytes() -> bytes:
    return b'{"summary":"ok"}'


def _artifact_digest() -> str:
    from authority_sim.canonical import sha256_digest

    return sha256_digest(_artifact_bytes())


def _manifest_with_content(content_digest: str, byte_length: int):
    from authority_sim.records import create_record

    document = _documents()["artifact_manifest"]
    document["content_digest"] = content_digest
    document["byte_length"] = byte_length
    return create_record(document)


def _manifest_digest(manifest) -> str:
    from authority_sim.canonical import canonical_bytes, sha256_digest

    return sha256_digest(canonical_bytes(manifest.to_document()))


def _artifact_pin(manifest):
    from authority_sim.records import FrozenObject

    return FrozenObject(
        (
            ("artifact_id", manifest.artifact_id),
            ("content_digest", manifest.content_digest),
            ("manifest_digest", _manifest_digest(manifest)),
        )
    )


def _receipt_for_manifest(manifest):
    from authority_sim.records import create_record

    document = _documents()["execution_receipt"]
    document["artifact_refs"][0]["content_digest"] = manifest.content_digest
    document["artifact_refs"][0]["manifest_digest"] = _manifest_digest(manifest)
    return create_record(document)


class TestArtifactVerification(unittest.TestCase):
    def test_red_bare_artifact_id_without_content_or_manifest_pin(self):
        from authority_sim.records import FrozenObject

        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        records = _records()
        content = _artifact_bytes()
        manifest = _manifest_with_content(
            _artifact_digest(),
            len(content),
        )
        store = ArtifactStore()
        store.capture(manifest, content, accepted=True)

        verifier = ArtifactVerifier(store)
        pin = FrozenObject((("artifact_id", manifest.artifact_id),))

        decision = verifier.verify(
            manifest=manifest,
            pin=pin,
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=records["task_envelope"].acceptance_checks,
            observations=records["execution_receipt"].observations,
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "ARTIFACT_MISMATCH")

    def test_red_substituted_bytes_same_artifact_id_are_denied(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)

        verifier = ArtifactVerifier(store)
        decision = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
            submitted_bytes=b'{"summary":"tampered"}',
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "ARTIFACT_MISMATCH")

    def test_rejects_wrong_manifest_digest_even_if_content_digest_matches(self):
        from authority_sim.canonical import sha256_digest
        from authority_sim.records import FrozenObject

        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)
        wrong_pin = FrozenObject(
            (
                ("artifact_id", manifest.artifact_id),
                ("content_digest", sha256_digest(_artifact_bytes())),
                ("manifest_digest", "sha256:" + ("0" * 64)),
            )
        )

        decision = verifier.verify(
            manifest=manifest,
            pin=wrong_pin,
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "ARTIFACT_MISMATCH")

    def test_failed_semantic_acceptance_or_missing_evidence_denies(self):
        from authority_sim.records import FrozenObject

        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)

        failed_observations = (
            FrozenObject(
                (
                    ("category", "test"),
                    ("evidence_artifact_id", manifest.artifact_id),
                    ("observation_id", "obs_01schema"),
                    ("status", "fail"),
                    ("summary_code", "SCHEMA_INVALID"),
                    ("trust_class", _records()["execution_receipt"].observations[1].get("trust_class")),
                )
            ),
        )

        failed = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=failed_observations,
        )
        missing = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=(_records()["execution_receipt"].observations[0],),
        )

        self.assertFalse(failed.accepted)
        self.assertFalse(missing.accepted)
        self.assertEqual(failed.denied.code.name, "ACCEPTANCE_FAILED")
        self.assertEqual(missing.denied.code.name, "ACCEPTANCE_FAILED")

    def test_one_observation_cannot_satisfy_two_required_checks(self):
        from authority_sim.records import create_record

        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        documents = _documents()
        documents["task_envelope"]["acceptance_checks"].append(
            {
                "check_id": "check_hash",
                "check_type": "hash",
                "minimum_trust_class": "governor_observed",
                "required": True,
                "target_ref": "artifact:summary",
            }
        )
        task = create_record(documents["task_envelope"])
        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)

        decision = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=task.acceptance_checks,
            observations=(_records()["execution_receipt"].observations[1],),
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "ACCEPTANCE_FAILED")

    def test_cross_binding_or_wrong_length_denies(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()) + 1,
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)

        wrong_length = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
        )
        cross_run = verifier.verify(
            manifest=_records()["artifact_manifest"],
            pin=_records()["execution_receipt"].artifact_refs[0],
            operator_id=_records()["artifact_manifest"].operator_id,
            task_id=_records()["artifact_manifest"].task_id,
            run_id="run_02foreign",
            node_id=_records()["artifact_manifest"].producer.node_id,
            process_id=_records()["artifact_manifest"].producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
        )

        self.assertFalse(wrong_length.accepted)
        self.assertFalse(cross_run.accepted)
        self.assertEqual(wrong_length.denied.code.name, "ARTIFACT_MISMATCH")
        self.assertEqual(cross_run.denied.code.name, "IDENTITY_MISMATCH")

    def test_untrusted_conflict_is_quarantined_without_recovery(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=False)
        store.capture(manifest, b'{"summary":"conflict"}', accepted=False)
        verifier = ArtifactVerifier(store)

        decision = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
        )

        self.assertFalse(decision.accepted)
        self.assertTrue(decision.quarantined)
        self.assertFalse(decision.recovery_required)
        self.assertEqual(decision.denied.code.name, "REPLAY_DETECTED")

    def test_accepted_contradiction_requires_recovery(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)

        decision = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
            submitted_bytes=b'{"summary":"conflict"}',
            canonical=True,
        )

        self.assertFalse(decision.accepted)
        self.assertTrue(decision.quarantined)
        self.assertTrue(decision.recovery_required)
        self.assertEqual(decision.denied.code.name, "RECOVERY_REQUIRED")

        replay = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
        )

        self.assertFalse(replay.accepted)
        self.assertTrue(replay.quarantined)
        self.assertTrue(replay.recovery_required)
        self.assertEqual(replay.denied.code.name, "RECOVERY_REQUIRED")

    def test_unbound_canonical_conflict_cannot_poison_accepted_artifact(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)

        forged = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id="operator:forged",
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
            submitted_bytes=b'{"summary":"conflict"}',
            canonical=True,
        )
        valid = verifier.verify(
            manifest=manifest,
            pin=_artifact_pin(manifest),
            operator_id=manifest.operator_id,
            task_id=manifest.task_id,
            run_id=manifest.run_id,
            node_id=manifest.producer.node_id,
            process_id=manifest.producer.process_id,
            acceptance_checks=_records()["task_envelope"].acceptance_checks,
            observations=_records()["execution_receipt"].observations,
        )

        self.assertFalse(forged.accepted)
        self.assertFalse(forged.recovery_required)
        self.assertEqual(forged.denied.code.name, "IDENTITY_MISMATCH")
        self.assertTrue(valid.accepted)

    def test_malformed_acceptance_sequences_deny_instead_of_fail_open(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ArtifactVerifier(store)

        for case_id, checks, observations in (
            ("checks-list", [], _records()["execution_receipt"].observations),
            ("observations-list", _records()["task_envelope"].acceptance_checks, []),
            ("bad-check-item", (object(),), _records()["execution_receipt"].observations),
            ("bad-observation-item", _records()["task_envelope"].acceptance_checks, (object(),)),
        ):
            with self.subTest(case_id=case_id):
                decision = verifier.verify(
                    manifest=manifest,
                    pin=_artifact_pin(manifest),
                    operator_id=manifest.operator_id,
                    task_id=manifest.task_id,
                    run_id=manifest.run_id,
                    node_id=manifest.producer.node_id,
                    process_id=manifest.producer.process_id,
                    acceptance_checks=checks,
                    observations=observations,
                )

                self.assertFalse(decision.accepted)
                self.assertFalse(decision.recovery_required)
                self.assertEqual(decision.denied.code.name, "SCHEMA_INVALID")

    def test_verifier_surface_excludes_authority_mutation_methods(self):
        from authority_sim.artifacts import ArtifactStore, ArtifactVerifier

        store = ArtifactStore()
        verifier = ArtifactVerifier(store)

        for target in (store, verifier):
            self.assertFalse(hasattr(target, "append"))
            self.assertFalse(hasattr(target, "promote"))
            self.assertFalse(hasattr(target, "compare_and_append"))


class TestReceiptVerification(unittest.TestCase):
    def test_coherent_success_receipt_is_verified(self):
        from authority_sim.artifacts import ArtifactStore
        from authority_sim.receipts import ReceiptVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)

        decision = ReceiptVerifier(store).verify(
            receipt=_receipt_for_manifest(manifest),
            capability=_records()["capability_claim"],
            task=_records()["task_envelope"],
            manifest=manifest,
        )

        self.assertTrue(decision.accepted)
        self.assertIsNone(decision.denied)
        self.assertFalse(decision.quarantined)
        self.assertFalse(decision.recovery_required)

    def test_red_trust_downgrade_cannot_satisfy_required_check(self):
        from authority_sim.records import FrozenObject, TrustClass

        from authority_sim.artifacts import ArtifactStore
        from authority_sim.receipts import ReceiptVerifier

        records = _records()
        content = _artifact_bytes()
        manifest = _manifest_with_content(
            _artifact_digest(),
            len(content),
        )
        store = ArtifactStore()
        store.capture(manifest, content, accepted=True)
        downgraded = (
            _receipt_for_manifest(manifest).observations[0],
            FrozenObject(
                (
                    ("category", "test"),
                    ("evidence_artifact_id", manifest.artifact_id),
                    ("observation_id", "obs_01schema"),
                    ("status", "pass"),
                    ("summary_code", "SCHEMA_VALID"),
                    ("trust_class", TrustClass.ADAPTER_PARSED),
                )
            ),
        )
        verifier = ReceiptVerifier(store)

        decision = verifier.verify(
            receipt=_receipt_for_manifest(manifest),
            capability=records["capability_claim"],
            task=records["task_envelope"],
            manifest=manifest,
            observations=downgraded,
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "ACCEPTANCE_FAILED")

    def test_red_failed_terminal_state_requires_concrete_failure_signal(self):
        from authority_sim.records import create_record

        from authority_sim.artifacts import ArtifactStore
        from authority_sim.receipts import ReceiptVerifier

        documents = _documents()
        receipt_doc = documents["execution_receipt"]
        receipt_doc["terminal_state"] = "failed"
        receipt_doc["process_result"]["exit_code"] = 0
        receipt_doc["process_result"]["signal"] = None
        receipt_doc["process_result"]["budget_exceeded"] = False
        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        receipt_doc["artifact_refs"][0]["content_digest"] = _artifact_digest()
        receipt_doc["artifact_refs"][0]["manifest_digest"] = _manifest_digest(manifest)
        receipt_doc["observations"][1]["status"] = "fail"
        receipt = create_record(receipt_doc)
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ReceiptVerifier(store)

        decision = verifier.verify(
            receipt=receipt,
            capability=_records()["capability_claim"],
            task=_records()["task_envelope"],
            manifest=manifest,
            observations=_receipt_for_manifest(manifest).observations,
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "RECEIPT_UNVERIFIED")

    def test_success_receipt_still_requires_acceptance_and_exact_binding(self):
        from authority_sim.records import create_record

        from authority_sim.artifacts import ArtifactStore
        from authority_sim.receipts import ReceiptVerifier

        documents = _documents()
        receipt_doc = documents["execution_receipt"]
        receipt_doc["workspace_ref"] = "workspace:other"
        receipt_doc["artifact_refs"][0]["content_digest"] = _artifact_digest()
        receipt = create_record(receipt_doc)
        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ReceiptVerifier(store)

        decision = verifier.verify(
            receipt=receipt,
            capability=_records()["capability_claim"],
            task=_records()["task_envelope"],
            manifest=manifest,
        )

        self.assertFalse(decision.accepted)
        self.assertEqual(decision.denied.code.name, "IDENTITY_MISMATCH")

    def test_model_asserted_alone_never_promotes_and_hostile_values_deny_generically(self):
        from authority_sim.records import FrozenObject, TrustClass

        from authority_sim.artifacts import ArtifactStore
        from authority_sim.receipts import ReceiptVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ReceiptVerifier(store)
        weak = (
            _receipt_for_manifest(manifest).observations[0],
            FrozenObject(
                (
                    ("category", "test"),
                    ("evidence_artifact_id", manifest.artifact_id),
                    ("observation_id", "obs_01schema"),
                    ("status", "pass"),
                    ("summary_code", "SCHEMA_VALID"),
                    ("trust_class", TrustClass.MODEL_ASSERTED),
                )
            ),
        )

        weak_decision = verifier.verify(
            receipt=_receipt_for_manifest(manifest),
            capability=_records()["capability_claim"],
            task=_records()["task_envelope"],
            manifest=manifest,
            observations=weak,
        )
        hostile_decision = verifier.verify_trust(
            required=_records()["task_envelope"].acceptance_checks[0].get("minimum_trust_class"),
            observed="governor_observed",
        )

        self.assertFalse(weak_decision.accepted)
        self.assertFalse(hostile_decision.accepted)
        self.assertEqual(weak_decision.denied.code.name, "ACCEPTANCE_FAILED")
        self.assertEqual(hostile_decision.denied.code.name, "ACCEPTANCE_FAILED")

    def test_result_objects_are_frozen_slots_and_non_echo(self):
        from authority_sim.artifacts import ArtifactStore
        from authority_sim.receipts import ReceiptVerifier

        manifest = _manifest_with_content(
            _artifact_digest(),
            len(_artifact_bytes()),
        )
        store = ArtifactStore()
        store.capture(manifest, _artifact_bytes(), accepted=True)
        verifier = ReceiptVerifier(store)
        decision = verifier.verify(
            receipt=_receipt_for_manifest(manifest),
            capability=_records()["capability_claim"],
            task=_records()["task_envelope"],
            manifest=manifest,
        )

        self.assertFalse(hasattr(decision, "__dict__"))
        self.assertIsInstance(hash(decision), int)
        with self.assertRaises(FrozenInstanceError):
            decision.accepted = False
        self.assertEqual(tuple(field.name for field in fields(decision)), ("accepted", "denied", "quarantined", "recovery_required"))
        self.assertNotIn("artifact_01summary", repr(decision))
        self.assertNotIn("receipt_01synthetic", repr(decision))

    def test_source_has_no_forbidden_ambient_access(self):
        for path in (ARTIFACTS_SOURCE, RECEIPTS_SOURCE):
            self.assertTrue(path.is_file())
            source = path.read_text(encoding="utf-8")
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
                    {"os", "pathlib", "socket", "subprocess", "time", "random", "secrets"}
                )
            )
            for forbidden in ('open(', 'eval(', 'exec('):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
