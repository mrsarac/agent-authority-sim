from __future__ import annotations

import inspect
import unittest
from dataclasses import FrozenInstanceError, is_dataclass


class TestFakeRuntimeSurface(unittest.TestCase):
    def test_adapter_manifest_is_exact_immutable_and_version_pinned(self):
        from authority_sim.fake_runtime import AdapterManifest
        from authority_sim.scenarios import default_adapter_manifest

        manifest = default_adapter_manifest()
        self.assertIs(type(manifest), AdapterManifest)
        self.assertTrue(is_dataclass(manifest))
        self.assertTrue(type(manifest).__dataclass_params__.frozen)
        self.assertFalse(hasattr(manifest, "__dict__"))
        self.assertEqual(manifest.version, "0.1.0")
        self.assertEqual(
            manifest.features,
            (
                "structured-output",
                "cancellation",
                "network-egress",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            manifest.version = "9.9.9"

    def test_manifest_rejects_blank_unknown_case_variant_and_stale_identity(self):
        from authority_sim.fake_runtime import AdapterManifest

        base = {
            "adapter_id": "adapter:fake-worker",
            "version": "0.1.0",
            "binary_digest": "sha256:" + ("a" * 64),
            "manifest_digest": "sha256:" + ("b" * 64),
            "features": (
                "structured-output",
                "cancellation",
                "network-egress",
            ),
        }
        invalid_mutations = (
            {"features": ("",)},
            {"features": ("unknown-feature",)},
            {"features": ("Structured-Output",)},
            {"version": "0.1.1"},
            {"manifest_digest": "sha256:" + ("c" * 64)},
        )
        for mutation in invalid_mutations:
            mutated = dict(base)
            mutated.update(mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "^FAKE_RUNTIME_INVALID$"):
                    AdapterManifest(**mutated)

    def test_fake_adapter_denies_missing_and_unknown_required_features(self):
        from authority_sim.errors import Denied, ReasonCode
        from authority_sim.fake_runtime import FakeAdapter
        from authority_sim.scenarios import (
            default_adapter_manifest,
            task_with_required_features,
        )

        adapter = FakeAdapter(default_adapter_manifest())
        missing = adapter.check_task(
            task_with_required_features(("structured-output", "sandbox-tools")),
        )

        self.assertEqual(missing, Denied(ReasonCode.ADAPTER_UNSUPPORTED))
        self.assertIsNone(
            adapter.check_task(
                task_with_required_features(("structured-output", "cancellation")),
            ),
        )

    def test_worker_constructor_accepts_only_submission_port(self):
        from authority_sim.fake_runtime import FakeWorker

        self.assertEqual(
            tuple(inspect.signature(FakeWorker).parameters),
            ("worker_id", "submission_port"),
        )

    def test_public_surfaces_expose_no_authority_mutation_methods(self):
        from authority_sim.fake_runtime import (
            FakeAdapter,
            FakeWorker,
            ReceiptSurface,
            WorkerSubmissionPort,
        )
        from authority_sim.scenarios import default_adapter_manifest

        adapter = FakeAdapter(default_adapter_manifest())
        port = WorkerSubmissionPort()
        worker = FakeWorker("worker:synthetic", port)
        receipt = ReceiptSurface(
            run_id="run_01synthetic",
            terminal_state="denied",
            quarantined_artifact_refs=(),
        )

        forbidden = {
            "append",
            "promote",
            "policy_update",
            "renew_lease",
            "increment_epoch",
            "recover",
        }
        for surface in (adapter, port, worker, receipt):
            with self.subTest(surface=type(surface).__name__):
                self.assertTrue(forbidden.isdisjoint(dir(surface)))

    def test_authority_event_submission_denies_without_mutation(self):
        from authority_sim.errors import Denied, ReasonCode
        from authority_sim.fake_runtime import WorkerSubmissionPort
        from authority_sim.scenarios import authority_event_record

        port = WorkerSubmissionPort()
        before = port.snapshot()
        event = authority_event_record()

        self.assertEqual(
            port.submit_receipt(event),
            Denied(ReasonCode.SCHEMA_INVALID),
        )
        self.assertEqual(
            port.submit_proposal(event),
            Denied(ReasonCode.SCHEMA_INVALID),
        )
        self.assertEqual(port.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
