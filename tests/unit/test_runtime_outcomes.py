from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from authority_sim.errors import ReasonCode
from authority_sim.transitions import RunState


def _utc(hour: int, minute: int, second: int) -> datetime:
    return datetime(2026, 8, 15, hour, minute, second, tzinfo=timezone.utc)


class TestRuntimeOutcomes(unittest.TestCase):
    def setUp(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import default_adapter_manifest

        self.port = WorkerSubmissionPort()
        self.adapter = FakeAdapter(default_adapter_manifest())
        self.worker = FakeWorker("worker:synthetic", self.port)

    def test_success_run_reaches_terminal_success_and_submits_receipt_and_proposal(self):
        from authority_sim.fake_runtime import SubmissionSnapshot
        from authority_sim.scenarios import success_scenario

        outcome = self.worker.run(
            self.adapter,
            success_scenario(),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(outcome.run_state, RunState.SUCCEEDED)
        self.assertEqual(outcome.run_state_name, "SUCCEEDED")
        self.assertEqual(outcome.receipt.terminal_state, "success")
        self.assertEqual(outcome.submission, SubmissionSnapshot(1, 1))
        self.assertFalse(outcome.replayed)
        self.assertIsNone(outcome.reason)
        self.assertEqual(self.port.snapshot(), SubmissionSnapshot(1, 1))

    def test_cancellation_is_terminal_replay_retains_terminal_and_quarantines_partial_artifacts(self):
        from authority_sim.fake_runtime import SubmissionSnapshot
        from authority_sim.scenarios import cancelled_scenario

        scenario = cancelled_scenario()
        first = self.worker.run(
            self.adapter,
            scenario,
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 6),
        )
        replay = self.worker.run(
            self.adapter,
            scenario,
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 2),
            worker_finished_at=_utc(14, 0, 7),
        )

        self.assertIs(first.run_state, RunState.CANCELLED)
        self.assertEqual(first.receipt.terminal_state, "cancelled")
        self.assertEqual(len(first.receipt.quarantined_artifact_refs), 1)
        self.assertEqual(first.submission, SubmissionSnapshot(1, 0))
        self.assertFalse(first.replayed)
        self.assertIs(replay.run_state, RunState.CANCELLED)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.submission, SubmissionSnapshot(1, 0))
        self.assertEqual(self.port.snapshot(), SubmissionSnapshot(1, 0))

    def test_cancellation_cannot_relabel_budget_egress_or_process_failure(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import (
            budget_breach_scenario,
            default_adapter_manifest,
            egress_scenario,
            success_scenario,
        )

        cases = (
            (
                "budget",
                replace(
                    budget_breach_scenario("max_tool_calls", urgent=False),
                    cancellation_requested=True,
                    run_id="run_90budgetaa",
                ),
                RunState.FAILED,
                ReasonCode.BUDGET_EXCEEDED,
            ),
            (
                "egress",
                replace(
                    egress_scenario(
                        capability_aliases=("egress:registry",),
                        pinned_destination="synthetic://registry/api",
                        requested_destination="synthetic://registry/other",
                        network_limit=1,
                        network_usage=1,
                    ),
                    cancellation_requested=True,
                    run_id="run_91egressaa",
                ),
                RunState.FAILED,
                ReasonCode.SCOPE_EXCEEDED,
            ),
            (
                "process",
                replace(
                    success_scenario(),
                    cancellation_requested=True,
                    exit_code=9,
                    run_id="run_92relabela",
                ),
                RunState.FAILED,
                None,
            ),
        )
        for case_id, scenario, expected_state, expected_reason in cases:
            with self.subTest(case_id=case_id):
                outcome = FakeWorker(
                    "worker:precedence",
                    WorkerSubmissionPort(),
                ).run(
                    FakeAdapter(default_adapter_manifest()),
                    scenario,
                    authority_as_of=_utc(14, 0, 5),
                    worker_started_at=_utc(14, 0, 1),
                    worker_finished_at=_utc(14, 0, 12),
                )

                self.assertIs(outcome.run_state, expected_state)
                self.assertIs(outcome.reason, expected_reason)
                self.assertNotEqual(outcome.receipt.terminal_state, "cancelled")

    def test_same_run_id_with_different_scenario_is_denied_not_replayed(self):
        from authority_sim.fake_runtime import SubmissionSnapshot
        from authority_sim.scenarios import success_scenario

        scenario = success_scenario()
        first = self.worker.run(
            self.adapter,
            scenario,
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )
        conflicting = self.worker.run(
            self.adapter,
            replace(scenario, filesystem_change_count=2),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 2),
            worker_finished_at=_utc(14, 0, 13),
        )

        self.assertIs(first.run_state, RunState.SUCCEEDED)
        self.assertIs(conflicting.run_state, RunState.DENIED)
        self.assertFalse(conflicting.replayed)
        self.assertIs(conflicting.reason, ReasonCode.REPLAY_DETECTED)
        self.assertIsNone(conflicting.receipt.record)
        self.assertEqual(conflicting.submission, SubmissionSnapshot(1, 1))

    def test_pre_valid_authority_time_and_empty_success_artifact_deny_without_crash(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import default_adapter_manifest, success_scenario

        scenario = success_scenario()
        pre_valid = FakeWorker("worker:prevalid", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            scenario,
            authority_as_of=_utc(13, 59, 59),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )
        empty_artifact = FakeWorker("worker:empty", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            replace(scenario, run_id="run_88emptyaaa", artifact_refs=()),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(pre_valid.run_state, RunState.DENIED)
        self.assertIs(pre_valid.reason, ReasonCode.CAPABILITY_INVALID)
        self.assertIs(empty_artifact.run_state, RunState.DENIED)
        self.assertIs(empty_artifact.reason, ReasonCode.ARTIFACT_MISMATCH)

    def test_workspace_path_escape_denies_before_execution(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import default_adapter_manifest, success_scenario

        outcome = FakeWorker("worker:path", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            replace(success_scenario(), run_id="run_89pathaaaa", workspace_paths=("../escape",)),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(outcome.run_state, RunState.DENIED)
        self.assertIs(outcome.reason, ReasonCode.SCOPE_EXCEEDED)

    def test_observed_effects_require_task_and_capability_actions(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.records import create_record
        from authority_sim.scenarios import default_adapter_manifest, success_scenario

        scenario = success_scenario()
        task_document = scenario.task.to_document()
        task_document["required_actions"] = ["read_artifact"]
        capability_document = scenario.capability.to_document()
        capability_document["allowed_actions"] = ["read_artifact"]
        denied = FakeWorker("worker:effects", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            replace(
                scenario,
                run_id="run_93effectsaa",
                task=create_record(task_document),
                capability=create_record(capability_document),
            ),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(denied.run_state, RunState.DENIED)
        self.assertIs(denied.reason, ReasonCode.SCOPE_EXCEEDED)

    def test_timeout_is_terminal_and_partial_artifacts_become_quarantined_evidence(self):
        from authority_sim.fake_runtime import SubmissionSnapshot
        from authority_sim.scenarios import timed_out_scenario

        outcome = self.worker.run(
            self.adapter,
            timed_out_scenario(),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 1, 2),
        )

        self.assertIs(outcome.run_state, RunState.TIMED_OUT)
        self.assertEqual(outcome.receipt.terminal_state, "timed_out")
        self.assertEqual(len(outcome.receipt.quarantined_artifact_refs), 1)
        self.assertEqual(outcome.submission, SubmissionSnapshot(1, 0))
        self.assertIs(outcome.reason, ReasonCode.BUDGET_EXCEEDED)

    def test_authority_as_of_controls_expiry_worker_timestamps_are_metadata_only(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import default_adapter_manifest, success_scenario

        late_worker = FakeWorker("worker:late-one", WorkerSubmissionPort())
        late = late_worker.run(
            FakeAdapter(default_adapter_manifest()),
            success_scenario(),
            authority_as_of=_utc(14, 9, 59),
            worker_started_at=_utc(14, 20, 1),
            worker_finished_at=_utc(14, 20, 12),
        )
        expired = FakeWorker("worker:late-two", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            success_scenario(),
            authority_as_of=_utc(14, 10, 0),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(late.run_state, RunState.SUCCEEDED)
        self.assertEqual(late.receipt.record.started_at, _utc(14, 20, 1))
        self.assertEqual(late.receipt.record.finished_at, _utc(14, 20, 12))
        self.assertIs(expired.run_state, RunState.DENIED)
        self.assertEqual(expired.receipt.terminal_state, "denied")
        self.assertIs(expired.reason, ReasonCode.CAPABILITY_INVALID)


if __name__ == "__main__":
    unittest.main()
