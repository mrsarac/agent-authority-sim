from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from authority_sim.errors import ReasonCode
from authority_sim.transitions import RunState


def _utc(hour: int, minute: int, second: int) -> datetime:
    return datetime(2026, 8, 15, hour, minute, second, tzinfo=timezone.utc)


class IntSubclass(int):
    pass


class TestBudgetGuards(unittest.TestCase):
    def test_limits_and_usage_require_exact_integers_and_reject_bool_as_int(self):
        from authority_sim.fake_runtime import BudgetLimits, BudgetUsage

        invalid_values = (True, IntSubclass(1))
        for invalid in invalid_values:
            with self.subTest(invalid_type=type(invalid).__name__):
                with self.assertRaisesRegex(ValueError, "^FAKE_RUNTIME_INVALID$"):
                    BudgetLimits(invalid, 0, 0, 0, 0, 0, 0)
                with self.assertRaisesRegex(ValueError, "^FAKE_RUNTIME_INVALID$"):
                    BudgetUsage(invalid, 0, 0, 0, 0, 0, 0)

    def test_each_hard_budget_cap_is_checked_independently_with_no_urgent_bypass(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import budget_breach_scenario, default_adapter_manifest

        expected = {
            "max_wall_ms": RunState.TIMED_OUT,
            "max_tool_calls": RunState.FAILED,
            "max_output_bytes": RunState.FAILED,
            "max_fresh_input_tokens": RunState.FAILED,
            "max_output_tokens": RunState.FAILED,
            "max_network_requests": RunState.DENIED,
            "max_processes": RunState.FAILED,
        }
        for metric, run_state in expected.items():
            with self.subTest(metric=metric):
                outcome = FakeWorker(
                    "worker:budget",
                    WorkerSubmissionPort(),
                ).run(
                    FakeAdapter(default_adapter_manifest()),
                    budget_breach_scenario(metric, urgent=True),
                    authority_as_of=_utc(14, 0, 5),
                    worker_started_at=_utc(14, 0, 1),
                    worker_finished_at=_utc(14, 0, 12),
                )
                self.assertIs(outcome.run_state, run_state)
                self.assertIs(outcome.reason, ReasonCode.BUDGET_EXCEEDED)

    def test_zero_aliases_and_zero_network_budget_deny_every_destination(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import default_adapter_manifest, egress_scenario

        outcome = FakeWorker("worker:egress-a", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            egress_scenario(
                capability_aliases=(),
                pinned_destination=None,
                requested_destination="synthetic://registry/api",
                network_limit=0,
                network_usage=0,
            ),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(outcome.run_state, RunState.DENIED)
        self.assertIs(outcome.reason, ReasonCode.SCOPE_EXCEEDED)

    def test_one_alias_permits_only_its_exact_pinned_synthetic_destination(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.scenarios import default_adapter_manifest, egress_scenario

        success = FakeWorker("worker:egress-b", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            egress_scenario(
                capability_aliases=("egress:registry",),
                pinned_destination="synthetic://registry/api",
                requested_destination="synthetic://registry/api",
                network_limit=1,
                network_usage=1,
            ),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )
        denied = FakeWorker("worker:egress-c", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            egress_scenario(
                capability_aliases=("egress:registry",),
                pinned_destination="synthetic://registry/api",
                requested_destination="synthetic://registry/other",
                network_limit=1,
                network_usage=1,
            ),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(success.run_state, RunState.SUCCEEDED)
        self.assertIsNone(success.reason)
        self.assertIs(denied.run_state, RunState.FAILED)
        self.assertIs(denied.reason, ReasonCode.SCOPE_EXCEEDED)

        self_authorized = FakeWorker(
            "worker:egress-self-authorized",
            WorkerSubmissionPort(),
        ).run(
            FakeAdapter(default_adapter_manifest()),
            egress_scenario(
                capability_aliases=("egress:registry",),
                pinned_destination="synthetic://evil/endpoint",
                requested_destination="synthetic://evil/endpoint",
                network_limit=1,
                network_usage=1,
            ),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )
        self.assertIs(self_authorized.run_state, RunState.FAILED)
        self.assertIs(self_authorized.reason, ReasonCode.SCOPE_EXCEEDED)

    def test_egress_requires_action_and_actual_request_count_consumes_budget(self):
        from authority_sim.fake_runtime import FakeAdapter, FakeWorker, WorkerSubmissionPort
        from authority_sim.records import create_record
        from authority_sim.scenarios import default_adapter_manifest, egress_scenario

        base = egress_scenario(
            capability_aliases=("egress:registry",),
            pinned_destination="synthetic://registry/api",
            requested_destination="synthetic://registry/api",
            network_limit=1,
            network_usage=1,
        )
        capability = create_record(
            {
                **base.capability.to_document(),
                "allowed_actions": ["read_artifact"],
            }
        )
        without_action = FakeWorker("worker:egress-d", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            replace(base, capability=capability),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )
        zero_budget = FakeWorker("worker:egress-e", WorkerSubmissionPort()).run(
            FakeAdapter(default_adapter_manifest()),
            egress_scenario(
                capability_aliases=("egress:registry",),
                pinned_destination="synthetic://registry/api",
                requested_destination="synthetic://registry/api",
                network_limit=0,
                network_usage=0,
            ),
            authority_as_of=_utc(14, 0, 5),
            worker_started_at=_utc(14, 0, 1),
            worker_finished_at=_utc(14, 0, 12),
        )

        self.assertIs(without_action.run_state, RunState.DENIED)
        self.assertIs(without_action.reason, ReasonCode.SCOPE_EXCEEDED)
        self.assertIs(zero_budget.run_state, RunState.DENIED)
        self.assertIs(zero_budget.reason, ReasonCode.BUDGET_EXCEEDED)

    def test_workspace_resolver_accepts_only_lexical_descendants(self):
        from authority_sim.fake_runtime import WorkspaceResolver

        resolver = WorkspaceResolver("workspace:synthetic")
        accepted = resolver.resolve("output/summary.json")
        self.assertTrue(accepted.accepted)
        self.assertEqual(
            accepted.workspace_ref,
            "workspace:synthetic/output/summary.json",
        )

        hostile = (
            "../escape",
            "/absolute",
            "dir//file",
            "dir/../file",
            "dir\\file",
            "dir\u2215file",
            "dir/",
            ".",
            "",
        )
        for path in hostile:
            with self.subTest(path=path):
                denied = resolver.resolve(path)
                self.assertFalse(denied.accepted)
                self.assertIs(denied.reason, ReasonCode.SCOPE_EXCEEDED)


if __name__ == "__main__":
    unittest.main()
