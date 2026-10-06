from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FAKE_RUNTIME = ROOT / "src" / "authority_sim" / "fake_runtime.py"
SCENARIOS = ROOT / "src" / "authority_sim" / "scenarios.py"


class TestPublicSurfaceSecurity(unittest.TestCase):
    def test_new_runtime_modules_use_no_ambient_or_host_escape_apis(self):
        for path in (FAKE_RUNTIME, SCENARIOS):
            with self.subTest(path=path.name):
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
                        {
                            "os",
                            "pathlib",
                            "socket",
                            "subprocess",
                            "time",
                            "random",
                            "secrets",
                        },
                    ),
                )
                for forbidden in (
                    "open(",
                    "eval(",
                    "exec(",
                    "FakeClock",
                    "AuthorityCore",
                    "InMemoryAuthorityLog",
                    "OperatorRecoveryPort",
                ):
                    self.assertNotIn(forbidden, source)

    def test_public_runtime_types_have_slots_and_no_hidden_mutation_dicts(self):
        from authority_sim.fake_runtime import (
            AdapterManifest,
            BudgetLimits,
            BudgetUsage,
            FakeAdapter,
            FakeWorker,
            ReceiptSurface,
            RuntimeOutcome,
            SubmissionSnapshot,
            WorkerSubmissionPort,
        )
        from authority_sim.scenarios import default_adapter_manifest

        instances = (
            default_adapter_manifest(),
            BudgetLimits(1, 0, 0, 0, 0, 0, 0),
            BudgetUsage(0, 0, 0, 0, 0, 0, 0),
            FakeAdapter(default_adapter_manifest()),
            WorkerSubmissionPort(),
            FakeWorker("worker:synthetic", WorkerSubmissionPort()),
            ReceiptSurface("run_01synthetic", "denied", ()),
            SubmissionSnapshot(0, 0),
            RuntimeOutcome(
                run_id="run_01synthetic",
                run_state_name="DENIED",
                receipt=ReceiptSurface("run_01synthetic", "denied", ()),
                submission=SubmissionSnapshot(0, 0),
                replayed=False,
            ),
        )
        expected_types = (
            AdapterManifest,
            BudgetLimits,
            BudgetUsage,
            FakeAdapter,
            WorkerSubmissionPort,
            FakeWorker,
            ReceiptSurface,
            SubmissionSnapshot,
            RuntimeOutcome,
        )
        self.assertEqual(tuple(type(item) for item in instances), expected_types)
        for item in instances:
            with self.subTest(item=type(item).__name__):
                self.assertFalse(hasattr(item, "__dict__"))


if __name__ == "__main__":
    unittest.main()
