from __future__ import annotations

import ast
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_SOURCE = ROOT / "src" / "authority_sim" / "workspace.py"


class StringSubclass(str):
    pass


class EqualBypass:
    comparisons = 0

    def __eq__(self, other):
        type(self).comparisons += 1
        return True


class ExplosiveEquality:
    comparisons = 0

    def __eq__(self, other):
        type(self).comparisons += 1
        raise RuntimeError("HOSTILE_WORKSPACE_SENTINEL")


class TestWorkspaceValues(unittest.TestCase):
    def test_workspace_id_and_path_require_exact_nonblank_strings(self):
        from authority_sim.workspace import WorkspaceId, WorkspacePath

        invalid_ids = ("", " workspace:a", "workspace:a ", StringSubclass("workspace:a"))
        for value in invalid_ids:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$"):
                    WorkspaceId(value)
        with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$"):
            WorkspacePath(StringSubclass("safe/file.txt"))

    def test_valid_logical_path_is_preserved_without_normalization(self):
        from authority_sim.workspace import WorkspacePath

        path = WorkspacePath("reports/İstanbul 🚀.json")
        self.assertEqual(path.logical_path, "reports/İstanbul 🚀.json")

    def test_ambiguous_and_host_like_paths_are_rejected(self):
        from authority_sim.workspace import WorkspacePath

        invalid_paths = (
            "",
            "/absolute/path",
            "~/private",
            "foo/../bar",
            "foo/./bar",
            "foo//bar",
            "foo/bar/",
            "C:/Windows",
            "C:\\Windows",
            "foo\\bar",
            "foo/\0/bar",
            " foo/bar",
            "foo/bar ",
            "foo/ bar",
            "foo/link:target",
            "foo/symlink:target",
            "foo/a->b",
        )
        for value in invalid_paths:
            with self.subTest(value=value.encode("unicode_escape")):
                with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$"):
                    WorkspacePath(value)

    def test_value_objects_are_frozen_slot_backed_and_privacy_safe(self):
        from authority_sim.workspace import (
            BoundWorkspacePath,
            WorkspaceId,
            WorkspacePath,
        )

        workspace_id = WorkspaceId("SECRET_WORKSPACE_SENTINEL")
        path = WorkspacePath("SECRET_PATH_SENTINEL/file.txt")
        bound = BoundWorkspacePath(workspace_id, path)
        for value in (workspace_id, path, bound):
            self.assertFalse(hasattr(value, "__dict__"))
            self.assertNotIn("SECRET_WORKSPACE_SENTINEL", repr(value))
            self.assertNotIn("SECRET_PATH_SENTINEL", repr(value))
        with self.assertRaises(FrozenInstanceError):
            workspace_id.value = "other"
        with self.assertRaises(FrozenInstanceError):
            path.logical_path = "other"
        with self.assertRaises(FrozenInstanceError):
            bound.path = WorkspacePath("other")


class TestSyntheticWorkspace(unittest.TestCase):
    def setUp(self):
        from authority_sim.workspace import SyntheticWorkspace, WorkspaceId

        self.workspace_id = WorkspaceId("workspace:a")
        self.workspace = SyntheticWorkspace(self.workspace_id)

    def test_resolution_returns_a_bound_immutable_reference_not_a_string(self):
        from authority_sim.workspace import BoundWorkspacePath, WorkspacePath

        path = WorkspacePath("safe/result.json")
        result = self.workspace.resolve(self.workspace_id, path)
        self.assertIs(type(result), BoundWorkspacePath)
        self.assertEqual(result.workspace_id, self.workspace_id)
        self.assertEqual(result.path, path)
        self.assertNotIsInstance(result, str)

    def test_mismatched_workspace_is_rejected_generically(self):
        from authority_sim.workspace import WorkspaceId, WorkspacePath

        with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$") as caught:
            self.workspace.resolve(
                WorkspaceId("SECRET_OTHER_WORKSPACE"),
                WorkspacePath("safe/result.json"),
            )
        self.assertNotIn("SECRET_OTHER_WORKSPACE", str(caught.exception))

    def test_type_validation_occurs_before_any_hostile_equality(self):
        from authority_sim.workspace import WorkspacePath

        path = WorkspacePath("safe/result.json")
        EqualBypass.comparisons = 0
        with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$"):
            self.workspace.resolve(EqualBypass(), path)
        self.assertEqual(EqualBypass.comparisons, 0)

        ExplosiveEquality.comparisons = 0
        with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$") as caught:
            self.workspace.resolve(ExplosiveEquality(), path)
        self.assertEqual(ExplosiveEquality.comparisons, 0)
        self.assertNotIn("HOSTILE_WORKSPACE_SENTINEL", str(caught.exception))

    def test_path_type_validation_occurs_before_resolution(self):
        with self.assertRaisesRegex(ValueError, "^WORKSPACE_INVALID$"):
            self.workspace.resolve(self.workspace_id, "safe/result.json")

    def test_workspace_is_frozen_slot_backed_and_has_no_raw_resolver(self):
        self.assertFalse(hasattr(self.workspace, "__dict__"))
        self.assertFalse(hasattr(self.workspace, "open"))
        self.assertFalse(hasattr(self.workspace, "read"))
        self.assertFalse(hasattr(self.workspace, "write"))
        with self.assertRaises(FrozenInstanceError):
            self.workspace.workspace_id = self.workspace_id

    def test_source_has_no_host_filesystem_network_or_process_access(self):
        self.assertTrue(WORKSPACE_SOURCE.is_file())
        source = WORKSPACE_SOURCE.read_text(encoding="utf-8")
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
                {"os", "pathlib", "subprocess", "socket", "urllib"},
            ),
        )
        for forbidden in ("Path.home", "expanduser", "open(", "/Users/"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
