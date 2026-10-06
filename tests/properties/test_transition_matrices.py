from __future__ import annotations

import ast
import json
import unittest
from dataclasses import FrozenInstanceError
from enum import Enum
from itertools import product
from pathlib import Path

from authority_sim.errors import Denied, ReasonCode
from authority_sim.transitions import (
    AUTHORITY_MATRIX,
    BINDING_MATRIX,
    CAPABILITY_MATRIX,
    POLICY_MATRIX,
    PROMOTION_MATRIX,
    RECEIPT_MATRIX,
    RUN_MATRIX,
    TASK_MATRIX,
    AuthorityEventType,
    AuthorityState,
    AuthorityTransitionEvent,
    BindingDecision,
    CapabilityState,
    CapabilityTransitionEvent,
    ObjectKind,
    PolicyState,
    PolicyTransitionEvent,
    PromotionState,
    PromotionTransitionEvent,
    ReceiptState,
    ReceiptTransitionEvent,
    RunOutcome,
    RunState,
    StateMachineDomain,
    TaskState,
    TaskTransitionEvent,
    TransitionDecision,
    TransitionDisposition,
    authority_transition,
    capability_transition,
    event_binding,
    policy_transition,
    promotion_transition,
    receipt_transition,
    run_transition,
    task_transition,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "spec" / "v0.1.0" / "contracts.schema.json"
SOURCE = ROOT / "src" / "authority_sim" / "transitions.py"


EXPECTED_VOCABULARIES = {
    AuthorityState: (
        "UNINITIALIZED",
        "NO_WRITER",
        "ACTIVE",
        "FENCED",
        "RECOVERY_REQUIRED",
        "HALTED",
    ),
    AuthorityTransitionEvent: (
        "authority_initialized",
        "lease_renewed",
        "lease_released",
        "lease_expired",
        "authority_fenced",
        "lease_acquired",
        "recovery_started",
        "contradiction",
        "restore_verified",
        "authority_halted",
        "ordinary_write",
    ),
    TaskState: (
        "NONE",
        "ISSUED",
        "ACTIVE",
        "EVIDENCE_PENDING",
        "PROMOTION_PENDING",
        "PROMOTED",
        "COMPLETED_NO_CHANGE",
        "REJECTED",
        "QUARANTINED",
        "REVOKED",
        "EXPIRED",
    ),
    TaskTransitionEvent: (
        "task_issued",
        "first_run_claimed",
        "receipt_submitted",
        "receipt_verified",
        "receipt_rejected_retryable",
        "receipt_rejected_final",
        "promotion_recorded",
        "record_no_change",
        "proposal_rejected",
        "evidence_contradiction",
        "task_revoked",
        "task_expired",
        "byte_identical_replay",
        "new_run_or_proposal",
    ),
    CapabilityState: (
        "NONE",
        "ISSUED",
        "ACTIVE",
        "EXPIRED",
        "REVOKED",
        "CONSUMED",
    ),
    CapabilityTransitionEvent: (
        "capability_issued",
        "first_valid_use",
        "capability_expired",
        "capability_revoked",
        "single_use_consumed",
        "use_or_reissue_attempt",
        "byte_identical_replay",
    ),
    RunState: (
        "NONE",
        "CREATED",
        "CLAIMED",
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
        "TIMED_OUT",
        "DENIED",
    ),
    RunOutcome: (
        "run_created",
        "run_claimed",
        "run_started",
        "exit_zero",
        "exit_nonzero",
        "cancellation_accepted",
        "deadline_reached",
        "check_failed",
        "byte_identical_replay",
        "relabel_attempt",
    ),
    ReceiptState: (
        "NONE",
        "SUBMITTED",
        "VERIFIED",
        "REJECTED",
        "QUARANTINED",
    ),
    ReceiptTransitionEvent: (
        "receipt_submitted",
        "receipt_accepted",
        "receipt_rejected",
        "receipt_quarantined",
        "byte_identical_replay",
        "byte_different_replay",
    ),
    PromotionState: (
        "NONE",
        "PROPOSAL_RECEIVED",
        "RECEIPT_VERIFIED",
        "PROMOTED",
        "REJECTED",
        "QUARANTINED",
    ),
    PromotionTransitionEvent: (
        "proposal_submitted",
        "receipts_verified",
        "validation_rejected",
        "contradiction",
        "promotion_decision",
        "byte_identical_replay",
        "alternate_result",
    ),
    PolicyState: (
        "UNINITIALIZED",
        "ACTIVE",
        "RECOVERY_REQUIRED",
    ),
    PolicyTransitionEvent: (
        "policy_activated",
        "rollback_attempt",
        "canonical_conflict",
        "policy_recovery",
    ),
}


EXPECTED_ALLOWED = {
    "authority": frozenset(
        {
            ("UNINITIALIZED", "authority_initialized", "ACTIVE"),
            ("UNINITIALIZED", "recovery_started", "RECOVERY_REQUIRED"),
            ("UNINITIALIZED", "contradiction", "RECOVERY_REQUIRED"),
            ("UNINITIALIZED", "authority_halted", "HALTED"),
            ("ACTIVE", "lease_renewed", "ACTIVE"),
            ("ACTIVE", "lease_released", "NO_WRITER"),
            ("ACTIVE", "lease_expired", "NO_WRITER"),
            ("ACTIVE", "authority_fenced", "FENCED"),
            ("ACTIVE", "lease_acquired", "ACTIVE"),
            ("ACTIVE", "recovery_started", "RECOVERY_REQUIRED"),
            ("ACTIVE", "contradiction", "RECOVERY_REQUIRED"),
            ("ACTIVE", "authority_halted", "HALTED"),
            ("NO_WRITER", "lease_acquired", "ACTIVE"),
            ("NO_WRITER", "recovery_started", "RECOVERY_REQUIRED"),
            ("NO_WRITER", "contradiction", "RECOVERY_REQUIRED"),
            ("NO_WRITER", "authority_halted", "HALTED"),
            ("FENCED", "recovery_started", "RECOVERY_REQUIRED"),
            ("FENCED", "contradiction", "RECOVERY_REQUIRED"),
            ("FENCED", "authority_halted", "HALTED"),
            ("RECOVERY_REQUIRED", "recovery_started", "RECOVERY_REQUIRED"),
            ("RECOVERY_REQUIRED", "contradiction", "RECOVERY_REQUIRED"),
            ("RECOVERY_REQUIRED", "restore_verified", "ACTIVE"),
            ("RECOVERY_REQUIRED", "authority_halted", "HALTED"),
            ("HALTED", "restore_verified", "ACTIVE"),
            ("HALTED", "authority_halted", "HALTED"),
        },
    ),
    "task": frozenset(
        {
            ("NONE", "task_issued", "ISSUED"),
            ("ISSUED", "first_run_claimed", "ACTIVE"),
            ("ACTIVE", "receipt_submitted", "EVIDENCE_PENDING"),
            ("EVIDENCE_PENDING", "receipt_verified", "PROMOTION_PENDING"),
            ("EVIDENCE_PENDING", "receipt_rejected_retryable", "ACTIVE"),
            ("EVIDENCE_PENDING", "receipt_rejected_final", "REJECTED"),
            ("PROMOTION_PENDING", "promotion_recorded", "PROMOTED"),
            ("PROMOTION_PENDING", "record_no_change", "COMPLETED_NO_CHANGE"),
            ("PROMOTION_PENDING", "proposal_rejected", "REJECTED"),
            *((state, "evidence_contradiction", "QUARANTINED") for state in (
                "ISSUED", "ACTIVE", "EVIDENCE_PENDING", "PROMOTION_PENDING",
            )),
            *((state, "task_revoked", "REVOKED") for state in (
                "ISSUED", "ACTIVE", "EVIDENCE_PENDING", "PROMOTION_PENDING",
            )),
            *((state, "task_expired", "EXPIRED") for state in (
                "ISSUED", "ACTIVE", "EVIDENCE_PENDING", "PROMOTION_PENDING",
            )),
            *((state, "byte_identical_replay", state) for state in (
                "PROMOTED", "COMPLETED_NO_CHANGE", "REJECTED", "QUARANTINED",
                "REVOKED", "EXPIRED",
            )),
        },
    ),
    "capability": frozenset(
        {
            ("NONE", "capability_issued", "ISSUED"),
            ("ISSUED", "first_valid_use", "ACTIVE"),
            ("ISSUED", "capability_expired", "EXPIRED"),
            ("ACTIVE", "capability_expired", "EXPIRED"),
            ("ISSUED", "capability_revoked", "REVOKED"),
            ("ACTIVE", "capability_revoked", "REVOKED"),
            ("ACTIVE", "single_use_consumed", "CONSUMED"),
            *((state, "byte_identical_replay", state) for state in (
                "EXPIRED", "REVOKED", "CONSUMED",
            )),
        },
    ),
    "run": frozenset(
        {
            ("NONE", "run_created", "CREATED"),
            ("CREATED", "run_claimed", "CLAIMED"),
            ("CLAIMED", "run_started", "RUNNING"),
            ("RUNNING", "exit_zero", "SUCCEEDED"),
            ("RUNNING", "exit_nonzero", "FAILED"),
            ("CREATED", "cancellation_accepted", "CANCELLED"),
            ("CLAIMED", "cancellation_accepted", "CANCELLED"),
            ("RUNNING", "cancellation_accepted", "CANCELLED"),
            ("RUNNING", "deadline_reached", "TIMED_OUT"),
            ("CREATED", "check_failed", "DENIED"),
            ("CLAIMED", "check_failed", "DENIED"),
            *((state, "byte_identical_replay", state) for state in (
                "SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT", "DENIED",
            )),
        },
    ),
    "receipt": frozenset(
        {
            ("NONE", "receipt_submitted", "SUBMITTED"),
            ("SUBMITTED", "receipt_accepted", "VERIFIED"),
            ("SUBMITTED", "receipt_rejected", "REJECTED"),
            ("SUBMITTED", "receipt_quarantined", "QUARANTINED"),
            *((state, "byte_identical_replay", state) for state in (
                "VERIFIED", "REJECTED", "QUARANTINED",
            )),
        },
    ),
    "promotion": frozenset(
        {
            ("NONE", "proposal_submitted", "PROPOSAL_RECEIVED"),
            ("PROPOSAL_RECEIVED", "receipts_verified", "RECEIPT_VERIFIED"),
            ("PROPOSAL_RECEIVED", "validation_rejected", "REJECTED"),
            ("RECEIPT_VERIFIED", "validation_rejected", "REJECTED"),
            ("PROPOSAL_RECEIVED", "contradiction", "QUARANTINED"),
            ("RECEIPT_VERIFIED", "contradiction", "QUARANTINED"),
            ("RECEIPT_VERIFIED", "promotion_decision", "PROMOTED"),
            *((state, "byte_identical_replay", state) for state in (
                "PROMOTED", "REJECTED", "QUARANTINED",
            )),
        },
    ),
    "policy": frozenset(
        {
            ("UNINITIALIZED", "policy_activated", "ACTIVE"),
            ("ACTIVE", "policy_activated", "ACTIVE"),
            ("UNINITIALIZED", "canonical_conflict", "RECOVERY_REQUIRED"),
            ("ACTIVE", "canonical_conflict", "RECOVERY_REQUIRED"),
            ("RECOVERY_REQUIRED", "canonical_conflict", "RECOVERY_REQUIRED"),
            ("RECOVERY_REQUIRED", "policy_recovery", "ACTIVE"),
        },
    ),
}


MATRIX_SPECS = (
    ("authority", AUTHORITY_MATRIX, AuthorityState, AuthorityTransitionEvent, 66, 25),
    ("task", TASK_MATRIX, TaskState, TaskTransitionEvent, 154, 27),
    ("capability", CAPABILITY_MATRIX, CapabilityState, CapabilityTransitionEvent, 42, 10),
    ("run", RUN_MATRIX, RunState, RunOutcome, 90, 16),
    ("receipt", RECEIPT_MATRIX, ReceiptState, ReceiptTransitionEvent, 30, 7),
    ("promotion", PROMOTION_MATRIX, PromotionState, PromotionTransitionEvent, 42, 10),
    ("policy", POLICY_MATRIX, PolicyState, PolicyTransitionEvent, 12, 6),
)


TERMINAL_STATES = {
    "task": frozenset(
        {
            TaskState.PROMOTED,
            TaskState.COMPLETED_NO_CHANGE,
            TaskState.REJECTED,
            TaskState.QUARANTINED,
            TaskState.REVOKED,
            TaskState.EXPIRED,
        },
    ),
    "capability": frozenset(
        {CapabilityState.EXPIRED, CapabilityState.REVOKED, CapabilityState.CONSUMED},
    ),
    "run": frozenset(
        {
            RunState.SUCCEEDED,
            RunState.FAILED,
            RunState.CANCELLED,
            RunState.TIMED_OUT,
            RunState.DENIED,
        },
    ),
    "receipt": frozenset(
        {ReceiptState.VERIFIED, ReceiptState.REJECTED, ReceiptState.QUARANTINED},
    ),
    "promotion": frozenset(
        {
            PromotionState.PROMOTED,
            PromotionState.REJECTED,
            PromotionState.QUARANTINED,
        },
    ),
}


class ForeignEnum(Enum):
    ACTIVE = "ACTIVE"
    TASK_ISSUED = "task_issued"


class HostileValue:
    calls = 0

    def __eq__(self, other):
        type(self).calls += 1
        raise RuntimeError("HOSTILE_TRANSITION_SENTINEL")

    def __hash__(self):
        type(self).calls += 1
        raise RuntimeError("HOSTILE_TRANSITION_SENTINEL")

    def __repr__(self):
        type(self).calls += 1
        return "HOSTILE_TRANSITION_SENTINEL"

    def __str__(self):
        type(self).calls += 1
        return "HOSTILE_TRANSITION_SENTINEL"


class TestClosedTransitionMatrices(unittest.TestCase):
    def test_exact_closed_vocabularies(self):
        for enum_type, expected_values in EXPECTED_VOCABULARIES.items():
            with self.subTest(enum=enum_type.__name__):
                actual = tuple(member.value for member in enum_type)
                self.assertEqual(actual, expected_values)
                self.assertEqual(len(actual), len(set(actual)))

    def test_matrices_are_full_cartesian_and_exactly_classified(self):
        for name, matrix, state_type, event_type, total, allowed in MATRIX_SPECS:
            with self.subTest(matrix=name):
                expected_pairs = frozenset(product(state_type, event_type))
                actual_pairs = frozenset((cell.state, cell.event) for cell in matrix)
                uncovered = expected_pairs - actual_pairs
                extra = actual_pairs - expected_pairs
                allowed_cells = tuple(
                    cell
                    for cell in matrix
                    if cell.decision.disposition is TransitionDisposition.ALLOWED
                )
                denied_cells = tuple(
                    cell
                    for cell in matrix
                    if cell.decision.disposition is TransitionDisposition.DENIED
                )
                print(
                    f"matrix_{name} total={len(matrix)} allowed={len(allowed_cells)} "
                    f"denied={len(denied_cells)} uncovered={len(uncovered)}",
                )
                self.assertEqual(len(matrix), total)
                self.assertEqual(len(actual_pairs), total)
                self.assertEqual(len(allowed_cells), allowed)
                self.assertEqual(len(denied_cells), total - allowed)
                self.assertEqual(uncovered, frozenset())
                self.assertEqual(extra, frozenset())
                self.assertEqual(len(allowed_cells) + len(denied_cells), total)

    def test_all_seven_allowed_transition_sets_match_normative_rules_exactly(self):
        for name, matrix, _, _, _, _ in MATRIX_SPECS:
            with self.subTest(matrix=name):
                actual = frozenset(
                    (
                        cell.state.value,
                        cell.event.value,
                        cell.decision.resulting_state.value,
                    )
                    for cell in matrix
                    if cell.decision.disposition is TransitionDisposition.ALLOWED
                )
                self.assertEqual(actual, EXPECTED_ALLOWED[name])

    def test_every_denied_cell_preserves_its_current_state(self):
        for name, matrix, _, _, _, _ in MATRIX_SPECS:
            for cell in matrix:
                if cell.decision.disposition is TransitionDisposition.DENIED:
                    with self.subTest(matrix=name, state=cell.state, event=cell.event):
                        self.assertIs(cell.decision.resulting_state, cell.state)

    def test_terminal_states_remain_terminal_for_every_event_family(self):
        matrices = {name: matrix for name, matrix, *_ in MATRIX_SPECS}
        for name, states in TERMINAL_STATES.items():
            for cell in matrices[name]:
                if cell.state in states:
                    with self.subTest(matrix=name, state=cell.state, event=cell.event):
                        self.assertIs(cell.decision.resulting_state, cell.state)

    def test_removing_one_entry_creates_exactly_one_uncovered_cell(self):
        for name, matrix, state_type, event_type, _, _ in MATRIX_SPECS:
            with self.subTest(matrix=name):
                mutated = matrix[:-1]
                expected_pairs = frozenset(product(state_type, event_type))
                actual_pairs = frozenset((cell.state, cell.event) for cell in mutated)
                self.assertEqual(len(expected_pairs - actual_pairs), 1)

    def test_runtime_lookup_returns_the_same_immutable_decision_as_each_cell(self):
        lookups = {
            "authority": authority_transition,
            "task": task_transition,
            "capability": capability_transition,
            "run": run_transition,
            "receipt": receipt_transition,
            "promotion": promotion_transition,
            "policy": policy_transition,
        }
        for name, matrix, *_ in MATRIX_SPECS:
            lookup = lookups[name]
            for cell in matrix:
                with self.subTest(matrix=name, state=cell.state, event=cell.event):
                    self.assertIs(lookup(cell.state, cell.event), cell.decision)

    def test_decisions_and_cells_are_deeply_immutable_and_redacted(self):
        for _, matrix, *_ in MATRIX_SPECS:
            for cell in matrix:
                self.assertFalse(hasattr(cell, "__dict__"))
                self.assertFalse(hasattr(cell.decision, "__dict__"))
                self.assertIsInstance(hash(cell), int)
                self.assertIsInstance(hash(cell.decision), int)
                self.assertEqual(repr(cell), "TransitionCell(...)")
                self.assertEqual(repr(cell.decision), "TransitionDecision(...)")
                with self.assertRaises(FrozenInstanceError):
                    cell.decision.resulting_state = cell.state

    def test_invented_cross_enum_and_hostile_values_deny_without_dispatch_or_echo(self):
        HostileValue.calls = 0
        cases = (
            (authority_transition, ForeignEnum.ACTIVE, AuthorityTransitionEvent.LEASE_RENEWED),
            (authority_transition, AuthorityState.ACTIVE, ForeignEnum.TASK_ISSUED),
            (task_transition, AuthorityState.ACTIVE, TaskTransitionEvent.TASK_ISSUED),
            (capability_transition, HostileValue(), CapabilityTransitionEvent.FIRST_VALID_USE),
            (run_transition, RunState.RUNNING, HostileValue()),
            (receipt_transition, "SUBMITTED", ReceiptTransitionEvent.RECEIPT_ACCEPTED),
            (promotion_transition, PromotionState.NONE, None),
            (policy_transition, PolicyState.ACTIVE, 1),
        )
        for lookup, state, event in cases:
            with self.subTest(lookup=lookup.__name__):
                result = lookup(state, event)
                self.assertIs(type(result), Denied)
                self.assertIs(result.code, ReasonCode.SCHEMA_INVALID)
                self.assertEqual(str(result), "Denied(code=SCHEMA_INVALID)")
                self.assertNotIn("HOSTILE_TRANSITION_SENTINEL", str(result))
        self.assertEqual(HostileValue.calls, 0)


class TestEventBindingMatrix(unittest.TestCase):
    @staticmethod
    def _schema_binding_rules():
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        event_schema = schema["$defs"]["authorityEvent"]
        events = tuple(event_schema["properties"]["event_type"]["enum"])
        object_kinds = tuple(event_schema["properties"]["object_kind"]["enum"])
        domains = tuple(
            event_schema["properties"]["transition"]["properties"]["state_machine"]["enum"],
        )
        rules = set()
        for condition in event_schema["allOf"]:
            event_rule = (
                condition.get("if", {})
                .get("properties", {})
                .get("event_type", {})
                .get("enum")
            )
            if event_rule is None:
                continue
            then = condition["then"]["properties"]
            object_kind = then["object_kind"]["const"]
            domain = then["transition"]["properties"]["state_machine"]["const"]
            for event in event_rule:
                rules.add((event, object_kind, domain))
        return events, object_kinds, domains, frozenset(rules)

    def test_closed_binding_vocabularies_and_positive_allowlist_match_schema_exactly(self):
        events, objects, domains, schema_rules = self._schema_binding_rules()
        self.assertEqual(tuple(member.value for member in AuthorityEventType), events)
        self.assertEqual(tuple(member.value for member in ObjectKind), objects)
        self.assertEqual(tuple(member.value for member in StateMachineDomain), domains)
        actual_rules = frozenset(
            (cell.event_type.value, cell.object_kind.value, cell.domain.value)
            for cell in BINDING_MATRIX
            if cell.decision.allowed
        )
        self.assertEqual(len(schema_rules), 22)
        self.assertEqual(actual_rules, schema_rules)

    def test_full_binding_cartesian_has_no_uncovered_or_duplicate_tuple(self):
        expected = frozenset(product(AuthorityEventType, ObjectKind, StateMachineDomain))
        actual = frozenset(
            (cell.event_type, cell.object_kind, cell.domain)
            for cell in BINDING_MATRIX
        )
        allowed = tuple(cell for cell in BINDING_MATRIX if cell.decision.allowed)
        denied = tuple(cell for cell in BINDING_MATRIX if not cell.decision.allowed)
        uncovered = expected - actual
        print(
            f"matrix_binding total={len(BINDING_MATRIX)} allowed={len(allowed)} "
            f"denied={len(denied)} uncovered={len(uncovered)}",
        )
        self.assertEqual(len(expected), 22 * 8 * 6)
        self.assertEqual(len(BINDING_MATRIX), 1056)
        self.assertEqual(len(actual), 1056)
        self.assertEqual(len(allowed), 22)
        self.assertEqual(len(denied), 1034)
        self.assertEqual(uncovered, frozenset())
        self.assertEqual(actual - expected, frozenset())

    def test_every_binding_tuple_resolves_to_the_precomputed_immutable_decision(self):
        for cell in BINDING_MATRIX:
            with self.subTest(
                event=cell.event_type,
                object_kind=cell.object_kind,
                domain=cell.domain,
            ):
                result = event_binding(cell.event_type, cell.object_kind, cell.domain)
                self.assertIs(result, cell.decision)
                self.assertIs(type(result), BindingDecision)
                self.assertFalse(hasattr(result, "__dict__"))
                self.assertFalse(hasattr(cell, "__dict__"))
                self.assertIsInstance(hash(result), int)
                self.assertIsInstance(hash(cell), int)
                self.assertEqual(repr(result), "BindingDecision(...)")
                self.assertEqual(repr(cell), "BindingCell(...)")

    def test_every_non_allowlisted_binding_denies(self):
        _, _, _, schema_rules = self._schema_binding_rules()
        for cell in BINDING_MATRIX:
            key = (cell.event_type.value, cell.object_kind.value, cell.domain.value)
            with self.subTest(key=key):
                self.assertEqual(cell.decision.allowed, key in schema_rules)

    def test_removing_one_binding_entry_creates_one_uncovered_tuple(self):
        mutated = BINDING_MATRIX[:-1]
        expected = frozenset(product(AuthorityEventType, ObjectKind, StateMachineDomain))
        actual = frozenset(
            (cell.event_type, cell.object_kind, cell.domain)
            for cell in mutated
        )
        self.assertEqual(len(expected - actual), 1)

    def test_binding_hostile_and_cross_enum_values_deny_before_comparison(self):
        HostileValue.calls = 0
        cases = (
            (HostileValue(), ObjectKind.AUTHORITY, StateMachineDomain.AUTHORITY),
            (AuthorityEventType.AUTHORITY_INITIALIZED, HostileValue(), StateMachineDomain.AUTHORITY),
            (AuthorityEventType.AUTHORITY_INITIALIZED, ObjectKind.AUTHORITY, HostileValue()),
            (ForeignEnum.TASK_ISSUED, ObjectKind.TASK_ENVELOPE, StateMachineDomain.TASK),
            (AuthorityEventType.TASK_ISSUED, ContractKindLike.TASK_ENVELOPE, StateMachineDomain.TASK),
            (AuthorityEventType.TASK_ISSUED, ObjectKind.TASK_ENVELOPE, AuthorityState.ACTIVE),
        )
        for event, object_kind, domain in cases:
            result = event_binding(event, object_kind, domain)
            self.assertIs(type(result), Denied)
            self.assertIs(result.code, ReasonCode.SCHEMA_INVALID)
            self.assertEqual(str(result), "Denied(code=SCHEMA_INVALID)")
        self.assertEqual(HostileValue.calls, 0)


class ContractKindLike(Enum):
    TASK_ENVELOPE = "task_envelope"


class TestTransitionArchitecture(unittest.TestCase):
    def test_source_has_no_ambient_or_external_capability_imports(self):
        self.assertTrue(SOURCE.is_file())
        source = SOURCE.read_text(encoding="utf-8")
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
                    "asyncio",
                    "datetime",
                    "ftplib",
                    "http",
                    "os",
                    "pathlib",
                    "random",
                    "requests",
                    "socket",
                    "ssl",
                    "subprocess",
                    "time",
                    "urllib",
                },
            ),
        )
        for forbidden in (
            "datetime.now",
            "datetime.utcnow",
            "time.time",
            "os.environ",
            "open(",
            "Path(",
            "subprocess.",
            "socket.",
        ):
            self.assertNotIn(forbidden, source)

    def test_public_constants_expose_no_mutable_dictionary(self):
        import authority_sim.transitions as transitions

        public_values = {
            name: value
            for name, value in vars(transitions).items()
            if not name.startswith("_")
        }
        dictionaries = {
            name: value
            for name, value in public_values.items()
            if type(value) is dict
        }
        self.assertEqual(dictionaries, {})
        for name in (
            "AUTHORITY_MATRIX",
            "TASK_MATRIX",
            "CAPABILITY_MATRIX",
            "RUN_MATRIX",
            "RECEIPT_MATRIX",
            "PROMOTION_MATRIX",
            "POLICY_MATRIX",
            "BINDING_MATRIX",
        ):
            self.assertIs(type(public_values[name]), tuple)


if __name__ == "__main__":
    unittest.main()
