from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, unique

from authority_sim.errors import Denied, ReasonCode


@unique
class TransitionDisposition(Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


@unique
class AuthorityState(Enum):
    UNINITIALIZED = "UNINITIALIZED"
    NO_WRITER = "NO_WRITER"
    ACTIVE = "ACTIVE"
    FENCED = "FENCED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    HALTED = "HALTED"


@unique
class AuthorityTransitionEvent(Enum):
    AUTHORITY_INITIALIZED = "authority_initialized"
    LEASE_RENEWED = "lease_renewed"
    LEASE_RELEASED = "lease_released"
    LEASE_EXPIRED = "lease_expired"
    AUTHORITY_FENCED = "authority_fenced"
    LEASE_ACQUIRED = "lease_acquired"
    RECOVERY_STARTED = "recovery_started"
    CONTRADICTION = "contradiction"
    RESTORE_VERIFIED = "restore_verified"
    AUTHORITY_HALTED = "authority_halted"
    ORDINARY_WRITE = "ordinary_write"


@unique
class TaskState(Enum):
    NONE = "NONE"
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    PROMOTION_PENDING = "PROMOTION_PENDING"
    PROMOTED = "PROMOTED"
    COMPLETED_NO_CHANGE = "COMPLETED_NO_CHANGE"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@unique
class TaskTransitionEvent(Enum):
    TASK_ISSUED = "task_issued"
    FIRST_RUN_CLAIMED = "first_run_claimed"
    RECEIPT_SUBMITTED = "receipt_submitted"
    RECEIPT_VERIFIED = "receipt_verified"
    RECEIPT_REJECTED_RETRYABLE = "receipt_rejected_retryable"
    RECEIPT_REJECTED_FINAL = "receipt_rejected_final"
    PROMOTION_RECORDED = "promotion_recorded"
    RECORD_NO_CHANGE = "record_no_change"
    PROPOSAL_REJECTED = "proposal_rejected"
    EVIDENCE_CONTRADICTION = "evidence_contradiction"
    TASK_REVOKED = "task_revoked"
    TASK_EXPIRED = "task_expired"
    BYTE_IDENTICAL_REPLAY = "byte_identical_replay"
    NEW_RUN_OR_PROPOSAL = "new_run_or_proposal"


@unique
class CapabilityState(Enum):
    NONE = "NONE"
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    CONSUMED = "CONSUMED"


@unique
class CapabilityTransitionEvent(Enum):
    CAPABILITY_ISSUED = "capability_issued"
    FIRST_VALID_USE = "first_valid_use"
    CAPABILITY_EXPIRED = "capability_expired"
    CAPABILITY_REVOKED = "capability_revoked"
    SINGLE_USE_CONSUMED = "single_use_consumed"
    USE_OR_REISSUE_ATTEMPT = "use_or_reissue_attempt"
    BYTE_IDENTICAL_REPLAY = "byte_identical_replay"


@unique
class RunState(Enum):
    NONE = "NONE"
    CREATED = "CREATED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    DENIED = "DENIED"


@unique
class RunOutcome(Enum):
    RUN_CREATED = "run_created"
    RUN_CLAIMED = "run_claimed"
    RUN_STARTED = "run_started"
    EXIT_ZERO = "exit_zero"
    EXIT_NONZERO = "exit_nonzero"
    CANCELLATION_ACCEPTED = "cancellation_accepted"
    DEADLINE_REACHED = "deadline_reached"
    CHECK_FAILED = "check_failed"
    BYTE_IDENTICAL_REPLAY = "byte_identical_replay"
    RELABEL_ATTEMPT = "relabel_attempt"


@unique
class ReceiptState(Enum):
    NONE = "NONE"
    SUBMITTED = "SUBMITTED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"


@unique
class ReceiptTransitionEvent(Enum):
    RECEIPT_SUBMITTED = "receipt_submitted"
    RECEIPT_ACCEPTED = "receipt_accepted"
    RECEIPT_REJECTED = "receipt_rejected"
    RECEIPT_QUARANTINED = "receipt_quarantined"
    BYTE_IDENTICAL_REPLAY = "byte_identical_replay"
    BYTE_DIFFERENT_REPLAY = "byte_different_replay"


@unique
class PromotionState(Enum):
    NONE = "NONE"
    PROPOSAL_RECEIVED = "PROPOSAL_RECEIVED"
    RECEIPT_VERIFIED = "RECEIPT_VERIFIED"
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"


@unique
class PromotionTransitionEvent(Enum):
    PROPOSAL_SUBMITTED = "proposal_submitted"
    RECEIPTS_VERIFIED = "receipts_verified"
    VALIDATION_REJECTED = "validation_rejected"
    CONTRADICTION = "contradiction"
    PROMOTION_DECISION = "promotion_decision"
    BYTE_IDENTICAL_REPLAY = "byte_identical_replay"
    ALTERNATE_RESULT = "alternate_result"


@unique
class PolicyState(Enum):
    UNINITIALIZED = "UNINITIALIZED"
    ACTIVE = "ACTIVE"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


@unique
class PolicyTransitionEvent(Enum):
    POLICY_ACTIVATED = "policy_activated"
    ROLLBACK_ATTEMPT = "rollback_attempt"
    CANONICAL_CONFLICT = "canonical_conflict"
    POLICY_RECOVERY = "policy_recovery"


@unique
class AuthorityEventType(Enum):
    AUTHORITY_INITIALIZED = "authority_initialized"
    LEASE_ACQUIRED = "lease_acquired"
    LEASE_RENEWED = "lease_renewed"
    LEASE_RELEASED = "lease_released"
    AUTHORITY_FENCED = "authority_fenced"
    RECOVERY_STARTED = "recovery_started"
    TASK_ISSUED = "task_issued"
    TASK_REVOKED = "task_revoked"
    CAPABILITY_ISSUED = "capability_issued"
    CAPABILITY_REVOKED = "capability_revoked"
    RECEIPT_ACCEPTED = "receipt_accepted"
    RECEIPT_REJECTED = "receipt_rejected"
    PROMOTION_RECORDED = "promotion_recorded"
    PROMOTION_REJECTED = "promotion_rejected"
    POLICY_ACTIVATED = "policy_activated"
    POLICY_RECOVERY = "policy_recovery"
    RESTORE_VERIFIED = "restore_verified"
    RESTORE_REJECTED = "restore_rejected"
    AUTHORITY_HALTED = "authority_halted"
    CAPABILITY_CONSUMED = "capability_consumed"
    RECEIPT_QUARANTINED = "receipt_quarantined"
    PROMOTION_QUARANTINED = "promotion_quarantined"


@unique
class ObjectKind(Enum):
    AUTHORITY = "authority"
    AUTHORITY_LEASE = "authority_lease"
    TASK_ENVELOPE = "task_envelope"
    CAPABILITY_CLAIM = "capability_claim"
    EXECUTION_RECEIPT = "execution_receipt"
    PROMOTION_DECISION = "promotion_decision"
    POLICY_EVIDENCE = "policy_evidence"
    RESTORE_EVIDENCE = "restore_evidence"


@unique
class StateMachineDomain(Enum):
    AUTHORITY = "authority"
    TASK = "task"
    CAPABILITY = "capability"
    RECEIPT = "receipt"
    PROMOTION = "promotion"
    POLICY = "policy"


_STATE_TYPES = (
    AuthorityState,
    TaskState,
    CapabilityState,
    RunState,
    ReceiptState,
    PromotionState,
    PolicyState,
)
_EVENT_TYPES = (
    AuthorityTransitionEvent,
    TaskTransitionEvent,
    CapabilityTransitionEvent,
    RunOutcome,
    ReceiptTransitionEvent,
    PromotionTransitionEvent,
    PolicyTransitionEvent,
)
_MATRIX_TYPES = tuple(zip(_STATE_TYPES, _EVENT_TYPES, strict=True))


@dataclass(frozen=True, slots=True, repr=False)
class TransitionDecision:
    disposition: TransitionDisposition
    resulting_state: Enum

    def __post_init__(self) -> None:
        if type(self.disposition) is not TransitionDisposition:
            raise TypeError("TRANSITION_INVALID") from None
        if not any(type(self.resulting_state) is state_type for state_type in _STATE_TYPES):
            raise TypeError("TRANSITION_INVALID") from None

    @property
    def allowed(self) -> bool:
        return self.disposition is TransitionDisposition.ALLOWED

    def __repr__(self) -> str:
        return "TransitionDecision(...)"


@dataclass(frozen=True, slots=True, repr=False)
class TransitionCell:
    state: Enum
    event: Enum
    decision: TransitionDecision

    def __post_init__(self) -> None:
        valid_pair = any(
            type(self.state) is state_type and type(self.event) is event_type
            for state_type, event_type in _MATRIX_TYPES
        )
        if not valid_pair or type(self.decision) is not TransitionDecision:
            raise TypeError("TRANSITION_INVALID") from None
        if type(self.decision.resulting_state) is not type(self.state):
            raise TypeError("TRANSITION_INVALID") from None
        if (
            self.decision.disposition is TransitionDisposition.DENIED
            and self.decision.resulting_state is not self.state
        ):
            raise TypeError("TRANSITION_INVALID") from None

    def __repr__(self) -> str:
        return "TransitionCell(...)"


@dataclass(frozen=True, slots=True, repr=False)
class BindingDecision:
    allowed: bool

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise TypeError("TRANSITION_INVALID") from None

    def __repr__(self) -> str:
        return "BindingDecision(...)"


@dataclass(frozen=True, slots=True, repr=False)
class BindingCell:
    event_type: AuthorityEventType
    object_kind: ObjectKind
    domain: StateMachineDomain
    decision: BindingDecision

    def __post_init__(self) -> None:
        if (
            type(self.event_type) is not AuthorityEventType
            or type(self.object_kind) is not ObjectKind
            or type(self.domain) is not StateMachineDomain
            or type(self.decision) is not BindingDecision
        ):
            raise TypeError("TRANSITION_INVALID") from None

    def __repr__(self) -> str:
        return "BindingCell(...)"


_AUTHORITY_RULES = (
    (AuthorityState.UNINITIALIZED, AuthorityTransitionEvent.AUTHORITY_INITIALIZED, AuthorityState.ACTIVE),
    (AuthorityState.UNINITIALIZED, AuthorityTransitionEvent.RECOVERY_STARTED, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.UNINITIALIZED, AuthorityTransitionEvent.CONTRADICTION, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.UNINITIALIZED, AuthorityTransitionEvent.AUTHORITY_HALTED, AuthorityState.HALTED),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.LEASE_RENEWED, AuthorityState.ACTIVE),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.LEASE_RELEASED, AuthorityState.NO_WRITER),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.LEASE_EXPIRED, AuthorityState.NO_WRITER),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.AUTHORITY_FENCED, AuthorityState.FENCED),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.LEASE_ACQUIRED, AuthorityState.ACTIVE),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.RECOVERY_STARTED, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.CONTRADICTION, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.ACTIVE, AuthorityTransitionEvent.AUTHORITY_HALTED, AuthorityState.HALTED),
    (AuthorityState.NO_WRITER, AuthorityTransitionEvent.LEASE_ACQUIRED, AuthorityState.ACTIVE),
    (AuthorityState.NO_WRITER, AuthorityTransitionEvent.RECOVERY_STARTED, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.NO_WRITER, AuthorityTransitionEvent.CONTRADICTION, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.NO_WRITER, AuthorityTransitionEvent.AUTHORITY_HALTED, AuthorityState.HALTED),
    (AuthorityState.FENCED, AuthorityTransitionEvent.RECOVERY_STARTED, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.FENCED, AuthorityTransitionEvent.CONTRADICTION, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.FENCED, AuthorityTransitionEvent.AUTHORITY_HALTED, AuthorityState.HALTED),
    (AuthorityState.RECOVERY_REQUIRED, AuthorityTransitionEvent.RECOVERY_STARTED, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.RECOVERY_REQUIRED, AuthorityTransitionEvent.CONTRADICTION, AuthorityState.RECOVERY_REQUIRED),
    (AuthorityState.RECOVERY_REQUIRED, AuthorityTransitionEvent.RESTORE_VERIFIED, AuthorityState.ACTIVE),
    (AuthorityState.RECOVERY_REQUIRED, AuthorityTransitionEvent.AUTHORITY_HALTED, AuthorityState.HALTED),
    (AuthorityState.HALTED, AuthorityTransitionEvent.RESTORE_VERIFIED, AuthorityState.ACTIVE),
    (AuthorityState.HALTED, AuthorityTransitionEvent.AUTHORITY_HALTED, AuthorityState.HALTED),
)

_TASK_LIVE_STATES = (
    TaskState.ISSUED,
    TaskState.ACTIVE,
    TaskState.EVIDENCE_PENDING,
    TaskState.PROMOTION_PENDING,
)
_TASK_TERMINAL_STATES = (
    TaskState.PROMOTED,
    TaskState.COMPLETED_NO_CHANGE,
    TaskState.REJECTED,
    TaskState.QUARANTINED,
    TaskState.REVOKED,
    TaskState.EXPIRED,
)
_TASK_RULES = (
    (TaskState.NONE, TaskTransitionEvent.TASK_ISSUED, TaskState.ISSUED),
    (TaskState.ISSUED, TaskTransitionEvent.FIRST_RUN_CLAIMED, TaskState.ACTIVE),
    (TaskState.ACTIVE, TaskTransitionEvent.RECEIPT_SUBMITTED, TaskState.EVIDENCE_PENDING),
    (TaskState.EVIDENCE_PENDING, TaskTransitionEvent.RECEIPT_VERIFIED, TaskState.PROMOTION_PENDING),
    (TaskState.EVIDENCE_PENDING, TaskTransitionEvent.RECEIPT_REJECTED_RETRYABLE, TaskState.ACTIVE),
    (TaskState.EVIDENCE_PENDING, TaskTransitionEvent.RECEIPT_REJECTED_FINAL, TaskState.REJECTED),
    (TaskState.PROMOTION_PENDING, TaskTransitionEvent.PROMOTION_RECORDED, TaskState.PROMOTED),
    (TaskState.PROMOTION_PENDING, TaskTransitionEvent.RECORD_NO_CHANGE, TaskState.COMPLETED_NO_CHANGE),
    (TaskState.PROMOTION_PENDING, TaskTransitionEvent.PROPOSAL_REJECTED, TaskState.REJECTED),
) + tuple(
    (state, TaskTransitionEvent.EVIDENCE_CONTRADICTION, TaskState.QUARANTINED)
    for state in _TASK_LIVE_STATES
) + tuple(
    (state, TaskTransitionEvent.TASK_REVOKED, TaskState.REVOKED)
    for state in _TASK_LIVE_STATES
) + tuple(
    (state, TaskTransitionEvent.TASK_EXPIRED, TaskState.EXPIRED)
    for state in _TASK_LIVE_STATES
) + tuple(
    (state, TaskTransitionEvent.BYTE_IDENTICAL_REPLAY, state)
    for state in _TASK_TERMINAL_STATES
)

_CAPABILITY_TERMINAL_STATES = (
    CapabilityState.EXPIRED,
    CapabilityState.REVOKED,
    CapabilityState.CONSUMED,
)
_CAPABILITY_RULES = (
    (CapabilityState.NONE, CapabilityTransitionEvent.CAPABILITY_ISSUED, CapabilityState.ISSUED),
    (CapabilityState.ISSUED, CapabilityTransitionEvent.FIRST_VALID_USE, CapabilityState.ACTIVE),
    (CapabilityState.ISSUED, CapabilityTransitionEvent.CAPABILITY_EXPIRED, CapabilityState.EXPIRED),
    (CapabilityState.ACTIVE, CapabilityTransitionEvent.CAPABILITY_EXPIRED, CapabilityState.EXPIRED),
    (CapabilityState.ISSUED, CapabilityTransitionEvent.CAPABILITY_REVOKED, CapabilityState.REVOKED),
    (CapabilityState.ACTIVE, CapabilityTransitionEvent.CAPABILITY_REVOKED, CapabilityState.REVOKED),
    (CapabilityState.ACTIVE, CapabilityTransitionEvent.SINGLE_USE_CONSUMED, CapabilityState.CONSUMED),
) + tuple(
    (state, CapabilityTransitionEvent.BYTE_IDENTICAL_REPLAY, state)
    for state in _CAPABILITY_TERMINAL_STATES
)

_RUN_TERMINAL_STATES = (
    RunState.SUCCEEDED,
    RunState.FAILED,
    RunState.CANCELLED,
    RunState.TIMED_OUT,
    RunState.DENIED,
)
_RUN_RULES = (
    (RunState.NONE, RunOutcome.RUN_CREATED, RunState.CREATED),
    (RunState.CREATED, RunOutcome.RUN_CLAIMED, RunState.CLAIMED),
    (RunState.CLAIMED, RunOutcome.RUN_STARTED, RunState.RUNNING),
    (RunState.RUNNING, RunOutcome.EXIT_ZERO, RunState.SUCCEEDED),
    (RunState.RUNNING, RunOutcome.EXIT_NONZERO, RunState.FAILED),
    (RunState.CREATED, RunOutcome.CANCELLATION_ACCEPTED, RunState.CANCELLED),
    (RunState.CLAIMED, RunOutcome.CANCELLATION_ACCEPTED, RunState.CANCELLED),
    (RunState.RUNNING, RunOutcome.CANCELLATION_ACCEPTED, RunState.CANCELLED),
    (RunState.RUNNING, RunOutcome.DEADLINE_REACHED, RunState.TIMED_OUT),
    (RunState.CREATED, RunOutcome.CHECK_FAILED, RunState.DENIED),
    (RunState.CLAIMED, RunOutcome.CHECK_FAILED, RunState.DENIED),
) + tuple(
    (state, RunOutcome.BYTE_IDENTICAL_REPLAY, state)
    for state in _RUN_TERMINAL_STATES
)

_RECEIPT_TERMINAL_STATES = (
    ReceiptState.VERIFIED,
    ReceiptState.REJECTED,
    ReceiptState.QUARANTINED,
)
_RECEIPT_RULES = (
    (ReceiptState.NONE, ReceiptTransitionEvent.RECEIPT_SUBMITTED, ReceiptState.SUBMITTED),
    (ReceiptState.SUBMITTED, ReceiptTransitionEvent.RECEIPT_ACCEPTED, ReceiptState.VERIFIED),
    (ReceiptState.SUBMITTED, ReceiptTransitionEvent.RECEIPT_REJECTED, ReceiptState.REJECTED),
    (ReceiptState.SUBMITTED, ReceiptTransitionEvent.RECEIPT_QUARANTINED, ReceiptState.QUARANTINED),
) + tuple(
    (state, ReceiptTransitionEvent.BYTE_IDENTICAL_REPLAY, state)
    for state in _RECEIPT_TERMINAL_STATES
)

_PROMOTION_TERMINAL_STATES = (
    PromotionState.PROMOTED,
    PromotionState.REJECTED,
    PromotionState.QUARANTINED,
)
_PROMOTION_RULES = (
    (PromotionState.NONE, PromotionTransitionEvent.PROPOSAL_SUBMITTED, PromotionState.PROPOSAL_RECEIVED),
    (PromotionState.PROPOSAL_RECEIVED, PromotionTransitionEvent.RECEIPTS_VERIFIED, PromotionState.RECEIPT_VERIFIED),
    (PromotionState.PROPOSAL_RECEIVED, PromotionTransitionEvent.VALIDATION_REJECTED, PromotionState.REJECTED),
    (PromotionState.RECEIPT_VERIFIED, PromotionTransitionEvent.VALIDATION_REJECTED, PromotionState.REJECTED),
    (PromotionState.PROPOSAL_RECEIVED, PromotionTransitionEvent.CONTRADICTION, PromotionState.QUARANTINED),
    (PromotionState.RECEIPT_VERIFIED, PromotionTransitionEvent.CONTRADICTION, PromotionState.QUARANTINED),
    (PromotionState.RECEIPT_VERIFIED, PromotionTransitionEvent.PROMOTION_DECISION, PromotionState.PROMOTED),
) + tuple(
    (state, PromotionTransitionEvent.BYTE_IDENTICAL_REPLAY, state)
    for state in _PROMOTION_TERMINAL_STATES
)

_POLICY_RULES = (
    (PolicyState.UNINITIALIZED, PolicyTransitionEvent.POLICY_ACTIVATED, PolicyState.ACTIVE),
    (PolicyState.ACTIVE, PolicyTransitionEvent.POLICY_ACTIVATED, PolicyState.ACTIVE),
    (PolicyState.UNINITIALIZED, PolicyTransitionEvent.CANONICAL_CONFLICT, PolicyState.RECOVERY_REQUIRED),
    (PolicyState.ACTIVE, PolicyTransitionEvent.CANONICAL_CONFLICT, PolicyState.RECOVERY_REQUIRED),
    (PolicyState.RECOVERY_REQUIRED, PolicyTransitionEvent.CANONICAL_CONFLICT, PolicyState.RECOVERY_REQUIRED),
    (PolicyState.RECOVERY_REQUIRED, PolicyTransitionEvent.POLICY_RECOVERY, PolicyState.ACTIVE),
)

_BINDING_RULES = (
    (AuthorityEventType.AUTHORITY_INITIALIZED, ObjectKind.AUTHORITY, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.AUTHORITY_FENCED, ObjectKind.AUTHORITY, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.AUTHORITY_HALTED, ObjectKind.AUTHORITY, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.RECOVERY_STARTED, ObjectKind.AUTHORITY, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.LEASE_ACQUIRED, ObjectKind.AUTHORITY_LEASE, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.LEASE_RENEWED, ObjectKind.AUTHORITY_LEASE, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.LEASE_RELEASED, ObjectKind.AUTHORITY_LEASE, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.TASK_ISSUED, ObjectKind.TASK_ENVELOPE, StateMachineDomain.TASK),
    (AuthorityEventType.TASK_REVOKED, ObjectKind.TASK_ENVELOPE, StateMachineDomain.TASK),
    (AuthorityEventType.CAPABILITY_ISSUED, ObjectKind.CAPABILITY_CLAIM, StateMachineDomain.CAPABILITY),
    (AuthorityEventType.CAPABILITY_REVOKED, ObjectKind.CAPABILITY_CLAIM, StateMachineDomain.CAPABILITY),
    (AuthorityEventType.CAPABILITY_CONSUMED, ObjectKind.CAPABILITY_CLAIM, StateMachineDomain.CAPABILITY),
    (AuthorityEventType.RECEIPT_ACCEPTED, ObjectKind.EXECUTION_RECEIPT, StateMachineDomain.RECEIPT),
    (AuthorityEventType.RECEIPT_REJECTED, ObjectKind.EXECUTION_RECEIPT, StateMachineDomain.RECEIPT),
    (AuthorityEventType.RECEIPT_QUARANTINED, ObjectKind.EXECUTION_RECEIPT, StateMachineDomain.RECEIPT),
    (AuthorityEventType.PROMOTION_RECORDED, ObjectKind.PROMOTION_DECISION, StateMachineDomain.PROMOTION),
    (AuthorityEventType.PROMOTION_REJECTED, ObjectKind.PROMOTION_DECISION, StateMachineDomain.PROMOTION),
    (AuthorityEventType.PROMOTION_QUARANTINED, ObjectKind.PROMOTION_DECISION, StateMachineDomain.PROMOTION),
    (AuthorityEventType.POLICY_ACTIVATED, ObjectKind.POLICY_EVIDENCE, StateMachineDomain.POLICY),
    (AuthorityEventType.POLICY_RECOVERY, ObjectKind.POLICY_EVIDENCE, StateMachineDomain.POLICY),
    (AuthorityEventType.RESTORE_VERIFIED, ObjectKind.RESTORE_EVIDENCE, StateMachineDomain.AUTHORITY),
    (AuthorityEventType.RESTORE_REJECTED, ObjectKind.RESTORE_EVIDENCE, StateMachineDomain.AUTHORITY),
)


def _result_for(
    state: Enum,
    event: Enum,
    rules: tuple[tuple[Enum, Enum, Enum], ...],
) -> TransitionDecision:
    for current_state, candidate_event, resulting_state in rules:
        if current_state is state and candidate_event is event:
            return TransitionDecision(
                TransitionDisposition.ALLOWED,
                resulting_state,
            )
    return TransitionDecision(TransitionDisposition.DENIED, state)


def _materialize(
    state_type: type[Enum],
    event_type: type[Enum],
    rules: tuple[tuple[Enum, Enum, Enum], ...],
) -> tuple[TransitionCell, ...]:
    return tuple(
        TransitionCell(
            state=state,
            event=event,
            decision=_result_for(state, event, rules),
        )
        for state in state_type
        for event in event_type
    )


AUTHORITY_MATRIX = _materialize(
    AuthorityState,
    AuthorityTransitionEvent,
    _AUTHORITY_RULES,
)
TASK_MATRIX = _materialize(TaskState, TaskTransitionEvent, _TASK_RULES)
CAPABILITY_MATRIX = _materialize(
    CapabilityState,
    CapabilityTransitionEvent,
    _CAPABILITY_RULES,
)
RUN_MATRIX = _materialize(RunState, RunOutcome, _RUN_RULES)
RECEIPT_MATRIX = _materialize(
    ReceiptState,
    ReceiptTransitionEvent,
    _RECEIPT_RULES,
)
PROMOTION_MATRIX = _materialize(
    PromotionState,
    PromotionTransitionEvent,
    _PROMOTION_RULES,
)
POLICY_MATRIX = _materialize(PolicyState, PolicyTransitionEvent, _POLICY_RULES)

_ALLOWED_BINDING = BindingDecision(True)
_DENIED_BINDING = BindingDecision(False)
BINDING_MATRIX = tuple(
    BindingCell(
        event_type=event_type,
        object_kind=object_kind,
        domain=domain,
        decision=(
            _ALLOWED_BINDING
            if any(
                rule_event is event_type
                and rule_object is object_kind
                and rule_domain is domain
                for rule_event, rule_object, rule_domain in _BINDING_RULES
            )
            else _DENIED_BINDING
        ),
    )
    for event_type in AuthorityEventType
    for object_kind in ObjectKind
    for domain in StateMachineDomain
)


def _lookup_transition(
    matrix: tuple[TransitionCell, ...],
    state: object,
    event: object,
    state_type: type[Enum],
    event_type: type[Enum],
) -> TransitionDecision | Denied:
    if type(state) is not state_type or type(event) is not event_type:
        return Denied(ReasonCode.SCHEMA_INVALID)
    for cell in matrix:
        if cell.state is state and cell.event is event:
            return cell.decision
    return Denied(ReasonCode.RECOVERY_REQUIRED)


def authority_transition(
    state: object,
    event: object,
) -> TransitionDecision | Denied:
    return _lookup_transition(
        AUTHORITY_MATRIX,
        state,
        event,
        AuthorityState,
        AuthorityTransitionEvent,
    )


def task_transition(state: object, event: object) -> TransitionDecision | Denied:
    return _lookup_transition(
        TASK_MATRIX,
        state,
        event,
        TaskState,
        TaskTransitionEvent,
    )


def capability_transition(
    state: object,
    event: object,
) -> TransitionDecision | Denied:
    return _lookup_transition(
        CAPABILITY_MATRIX,
        state,
        event,
        CapabilityState,
        CapabilityTransitionEvent,
    )


def run_transition(state: object, event: object) -> TransitionDecision | Denied:
    return _lookup_transition(RUN_MATRIX, state, event, RunState, RunOutcome)


def receipt_transition(
    state: object,
    event: object,
) -> TransitionDecision | Denied:
    return _lookup_transition(
        RECEIPT_MATRIX,
        state,
        event,
        ReceiptState,
        ReceiptTransitionEvent,
    )


def promotion_transition(
    state: object,
    event: object,
) -> TransitionDecision | Denied:
    return _lookup_transition(
        PROMOTION_MATRIX,
        state,
        event,
        PromotionState,
        PromotionTransitionEvent,
    )


def policy_transition(state: object, event: object) -> TransitionDecision | Denied:
    return _lookup_transition(
        POLICY_MATRIX,
        state,
        event,
        PolicyState,
        PolicyTransitionEvent,
    )


def event_binding(
    event_type: object,
    object_kind: object,
    domain: object,
) -> BindingDecision | Denied:
    if (
        type(event_type) is not AuthorityEventType
        or type(object_kind) is not ObjectKind
        or type(domain) is not StateMachineDomain
    ):
        return Denied(ReasonCode.SCHEMA_INVALID)
    for cell in BINDING_MATRIX:
        if (
            cell.event_type is event_type
            and cell.object_kind is object_kind
            and cell.domain is domain
        ):
            return cell.decision
    return Denied(ReasonCode.RECOVERY_REQUIRED)
