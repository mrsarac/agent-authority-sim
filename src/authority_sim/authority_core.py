from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, unique
from typing import NoReturn, cast

from authority_sim.authority_log import AuthorityLogError, FaultPoint, InMemoryAuthorityLog
from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.errors import ReasonCode
from authority_sim.records import (
    AuthorityLeaseRecord,
    CapabilityClaimRecord,
    ContractKind,
    LeaseAction,
    TaskEnvelopeRecord,
    create_record,
)
from authority_sim.transitions import (
    AuthorityState,
    AuthorityTransitionEvent,
    CapabilityState,
    CapabilityTransitionEvent,
    TaskState,
    TaskTransitionEvent,
    TransitionDecision,
    authority_transition,
    capability_transition,
    task_transition,
)


class _CoreFailure(ValueError):
    __slots__ = ("reason",)
    reason: ReasonCode

    def __init__(self, reason: ReasonCode) -> None:
        if type(reason) is not ReasonCode:
            raise ValueError("AUTHORITY_CORE_INVALID") from None
        object.__setattr__(self, "reason", reason)
        ValueError.__init__(self, "AUTHORITY_CORE_INVALID")


def _fail(reason: ReasonCode) -> NoReturn:
    raise _CoreFailure(reason) from None


def _safe_utc(value: object) -> datetime:
    if type(value) is not datetime:
        _fail(ReasonCode.SCHEMA_INVALID)
    stable = cast(datetime, value)
    try:
        offset = stable.utcoffset()
    except Exception:
        _fail(ReasonCode.SCHEMA_INVALID)
    if stable.tzinfo is None or type(offset) is not timedelta or offset != timedelta(0):
        _fail(ReasonCode.SCHEMA_INVALID)
    try:
        return datetime(
            stable.year,
            stable.month,
            stable.day,
            stable.hour,
            stable.minute,
            stable.second,
            stable.microsecond,
            tzinfo=timezone.utc,
            fold=stable.fold,
        )
    except Exception:
        _fail(ReasonCode.SCHEMA_INVALID)


def _timestamp(value: datetime) -> str:
    stable = _safe_utc(value)
    if stable.microsecond:
        return stable.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return stable.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str:
        _fail(ReasonCode.SCHEMA_INVALID)
    text = cast(str, value)
    if not text.endswith("Z"):
        _fail(ReasonCode.SCHEMA_INVALID)
    body = text[:-1]
    fraction = body.split(".", 1)[1] if "." in body else ""
    if len(fraction) > 6 and any(character != "0" for character in fraction[6:]):
        _fail(ReasonCode.SCHEMA_INVALID)
    try:
        parsed = datetime.fromisoformat(body + "+00:00")
    except Exception:
        _fail(ReasonCode.SCHEMA_INVALID)
    return _safe_utc(parsed)


def _require_digest(value: object) -> str:
    if type(value) is not str:
        _fail(ReasonCode.SCHEMA_INVALID)
    text = cast(str, value)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        _fail(ReasonCode.SCHEMA_INVALID)
    return text


def _require_head(value: object) -> str | None:
    if value is None:
        return None
    return _require_digest(value)


def _require_authorization_ref(value: object) -> str:
    if type(value) is not str:
        _fail(ReasonCode.SCHEMA_INVALID)
    text = cast(str, value)
    if re.fullmatch(r"(?:operator-decision|policy-decision):[A-Za-z0-9._:/-]{3,180}", text) is None:
        _fail(ReasonCode.SCHEMA_INVALID)
    return text


@unique
class OperatorAction(Enum):
    INITIALIZE = "INITIALIZE"
    ACQUIRE = "ACQUIRE"
    HALT = "HALT"


_AUTHORIZATION_TOKEN = object()
_CONTRADICTION_TOKEN = object()
_RECOVERY_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedOperatorAuthorization:
    action: OperatorAction
    authorization_ref: str
    authority_epoch: int

    def __init__(
        self,
        token: object,
        action: OperatorAction,
        authorization_ref: str,
        authority_epoch: int,
    ) -> None:
        if token is not _AUTHORIZATION_TOKEN:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(action) is not OperatorAction:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_ref = _require_authorization_ref(authorization_ref)
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(ReasonCode.SCHEMA_INVALID)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "authorization_ref", stable_ref)
        object.__setattr__(self, "authority_epoch", authority_epoch)

    def __repr__(self) -> str:
        return "VerifiedOperatorAuthorization(...)"


class OperatorRecoveryPort:
    __slots__ = ()

    def authorize_initialization(
        self,
        authorization_ref: str,
    ) -> VerifiedOperatorAuthorization:
        return VerifiedOperatorAuthorization(
            _AUTHORIZATION_TOKEN,
            OperatorAction.INITIALIZE,
            _require_authorization_ref(authorization_ref),
            1,
        )

    def authorize_acquisition(
        self,
        authorization_ref: str,
        *,
        authority_epoch: int,
    ) -> VerifiedOperatorAuthorization:
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(ReasonCode.SCHEMA_INVALID)
        return VerifiedOperatorAuthorization(
            _AUTHORIZATION_TOKEN,
            OperatorAction.ACQUIRE,
            _require_authorization_ref(authorization_ref),
            authority_epoch,
        )

    def authorize_recovery(
        self,
        authorization_ref: str,
        *,
        recovery_epoch: int,
        restore_evidence_ref: str,
        restore_evidence_bytes: bytes,
    ) -> VerifiedRecoveryAuthorization:
        return VerifiedRecoveryAuthorization(
            _RECOVERY_TOKEN,
            authorization_ref,
            recovery_epoch,
            restore_evidence_ref,
            restore_evidence_bytes,
        )

    def authorize_halt(
        self,
        authorization_ref: str,
        *,
        authority_epoch: int,
    ) -> VerifiedOperatorAuthorization:
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(ReasonCode.SCHEMA_INVALID)
        return VerifiedOperatorAuthorization(
            _AUTHORIZATION_TOKEN,
            OperatorAction.HALT,
            _require_authorization_ref(authorization_ref),
            authority_epoch,
        )

    def __repr__(self) -> str:
        return "OperatorRecoveryPort(...)"


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedContradiction:
    evidence_ref: str
    evidence_bytes: bytes

    def __init__(self, token: object, evidence_ref: str, evidence_bytes: bytes) -> None:
        if token is not _CONTRADICTION_TOKEN:
            _fail(ReasonCode.SCHEMA_INVALID)
        if (
            type(evidence_ref) is not str
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9._:/-]{3,180}", evidence_ref) is None
            or type(evidence_bytes) is not bytes
            or not evidence_bytes
        ):
            _fail(ReasonCode.SCHEMA_INVALID)
        object.__setattr__(self, "evidence_ref", evidence_ref)
        object.__setattr__(self, "evidence_bytes", evidence_bytes)

    def __repr__(self) -> str:
        return "VerifiedContradiction(...)"


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedRecoveryAuthorization:
    authorization_ref: str
    recovery_epoch: int
    restore_evidence_ref: str
    restore_evidence_bytes: bytes

    def __init__(
        self,
        token: object,
        authorization_ref: str,
        recovery_epoch: int,
        restore_evidence_ref: str,
        restore_evidence_bytes: bytes,
    ) -> None:
        if token is not _RECOVERY_TOKEN:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_ref = _require_authorization_ref(authorization_ref)
        if (
            type(recovery_epoch) is not int
            or recovery_epoch < 1
            or type(restore_evidence_ref) is not str
            or re.fullmatch(
                r"[A-Za-z][A-Za-z0-9._:/-]{3,180}",
                restore_evidence_ref,
            ) is None
            or type(restore_evidence_bytes) is not bytes
            or not restore_evidence_bytes
        ):
            _fail(ReasonCode.SCHEMA_INVALID)
        object.__setattr__(self, "authorization_ref", stable_ref)
        object.__setattr__(self, "recovery_epoch", recovery_epoch)
        object.__setattr__(self, "restore_evidence_ref", restore_evidence_ref)
        object.__setattr__(self, "restore_evidence_bytes", restore_evidence_bytes)

    def __repr__(self) -> str:
        return "VerifiedRecoveryAuthorization(...)"


class AuthorityVerifierPort:
    __slots__ = ()

    def verify_contradiction(
        self,
        evidence_ref: str,
        evidence_bytes: bytes,
    ) -> VerifiedContradiction:
        return VerifiedContradiction(
            _CONTRADICTION_TOKEN,
            evidence_ref,
            evidence_bytes,
        )

    def __repr__(self) -> str:
        return "AuthorityVerifierPort(...)"


def _validate_restore_object(object_kind: object, object_bytes: bytes) -> None:
    contract_kinds = {
        ContractKind.AUTHORITY_LEASE.value,
        ContractKind.TASK_ENVELOPE.value,
        ContractKind.CAPABILITY_CLAIM.value,
        ContractKind.EXECUTION_RECEIPT.value,
        ContractKind.PROMOTION_DECISION.value,
    }
    try:
        if type(object_kind) is not str or type(object_bytes) is not bytes:
            _fail(ReasonCode.RECOVERY_REQUIRED)
        stable_kind = cast(str, object_kind)
        if stable_kind in contract_kinds:
            document = json.loads(object_bytes.decode("utf-8"))
            if type(document) is not dict or canonical_bytes(document) != object_bytes:
                _fail(ReasonCode.RECOVERY_REQUIRED)
            record = create_record(document)
            if record.to_document().get("kind") != stable_kind:
                _fail(ReasonCode.RECOVERY_REQUIRED)
            return
        if stable_kind == "authority":
            document = json.loads(object_bytes.decode("utf-8"))
            if type(document) is not dict or canonical_bytes(document) != object_bytes:
                _fail(ReasonCode.RECOVERY_REQUIRED)
            if (
                type(document.get("authority_epoch")) is not int
                or cast(int, document.get("authority_epoch")) < 1
                or type(document.get("lease_generation")) is not int
                or cast(int, document.get("lease_generation")) < 1
                or type(document.get("operator_id")) is not str
                or document.get("state") not in {state.value for state in AuthorityState}
            ):
                _fail(ReasonCode.RECOVERY_REQUIRED)
            return
        if stable_kind in {"policy_evidence", "restore_evidence"} and object_bytes:
            return
        _fail(ReasonCode.RECOVERY_REQUIRED)
    except _CoreFailure:
        raise
    except Exception:
        _fail(ReasonCode.RECOVERY_REQUIRED)


class AuthorityRestoreVerifierPort:
    __slots__ = ()

    def verify_restore_state(
        self,
        *,
        canonical_object_bytes: object,
        accepted_event_bytes: object,
    ) -> RestoreVerification:
        try:
            object_map = _restore_objects(canonical_object_bytes)
            stable_events = _restore_events(accepted_event_bytes)
            if stable_events:
                replay = InMemoryAuthorityLog()
                replay.compare_and_append(
                    expected_head=None,
                    event_bytes=stable_events,
                )
            documents = tuple(
                cast(dict[str, object], json.loads(raw.decode("utf-8")))
                for raw in stable_events
            )
            for document in documents:
                object_ref = document.get("object_ref")
                object_digest = document.get("object_digest")
                if type(object_ref) is not str or type(object_digest) is not str:
                    _fail(ReasonCode.RECOVERY_REQUIRED)
                object_bytes = object_map.get(object_ref)
                if object_bytes is None or sha256_digest(object_bytes) != object_digest:
                    _fail(ReasonCode.RECOVERY_REQUIRED)
                _validate_restore_object(document.get("object_kind"), object_bytes)

            for index, document in enumerate(documents):
                event_type = document.get("event_type")
                object_ref = document.get("object_ref")
                if type(event_type) is not str or type(object_ref) is not str:
                    _fail(ReasonCode.RECOVERY_REQUIRED)
                if event_type == "task_issued":
                    if index + 1 >= len(documents):
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    task_bytes = object_map.get(object_ref)
                    if task_bytes is None:
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    task_record = create_record(json.loads(task_bytes.decode("utf-8")))
                    if type(task_record) is not TaskEnvelopeRecord:
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    stable_task = cast(TaskEnvelopeRecord, task_record)
                    next_document = documents[index + 1]
                    if (
                        next_document.get("event_type") != "capability_issued"
                        or next_document.get("object_ref") != stable_task.capability_id
                    ):
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    claim_bytes = object_map.get(stable_task.capability_id)
                    if claim_bytes is None:
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    claim_record = create_record(json.loads(claim_bytes.decode("utf-8")))
                    if (
                        type(claim_record) is not CapabilityClaimRecord
                        or cast(CapabilityClaimRecord, claim_record).parent_capability_id
                        is not None
                        or cast(CapabilityClaimRecord, claim_record).task_id
                        != stable_task.task_id
                    ):
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                if event_type == "capability_issued":
                    claim_bytes = object_map.get(object_ref)
                    if claim_bytes is None:
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    claim_record = create_record(json.loads(claim_bytes.decode("utf-8")))
                    if type(claim_record) is not CapabilityClaimRecord:
                        _fail(ReasonCode.RECOVERY_REQUIRED)
                    stable_claim = cast(CapabilityClaimRecord, claim_record)
                    if stable_claim.parent_capability_id is None:
                        if index == 0:
                            _fail(ReasonCode.RECOVERY_REQUIRED)
                        previous_document = documents[index - 1]
                        if previous_document.get("event_type") != "task_issued":
                            _fail(ReasonCode.RECOVERY_REQUIRED)
                        previous_ref = previous_document.get("object_ref")
                        if type(previous_ref) is not str:
                            _fail(ReasonCode.RECOVERY_REQUIRED)
                        task_bytes = object_map.get(previous_ref)
                        if task_bytes is None:
                            _fail(ReasonCode.RECOVERY_REQUIRED)
                        task_record = create_record(json.loads(task_bytes.decode("utf-8")))
                        if (
                            type(task_record) is not TaskEnvelopeRecord
                            or cast(TaskEnvelopeRecord, task_record).task_id
                            != stable_claim.task_id
                            or cast(TaskEnvelopeRecord, task_record).capability_id
                            != stable_claim.capability_id
                        ):
                            _fail(ReasonCode.RECOVERY_REQUIRED)
            return RestoreVerification(True, None, False)
        except _CoreFailure as failure:
            return RestoreVerification(False, failure.reason, False)
        except AuthorityLogError:
            return RestoreVerification(False, ReasonCode.RECOVERY_REQUIRED, False)
        except Exception:
            return RestoreVerification(False, ReasonCode.RECOVERY_REQUIRED, False)

    def __repr__(self) -> str:
        return "AuthorityRestoreVerifierPort(...)"


class AuthorityTaskPort:
    __slots__ = ()

    def issue_task(
        self,
        core: object,
        task_envelope_bytes: object,
        capability_claim_bytes: object,
        *,
        expected_head: object,
        as_of: object,
        fault: FaultPoint | None = None,
    ) -> TaskIssueDecision:
        if type(core) is not AuthorityCore:
            _fail(ReasonCode.AUTHORITY_STALE)
        return cast(AuthorityCore, core)._issue_task(
            task_envelope_bytes,
            capability_claim_bytes,
            expected_head=expected_head,
            as_of=as_of,
            fault=fault,
        )

    def __repr__(self) -> str:
        return "AuthorityTaskPort(...)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthorityBinding:
    authority_epoch: int
    lease_generation: int
    writer_id: str
    lease_id: str
    policy_digest: str

    def __post_init__(self) -> None:
        if type(self.authority_epoch) is not int or self.authority_epoch < 1:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.lease_generation) is not int or self.lease_generation < 1:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.writer_id) is not str or len(self.writer_id) < 4:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.lease_id) is not str or len(self.lease_id) < 4:
            _fail(ReasonCode.SCHEMA_INVALID)
        _require_digest(self.policy_digest)

    def __repr__(self) -> str:
        return "AuthorityBinding(...)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthoritySnapshot:
    state: AuthorityState
    operator_id: str
    authority_epoch: int
    lease_generation: int
    writer_id: str | None
    lease_id: str | None
    latest_lease_record_id: str | None
    expires_at: datetime | None
    policy_digest: str | None
    authority_head: str | None
    promotion_eligible: bool
    lease_record_bytes: tuple[bytes, ...]
    canonical_object_bytes: tuple[tuple[str, bytes], ...]
    accepted_event_bytes: tuple[bytes, ...]
    log_projection_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.state) is not AuthorityState:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.operator_id) is not str:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.authority_epoch) is not int or self.authority_epoch < 0:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.lease_generation) is not int or self.lease_generation < 0:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.promotion_eligible) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.lease_record_bytes) is not tuple:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.canonical_object_bytes) is not tuple:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.accepted_event_bytes) is not tuple:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.log_projection_bytes) is not bytes:
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "AuthoritySnapshot(...)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthorityDecision:
    accepted: bool
    reason: ReasonCode | None
    snapshot: AuthoritySnapshot

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.reason is not None and type(self.reason) is not ReasonCode:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.accepted != (self.reason is None):
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.snapshot) is not AuthoritySnapshot:
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "AuthorityDecision(...)"


@dataclass(frozen=True, slots=True, repr=False)
class TaskIssueDecision:
    accepted: bool
    reason: ReasonCode | None
    fault_reported: bool
    snapshot: AuthoritySnapshot
    accepted_event_bytes: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.reason is not None and type(self.reason) is not ReasonCode:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.fault_reported) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.accepted != (self.reason is None):
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.snapshot) is not AuthoritySnapshot:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.accepted_event_bytes) is not tuple:
            _fail(ReasonCode.SCHEMA_INVALID)
        if any(type(raw) is not bytes for raw in self.accepted_event_bytes):
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "TaskIssueDecision(...)"


@dataclass(frozen=True, slots=True, repr=False)
class RestoreVerification:
    accepted: bool
    reason: ReasonCode | None
    append_attempted: bool

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.reason is not None and type(self.reason) is not ReasonCode:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.accepted != (self.reason is None):
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.append_attempted) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "RestoreVerification(...)"


@dataclass(frozen=True, slots=True, repr=False)
class _LeaseCandidate:
    record: AuthorityLeaseRecord
    raw: bytes
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True, repr=False)
class _CoreState:
    state: AuthorityState
    operator_id: str
    authority_epoch: int
    lease_generation: int
    writer_id: str | None
    lease_id: str | None
    policy_digest: str | None
    leases: tuple[_LeaseCandidate, ...]
    canonical_objects: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True, repr=False)
class _TaskCandidate:
    record: TaskEnvelopeRecord
    raw: bytes
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True, repr=False)
class _ClaimCandidate:
    record: CapabilityClaimRecord
    raw: bytes
    valid_from: datetime
    expires_at: datetime


def _parse_lease(raw: object) -> _LeaseCandidate:
    if type(raw) is not bytes:
        _fail(ReasonCode.SCHEMA_INVALID)
    stable_raw = cast(bytes, raw)
    try:
        document = json.loads(stable_raw.decode("utf-8"))
        if type(document) is not dict or canonical_bytes(document) != stable_raw:
            _fail(ReasonCode.SCHEMA_INVALID)
        record = create_record(document)
        if type(record) is not AuthorityLeaseRecord:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_record = cast(AuthorityLeaseRecord, record)
        issued_at = _parse_timestamp(document.get("issued_at"))
        valid_from = _parse_timestamp(document.get("valid_from"))
        expires_at = _parse_timestamp(document.get("expires_at"))
        if not issued_at <= valid_from < expires_at:
            _fail(ReasonCode.SCHEMA_INVALID)
        return _LeaseCandidate(
            record=stable_record,
            raw=stable_raw,
            issued_at=issued_at,
            valid_from=valid_from,
            expires_at=expires_at,
        )
    except _CoreFailure:
        raise
    except Exception:
        _fail(ReasonCode.SCHEMA_INVALID)


def _parse_task(raw: object) -> _TaskCandidate:
    if type(raw) is not bytes:
        _fail(ReasonCode.SCHEMA_INVALID)
    stable_raw = cast(bytes, raw)
    try:
        document = json.loads(stable_raw.decode("utf-8"))
        if type(document) is not dict or canonical_bytes(document) != stable_raw:
            _fail(ReasonCode.SCHEMA_INVALID)
        record = create_record(document)
        if type(record) is not TaskEnvelopeRecord:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_record = cast(TaskEnvelopeRecord, record)
        issued_at = _parse_timestamp(document.get("issued_at"))
        expires_at = _parse_timestamp(document.get("expires_at"))
        if not issued_at < expires_at:
            _fail(ReasonCode.SCHEMA_INVALID)
        return _TaskCandidate(
            record=stable_record,
            raw=stable_raw,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except _CoreFailure:
        raise
    except Exception:
        _fail(ReasonCode.SCHEMA_INVALID)


def _parse_claim(raw: object) -> _ClaimCandidate:
    if type(raw) is not bytes:
        _fail(ReasonCode.SCHEMA_INVALID)
    stable_raw = cast(bytes, raw)
    try:
        document = json.loads(stable_raw.decode("utf-8"))
        if type(document) is not dict or canonical_bytes(document) != stable_raw:
            _fail(ReasonCode.SCHEMA_INVALID)
        record = create_record(document)
        if type(record) is not CapabilityClaimRecord:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_record = cast(CapabilityClaimRecord, record)
        valid_from = _parse_timestamp(document.get("valid_from"))
        expires_at = _parse_timestamp(document.get("expires_at"))
        if not valid_from < expires_at:
            _fail(ReasonCode.SCHEMA_INVALID)
        return _ClaimCandidate(
            record=stable_record,
            raw=stable_raw,
            valid_from=valid_from,
            expires_at=expires_at,
        )
    except _CoreFailure:
        raise
    except Exception:
        _fail(ReasonCode.SCHEMA_INVALID)


def _transition(
    state: AuthorityState,
    event: AuthorityTransitionEvent,
) -> AuthorityState:
    result = authority_transition(state, event)
    if type(result) is not TransitionDecision or not result.allowed:
        _fail(ReasonCode.AUTHORITY_STALE)
    resulting_state = result.resulting_state
    if type(resulting_state) is not AuthorityState:
        _fail(ReasonCode.RECOVERY_REQUIRED)
    return cast(AuthorityState, resulting_state)


def _build_event(
    *,
    operator_id: str,
    event_id: str,
    sequence: int,
    previous_event_digest: str | None,
    event_type: str,
    actor_class: str,
    actor_id: str,
    object_kind: str,
    object_ref: str,
    object_bytes: bytes,
    expected_state: Enum,
    resulting_state: Enum,
    authority_epoch: int,
    lease_generation: int,
    policy_digest: str,
    observed_at: datetime,
    state_machine: str = "authority",
) -> tuple[bytes, str]:
    document = {
        "kind": "authority_event",
        "schema_version": "0.1.0",
        "operator_id": operator_id,
        "event_id": event_id,
        "sequence": sequence,
        "authority_epoch": authority_epoch,
        "lease_generation": lease_generation,
        "previous_event_digest": previous_event_digest,
        "event_digest": "sha256:" + ("0" * 64),
        "event_type": event_type,
        "actor": {
            "actor_class": actor_class,
            "actor_id": actor_id,
        },
        "object_kind": object_kind,
        "object_ref": object_ref,
        "object_digest": sha256_digest(object_bytes),
        "transition": {
            "state_machine": state_machine,
            "expected_state": expected_state.value,
            "resulting_state": resulting_state.value,
        },
        "policy_digest": policy_digest,
        "observed_at": _timestamp(observed_at),
        "idempotency_key": f"authority.event:{event_id}",
    }
    body = dict(document)
    body.pop("event_digest")
    digest = sha256_digest(canonical_bytes(body))
    document["event_digest"] = digest
    return canonical_bytes(document), digest


def _event_id(label: str, object_bytes: bytes) -> str:
    if type(label) is not str or type(object_bytes) is not bytes:
        _fail(ReasonCode.SCHEMA_INVALID)
    digest = sha256_digest(label.encode("utf-8") + b":" + object_bytes)
    return "event_" + digest[7:31]


def _append_object(
    objects: tuple[tuple[str, bytes], ...],
    object_ref: str,
    object_bytes: bytes,
) -> tuple[tuple[str, bytes], ...]:
    for existing_ref, existing_bytes in objects:
        if existing_ref == object_ref:
            if existing_bytes == object_bytes:
                return objects
            _fail(ReasonCode.RECOVERY_REQUIRED)
    return objects + ((object_ref, object_bytes),)


def _committed_batch(
    accepted_event_bytes: tuple[bytes, ...],
    event_bytes: tuple[bytes, ...],
) -> bool:
    if len(accepted_event_bytes) < len(event_bytes):
        return False
    return accepted_event_bytes[-len(event_bytes):] == event_bytes


def _find_task_replay(
    accepted_event_bytes: tuple[bytes, ...],
    *,
    expected_head: str,
    task_event_id: str,
    claim_event_id: str,
) -> tuple[bytes, bytes] | None:
    for index, raw in enumerate(accepted_event_bytes):
        document = json.loads(raw.decode("utf-8"))
        if (
            document.get("event_id") == task_event_id
            and document.get("event_type") == "task_issued"
            and document.get("previous_event_digest") == expected_head
            and index + 1 < len(accepted_event_bytes)
        ):
            next_raw = accepted_event_bytes[index + 1]
            next_document = json.loads(next_raw.decode("utf-8"))
            if (
                next_document.get("event_id") == claim_event_id
                and next_document.get("event_type") == "capability_issued"
                and next_document.get("previous_event_digest")
                == document.get("event_digest")
            ):
                return raw, next_raw
    return None


def _restore_objects(
    canonical_object_bytes: object,
) -> dict[str, bytes]:
    if type(canonical_object_bytes) is not tuple:
        _fail(ReasonCode.SCHEMA_INVALID)
    stable_entries = cast(tuple[tuple[object, object], ...], canonical_object_bytes)
    objects: dict[str, bytes] = {}
    for entry in stable_entries:
        if type(entry) is not tuple or len(entry) != 2:
            _fail(ReasonCode.SCHEMA_INVALID)
        object_ref, object_bytes = entry
        if type(object_ref) is not str or type(object_bytes) is not bytes:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_ref = cast(str, object_ref)
        stable_bytes = cast(bytes, object_bytes)
        existing = objects.get(stable_ref)
        if existing is not None and existing != stable_bytes:
            _fail(ReasonCode.RECOVERY_REQUIRED)
        objects[stable_ref] = stable_bytes
    return objects


def _restore_events(
    accepted_event_bytes: object,
) -> tuple[bytes, ...]:
    if type(accepted_event_bytes) is not tuple:
        _fail(ReasonCode.SCHEMA_INVALID)
    stable_events = cast(tuple[object, ...], accepted_event_bytes)
    if any(type(raw) is not bytes for raw in stable_events):
        _fail(ReasonCode.SCHEMA_INVALID)
    return cast(tuple[bytes, ...], stable_events)


class AuthorityCore:
    __slots__ = ("__log", "__state")
    __log: InMemoryAuthorityLog
    __state: _CoreState

    def __init__(self, operator_id: str) -> None:
        if (
            type(operator_id) is not str
            or re.fullmatch(r"operator:[a-z0-9][a-z0-9._-]{2,63}", operator_id) is None
        ):
            _fail(ReasonCode.SCHEMA_INVALID)
        object.__setattr__(self, "_AuthorityCore__log", InMemoryAuthorityLog())
        object.__setattr__(
            self,
            "_AuthorityCore__state",
            _CoreState(
                state=AuthorityState.UNINITIALIZED,
                operator_id=operator_id,
                authority_epoch=0,
                lease_generation=0,
                writer_id=None,
                lease_id=None,
                policy_digest=None,
                leases=(),
                canonical_objects=(),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AUTHORITY_CORE_INVALID")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("AUTHORITY_CORE_INVALID")

    def __repr__(self) -> str:
        return "AuthorityCore(...)"

    def _snapshot(self, as_of: datetime | None) -> AuthoritySnapshot:
        state = self.__state
        log_snapshot = self.__log.snapshot()
        latest = state.leases[-1] if state.leases else None
        effective_state = state.state
        promotion_eligible = False
        if latest is not None and as_of is not None and state.state is AuthorityState.ACTIVE:
            if as_of < latest.expires_at:
                promotion_eligible = True
            else:
                effective_state = AuthorityState.NO_WRITER
        return AuthoritySnapshot(
            state=effective_state,
            operator_id=state.operator_id,
            authority_epoch=state.authority_epoch,
            lease_generation=state.lease_generation,
            writer_id=state.writer_id,
            lease_id=state.lease_id,
            latest_lease_record_id=(
                latest.record.lease_record_id if latest is not None else None
            ),
            expires_at=latest.expires_at if latest is not None else None,
            policy_digest=state.policy_digest,
            authority_head=log_snapshot.head,
            promotion_eligible=promotion_eligible,
            lease_record_bytes=tuple(lease.raw for lease in state.leases),
            canonical_object_bytes=state.canonical_objects,
            accepted_event_bytes=log_snapshot.accepted_event_bytes,
            log_projection_bytes=log_snapshot.projection_bytes,
        )

    def snapshot(self, *, as_of: datetime) -> AuthoritySnapshot:
        try:
            stable_as_of = _safe_utc(as_of)
            return self._snapshot(stable_as_of)
        except Exception:
            return self._snapshot(None)

    def _denied(
        self,
        reason: ReasonCode,
        as_of: datetime | None,
    ) -> AuthorityDecision:
        return AuthorityDecision(False, reason, self._snapshot(as_of))

    def _task_denied(
        self,
        reason: ReasonCode,
        as_of: datetime | None,
        *,
        fault_reported: bool,
        accepted_event_bytes: tuple[bytes, ...] = (),
    ) -> TaskIssueDecision:
        return TaskIssueDecision(
            False,
            reason,
            fault_reported,
            self._snapshot(as_of),
            accepted_event_bytes,
        )

    def _issue_task(
        self,
        task_envelope_bytes: object,
        capability_claim_bytes: object,
        *,
        expected_head: object,
        as_of: object,
        fault: FaultPoint | None = None,
    ) -> TaskIssueDecision:
        stable_as_of: datetime | None = None
        event_batch: tuple[bytes, bytes] = ()
        staged_objects: tuple[tuple[str, bytes], ...] | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            if fault is not None and type(fault) is not FaultPoint:
                _fail(ReasonCode.SCHEMA_INVALID)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if (
                state.state is not AuthorityState.ACTIVE
                or not state.leases
                or self._snapshot(stable_as_of).state is not AuthorityState.ACTIVE
                or state.policy_digest is None
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            task = _parse_task(task_envelope_bytes)
            claim = _parse_claim(capability_claim_bytes)
            task_record = task.record
            claim_record = claim.record
            if (
                task_record.kind is not ContractKind.TASK_ENVELOPE
                or claim_record.kind is not ContractKind.CAPABILITY_CLAIM
                or task_record.operator_id != state.operator_id
                or claim_record.operator_id != state.operator_id
                or task_record.authority_epoch != state.authority_epoch
                or claim_record.authority_epoch != state.authority_epoch
                or task_record.lease_generation != state.lease_generation
                or claim_record.lease_generation != state.lease_generation
                or task_record.policy_digest != state.policy_digest
                or claim_record.policy_digest != state.policy_digest
                or task_record.expected_authority_head != stable_head
                or task_record.capability_id != claim_record.capability_id
                or claim_record.parent_capability_id is not None
                or claim_record.task_id != task_record.task_id
                or claim_record.workspace_ref != task_record.workspace_ref
                or claim_record.audience.to_document()
                != task_record.audience.to_document()
                or claim_record.delegation_depth != 0
                or not task.issued_at <= stable_as_of < task.expires_at
                or not claim.valid_from <= stable_as_of < claim.expires_at
                or claim.valid_from < task.issued_at
                or claim.expires_at > task.expires_at
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            task_input_ids = tuple(
                input_ref.get("artifact_id")
                for input_ref in task_record.input_refs
            )
            if (
                claim_record.issuer_id != state.writer_id
                or claim_record.subject.get("node_id")
                != task_record.audience.get("node_id")
                or any(type(artifact_id) is not str for artifact_id in task_input_ids)
            ):
                _fail(ReasonCode.AUTHORITY_STALE)
            if (
                set(claim_record.allowed_actions)
                != set(task_record.required_actions)
                or set(claim_record.allowed_input_artifact_ids)
                != set(cast(tuple[str, ...], task_input_ids))
                or claim_record.egress_aliases
                or claim_record.broker_handle_refs
                or claim_record.resource_bounds.to_document()
                != task_record.budget.to_document()
            ):
                _fail(ReasonCode.SCOPE_EXCEEDED)

            existing_objects = dict(state.canonical_objects)
            existing_task = existing_objects.get(task_record.task_id)
            existing_claim = existing_objects.get(claim_record.capability_id)
            if existing_task is not None and existing_task != task.raw:
                _fail(ReasonCode.REPLAY_DETECTED)
            if existing_claim is not None and existing_claim != claim.raw:
                _fail(ReasonCode.REPLAY_DETECTED)
            if (existing_task is None) != (existing_claim is None):
                _fail(ReasonCode.RECOVERY_REQUIRED)
            if existing_task is not None and existing_claim is not None:
                replay_batch = _find_task_replay(
                    log_snapshot.accepted_event_bytes,
                    expected_head=stable_head,
                    task_event_id=_event_id("task-issued", task.raw),
                    claim_event_id=_event_id("capability-issued", claim.raw),
                )
                if replay_batch is None:
                    _fail(ReasonCode.RECOVERY_REQUIRED)
                return TaskIssueDecision(
                    True,
                    None,
                    False,
                    self._snapshot(stable_as_of),
                    replay_batch,
                )

            task_result = task_transition(TaskState.NONE, TaskTransitionEvent.TASK_ISSUED)
            claim_result = capability_transition(
                CapabilityState.NONE,
                CapabilityTransitionEvent.CAPABILITY_ISSUED,
            )
            if (
                type(task_result) is not TransitionDecision
                or not task_result.allowed
                or type(task_result.resulting_state) is not TaskState
                or type(claim_result) is not TransitionDecision
                or not claim_result.allowed
                or type(claim_result.resulting_state) is not CapabilityState
            ):
                _fail(ReasonCode.RECOVERY_REQUIRED)

            first, first_digest = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("task-issued", task.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="task_issued",
                actor_class="authority_core",
                actor_id=cast(str, state.writer_id),
                object_kind="task_envelope",
                object_ref=task_record.task_id,
                object_bytes=task.raw,
                expected_state=TaskState.NONE,
                resulting_state=cast(TaskState, task_result.resulting_state),
                authority_epoch=state.authority_epoch,
                lease_generation=state.lease_generation,
                policy_digest=state.policy_digest,
                observed_at=stable_as_of,
                state_machine="task",
            )
            second, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("capability-issued", claim.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 2,
                previous_event_digest=first_digest,
                event_type="capability_issued",
                actor_class="authority_core",
                actor_id=cast(str, state.writer_id),
                object_kind="capability_claim",
                object_ref=claim_record.capability_id,
                object_bytes=claim.raw,
                expected_state=CapabilityState.NONE,
                resulting_state=cast(CapabilityState, claim_result.resulting_state),
                authority_epoch=state.authority_epoch,
                lease_generation=state.lease_generation,
                policy_digest=state.policy_digest,
                observed_at=stable_as_of,
                state_machine="capability",
            )
            event_batch = (first, second)
            staged_objects = _append_object(
                state.canonical_objects,
                task_record.task_id,
                task.raw,
            )
            staged_objects = _append_object(
                staged_objects,
                claim_record.capability_id,
                claim.raw,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=event_batch,
                fault=fault,
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=state.state,
                    operator_id=state.operator_id,
                    authority_epoch=state.authority_epoch,
                    lease_generation=state.lease_generation,
                    writer_id=state.writer_id,
                    lease_id=state.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases,
                    canonical_objects=staged_objects,
                ),
            )
            return TaskIssueDecision(
                True,
                None,
                False,
                self._snapshot(stable_as_of),
                event_batch,
            )
        except _CoreFailure as failure:
            return self._task_denied(
                failure.reason,
                stable_as_of,
                fault_reported=False,
            )
        except AuthorityLogError as failure:
            if (
                str(failure) == "FAULT_INJECTED"
                and event_batch
                and _committed_batch(self.__log.snapshot().accepted_event_bytes, event_batch)
                and staged_objects is not None
            ):
                state = self.__state
                object.__setattr__(
                    self,
                    "_AuthorityCore__state",
                    _CoreState(
                        state=state.state,
                        operator_id=state.operator_id,
                        authority_epoch=state.authority_epoch,
                        lease_generation=state.lease_generation,
                        writer_id=state.writer_id,
                        lease_id=state.lease_id,
                        policy_digest=state.policy_digest,
                        leases=state.leases,
                        canonical_objects=staged_objects,
                    ),
                )
                return TaskIssueDecision(
                    True,
                    None,
                    True,
                    self._snapshot(stable_as_of),
                    event_batch,
                )
            reason = ReasonCode.ACCEPTANCE_FAILED
            if str(failure) == "EXPECTED_HEAD_MISMATCH":
                reason = ReasonCode.EXPECTED_HEAD_MISMATCH
            elif str(failure) == "REPLAY_DETECTED":
                reason = ReasonCode.REPLAY_DETECTED
            return self._task_denied(
                reason,
                stable_as_of,
                fault_reported=str(failure) == "FAULT_INJECTED",
            )
        except Exception:
            return self._task_denied(
                ReasonCode.SCHEMA_INVALID,
                stable_as_of,
                fault_reported=False,
            )

    def initialize(
        self,
        lease_bytes: object,
        authorization: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            if type(authorization) is not VerifiedOperatorAuthorization:
                _fail(ReasonCode.AUTHORITY_STALE)
            stable_authorization = cast(VerifiedOperatorAuthorization, authorization)
            if (
                stable_authorization.action is not OperatorAction.INITIALIZE
                or stable_authorization.authority_epoch != 1
            ):
                _fail(ReasonCode.AUTHORITY_STALE)
            state = self.__state
            if state.state is not AuthorityState.UNINITIALIZED or stable_head is not None:
                _fail(ReasonCode.AUTHORITY_STALE)

            lease = _parse_lease(lease_bytes)
            record = lease.record
            if (
                record.kind is not ContractKind.AUTHORITY_LEASE
                or record.operator_id != state.operator_id
                or record.lease_action is not LeaseAction.ACQUIRE
                or record.authorization_ref != stable_authorization.authorization_ref
                or record.expected_authority_state != AuthorityState.UNINITIALIZED.value
                or record.authority_epoch != 1
                or record.lease_generation != 1
                or record.prior_authority_head is not None
                or record.previous_lease_record_id is not None
                or not lease.valid_from <= stable_as_of < lease.expires_at
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            active_state = _transition(
                AuthorityState.UNINITIALIZED,
                AuthorityTransitionEvent.AUTHORITY_INITIALIZED,
            )
            bound_state = _transition(
                active_state,
                AuthorityTransitionEvent.LEASE_ACQUIRED,
            )
            authority_ref = "authority:epoch:1"
            authority_bytes = canonical_bytes(
                {
                    "authority_epoch": 1,
                    "lease_generation": 1,
                    "lease_record_digest": sha256_digest(lease.raw),
                    "operator_id": state.operator_id,
                    "policy_digest": record.policy_digest,
                    "state": bound_state.value,
                    "writer_id": record.writer_id,
                },
            )
            first, first_digest = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("initialize", authority_bytes),
                sequence=1,
                previous_event_digest=None,
                event_type="authority_initialized",
                actor_class="authority_core",
                actor_id=record.writer_id,
                object_kind="authority",
                object_ref=authority_ref,
                object_bytes=authority_bytes,
                expected_state=AuthorityState.UNINITIALIZED,
                resulting_state=active_state,
                authority_epoch=1,
                lease_generation=1,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            second, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("lease-acquired", lease.raw),
                sequence=2,
                previous_event_digest=first_digest,
                event_type="lease_acquired",
                actor_class="authority_core",
                actor_id=record.writer_id,
                object_kind="authority_lease",
                object_ref=record.lease_record_id,
                object_bytes=lease.raw,
                expected_state=active_state,
                resulting_state=bound_state,
                authority_epoch=1,
                lease_generation=1,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                authority_ref,
                authority_bytes,
            )
            staged_objects = _append_object(
                staged_objects,
                record.lease_record_id,
                lease.raw,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(first, second),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=bound_state,
                    operator_id=state.operator_id,
                    authority_epoch=1,
                    lease_generation=1,
                    writer_id=record.writer_id,
                    lease_id=record.lease_id,
                    policy_digest=record.policy_digest,
                    leases=(lease,),
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def renew(
        self,
        lease_bytes: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if (
                state.state is not AuthorityState.ACTIVE
                or not state.leases
                or self._snapshot(stable_as_of).state is not AuthorityState.ACTIVE
            ):
                _fail(ReasonCode.LEASE_EXPIRED)

            current = state.leases[-1]
            renewal = _parse_lease(lease_bytes)
            record = renewal.record
            prior = current.record
            if record.policy_digest != state.policy_digest:
                _fail(ReasonCode.POLICY_MISMATCH)
            if (
                record.kind is not ContractKind.AUTHORITY_LEASE
                or record.operator_id != state.operator_id
                or record.lease_action is not LeaseAction.RENEW
                or record.expected_authority_state != AuthorityState.ACTIVE.value
                or record.prior_authority_head != stable_head
                or record.previous_lease_record_id != prior.lease_record_id
                or record.lease_record_id == prior.lease_record_id
                or record.nonce == prior.nonce
                or record.writer_id != state.writer_id
                or record.lease_id != state.lease_id
                or record.authority_epoch != state.authority_epoch
                or record.lease_generation != state.lease_generation
                or renewal.issued_at < current.issued_at
                or renewal.valid_from < current.valid_from
                or not renewal.valid_from <= stable_as_of < renewal.expires_at
                or renewal.expires_at <= current.expires_at
                or any(
                    existing.record.lease_record_id == record.lease_record_id
                    or existing.record.nonce == record.nonce
                    for existing in state.leases
                )
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            resulting_state = _transition(
                AuthorityState.ACTIVE,
                AuthorityTransitionEvent.LEASE_RENEWED,
            )
            event_bytes, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("lease-renewed", renewal.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="lease_renewed",
                actor_class="authority_core",
                actor_id=record.writer_id,
                object_kind="authority_lease",
                object_ref=record.lease_record_id,
                object_bytes=renewal.raw,
                expected_state=AuthorityState.ACTIVE,
                resulting_state=resulting_state,
                authority_epoch=state.authority_epoch,
                lease_generation=state.lease_generation,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                record.lease_record_id,
                renewal.raw,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(event_bytes,),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=resulting_state,
                    operator_id=state.operator_id,
                    authority_epoch=state.authority_epoch,
                    lease_generation=state.lease_generation,
                    writer_id=state.writer_id,
                    lease_id=state.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases + (renewal,),
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def reissue(
        self,
        lease_bytes: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if (
                state.state is not AuthorityState.ACTIVE
                or not state.leases
                or self._snapshot(stable_as_of).state is not AuthorityState.ACTIVE
            ):
                _fail(ReasonCode.LEASE_EXPIRED)

            current = state.leases[-1]
            reissue = _parse_lease(lease_bytes)
            record = reissue.record
            prior = current.record
            if record.policy_digest != state.policy_digest:
                _fail(ReasonCode.POLICY_MISMATCH)
            if (
                record.kind is not ContractKind.AUTHORITY_LEASE
                or record.operator_id != state.operator_id
                or record.lease_action is not LeaseAction.REISSUE
                or record.expected_authority_state != AuthorityState.ACTIVE.value
                or record.prior_authority_head != stable_head
                or record.previous_lease_record_id != prior.lease_record_id
                or record.lease_record_id == prior.lease_record_id
                or record.nonce == prior.nonce
                or record.lease_id == state.lease_id
                or record.authority_epoch != state.authority_epoch
                or record.lease_generation != state.lease_generation + 1
                or reissue.issued_at < current.issued_at
                or reissue.valid_from < current.valid_from
                or not reissue.valid_from <= stable_as_of < reissue.expires_at
                or any(
                    existing.record.lease_record_id == record.lease_record_id
                    or existing.record.nonce == record.nonce
                    for existing in state.leases
                )
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            resulting_state = _transition(
                AuthorityState.ACTIVE,
                AuthorityTransitionEvent.LEASE_ACQUIRED,
            )
            event_bytes, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("lease-reissued", reissue.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="lease_acquired",
                actor_class="authority_core",
                actor_id=record.writer_id,
                object_kind="authority_lease",
                object_ref=record.lease_record_id,
                object_bytes=reissue.raw,
                expected_state=AuthorityState.ACTIVE,
                resulting_state=resulting_state,
                authority_epoch=state.authority_epoch,
                lease_generation=record.lease_generation,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                record.lease_record_id,
                reissue.raw,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(event_bytes,),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=resulting_state,
                    operator_id=state.operator_id,
                    authority_epoch=state.authority_epoch,
                    lease_generation=record.lease_generation,
                    writer_id=record.writer_id,
                    lease_id=record.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases + (reissue,),
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def release(
        self,
        binding: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if (
                type(binding) is not AuthorityBinding
                or state.state is not AuthorityState.ACTIVE
                or not state.leases
                or self._snapshot(stable_as_of).state is not AuthorityState.ACTIVE
            ):
                _fail(ReasonCode.AUTHORITY_STALE)
            stable_binding = cast(AuthorityBinding, binding)
            if (
                stable_binding.authority_epoch != state.authority_epoch
                or stable_binding.lease_generation != state.lease_generation
                or stable_binding.writer_id != state.writer_id
                or stable_binding.lease_id != state.lease_id
            ):
                _fail(ReasonCode.AUTHORITY_STALE)
            if stable_binding.policy_digest != state.policy_digest:
                _fail(ReasonCode.POLICY_MISMATCH)

            current = state.leases[-1]
            resulting_state = _transition(
                AuthorityState.ACTIVE,
                AuthorityTransitionEvent.LEASE_RELEASED,
            )
            event_bytes, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("lease-released", current.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="lease_released",
                actor_class="authority_core",
                actor_id=stable_binding.writer_id,
                object_kind="authority_lease",
                object_ref=current.record.lease_record_id,
                object_bytes=current.raw,
                expected_state=AuthorityState.ACTIVE,
                resulting_state=resulting_state,
                authority_epoch=state.authority_epoch,
                lease_generation=state.lease_generation,
                policy_digest=cast(str, state.policy_digest),
                observed_at=stable_as_of,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(event_bytes,),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=resulting_state,
                    operator_id=state.operator_id,
                    authority_epoch=state.authority_epoch,
                    lease_generation=state.lease_generation,
                    writer_id=state.writer_id,
                    lease_id=state.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases,
                    canonical_objects=state.canonical_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def acquire(
        self,
        lease_bytes: object,
        authorization: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if type(authorization) is not VerifiedOperatorAuthorization:
                _fail(ReasonCode.AUTHORITY_STALE)
            stable_authorization = cast(VerifiedOperatorAuthorization, authorization)
            if stable_authorization.action is not OperatorAction.ACQUIRE:
                _fail(ReasonCode.AUTHORITY_STALE)
            if (
                not state.leases
                or self._snapshot(stable_as_of).state is not AuthorityState.NO_WRITER
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            current = state.leases[-1]
            acquisition = _parse_lease(lease_bytes)
            record = acquisition.record
            if record.policy_digest != state.policy_digest:
                _fail(ReasonCode.POLICY_MISMATCH)
            if (
                record.kind is not ContractKind.AUTHORITY_LEASE
                or record.operator_id != state.operator_id
                or record.lease_action is not LeaseAction.ACQUIRE
                or record.authorization_ref != stable_authorization.authorization_ref
                or record.expected_authority_state != AuthorityState.NO_WRITER.value
                or record.prior_authority_head != stable_head
                or record.previous_lease_record_id != current.record.lease_record_id
                or record.lease_record_id == current.record.lease_record_id
                or record.nonce == current.record.nonce
                or record.lease_id == state.lease_id
                or record.authority_epoch != state.authority_epoch + 1
                or record.authority_epoch != stable_authorization.authority_epoch
                or record.lease_generation != 1
                or acquisition.issued_at < current.issued_at
                or acquisition.valid_from < current.valid_from
                or not acquisition.valid_from <= stable_as_of < acquisition.expires_at
                or any(
                    existing.record.lease_record_id == record.lease_record_id
                    or existing.record.nonce == record.nonce
                    for existing in state.leases
                )
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            resulting_state = _transition(
                AuthorityState.NO_WRITER,
                AuthorityTransitionEvent.LEASE_ACQUIRED,
            )
            event_bytes, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("lease-acquired", acquisition.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="lease_acquired",
                actor_class="operator_recovery",
                actor_id=record.writer_id,
                object_kind="authority_lease",
                object_ref=record.lease_record_id,
                object_bytes=acquisition.raw,
                expected_state=AuthorityState.NO_WRITER,
                resulting_state=resulting_state,
                authority_epoch=record.authority_epoch,
                lease_generation=record.lease_generation,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                record.lease_record_id,
                acquisition.raw,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(event_bytes,),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=resulting_state,
                    operator_id=state.operator_id,
                    authority_epoch=record.authority_epoch,
                    lease_generation=record.lease_generation,
                    writer_id=record.writer_id,
                    lease_id=record.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases + (acquisition,),
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def check_promotion(
        self,
        binding: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if type(binding) is not AuthorityBinding:
                _fail(ReasonCode.AUTHORITY_STALE)
            snapshot = self._snapshot(stable_as_of)
            if snapshot.state is not AuthorityState.ACTIVE:
                if state.state in (
                    AuthorityState.RECOVERY_REQUIRED,
                    AuthorityState.HALTED,
                ):
                    reason = ReasonCode.RECOVERY_REQUIRED
                elif state.state is AuthorityState.ACTIVE and state.leases:
                    reason = ReasonCode.LEASE_EXPIRED
                else:
                    reason = ReasonCode.AUTHORITY_STALE
                _fail(reason)
            stable_binding = cast(AuthorityBinding, binding)
            if (
                stable_binding.authority_epoch != state.authority_epoch
                or stable_binding.lease_generation != state.lease_generation
                or stable_binding.writer_id != state.writer_id
                or stable_binding.lease_id != state.lease_id
            ):
                _fail(ReasonCode.AUTHORITY_STALE)
            if stable_binding.policy_digest != state.policy_digest:
                _fail(ReasonCode.POLICY_MISMATCH)
            return AuthorityDecision(True, None, snapshot)
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def record_contradiction(
        self,
        contradiction: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if type(contradiction) is not VerifiedContradiction:
                _fail(ReasonCode.AUTHORITY_STALE)
            if not state.leases or state.policy_digest is None:
                _fail(ReasonCode.AUTHORITY_STALE)
            current_state = self._snapshot(stable_as_of).state
            if current_state is AuthorityState.HALTED:
                _fail(ReasonCode.RECOVERY_REQUIRED)
            stable_contradiction = cast(VerifiedContradiction, contradiction)
            resulting_state = _transition(
                current_state,
                AuthorityTransitionEvent.RECOVERY_STARTED,
            )
            authority_bytes = canonical_bytes(
                {
                    "authority_epoch": state.authority_epoch,
                    "evidence_digest": sha256_digest(
                        stable_contradiction.evidence_bytes,
                    ),
                    "evidence_ref": stable_contradiction.evidence_ref,
                    "lease_generation": state.lease_generation,
                    "operator_id": state.operator_id,
                    "prior_authority_head": stable_head,
                    "state": resulting_state.value,
                },
            )
            authority_ref = (
                "authority:recovery:"
                + sha256_digest(authority_bytes)[7:31]
            )
            event_bytes, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("recovery-started", authority_bytes),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="recovery_started",
                actor_class="authority_core",
                actor_id="authority:core",
                object_kind="authority",
                object_ref=authority_ref,
                object_bytes=authority_bytes,
                expected_state=current_state,
                resulting_state=resulting_state,
                authority_epoch=state.authority_epoch,
                lease_generation=state.lease_generation,
                policy_digest=state.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                authority_ref,
                authority_bytes,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(event_bytes,),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=resulting_state,
                    operator_id=state.operator_id,
                    authority_epoch=state.authority_epoch,
                    lease_generation=state.lease_generation,
                    writer_id=state.writer_id,
                    lease_id=state.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases,
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def recover(
        self,
        lease_bytes: object,
        authorization: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if type(authorization) is not VerifiedRecoveryAuthorization:
                _fail(ReasonCode.AUTHORITY_STALE)
            if (
                state.state
                not in (AuthorityState.RECOVERY_REQUIRED, AuthorityState.HALTED)
                or not state.leases
                or state.policy_digest is None
            ):
                _fail(ReasonCode.RECOVERY_REQUIRED)
            stable_authorization = cast(VerifiedRecoveryAuthorization, authorization)
            current = state.leases[-1]
            recovery = _parse_lease(lease_bytes)
            record = recovery.record
            if record.policy_digest != state.policy_digest:
                _fail(ReasonCode.POLICY_MISMATCH)
            if (
                record.kind is not ContractKind.AUTHORITY_LEASE
                or record.operator_id != state.operator_id
                or record.lease_action is not LeaseAction.RECOVERY
                or record.authorization_ref != stable_authorization.authorization_ref
                or record.expected_authority_state != state.state.value
                or record.prior_authority_head != stable_head
                or record.previous_lease_record_id != current.record.lease_record_id
                or record.lease_record_id == current.record.lease_record_id
                or record.nonce == current.record.nonce
                or record.lease_id == state.lease_id
                or record.authority_epoch != state.authority_epoch + 1
                or record.authority_epoch != stable_authorization.recovery_epoch
                or record.lease_generation != 1
                or recovery.issued_at < current.issued_at
                or recovery.valid_from < current.valid_from
                or not recovery.valid_from <= stable_as_of < recovery.expires_at
                or any(
                    existing.record.lease_record_id == record.lease_record_id
                    or existing.record.nonce == record.nonce
                    for existing in state.leases
                )
            ):
                _fail(ReasonCode.AUTHORITY_STALE)

            restored_state = _transition(
                state.state,
                AuthorityTransitionEvent.RESTORE_VERIFIED,
            )
            bound_state = _transition(
                restored_state,
                AuthorityTransitionEvent.LEASE_ACQUIRED,
            )
            first, first_digest = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id(
                    "restore-verified",
                    stable_authorization.restore_evidence_bytes,
                ),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="restore_verified",
                actor_class="operator_recovery",
                actor_id="operator:recovery-port",
                object_kind="restore_evidence",
                object_ref=stable_authorization.restore_evidence_ref,
                object_bytes=stable_authorization.restore_evidence_bytes,
                expected_state=state.state,
                resulting_state=restored_state,
                authority_epoch=record.authority_epoch,
                lease_generation=record.lease_generation,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            second, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("recovery-lease", recovery.raw),
                sequence=len(log_snapshot.accepted_event_bytes) + 2,
                previous_event_digest=first_digest,
                event_type="lease_acquired",
                actor_class="operator_recovery",
                actor_id="operator:recovery-port",
                object_kind="authority_lease",
                object_ref=record.lease_record_id,
                object_bytes=recovery.raw,
                expected_state=restored_state,
                resulting_state=bound_state,
                authority_epoch=record.authority_epoch,
                lease_generation=record.lease_generation,
                policy_digest=record.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                stable_authorization.restore_evidence_ref,
                stable_authorization.restore_evidence_bytes,
            )
            staged_objects = _append_object(
                staged_objects,
                record.lease_record_id,
                recovery.raw,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(first, second),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=bound_state,
                    operator_id=state.operator_id,
                    authority_epoch=record.authority_epoch,
                    lease_generation=record.lease_generation,
                    writer_id=record.writer_id,
                    lease_id=record.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases + (recovery,),
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)

    def halt(
        self,
        authorization: object,
        *,
        expected_head: object,
        as_of: object,
    ) -> AuthorityDecision:
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            stable_head = _require_head(expected_head)
            state = self.__state
            log_snapshot = self.__log.snapshot()
            if stable_head is None or stable_head != log_snapshot.head:
                _fail(ReasonCode.EXPECTED_HEAD_MISMATCH)
            if type(authorization) is not VerifiedOperatorAuthorization:
                _fail(ReasonCode.AUTHORITY_STALE)
            stable_authorization = cast(VerifiedOperatorAuthorization, authorization)
            if (
                stable_authorization.action is not OperatorAction.HALT
                or stable_authorization.authority_epoch != state.authority_epoch
                or not state.leases
                or state.policy_digest is None
            ):
                _fail(ReasonCode.AUTHORITY_STALE)
            current_state = self._snapshot(stable_as_of).state
            resulting_state = _transition(
                current_state,
                AuthorityTransitionEvent.AUTHORITY_HALTED,
            )
            authority_bytes = canonical_bytes(
                {
                    "authority_epoch": state.authority_epoch,
                    "authorization_ref": stable_authorization.authorization_ref,
                    "lease_generation": state.lease_generation,
                    "operator_id": state.operator_id,
                    "prior_authority_head": stable_head,
                    "state": resulting_state.value,
                },
            )
            authority_ref = "authority:halt:" + sha256_digest(authority_bytes)[7:31]
            event_bytes, _ = _build_event(
                operator_id=state.operator_id,
                event_id=_event_id("authority-halted", authority_bytes),
                sequence=len(log_snapshot.accepted_event_bytes) + 1,
                previous_event_digest=stable_head,
                event_type="authority_halted",
                actor_class="operator_recovery",
                actor_id="operator:recovery-port",
                object_kind="authority",
                object_ref=authority_ref,
                object_bytes=authority_bytes,
                expected_state=current_state,
                resulting_state=resulting_state,
                authority_epoch=state.authority_epoch,
                lease_generation=state.lease_generation,
                policy_digest=state.policy_digest,
                observed_at=stable_as_of,
            )
            staged_objects = _append_object(
                state.canonical_objects,
                authority_ref,
                authority_bytes,
            )
            self.__log.compare_and_append(
                expected_head=stable_head,
                event_bytes=(event_bytes,),
            )
            object.__setattr__(
                self,
                "_AuthorityCore__state",
                _CoreState(
                    state=resulting_state,
                    operator_id=state.operator_id,
                    authority_epoch=state.authority_epoch,
                    lease_generation=state.lease_generation,
                    writer_id=state.writer_id,
                    lease_id=state.lease_id,
                    policy_digest=state.policy_digest,
                    leases=state.leases,
                    canonical_objects=staged_objects,
                ),
            )
            return AuthorityDecision(True, None, self._snapshot(stable_as_of))
        except _CoreFailure as failure:
            return self._denied(failure.reason, stable_as_of)
        except AuthorityLogError as failure:
            reason = (
                ReasonCode.EXPECTED_HEAD_MISMATCH
                if str(failure) == "EXPECTED_HEAD_MISMATCH"
                else ReasonCode.REPLAY_DETECTED
            )
            return self._denied(reason, stable_as_of)
        except Exception:
            return self._denied(ReasonCode.SCHEMA_INVALID, stable_as_of)
