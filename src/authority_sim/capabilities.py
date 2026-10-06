from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum, unique
from typing import NoReturn, cast

from authority_sim.canonical import canonical_bytes
from authority_sim.errors import ReasonCode
from authority_sim.records import CapabilityClaimRecord, ContractKind, create_record
from authority_sim.transitions import (
    CapabilityState,
    CapabilityTransitionEvent,
    TransitionDecision,
    capability_transition,
)


class _CapabilityFailure(ValueError):
    __slots__ = ("reason",)
    reason: ReasonCode

    def __init__(self, reason: ReasonCode) -> None:
        if type(reason) is not ReasonCode:
            raise ValueError("CAPABILITY_INVALID") from None
        object.__setattr__(self, "reason", reason)
        ValueError.__init__(self, "CAPABILITY_INVALID")


def _fail(reason: ReasonCode) -> NoReturn:
    raise _CapabilityFailure(reason) from None


def _safe_utc(value: object) -> datetime:
    if type(value) is not datetime:
        _fail(ReasonCode.CAPABILITY_INVALID)
    stable = cast(datetime, value)
    try:
        offset = stable.utcoffset()
    except Exception:
        _fail(ReasonCode.CAPABILITY_INVALID)
    if stable.tzinfo is None or type(offset) is not timedelta or offset != timedelta(0):
        _fail(ReasonCode.CAPABILITY_INVALID)
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


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str:
        _fail(ReasonCode.CAPABILITY_INVALID)
    text = cast(str, value)
    if not text.endswith("Z"):
        _fail(ReasonCode.CAPABILITY_INVALID)
    body = text[:-1]
    fraction = body.split(".", 1)[1] if "." in body else ""
    if len(fraction) > 6 and any(character != "0" for character in fraction[6:]):
        _fail(ReasonCode.CAPABILITY_INVALID)
    try:
        parsed = datetime.fromisoformat(body + "+00:00")
    except Exception:
        _fail(ReasonCode.CAPABILITY_INVALID)
    return _safe_utc(parsed)


def _require_tuple_of_strings(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        _fail(ReasonCode.CAPABILITY_INVALID)
    stable = cast(tuple[object, ...], value)
    if any(type(item) is not str for item in stable):
        _fail(ReasonCode.CAPABILITY_INVALID)
    return cast(tuple[str, ...], stable)


@unique
class CapabilityAction(Enum):
    READ_ARTIFACT = "read_artifact"
    SEARCH_ARTIFACT = "search_artifact"
    WRITE_WORKSPACE = "write_workspace"
    RUN_TEST = "run_test"
    EXECUTE_PROCESS = "execute_process"
    NETWORK_EGRESS = "network_egress"
    EXTERNAL_WRITE = "external_write"
    SECRET_USE = "secret_use"


@unique
class CapabilityAttempt(Enum):
    RUN_START = "run_start"
    RECEIPT_VERIFY = "receipt_verify"
    PROMOTION = "promotion"
    RECONNECT = "reconnect"


@dataclass(frozen=True, slots=True, repr=False)
class CapabilitySnapshot:
    capability_id: str
    parent_capability_id: str | None
    operator_id: str
    task_id: str
    workspace_ref: str
    authority_epoch: int
    lease_generation: int
    policy_digest: str
    delegation_depth: int
    state: CapabilityState

    def __post_init__(self) -> None:
        if type(self.capability_id) is not str:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if self.parent_capability_id is not None and type(self.parent_capability_id) is not str:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if type(self.operator_id) is not str or type(self.task_id) is not str:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if type(self.workspace_ref) is not str or type(self.policy_digest) is not str:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if type(self.authority_epoch) is not int or type(self.lease_generation) is not int:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if type(self.delegation_depth) is not int:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if type(self.state) is not CapabilityState:
            _fail(ReasonCode.CAPABILITY_INVALID)

    def __repr__(self) -> str:
        return "CapabilitySnapshot(...)"


@dataclass(frozen=True, slots=True, repr=False)
class CapabilityDecision:
    accepted: bool
    reason: ReasonCode | None
    snapshot: CapabilitySnapshot | None

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if self.reason is not None and type(self.reason) is not ReasonCode:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if self.accepted != (self.reason is None):
            _fail(ReasonCode.CAPABILITY_INVALID)
        if self.accepted and type(self.snapshot) is not CapabilitySnapshot:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if not self.accepted and self.snapshot is not None and type(self.snapshot) is not CapabilitySnapshot:
            _fail(ReasonCode.CAPABILITY_INVALID)

    def __repr__(self) -> str:
        return "CapabilityDecision(...)"


@dataclass(frozen=True, slots=True, repr=False)
class _ClaimEntry:
    record: CapabilityClaimRecord
    raw: bytes
    valid_from: datetime
    expires_at: datetime
    state: CapabilityState


def _parse_claim(raw: object) -> _ClaimEntry:
    if type(raw) is not bytes:
        _fail(ReasonCode.CAPABILITY_INVALID)
    stable_raw = cast(bytes, raw)
    try:
        document = json.loads(stable_raw.decode("utf-8"))
        if type(document) is not dict or canonical_bytes(document) != stable_raw:
            _fail(ReasonCode.CAPABILITY_INVALID)
        record = create_record(document)
        if type(record) is not CapabilityClaimRecord:
            _fail(ReasonCode.CAPABILITY_INVALID)
        stable_record = cast(CapabilityClaimRecord, record)
        if stable_record.kind is not ContractKind.CAPABILITY_CLAIM:
            _fail(ReasonCode.CAPABILITY_INVALID)
        valid_from = _parse_timestamp(document.get("valid_from"))
        expires_at = _parse_timestamp(document.get("expires_at"))
        if not valid_from < expires_at:
            _fail(ReasonCode.CAPABILITY_INVALID)
        return _ClaimEntry(
            record=stable_record,
            raw=stable_raw,
            valid_from=valid_from,
            expires_at=expires_at,
            state=CapabilityState.ISSUED,
        )
    except _CapabilityFailure:
        raise
    except Exception:
        _fail(ReasonCode.CAPABILITY_INVALID)


def _transition(state: CapabilityState, event: CapabilityTransitionEvent) -> CapabilityState:
    result = capability_transition(state, event)
    if type(result) is not TransitionDecision or not result.allowed:
        _fail(ReasonCode.CAPABILITY_INVALID)
    resulting_state = result.resulting_state
    if type(resulting_state) is not CapabilityState:
        _fail(ReasonCode.CAPABILITY_INVALID)
    return cast(CapabilityState, resulting_state)


def _resource_bounds(record: CapabilityClaimRecord) -> dict[str, int]:
    bounds = record.resource_bounds.to_document()
    if type(bounds) is not dict:
        _fail(ReasonCode.CAPABILITY_INVALID)
    typed = cast(dict[str, object], bounds)
    result: dict[str, int] = {}
    for key, value in typed.items():
        if type(value) is not int:
            _fail(ReasonCode.CAPABILITY_INVALID)
        result[key] = value
    return result


class CapabilityBroker:
    __slots__ = ("__claims",)
    __claims: dict[str, _ClaimEntry]

    def __init__(self) -> None:
        object.__setattr__(self, "_CapabilityBroker__claims", {})

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("CAPABILITY_INVALID")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("CAPABILITY_INVALID")

    def __repr__(self) -> str:
        return "CapabilityBroker(...)"

    def _effective_state(self, entry: _ClaimEntry, as_of: datetime) -> CapabilityState:
        if entry.state is CapabilityState.REVOKED:
            return CapabilityState.REVOKED
        if as_of >= entry.expires_at:
            return CapabilityState.EXPIRED
        return entry.state

    def _snapshot(self, entry: _ClaimEntry, as_of: datetime) -> CapabilitySnapshot:
        record = entry.record
        return CapabilitySnapshot(
            capability_id=record.capability_id,
            parent_capability_id=record.parent_capability_id,
            operator_id=record.operator_id,
            task_id=record.task_id,
            workspace_ref=record.workspace_ref,
            authority_epoch=record.authority_epoch,
            lease_generation=record.lease_generation,
            policy_digest=record.policy_digest,
            delegation_depth=record.delegation_depth,
            state=self._effective_state(entry, as_of),
        )

    def _deny(
        self,
        reason: ReasonCode,
        entry: _ClaimEntry,
        as_of: datetime,
    ) -> CapabilityDecision:
        return CapabilityDecision(False, reason, self._snapshot(entry, as_of))

    def _ancestor_reason(
        self,
        entry: _ClaimEntry,
        as_of: datetime,
    ) -> ReasonCode | None:
        parent_id = entry.record.parent_capability_id
        seen: set[str] = set()
        while parent_id is not None:
            if parent_id in seen:
                return ReasonCode.CAPABILITY_INVALID
            seen.add(parent_id)
            parent = self.__claims.get(parent_id)
            if parent is None:
                return ReasonCode.CAPABILITY_INVALID
            state = self._effective_state(parent, as_of)
            if state is CapabilityState.REVOKED:
                return ReasonCode.CAPABILITY_REVOKED
            if state in (CapabilityState.EXPIRED, CapabilityState.CONSUMED):
                return ReasonCode.CAPABILITY_INVALID
            parent_id = parent.record.parent_capability_id
        return None

    def register_claim(self, claim_bytes: object, *, as_of: object) -> CapabilityDecision:
        claim: _ClaimEntry | None = None
        stable_as_of: datetime | None = None
        try:
            stable_as_of = _safe_utc(as_of)
            claim = _parse_claim(claim_bytes)
            record = claim.record
            if stable_as_of >= claim.expires_at:
                _fail(ReasonCode.CAPABILITY_INVALID)
            existing = self.__claims.get(record.capability_id)
            if existing is not None:
                if existing.state is CapabilityState.REVOKED:
                    return self._deny(ReasonCode.CAPABILITY_REVOKED, existing, stable_as_of)
                ancestor_reason = self._ancestor_reason(existing, stable_as_of)
                if ancestor_reason is not None:
                    return self._deny(ancestor_reason, existing, stable_as_of)
                if existing.raw == claim.raw:
                    return CapabilityDecision(True, None, self._snapshot(existing, stable_as_of))
                return self._deny(ReasonCode.REPLAY_DETECTED, existing, stable_as_of)
            for entry in self.__claims.values():
                if entry.record.revocation_id == record.revocation_id:
                    return self._deny(ReasonCode.REPLAY_DETECTED, entry, stable_as_of)

            if record.parent_capability_id is not None:
                parent = self.__claims.get(record.parent_capability_id)
                if parent is None:
                    _fail(ReasonCode.CAPABILITY_INVALID)
                if self._effective_state(parent, stable_as_of) in (
                    CapabilityState.REVOKED,
                    CapabilityState.EXPIRED,
                    CapabilityState.CONSUMED,
                ):
                    return self._deny(ReasonCode.CAPABILITY_REVOKED, parent, stable_as_of)
                ancestor_reason = self._ancestor_reason(parent, stable_as_of)
                if ancestor_reason is not None:
                    return self._deny(ancestor_reason, parent, stable_as_of)
                parent_record = parent.record
                if (
                    record.operator_id != parent_record.operator_id
                    or record.task_id != parent_record.task_id
                    or record.workspace_ref != parent_record.workspace_ref
                    or record.authority_epoch != parent_record.authority_epoch
                    or record.lease_generation != parent_record.lease_generation
                    or record.policy_digest != parent_record.policy_digest
                ):
                    _fail(ReasonCode.CAPABILITY_INVALID)
                if record.delegation_depth <= parent_record.delegation_depth:
                    _fail(ReasonCode.CAPABILITY_INVALID)
                if not set(record.allowed_actions).issubset(set(parent_record.allowed_actions)):
                    _fail(ReasonCode.SCOPE_EXCEEDED)
                if not set(record.allowed_input_artifact_ids).issubset(
                    set(parent_record.allowed_input_artifact_ids),
                ):
                    _fail(ReasonCode.SCOPE_EXCEEDED)
                if not set(record.egress_aliases).issubset(set(parent_record.egress_aliases)):
                    _fail(ReasonCode.SCOPE_EXCEEDED)
                if not set(record.broker_handle_refs).issubset(
                    set(parent_record.broker_handle_refs),
                ):
                    _fail(ReasonCode.SCOPE_EXCEEDED)
                if claim.valid_from < parent.valid_from or claim.expires_at > parent.expires_at:
                    _fail(ReasonCode.SCOPE_EXCEEDED)
                child_bounds = _resource_bounds(record)
                parent_bounds = _resource_bounds(parent_record)
                for key, value in child_bounds.items():
                    if value > parent_bounds[key]:
                        _fail(ReasonCode.SCOPE_EXCEEDED)

            self.__claims[record.capability_id] = claim
            return CapabilityDecision(True, None, self._snapshot(claim, stable_as_of))
        except _CapabilityFailure as failure:
            snapshot = (
                None
                if claim is None or stable_as_of is None
                else self._snapshot(claim, stable_as_of)
            )
            return CapabilityDecision(False, failure.reason, snapshot)

    def revoke(self, capability_id: object, *, as_of: object) -> CapabilityDecision:
        stable_as_of = _safe_utc(as_of)
        if type(capability_id) is not str:
            _fail(ReasonCode.CAPABILITY_INVALID)
        stable_id = cast(str, capability_id)
        entry = self.__claims.get(stable_id)
        if entry is None:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if entry.state is CapabilityState.REVOKED:
            return CapabilityDecision(True, None, self._snapshot(entry, stable_as_of))
        updated = _ClaimEntry(
            record=entry.record,
            raw=entry.raw,
            valid_from=entry.valid_from,
            expires_at=entry.expires_at,
            state=_transition(entry.state, CapabilityTransitionEvent.CAPABILITY_REVOKED),
        )
        self.__claims[stable_id] = updated
        return CapabilityDecision(True, None, self._snapshot(updated, stable_as_of))

    def authorize(
        self,
        capability_id: object,
        *,
        attempt: object,
        action: object,
        input_artifact_ids: object,
        egress_aliases: object,
        broker_handle_refs: object,
        operator_id: object,
        task_id: object,
        workspace_ref: object,
        authority_epoch: object,
        lease_generation: object,
        policy_digest: object,
        as_of: object,
        urgency: object | None = None,
        confidence: object | None = None,
    ) -> CapabilityDecision:
        del urgency
        del confidence
        stable_as_of = _safe_utc(as_of)
        if type(capability_id) is not str:
            _fail(ReasonCode.CAPABILITY_INVALID)
        entry = self.__claims.get(cast(str, capability_id))
        if entry is None:
            _fail(ReasonCode.CAPABILITY_INVALID)
        if type(attempt) is not CapabilityAttempt or type(action) is not CapabilityAction:
            return self._deny(ReasonCode.CAPABILITY_INVALID, entry, stable_as_of)
        stable_inputs = _require_tuple_of_strings(input_artifact_ids)
        stable_egress = _require_tuple_of_strings(egress_aliases)
        stable_handles = _require_tuple_of_strings(broker_handle_refs)
        if (
            type(operator_id) is not str
            or type(task_id) is not str
            or type(workspace_ref) is not str
            or type(authority_epoch) is not int
            or type(lease_generation) is not int
            or type(policy_digest) is not str
        ):
            return self._deny(ReasonCode.CAPABILITY_INVALID, entry, stable_as_of)
        state = self._effective_state(entry, stable_as_of)
        if state is CapabilityState.REVOKED:
            return self._deny(ReasonCode.CAPABILITY_REVOKED, entry, stable_as_of)
        if state in (CapabilityState.EXPIRED, CapabilityState.CONSUMED):
            return self._deny(ReasonCode.CAPABILITY_INVALID, entry, stable_as_of)
        ancestor_reason = self._ancestor_reason(entry, stable_as_of)
        if ancestor_reason is not None:
            return self._deny(ancestor_reason, entry, stable_as_of)
        record = entry.record
        if (
            operator_id != record.operator_id
            or task_id != record.task_id
            or workspace_ref != record.workspace_ref
            or authority_epoch != record.authority_epoch
            or lease_generation != record.lease_generation
            or policy_digest != record.policy_digest
        ):
            return self._deny(ReasonCode.CAPABILITY_INVALID, entry, stable_as_of)
        if cast(CapabilityAction, action).value not in record.allowed_actions:
            return self._deny(ReasonCode.SCOPE_EXCEEDED, entry, stable_as_of)
        if not set(stable_inputs).issubset(set(record.allowed_input_artifact_ids)):
            return self._deny(ReasonCode.SCOPE_EXCEEDED, entry, stable_as_of)
        if not set(stable_egress).issubset(set(record.egress_aliases)):
            return self._deny(ReasonCode.SCOPE_EXCEEDED, entry, stable_as_of)
        if not set(stable_handles).issubset(set(record.broker_handle_refs)):
            return self._deny(ReasonCode.SCOPE_EXCEEDED, entry, stable_as_of)

        updated = entry
        if state is CapabilityState.ISSUED:
            updated = _ClaimEntry(
                record=entry.record,
                raw=entry.raw,
                valid_from=entry.valid_from,
                expires_at=entry.expires_at,
                state=_transition(entry.state, CapabilityTransitionEvent.FIRST_VALID_USE),
            )
            self.__claims[record.capability_id] = updated
        return CapabilityDecision(True, None, self._snapshot(updated, stable_as_of))
