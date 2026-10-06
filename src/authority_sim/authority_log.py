from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import NoReturn, cast

from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.records import AuthorityEventRecord, create_record


class FaultPoint(Enum):
    BEFORE_STAGE = "BEFORE_STAGE"
    BETWEEN_STAGE_RECORDS = "BETWEEN_STAGE_RECORDS"
    AFTER_SWAP = "AFTER_SWAP"


class _LogReason(Enum):
    INVALID = "AUTHORITY_LOG_INVALID"
    EXPECTED_HEAD_MISMATCH = "EXPECTED_HEAD_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    FAULT_INJECTED = "FAULT_INJECTED"


class AuthorityLogError(ValueError):
    __slots__ = ("reason",)

    def __init__(self, reason: _LogReason) -> None:
        if type(reason) is not _LogReason:
            raise ValueError("AUTHORITY_LOG_INVALID") from None
        object.__setattr__(self, "reason", reason)
        ValueError.__init__(self, reason.value)

    def __repr__(self) -> str:
        return f"AuthorityLogError('{self.reason.value}')"


def _raise(reason: _LogReason) -> NoReturn:
    raise AuthorityLogError(reason) from None


def _is_digest(value: object) -> bool:
    if type(value) is not str:
        return False
    text = cast(str, value)
    return (
        len(text) == 71
        and text.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in text[7:])
    )


def _require_head(value: object) -> str | None:
    if value is None:
        return None
    if not _is_digest(value):
        _raise(_LogReason.INVALID)
    return cast(str, value)


@dataclass(frozen=True, slots=True, repr=False)
class AppendResult:
    prior_head: str | None
    resulting_head: str
    first_sequence: int
    last_sequence: int

    def __post_init__(self) -> None:
        if self.prior_head is not None and not _is_digest(self.prior_head):
            _raise(_LogReason.INVALID)
        if not _is_digest(self.resulting_head):
            _raise(_LogReason.INVALID)
        if type(self.first_sequence) is not int or self.first_sequence < 1:
            _raise(_LogReason.INVALID)
        if type(self.last_sequence) is not int or self.last_sequence < self.first_sequence:
            _raise(_LogReason.INVALID)

    def __repr__(self) -> str:
        return "AppendResult(...)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthorityLogSnapshot:
    head: str | None
    accepted_event_bytes: tuple[bytes, ...]
    projection_bytes: bytes

    def __post_init__(self) -> None:
        if self.head is not None and not _is_digest(self.head):
            _raise(_LogReason.INVALID)
        if type(self.accepted_event_bytes) is not tuple:
            _raise(_LogReason.INVALID)
        if any(type(raw) is not bytes for raw in self.accepted_event_bytes):
            _raise(_LogReason.INVALID)
        if type(self.projection_bytes) is not bytes:
            _raise(_LogReason.INVALID)

    def __repr__(self) -> str:
        return "AuthorityLogSnapshot(...)"


@dataclass(frozen=True, slots=True, repr=False)
class _AcceptedEvent:
    record: AuthorityEventRecord
    raw: bytes
    observed_key: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _LogState:
    events: tuple[_AcceptedEvent, ...]
    head: str | None
    projection_bytes: bytes


def _observed_key(value: object) -> tuple[int, int, int, int, int, int, int]:
    if type(value) is not str:
        _raise(_LogReason.INVALID)
    text = cast(str, value)
    if not text.endswith("Z"):
        _raise(_LogReason.INVALID)
    without_zone = text[:-1]
    if "." in without_zone:
        base_text, fraction = without_zone.split(".", 1)
    else:
        base_text, fraction = without_zone, ""
    if len(fraction) > 9 or (fraction and not fraction.isdigit()):
        _raise(_LogReason.INVALID)
    try:
        base = datetime.fromisoformat(base_text)
    except Exception:
        _raise(_LogReason.INVALID)
    nanosecond = int(fraction.ljust(9, "0")) if fraction else 0
    return (
        base.year,
        base.month,
        base.day,
        base.hour,
        base.minute,
        base.second,
        nanosecond,
    )


def _parse_event(raw: bytes) -> _AcceptedEvent:
    try:
        document = json.loads(raw.decode("utf-8"))
        if type(document) is not dict:
            _raise(_LogReason.INVALID)
        if canonical_bytes(document) != raw:
            _raise(_LogReason.INVALID)
        record = create_record(document)
        if type(record) is not AuthorityEventRecord:
            _raise(_LogReason.INVALID)
        stable_record = cast(AuthorityEventRecord, record)
        body = dict(document)
        declared_digest = body.pop("event_digest")
        computed_digest = sha256_digest(canonical_bytes(body))
        if type(declared_digest) is not str or declared_digest != computed_digest:
            _raise(_LogReason.INVALID)
        return _AcceptedEvent(
            record=stable_record,
            raw=raw,
            observed_key=_observed_key(document.get("observed_at")),
        )
    except AuthorityLogError:
        raise
    except Exception:
        _raise(_LogReason.INVALID)


def _projection(events: tuple[_AcceptedEvent, ...]) -> bytes:
    return canonical_bytes(
        {
            "events": [
                {
                    "event_digest": event.record.event_digest,
                    "event_id": event.record.event_id,
                    "event_type": event.record.event_type,
                    "object_digest": event.record.object_digest,
                    "object_ref": event.record.object_ref,
                    "sequence": event.record.sequence,
                }
                for event in events
            ],
            "head": events[-1].record.event_digest if events else None,
        },
    )


def _existing_index(
    events: tuple[_AcceptedEvent, ...],
    candidate: _AcceptedEvent,
) -> int | None:
    event_id_index: int | None = None
    idempotency_index: int | None = None
    for index, accepted in enumerate(events):
        if accepted.record.event_id == candidate.record.event_id:
            event_id_index = index
        if accepted.record.idempotency_key == candidate.record.idempotency_key:
            idempotency_index = index
    if event_id_index is None and idempotency_index is None:
        return None
    if event_id_index is None or idempotency_index is None:
        _raise(_LogReason.REPLAY_DETECTED)
    if event_id_index != idempotency_index:
        _raise(_LogReason.REPLAY_DETECTED)
    stable_index = cast(int, event_id_index)
    accepted = events[stable_index]
    if accepted.raw != candidate.raw:
        _raise(_LogReason.REPLAY_DETECTED)
    return stable_index


def _result_for_slice(
    events: tuple[_AcceptedEvent, ...],
    first_index: int,
    last_index: int,
) -> AppendResult:
    prior_head = (
        None
        if first_index == 0
        else events[first_index - 1].record.event_digest
    )
    return AppendResult(
        prior_head=prior_head,
        resulting_head=events[last_index].record.event_digest,
        first_sequence=events[first_index].record.sequence,
        last_sequence=events[last_index].record.sequence,
    )


class InMemoryAuthorityLog:
    __slots__ = ("__state",)
    __state: _LogState

    def __init__(self) -> None:
        object.__setattr__(
            self,
            "_InMemoryAuthorityLog__state",
            _LogState(events=(), head=None, projection_bytes=_projection(())),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AUTHORITY_LOG_INVALID")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("AUTHORITY_LOG_INVALID")

    def __repr__(self) -> str:
        return "InMemoryAuthorityLog(...)"

    def snapshot(self) -> AuthorityLogSnapshot:
        state = self.__state
        return AuthorityLogSnapshot(
            head=state.head,
            accepted_event_bytes=tuple(event.raw for event in state.events),
            projection_bytes=state.projection_bytes,
        )

    def compare_and_append(
        self,
        *,
        expected_head: str | None,
        event_bytes: tuple[bytes, ...],
        fault: FaultPoint | None = None,
    ) -> AppendResult:
        stable_expected_head = _require_head(expected_head)
        if type(event_bytes) is not tuple or not event_bytes:
            _raise(_LogReason.INVALID)
        if any(type(raw) is not bytes for raw in event_bytes):
            _raise(_LogReason.INVALID)
        if fault is not None and type(fault) is not FaultPoint:
            _raise(_LogReason.INVALID)

        candidates = tuple(_parse_event(raw) for raw in event_bytes)
        if len({candidate.record.event_id for candidate in candidates}) != len(candidates):
            _raise(_LogReason.REPLAY_DETECTED)
        if len({candidate.record.idempotency_key for candidate in candidates}) != len(candidates):
            _raise(_LogReason.REPLAY_DETECTED)

        state = self.__state
        existing_indices = tuple(
            _existing_index(state.events, candidate)
            for candidate in candidates
        )
        if all(index is not None for index in existing_indices):
            stable_indices = cast(tuple[int, ...], existing_indices)
            first_index = stable_indices[0]
            expected_indices = tuple(
                range(first_index, first_index + len(stable_indices)),
            )
            if stable_indices != expected_indices:
                _raise(_LogReason.REPLAY_DETECTED)
            original_prior_head = (
                None
                if first_index == 0
                else state.events[first_index - 1].record.event_digest
            )
            if stable_expected_head != original_prior_head:
                _raise(_LogReason.EXPECTED_HEAD_MISMATCH)
            return _result_for_slice(
                state.events,
                first_index,
                stable_indices[-1],
            )
        if any(index is not None for index in existing_indices):
            _raise(_LogReason.REPLAY_DETECTED)

        if stable_expected_head != state.head:
            _raise(_LogReason.EXPECTED_HEAD_MISMATCH)
        if fault is FaultPoint.BEFORE_STAGE:
            _raise(_LogReason.FAULT_INJECTED)

        staged_events = state.events
        previous_head = state.head
        previous_time = (
            None
            if not staged_events
            else staged_events[-1].observed_key
        )
        first_sequence = len(staged_events) + 1
        for index, candidate in enumerate(candidates):
            record = candidate.record
            if record.sequence != len(staged_events) + 1:
                _raise(_LogReason.INVALID)
            if record.previous_event_digest != previous_head:
                _raise(_LogReason.INVALID)
            if previous_time is not None and candidate.observed_key < previous_time:
                _raise(_LogReason.INVALID)
            staged_events = staged_events + (candidate,)
            previous_head = record.event_digest
            previous_time = candidate.observed_key
            if index == 0 and fault is FaultPoint.BETWEEN_STAGE_RECORDS:
                _raise(_LogReason.FAULT_INJECTED)

        next_state = _LogState(
            events=staged_events,
            head=previous_head,
            projection_bytes=_projection(staged_events),
        )
        object.__setattr__(self, "_InMemoryAuthorityLog__state", next_state)
        if fault is FaultPoint.AFTER_SWAP:
            _raise(_LogReason.FAULT_INJECTED)
        return AppendResult(
            prior_head=state.head,
            resulting_head=cast(str, next_state.head),
            first_sequence=first_sequence,
            last_sequence=len(staged_events),
        )
