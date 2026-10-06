from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TypeAlias, Union, cast

from authority_sim.contracts import validate_document


class RecordError(ValueError):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("RECORD_INVALID")

    def __repr__(self) -> str:
        return "RecordError('RECORD_INVALID')"


class ContractKind(Enum):
    AUTHORITY_LEASE = "authority_lease"
    TASK_ENVELOPE = "task_envelope"
    CAPABILITY_CLAIM = "capability_claim"
    ARTIFACT_MANIFEST = "artifact_manifest"
    EXECUTION_RECEIPT = "execution_receipt"
    PROMOTION_PROPOSAL = "promotion_proposal"
    PROMOTION_DECISION = "promotion_decision"
    AUTHORITY_EVENT = "authority_event"


class TrustClass(Enum):
    GOVERNOR_OBSERVED = "governor_observed"
    ADAPTER_PARSED = "adapter_parsed"
    TOOL_SELF_REPORTED = "tool_self_reported"
    MODEL_ASSERTED = "model_asserted"


class LeaseAction(Enum):
    ACQUIRE = "acquire"
    RENEW = "renew"
    REISSUE = "reissue"
    RECOVERY = "recovery"


class Classification(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class Provenance(Enum):
    GOVERNOR_OBSERVED = "governor_observed"
    ADAPTER_PARSED = "adapter_parsed"
    TOOL_SELF_REPORTED = "tool_self_reported"
    MODEL_ASSERTED = "model_asserted"


ImmutableValue: TypeAlias = Union[
    None,
    bool,
    int,
    str,
    datetime,
    ContractKind,
    TrustClass,
    LeaseAction,
    Classification,
    Provenance,
    "FrozenObject",
    "ProducerRecord",
    tuple["ImmutableValue", ...],
]


def _record_error() -> RecordError:
    return RecordError()


def _safe_datetime(value: object) -> datetime:
    if type(value) is not datetime:
        raise _record_error() from None
    stable = cast(datetime, value)
    try:
        offset = stable.utcoffset()
    except Exception:
        raise _record_error() from None
    if stable.tzinfo is None or type(offset) is not timedelta or offset != timedelta(0):
        raise _record_error() from None
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
        raise _record_error() from None


def _freeze_value(name: str, value: object) -> ImmutableValue:
    if name == "kind":
        if type(value) is not ContractKind:
            raise _record_error() from None
        return cast(ContractKind, value)
    if name == "lease_action":
        if type(value) is not LeaseAction:
            raise _record_error() from None
        return cast(LeaseAction, value)
    if name == "classification":
        if type(value) is not Classification:
            raise _record_error() from None
        return cast(Classification, value)
    if name == "provenance":
        if type(value) is not Provenance:
            raise _record_error() from None
        return cast(Provenance, value)
    if name in ("trust_class", "minimum_trust_class"):
        if type(value) is not TrustClass:
            raise _record_error() from None
        return cast(TrustClass, value)
    if name in (
        "issued_at",
        "valid_from",
        "expires_at",
        "created_at",
        "started_at",
        "finished_at",
        "decided_at",
        "observed_at",
    ):
        return _safe_datetime(value)
    if name == "producer":
        if type(value) is not ProducerRecord:
            raise _record_error() from None
        return cast(ProducerRecord, value)

    if value is None:
        return None
    value_type = type(value)
    if value_type is bool:
        return cast(bool, value)
    if value_type is int:
        return cast(int, value)
    if value_type is str:
        text = cast(str, value)
        if not text or text.strip() != text:
            raise _record_error() from None
        return text
    if value_type is tuple:
        sequence = cast(tuple[object, ...], value)
        return tuple(_freeze_value("", item) for item in sequence)
    if value_type is FrozenObject:
        return cast(FrozenObject, value)
    if value_type is ProducerRecord:
        return cast(ProducerRecord, value)
    raise _record_error() from None


@dataclass(frozen=True, slots=True, repr=False)
class FrozenObject:
    entries: tuple[tuple[str, ImmutableValue], ...]

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple:
            raise _record_error() from None
        stable_entries: list[tuple[str, ImmutableValue]] = []
        seen: set[str] = set()
        for entry in self.entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise _record_error() from None
            key, value = entry
            if type(key) is not str or not key or key.strip() != key or key in seen:
                raise _record_error() from None
            seen.add(key)
            stable_entries.append((key, _freeze_value(key, value)))
        stable_entries.sort(key=lambda item: item[0])
        object.__setattr__(self, "entries", tuple(stable_entries))

    def get(self, key: str) -> ImmutableValue:
        if type(key) is not str:
            raise _record_error() from None
        for existing_key, value in self.entries:
            if existing_key == key:
                return value
        raise _record_error() from None

    def to_document(self) -> dict[str, object]:
        return {key: _thaw_value(value) for key, value in self.entries}

    def __repr__(self) -> str:
        return "FrozenObject(...)"


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ProducerRecord:
    node_id: str
    adapter_id: str
    process_id: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        if args or frozenset(kwargs) != {"node_id", "adapter_id", "process_id"}:
            raise _record_error() from None
        stable: dict[str, str] = {}
        for name in ("node_id", "adapter_id", "process_id"):
            value = kwargs[name]
            if type(value) is not str:
                raise _record_error() from None
            text = cast(str, value)
            if not text or text.strip() != text:
                raise _record_error() from None
            if name == "node_id":
                pattern = r"node:[a-z0-9][a-z0-9._-]{2,63}"
            elif name == "adapter_id":
                pattern = r"adapter:[a-z0-9][a-z0-9._-]{2,63}"
            else:
                pattern = r"process:[A-Za-z0-9._-]{3,128}"
            if re.fullmatch(pattern, text) is None:
                raise _record_error() from None
            stable[name] = text
        object.__setattr__(self, "node_id", stable["node_id"])
        object.__setattr__(self, "adapter_id", stable["adapter_id"])
        object.__setattr__(self, "process_id", stable["process_id"])

    def to_document(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "adapter_id": self.adapter_id,
            "process_id": self.process_id,
        }

    def __repr__(self) -> str:
        return "ProducerRecord(...)"


class _RecordMethods:
    __slots__ = ()

    def to_document(self) -> dict[str, object]:
        return {
            name: _thaw_value(getattr(self, name))
            for name in _expected_names(type(self))
        }

    def __repr__(self) -> str:
        return f"{type(self).__name__}(...)"


def _thaw_datetime(value: datetime) -> str:
    stable = _safe_datetime(value)
    if stable.microsecond:
        return stable.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return stable.strftime("%Y-%m-%dT%H:%M:%SZ")


def _thaw_value(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) in (ContractKind, TrustClass, LeaseAction, Classification, Provenance):
        return cast(Enum, value).value
    if type(value) is datetime:
        return _thaw_datetime(cast(datetime, value))
    if type(value) is tuple:
        return [_thaw_value(item) for item in cast(tuple[object, ...], value)]
    if type(value) is FrozenObject:
        return cast(FrozenObject, value).to_document()
    if type(value) is ProducerRecord:
        return cast(ProducerRecord, value).to_document()
    raise _record_error() from None


def _initialize_record(
    record: _RecordMethods,
    args: tuple[object, ...],
    kwargs: dict[str, object],
    expected_kind: ContractKind,
) -> None:
    try:
        expected_names = _expected_names(type(record))
        if args or frozenset(kwargs) != frozenset(expected_names):
            raise _record_error()
        stable_values = {
            name: _freeze_value(name, kwargs[name])
            for name in expected_names
        }
        if stable_values["kind"] is not expected_kind:
            raise _record_error()
        raw = {
            name: _thaw_value(stable_values[name])
            for name in expected_names
        }
        validate_document(raw)
        for name in expected_names:
            object.__setattr__(record, name, stable_values[name])
    except Exception:
        raise _record_error() from None


@dataclass(frozen=True, slots=True, init=False, repr=False)
class AuthorityLeaseRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    lease_record_id: str
    lease_id: str
    authority_epoch: int
    lease_generation: int
    writer_id: str
    lease_action: LeaseAction
    authorization_ref: str
    expected_authority_state: str
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    policy_digest: str
    prior_authority_head: str | None
    previous_lease_record_id: str | None
    projection: str
    encoding_profile: str
    nonce: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.AUTHORITY_LEASE)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class TaskEnvelopeRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    task_id: str
    decision_ref: str
    authority_epoch: int
    lease_generation: int
    issued_at: datetime
    expires_at: datetime
    policy_digest: str
    expected_authority_head: str
    capability_id: str
    audience: FrozenObject
    goal: str
    workspace_ref: str
    input_refs: tuple[FrozenObject, ...]
    context_refs: tuple[FrozenObject, ...]
    required_actions: tuple[str, ...]
    required_adapter_features: tuple[str, ...]
    acceptance_checks: tuple[FrozenObject, ...]
    budget: FrozenObject
    idempotency_key: str
    nonce: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.TASK_ENVELOPE)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class CapabilityClaimRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    capability_id: str
    parent_capability_id: str | None
    task_id: str
    authority_epoch: int
    lease_generation: int
    issuer_id: str
    subject: FrozenObject
    audience: FrozenObject
    policy_digest: str
    workspace_ref: str
    allowed_actions: tuple[str, ...]
    allowed_input_artifact_ids: tuple[str, ...]
    egress_aliases: tuple[str, ...]
    broker_handle_refs: tuple[str, ...]
    resource_bounds: FrozenObject
    valid_from: datetime
    expires_at: datetime
    revocation_id: str
    delegation_depth: int
    projection: str
    encoding_profile: str
    nonce: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.CAPABILITY_CLAIM)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ArtifactManifestRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    artifact_id: str
    task_id: str
    run_id: str
    producer: ProducerRecord
    content_digest: str
    byte_length: int
    media_type: str
    classification: Classification
    storage_ref: str
    created_at: datetime
    parent_artifact_ids: tuple[str, ...]
    provenance: Provenance
    immutable: bool

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.ARTIFACT_MANIFEST)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class ExecutionReceiptRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    receipt_id: str
    task_id: str
    capability_id: str
    authority_epoch: int
    lease_generation: int
    run_id: str
    node_id: str
    process_id: str
    adapter_identity: FrozenObject
    workspace_ref: str
    policy_digest: str
    started_at: datetime
    finished_at: datetime
    terminal_state: str
    process_result: FrozenObject
    observations: tuple[FrozenObject, ...]
    artifact_refs: tuple[FrozenObject, ...]
    usage: tuple[FrozenObject, ...]
    nonce: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.EXECUTION_RECEIPT)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class PromotionProposalRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    proposal_id: str
    task_id: str
    capability_id: str
    authority_epoch: int
    lease_generation: int
    expected_authority_head: str
    receipt_ids: tuple[str, ...]
    artifact_refs: tuple[FrozenObject, ...]
    requested_effect: str
    acceptance_evidence: tuple[FrozenObject, ...]
    proposed_by: FrozenObject
    created_at: datetime
    idempotency_key: str
    nonce: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.PROMOTION_PROPOSAL)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class PromotionDecisionRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    promotion_decision_id: str
    proposal_id: str
    task_id: str
    authority_epoch: int
    lease_generation: int
    authority_writer_id: str
    prior_authority_head: str
    decision: str
    reason_code: str
    accepted_artifacts: tuple[FrozenObject, ...]
    prior_state: str
    next_state: str
    decided_at: datetime
    idempotency_key: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.PROMOTION_DECISION)


@dataclass(frozen=True, slots=True, init=False, repr=False)
class AuthorityEventRecord(_RecordMethods):
    kind: ContractKind
    schema_version: str
    operator_id: str
    event_id: str
    sequence: int
    authority_epoch: int
    lease_generation: int
    previous_event_digest: str | None
    event_digest: str
    event_type: str
    actor: FrozenObject
    object_kind: str
    object_ref: str
    object_digest: str
    transition: FrozenObject
    policy_digest: str
    observed_at: datetime
    idempotency_key: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        _initialize_record(self, args, kwargs, ContractKind.AUTHORITY_EVENT)


def _expected_names(record_type: type[_RecordMethods]) -> tuple[str, ...]:
    if record_type is AuthorityLeaseRecord:
        return (
            "kind", "schema_version", "operator_id", "lease_record_id",
            "lease_id", "authority_epoch", "lease_generation", "writer_id",
            "lease_action", "authorization_ref", "expected_authority_state",
            "issued_at", "valid_from", "expires_at", "policy_digest",
            "prior_authority_head", "previous_lease_record_id", "projection",
            "encoding_profile", "nonce",
        )
    if record_type is TaskEnvelopeRecord:
        return (
            "kind", "schema_version", "operator_id", "task_id",
            "decision_ref", "authority_epoch", "lease_generation", "issued_at",
            "expires_at", "policy_digest", "expected_authority_head",
            "capability_id", "audience", "goal", "workspace_ref", "input_refs",
            "context_refs", "required_actions", "required_adapter_features",
            "acceptance_checks", "budget", "idempotency_key", "nonce",
        )
    if record_type is CapabilityClaimRecord:
        return (
            "kind", "schema_version", "operator_id", "capability_id",
            "parent_capability_id", "task_id", "authority_epoch",
            "lease_generation", "issuer_id", "subject", "audience",
            "policy_digest", "workspace_ref", "allowed_actions",
            "allowed_input_artifact_ids", "egress_aliases", "broker_handle_refs",
            "resource_bounds", "valid_from", "expires_at", "revocation_id",
            "delegation_depth", "projection", "encoding_profile", "nonce",
        )
    if record_type is ArtifactManifestRecord:
        return (
            "kind", "schema_version", "operator_id", "artifact_id", "task_id",
            "run_id", "producer", "content_digest", "byte_length", "media_type",
            "classification", "storage_ref", "created_at", "parent_artifact_ids",
            "provenance", "immutable",
        )
    if record_type is ExecutionReceiptRecord:
        return (
            "kind", "schema_version", "operator_id", "receipt_id", "task_id",
            "capability_id", "authority_epoch", "lease_generation", "run_id",
            "node_id", "process_id", "adapter_identity", "workspace_ref",
            "policy_digest", "started_at", "finished_at", "terminal_state",
            "process_result", "observations", "artifact_refs", "usage", "nonce",
        )
    if record_type is PromotionProposalRecord:
        return (
            "kind", "schema_version", "operator_id", "proposal_id", "task_id",
            "capability_id", "authority_epoch", "lease_generation",
            "expected_authority_head", "receipt_ids", "artifact_refs",
            "requested_effect", "acceptance_evidence", "proposed_by", "created_at",
            "idempotency_key", "nonce",
        )
    if record_type is PromotionDecisionRecord:
        return (
            "kind", "schema_version", "operator_id", "promotion_decision_id",
            "proposal_id", "task_id", "authority_epoch", "lease_generation",
            "authority_writer_id", "prior_authority_head", "decision",
            "reason_code", "accepted_artifacts", "prior_state", "next_state",
            "decided_at", "idempotency_key",
        )
    if record_type is AuthorityEventRecord:
        return (
            "kind", "schema_version", "operator_id", "event_id", "sequence",
            "authority_epoch", "lease_generation", "previous_event_digest",
            "event_digest", "event_type", "actor", "object_kind", "object_ref",
            "object_digest", "transition", "policy_digest", "observed_at",
            "idempotency_key",
        )
    raise _record_error() from None


def _parse_datetime(value: object) -> datetime:
    if type(value) is not str:
        raise _record_error() from None
    text = cast(str, value)
    if not text.endswith("Z"):
        raise _record_error() from None
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except Exception:
        raise _record_error() from None
    return _safe_datetime(parsed)


def _convert_raw_value(name: str, value: object) -> ImmutableValue:
    try:
        if name == "kind":
            return ContractKind(cast(str, value))
        if name == "lease_action":
            return LeaseAction(cast(str, value))
        if name == "classification":
            return Classification(cast(str, value))
        if name == "provenance":
            return Provenance(cast(str, value))
        if name in ("trust_class", "minimum_trust_class"):
            return TrustClass(cast(str, value))
        if name in (
            "issued_at",
            "valid_from",
            "expires_at",
            "created_at",
            "started_at",
            "finished_at",
            "decided_at",
            "observed_at",
        ):
            return _parse_datetime(value)
        if name == "producer":
            if type(value) is not dict:
                raise _record_error()
            producer = cast(dict[str, object], value)
            return ProducerRecord(**producer)
        if type(value) is dict:
            mapping = cast(dict[str, object], value)
            entries = tuple(
                (key, _convert_raw_value(key, item))
                for key, item in sorted(mapping.items())
            )
            return FrozenObject(entries)
        if type(value) is list:
            sequence = cast(list[object], value)
            return tuple(_convert_raw_value("", item) for item in sequence)
        return _freeze_value(name, value)
    except Exception:
        raise _record_error() from None


def _record_type(kind: ContractKind) -> type[_RecordMethods]:
    if kind is ContractKind.AUTHORITY_LEASE:
        return AuthorityLeaseRecord
    if kind is ContractKind.TASK_ENVELOPE:
        return TaskEnvelopeRecord
    if kind is ContractKind.CAPABILITY_CLAIM:
        return CapabilityClaimRecord
    if kind is ContractKind.ARTIFACT_MANIFEST:
        return ArtifactManifestRecord
    if kind is ContractKind.EXECUTION_RECEIPT:
        return ExecutionReceiptRecord
    if kind is ContractKind.PROMOTION_PROPOSAL:
        return PromotionProposalRecord
    if kind is ContractKind.PROMOTION_DECISION:
        return PromotionDecisionRecord
    if kind is ContractKind.AUTHORITY_EVENT:
        return AuthorityEventRecord
    raise _record_error() from None


def create_record(document: dict) -> _RecordMethods:
    try:
        if type(document) is not dict:
            raise _record_error()
        validate_document(document)
        raw = cast(dict[str, object], document)
        converted = {
            key: _convert_raw_value(key, value)
            for key, value in raw.items()
        }
        kind = converted.get("kind")
        if type(kind) is not ContractKind:
            raise _record_error()
        record_type = _record_type(cast(ContractKind, kind))
        return record_type(**converted)
    except Exception:
        raise _record_error() from None
