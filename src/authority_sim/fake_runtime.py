from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import cast

from authority_sim.canonical import canonical_bytes
from authority_sim.errors import Denied, ReasonCode
from authority_sim.records import (
    AuthorityEventRecord,
    CapabilityClaimRecord,
    ExecutionReceiptRecord,
    FrozenObject,
    PromotionProposalRecord,
    TaskEnvelopeRecord,
    create_record,
)
from authority_sim.transitions import RunOutcome, RunState, TransitionDecision, run_transition


_ERROR = "FAKE_RUNTIME_INVALID"
_PINNED_ADAPTER_ID = "adapter:fake-worker"
_PINNED_ADAPTER_VERSION = "0.1.0"
_PINNED_BINARY_DIGEST = "sha256:" + ("a" * 64)
_PINNED_MANIFEST_DIGEST = "sha256:" + ("b" * 64)
_PINNED_FEATURES = (
    "structured-output",
    "cancellation",
    "network-egress",
)
_PINNED_EGRESS_DESTINATIONS = (
    ("egress:registry", "synthetic://registry/api"),
)
_RUN_ID_PATTERN = re.compile(r"run_[a-z0-9][a-z0-9-]{7,63}")
_TERMINAL_STATES = frozenset(
    ("success", "failed", "cancelled", "timed_out", "denied"),
)


def _invalid() -> ValueError:
    return ValueError(_ERROR)


def _require_text(value: object) -> str:
    if type(value) is not str:
        raise _invalid() from None
    text = cast(str, value)
    if not text or text.strip() != text:
        raise _invalid() from None
    return text


def _require_worker_id(value: object) -> str:
    text = _require_text(value)
    if re.fullmatch(r"worker:[a-z0-9][a-z0-9._-]{2,63}", text) is None:
        raise _invalid() from None
    return text


def _require_digest(value: object) -> str:
    text = _require_text(value)
    if (
        len(text) != 71
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise _invalid() from None
    return text


def _require_exact_int(value: object) -> int:
    if type(value) is not int:
        raise _invalid() from None
    stable = cast(int, value)
    if stable < 0:
        raise _invalid() from None
    return stable


def _require_bool(value: object) -> bool:
    if type(value) is not bool:
        raise _invalid() from None
    return cast(bool, value)


def _safe_utc(value: object) -> datetime:
    if type(value) is not datetime:
        raise _invalid() from None
    stable = cast(datetime, value)
    try:
        offset = stable.utcoffset()
    except Exception:
        raise _invalid() from None
    if stable.tzinfo is None or type(offset) is not timedelta or offset != timedelta(0):
        raise _invalid() from None
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
        raise _invalid() from None


def _freeze_artifact_refs(value: object) -> tuple[FrozenObject, ...]:
    if type(value) is not tuple:
        raise _invalid() from None
    entries = cast(tuple[object, ...], value)
    stable: list[FrozenObject] = []
    for entry in entries:
        if type(entry) is not FrozenObject:
            raise _invalid() from None
        stable.append(cast(FrozenObject, entry))
    return tuple(stable)


def _require_run_id(value: object) -> str:
    text = _require_text(value)
    if _RUN_ID_PATTERN.fullmatch(text) is None:
        raise _invalid() from None
    return text


def _timestamp(value: datetime) -> str:
    stable = _safe_utc(value)
    if stable.microsecond:
        return stable.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return stable.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_suffix(run_id: str) -> str:
    stable_run_id = _require_run_id(run_id)
    return stable_run_id[4:]


def _require_reason(value: object) -> ReasonCode | None:
    if value is None:
        return None
    if type(value) is not ReasonCode:
        raise _invalid() from None
    return cast(ReasonCode, value)


def _copy_pin(value: FrozenObject) -> dict[str, object]:
    return value.to_document()


def _metric_value(document: FrozenObject, key: str) -> int:
    value = document.get(key)
    if type(value) is not int:
        raise _invalid() from None
    return cast(int, value)


def _limits_document(limits: BudgetLimits) -> dict[str, int]:
    return {
        "max_wall_ms": limits.max_wall_ms,
        "max_tool_calls": limits.max_tool_calls,
        "max_output_bytes": limits.max_output_bytes,
        "max_fresh_input_tokens": limits.max_fresh_input_tokens,
        "max_output_tokens": limits.max_output_tokens,
        "max_network_requests": limits.max_network_requests,
        "max_processes": limits.max_processes,
    }


def _usage_document(usage: BudgetUsage) -> dict[str, int]:
    return {
        "wall_ms": usage.wall_ms,
        "tool_calls": usage.tool_calls,
        "output_bytes": usage.output_bytes,
        "fresh_input_tokens": usage.fresh_input_tokens,
        "output_tokens": usage.output_tokens,
        "network_requests": usage.network_requests,
        "processes": usage.processes,
    }


def _advance_run(state: RunState, event: RunOutcome) -> RunState:
    result = run_transition(state, event)
    if type(result) is not TransitionDecision or not result.allowed:
        raise _invalid() from None
    next_state = result.resulting_state
    if type(next_state) is not RunState:
        raise _invalid() from None
    return cast(RunState, next_state)


@dataclass(frozen=True, slots=True)
class AdapterManifest:
    adapter_id: str
    version: str
    binary_digest: str
    manifest_digest: str
    features: tuple[str, ...]

    def __post_init__(self) -> None:
        if _require_text(self.adapter_id) != _PINNED_ADAPTER_ID:
            raise _invalid() from None
        if _require_text(self.version) != _PINNED_ADAPTER_VERSION:
            raise _invalid() from None
        if _require_digest(self.binary_digest) != _PINNED_BINARY_DIGEST:
            raise _invalid() from None
        if _require_digest(self.manifest_digest) != _PINNED_MANIFEST_DIGEST:
            raise _invalid() from None
        if type(self.features) is not tuple or self.features != _PINNED_FEATURES:
            raise _invalid() from None
        for feature in self.features:
            if type(feature) is not str or feature not in _PINNED_FEATURES:
                raise _invalid() from None


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    max_wall_ms: int
    max_tool_calls: int
    max_output_bytes: int
    max_fresh_input_tokens: int
    max_output_tokens: int
    max_network_requests: int
    max_processes: int

    def __post_init__(self) -> None:
        _require_exact_int(self.max_wall_ms)
        _require_exact_int(self.max_tool_calls)
        _require_exact_int(self.max_output_bytes)
        _require_exact_int(self.max_fresh_input_tokens)
        _require_exact_int(self.max_output_tokens)
        _require_exact_int(self.max_network_requests)
        _require_exact_int(self.max_processes)


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    wall_ms: int
    tool_calls: int
    output_bytes: int
    fresh_input_tokens: int
    output_tokens: int
    network_requests: int
    processes: int

    def __post_init__(self) -> None:
        _require_exact_int(self.wall_ms)
        _require_exact_int(self.tool_calls)
        _require_exact_int(self.output_bytes)
        _require_exact_int(self.fresh_input_tokens)
        _require_exact_int(self.output_tokens)
        _require_exact_int(self.network_requests)
        _require_exact_int(self.processes)


@dataclass(frozen=True, slots=True)
class PathResolution:
    accepted: bool
    workspace_ref: str | None
    reason: ReasonCode | None

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise _invalid() from None
        if self.workspace_ref is not None and type(self.workspace_ref) is not str:
            raise _invalid() from None
        if self.reason is not None and type(self.reason) is not ReasonCode:
            raise _invalid() from None
        if self.accepted != (self.workspace_ref is not None and self.reason is None):
            raise _invalid() from None


class WorkspaceResolver:
    __slots__ = ("__root",)

    def __init__(self, workspace_ref: str) -> None:
        root = _require_text(workspace_ref)
        if re.fullmatch(r"workspace:[a-z0-9][a-z0-9._-]{2,127}", root) is None:
            raise _invalid() from None
        object.__setattr__(self, "_WorkspaceResolver__root", root)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_ERROR)

    def resolve(self, relative_path: object) -> PathResolution:
        if type(relative_path) is not str:
            return PathResolution(False, None, ReasonCode.SCOPE_EXCEEDED)
        path = cast(str, relative_path)
        if (
            not path
            or path.strip() != path
            or path.startswith(("/", "\\"))
            or "\\" in path
            or any(separator in path for separator in ("\u2044", "\u2215", "\uff0f", "\uff3c"))
        ):
            return PathResolution(False, None, ReasonCode.SCOPE_EXCEEDED)
        components = path.split("/")
        if any(
            component in ("", ".", "..")
            or re.fullmatch(r"[A-Za-z0-9._-]+", component) is None
            for component in components
        ):
            return PathResolution(False, None, ReasonCode.SCOPE_EXCEEDED)
        return PathResolution(True, self.__root + "/" + "/".join(components), None)


@dataclass(frozen=True, slots=True, init=False)
class ReceiptSurface:
    run_id: str
    terminal_state: str
    quarantined_artifact_refs: tuple[FrozenObject, ...]
    record: ExecutionReceiptRecord | None

    def __init__(
        self,
        run_id: str,
        terminal_state: str,
        quarantined_artifact_refs: tuple[FrozenObject, ...],
        record: ExecutionReceiptRecord | None = None,
    ) -> None:
        stable_run_id = _require_run_id(run_id)
        stable_terminal_state = _require_text(terminal_state)
        if stable_terminal_state not in _TERMINAL_STATES:
            raise _invalid() from None
        stable_refs = _freeze_artifact_refs(quarantined_artifact_refs)
        if record is not None and type(record) is not ExecutionReceiptRecord:
            raise _invalid() from None
        object.__setattr__(self, "run_id", stable_run_id)
        object.__setattr__(self, "terminal_state", stable_terminal_state)
        object.__setattr__(self, "quarantined_artifact_refs", stable_refs)
        object.__setattr__(self, "record", record)


@dataclass(frozen=True, slots=True)
class SubmissionSnapshot:
    receipt_count: int
    proposal_count: int

    def __post_init__(self) -> None:
        _require_exact_int(self.receipt_count)
        _require_exact_int(self.proposal_count)


@dataclass(frozen=True, slots=True, init=False)
class RuntimeOutcome:
    run_id: str
    run_state: RunState
    receipt: ReceiptSurface
    submission: SubmissionSnapshot
    replayed: bool
    reason: ReasonCode | None

    def __init__(
        self,
        *,
        run_id: str,
        run_state_name: str,
        receipt: ReceiptSurface,
        submission: SubmissionSnapshot,
        replayed: bool,
        reason: ReasonCode | None = None,
    ) -> None:
        stable_run_id = _require_run_id(run_id)
        stable_state_name = _require_text(run_state_name)
        if stable_state_name not in RunState.__members__:
            raise _invalid() from None
        if type(receipt) is not ReceiptSurface or type(submission) is not SubmissionSnapshot:
            raise _invalid() from None
        stable_replayed = _require_bool(replayed)
        stable_reason = _require_reason(reason)
        object.__setattr__(self, "run_id", stable_run_id)
        object.__setattr__(self, "run_state", RunState[stable_state_name])
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "submission", submission)
        object.__setattr__(self, "replayed", stable_replayed)
        object.__setattr__(self, "reason", stable_reason)

    @property
    def run_state_name(self) -> str:
        return self.run_state.name


class WorkerSubmissionPort:
    __slots__ = ("__receipts", "__proposals")
    __receipts: tuple[ExecutionReceiptRecord, ...]
    __proposals: tuple[PromotionProposalRecord, ...]

    def __init__(self) -> None:
        object.__setattr__(self, "_WorkerSubmissionPort__receipts", ())
        object.__setattr__(self, "_WorkerSubmissionPort__proposals", ())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_ERROR)

    def snapshot(self) -> SubmissionSnapshot:
        return SubmissionSnapshot(len(self.__receipts), len(self.__proposals))

    def submitted_receipts(self) -> tuple[ExecutionReceiptRecord, ...]:
        return self.__receipts

    def submitted_proposals(self) -> tuple[PromotionProposalRecord, ...]:
        return self.__proposals

    def submit_receipt(self, receipt: object) -> Denied | None:
        if type(receipt) is AuthorityEventRecord or type(receipt) is not ExecutionReceiptRecord:
            return Denied(ReasonCode.SCHEMA_INVALID)
        stable = cast(ExecutionReceiptRecord, receipt)
        for existing in self.__receipts:
            if existing.receipt_id == stable.receipt_id:
                if existing == stable:
                    return None
                return Denied(ReasonCode.REPLAY_DETECTED)
        object.__setattr__(
            self,
            "_WorkerSubmissionPort__receipts",
            self.__receipts + (stable,),
        )
        return None

    def submit_proposal(self, proposal: object) -> Denied | None:
        if type(proposal) is AuthorityEventRecord or type(proposal) is not PromotionProposalRecord:
            return Denied(ReasonCode.SCHEMA_INVALID)
        stable = cast(PromotionProposalRecord, proposal)
        for existing in self.__proposals:
            if existing.proposal_id == stable.proposal_id:
                if existing == stable:
                    return None
                return Denied(ReasonCode.REPLAY_DETECTED)
        object.__setattr__(
            self,
            "_WorkerSubmissionPort__proposals",
            self.__proposals + (stable,),
        )
        return None


class FakeAdapter:
    __slots__ = ("__manifest",)
    __manifest: AdapterManifest

    def __init__(self, manifest: AdapterManifest) -> None:
        if type(manifest) is not AdapterManifest:
            raise _invalid() from None
        object.__setattr__(self, "_FakeAdapter__manifest", manifest)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_ERROR)

    def check_task(self, task: object) -> Denied | None:
        if type(task) is not TaskEnvelopeRecord:
            return Denied(ReasonCode.SCHEMA_INVALID)
        stable_task = cast(TaskEnvelopeRecord, task)
        try:
            if stable_task.audience.get("adapter_id") != self.__manifest.adapter_id:
                return Denied(ReasonCode.ADAPTER_UNSUPPORTED)
            for feature in stable_task.required_adapter_features:
                if type(feature) is not str or feature not in self.__manifest.features:
                    return Denied(ReasonCode.ADAPTER_UNSUPPORTED)
            return None
        except Exception:
            return Denied(ReasonCode.ADAPTER_UNSUPPORTED)

    def check_receipt(self, receipt: object) -> Denied | None:
        if type(receipt) is not ExecutionReceiptRecord:
            return Denied(ReasonCode.SCHEMA_INVALID)
        stable = cast(ExecutionReceiptRecord, receipt)
        try:
            identity = stable.adapter_identity
            if identity.get("adapter_id") != self.__manifest.adapter_id:
                return Denied(ReasonCode.ADAPTER_UNSUPPORTED)
            if identity.get("version") != self.__manifest.version:
                return Denied(ReasonCode.ADAPTER_UNSUPPORTED)
            if identity.get("binary_digest") != self.__manifest.binary_digest:
                return Denied(ReasonCode.ADAPTER_UNSUPPORTED)
            if identity.get("manifest_digest") != self.__manifest.manifest_digest:
                return Denied(ReasonCode.ADAPTER_UNSUPPORTED)
            return None
        except Exception:
            return Denied(ReasonCode.ADAPTER_UNSUPPORTED)

    def _identity_document(self) -> dict[str, object]:
        return {
            "adapter_id": self.__manifest.adapter_id,
            "version": self.__manifest.version,
            "binary_digest": self.__manifest.binary_digest,
            "manifest_digest": self.__manifest.manifest_digest,
        }

    def _resolve_egress_destination(self, alias: object) -> str | None:
        if type(alias) is not str:
            return None
        for pinned_alias, destination in _PINNED_EGRESS_DESTINATIONS:
            if alias == pinned_alias:
                return destination
        return None


def _scenario_bytes(scenario: object) -> bytes:
    from authority_sim.scenarios import ScriptedScenario

    if type(scenario) is not ScriptedScenario:
        raise _invalid() from None
    stable = cast(ScriptedScenario, scenario)
    return canonical_bytes(
        {
            "name": stable.name,
            "run_id": stable.run_id,
            "task": stable.task.to_document(),
            "capability": stable.capability.to_document(),
            "limits": _limits_document(stable.limits),
            "usage": _usage_document(stable.usage),
            "exit_code": stable.exit_code,
            "signal": stable.signal,
            "filesystem_change_count": stable.filesystem_change_count,
            "cancellation_requested": stable.cancellation_requested,
            "urgent": stable.urgent,
            "artifact_refs": [item.to_document() for item in stable.artifact_refs],
            "partial_artifact_refs": [
                item.to_document() for item in stable.partial_artifact_refs
            ],
            "requested_egress": [
                {"alias": item.alias, "destination": item.destination}
                for item in stable.requested_egress
            ],
            "pinned_egress": [
                {"alias": item.alias, "destination": item.destination}
                for item in stable.pinned_egress
            ],
            "workspace_paths": list(stable.workspace_paths),
        },
    )


class FakeWorker:
    __slots__ = ("__worker_id", "__submission_port", "__outcomes")
    __worker_id: str
    __submission_port: WorkerSubmissionPort
    __outcomes: tuple[tuple[str, bytes, RuntimeOutcome], ...]

    def __init__(self, worker_id: str, submission_port: WorkerSubmissionPort) -> None:
        stable_worker_id = _require_worker_id(worker_id)
        if type(submission_port) is not WorkerSubmissionPort:
            raise _invalid() from None
        object.__setattr__(self, "_FakeWorker__worker_id", stable_worker_id)
        object.__setattr__(self, "_FakeWorker__submission_port", submission_port)
        object.__setattr__(self, "_FakeWorker__outcomes", ())

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(_ERROR)

    def __delattr__(self, name: str) -> None:
        raise AttributeError(_ERROR)

    def _cached(self, run_id: str) -> tuple[bytes, RuntimeOutcome] | None:
        for existing_run_id, scenario_bytes, outcome in self.__outcomes:
            if existing_run_id == run_id:
                return scenario_bytes, outcome
        return None

    def _remember(self, scenario_bytes: bytes, outcome: RuntimeOutcome) -> None:
        object.__setattr__(
            self,
            "_FakeWorker__outcomes",
            self.__outcomes + ((outcome.run_id, scenario_bytes, outcome),),
        )

    def _receipt_record(
        self,
        adapter: FakeAdapter,
        task: TaskEnvelopeRecord,
        capability: CapabilityClaimRecord,
        run_id: str,
        terminal_state: str,
        worker_started_at: datetime,
        worker_finished_at: datetime,
        usage: BudgetUsage,
        filesystem_change_count: int,
        artifact_refs: tuple[FrozenObject, ...],
        budget_exceeded: bool,
        exit_code: int | None,
        signal: int | None,
    ) -> ExecutionReceiptRecord:
        suffix = _run_suffix(run_id)
        observations: list[dict[str, object]] = [
            {
                "observation_id": "obs_01process",
                "trust_class": "governor_observed",
                "category": "process",
                "status": "pass" if terminal_state == "success" else "fail",
                "summary_code": (
                    "PROCESS_EXIT_ZERO"
                    if terminal_state == "success"
                    else "PROCESS_TERMINAL"
                ),
            }
        ]
        if terminal_state == "success":
            observations.append(
                {
                    "observation_id": "obs_01schema",
                    "trust_class": "governor_observed",
                    "category": "test",
                    "status": "pass",
                    "summary_code": "SCHEMA_VALID",
                    "evidence_artifact_id": artifact_refs[0].get("artifact_id"),
                },
            )
        document = {
            "kind": "execution_receipt",
            "schema_version": "0.1.0",
            "operator_id": task.operator_id,
            "receipt_id": "receipt_" + suffix,
            "task_id": task.task_id,
            "capability_id": capability.capability_id,
            "authority_epoch": task.authority_epoch,
            "lease_generation": task.lease_generation,
            "run_id": run_id,
            "node_id": capability.subject.get("node_id"),
            "process_id": capability.subject.get("process_id"),
            "adapter_identity": adapter._identity_document(),
            "workspace_ref": task.workspace_ref,
            "policy_digest": task.policy_digest,
            "started_at": _timestamp(worker_started_at),
            "finished_at": _timestamp(worker_finished_at),
            "terminal_state": terminal_state,
            "process_result": {
                "exit_code": exit_code,
                "signal": signal,
                "wall_ms": usage.wall_ms,
                "budget_exceeded": budget_exceeded,
                "filesystem_change_count": filesystem_change_count,
                "network_request_count": usage.network_requests,
            },
            "observations": observations,
            "usage": [
                {
                    "metric": "fresh_input_tokens",
                    "value": usage.fresh_input_tokens,
                    "authority_state": "observed_exact",
                },
                {
                    "metric": "output_tokens",
                    "value": usage.output_tokens,
                    "authority_state": "observed_exact",
                },
                {
                    "metric": "artifact_bytes",
                    "value": usage.output_bytes,
                    "authority_state": "observed_exact",
                },
            ],
            "nonce": "receipt_nonce_abcdefghijklmnopqrstuvwxyz_01",
            "artifact_refs": [_copy_pin(pin) for pin in artifact_refs],
        }
        record = create_record(document)
        if type(record) is not ExecutionReceiptRecord:
            raise _invalid() from None
        return cast(ExecutionReceiptRecord, record)

    def _proposal_record(
        self,
        task: TaskEnvelopeRecord,
        capability: CapabilityClaimRecord,
        receipt: ExecutionReceiptRecord,
        worker_finished_at: datetime,
        artifact_refs: tuple[FrozenObject, ...],
    ) -> PromotionProposalRecord:
        suffix = _run_suffix(receipt.run_id)
        document = {
            "kind": "promotion_proposal",
            "schema_version": "0.1.0",
            "operator_id": task.operator_id,
            "proposal_id": "proposal_" + suffix,
            "task_id": task.task_id,
            "capability_id": capability.capability_id,
            "authority_epoch": task.authority_epoch,
            "lease_generation": task.lease_generation,
            "expected_authority_head": task.expected_authority_head,
            "receipt_ids": [receipt.receipt_id],
            "artifact_refs": [_copy_pin(pin) for pin in artifact_refs],
            "requested_effect": "accept_artifact",
            "acceptance_evidence": [
                {
                    "check_id": "check_schema",
                    "observation_id": "obs_01schema",
                    "status": "pass",
                    "evidence_artifact_id": artifact_refs[0].get("artifact_id"),
                }
            ],
            "proposed_by": {
                "actor_class": "worker",
                "actor_id": capability.subject.get("process_id"),
            },
            "created_at": _timestamp(worker_finished_at + timedelta(seconds=1)),
            "idempotency_key": "promotion.propose:" + suffix,
            "nonce": "proposal_nonce_abcdefghijklmnopqrstuvwxyz_01",
        }
        record = create_record(document)
        if type(record) is not PromotionProposalRecord:
            raise _invalid() from None
        return cast(PromotionProposalRecord, record)

    def _finalize(
        self,
        *,
        run_id: str,
        run_state: RunState,
        receipt: ExecutionReceiptRecord,
        quarantined_artifact_refs: tuple[FrozenObject, ...],
        proposal: PromotionProposalRecord | None,
        reason: ReasonCode | None,
        scenario_bytes: bytes,
    ) -> RuntimeOutcome:
        receipt_result = self.__submission_port.submit_receipt(receipt)
        if type(receipt_result) is Denied:
            raise _invalid() from None
        if proposal is not None:
            proposal_result = self.__submission_port.submit_proposal(proposal)
            if type(proposal_result) is Denied:
                raise _invalid() from None
        outcome = RuntimeOutcome(
            run_id=run_id,
            run_state_name=run_state.name,
            receipt=ReceiptSurface(
                run_id,
                receipt.terminal_state,
                quarantined_artifact_refs,
                receipt,
            ),
            submission=self.__submission_port.snapshot(),
            replayed=False,
            reason=reason,
        )
        self._remember(scenario_bytes, outcome)
        return outcome

    def run(
        self,
        adapter: object,
        scenario: object,
        *,
        authority_as_of: datetime,
        worker_started_at: datetime,
        worker_finished_at: datetime,
    ) -> RuntimeOutcome:
        from authority_sim.scenarios import ScriptedScenario

        if type(adapter) is not FakeAdapter or type(scenario) is not ScriptedScenario:
            raise _invalid() from None
        stable_adapter = cast(FakeAdapter, adapter)
        stable_scenario = cast(ScriptedScenario, scenario)
        stable_authority_as_of = _safe_utc(authority_as_of)
        stable_started_at = _safe_utc(worker_started_at)
        stable_finished_at = _safe_utc(worker_finished_at)
        scenario_bytes = _scenario_bytes(stable_scenario)
        cached = self._cached(stable_scenario.run_id)
        if cached is not None:
            cached_bytes, cached_outcome = cached
            if cached_bytes != scenario_bytes:
                return RuntimeOutcome(
                    run_id=stable_scenario.run_id,
                    run_state_name=RunState.DENIED.name,
                    receipt=ReceiptSurface(stable_scenario.run_id, "denied", ()),
                    submission=self.__submission_port.snapshot(),
                    replayed=False,
                    reason=ReasonCode.REPLAY_DETECTED,
                )
            replay_state = _advance_run(
                cached_outcome.run_state,
                RunOutcome.BYTE_IDENTICAL_REPLAY,
            )
            return RuntimeOutcome(
                run_id=cached_outcome.run_id,
                run_state_name=replay_state.name,
                receipt=cached_outcome.receipt,
                submission=cached_outcome.submission,
                replayed=True,
                reason=cached_outcome.reason,
            )

        run_state = _advance_run(RunState.NONE, RunOutcome.RUN_CREATED)
        run_state = _advance_run(run_state, RunOutcome.RUN_CLAIMED)

        def deny_before_start(reason: ReasonCode) -> RuntimeOutcome:
            denied_state = _advance_run(run_state, RunOutcome.CHECK_FAILED)
            receipt = self._receipt_record(
                stable_adapter,
                stable_scenario.task,
                stable_scenario.capability,
                stable_scenario.run_id,
                "denied",
                stable_started_at,
                stable_finished_at,
                stable_scenario.usage,
                stable_scenario.filesystem_change_count,
                (),
                reason is ReasonCode.BUDGET_EXCEEDED,
                None,
                None,
            )
            return self._finalize(
                run_id=stable_scenario.run_id,
                run_state=denied_state,
                receipt=receipt,
                quarantined_artifact_refs=(),
                proposal=None,
                reason=reason,
                scenario_bytes=scenario_bytes,
            )

        if stable_adapter.check_task(stable_scenario.task) is not None:
            return deny_before_start(ReasonCode.ADAPTER_UNSUPPORTED)

        task = stable_scenario.task
        capability = stable_scenario.capability
        if (
            capability.operator_id != task.operator_id
            or capability.task_id != task.task_id
            or capability.capability_id != task.capability_id
            or capability.authority_epoch != task.authority_epoch
            or capability.lease_generation != task.lease_generation
            or capability.policy_digest != task.policy_digest
            or capability.workspace_ref != task.workspace_ref
            or capability.audience.to_document() != task.audience.to_document()
            or capability.subject.get("node_id") != task.audience.get("node_id")
        ):
            return deny_before_start(ReasonCode.IDENTITY_MISMATCH)

        if (
            stable_authority_as_of < task.issued_at
            or stable_authority_as_of < capability.valid_from
            or stable_authority_as_of >= task.expires_at
            or stable_authority_as_of >= capability.expires_at
        ):
            return deny_before_start(ReasonCode.CAPABILITY_INVALID)

        try:
            task_input_ids = tuple(
                input_ref.get("artifact_id") for input_ref in task.input_refs
            )
            if any(type(item) is not str for item in task_input_ids):
                return deny_before_start(ReasonCode.SCOPE_EXCEEDED)
            if (
                not set(task.required_actions).issubset(set(capability.allowed_actions))
                or not set(task_input_ids).issubset(
                    set(capability.allowed_input_artifact_ids)
                )
                or task.budget.to_document() != _limits_document(stable_scenario.limits)
                or capability.resource_bounds.to_document()
                != _limits_document(stable_scenario.limits)
            ):
                return deny_before_start(ReasonCode.SCOPE_EXCEEDED)
            task_actions = set(task.required_actions)
            capability_actions = set(capability.allowed_actions)
            effect_actions: set[str] = set()
            if (
                stable_scenario.filesystem_change_count
                or stable_scenario.artifact_refs
                or stable_scenario.partial_artifact_refs
            ):
                effect_actions.add("write_workspace")
            if stable_scenario.usage.processes:
                effect_actions.add("execute_process")
            if stable_scenario.requested_egress:
                effect_actions.add("network_egress")
            if not effect_actions.issubset(task_actions) or not effect_actions.issubset(
                capability_actions
            ):
                return deny_before_start(ReasonCode.SCOPE_EXCEEDED)
        except Exception:
            return deny_before_start(ReasonCode.SCOPE_EXCEEDED)

        resolver = WorkspaceResolver(task.workspace_ref)
        if any(
            not resolver.resolve(path).accepted
            for path in stable_scenario.workspace_paths
        ):
            return deny_before_start(ReasonCode.SCOPE_EXCEEDED)

        requested_count = len(stable_scenario.requested_egress)
        if requested_count and (
            "network_egress" not in capability.allowed_actions
            or "network_egress" not in task.required_actions
            or any(
                request.alias not in capability.egress_aliases
                for request in stable_scenario.requested_egress
            )
        ):
            return deny_before_start(ReasonCode.SCOPE_EXCEEDED)
        if (
            requested_count > stable_scenario.limits.max_network_requests
            or stable_scenario.usage.network_requests
            > stable_scenario.limits.max_network_requests
        ):
            return deny_before_start(ReasonCode.BUDGET_EXCEEDED)
        if requested_count != stable_scenario.usage.network_requests:
            return deny_before_start(ReasonCode.RECEIPT_UNVERIFIED)

        non_wall_within_budget = (
            stable_scenario.usage.tool_calls <= stable_scenario.limits.max_tool_calls
            and stable_scenario.usage.output_bytes <= stable_scenario.limits.max_output_bytes
            and stable_scenario.usage.fresh_input_tokens
            <= stable_scenario.limits.max_fresh_input_tokens
            and stable_scenario.usage.output_tokens
            <= stable_scenario.limits.max_output_tokens
            and stable_scenario.usage.processes <= stable_scenario.limits.max_processes
        )
        if (
            not stable_scenario.cancellation_requested
            and stable_scenario.usage.wall_ms <= stable_scenario.limits.max_wall_ms
            and non_wall_within_budget
            and stable_scenario.exit_code in (None, 0)
            and stable_scenario.signal is None
            and not stable_scenario.artifact_refs
        ):
            return deny_before_start(ReasonCode.ARTIFACT_MISMATCH)

        run_state = _advance_run(run_state, RunOutcome.RUN_STARTED)

        budget_breach: ReasonCode | None = None
        if stable_scenario.usage.wall_ms > stable_scenario.limits.max_wall_ms:
            run_state = _advance_run(run_state, RunOutcome.DEADLINE_REACHED)
            budget_breach = ReasonCode.BUDGET_EXCEEDED
            receipt = self._receipt_record(
                stable_adapter,
                stable_scenario.task,
                stable_scenario.capability,
                stable_scenario.run_id,
                "timed_out",
                stable_started_at,
                stable_finished_at,
                stable_scenario.usage,
                stable_scenario.filesystem_change_count,
                stable_scenario.partial_artifact_refs,
                True,
                None,
                None,
            )
            return self._finalize(
                run_id=stable_scenario.run_id,
                run_state=run_state,
                receipt=receipt,
                quarantined_artifact_refs=stable_scenario.partial_artifact_refs,
                proposal=None,
                reason=budget_breach,
                scenario_bytes=scenario_bytes,
            )

        if (
            stable_scenario.usage.tool_calls > stable_scenario.limits.max_tool_calls
            or stable_scenario.usage.output_bytes > stable_scenario.limits.max_output_bytes
            or stable_scenario.usage.fresh_input_tokens
            > stable_scenario.limits.max_fresh_input_tokens
            or stable_scenario.usage.output_tokens > stable_scenario.limits.max_output_tokens
            or stable_scenario.usage.network_requests
            > stable_scenario.limits.max_network_requests
            or stable_scenario.usage.processes > stable_scenario.limits.max_processes
        ):
            run_state = _advance_run(run_state, RunOutcome.EXIT_NONZERO)
            receipt = self._receipt_record(
                stable_adapter,
                stable_scenario.task,
                stable_scenario.capability,
                stable_scenario.run_id,
                "failed",
                stable_started_at,
                stable_finished_at,
                stable_scenario.usage,
                stable_scenario.filesystem_change_count,
                (),
                True,
                0,
                None,
            )
            return self._finalize(
                run_id=stable_scenario.run_id,
                run_state=run_state,
                receipt=receipt,
                quarantined_artifact_refs=(),
                proposal=None,
                reason=ReasonCode.BUDGET_EXCEEDED,
                scenario_bytes=scenario_bytes,
            )

        for request in stable_scenario.requested_egress:
            if request.alias not in stable_scenario.capability.egress_aliases:
                run_state = _advance_run(run_state, RunOutcome.EXIT_NONZERO)
                receipt = self._receipt_record(
                    stable_adapter,
                    stable_scenario.task,
                    stable_scenario.capability,
                    stable_scenario.run_id,
                    "failed",
                    stable_started_at,
                    stable_finished_at,
                    stable_scenario.usage,
                    stable_scenario.filesystem_change_count,
                    (),
                    False,
                    1,
                    None,
                )
                return self._finalize(
                    run_id=stable_scenario.run_id,
                    run_state=run_state,
                    receipt=receipt,
                    quarantined_artifact_refs=(),
                    proposal=None,
                    reason=ReasonCode.SCOPE_EXCEEDED,
                    scenario_bytes=scenario_bytes,
                )
            exact_match = (
                stable_adapter._resolve_egress_destination(request.alias)
                == request.destination
            )
            if not exact_match:
                run_state = _advance_run(run_state, RunOutcome.EXIT_NONZERO)
                receipt = self._receipt_record(
                    stable_adapter,
                    stable_scenario.task,
                    stable_scenario.capability,
                    stable_scenario.run_id,
                    "failed",
                    stable_started_at,
                    stable_finished_at,
                    stable_scenario.usage,
                    stable_scenario.filesystem_change_count,
                    (),
                    False,
                    1,
                    None,
                )
                return self._finalize(
                    run_id=stable_scenario.run_id,
                    run_state=run_state,
                    receipt=receipt,
                    quarantined_artifact_refs=(),
                    proposal=None,
                    reason=ReasonCode.SCOPE_EXCEEDED,
                    scenario_bytes=scenario_bytes,
                )

        if stable_scenario.signal is not None or stable_scenario.exit_code not in (None, 0):
            run_state = _advance_run(run_state, RunOutcome.EXIT_NONZERO)
            receipt = self._receipt_record(
                stable_adapter,
                stable_scenario.task,
                stable_scenario.capability,
                stable_scenario.run_id,
                "failed",
                stable_started_at,
                stable_finished_at,
                stable_scenario.usage,
                stable_scenario.filesystem_change_count,
                (),
                False,
                stable_scenario.exit_code,
                stable_scenario.signal,
            )
            return self._finalize(
                run_id=stable_scenario.run_id,
                run_state=run_state,
                receipt=receipt,
                quarantined_artifact_refs=(),
                proposal=None,
                reason=None,
                scenario_bytes=scenario_bytes,
            )

        if stable_scenario.cancellation_requested:
            run_state = _advance_run(run_state, RunOutcome.CANCELLATION_ACCEPTED)
            receipt = self._receipt_record(
                stable_adapter,
                stable_scenario.task,
                stable_scenario.capability,
                stable_scenario.run_id,
                "cancelled",
                stable_started_at,
                stable_finished_at,
                stable_scenario.usage,
                stable_scenario.filesystem_change_count,
                stable_scenario.partial_artifact_refs,
                False,
                None,
                None,
            )
            return self._finalize(
                run_id=stable_scenario.run_id,
                run_state=run_state,
                receipt=receipt,
                quarantined_artifact_refs=stable_scenario.partial_artifact_refs,
                proposal=None,
                reason=None,
                scenario_bytes=scenario_bytes,
            )

        run_state = _advance_run(run_state, RunOutcome.EXIT_ZERO)
        receipt = self._receipt_record(
            stable_adapter,
            stable_scenario.task,
            stable_scenario.capability,
            stable_scenario.run_id,
            "success",
            stable_started_at,
            stable_finished_at,
            stable_scenario.usage,
            stable_scenario.filesystem_change_count,
            stable_scenario.artifact_refs,
            False,
            0,
            None,
        )
        proposal = self._proposal_record(
            stable_scenario.task,
            stable_scenario.capability,
            receipt,
            stable_finished_at,
            stable_scenario.artifact_refs,
        )
        return self._finalize(
            run_id=stable_scenario.run_id,
            run_state=run_state,
            receipt=receipt,
            quarantined_artifact_refs=(),
            proposal=proposal,
            reason=None,
            scenario_bytes=scenario_bytes,
        )
