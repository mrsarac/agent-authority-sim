from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from authority_sim.fake_runtime import AdapterManifest, BudgetLimits, BudgetUsage
from authority_sim.records import (
    AuthorityEventRecord,
    CapabilityClaimRecord,
    FrozenObject,
    TaskEnvelopeRecord,
    create_record,
)


_DIGEST_A = "sha256:" + ("a" * 64)
_DIGEST_B = "sha256:" + ("b" * 64)
_DIGEST_C = "sha256:" + ("c" * 64)
_DIGEST_D = "sha256:" + ("d" * 64)
_MANIFEST_DIGEST = "sha256:549afc8f729e2c219d4b9eaa744f87796b511d3ad325ff23132d175dd1c39f5f"


def _utc(hour: int, minute: int, second: int) -> datetime:
    return datetime(2026, 8, 15, hour, minute, second, tzinfo=timezone.utc)


def _artifact_pin() -> FrozenObject:
    return FrozenObject(
        (
            ("artifact_id", "artifact_01summary"),
            ("content_digest", _DIGEST_D),
            ("manifest_digest", _MANIFEST_DIGEST),
        ),
    )


def _budget_dict(limits: BudgetLimits) -> dict[str, int]:
    return {
        "max_wall_ms": limits.max_wall_ms,
        "max_tool_calls": limits.max_tool_calls,
        "max_output_bytes": limits.max_output_bytes,
        "max_fresh_input_tokens": limits.max_fresh_input_tokens,
        "max_output_tokens": limits.max_output_tokens,
        "max_network_requests": limits.max_network_requests,
        "max_processes": limits.max_processes,
    }


def _task_record(
    *,
    task_id: str,
    capability_id: str,
    required_features: tuple[str, ...],
    required_actions: tuple[str, ...],
    limits: BudgetLimits,
    expires_at: str,
) -> TaskEnvelopeRecord:
    record = create_record(
        {
            "kind": "task_envelope",
            "schema_version": "0.1.0",
            "operator_id": "operator:demo",
            "task_id": task_id,
            "decision_ref": "operator-decision:D-0001/S1/A",
            "authority_epoch": 7,
            "lease_generation": 2,
            "issued_at": "2026-08-15T14:00:00Z",
            "expires_at": expires_at,
            "policy_digest": _DIGEST_C,
            "expected_authority_head": _DIGEST_A,
            "capability_id": capability_id,
            "audience": {
                "node_id": "node:synthetic-a",
                "adapter_id": "adapter:fake-worker",
            },
            "goal": "Return one deterministic summary artifact.",
            "workspace_ref": "workspace:synthetic",
            "input_refs": [
                {
                    "artifact_id": "artifact_01fixture",
                    "content_digest": _DIGEST_B,
                    "byte_length": 128,
                    "media_type": "application/json",
                    "classification": "internal",
                }
            ],
            "context_refs": [],
            "required_actions": list(required_actions),
            "required_adapter_features": list(required_features),
            "acceptance_checks": [
                {
                    "check_id": "check_schema",
                    "check_type": "schema",
                    "minimum_trust_class": "governor_observed",
                    "required": True,
                    "target_ref": "artifact:summary",
                }
            ],
            "budget": _budget_dict(limits),
            "idempotency_key": "task.issue:" + task_id[-11:],
            "nonce": "task_nonce_abcdefghijklmnopqrstuvwxyz_01",
        },
    )
    if type(record) is not TaskEnvelopeRecord:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    return record


def _capability_record(
    *,
    capability_id: str,
    task_id: str,
    limits: BudgetLimits,
    egress_aliases: tuple[str, ...],
    allowed_actions: tuple[str, ...],
    expires_at: str,
) -> CapabilityClaimRecord:
    record = create_record(
        {
            "kind": "capability_claim",
            "schema_version": "0.1.0",
            "operator_id": "operator:demo",
            "capability_id": capability_id,
            "parent_capability_id": None,
            "task_id": task_id,
            "authority_epoch": 7,
            "lease_generation": 2,
            "issuer_id": "authority:simulator",
            "subject": {
                "node_id": "node:synthetic-a",
                "process_id": "process:fake-001",
            },
            "audience": {
                "node_id": "node:synthetic-a",
                "adapter_id": "adapter:fake-worker",
            },
            "policy_digest": _DIGEST_C,
            "workspace_ref": "workspace:synthetic",
            "allowed_actions": list(allowed_actions),
            "allowed_input_artifact_ids": [
                "artifact_01fixture",
            ],
            "egress_aliases": list(egress_aliases),
            "broker_handle_refs": [],
            "resource_bounds": _budget_dict(limits),
            "valid_from": "2026-08-15T14:00:00Z",
            "expires_at": expires_at,
            "revocation_id": "revoke_01synthetic",
            "delegation_depth": 0,
            "projection": "governor_only",
            "encoding_profile": "simulation_unsigned_v1",
            "nonce": "capability_nonce_abcdefghijklmnopqrstuv_01",
        },
    )
    if type(record) is not CapabilityClaimRecord:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    return record


@dataclass(frozen=True, slots=True)
class ScriptedEgress:
    alias: str
    destination: str

    def __post_init__(self) -> None:
        if (
            type(self.alias) is not str
            or type(self.destination) is not str
            or not self.alias
            or not self.destination
            or self.alias.strip() != self.alias
            or self.destination.strip() != self.destination
        ):
            raise ValueError("FAKE_RUNTIME_INVALID") from None


@dataclass(frozen=True, slots=True)
class ScriptedScenario:
    name: str
    run_id: str
    task: TaskEnvelopeRecord
    capability: CapabilityClaimRecord
    limits: BudgetLimits
    usage: BudgetUsage
    exit_code: int | None
    signal: int | None
    filesystem_change_count: int
    cancellation_requested: bool
    urgent: bool
    artifact_refs: tuple[FrozenObject, ...]
    partial_artifact_refs: tuple[FrozenObject, ...]
    requested_egress: tuple[ScriptedEgress, ...]
    pinned_egress: tuple[ScriptedEgress, ...]
    workspace_paths: tuple[str, ...] = ("output/summary.json",)

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name or self.name.strip() != self.name:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.run_id) is not str or not self.run_id or self.run_id.strip() != self.run_id:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.task) is not TaskEnvelopeRecord or type(self.capability) is not CapabilityClaimRecord:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.limits) is not BudgetLimits or type(self.usage) is not BudgetUsage:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if self.signal is not None and type(self.signal) is not int:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.filesystem_change_count) is not int or self.filesystem_change_count < 0:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.cancellation_requested) is not bool or type(self.urgent) is not bool:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.artifact_refs) is not tuple or type(self.partial_artifact_refs) is not tuple:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.requested_egress) is not tuple or type(self.pinned_egress) is not tuple:
            raise ValueError("FAKE_RUNTIME_INVALID") from None
        if type(self.workspace_paths) is not tuple or any(
            type(path) is not str for path in self.workspace_paths
        ):
            raise ValueError("FAKE_RUNTIME_INVALID") from None


def _scenario(
    *,
    name: str,
    run_id: str,
    task_id: str,
    capability_id: str,
    limits: BudgetLimits,
    usage: BudgetUsage,
    required_features: tuple[str, ...] = ("structured-output", "cancellation"),
    egress_aliases: tuple[str, ...] = (),
    exit_code: int | None = 0,
    signal: int | None = None,
    filesystem_change_count: int = 1,
    cancellation_requested: bool = False,
    urgent: bool = False,
    artifact_refs: tuple[FrozenObject, ...] = (),
    partial_artifact_refs: tuple[FrozenObject, ...] = (),
    requested_egress: tuple[ScriptedEgress, ...] = (),
    pinned_egress: tuple[ScriptedEgress, ...] = (),
) -> ScriptedScenario:
    expires_at = "2026-08-15T14:10:00Z"
    actions = ["read_artifact"]
    if filesystem_change_count or artifact_refs or partial_artifact_refs:
        actions.append("write_workspace")
    if usage.processes:
        actions.append("execute_process")
    if requested_egress:
        actions.append("network_egress")
    stable_actions = tuple(actions)
    return ScriptedScenario(
        name=name,
        run_id=run_id,
        task=_task_record(
            task_id=task_id,
            capability_id=capability_id,
            required_features=required_features,
            required_actions=stable_actions,
            limits=limits,
            expires_at=expires_at,
        ),
        capability=_capability_record(
            capability_id=capability_id,
            task_id=task_id,
            limits=limits,
            egress_aliases=egress_aliases,
            allowed_actions=stable_actions,
            expires_at=expires_at,
        ),
        limits=limits,
        usage=usage,
        exit_code=exit_code,
        signal=signal,
        filesystem_change_count=filesystem_change_count,
        cancellation_requested=cancellation_requested,
        urgent=urgent,
        artifact_refs=artifact_refs,
        partial_artifact_refs=partial_artifact_refs,
        requested_egress=requested_egress,
        pinned_egress=pinned_egress,
    )


def default_adapter_manifest() -> AdapterManifest:
    return AdapterManifest(
        adapter_id="adapter:fake-worker",
        version="0.1.0",
        binary_digest=_DIGEST_A,
        manifest_digest=_DIGEST_B,
        features=(
            "structured-output",
            "cancellation",
            "network-egress",
        ),
    )


def task_with_required_features(
    features: tuple[str, ...],
) -> TaskEnvelopeRecord:
    if type(features) is not tuple:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    return _task_record(
        task_id="task_01synthetic",
        capability_id="cap_01synthetic",
        required_features=features,
        required_actions=("read_artifact",),
        limits=BudgetLimits(60000, 20, 65536, 8000, 2000, 0, 2),
        expires_at="2026-08-15T14:10:00Z",
    )


def success_scenario() -> ScriptedScenario:
    return _scenario(
        name="success",
        run_id="run_01synthetic",
        task_id="task_01synthetic",
        capability_id="cap_01synthetic",
        limits=BudgetLimits(60000, 20, 65536, 8000, 2000, 0, 2),
        usage=BudgetUsage(11000, 1, 512, 128, 64, 0, 1),
        artifact_refs=(_artifact_pin(),),
    )


def cancelled_scenario() -> ScriptedScenario:
    return _scenario(
        name="cancelled",
        run_id="run_02synthetic",
        task_id="task_02synthetic",
        capability_id="cap_02synthetic",
        limits=BudgetLimits(60000, 20, 65536, 8000, 2000, 0, 2),
        usage=BudgetUsage(5000, 1, 128, 64, 32, 0, 1),
        exit_code=None,
        cancellation_requested=True,
        partial_artifact_refs=(_artifact_pin(),),
    )


def timed_out_scenario() -> ScriptedScenario:
    return _scenario(
        name="timed-out",
        run_id="run_03synthetic",
        task_id="task_03synthetic",
        capability_id="cap_03synthetic",
        limits=BudgetLimits(60000, 20, 65536, 8000, 2000, 0, 2),
        usage=BudgetUsage(60001, 1, 256, 64, 32, 0, 1),
        exit_code=None,
        partial_artifact_refs=(_artifact_pin(),),
    )


def budget_breach_scenario(metric: str, urgent: bool) -> ScriptedScenario:
    if type(metric) is not str:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    limits = BudgetLimits(60000, 20, 65536, 8000, 2000, 0, 2)
    values = {
        "max_wall_ms": (60001, 1, 512, 128, 64, 0, 1),
        "max_tool_calls": (11000, 21, 512, 128, 64, 0, 1),
        "max_output_bytes": (11000, 1, 65537, 128, 64, 0, 1),
        "max_fresh_input_tokens": (11000, 1, 512, 8001, 64, 0, 1),
        "max_output_tokens": (11000, 1, 512, 128, 2001, 0, 1),
        "max_network_requests": (11000, 1, 512, 128, 64, 1, 1),
        "max_processes": (11000, 1, 512, 128, 64, 0, 3),
    }
    if metric not in values:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    wall_ms, tool_calls, output_bytes, fresh_input_tokens, output_tokens, network_requests, processes = values[metric]
    return _scenario(
        name="budget-" + metric,
        run_id="run_1" + metric[4:11].replace("_", "") + "aaaa",
        task_id="task_1" + metric[4:11].replace("_", "") + "aaaa",
        capability_id="cap_1" + metric[4:11].replace("_", "") + "aaaa",
        limits=limits,
        usage=BudgetUsage(
            wall_ms,
            tool_calls,
            output_bytes,
            fresh_input_tokens,
            output_tokens,
            network_requests,
            processes,
        ),
        urgent=urgent,
    )


def egress_scenario(
    *,
    capability_aliases: tuple[str, ...],
    pinned_destination: str | None,
    requested_destination: str,
    network_limit: int,
    network_usage: int,
) -> ScriptedScenario:
    if type(capability_aliases) is not tuple:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    pinned: tuple[ScriptedEgress, ...] = ()
    if pinned_destination is not None:
        pinned = (ScriptedEgress("egress:registry", pinned_destination),)
    return _scenario(
        name="egress",
        run_id="run_20egressaa",
        task_id="task_20egressaa",
        capability_id="cap_20egressaa",
        limits=BudgetLimits(60000, 20, 65536, 8000, 2000, network_limit, 2),
        usage=BudgetUsage(11000, 1, 512, 128, 64, network_usage, 1),
        required_features=("structured-output", "network-egress"),
        egress_aliases=capability_aliases,
        artifact_refs=(_artifact_pin(),),
        requested_egress=(ScriptedEgress("egress:registry", requested_destination),),
        pinned_egress=pinned,
    )


def authority_event_record() -> AuthorityEventRecord:
    record = create_record(
        {
            "kind": "authority_event",
            "schema_version": "0.1.0",
            "operator_id": "operator:demo",
            "event_id": "event_01synthetic",
            "sequence": 42,
            "authority_epoch": 7,
            "lease_generation": 2,
            "previous_event_digest": _DIGEST_A,
            "event_digest": "sha256:4534e9775e5232453eed8bd518e0e22a5f2c0bd369bdb933b2d15cad4d01de66",
            "event_type": "promotion_recorded",
            "actor": {
                "actor_class": "authority_core",
                "actor_id": "authority:simulator",
            },
            "object_kind": "promotion_decision",
            "object_ref": "promotion_01synthetic",
            "object_digest": "sha256:3756ee913d8c950e4d32b68b55dbd1d3725a87008bb0e567601411faa5d21e71",
            "transition": {
                "state_machine": "promotion",
                "expected_state": "RECEIPT_VERIFIED",
                "resulting_state": "PROMOTED",
            },
            "policy_digest": _DIGEST_C,
            "observed_at": "2026-08-15T14:00:14Z",
            "idempotency_key": "authority.event:01synthetic",
        },
    )
    if type(record) is not AuthorityEventRecord:
        raise ValueError("FAKE_RUNTIME_INVALID") from None
    return record


__all__ = (
    "AdapterManifest",
    "ScriptedScenario",
    "ScriptedEgress",
    "authority_event_record",
    "budget_breach_scenario",
    "cancelled_scenario",
    "default_adapter_manifest",
    "egress_scenario",
    "success_scenario",
    "task_with_required_features",
    "timed_out_scenario",
)
