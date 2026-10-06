from __future__ import annotations

from typing import TypeVar, cast

from authority_sim.artifacts import (
    ArtifactStore,
    ArtifactVerifier,
    VerificationDecision,
)
from authority_sim.errors import ReasonCode
from authority_sim.records import (
    ArtifactManifestRecord,
    CapabilityClaimRecord,
    ExecutionReceiptRecord,
    FrozenObject,
    TaskEnvelopeRecord,
)


_RecordT = TypeVar(
    "_RecordT",
    ArtifactManifestRecord,
    CapabilityClaimRecord,
    ExecutionReceiptRecord,
    TaskEnvelopeRecord,
)


def _accept() -> VerificationDecision:
    return VerificationDecision(
        accepted=True,
        denied=None,
        quarantined=False,
        recovery_required=False,
    )


def _exact_record(value: object, expected_type: type[_RecordT]) -> _RecordT:
    if type(value) is not expected_type:
        raise TypeError("RECEIPT_INVALID") from None
    return value


def _exact_tuple(value: object) -> tuple[FrozenObject, ...]:
    if type(value) is not tuple:
        raise TypeError("RECEIPT_INVALID") from None
    return cast(tuple[FrozenObject, ...], value)


def _process_value(result: FrozenObject, name: str) -> object:
    try:
        return result.get(name)
    except Exception:
        raise TypeError("RECEIPT_INVALID") from None


def _reject(code: ReasonCode) -> VerificationDecision:
    from authority_sim.errors import Denied

    return VerificationDecision(
        accepted=False,
        denied=Denied(code),
        quarantined=False,
        recovery_required=False,
    )


class ReceiptVerifier:
    _artifact_verifier: ArtifactVerifier
    __slots__ = ("_artifact_verifier",)

    def __init__(self, store: ArtifactStore) -> None:
        if type(store) is not ArtifactStore:
            raise TypeError("RECEIPT_INVALID") from None
        object.__setattr__(self, "_artifact_verifier", ArtifactVerifier(store))

    def verify_trust(self, *, required: object, observed: object) -> VerificationDecision:
        from authority_sim.artifacts import _trust_satisfies

        if _trust_satisfies(required, observed):
            return _accept()
        return _reject(ReasonCode.ACCEPTANCE_FAILED)

    def verify(
        self,
        *,
        receipt: ExecutionReceiptRecord,
        capability: CapabilityClaimRecord,
        task: TaskEnvelopeRecord,
        manifest: ArtifactManifestRecord,
        observations: tuple[FrozenObject, ...] | None = None,
    ) -> VerificationDecision:
        try:
            stable_receipt = _exact_record(receipt, ExecutionReceiptRecord)
            stable_capability = _exact_record(capability, CapabilityClaimRecord)
            stable_task = _exact_record(task, TaskEnvelopeRecord)
            stable_manifest = _exact_record(manifest, ArtifactManifestRecord)
            stable_observations = (
                stable_receipt.observations
                if observations is None
                else _exact_tuple(observations)
            )
        except Exception:
            return _reject(ReasonCode.RECEIPT_UNVERIFIED)

        binding = self._verify_binding(
            receipt=stable_receipt,
            capability=stable_capability,
            task=stable_task,
            manifest=stable_manifest,
        )
        if not binding.accepted:
            return binding

        terminal = self._verify_terminal_state(
            terminal_state=stable_receipt.terminal_state,
            process_result=stable_receipt.process_result,
            observations=stable_observations,
        )
        if not terminal.accepted:
            return terminal

        pin = None
        for artifact_ref in stable_receipt.artifact_refs:
            if type(artifact_ref) is not FrozenObject:
                return _reject(ReasonCode.ARTIFACT_MISMATCH)
            artifact_id = None
            try:
                artifact_id = artifact_ref.get("artifact_id")
            except Exception:
                return _reject(ReasonCode.ARTIFACT_MISMATCH)
            if artifact_id == stable_manifest.artifact_id:
                pin = artifact_ref
                break
        if pin is None:
            return _reject(ReasonCode.ARTIFACT_MISMATCH)

        return self._artifact_verifier.verify(
            manifest=stable_manifest,
            pin=pin,
            operator_id=stable_receipt.operator_id,
            task_id=stable_receipt.task_id,
            run_id=stable_receipt.run_id,
            node_id=stable_receipt.node_id,
            process_id=stable_receipt.process_id,
            acceptance_checks=stable_task.acceptance_checks,
            observations=stable_observations,
        )

    def _verify_binding(
        self,
        *,
        receipt: ExecutionReceiptRecord,
        capability: CapabilityClaimRecord,
        task: TaskEnvelopeRecord,
        manifest: ArtifactManifestRecord,
    ) -> VerificationDecision:
        subject_node = capability.subject.get("node_id")
        subject_process = capability.subject.get("process_id")
        audience_node = capability.audience.get("node_id")
        audience_adapter = capability.audience.get("adapter_id")
        task_node = task.audience.get("node_id")
        task_adapter = task.audience.get("adapter_id")
        receipt_adapter = receipt.adapter_identity.get("adapter_id")
        if (
            receipt.operator_id != capability.operator_id
            or receipt.operator_id != task.operator_id
            or receipt.operator_id != manifest.operator_id
            or receipt.task_id != capability.task_id
            or receipt.task_id != task.task_id
            or receipt.task_id != manifest.task_id
            or receipt.capability_id != capability.capability_id
            or receipt.capability_id != task.capability_id
            or receipt.authority_epoch != capability.authority_epoch
            or receipt.authority_epoch != task.authority_epoch
            or receipt.lease_generation != capability.lease_generation
            or receipt.lease_generation != task.lease_generation
            or receipt.run_id != manifest.run_id
            or receipt.node_id != subject_node
            or receipt.node_id != audience_node
            or receipt.node_id != task_node
            or receipt.node_id != manifest.producer.node_id
            or receipt.process_id != subject_process
            or receipt.process_id != manifest.producer.process_id
            or receipt.workspace_ref != capability.workspace_ref
            or receipt.workspace_ref != task.workspace_ref
            or receipt.policy_digest != capability.policy_digest
            or receipt.policy_digest != task.policy_digest
            or receipt.adapter_identity.get("adapter_id") != manifest.producer.adapter_id
            or receipt_adapter != audience_adapter
            or receipt_adapter != task_adapter
        ):
            return _reject(ReasonCode.IDENTITY_MISMATCH)
        return _accept()

    def _verify_terminal_state(
        self,
        *,
        terminal_state: str,
        process_result: FrozenObject,
        observations: tuple[FrozenObject, ...],
    ) -> VerificationDecision:
        try:
            exit_code = _process_value(process_result, "exit_code")
            signal = _process_value(process_result, "signal")
            budget_exceeded = _process_value(process_result, "budget_exceeded")
        except Exception:
            return _reject(ReasonCode.RECEIPT_UNVERIFIED)

        failed_observation = False
        for observation in observations:
            if type(observation) is not FrozenObject:
                return _reject(ReasonCode.RECEIPT_UNVERIFIED)
            if observation.get("status") == "fail":
                failed_observation = True
                break

        if terminal_state == "success":
            if budget_exceeded is True:
                return _reject(ReasonCode.BUDGET_EXCEEDED)
            if exit_code != 0 or signal is not None or budget_exceeded is not False or failed_observation:
                return _reject(ReasonCode.RECEIPT_UNVERIFIED)
            return _accept()

        if terminal_state == "failed":
            if (
                exit_code != 0
                or signal is not None
                or budget_exceeded is True
                or failed_observation
            ):
                return _accept()
            return _reject(ReasonCode.RECEIPT_UNVERIFIED)

        return _reject(ReasonCode.RECEIPT_UNVERIFIED)


__all__ = ("ReceiptVerifier",)
