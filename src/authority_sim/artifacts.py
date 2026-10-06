from __future__ import annotations

from dataclasses import dataclass

from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.errors import Denied, ReasonCode
from authority_sim.records import ArtifactManifestRecord, FrozenObject, TrustClass
from authority_sim.stores import ImmutableStore, StoreMissing


_TRUST_LEVELS = {
    TrustClass.GOVERNOR_OBSERVED: 0,
    TrustClass.ADAPTER_PARSED: 1,
    TrustClass.TOOL_SELF_REPORTED: 2,
    TrustClass.MODEL_ASSERTED: 3,
}


def _exact_str(value: object) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise TypeError("ARTIFACT_INVALID") from None
    return value


def _exact_bool(value: object) -> bool:
    if type(value) is not bool:
        raise TypeError("ARTIFACT_INVALID") from None
    return value


def _capture_bytes(data: object) -> bytes:
    if type(data) is bytes:
        return data
    if type(data) is bytearray:
        return bytes(data)
    raise TypeError("ARTIFACT_INVALID") from None


def _tuple_with_text(
    values: tuple[str, ...],
    value: str,
) -> tuple[str, ...]:
    if value in values:
        return values
    return tuple(sorted(values + (value,)))


def _require_manifest(manifest: object) -> ArtifactManifestRecord:
    if type(manifest) is not ArtifactManifestRecord:
        raise TypeError("ARTIFACT_INVALID") from None
    return manifest


def _manifest_digest(manifest: ArtifactManifestRecord) -> str:
    return sha256_digest(canonical_bytes(manifest.to_document()))


def _pin_value(pin: FrozenObject, name: str) -> str | None:
    for key, value in pin.entries:
        if key == name and type(value) is str:
            return value
    return None


def _pin_complete(pin: object) -> bool:
    if type(pin) is not FrozenObject:
        return False
    keys = tuple(key for key, _value in pin.entries)
    return keys == ("artifact_id", "content_digest", "manifest_digest")


def _trust_satisfies(required: object, observed: object) -> bool:
    if type(required) is not TrustClass or type(observed) is not TrustClass:
        return False
    if observed is TrustClass.MODEL_ASSERTED:
        return False
    return _TRUST_LEVELS[observed] <= _TRUST_LEVELS[required]


def _accepted() -> VerificationDecision:
    return VerificationDecision(
        accepted=True,
        denied=None,
        quarantined=False,
        recovery_required=False,
    )


def _denied(
    code: ReasonCode,
    *,
    quarantined: bool = False,
    recovery_required: bool = False,
) -> VerificationDecision:
    return VerificationDecision(
        accepted=False,
        denied=Denied(code),
        quarantined=quarantined,
        recovery_required=recovery_required,
    )


@dataclass(frozen=True, slots=True, repr=False)
class VerificationDecision:
    accepted: bool
    denied: Denied | None
    quarantined: bool
    recovery_required: bool

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise TypeError("ARTIFACT_INVALID") from None
        if self.denied is not None and type(self.denied) is not Denied:
            raise TypeError("ARTIFACT_INVALID") from None
        if type(self.quarantined) is not bool:
            raise TypeError("ARTIFACT_INVALID") from None
        if type(self.recovery_required) is not bool:
            raise TypeError("ARTIFACT_INVALID") from None
        if self.accepted:
            if (
                self.denied is not None
                or self.quarantined
                or self.recovery_required
            ):
                raise TypeError("ARTIFACT_INVALID") from None
        else:
            if self.denied is None:
                raise TypeError("ARTIFACT_INVALID") from None
        if self.recovery_required and not self.quarantined:
            raise TypeError("ARTIFACT_INVALID") from None

    def __repr__(self) -> str:
        return "VerificationDecision(...)"


class ArtifactStore:
    _accepted_ids: tuple[str, ...]
    _accepted_content: ImmutableStore
    _accepted_manifests: ImmutableStore
    _untrusted_content: ImmutableStore
    _untrusted_manifests: ImmutableStore
    _accepted_contradictions: tuple[str, ...]
    _untrusted_conflicts: tuple[str, ...]

    __slots__ = (
        "_accepted_ids",
        "_accepted_content",
        "_accepted_manifests",
        "_untrusted_content",
        "_untrusted_manifests",
        "_accepted_contradictions",
        "_untrusted_conflicts",
    )

    def __init__(self) -> None:
        object.__setattr__(self, "_accepted_ids", ())
        object.__setattr__(self, "_accepted_content", ImmutableStore())
        object.__setattr__(self, "_accepted_manifests", ImmutableStore())
        object.__setattr__(self, "_untrusted_content", ImmutableStore())
        object.__setattr__(self, "_untrusted_manifests", ImmutableStore())
        object.__setattr__(self, "_accepted_contradictions", ())
        object.__setattr__(self, "_untrusted_conflicts", ())

    def _mark_conflict(self, artifact_id: str, *, accepted: bool) -> None:
        if accepted:
            object.__setattr__(
                self,
                "_accepted_contradictions",
                _tuple_with_text(self._accepted_contradictions, artifact_id),
            )
            return
        object.__setattr__(
            self,
            "_untrusted_conflicts",
            _tuple_with_text(self._untrusted_conflicts, artifact_id),
        )

    def capture(
        self,
        manifest: ArtifactManifestRecord,
        content_bytes: bytes | bytearray,
        *,
        accepted: bool,
    ) -> None:
        stable_manifest = _require_manifest(manifest)
        stable_content = _capture_bytes(content_bytes)
        stable_accepted = _exact_bool(accepted)
        artifact_id = stable_manifest.artifact_id
        manifest_bytes = canonical_bytes(stable_manifest.to_document())
        if stable_accepted:
            try:
                self._accepted_content.store_canonical(artifact_id, stable_content)
                self._accepted_manifests.store_canonical(artifact_id, manifest_bytes)
                object.__setattr__(
                    self,
                    "_accepted_ids",
                    _tuple_with_text(self._accepted_ids, artifact_id),
                )
            except ValueError:
                self._mark_conflict(artifact_id, accepted=True)
            return
        try:
            self._untrusted_content.store(artifact_id, stable_content)
            self._untrusted_manifests.store(artifact_id, manifest_bytes)
        except ValueError:
            self._mark_conflict(artifact_id, accepted=False)

    def content_bytes(self, artifact_id: str) -> bytes:
        stable_id = _exact_str(artifact_id)
        try:
            return self._accepted_content.get(stable_id)
        except StoreMissing:
            return self._untrusted_content.get(stable_id)

    def manifest_bytes(self, artifact_id: str) -> bytes:
        stable_id = _exact_str(artifact_id)
        try:
            return self._accepted_manifests.get(stable_id)
        except StoreMissing:
            return self._untrusted_manifests.get(stable_id)

    def has_untrusted_conflict(self, artifact_id: str) -> bool:
        return _exact_str(artifact_id) in self._untrusted_conflicts

    def has_accepted_contradiction(self, artifact_id: str) -> bool:
        return _exact_str(artifact_id) in self._accepted_contradictions

    def is_accepted(self, artifact_id: str) -> bool:
        return _exact_str(artifact_id) in self._accepted_ids


class ArtifactVerifier:
    _store: ArtifactStore
    __slots__ = ("_store",)

    def __init__(self, store: ArtifactStore) -> None:
        if type(store) is not ArtifactStore:
            raise TypeError("ARTIFACT_INVALID") from None
        object.__setattr__(self, "_store", store)

    def verify(
        self,
        *,
        manifest: ArtifactManifestRecord,
        pin: FrozenObject,
        operator_id: str,
        task_id: str,
        run_id: str,
        node_id: str,
        process_id: str,
        acceptance_checks: tuple[FrozenObject, ...],
        observations: tuple[FrozenObject, ...],
        submitted_bytes: bytes | bytearray | None = None,
        canonical: bool = False,
    ) -> VerificationDecision:
        try:
            stable_manifest = _require_manifest(manifest)
            stable_pin = pin if type(pin) is FrozenObject else None
            stable_operator = _exact_str(operator_id)
            stable_task = _exact_str(task_id)
            stable_run = _exact_str(run_id)
            stable_node = _exact_str(node_id)
            stable_process = _exact_str(process_id)
            if type(acceptance_checks) is not tuple or any(
                type(check) is not FrozenObject for check in acceptance_checks
            ):
                raise TypeError("ARTIFACT_INVALID") from None
            if type(observations) is not tuple or any(
                type(observation) is not FrozenObject for observation in observations
            ):
                raise TypeError("ARTIFACT_INVALID") from None
            stable_checks = acceptance_checks
            stable_observations = observations
            stable_submitted = (
                None if submitted_bytes is None else _capture_bytes(submitted_bytes)
            )
            stable_canonical = _exact_bool(canonical)
        except Exception:
            return _denied(ReasonCode.SCHEMA_INVALID)

        if stable_pin is None:
            return _denied(ReasonCode.ARTIFACT_MISMATCH)
        artifact_id = stable_manifest.artifact_id
        if self._store.has_accepted_contradiction(artifact_id):
            return _denied(
                ReasonCode.RECOVERY_REQUIRED,
                quarantined=True,
                recovery_required=True,
            )
        if self._store.has_untrusted_conflict(artifact_id):
            return _denied(
                ReasonCode.REPLAY_DETECTED,
                quarantined=True,
                recovery_required=False,
            )

        if (
            stable_manifest.operator_id != stable_operator
            or stable_manifest.task_id != stable_task
            or stable_manifest.run_id != stable_run
            or stable_manifest.producer.node_id != stable_node
            or stable_manifest.producer.process_id != stable_process
        ):
            return _denied(ReasonCode.IDENTITY_MISMATCH)

        if not _pin_complete(stable_pin):
            return _denied(ReasonCode.ARTIFACT_MISMATCH)

        try:
            captured_content = self._store.content_bytes(artifact_id)
            captured_manifest = self._store.manifest_bytes(artifact_id)
        except Exception:
            return _denied(ReasonCode.ARTIFACT_MISMATCH)

        if stable_submitted is not None and stable_submitted != captured_content:
            if stable_canonical:
                self._store._mark_conflict(artifact_id, accepted=True)
                return _denied(
                    ReasonCode.RECOVERY_REQUIRED,
                    quarantined=True,
                    recovery_required=True,
                )
            return _denied(ReasonCode.ARTIFACT_MISMATCH)

        if stable_manifest.byte_length != len(captured_content):
            return _denied(ReasonCode.ARTIFACT_MISMATCH)

        computed_content_digest = sha256_digest(captured_content)
        computed_manifest_digest = _manifest_digest(stable_manifest)
        if captured_manifest != canonical_bytes(stable_manifest.to_document()):
            return _denied(ReasonCode.ARTIFACT_MISMATCH)
        if (
            _pin_value(stable_pin, "artifact_id") != artifact_id
            or _pin_value(stable_pin, "content_digest") != computed_content_digest
            or _pin_value(stable_pin, "manifest_digest") != computed_manifest_digest
            or stable_manifest.content_digest != computed_content_digest
        ):
            return _denied(ReasonCode.ARTIFACT_MISMATCH)

        return self._verify_acceptance(
            artifact_id=artifact_id,
            acceptance_checks=stable_checks,
            observations=stable_observations,
        )

    def _verify_acceptance(
        self,
        *,
        artifact_id: str,
        acceptance_checks: tuple[FrozenObject, ...],
        observations: tuple[FrozenObject, ...],
    ) -> VerificationDecision:
        used_observation_ids: set[str] = set()
        for check in acceptance_checks:
            if type(check) is not FrozenObject:
                return _denied(ReasonCode.ACCEPTANCE_FAILED)
            required = check.get("required")
            if type(required) is not bool or not required:
                continue
            minimum = check.get("minimum_trust_class")
            matched = False
            for observation in observations:
                if type(observation) is not FrozenObject:
                    return _denied(ReasonCode.ACCEPTANCE_FAILED)
                observation_id = _pin_value(observation, "observation_id")
                if observation_id is None or observation_id in used_observation_ids:
                    continue
                evidence_artifact_id = _pin_value(observation, "evidence_artifact_id")
                status = _pin_value(observation, "status")
                if evidence_artifact_id != artifact_id:
                    continue
                if status == "fail":
                    return _denied(ReasonCode.ACCEPTANCE_FAILED)
                if status != "pass":
                    continue
                if _trust_satisfies(minimum, observation.get("trust_class")):
                    matched = True
                    used_observation_ids.add(observation_id)
                    break
            if not matched:
                return _denied(ReasonCode.ACCEPTANCE_FAILED)
        return _accepted()


__all__ = ("ArtifactStore", "ArtifactVerifier", "VerificationDecision")
