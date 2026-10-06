from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum, unique
from typing import NoReturn, cast

from authority_sim.canonical import canonical_bytes, sha256_digest
from authority_sim.errors import ReasonCode
from authority_sim.transitions import PolicyState


class _PolicyFailure(ValueError):
    __slots__ = ("reason",)
    reason: ReasonCode

    def __init__(self, reason: ReasonCode) -> None:
        if type(reason) is not ReasonCode:
            raise ValueError("POLICY_INVALID") from None
        object.__setattr__(self, "reason", reason)
        ValueError.__init__(self, "POLICY_INVALID")


def _fail(reason: ReasonCode) -> NoReturn:
    raise _PolicyFailure(reason) from None


@unique
class PolicyActor(Enum):
    OPERATOR = "operator"
    WORKER = "worker"
    COORDINATOR = "coordinator"
    RESTORE = "restore"
    REPLAY = "replay"


@unique
class _AuthorizationKind(Enum):
    ACTIVATE = "activate"
    RECOVER = "recover"


_POLICY_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedPolicyAuthorization:
    kind: _AuthorizationKind
    authorization_ref: str
    authority_epoch: int

    def __init__(
        self,
        token: object,
        kind: _AuthorizationKind,
        authorization_ref: str,
        authority_epoch: int,
    ) -> None:
        if token is not _POLICY_TOKEN:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(kind) is not _AuthorizationKind:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(authorization_ref) is not str or not authorization_ref:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(ReasonCode.SCHEMA_INVALID)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "authorization_ref", authorization_ref)
        object.__setattr__(self, "authority_epoch", authority_epoch)

    def __repr__(self) -> str:
        return "VerifiedPolicyAuthorization(...)"


class OperatorPolicyPort:
    __slots__ = ()

    def authorize_activation(
        self,
        authorization_ref: str,
        *,
        authority_epoch: int,
    ) -> VerifiedPolicyAuthorization:
        return VerifiedPolicyAuthorization(
            _POLICY_TOKEN,
            _AuthorizationKind.ACTIVATE,
            authorization_ref,
            authority_epoch,
        )

    def authorize_recovery(
        self,
        authorization_ref: str,
        *,
        authority_epoch: int,
    ) -> VerifiedPolicyAuthorization:
        return VerifiedPolicyAuthorization(
            _POLICY_TOKEN,
            _AuthorizationKind.RECOVER,
            authorization_ref,
            authority_epoch,
        )

    def __repr__(self) -> str:
        return "OperatorPolicyPort(...)"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyStub:
    policy_key: str
    version: int
    digest: str
    raw: bytes

    @classmethod
    def from_bytes(cls, raw: object) -> PolicyStub:
        if type(raw) is not bytes:
            _fail(ReasonCode.SCHEMA_INVALID)
        stable_raw = cast(bytes, raw)
        try:
            document = json.loads(stable_raw.decode("utf-8"))
            if type(document) is not dict or canonical_bytes(document) != stable_raw:
                _fail(ReasonCode.SCHEMA_INVALID)
            policy_key = document.get("policy_key")
            version = document.get("policy_version")
            ruleset = document.get("ruleset")
            if (
                type(policy_key) is not str
                or type(version) is not int
                or version < 1
                or type(ruleset) is not str
            ):
                _fail(ReasonCode.SCHEMA_INVALID)
            return cls(
                policy_key=policy_key,
                version=version,
                digest=sha256_digest(stable_raw),
                raw=stable_raw,
            )
        except _PolicyFailure:
            raise
        except Exception:
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "PolicyStub(...)"


@dataclass(frozen=True, slots=True, repr=False)
class PolicySnapshot:
    state: PolicyState
    authority_epoch: int
    active_version: int | None
    active_digest: str | None

    def __post_init__(self) -> None:
        if type(self.state) is not PolicyState:
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.authority_epoch) is not int or self.authority_epoch < 0:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.active_version is not None and (
            type(self.active_version) is not int or self.active_version < 1
        ):
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.active_digest is not None and type(self.active_digest) is not str:
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "PolicySnapshot(...)"


@dataclass(frozen=True, slots=True, repr=False)
class PolicyDecision:
    accepted: bool
    reason: ReasonCode | None
    snapshot: PolicySnapshot

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.reason is not None and type(self.reason) is not ReasonCode:
            _fail(ReasonCode.SCHEMA_INVALID)
        if self.accepted != (self.reason is None):
            _fail(ReasonCode.SCHEMA_INVALID)
        if type(self.snapshot) is not PolicySnapshot:
            _fail(ReasonCode.SCHEMA_INVALID)

    def __repr__(self) -> str:
        return "PolicyDecision(...)"


@dataclass(frozen=True, slots=True, repr=False)
class _PolicyState:
    state: PolicyState
    authority_epoch: int
    active_policy: PolicyStub | None


class PolicyFloor:
    __slots__ = ("__state",)
    __state: _PolicyState

    def __init__(self) -> None:
        object.__setattr__(
            self,
            "_PolicyFloor__state",
            _PolicyState(
                state=PolicyState.UNINITIALIZED,
                authority_epoch=0,
                active_policy=None,
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("POLICY_INVALID")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("POLICY_INVALID")

    def __repr__(self) -> str:
        return "PolicyFloor(...)"

    def _snapshot(self) -> PolicySnapshot:
        state = self.__state
        policy = state.active_policy
        return PolicySnapshot(
            state=state.state,
            authority_epoch=state.authority_epoch,
            active_version=None if policy is None else policy.version,
            active_digest=None if policy is None else policy.digest,
        )

    def _deny(self, reason: ReasonCode) -> PolicyDecision:
        return PolicyDecision(False, reason, self._snapshot())

    def apply(
        self,
        policy: object,
        *,
        actor: object,
        authorization: object,
    ) -> PolicyDecision:
        try:
            if type(policy) is not PolicyStub or type(actor) is not PolicyActor:
                _fail(ReasonCode.SCHEMA_INVALID)
            if type(authorization) is not VerifiedPolicyAuthorization:
                _fail(ReasonCode.SCHEMA_INVALID)
            stable_policy = cast(PolicyStub, policy)
            stable_actor = cast(PolicyActor, actor)
            stable_auth = cast(VerifiedPolicyAuthorization, authorization)
            state = self.__state
            current = state.active_policy

            if stable_auth.kind is _AuthorizationKind.ACTIVATE:
                if stable_actor is not PolicyActor.OPERATOR:
                    _fail(ReasonCode.POLICY_MISMATCH)
                if current is not None and stable_auth.authority_epoch < state.authority_epoch:
                    _fail(ReasonCode.POLICY_MISMATCH)
                if current is not None:
                    if stable_policy.policy_key != current.policy_key:
                        _fail(ReasonCode.POLICY_MISMATCH)
                    if stable_policy.version < current.version:
                        _fail(ReasonCode.POLICY_MISMATCH)
                    if stable_policy.version == current.version and stable_policy.digest != current.digest:
                        _fail(ReasonCode.POLICY_MISMATCH)
                    if stable_policy.version == current.version and stable_policy.digest == current.digest:
                        return PolicyDecision(True, None, self._snapshot())
                object.__setattr__(
                    self,
                    "_PolicyFloor__state",
                    _PolicyState(
                        state=PolicyState.ACTIVE,
                        authority_epoch=max(state.authority_epoch, stable_auth.authority_epoch),
                        active_policy=stable_policy,
                    ),
                )
                return PolicyDecision(True, None, self._snapshot())

            if stable_actor is not PolicyActor.OPERATOR:
                _fail(ReasonCode.POLICY_MISMATCH)
            if (
                current is None
                or stable_policy.policy_key != current.policy_key
                or stable_auth.authority_epoch <= state.authority_epoch
            ):
                _fail(ReasonCode.POLICY_MISMATCH)
            object.__setattr__(
                self,
                "_PolicyFloor__state",
                _PolicyState(
                    state=PolicyState.ACTIVE,
                    authority_epoch=stable_auth.authority_epoch,
                    active_policy=stable_policy,
                ),
            )
            return PolicyDecision(True, None, self._snapshot())
        except _PolicyFailure as failure:
            return self._deny(failure.reason)
