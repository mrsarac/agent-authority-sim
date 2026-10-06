from enum import Enum, unique
from dataclasses import dataclass

@unique
class ReasonCode(Enum):
    SCHEMA_INVALID = "SCHEMA_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    AUTHORITY_STALE = "AUTHORITY_STALE"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    CAPABILITY_INVALID = "CAPABILITY_INVALID"
    CAPABILITY_REVOKED = "CAPABILITY_REVOKED"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    ADAPTER_UNSUPPORTED = "ADAPTER_UNSUPPORTED"
    RECEIPT_UNVERIFIED = "RECEIPT_UNVERIFIED"
    ARTIFACT_MISMATCH = "ARTIFACT_MISMATCH"
    EXPECTED_HEAD_MISMATCH = "EXPECTED_HEAD_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    ACCEPTANCE_FAILED = "ACCEPTANCE_FAILED"
    POLICY_MISMATCH = "POLICY_MISMATCH"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"

@dataclass(frozen=True, slots=True)
class Denied:
    code: ReasonCode

    def __post_init__(self):
        if type(self.code) is not ReasonCode:
            raise TypeError("Denied.code must be an exact ReasonCode enum member")

    def __str__(self):
        return f"Denied(code={self.code.name})"

    def __repr__(self):
        return f"Denied(code={self.code.name})"
