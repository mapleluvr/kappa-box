"""L1 operation outcome boundary: refused, failed, and unknown wrappers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "operation-outcome.schema.json"
)

_ACCEPTANCE_STATES = frozenset(
    {"unverified", "verifying", "verified", "failed", "stale"}
)

REFUSED_CODES = frozenset(
    {
        "profile_unknown",
        "profile_unverified",
        "invalid_profile",
        "facts_mismatch",
        "grant_denied",
        "network_profile_denied",
        "image_unavailable",
        "resource_exhausted",
        "invalid_state",
        "unsupported",
        "unauthorized",
        "idempotency_conflict",
    }
)
FAILED_CODES = frozenset({"provisioning_failed", "snapshot_unstable"})
UNKNOWN_CODES = frozenset({"host_unreachable", "deadline_exceeded"})
RETRYABLE_CODES = frozenset(
    {
        "image_unavailable",
        "resource_exhausted",
        "host_unreachable",
        "snapshot_unstable",
        "deadline_exceeded",
    }
)

_WRAPPER_BY_CODE = {
    **dict.fromkeys(REFUSED_CODES, "refused"),
    **dict.fromkeys(FAILED_CODES, "failed"),
    **dict.fromkeys(UNKNOWN_CODES, "unknown"),
}
if len(_WRAPPER_BY_CODE) != len(REFUSED_CODES | FAILED_CODES | UNKNOWN_CODES):
    raise RuntimeError("error code wrapper assignment overlaps")

_SIDE_EFFECTS_BY_KIND = {
    "refused": "none",
    "failed": "present",
    "unknown": "unreconciled",
}
_ENVELOPE_SIDE_EFFECT = {
    "none": "none",
    "present": "present",
    "unreconciled": "unknown",
}


class OutcomeKind(StrEnum):
    REFUSED = "refused"
    FAILED = "failed"
    UNKNOWN = "unknown"


class SideEffects(StrEnum):
    NONE = "none"
    PRESENT = "present"
    UNRECONCILED = "unreconciled"


@dataclass(frozen=True)
class OperationOutcome:
    """One machine-checkable L1 operation error result."""

    kind: OutcomeKind
    code: str
    side_effects: SideEffects

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE_CODES

    def render(self) -> str:
        return f"{self.kind}({self.code})"

    def to_record(self) -> dict[str, str | bool]:
        record = {
            "kind": str(self.kind),
            "code": self.code,
            "sideEffects": str(self.side_effects),
            "reconcile": self.kind is OutcomeKind.UNKNOWN,
        }
        _validate_record(record)
        return record

    def to_envelope_fields(self) -> dict[str, str | bool]:
        """Project onto the overlapping S0 error-envelope fields.

        The Box record keeps `sideEffects` (plural) and `unreconciled`.
        The unfrozen cross-component envelope uses `sideEffect` (singular)
        with `{none, present, unknown}` and a `reconcile` flag. This is a
        field mapping only: it does not add operation/requestId or invent a
        full service envelope.
        """
        return {
            "kind": str(self.kind),
            "code": self.code,
            "sideEffect": _ENVELOPE_SIDE_EFFECT[str(self.side_effects)],
            "retry": "inspect-before-retry" if self.retryable else "none",
            "reconcile": self.kind is OutcomeKind.UNKNOWN,
        }


def refused(code: str) -> OperationOutcome:
    """Refuse an L1 operation before any backend side effects."""
    return _wrap("refused", code)


def failed(code: str) -> OperationOutcome:
    """Record an L1 failure after backend side effects already happened."""
    return _wrap("failed", code)


def unknown(code: str) -> OperationOutcome:
    """Record that this invocation's side-effect scope cannot be determined."""
    return _wrap("unknown", code)


class OperationOutcomeError(RuntimeError):
    """Typed L1 operation result that failed closed."""

    def __init__(self, outcome: OperationOutcome, *, detail: str = "") -> None:
        message = outcome.render()
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)
        self.outcome = outcome

    def to_record(self) -> dict[str, str | bool]:
        return self.outcome.to_record()


def l1_create_gate(
    *,
    profile_registered: bool,
    profile_acceptance: str,
) -> OperationOutcome | None:
    """Refuse L1 create before the backend runs, or allow it to proceed."""
    if profile_acceptance not in _ACCEPTANCE_STATES:
        raise ValueError(f"invalid profile acceptance: {profile_acceptance}")
    if not profile_registered:
        return refused("profile_unknown")
    if profile_acceptance != "verified":
        return refused("profile_unverified")
    return None


def l1_execution_error(*, error_code: str) -> OperationOutcome:
    """Map a post-invocation L1 error code onto its wrapper.

    Refused codes are rejected here because they are pre-execution. Failed
    codes mean a determined backend failure with side effects. Unknown codes
    mean the side-effect scope cannot be determined and reconcile is required;
    callers must not use them for a confirmed pre-call host miss.
    """
    wrapper = _WRAPPER_BY_CODE.get(error_code)
    if wrapper is None:
        raise ValueError(f"unknown error code: {error_code}")
    if wrapper == "refused":
        raise ValueError(f"{error_code} is a pre-execution refused code")
    if wrapper == "unknown":
        return unknown(error_code)
    return failed(error_code)


def outcome_from_record(record: Mapping[str, Any]) -> OperationOutcome:
    """Parse and validate one operation outcome record."""
    _validate_record(record)
    kind = record["kind"]
    code = record["code"]
    side_effects = record["sideEffects"]
    if not isinstance(kind, str) or not isinstance(code, str):
        raise ValueError("kind and code must be strings")
    if not isinstance(side_effects, str):
        raise ValueError("sideEffects must be a string")
    reconcile = record["reconcile"]
    if not isinstance(reconcile, bool):
        raise ValueError("reconcile must be a boolean")
    outcome = _wrap(kind, code)
    if str(outcome.side_effects) != side_effects:
        raise ValueError("sideEffects does not match outcome kind")
    if reconcile != (outcome.kind is OutcomeKind.UNKNOWN):
        raise ValueError("reconcile does not match outcome kind")
    return outcome


def _wrap(kind: str, code: str) -> OperationOutcome:
    assigned = _WRAPPER_BY_CODE.get(code)
    if assigned is None:
        raise ValueError(f"unknown error code: {code}")
    if assigned != kind:
        raise ValueError(f"{code} must be wrapped as {assigned}, not {kind}")
    return OperationOutcome(
        kind=OutcomeKind(kind),
        code=code,
        side_effects=SideEffects(_SIDE_EFFECTS_BY_KIND[assigned]),
    )


@cache
def _schema_validator() -> Draft202012Validator:
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("operation outcome schema is unavailable") from error
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_record(record: Mapping[str, Any]) -> None:
    try:
        _schema_validator().validate(record)
    except ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "outcome"
        raise ValueError(
            f"operation outcome schema validation failed at {location}: {error.message}"
        ) from error
