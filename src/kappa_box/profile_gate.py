"""S3 host/profile evidence gate. Registry text is not host evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

_VERIFIED = "verified"
_UNVERIFIED = "unverified"


@dataclass(frozen=True)
class ProfileGateDecision:
    acceptance: str
    available: bool
    facts_digest: str | None
    host_result: str
    failure_groups: tuple[str, ...]


class ProfileGate(Protocol):
    def evaluate(
        self, *, profile_id: str, registry_acceptance: str
    ) -> ProfileGateDecision: ...


def evaluate_host_record(
    *,
    registry_acceptance: str,
    host_record: Mapping[str, Any] | None,
    facts_digest: str | None,
) -> ProfileGateDecision:
    """Decide inspect.available from live host evidence, not registry advertising."""
    if host_record is None:
        return ProfileGateDecision(
            acceptance=_UNVERIFIED,
            available=False,
            facts_digest=None,
            host_result="absent",
            failure_groups=("host_evidence_missing",),
        )
    raw_failures = host_record.get("failureGroups") or ()
    failures = tuple(str(item) for item in raw_failures)
    if failures:
        return ProfileGateDecision(
            acceptance=_UNVERIFIED,
            available=False,
            facts_digest=None,
            host_result="fail",
            failure_groups=failures,
        )
    digest = facts_digest if isinstance(facts_digest, str) and facts_digest else None
    if digest is None:
        return ProfileGateDecision(
            acceptance=_UNVERIFIED,
            available=False,
            facts_digest=None,
            host_result="pass",
            failure_groups=("facts_missing",),
        )
    if registry_acceptance != _VERIFIED:
        return ProfileGateDecision(
            acceptance=_UNVERIFIED,
            available=False,
            facts_digest=digest,
            host_result="pass",
            failure_groups=("registry_unverified",),
        )
    return ProfileGateDecision(
        acceptance=_VERIFIED,
        available=True,
        facts_digest=digest,
        host_result="pass",
        failure_groups=(),
    )


class RecordedHostGate:
    def __init__(
        self,
        host_record: Mapping[str, Any] | None,
        facts_digest: str | None = None,
    ) -> None:
        self._host_record = host_record
        self._facts_digest = facts_digest

    def evaluate(
        self, *, profile_id: str, registry_acceptance: str
    ) -> ProfileGateDecision:
        del profile_id
        return evaluate_host_record(
            registry_acceptance=registry_acceptance,
            host_record=self._host_record,
            facts_digest=self._facts_digest,
        )
