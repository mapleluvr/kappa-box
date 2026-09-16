from __future__ import annotations

from kappa_box.profile_gate import evaluate_host_record


def test_missing_host_record_never_advertises_verified() -> None:
    decision = evaluate_host_record(
        registry_acceptance="verified",
        host_record=None,
        facts_digest="sha256:abc",
    )
    assert decision.acceptance == "unverified"
    assert decision.available is False
    assert decision.facts_digest is None
    assert "host_evidence_missing" in decision.failure_groups


def test_host_failure_overrides_registry_verified() -> None:
    decision = evaluate_host_record(
        registry_acceptance="verified",
        host_record={"failureGroups": ["host"]},
        facts_digest="sha256:abc",
    )
    assert decision.acceptance == "unverified"
    assert decision.available is False
    assert decision.host_result == "fail"
    assert decision.failure_groups == ("host",)


def test_host_pass_without_facts_stays_unverified() -> None:
    decision = evaluate_host_record(
        registry_acceptance="verified",
        host_record={"failureGroups": []},
        facts_digest=None,
    )
    assert decision.acceptance == "unverified"
    assert decision.available is False
    assert decision.host_result == "pass"
    assert "facts_missing" in decision.failure_groups


def test_verified_requires_host_pass_facts_and_registry() -> None:
    decision = evaluate_host_record(
        registry_acceptance="verified",
        host_record={"failureGroups": []},
        facts_digest="sha256:facts",
    )
    assert decision.acceptance == "verified"
    assert decision.available is True
    assert decision.facts_digest == "sha256:facts"
    assert decision.failure_groups == ()


def test_host_pass_does_not_promote_unverified_registry() -> None:
    decision = evaluate_host_record(
        registry_acceptance="unverified",
        host_record={"failureGroups": []},
        facts_digest="sha256:facts",
    )
    assert decision.acceptance == "unverified"
    assert decision.available is False
    assert "registry_unverified" in decision.failure_groups
