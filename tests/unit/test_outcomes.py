from __future__ import annotations

import json
from pathlib import Path

import pytest

from kappa_box.outcomes import (
    FAILED_CODES,
    REFUSED_CODES,
    UNKNOWN_CODES,
    failed,
    l1_create_gate,
    l1_execution_error,
    outcome_from_record,
    refused,
    unknown,
)

ROOT = Path(__file__).parents[2]


def test_l1_create_gate_refuses_unverified_profile_without_side_effects():
    outcome = l1_create_gate(
        profile_registered=True,
        profile_acceptance="unverified",
    )

    assert outcome is not None
    assert outcome.kind == "refused"
    assert outcome.code == "profile_unverified"
    assert outcome.side_effects == "none"
    assert outcome.render() == "refused(profile_unverified)"
    assert outcome.retryable is False
    assert outcome.to_record() == {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
    }


def test_l1_create_gate_allows_verified_profile():
    assert (
        l1_create_gate(profile_registered=True, profile_acceptance="verified") is None
    )


def test_failed_code_maps_to_failed_wrapper():
    outcome = l1_execution_error(error_code="provisioning_failed")

    assert outcome.kind == "failed"
    assert outcome.code == "provisioning_failed"
    assert outcome.side_effects == "present"
    assert outcome.render() == "failed(provisioning_failed)"
    assert outcome.retryable is False
    assert outcome.to_record() == {
        "kind": "failed",
        "code": "provisioning_failed",
        "sideEffects": "present",
        "reconcile": False,
    }


def test_unknown_code_maps_to_unreconciled_wrapper():
    outcome = l1_execution_error(error_code="deadline_exceeded")

    assert outcome.kind == "unknown"
    assert outcome.code == "deadline_exceeded"
    assert outcome.side_effects == "unreconciled"
    assert outcome.render() == "unknown(deadline_exceeded)"
    assert outcome.retryable is True
    assert outcome.to_record() == {
        "kind": "unknown",
        "code": "deadline_exceeded",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }


def test_host_unreachable_maps_to_unknown_without_lost_flag():
    outcome = l1_execution_error(error_code="host_unreachable")

    assert outcome.to_record() == {
        "kind": "unknown",
        "code": "host_unreachable",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }


def test_same_code_cannot_be_used_under_another_wrapper():
    with pytest.raises(ValueError, match="refused"):
        refused("provisioning_failed")
    with pytest.raises(ValueError, match="failed"):
        failed("profile_unverified")
    with pytest.raises(ValueError, match="unknown"):
        unknown("provisioning_failed")


@pytest.mark.parametrize("acceptance", ["verifying", "failed", "stale"])
def test_l1_create_gate_refuses_registered_but_unverified_acceptance(
    acceptance: str,
):
    outcome = l1_create_gate(
        profile_registered=True,
        profile_acceptance=acceptance,
    )

    assert outcome is not None
    assert outcome.render() == "refused(profile_unverified)"
    assert outcome.side_effects == "none"


def test_l1_create_gate_refuses_unregistered_profile_without_side_effects():
    outcome = l1_create_gate(
        profile_registered=False,
        profile_acceptance="unverified",
    )

    assert outcome is not None
    assert outcome.render() == "refused(profile_unknown)"
    assert outcome.side_effects == "none"


def test_l1_execution_error_rejects_pre_execution_refused_code():
    with pytest.raises(ValueError, match="pre-execution refused"):
        l1_execution_error(error_code="profile_unverified")


def test_outcome_record_does_not_carry_facts_or_acceptance():
    record = refused("profile_unverified").to_record()

    assert "acceptance" not in record
    assert "facts" not in record
    assert "operation" not in record
    assert "requestId" not in record
    assert "sideEffect" not in record


def test_envelope_projection_maps_side_effects_and_reconcile():
    refused_fields = refused("profile_unverified").to_envelope_fields()
    failed_fields = failed("provisioning_failed").to_envelope_fields()
    unknown_fields = unknown("host_unreachable").to_envelope_fields()

    assert refused_fields == {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffect": "none",
        "retry": "none",
        "reconcile": False,
    }
    assert failed_fields == {
        "kind": "failed",
        "code": "provisioning_failed",
        "sideEffect": "present",
        "retry": "none",
        "reconcile": False,
    }
    assert unknown_fields == {
        "kind": "unknown",
        "code": "host_unreachable",
        "sideEffect": "unknown",
        "retry": "inspect-before-retry",
        "reconcile": True,
    }


def test_outcome_from_record_round_trips_failed_result():
    original = failed("provisioning_failed")

    assert outcome_from_record(original.to_record()) == original


def test_outcome_from_record_rejects_wrapper_mismatch():
    with pytest.raises(ValueError, match="schema validation failed"):
        outcome_from_record(
            {
                "kind": "failed",
                "code": "profile_unverified",
                "sideEffects": "present",
                "reconcile": False,
            }
        )


def test_python_wrapper_assignment_matches_schema():
    schema = json.loads(
        (ROOT / "schemas" / "operation-outcome.schema.json").read_text(encoding="utf-8")
    )
    expected_side_effects = {
        "refused": "none",
        "failed": "present",
        "unknown": "unreconciled",
    }
    expected_reconcile = {"refused": False, "failed": False, "unknown": True}
    by_kind = {}
    for variant in schema["oneOf"]:
        kind = variant["properties"]["kind"]["const"]
        by_kind[kind] = set(variant["properties"]["code"]["enum"])
        assert (
            variant["properties"]["sideEffects"]["const"] == expected_side_effects[kind]
        )
        assert variant["properties"]["reconcile"]["const"] is expected_reconcile[kind]
        assert "reconcile" in variant["required"]

    assert by_kind["refused"] == REFUSED_CODES
    assert by_kind["failed"] == FAILED_CODES
    assert by_kind["unknown"] == UNKNOWN_CODES
