from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]


def load_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        load_schema(name), format_checker=FormatChecker()
    )


def test_s1_outcome_schema_accepts_unverified_create_refusal():
    record = {
        "operationId": "operation-s1-fixture-0001",
        "operation": "sandboxes.create",
        "identity": {
            "runId": "run-s1-fixture-0001",
            "requestId": "request-s1-fixture-0001",
            "profileId": "wsl2:l1@openshell-docker",
        },
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
    }

    assert list(validator("s1-outcome.schema.json").iter_errors(record)) == []


def test_s1_outcome_schema_rejects_inner_only_l1_record():
    record = {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
    }

    assert list(validator("s1-outcome.schema.json").iter_errors(record))


def test_s1_event_schema_accepts_runtime_owned_cursor():
    record = {
        "schemaVersion": "s1-draft-1",
        "eventId": "event-1",
        "cursor": "1",
        "type": "box.sandboxes.create",
        "identity": {
            "runId": "run-s1-fixture-0001",
            "requestId": "request-s1-fixture-0001",
            "profileId": "wsl2:l1@openshell-docker",
            "operationId": "operation-s1-fixture-0001",
            "revision": 1,
        },
        "revision": 1,
        "cause": {"kind": "external_intent", "requestId": "request-s1-fixture-0001"},
        "payload": {"kind": "refused", "code": "profile_unverified"},
        "provenance": {"owner": "kappa-box", "source": "runtime"},
    }

    assert list(validator("s1-event.schema.json").iter_errors(record)) == []
