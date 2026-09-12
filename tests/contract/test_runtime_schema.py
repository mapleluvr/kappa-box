from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]


def test_runtime_vertical_slice_schema_accepts_unverified_record():
    schema = json.loads(
        (ROOT / "schemas" / "runtime-vertical-slice.schema.json").read_text(
            encoding="utf-8"
        )
    )
    record = {
        "profileId": "wsl2:l1@openshell-docker",
        "probeSuiteVersion": "0.1.0-runtime-vertical-slice",
        "probeStatus": "runtime_vertical_slice",
        "acceptance": "unverified",
        "sourceCommit": "abc1234",
        "collectedAt": "2026-09-12T09:00:00Z",
        "image": "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:" + "a" * 64,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": [],
        "stages": [
            {"name": "preflight", "status": "pass"},
            {"name": "create", "status": "pass", "sandboxName": "example"},
        ],
    }

    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(record)
    )

    assert errors == []


def test_runtime_vertical_slice_schema_rejects_verified_record():
    schema = json.loads(
        (ROOT / "schemas" / "runtime-vertical-slice.schema.json").read_text(
            encoding="utf-8"
        )
    )
    record = {
        "profileId": "wsl2:l1@openshell-docker",
        "probeSuiteVersion": "0.1.0-runtime-vertical-slice",
        "probeStatus": "runtime_vertical_slice",
        "acceptance": "verified",
        "sourceCommit": "abc1234",
        "collectedAt": "2026-09-12T09:00:00Z",
        "image": "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:" + "a" * 64,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": [],
        "stages": [],
    }

    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(record)
    )

    assert errors
