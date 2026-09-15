from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).parents[2]
_IMAGE = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:" + "a" * 64


def schema():
    return json.loads(
        (ROOT / "schemas" / "runtime-vertical-slice.schema.json").read_text(
            encoding="utf-8"
        )
    )


def valid_record(**overrides):
    record = {
        "profileId": "wsl2:l1@openshell-docker",
        "probeSuiteVersion": "0.1.0-runtime-vertical-slice",
        "probeStatus": "runtime_vertical_slice",
        "evidenceClass": "probe_only",
        "acceptance": "unverified",
        "sourceCommit": "abc1234",
        "collectedAt": "2026-09-12T09:00:00Z",
        "image": _IMAGE,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": [],
        "stages": [
            {"name": "preflight", "status": "pass"},
            {"name": "create", "status": "pass", "sandboxName": "example"},
        ],
    }
    record.update(overrides)
    return record


def errors(record):
    return list(
        Draft202012Validator(schema(), format_checker=FormatChecker()).iter_errors(
            record
        )
    )


def test_runtime_vertical_slice_schema_accepts_unverified_record():
    assert errors(valid_record()) == []


def test_runtime_vertical_slice_schema_rejects_empty_stages():
    assert errors(valid_record(stages=[]))


def test_runtime_vertical_slice_schema_rejects_verified_record():
    assert errors(
        valid_record(
            acceptance="verified", stages=[{"name": "preflight", "status": "pass"}]
        )
    )


def test_runtime_vertical_slice_schema_requires_evidence_class():
    record = valid_record()
    del record["evidenceClass"]
    assert errors(record)


def test_runtime_vertical_slice_schema_carries_truncation():
    assert (
        errors(
            valid_record(
                failureGroups=["channels"],
                stages=[
                    {
                        "name": "exec",
                        "status": "fail",
                        "returncode": 0,
                        "truncated": True,
                    }
                ],
            )
        )
        == []
    )
