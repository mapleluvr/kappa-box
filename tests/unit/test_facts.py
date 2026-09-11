from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kappa_box.facts import canonical_facts_bytes, facts_digest

BASE_FACTS = {
    "schemaVersion": "1",
    "sandboxId": "sb-1",
    "profileId": "wsl2:l1@openshell-docker",
    "kernel": "6.18.33.2-microsoft-standard-WSL2",
    "lsm": ["landlock", "capability"],
    "landlock": {
        "enabled": True,
        "abi": 6,
        "compatibility": "hard_requirement",
    },
    "seccomp": {"enabled": True, "profile": "openshell-default"},
    "cgroup": {
        "version": "v2",
        "path": "/user.slice/kappa/sb-1",
        "limits": {
            "cpu": {"state": "enforced", "value": 2, "unit": "cores"},
            "memory": {
                "state": "enforced",
                "value": 2147483648,
                "unit": "bytes",
            },
            "pids": {"state": "enforced", "value": 256, "unit": "count"},
        },
    },
    "runtime": {
        "engineVersion": "29.1.3",
        "name": "runc",
        "version": "1.3.4",
        "rootless": True,
    },
    "image": {
        "reference": "ghcr.io/example/base",
        "digest": "sha256:" + "a" * 64,
    },
    "network": {"profile": "restricted", "egressPath": "openshell-proxy"},
    "time": {
        "collectedAt": datetime.now(UTC).isoformat(),
        "probeSuiteVersion": "0.1.0",
    },
}


def test_digest_ignores_instance_and_collection_metadata():
    later = {**BASE_FACTS, "sandboxId": "sb-2"}
    later["cgroup"] = {
        **BASE_FACTS["cgroup"],
        "path": "/user.slice/kappa/sb-2",
    }
    later["time"] = {
        "collectedAt": "2030-01-01T00:00:00+00:00",
        "probeSuiteVersion": "0.1.0",
    }

    assert facts_digest(BASE_FACTS) == facts_digest(later)


def test_digest_is_stable_when_object_keys_and_lsm_order_change():
    reordered = {key: BASE_FACTS[key] for key in reversed(list(BASE_FACTS))}
    reordered["lsm"] = ["capability", "landlock"]

    assert canonical_facts_bytes(BASE_FACTS) == canonical_facts_bytes(reordered)


def test_digest_changes_when_an_enforced_fact_changes():
    changed = {**BASE_FACTS, "seccomp": {"enabled": False, "profile": None}}

    assert facts_digest(BASE_FACTS) != facts_digest(changed)


def test_digest_rejects_missing_nested_runtime_fact():
    incomplete = {**BASE_FACTS, "runtime": {"name": "runc"}}

    with pytest.raises(ValueError, match="runtime.engineVersion"):
        facts_digest(incomplete)


def test_digest_rejects_unknown_fact_fields():
    invalid = {**BASE_FACTS, "unexpected": True}

    with pytest.raises(ValueError, match="unknown facts: unexpected"):
        facts_digest(invalid)


def test_digest_rejects_invalid_collection_timestamp():
    invalid = {
        **BASE_FACTS,
        "time": {"collectedAt": "yesterday", "probeSuiteVersion": "0.1.0"},
    }

    with pytest.raises(
        ValueError, match="time.collectedAt must be an RFC 3339 timestamp"
    ):
        facts_digest(invalid)


def test_digest_rejects_timestamp_without_timezone():
    invalid = {
        **BASE_FACTS,
        "time": {"collectedAt": "2026-09-11T12:00:00", "probeSuiteVersion": "0.1.0"},
    }

    with pytest.raises(ValueError, match="RFC 3339 timestamp"):
        facts_digest(invalid)


def test_digest_rejects_oversized_seccomp_profile():
    invalid = {**BASE_FACTS, "seccomp": {"enabled": True, "profile": "x" * 257}}

    with pytest.raises(ValueError, match="seccomp.profile exceeds maximum length"):
        facts_digest(invalid)


def test_digest_rejects_timestamp_without_rfc3339_separator():
    invalid = {
        **BASE_FACTS,
        "time": {
            "collectedAt": "2026-09-11 12:00:00+00:00",
            "probeSuiteVersion": "0.1.0",
        },
    }

    with pytest.raises(ValueError, match="RFC 3339 timestamp"):
        facts_digest(invalid)


def test_digest_rejects_inconsistent_landlock_fact():
    invalid = {
        **BASE_FACTS,
        "landlock": {"enabled": False, "abi": 6, "compatibility": "hard_requirement"},
    }

    with pytest.raises(ValueError, match="landlock.abi must be null when disabled"):
        facts_digest(invalid)
