from __future__ import annotations

import json
from pathlib import Path

import pytest

from kappa_box.profile import load_profile

ROOT = Path(__file__).parents[2]


def valid_expected_facts(profile_id: str) -> dict:
    return {
        "schemaVersion": "1",
        "profileId": profile_id,
        "kernel": "6.18.33.2-microsoft-standard-WSL2",
        "lsm": ["capability", "landlock"],
        "landlock": {"enabled": True, "abi": 6, "compatibility": "hard_requirement"},
        "seccomp": {"enabled": True, "profile": "builtin"},
        "cgroup": {
            "version": "v2",
            "limits": {
                "cpu": {"state": "enforced", "value": 2, "unit": "cores"},
                "memory": {"state": "enforced", "value": 2147483648, "unit": "bytes"},
                "pids": {"state": "enforced", "value": 256, "unit": "count"},
            },
        },
        "runtime": {
            "engineVersion": "29.1.3",
            "name": "runc",
            "version": "1.3.4",
            "rootless": True,
        },
        "image": {"digest": "sha256:" + "a" * 64},
        "network": {"profile": "restricted", "egressPath": "openshell-proxy"},
    }


def test_load_profile_validates_registry_identity_and_returns_profile():
    profile = load_profile(
        ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json"
    )

    assert profile["id"] == "wsl2:l1@openshell-docker"
    assert profile["acceptance"] == "unverified"


def test_load_profile_rejects_registry_identity_mismatch(tmp_path: Path):
    profile = json.loads(
        (ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json").read_text(
            encoding="utf-8"
        )
    )
    profile["variant"] = "oci-direct"
    path = tmp_path / "invalid-profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")

    with pytest.raises(ValueError, match="profile schema validation failed"):
        load_profile(path)


def test_load_profile_rejects_facts_for_another_profile(tmp_path: Path):
    profile = json.loads(
        (ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json").read_text(
            encoding="utf-8"
        )
    )
    profile["acceptance"] = "unverified"
    profile["expectedFacts"] = valid_expected_facts("linux:l1@podman-rootless")
    path = tmp_path / "mismatched-facts-profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")

    with pytest.raises(ValueError, match="expectedFacts.profileId"):
        load_profile(path)


def complete_verified_profile() -> dict:
    profile = json.loads(
        (ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json").read_text(
            encoding="utf-8"
        )
    )
    profile.update(
        acceptance="verified",
        expectedFacts=valid_expected_facts("wsl2:l1@openshell-docker"),
        runtime={"engine": "docker", "name": "openshell", "rootless": True},
        channels={
            "longLivedProcess": True,
            "pty": True,
            "separateStdoutStderr": True,
            "maxArtifactBytes": 8388608,
            "snapshot": "stable",
        },
        pins={
            "host": "windows-10.0.26200.9168",
            "distribution": "kappa-box-ubuntu-24.04",
            "kernel": "6.18.33.2-microsoft-standard-WSL2",
            "engine": "docker-29.1.3",
            "runtime": "runc-1.3.4",
            "gateway": "openshell-0.0.99",
            "supervisor": "openshell-supervisor-0.0.99",
            "image": "sha256:" + "a" * 64,
        },
        probe={
            "suiteVersion": "1.0.0",
            "lastRunAt": "2026-09-11T12:00:00Z",
            "result": "pass",
            "failureGroups": [],
            "evidenceRef": "evidence/releases/probe.json",
        },
    )
    return profile


def test_load_profile_rejects_verified_profile_with_invalid_probe_timestamp(
    tmp_path: Path,
):
    profile = complete_verified_profile()
    profile["probe"]["lastRunAt"] = "not-a-date"
    path = tmp_path / "invalid-probe-time-profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")

    with pytest.raises(ValueError, match="probe.lastRunAt"):
        load_profile(path)


def test_load_profile_rejects_verified_profile_without_evidence(tmp_path: Path):
    profile = json.loads(
        (ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json").read_text(
            encoding="utf-8"
        )
    )
    profile["acceptance"] = "verified"
    path = tmp_path / "unproven-profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")

    with pytest.raises(ValueError, match="profile schema validation failed"):
        load_profile(path)
