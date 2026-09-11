from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).parents[2]


def load_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    facts = load_schema("facts.schema.json")
    profile = load_schema(name)
    registry = (
        Registry()
        .with_resource(facts["$id"], Resource.from_contents(facts))
        .with_resource(profile["$id"], Resource.from_contents(profile))
    )
    return Draft202012Validator(
        profile, registry=registry, format_checker=FormatChecker()
    )


def canonical_facts() -> dict:
    return {
        "schemaVersion": "1",
        "profileId": "wsl2:l1@openshell-docker",
        "kernel": "6.18.33.2-microsoft-standard-WSL2",
        "lsm": ["capability", "landlock"],
        "landlock": {
            "enabled": True,
            "abi": 6,
            "compatibility": "hard_requirement",
        },
        "seccomp": {"enabled": True, "profile": "builtin"},
        "cgroup": {
            "version": "v2",
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
            "digest": "sha256:" + "a" * 64,
        },
        "network": {"profile": "restricted", "egressPath": "openshell-proxy"},
    }


def facts_validator() -> Draft202012Validator:
    facts = load_schema("facts.schema.json")
    registry = Registry().with_resource(facts["$id"], Resource.from_contents(facts))
    return Draft202012Validator(
        facts, registry=registry, format_checker=FormatChecker()
    )


def observed_facts() -> dict:
    facts = copy.deepcopy(canonical_facts())
    facts["sandboxId"] = "sb-1"
    facts["cgroup"]["path"] = "/user.slice/kappa/sb-1"
    facts["image"]["reference"] = "ghcr.io/example/base"
    facts["time"] = {
        "collectedAt": "2026-09-11T12:00:00Z",
        "probeSuiteVersion": "0.1.0",
    }
    return facts


def unverified_profile() -> dict:
    return {
        "schemaVersion": "1",
        "id": "wsl2:l1@openshell-docker",
        "hostClass": "wsl2",
        "tier": "l1",
        "variant": "openshell-docker",
        "acceptance": "unverified",
        "runtime": {"engine": "docker", "name": "openshell", "rootless": None},
        "policy": {
            "landlockCompatibility": "hard_requirement",
            "networkProfiles": ["restricted"],
            "grants": [{"path": "/work", "mode": "rw"}],
        },
        "limits": {"cpu": None, "memoryBytes": None, "pids": None},
        "channels": {
            "longLivedProcess": None,
            "pty": None,
            "separateStdoutStderr": None,
            "maxArtifactBytes": None,
            "snapshot": None,
        },
        "expectedFacts": None,
        "pins": {},
        "probe": {
            "suiteVersion": None,
            "lastRunAt": None,
            "result": "never_run",
        },
    }


def test_facts_schema_accepts_complete_observation():
    errors = list(facts_validator().iter_errors(observed_facts()))

    assert errors == []


def test_facts_schema_rejects_observation_without_cgroup_path():
    facts = observed_facts()
    del facts["cgroup"]["path"]

    errors = list(facts_validator().iter_errors(facts))

    assert errors


def test_facts_schema_rejects_disabled_hard_requirement_landlock():
    facts = observed_facts()
    facts["landlock"] = {
        "enabled": False,
        "abi": None,
        "compatibility": "hard_requirement",
    }

    errors = list(facts_validator().iter_errors(facts))

    assert errors


def test_canonical_facts_projection_is_valid_for_expected_facts():
    facts_schema = load_schema("facts.schema.json")
    projection_schema = {
        "$id": "https://kappa-box.invalid/schemas/canonical-facts-test.schema.json",
        "$ref": facts_schema["$id"] + "#/$defs/canonicalFacts",
    }
    registry = Registry().with_resource(
        facts_schema["$id"], Resource.from_contents(facts_schema)
    )
    errors = list(
        Draft202012Validator(projection_schema, registry=registry).iter_errors(
            canonical_facts()
        )
    )

    assert errors == []


def test_profile_schema_resolves_facts_schema_and_accepts_unverified_profile():
    errors = list(validator("profile.schema.json").iter_errors(unverified_profile()))

    assert errors == []


def test_profile_schema_rejects_grant_path_traversal():
    profile = unverified_profile()
    profile["policy"]["grants"] = [{"path": "/work/../etc", "mode": "rw"}]

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert any("grants" in error.json_path for error in errors)


def test_profile_schema_accepts_complete_verified_profile():
    profile = unverified_profile()
    profile.update(
        acceptance="verified",
        expectedFacts=canonical_facts(),
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
            "distribution": "Ubuntu-24.04",
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

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert errors == []


def test_profile_schema_rejects_verified_profile_with_failure_groups():
    profile = unverified_profile()
    profile.update(
        acceptance="verified",
        expectedFacts=canonical_facts(),
        runtime={"engine": "docker", "name": "openshell", "rootless": True},
        channels={
            "longLivedProcess": True,
            "pty": True,
            "separateStdoutStderr": True,
            "maxArtifactBytes": 8388608,
            "snapshot": "stable",
        },
        pins={key: "sha256:" + "a" * 64 for key in ["image"]},
        probe={
            "suiteVersion": "1.0.0",
            "lastRunAt": "2026-09-11T12:00:00Z",
            "result": "pass",
            "failureGroups": ["network"],
            "evidenceRef": "evidence/releases/probe.json",
        },
    )
    profile["pins"].update(
        {
            "host": "host",
            "distribution": "Ubuntu-24.04",
            "kernel": "kernel",
            "engine": "engine",
            "runtime": "runtime",
            "gateway": "gateway",
            "supervisor": "supervisor",
        }
    )

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert errors


def test_profile_schema_rejects_id_host_and_tier_mismatch():
    profile = unverified_profile()
    profile["hostClass"] = "linux"
    profile["tier"] = "l2"

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert any("hostClass" in error.json_path for error in errors)
    assert any("tier" in error.json_path for error in errors)


def test_registered_profile_matches_profile_schema():
    profile = json.loads(
        (ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json").read_text(
            encoding="utf-8"
        )
    )

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert errors == []


def test_profile_schema_rejects_id_variant_mismatch_for_registered_profile():
    profile = unverified_profile()
    profile["variant"] = "oci-direct"

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert any("variant" in error.json_path for error in errors)


def test_profile_schema_rejects_variant_without_variant_in_id():
    profile = unverified_profile()
    profile["id"] = "linux:l1"
    profile["hostClass"] = "linux"
    profile["variant"] = "podman-rootless"

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert errors


def test_profile_schema_rejects_verified_profile_without_probe_and_pins():
    profile = unverified_profile()
    profile.update(
        acceptance="verified",
        expectedFacts=canonical_facts(),
    )

    errors = list(validator("profile.schema.json").iter_errors(profile))

    assert any("pins" in error.json_path for error in errors)
    assert any("probe" in error.json_path for error in errors)
