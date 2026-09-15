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


def inventory_validator() -> Draft202012Validator:
    inventory = load_schema("inventory.schema.json")
    return Draft202012Validator(inventory, format_checker=FormatChecker())


def host_observation_validator() -> Draft202012Validator:
    schema = load_schema("host-observation.schema.json")
    return Draft202012Validator(schema, format_checker=FormatChecker())


def landlock_validator() -> Draft202012Validator:
    schema = load_schema("landlock-capability.schema.json")
    return Draft202012Validator(schema, format_checker=FormatChecker())


def runtime_vertical_slice_validator() -> Draft202012Validator:
    schema = load_schema("runtime-vertical-slice.schema.json")
    return Draft202012Validator(schema, format_checker=FormatChecker())


def operation_outcome_validator() -> Draft202012Validator:
    schema = load_schema("operation-outcome.schema.json")
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _landlock_record(*, status: str = "supported") -> dict:
    supported = status == "supported"
    return {
        "profileId": "wsl2:l1@openshell-docker",
        "collectedAt": "2026-09-11T12:00:00Z",
        "acceptance": "unverified",
        "probeStatus": "landlock_capability",
        "probeSuiteVersion": "0.1.0-landlock-capability",
        "sourceCommit": "test-commit",
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": [] if supported else ["landlock"],
        "capability": {
            "status": status,
            "abiVersion": 7 if supported else None,
            "error": None if supported else "command failed",
        },
        "commands": [
            {
                "name": "host.landlock.abi",
                "argv": [
                    "wsl.exe",
                    "-d",
                    "kappa-box-ubuntu-24.04",
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    "probe",
                ],
                "returncode": 0 if supported else 1,
                "stdout": "abi:7\n" if supported else "",
                "stderr": "" if supported else "failed",
                "duration_ms": 1,
                "timed_out": False,
                "truncated": False,
            }
        ],
    }


def _host_command(name: str, argv: list[str]) -> dict:
    return {
        "name": name,
        "argv": argv,
        "returncode": 0,
        "timed_out": False,
        "truncated": False,
    }


def _host_observation_record(*, result: str) -> dict:
    distro = "kappa-box-ubuntu-24.04"
    commands = [
        _host_command("wsl.version", ["wsl.exe", "--version"]),
        _host_command("wsl.list", ["wsl.exe", "-l", "-v"]),
        _host_command("wsl.kernel", ["wsl.exe", "-d", distro, "--", "uname", "-r"]),
        _host_command(
            "wsl.conf", ["wsl.exe", "-d", distro, "--", "cat", "/etc/wsl.conf"]
        ),
        _host_command(
            "docker.version", ["wsl.exe", "-d", distro, "--", "docker", "version"]
        ),
        _host_command("docker.info", ["wsl.exe", "-d", distro, "--", "docker", "info"]),
        _host_command(
            "host.mountinfo",
            ["wsl.exe", "-d", distro, "--", "cat", "/proc/self/mountinfo"],
        ),
        _host_command(
            "host.interop",
            [
                "wsl.exe",
                "-d",
                distro,
                "--",
                "cat",
                "/proc/sys/fs/binfmt_misc/WSLInterop",
            ],
        ),
        _host_command(
            "host.cgroup.controllers",
            ["wsl.exe", "-d", distro, "--", "cat", "/sys/fs/cgroup/cgroup.controllers"],
        ),
        _host_command(
            "host.cgroup.subtree",
            [
                "wsl.exe",
                "-d",
                distro,
                "--",
                "cat",
                "/sys/fs/cgroup/cgroup.subtree_control",
            ],
        ),
        _host_command(
            "host.lsm",
            ["wsl.exe", "-d", distro, "--", "cat", "/sys/kernel/security/lsm"],
        ),
        _host_command(
            "host.lsm.proc",
            ["wsl.exe", "-d", distro, "--", "cat", "/proc/sys/kernel/lsm"],
        ),
    ]
    failed = result == "fail"
    return {
        "profileId": "wsl2:l1@openshell-docker",
        "collectedAt": "2026-09-11T12:00:00Z",
        "acceptance": "unverified",
        "probeStatus": "host_visibility",
        "probeSuiteVersion": "0.1.0-host-visibility",
        "sourceCommit": "test-commit",
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": ["host"] if failed else [],
        "groups": [
            {
                "name": "host",
                "result": result,
                "reason": "host isolation visibility failed"
                if failed
                else "host isolation visibility checks passed",
            }
        ],
        "commands": commands,
        "observations": {
            "kernel": "6.18.33.2-microsoft-standard-WSL2",
            "distro": {
                "name": "kappa-box-ubuntu-24.04",
                "wslVersion": "2.7.11.0",
                "windowsVersion": "10.0.26200.9168",
                "state": "Running",
                "siblings": ["docker-desktop"],
            },
            "wslConf": {
                "systemd": True,
                "automountEnabled": None if failed else False,
                "interopEnabled": None if failed else False,
                "presentKeys": ["boot.systemd"],
            },
            "mounts": {
                "windowsDriveMounts": ["/mnt/c"] if failed else [],
                "drvfsPresent": failed,
            },
            "interop": {
                "wslInteropFile": "present" if failed else "missing",
                "enabled": failed,
            },
            "cgroup": {
                "controllers": ["cpu", "memory", "pids"],
                "subtreeControl": ["cpu", "memory", "pids"],
                "controllersReadable": True,
                "subtreeReadable": True,
                "driver": "systemd",
                "version": "2",
            },
            "lsm": {
                "names": ["capability"] if failed else ["capability", "landlock"],
                "landlockPresent": not failed,
                "source": "host.lsm",
            },
            "engine": {
                "engineVersion": "29.1.3",
                "defaultRuntime": "runc",
                "cgroupDriver": "systemd",
                "cgroupVersion": "2",
                "dockerRootDir": "/var/lib/docker",
            },
            "wslShare": {
                "path": r"\\wsl$\kappa-box-ubuntu-24.04",
                "visibility": "visible" if failed else "missing",
            },
        },
    }


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


def test_landlock_capability_supported_record_matches_schema():
    record = _landlock_record()

    assert list(landlock_validator().iter_errors(record)) == []


def test_landlock_capability_failure_requires_failure_group_and_error():
    record = _landlock_record(status="unreadable")

    assert list(landlock_validator().iter_errors(record)) == []
    record["failureGroups"] = []
    assert list(landlock_validator().iter_errors(record))


def test_readonly_inventory_release_summary_matches_inventory_schema():
    summary = json.loads(
        (
            ROOT / "evidence" / "releases" / "initial-readonly-inventory-summary.json"
        ).read_text(encoding="utf-8")
    )

    errors = list(inventory_validator().iter_errors(summary))

    assert errors == []


def test_landlock_release_summary_matches_landlock_schema():
    summary = json.loads(
        (
            ROOT
            / "evidence"
            / "releases"
            / "landlock-capability-2026-09-12-summary.json"
        ).read_text(encoding="utf-8")
    )

    errors = list(landlock_validator().iter_errors(summary))

    assert errors == []
    assert summary["sourceCommit"] == "a24fcf1"
    assert summary["capability"] == {
        "status": "supported",
        "abiVersion": 7,
        "error": None,
    }
    assert all("stdout" not in command for command in summary["commands"])
    assert all("stderr" not in command for command in summary["commands"])


def test_host_visibility_dedicated_release_summary_matches_host_schema():
    summary = json.loads(
        (
            ROOT / "evidence" / "releases" / "host-visibility-2026-09-12-summary.json"
        ).read_text(encoding="utf-8")
    )

    errors = list(host_observation_validator().iter_errors(summary))

    assert errors == []
    assert summary["sourceCommit"] == "cbc7891"
    assert summary["observations"]["wslConf"]["automountEnabled"] is False
    assert summary["observations"]["wslConf"]["interopEnabled"] is False
    assert summary["observations"]["mounts"]["drvfsPresent"] is False
    assert summary["observations"]["interop"]["enabled"] is False
    assert summary["observations"]["wslShare"]["visibility"] == "visible"
    assert summary["failureGroups"] == ["host"]
    assert "LSM list is unreadable" in summary["groups"][0]["reason"]
    assert "wsl$" in summary["groups"][0]["reason"]
    assert all("stdout" not in command for command in summary["commands"])
    assert all("stderr" not in command for command in summary["commands"])

    schema = load_schema("inventory.schema.json")

    assert schema["properties"]["failureGroups"]["maxItems"] == 0
    assert schema["properties"]["facts"]["type"] == "null"
    assert schema["properties"]["acceptance"]["const"] == "unverified"


def test_host_observation_schema_accepts_unverified_host_failure():
    record = _host_observation_record(result="fail")

    errors = list(host_observation_validator().iter_errors(record))

    assert errors == []


def test_host_observation_schema_rejects_facts_and_verified_acceptance():
    record = _host_observation_record(result="fail")
    record["facts"] = {"kernel": "x"}
    record["acceptance"] = "verified"

    errors = list(host_observation_validator().iter_errors(record))

    assert errors


def test_host_observation_schema_rejects_fail_without_failure_groups():
    record = _host_observation_record(result="fail")
    record["failureGroups"] = []

    errors = list(host_observation_validator().iter_errors(record))

    assert errors


def test_host_observation_schema_rejects_pass_with_failure_groups():
    record = _host_observation_record(result="pass")
    record["failureGroups"] = ["host"]

    errors = list(host_observation_validator().iter_errors(record))

    assert errors


def test_host_observation_schema_accepts_unreadable_wsl_share():
    record = _host_observation_record(result="fail")
    record["observations"]["wslShare"] = {
        "path": r"\\wsl$\kappa-box-ubuntu-24.04",
        "visibility": "unreadable",
    }

    errors = list(host_observation_validator().iter_errors(record))

    assert errors == []


def test_host_observation_schema_rejects_boolean_only_wsl_share():
    record = _host_observation_record(result="fail")
    record["observations"]["wslShare"] = {
        "path": r"\\wsl$\kappa-box-ubuntu-24.04",
        "visible": True,
    }

    errors = list(host_observation_validator().iter_errors(record))

    assert errors


def test_host_observation_schema_requires_command_truncated_flag():
    record = _host_observation_record(result="fail")
    for command in record["commands"]:
        command.pop("truncated", None)

    errors = list(host_observation_validator().iter_errors(record))

    assert errors


def test_host_observation_schema_accepts_truncated_command_flag():
    record = _host_observation_record(result="fail")
    for command in record["commands"]:
        command["truncated"] = False
    record["commands"][6]["truncated"] = True

    errors = list(host_observation_validator().iter_errors(record))

    assert errors == []


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
        pins={"image": "sha256:" + "a" * 64},
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
            "distribution": "kappa-box-ubuntu-24.04",
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


def test_runtime_vertical_slice_schema_rejects_verified_acceptance():
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

    assert list(runtime_vertical_slice_validator().iter_errors(record))


def test_operation_outcome_schema_accepts_refused_profile_unverified():
    record = {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
    }

    assert list(operation_outcome_validator().iter_errors(record)) == []


def test_operation_outcome_schema_accepts_failed_after_execution():
    record = {
        "kind": "failed",
        "code": "provisioning_failed",
        "sideEffects": "present",
        "reconcile": False,
    }

    assert list(operation_outcome_validator().iter_errors(record)) == []


def test_operation_outcome_schema_accepts_unknown_unreconciled():
    record = {
        "kind": "unknown",
        "code": "deadline_exceeded",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }

    assert list(operation_outcome_validator().iter_errors(record)) == []


def test_operation_outcome_schema_accepts_unknown_host_unreachable():
    record = {
        "kind": "unknown",
        "code": "host_unreachable",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }

    assert list(operation_outcome_validator().iter_errors(record)) == []


def test_operation_outcome_schema_rejects_refused_with_side_effects():
    record = {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "present",
        "reconcile": False,
    }

    assert list(operation_outcome_validator().iter_errors(record))


def test_operation_outcome_schema_rejects_failed_profile_unverified():
    record = {
        "kind": "failed",
        "code": "profile_unverified",
        "sideEffects": "present",
        "reconcile": False,
    }

    assert list(operation_outcome_validator().iter_errors(record))


def test_operation_outcome_schema_rejects_unknown_without_reconcile():
    record = {
        "kind": "unknown",
        "code": "deadline_exceeded",
        "sideEffects": "unreconciled",
        "reconcile": False,
    }

    assert list(operation_outcome_validator().iter_errors(record))


def test_operation_outcome_schema_rejects_cross_component_envelope_fields():
    record = {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
        "sideEffect": "none",
        "operation": "sandboxes.create",
        "requestId": "req-1",
    }

    assert list(operation_outcome_validator().iter_errors(record))
