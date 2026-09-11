from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from kappa_box.probes import (
    CommandResult,
    SubprocessExecutor,
    _bounded_text,
    collect_readonly_inventory,
    default_command_specs,
)
from kappa_box.profile import validate_profile_identity

ROOT = Path(__file__).parents[2]


@dataclass
class FakeExecutor:
    results: dict[str, CommandResult]

    def run(
        self, name: str, argv: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        recorded = self.results[name]
        return CommandResult(
            name=recorded.name,
            argv=argv,
            returncode=recorded.returncode,
            stdout=recorded.stdout,
            stderr=recorded.stderr,
            duration_ms=recorded.duration_ms,
            timed_out=recorded.timed_out,
        )


def result(name: str, *, returncode: int = 0, stdout: str = "ok") -> CommandResult:
    return CommandResult(
        name=name,
        argv=("tool", name),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        duration_ms=1,
        timed_out=False,
    )


def test_profile_identity_requires_variant_to_match_id():
    profile = {
        "id": "wsl2:l1@openshell-docker",
        "hostClass": "wsl2",
        "tier": "l1",
        "variant": "oci-direct",
    }

    with pytest.raises(ValueError, match="does not match variant"):
        validate_profile_identity(profile)


def test_profile_identity_rejects_variant_without_id_variant():
    with pytest.raises(ValueError, match="variant is present"):
        validate_profile_identity(
            {
                "id": "linux:l1",
                "hostClass": "linux",
                "tier": "l1",
                "variant": "podman-rootless",
            }
        )


def test_profile_identity_accepts_matching_id_fields():
    validate_profile_identity(
        {
            "id": "wsl2:l1@openshell-docker",
            "hostClass": "wsl2",
            "tier": "l1",
            "variant": "openshell-docker",
        }
    )


def test_registry_profile_identity_is_valid():
    profile = json.loads(
        (ROOT / "profiles" / "registry" / "wsl2-l1-openshell-docker.json").read_text(
            encoding="utf-8"
        )
    )

    validate_profile_identity(profile)


def test_bounded_text_decodes_utf16le_output_from_wsl():
    assert (
        _bounded_text("WSL 2.7.11.0\r\n".encode("utf-16le"), 1024) == "WSL 2.7.11.0\r\n"
    )


def test_inventory_uses_only_fixed_read_only_commands():
    specs = default_command_specs("Ubuntu-24.04")
    executor = FakeExecutor({spec.name: result(spec.name) for spec in specs})

    inventory = collect_readonly_inventory(
        "wsl2:l1@openshell-docker",
        executor=executor,
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
    )

    assert inventory["probeSuiteVersion"] == "0.1.0-inventory"
    assert inventory["sourceCommit"] == "test-commit"
    assert inventory["facts"] is None
    assert inventory["factsDigest"] is None
    assert inventory["pins"] is None
    assert inventory["failureGroups"] == []
    assert [command["name"] for command in inventory["commands"]] == [
        "wsl.version",
        "wsl.list",
        "wsl.kernel",
        "wsl.conf",
        "docker.version",
        "docker.info",
    ]
    assert all(command["argv"] for command in inventory["commands"])
    assert inventory["commands"][-1]["argv"] == [
        "wsl.exe",
        "-d",
        "Ubuntu-24.04",
        "--",
        "docker",
        "info",
    ]


def test_inventory_rejects_executor_result_with_wrong_command_identity():
    class LyingExecutor:
        distribution = "Ubuntu-24.04"

        def run(
            self, name: str, argv: tuple[str, ...], timeout_seconds: float
        ) -> CommandResult:
            return CommandResult(
                name="spoofed",
                argv=("sh", "-c", "echo unsafe"),
                returncode=0,
                stdout="ok",
                stderr="",
                duration_ms=1,
                timed_out=False,
            )

    with pytest.raises(ValueError, match="result does not match registered command"):
        collect_readonly_inventory(
            "wsl2:l1@openshell-docker",
            executor=LyingExecutor(),
            collected_at="2026-09-11T12:00:00Z",
            source_commit="test-commit",
        )


def test_subprocess_executor_bounds_os_error_output(monkeypatch):
    from kappa_box import probes

    def fail(*args, **kwargs):
        raise OSError("x" * 1000)

    monkeypatch.setattr(probes.subprocess, "run", fail)
    result = SubprocessExecutor(max_output_bytes=16).run(
        "wsl.version", ("wsl.exe", "--version"), 30.0
    )

    assert result.returncode == 127
    assert len(result.stderr.encode("utf-8")) <= 16


def test_inventory_retains_command_failures_without_claiming_profile_failure():
    specs = default_command_specs("Ubuntu-24.04")
    results = {
        spec.name: result(
            spec.name,
            returncode=1 if spec.name == "docker.info" else 0,
            stdout="",
        )
        for spec in specs
    }
    results["docker.info"] = CommandResult(
        name="docker.info",
        argv=("wsl.exe", "-d", "Ubuntu-24.04", "--", "docker", "info"),
        returncode=1,
        stdout="",
        stderr="daemon unavailable",
        duration_ms=2,
        timed_out=False,
    )

    inventory = collect_readonly_inventory(
        "wsl2:l1@openshell-docker",
        executor=FakeExecutor(results),
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
    )

    docker_info = next(
        command for command in inventory["commands"] if command["name"] == "docker.info"
    )
    assert docker_info["returncode"] == 1
    assert docker_info["stderr"] == "daemon unavailable"
    assert inventory["acceptance"] == "unverified"
    assert inventory["probeStatus"] == "inventory_only"


def test_inventory_rejects_non_registered_distribution():
    specs = default_command_specs("Ubuntu-24.04")
    executor = FakeExecutor({spec.name: result(spec.name) for spec in specs})

    with pytest.raises(ValueError, match="registered distribution"):
        collect_readonly_inventory(
            "wsl2:l1@openshell-docker",
            executor=executor,
            collected_at="2026-09-11T12:00:00Z",
            source_commit="test-commit",
            distribution="Other-Distro",
        )


def test_subprocess_executor_rejects_non_registered_distribution():
    from kappa_box.probes import SubprocessExecutor

    with pytest.raises(ValueError, match="registered distribution"):
        SubprocessExecutor(distribution="Other-Distro")


def test_subprocess_executor_rejects_commands_outside_fixed_registry():
    from kappa_box.probes import SubprocessExecutor

    executor = SubprocessExecutor()

    with pytest.raises(ValueError, match="not registered"):
        executor.run("arbitrary", ("sh", "-c", "echo unsafe"), 30.0)
