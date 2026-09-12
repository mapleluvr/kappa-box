from __future__ import annotations

from dataclasses import dataclass

import pytest

from kappa_box.landlock_probe import collect_landlock_capability
from kappa_box.probes import (
    LANDLOCK_ABI_SCRIPT,
    CommandResult,
    landlock_command_specs,
)

PROFILE_ID = "wsl2:l1@openshell-docker"
DISTRIBUTION = "kappa-box-ubuntu-24.04"


@dataclass
class FakeExecutor:
    result: CommandResult
    distribution: str = DISTRIBUTION

    def run(
        self, name: str, argv: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        return CommandResult(
            name=self.result.name,
            argv=argv,
            returncode=self.result.returncode,
            stdout=self.result.stdout,
            stderr=self.result.stderr,
            duration_ms=self.result.duration_ms,
            timed_out=self.result.timed_out,
            truncated=self.result.truncated,
        )


def command_result(
    *,
    stdout: str,
    returncode: int = 0,
    stderr: str = "",
    timed_out: bool = False,
    truncated: bool = False,
) -> CommandResult:
    spec = landlock_command_specs(DISTRIBUTION)[0]
    return CommandResult(
        name=spec.name,
        argv=spec.argv,
        returncode=124 if timed_out else returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=timed_out,
        truncated=truncated,
    )


def collect(result: CommandResult) -> dict:
    return collect_landlock_capability(
        PROFILE_ID,
        executor=FakeExecutor(result),
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
    )


def test_landlock_command_uses_fixed_non_shell_argv():
    spec = landlock_command_specs(DISTRIBUTION)[0]

    assert spec.name == "host.landlock.abi"
    assert spec.argv == (
        "wsl.exe",
        "-d",
        DISTRIBUTION,
        "--",
        "/usr/bin/python3",
        "-c",
        LANDLOCK_ABI_SCRIPT,
    )
    assert "sh" not in spec.argv
    assert "-c" in spec.argv


def test_supported_landlock_abi_is_recorded_without_acceptance_claim():
    record = collect(command_result(stdout="abi:7\n"))

    assert record["probeStatus"] == "landlock_capability"
    assert record["acceptance"] == "unverified"
    assert record["capability"] == {
        "status": "supported",
        "abiVersion": 7,
        "error": None,
    }
    assert record["facts"] is None
    assert record["factsDigest"] is None
    assert record["pins"] is None
    assert record["failureGroups"] == []


def test_landlock_unsupported_errno_is_distinguished_from_unreadable():
    record = collect(command_result(stdout="errno:38\n"))

    assert record["capability"] == {
        "status": "unsupported",
        "abiVersion": None,
        "error": "errno:38",
    }


def test_landlock_unsupported_eopnotsupp_is_distinguished_from_unreadable():
    record = collect(command_result(stdout="errno:95\n"))

    assert record["capability"] == {
        "status": "unsupported",
        "abiVersion": None,
        "error": "errno:95",
    }
    assert record["failureGroups"] == ["landlock"]

    record = collect(
        command_result(returncode=1, stdout="", stderr="python3: unavailable")
    )

    assert record["capability"] == {
        "status": "unreadable",
        "abiVersion": None,
        "error": "command failed",
    }


def test_landlock_probe_fails_closed_on_truncated_output():
    record = collect(command_result(stdout="abi:7\n", truncated=True))

    assert record["capability"] == {
        "status": "unreadable",
        "abiVersion": None,
        "error": "command output is truncated",
    }


def test_landlock_probe_rejects_result_with_wrong_command_identity():
    class LyingExecutor(FakeExecutor):
        def run(
            self, name: str, argv: tuple[str, ...], timeout_seconds: float
        ) -> CommandResult:
            return CommandResult(
                name="spoofed",
                argv=("sh", "-c", "echo unsafe"),
                returncode=0,
                stdout="abi:7",
                stderr="",
                duration_ms=1,
                timed_out=False,
            )

    with pytest.raises(ValueError, match="result does not match registered command"):
        collect_landlock_capability(
            PROFILE_ID,
            executor=LyingExecutor(command_result(stdout="abi:7")),
            collected_at="2026-09-11T12:00:00Z",
            source_commit="test-commit",
        )
