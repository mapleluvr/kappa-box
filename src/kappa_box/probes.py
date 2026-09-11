"""Read-only host inventory probes for the first WSL2 profile."""

from __future__ import annotations

import subprocess
import time
from dataclasses import asdict, dataclass
from typing import Any, Protocol

_FIRST_PROFILE = "wsl2:l1@openshell-docker"
_FIRST_PROFILE_DISTRIBUTION = "Ubuntu-24.04"
_PROBE_SUITE_VERSION = "0.1.0-inventory"


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class CommandResult:
    name: str
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool


class CommandExecutor(Protocol):
    def run(
        self, name: str, argv: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        pass


class SubprocessExecutor:
    """Execute the fixed probe commands and bound captured output."""

    def __init__(
        self,
        distribution: str = "Ubuntu-24.04",
        max_output_bytes: int = 64 * 1024,
    ) -> None:
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        if distribution != _FIRST_PROFILE_DISTRIBUTION:
            raise ValueError("distribution is not the registered distribution")
        self._distribution = distribution
        self._allowed_commands = {
            spec.name: spec for spec in default_command_specs(distribution)
        }
        self._max_output_bytes = max_output_bytes

    @property
    def distribution(self) -> str:
        return self._distribution

    def run(
        self, name: str, argv: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        expected = self._allowed_commands.get(name)
        if expected is None or expected.argv != argv:
            raise ValueError(f"probe command is not registered: {name}")
        if expected.timeout_seconds != timeout_seconds:
            raise ValueError(f"probe timeout does not match registration: {name}")

        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
            return CommandResult(
                name=name,
                argv=argv,
                returncode=completed.returncode,
                stdout=_bounded_text(completed.stdout, self._max_output_bytes),
                stderr=_bounded_text(completed.stderr, self._max_output_bytes),
                duration_ms=_duration_ms(started),
                timed_out=False,
            )
        except (subprocess.TimeoutExpired, OSError) as error:
            if isinstance(error, subprocess.TimeoutExpired):
                return CommandResult(
                    name=name,
                    argv=argv,
                    returncode=124,
                    stdout=_bounded_text(
                        _exception_output(error.stdout), self._max_output_bytes
                    ),
                    stderr=_bounded_text(
                        _exception_output(error.stderr), self._max_output_bytes
                    ),
                    duration_ms=_duration_ms(started),
                    timed_out=True,
                )
            return CommandResult(
                name=name,
                argv=argv,
                returncode=127,
                stdout="",
                stderr=str(error),
                duration_ms=_duration_ms(started),
                timed_out=False,
            )


def _duration_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


def _exception_output(data: bytes | str | None) -> bytes | str:
    return b"" if data is None else data


def _bounded_text(data: bytes | str, max_bytes: int) -> str:
    if isinstance(data, bytes):
        bounded = data[:max_bytes]
        if _looks_like_utf16le(bounded):
            return bounded.decode("utf-16le", errors="replace")
        return bounded.decode("utf-8", errors="replace")
    return data.encode("utf-8")[:max_bytes].decode("utf-8", errors="replace")


def _looks_like_utf16le(data: bytes) -> bool:
    return len(data) >= 2 and data[1::2].count(0) > len(data[1::2]) // 2


def default_command_specs(distribution: str) -> tuple[CommandSpec, ...]:
    """Return the fixed read-only inventory commands for one WSL distro."""
    if not distribution or any(char in distribution for char in "\r\n"):
        raise ValueError("distribution must be a non-empty single-line name")

    return (
        CommandSpec("wsl.version", ("wsl.exe", "--version")),
        CommandSpec("wsl.list", ("wsl.exe", "-l", "-v")),
        CommandSpec(
            "wsl.kernel",
            ("wsl.exe", "-d", distribution, "--", "uname", "-r"),
        ),
        CommandSpec(
            "wsl.conf",
            ("wsl.exe", "-d", distribution, "--", "cat", "/etc/wsl.conf"),
        ),
        CommandSpec(
            "docker.version",
            ("wsl.exe", "-d", distribution, "--", "docker", "version"),
        ),
        CommandSpec(
            "docker.info",
            ("wsl.exe", "-d", distribution, "--", "docker", "info"),
        ),
    )


def collect_readonly_inventory(
    profile_id: str,
    *,
    executor: CommandExecutor,
    collected_at: str,
    distribution: str = _FIRST_PROFILE_DISTRIBUTION,
) -> dict[str, Any]:
    """Run fixed host inventory commands without making an acceptance claim.

    This first probe is deliberately inventory-only. It records command
    failures for diagnosis, while acceptance remains ``unverified`` until the
    complete enforcement and behavior suite has passed.
    """
    if profile_id != _FIRST_PROFILE:
        raise ValueError(f"unsupported inventory profile: {profile_id}")
    if distribution != _FIRST_PROFILE_DISTRIBUTION:
        raise ValueError("distribution is not the registered distribution")
    executor_distribution = getattr(executor, "distribution", distribution)
    if executor_distribution != distribution:
        raise ValueError("executor distribution does not match registered distribution")

    commands = []
    for spec in default_command_specs(distribution):
        command = executor.run(spec.name, spec.argv, spec.timeout_seconds)
        command_record = asdict(command)
        command_record["argv"] = list(command.argv)
        commands.append(command_record)

    return {
        "profileId": profile_id,
        "collectedAt": collected_at,
        "acceptance": "unverified",
        "probeStatus": "inventory_only",
        "probeSuiteVersion": _PROBE_SUITE_VERSION,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": [],
        "commands": commands,
    }
