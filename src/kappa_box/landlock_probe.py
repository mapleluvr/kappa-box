"""Read-only Landlock capability probe for the first WSL2 profile."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from kappa_box.probes import CommandExecutor, landlock_command_specs


def redact_landlock_capability(record: dict[str, Any]) -> dict[str, Any]:
    """Return a command metadata summary without command streams."""
    summary = {key: value for key, value in record.items() if key != "commands"}
    summary["commands"] = [
        {
            key: command[key]
            for key in (
                "name",
                "argv",
                "returncode",
                "duration_ms",
                "timed_out",
                "truncated",
            )
        }
        for command in record["commands"]
    ]
    return summary


def write_landlock_capability_evidence(
    record: dict[str, Any],
    *,
    raw_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Write ignored raw output and a commit-safe release summary."""
    summary = redact_landlock_capability(record)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


_FIRST_PROFILE = "wsl2:l1@openshell-docker"
_FIRST_PROFILE_DISTRIBUTION = "kappa-box-ubuntu-24.04"
_PROBE_SUITE_VERSION = "0.1.0-landlock-capability"
_LANDLOCK_RESULT = re.compile(r"^(abi|errno):(\d+)$")
_UNSUPPORTED_ERRNOS = {38, 95}  # ENOSYS, EOPNOTSUPP


def collect_landlock_capability(
    profile_id: str,
    *,
    executor: CommandExecutor,
    collected_at: str,
    source_commit: str,
    distribution: str = _FIRST_PROFILE_DISTRIBUTION,
) -> dict[str, Any]:
    """Read the kernel Landlock ABI without making an acceptance claim."""
    if profile_id != _FIRST_PROFILE:
        raise ValueError(f"unsupported Landlock profile: {profile_id}")
    if distribution != _FIRST_PROFILE_DISTRIBUTION:
        raise ValueError("distribution is not the registered distribution")
    if not source_commit:
        raise ValueError("source_commit must be non-empty")
    executor_distribution = getattr(executor, "distribution", distribution)
    if executor_distribution != distribution:
        raise ValueError("executor distribution does not match registered distribution")

    spec = landlock_command_specs(distribution)[0]
    command = executor.run(spec.name, spec.argv, spec.timeout_seconds)
    if command.name != spec.name or command.argv != spec.argv:
        raise ValueError(
            f"executor result does not match registered command: {spec.name}"
        )
    command_record = {
        "name": command.name,
        "argv": list(command.argv),
        "returncode": command.returncode,
        "stdout": command.stdout,
        "stderr": command.stderr,
        "duration_ms": command.duration_ms,
        "timed_out": command.timed_out,
        "truncated": command.truncated,
    }
    capability = _parse_capability(command_record)
    failure_groups = [] if capability["status"] == "supported" else ["landlock"]
    return {
        "profileId": profile_id,
        "collectedAt": collected_at,
        "acceptance": "unverified",
        "probeStatus": "landlock_capability",
        "probeSuiteVersion": _PROBE_SUITE_VERSION,
        "sourceCommit": source_commit,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": failure_groups,
        "capability": capability,
        "commands": [command_record],
    }


def _parse_capability(command: dict[str, Any]) -> dict[str, Any]:
    if command["timed_out"] or command["returncode"] != 0:
        return {
            "status": "unreadable",
            "abiVersion": None,
            "error": "command failed",
        }
    if command.get("truncated"):
        return {
            "status": "unreadable",
            "abiVersion": None,
            "error": "command output is truncated",
        }
    match = _LANDLOCK_RESULT.fullmatch(str(command.get("stdout") or "").strip())
    if match is None:
        return {
            "status": "unreadable",
            "abiVersion": None,
            "error": "invalid capability output",
        }
    kind, raw_value = match.groups()
    value = int(raw_value)
    if kind == "abi" and value >= 1:
        return {"status": "supported", "abiVersion": value, "error": None}
    if kind == "errno" and value in _UNSUPPORTED_ERRNOS:
        return {
            "status": "unsupported",
            "abiVersion": None,
            "error": f"errno:{value}",
        }
    return {
        "status": "unreadable",
        "abiVersion": None,
        "error": "invalid capability result",
    }
