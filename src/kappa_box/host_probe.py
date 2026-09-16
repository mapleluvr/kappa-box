"""Read-only host isolation visibility for the first WSL2 profile."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from kappa_box.probes import (
    CommandExecutor,
    CommandSpec,
    host_visibility_command_specs,
)

_FIRST_PROFILE = "wsl2:l1@openshell-docker"
_FIRST_PROFILE_DISTRIBUTION = "kappa-box-ubuntu-24.04"
_PROBE_SUITE_VERSION = "0.1.0-host-visibility"
WSL_SHARE_PATH = r"\\wsl$\kappa-box-ubuntu-24.04"
ALLOW_WSL_SHARE_ENV = "KAPPA_BOX_ALLOW_WSL_SHARE"
_REQUIRED_CONTROLLERS = ("cpu", "memory", "pids")
_DRIVE_MOUNT = re.compile(r"^/mnt/[a-zA-Z]$")
_SENSITIVE_DOCKER_KEYS = ("Name", "ID", "HTTP Proxy", "HTTPS Proxy")


ShareVisibility = Literal["visible", "missing", "unreadable"]
_SHARE_STATES = {"visible", "missing", "unreadable"}


class ShareVisibilityChecker(Protocol):
    def observe(self, path: str) -> ShareVisibility: ...


class PathShareVisibilityChecker:
    """Check the registered WSL share path without taking caller paths."""

    def observe(self, path: str) -> ShareVisibility:
        if path != WSL_SHARE_PATH:
            raise ValueError("wsl share path is not registered")
        try:
            Path(WSL_SHARE_PATH).stat()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "unreadable"
        return "visible"


@dataclass(frozen=True)
class CheckOutcome:
    name: str
    passed: bool
    reason: str


def collect_host_visibility(
    profile_id: str,
    *,
    executor: CommandExecutor,
    collected_at: str,
    source_commit: str,
    distribution: str = _FIRST_PROFILE_DISTRIBUTION,
    share_checker: ShareVisibilityChecker | None = None,
) -> dict[str, Any]:
    """Run closed host-visibility commands and judge the host group.

    The record stays ``unverified`` and never writes facts or pins. A host
    group failure is evidence, not profile acceptance.
    """
    if profile_id != _FIRST_PROFILE:
        raise ValueError(f"unsupported host visibility profile: {profile_id}")
    if distribution != _FIRST_PROFILE_DISTRIBUTION:
        raise ValueError("distribution is not the registered distribution")
    if not source_commit:
        raise ValueError("source_commit must be non-empty")
    executor_distribution = getattr(executor, "distribution", distribution)
    if executor_distribution != distribution:
        raise ValueError("executor distribution does not match registered distribution")

    checker = share_checker or PathShareVisibilityChecker()
    commands = _run_commands(executor, host_visibility_command_specs(distribution))
    by_name = {command["name"]: command for command in commands}
    observations, checks = _observe_and_judge(
        by_name,
        checker,
        allow_wsl_share=_allow_wsl_share(),
    )
    failed = [check for check in checks if not check.passed]
    if failed:
        group = {
            "name": "host",
            "result": "fail",
            "reason": "; ".join(check.reason for check in failed),
        }
        failure_groups = ["host"]
    else:
        group = {
            "name": "host",
            "result": "pass",
            "reason": "host isolation visibility checks passed",
        }
        failure_groups = []

    return {
        "profileId": profile_id,
        "collectedAt": collected_at,
        "acceptance": "unverified",
        "probeStatus": "host_visibility",
        "probeSuiteVersion": _PROBE_SUITE_VERSION,
        "sourceCommit": source_commit,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": failure_groups,
        "groups": [group],
        "commands": commands,
        "observations": observations,
    }


def redact_host_observation(record: dict[str, Any]) -> dict[str, Any]:
    """Return a commit-safe copy with command streams and secrets removed."""
    summary = {key: value for key, value in record.items() if key != "commands"}
    summary["commands"] = [
        {
            "name": command["name"],
            "argv": list(command["argv"]),
            "returncode": command["returncode"],
            "timed_out": command["timed_out"],
            "truncated": bool(command.get("truncated")),
        }
        for command in record["commands"]
    ]
    blob = json.dumps(summary)
    leaked = [value for value in _sensitive_values(record["commands"]) if value in blob]
    if leaked:
        raise ValueError(
            f"host visibility summary leaked sensitive values: {leaked[0]}"
        )
    return summary


def write_host_visibility_evidence(
    record: dict[str, Any],
    *,
    raw_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Write gitignored raw JSON and a redacted release summary."""
    summary = redact_host_observation(record)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _run_commands(
    executor: CommandExecutor, specs: tuple[CommandSpec, ...]
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    for spec in specs:
        command = executor.run(spec.name, spec.argv, spec.timeout_seconds)
        if command.name != spec.name or command.argv != spec.argv:
            raise ValueError(
                f"executor result does not match registered command: {spec.name}"
            )
        command_record = asdict(command)
        command_record["argv"] = list(command.argv)
        commands.append(command_record)
    return commands


def _allow_wsl_share() -> bool:
    value = os.environ.get(ALLOW_WSL_SHARE_ENV)
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _observe_and_judge(
    commands: dict[str, dict[str, Any]],
    share_checker: ShareVisibilityChecker,
    *,
    allow_wsl_share: bool = False,
) -> tuple[dict[str, Any], list[CheckOutcome]]:
    kernel = _parse_kernel(commands["wsl.kernel"])
    distro = _parse_distro(commands["wsl.version"], commands["wsl.list"])
    wsl_conf = _parse_wsl_conf(commands["wsl.conf"])
    mounts = _parse_mounts(commands["host.mountinfo"])
    interop = _parse_interop(commands["host.interop"])
    cgroup = _parse_cgroup(
        commands["host.cgroup.controllers"],
        commands["host.cgroup.subtree"],
        commands["docker.info"],
    )
    lsm = _parse_lsm(commands["host.lsm"], commands["host.lsm.proc"])
    engine = _parse_engine(commands["docker.version"], commands["docker.info"])
    wsl_share = _parse_wsl_share(share_checker, allow_wsl_share=allow_wsl_share)

    observations = {
        "kernel": kernel,
        "distro": distro,
        "wslConf": wsl_conf,
        "mounts": mounts,
        "interop": interop,
        "cgroup": cgroup,
        "lsm": lsm,
        "engine": engine,
        "wslShare": wsl_share,
    }
    checks = [
        *_wsl_conf_checks(commands["wsl.conf"], wsl_conf),
        _mounts_check(commands["host.mountinfo"], mounts),
        _interop_check(interop),
        _cgroup_controllers_check(commands["host.cgroup.controllers"], cgroup),
        _cgroup_subtree_check(commands["host.cgroup.subtree"], cgroup),
        _lsm_check(lsm),
        _wsl_share_check(wsl_share),
    ]
    return observations, checks


def _command_readable(command: dict[str, Any]) -> bool:
    return (
        not command["timed_out"]
        and command["returncode"] == 0
        and bool(str(command.get("stdout") or "").strip())
    )


def _parse_kernel(command: dict[str, Any]) -> str | None:
    if not _command_readable(command):
        return None
    kernel = str(command["stdout"]).strip()
    return kernel or None


def _parse_distro(
    version_command: dict[str, Any], list_command: dict[str, Any]
) -> dict[str, Any]:
    wsl_version = None
    windows_version = None
    for line in str(version_command.get("stdout") or "").splitlines():
        stripped = line.strip()
        if re.match(r"^WSL\s*(版本|version)\s*:", stripped, re.IGNORECASE):
            wsl_version = stripped.split(":", 1)[1].strip() or None
        elif re.match(r"^Windows(\s*(版本|version))?\s*:", stripped, re.IGNORECASE):
            windows_version = stripped.split(":", 1)[1].strip() or None

    state = None
    siblings: list[str] = []
    for line in str(list_command.get("stdout") or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.upper().startswith("NAME"):
            continue
        if stripped.startswith("*"):
            stripped = stripped[1:].strip()
        parts = stripped.split()
        if len(parts) < 3:
            continue
        name, distro_state, _version = parts[0], parts[1], parts[2]
        if name == _FIRST_PROFILE_DISTRIBUTION:
            state = distro_state
        else:
            siblings.append(name)
    return {
        "name": _FIRST_PROFILE_DISTRIBUTION,
        "wslVersion": wsl_version,
        "windowsVersion": windows_version,
        "state": state,
        "siblings": siblings,
    }


def _parse_wsl_conf(command: dict[str, Any]) -> dict[str, Any]:
    present_keys: list[str] = []
    values: dict[str, str] = {}
    if _command_readable(command) or (
        not command["timed_out"] and command["returncode"] == 0
    ):
        section = None
        for raw in str(command.get("stdout") or "").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().lower()
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().lower()
            full_key = f"{section}.{key}" if section else key
            present_keys.append(full_key)
            values[full_key] = value.strip()
    return {
        "systemd": _ini_bool(values.get("boot.systemd")),
        "automountEnabled": _ini_bool(values.get("automount.enabled")),
        "interopEnabled": _ini_bool(values.get("interop.enabled")),
        "presentKeys": present_keys,
    }


def _ini_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _parse_mounts(command: dict[str, Any]) -> dict[str, Any]:
    drive_mounts: list[str] = []
    drvfs_present = False
    if _command_readable(command):
        for line in str(command["stdout"]).splitlines():
            stripped = line.strip()
            if " - " not in stripped:
                continue
            left, right = stripped.split(" - ", 1)
            left_parts = left.split()
            right_parts = right.split()
            if len(left_parts) < 5 or not right_parts:
                continue
            mountpoint = left_parts[4]
            fstype = right_parts[0]
            super_options = right_parts[2] if len(right_parts) > 2 else ""
            if (
                fstype == "drvfs"
                or "drvfs" in super_options
                or "aname=drvfs" in super_options
            ):
                drvfs_present = True
            if _DRIVE_MOUNT.fullmatch(mountpoint) and mountpoint not in drive_mounts:
                drive_mounts.append(mountpoint)
                drvfs_present = True
    return {
        "windowsDriveMounts": drive_mounts,
        "drvfsPresent": drvfs_present,
    }


def _parse_interop(command: dict[str, Any]) -> dict[str, Any]:
    stderr = str(command.get("stderr") or "")
    if command["timed_out"]:
        return {"wslInteropFile": "unreadable", "enabled": None}
    if command["returncode"] == 0:
        return {"wslInteropFile": "present", "enabled": True}
    if command["returncode"] != 0 and "no such file" in stderr.lower():
        return {"wslInteropFile": "missing", "enabled": False}
    return {"wslInteropFile": "unreadable", "enabled": None}


def _parse_cgroup(
    controllers_command: dict[str, Any],
    subtree_command: dict[str, Any],
    docker_info: dict[str, Any],
) -> dict[str, Any]:
    controllers_readable = _command_readable(controllers_command)
    subtree_readable = (
        not subtree_command["timed_out"] and subtree_command["returncode"] == 0
    )
    controllers = (
        str(controllers_command.get("stdout") or "").split()
        if controllers_readable
        else []
    )
    subtree = (
        str(subtree_command.get("stdout") or "").split() if subtree_readable else []
    )
    info_fields = _docker_info_fields(docker_info)
    return {
        "controllers": controllers,
        "subtreeControl": subtree,
        "controllersReadable": controllers_readable,
        "subtreeReadable": subtree_readable,
        "driver": info_fields.get("Cgroup Driver"),
        "version": info_fields.get("Cgroup Version"),
    }


def _parse_lsm(primary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    for source, command in (("host.lsm", primary), ("host.lsm.proc", fallback)):
        if _command_readable(command):
            names = [
                name
                for name in str(command["stdout"]).strip().replace(" ", "").split(",")
                if name
            ]
            return {
                "names": names,
                "landlockPresent": "landlock" in names,
                "source": source,
            }
    return {"names": [], "landlockPresent": None, "source": None}


def _parse_engine(
    version_command: dict[str, Any], info_command: dict[str, Any]
) -> dict[str, Any]:
    info_fields = _docker_info_fields(info_command)
    return {
        "engineVersion": _docker_engine_version(version_command)
        or info_fields.get("Server Version"),
        "defaultRuntime": info_fields.get("Default Runtime"),
        "cgroupDriver": info_fields.get("Cgroup Driver"),
        "cgroupVersion": info_fields.get("Cgroup Version"),
        "dockerRootDir": info_fields.get("Docker Root Dir"),
    }


def _docker_engine_version(command: dict[str, Any]) -> str | None:
    in_server = False
    in_engine = False
    for line in str(command.get("stdout") or "").splitlines():
        stripped = line.strip()
        if stripped == "Server:":
            in_server = True
            in_engine = False
            continue
        if in_server and stripped == "Engine:":
            in_engine = True
            continue
        if in_server and in_engine and stripped.startswith("Version:"):
            return stripped.split(":", 1)[1].strip() or None
        if (
            in_server
            and stripped.endswith(":")
            and not line[:1].isspace()
            and stripped != "Engine:"
        ):
            in_server = False
            in_engine = False
    return None


def _docker_info_fields(command: dict[str, Any]) -> dict[str, str]:
    wanted = {
        "Server Version",
        "Cgroup Driver",
        "Cgroup Version",
        "Default Runtime",
        "Docker Root Dir",
    }
    fields: dict[str, str] = {}
    for line in str(command.get("stdout") or "").splitlines():
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        if key in wanted:
            fields[key] = value.strip()
    return fields


def _parse_wsl_share(
    share_checker: ShareVisibilityChecker,
    *,
    allow_wsl_share: bool = False,
) -> dict[str, Any]:
    try:
        visibility = share_checker.observe(WSL_SHARE_PATH)
    except OSError:
        visibility = "unreadable"
    if visibility not in _SHARE_STATES:
        visibility = "unreadable"
    record: dict[str, Any] = {"path": WSL_SHARE_PATH, "visibility": visibility}
    if allow_wsl_share:
        record["enforced"] = False
        record["waivedBy"] = ALLOW_WSL_SHARE_ENV
    return record


def _wsl_conf_checks(
    command: dict[str, Any], parsed: dict[str, Any]
) -> list[CheckOutcome]:
    if command["timed_out"] or command["returncode"] != 0:
        return [
            CheckOutcome(
                "wsl.conf",
                False,
                "wsl.conf is unreadable",
            )
        ]
    checks = []
    if parsed["automountEnabled"] is not False:
        checks.append(
            CheckOutcome(
                "wsl.conf.automount",
                False,
                "wsl.conf automount.enabled is not false",
            )
        )
    if parsed["interopEnabled"] is not False:
        checks.append(
            CheckOutcome(
                "wsl.conf.interop",
                False,
                "wsl.conf interop.enabled is not false",
            )
        )
    return checks


def _mounts_check(command: dict[str, Any], parsed: dict[str, Any]) -> CheckOutcome:
    if command["timed_out"] or command["returncode"] != 0:
        return CheckOutcome("mounts.drvfs", False, "mountinfo is unreadable")
    if command.get("truncated"):
        return CheckOutcome("mounts.drvfs", False, "mountinfo output is truncated")
    if parsed["drvfsPresent"] or parsed["windowsDriveMounts"]:
        mounts = ",".join(parsed["windowsDriveMounts"]) or "drvfs"
        return CheckOutcome(
            "mounts.drvfs",
            False,
            f"mountinfo contains drvfs or Windows drive mounts: {mounts}",
        )
    return CheckOutcome("mounts.drvfs", True, "no drvfs or Windows drive mounts")


def _interop_check(parsed: dict[str, Any]) -> CheckOutcome:
    if parsed["wslInteropFile"] == "missing" and parsed["enabled"] is False:
        return CheckOutcome("interop.wslinterop", True, "WSLInterop file is absent")
    if parsed["wslInteropFile"] == "present":
        return CheckOutcome("interop.wslinterop", False, "WSLInterop is enabled")
    return CheckOutcome("interop.wslinterop", False, "WSLInterop is unreadable")


def _cgroup_controllers_check(
    command: dict[str, Any], parsed: dict[str, Any]
) -> CheckOutcome:
    if not parsed["controllersReadable"]:
        detail = "timed out" if command["timed_out"] else "unreadable"
        return CheckOutcome(
            "cgroup.controllers",
            False,
            f"cgroup.controllers is {detail}",
        )
    missing = [
        name for name in _REQUIRED_CONTROLLERS if name not in parsed["controllers"]
    ]
    if missing:
        return CheckOutcome(
            "cgroup.controllers",
            False,
            "cgroup.controllers missing required controllers: " + ",".join(missing),
        )
    return CheckOutcome(
        "cgroup.controllers",
        True,
        "cgroup.controllers includes cpu, memory, and pids",
    )


def _cgroup_subtree_check(
    command: dict[str, Any], parsed: dict[str, Any]
) -> CheckOutcome:
    if command["timed_out"] or command["returncode"] != 0:
        return CheckOutcome(
            "cgroup.subtree",
            False,
            "cgroup.subtree_control is unreadable",
        )
    missing = [
        name for name in _REQUIRED_CONTROLLERS if name not in parsed["subtreeControl"]
    ]
    if missing:
        return CheckOutcome(
            "cgroup.subtree",
            False,
            "cgroup.subtree_control missing required controllers: " + ",".join(missing),
        )
    return CheckOutcome(
        "cgroup.subtree",
        True,
        "cgroup.subtree_control includes cpu, memory, and pids",
    )


def _lsm_check(parsed: dict[str, Any]) -> CheckOutcome:
    if parsed["source"] is None:
        return CheckOutcome("lsm.landlock", False, "LSM list is unreadable")
    if not parsed["landlockPresent"]:
        return CheckOutcome(
            "lsm.landlock",
            False,
            "LSM list does not include landlock",
        )
    return CheckOutcome("lsm.landlock", True, "LSM list includes landlock")


def _wsl_share_check(parsed: dict[str, Any]) -> CheckOutcome:
    visibility = parsed["visibility"]
    if parsed.get("enforced") is False:
        return CheckOutcome(
            "wsl.share",
            True,
            f"wsl.share waived by {ALLOW_WSL_SHARE_ENV}; {WSL_SHARE_PATH} is {visibility}",
        )
    if visibility == "missing":
        return CheckOutcome(
            "wsl.share",
            True,
            f"{WSL_SHARE_PATH} is not visible from Windows",
        )
    if visibility == "visible":
        return CheckOutcome(
            "wsl.share",
            False,
            f"{WSL_SHARE_PATH} is visible from Windows",
        )
    return CheckOutcome(
        "wsl.share",
        False,
        f"{WSL_SHARE_PATH} is unreadable",
    )


def _sensitive_values(commands: list[dict[str, Any]]) -> set[str]:
    values: set[str] = set()
    by_name = {command["name"]: command for command in commands}
    info = str(by_name.get("docker.info", {}).get("stdout") or "")
    for line in info.splitlines():
        stripped = line.strip()
        for key in _SENSITIVE_DOCKER_KEYS:
            prefix = f"{key}:"
            if stripped.startswith(prefix):
                value = stripped.split(":", 1)[1].strip()
                if value:
                    values.add(value)
    conf = str(by_name.get("wsl.conf", {}).get("stdout") or "")
    for line in conf.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("default="):
            value = stripped.split("=", 1)[1].strip()
            if value:
                values.add(value)
    return values
