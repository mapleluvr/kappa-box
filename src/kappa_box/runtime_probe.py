"""Evidence-producing orchestration for the real OpenShell Docker slice."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Protocol

from kappa_box.runtime import ExecResult, Sandbox, SandboxRequest, SandboxState

_PROFILE = "wsl2:l1@openshell-docker"
_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)
_PROBE_SUITE_VERSION = "0.1.0-runtime-vertical-slice"
_EVIDENCE_CLASS = "probe_only"
_STAGE_ORDER = ("preflight", "create", "ready", "exec", "stop", "delete")
_SENSITIVE_KEY = re.compile(
    r"(?i)(token|password|passwd|secret|api[_-]?key|private[_-]?key|credential)"
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(authorization\s*:\s*bearer\s+|bearer\s+|"
    r"(?:token|password|passwd|secret|api[_-]?key|private[_-]?key|credential)\s*[:=]\s*)"
    r"[^\s,;]+"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_TOP_LEVEL_FIELDS = {
    "profileId",
    "probeStatus",
    "probeSuiteVersion",
    "evidenceClass",
    "acceptance",
    "sourceCommit",
    "facts",
    "factsDigest",
    "pins",
    "failureGroups",
    "collectedAt",
    "image",
    "stages",
}


class RuntimeSlice(Protocol):
    def preflight(self, *, timeout_seconds: float = 30.0) -> None: ...

    def create(
        self, request: SandboxRequest, *, timeout_seconds: float = 120.0
    ) -> Sandbox: ...

    def wait_ready(
        self, sandbox: Sandbox, *, timeout_seconds: float = 120.0
    ) -> Sandbox: ...

    def exec(
        self,
        sandbox: Sandbox,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float = 120.0,
    ) -> ExecResult: ...

    def stop(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0) -> Sandbox: ...

    def delete(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0) -> Sandbox: ...


def collect_runtime_vertical_slice(
    runtime: RuntimeSlice,
    *,
    profile_id: str,
    source_commit: str,
    collected_at: str,
) -> dict[str, Any]:
    """Run the fixed lifecycle through the real runtime boundary.

    This probe records route and operation behavior but deliberately never
    changes profile acceptance or manufactures facts from adapter responses.
    """
    if profile_id != _PROFILE:
        raise ValueError(f"unsupported runtime profile: {profile_id}")
    if not source_commit:
        raise ValueError("source_commit must be non-empty")
    stages: list[dict[str, Any]] = []
    failure_groups: set[str] = set()
    sandbox: Sandbox | None = None

    def stage(name: str, status: str, **fields: Any) -> None:
        stages.append({"name": name, "status": status, **fields})

    try:
        runtime.preflight()
        stage("preflight", "pass")
        request = SandboxRequest(
            profile_id=profile_id,
            image=_IMAGE,
            command=("/bin/sleep", "300"),
            cpu="1",
            memory="512Mi",
        )
        sandbox = runtime.create(request)
        stage("create", "pass", sandboxName=sandbox.name, state=sandbox.state.value)
        sandbox = runtime.wait_ready(sandbox, timeout_seconds=120.0)
        if sandbox.state is not SandboxState.READY:
            failure_groups.add("lifecycle")
            stage("ready", "fail", state=sandbox.state.value)
        else:
            stage("ready", "pass", state=sandbox.state.value)
            result = runtime.exec(sandbox, ("id",), timeout_seconds=120.0)
            exec_status = (
                "pass" if result.exit_code == 0 and not result.truncated else "fail"
            )
            stage(
                "exec",
                exec_status,
                command=["id"],
                returncode=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                truncated=result.truncated,
            )
            if exec_status == "fail":
                failure_groups.add("channels")
    except Exception as error:  # noqa: BLE001
        failure_groups.add("runtime")
        stage("runtime", "fail", error=type(error).__name__, message=str(error))
    finally:
        if sandbox is not None and sandbox.state is not SandboxState.DELETED:
            if sandbox.state is SandboxState.READY:
                try:
                    sandbox = runtime.stop(sandbox, timeout_seconds=60.0)
                    stage("stop", "pass", state=sandbox.state.value)
                except Exception as error:  # noqa: BLE001
                    failure_groups.add("lifecycle")
                    stage(
                        "stop", "fail", error=type(error).__name__, message=str(error)
                    )
            elif sandbox.state is SandboxState.PROVISIONING:
                failure_groups.add("lifecycle")
                stage("stop", "skipped", reason="sandbox_not_ready")
            if sandbox.state is not SandboxState.DELETED:
                try:
                    sandbox = runtime.delete(sandbox, timeout_seconds=60.0)
                    stage("delete", "pass", state=sandbox.state.value)
                except Exception as error:  # noqa: BLE001
                    failure_groups.add("lifecycle")
                    stage(
                        "delete", "fail", error=type(error).__name__, message=str(error)
                    )

    record = {
        "profileId": profile_id,
        "probeStatus": "runtime_vertical_slice",
        "probeSuiteVersion": _PROBE_SUITE_VERSION,
        "evidenceClass": _EVIDENCE_CLASS,
        "acceptance": "unverified",
        "sourceCommit": source_commit,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": sorted(failure_groups),
        "collectedAt": collected_at,
        "image": _IMAGE,
        "stages": stages,
    }
    _validate_runtime_record(record)
    return record


def redact_runtime_vertical_slice(record: dict[str, Any]) -> dict[str, Any]:
    """Create the commit-safe summary without command streams or errors."""
    summary = {
        key: record[key]
        for key in _TOP_LEVEL_FIELDS
        if key in record and key != "stages"
    }
    summary["stages"] = []
    for stage in record.get("stages", []):
        summary_stage = {
            key: value
            for key, value in stage.items()
            if key
            in {
                "name",
                "status",
                "sandboxName",
                "state",
                "command",
                "returncode",
                "truncated",
                "reason",
            }
        }
        summary["stages"].append(summary_stage)
    _validate_runtime_record({**summary, "stages": summary["stages"]}, summary=True)
    return summary


def write_runtime_vertical_slice_evidence(
    record: dict[str, Any],
    *,
    raw_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Write redacted diagnostic output and a smaller release summary."""
    _validate_runtime_record(record)
    summary = redact_runtime_vertical_slice(record)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    raw_record = _redact_value(
        {key: record[key] for key in _TOP_LEVEL_FIELDS if key in record}
    )
    raw_path.write_text(json.dumps(raw_record, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def _redact_value(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            name: "[REDACTED]"
            if _SENSITIVE_KEY.search(name)
            else _redact_value(item, key=name)
            for name, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, key=key) for item in value]
    if isinstance(value, str):
        redacted = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
        return _SENSITIVE_VALUE.sub("[REDACTED]", redacted)
    return value


def _validate_runtime_record(record: dict[str, Any], *, summary: bool = False) -> None:
    required = {
        "profileId",
        "probeStatus",
        "probeSuiteVersion",
        "evidenceClass",
        "acceptance",
        "sourceCommit",
        "facts",
        "factsDigest",
        "pins",
        "failureGroups",
        "collectedAt",
        "image",
        "stages",
    }
    if not required.issubset(record):
        raise ValueError("runtime evidence is missing required fields")
    if (
        record["profileId"] != _PROFILE
        or record["probeStatus"] != "runtime_vertical_slice"
    ):
        raise ValueError("runtime evidence profile or status is invalid")
    if record["probeSuiteVersion"] != _PROBE_SUITE_VERSION:
        raise ValueError("runtime evidence suite version is invalid")
    if (
        record["evidenceClass"] != _EVIDENCE_CLASS
        or record["acceptance"] != "unverified"
    ):
        raise ValueError("runtime evidence acceptance is invalid")
    if not isinstance(record["sourceCommit"], str) or not record["sourceCommit"]:
        raise ValueError("runtime evidence source commit is invalid")
    if (
        record["facts"] is not None
        or record["factsDigest"] is not None
        or record["pins"] is not None
    ):
        raise ValueError("runtime slice cannot contain facts or pins")
    if not isinstance(record["failureGroups"], list) or any(
        group not in {"runtime", "lifecycle", "channels"}
        for group in record["failureGroups"]
    ):
        raise ValueError("runtime evidence failure groups are invalid")
    if not isinstance(record["stages"], list):
        raise TypeError("runtime evidence stages are invalid")
    for item in record["stages"]:
        if not isinstance(item, dict) or item.get("name") not in {
            "preflight",
            "create",
            "ready",
            "exec",
            "stop",
            "delete",
            "runtime",
        }:
            raise ValueError("runtime evidence stage is invalid")
        if item.get("status") not in {"pass", "fail", "skipped"}:
            raise ValueError("runtime evidence stage status is invalid")
        if item.get("status") == "fail":
            expected = {
                "preflight": "runtime",
                "create": "runtime",
                "ready": "lifecycle",
                "exec": "channels",
                "stop": "lifecycle",
                "delete": "lifecycle",
                "runtime": "runtime",
            }[item["name"]]
            if expected not in record["failureGroups"]:
                raise ValueError("runtime evidence failure group is incomplete")
    if not summary and not record["failureGroups"]:
        names = [item["name"] for item in record["stages"]]
        if names != list(_STAGE_ORDER) or any(
            item["status"] != "pass" for item in record["stages"]
        ):
            raise ValueError("successful runtime evidence has an incomplete lifecycle")
