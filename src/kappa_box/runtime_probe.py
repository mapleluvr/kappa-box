"""Evidence-producing orchestration for the real OpenShell Docker slice."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from kappa_box.runtime import ExecResult, Sandbox, SandboxRequest, SandboxState

_PROFILE = "wsl2:l1@openshell-docker"
_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)


_PROBE_SUITE_VERSION = "0.1.0-runtime-vertical-slice"


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
    """Run create/ready/exec/stop/delete through the real runtime boundary.

    This probe records the route and operation behavior but deliberately never
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
            stage(
                "exec",
                "pass" if result.exit_code == 0 else "fail",
                command=["id"],
                returncode=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
            )
            if result.exit_code != 0:
                failure_groups.add("channels")
    except Exception as error:  # noqa: BLE001
        failure_groups.add("runtime")
        stage("runtime", "fail", error=type(error).__name__, message=str(error))
    finally:
        if sandbox is not None and sandbox.state is not SandboxState.DELETED:
            try:
                if sandbox.state is SandboxState.READY:
                    sandbox = runtime.stop(sandbox, timeout_seconds=60.0)
                    stage("stop", "pass", state=sandbox.state.value)
                elif sandbox.state is SandboxState.PROVISIONING:
                    failure_groups.add("lifecycle")
                    stage("stop", "skipped", reason="sandbox_not_ready")
                if sandbox.state is not SandboxState.DELETED:
                    sandbox = runtime.delete(sandbox, timeout_seconds=60.0)
                    stage("delete", "pass", state=sandbox.state.value)
            except Exception:  # noqa: BLE001
                failure_groups.add("lifecycle")
    return {
        "profileId": profile_id,
        "probeStatus": "runtime_vertical_slice",
        "probeSuiteVersion": _PROBE_SUITE_VERSION,
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


def redact_runtime_vertical_slice(record: dict[str, Any]) -> dict[str, Any]:
    """Remove command streams from the commit-safe release summary."""
    summary = {key: value for key, value in record.items() if key != "stages"}
    summary["stages"] = []
    for stage in record["stages"]:
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
                "reason",
                "error",
            }
        }
        summary["stages"].append(summary_stage)
    return summary


def write_runtime_vertical_slice_evidence(
    record: dict[str, Any],
    *,
    raw_path: Path,
    summary_path: Path,
) -> dict[str, Any]:
    """Write ignored raw output and a redacted release summary."""
    summary = redact_runtime_vertical_slice(record)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
