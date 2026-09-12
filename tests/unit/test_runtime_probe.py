from __future__ import annotations

from pathlib import Path

from kappa_box.runtime import (
    ExecResult,
    Sandbox,
    SandboxRequest,
    SandboxState,
)
from kappa_box.runtime_probe import (
    collect_runtime_vertical_slice,
    write_runtime_vertical_slice_evidence,
)


class FakeRuntime:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.sandbox = Sandbox(
            name="route-probe",
            profile_id="wsl2:l1@openshell-docker",
            image="image@sha256:" + "a" * 64,
            state=SandboxState.PROVISIONING,
        )

    def preflight(self):
        self.calls.append("preflight")

    def create(self, request: SandboxRequest):
        self.calls.append("create")
        return self.sandbox

    def wait_ready(self, sandbox: Sandbox, *, timeout_seconds: float):
        self.calls.append("ready")
        return Sandbox(
            name=sandbox.name,
            profile_id=sandbox.profile_id,
            image=sandbox.image,
            state=SandboxState.READY,
        )

    def exec(self, sandbox: Sandbox, argv: tuple[str, ...], *, timeout_seconds: float):
        self.calls.append("exec")
        return ExecResult(exit_code=0, stdout="uid=65532(sandbox)\n", stderr="")

    def stop(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0):
        self.calls.append("stop")
        return Sandbox(
            name=sandbox.name,
            profile_id=sandbox.profile_id,
            image=sandbox.image,
            state=SandboxState.STOPPED,
        )

    def delete(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0):
        self.calls.append("delete")
        return Sandbox(
            name=sandbox.name,
            profile_id=sandbox.profile_id,
            image=sandbox.image,
            state=SandboxState.DELETED,
        )


def test_runtime_vertical_slice_records_real_operation_order_and_stays_unverified():
    runtime = FakeRuntime()

    record = collect_runtime_vertical_slice(
        runtime,
        profile_id="wsl2:l1@openshell-docker",
        source_commit="abc1234",
        collected_at="2026-09-12T09:00:00Z",
    )

    assert runtime.calls == ["preflight", "create", "ready", "exec", "stop", "delete"]
    assert record["acceptance"] == "unverified"
    assert record["probeStatus"] == "runtime_vertical_slice"
    assert record["failureGroups"] == []
    assert record["facts"] is None
    assert record["factsDigest"] is None
    assert record["pins"] is None
    assert record["probeSuiteVersion"] == "0.1.0-runtime-vertical-slice"
    assert record["stages"][3]["stdout"] == "uid=65532(sandbox)\n"


def test_runtime_vertical_slice_evidence_redacts_command_streams(tmp_path: Path):
    record = {
        "profileId": "wsl2:l1@openshell-docker",
        "probeSuiteVersion": "0.1.0-runtime-vertical-slice",
        "probeStatus": "runtime_vertical_slice",
        "acceptance": "unverified",
        "sourceCommit": "abc1234",
        "collectedAt": "2026-09-12T09:00:00Z",
        "image": "image@sha256:" + "a" * 64,
        "facts": None,
        "factsDigest": None,
        "pins": None,
        "failureGroups": [],
        "stages": [
            {
                "name": "exec",
                "status": "pass",
                "returncode": 0,
                "stdout": "secret output",
                "stderr": "secret error",
            }
        ],
    }

    summary = write_runtime_vertical_slice_evidence(
        record,
        raw_path=tmp_path / "raw.json",
        summary_path=tmp_path / "summary.json",
    )

    assert summary["stages"] == [{"name": "exec", "status": "pass", "returncode": 0}]
    assert "secret output" not in (tmp_path / "summary.json").read_text()
    assert "secret error" in (tmp_path / "raw.json").read_text()


def test_runtime_vertical_slice_marks_failure_and_attempts_cleanup():
    runtime = FakeRuntime()
    runtime.exec = lambda *args, **kwargs: ExecResult(
        exit_code=23, stdout="", stderr="denied"
    )

    record = collect_runtime_vertical_slice(
        runtime,
        profile_id="wsl2:l1@openshell-docker",
        source_commit="abc1234",
        collected_at="2026-09-12T09:00:00Z",
    )

    assert record["acceptance"] == "unverified"
    assert record["failureGroups"] == ["channels"]
    assert runtime.calls[-2:] == ["stop", "delete"]
