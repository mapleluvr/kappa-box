from __future__ import annotations

import json

import pytest

from kappa_box.runtime import (
    ExecResult,
    IdempotencyConflictError,
    OpenShellDockerAdapter,
    RuntimeCommandResult,
    RuntimeConfig,
    RuntimeService,
    Sandbox,
    SandboxRequest,
    SandboxState,
)


class RecordingRunner:
    def __init__(self, results: list[RuntimeCommandResult]) -> None:
        self.results = iter(results)
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def run(
        self, argv: tuple[str, ...], timeout_seconds: float
    ) -> RuntimeCommandResult:
        self.calls.append((argv, timeout_seconds))
        return next(self.results)


_REGISTERED_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)


def config() -> RuntimeConfig:
    return RuntimeConfig(
        profile_id="wsl2:l1@openshell-docker",
        distribution="kappa-box-ubuntu-24.04",
        gateway_endpoint="http://127.0.0.1:17670",
        openshell_binary="/usr/local/bin/openshell",
        approved_images=(_REGISTERED_IMAGE,),
        gateway_insecure=True,
    )


def result(stdout: str = "", *, returncode: int = 0, stderr: str = ""):
    return RuntimeCommandResult(
        argv=(), returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_subprocess_runner_marks_bounded_output(monkeypatch):
    class Completed:
        returncode = 0
        stdout = "abcdef"
        stderr = ""

    monkeypatch.setattr(
        "kappa_box.runtime.subprocess.run", lambda *args, **kwargs: Completed()
    )

    from kappa_box.runtime import SubprocessRuntimeRunner

    command_result = SubprocessRuntimeRunner(max_output_bytes=3).run(("echo",), 5)

    assert command_result.stdout == "abc"
    assert command_result.truncated is True


def test_runtime_config_rejects_unregistered_gateway_or_image():
    with pytest.raises(ValueError, match="gateway endpoint is not registered"):
        RuntimeConfig(
            profile_id=config().profile_id,
            distribution=config().distribution,
            gateway_endpoint="http://192.168.1.20:17670",
            openshell_binary=config().openshell_binary,
            approved_images=config().approved_images,
            gateway_insecure=True,
        )
    with pytest.raises(ValueError, match="image pin is not registered"):
        RuntimeConfig(
            profile_id=config().profile_id,
            distribution=config().distribution,
            gateway_endpoint=config().gateway_endpoint,
            openshell_binary=config().openshell_binary,
            approved_images=("ghcr.io/example/image:latest",),
            gateway_insecure=True,
        )


def test_subprocess_runner_decodes_wsl_output_as_utf8(monkeypatch):
    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    call: dict[str, object] = {}

    def fake_run(*args, **kwargs):
        call.update(kwargs)
        return Completed()

    monkeypatch.setattr("kappa_box.runtime.subprocess.run", fake_run)

    from kappa_box.runtime import SubprocessRuntimeRunner

    SubprocessRuntimeRunner().run(("echo",), 5)

    assert call["encoding"] == "utf-8"
    assert call["errors"] == "replace"


def test_create_rejects_unregistered_profile_and_image_before_host_call():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)

    with pytest.raises(ValueError, match="profile is not registered"):
        adapter.create(
            SandboxRequest(
                profile_id="linux:l1@podman-rootless",
                image=config().approved_images[0],
                command=("/bin/sleep", "30"),
            )
        )
    with pytest.raises(ValueError, match="image is not approved"):
        adapter.create(
            SandboxRequest(
                profile_id=config().profile_id,
                image="ghcr.io/example/image@sha256:" + "0" * 64,
                command=("/bin/sleep", "30"),
            )
        )
    assert runner.calls == []


def test_create_parses_name_then_waits_for_ready():
    runner = RecordingRunner(
        [
            result("Created sandbox: route-probe\n"),
            result(json.dumps({"name": "route-probe", "phase": "Ready"})),
        ]
    )
    adapter = OpenShellDockerAdapter(config(), runner)

    sandbox = adapter.create(
        SandboxRequest(
            profile_id=config().profile_id,
            image=config().approved_images[0],
            command=("/bin/sleep", "30"),
            cpu="1",
            memory="512Mi",
        )
    )

    assert sandbox.name == "route-probe"
    assert sandbox.state is SandboxState.PROVISIONING
    ready = adapter.wait_ready(sandbox, timeout_seconds=5)
    assert ready.state is SandboxState.READY
    assert runner.calls[0][0] == (
        "wsl.exe",
        "-d",
        "kappa-box-ubuntu-24.04",
        "-u",
        "root",
        "--",
        "/usr/local/bin/openshell",
        "sandbox",
        "create",
        "--gateway-endpoint",
        "http://127.0.0.1:17670",
        "--gateway-insecure",
        "--from",
        _REGISTERED_IMAGE,
        "--cpu",
        "1",
        "--memory",
        "512Mi",
        "--no-auto-providers",
        "--no-tty",
        "--detach",
        "--",
        "/bin/sleep",
        "30",
    )


def test_exec_rejects_cwd_outside_registered_grant():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=config().profile_id,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )

    with pytest.raises(ValueError, match="cwd is outside registered grants"):
        adapter.exec(sandbox, ("id",), cwd="/etc")
    assert runner.calls == []


def test_exec_preserves_separate_streams_and_requires_ready():
    runner = RecordingRunner(
        [
            result(json.dumps({"name": "route-probe", "phase": "Ready"})),
            result("out", stderr="err"),
        ]
    )
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = adapter.adopt("route-probe")

    with pytest.raises(ValueError, match="sandbox is not ready"):
        adapter.exec(sandbox, ("id",))

    sandbox = adapter.wait_ready(sandbox, timeout_seconds=5)
    execution = adapter.exec(sandbox, ("id",), cwd="/work")
    assert execution == ExecResult(exit_code=0, stdout="out", stderr="err")
    assert runner.calls[-1][0][-4:] == (
        "--workdir",
        "/work",
        "--",
        "id",
    )


def test_upload_and_download_use_registered_file_channel():
    runner = RecordingRunner([result(), result()])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=config().profile_id,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )

    adapter.upload(sandbox, "/tmp/input.txt", "/work/input.txt")
    adapter.download(sandbox, "/work/report.json", "/tmp/report.json")

    assert runner.calls[0][0][7:9] == ("sandbox", "upload")
    assert runner.calls[0][0][12:] == (
        "--no-git-ignore",
        "route-probe",
        "/tmp/input.txt",
        "/work/input.txt",
    )
    assert runner.calls[1][0][7:9] == ("sandbox", "download")
    assert runner.calls[1][0][12:] == (
        "route-probe",
        "/work/report.json",
        "/tmp/report.json",
    )


def test_file_channel_rejects_paths_outside_registered_grant():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=config().profile_id,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )

    with pytest.raises(ValueError, match="path is outside registered grants"):
        adapter.upload(sandbox, "/tmp/input.txt", "/etc/input.txt")
    with pytest.raises(ValueError, match="path is outside registered grants"):
        adapter.download(sandbox, "/var/log/out", "/tmp/out")
    assert runner.calls == []


def test_stop_and_delete_are_idempotent_operations_and_update_state():
    runner = RecordingRunner(
        [
            result(json.dumps({"name": "route-probe", "phase": "Ready"})),
            result(),
            result(),
        ]
    )
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = adapter.wait_ready(adapter.adopt("route-probe"), timeout_seconds=5)

    stopped = adapter.stop(sandbox)
    assert stopped.state is SandboxState.STOPPED
    assert adapter.stop(stopped).state is SandboxState.STOPPED
    deleted = adapter.delete(stopped)
    assert deleted.state is SandboxState.DELETED
    assert adapter.delete(deleted).state is SandboxState.DELETED
    assert [call[0][7:9] for call in runner.calls] == [
        ("sandbox", "get"),
        ("sandbox", "stop"),
        ("sandbox", "delete"),
    ]


def test_service_replays_same_idempotency_key_without_second_creation():
    runner = RecordingRunner([result("Created sandbox: route-probe\n")])
    service = RuntimeService(OpenShellDockerAdapter(config(), runner))
    request = SandboxRequest(
        profile_id=config().profile_id,
        image=config().approved_images[0],
        command=("/bin/sleep", "30"),
    )

    first = service.create("attempt-1", request)
    second = service.create("attempt-1", request)

    assert second == first
    assert len(runner.calls) == 1


def test_service_rejects_idempotency_key_reuse_with_different_request():
    runner = RecordingRunner([result("Created sandbox: route-probe\n")])
    service = RuntimeService(OpenShellDockerAdapter(config(), runner))
    request = SandboxRequest(
        profile_id=config().profile_id,
        image=config().approved_images[0],
        command=("/bin/sleep", "30"),
    )

    service.create("attempt-1", request)
    with pytest.raises(IdempotencyConflictError):
        service.create(
            "attempt-1",
            SandboxRequest(
                profile_id=config().profile_id,
                image=config().approved_images[0],
                command=("/bin/sleep", "60"),
            ),
        )
