from __future__ import annotations

import json
from pathlib import Path

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

_REGISTERED_PROFILE = "wsl2:l1@openshell-docker"
_REGISTERED_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
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


def config(
    *,
    profile_acceptance: str = "unverified",
    probe_only: bool = True,
    policy_verified: bool = False,
) -> RuntimeConfig:
    return RuntimeConfig(
        profile_id=_REGISTERED_PROFILE,
        distribution="kappa-box-ubuntu-24.04",
        gateway_endpoint="http://127.0.0.1:17670",
        openshell_binary="/usr/local/bin/openshell",
        approved_images=(_REGISTERED_IMAGE,),
        gateway_insecure=True,
        profile_acceptance=profile_acceptance,
        probe_only=probe_only,
        policy_verified=policy_verified,
    )


def result(
    stdout: str = "",
    *,
    returncode: int = 0,
    stderr: str = "",
    truncated: bool = False,
) -> RuntimeCommandResult:
    return RuntimeCommandResult(
        argv=(),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
    )


def ready_sandbox(adapter: OpenShellDockerAdapter) -> Sandbox:
    runner = adapter._runner
    assert isinstance(runner, RecordingRunner)
    sandbox = adapter.adopt("route-probe")
    return sandbox


def backend_json(
    *,
    phase: str = "Ready",
    image: str = _REGISTERED_IMAGE,
    profile: str = _REGISTERED_PROFILE,
) -> str:
    return json.dumps(
        {
            "name": "route-probe",
            "image": image,
            "labels": {"kappa-box.profile": profile},
            "phase": phase,
        }
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


def test_runtime_config_rejects_unregistered_gateway_or_image():
    with pytest.raises(ValueError, match="gateway endpoint is not registered"):
        RuntimeConfig(
            profile_id=_REGISTERED_PROFILE,
            distribution="kappa-box-ubuntu-24.04",
            gateway_endpoint="http://192.168.1.20:17670",
            openshell_binary="/usr/local/bin/openshell",
            approved_images=(_REGISTERED_IMAGE,),
            gateway_insecure=True,
            probe_only=True,
        )
    with pytest.raises(ValueError, match="image pin is not registered"):
        RuntimeConfig(
            profile_id=_REGISTERED_PROFILE,
            distribution="kappa-box-ubuntu-24.04",
            gateway_endpoint="http://127.0.0.1:17670",
            openshell_binary="/usr/local/bin/openshell",
            approved_images=("ghcr.io/example/image:latest",),
            gateway_insecure=True,
            probe_only=True,
        )


def test_runtime_config_rejects_plaintext_outside_probe_only():
    with pytest.raises(ValueError, match="probe-only"):
        config(probe_only=False)


def test_runtime_config_rejects_unregistered_binary():
    with pytest.raises(ValueError, match="OpenShell binary is not registered"):
        RuntimeConfig(
            profile_id=_REGISTERED_PROFILE,
            distribution="kappa-box-ubuntu-24.04",
            gateway_endpoint="http://127.0.0.1:17670",
            openshell_binary="/tmp/openshell-wrapper",
            approved_images=(_REGISTERED_IMAGE,),
            gateway_insecure=True,
            probe_only=True,
        )


def test_create_rejects_unregistered_profile_and_image_before_host_call():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)

    with pytest.raises(ValueError, match="profile is not registered"):
        adapter.create(
            SandboxRequest(
                profile_id="linux:l1@podman-rootless",
                image=_REGISTERED_IMAGE,
                command=("/bin/sleep", "30"),
            )
        )
    with pytest.raises(ValueError, match="image is not approved"):
        adapter.create(
            SandboxRequest(
                profile_id=_REGISTERED_PROFILE,
                image="ghcr.io/example/image@sha256:" + "0" * 64,
                command=("/bin/sleep", "30"),
            )
        )
    assert runner.calls == []


def test_create_parses_name_then_waits_for_ready():
    runner = RecordingRunner([result('{"name":"route-probe"}'), result(backend_json())])
    adapter = OpenShellDockerAdapter(config(), runner)

    sandbox = adapter.create(
        SandboxRequest(
            profile_id=_REGISTERED_PROFILE,
            image=_REGISTERED_IMAGE,
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
        r"C:\Windows\System32\wsl.exe",
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
        "--output",
        "json",
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
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )
    adapter._bind(sandbox)

    with pytest.raises(ValueError, match="cwd is outside registered grants"):
        adapter.exec(sandbox, ("id",), cwd="/etc")
    assert runner.calls == []


def test_exec_preserves_separate_streams_and_requires_ready():
    runner = RecordingRunner(
        [
            result(backend_json(phase="Provisioning")),
            result(backend_json(phase="Ready")),
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
    assert runner.calls[-1][0][-4:] == ("--workdir", "/work", "--", "id")


def test_upload_and_download_use_registered_file_channel():
    runner = RecordingRunner([result(), result()])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )
    adapter._bind(sandbox)
    source = adapter.register_staging_path("/var/lib/kappa-box/staging/input.txt")
    destination = adapter.register_staging_path(
        "/var/lib/kappa-box/staging/report.json"
    )

    adapter.upload(sandbox, source, "/work/input.txt")
    adapter.download(sandbox, "/work/report.json", destination)

    assert runner.calls[0][0][7:9] == ("sandbox", "upload")
    assert runner.calls[0][0][12:] == (
        "--no-git-ignore",
        "route-probe",
        "/var/lib/kappa-box/staging/input.txt",
        "/work/input.txt",
    )
    assert runner.calls[1][0][7:9] == ("sandbox", "download")
    assert runner.calls[1][0][12:] == (
        "route-probe",
        "/work/report.json",
        "/var/lib/kappa-box/staging/report.json",
    )


def test_file_channel_rejects_paths_outside_registered_grant():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )
    adapter._bind(sandbox)
    source = adapter.register_staging_path("/var/lib/kappa-box/staging/input.txt")
    destination = adapter.register_staging_path("/var/lib/kappa-box/staging/out")

    with pytest.raises(ValueError, match="path is outside registered grants"):
        adapter.upload(sandbox, source, "/etc/input.txt")
    with pytest.raises(ValueError, match="path is outside registered grants"):
        adapter.download(sandbox, "/var/log/out", destination)
    assert runner.calls == []


def test_upload_rejects_local_path_outside_trusted_staging_root():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )
    adapter._bind(sandbox)

    with pytest.raises(ValueError, match="staging root"):
        adapter.register_staging_path("/etc/shadow")
    with pytest.raises(TypeError, match="staging handle"):
        adapter.upload(sandbox, "/etc/shadow", "/work/input.txt")
    assert runner.calls == []


def test_foreign_sandbox_handle_cannot_be_used():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)
    foreign = Sandbox(
        name="other-sandbox",
        profile_id="other-profile",
        image="other-image",
        state=SandboxState.READY,
    )

    with pytest.raises(ValueError, match="sandbox handle is not bound"):
        adapter.exec(foreign, ("id",))
    assert runner.calls == []


def test_adopt_requires_backend_identity_and_registered_image():
    runner = RecordingRunner([result(backend_json(phase="Ready"))])
    adapter = OpenShellDockerAdapter(config(), runner)

    adopted = adapter.adopt("route-probe")

    assert adopted.image == _REGISTERED_IMAGE
    assert adopted.profile_id == _REGISTERED_PROFILE
    assert adopted.state is SandboxState.READY


def test_delete_allows_provisioning_cleanup():
    runner = RecordingRunner([result('{"name":"route-probe"}'), result()])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = adapter.create(
        SandboxRequest(
            profile_id=_REGISTERED_PROFILE,
            image=_REGISTERED_IMAGE,
            command=("/bin/sleep", "30"),
        )
    )

    deleted = adapter.delete(sandbox)

    assert deleted.state is SandboxState.DELETED
    assert runner.calls[-1][0][7:9] == ("sandbox", "delete")


def test_wait_ready_rejects_expired_deadline_before_polling():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        state=SandboxState.PROVISIONING,
    )
    adapter._bind(sandbox)

    with pytest.raises(ValueError, match="timeout_seconds must be finite and positive"):
        adapter.wait_ready(sandbox, timeout_seconds=0)
    assert runner.calls == []


def test_exec_propagates_output_truncation():
    runner = RecordingRunner([result("partial", truncated=True)])
    adapter = OpenShellDockerAdapter(config(), runner)
    sandbox = Sandbox(
        name="route-probe",
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        state=SandboxState.READY,
    )
    adapter._bind(sandbox)

    execution = adapter.exec(sandbox, ("id",))

    assert execution.truncated is True


def test_env_requires_registered_non_secret_key():
    runner = RecordingRunner([])
    adapter = OpenShellDockerAdapter(config(), runner)

    with pytest.raises(ValueError, match="environment variables are not registered"):
        adapter.create(
            SandboxRequest(
                profile_id=_REGISTERED_PROFILE,
                image=_REGISTERED_IMAGE,
                command=("/bin/sleep", "30"),
                env=(("TOKEN", "secret"),),
            )
        )

    assert runner.calls == []


def test_service_replays_same_idempotency_key_from_persistent_store(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    request = SandboxRequest(
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        command=("/bin/sleep", "30"),
    )
    service = RuntimeService(
        OpenShellDockerAdapter(
            config(profile_acceptance="verified", policy_verified=True), runner
        ),
        state_path=tmp_path / "runtime.db",
    )

    first = service.create("attempt-1", request)
    second = service.create("attempt-1", request)

    assert second == first
    assert len(runner.calls) == 1


def test_service_rejects_idempotency_key_reuse_with_different_request(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    service = RuntimeService(
        OpenShellDockerAdapter(
            config(profile_acceptance="verified", policy_verified=True), runner
        ),
        state_path=tmp_path / "runtime.db",
    )
    request = SandboxRequest(
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        command=("/bin/sleep", "30"),
    )

    service.create("attempt-1", request)
    with pytest.raises(IdempotencyConflictError):
        service.create(
            "attempt-1",
            SandboxRequest(
                profile_id=_REGISTERED_PROFILE,
                image=_REGISTERED_IMAGE,
                command=("/bin/sleep", "60"),
            ),
        )


def test_service_refuses_unverified_profile_before_backend_call(tmp_path: Path):
    runner = RecordingRunner([])
    service = RuntimeService(
        OpenShellDockerAdapter(config(), runner), state_path=tmp_path / "runtime.db"
    )

    with pytest.raises(RuntimeError, match="profile_unverified"):
        service.create(
            "attempt-1",
            SandboxRequest(
                profile_id=_REGISTERED_PROFILE,
                image=_REGISTERED_IMAGE,
                command=("/bin/sleep", "30"),
            ),
        )
    assert runner.calls == []
