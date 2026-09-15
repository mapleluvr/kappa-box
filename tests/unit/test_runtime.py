from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from kappa_box import runtime as runtime_mod
from kappa_box.outcomes import OperationOutcomeError, l1_execution_error
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
    _request_json,
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
            openshell_binary="/unregistered/openshell-wrapper",
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
        adapter.upload(sandbox, "/etc/shadow", "/work/input.txt")  # type: ignore[arg-type]
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


def _create_request() -> SandboxRequest:
    return SandboxRequest(
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        command=("/bin/sleep", "30"),
    )


def _verified_service(tmp_path: Path, runner: RecordingRunner) -> RuntimeService:
    return RuntimeService(
        OpenShellDockerAdapter(
            config(profile_acceptance="verified", policy_verified=True), runner
        ),
        state_path=tmp_path / "runtime.db",
    )


def test_service_rejects_idempotency_key_reuse_with_different_request(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    service = _verified_service(tmp_path, runner)
    request = _create_request()

    service.create("attempt-1", request)
    with pytest.raises(IdempotencyConflictError) as caught:
        service.create(
            "attempt-1",
            SandboxRequest(
                profile_id=_REGISTERED_PROFILE,
                image=_REGISTERED_IMAGE,
                command=("/bin/sleep", "60"),
            ),
        )
    assert caught.value.to_record() == {
        "kind": "refused",
        "code": "idempotency_conflict",
        "sideEffects": "none",
        "reconcile": False,
    }


def test_service_refuses_unverified_profile_before_backend_call(tmp_path: Path):
    runner = RecordingRunner([])
    state_path = tmp_path / "runtime.db"
    service = RuntimeService(
        OpenShellDockerAdapter(config(), runner), state_path=state_path
    )

    with pytest.raises(OperationOutcomeError) as caught:
        service.create("attempt-1", _create_request())

    record = caught.value.to_record()
    assert record == {
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
    }
    assert runner.calls == []
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT count(*) FROM operations").fetchone()[0] == 0


def test_service_create_allows_verified_profile(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    service = _verified_service(tmp_path, runner)

    sandbox = service.create("attempt-1", _create_request())

    assert sandbox.name == "route-probe"
    assert sandbox.state is SandboxState.PROVISIONING
    assert runner.calls[0][0][7:9] == ("sandbox", "create")


def test_service_create_backend_failure_is_failed_provisioning(tmp_path: Path):
    runner = RecordingRunner(
        [result(returncode=1, stderr="engine rejected create"), result("[]")]
    )
    service = _verified_service(tmp_path, runner)

    with pytest.raises(OperationOutcomeError) as caught:
        service.create("attempt-1", _create_request())

    assert caught.value.to_record() == {
        "kind": "failed",
        "code": "provisioning_failed",
        "sideEffects": "present",
        "reconcile": False,
    }
    assert any(argv[7:9] == ("sandbox", "create") for argv, _ in runner.calls)


def test_service_create_lost_response_is_unknown_and_requires_reconcile(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    service = _verified_service(tmp_path, runner)

    with pytest.raises(OperationOutcomeError) as caught:
        service.create("attempt-1", _create_request())

    assert caught.value.to_record() == {
        "kind": "unknown",
        "code": "deadline_exceeded",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }
    assert any(argv[7:9] == ("sandbox", "create") for argv, _ in runner.calls)


def test_service_create_indeterminate_host_contact_is_unknown_host_unreachable(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result(returncode=127, stderr="cannot execute host command"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    service = _verified_service(tmp_path, runner)

    with pytest.raises(OperationOutcomeError) as caught:
        service.create("attempt-1", _create_request())

    assert caught.value.to_record() == {
        "kind": "unknown",
        "code": "host_unreachable",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }
    assert any(argv[7:9] == ("sandbox", "create") for argv, _ in runner.calls)


def _verbs(runner: RecordingRunner) -> list[tuple[str, ...]]:
    return [argv[7:9] for argv, _ in runner.calls]


def _claim_row(state_path: Path, key: str) -> sqlite3.Row | None:
    with sqlite3.connect(state_path) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM operations WHERE idempotency_key = ?",
            (key,),
        ).fetchone()


def _seed_incomplete_claim(state_path: Path, key: str, request: SandboxRequest) -> None:
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            """
            INSERT INTO operations (
                idempotency_key, request_json, sandbox_name, profile_id, image, state
            ) VALUES (?, ?, NULL, ?, ?, ?)
            """,
            (key, _request_json(request), request.profile_id, "", "creating"),
        )
        connection.commit()


_WRONG_IMAGE = "ghcr.io/example/image@sha256:" + "0" * 64
_FAILED_CREATE_RECORD = {
    "kind": "failed",
    "code": "provisioning_failed",
    "sideEffects": "present",
    "reconcile": False,
}
_UNKNOWN_CREATE_RECORD = {
    "kind": "unknown",
    "code": "deadline_exceeded",
    "sideEffects": "unreconciled",
    "reconcile": True,
}
_EXPLICIT_EMPTY_SELECTOR_BODIES = (
    pytest.param("[]", id="empty-list"),
    pytest.param('{"sandboxes":[]}', id="empty-sandboxes"),
    pytest.param('{"items":[]}', id="empty-items"),
    pytest.param('{"data":[]}', id="empty-data"),
)
_NONEMPTY_MISMATCH_BODIES = (
    pytest.param(
        json.dumps(
            [
                {
                    "name": "other-sandbox",
                    "image": _WRONG_IMAGE,
                    "labels": {"kappa-box.profile": _REGISTERED_PROFILE},
                    "phase": "Ready",
                }
            ]
        ),
        id="nonempty-list-image-mismatch",
    ),
    pytest.param(
        json.dumps(
            {
                "sandboxes": [
                    {
                        "name": "route-probe",
                        "image": _REGISTERED_IMAGE,
                        "labels": {"kappa-box.profile": "linux:l1@podman-rootless"},
                        "phase": "Ready",
                    }
                ]
            }
        ),
        id="envelope-sandboxes-profile-mismatch",
    ),
    pytest.param(
        json.dumps({"items": [{"name": "route-probe", "phase": "Ready"}]}),
        id="envelope-items-missing-fields",
    ),
    pytest.param(
        backend_json(image=_WRONG_IMAGE),
        id="single-object-image-mismatch",
    ),
)


def _first_create_results(kind: str) -> list[RuntimeCommandResult]:
    if kind == "failed":
        return [
            result(returncode=1, stderr="engine rejected create"),
            result("[]"),
        ]
    return [
        result(returncode=124, stderr="timed out"),
        result(returncode=1, stderr="list failed"),
    ]


def _stored_create_record(kind: str) -> dict[str, str | bool]:
    return _FAILED_CREATE_RECORD if kind == "failed" else _UNKNOWN_CREATE_RECORD


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        (
            {"profile_id": "linux:l1@podman-rootless"},
            "profile is not registered",
        ),
        (
            {"image": "ghcr.io/example/image@sha256:" + "0" * 64},
            "image is not approved",
        ),
        (
            {"env": (("TOKEN", "secret"),)},
            "environment variables are not registered",
        ),
    ],
)
def test_service_create_pre_backend_validation_is_not_swallowed_as_unknown(
    tmp_path: Path,
    overrides: dict[str, object],
    match: str,
):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    service = _verified_service(tmp_path, runner)
    state_path = tmp_path / "runtime.db"
    valid = _create_request()
    invalid = SandboxRequest(
        profile_id=str(overrides.get("profile_id", valid.profile_id)),
        image=str(overrides.get("image", valid.image)),
        command=valid.command,
        env=overrides.get("env", valid.env),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match=match) as caught:
        service.create("attempt-1", invalid)

    assert not isinstance(caught.value, OperationOutcomeError)
    assert runner.calls == []
    assert _claim_row(state_path, "attempt-1") is None

    sandbox = service.create("attempt-1", valid)

    assert sandbox.name == "route-probe"
    assert _verbs(runner) == [("sandbox", "create")]
    saved = _claim_row(state_path, "attempt-1")
    assert saved is not None
    assert saved["sandbox_name"] == "route-probe"


@pytest.mark.parametrize("absent_body", _EXPLICIT_EMPTY_SELECTOR_BODIES)
def test_service_create_failed_claim_retries_create_after_confirmed_absent(
    tmp_path: Path,
    absent_body: str,
):
    runner = RecordingRunner(
        [
            result(returncode=1, stderr="engine rejected create"),
            result("[]"),
            result(absent_body),
            result('{"name":"route-probe"}'),
        ]
    )
    service = _verified_service(tmp_path, runner)
    state_path = tmp_path / "runtime.db"
    request = _create_request()

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", request)
    sandbox = service.create("attempt-1", request)

    assert first.value.to_record() == _FAILED_CREATE_RECORD
    assert sandbox.name == "route-probe"
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
        ("sandbox", "create"),
    ]
    row = _claim_row(state_path, "attempt-1")
    assert row is not None
    assert row["sandbox_name"] == "route-probe"
    assert row["outcome_json"] is None


def test_service_create_failed_claim_adopts_if_reconcile_hits(tmp_path: Path):
    runner = RecordingRunner(
        [
            result(returncode=1, stderr="engine rejected create"),
            result("[]"),
            result(backend_json(phase="Failed")),
        ]
    )
    service = _verified_service(tmp_path, runner)

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", _create_request())
    recovered = service.create("attempt-1", _create_request())

    assert first.value.to_record()["kind"] == "failed"
    assert recovered.name == "route-probe"
    assert recovered.state is SandboxState.FAILED
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


def test_service_create_failed_claim_keeps_failed_when_reconcile_unreadable(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result(returncode=1, stderr="engine rejected create"),
            result("[]"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    service = _verified_service(tmp_path, runner)
    request = _create_request()

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", request)
    with pytest.raises(OperationOutcomeError) as second:
        service.create("attempt-1", request)

    assert first.value.to_record() == {
        "kind": "failed",
        "code": "provisioning_failed",
        "sideEffects": "present",
        "reconcile": False,
    }
    assert second.value.to_record() == first.value.to_record()
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


@pytest.mark.parametrize("absent_body", _EXPLICIT_EMPTY_SELECTOR_BODIES)
def test_service_create_unknown_claim_waits_for_late_instance_after_empty_selector(
    tmp_path: Path,
    absent_body: str,
):
    runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
            result(absent_body),
            result(backend_json(phase="Provisioning")),
        ]
    )
    service = _verified_service(tmp_path, runner)
    request = _create_request()

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", request)
    with pytest.raises(OperationOutcomeError) as second:
        service.create("attempt-1", request)

    assert first.value.to_record() == _UNKNOWN_CREATE_RECORD
    assert second.value.to_record() == _UNKNOWN_CREATE_RECORD
    row = _claim_row(tmp_path / "runtime.db", "attempt-1")
    assert row is not None
    assert row["sandbox_name"] is None
    assert json.loads(row["outcome_json"]) == _UNKNOWN_CREATE_RECORD

    recovered = service.create("attempt-1", request)

    assert recovered.name == "route-probe"
    assert recovered.state is SandboxState.PROVISIONING
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


def test_service_create_unknown_claim_does_not_create_when_reconcile_unreadable(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    service = _verified_service(tmp_path, runner)
    request = _create_request()

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", request)
    with pytest.raises(OperationOutcomeError) as second:
        service.create("attempt-1", request)

    assert first.value.to_record()["kind"] == "unknown"
    assert second.value.to_record() == first.value.to_record()
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


def test_service_create_unknown_claim_does_not_create_when_reconcile_json_unreadable(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
            result("not-json"),
        ]
    )
    service = _verified_service(tmp_path, runner)
    request = _create_request()

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", request)
    with pytest.raises(OperationOutcomeError) as second:
        service.create("attempt-1", request)

    assert first.value.to_record() == _UNKNOWN_CREATE_RECORD
    assert second.value.to_record() == first.value.to_record()
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


@pytest.mark.parametrize("kind", ["failed", "unknown"])
@pytest.mark.parametrize("mismatch_body", _NONEMPTY_MISMATCH_BODIES)
def test_service_create_incomplete_claim_does_not_retry_on_nonempty_mismatch(
    tmp_path: Path,
    kind: str,
    mismatch_body: str,
):
    runner = RecordingRunner(
        [
            *_first_create_results(kind),
            result(mismatch_body),
            result('{"name":"route-probe"}'),
        ]
    )
    service = _verified_service(tmp_path, runner)
    state_path = tmp_path / "runtime.db"
    request = _create_request()
    record = _stored_create_record(kind)

    with pytest.raises(OperationOutcomeError) as first:
        service.create("attempt-1", request)
    with pytest.raises(OperationOutcomeError) as second:
        service.create("attempt-1", request)

    assert first.value.to_record() == record
    assert second.value.to_record() == record
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]
    row = _claim_row(state_path, "attempt-1")
    assert row is not None
    assert row["sandbox_name"] is None
    assert json.loads(row["outcome_json"]) == record


def test_service_create_unknown_claim_adopts_reconciled_sandbox(tmp_path: Path):
    runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
            result(backend_json(phase="Provisioning")),
        ]
    )
    service = _verified_service(tmp_path, runner)
    request = _create_request()

    with pytest.raises(OperationOutcomeError):
        service.create("attempt-1", request)
    recovered = service.create("attempt-1", request)

    assert recovered.name == "route-probe"
    assert recovered.state is SandboxState.PROVISIONING
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


@pytest.mark.parametrize("absent_body", _EXPLICIT_EMPTY_SELECTOR_BODIES)
def test_service_create_null_claim_waits_for_late_instance_after_empty_selector(
    tmp_path: Path, absent_body: str
):
    runner = RecordingRunner(
        [
            result(absent_body),
            result(backend_json(phase="Provisioning")),
        ]
    )
    service = _verified_service(tmp_path, runner)
    state_path = tmp_path / "runtime.db"
    request = _create_request()
    _seed_incomplete_claim(state_path, "attempt-1", request)

    with pytest.raises(OperationOutcomeError) as caught:
        service.create("attempt-1", request)

    assert caught.value.to_record() == {
        "kind": "unknown",
        "code": "host_unreachable",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }
    saved = _claim_row(state_path, "attempt-1")
    assert saved is not None
    assert saved["sandbox_name"] is None

    recovered = service.create("attempt-1", request)

    assert recovered.name == "route-probe"
    assert _verbs(runner) == [("sandbox", "list"), ("sandbox", "list")]
    saved = _claim_row(state_path, "attempt-1")
    assert saved is not None
    assert saved["sandbox_name"] == "route-probe"


def test_service_create_null_claim_adopts_if_reconcile_hits(tmp_path: Path):
    runner = RecordingRunner([result(backend_json(phase="Provisioning"))])
    service = _verified_service(tmp_path, runner)
    state_path = tmp_path / "runtime.db"
    request = _create_request()
    _seed_incomplete_claim(state_path, "attempt-1", request)

    recovered = service.create("attempt-1", request)

    assert recovered.name == "route-probe"
    assert recovered.state is SandboxState.PROVISIONING
    assert _verbs(runner) == [("sandbox", "list")]
    saved = _claim_row(state_path, "attempt-1")
    assert saved is not None
    assert saved["sandbox_name"] == "route-probe"


def test_service_create_null_claim_does_not_create_when_reconcile_unreadable(
    tmp_path: Path,
):
    runner = RecordingRunner([result(returncode=1, stderr="list failed")])
    service = _verified_service(tmp_path, runner)
    state_path = tmp_path / "runtime.db"
    request = _create_request()
    _seed_incomplete_claim(state_path, "attempt-1", request)

    with pytest.raises(OperationOutcomeError) as caught:
        service.create("attempt-1", request)

    assert caught.value.to_record() == {
        "kind": "unknown",
        "code": "host_unreachable",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }
    assert _verbs(runner) == [("sandbox", "list")]
    saved = _claim_row(state_path, "attempt-1")
    assert saved is not None
    assert saved["sandbox_name"] is None


def test_service_create_recovers_sandbox_from_sqlite_across_runtime_service(
    tmp_path: Path,
):
    request = _create_request()
    first_runner = RecordingRunner([result('{"name":"route-probe"}')])
    first = _verified_service(tmp_path, first_runner)
    created = first.create("attempt-1", request)

    second_runner = RecordingRunner([result(backend_json())])
    second = _verified_service(tmp_path, second_runner)
    recovered = second.create("attempt-1", request)

    assert recovered.name == created.name
    assert recovered.state is SandboxState.READY
    assert _verbs(first_runner) == [("sandbox", "create")]
    assert _verbs(second_runner) == [("sandbox", "get")]


def test_service_create_failed_claim_retries_across_runtime_service(tmp_path: Path):
    request = _create_request()
    first_runner = RecordingRunner(
        [
            result(returncode=1, stderr="engine rejected create"),
            result("[]"),
        ]
    )
    first = _verified_service(tmp_path, first_runner)
    with pytest.raises(OperationOutcomeError) as caught:
        first.create("attempt-1", request)
    assert caught.value.to_record()["kind"] == "failed"
    assert caught.value.to_record()["code"] == "provisioning_failed"

    second_runner = RecordingRunner(
        [
            result("[]"),
            result('{"name":"route-probe"}'),
        ]
    )
    second = _verified_service(tmp_path, second_runner)
    sandbox = second.create("attempt-1", request)

    assert sandbox.name == "route-probe"
    assert _verbs(first_runner) == [("sandbox", "create"), ("sandbox", "list")]
    assert _verbs(second_runner) == [("sandbox", "list"), ("sandbox", "create")]
    saved = _claim_row(tmp_path / "runtime.db", "attempt-1")
    assert saved is not None
    assert saved["sandbox_name"] == "route-probe"


def test_service_create_unknown_claim_remains_unknown_across_runtime_service(
    tmp_path: Path,
):
    request = _create_request()
    first_runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    first = _verified_service(tmp_path, first_runner)
    with pytest.raises(OperationOutcomeError) as caught:
        first.create("attempt-1", request)
    assert caught.value.to_record() == {
        "kind": "unknown",
        "code": "deadline_exceeded",
        "sideEffects": "unreconciled",
        "reconcile": True,
    }

    second_runner = RecordingRunner(
        [
            result("[]"),
            result('{"name":"route-probe"}'),
        ]
    )
    second = _verified_service(tmp_path, second_runner)
    with pytest.raises(OperationOutcomeError) as replay:
        second.create("attempt-1", request)

    assert replay.value.to_record() == _UNKNOWN_CREATE_RECORD
    assert _verbs(first_runner) == [("sandbox", "create"), ("sandbox", "list")]
    assert _verbs(second_runner) == [("sandbox", "list")]
    row = _claim_row(tmp_path / "runtime.db", "attempt-1")
    assert row is not None
    assert row["sandbox_name"] is None
    assert json.loads(row["outcome_json"]) == _UNKNOWN_CREATE_RECORD


@pytest.mark.parametrize(
    ("command_result", "error_code"),
    [
        (result(returncode=1, stderr="engine rejected create"), "provisioning_failed"),
        (result(returncode=124, stderr="timed out"), "deadline_exceeded"),
        (
            result(returncode=127, stderr="cannot execute host command"),
            "host_unreachable",
        ),
        (result(stdout="partial", truncated=True), "deadline_exceeded"),
        (result(stdout=""), "host_unreachable"),
    ],
)
def test_adapter_create_maps_backend_errors_through_l1_execution_error(
    monkeypatch: pytest.MonkeyPatch,
    command_result: RuntimeCommandResult,
    error_code: str,
):
    seen: list[str] = []
    real = l1_execution_error

    def wrapped(*, error_code: str):
        seen.append(error_code)
        return real(error_code=error_code)

    monkeypatch.setattr(runtime_mod, "l1_execution_error", wrapped, raising=False)
    runner = RecordingRunner([command_result])
    adapter = OpenShellDockerAdapter(config(), runner)

    with pytest.raises(OperationOutcomeError) as caught:
        adapter.create(_create_request())

    assert seen == [error_code]
    assert caught.value.outcome == real(error_code=error_code)
    assert _verbs(runner) == [("sandbox", "create")]
