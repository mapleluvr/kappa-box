from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from kappa_box.facade import OperationFacade, _validate_event
from kappa_box.runtime import (
    OpenShellDockerAdapter,
    RuntimeCommandResult,
    RuntimeConfig,
    RuntimeService,
    SandboxRequest,
    SandboxState,
)

_REGISTERED_PROFILE = "wsl2:l1@openshell-docker"
_REGISTERED_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)
_S1_IDENTITY = {
    "runId": "run-s1-fixture-0001",
    "candidateRef": "candidate-s1-fixture-0001",
    "baselineRef": "baseline-pi-0.85.1-native",
    "benchmarkRevision": "benchmark-s1-fixture-r1",
    "profileId": "wsl2:l1@openshell-docker",
    "factsDigest": None,
    "sandboxId": None,
    "sessionId": "session-s1-fixture-0001",
    "branchId": "branch-s1-empty-leaf",
    "requestId": "request-s1-fixture-0001",
    "revision": 0,
    "operationId": "operation-s1-fixture-0001",
    "artifactRef": None,
    "eventId": "event-s1-fixture-0001",
    "cursor": "cursor-s1-fixture-0001",
}


class RecordingRunner:
    def __init__(self, results: list[RuntimeCommandResult]) -> None:
        self.results = iter(results)
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def run(
        self, argv: tuple[str, ...], timeout_seconds: float
    ) -> RuntimeCommandResult:
        self.calls.append((argv, timeout_seconds))
        return next(self.results)


class StickyRunner:
    def __init__(self, results: list[RuntimeCommandResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[tuple[str, ...], float]] = []
        self._index = 0

    def run(
        self, argv: tuple[str, ...], timeout_seconds: float
    ) -> RuntimeCommandResult:
        self.calls.append((argv, timeout_seconds))
        if self._index < len(self.results) - 1:
            current = self.results[self._index]
            self._index += 1
            return current
        return self.results[-1]


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


def backend_json(*, phase: str = "Ready") -> str:
    return json.dumps(
        {
            "name": "route-probe",
            "image": _REGISTERED_IMAGE,
            "labels": {"kappa-box.profile": _REGISTERED_PROFILE},
            "phase": phase,
        }
    )


def _create_request() -> SandboxRequest:
    return SandboxRequest(
        profile_id=_REGISTERED_PROFILE,
        image=_REGISTERED_IMAGE,
        command=("/bin/sleep", "30"),
    )


def _service(tmp_path: Path, runner: RecordingRunner, **kwargs) -> RuntimeService:
    return RuntimeService(
        OpenShellDockerAdapter(config(**kwargs), runner),
        state_path=tmp_path / "runtime.db",
        collect_dir=tmp_path / "collect",
    )


def _facade(tmp_path: Path, runner: RecordingRunner, **kwargs) -> OperationFacade:
    return OperationFacade(_service(tmp_path, runner, **kwargs))


def _verbs(runner: RecordingRunner | StickyRunner) -> list[tuple[str, ...]]:
    return [argv[7:9] for argv, _ in runner.calls]


def test_inspect_returns_registered_unverified_profile_without_facts(tmp_path: Path):
    runner = RecordingRunner([])
    facade = _facade(tmp_path, runner)

    inspected = facade.inspect(_REGISTERED_PROFILE, identity=_S1_IDENTITY)

    assert inspected.kind is None
    assert inspected.operation == "profiles.inspect"
    assert inspected.operation_id == "operation-s1-fixture-0001"
    assert inspected.identity["runId"] == "run-s1-fixture-0001"
    assert inspected.identity["requestId"] == "request-s1-fixture-0001"
    assert inspected.identity["profileId"] == _REGISTERED_PROFILE
    assert inspected.payload["acceptance"] == "unverified"
    assert inspected.payload["available"] is False
    assert inspected.payload.get("factsDigest") is None
    assert inspected.identity.get("factsDigest") is None
    assert inspected.identity.get("sandboxId") is None
    assert inspected.identity.get("artifactRef") is None
    assert runner.calls == []


def test_inspect_unknown_profile_is_refused_without_backend(tmp_path: Path):
    runner = RecordingRunner([])
    facade = _facade(tmp_path, runner)

    inspected = facade.inspect("linux:l1@podman-rootless", identity=_S1_IDENTITY)

    record = inspected.to_outcome_record()
    assert record is not None
    assert record["operation"] == "profiles.inspect"
    assert record["kind"] == "refused"
    assert record["code"] == "profile_unknown"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert runner.calls == []


def test_create_refuses_unverified_profile_with_s1_outcome_before_claim_and_backend(
    tmp_path: Path,
):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    state_path = tmp_path / "runtime.db"
    facade = _facade(tmp_path, runner)

    created = facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)

    record = created.to_outcome_record()
    assert record == {
        "operationId": "operation-s1-fixture-0001",
        "operation": "sandboxes.create",
        "identity": {
            "runId": "run-s1-fixture-0001",
            "requestId": "request-s1-fixture-0001",
            "profileId": _REGISTERED_PROFILE,
        },
        "kind": "refused",
        "code": "profile_unverified",
        "sideEffects": "none",
        "reconcile": False,
    }
    assert created.identity.get("sandboxId") is None
    assert created.identity.get("factsDigest") is None
    assert created.identity.get("artifactRef") is None
    assert runner.calls == []
    with sqlite3.connect(state_path) as connection:
        assert connection.execute("SELECT count(*) FROM operations").fetchone()[0] == 0


def test_observe_associates_shared_identity_and_reads_from_cursor(tmp_path: Path):
    runner = RecordingRunner([])
    facade = _facade(tmp_path, runner)

    facade.inspect(_REGISTERED_PROFILE, identity=_S1_IDENTITY)
    facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    events = facade.observe()

    assert [event["type"] for event in events] == [
        "box.profiles.inspect",
        "box.sandboxes.create",
    ]
    cursors = [event["cursor"] for event in events]
    assert cursors == ["1", "2"]
    for event in events:
        assert event["schemaVersion"] == "s1-draft-1"
        assert event["identity"]["runId"] == "run-s1-fixture-0001"
        assert event["identity"]["requestId"] == "request-s1-fixture-0001"
        assert event["identity"]["profileId"] == _REGISTERED_PROFILE
        assert event["identity"]["operationId"] == "operation-s1-fixture-0001"
        assert event["identity"]["sessionId"] == "session-s1-fixture-0001"
        assert event["identity"]["branchId"] == "branch-s1-empty-leaf"
        assert event["provenance"] == {"owner": "kappa-box", "source": "runtime"}
        assert event["eventId"] != "event-s1-fixture-0001"
        assert event["cursor"] != "cursor-s1-fixture-0001"
    assert events[1]["payload"]["kind"] == "refused"
    assert events[1]["payload"]["code"] == "profile_unverified"
    replayed = facade.observe(cursor="1")
    assert [event["cursor"] for event in replayed] == ["2"]
    assert facade.observe(cursor="2") == []


def test_observe_survives_new_facade_on_same_state_path(tmp_path: Path):
    first_runner = RecordingRunner([])
    first = _facade(tmp_path, first_runner)
    state_path = tmp_path / "runtime.db"

    first.inspect(_REGISTERED_PROFILE, identity=_S1_IDENTITY)
    created = first.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    first_events = first.observe()

    created_record = created.to_outcome_record()
    assert created_record is not None
    assert created_record["kind"] == "refused"
    assert created_record["code"] == "profile_unverified"
    assert created_record["sideEffects"] == "none"
    assert first_runner.calls == []
    assert _claim_count(state_path) == 0
    assert [event["cursor"] for event in first_events] == ["1", "2"]
    assert [event["eventId"] for event in first_events] == ["event-1", "event-2"]

    second_runner = RecordingRunner([result('{"name":"route-probe"}')])
    second = _facade(tmp_path, second_runner)
    replayed = second.observe()

    assert replayed == first_events
    assert [event["cursor"] for event in replayed] == ["1", "2"]
    assert [event["eventId"] for event in replayed] == ["event-1", "event-2"]
    assert len({event["eventId"] for event in replayed}) == len(replayed)
    assert second.observe(cursor="1") == first_events[1:]
    assert second.observe(cursor="2") == []
    with pytest.raises(ValueError, match="event cursor is invalid"):
        second.observe(cursor=_S1_IDENTITY["cursor"])
    for event in replayed:
        assert event["eventId"] != _S1_IDENTITY["eventId"]
        assert event["cursor"] != _S1_IDENTITY["cursor"]
        assert event["payload"].get("factsDigest") is None
        assert event["payload"].get("artifactRef") is None
        assert event["payload"].get("state") != "ready"
        assert event["identity"].get("factsDigest") is None
        assert event["identity"].get("artifactRef") is None
        assert event["identity"].get("sandboxId") is None

    refused_again = second.create("attempt-2", _create_request(), identity=_S1_IDENTITY)
    refused_record = refused_again.to_outcome_record()
    assert refused_record is not None
    assert refused_record["kind"] == "refused"
    assert refused_record["code"] == "profile_unverified"
    assert refused_record["sideEffects"] == "none"
    assert second_runner.calls == []
    assert _claim_count(state_path) == 0
    continued = second.observe(cursor="2")
    assert [event["cursor"] for event in continued] == ["3"]
    assert continued[0]["eventId"] == "event-3"
    assert continued[0]["payload"]["code"] == "profile_unverified"
    assert continued[0]["payload"].get("factsDigest") is None
    assert continued[0]["payload"].get("artifactRef") is None
    third = _facade(tmp_path, RecordingRunner([]))
    assert [event["cursor"] for event in third.observe()] == ["1", "2", "3"]
    assert [event["eventId"] for event in third.observe()] == [
        "event-1",
        "event-2",
        "event-3",
    ]


def test_owner_operation_id_unique_across_new_facade_and_service(tmp_path: Path):
    identity = {**_S1_IDENTITY, "operationId": None}
    first_runner = RecordingRunner([])
    first = _facade(tmp_path, first_runner)
    state_path = tmp_path / "runtime.db"

    first_inspect = first.inspect(_REGISTERED_PROFILE, identity=identity)
    first_create = first.create("attempt-1", _create_request(), identity=identity)
    first_events = first.observe()
    first_ids = [first_inspect.operation_id, first_create.operation_id]

    first_record = first_create.to_outcome_record()
    assert first_ids[0] != first_ids[1]
    assert [event["identity"]["operationId"] for event in first_events] == first_ids
    assert first_record is not None
    assert first_record["code"] == "profile_unverified"
    assert first_runner.calls == []
    assert _claim_count(state_path) == 0

    second_runner = RecordingRunner([])
    second_service = RuntimeService(
        OpenShellDockerAdapter(config(), second_runner),
        state_path=state_path,
    )
    second = OperationFacade(second_service)
    second_inspect = second.inspect(_REGISTERED_PROFILE, identity=identity)
    continued = second.observe(cursor=first_events[-1]["cursor"])
    all_events = second.observe()
    all_ids = [event["identity"]["operationId"] for event in all_events]

    assert second_inspect.operation_id not in first_ids
    assert continued[0]["identity"]["operationId"] == second_inspect.operation_id
    assert all_ids == [*first_ids, second_inspect.operation_id]
    assert len(set(all_ids)) == 3
    for event in all_events:
        assert event["identity"]["operationId"] == f"operation-{event['cursor']}"
        assert event["eventId"] == f"event-{event['cursor']}"
    assert second_runner.calls == []
    assert _claim_count(state_path) == 0

    third_service = RuntimeService(
        OpenShellDockerAdapter(config(), RecordingRunner([])),
        state_path=state_path,
    )
    third = OperationFacade(third_service)
    third_inspect = third.inspect(_REGISTERED_PROFILE, identity=identity)
    replayed_ids = [event["identity"]["operationId"] for event in third.observe()]
    assert third_inspect.operation_id not in all_ids
    assert len(set(replayed_ids)) == 4
    assert replayed_ids[-1] == third_inspect.operation_id
    assert third.observe(cursor="3")[0]["cursor"] == "4"


def test_append_event_validation_failure_does_not_change_list_events(tmp_path: Path):
    service = _service(tmp_path, RecordingRunner([]))
    event = {
        "schemaVersion": "s1-draft-1",
        "type": "box.profiles.inspect",
        "identity": {
            "profileId": _REGISTERED_PROFILE,
            "operationId": "operation-supplied",
        },
        "cause": {"kind": "external_intent"},
        "payload": {"acceptance": "unverified"},
        "provenance": {"owner": "kappa-box", "source": "runtime"},
    }

    stored = service.append_event(event, validate=_validate_event)
    before = service.list_events()
    assert before == [stored]
    assert stored["eventId"] == "event-1"
    assert stored["cursor"] == "1"

    with pytest.raises(ValueError, match="s1 event schema validation failed"):
        service.append_event({**event, "unexpected": True}, validate=_validate_event)

    assert service.list_events() == before
    restarted = RuntimeService(
        OpenShellDockerAdapter(config(), RecordingRunner([])),
        state_path=tmp_path / "runtime.db",
    )
    assert restarted.list_events() == before


def test_wait_ready_exec_collect_delete_after_refusal_do_not_call_backend(
    tmp_path: Path,
):
    runner = RecordingRunner([])
    facade = _facade(tmp_path, runner)
    facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)

    waited = facade.wait_ready("attempt-1", identity=_S1_IDENTITY)
    executed = facade.exec("attempt-1", ("id",), identity=_S1_IDENTITY)
    collected = facade.collect(
        "attempt-1",
        [{"path": "/work/report.json"}],
        identity=_S1_IDENTITY,
    )
    deleted = facade.delete("attempt-1", identity=_S1_IDENTITY)

    for result_record, operation in (
        (waited, "sandboxes.waitReady"),
        (executed, "exec"),
        (collected, "collect"),
        (deleted, "sandboxes.delete"),
    ):
        record = result_record.to_outcome_record()
        assert record is not None
        assert record["operation"] == operation
        assert record["kind"] == "refused"
        assert record["code"] == "invalid_state"
        assert record["sideEffects"] == "none"
        assert result_record.identity.get("sandboxId") is None
        assert result_record.identity.get("artifactRef") is None
        assert result_record.payload.get("artifactRef") is None
    assert runner.calls == []


def test_unsupported_s1_operation_is_refused_without_backend(tmp_path: Path):
    runner = RecordingRunner([])
    facade = _facade(tmp_path, runner)

    opened = facade.invoke("sessions.open", identity=_S1_IDENTITY)
    started = facade.invoke("sandboxes.start", identity=_S1_IDENTITY)

    for result_record, operation in (
        (opened, "sessions.open"),
        (started, "sandboxes.start"),
    ):
        record = result_record.to_outcome_record()
        assert record is not None
        assert record["operation"] == operation
        assert record["kind"] == "refused"
        assert record["code"] == "unsupported"
        assert record["sideEffects"] == "none"
        assert record["reconcile"] is False
    assert runner.calls == []


def test_create_preserves_failed_and_unknown_and_keeps_them_distinct(tmp_path: Path):
    failed_runner = RecordingRunner(
        [result(returncode=1, stderr="engine rejected create"), result("[]")]
    )
    failed_facade = _facade(
        tmp_path / "failed",
        failed_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    unknown_runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    unknown_facade = _facade(
        tmp_path / "unknown",
        unknown_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )

    failed = failed_facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    unknown = unknown_facade.create(
        "attempt-1", _create_request(), identity=_S1_IDENTITY
    )

    failed_record = failed.to_outcome_record()
    unknown_record = unknown.to_outcome_record()
    assert failed_record is not None
    assert unknown_record is not None
    assert failed_record["kind"] == "failed"
    assert failed_record["code"] == "provisioning_failed"
    assert failed_record["sideEffects"] == "present"
    assert failed_record["reconcile"] is False
    assert unknown_record["kind"] == "unknown"
    assert unknown_record["code"] == "deadline_exceeded"
    assert unknown_record["sideEffects"] == "unreconciled"
    assert unknown_record["reconcile"] is True
    assert failed_record["kind"] != unknown_record["kind"]
    assert ("sandbox", "create") in _verbs(failed_runner)
    assert ("sandbox", "create") in _verbs(unknown_runner)


def test_unknown_create_does_not_retry_create_on_unreadable_reconcile(tmp_path: Path):
    runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result(returncode=1, stderr="list failed"),
            result(returncode=1, stderr="list failed"),
        ]
    )
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )

    first = facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    second = facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)

    assert first.to_outcome_record() is not None
    assert second.to_outcome_record() == first.to_outcome_record()
    assert first.kind == "unknown"
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "list"),
        ("sandbox", "list"),
    ]


def test_verified_recording_path_exec_and_delete_do_not_fabricate_facts_or_artifact(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result('{"name":"route-probe"}'),
            result(backend_json()),
            result("out", stderr="err"),
            result(),
            result(),
        ]
    )
    collect_dir = tmp_path / "collect"
    collect_dir.mkdir()
    (collect_dir / "artifact").write_bytes(b"stable-snapshot")
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    identity = {**_S1_IDENTITY, "operationId": None}

    created = facade.create("attempt-1", _create_request(), identity=identity)
    waited = facade.wait_ready("attempt-1", identity=identity)
    executed = facade.exec("attempt-1", ("id",), cwd="/work", identity=identity)
    collected = facade.collect(
        "attempt-1",
        [{"path": "/work/report.json"}],
        identity=identity,
    )
    deleted = facade.delete("attempt-1", identity=identity)

    assert created.kind is None
    assert created.payload["state"] == "provisioning"
    assert created.identity["sandboxId"] == "route-probe"
    assert created.identity.get("factsDigest") is None
    assert waited.kind is None
    assert waited.payload["state"] == "ready"
    assert waited.payload.get("factsDigest") is None
    assert waited.identity.get("factsDigest") is None
    assert executed.kind is None
    assert executed.payload["exitCode"] == 0
    assert executed.payload["stdout"] == "out"
    assert executed.payload["stderr"] == "err"
    digest = hashlib.sha256(b"stable-snapshot").hexdigest()
    assert collected.kind is None
    assert collected.payload["artifactRef"] == f"sha256:{digest}"
    assert collected.payload["snapshot"] is True
    assert collected.payload["source"] == "/work/report.json"
    assert deleted.kind is None
    assert deleted.payload["state"] == "deleted"
    assert _verbs(runner) == [
        ("sandbox", "create"),
        ("sandbox", "get"),
        ("sandbox", "exec"),
        ("sandbox", "download"),
        ("sandbox", "delete"),
    ]


@pytest.mark.skip(
    reason="verified host/profile evidence is not available on the current host"
)
def test_ready_lifecycle_with_facts_digest_and_artifact_ref():
    raise AssertionError("current host must not fabricate ready evidence")


def _unknown_profile_request() -> SandboxRequest:
    return SandboxRequest(
        profile_id="linux:l1@podman-rootless",
        image=_REGISTERED_IMAGE,
        command=("/bin/sleep", "30"),
    )


def _claim_count(state_path: Path) -> int:
    with sqlite3.connect(state_path) as connection:
        return int(connection.execute("SELECT count(*) FROM operations").fetchone()[0])


def _claim_state(state_path: Path, key: str) -> str | None:
    with sqlite3.connect(state_path) as connection:
        row = connection.execute(
            "SELECT state FROM operations WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
    return None if row is None else str(row[0])


def test_wait_ready_failed_sandbox_is_failed_provisioning(tmp_path: Path):
    runner = RecordingRunner(
        [result('{"name":"route-probe"}'), result(backend_json(phase="Failed"))]
    )
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )

    created = facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    waited = facade.wait_ready("attempt-1", identity=_S1_IDENTITY)

    assert created.kind is None
    record = waited.to_outcome_record()
    assert record is not None
    assert record["operation"] == "sandboxes.waitReady"
    assert record["kind"] == "failed"
    assert record["code"] == "provisioning_failed"
    assert record["sideEffects"] == "present"
    assert record["reconcile"] is False
    assert waited.payload.get("factsDigest") is None
    assert _claim_state(tmp_path / "runtime.db", "attempt-1") == SandboxState.FAILED


@pytest.mark.parametrize("phase", ["Stopped", "Deleted"])
def test_wait_ready_stopped_or_deleted_is_refused_invalid_state(
    tmp_path: Path, phase: str
):
    runner = RecordingRunner(
        [result('{"name":"route-probe"}'), result(backend_json(phase=phase))]
    )
    facade = _facade(
        tmp_path / phase.lower(),
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )

    facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    waited = facade.wait_ready("attempt-1", identity=_S1_IDENTITY)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_state"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert waited.kind != "unknown"


def test_wait_ready_timeout_on_known_sandbox_is_not_unknown_reconcile(
    tmp_path: Path,
):
    runner = StickyRunner(
        [
            result('{"name":"route-probe"}'),
            result(backend_json(phase="Provisioning")),
        ]
    )
    facade = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True), runner
            ),
            state_path=tmp_path / "runtime.db",
        )
    )
    facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)

    waited = facade.wait_ready("attempt-1", identity=_S1_IDENTITY, timeout_seconds=0.2)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_state"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert waited.kind != "unknown"
    assert ("sandbox", "create") in _verbs(runner)
    assert ("sandbox", "get") in _verbs(runner)


def test_wait_ready_get_timeout_on_known_sandbox_is_refused_invalid_state(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result('{"name":"route-probe"}'),
            result(returncode=124, stderr="timed out"),
            result('{"name":"route-probe-2"}'),
        ]
    )
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    created = facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    assert created.kind is None

    waited = facade.wait_ready("attempt-1", identity=_S1_IDENTITY)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["operation"] == "sandboxes.waitReady"
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_state"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert waited.payload.get("factsDigest") is None
    assert _verbs(runner) == [("sandbox", "create"), ("sandbox", "get")]
    assert (
        _claim_state(tmp_path / "runtime.db", "attempt-1") == SandboxState.PROVISIONING
    )


def test_wait_ready_get_failure_on_known_sandbox_is_unknown_host_unreachable(
    tmp_path: Path,
):
    runner = RecordingRunner(
        [
            result('{"name":"route-probe"}'),
            result(returncode=1, stderr="gateway down"),
            result('{"name":"route-probe-2"}'),
        ]
    )
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    created = facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    assert created.kind is None

    waited = facade.wait_ready("attempt-1", identity=_S1_IDENTITY)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["operation"] == "sandboxes.waitReady"
    assert record["kind"] == "unknown"
    assert record["code"] == "host_unreachable"
    assert record["sideEffects"] == "unreconciled"
    assert record["reconcile"] is True
    assert waited.payload.get("factsDigest") is None
    assert _verbs(runner) == [("sandbox", "create"), ("sandbox", "get")]
    assert (
        _claim_state(tmp_path / "runtime.db", "attempt-1") == SandboxState.PROVISIONING
    )


def test_service_peek_reads_sqlite_without_adopt_or_state_update(tmp_path: Path):
    create_runner = RecordingRunner([result('{"name":"route-probe"}')])
    state_path = tmp_path / "runtime.db"
    first = RuntimeService(
        OpenShellDockerAdapter(
            config(profile_acceptance="verified", policy_verified=True), create_runner
        ),
        state_path=state_path,
    )
    created = first.create("attempt-1", _create_request())
    assert created.state is SandboxState.PROVISIONING
    assert _verbs(create_runner) == [("sandbox", "create")]

    peek_runner = RecordingRunner([result(backend_json(phase="Failed"))])
    second = RuntimeService(
        OpenShellDockerAdapter(
            config(profile_acceptance="verified", policy_verified=True), peek_runner
        ),
        state_path=state_path,
    )

    peeked = second.peek("attempt-1")

    assert peeked is not None
    assert peeked.name == "route-probe"
    assert peeked.state is SandboxState.PROVISIONING
    assert peek_runner.calls == []
    assert _claim_state(state_path, "attempt-1") == SandboxState.PROVISIONING


def test_collect_uses_local_peek_and_does_not_adopt_or_write_artifact(
    tmp_path: Path,
):
    create_runner = RecordingRunner(
        [result('{"name":"route-probe"}'), result(backend_json())]
    )
    state_path = tmp_path / "runtime.db"
    first = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True),
                create_runner,
            ),
            state_path=state_path,
        )
    )
    first.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    waited = first.wait_ready("attempt-1", identity=_S1_IDENTITY)
    assert waited.kind is None
    assert waited.payload["state"] == "ready"

    peek_runner = RecordingRunner([result(backend_json(phase="Failed"))])
    second = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True),
                peek_runner,
            ),
            state_path=state_path,
        )
    )
    collected = second.collect(
        "attempt-1",
        [{"path": "/work/report.json"}],
        identity=_S1_IDENTITY,
    )

    record = collected.to_outcome_record()
    assert record is not None
    assert record["kind"] == "unknown"
    assert record["code"] == "host_unreachable"
    assert collected.payload.get("artifactRef") is None
    assert collected.identity.get("artifactRef") is None
    assert peek_runner.calls
    assert peek_runner.calls[0][0][7:9] == ("sandbox", "download")
    assert _claim_state(state_path, "attempt-1") == SandboxState.READY


def test_collect_unreadable_lookup_is_unknown_host_unreachable(tmp_path: Path):
    class UnreadablePeekService(RuntimeService):
        def peek(self, idempotency_key: str):
            raise RuntimeError("sandbox adoption failed: backend down")

    runner = RecordingRunner([])
    facade = OperationFacade(
        UnreadablePeekService(
            OpenShellDockerAdapter(config(), runner),
            state_path=tmp_path / "runtime.db",
        )
    )

    collected = facade.collect(
        "attempt-1",
        [{"path": "/work/report.json"}],
        identity=_S1_IDENTITY,
    )

    record = collected.to_outcome_record()
    assert record is not None
    assert record["kind"] == "unknown"
    assert record["code"] == "host_unreachable"
    assert record["sideEffects"] == "unreconciled"
    assert record["reconcile"] is True
    assert collected.payload.get("artifactRef") is None
    assert runner.calls == []


@pytest.mark.parametrize(
    "error",
    [sqlite3.OperationalError("disk I/O error"), OSError("database missing")],
)
def test_collect_sqlite_or_oserror_lookup_is_unknown_host_unreachable(
    tmp_path: Path, error: Exception
):
    class BrokenPeekService(RuntimeService):
        def peek(self, idempotency_key: str):
            raise error

    runner = RecordingRunner([])
    facade = OperationFacade(
        BrokenPeekService(
            OpenShellDockerAdapter(config(), runner),
            state_path=tmp_path / "runtime.db",
        )
    )

    collected = facade.collect(
        "attempt-1",
        [{"path": "/work/report.json"}],
        identity=_S1_IDENTITY,
    )

    record = collected.to_outcome_record()
    assert record is not None
    assert record["kind"] == "unknown"
    assert record["code"] == "host_unreachable"
    assert record["sideEffects"] == "unreconciled"
    assert record["reconcile"] is True
    assert collected.payload.get("artifactRef") is None
    assert runner.calls == []


def test_oversized_run_id_is_refused_before_backend_and_claim(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    state_path = tmp_path / "runtime.db"
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    identity = {**_S1_IDENTITY, "runId": "r" * 300}

    created = facade.create("attempt-1", _create_request(), identity=identity)

    record = created.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_profile"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert "runId" not in record["identity"] or len(record["identity"]["runId"]) <= 256
    assert runner.calls == []
    assert _claim_count(state_path) == 0
    events = facade.observe()
    assert events[0]["payload"]["code"] == "invalid_profile"
    assert len(events[0]["identity"].get("runId", "x")) <= 256


def test_oversized_operation_id_is_refused_before_backend_and_claim(
    tmp_path: Path,
):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    state_path = tmp_path / "runtime.db"
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    identity = {**_S1_IDENTITY, "operationId": "op-" + ("x" * 300)}

    created = facade.create("attempt-1", _create_request(), identity=identity)

    record = created.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_profile"
    assert record["sideEffects"] == "none"
    assert len(record["operationId"]) <= 256
    assert runner.calls == []
    assert _claim_count(state_path) == 0


def test_unknown_profile_create_is_profile_unknown_before_claim_on_unverified_host(
    tmp_path: Path,
):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    state_path = tmp_path / "runtime.db"
    facade = _facade(tmp_path, runner)

    created = facade.create(
        "attempt-1", _unknown_profile_request(), identity=_S1_IDENTITY
    )

    record = created.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "profile_unknown"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert record["code"] != "profile_unverified"
    assert created.identity.get("sandboxId") is None
    assert runner.calls == []
    assert _claim_count(state_path) == 0


def test_exec_request_value_errors_are_typed_outcomes(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}'), result(backend_json())])
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    facade.wait_ready("attempt-1", identity=_S1_IDENTITY)
    calls_after_ready = list(runner.calls)

    empty = facade.exec("attempt-1", (), identity=_S1_IDENTITY)
    denied = facade.exec("attempt-1", ("id",), cwd="/etc", identity=_S1_IDENTITY)
    timed = facade.wait_ready("attempt-1", identity=_S1_IDENTITY, timeout_seconds=0)

    empty_record = empty.to_outcome_record()
    denied_record = denied.to_outcome_record()
    timed_record = timed.to_outcome_record()
    assert empty_record is not None
    assert empty_record["kind"] == "refused"
    assert empty_record["code"] == "invalid_profile"
    assert empty_record["sideEffects"] == "none"
    assert denied_record is not None
    assert denied_record["kind"] == "refused"
    assert denied_record["code"] == "grant_denied"
    assert denied_record["sideEffects"] == "none"
    assert timed_record is not None
    assert timed_record["kind"] == "refused"
    assert timed_record["code"] == "invalid_state"
    assert timed_record["reconcile"] is False
    assert runner.calls == calls_after_ready


def test_invalid_idempotency_key_is_refused_without_claim(tmp_path: Path):
    runner = RecordingRunner([result('{"name":"route-probe"}')])
    state_path = tmp_path / "runtime.db"
    facade = _facade(
        tmp_path,
        runner,
        profile_acceptance="verified",
        policy_verified=True,
    )

    created = facade.create("", _create_request(), identity=_S1_IDENTITY)

    record = created.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_state"
    assert record["sideEffects"] == "none"
    assert runner.calls == []
    assert _claim_count(state_path) == 0


def test_wait_ready_get_timeout_on_fresh_service_is_refused_invalid_state(
    tmp_path: Path,
):
    state_path = tmp_path / "runtime.db"
    first_runner = RecordingRunner([result('{"name":"route-probe"}')])
    first = _facade(
        tmp_path,
        first_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    created = first.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    assert created.kind is None
    assert _verbs(first_runner) == [("sandbox", "create")]

    second_runner = RecordingRunner(
        [
            result(returncode=124, stderr="timed out"),
            result('{"name":"route-probe-2"}'),
        ]
    )
    second = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True),
                second_runner,
            ),
            state_path=state_path,
        )
    )
    waited = second.wait_ready("attempt-1", identity=_S1_IDENTITY)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["operation"] == "sandboxes.waitReady"
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_state"
    assert record["sideEffects"] == "none"
    assert record["reconcile"] is False
    assert "sandboxId" not in record["identity"]
    events = second.observe()
    assert events[-1]["type"] == "box.sandboxes.waitReady"
    assert events[-1]["identity"]["sandboxId"] == "route-probe"
    assert events[-1]["payload"]["kind"] == "refused"
    assert events[-1]["payload"]["code"] == "invalid_state"
    assert _verbs(second_runner) == [("sandbox", "get")]
    assert _claim_state(state_path, "attempt-1") == SandboxState.PROVISIONING


def test_wait_ready_does_not_rewrite_ready_claim_before_inspect_timeout(
    tmp_path: Path,
):
    state_path = tmp_path / "runtime.db"
    first_runner = RecordingRunner(
        [result('{"name":"route-probe"}'), result(backend_json())]
    )
    first = _facade(
        tmp_path,
        first_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    first.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    ready = first.wait_ready("attempt-1", identity=_S1_IDENTITY)
    assert ready.kind is None
    assert ready.payload["state"] == "ready"

    second_runner = RecordingRunner(
        [
            result(backend_json(phase="Provisioning")),
            result(returncode=124, stderr="timed out"),
            result('{"name":"route-probe-2"}'),
        ]
    )
    second = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True),
                second_runner,
            ),
            state_path=state_path,
        )
    )
    waited = second.wait_ready("attempt-1", identity=_S1_IDENTITY)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["kind"] == "refused"
    assert record["code"] == "invalid_state"
    assert record["reconcile"] is False
    assert "sandboxId" not in record["identity"]
    events = second.observe()
    assert events[-1]["identity"]["sandboxId"] == "route-probe"
    assert _verbs(second_runner) == [("sandbox", "get"), ("sandbox", "get")]
    assert _claim_state(state_path, "attempt-1") == SandboxState.READY


def test_wait_ready_get_failure_on_fresh_service_is_unknown_host_unreachable(
    tmp_path: Path,
):
    state_path = tmp_path / "runtime.db"
    first_runner = RecordingRunner([result('{"name":"route-probe"}')])
    first = _facade(
        tmp_path,
        first_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    first.create("attempt-1", _create_request(), identity=_S1_IDENTITY)

    second_runner = RecordingRunner(
        [
            result(returncode=1, stderr="gateway down"),
            result('{"name":"route-probe-2"}'),
        ]
    )
    second = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True),
                second_runner,
            ),
            state_path=state_path,
        )
    )
    waited = second.wait_ready("attempt-1", identity=_S1_IDENTITY)

    record = waited.to_outcome_record()
    assert record is not None
    assert record["kind"] == "unknown"
    assert record["code"] == "host_unreachable"
    assert record["sideEffects"] == "unreconciled"
    assert record["reconcile"] is True
    assert "sandboxId" not in record["identity"]
    events = second.observe()
    assert events[-1]["identity"]["sandboxId"] == "route-probe"
    assert events[-1]["payload"]["code"] == "host_unreachable"
    assert _verbs(second_runner) == [("sandbox", "get")]
    assert _claim_state(state_path, "attempt-1") == SandboxState.PROVISIONING


def test_wait_ready_exec_delete_error_events_include_known_sandbox_id(
    tmp_path: Path,
):
    wait_runner = RecordingRunner(
        [result('{"name":"route-probe"}'), result(returncode=124, stderr="timed out")]
    )
    wait_facade = _facade(
        tmp_path / "wait",
        wait_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    wait_facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    waited = wait_facade.wait_ready("attempt-1", identity=_S1_IDENTITY)
    wait_record = waited.to_outcome_record()
    assert wait_record is not None
    assert "sandboxId" not in wait_record["identity"]
    wait_event = wait_facade.observe()[-1]
    assert wait_event["type"] == "box.sandboxes.waitReady"
    assert wait_event["identity"]["sandboxId"] == "route-probe"
    assert wait_event["payload"]["kind"] == "refused"
    assert wait_event["payload"]["code"] == "invalid_state"

    exec_runner = RecordingRunner([result('{"name":"route-probe"}')])
    exec_facade = _facade(
        tmp_path / "exec",
        exec_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    exec_facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    executed = exec_facade.exec("attempt-1", ("id",), identity=_S1_IDENTITY)
    exec_record = executed.to_outcome_record()
    assert exec_record is not None
    assert exec_record["kind"] == "refused"
    assert exec_record["code"] == "invalid_state"
    assert "sandboxId" not in exec_record["identity"]
    exec_event = exec_facade.observe()[-1]
    assert exec_event["type"] == "box.exec"
    assert exec_event["identity"]["sandboxId"] == "route-probe"

    delete_runner = RecordingRunner(
        [
            result('{"name":"route-probe"}'),
            result(returncode=1, stderr="delete failed"),
        ]
    )
    delete_facade = _facade(
        tmp_path / "delete",
        delete_runner,
        profile_acceptance="verified",
        policy_verified=True,
    )
    delete_facade.create("attempt-1", _create_request(), identity=_S1_IDENTITY)
    deleted = delete_facade.delete("attempt-1", identity=_S1_IDENTITY)
    delete_record = deleted.to_outcome_record()
    assert delete_record is not None
    assert delete_record["kind"] == "unknown"
    assert delete_record["code"] == "host_unreachable"
    assert "sandboxId" not in delete_record["identity"]
    delete_event = delete_facade.observe()[-1]
    assert delete_event["type"] == "box.sandboxes.delete"
    assert delete_event["identity"]["sandboxId"] == "route-probe"
    assert delete_event["payload"]["code"] == "host_unreachable"
