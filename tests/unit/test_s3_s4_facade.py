from __future__ import annotations

from pathlib import Path

from kappa_box.facade import OperationFacade
from kappa_box.profile_gate import evaluate_host_record
from kappa_box.runtime import OpenShellDockerAdapter, RuntimeService

from test_facade import (
    RecordingRunner,
    _REGISTERED_PROFILE,
    _S1_IDENTITY,
    _create_request,
    backend_json,
    config,
    result,
)


class _AdvertiseVerifiedButHostFailed:
    def evaluate(self, *, profile_id: str, registry_acceptance: str):
        del profile_id, registry_acceptance
        return evaluate_host_record(
            registry_acceptance="verified",
            host_record={"failureGroups": ["host"]},
            facts_digest="sha256:advertised",
        )


def test_inspect_does_not_advertise_verified_registry_when_host_fails(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner([])
    facade = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(config(), runner),
            state_path=tmp_path / "runtime.db",
        ),
        profile_gate=_AdvertiseVerifiedButHostFailed(),
    )

    inspected = facade.inspect(_REGISTERED_PROFILE, identity=_S1_IDENTITY)

    assert inspected.payload["acceptance"] == "unverified"
    assert inspected.payload["available"] is False
    assert inspected.payload["hostResult"] == "fail"
    assert inspected.payload["failureGroups"] == ["host"]
    assert inspected.payload["factsDigest"] is None
    assert runner.calls == []


def test_collect_without_snapshot_bytes_is_unknown_not_forged(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner(
        [
            result('{"name":"route-probe"}'),
            result(backend_json()),
            result(),
        ]
    )
    facade = OperationFacade(
        RuntimeService(
            OpenShellDockerAdapter(
                config(profile_acceptance="verified", policy_verified=True),
                runner,
            ),
            state_path=tmp_path / "runtime.db",
            collect_dir=tmp_path / "collect",
        )
    )
    identity = {**_S1_IDENTITY, "operationId": None}
    facade.create("attempt-1", _create_request(), identity=identity)
    facade.wait_ready("attempt-1", identity=identity)
    collected = facade.collect(
        "attempt-1", [{"path": "/work/report.json"}], identity=identity
    )
    record = collected.to_outcome_record()
    assert record is not None
    assert record["kind"] == "unknown"
    assert record["code"] == "host_unreachable"
    assert collected.payload.get("artifactRef") is None
