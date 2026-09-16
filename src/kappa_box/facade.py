"""S1 operation, event, and artifact facade over RuntimeService."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from kappa_box.outcomes import (
    OperationOutcome,
    OperationOutcomeError,
    failed,
    refused,
    unknown,
)
from kappa_box.profile import load_profile
from kappa_box.runtime import (
    RuntimeService,
    Sandbox,
    SandboxRequest,
    SandboxState,
)

_ROOT = Path(__file__).resolve().parents[2]
_EVENT_SCHEMA_PATH = _ROOT / "schemas" / "s1-event.schema.json"
_OUTCOME_SCHEMA_PATH = _ROOT / "schemas" / "s1-outcome.schema.json"
_REGISTERED_PROFILE = "wsl2:l1@openshell-docker"
_DEFAULT_REGISTRY = {
    _REGISTERED_PROFILE: _ROOT
    / "profiles"
    / "registry"
    / "wsl2-l1-openshell-docker.json",
}
_SCHEMA_VERSION = "s1-draft-1"
_S1_OPERATIONS = (
    "profiles.inspect",
    "sandboxes.create",
    "sandboxes.waitReady",
    "exec",
    "collect",
    "sandboxes.delete",
)
_FORWARDED_IDENTITY = (
    "runId",
    "candidateRef",
    "baselineRef",
    "benchmarkRevision",
    "sessionId",
    "branchId",
    "requestId",
)
_OUTCOME_IDENTITY = ("runId", "requestId")
_ENVELOPE_STRING_KEYS = (*_FORWARDED_IDENTITY, "operationId", "profileId")
_ENVELOPE_MAX = 256
_VALUE_ERROR_CODES = (
    ("unknown idempotency key", "invalid_state"),
    ("idempotency key must be non-empty and bounded", "invalid_state"),
    ("timeout_seconds must be finite and positive", "invalid_state"),
    ("sandbox is not ready", "invalid_state"),
    ("sandbox is deleted", "invalid_state"),
    ("sandbox is not collectable", "invalid_state"),
    ("sandbox name is invalid", "invalid_state"),
    ("sandbox handle is not bound", "invalid_state"),
    ("profile is not registered", "profile_unknown"),
    ("image is not approved", "invalid_profile"),
    ("environment variables are not registered", "invalid_profile"),
    ("exec argv must be non-empty", "invalid_profile"),
    ("exec cwd must be an absolute sandbox path", "grant_denied"),
    ("cwd is outside registered grants", "grant_denied"),
    ("path is outside registered grants", "grant_denied"),
)


@dataclass(frozen=True)
class OperationResult:
    """One S1 facade operation result. Error outcomes wrap the L1 record."""

    operation_id: str
    operation: str
    identity: dict[str, Any]
    kind: str | None
    code: str | None
    side_effects: str
    reconcile: bool
    payload: dict[str, Any]

    def to_outcome_record(self) -> dict[str, Any] | None:
        if self.kind is None:
            return None
        record = {
            "operationId": self.operation_id,
            "operation": self.operation,
            "identity": {
                key: self.identity[key]
                for key in ("runId", "requestId", "profileId")
                if key in self.identity
            },
            "kind": self.kind,
            "code": self.code,
            "sideEffects": self.side_effects,
            "reconcile": self.reconcile,
        }
        _validate_outcome(record)
        return record


class OperationFacade:
    """S1 operation surface with a runtime-owned event cursor on state_path."""

    def __init__(
        self,
        service: RuntimeService,
        *,
        profile_registry: Mapping[str, Path] | None = None,
    ) -> None:
        self._service = service
        self._registry = {
            profile_id: Path(path)
            for profile_id, path in (profile_registry or _DEFAULT_REGISTRY).items()
        }
        self._lock = threading.RLock()

    def inspect(
        self,
        profile_id: str,
        *,
        identity: Mapping[str, Any] | None = None,
    ) -> OperationResult:
        return self.invoke("profiles.inspect", identity=identity, profile_id=profile_id)

    def create(
        self,
        idempotency_key: str,
        request: SandboxRequest,
        *,
        identity: Mapping[str, Any] | None = None,
    ) -> OperationResult:
        return self.invoke(
            "sandboxes.create",
            identity=identity,
            idempotency_key=idempotency_key,
            request=request,
        )

    def wait_ready(
        self,
        idempotency_key: str,
        *,
        identity: Mapping[str, Any] | None = None,
        timeout_seconds: float = 120.0,
    ) -> OperationResult:
        return self.invoke(
            "sandboxes.waitReady",
            identity=identity,
            idempotency_key=idempotency_key,
            timeout_seconds=timeout_seconds,
        )

    def exec(
        self,
        idempotency_key: str,
        argv: tuple[str, ...],
        *,
        cwd: str | None = None,
        identity: Mapping[str, Any] | None = None,
        timeout_seconds: float = 120.0,
    ) -> OperationResult:
        return self.invoke(
            "exec",
            identity=identity,
            idempotency_key=idempotency_key,
            argv=argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )

    def collect(
        self,
        idempotency_key: str,
        items: Any,
        *,
        identity: Mapping[str, Any] | None = None,
    ) -> OperationResult:
        return self.invoke(
            "collect",
            identity=identity,
            idempotency_key=idempotency_key,
            items=items,
        )

    def delete(
        self,
        idempotency_key: str,
        *,
        identity: Mapping[str, Any] | None = None,
    ) -> OperationResult:
        return self.invoke(
            "sandboxes.delete",
            identity=identity,
            idempotency_key=idempotency_key,
        )

    def invoke(
        self,
        operation: str,
        *,
        identity: Mapping[str, Any] | None = None,
        **arguments: Any,
    ) -> OperationResult:
        if _envelope_invalid(operation, identity):
            return self._finish_error(
                _recorded_operation(operation),
                _usable_identity(identity),
                refused("invalid_profile"),
            )
        handlers = {
            "profiles.inspect": self._inspect,
            "sandboxes.create": self._create,
            "sandboxes.waitReady": self._wait_ready,
            "exec": self._exec,
            "collect": self._collect,
            "sandboxes.delete": self._delete,
        }
        handler = handlers.get(operation)
        if handler is None:
            return self._finish_error(operation, identity, refused("unsupported"))
        return handler(identity=identity, **arguments)

    def observe(self, cursor: str | None = None) -> list[dict[str, Any]]:
        start = _cursor_index(cursor)
        return self._service.list_events(after=start)

    def _inspect(
        self, *, identity: Mapping[str, Any] | None, profile_id: str
    ) -> OperationResult:
        if not isinstance(profile_id, str) or not (
            0 < len(profile_id) <= _ENVELOPE_MAX
        ):
            return self._finish_error(
                "profiles.inspect", identity, refused("invalid_profile")
            )
        path = self._registry.get(profile_id)
        if path is None:
            return self._finish_error(
                "profiles.inspect",
                identity,
                refused("profile_unknown"),
                profile_id=profile_id,
            )
        profile = load_profile(path)
        acceptance = profile["acceptance"]
        payload = {
            "profileId": profile["id"],
            "acceptance": acceptance,
            "available": acceptance == "verified",
            "hostClass": profile["hostClass"],
            "tier": profile["tier"],
            "variant": profile.get("variant"),
        }
        return self._finish_success(
            "profiles.inspect",
            identity,
            payload,
            profile_id=profile["id"],
        )

    def _create(
        self,
        *,
        identity: Mapping[str, Any] | None,
        idempotency_key: str,
        request: SandboxRequest,
    ) -> OperationResult:
        if not isinstance(request.profile_id, str) or not (
            0 < len(request.profile_id) <= _ENVELOPE_MAX
        ):
            return self._finish_error(
                "sandboxes.create", identity, refused("invalid_profile")
            )
        if request.profile_id not in self._registry:
            return self._finish_error(
                "sandboxes.create",
                identity,
                refused("profile_unknown"),
                profile_id=request.profile_id,
            )

        def _call() -> Sandbox:
            return self._service.create(idempotency_key, request)

        sandbox = self._call_service(
            "sandboxes.create", identity, _call, profile_id=request.profile_id
        )
        if isinstance(sandbox, OperationResult):
            return sandbox
        return self._finish_success(
            "sandboxes.create",
            identity,
            {"state": sandbox.state.value, "sandboxId": sandbox.name},
            profile_id=sandbox.profile_id,
            sandbox_id=sandbox.name,
        )

    def _wait_ready(
        self,
        *,
        identity: Mapping[str, Any] | None,
        idempotency_key: str,
        timeout_seconds: float = 120.0,
    ) -> OperationResult:
        profile_id, sandbox_id = self._local_identity(idempotency_key)

        def _call() -> Sandbox:
            return self._service.wait_ready(
                idempotency_key, timeout_seconds=timeout_seconds
            )

        sandbox = self._call_service(
            "sandboxes.waitReady",
            identity,
            _call,
            profile_id=profile_id,
            sandbox_id=sandbox_id,
            timeout_outcome=refused("invalid_state"),
        )
        if isinstance(sandbox, OperationResult):
            return sandbox
        if sandbox.state is SandboxState.READY:
            return self._finish_success(
                "sandboxes.waitReady",
                identity,
                {"state": sandbox.state.value, "factsDigest": None},
                profile_id=sandbox.profile_id,
                sandbox_id=sandbox.name,
            )
        outcome = (
            failed("provisioning_failed")
            if sandbox.state is SandboxState.FAILED
            else refused("invalid_state")
        )
        return self._finish_error(
            "sandboxes.waitReady",
            identity,
            outcome,
            profile_id=sandbox.profile_id,
            sandbox_id=sandbox.name,
        )

    def _exec(
        self,
        *,
        identity: Mapping[str, Any] | None,
        idempotency_key: str,
        argv: tuple[str, ...],
        cwd: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> OperationResult:
        profile_id, sandbox_id = self._local_identity(idempotency_key)

        def _call() -> Any:
            return self._service.exec(
                idempotency_key,
                argv,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
            )

        execution = self._call_service(
            "exec",
            identity,
            _call,
            profile_id=profile_id,
            sandbox_id=sandbox_id,
        )
        if isinstance(execution, OperationResult):
            return execution
        sandbox = self._peek(idempotency_key)
        return self._finish_success(
            "exec",
            identity,
            {
                "exitCode": execution.exit_code,
                "stdout": execution.stdout,
                "stderr": execution.stderr,
                "truncated": execution.truncated,
            },
            profile_id=None if sandbox is None else sandbox.profile_id,
            sandbox_id=None if sandbox is None else sandbox.name,
        )

    def _collect(
        self,
        *,
        identity: Mapping[str, Any] | None,
        idempotency_key: str,
        items: Any,
    ) -> OperationResult:
        del items
        try:
            sandbox = self._peek(idempotency_key)
        except (RuntimeError, OSError, sqlite3.Error):
            return self._finish_error("collect", identity, unknown("host_unreachable"))
        if sandbox is None or sandbox.state not in {
            SandboxState.READY,
            SandboxState.STOPPED,
        }:
            return self._finish_error(
                "collect",
                identity,
                refused("invalid_state"),
                profile_id=None if sandbox is None else sandbox.profile_id,
                sandbox_id=None if sandbox is None else sandbox.name,
            )
        return self._finish_error(
            "collect",
            identity,
            refused("unsupported"),
            profile_id=sandbox.profile_id,
            sandbox_id=sandbox.name,
        )

    def _delete(
        self,
        *,
        identity: Mapping[str, Any] | None,
        idempotency_key: str,
    ) -> OperationResult:
        profile_id, sandbox_id = self._local_identity(idempotency_key)

        def _call() -> Sandbox:
            return self._service.delete(idempotency_key)

        sandbox = self._call_service(
            "sandboxes.delete",
            identity,
            _call,
            profile_id=profile_id,
            sandbox_id=sandbox_id,
        )
        if isinstance(sandbox, OperationResult):
            return sandbox
        return self._finish_success(
            "sandboxes.delete",
            identity,
            {"state": sandbox.state.value},
            profile_id=sandbox.profile_id,
            sandbox_id=sandbox.name,
        )

    def _call_service(
        self,
        operation: str,
        identity: Mapping[str, Any] | None,
        fn: Any,
        *,
        profile_id: str | None = None,
        sandbox_id: str | None = None,
        timeout_outcome: OperationOutcome | None = None,
    ) -> Any:
        try:
            return fn()
        except OperationOutcomeError as error:
            return self._finish_error(
                operation,
                identity,
                error.outcome,
                profile_id=profile_id,
                sandbox_id=sandbox_id,
            )
        except KeyError:
            return self._finish_error(
                operation,
                identity,
                refused("invalid_state"),
                profile_id=profile_id,
                sandbox_id=sandbox_id,
            )
        except TimeoutError:
            return self._finish_error(
                operation,
                identity,
                timeout_outcome or unknown("deadline_exceeded"),
                profile_id=profile_id,
                sandbox_id=sandbox_id,
            )
        except ValueError as error:
            code = _refused_value_error(error)
            if code is None:
                raise
            return self._finish_error(
                operation,
                identity,
                refused(code),
                profile_id=profile_id,
                sandbox_id=sandbox_id,
            )
        except (RuntimeError, OSError, sqlite3.Error):
            return self._finish_error(
                operation,
                identity,
                unknown("host_unreachable"),
                profile_id=profile_id,
                sandbox_id=sandbox_id,
            )

    def _peek(self, idempotency_key: str) -> Sandbox | None:
        return self._service.peek(idempotency_key)

    def _local_identity(self, idempotency_key: str) -> tuple[str | None, str | None]:
        try:
            sandbox = self._peek(idempotency_key)
        except (RuntimeError, OSError, sqlite3.Error):
            return None, None
        if sandbox is None:
            return None, None
        return sandbox.profile_id, sandbox.name

    def _finish_success(
        self,
        operation: str,
        identity: Mapping[str, Any] | None,
        payload: dict[str, Any],
        *,
        profile_id: str | None,
        sandbox_id: str | None = None,
    ) -> OperationResult:
        return self._finish(
            operation,
            identity,
            kind=None,
            code=None,
            side_effects="none" if operation == "profiles.inspect" else "present",
            reconcile=False,
            payload=payload,
            profile_id=profile_id,
            sandbox_id=sandbox_id,
        )

    def _finish_error(
        self,
        operation: str,
        identity: Mapping[str, Any] | None,
        outcome: OperationOutcome,
        *,
        profile_id: str | None = None,
        sandbox_id: str | None = None,
    ) -> OperationResult:
        record = outcome.to_record()
        return self._finish(
            operation,
            identity,
            kind=str(record["kind"]),
            code=str(record["code"]),
            side_effects=str(record["sideEffects"]),
            reconcile=bool(record["reconcile"]),
            payload={
                "kind": record["kind"],
                "code": record["code"],
                "sideEffects": record["sideEffects"],
                "reconcile": record["reconcile"],
            },
            profile_id=profile_id,
            sandbox_id=sandbox_id,
        )

    def _finish(
        self,
        operation: str,
        identity: Mapping[str, Any] | None,
        *,
        kind: str | None,
        code: str | None,
        side_effects: str,
        reconcile: bool,
        payload: dict[str, Any],
        profile_id: str | None,
        sandbox_id: str | None,
    ) -> OperationResult:
        supplied = {} if identity is None else identity
        operation_id = _string_field(supplied, "operationId")
        resolved_profile = profile_id or _string_field(supplied, "profileId")
        if resolved_profile is None or len(resolved_profile) > _ENVELOPE_MAX:
            resolved_profile = _REGISTERED_PROFILE
        with self._lock:
            result_identity = _result_identity(
                supplied, profile_id=resolved_profile, sandbox_id=sandbox_id
            )
            event_payload = dict(payload)
            stored = self._append_event(
                operation=operation,
                operation_id=operation_id,
                supplied=supplied,
                profile_id=resolved_profile,
                sandbox_id=sandbox_id,
                payload=event_payload,
            )
            operation_id = str(stored["identity"]["operationId"])
        return OperationResult(
            operation_id=operation_id,
            operation=operation,
            identity=result_identity,
            kind=kind,
            code=code,
            side_effects=side_effects,
            reconcile=reconcile,
            payload=payload,
        )

    def _append_event(
        self,
        *,
        operation: str,
        operation_id: str | None,
        supplied: Mapping[str, Any],
        profile_id: str,
        sandbox_id: str | None,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        event_identity: dict[str, Any] = {
            "profileId": profile_id,
        }
        if operation_id is not None:
            event_identity["operationId"] = operation_id
        for key in _FORWARDED_IDENTITY:
            value = _string_field(supplied, key)
            if value is not None:
                event_identity[key] = value
        if sandbox_id is not None:
            event_identity["sandboxId"] = sandbox_id
        cause: dict[str, Any] = {"kind": "external_intent"}
        request_id = _string_field(supplied, "requestId")
        if request_id is not None:
            cause["requestId"] = request_id
        event = {
            "schemaVersion": _SCHEMA_VERSION,
            "type": f"box.{operation}",
            "identity": event_identity,
            "cause": cause,
            "payload": payload,
            "provenance": {"owner": "kappa-box", "source": "runtime"},
        }
        return self._service.append_event(event, validate=_validate_event)


def _result_identity(
    supplied: Mapping[str, Any],
    *,
    profile_id: str,
    sandbox_id: str | None,
) -> dict[str, Any]:
    record: dict[str, Any] = {"profileId": profile_id}
    for key in _OUTCOME_IDENTITY:
        value = _string_field(supplied, key)
        if value is not None:
            record[key] = value
    if sandbox_id is not None:
        record["sandboxId"] = sandbox_id
    return record


def _string_field(supplied: Mapping[str, Any], key: str) -> str | None:
    value = supplied.get(key)
    if isinstance(value, str) and value and len(value) <= _ENVELOPE_MAX:
        return value
    return None


def _recorded_operation(operation: object) -> str:
    if (
        isinstance(operation, str)
        and operation
        and len(operation) <= 128
        and len(f"box.{operation}") <= 128
    ):
        return operation
    return "invalid"


def _usable_identity(identity: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(identity, Mapping):
        return {}
    usable: dict[str, Any] = {}
    for key in _ENVELOPE_STRING_KEYS:
        value = identity.get(key)
        if isinstance(value, str) and value and len(value) <= _ENVELOPE_MAX:
            usable[key] = value
    return usable


def _envelope_invalid(operation: object, identity: Mapping[str, Any] | None) -> bool:
    if (
        not isinstance(operation, str)
        or not operation
        or len(operation) > 128
        or len(f"box.{operation}") > 128
    ):
        return True
    if identity is None:
        return False
    if not isinstance(identity, Mapping):
        return True
    for key in _ENVELOPE_STRING_KEYS:
        if key not in identity:
            continue
        value = identity[key]
        if value is None:
            continue
        if isinstance(value, str) and not value:
            continue
        if not isinstance(value, str) or len(value) > _ENVELOPE_MAX:
            return True
    return False


def _cursor_index(cursor: str | None) -> int:
    if cursor in (None, "", "0"):
        return 0
    if (
        not isinstance(cursor, str)
        or not cursor.isdigit()
        or cursor != str(int(cursor))
    ):
        raise ValueError("event cursor is invalid")
    return int(cursor)


def _refused_value_error(error: ValueError) -> str | None:
    message = str(error)
    for fragment, code in _VALUE_ERROR_CODES:
        if fragment in message:
            return code
    return None


@cache
def _event_validator() -> Draft202012Validator:
    try:
        schema = json.loads(_EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("s1 event schema is unavailable") from error
    return Draft202012Validator(schema, format_checker=FormatChecker())


@cache
def _outcome_validator() -> Draft202012Validator:
    try:
        schema = json.loads(_OUTCOME_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("s1 outcome schema is unavailable") from error
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_event(record: Mapping[str, Any]) -> None:
    try:
        _event_validator().validate(record)
    except ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "event"
        raise ValueError(
            f"s1 event schema validation failed at {location}: {error.message}"
        ) from error


def _validate_outcome(record: Mapping[str, Any]) -> None:
    try:
        _outcome_validator().validate(record)
    except ValidationError as error:
        location = ".".join(str(part) for part in error.absolute_path) or "outcome"
        raise ValueError(
            f"s1 outcome schema validation failed at {location}: {error.message}"
        ) from error


# Keep the supported operation list discoverable without exposing handlers.
SUPPORTED_OPERATIONS = _S1_OPERATIONS
