"""Real OpenShell Docker runtime adapter for the registered WSL2 profile."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from kappa_box.outcomes import (
    OperationOutcome,
    OperationOutcomeError,
    failed,
    l1_create_gate,
    l1_execution_error,
    outcome_from_record,
    refused,
    unknown,
)

_REGISTERED_PROFILE = "wsl2:l1@openshell-docker"
_REGISTERED_DISTRIBUTION = "kappa-box-ubuntu-24.04"
_REGISTERED_GATEWAY_ENDPOINT = "http://127.0.0.1:17670"
_REGISTERED_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)
_REGISTERED_OPEN_SHELL_BINARY = "/usr/local/bin/openshell"
_REGISTERED_STAGING_ROOT = "/var/lib/kappa-box/staging"
_WSL_BINARY = r"C:\Windows\System32\wsl.exe"
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CREATED_SANDBOX = re.compile(r"Created sandbox:\s*([A-Za-z0-9][A-Za-z0-9-]*)")
_MAX_OUTPUT_BYTES = 256 * 1024


class IdempotencyConflictError(OperationOutcomeError):
    """The same idempotency key was used for a different request."""

    def __init__(self, message: str = "idempotency key request differs") -> None:
        super().__init__(refused("idempotency_conflict"), detail=message)


@dataclass(frozen=True)
class RuntimeCommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False


class RuntimeCommandRunner(Protocol):
    def run(
        self, argv: tuple[str, ...], timeout_seconds: float
    ) -> RuntimeCommandResult: ...


class SubprocessRuntimeRunner:
    """Run the fixed WSL/OpenShell command boundary on the Windows host."""

    def __init__(self, *, max_output_bytes: int = _MAX_OUTPUT_BYTES) -> None:
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        self._max_output_bytes = max_output_bytes

    def run(
        self, argv: tuple[str, ...], timeout_seconds: float
    ) -> RuntimeCommandResult:
        _validate_timeout(timeout_seconds)
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
            stdout, stdout_truncated = _bounded_text(
                completed.stdout, self._max_output_bytes
            )
            stderr, stderr_truncated = _bounded_text(
                completed.stderr, self._max_output_bytes
            )
            return RuntimeCommandResult(
                argv=argv,
                returncode=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                truncated=stdout_truncated or stderr_truncated,
            )
        except subprocess.TimeoutExpired as error:
            stdout, stdout_truncated = _bounded_text(
                _as_text(error.stdout), self._max_output_bytes
            )
            stderr, stderr_truncated = _bounded_text(
                _as_text(error.stderr), self._max_output_bytes
            )
            return RuntimeCommandResult(
                argv=argv,
                returncode=124,
                stdout=stdout,
                stderr=stderr,
                truncated=stdout_truncated or stderr_truncated,
            )
        except OSError as error:
            stderr, stderr_truncated = _bounded_text(str(error), self._max_output_bytes)
            return RuntimeCommandResult(
                argv=argv,
                returncode=127,
                stdout="",
                stderr=stderr,
                truncated=stderr_truncated,
            )


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return (
        value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    )


def _bounded_text(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    truncated = len(encoded) > max_bytes
    return encoded[:max_bytes].decode("utf-8", errors="replace"), truncated


def _validate_timeout(timeout_seconds: float) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be finite and positive")


class SandboxState(StrEnum):
    PROVISIONING = "provisioning"
    READY = "ready"
    STOPPED = "stopped"
    FAILED = "failed"
    DELETED = "deleted"


@dataclass(frozen=True)
class RuntimeConfig:
    profile_id: str
    distribution: str
    gateway_endpoint: str
    openshell_binary: str
    approved_images: tuple[str, ...]
    gateway_insecure: bool = False
    granted_roots: tuple[str, ...] = ("/work",)
    trusted_staging_root: str = _REGISTERED_STAGING_ROOT
    allowed_env_keys: tuple[str, ...] = ()
    profile_acceptance: str = "unverified"
    probe_only: bool = False
    policy_verified: bool = False
    network_profile: str = "offline"
    landlock_compatibility: str = "hard_requirement"
    default_cpu: str = "1"
    default_memory: str = "512Mi"

    def __post_init__(self) -> None:
        if self.profile_id != _REGISTERED_PROFILE:
            raise ValueError("runtime profile is not registered")
        if self.distribution != _REGISTERED_DISTRIBUTION:
            raise ValueError("runtime distribution is not registered")
        if self.gateway_endpoint != _REGISTERED_GATEWAY_ENDPOINT:
            raise ValueError("gateway endpoint is not registered")
        if not self.gateway_endpoint.startswith(("http://", "https://")):
            raise ValueError("gateway endpoint must be an HTTP URL")
        if self.gateway_endpoint.startswith("http://") and not (
            self.gateway_insecure and self.probe_only
        ):
            raise ValueError(
                "plaintext gateway requires explicit probe-only insecure opt-in"
            )
        if self.gateway_insecure and not self.probe_only:
            raise ValueError("insecure gateway is only available to probes")
        if self.openshell_binary != _REGISTERED_OPEN_SHELL_BINARY:
            raise ValueError("OpenShell binary is not registered")
        if not self.approved_images:
            raise ValueError("at least one approved image is required")
        if self.approved_images != (_REGISTERED_IMAGE,):
            raise ValueError("image pin is not registered")
        if self.granted_roots != ("/work",):
            raise ValueError("grant roots are not registered")
        if self.trusted_staging_root != _REGISTERED_STAGING_ROOT:
            raise ValueError("staging root is not registered")
        if self.profile_acceptance not in {"verified", "unverified"}:
            raise ValueError("profile acceptance is invalid")
        if self.network_profile not in {"offline", "restricted"}:
            raise ValueError("network profile is not registered")
        if self.landlock_compatibility != "hard_requirement":
            raise ValueError("Landlock compatibility must be hard_requirement")
        if any(not key or "=" in key or "\x00" in key for key in self.allowed_env_keys):
            raise ValueError("registered environment key is invalid")


@dataclass(frozen=True)
class SandboxRequest:
    profile_id: str
    image: str
    command: tuple[str, ...]
    cpu: str | None = None
    memory: str | None = None
    env: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.command or any(not part for part in self.command):
            raise ValueError("sandbox command must be non-empty")
        for key, value in self.env:
            if not key or "=" in key or "\x00" in key or "\x00" in value:
                raise ValueError("sandbox environment contains an invalid entry")


@dataclass(frozen=True)
class StagingHandle:
    """Opaque handle for a path owned by the trusted staging service."""

    token: str


@dataclass(frozen=True)
class Sandbox:
    name: str
    profile_id: str
    image: str
    state: SandboxState


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False


@dataclass(frozen=True)
class CollectResult:
    source: str
    artifact_ref: str
    bytes_hashed: int
    snapshot: bool = True


class RuntimeService:
    """Own persistent sandbox lifecycle, idempotency, and event cursor."""

    def __init__(
        self,
        adapter: OpenShellDockerAdapter,
        *,
        state_path: Path,
        collect_dir: Path | None = None,
    ) -> None:
        self._adapter = adapter
        self._state_path = Path(state_path)
        self._collect_dir = Path(collect_dir) if collect_dir is not None else self._state_path.parent / "collect"
        self._handles: dict[str, Sandbox] = {}
        self._lock = threading.RLock()
        self._initialize_store()

    def create(self, idempotency_key: str, request: SandboxRequest) -> Sandbox:
        _validate_idempotency_key(idempotency_key)
        gate = l1_create_gate(
            profile_registered=True,
            profile_acceptance=self._adapter.profile_acceptance,
        )
        if gate is not None:
            raise OperationOutcomeError(gate)
        self._adapter._validate_request(request)
        request_json = _request_json(request)
        with self._lock:
            row = self._claim_or_read(idempotency_key, request_json)
            if row is not None:
                if row["request_json"] != request_json:
                    raise IdempotencyConflictError("idempotency key request differs")
                if idempotency_key in self._handles:
                    return self._handles[idempotency_key]
                if row["sandbox_name"] is None:
                    return self._replay_incomplete_create(
                        idempotency_key, request, request_json, row
                    )
                return self._handle_from_row(idempotency_key, row)
            return self._invoke_create(idempotency_key, request, request_json)

    def _replay_incomplete_create(
        self,
        key: str,
        request: SandboxRequest,
        request_json: str,
        row: sqlite3.Row,
    ) -> Sandbox:
        recovered, confirmed_absent = self._adapter._lookup_by_idempotency(
            key, image=request.image
        )
        if recovered is not None:
            self._save(key, request_json, recovered)
            return recovered
        stored = _outcome_from_row(row)
        # An empty list cannot rule out a detached create still being accepted.
        if (
            not confirmed_absent
            or stored is None
            or stored.kind != "failed"
            or stored.code != "provisioning_failed"
        ):
            raise OperationOutcomeError(
                stored
                if stored is not None
                else l1_execution_error(error_code="host_unreachable")
            )
        return self._invoke_create(key, request, request_json)

    def _invoke_create(
        self, key: str, request: SandboxRequest, request_json: str
    ) -> Sandbox:
        try:
            sandbox = self._adapter.create(request, idempotency_key=key)
        except OperationOutcomeError as error:
            if error.outcome.kind == "refused":
                self._release_incomplete_claim(key)
                raise
            recovered, _confirmed = self._adapter._lookup_by_idempotency(
                key, image=request.image
            )
            if recovered is not None:
                self._save(key, request_json, recovered)
                return recovered
            self._save_outcome(key, request_json, error.outcome)
            raise
        except ValueError:
            self._release_incomplete_claim(key)
            raise
        except Exception as error:
            recovered, _confirmed = self._adapter._lookup_by_idempotency(
                key, image=request.image
            )
            if recovered is not None:
                self._save(key, request_json, recovered)
                return recovered
            outcome = l1_execution_error(error_code="host_unreachable")
            self._save_outcome(key, request_json, outcome)
            raise OperationOutcomeError(outcome) from error
        self._save(key, request_json, sandbox)
        return sandbox

    def wait_ready(
        self, idempotency_key: str, *, timeout_seconds: float = 120.0
    ) -> Sandbox:
        with self._lock:
            sandbox = self._known(idempotency_key)
            try:
                ready = self._adapter.wait_ready(
                    sandbox, timeout_seconds=timeout_seconds
                )
            except TimeoutError as error:
                raise OperationOutcomeError(
                    refused("invalid_state"), detail=str(error)
                ) from error
            self._save(
                idempotency_key,
                _request_json_for(self._state_path, idempotency_key),
                ready,
            )
            self._handles[idempotency_key] = ready
            if ready.state is SandboxState.READY:
                return ready
            if ready.state is SandboxState.FAILED:
                raise OperationOutcomeError(failed("provisioning_failed"))
            raise OperationOutcomeError(refused("invalid_state"))

    def exec(
        self,
        idempotency_key: str,
        argv: tuple[str, ...],
        *,
        cwd: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> ExecResult:
        with self._lock:
            return self._adapter.exec(
                self._known(idempotency_key),
                argv,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
            )

    def stop(self, idempotency_key: str) -> Sandbox:
        with self._lock:
            stopped = self._adapter.stop(self._known(idempotency_key))
            self._update_state(idempotency_key, stopped)
            return stopped

    def delete(self, idempotency_key: str) -> Sandbox:
        with self._lock:
            deleted = self._adapter.delete(self._known(idempotency_key))
            self._update_state(idempotency_key, deleted)
            return deleted

    def collect(
        self,
        idempotency_key: str,
        source: str,
        *,
        timeout_seconds: float = 120.0,
    ) -> CollectResult:
        with self._lock:
            if self._adapter.profile_acceptance != "verified":
                raise OperationOutcomeError(refused("unsupported"))
            sandbox = self._known(idempotency_key)
            posix = f"{self._adapter._config.trusted_staging_root}/collect-{idempotency_key}"
            handle = self._adapter.register_staging_path(posix)
            self._adapter.download(
                sandbox, source, handle, timeout_seconds=timeout_seconds
            )
            artifact = self._collect_dir / "artifact"
            if not artifact.is_file():
                raise OperationOutcomeError(unknown("host_unreachable"))
            payload = artifact.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            return CollectResult(
                source=source,
                artifact_ref=f"sha256:{digest}",
                bytes_hashed=len(payload),
            )

    def append_event(
        self,
        event: dict[str, Any],
        *,
        validate: Callable[[Mapping[str, Any]], None],
    ) -> dict[str, Any]:
        with self._lock, sqlite3.connect(self._state_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT COALESCE(MAX(cursor), 0) FROM events"
            ).fetchone()
            revision = int((row or (0,))[0]) + 1
            stored = _event_with_owner_cursor(event, revision)
            validate(stored)
            payload = json.dumps(stored, sort_keys=True, separators=(",", ":"))
            connection.execute(
                """
                INSERT INTO events (cursor, event_id, event_json)
                VALUES (?, ?, ?)
                """,
                (revision, stored["eventId"], payload),
            )
            connection.commit()
        return json.loads(payload)

    def list_events(self, *, after: int = 0) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self._state_path) as connection:
            rows = connection.execute(
                """
                SELECT event_json FROM events
                WHERE cursor > ?
                ORDER BY cursor ASC
                """,
                (after,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def peek(self, idempotency_key: str) -> Sandbox | None:
        with self._lock:
            handle = self._handles.get(idempotency_key)
            if handle is not None:
                return handle
            row = self._read(idempotency_key)
            if row is None or row["sandbox_name"] is None:
                return None
            try:
                state = SandboxState(row["state"])
            except ValueError as error:
                raise RuntimeError("sandbox local state cannot be confirmed") from error
            return Sandbox(
                name=row["sandbox_name"],
                profile_id=row["profile_id"],
                image=row["image"],
                state=state,
            )

    def _known(self, idempotency_key: str) -> Sandbox:
        try:
            return self._handles[idempotency_key]
        except KeyError:
            sandbox = self.peek(idempotency_key)
            if sandbox is None:
                raise KeyError("unknown idempotency key") from None
            self._adapter._bind(sandbox)
            self._handles[idempotency_key] = sandbox
            return sandbox

    def _handle_from_row(self, key: str, row: sqlite3.Row) -> Sandbox:
        state = SandboxState(row["state"])
        if state is SandboxState.DELETED:
            return Sandbox(
                name=row["sandbox_name"],
                profile_id=row["profile_id"],
                image=row["image"],
                state=state,
            )
        sandbox = self._adapter.adopt(row["sandbox_name"])
        self._handles[key] = sandbox
        if sandbox.state is not state:
            self._update_state(key, sandbox)
        return sandbox

    def _initialize_store(self) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._state_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operations (
                    idempotency_key TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    sandbox_name TEXT,
                    profile_id TEXT NOT NULL,
                    image TEXT NOT NULL,
                    state TEXT NOT NULL,
                    outcome_json TEXT
                )
                """
            )
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(operations)")
            }
            if "outcome_json" not in columns:
                connection.execute(
                    "ALTER TABLE operations ADD COLUMN outcome_json TEXT"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    cursor INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_json TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def _claim_or_read(self, key: str, request_json: str) -> sqlite3.Row | None:
        with sqlite3.connect(self._state_path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operations WHERE idempotency_key = ?", (key,)
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO operations (
                        idempotency_key,
                        request_json,
                        sandbox_name,
                        profile_id,
                        image,
                        state,
                        outcome_json
                    ) VALUES (?, ?, NULL, ?, ?, ?, NULL)
                    """,
                    (key, request_json, self._adapter.profile_id, "", "creating"),
                )
            connection.commit()
            return row

    def _read(self, key: str) -> sqlite3.Row | None:
        with sqlite3.connect(self._state_path) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM operations WHERE idempotency_key = ?", (key,)
            ).fetchone()

    def _save(self, key: str, request_json: str, sandbox: Sandbox) -> None:
        with sqlite3.connect(self._state_path) as connection:
            connection.execute(
                """
                UPDATE operations
                SET request_json = ?,
                    sandbox_name = ?,
                    profile_id = ?,
                    image = ?,
                    state = ?,
                    outcome_json = NULL
                WHERE idempotency_key = ?
                """,
                (
                    request_json,
                    sandbox.name,
                    sandbox.profile_id,
                    sandbox.image,
                    sandbox.state.value,
                    key,
                ),
            )
            connection.commit()
        self._handles[key] = sandbox

    def _save_outcome(
        self, key: str, request_json: str, outcome: OperationOutcome
    ) -> None:
        record = json.dumps(outcome.to_record(), sort_keys=True, separators=(",", ":"))
        with sqlite3.connect(self._state_path) as connection:
            connection.execute(
                """
                UPDATE operations
                SET request_json = ?, outcome_json = ?
                WHERE idempotency_key = ? AND sandbox_name IS NULL
                """,
                (request_json, record, key),
            )
            connection.commit()

    def _release_incomplete_claim(self, key: str) -> None:
        with sqlite3.connect(self._state_path) as connection:
            connection.execute(
                """
                DELETE FROM operations
                WHERE idempotency_key = ? AND sandbox_name IS NULL
                """,
                (key,),
            )
            connection.commit()
        self._handles.pop(key, None)

    def _update_state(self, key: str, sandbox: Sandbox) -> None:
        row = self._read(key)
        if row is None:
            raise KeyError("unknown idempotency key")
        self._save(key, row["request_json"], sandbox)


class OpenShellDockerAdapter:
    """Translate the registered operation surface to OpenShell CLI calls."""

    def __init__(self, config: RuntimeConfig, runner: RuntimeCommandRunner) -> None:
        self._config = config
        self._runner = runner
        self._bound: dict[str, tuple[str, str]] = {}
        self._staging: dict[str, str] = {}

    @property
    def profile_id(self) -> str:
        return self._config.profile_id

    @property
    def profile_acceptance(self) -> str:
        return self._config.profile_acceptance

    def preflight(self, *, timeout_seconds: float = 30.0) -> None:
        result = self._run(
            ("sandbox", "list", "--output", "json"), timeout_seconds=timeout_seconds
        )
        if result.returncode != 0:
            raise RuntimeError(f"OpenShell preflight failed: {result.stderr.strip()}")
        if result.truncated:
            raise RuntimeError("OpenShell preflight output was truncated")
        try:
            json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("OpenShell preflight returned invalid JSON") from error

    def create(
        self,
        request: SandboxRequest,
        *,
        idempotency_key: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> Sandbox:
        self._validate_request(request)
        argv = [
            "sandbox",
            "create",
            "--output",
            "json",
            "--from",
            request.image,
            "--cpu",
            request.cpu or self._config.default_cpu,
            "--memory",
            request.memory or self._config.default_memory,
            "--no-auto-providers",
            "--no-tty",
            "--detach",
        ]
        if idempotency_key is not None:
            _validate_idempotency_key(idempotency_key)
            argv.extend(("--label", f"kappa-box.idempotency={idempotency_key}"))
            argv.extend(("--label", f"kappa-box.profile={request.profile_id}"))
        for key, value in sorted(request.env):
            argv.extend(("--env", f"{key}={value}"))
        argv.extend(("--", *request.command))
        result = self._run(tuple(argv), timeout_seconds=timeout_seconds)
        error_code = _create_error_code(result)
        if error_code is not None:
            raise OperationOutcomeError(
                l1_execution_error(error_code=error_code),
                detail=result.stderr.strip(),
            )
        name = _parse_created_name(result.stdout)
        if name is None:
            raise OperationOutcomeError(
                l1_execution_error(error_code="host_unreachable"),
                detail="sandbox create returned no sandbox identity",
            )
        sandbox = Sandbox(
            name=name,
            profile_id=request.profile_id,
            image=request.image,
            state=SandboxState.PROVISIONING,
        )
        self._bind(sandbox)
        return sandbox

    def reconcile(self, idempotency_key: str, *, image: str) -> Sandbox | None:
        sandbox, _confirmed = self._lookup_by_idempotency(idempotency_key, image=image)
        return sandbox

    def _lookup_by_idempotency(
        self, idempotency_key: str, *, image: str
    ) -> tuple[Sandbox | None, bool]:
        _validate_idempotency_key(idempotency_key)
        result = self._run(
            (
                "sandbox",
                "list",
                "--selector",
                f"kappa-box.idempotency={idempotency_key}",
                "--output",
                "json",
            ),
            timeout_seconds=30.0,
        )
        if result.returncode != 0 or result.truncated:
            return None, False
        parsed = _parse_backend_items(result.stdout)
        if parsed is None:
            return None, False
        items, confirmed_absent = parsed
        for item in items:
            candidate = _backend_sandbox(item, self._config, image=image)
            if candidate is not None:
                self._bind(candidate)
                return candidate, False
        return None, confirmed_absent

    def adopt(self, name: str) -> Sandbox:
        if not _valid_name(name):
            raise ValueError("sandbox name is invalid")
        result = self._run(
            ("sandbox", "get", "--output", "json", name), timeout_seconds=30.0
        )
        if result.returncode == 124:
            raise TimeoutError(f"sandbox inspect timed out: {name}")
        if result.returncode != 0:
            raise RuntimeError(f"sandbox adoption failed: {result.stderr.strip()}")
        if result.truncated:
            raise RuntimeError("sandbox adoption output was truncated")
        sandbox = _parse_backend_sandbox(result.stdout, self._config)
        self._bind(sandbox)
        return sandbox

    def wait_ready(
        self, sandbox: Sandbox, *, timeout_seconds: float = 120.0
    ) -> Sandbox:
        _validate_timeout(timeout_seconds)
        self._validate_sandbox(sandbox)
        self._require_not_terminal(sandbox)
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"sandbox did not become ready: {sandbox.name}")
            result = self._run(
                ("sandbox", "get", "--output", "json", sandbox.name),
                timeout_seconds=min(30.0, remaining),
            )
            if result.returncode == 124:
                raise TimeoutError(f"sandbox inspect timed out: {sandbox.name}")
            if result.returncode != 0:
                if _looks_deleted(result.stderr):
                    return _with_state(sandbox, SandboxState.DELETED)
                raise RuntimeError(f"sandbox inspect failed: {result.stderr.strip()}")
            if result.truncated:
                raise RuntimeError("sandbox inspect output was truncated")
            phase = _sandbox_phase(result.stdout)
            if phase is not None and phase in {
                SandboxState.READY,
                SandboxState.FAILED,
                SandboxState.STOPPED,
                SandboxState.DELETED,
            }:
                return _with_state(sandbox, phase)
            time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))

    def exec(
        self,
        sandbox: Sandbox,
        argv: tuple[str, ...],
        *,
        cwd: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> ExecResult:
        _validate_timeout(timeout_seconds)
        self._validate_sandbox(sandbox)
        self._require_ready(sandbox)
        if not argv or any(not item for item in argv):
            raise ValueError("exec argv must be non-empty")
        command = ["sandbox", "exec", "--name", sandbox.name, "--no-tty"]
        if cwd is not None:
            if not cwd.startswith("/") or "\x00" in cwd:
                raise ValueError("exec cwd must be an absolute sandbox path")
            if not _path_in_grants(cwd, self._config.granted_roots):
                raise ValueError("cwd is outside registered grants")
            command.extend(("--workdir", cwd))
        command.extend(("--", *argv))
        result = self._run(tuple(command), timeout_seconds=timeout_seconds)
        return ExecResult(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            truncated=result.truncated,
        )

    def register_staging_path(self, path: str) -> StagingHandle:
        _validate_local_path(path, self._config.trusted_staging_root)
        token = hashlib.sha256(path.encode("utf-8")).hexdigest()
        self._staging[token] = path
        return StagingHandle(token)

    def upload(
        self,
        sandbox: Sandbox,
        source: StagingHandle,
        destination: str,
        *,
        timeout_seconds: float = 120.0,
    ) -> None:
        _validate_timeout(timeout_seconds)
        self._validate_sandbox(sandbox)
        self._require_ready(sandbox)
        local_path = self._resolve_staging_handle(source)
        _validate_grant_path(destination, self._config.granted_roots)
        result = self._run(
            (
                "sandbox",
                "upload",
                "--no-git-ignore",
                sandbox.name,
                local_path,
                destination,
            ),
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sandbox upload failed: {result.stderr.strip()}")
        if result.truncated:
            raise RuntimeError("sandbox upload output was truncated")

    def download(
        self,
        sandbox: Sandbox,
        source: str,
        destination: StagingHandle,
        *,
        timeout_seconds: float = 120.0,
    ) -> None:
        _validate_timeout(timeout_seconds)
        self._validate_sandbox(sandbox)
        if sandbox.state not in {SandboxState.READY, SandboxState.STOPPED}:
            raise ValueError("sandbox is not collectable")
        _validate_grant_path(source, self._config.granted_roots)
        local_path = self._resolve_staging_handle(destination)
        result = self._run(
            ("sandbox", "download", sandbox.name, source, local_path),
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sandbox download failed: {result.stderr.strip()}")
        if result.truncated:
            raise RuntimeError("sandbox download output was truncated")

    def stop(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0) -> Sandbox:
        _validate_timeout(timeout_seconds)
        self._validate_sandbox(sandbox)
        if sandbox.state in {SandboxState.STOPPED, SandboxState.DELETED}:
            return sandbox
        self._require_ready(sandbox)
        result = self._run(
            ("sandbox", "stop", sandbox.name), timeout_seconds=timeout_seconds
        )
        if result.returncode != 0 and not _looks_stopped(result.stderr):
            raise RuntimeError(f"sandbox stop failed: {result.stderr.strip()}")
        return _with_state(sandbox, SandboxState.STOPPED)

    def delete(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0) -> Sandbox:
        _validate_timeout(timeout_seconds)
        self._validate_sandbox(sandbox)
        if sandbox.state is SandboxState.DELETED:
            return sandbox
        result = self._run(
            ("sandbox", "delete", sandbox.name), timeout_seconds=timeout_seconds
        )
        if result.returncode != 0 and not _looks_deleted(result.stderr):
            raise RuntimeError(f"sandbox delete failed: {result.stderr.strip()}")
        deleted = _with_state(sandbox, SandboxState.DELETED)
        self._bound.pop(sandbox.name, None)
        return deleted

    def _validate_request(self, request: SandboxRequest) -> None:
        if request.profile_id != self._config.profile_id:
            raise ValueError("profile is not registered")
        if request.image not in self._config.approved_images:
            raise ValueError("image is not approved")
        if not self._config.probe_only:
            if self._config.profile_acceptance != "verified":
                raise OperationOutcomeError(refused("profile_unverified"))
            if not self._config.policy_verified:
                raise RuntimeError("policy_unverified")
        invalid_keys = [
            key for key, _ in request.env if key not in self._config.allowed_env_keys
        ]
        if invalid_keys:
            raise ValueError("environment variables are not registered")

    def _validate_sandbox(self, sandbox: Sandbox) -> None:
        if not _valid_name(sandbox.name):
            raise ValueError("sandbox name is invalid")
        identity = self._bound.get(sandbox.name)
        if identity != (sandbox.profile_id, sandbox.image):
            raise ValueError("sandbox handle is not bound")
        if sandbox.profile_id != self._config.profile_id:
            raise ValueError("sandbox handle is not bound")
        if sandbox.image not in self._config.approved_images:
            raise ValueError("sandbox handle is not bound")

    def _resolve_staging_handle(self, handle: StagingHandle) -> str:
        if not isinstance(handle, StagingHandle):
            raise TypeError("staging handle is required")
        try:
            return self._staging[handle.token]
        except KeyError as error:
            raise ValueError("staging handle is not registered") from error

    def _bind(self, sandbox: Sandbox) -> None:
        self._bound[sandbox.name] = (sandbox.profile_id, sandbox.image)

    def _run(
        self, command: tuple[str, ...], *, timeout_seconds: float
    ) -> RuntimeCommandResult:
        _validate_timeout(timeout_seconds)
        return self._runner.run(self._base_command(command), timeout_seconds)

    def _base_command(self, command: tuple[str, ...]) -> tuple[str, ...]:
        flags = ["--gateway-endpoint", self._config.gateway_endpoint]
        if self._config.gateway_insecure:
            flags.append("--gateway-insecure")
        return (
            _WSL_BINARY,
            "-d",
            self._config.distribution,
            "-u",
            "root",
            "--",
            self._config.openshell_binary,
            *command[:2],
            *flags,
            *command[2:],
        )

    @staticmethod
    def _require_ready(sandbox: Sandbox) -> None:
        if sandbox.state is not SandboxState.READY:
            raise ValueError("sandbox is not ready")

    @staticmethod
    def _require_not_terminal(sandbox: Sandbox) -> None:
        if sandbox.state is SandboxState.DELETED:
            raise ValueError("sandbox is deleted")


def _create_error_code(result: RuntimeCommandResult) -> str | None:
    if result.returncode == 124 or result.truncated:
        return "deadline_exceeded"
    if result.returncode == 127:
        return "host_unreachable"
    if result.returncode != 0:
        return "provisioning_failed"
    return None


def _event_with_owner_cursor(event: dict[str, Any], revision: int) -> dict[str, Any]:
    stored = json.loads(json.dumps(event))
    stored["eventId"] = f"event-{revision}"
    stored["cursor"] = str(revision)
    stored["revision"] = revision
    identity = stored.get("identity")
    if isinstance(identity, dict):
        identity["revision"] = revision
        if "operationId" not in identity or identity["operationId"] in (None, ""):
            identity["operationId"] = f"operation-{revision}"
    return stored


def _outcome_from_row(row: sqlite3.Row) -> OperationOutcome | None:
    try:
        raw = row["outcome_json"]
    except (IndexError, KeyError):
        return None
    if not raw:
        return None
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        raise ValueError("stored operation outcome is invalid")
    return outcome_from_record(loaded)


def _validate_idempotency_key(key: str) -> None:
    if not key or "\x00" in key or len(key) > 256:
        raise ValueError("idempotency key must be non-empty and bounded")


def _request_json(request: SandboxRequest) -> str:
    return json.dumps(
        {
            "profile_id": request.profile_id,
            "image": request.image,
            "command": list(request.command),
            "cpu": request.cpu,
            "memory": request.memory,
            "env": [list(entry) for entry in request.env],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _request_json_for(path: Path, key: str) -> str:
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT request_json FROM operations WHERE idempotency_key = ?", (key,)
        ).fetchone()
    if row is None:
        raise KeyError("unknown idempotency key")
    return str(row[0])


def _validate_grant_path(path: str, roots: tuple[str, ...]) -> None:
    if not _path_in_grants(path, roots):
        raise ValueError("path is outside registered grants")


def _validate_local_path(path: str, staging_root: str) -> None:
    if not _path_in_grants(path, (staging_root,)):
        raise ValueError("local path is outside registered staging root")


def _path_in_grants(path: str, roots: tuple[str, ...]) -> bool:
    if not path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        return False
    return any(path == root or path.startswith(root + "/") for root in roots)


def _parse_created_name(stdout: str) -> str | None:
    clean = _ANSI_ESCAPE.sub("", stdout)
    try:
        value = json.loads(clean)
    except json.JSONDecodeError:
        value = None
    name = _find_string(value, {"name", "sandboxName", "sandbox_id"})
    if name is not None and _valid_name(name):
        return name
    match = _CREATED_SANDBOX.search(clean)
    return match.group(1) if match else None


def _valid_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", name))


def _with_state(sandbox: Sandbox, state: SandboxState) -> Sandbox:
    return Sandbox(
        name=sandbox.name,
        profile_id=sandbox.profile_id,
        image=sandbox.image,
        state=state,
    )


def _parse_backend_sandbox(stdout: str, config: RuntimeConfig) -> Sandbox:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("sandbox identity was not valid JSON") from error
    sandbox = _backend_sandbox(value, config, image=config.approved_images[0])
    if sandbox is None:
        raise RuntimeError("sandbox identity is not registered")
    return sandbox


def _parse_backend_items(stdout: str) -> tuple[list[Any], bool] | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(value, list):
        return value, value == []
    if isinstance(value, dict):
        for key in ("sandboxes", "items", "data"):
            items = value.get(key)
            if isinstance(items, list):
                return items, items == []
        return [value], False
    return None


def _backend_sandbox(
    value: Any, config: RuntimeConfig, *, image: str
) -> Sandbox | None:
    if not isinstance(value, dict):
        return None
    name = _find_string(value, {"name", "sandboxName", "sandbox_id"})
    image_value = _find_string(value, {"image", "imageReference", "image_reference"})
    labels = _find_mapping(value, {"labels", "metadata"})
    profile_label = _find_label(labels, "kappa-box.profile")
    if name is None or not _valid_name(name) or image_value != image:
        return None
    if profile_label != config.profile_id:
        return None
    phase = _sandbox_phase(value)
    return Sandbox(
        name=name,
        profile_id=config.profile_id,
        image=image,
        state=phase or SandboxState.PROVISIONING,
    )


def _find_string(value: Any, keys: set[str]) -> str | None:
    if isinstance(value, dict):
        for key in keys:
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
        for child in value.values():
            found = _find_string(child, keys)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_string(child, keys)
            if found is not None:
                return found
    return None


def _find_mapping(value: Any, keys: set[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        for key in keys:
            candidate = value.get(key)
            if isinstance(candidate, dict):
                return candidate
        for child in value.values():
            found = _find_mapping(child, keys)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_mapping(child, keys)
            if found:
                return found
    return {}


def _find_label(labels: dict[str, Any], key: str) -> str | None:
    value = labels.get(key)
    return value if isinstance(value, str) else None


def _sandbox_phase(value: Any) -> SandboxState | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    phase_value = _find_string(value, {"phase", "status", "state"})
    phase = (phase_value or "").lower()
    if phase in {"ready", "running"}:
        return SandboxState.READY
    if phase in {"failed", "error"}:
        return SandboxState.FAILED
    if phase in {"stopped", "paused"}:
        return SandboxState.STOPPED
    if phase in {"deleted", "not_found"}:
        return SandboxState.DELETED
    return None


def _looks_deleted(stderr: str) -> bool:
    text = stderr.lower()
    return "not found" in text or "does not exist" in text


def _looks_stopped(stderr: str) -> bool:
    text = stderr.lower()
    return "already stopped" in text or "not running" in text
