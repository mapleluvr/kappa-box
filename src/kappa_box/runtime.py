"""Real OpenShell Docker runtime adapter for the registered WSL2 profile."""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

_REGISTERED_PROFILE = "wsl2:l1@openshell-docker"
_REGISTERED_DISTRIBUTION = "kappa-box-ubuntu-24.04"
_REGISTERED_GATEWAY_ENDPOINT = "http://127.0.0.1:17670"
_REGISTERED_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base@"
    "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CREATED_SANDBOX = re.compile(r"Created sandbox:\s*([A-Za-z0-9][A-Za-z0-9-]*)")
_MAX_OUTPUT_BYTES = 256 * 1024


class IdempotencyConflictError(ValueError):
    """The same idempotency key was used for a different request."""


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
        if self.gateway_endpoint.startswith("http://") and not self.gateway_insecure:
            raise ValueError("plaintext gateway requires explicit insecure opt-in")
        if not self.openshell_binary.startswith("/"):
            raise ValueError("OpenShell binary must be an absolute WSL path")
        if not self.approved_images:
            raise ValueError("at least one approved image is required")
        if self.approved_images != (_REGISTERED_IMAGE,):
            raise ValueError("image pin is not registered")
        if self.granted_roots != ("/work",):
            raise ValueError("grant roots are not registered")


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


class RuntimeService:
    """Own sandbox lifecycle and idempotency for one host runtime process."""

    def __init__(self, adapter: OpenShellDockerAdapter) -> None:
        self._adapter = adapter
        self._requests: dict[str, tuple[SandboxRequest, Sandbox]] = {}

    def create(self, idempotency_key: str, request: SandboxRequest) -> Sandbox:
        if not idempotency_key or "\x00" in idempotency_key:
            raise ValueError("idempotency key must be non-empty")
        existing = self._requests.get(idempotency_key)
        if existing is not None:
            if existing[0] != request:
                raise IdempotencyConflictError("idempotency key request differs")
            return existing[1]
        sandbox = self._adapter.create(request)
        self._requests[idempotency_key] = (request, sandbox)
        return sandbox

    def wait_ready(
        self, idempotency_key: str, *, timeout_seconds: float = 120.0
    ) -> Sandbox:
        sandbox = self._known(idempotency_key)
        ready = self._adapter.wait_ready(sandbox, timeout_seconds=timeout_seconds)
        self._replace(idempotency_key, ready)
        return ready

    def exec(
        self,
        idempotency_key: str,
        argv: tuple[str, ...],
        *,
        cwd: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> ExecResult:
        return self._adapter.exec(
            self._known(idempotency_key),
            argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
        )

    def stop(self, idempotency_key: str) -> Sandbox:
        ready = self._adapter.stop(self._known(idempotency_key))
        self._replace(idempotency_key, ready)
        return ready

    def delete(self, idempotency_key: str) -> Sandbox:
        deleted = self._adapter.delete(self._known(idempotency_key))
        self._replace(idempotency_key, deleted)
        return deleted

    def _known(self, idempotency_key: str) -> Sandbox:
        try:
            return self._requests[idempotency_key][1]
        except KeyError as error:
            raise KeyError("unknown idempotency key") from error

    def _replace(self, idempotency_key: str, sandbox: Sandbox) -> None:
        request, _ = self._requests[idempotency_key]
        self._requests[idempotency_key] = (request, sandbox)


class OpenShellDockerAdapter:
    """Translate the registered operation surface to OpenShell CLI calls."""

    def __init__(self, config: RuntimeConfig, runner: RuntimeCommandRunner) -> None:
        self._config = config
        self._runner = runner

    def preflight(self, *, timeout_seconds: float = 30.0) -> None:
        result = self._run(
            ("sandbox", "list", "--output", "json"), timeout_seconds=timeout_seconds
        )
        if result.returncode != 0:
            raise RuntimeError(f"OpenShell preflight failed: {result.stderr.strip()}")
        try:
            json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("OpenShell preflight returned invalid JSON") from error

    def create(
        self, request: SandboxRequest, *, timeout_seconds: float = 120.0
    ) -> Sandbox:
        self._validate_request(request)
        argv = [
            "sandbox",
            "create",
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
        for key, value in sorted(request.env):
            argv.extend(("--env", f"{key}={value}"))
        argv.extend(("--", *request.command))
        result = self._run(tuple(argv), timeout_seconds=timeout_seconds)
        if result.returncode != 0:
            raise RuntimeError(f"sandbox create failed: {result.stderr.strip()}")
        name = _parse_created_name(result.stdout)
        if name is None:
            raise RuntimeError("sandbox create returned no sandbox identity")
        return Sandbox(
            name=name,
            profile_id=request.profile_id,
            image=request.image,
            state=SandboxState.PROVISIONING,
        )

    def adopt(self, name: str, *, image: str = "unknown") -> Sandbox:
        if not _valid_name(name):
            raise ValueError("sandbox name is invalid")
        return Sandbox(
            name=name,
            profile_id=self._config.profile_id,
            image=image,
            state=SandboxState.PROVISIONING,
        )

    def wait_ready(
        self, sandbox: Sandbox, *, timeout_seconds: float = 120.0
    ) -> Sandbox:
        self._require_not_terminal(sandbox)
        deadline = time.monotonic() + timeout_seconds
        while True:
            result = self._run(
                ("sandbox", "get", "--output", "json", sandbox.name),
                timeout_seconds=min(30.0, max(1.0, deadline - time.monotonic())),
            )
            if result.returncode != 0:
                if _looks_deleted(result.stderr):
                    return _with_state(sandbox, SandboxState.DELETED)
                raise RuntimeError(f"sandbox inspect failed: {result.stderr.strip()}")
            phase = _sandbox_phase(result.stdout)
            if phase == SandboxState.READY:
                return _with_state(sandbox, phase)
            if phase in {
                SandboxState.FAILED,
                SandboxState.STOPPED,
                SandboxState.DELETED,
            }:
                return _with_state(sandbox, phase)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"sandbox did not become ready: {sandbox.name}")
            time.sleep(0.25)

    def exec(
        self,
        sandbox: Sandbox,
        argv: tuple[str, ...],
        *,
        cwd: str | None = None,
        timeout_seconds: float = 120.0,
    ) -> ExecResult:
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
        )

    def upload(
        self,
        sandbox: Sandbox,
        local_path: str,
        destination: str,
        *,
        timeout_seconds: float = 120.0,
    ) -> None:
        self._require_ready(sandbox)
        _validate_local_path(local_path)
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

    def download(
        self,
        sandbox: Sandbox,
        source: str,
        local_path: str,
        *,
        timeout_seconds: float = 120.0,
    ) -> None:
        if sandbox.state not in {SandboxState.READY, SandboxState.STOPPED}:
            raise ValueError("sandbox is not collectable")
        _validate_grant_path(source, self._config.granted_roots)
        _validate_local_path(local_path)
        result = self._run(
            ("sandbox", "download", sandbox.name, source, local_path),
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0:
            raise RuntimeError(f"sandbox download failed: {result.stderr.strip()}")

    def stop(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0) -> Sandbox:
        if sandbox.state in {SandboxState.STOPPED, SandboxState.DELETED}:
            return sandbox
        self._require_known(sandbox)
        result = self._run(
            ("sandbox", "stop", sandbox.name), timeout_seconds=timeout_seconds
        )
        if result.returncode != 0 and not _looks_stopped(result.stderr):
            raise RuntimeError(f"sandbox stop failed: {result.stderr.strip()}")
        return _with_state(sandbox, SandboxState.STOPPED)

    def delete(self, sandbox: Sandbox, *, timeout_seconds: float = 60.0) -> Sandbox:
        if sandbox.state is SandboxState.DELETED:
            return sandbox
        self._require_known(sandbox)
        result = self._run(
            ("sandbox", "delete", sandbox.name), timeout_seconds=timeout_seconds
        )
        if result.returncode != 0 and not _looks_deleted(result.stderr):
            raise RuntimeError(f"sandbox delete failed: {result.stderr.strip()}")
        return _with_state(sandbox, SandboxState.DELETED)

    def _validate_request(self, request: SandboxRequest) -> None:
        if request.profile_id != self._config.profile_id:
            raise ValueError("profile is not registered")
        if request.image not in self._config.approved_images:
            raise ValueError("image is not approved")

    def _run(
        self, command: tuple[str, ...], *, timeout_seconds: float
    ) -> RuntimeCommandResult:
        return self._runner.run(self._base_command(command), timeout_seconds)

    def _base_command(self, command: tuple[str, ...]) -> tuple[str, ...]:
        flags = ["--gateway-endpoint", self._config.gateway_endpoint]
        if self._config.gateway_insecure:
            flags.append("--gateway-insecure")
        return (
            "wsl.exe",
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
    def _require_known(sandbox: Sandbox) -> None:
        if sandbox.state is SandboxState.PROVISIONING:
            raise ValueError("sandbox is still provisioning")

    @staticmethod
    def _require_not_terminal(sandbox: Sandbox) -> None:
        if sandbox.state is SandboxState.DELETED:
            raise ValueError("sandbox is deleted")


def _validate_grant_path(path: str, roots: tuple[str, ...]) -> None:
    if not _path_in_grants(path, roots):
        raise ValueError("path is outside registered grants")


def _validate_local_path(path: str) -> None:
    if not path.startswith("/") or "\x00" in path:
        raise ValueError("local path must be an absolute WSL path")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        raise ValueError("local path contains an invalid segment")


def _path_in_grants(path: str, roots: tuple[str, ...]) -> bool:
    if not path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts[1:]):
        return False
    return any(path == root or path.startswith(root + "/") for root in roots)


def _parse_created_name(stdout: str) -> str | None:
    match = _CREATED_SANDBOX.search(_ANSI_ESCAPE.sub("", stdout))
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


def _sandbox_phase(stdout: str) -> SandboxState | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    phase = str(value.get("phase", value.get("status", ""))).lower()
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
