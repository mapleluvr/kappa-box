"""Canonicalization and digesting for observed runtime facts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

_REQUIRED_FACTS = {
    "schemaVersion",
    "profileId",
    "kernel",
    "lsm",
    "landlock",
    "seccomp",
    "cgroup",
    "runtime",
    "image",
    "network",
    "sandboxId",
    "time",
}

_PROFILE_ID = re.compile(
    r"^[a-z][a-z0-9-]*:(?:l[123]|managed|obs)(?:@[a-z0-9][a-z0-9._-]*)?$"
)
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_TOP_LEVEL = _REQUIRED_FACTS


# These fields identify one observation or deployment location. They remain in
# the returned facts but must not make equivalent capability facts diverge.
_VOLATILE_FACT_PATHS = {
    ("sandboxId",),
    ("time",),
    ("cgroup", "path"),
    ("image", "reference"),
}


def _without_volatile_fields(value: Any, path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _without_volatile_fields(child, path + (key,))
            for key, child in value.items()
            if path + (key,) not in _VOLATILE_FACT_PATHS
        }
    if isinstance(value, list):
        normalized = [_without_volatile_fields(child, path) for child in value]
        if path == ("lsm",):
            return sorted(normalized)
        return normalized
    return value


def _required_fact_errors(facts: Mapping[str, Any]) -> list[str]:
    return sorted(_REQUIRED_FACTS - facts.keys())


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must be an object")  # noqa: TRY004
    return value


def _require_keys(value: Mapping[str, Any], required: set[str], path: str) -> None:
    missing = sorted(required - value.keys())
    if missing:
        raise ValueError(f"missing required facts: {path}.{missing[0]}")
    unknown = sorted(set(value) - required)
    if unknown:
        raise ValueError(f"unknown facts: {path}.{unknown[0]}")


def _require_string(value: Any, path: str, max_length: int | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path} must be a non-empty string")
    if max_length is not None and len(value) > max_length:
        raise ValueError(f"{path} exceeds maximum length")
    return value


def _validate_limit(value: Any, path: str, unit: str, integer: bool) -> None:
    limit = _require_mapping(value, path)
    _require_keys(limit, {"state", "value", "unit"}, path)
    state = limit["state"]
    if state not in {"enforced", "unlimited", "unavailable"}:
        raise ValueError(f"{path}.state is invalid")
    if limit["unit"] != unit:
        raise ValueError(f"{path}.unit must be {unit}")
    amount = limit["value"]
    if state == "enforced":
        valid_number = (
            isinstance(amount, (int, float))
            and not isinstance(amount, bool)
            and math.isfinite(amount)
        )
        if integer:
            valid_number = isinstance(amount, int) and not isinstance(amount, bool)
        if not valid_number or amount <= 0:
            raise ValueError(f"{path}.value must be positive when enforced")
    elif amount is not None:
        raise ValueError(f"{path}.value must be null when {state}")


def _validate_facts(facts: Mapping[str, Any]) -> None:
    unknown = sorted(set(facts) - _TOP_LEVEL)
    if unknown:
        raise ValueError(f"unknown facts: {unknown[0]}")

    missing = _required_fact_errors(facts)
    if missing:
        raise ValueError(f"missing required facts: {', '.join(missing)}")

    if facts["schemaVersion"] != "1":
        raise ValueError("schemaVersion must be 1")
    sandbox_id = _require_string(facts["sandboxId"], "sandboxId", 128)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", sandbox_id):
        raise ValueError("sandboxId has invalid format")
    profile_id = _require_string(facts["profileId"], "profileId", 256)
    if not _PROFILE_ID.fullmatch(profile_id):
        raise ValueError("profileId has invalid format")
    _require_string(facts["kernel"], "kernel", 256)

    lsm = facts["lsm"]
    if not isinstance(lsm, list) or any(
        not isinstance(item, str) or not item or len(item) > 64 for item in lsm
    ):
        raise ValueError("lsm must be a list of non-empty strings")
    if len(set(lsm)) != len(lsm):
        raise ValueError("lsm must not contain duplicates")

    landlock = _require_mapping(facts["landlock"], "landlock")
    _require_keys(landlock, {"enabled", "abi", "compatibility"}, "landlock")
    if not isinstance(landlock["enabled"], bool):
        raise ValueError("landlock.enabled must be boolean")  # noqa: TRY004
    if landlock["enabled"]:
        if (
            not isinstance(landlock["abi"], int)
            or isinstance(landlock["abi"], bool)
            or landlock["abi"] < 1
        ):
            raise ValueError("landlock.abi must be a positive integer when enabled")
    elif landlock["abi"] is not None:
        raise ValueError("landlock.abi must be null when disabled")
    if landlock["compatibility"] not in {"hard_requirement", "best_effort"}:
        raise ValueError("landlock.compatibility is invalid")
    if not landlock["enabled"] and landlock["compatibility"] != "best_effort":
        raise ValueError("disabled landlock must use best_effort")

    seccomp = _require_mapping(facts["seccomp"], "seccomp")
    _require_keys(seccomp, {"enabled", "profile"}, "seccomp")
    if not isinstance(seccomp["enabled"], bool):
        raise ValueError("seccomp.enabled must be boolean")  # noqa: TRY004
    if seccomp["enabled"]:
        _require_string(seccomp["profile"], "seccomp.profile", 256)
    elif seccomp["profile"] is not None:
        raise ValueError("seccomp.profile must be null when disabled")

    cgroup = _require_mapping(facts["cgroup"], "cgroup")
    _require_keys(cgroup, {"version", "path", "limits"}, "cgroup")
    if cgroup["version"] not in {"v1", "v2", "unknown"}:
        raise ValueError("cgroup.version is invalid")
    _require_string(cgroup["path"], "cgroup.path", 1024)
    limits = _require_mapping(cgroup["limits"], "cgroup.limits")
    _require_keys(limits, {"cpu", "memory", "pids"}, "cgroup.limits")
    _validate_limit(limits["cpu"], "cgroup.limits.cpu", "cores", False)
    _validate_limit(limits["memory"], "cgroup.limits.memory", "bytes", True)
    _validate_limit(limits["pids"], "cgroup.limits.pids", "count", True)

    runtime = _require_mapping(facts["runtime"], "runtime")
    _require_keys(runtime, {"engineVersion", "name", "version", "rootless"}, "runtime")
    _require_string(runtime["engineVersion"], "runtime.engineVersion", 128)
    _require_string(runtime["name"], "runtime.name", 128)
    _require_string(runtime["version"], "runtime.version", 128)
    if not isinstance(runtime["rootless"], bool):
        raise ValueError("runtime.rootless must be boolean")  # noqa: TRY004

    image = _require_mapping(facts["image"], "image")
    _require_keys(image, {"reference", "digest"}, "image")
    _require_string(image["reference"], "image.reference", 1024)
    digest = _require_string(image["digest"], "image.digest")
    if not _DIGEST.fullmatch(digest):
        raise ValueError("image.digest must be a sha256 digest")

    network = _require_mapping(facts["network"], "network")
    _require_keys(network, {"profile", "egressPath"}, "network")
    _require_string(network["profile"], "network.profile", 128)
    _require_string(network["egressPath"], "network.egressPath", 512)

    observation_time = _require_mapping(facts["time"], "time")
    _require_keys(observation_time, {"collectedAt", "probeSuiteVersion"}, "time")
    _require_string(observation_time["collectedAt"], "time.collectedAt", 128)
    if not _RFC3339.fullmatch(observation_time["collectedAt"]):
        raise ValueError("time.collectedAt must be an RFC 3339 timestamp")
    try:
        parsed_time = datetime.fromisoformat(observation_time["collectedAt"])
    except ValueError as error:
        raise ValueError("time.collectedAt must be an RFC 3339 timestamp") from error
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise ValueError("time.collectedAt must include a timezone")
    _require_string(
        observation_time["probeSuiteVersion"], "time.probeSuiteVersion", 128
    )


def canonical_facts(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable capability projection of one facts observation.

    The observation envelope (sandbox identity and collection metadata), the
    cgroup instance path, and the image's mutable reference are retained by
    callers in the original facts but excluded from the capability digest.
    """
    if not isinstance(facts, Mapping):
        raise ValueError("facts must be an object")  # noqa: TRY004

    _validate_facts(facts)
    return _without_volatile_fields(dict(facts))


def canonical_facts_bytes(facts: Mapping[str, Any]) -> bytes:
    """Serialize canonical facts with deterministic UTF-8 JSON bytes."""
    return json.dumps(
        canonical_facts(facts),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def facts_digest(facts: Mapping[str, Any]) -> str:
    """Return the SHA-256 digest of canonical capability facts."""
    return "sha256:" + hashlib.sha256(canonical_facts_bytes(facts)).hexdigest()
