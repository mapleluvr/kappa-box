from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class ProfileIdentityError(ValueError):
    """The registered fields do not describe the profile id."""


def validate_profile_identity(profile: Mapping[str, object]) -> None:
    """Require id, hostClass, tier, and variant to describe one identity."""
    profile_id = profile.get("id")
    host_class = profile.get("hostClass")
    tier = profile.get("tier")
    if not all(
        isinstance(value, str) and value for value in (profile_id, host_class, tier)
    ):
        raise ProfileIdentityError("profile identity fields must be non-empty strings")

    profile_base, separator, profile_variant = profile_id.partition("@")
    id_host, id_separator, id_tier = profile_base.partition(":")
    if not id_separator or id_host != host_class or id_tier != tier:
        raise ProfileIdentityError("profile id does not match hostClass and tier")

    declared_variant = profile.get("variant")
    if separator:
        if declared_variant != profile_variant:
            raise ProfileIdentityError("profile id does not match variant")
    elif declared_variant is not None:
        raise ProfileIdentityError("variant is present but profile id has no variant")


def load_profile(path: str | Path) -> dict[str, Any]:
    """Load one JSON profile and enforce its schema and identity binding."""
    profile_path = Path(path)
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid profile file: {profile_path}") from error
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")  # noqa: TRY004

    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    try:
        facts_schema = json.loads(
            (schema_root / "facts.schema.json").read_text(encoding="utf-8")
        )
        profile_schema = json.loads(
            (schema_root / "profile.schema.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("profile schemas are unavailable") from error

    registry = (
        Registry()
        .with_resource(facts_schema["$id"], Resource.from_contents(facts_schema))
        .with_resource(profile_schema["$id"], Resource.from_contents(profile_schema))
    )
    errors = sorted(
        Draft202012Validator(
            profile_schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).iter_errors(profile),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "profile"
        raise ValueError(
            f"profile schema validation failed at {location}: {first.message}"
        )

    validate_profile_identity(profile)
    probe = profile["probe"]
    last_run_at = probe["lastRunAt"]
    if last_run_at is not None:
        if not _RFC3339.fullmatch(last_run_at):
            raise ValueError("probe.lastRunAt must be an RFC 3339 timestamp")
        try:
            datetime.fromisoformat(last_run_at)
        except ValueError as error:
            raise ValueError("probe.lastRunAt must be an RFC 3339 timestamp") from error

    expected_facts = profile.get("expectedFacts")
    if (
        isinstance(expected_facts, Mapping)
        and expected_facts.get("profileId") != profile["id"]
    ):
        raise ValueError("expectedFacts.profileId does not match profile id")
    return profile
