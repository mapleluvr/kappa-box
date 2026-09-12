"""Probe runner entry for kappa-box."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from kappa_box.host_probe import collect_host_visibility, write_host_visibility_evidence
from kappa_box.landlock_probe import (
    collect_landlock_capability,
    write_landlock_capability_evidence,
)
from kappa_box.probes import SubprocessExecutor
from kappa_box.runtime import (
    OpenShellDockerAdapter,
    RuntimeConfig,
    SubprocessRuntimeRunner,
)
from kappa_box.runtime_probe import (
    collect_runtime_vertical_slice,
    write_runtime_vertical_slice_evidence,
)

_ROOT = Path(__file__).resolve().parents[2]
_PROFILE = "wsl2:l1@openshell-docker"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kappa_box")
    subparsers = parser.add_subparsers(dest="command", required=True)
    host = subparsers.add_parser(
        "host-visibility",
        help="Run the read-only host isolation visibility probe",
    )
    host.add_argument("--profile", required=True)
    landlock = subparsers.add_parser(
        "landlock-capability",
        help="Read the kernel Landlock ABI without making an acceptance claim",
    )
    landlock.add_argument("--profile", required=True)
    runtime = subparsers.add_parser(
        "runtime-vertical-slice",
        help="Exercise the real OpenShell Docker lifecycle without verification",
    )
    runtime.add_argument("--profile", required=True)
    runtime.add_argument("--gateway-insecure", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "host-visibility":
        return run_host_visibility(args.profile)
    if args.command == "landlock-capability":
        return run_landlock_capability(args.profile)
    if args.command == "runtime-vertical-slice":
        return run_runtime_vertical_slice(
            args.profile, gateway_insecure=args.gateway_insecure
        )
    parser.error(f"unsupported command: {args.command}")


def run_host_visibility(profile_id: str) -> int:
    if profile_id != _PROFILE:
        raise SystemExit(f"unsupported host visibility profile: {profile_id}")
    collected_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    source_commit = _source_commit(_ROOT)
    record = collect_host_visibility(
        profile_id,
        executor=SubprocessExecutor(),
        collected_at=collected_at,
        source_commit=source_commit,
    )
    date = collected_at[:10]
    raw_path = _ROOT / "evidence" / "probe-runs" / "host-visibility.json"
    summary_path = (
        _ROOT / "evidence" / "releases" / f"host-visibility-{date}-summary.json"
    )
    summary = write_host_visibility_evidence(
        record, raw_path=raw_path, summary_path=summary_path
    )
    group = summary["groups"][0]
    print(
        json.dumps(
            {
                "profileId": summary["profileId"],
                "probeStatus": summary["probeStatus"],
                "acceptance": summary["acceptance"],
                "sourceCommit": summary["sourceCommit"],
                "failureGroups": summary["failureGroups"],
                "host": group,
                "rawPath": str(raw_path),
                "summaryPath": str(summary_path),
            },
            indent=2,
        )
    )
    return 0


def run_landlock_capability(profile_id: str) -> int:
    if profile_id != _PROFILE:
        raise SystemExit(f"unsupported Landlock profile: {profile_id}")
    collected_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    source_commit = _source_commit(_ROOT)
    record = collect_landlock_capability(
        profile_id,
        executor=SubprocessExecutor(),
        collected_at=collected_at,
        source_commit=source_commit,
    )
    date = collected_at[:10]
    raw_path = _ROOT / "evidence" / "probe-runs" / "landlock-capability.json"
    summary_path = (
        _ROOT / "evidence" / "releases" / f"landlock-capability-{date}-summary.json"
    )
    summary = write_landlock_capability_evidence(
        record, raw_path=raw_path, summary_path=summary_path
    )
    print(
        json.dumps(
            {
                "profileId": summary["profileId"],
                "probeStatus": summary["probeStatus"],
                "acceptance": summary["acceptance"],
                "sourceCommit": summary["sourceCommit"],
                "failureGroups": summary["failureGroups"],
                "capability": summary["capability"],
                "rawPath": str(raw_path),
                "summaryPath": str(summary_path),
            },
            indent=2,
        )
    )
    return 0


def run_runtime_vertical_slice(
    profile_id: str, *, gateway_insecure: bool = False
) -> int:
    if profile_id != _PROFILE:
        raise SystemExit(f"unsupported runtime profile: {profile_id}")
    collected_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    source_commit = _source_commit(_ROOT)
    config = RuntimeConfig(
        profile_id=profile_id,
        distribution="kappa-box-ubuntu-24.04",
        gateway_endpoint="http://127.0.0.1:17670",
        openshell_binary="/usr/local/bin/openshell",
        approved_images=(
            (
                "ghcr.io/nvidia/openshell-community/sandboxes/base@"
                "sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
            ),
        ),
        gateway_insecure=gateway_insecure,
    )
    adapter = OpenShellDockerAdapter(config, SubprocessRuntimeRunner())
    record = collect_runtime_vertical_slice(
        adapter,
        profile_id=profile_id,
        source_commit=source_commit,
        collected_at=collected_at,
    )
    date = collected_at[:10]
    raw_path = _ROOT / "evidence" / "probe-runs" / "runtime-vertical-slice.json"
    summary_path = (
        _ROOT / "evidence" / "releases" / f"runtime-vertical-slice-{date}-summary.json"
    )
    summary = write_runtime_vertical_slice_evidence(
        record, raw_path=raw_path, summary_path=summary_path
    )
    print(
        json.dumps(
            {
                "profileId": summary["profileId"],
                "probeStatus": summary["probeStatus"],
                "acceptance": summary["acceptance"],
                "sourceCommit": summary["sourceCommit"],
                "failureGroups": summary["failureGroups"],
                "stages": summary["stages"],
                "rawPath": str(raw_path),
                "summaryPath": str(summary_path),
            },
            indent=2,
        )
    )
    return 0


def _source_commit(root: Path) -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout.strip():
        raise RuntimeError("refusing to collect evidence from a dirty worktree")
    completed = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    commit = completed.stdout.strip()
    if not commit:
        raise RuntimeError("source commit is empty")
    return commit


if __name__ == "__main__":
    sys.exit(main())
