from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from kappa_box import host_probe as host_probe_mod
from kappa_box.host_probe import (
    WSL_SHARE_PATH,
    PathShareVisibilityChecker,
    ShareVisibility,
    collect_host_visibility,
    redact_host_observation,
)
from kappa_box.probes import (
    CommandResult,
    SubprocessExecutor,
    collect_readonly_inventory,
    default_command_specs,
    host_visibility_command_specs,
    inventory_command_specs,
)

ROOT = Path(__file__).parents[2]
FIXTURE_DIR = ROOT / "tests" / "probes" / "fixtures" / "host-visibility"
PROFILE_ID = "wsl2:l1@openshell-docker"
FORBIDDEN_OBSERVATION_KEYS = {
    "abi",
    "digest",
    "egressPath",
    "limits",
    "seccomp",
    "image",
    "network",
    "sandboxId",
    "landlock",
}


@dataclass
class FakeExecutor:
    results: dict[str, CommandResult]
    distribution: str = "kappa-box-ubuntu-24.04"

    def run(
        self, name: str, argv: tuple[str, ...], timeout_seconds: float
    ) -> CommandResult:
        recorded = self.results[name]
        return CommandResult(
            name=recorded.name,
            argv=argv,
            returncode=recorded.returncode,
            stdout=recorded.stdout,
            stderr=recorded.stderr,
            duration_ms=recorded.duration_ms,
            timed_out=recorded.timed_out,
            truncated=recorded.truncated,
        )


@dataclass
class FakeShareChecker:
    state: ShareVisibility
    seen: list[str]

    def observe(self, path: str) -> ShareVisibility:
        self.seen.append(path)
        if path != WSL_SHARE_PATH:
            raise ValueError("wsl share path is not registered")
        return self.state


def _fixture_text(name: str, suffix: str) -> str:
    path = FIXTURE_DIR / f"{name}.{suffix}.txt"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _command_result(
    spec,
    *,
    returncode: int = 0,
    stdout: str | None = None,
    stderr: str | None = None,
    timed_out: bool = False,
    truncated: bool = False,
) -> CommandResult:
    if stdout is None:
        stdout = _fixture_text(spec.name, "stdout")
    if stderr is None:
        stderr = _fixture_text(spec.name, "stderr")
    if spec.name in {"host.lsm", "host.lsm.proc"} and stdout == "" and stderr:
        returncode = 1
    return CommandResult(
        name=spec.name,
        argv=spec.argv,
        returncode=124 if timed_out else returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=1,
        timed_out=timed_out,
        truncated=truncated,
    )


def daily_distro_results(**overrides: CommandResult) -> dict[str, CommandResult]:
    results = {
        spec.name: _command_result(spec)
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    results.update(overrides)
    return results


def collect_daily(**overrides: CommandResult):
    checker = FakeShareChecker(state="visible", seen=[])
    record = collect_host_visibility(
        PROFILE_ID,
        executor=FakeExecutor(daily_distro_results(**overrides)),
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
        share_checker=checker,
    )
    return record, checker


def host_group(record: dict) -> dict:
    return record["groups"][0]


def observation_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for child in value.values():
            keys.update(observation_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(observation_keys(child))
    return keys


def host_observation_validator() -> Draft202012Validator:
    schema = json.loads(
        (ROOT / "schemas" / "host-observation.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_daily_distro_parses_inventory_stdout_without_writing_facts():
    record, _checker = collect_daily()
    observations = record["observations"]

    assert observations["kernel"] == "6.18.33.2-microsoft-standard-WSL2"
    assert observations["distro"]["name"] == "kappa-box-ubuntu-24.04"
    assert observations["distro"]["wslVersion"] == "2.7.11.0"
    assert observations["distro"]["windowsVersion"] == "10.0.26200.9168"
    assert observations["distro"]["state"] == "Running"
    assert observations["distro"]["siblings"] == ["docker-desktop"]
    assert observations["wslConf"]["systemd"] is True
    assert observations["wslConf"]["automountEnabled"] is None
    assert observations["wslConf"]["interopEnabled"] is None
    assert "boot.systemd" in observations["wslConf"]["presentKeys"]
    assert "user.default" in observations["wslConf"]["presentKeys"]
    assert observations["engine"]["engineVersion"] == "29.1.3"
    assert observations["engine"]["cgroupDriver"] == "systemd"
    assert observations["engine"]["cgroupVersion"] == "2"
    assert observations["engine"]["defaultRuntime"] == "runc"
    assert observations["engine"]["dockerRootDir"] == "/var/lib/docker"
    assert record["facts"] is None
    assert record["factsDigest"] is None
    assert record["pins"] is None
    assert record["acceptance"] == "unverified"


def test_missing_wsl_conf_isolation_keys_fail_host_group():
    record, _checker = collect_daily()
    reason = host_group(record)["reason"]

    assert host_group(record)["result"] == "fail"
    assert record["failureGroups"] == ["host"]
    assert "automount.enabled" in reason
    assert "interop.enabled" in reason


def test_drvfs_mounts_fail_host_group():
    record, _checker = collect_daily()
    mounts = record["observations"]["mounts"]

    assert mounts["drvfsPresent"] is True
    assert mounts["windowsDriveMounts"] == ["/mnt/c", "/mnt/d", "/mnt/e"]
    assert "/mnt/c" in host_group(record)["reason"]


def test_readable_wslinterop_file_fails_host_group():
    record, _checker = collect_daily()

    assert record["observations"]["interop"]["wslInteropFile"] == "present"
    assert record["observations"]["interop"]["enabled"] is True
    assert "WSLInterop" in host_group(record)["reason"]


def test_missing_wslinterop_file_passes_interop_check():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_daily(
        **{
            "host.interop": _command_result(
                specs["host.interop"],
                returncode=1,
                stdout="",
                stderr="cat: /proc/sys/fs/binfmt_misc/WSLInterop: No such file or directory",
            )
        }
    )

    assert record["observations"]["interop"]["wslInteropFile"] == "missing"
    assert record["observations"]["interop"]["enabled"] is False
    assert "WSLInterop" not in host_group(record)["reason"]


def test_missing_cgroup_controller_fails_host_group():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_daily(
        **{
            "host.cgroup.controllers": _command_result(
                specs["host.cgroup.controllers"],
                stdout="cpuset io hugetlb rdma\n",
            )
        }
    )

    assert record["observations"]["cgroup"]["controllersReadable"] is True
    assert "cpu" in host_group(record)["reason"]
    assert "memory" in host_group(record)["reason"]
    assert "pids" in host_group(record)["reason"]
    assert host_group(record)["result"] == "fail"


def test_unreadable_cgroup_controllers_fail_closed_without_unavailable():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_daily(
        **{
            "host.cgroup.controllers": _command_result(
                specs["host.cgroup.controllers"],
                timed_out=True,
                stdout="",
                stderr="timed out",
            )
        }
    )
    blob = json.dumps(record)

    assert record["observations"]["cgroup"]["controllersReadable"] is False
    assert host_group(record)["result"] == "fail"
    assert "cgroup.controllers" in host_group(record)["reason"]
    assert "unavailable" not in blob


def test_lsm_without_landlock_fails_host_group():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_daily(
        **{
            "host.lsm": _command_result(
                specs["host.lsm"],
                stdout="lockdown,capability,yama\n",
                stderr="",
            )
        }
    )

    assert record["observations"]["lsm"]["names"] == [
        "lockdown",
        "capability",
        "yama",
    ]
    assert record["observations"]["lsm"]["landlockPresent"] is False
    assert record["observations"]["lsm"]["source"] == "host.lsm"
    assert "landlock" in host_group(record)["reason"]


def test_unreadable_lsm_sources_report_unknown_landlock_presence():
    record, _checker = collect_daily()

    assert record["observations"]["lsm"] == {
        "names": [],
        "landlockPresent": None,
        "source": None,
    }
    assert host_group(record)["result"] == "fail"
    assert "LSM list is unreadable" in host_group(record)["reason"]

    record, checker = collect_daily()

    assert checker.seen == [WSL_SHARE_PATH]
    assert record["observations"]["wslShare"] == {
        "path": WSL_SHARE_PATH,
        "visibility": "visible",
    }
    assert WSL_SHARE_PATH in host_group(record)["reason"]


def test_subprocess_executor_rejects_tampered_host_command_argv():
    executor = SubprocessExecutor()

    with pytest.raises(ValueError, match="not registered"):
        executor.run(
            "host.mountinfo",
            ("wsl.exe", "-d", "kappa-box-ubuntu-24.04", "--", "cat", "/etc/passwd"),
            30.0,
        )
    with pytest.raises(ValueError, match="not registered"):
        executor.run("host.unknown", ("wsl.exe", "--version"), 30.0)


def test_host_observation_matches_schema_and_keeps_acceptance_unverified():
    record, _checker = collect_daily()
    summary = redact_host_observation(record)

    assert list(host_observation_validator().iter_errors(record)) == []
    assert list(host_observation_validator().iter_errors(summary)) == []
    assert record["acceptance"] == "unverified"
    assert summary["acceptance"] == "unverified"
    assert record["probeStatus"] == "host_visibility"
    assert record["facts"] is None
    assert record["factsDigest"] is None
    assert record["pins"] is None
    assert summary["facts"] is None
    assert summary["factsDigest"] is None
    assert summary["pins"] is None


def test_redacted_summary_strips_stdout_and_sensitive_inventory_values():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    leaky_info = (
        _fixture_text("docker.info", "stdout")
        .replace("Name: redacted-host", "Name: RELENTLESS")
        .replace("ID: redacted-id", "ID: c7014def-9fd4-4368-96cc-3778effc0b7e")
    )
    leaky_info += (
        "HTTP Proxy: http://127.0.0.1:16410\nHTTPS Proxy: http://127.0.0.1:16410\n"
    )
    leaky_conf = "[boot]\nsystemd=true\n\n[user]\ndefault=administrator\n"
    record, _checker = collect_daily(
        **{
            "docker.info": _command_result(specs["docker.info"], stdout=leaky_info),
            "wsl.conf": _command_result(specs["wsl.conf"], stdout=leaky_conf),
        }
    )
    summary = redact_host_observation(record)
    blob = json.dumps(summary)

    assert "stdout" not in summary["commands"][0]
    assert "stderr" not in summary["commands"][0]
    assert all("stdout" not in command for command in summary["commands"])
    assert all("stderr" not in command for command in summary["commands"])
    assert "RELENTLESS" not in blob
    assert "c7014def-9fd4-4368-96cc-3778effc0b7e" not in blob
    assert "http://127.0.0.1:16410" not in blob
    assert "administrator" not in blob
    assert record["observations"]["engine"]["engineVersion"] == "29.1.3"


def test_readonly_inventory_contract_is_unchanged_by_host_visibility_commands():
    specs = inventory_command_specs("kappa-box-ubuntu-24.04")
    executor = FakeExecutor(
        {
            spec.name: CommandResult(
                name=spec.name,
                argv=spec.argv,
                returncode=0,
                stdout="ok",
                stderr="",
                duration_ms=1,
                timed_out=False,
            )
            for spec in specs
        }
    )

    inventory = collect_readonly_inventory(
        PROFILE_ID,
        executor=executor,
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
    )

    assert inventory["probeStatus"] == "inventory_only"
    assert inventory["acceptance"] == "unverified"
    assert inventory["failureGroups"] == []
    assert inventory["facts"] is None
    assert [command["name"] for command in inventory["commands"]] == [
        spec.name for spec in specs
    ]
    assert "host.mountinfo" not in [
        command["name"] for command in inventory["commands"]
    ]


def test_parser_does_not_fill_facts_shaped_fields():
    record, _checker = collect_daily()
    keys = observation_keys(record["observations"])

    assert record["facts"] is None
    assert FORBIDDEN_OBSERVATION_KEYS.isdisjoint(keys)
    assert "seccomp" not in json.dumps(record["observations"])
    assert "builtin" not in json.dumps(record["observations"])


def test_dedicated_distro_fixture_can_pass_host_group():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    checker = FakeShareChecker(state="missing", seen=[])
    record = collect_host_visibility(
        PROFILE_ID,
        executor=FakeExecutor(
            daily_distro_results(
                **{
                    "wsl.conf": _command_result(
                        specs["wsl.conf"],
                        stdout=(
                            "[boot]\nsystemd=true\n\n"
                            "[automount]\nenabled=false\n\n"
                            "[interop]\nenabled=false\n"
                        ),
                    ),
                    "host.mountinfo": _command_result(
                        specs["host.mountinfo"],
                        stdout=(
                            "82 67 8:80 / / rw,relatime - ext4 /dev/sdf rw\n"
                            "78 82 0:34 / /mnt/wsl rw,relatime - tmpfs none rw\n"
                        ),
                    ),
                    "host.interop": _command_result(
                        specs["host.interop"],
                        returncode=1,
                        stdout="",
                        stderr="cat: /proc/sys/fs/binfmt_misc/WSLInterop: No such file or directory",
                    ),
                    "host.lsm": _command_result(
                        specs["host.lsm"],
                        stdout="capability,landlock\n",
                        stderr="",
                    ),
                }
            )
        ),
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
        share_checker=checker,
    )

    assert host_group(record)["result"] == "pass"
    assert record["failureGroups"] == []
    assert record["acceptance"] == "unverified"
    assert record["observations"]["lsm"]["landlockPresent"] is True
    assert record["observations"]["mounts"]["drvfsPresent"] is False
    assert list(host_observation_validator().iter_errors(record)) == []


def test_closed_command_table_includes_host_visibility_argv():
    specs = host_visibility_command_specs("kappa-box-ubuntu-24.04")
    by_name = {spec.name: spec.argv for spec in specs}

    assert by_name["host.mountinfo"] == (
        "wsl.exe",
        "-d",
        "kappa-box-ubuntu-24.04",
        "--",
        "cat",
        "/proc/self/mountinfo",
    )
    assert by_name["host.interop"][-1] == "/proc/sys/fs/binfmt_misc/WSLInterop"
    assert by_name["host.cgroup.controllers"][-1] == "/sys/fs/cgroup/cgroup.controllers"
    assert by_name["host.cgroup.subtree"][-1] == "/sys/fs/cgroup/cgroup.subtree_control"
    assert by_name["host.lsm"][-1] == "/sys/kernel/security/lsm"
    assert by_name["host.lsm.proc"][-1] == "/proc/sys/kernel/lsm"
    assert default_command_specs("kappa-box-ubuntu-24.04") == specs
    for spec in specs:
        assert "sh" not in spec.argv
        assert "-c" not in spec.argv


def isolated_pass_overrides() -> dict[str, CommandResult]:
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    return {
        "wsl.conf": _command_result(
            specs["wsl.conf"],
            stdout=(
                "[boot]\nsystemd=true\n\n"
                "[automount]\nenabled=false\n\n"
                "[interop]\nenabled=false\n"
            ),
        ),
        "host.mountinfo": _command_result(
            specs["host.mountinfo"],
            stdout=(
                "82 67 8:80 / / rw,relatime - ext4 /dev/sdf rw\n"
                "78 82 0:34 / /mnt/wsl rw,relatime - tmpfs none rw\n"
            ),
        ),
        "host.interop": _command_result(
            specs["host.interop"],
            returncode=1,
            stdout="",
            stderr=(
                "cat: /proc/sys/fs/binfmt_misc/WSLInterop: No such file or directory"
            ),
        ),
        "host.lsm": _command_result(
            specs["host.lsm"],
            stdout="capability,landlock\n",
            stderr="",
        ),
    }


def collect_isolated(share_state: ShareVisibility, **overrides: CommandResult):
    checker = FakeShareChecker(state=share_state, seen=[])
    merged = isolated_pass_overrides()
    merged.update(overrides)
    record = collect_host_visibility(
        PROFILE_ID,
        executor=FakeExecutor(daily_distro_results(**merged)),
        collected_at="2026-09-11T12:00:00Z",
        source_commit="test-commit",
        share_checker=checker,
    )
    return record, checker


class _FakeSharePath:
    def __init__(self, path: str, error: BaseException | None = None) -> None:
        self.path = path
        self._error = error

    def stat(self, *args, **kwargs):
        if self._error is not None:
            raise self._error

    def exists(self, *args, **kwargs) -> bool:
        try:
            self.stat()
        except OSError:
            return False
        return True


def test_path_share_checker_rejects_unregistered_path(monkeypatch):
    def factory(path: str) -> _FakeSharePath:
        raise AssertionError("Path must not be constructed for an unregistered path")

    monkeypatch.setattr(host_probe_mod, "Path", factory)
    with pytest.raises(ValueError, match="not registered"):
        PathShareVisibilityChecker().observe(r"C:\Windows")


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (FileNotFoundError("missing"), "missing"),
        (PermissionError("denied"), "unreadable"),
        (OSError("network path"), "unreadable"),
    ],
)
def test_path_share_checker_maps_stat_errors(monkeypatch, error, expected):
    monkeypatch.setattr(
        host_probe_mod, "Path", lambda path: _FakeSharePath(path, error)
    )
    assert PathShareVisibilityChecker().observe(WSL_SHARE_PATH) == expected
    assert host_probe_mod.Path(WSL_SHARE_PATH).exists() is False


def test_path_share_checker_visible_when_stat_succeeds(monkeypatch):
    monkeypatch.setattr(host_probe_mod, "Path", lambda path: _FakeSharePath(path))
    assert PathShareVisibilityChecker().observe(WSL_SHARE_PATH) == "visible"


def test_unreadable_wsl_share_fails_host_group_when_other_checks_pass():
    record, checker = collect_isolated("unreadable")
    reason = host_group(record)["reason"]

    assert checker.seen == [WSL_SHARE_PATH]
    assert record["observations"]["wslShare"] == {
        "path": WSL_SHARE_PATH,
        "visibility": "unreadable",
    }
    assert host_group(record)["result"] == "fail"
    assert "unreadable" in reason
    assert "visible from Windows" not in reason


def test_missing_wsl_share_passes_share_check_when_other_checks_pass():
    record, checker = collect_isolated("missing")

    assert checker.seen == [WSL_SHARE_PATH]
    assert record["observations"]["wslShare"]["visibility"] == "missing"
    assert host_group(record)["result"] == "pass"
    assert record["failureGroups"] == []


def test_allow_wsl_share_env_does_not_fail_visible_share_when_other_checks_pass(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("KAPPA_BOX_ALLOW_WSL_SHARE", "1")
    record, checker = collect_isolated("visible")

    assert checker.seen == [WSL_SHARE_PATH]
    assert record["observations"]["wslShare"]["visibility"] == "visible"
    assert record["observations"]["wslShare"]["enforced"] is False
    assert record["observations"]["wslShare"]["waivedBy"] == "KAPPA_BOX_ALLOW_WSL_SHARE"
    assert host_group(record)["result"] == "pass"
    assert record["failureGroups"] == []
    assert "visible from Windows" not in host_group(record)["reason"]
    assert record["acceptance"] == "unverified"


def test_allow_wsl_share_env_does_not_skip_lsm_check(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("KAPPA_BOX_ALLOW_WSL_SHARE", "1")
    record, _checker = collect_daily()
    reason = host_group(record)["reason"]

    assert host_group(record)["result"] == "fail"
    assert "LSM list is unreadable" in reason
    assert "visible from Windows" not in reason


def test_empty_cgroup_subtree_fails_closed_with_specific_reason():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_isolated(
        "missing",
        **{
            "host.cgroup.subtree": _command_result(
                specs["host.cgroup.subtree"],
                stdout="\n",
            )
        },
    )
    reason = host_group(record)["reason"]

    assert record["observations"]["cgroup"]["subtreeReadable"] is True
    assert record["observations"]["cgroup"]["subtreeControl"] == []
    assert host_group(record)["result"] == "fail"
    assert "cgroup.subtree_control missing required controllers:" in reason
    assert "cpu" in reason
    assert "memory" in reason
    assert "pids" in reason


def test_cgroup_subtree_missing_required_controllers_fails_host_group():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_isolated(
        "missing",
        **{
            "host.cgroup.subtree": _command_result(
                specs["host.cgroup.subtree"],
                stdout="cpuset io hugetlb rdma\n",
            )
        },
    )
    reason = host_group(record)["reason"]

    assert record["observations"]["cgroup"]["subtreeReadable"] is True
    assert host_group(record)["result"] == "fail"
    assert "cgroup.subtree_control missing required controllers:" in reason
    assert "cpu" in reason
    assert "memory" in reason
    assert "pids" in reason


def test_truncated_mountinfo_fails_host_group():
    specs = {
        spec.name: spec
        for spec in host_visibility_command_specs("kappa-box-ubuntu-24.04")
    }
    record, _checker = collect_isolated(
        "missing",
        **{
            "host.mountinfo": _command_result(
                specs["host.mountinfo"],
                stdout=(
                    "82 67 8:80 / / rw,relatime - ext4 /dev/sdf rw\n"
                    "78 82 0:34 / /mnt/wsl rw,relatime - tmpfs none rw\n"
                ),
                truncated=True,
            )
        },
    )
    mountinfo = next(
        command for command in record["commands"] if command["name"] == "host.mountinfo"
    )

    assert mountinfo["truncated"] is True
    assert record["observations"]["mounts"]["drvfsPresent"] is False
    assert host_group(record)["result"] == "fail"
    assert "truncated" in host_group(record)["reason"]
