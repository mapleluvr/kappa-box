from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from kappa_box import __main__ as main_mod


def test_source_commit_rejects_dirty_worktree(monkeypatch, tmp_path: Path):
    def fake_run(argv, **kwargs):
        assert kwargs.get("cwd") == tmp_path
        if argv == ["git", "status", "--porcelain"]:
            return subprocess.CompletedProcess(
                argv, 0, stdout=" M src/kappa_box/host_probe.py\n", stderr=""
            )
        raise AssertionError(f"unexpected git command: {argv}")

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="dirty worktree"):
        main_mod._source_commit(tmp_path)


def test_source_commit_returns_head_commit_when_clean(monkeypatch, tmp_path: Path):
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        assert kwargs.get("cwd") == tmp_path
        seen.append(list(argv))
        if argv == ["git", "status", "--porcelain"]:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if argv == ["git", "rev-parse", "--short", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, stdout="4b70ba7\n", stderr="")
        raise AssertionError(f"unexpected git command: {argv}")

    monkeypatch.setattr(main_mod.subprocess, "run", fake_run)

    assert main_mod._source_commit(tmp_path) == "4b70ba7"
    assert seen == [
        ["git", "status", "--porcelain"],
        ["git", "rev-parse", "--short", "HEAD"],
    ]


def test_run_host_visibility_does_not_collect_on_dirty_worktree(monkeypatch):
    called: list[str] = []

    def fake_source_commit(root: Path) -> str:
        raise RuntimeError("refusing to collect evidence from a dirty worktree")

    monkeypatch.setattr(main_mod, "_source_commit", fake_source_commit)
    monkeypatch.setattr(
        main_mod,
        "collect_host_visibility",
        lambda *args, **kwargs: called.append("collect"),
    )
    monkeypatch.setattr(
        main_mod,
        "write_host_visibility_evidence",
        lambda *args, **kwargs: called.append("write"),
    )

    with pytest.raises(RuntimeError, match="dirty worktree"):
        main_mod.run_host_visibility("wsl2:l1@openshell-docker")
    assert called == []
