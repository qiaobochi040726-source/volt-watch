"""Config files replaced by pacman (.pacnew/.pacsave) are findings."""

import os

from volt_watch import auditor, collector
from volt_watch.checks import config_drift_check
from volt_watch.collector import (
    MAX_DRIFT_DEPTH,
    MAX_DRIFT_ENTRIES,
    config_drift,
)
from volt_watch.finding import Finding
from volt_watch.severity import Severity


def _touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("content\n", encoding="utf-8")


def test_both_suffixes_are_reported_as_relative_paths(tmp_path):
    _touch(tmp_path / "mkinitcpio.d" / "linux.preset.pacsave")
    _touch(tmp_path / "ssh" / "sshd_config.pacnew")
    _touch(tmp_path / "ssh" / "sshd_config")
    _touch(tmp_path / "pac.conf.pacorig")

    drift = config_drift(str(tmp_path))

    assert drift["pacnew"] == [os.path.join("ssh", "sshd_config.pacnew")]
    assert drift["pacsave"] == [os.path.join("mkinitcpio.d", "linux.preset.pacsave")]
    assert drift["truncated"] is False


def test_a_clean_tree_is_an_empty_answer(tmp_path):
    _touch(tmp_path / "empty.conf")

    drift = config_drift(str(tmp_path))

    assert drift == {"pacnew": [], "pacsave": [], "truncated": False}


def test_a_missing_root_is_unknown(tmp_path):
    assert config_drift(str(tmp_path / "absent")) is None


def test_an_unreadable_directory_anywhere_is_unknown(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir()
    _touch(locked / "x.pacnew")
    real_scandir = os.scandir

    def failing_scandir(path):
        if str(path) == str(locked):
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", failing_scandir)

    assert config_drift(str(tmp_path)) is None


def test_symlinks_are_never_followed(tmp_path):
    outside = tmp_path / "outside"
    inside = tmp_path / "inside"
    _touch(outside / "target.pacnew")
    inside.mkdir()
    (inside / "link.pacnew").symlink_to(outside / "target.pacnew")
    (inside / "dirlink").symlink_to(outside, target_is_directory=True)

    drift = config_drift(str(inside))

    assert drift == {"pacnew": [], "pacsave": [], "truncated": False}


def test_the_depth_bound_is_enforced(tmp_path):
    shallow = tmp_path / ("a" * 1)
    deep = tmp_path.joinpath(*(["d"] * (MAX_DRIFT_DEPTH + 1)))
    _touch(shallow / "ok.pacnew")
    _touch(deep / "too-far.pacnew")

    drift = config_drift(str(tmp_path))

    assert drift["pacnew"] == [os.path.join("a", "ok.pacnew")]


def test_the_entry_cap_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "MAX_DRIFT_ENTRIES", 2)
    for name in ("one.pacnew", "two.pacnew", "three.pacsave"):
        _touch(tmp_path / name)

    drift = config_drift(str(tmp_path))

    assert drift["truncated"] is True
    assert len(drift["pacnew"]) + len(drift["pacsave"]) <= 2


def test_an_unknown_scan_reports_the_unknown_state():
    findings = config_drift_check(None)

    assert len(findings) == 1
    assert findings[0].check == "config.drift_unknown"
    assert findings[0].severity is Severity.WARNING


def test_a_clean_scan_has_no_finding():
    clean = {"pacnew": [], "pacsave": [], "truncated": False}

    assert config_drift_check(clean) == []


def test_drift_names_the_files_and_is_a_warning():
    drift = {
        "pacnew": ["etc/a.pacnew"],
        "pacsave": ["etc/b.pacsave"],
        "truncated": False,
    }

    findings = config_drift_check(drift)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, Finding)
    assert finding.check == "config.drift"
    assert finding.severity is Severity.WARNING
    assert "2 replaced config" in finding.message
    assert finding.evidence["pacnew"] == ["etc/a.pacnew"]
    assert finding.evidence["pacsave"] == ["etc/b.pacsave"]


def test_the_config_group_runs_the_check(monkeypatch):
    monkeypatch.setattr(
        collector,
        "config_drift",
        lambda: {"pacnew": [], "pacsave": [], "truncated": False},
    )

    assert auditor.CHECKS["config"][0]() == []
