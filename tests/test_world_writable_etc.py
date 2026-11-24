"""Test-first: world-writable files and directories under /etc are findings."""

import os

import pytest

from volt_watch import auditor
from volt_watch.checks import MAX_WORLD_WRITABLE_ENTRIES, world_writable_etc_check
from volt_watch.collector import MAX_WORLD_WRITABLE_DEPTH, world_writable_etc
from volt_watch.severity import Severity


def _touch(path, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("content\n", encoding="utf-8")
    path.chmod(mode)
    return path


def test_only_the_world_writable_file_is_returned(tmp_path):
    _touch(tmp_path / "safe.conf")
    _touch(tmp_path / "ssh" / "unsafe.conf", 0o666)

    result = world_writable_etc(str(tmp_path))

    assert [item["path"] for item in result] == [os.path.join("ssh", "unsafe.conf")]


def test_a_world_writable_directory_is_returned_with_its_mode(tmp_path):
    _touch(tmp_path / "cron.d" / "job", 0o644)
    (tmp_path / "cron.d").chmod(0o777)

    result = world_writable_etc(str(tmp_path))

    assert result == [{"path": "cron.d", "mode": "0o777"}]


def test_symlinks_are_not_reported_and_their_targets_are_not_walked(tmp_path):
    outside = tmp_path / "outside"
    _touch(outside / "secret", 0o666)
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "link").symlink_to(outside / "secret")
    (inside / "dirlink").symlink_to(outside, target_is_directory=True)

    assert world_writable_etc(str(inside)) == []


def test_an_unreadable_root_is_unknown_not_clean(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir()
    _touch(locked / "sshd_config", 0o666)
    real_scandir = os.scandir

    def failing_scandir(path):
        if str(path) == str(locked):
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", failing_scandir)

    assert world_writable_etc(str(locked)) is None


def test_a_missing_root_is_unknown(tmp_path):
    assert world_writable_etc(str(tmp_path / "absent")) is None


def test_the_depth_bound_is_a_named_constant():
    assert isinstance(MAX_WORLD_WRITABLE_DEPTH, int)
    assert 0 < MAX_WORLD_WRITABLE_DEPTH <= 10


def test_a_file_beyond_the_depth_bound_is_not_walked(tmp_path):
    deep = tmp_path.joinpath(*(["d"] * (MAX_WORLD_WRITABLE_DEPTH + 2)))
    _touch(deep / "too-far", 0o666)
    _touch(tmp_path / "visible", 0o666)

    found = world_writable_etc(str(tmp_path))

    assert found == [{"path": "visible", "mode": "0o666"}]


def test_a_clean_list_produces_no_finding():
    assert world_writable_etc_check([]) == []


def test_an_unreadable_etc_is_a_distinct_unknown_finding():
    findings = world_writable_etc_check(None)

    assert len(findings) == 1
    assert findings[0].check == "config.world_writable_unknown"
    assert findings[0].severity is Severity.WARNING
    assert findings[0].evidence == {"path": "/etc"}


def test_an_ordinary_path_is_a_warning_with_evidence():
    item = {"path": "weird.conf", "mode": "0o666"}

    findings = world_writable_etc_check([item])

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check == "config.world_writable"
    assert finding.severity is Severity.WARNING
    assert finding.evidence["paths"] == [item]
    assert finding.evidence["total"] == 1


@pytest.mark.parametrize("path", [
    "ssh/sshd_config",
    "sudoers.d/10-wheel",
    "pam.d/system-auth",
    "systemd/system/sshd.service",
    "cron.d/backup",
    "cron.daily/cleanup",
])
def test_a_path_that_turns_a_write_into_root_is_critical(path):
    findings = world_writable_etc_check([{"path": path, "mode": "0o666"}])

    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_a_file_named_like_a_sensitive_directory_is_only_a_warning():
    findings = world_writable_etc_check([{"path": "sshd_config", "mode": "0o666"}])

    assert findings[0].severity is Severity.WARNING


def test_evidence_is_capped_but_the_total_is_exact():
    items = [{"path": f"spool/{index}", "mode": "0o666"} for index in range(25)]

    finding = world_writable_etc_check(items)[0]

    assert MAX_WORLD_WRITABLE_ENTRIES == 20
    assert len(finding.evidence["paths"]) == 20
    assert finding.evidence["total"] == 25
    assert "and 5 more" in finding.message


def test_check_config_runs_the_world_writable_scan(monkeypatch):
    monkeypatch.setattr(
        auditor.collector,
        "config_drift",
        lambda: {"pacnew": [], "pacsave": [], "truncated": False},
    )
    monkeypatch.setattr(
        auditor.collector,
        "world_writable_etc",
        lambda: [{"path": "ssh/sshd_config", "mode": "0o666"}],
    )

    findings = auditor.audit(only="config")

    assert any(f.check == "config.world_writable" for f in findings)


def test_returned_paths_are_sorted_for_a_stable_report(tmp_path):
    _touch(tmp_path / "z.conf", 0o666)
    _touch(tmp_path / "a.conf", 0o666)

    found = world_writable_etc(str(tmp_path))

    assert [item["path"] for item in found] == ["a.conf", "z.conf"]
