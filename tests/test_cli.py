"""Tests for the command line interface."""

import json
from pathlib import Path

import pytest

from volt_watch import cli


def test_json_output_lists_every_finding(capsys):
    findings = [
        {
            "check": "sshd.exposed",
            "severity": "critical",
            "message": "SSH is open",
            "remedy": "Restrict it",
            "evidence": {"port": 22},
        }
    ]
    code = cli.main(["--json"], findings=findings)

    out = json.loads(capsys.readouterr().out)

    assert code == 1
    assert out["findings"] == findings
    assert out["counts"]["critical"] == 1


def test_plain_output_prints_one_line_per_finding(capsys):
    findings = [
        {"check": "a", "severity": "critical", "message": "m1", "remedy": "r", "evidence": {}},
        {"check": "b", "severity": "warning", "message": "m2", "remedy": "r", "evidence": {}},
    ]
    cli.main([], findings=findings)

    out = capsys.readouterr().out

    assert "critical  a" in out
    assert "warning   b" in out
    assert "2 finding(s)" in out


def test_exit_code_is_zero_when_nothing_is_wrong(capsys):
    code = cli.main(["--json"], findings=[])

    assert code == 0
    assert json.loads(capsys.readouterr().out)["counts"]["total"] == 0


def test_exit_code_ignores_info_findings(capsys):
    findings = [
        {"check": "x", "severity": "info", "message": "m", "remedy": "", "evidence": {}}
    ]

    assert cli.main([], findings=findings) == 0


def test_quiet_suppresses_plain_output(capsys):
    findings = [
        {"check": "a", "severity": "critical", "message": "m", "remedy": "r", "evidence": {}}
    ]
    cli.main(["--quiet"], findings=findings)

    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("mode", [[], ["--quiet"], ["--json"]])
def test_unwritable_output_is_an_auditor_error(tmp_path, monkeypatch, capsys, mode):
    target = tmp_path / "baseline.json"
    findings = [
        {"check": "test.warning", "severity": "warning", "message": "m",
         "remedy": "", "evidence": {}},
    ]

    def fail_to_write(path, *args, **kwargs):
        assert path == target
        raise PermissionError("permission denied")

    monkeypatch.setattr(Path, "write_text", fail_to_write)

    assert cli.main([*mode, "--output", str(target)], findings=findings) == 2

    captured = capsys.readouterr()
    message = f"could not write {str(target)!r}: permission denied"
    if "--json" in mode:
        payload = json.loads(captured.out)
        assert payload["error"] == message
        assert payload["findings"] == findings
        assert payload["counts"]["warning"] == 1
        assert captured.err == ""
    else:
        assert captured.out == ""
        assert captured.err == f"volt-watch: error: {message}\n"
