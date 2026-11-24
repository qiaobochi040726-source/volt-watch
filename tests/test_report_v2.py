"""Tests for issue #59: JSON report timestamp and coverage counters."""

import json
from datetime import datetime

from volt_watch import cli, collector


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _finding(check="sshd.exposed", severity="critical", evidence=None):
    return {
        "check": check,
        "severity": severity,
        "message": f"{check} message",
        "remedy": "do the thing",
        "evidence": evidence if evidence is not None else {"port": 22},
    }


def test_payload_version_is_2(capsys):
    cli.main(["--json"], findings=[_finding()])
    out = json.loads(capsys.readouterr().out)
    assert out["version"] == 2


def test_payload_has_generated_at_utc_iso8601(capsys):
    cli.main(["--json"], findings=[])
    out = json.loads(capsys.readouterr().out)
    ts = out["generated_at"]
    assert isinstance(ts, str)
    assert ts.endswith("Z")
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_payload_has_coverage_shape(capsys):
    cli.main(["--json"], findings=[])
    out = json.loads(capsys.readouterr().out)
    cov = out["coverage"]
    assert isinstance(cov["readers"], int)
    assert isinstance(cov["degraded"], list)
    assert all(isinstance(d, str) for d in cov["degraded"])


def test_injected_findings_have_empty_degraded(capsys):
    # The findings seam skips the audit, so no reader degraded.
    cli.main(["--json"], findings=[])
    out = json.loads(capsys.readouterr().out)
    assert out["coverage"]["degraded"] == []


def test_real_run_reports_degraded_readers(monkeypatch, capsys):
    def boom(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(collector.subprocess, "run", boom)
    collector.collector_errors()  # drain anything from earlier tests

    cli.main(["--json"])
    out = json.loads(capsys.readouterr().out)

    assert "tailscale_status" in out["coverage"]["degraded"]
    assert out["coverage"]["readers"] >= 1
    degraded = [f for f in out["findings"] if f["check"] == "auditor.degraded"][0]
    assert set(out["coverage"]["degraded"]) == set(degraded["evidence"]["readers"])


def test_degraded_coverage_matches_finding_with_injected_findings(capsys):
    findings = [_finding(check="auditor.degraded", evidence={"readers": {"ufw_rules": "not installed"}})]
    cli.main(["--json"], findings=findings)
    out = json.loads(capsys.readouterr().out)
    assert out["coverage"]["degraded"] == ["ufw_rules"]


def test_since_against_v1_baseline_still_works(tmp_path, capsys):
    """A v1 baseline has no generated_at/coverage; comparison uses findings only."""
    v1 = {
        "version": 1,
        "host": "old",
        "findings": [_finding()],
        "counts": {"total": 1, "critical": 1, "warning": 0, "info": 0},
    }
    baseline = tmp_path / "v1.json"
    baseline.write_text(json.dumps(v1), encoding="utf-8")

    code = cli.main(["--json", "--since", str(baseline)], findings=[_finding()])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["version"] == 2


def test_since_v1_new_finding_still_regresses(tmp_path):
    v1 = {
        "version": 1,
        "host": "old",
        "findings": [],
        "counts": {"total": 0, "critical": 0, "warning": 0, "info": 0},
    }
    baseline = tmp_path / "v1.json"
    baseline.write_text(json.dumps(v1), encoding="utf-8")
    assert cli.main(["--since", str(baseline)], findings=[_finding()]) == 1


def test_output_writes_v2_fields(tmp_path):
    out_file = tmp_path / "report.json"
    cli.main(["--json", "--output", str(out_file)], findings=[_finding()])
    written = json.loads(out_file.read_text(encoding="utf-8"))
    assert written["version"] == 2
    assert "generated_at" in written
    assert "coverage" in written


def test_unknown_prefix_json_error_uses_v2_schema(capsys):
    code = cli.main(["--json", "--check", "nope"], findings=[])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["version"] == 2
    assert "generated_at" in out
    assert "coverage" in out
