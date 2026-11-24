"""Test-first: the firewall default policy matters beyond SSH."""

from volt_watch import auditor, collector
from volt_watch.checks import firewall_default_check
from volt_watch.severity import Severity


class _Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _run(monkeypatch, text, returncode=0):
    monkeypatch.setattr(
        collector.subprocess,
        "run",
        lambda cmd, **kwargs: _Result(text, returncode),
    )


def test_reject_is_a_readable_default_policy(monkeypatch):
    _run(monkeypatch, "Default: reject (incoming), allow (outgoing)\n")

    assert collector.ufw_default_incoming() == "reject"


def test_an_unusual_incoming_word_is_preserved_for_the_check_to_warn(monkeypatch):
    _run(monkeypatch, "Default: mystery (incoming), allow (outgoing)\n")

    assert collector.ufw_default_incoming() == "mystery"


def test_allow_is_a_critical_default_allow_finding():
    findings = firewall_default_check("allow")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check == "firewall.default_allow"
    assert finding.severity is Severity.CRITICAL
    assert "allow" in finding.message
    assert "ufw default deny incoming" in finding.remedy


def test_deny_and_reject_produce_no_finding():
    assert firewall_default_check("deny") == []
    assert firewall_default_check("reject") == []


def test_none_is_not_a_finding():
    """The unreadable case is owned by sshd.firewall_unreadable."""
    assert firewall_default_check(None) == []


def test_an_unusual_policy_is_warning_not_silence():
    findings = firewall_default_check("mystery")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check == "firewall.default_allow"
    assert finding.severity is Severity.WARNING
    assert "mystery" in finding.message


def test_check_firewall_runs_the_default_policy_check(monkeypatch):
    # --check firewall runs both the default-policy and the SSH-exposure check.
    monkeypatch.setattr(auditor.collector, "ufw_rules", lambda: [])
    monkeypatch.setattr(auditor.collector, "ufw_default_incoming", lambda: "allow")
    monkeypatch.setattr(auditor.collector, "collector_errors", dict)

    checks = [f.check for f in auditor.audit(only="firewall")]

    assert "firewall.default_allow" in checks
    assert "sshd.unrestricted" in checks
