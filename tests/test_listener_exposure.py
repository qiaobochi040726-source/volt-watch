"""Tests for the listener exposure check."""

from volt_watch.checks import listener_exposure_check
from volt_watch.collector import parse_ss_listeners


def _listener(address, port, process=""):
    return {"address": address, "port": port, "process": process, "socket": ""}


def test_loopback_listener_is_not_reported():
    listeners = [
        _listener("127.0.0.1", "631", "cupsd"),
        _listener("::1", "25"),
    ]

    assert listener_exposure_check(listeners, [], "deny") == []


def test_unmentioned_port_is_info_when_the_default_denies():
    listeners = [_listener("0.0.0.0", "8099", "next-server")]
    rules = [{"port": "22/tcp", "action": "ALLOW", "interface": "tailscale0", "source": "Anywhere"}]

    findings = listener_exposure_check(listeners, rules, "deny")

    assert [f.check for f in findings] == ["network.listener_unrestricted"]
    assert findings[0].severity.value == "info"


def test_unmentioned_port_is_a_warning_when_the_default_allows():
    listeners = [_listener("0.0.0.0", "8099", "next-server")]

    findings = listener_exposure_check(listeners, [], "allow")

    assert [f.check for f in findings] == ["network.listener_unrestricted"]
    assert findings[0].severity.value == "warning"


def test_broad_allow_on_the_port_is_critical():
    listeners = [_listener("0.0.0.0", "8099", "next-server")]
    rules = [{"port": "8099/tcp", "action": "ALLOW", "interface": "", "source": "Anywhere"}]

    findings = listener_exposure_check(listeners, rules, "deny")

    assert [f.check for f in findings] == ["network.listener_exposed"]
    assert findings[0].severity.value == "critical"
    assert "tailscale0" in findings[0].remedy


def test_allow_scoped_to_tailscale_is_not_reported():
    listeners = [_listener("0.0.0.0", "8099", "next-server")]
    rules = [{"port": "8099/tcp", "action": "ALLOW", "interface": "tailscale0", "source": "Anywhere"}]

    assert listener_exposure_check(listeners, rules, "deny") == []


def test_rules_none_reports_firewall_unreadable():
    listeners = [_listener("0.0.0.0", "8099", "next-server")]

    findings = listener_exposure_check(listeners, None, "deny")

    assert [f.check for f in findings] == ["network.firewall_unreadable"]
    assert findings[0].severity.value == "warning"


def test_parse_ss_listeners_keeps_only_listen_rows_and_reads_processes():
    text = (
        "State Recv-Q Send-Q Local:Port Peer:Port Process\n"
        'LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=1,fd=3))\n'
        'LISTEN 0 128 0.0.0.0:8099 0.0.0.0:* users:(("next-server",pid=1234,fd=21))\n'
        'LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=2,fd=5))\n'
        "LISTEN 0 128 [::1]:25 [::]:*\n"
        "ESTAB 0 0 100.71.164.78:55085 1.2.3.4:443\n"
    )

    assert parse_ss_listeners(text) == [
        {"address": "127.0.0.1", "port": "631", "process": 'users:(("cupsd",pid=1,fd=3))', "socket": ""},
        {"address": "0.0.0.0", "port": "8099", "process": 'users:(("next-server",pid=1234,fd=21))', "socket": ""},
        {"address": "::", "port": "22", "process": 'users:(("sshd",pid=2,fd=5))', "socket": ""},
        {"address": "::1", "port": "25", "process": "", "socket": ""},
    ]
