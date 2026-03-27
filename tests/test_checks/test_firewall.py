from srvaudit.checks.firewall import FirewallCheck
from srvaudit.models import DistroInfo, Severity
from tests.conftest import MockTransport

UFW_ACTIVE = """\
Status: active

To                         Action      From
--                         ------      ----
OpenSSH                    ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
"""

IPTABLES_DOCKER = """\
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0

Chain FORWARD (policy DROP)
target     prot opt source               destination
DOCKER-USER  all  --  0.0.0.0/0          0.0.0.0/0
DOCKER     all  --  0.0.0.0/0            0.0.0.0/0

Chain DOCKER (1 references)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            172.17.0.2     tcp dpt:8080
"""


def _make_check(responses, return_codes=None):
    transport = MockTransport(responses, return_codes or {})
    distro = DistroInfo(id="debian", version="13", family="debian")
    return FirewallCheck(transport, distro)


def test_ufw_active():
    check = _make_check({"ufw status 2>/dev/null": UFW_ACTIVE})
    findings = check.run()
    ok = [f for f in findings if f.severity == Severity.OK]
    assert any("UFW" in f.title for f in ok)


def test_docker_iptables_is_info_not_warning():
    check = _make_check(
        {
            "ufw status 2>/dev/null": "Status: inactive",
            "firewall-cmd --state 2>/dev/null": "",
            "nft list ruleset 2>/dev/null": "",
            "iptables -L -n 2>/dev/null": IPTABLES_DOCKER,
        },
        {
            "ufw status 2>/dev/null": 0,
            "firewall-cmd --state 2>/dev/null": 1,
            "nft list ruleset 2>/dev/null": 1,
        },
    )
    findings = check.run()
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    assert len(warnings) == 0
    infos = [f for f in findings if f.severity == Severity.INFO]
    assert any("Docker" in f.title for f in infos)


def test_no_firewall_warning():
    check = _make_check(
        {
            "ufw status 2>/dev/null": "",
            "firewall-cmd --state 2>/dev/null": "",
            "nft list ruleset 2>/dev/null": "",
            "iptables -L -n 2>/dev/null": "",
            "which docker 2>/dev/null": "",
        },
        {
            "ufw status 2>/dev/null": 1,
            "firewall-cmd --state 2>/dev/null": 1,
            "nft list ruleset 2>/dev/null": 1,
            "iptables -L -n 2>/dev/null": 1,
            "which docker 2>/dev/null": 127,
        },
    )
    findings = check.run()
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    assert len(warnings) == 1
    assert "No firewall" in warnings[0].title
