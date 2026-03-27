from srvaudit.checks.open_ports import OpenPortsCheck, is_public, parse_listen_addr
from srvaudit.models import DistroInfo, Severity
from tests.conftest import MockTransport


def test_parse_ipv4():
    host, port = parse_listen_addr("0.0.0.0:8080")
    assert host == "0.0.0.0"
    assert port == 8080


def test_parse_ipv4_localhost():
    host, port = parse_listen_addr("127.0.0.1:3306")
    assert host == "127.0.0.1"
    assert port == 3306


def test_parse_ipv6_bracket():
    host, port = parse_listen_addr("[::]:22")
    assert port == 22


def test_parse_ipv6_triple_colon():
    host, port = parse_listen_addr(":::8080")
    assert port == 8080


def test_parse_ipv6_localhost():
    host, port = parse_listen_addr("[::1]:5432")
    assert port == 5432


def test_parse_wildcard():
    host, port = parse_listen_addr("*:3000")
    assert port == 3000


def test_is_public_zero():
    assert is_public("0.0.0.0") is True


def test_is_public_star():
    assert is_public("*") is True


def test_is_public_ipv6_any():
    assert is_public("::") is True


def test_is_not_public_localhost():
    assert is_public("127.0.0.1") is False


def test_is_not_public_ipv6_localhost():
    assert is_public("::1") is False


SS_OUTPUT = """\
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
LISTEN 0      128    0.0.0.0:22           0.0.0.0:*
LISTEN 0      128    0.0.0.0:3306         0.0.0.0:*
LISTEN 0      128    127.0.0.1:6379       0.0.0.0:*
LISTEN 0      128    0.0.0.0:80           0.0.0.0:*
"""


def _make_check(ss_output):
    transport = MockTransport({"ss -tlnp 2>/dev/null": ss_output})
    distro = DistroInfo(id="debian", version="13", family="debian")
    return OpenPortsCheck(transport, distro)


def test_detects_dangerous_port():
    check = _make_check(SS_OUTPUT)
    findings = check.run()
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 1
    assert "3306" in criticals[0].title


def test_ssh_and_http_ok():
    check = _make_check(SS_OUTPUT)
    findings = check.run()
    ok_findings = [f for f in findings if f.severity == Severity.OK]
    titles = " ".join(f.title for f in ok_findings)
    assert "SSH" in titles
    assert "HTTP" in titles


def test_localhost_not_flagged():
    check = _make_check(SS_OUTPUT)
    findings = check.run()
    all_titles = " ".join(f.title for f in findings)
    assert "6379" not in all_titles
