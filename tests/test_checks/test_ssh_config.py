from srvaudit.checks.ssh_config import SSHConfigCheck
from srvaudit.models import DistroInfo, Severity
from tests.conftest import MockTransport

SECURE_CONFIG = """
Port 22
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
"""

INSECURE_CONFIG = """
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
"""

PROHIBIT_PASSWORD_CONFIG = """
PermitRootLogin prohibit-password
PasswordAuthentication no
"""

CONFIG_WITH_INCLUDE = """
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
"""

INCLUDE_OVERRIDE = """
PermitRootLogin no
PasswordAuthentication no
"""


def _make_check(responses, return_codes=None):
    transport = MockTransport(responses, return_codes or {})
    distro = DistroInfo(id="ubuntu", version="22.04", family="debian")
    return SSHConfigCheck(transport, distro)


def test_secure_config():
    check = _make_check({"cat /etc/ssh/sshd_config 2>/dev/null": SECURE_CONFIG})
    findings = check.run()
    severities = {f.severity for f in findings}
    assert Severity.CRITICAL not in severities
    assert Severity.WARNING not in severities


def test_insecure_config():
    check = _make_check({"cat /etc/ssh/sshd_config 2>/dev/null": INSECURE_CONFIG})
    findings = check.run()
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    assert len(criticals) >= 2  # root login + empty passwords
    assert len(warnings) >= 2  # password auth + x11


def test_prohibit_password_is_ok():
    check = _make_check({"cat /etc/ssh/sshd_config 2>/dev/null": PROHIBIT_PASSWORD_CONFIG})
    findings = check.run()
    root_findings = [f for f in findings if "Root login" in f.title or "root" in f.title.lower()]
    for f in root_findings:
        assert f.severity != Severity.CRITICAL
        assert f.severity != Severity.WARNING


def test_include_support():
    check = _make_check(
        {
            "cat /etc/ssh/sshd_config 2>/dev/null": CONFIG_WITH_INCLUDE,
            "cat '/etc/ssh/sshd_config.d/*.conf' 2>/dev/null": INCLUDE_OVERRIDE,
        }
    )
    # Verify it runs without error with Include directives
    check.run()


def test_unreadable_config():
    check = _make_check(
        {"cat /etc/ssh/sshd_config 2>/dev/null": ""},
        {"cat /etc/ssh/sshd_config 2>/dev/null": 1},
    )
    findings = check.run()
    skipped = [f for f in findings if f.severity == Severity.SKIP]
    assert len(skipped) >= 1
