from srvaudit.checks.fail2ban import Fail2banCheck
from srvaudit.models import Severity
from tests.conftest import MockTransport


def test_detects_exposed_ssh_on_nonstandard_port(ubuntu_distro):
    transport = MockTransport(
        {
            "fail2ban-client status 2>/dev/null": "",
            "which fail2ban-server 2>/dev/null": "",
            "ss -tlnp 2>/dev/null | grep sshd": (
                'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=123,fd=3))'
            ),
        },
        {
            "fail2ban-client status 2>/dev/null": 127,
            "which fail2ban-server 2>/dev/null": 127,
            "ss -tlnp 2>/dev/null | grep sshd": 0,
        },
    )

    findings = Fail2banCheck(transport, ubuntu_distro).run()

    assert any(
        f.severity == Severity.WARNING and "fail2ban is not installed" in f.title for f in findings
    )
