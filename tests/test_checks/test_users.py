from srvaudit.checks.users import UsersCheck
from srvaudit.models import DistroInfo, Severity
from tests.conftest import MockTransport

PASSWD_NORMAL = "root\n"

PASSWD_TWO_UID0 = "root\nbackdoor\n"


def _make_check(awk_output, getent_output="root:x:0:0::/root:/bin/bash\n"):
    transport = MockTransport(
        {
            "awk -F: '$3 == 0 {print $1}' /etc/passwd": awk_output,
            "getent passwd | grep -vE '(/nologin|/false|/sync|/halt|/shutdown)$'": getent_output,
        }
    )
    distro = DistroInfo(id="debian", version="13", family="debian")
    return UsersCheck(transport, distro)


def test_only_root_uid0():
    check = _make_check(PASSWD_NORMAL)
    findings = check.run()
    ok = [f for f in findings if f.severity == Severity.OK]
    assert any("Only root" in f.title for f in ok)


def test_extra_uid0_user():
    check = _make_check(PASSWD_TWO_UID0)
    findings = check.run()
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 1
    assert "backdoor" in criticals[0].title


def test_prompt_artifact_filtered():
    check = _make_check("root\n$\n")
    findings = check.run()
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 0


def test_hyphenated_username_detected():
    check = _make_check("root\ntest-admin\n")
    findings = check.run()
    criticals = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(criticals) == 1
    assert "test-admin" in criticals[0].title
