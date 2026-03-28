from srvaudit.checks.updates import UpdatesCheck
from srvaudit.models import Severity
from tests.conftest import MockTransport

COMMAND_YUM = "yum check-update --quiet 2>/dev/null"
COMMAND_DNF = "dnf check-update --quiet 2>/dev/null"
COMMAND_APK = "apk version -l '<' 2>/dev/null"


def test_yum_fallback_to_dnf_counts_lines(centos_distro):
    transport = MockTransport(
        {
            COMMAND_YUM: "",
            COMMAND_DNF: "pkg1.x86_64 1 repo\npkg2.noarch 2 repo\n",
        },
        {
            COMMAND_YUM: 127,
            COMMAND_DNF: 100,
        },
    )

    findings = UpdatesCheck(transport, centos_distro).run()

    assert any(
        f.severity == Severity.INFO and "2 packages can be upgraded" in f.title for f in findings
    )


def test_yum_and_dnf_errors_return_skip(centos_distro):
    transport = MockTransport(
        {
            COMMAND_YUM: "error",
            COMMAND_DNF: "error",
        },
        {
            COMMAND_YUM: 1,
            COMMAND_DNF: 1,
        },
    )

    findings = UpdatesCheck(transport, centos_distro).run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.SKIP
    assert "yum/dnf" in findings[0].title


def test_apk_counts_lines_without_wc(alpine_distro):
    transport = MockTransport(
        {
            COMMAND_APK: "pkg1\npkg2\npkg3\n",
        },
        {
            COMMAND_APK: 0,
        },
    )

    findings = UpdatesCheck(transport, alpine_distro).run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "3 packages can be upgraded" in findings[0].title
