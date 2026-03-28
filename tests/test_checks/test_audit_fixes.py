from srvaudit.checks.capabilities import CapabilitiesCheck
from srvaudit.checks.cron import CronCheck
from srvaudit.checks.dotenv import DotenvCheck
from srvaudit.checks.world_writable import WorldWritableCheck
from srvaudit.models import DistroInfo, Severity
from tests.conftest import MockTransport

WORLD_WRITABLE_CMD = (
    "find / -maxdepth 3 -perm -002 -type f"
    " -not -path '/proc/*'"
    " -not -path '/sys/*'"
    " -not -path '/dev/*'"
    " -not -path '/run/*'"
    " -not -path '/tmp/*'"
    " 2>/dev/null | head -20"
)
CAPABILITIES_CMD = "getcap -r / 2>/dev/null | head -50"
CRON_USERS_CMD = "getent passwd | awk -F: '$7 !~ /(nologin|false)/ {print $1}' | head -20"
SYSTEM_CRON_CMD = "ls /etc/cron.d/ 2>/dev/null | head -20"
DOTENV_DIR_CMD = "test -d /var/www"
DOTENV_FIND_CMD = "find /var/www -maxdepth 3 -name '.env' -type f 2>/dev/null | head -10"
TRUNCATED_20_NOTE = "(showing first 20 results, may be incomplete)"
TRUNCATED_50_NOTE = "(showing first 50 results, may be incomplete)"
TRUNCATED_10_NOTE = "(showing first 10 results, may be incomplete)"


def test_world_writable_find_failure_is_skip():
    transport = MockTransport(
        {WORLD_WRITABLE_CMD: ""},
        {WORLD_WRITABLE_CMD: 1},
    )

    findings = WorldWritableCheck(transport, DistroInfo()).run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.SKIP
    assert findings[0].title == "Skipped: find command failed"


def test_world_writable_truncation_note_added():
    files = "\n".join(f"/path/file{i}" for i in range(20))
    transport = MockTransport({WORLD_WRITABLE_CMD: files})

    findings = WorldWritableCheck(transport, DistroInfo()).run()

    assert len(findings) == 1
    assert TRUNCATED_20_NOTE in findings[0].details


def test_capabilities_truncation_note_added(ubuntu_distro):
    output = "\n".join(f"/usr/bin/tool{i}=cap_setuid+ep" for i in range(50))
    transport = MockTransport({CAPABILITIES_CMD: output})

    findings = CapabilitiesCheck(transport, ubuntu_distro).run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert TRUNCATED_50_NOTE in findings[0].details


def test_cron_truncation_note_added(ubuntu_distro):
    users = "\n".join(f"user{i}" for i in range(1, 21))
    system_cron_files = "\n".join(f"job{i}" for i in range(1, 21))
    transport = MockTransport(
        {
            CRON_USERS_CMD: users,
            "crontab -l -u user1 2>/dev/null": "* * * * * /bin/true\n",
            SYSTEM_CRON_CMD: system_cron_files,
        }
    )

    findings = CronCheck(transport, ubuntu_distro).run()

    assert any(
        f.title.startswith("user1:") and TRUNCATED_20_NOTE in f.details for f in findings
    )
    assert any(
        "system cron files" in f.title and TRUNCATED_20_NOTE in f.details
        for f in findings
    )


def test_dotenv_truncation_note_added(ubuntu_distro):
    files = "\n".join(f"/var/www/site{i}/.env" for i in range(10))
    transport = MockTransport(
        {
            DOTENV_DIR_CMD: "",
            DOTENV_FIND_CMD: files,
        },
        {
            DOTENV_DIR_CMD: 0,
            DOTENV_FIND_CMD: 0,
        },
    )

    findings = DotenvCheck(transport, ubuntu_distro).run()

    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert TRUNCATED_10_NOTE in findings[0].details
