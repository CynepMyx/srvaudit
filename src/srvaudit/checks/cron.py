from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding

USER_LIMIT = 20
SYSTEM_CRON_LIMIT = 20
DETAIL_LIMIT = 10
JOB_DETAIL_LIMIT = 5


@check(name="cron", category="persistence", requires_sudo=True)
class CronCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        self._check_user_crontabs(findings)
        self._check_system_cron(findings)
        return findings

    def _check_user_crontabs(self, findings: list):
        # Get users with login shells
        users_result = self.execute(
            f"getent passwd | awk -F: '$7 !~ /(nologin|false)/ {{print $1}}' | head -{USER_LIMIT}"
        )
        if not users_result.success:
            return

        users = [user.strip() for user in users_result.stdout.splitlines() if user.strip()]
        users_truncated = len(users) == USER_LIMIT

        for user in users:
            if not user or user in ("$", "#") or not all(c.isalnum() or c in "-_." for c in user):
                continue
            result = self.execute(f"crontab -l -u {user} 2>/dev/null")
            if result.success and result.stdout.strip():
                jobs = [
                    line.strip()
                    for line in result.stdout.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                if jobs:
                    details = "\n".join(jobs[:JOB_DETAIL_LIMIT])
                    if users_truncated:
                        note = f"(showing first {USER_LIMIT} results, may be incomplete)"
                        details = f"{details}\n{note}" if details else note
                    findings.append(
                        self.info(
                            f"{user}: {len(jobs)} cron job(s)",
                            details=details,
                        )
                    )

    def _check_system_cron(self, findings: list):
        result = self.execute(f"ls /etc/cron.d/ 2>/dev/null | head -{SYSTEM_CRON_LIMIT}")
        if result.success and result.stdout.strip():
            files = [
                f.strip()
                for f in result.stdout.splitlines()
                if f.strip() and f.strip() not in (".placeholder", "e2scrub_all")
            ]
            if files:
                details = ", ".join(files[:DETAIL_LIMIT])
                if len(files) == SYSTEM_CRON_LIMIT:
                    note = (
                        f"(showing first {SYSTEM_CRON_LIMIT} results, may be incomplete)"
                    )
                    details = f"{details}\n{note}" if details else note
                findings.append(
                    self.info(
                        f"{len(files)} system cron files in /etc/cron.d/",
                        details=details,
                    )
                )
