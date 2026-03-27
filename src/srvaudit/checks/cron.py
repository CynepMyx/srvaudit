from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


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
            "getent passwd | awk -F: '$7 !~ /(nologin|false)/ {print $1}' | head -20"
        )
        if not users_result.success:
            return

        for user in users_result.stdout.splitlines():
            user = user.strip()
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
                    findings.append(
                        self.info(
                            f"{user}: {len(jobs)} cron job(s)",
                            details="\n".join(jobs[:5]),
                        )
                    )

    def _check_system_cron(self, findings: list):
        result = self.execute("ls /etc/cron.d/ 2>/dev/null | head -20")
        if result.success and result.stdout.strip():
            files = [
                f.strip()
                for f in result.stdout.splitlines()
                if f.strip() and f.strip() not in (".placeholder", "e2scrub_all")
            ]
            if files:
                findings.append(
                    self.info(
                        f"{len(files)} system cron files in /etc/cron.d/",
                        details=", ".join(files[:10]),
                    )
                )
