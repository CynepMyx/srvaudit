from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="users", category="access", quick=True)
class UsersCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        self._check_uid_zero(findings)
        self._check_login_shells(findings)
        return findings

    def _check_uid_zero(self, findings: list):
        result = self.execute("awk -F: '$3 == 0 {print $1}' /etc/passwd")
        if not result.success:
            findings.append(self.skip("Cannot read /etc/passwd"))
            return

        uid0_users = [
            u.strip() for u in result.stdout.splitlines() if u.strip() and u.strip().isalnum()
        ]
        non_root = [u for u in uid0_users if u != "root"]
        if non_root:
            findings.append(
                self.critical(
                    f"Non-root users with UID 0: {', '.join(non_root)}",
                    details=(
                        "Only root should have UID 0."
                        " Other accounts with UID 0 have full root privileges."
                    ),
                    fix_command=f"usermod -u <new_uid> {non_root[0]}",
                )
            )
        else:
            findings.append(self.ok("Only root has UID 0"))

    def _check_login_shells(self, findings: list):
        result = self.execute("getent passwd | grep -vE '(/nologin|/false|/sync|/halt|/shutdown)$'")
        if not result.success:
            return

        users_with_shell = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 7 and parts[0]:
                users_with_shell.append(parts[0])

        if len(users_with_shell) > 5:
            findings.append(
                self.info(
                    f"{len(users_with_shell)} users with login shells",
                    details=", ".join(users_with_shell[:10]),
                )
            )
