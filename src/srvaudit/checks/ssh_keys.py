from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="ssh_keys", category="access", quick=True, requires_sudo=True)
class SSHKeysCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        users = self._get_users_with_home()
        for user, home in users:
            self._check_authorized_keys(user, home, findings)
        return findings

    def _get_users_with_home(self) -> list:
        result = self.execute("getent passwd | awk -F: '$3 >= 0 && $3 < 65534 {print $1, $6}'")
        if not result.success:
            return []

        users = []
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                users.append((parts[0], parts[1]))
        return users

    def _check_authorized_keys(self, user: str, home: str, findings: list):
        ak_path = f"{home}/.ssh/authorized_keys"
        result = self.execute(f"cat {ak_path} 2>/dev/null")
        if not result.success:
            return

        keys = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        if not keys:
            return

        if len(keys) > 5:
            findings.append(
                self.warning(
                    f"{user}: {len(keys)} SSH keys in authorized_keys",
                    details=f"Review keys in {ak_path} for unused entries",
                )
            )
        else:
            findings.append(
                self.info(
                    f"{user}: {len(keys)} SSH key(s) in authorized_keys",
                )
            )

        # Check for keys with command= restriction or no-pty
        for key in keys:
            if "command=" in key:
                findings.append(
                    self.info(
                        f"{user}: key with command= restriction found",
                    )
                )
                break
