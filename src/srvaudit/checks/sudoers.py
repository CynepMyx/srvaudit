from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="sudoers", category="access", requires_sudo=True)
class SudoersCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []

        result = self.execute("cat /etc/sudoers 2>/dev/null")
        if not result.success:
            findings.append(self.skip("Cannot read /etc/sudoers"))
            return findings

        self._check_nopasswd(result.stdout, findings)

        # Check sudoers.d
        inc = self.execute("cat /etc/sudoers.d/* 2>/dev/null")
        if inc.success and inc.stdout.strip():
            self._check_nopasswd(inc.stdout, findings)

        return findings

    def _check_nopasswd(self, text: str, findings: list):
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if "NOPASSWD" in line and "ALL" in line:
                user_part = line.split()[0]
                findings.append(
                    self.warning(
                        f"NOPASSWD sudo for '{user_part}' with broad permissions",
                        details=line[:80],
                    )
                )
