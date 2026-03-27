from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="world_writable", category="persistence")
class WorldWritableCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []

        result = self.execute(
            "find / -maxdepth 3 -perm -002 -type f"
            " -not -path '/proc/*'"
            " -not -path '/sys/*'"
            " -not -path '/dev/*'"
            " -not -path '/run/*'"
            " -not -path '/tmp/*'"
            " 2>/dev/null | head -20"
        )
        if not result.success or not result.stdout.strip():
            findings.append(self.ok("No world-writable files found"))
            return findings

        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

        if files:
            findings.append(
                self.warning(
                    f"{len(files)} world-writable file(s) found",
                    details="\n".join(files[:10]),
                    fix_command=f"chmod o-w {files[0]}",
                )
            )

        return findings
