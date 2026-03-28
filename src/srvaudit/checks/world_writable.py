from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding

RESULT_LIMIT = 20
DETAIL_LIMIT = 10


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
            f" 2>/dev/null | head -{RESULT_LIMIT}"
        )
        if not result.stdout.strip():
            if result.return_code != 0:
                findings.append(self.skip("find command failed"))
            else:
                findings.append(self.ok("No world-writable files found"))
            return findings

        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

        if files:
            details = "\n".join(files[:DETAIL_LIMIT])
            if len(files) == RESULT_LIMIT:
                note = f"(showing first {RESULT_LIMIT} results, may be incomplete)"
                details = f"{details}\n{note}" if details else note
            findings.append(
                self.warning(
                    f"{len(files)} world-writable file(s) found",
                    details=details,
                    fix_command=f"chmod o-w {files[0]}",
                )
            )

        return findings
