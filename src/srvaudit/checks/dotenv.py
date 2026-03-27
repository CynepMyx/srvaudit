from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="dotenv", category="web")
class DotenvCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []

        # Only run if /var/www exists
        result = self.execute("test -d /var/www")
        if not result.success:
            return findings

        result = self.execute(
            "find /var/www -maxdepth 3 -name '.env' -type f 2>/dev/null | head -10"
        )
        if not result.success or not result.stdout.strip():
            return findings

        files = [f.strip() for f in result.stdout.splitlines() if f.strip()]
        if files:
            findings.append(
                self.warning(
                    f"{len(files)} .env file(s) found in web directories",
                    details="\n".join(files[:5]),
                    fix_command=("# Add to nginx config:\n# location ~ /\\.env { deny all; }"),
                )
            )

        return findings
