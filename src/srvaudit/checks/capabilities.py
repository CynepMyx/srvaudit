from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding, Severity

DANGEROUS_CAPS = {
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_net_raw",
    "cap_net_admin",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_chown",
    "cap_fowner",
}

KNOWN_SAFE = {
    "/usr/bin/ping",
    "/bin/ping",
    "/usr/sbin/clockdiff",
    "/usr/sbin/arping",
}

RESULT_LIMIT = 50
DETAIL_LIMIT = 10


@check(name="capabilities", category="system", requires_sudo=True)
class CapabilitiesCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        result = self.execute(f"getcap -r / 2>/dev/null | head -{RESULT_LIMIT}")
        if result.not_found:
            findings.append(self.skip("getcap not available"))
            return findings
        if not result.stdout.strip():
            findings.append(self.ok("No file capabilities found"))
            return findings

        suspicious = []
        raw_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        truncated = len(raw_lines) == RESULT_LIMIT

        for line in raw_lines:
            line = line.strip()
            if "=" not in line:
                continue
            parts = line.split("=", 1)
            filepath = parts[0].strip()
            caps = parts[1].strip().lower() if len(parts) > 1 else ""

            if filepath in KNOWN_SAFE:
                continue

            has_dangerous = any(cap in caps for cap in DANGEROUS_CAPS)
            if has_dangerous:
                suspicious.append(f"{filepath} = {caps}")

        if suspicious:
            details = "\n".join(suspicious[:DETAIL_LIMIT])
            if truncated:
                note = f"(showing first {RESULT_LIMIT} results, may be incomplete)"
                details = f"{details}\n{note}" if details else note
            findings.append(
                self.warning(
                    f"{len(suspicious)} files with dangerous capabilities",
                    details=details,
                )
            )
        elif truncated:
            findings.append(
                Finding(
                    check=self._check_meta.name,
                    severity=Severity.OK,
                    title="No suspicious file capabilities",
                    details=f"(showing first {RESULT_LIMIT} results, may be incomplete)",
                )
            )
        else:
            findings.append(self.ok("No suspicious file capabilities"))

        return findings
