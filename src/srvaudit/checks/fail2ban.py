from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="fail2ban", category="network", quick=True)
class Fail2banCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []

        result = self.execute("fail2ban-client status 2>/dev/null")
        if not result.success:
            result = self.execute("which fail2ban-server 2>/dev/null")
            if result.success:
                findings.append(self.ok("fail2ban is installed (run with --sudo for details)"))
                return findings

        if result.not_found or not result.success:
            # Check if SSH is exposed at all
            ssh_exposed = self._is_ssh_exposed()
            if not ssh_exposed:
                findings.append(self.info(
                    "fail2ban not installed (SSH may not be exposed)",
                ))
            else:
                findings.append(self.warning(
                    "fail2ban is not installed",
                    details="Protects against SSH brute-force attacks",
                    fix_command="apt install fail2ban && systemctl enable fail2ban && systemctl start fail2ban",
                ))
            return findings

        findings.append(self.ok("fail2ban is running"))

        # Check sshd jail
        sshd = self.execute("fail2ban-client status sshd 2>/dev/null")
        if sshd.success:
            for line in sshd.stdout.splitlines():
                if "Currently banned" in line:
                    count = line.split(":")[-1].strip()
                    if count and count != "0":
                        findings.append(self.info(f"fail2ban: {count} IPs currently banned (sshd)"))
                if "Total banned" in line:
                    total = line.split(":")[-1].strip()
                    if total:
                        findings.append(self.info(f"fail2ban: {total} total bans (sshd)"))
        else:
            findings.append(self.warning(
                "fail2ban sshd jail is not active",
                fix_command="fail2ban-client start sshd",
            ))

        return findings

    def _is_ssh_exposed(self) -> bool:
        result = self.execute("ss -tlnp 2>/dev/null | grep ':22 '")
        if result.success and result.stdout.strip():
            return "0.0.0.0" in result.stdout or "*:" in result.stdout or ":::" in result.stdout
        return False
