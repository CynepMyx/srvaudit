from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="firewall", category="network", quick=True, requires_sudo=True)
class FirewallCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []

        # Try ufw first (Debian/Ubuntu)
        ufw = self.execute("ufw status 2>/dev/null")
        if ufw.success and "status: active" in ufw.stdout.lower():
            findings.append(self.ok("UFW firewall is active"))
            self._check_ufw_rules(ufw.stdout, findings)
            return findings

        # Try firewalld (RHEL/CentOS)
        firewalld = self.execute("firewall-cmd --state 2>/dev/null")
        if firewalld.success and "running" in firewalld.stdout.lower():
            findings.append(self.ok("firewalld is active"))
            return findings

        # Try nftables
        nft = self.execute("nft list ruleset 2>/dev/null")
        if nft.success and nft.stdout.strip():
            rule_count = nft.stdout.count("\n")
            if rule_count > 5:
                findings.append(self.ok(f"nftables active ({rule_count} rules)"))
                return findings

        # Try raw iptables
        ipt = self.execute("iptables -L -n 2>/dev/null")
        if ipt.success:
            rule_count = len(
                [
                    line
                    for line in ipt.stdout.splitlines()
                    if line.strip()
                    and not line.startswith("Chain")
                    and not line.startswith("target")
                ]
            )
            # Docker adds its own iptables rules
            has_docker = "DOCKER" in ipt.stdout
            if rule_count > 3 and has_docker:
                findings.append(
                    self.info(
                        "No host firewall detected, Docker manages iptables directly",
                        details=f"{rule_count} iptables rules found (Docker-managed)",
                    )
                )
                return findings
            elif rule_count > 3:
                findings.append(self.ok(f"iptables active ({rule_count} rules)"))
                return findings

        # No firewall found
        docker_check = self.execute("which docker 2>/dev/null")
        if docker_check.success:
            findings.append(
                self.info(
                    "No host firewall detected (Docker manages network rules)",
                    details="Consider adding UFW or firewalld for non-Docker traffic",
                )
            )
        else:
            findings.append(
                self.warning(
                    "No firewall detected",
                    details="No active ufw, firewalld, nftables, or iptables rules found",
                    fix_command=(
                        "apt install ufw && ufw default deny incoming"
                        " && ufw allow ssh && ufw enable"
                    ),
                )
            )

        return findings

    def _check_ufw_rules(self, output: str, findings: list):
        lines = output.splitlines()
        allow_any = []
        for line in lines:
            if "ALLOW" in line and "Anywhere" in line:
                port = line.split()[0]
                if port not in ("OpenSSH", "22/tcp", "80/tcp", "443/tcp", "22", "80", "443"):
                    allow_any.append(port)
        if allow_any:
            findings.append(
                self.info(
                    f"UFW allows traffic on non-standard ports: {', '.join(allow_any[:5])}",
                )
            )
