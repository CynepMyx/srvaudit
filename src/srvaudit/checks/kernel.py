from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="kernel", category="system")
class KernelCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        self._check_reboot_required(findings)
        self._check_kernel_hardening(findings)
        return findings

    def _check_reboot_required(self, findings: list):
        # Debian/Ubuntu
        result = self.execute("test -f /var/run/reboot-required")
        if result.success:
            findings.append(
                self.warning(
                    "System reboot required",
                    details="Kernel or critical package was updated",
                    fix_command="reboot",
                )
            )
            return

        # RHEL: compare running vs installed kernel
        running = self.execute("uname -r")
        if not running.success:
            return

        if self.distro.is_rhel_family:
            installed = self.execute(
                "rpm -q kernel --last 2>/dev/null | head -1 | awk '{print $1}'"
            )
            if installed.success and installed.stdout.strip():
                installed_ver = installed.stdout.strip().replace("kernel-", "")
                if installed_ver != running.stdout.strip():
                    findings.append(
                        self.info(
                            f"Running kernel {running.stdout.strip()}, installed {installed_ver}",
                            details="Reboot may be needed",
                        )
                    )
                    return

        findings.append(self.ok(f"Kernel {running.stdout.strip()} (no reboot needed)"))

    def _check_kernel_hardening(self, findings: list):
        checks = {
            "net.ipv4.conf.all.send_redirects": ("0", "ICMP redirect sending"),
            "net.ipv4.conf.all.accept_redirects": ("0", "ICMP redirect acceptance"),
            "net.ipv4.conf.all.accept_source_route": ("0", "source routing"),
        }

        for param, (expected, desc) in checks.items():
            path = f"/proc/sys/{param.replace('.', '/')}"
            result = self.execute(f"cat {path} 2>/dev/null")
            if result.success:
                value = result.stdout.strip()
                if value != expected:
                    findings.append(
                        self.warning(
                            f"{desc} is enabled ({param}={value})",
                            fix_command=(
                                f"sysctl -w {param}={expected}"
                                f" && echo '{param}={expected}'"
                                f" >> /etc/sysctl.d/99-security.conf"
                            ),
                        )
                    )
