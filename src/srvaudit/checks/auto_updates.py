from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="auto_updates", category="system")
class AutoUpdatesCheck(BaseCheck):
    def run(self) -> List[Finding]:
        if self.distro.is_debian_family:
            return self._check_unattended_upgrades()
        elif self.distro.is_rhel_family:
            return self._check_dnf_automatic()
        elif self.distro.is_alpine:
            return [self.info("Alpine: no standard auto-update mechanism")]
        return [self.skip(f"Auto-updates check not supported for {self.distro.id}")]

    def _check_unattended_upgrades(self) -> List[Finding]:
        findings = []
        result = self.execute("cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
        if not result.success:
            findings.append(
                self.warning(
                    "Automatic security updates not configured",
                    fix_command=(
                        "apt install unattended-upgrades"
                        " && dpkg-reconfigure -plow unattended-upgrades"
                    ),
                )
            )
            return findings

        has_update = 'Update-Package-Lists "1"' in result.stdout
        has_upgrade = 'Unattended-Upgrade "1"' in result.stdout

        if has_update and has_upgrade:
            findings.append(self.ok("Automatic security updates enabled"))
        elif has_update:
            findings.append(
                self.warning(
                    "Package lists update automatically but upgrades are disabled",
                    fix_command=("dpkg-reconfigure -plow unattended-upgrades"),
                )
            )
        else:
            findings.append(
                self.warning(
                    "Automatic updates not fully configured",
                    fix_command=(
                        "apt install unattended-upgrades"
                        " && dpkg-reconfigure -plow unattended-upgrades"
                    ),
                )
            )
        return findings

    def _check_dnf_automatic(self) -> List[Finding]:
        findings = []
        result = self.execute("systemctl is-enabled dnf-automatic.timer 2>/dev/null")
        if result.success and "enabled" in result.stdout:
            findings.append(self.ok("dnf-automatic timer is enabled"))
        else:
            result2 = self.execute("which dnf-automatic 2>/dev/null")
            if result2.success:
                findings.append(
                    self.warning(
                        "dnf-automatic is installed but timer not enabled",
                        fix_command="systemctl enable --now dnf-automatic.timer",
                    )
                )
            else:
                findings.append(
                    self.warning(
                        "No automatic update mechanism found",
                        fix_command=(
                            "dnf install dnf-automatic"
                            " && systemctl enable --now dnf-automatic.timer"
                        ),
                    )
                )
        return findings
