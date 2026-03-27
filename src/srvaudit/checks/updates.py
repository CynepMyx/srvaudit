from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="updates", category="system", quick=True)
class UpdatesCheck(BaseCheck):
    def run(self) -> List[Finding]:
        if self.distro.is_debian_family:
            return self._check_apt()
        elif self.distro.is_rhel_family:
            return self._check_yum()
        elif self.distro.is_alpine:
            return self._check_apk()
        return [self.skip(f"Updates check not supported for {self.distro.id}")]

    def _check_apt(self) -> List[Finding]:
        findings = []
        result = self.execute("apt list --upgradable 2>/dev/null | grep -c upgradable", timeout=30)
        if not result.success:
            # Try alternative
            result = self.execute("/usr/lib/update-notifier/apt-check 2>&1")
            if result.success and ";" in result.stdout:
                parts = result.stdout.strip().split(";")
                total = int(parts[0]) if parts[0].isdigit() else 0
                security = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                if security > 0:
                    findings.append(self.warning(
                        f"{security} security updates pending",
                        details=f"{total} total updates available",
                        fix_command="apt update && apt upgrade -y",
                    ))
                elif total > 0:
                    findings.append(self.info(f"{total} updates available (no security updates)"))
                else:
                    findings.append(self.ok("System is up to date"))
                return findings
            findings.append(self.skip("Cannot check for updates"))
            return findings

        count = 0
        try:
            count = int(result.stdout.strip())
        except ValueError:
            pass

        if count > 10:
            findings.append(self.warning(
                f"{count} packages can be upgraded",
                fix_command="apt update && apt upgrade -y",
            ))
        elif count > 0:
            findings.append(self.info(f"{count} packages can be upgraded"))
        else:
            findings.append(self.ok("System is up to date"))

        # Check security updates specifically
        sec = self.execute("apt list --upgradable 2>/dev/null | grep -ci security")
        if sec.success:
            try:
                sec_count = int(sec.stdout.strip())
                if sec_count > 0:
                    findings.append(self.warning(
                        f"{sec_count} security updates pending",
                        fix_command="apt update && apt upgrade -y",
                    ))
            except ValueError:
                pass

        return findings

    def _check_yum(self) -> List[Finding]:
        findings = []
        result = self.execute("yum check-update --quiet 2>/dev/null | wc -l", timeout=30)
        if not result.success:
            result = self.execute("dnf check-update --quiet 2>/dev/null | wc -l", timeout=30)
        if not result.success:
            findings.append(self.skip("Cannot check for updates (yum/dnf)"))
            return findings

        try:
            count = int(result.stdout.strip())
            if count > 10:
                findings.append(self.warning(
                    f"{count} packages can be upgraded",
                    fix_command="yum update -y || dnf update -y",
                ))
            elif count > 0:
                findings.append(self.info(f"{count} packages can be upgraded"))
            else:
                findings.append(self.ok("System is up to date"))
        except ValueError:
            findings.append(self.skip("Cannot parse update count"))

        return findings

    def _check_apk(self) -> List[Finding]:
        findings = []
        result = self.execute("apk version -l '<' 2>/dev/null | wc -l", timeout=30)
        if not result.success:
            findings.append(self.skip("Cannot check for updates (apk)"))
            return findings

        try:
            count = int(result.stdout.strip())
            if count > 0:
                findings.append(self.info(f"{count} packages can be upgraded"))
            else:
                findings.append(self.ok("System is up to date"))
        except ValueError:
            pass

        return findings
