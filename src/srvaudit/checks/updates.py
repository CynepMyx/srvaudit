from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="updates", category="system", quick=True)
class UpdatesCheck(BaseCheck):
    def run(self) -> List[Finding]:
        if self.distro.is_debian_family:
            return self._check_apt()
        if self.distro.is_rhel_family:
            return self._check_yum()
        if self.distro.is_alpine:
            return self._check_apk()
        return [self.skip(f"Updates check not supported for {self.distro.id}")]

    def _count_update_lines(self, output: str) -> int:
        return len([line for line in output.splitlines() if line.strip()])

    def _findings_from_count(self, count: int, fix_command: str) -> List[Finding]:
        if count > 10:
            return [
                self.warning(
                    f"{count} packages can be upgraded",
                    fix_command=fix_command,
                )
            ]
        if count > 0:
            return [self.info(f"{count} packages can be upgraded")]
        return [self.ok("System is up to date")]

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
                    findings.append(
                        self.warning(
                            f"{security} security updates pending",
                            details=f"{total} total updates available",
                            fix_command="apt update && apt upgrade -y",
                        )
                    )
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
            findings.append(
                self.warning(
                    f"{count} packages can be upgraded",
                    fix_command="apt update && apt upgrade -y",
                )
            )
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
                    findings.append(
                        self.warning(
                            f"{sec_count} security updates pending",
                            fix_command="apt update && apt upgrade -y",
                        )
                    )
            except ValueError:
                pass

        return findings

    def _check_yum(self) -> List[Finding]:
        commands = (
            "yum check-update --quiet 2>/dev/null",
            "dnf check-update --quiet 2>/dev/null",
        )
        for command in commands:
            result = self.execute(command, timeout=30)
            if result.not_found:
                continue
            if result.return_code in (0, 100):
                count = self._count_update_lines(result.stdout)
                return self._findings_from_count(count, "yum update -y || dnf update -y")

        return [self.skip("Cannot check for updates (yum/dnf)")]

    def _check_apk(self) -> List[Finding]:
        result = self.execute("apk version -l '<' 2>/dev/null", timeout=30)
        if not result.success:
            return [self.skip("Cannot check for updates (apk)")]

        count = self._count_update_lines(result.stdout)
        return self._findings_from_count(count, "apk upgrade")
