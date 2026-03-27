from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="filesystem", category="system")
class FilesystemCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        self._check_disk_usage(findings)
        self._check_tmp_noexec(findings)
        return findings

    def _check_disk_usage(self, findings: list):
        result = self.execute("df -h --output=pcent,target 2>/dev/null | tail -n +2")
        if not result.success:
            result = self.execute("df -h 2>/dev/null")
            if not result.success:
                findings.append(self.skip("Cannot check disk usage"))
                return

        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            pct_str = parts[0].replace("%", "")
            try:
                pct = int(pct_str)
            except ValueError:
                continue

            mount = parts[-1] if len(parts) > 1 else "unknown"

            if mount in ("/dev", "/dev/shm", "/run", "/tmp"):
                continue

            if pct >= 95:
                findings.append(
                    self.critical(
                        f"Disk {mount} is {pct}% full",
                        fix_command=f"du -sh {mount}/* 2>/dev/null | sort -hr | head -10",
                    )
                )
            elif pct >= 85:
                findings.append(
                    self.warning(
                        f"Disk {mount} is {pct}% full",
                    )
                )

    def _check_tmp_noexec(self, findings: list):
        result = self.execute("mount | grep ' /tmp '")
        if not result.success:
            return

        if "noexec" not in result.stdout:
            findings.append(
                self.info(
                    "/tmp is mounted without noexec",
                    details="Executables can be run from /tmp",
                )
            )
