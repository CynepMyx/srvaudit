from __future__ import annotations

from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


@check(name="docker", category="services")
class DockerCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []

        result = self.execute("which docker 2>/dev/null")
        if not result.success:
            return findings

        self._check_socket_permissions(findings)
        self._check_privileged_containers(findings)
        self._check_exposed_ports(findings)
        return findings

    def _check_socket_permissions(self, findings: list):
        result = self.execute("ls -la /var/run/docker.sock 2>/dev/null")
        if not result.success:
            return

        if "srw-rw----" in result.stdout:
            findings.append(self.ok("Docker socket has restricted permissions"))
        elif "srw-rw-rw-" in result.stdout:
            findings.append(
                self.critical(
                    "Docker socket is world-writable",
                    details="Any user can control Docker = root equivalent",
                    fix_command="chmod 660 /var/run/docker.sock",
                )
            )

        # Check docker group members
        result = self.execute("getent group docker 2>/dev/null")
        if result.success and ":" in result.stdout:
            parts = result.stdout.strip().split(":")
            if len(parts) >= 4 and parts[3]:
                members = parts[3]
                findings.append(
                    self.info(
                        f"Docker group members: {members}",
                        details="Docker group = root-equivalent access",
                    )
                )

    def _check_privileged_containers(self, findings: list):
        result = self.execute(
            "docker ps -q 2>/dev/null"
            " | xargs -r docker inspect"
            " --format '{{.Name}} privileged={{.HostConfig.Privileged}}'"
            " 2>/dev/null"
        )
        if not result.success:
            return

        for line in result.stdout.splitlines():
            line = line.strip()
            if "privileged=true" in line:
                name = line.split()[0].lstrip("/") if line.split() else "unknown"
                findings.append(
                    self.warning(
                        f"Container '{name}' runs in privileged mode",
                        details="Privileged = full host access from container",
                    )
                )

    def _check_exposed_ports(self, findings: list):
        result = self.execute("docker ps --format '{{.Names}}\\t{{.Ports}}' 2>/dev/null")
        if not result.success:
            return

        for line in result.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 2:
                continue
            name = parts[0]
            ports = parts[1]
            if "0.0.0.0:" in ports and "->443" not in ports and "->80" not in ports:
                findings.append(
                    self.info(
                        f"Container '{name}' exposes ports on 0.0.0.0",
                        details=f"Ports: {ports}",
                    )
                )
