from __future__ import annotations

import re
from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding

KNOWN_DANGEROUS_PORTS = {
    2375: "Docker API (unencrypted)",
    2376: "Docker API (TLS)",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    5984: "CouchDB",
}

ADDR_PORT_RE = re.compile(r"\[?([^\]]*)\]?:(\d+)$")


def parse_listen_addr(addr: str) -> tuple:
    m = ADDR_PORT_RE.search(addr)
    if m:
        host = m.group(1)
        port = int(m.group(2))
        return host, port

    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return addr, 0


def is_public(host: str) -> bool:
    local = {"127.0.0.1", "::1", "localhost", ""}
    if host in local:
        return False
    if host.startswith("127."):
        return False
    return True


@check(name="open_ports", category="network", quick=True)
class OpenPortsCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        result = self.execute("ss -tlnp 2>/dev/null")
        if not result.success:
            result = self.execute("netstat -tlnp 2>/dev/null")
        if not result.success:
            findings.append(self.skip("Cannot list listening ports (ss/netstat not available)"))
            return findings

        public_ports = []
        all_ports = []

        for line in result.stdout.splitlines():
            if "LISTEN" not in line:
                continue
            fields = line.split()
            if len(fields) < 4:
                continue

            local_addr = fields[3]
            host, port = parse_listen_addr(local_addr)
            if port == 0:
                continue

            all_ports.append((host, port))
            if is_public(host):
                public_ports.append((host, port))

        for host, port in public_ports:
            if port in KNOWN_DANGEROUS_PORTS:
                svc = KNOWN_DANGEROUS_PORTS[port]
                findings.append(self.critical(
                    f"{svc} (port {port}) exposed on {host}",
                    details=f"Database/service port {port} is accessible from any IP",
                    fix_command=f"ufw deny {port} || iptables -A INPUT -p tcp --dport {port} -j DROP",
                ))
            elif port == 22:
                findings.append(self.ok(f"SSH (port {port}) open — expected"))
            elif port in (80, 443):
                findings.append(self.ok(f"HTTP/HTTPS (port {port}) open — expected"))
            else:
                findings.append(self.info(
                    f"Port {port} open on {host}",
                ))

        if not public_ports:
            findings.append(self.ok("No unexpected public ports"))

        return findings
