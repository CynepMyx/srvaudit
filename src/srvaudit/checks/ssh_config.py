from __future__ import annotations

import shlex
from typing import List

from srvaudit.checks.registry import BaseCheck, check
from srvaudit.models import Finding


def _parse_sshd_config(text: str) -> dict:
    config = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            config.setdefault(key, value)
    return config


@check(name="ssh_config", category="access", quick=True)
class SSHConfigCheck(BaseCheck):
    def run(self) -> List[Finding]:
        findings = []
        config = self._load_full_config()
        if not config:
            findings.append(self.skip("Cannot read sshd_config"))
            return findings

        self._check_root_login(config, findings)
        self._check_password_auth(config, findings)
        self._check_empty_passwords(config, findings)
        self._check_max_auth_tries(config, findings)
        self._check_x11_forwarding(config, findings)

        return findings

    def _load_full_config(self) -> dict:
        result = self.execute("cat /etc/ssh/sshd_config 2>/dev/null")
        if not result.success:
            return {}
        config = _parse_sshd_config(result.stdout)

        include = config.pop("Include", None)
        if include:
            for pattern in include.split():
                safe = shlex.quote(pattern)
                inc = self.execute(f"cat {safe} 2>/dev/null")
                if inc.success:
                    included = _parse_sshd_config(inc.stdout)
                    for k, v in included.items():
                        config.setdefault(k, v)
        return config

    def _check_root_login(self, config: dict, findings: list):
        value = config.get("PermitRootLogin", "prohibit-password")
        if value == "yes":
            findings.append(self.critical(
                "Root login with password is enabled",
                details=f"PermitRootLogin = {value}",
                fix_command=(
                    "sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' "
                    "/etc/ssh/sshd_config && systemctl reload sshd"
                ),
            ))
        elif value in ("prohibit-password", "forced-commands-only", "without-password"):
            findings.append(self.ok("Root login restricted to key-based only"))
        elif value == "no":
            findings.append(self.ok("Root login disabled"))

    def _check_password_auth(self, config: dict, findings: list):
        value = config.get("PasswordAuthentication", "yes")
        if value == "yes":
            findings.append(self.warning(
                "Password authentication is enabled",
                details="Key-based auth is more secure",
                fix_command=(
                    "sed -i 's/^#\\?PasswordAuthentication yes/PasswordAuthentication no/' "
                    "/etc/ssh/sshd_config && systemctl reload sshd"
                ),
            ))
        else:
            findings.append(self.ok("Password authentication disabled"))

    def _check_empty_passwords(self, config: dict, findings: list):
        value = config.get("PermitEmptyPasswords", "no")
        if value == "yes":
            findings.append(self.critical(
                "Empty passwords are permitted",
                fix_command=(
                    "sed -i 's/^PermitEmptyPasswords yes/PermitEmptyPasswords no/' "
                    "/etc/ssh/sshd_config && systemctl reload sshd"
                ),
            ))

    def _check_max_auth_tries(self, config: dict, findings: list):
        value = config.get("MaxAuthTries", "6")
        try:
            tries = int(value)
            if tries > 6:
                findings.append(self.warning(
                    f"MaxAuthTries is high ({tries})",
                    fix_command=f"echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config && systemctl reload sshd",
                ))
        except ValueError:
            pass

    def _check_x11_forwarding(self, config: dict, findings: list):
        value = config.get("X11Forwarding", "no")
        if value == "yes":
            findings.append(self.warning(
                "X11 forwarding is enabled",
                details="Not needed on servers",
                fix_command=(
                    "sed -i 's/^X11Forwarding yes/X11Forwarding no/' "
                    "/etc/ssh/sshd_config && systemctl reload sshd"
                ),
            ))
