from __future__ import annotations

import logging
import re

from srvaudit.models import DistroInfo, Environment
from srvaudit.transport import ShellTransport

logger = logging.getLogger("srvaudit")

FAMILY_MAP = {
    "ubuntu": "debian",
    "debian": "debian",
    "linuxmint": "debian",
    "pop": "debian",
    "centos": "rhel",
    "rhel": "rhel",
    "rocky": "rhel",
    "almalinux": "rhel",
    "fedora": "rhel",
    "alpine": "alpine",
    "opensuse": "suse",
    "sles": "suse",
    "arch": "arch",
}


def detect_distro(transport: ShellTransport) -> DistroInfo:
    result = transport.execute("cat /etc/os-release 2>/dev/null")
    if not result.success:
        result = transport.execute("uname -s")
        return DistroInfo(id="unknown", family="unknown")

    info = _parse_os_release(result.stdout)

    bash_result = transport.execute("which bash 2>/dev/null")
    info.has_bash = bash_result.success

    systemd_result = transport.execute("test -d /run/systemd/system")
    info.has_systemd = systemd_result.success

    return info


def _parse_os_release(text: str) -> DistroInfo:
    data = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key] = value.strip('"').strip("'")

    distro_id = data.get("ID", "unknown").lower()
    version = data.get("VERSION_ID", "")
    family = FAMILY_MAP.get(distro_id, "unknown")

    return DistroInfo(
        id=distro_id,
        version=version,
        family=family,
    )


def detect_environment(transport: ShellTransport) -> Environment:
    env = Environment()

    wsl_result = transport.execute("cat /proc/version 2>/dev/null")
    if wsl_result.success:
        lower = wsl_result.stdout.lower()
        env.is_wsl = "microsoft" in lower or "wsl" in lower

    container_result = transport.execute("test -f /.dockerenv")
    if not container_result.success:
        cgroup_result = transport.execute("grep -q 'docker\\|lxc\\|kubepods' /proc/1/cgroup 2>/dev/null")
        env.is_container = cgroup_result.success
    else:
        env.is_container = True

    bash_result = transport.execute("which bash 2>/dev/null")
    env.has_bash = bash_result.success

    return env
