from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from srvaudit.models import CheckMeta, CommandResult, DistroInfo, Finding, Severity
from srvaudit.transport import ShellTransport

_REGISTRY: dict[str, type[BaseCheck]] = {}


def check(
    name: str,
    category: str,
    quick: bool = False,
    requires_sudo: bool = False,
):
    def decorator(cls):
        cls._check_meta = CheckMeta(name, category, quick, requires_sudo)
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_all_checks() -> List[type[BaseCheck]]:
    return list(_REGISTRY.values())


def get_quick_checks() -> List[type[BaseCheck]]:
    return [c for c in _REGISTRY.values() if c._check_meta.quick]


class BaseCheck(ABC):
    _check_meta: CheckMeta

    def __init__(self, transport: ShellTransport, distro: DistroInfo):
        self.transport = transport
        self.distro = distro

    @abstractmethod
    def run(self) -> List[Finding]: ...

    def execute(self, cmd: str, timeout: Optional[int] = None) -> CommandResult:
        return self.transport.execute(cmd, timeout=timeout)

    def skip(self, reason: str) -> Finding:
        return Finding(
            check=self._check_meta.name,
            severity=Severity.SKIP,
            title=f"Skipped: {reason}",
        )

    def ok(self, title: str) -> Finding:
        return Finding(
            check=self._check_meta.name,
            severity=Severity.OK,
            title=title,
        )

    def critical(self, title: str, details: str = "", fix_command: str = "") -> Finding:
        return Finding(
            check=self._check_meta.name,
            severity=Severity.CRITICAL,
            title=title,
            details=details,
            fix_command=fix_command,
        )

    def warning(self, title: str, details: str = "", fix_command: str = "") -> Finding:
        return Finding(
            check=self._check_meta.name,
            severity=Severity.WARNING,
            title=title,
            details=details,
            fix_command=fix_command,
        )

    def info(self, title: str, details: str = "") -> Finding:
        return Finding(
            check=self._check_meta.name,
            severity=Severity.INFO,
            title=title,
            details=details,
        )
