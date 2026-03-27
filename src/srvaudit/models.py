from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"
    SKIP = "skip"


@dataclass
class CheckMeta:
    name: str
    category: str
    quick: bool = False
    requires_sudo: bool = False


@dataclass
class Finding:
    check: str
    severity: Severity
    title: str
    details: str = ""
    fix_command: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class CommandResult:
    command: str
    stdout: str
    return_code: int
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.return_code == 0

    @property
    def not_found(self) -> bool:
        return self.return_code == 127


@dataclass
class DistroInfo:
    id: str = "unknown"
    version: str = ""
    family: str = "unknown"
    has_bash: bool = True
    has_systemd: bool = True

    @property
    def is_debian_family(self) -> bool:
        return self.family == "debian"

    @property
    def is_rhel_family(self) -> bool:
        return self.family == "rhel"

    @property
    def is_alpine(self) -> bool:
        return self.id == "alpine"


@dataclass
class Environment:
    is_wsl: bool = False
    is_container: bool = False
    readonly_rootfs: bool = False
    has_bash: bool = True


@dataclass
class AuditReport:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    distro: Optional[DistroInfo] = None
    environment: Optional[Environment] = None
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    duration_sec: float = 0.0
    version: str = "0.1.0"
    disclaimer: str = (
        "This audit relies on system utilities on the target host. "
        "If the system is compromised, results may be unreliable. "
        "For rootkit detection, use offline analysis."
    )

    def to_dict(self) -> dict:
        d = {
            "target": self.target,
            "timestamp": self.timestamp,
            "version": self.version,
            "score": self.score,
            "grade": self.grade,
            "duration_sec": self.duration_sec,
            "disclaimer": self.disclaimer,
            "distro": asdict(self.distro) if self.distro else None,
            "environment": asdict(self.environment) if self.environment else None,
            "findings": [f.to_dict() for f in self.findings],
        }
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
