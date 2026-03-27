from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import pytest

from srvaudit.models import CommandResult, DistroInfo


class MockTransport:
    def __init__(self, responses: Dict[str, str] = None, return_codes: Dict[str, int] = None):
        self.responses = responses or {}
        self.return_codes = return_codes or {}
        self.executed = []

    def execute(self, cmd: str, timeout: int = None) -> CommandResult:
        self.executed.append(cmd)
        stdout = self.responses.get(cmd, "")
        rc = self.return_codes.get(cmd, 0)
        return CommandResult(command=cmd, stdout=stdout, return_code=rc)


@pytest.fixture
def ubuntu_distro():
    return DistroInfo(id="ubuntu", version="22.04", family="debian", has_bash=True, has_systemd=True)


@pytest.fixture
def centos_distro():
    return DistroInfo(id="centos", version="9", family="rhel", has_bash=True, has_systemd=True)


@pytest.fixture
def alpine_distro():
    return DistroInfo(id="alpine", version="3.19", family="alpine", has_bash=False, has_systemd=False)
