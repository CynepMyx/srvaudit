import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

import srvaudit.checks.registry as registry
import srvaudit.cli as cli
import srvaudit.output.terminal as terminal_output
from srvaudit.cli import _parse_target, app
from srvaudit.models import CheckMeta, DistroInfo, Environment, Finding, Severity

runner = CliRunner()


class _RegularCheck:
    _check_meta = CheckMeta("regular", "test")

    def __init__(self, transport, distro):
        self.transport = transport

    def run(self):
        return [Finding(check="regular", severity=Severity.OK, title="regular ok")]


class _SudoCheck:
    _check_meta = CheckMeta("sudo_check", "test", requires_sudo=True)

    def __init__(self, transport, distro):
        self.transport = transport

    def run(self):
        return [Finding(check="sudo_check", severity=Severity.OK, title="sudo ok")]


class _SecondSudoCheck:
    _check_meta = CheckMeta("second_sudo", "test", requires_sudo=True)

    def __init__(self, transport, distro):
        self.transport = transport

    def run(self):
        return [Finding(check="second_sudo", severity=Severity.OK, title="sudo ok")]


def _fake_distro(_transport):
    return DistroInfo(id="ubuntu", family="debian")


def _fake_environment(_transport):
    return Environment()


def test_parse_target_ipv6_brackets():
    assert _parse_target("root@[2001:db8::1]") == ("root", "2001:db8::1", 22)
    assert _parse_target("root@[2001:db8::1]:2222") == ("root", "2001:db8::1", 2222)


def test_scan_reports_checks_skipped_without_sudo(monkeypatch):
    class DummyTransport:
        def __init__(self, *args, sudo=False, **kwargs):
            self.sudo = sudo

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def check_passwordless_sudo(self):
            return True

    monkeypatch.setattr(cli, "ShellTransport", DummyTransport)
    monkeypatch.setattr(cli, "detect_distro", _fake_distro)
    monkeypatch.setattr(cli, "detect_environment", _fake_environment)
    monkeypatch.setattr(
        registry,
        "get_all_checks",
        lambda: [_RegularCheck, _SudoCheck, _SecondSudoCheck],
    )
    monkeypatch.setattr(registry, "get_quick_checks", lambda: [_RegularCheck, _SudoCheck])
    monkeypatch.setattr(terminal_output, "render_terminal", lambda report, verbose=False: None)

    result = runner.invoke(app, ["scan", "root@example.com"])

    assert result.exit_code == 0
    assert "2 checks skipped (need --sudo): sudo_check, second_sudo" in result.output


def test_scan_skips_sudo_checks_when_passwordless_sudo_missing(monkeypatch):
    seen_sudo = []

    class DummyTransport:
        def __init__(self, *args, sudo=False, **kwargs):
            self.sudo = sudo

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def check_passwordless_sudo(self):
            return False

    class RegularCheck:
        _check_meta = CheckMeta("regular", "test")

        def __init__(self, transport, distro):
            self.transport = transport

        def run(self):
            seen_sudo.append(self.transport.sudo)
            return [Finding(check="regular", severity=Severity.OK, title="regular ok")]

    monkeypatch.setattr(cli, "ShellTransport", DummyTransport)
    monkeypatch.setattr(cli, "detect_distro", _fake_distro)
    monkeypatch.setattr(cli, "detect_environment", _fake_environment)
    monkeypatch.setattr(registry, "get_all_checks", lambda: [RegularCheck, _SudoCheck])
    monkeypatch.setattr(registry, "get_quick_checks", lambda: [RegularCheck, _SudoCheck])

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as handle:
        output_path = Path(handle.name)

    result = runner.invoke(
        app,
        ["scan", "root@example.com", "--sudo", "--json", "-o", str(output_path)],
    )

    assert result.exit_code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    skipped = [finding for finding in data["findings"] if finding["severity"] == "skip"]
    assert skipped == [
        {
            "check": "sudo_check",
            "severity": "skip",
            "title": "Skipped: passwordless sudo not available",
            "details": "",
            "fix_command": "",
            "references": [],
        }
    ]
    assert seen_sudo == [False]
    output_path.unlink()
