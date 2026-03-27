import json
import tempfile
from pathlib import Path

from srvaudit.models import AuditReport, Finding, Severity


def _make_report(score, grade, findings):
    report = AuditReport(
        target="test@host:22",
        score=score,
        grade=grade,
        findings=findings,
    )
    return report.to_dict()


def _write_json(data):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, f)
    f.close()
    return f.name


def test_diff_no_changes(capsys):
    from typer.testing import CliRunner

    from srvaudit.cli import app

    runner = CliRunner()

    report = _make_report(
        80,
        "B",
        [
            Finding(
                check="ssh_config",
                severity=Severity.WARNING,
                title="Password auth enabled",
            ),
        ],
    )
    f1 = _write_json(report)
    result = runner.invoke(app, ["diff", f1, f1])
    assert result.exit_code == 0
    assert "UNCHANGED" in result.output
    assert "[0]" in result.output
    Path(f1).unlink()


def test_diff_improvement(capsys):
    from typer.testing import CliRunner

    from srvaudit.cli import app

    runner = CliRunner()

    before = _make_report(
        50,
        "C",
        [
            Finding(
                check="ssh_config",
                severity=Severity.CRITICAL,
                title="Root login enabled",
            ),
            Finding(
                check="firewall",
                severity=Severity.WARNING,
                title="No firewall",
            ),
        ],
    )
    after = _make_report(
        90,
        "A",
        [
            Finding(
                check="updates",
                severity=Severity.WARNING,
                title="5 updates pending",
            ),
        ],
    )
    f1 = _write_json(before)
    f2 = _write_json(after)
    result = runner.invoke(app, ["diff", f1, f2])
    assert result.exit_code == 0
    assert "FIXED" in result.output
    assert "Root login" in result.output
    assert "NEW" in result.output
    assert "+40" in result.output
    Path(f1).unlink()
    Path(f2).unlink()
