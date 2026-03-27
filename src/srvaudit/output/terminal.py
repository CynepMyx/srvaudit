from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from srvaudit.models import AuditReport, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.WARNING: "yellow",
    Severity.INFO: "cyan",
    Severity.OK: "green",
    Severity.SKIP: "dim",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
    Severity.OK: "OK",
    Severity.SKIP: "SKIP",
}

GRADE_COLORS = {
    "A": "green bold",
    "B": "green",
    "C": "yellow",
    "D": "red bold",
}


def render_terminal(report: AuditReport, verbose: bool = False):
    console = Console()

    grade_color = GRADE_COLORS.get(report.grade, "white")
    console.print()
    console.print(
        Panel(
            f"[bold]srvaudit[/bold] report for [cyan]{report.target}[/cyan]\n"
            f"Score: [{grade_color}]{report.score}/100 ({report.grade})[/{grade_color}]  |  "
            f"Duration: {report.duration_sec:.1f}s  |  "
            f"Distro: {report.distro.id} {report.distro.version}"
            if report.distro
            else "",
            title="srvaudit",
            border_style="blue",
        )
    )

    actionable = [f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.WARNING)]
    ok_count = sum(1 for f in report.findings if f.severity == Severity.OK)
    skip_count = sum(1 for f in report.findings if f.severity == Severity.SKIP)
    info_count = sum(1 for f in report.findings if f.severity == Severity.INFO)

    if actionable:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Check", width=16)
        table.add_column("Issue", min_width=30)
        table.add_column("Fix", min_width=20)

        for f in sorted(actionable, key=lambda x: list(Severity).index(x.severity)):
            color = SEVERITY_COLORS[f.severity]
            label = SEVERITY_LABELS[f.severity]
            table.add_row(
                f"[{color}]{label}[/{color}]",
                f.check,
                f"{f.title}\n{f.details}" if f.details else f.title,
                f.fix_command or "-",
            )
        console.print(table)
    else:
        console.print("[green]No critical or warning findings.[/green]")

    console.print(
        f"\n[green]{ok_count} passed[/green]  "
        f"[cyan]{info_count} info[/cyan]  "
        f"[dim]{skip_count} skipped[/dim]"
    )
    console.print(f"\n[dim]{report.disclaimer}[/dim]\n")
