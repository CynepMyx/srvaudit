from __future__ import annotations

import logging
import re
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from srvaudit import __version__
from srvaudit.distro import detect_distro, detect_environment
from srvaudit.models import AuditReport
from srvaudit.scoring import calculate_score, score_to_grade
from srvaudit.transport import HostKeyError, ShellTransport, SSHConnectionError

app = typer.Typer(
    name="srvaudit",
    help="Remote Linux server security audit via SSH",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _parse_target(target: str) -> tuple:
    target = target.replace("ssh://", "")
    user = "root"
    host = target
    port = 22

    if "@" in host:
        user, host = host.rsplit("@", 1)
    if ":" in host:
        host, port_str = host.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            pass

    return user, host, port


def version_callback(value: bool):
    if value:
        console.print(f"srvaudit {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    target: str = typer.Argument(..., help="SSH target: user@host[:port]"),
    port: Optional[int] = typer.Option(None, "-p", "--port", help="SSH port"),
    key: Optional[str] = typer.Option(None, "-i", "--key", help="SSH private key path"),
    password: bool = typer.Option(False, "--password", help="Prompt for password"),
    accept_host_key: bool = typer.Option(False, "--accept-host-key", help="Trust unknown host key"),
    known_hosts: Optional[str] = typer.Option(None, "--known-hosts", help="Custom known_hosts file"),
    sudo: bool = typer.Option(False, "--sudo", help="Run privileged checks via sudo"),
    quick: bool = typer.Option(False, "-q", "--quick", help="Quick mode: critical checks only"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Save report to file"),
    timeout: int = typer.Option(15, "--timeout", help="Per-command timeout in seconds"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show commands"),
    version: bool = typer.Option(False, "--version", callback=version_callback, is_eager=True),
):
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    user, host, default_port = _parse_target(target)
    ssh_port = port or default_port

    pwd = None
    if password:
        pwd = typer.prompt("SSH password", hide_input=True)

    console.print(f"[blue]Connecting to {user}@{host}:{ssh_port}...[/blue]")

    try:
        transport = ShellTransport(
            host=host,
            user=user,
            port=ssh_port,
            key_path=key,
            password=pwd,
            accept_host_key=accept_host_key,
            known_hosts=known_hosts,
            sudo=sudo,
            command_timeout=timeout,
        )
    except HostKeyError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2)
    except SSHConnectionError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2)

    start = time.monotonic()

    with transport:
        console.print("[blue]Detecting OS...[/blue]")
        distro = detect_distro(transport)
        environment = detect_environment(transport)
        console.print(f"[green]OS: {distro.id} {distro.version} ({distro.family})[/green]")

        from srvaudit.checks.registry import get_all_checks, get_quick_checks

        check_classes = get_quick_checks() if quick else get_all_checks()

        if not sudo:
            check_classes = [c for c in check_classes if not c._check_meta.requires_sudo]

        all_findings = []
        for check_cls in check_classes:
            meta = check_cls._check_meta
            if verbose:
                console.print(f"[dim]Running {meta.name}...[/dim]")
            try:
                instance = check_cls(transport, distro)
                findings = instance.run()
                all_findings.extend(findings)
            except Exception as e:
                logging.getLogger("srvaudit").warning(f"Check {meta.name} failed: {e}")
                from srvaudit.models import Finding, Severity
                all_findings.append(Finding(
                    check=meta.name,
                    severity=Severity.SKIP,
                    title=f"Check failed: {e}",
                ))

    duration = time.monotonic() - start
    score = calculate_score(all_findings)
    grade = score_to_grade(score)

    report = AuditReport(
        target=f"{user}@{host}:{ssh_port}",
        distro=distro,
        environment=environment,
        findings=all_findings,
        score=score,
        grade=grade,
        duration_sec=round(duration, 1),
    )

    if json_output or (output and output.endswith(".json")):
        from srvaudit.output.json_report import render_json
        json_str = render_json(report)
        if output:
            Path(output).write_text(json_str, encoding="utf-8")
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            print(json_str)
    else:
        from srvaudit.output.terminal import render_terminal
        render_terminal(report, verbose=verbose)
        if output:
            from srvaudit.output.json_report import render_json
            Path(output).write_text(render_json(report), encoding="utf-8")
            console.print(f"[green]Report saved to {output}[/green]")

    has_critical = any(f.severity.value == "critical" for f in all_findings)
    has_warning = any(f.severity.value == "warning" for f in all_findings)
    if has_critical or has_warning:
        raise typer.Exit(1)


@app.command()
def diff(
    before: str = typer.Argument(..., help="Path to before.json"),
    after: str = typer.Argument(..., help="Path to after.json"),
):
    import json as json_mod

    try:
        before_data = json_mod.loads(Path(before).read_text(encoding="utf-8"))
        after_data = json_mod.loads(Path(after).read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Error reading files: {e}[/red]")
        raise typer.Exit(2)

    b_score = before_data.get("score", 0)
    a_score = after_data.get("score", 0)
    diff_score = a_score - b_score

    console.print()
    console.print("[bold]srvaudit diff[/bold]")
    console.print(f"Before: {before_data.get('timestamp', '?')} | Score: {b_score}/100 ({before_data.get('grade', '?')})")

    diff_color = "green" if diff_score > 0 else "red" if diff_score < 0 else "white"
    sign = "+" if diff_score > 0 else ""
    console.print(
        f"After:  {after_data.get('timestamp', '?')} | Score: {a_score}/100 ({after_data.get('grade', '?')})  "
        f"[{diff_color}][{sign}{diff_score}][/{diff_color}]"
    )

    b_issues = {(f["check"], f["title"]): f for f in before_data.get("findings", []) if f["severity"] in ("critical", "warning")}
    a_issues = {(f["check"], f["title"]): f for f in after_data.get("findings", []) if f["severity"] in ("critical", "warning")}

    fixed = [b_issues[k] for k in b_issues if k not in a_issues]
    new = [a_issues[k] for k in a_issues if k not in b_issues]
    unchanged = [a_issues[k] for k in a_issues if k in b_issues]

    if fixed:
        console.print(f"\n[green]FIXED ({len(fixed)}):[/green]")
        for f in fixed:
            console.print(f"  [green][{f['severity'].upper()}][/green] {f['title']}")

    if new:
        console.print(f"\n[red]NEW ({len(new)}):[/red]")
        for f in new:
            console.print(f"  [red][{f['severity'].upper()}][/red] {f['title']}")

    if unchanged:
        console.print(f"\n[dim]UNCHANGED ({len(unchanged)}):[/dim]")
        for f in unchanged:
            console.print(f"  [dim][{f['severity'].upper()}] {f['title']}[/dim]")

    console.print()
