from __future__ import annotations

from srvaudit.models import AuditReport


def render_json(report: AuditReport) -> str:
    return report.to_json()
