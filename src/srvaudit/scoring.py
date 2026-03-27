from __future__ import annotations

from typing import List

from srvaudit.models import Finding, Severity

WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.WARNING: 8,
    Severity.INFO: 0,
    Severity.OK: 0,
    Severity.SKIP: 0,
}

GRADES = [
    (90, "A"),
    (70, "B"),
    (50, "C"),
    (0, "D"),
]


def calculate_score(findings: List[Finding]) -> int:
    penalties = sum(WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalties)

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    if has_critical:
        score = min(score, 45)

    return score


def score_to_grade(score: int) -> str:
    for threshold, grade in GRADES:
        if score >= threshold:
            return grade
    return "D"
