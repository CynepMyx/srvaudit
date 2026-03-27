from srvaudit.models import Finding, Severity
from srvaudit.scoring import calculate_score, score_to_grade


def _f(severity):
    return Finding(check="test", severity=severity, title="test")


def test_no_findings():
    assert calculate_score([]) == 100


def test_one_warning():
    assert calculate_score([_f(Severity.WARNING)]) == 92


def test_one_critical():
    score = calculate_score([_f(Severity.CRITICAL)])
    assert score <= 45


def test_critical_caps_at_45():
    score = calculate_score([_f(Severity.CRITICAL)])
    assert score == 45


def test_multiple_criticals():
    score = calculate_score([_f(Severity.CRITICAL), _f(Severity.CRITICAL)])
    # 100 - 50 = 50, but capped at 45 due to CRITICAL
    assert score == 45


def test_many_criticals_below_45():
    score = calculate_score([_f(Severity.CRITICAL)] * 4)
    # 100 - 100 = 0, below 45 cap, so stays at 0
    assert score == 0


def test_info_no_penalty():
    assert calculate_score([_f(Severity.INFO)]) == 100


def test_ok_no_penalty():
    assert calculate_score([_f(Severity.OK)]) == 100


def test_skip_no_penalty():
    assert calculate_score([_f(Severity.SKIP)]) == 100


def test_mixed():
    findings = [
        _f(Severity.WARNING),
        _f(Severity.WARNING),
        _f(Severity.INFO),
    ]
    assert calculate_score(findings) == 84


def test_grade_a():
    assert score_to_grade(95) == "A"


def test_grade_b():
    assert score_to_grade(75) == "B"


def test_grade_c():
    assert score_to_grade(55) == "C"


def test_grade_d():
    assert score_to_grade(40) == "D"


def test_grade_boundaries():
    assert score_to_grade(90) == "A"
    assert score_to_grade(89) == "B"
    assert score_to_grade(70) == "B"
    assert score_to_grade(69) == "C"
    assert score_to_grade(50) == "C"
    assert score_to_grade(49) == "D"
    assert score_to_grade(0) == "D"
