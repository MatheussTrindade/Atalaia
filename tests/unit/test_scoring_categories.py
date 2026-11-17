import pytest

from app.config.watchlist import ScoringRules
from app.core.categories import categorize
from app.core.scoring import score
from app.models.alert import Severity
from app.models.vulnerability import Vulnerability


def vuln(**kw) -> Vulnerability:
    return Vulnerability(cve_id="CVE-2026-0001", **kw)


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"in_kev": True}, Severity.CRITICAL),
        ({"cvss_score": 9.8}, Severity.HIGH),
        ({"cvss_score": 5.0, "epss": 0.6}, Severity.HIGH),
        ({"cvss_score": 7.5}, Severity.MEDIUM),
        ({"cvss_score": 3.0, "epss": 0.15}, Severity.MEDIUM),
        ({"cvss_score": 3.0, "epss": 0.01}, Severity.INFO),
        ({}, Severity.INFO),
    ],
)
def test_score(kw, expected):
    assert score(vuln(**kw))[0] is expected


def test_score_custom_rules():
    assert score(vuln(cvss_score=8.5), ScoringRules(high_cvss=8.0))[0] is Severity.HIGH


def test_ransomware_reason():
    _, reasons = score(vuln(in_kev=True, kev_ransomware=True))
    assert "ransomware" in reasons[1]


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({"cwes": ["CWE-78"]}, "Execução remota de código"),
        ({"cwes": ["CWE-79"]}, "XSS"),
        ({"cwes": ["CWE-502"]}, "Desserialização insegura"),
        ({"cwes": ["CWE-611"]}, "XXE"),
        (
            {"description": "Use after free allows an attacker to execute code over a network"},
            "Execução remota de código",
        ),
        ({"description": "allows an attacker to perform SQL injection"}, "Injeção SQL"),
        # RCE vence corrupção de memória quando os dois aparecem
        (
            {"cwes": ["CWE-122"], "description": "heap overflow allows remote code execution"},
            "Execução remota de código",
        ),
        ({}, "Outros"),
    ],
)
def test_categorize(kw, expected):
    assert categorize(vuln(**kw)) == expected
