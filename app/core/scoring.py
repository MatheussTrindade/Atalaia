"""Priorização dos alertas (ADR-0001).

Regra (limiares configuráveis em ``watchlist.scoring``):
- 🔴 CRÍTICO → está no CISA KEV (exploração ativa confirmada)
- 🟠 ALTO    → CVSS >= 9.0  OU  EPSS >= 0.5
- 🟡 MÉDIO   → CVSS >= 7.0  OU  EPSS >= 0.1
- ⚪ INFO    → demais itens da watchlist
"""

from __future__ import annotations

from app.config.watchlist import ScoringRules
from app.models.alert import Severity
from app.models.vulnerability import Vulnerability


def score(vuln: Vulnerability, rules: ScoringRules | None = None) -> tuple[Severity, list[str]]:
    rules = rules or ScoringRules()
    cvss, epss = vuln.cvss_score, vuln.epss

    if vuln.in_kev:
        reasons = ["Explorada ativamente (CISA KEV)"]
        if vuln.kev_ransomware:
            reasons.append("Usada em campanhas de ransomware")
        return Severity.CRITICAL, reasons

    for severity, min_cvss, min_epss in (
        (Severity.HIGH, rules.high_cvss, rules.high_epss),
        (Severity.MEDIUM, rules.medium_cvss, rules.medium_epss),
    ):
        reasons = []
        if cvss is not None and cvss >= min_cvss:
            reasons.append(f"CVSS ≥ {min_cvss:g}")
        if epss is not None and epss >= min_epss:
            reasons.append(f"EPSS ≥ {min_epss:g}")
        if reasons:
            return severity, reasons

    if cvss is None and epss is None:
        return Severity.INFO, ["Ainda sem CVSS/EPSS"]
    return Severity.INFO, ["Na watchlist"]
