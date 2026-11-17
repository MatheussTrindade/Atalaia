"""Modelo de alerta pronto para envio (vulnerabilidade + severidade)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from app.models.vulnerability import Vulnerability


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @property
    def emoji(self) -> str:
        return _EMOJI[self]

    @property
    def label(self) -> str:
        return _LABEL[self]


_RANK = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.INFO: 0}
_EMOJI = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.INFO: "⚪"}
_LABEL = {
    Severity.CRITICAL: "CRÍTICO",
    Severity.HIGH: "ALTO",
    Severity.MEDIUM: "MÉDIO",
    Severity.INFO: "INFO",
}


class Alert(BaseModel):
    vulnerability: Vulnerability
    severity: Severity
    reasons: list[str] = Field(default_factory=list)
    category: str = "Outros"
    matched_by: str | None = None

    @property
    def source(self) -> str:
        return "cisa_kev" if self.vulnerability.in_kev else "nvd"

    def sort_key(self) -> tuple[int, float, float]:
        v = self.vulnerability
        return (self.severity.rank, v.epss or 0.0, v.cvss_score or 0.0)
