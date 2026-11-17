"""Filtros aplicados sobre vulnerabilidades normalizadas.

Duas etapas, nesta ordem:

1. **Escopo** (``ScopeFilter``) — a vuln faz sentido para o MEU ambiente?
   - ``exclude`` sempre vence: perfis, vendors, produtos e palavras-chave fora do ambiente
     (ex.: ambiente Azure → nada de Google Workspace), inclusive para itens do KEV.
   - Depois precisa casar com a watchlist (perfis + vendors) — ou estar no KEV com
     ``alert_all_kev: true``.
2. **Risco** (``passes_risk``) — já enriquecida, tem CVSS/EPSS mínimos (ou está no KEV)?
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatchcase

from app.config.watchlist import Thresholds, Watchlist
from app.core.profiles import PROFILES
from app.models.vulnerability import AffectedProduct, Vulnerability, normalize_name


@dataclass(frozen=True)
class Rule:
    """Regra vendor/produto. ``products`` vazio = qualquer produto do vendor."""

    vendor: str
    products: tuple[str, ...]
    label: str

    def matches(self, item: AffectedProduct) -> bool:
        if not _pattern_match(item.vendor, self.vendor):
            return False
        return not self.products or any(_pattern_match(item.product, p) for p in self.products)

    def matches_text(self, text: str) -> bool:
        """Fallback para CVEs ainda sem CPE na NVD: vendor E produto citados na descrição."""
        if self.vendor == "*" or not _word_in(self.vendor, text):
            return False
        return not self.products or any(_word_in(p, text) for p in self.products)


@dataclass(frozen=True)
class ScopeDecision:
    in_scope: bool
    reason: str
    matched_by: str | None = None


def _pattern_match(value: str, pattern: str) -> bool:
    return fnmatchcase(value, pattern) or value.startswith(pattern.rstrip("*") + "_")


def _word_in(pattern: str, text: str) -> bool:
    phrase = pattern.replace("*", "").strip("_").replace("_", " ").strip()
    if len(phrase) < 3:
        return False
    return re.search(rf"\b{re.escape(phrase)}\b", text) is not None


def _profile_rules(names: list[str]) -> list[Rule]:
    return [
        Rule(vendor=vendor, products=tuple(products), label=f"perfil {name}")
        for name in names
        for vendor, products in PROFILES[name].items()
    ]


class ScopeFilter:
    def __init__(self, watchlist: Watchlist) -> None:
        self.alert_all_kev = watchlist.alert_all_kev
        self.include = _profile_rules(watchlist.environment.profiles) + [
            Rule(
                vendor=normalize_name(v.name),
                products=tuple(normalize_name(p) if "*" not in p else p for p in v.products),
                label=f"vendor {normalize_name(v.name)}",
            )
            for v in watchlist.vendors
        ]
        ex = watchlist.exclude
        self.exclude = _profile_rules(ex.profiles) + [
            Rule(vendor=normalize_name(v), products=(), label=f"exclude vendor {v}")
            for v in ex.vendors
        ]
        for spec in ex.products:
            vendor, _, product = spec.rpartition("/")
            self.exclude.append(
                Rule(vendor=vendor or "*", products=(product,), label=f"exclude produto {spec}")
            )
        self.exclude_keywords = [k.lower() for k in ex.keywords if k.strip()]

    def _candidates(self, vuln: Vulnerability) -> list[AffectedProduct]:
        items = list(vuln.affected)
        if vuln.vendor_label and vuln.product_label:  # KEV traz nomes "humanos"
            label = AffectedProduct(vendor=vuln.vendor_label, product=vuln.product_label)
            if label not in items:
                items.append(label)
        return items

    def evaluate(self, vuln: Vulnerability) -> ScopeDecision:
        text = f"{vuln.title or ''} {vuln.description}".lower()
        for keyword in self.exclude_keywords:
            if keyword in text:
                return ScopeDecision(False, f"palavra-chave excluída: {keyword!r}")

        candidates = self._candidates(vuln)
        remaining = [c for c in candidates if not any(r.matches(c) for r in self.exclude)]
        if candidates and not remaining:
            return ScopeDecision(False, "todos os produtos afetados estão fora do ambiente")
        if not candidates and any(r.matches_text(text) for r in self.exclude):
            return ScopeDecision(False, "descrição cita produto fora do ambiente")

        for item in remaining:
            for rule in self.include:
                if rule.matches(item):
                    return ScopeDecision(True, "watchlist", f"{item} ({rule.label})")
        if not candidates:
            for rule in self.include:
                if rule.matches_text(text):
                    return ScopeDecision(True, "watchlist (descrição)", f"{rule.label} · descrição")

        if vuln.in_kev and self.alert_all_kev:
            return ScopeDecision(True, "CISA KEV (alert_all_kev)", "CISA KEV")
        return ScopeDecision(False, "fora da watchlist")


def is_recent(vuln: Vulnerability, now: datetime, max_age_days: int) -> bool:
    """CVEs antigas só interessam se entraram agora no KEV."""
    if vuln.in_kev and vuln.kev_date_added is not None:
        return True
    if vuln.published_at is None:
        return True
    return vuln.published_at >= now - timedelta(days=max_age_days)


def passes_risk(vuln: Vulnerability, thresholds: Thresholds) -> bool:
    if vuln.in_kev:
        return True
    if vuln.cvss_score is None and vuln.epss is None:
        return thresholds.include_unscored
    return (vuln.cvss_score or 0) >= thresholds.min_cvss or (vuln.epss or 0) >= thresholds.min_epss
