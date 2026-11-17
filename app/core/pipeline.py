"""Orquestra o fluxo principal:

    collect → merge → escopo (ambiente) → enrich → risco → score/categoria
            → catálogo → dedupe → notify → persist

Garantias:
- Um alerta só é marcado como enviado APÓS confirmação do notifier.
- Falha em um coletor não derruba os demais (isolamento por fonte).
- O checkpoint de uma fonte só avança se a coleta dela deu certo e todos os envios
  confirmaram — na próxima rodada a janela é refeita e a deduplicação evita repetição.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.collectors.base import SourceError
from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.nvd import NvdCollector
from app.config.watchlist import Watchlist
from app.core.categories import categorize
from app.core.filters import ScopeFilter, is_recent, passes_risk
from app.core.scoring import score
from app.enrichers.epss import EpssEnricher
from app.models.alert import Alert
from app.models.vulnerability import Vulnerability
from app.notifiers.base import Notifier
from app.notifiers.formatter import format_overflow
from app.storage.state import StateStore

log = logging.getLogger(__name__)


@dataclass
class RunReport:
    collected: int = 0
    in_scope: int = 0
    excluded: int = 0
    alerts: int = 0
    sent: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"coletadas={self.collected} no_escopo={self.in_scope} excluídas={self.excluded} "
            f"alertas_novos={self.alerts} enviados={self.sent} falhas={self.failed} "
            f"erros_fonte={len(self.errors)}"
        )


class Pipeline:
    def __init__(
        self,
        kev: CisaKevCollector,
        nvd: NvdCollector,
        epss: EpssEnricher,
        notifier: Notifier,
        state: StateStore,
        watchlist: Watchlist,
        initial_lookback: timedelta = timedelta(days=3),
        cve_max_age_days: int = 30,
        max_alerts_per_run: int = 15,
    ) -> None:
        self.kev = kev
        self.nvd = nvd
        self.epss = epss
        self.notifier = notifier
        self.state = state
        self.watchlist = watchlist
        self.scope = ScopeFilter(watchlist)
        self.initial_lookback = initial_lookback
        self.cve_max_age_days = cve_max_age_days
        self.max_alerts_per_run = max_alerts_per_run

    # ------------------------------------------------------------ etapas
    def _since(self, source: str, now: datetime) -> datetime:
        return self.state.get_checkpoint(source) or now - self.initial_lookback

    def _collect(self, now: datetime, report: RunReport) -> tuple[dict[str, Vulnerability], set]:
        found: dict[str, Vulnerability] = {}
        ok_sources: set[str] = set()

        try:
            for v in self.kev.collect(self._since(self.kev.name, now), now):
                found[v.cve_id] = v
            ok_sources.add(self.kev.name)
        except SourceError as exc:
            log.error("%s", exc)
            report.errors.append(str(exc))

        try:
            for v in self.nvd.collect(self._since(self.nvd.name, now), now):
                if v.cve_id in self.kev.catalog:  # CVE antiga que já está no KEV
                    v = v.merge(self.kev.catalog[v.cve_id])
                if not is_recent(v, now, self.cve_max_age_days):
                    continue
                found[v.cve_id] = found[v.cve_id].merge(v) if v.cve_id in found else v
            ok_sources.add(self.nvd.name)
        except SourceError as exc:
            log.error("%s", exc)
            report.errors.append(str(exc))

        report.collected = len(found)
        return found, ok_sources

    def _complete_from_nvd(self, vuln: Vulnerability) -> Vulnerability:
        """Itens do KEV não trazem CVSS/CPE: busca o registro na NVD."""
        if "nvd" in vuln.sources:
            return vuln
        try:
            extra = self.nvd.fetch_cve(vuln.cve_id)
        except SourceError as exc:
            log.warning("Sem dados NVD para %s: %s", vuln.cve_id, exc)
            return vuln
        return vuln.merge(extra) if extra else vuln

    def build_alerts(self, found: dict[str, Vulnerability], report: RunReport) -> list[Alert]:
        scoped: list[tuple[Vulnerability, str | None]] = []
        for v in found.values():
            decision = self.scope.evaluate(v)
            if decision.in_scope:
                scoped.append((v, decision.matched_by))
            else:
                report.excluded += 1
                log.debug("%s fora do escopo: %s", v.cve_id, decision.reason)
        report.in_scope = len(scoped)

        matched_by = {v.cve_id: m for v, m in scoped}
        vulns = [self._complete_from_nvd(v) for v, _ in scoped]
        vulns = self.epss.enrich(vulns)

        alerts = []
        for v in vulns:
            severity, reasons = score(v, self.watchlist.scoring)
            alerts.append(
                Alert(
                    vulnerability=v,
                    severity=severity,
                    reasons=reasons,
                    category=categorize(v),
                    matched_by=matched_by.get(v.cve_id),
                )
            )
        self.state.upsert_catalog(alerts)  # cataloga tudo que é do ambiente
        return [a for a in alerts if passes_risk(a.vulnerability, self.watchlist.thresholds)]

    def _notify(self, alerts: list[Alert], report: RunReport) -> None:
        pending = sorted(
            (a for a in alerts if self.state.should_alert(a)), key=Alert.sort_key, reverse=True
        )
        report.alerts = len(pending)
        head, overflow = pending[: self.max_alerts_per_run], pending[self.max_alerts_per_run :]

        for alert in head:
            if self.notifier.send(alert):
                self.state.mark_sent(alert)
                report.sent += 1
            else:
                report.failed += 1

        if overflow:
            if self.notifier.send_text(format_overflow(overflow)):
                for alert in overflow:
                    self.state.mark_sent(alert)
                report.sent += len(overflow)
            else:
                report.failed += len(overflow)

    # ------------------------------------------------------------ execução
    def run_once(self, now: datetime | None = None) -> RunReport:
        now = now or datetime.now(UTC)
        report = RunReport()
        found, ok_sources = self._collect(now, report)
        alerts = self.build_alerts(found, report)
        self._notify(alerts, report)

        if report.failed == 0:
            for source in ok_sources:
                self.state.set_checkpoint(source, now)
        log.info("Rodada concluída (%s): %s", self.watchlist.environment.name, report.summary())
        return report
