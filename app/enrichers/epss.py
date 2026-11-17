"""Enriquecimento com EPSS (Exploit Prediction Scoring System — FIRST).

Fonte: https://www.first.org/epss/api
Retorna a probabilidade de exploração em 30 dias para cada CVE, consultada em lote.
"""

from __future__ import annotations

import logging

import requests

from app.models.vulnerability import Vulnerability

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 50  # mantém a URL bem abaixo do limite de tamanho


class EpssEnricher:
    def __init__(self, session: requests.Session, url: str = EPSS_URL) -> None:
        self.session = session
        self.url = url

    def fetch(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        scores: dict[str, tuple[float, float]] = {}
        for i in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[i : i + BATCH_SIZE]
            try:
                resp = self.session.get(self.url, params={"cve": ",".join(batch)})
                resp.raise_for_status()
                data = resp.json().get("data", [])
            except (requests.RequestException, ValueError) as exc:
                # EPSS é contexto: sem ele o alerta sai só com KEV/CVSS.
                log.warning("EPSS indisponível para lote: %s", type(exc).__name__)
                continue
            for row in data:
                try:
                    scores[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
                except (KeyError, TypeError, ValueError):
                    continue
        return scores

    def enrich(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        scores = self.fetch([v.cve_id for v in vulns])
        enriched = []
        for v in vulns:
            if v.cve_id in scores:
                epss, pct = scores[v.cve_id]
                v = v.model_copy(update={"epss": epss, "epss_percentile": pct})
            enriched.append(v)
        return enriched
