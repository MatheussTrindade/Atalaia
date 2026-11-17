"""Coletor do CISA KEV (Known Exploited Vulnerabilities).

Fonte: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed:  JSON público, sem autenticação.

``collect`` devolve só as entradas adicionadas na janela; o catálogo completo fica em
``catalog`` para marcar ``in_kev`` em CVEs vindas de outras fontes.
"""

from __future__ import annotations

import logging
from datetime import date, datetime

import requests
from pydantic import ValidationError

from app.collectors.base import SourceError
from app.models.vulnerability import Vulnerability

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def parse_entry(raw: dict) -> Vulnerability:
    return Vulnerability(
        cve_id=raw["cveID"],
        title=raw.get("vulnerabilityName"),
        description=raw.get("shortDescription") or "",
        vendor_label=raw.get("vendorProject"),
        product_label=raw.get("product"),
        cwes=list(raw.get("cwes") or []),
        in_kev=True,
        kev_date_added=_parse_date(raw.get("dateAdded")),
        kev_due_date=_parse_date(raw.get("dueDate")),
        kev_ransomware=str(raw.get("knownRansomwareCampaignUse", "")).lower() == "known",
        kev_required_action=raw.get("requiredAction"),
        sources={"cisa_kev"},
    )


class CisaKevCollector:
    name = "cisa_kev"

    def __init__(self, session: requests.Session, url: str = KEV_URL) -> None:
        self.session = session
        self.url = url
        self.catalog: dict[str, Vulnerability] = {}

    def fetch_catalog(self) -> dict[str, Vulnerability]:
        try:
            resp = self.session.get(self.url)
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise SourceError(f"CISA KEV indisponível: {type(exc).__name__}") from exc

        catalog: dict[str, Vulnerability] = {}
        for raw in payload.get("vulnerabilities", []):
            try:
                vuln = parse_entry(raw)
            except (KeyError, ValidationError) as exc:
                log.warning("Entrada KEV inválida ignorada: %s", type(exc).__name__)
                continue
            catalog[vuln.cve_id] = vuln
        if not catalog:
            raise SourceError("CISA KEV retornou catálogo vazio")
        self.catalog = catalog
        log.info("CISA KEV: %d entradas no catálogo", len(catalog))
        return catalog

    def collect(self, since: datetime, until: datetime) -> list[Vulnerability]:
        catalog = self.fetch_catalog()
        start, end = since.date(), until.date()
        return [
            v
            for v in catalog.values()
            if v.kev_date_added is not None and start <= v.kev_date_added <= end
        ]
