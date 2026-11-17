"""Coletor da NVD (National Vulnerability Database) — API CVE 2.0.

Fonte: https://nvd.nist.gov/developers/vulnerabilities
Auth:  API key opcional (``NVD_API_KEY``) — aumenta o rate limit.

- Consulta por janela ``lastModStartDate``/``lastModEndDate`` (máx. 120 dias): pega CVEs
  novas e também as que a NVD acabou de enriquecer com CPE/CVSS.
- Rate limit: 5 req/30s sem key, 50 req/30s com key → espaçamento de 6s / 0,6s.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import requests
from pydantic import SecretStr, ValidationError

from app.collectors.base import SourceError
from app.models.vulnerability import AffectedProduct, Reference, Vulnerability

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW = timedelta(days=120)
PAGE_SIZE = 2000
# Preferência de métrica: v3.1 > v3.0 > v4.0 > v2 (limiares do ADR-0001 são de CVSS v3).
CVSS_KEYS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV2", "2.0"),
)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key, version in CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = [e for e in entries if e.get("type") == "Primary"] or entries
        data = primary[0].get("cvssData", {})
        if data.get("baseScore") is not None:
            return float(data["baseScore"]), data.get("vectorString"), version
    return None, None, None


def _affected(configurations: list) -> list[AffectedProduct]:
    seen: dict[tuple[str, str], AffectedProduct] = {}
    for config in configurations or []:
        for node in config.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match.get("criteria", "").split(":")
                # cpe:2.3:<part>:<vendor>:<product>:...
                if len(parts) > 4 and parts[3] not in ("*", "-") and parts[4] not in ("*", "-"):
                    key = (parts[3], parts[4])
                    seen.setdefault(key, AffectedProduct(vendor=parts[3], product=parts[4]))
    return list(seen.values())


def parse_cve(raw: dict) -> Vulnerability:
    cve = raw["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    score, vector, version = _pick_cvss(cve.get("metrics", {}))
    cwes = [
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if str(d.get("value", "")).startswith("CWE-")
    ]
    return Vulnerability(
        cve_id=cve["id"],
        title=cve.get("cisaVulnerabilityName"),
        description=description,
        affected=_affected(cve.get("configurations", [])),
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=version,
        cwes=list(dict.fromkeys(cwes)),
        published_at=_parse_dt(cve.get("published")),
        last_modified_at=_parse_dt(cve.get("lastModified")),
        references=[
            Reference(url=r["url"], tags=r.get("tags", []))
            for r in cve.get("references", [])
            if r.get("url")
        ],
        sources={"nvd"},
    )


class NvdCollector:
    name = "nvd"

    def __init__(
        self,
        session: requests.Session,
        api_key: SecretStr | None = None,
        url: str = NVD_URL,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session = session
        self.api_key = api_key
        self.url = url
        self.interval = 0.6 if api_key else 6.0
        self._sleep = sleep
        self._clock = clock
        self._last_request: float | None = None

    def _get(self, params: dict) -> dict:
        if self._last_request is not None:
            wait = self.interval - (self._clock() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        headers = {"apiKey": self.api_key.get_secret_value()} if self.api_key else {}
        try:
            resp = self.session.get(self.url, params=params, headers=headers)
            self._last_request = self._clock()
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            status = getattr(getattr(exc, "response", None), "status_code", "-")
            raise SourceError(f"NVD indisponível: {type(exc).__name__} (HTTP {status})") from exc

    def _parse_page(self, payload: dict) -> list[Vulnerability]:
        items = []
        for raw in payload.get("vulnerabilities", []):
            if raw.get("cve", {}).get("vulnStatus") == "Rejected":
                continue
            try:
                items.append(parse_cve(raw))
            except (KeyError, ValueError, ValidationError) as exc:
                log.warning("CVE inválida da NVD ignorada: %s", type(exc).__name__)
        return items

    def collect(self, since: datetime, until: datetime) -> list[Vulnerability]:
        since = max(since, until - MAX_WINDOW)
        params = {
            "lastModStartDate": _fmt(since),
            "lastModEndDate": _fmt(until),
            "resultsPerPage": PAGE_SIZE,
        }
        results: list[Vulnerability] = []
        start = 0
        while True:
            payload = self._get({**params, "startIndex": start})
            results.extend(self._parse_page(payload))
            total = int(payload.get("totalResults", 0))
            per_page = int(payload.get("resultsPerPage", 0)) or PAGE_SIZE
            start += per_page
            if start >= total:
                break
        log.info("NVD: %d CVEs alteradas na janela", len(results))
        return results

    def fetch_cve(self, cve_id: str) -> Vulnerability | None:
        items = self._parse_page(self._get({"cveId": cve_id}))
        return items[0] if items else None
