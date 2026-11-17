from datetime import UTC, datetime

import pytest
import requests
import responses
from pydantic import SecretStr

from app.collectors.base import SourceError
from app.collectors.cisa_kev import KEV_URL, CisaKevCollector
from app.collectors.nvd import NVD_URL, NvdCollector
from app.enrichers.epss import EPSS_URL, EpssEnricher
from app.models.alert import Alert, Severity
from app.models.vulnerability import Vulnerability
from app.notifiers.formatter import format_alert
from app.notifiers.telegram import TelegramNotifier
from tests.conftest import load_fixture

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
FAKE_TOKEN = SecretStr("123456789:AAH" + "x" * 32)


@pytest.fixture
def session() -> requests.Session:
    return requests.Session()


@responses.activate
def test_kev_collects_window_and_keeps_catalog(session):
    responses.get(KEV_URL, json=load_fixture("kev.json"))
    kev = CisaKevCollector(session)
    items = kev.collect(datetime(2026, 11, 15, tzinfo=UTC), NOW)
    assert {v.cve_id for v in items} == {"CVE-2026-10001", "CVE-2026-10002"}
    assert "CVE-2021-44228" in kev.catalog
    smb = next(v for v in items if v.cve_id == "CVE-2026-10001")
    assert smb.kev_ransomware
    assert smb.kev_due_date.isoformat() == "2026-12-06"


@responses.activate
def test_kev_outage_raises_source_error(session):
    responses.get(KEV_URL, status=503)
    with pytest.raises(SourceError):
        CisaKevCollector(session).collect(NOW, NOW)


@responses.activate
def test_nvd_parses_and_skips_rejected(session):
    responses.get(NVD_URL, json=load_fixture("nvd_page.json"))
    nvd = NvdCollector(session, sleep=lambda _s: None)
    items = {v.cve_id: v for v in nvd.collect(datetime(2026, 11, 15, tzinfo=UTC), NOW)}
    assert "CVE-2026-20004" not in items
    cli = items["CVE-2026-20001"]
    assert cli.cvss_score == 9.8
    assert cli.cvss_version == "3.1"
    assert str(cli.affected[0]) == "microsoft/azure_cli"
    assert cli.published_at.tzinfo is not None
    assert (
        "lastModStartDate=2026-11-15T00%3A00%3A00.000%2B00%3A00" in responses.calls[0].request.url
    )


@responses.activate
def test_nvd_paginates_and_throttles(session):
    page = load_fixture("nvd_page.json")
    page1 = {
        **page,
        "resultsPerPage": 2,
        "totalResults": 4,
        "vulnerabilities": page["vulnerabilities"][:2],
    }
    page2 = {
        **page,
        "resultsPerPage": 2,
        "startIndex": 2,
        "totalResults": 4,
        "vulnerabilities": page["vulnerabilities"][2:],
    }
    responses.get(NVD_URL, json=page1)
    responses.get(NVD_URL, json=page2)
    sleeps: list[float] = []
    nvd = NvdCollector(session, api_key=SecretStr("k" * 20), sleep=sleeps.append, clock=lambda: 0.0)
    assert len(nvd.collect(NOW, NOW)) == 3
    assert sleeps == [pytest.approx(0.6)]
    assert responses.calls[1].request.headers["apiKey"] == "k" * 20


@responses.activate
def test_epss_enrich_and_tolerates_outage(session):
    responses.get(EPSS_URL, json=load_fixture("epss.json"))
    vulns = [Vulnerability(cve_id="CVE-2026-10001"), Vulnerability(cve_id="CVE-2026-99999")]
    enriched = EpssEnricher(session).enrich(vulns)
    assert enriched[0].epss == pytest.approx(0.9421)
    assert enriched[1].epss is None

    responses.replace(responses.GET, EPSS_URL, status=500)
    assert EpssEnricher(session).enrich(vulns)[0].epss is None


def _alert(**kw) -> Alert:
    v = Vulnerability(cve_id="CVE-2026-10001", **kw)
    return Alert(vulnerability=v, severity=Severity.CRITICAL, reasons=["Explorada ativamente"])


def test_formatter_escapes_and_blocks_unsafe_links():
    alert = _alert(
        description='<script>alert(1)</script> & <a href="javascript:x">click</a>',
        references=[{"url": "javascript:alert(1)", "tags": ["Vendor Advisory"]}],
    )
    text = format_alert(alert)
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "javascript:" not in text.replace("&quot;javascript:x&quot;", "")
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2026-10001"' in text


@responses.activate
def test_telegram_success_requires_ok_true(session):
    url = f"https://api.telegram.org/bot{FAKE_TOKEN.get_secret_value()}/sendMessage"
    responses.post(url, json={"ok": True, "result": {}})
    tg = TelegramNotifier(session, FAKE_TOKEN, "-100123", sleep=lambda _s: None)
    assert tg.send(_alert(description="x"))
    body = responses.calls[0].request.body.decode()
    assert '"parse_mode": "HTML"' in body


@responses.activate
def test_telegram_retries_on_429_and_fails_on_400(session, caplog):
    url = f"https://api.telegram.org/bot{FAKE_TOKEN.get_secret_value()}/sendMessage"
    responses.post(url, status=429, json={"ok": False, "parameters": {"retry_after": 7}})
    responses.post(url, json={"ok": True})
    sleeps: list[float] = []
    tg = TelegramNotifier(session, FAKE_TOKEN, "-100123", sleep=sleeps.append, clock=lambda: 0.0)
    assert tg.send_text("oi")
    assert 7 in sleeps

    responses.replace(responses.POST, url, status=400, json={"ok": False, "description": "bad"})
    assert not tg.send_text("oi")
    assert FAKE_TOKEN.get_secret_value() not in caplog.text


def test_formatter_normalizes_source_entities_without_unescaping_html():
    text = format_alert(_alert(description="OCI &ndash; Provisioning &lt;b&gt;x&lt;/b&gt;"))
    assert "OCI – Provisioning" in text
    assert "<b>x</b>" not in text
    assert "&lt;b&gt;x&lt;/b&gt;" in text
