"""Pipeline ponta a ponta com APIs gravadas (fixtures) e notifier em memória."""

from datetime import UTC, datetime, timedelta

import requests
import responses

from app.collectors.cisa_kev import KEV_URL, CisaKevCollector
from app.collectors.nvd import NVD_URL, NvdCollector
from app.core.pipeline import Pipeline
from app.enrichers.epss import EPSS_URL, EpssEnricher
from app.models.alert import Alert, Severity
from app.storage.state import StateStore
from tests.conftest import load_fixture

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


class MemoryNotifier:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.alerts: list[Alert] = []
        self.texts: list[str] = []

    def send(self, alert: Alert) -> bool:
        self.alerts.append(alert)
        return self.ok

    def send_text(self, text: str) -> bool:
        self.texts.append(text)
        return self.ok


def _mock_apis() -> None:
    responses.get(KEV_URL, json=load_fixture("kev.json"))
    responses.get(
        NVD_URL,
        json=load_fixture("nvd_kev_detail.json"),
        match=[responses.matchers.query_param_matcher({"cveId": "CVE-2026-10001"})],
    )
    responses.get(NVD_URL, json=load_fixture("nvd_page.json"))
    responses.get(EPSS_URL, json=load_fixture("epss.json"))


def _pipeline(watchlist, notifier, state, **kw) -> Pipeline:
    session = requests.Session()
    return Pipeline(
        kev=CisaKevCollector(session),
        nvd=NvdCollector(session, sleep=lambda _s: None),
        epss=EpssEnricher(session),
        notifier=notifier,
        state=state,
        watchlist=watchlist,
        initial_lookback=timedelta(days=3),
        **kw,
    )


@responses.activate
def test_azure_environment_end_to_end(azure_watchlist):
    _mock_apis()
    notifier = MemoryNotifier()
    state = StateStore(":memory:")
    report = _pipeline(azure_watchlist, notifier, state).run_once(now=NOW)

    sent = {a.vulnerability.cve_id: a for a in notifier.alerts}
    # Google Workspace (KEV e NVD) e Oracle (fora do ambiente) ficam de fora
    assert set(sent) == {"CVE-2026-10001", "CVE-2026-20001", "CVE-2026-20003"}

    smb = sent["CVE-2026-10001"]
    assert smb.severity is Severity.CRITICAL
    assert smb.vulnerability.cvss_score == 9.8  # completado pela NVD
    assert smb.vulnerability.epss is not None  # enriquecido pelo EPSS
    assert smb.category == "Execução remota de código"

    cli = sent["CVE-2026-20001"]
    assert cli.severity is Severity.HIGH
    assert "perfil azure" in cli.matched_by

    assert sent["CVE-2026-20003"].severity is Severity.INFO  # sem CVSS ainda
    # Ordenação: crítico primeiro
    assert notifier.alerts[0].vulnerability.cve_id == "CVE-2026-10001"

    assert report.sent == 3
    assert report.failed == 0
    assert len(state.catalog_rows()) == 3
    assert state.get_checkpoint("nvd") == NOW
    assert state.get_checkpoint("cisa_kev") == NOW


@responses.activate
def test_second_run_does_not_repeat(azure_watchlist):
    _mock_apis()
    state = StateStore(":memory:")
    _pipeline(azure_watchlist, MemoryNotifier(), state).run_once(now=NOW)
    again = MemoryNotifier()
    _pipeline(azure_watchlist, again, state).run_once(now=NOW + timedelta(minutes=30))
    assert again.alerts == []


@responses.activate
def test_failed_send_is_not_marked_and_checkpoint_holds(azure_watchlist):
    _mock_apis()
    state = StateStore(":memory:")
    report = _pipeline(azure_watchlist, MemoryNotifier(ok=False), state).run_once(now=NOW)
    assert report.failed == 3
    assert state.sent_severity("CVE-2026-10001") is None
    assert state.get_checkpoint("nvd") is None


@responses.activate
def test_source_outage_is_isolated(azure_watchlist):
    responses.get(KEV_URL, status=503)
    responses.get(NVD_URL, json=load_fixture("nvd_page.json"))
    responses.get(EPSS_URL, json=load_fixture("epss.json"))
    notifier = MemoryNotifier()
    state = StateStore(":memory:")
    report = _pipeline(azure_watchlist, notifier, state).run_once(now=NOW)
    assert len(report.errors) == 1
    assert {a.vulnerability.cve_id for a in notifier.alerts} == {"CVE-2026-20001", "CVE-2026-20003"}
    assert state.get_checkpoint("cisa_kev") is None
    assert state.get_checkpoint("nvd") == NOW


@responses.activate
def test_overflow_goes_to_single_summary(azure_watchlist):
    _mock_apis()
    notifier = MemoryNotifier()
    report = _pipeline(
        azure_watchlist, notifier, StateStore(":memory:"), max_alerts_per_run=1
    ).run_once(now=NOW)
    assert len(notifier.alerts) == 1
    assert len(notifier.texts) == 1
    assert "+2 alertas" in notifier.texts[0]
    assert report.sent == 3


def test_escalation_realerts(azure_watchlist):
    from app.models.vulnerability import Vulnerability

    state = StateStore(":memory:")
    v = Vulnerability(cve_id="CVE-2026-5555")
    high = Alert(vulnerability=v, severity=Severity.HIGH)
    state.mark_sent(high)
    assert not state.should_alert(high)
    assert not state.should_alert(Alert(vulnerability=v, severity=Severity.MEDIUM))
    assert state.should_alert(Alert(vulnerability=v, severity=Severity.CRITICAL))
