from datetime import UTC, date, datetime, timedelta

from app.config.watchlist import Thresholds, Watchlist
from app.core.filters import ScopeFilter, is_recent, passes_risk
from app.models.vulnerability import AffectedProduct, Vulnerability


def vuln(**kw) -> Vulnerability:
    return Vulnerability(cve_id=kw.pop("cve_id", "CVE-2026-0001"), **kw)


def ap(vendor: str, product: str) -> AffectedProduct:
    return AffectedProduct(vendor=vendor, product=product)


def test_profile_matches_cpe_with_wildcard(azure_watchlist):
    decision = ScopeFilter(azure_watchlist).evaluate(vuln(affected=[ap("microsoft", "azure_cli")]))
    assert decision.in_scope
    assert "perfil azure" in decision.matched_by


def test_prefix_match_on_product(azure_watchlist):
    v = vuln(affected=[ap("microsoft", "windows_server_2022")])
    assert ScopeFilter(azure_watchlist).evaluate(v).in_scope


def test_kev_human_labels_are_normalized(azure_watchlist):
    v = vuln(vendor_label="Microsoft", product_label="Windows SMB", in_kev=True)
    assert ScopeFilter(azure_watchlist).evaluate(v).in_scope


def test_google_workspace_excluded_even_from_kev():
    wl = Watchlist.model_validate(
        {"alert_all_kev": True, "exclude": {"profiles": ["google_workspace"]}}
    )
    v = vuln(vendor_label="Google", product_label="Workspace", in_kev=True)
    assert not ScopeFilter(wl).evaluate(v).in_scope


def test_alert_all_kev_brings_out_of_watchlist_kev():
    wl = Watchlist.model_validate({"alert_all_kev": True})
    v = vuln(vendor_label="Oracle", product_label="WebLogic Server", in_kev=True)
    assert ScopeFilter(wl).evaluate(v).matched_by == "CISA KEV"


def test_out_of_environment_vendor_is_dropped(azure_watchlist):
    v = vuln(affected=[ap("google", "gmail")])
    assert not ScopeFilter(azure_watchlist).evaluate(v).in_scope


def test_exclude_keyword(azure_watchlist):
    v = vuln(
        description="Issue in Google Workspace sync for Microsoft Outlook",
        affected=[ap("microsoft", "outlook")],
    )
    assert not ScopeFilter(azure_watchlist).evaluate(v).in_scope


def test_mixed_products_keep_in_scope_part(azure_watchlist):
    v = vuln(affected=[ap("google", "gmail"), ap("microsoft", "exchange_server")])
    assert ScopeFilter(azure_watchlist).evaluate(v).in_scope


def test_description_fallback_without_cpe(azure_watchlist):
    v = vuln(description="An XSS in Microsoft SharePoint Server allows spoofing.")
    decision = ScopeFilter(azure_watchlist).evaluate(v)
    assert decision.in_scope
    assert "descrição" in decision.matched_by


def test_exclude_product_spec():
    wl = Watchlist.model_validate(
        {
            "vendors": [{"name": "google", "products": []}],
            "exclude": {"products": ["google/chrome_os"]},
        }
    )
    f = ScopeFilter(wl)
    assert not f.evaluate(vuln(affected=[ap("google", "chrome_os")])).in_scope
    assert f.evaluate(vuln(affected=[ap("google", "chrome")])).in_scope


def test_passes_risk():
    t = Thresholds(min_cvss=7.0, min_epss=0.1, include_unscored=False)
    assert passes_risk(vuln(in_kev=True), t)
    assert passes_risk(vuln(cvss_score=7.5), t)
    assert passes_risk(vuln(cvss_score=4.0, epss=0.2), t)
    assert not passes_risk(vuln(cvss_score=5.0, epss=0.01), t)
    assert not passes_risk(vuln(), t)
    assert passes_risk(vuln(), Thresholds(include_unscored=True))


def test_is_recent():
    now = datetime(2026, 11, 16, tzinfo=UTC)
    old = vuln(published_at=now - timedelta(days=400))
    assert not is_recent(old, now, 30)
    new_in_kev = old.model_copy(update={"in_kev": True, "kev_date_added": date(2026, 11, 15)})
    assert is_recent(new_in_kev, now, 30)
    assert is_recent(vuln(published_at=now - timedelta(days=2)), now, 30)
