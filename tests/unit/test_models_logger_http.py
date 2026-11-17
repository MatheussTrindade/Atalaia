import logging

import pytest
from pydantic import ValidationError

from app.models.vulnerability import AffectedProduct, Vulnerability
from app.utils.http import USER_AGENT, build_session
from app.utils.logger import MASK, RedactingFormatter

FAKE_TOKEN = "123456789:AAH" + "x" * 32


def test_cve_id_validation():
    assert Vulnerability(cve_id=" cve-2026-12345 ").cve_id == "CVE-2026-12345"
    with pytest.raises(ValidationError):
        Vulnerability(cve_id="CVE-26-1")


def test_merge_keeps_and_combines():
    kev = Vulnerability(cve_id="CVE-2026-1111", in_kev=True, sources={"cisa_kev"}, cwes=["CWE-1"])
    nvd = Vulnerability(
        cve_id="CVE-2026-1111",
        cvss_score=9.1,
        sources={"nvd"},
        cwes=["CWE-1", "CWE-2"],
        affected=[AffectedProduct(vendor="a", product="b")],
    )
    merged = kev.merge(nvd)
    assert merged.in_kev
    assert merged.cvss_score == 9.1
    assert merged.sources == {"cisa_kev", "nvd"}
    assert merged.cwes == ["CWE-1", "CWE-2"]


def test_logger_redacts_token_pattern_and_secrets():
    fmt = RedactingFormatter("%(message)s", secrets=["supersecretkey"])
    record = logging.LogRecord(
        "x",
        logging.INFO,
        "",
        0,
        "url https://api.telegram.org/bot%s/send key=%s",
        (FAKE_TOKEN, "supersecretkey"),
        None,
    )
    out = fmt.format(record)
    assert FAKE_TOKEN not in out
    assert "supersecretkey" not in out
    assert out.count(MASK) == 2


def test_session_defaults_and_blocks_verify_false():
    session = build_session()
    assert session.headers["User-Agent"] == USER_AGENT
    with pytest.raises(ValueError, match="verify=False"):
        session.get("https://example.com", verify=False)  # noqa: S501
