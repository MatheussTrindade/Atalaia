"""Formatação das mensagens de alerta (HTML seguro para o Telegram).

Todo campo vindo das fontes passa por ``html.escape``; links só ``https://``.

    🔴 CRÍTICO · Explorada ativamente (CISA KEV)

    CVE-2026-12345 — Fortinet FortiOS
    🏷️ Execução remota de código
    Heap overflow no SSL-VPN permite RCE sem autenticação.

    📊 CVSS 9.8 · EPSS 0.94 (top 1%)
    ⏰ Prazo CISA para correção: 2026-11-28
    🎯 fortinet/fortios (vendor fortinet)
    🔗 NVD · Advisory do fabricante
"""

from __future__ import annotations

from html import escape, unescape

from app.models.alert import Alert

MAX_DESCRIPTION = 600
TELEGRAM_LIMIT = 4096


def _truncate(text: str, limit: int) -> str:
    # Algumas fontes já mandam entidades HTML (``&ndash;``): normaliza antes de escapar.
    text = " ".join(unescape(text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _link(url: str, label: str) -> str | None:
    if not url.lower().startswith("https://"):
        return None
    return f'<a href="{escape(url, quote=True)}">{escape(label)}</a>'


def _advisory_url(alert: Alert) -> str | None:
    refs = alert.vulnerability.references
    for wanted in ("Vendor Advisory", "Patch"):
        for ref in refs:
            if wanted in ref.tags and ref.url.lower().startswith("https://"):
                return ref.url
    return None


def format_alert(alert: Alert) -> str:
    v = alert.vulnerability
    lines = [f"{alert.severity.emoji} <b>{alert.severity.label}</b> · {escape(alert.reasons[0])}"]
    lines.append("")

    header = f"<b>{escape(v.cve_id)}</b>"
    if v.display_name:
        header += f" — {escape(_truncate(v.display_name, 120))}"
    lines.append(header)
    lines.append(f"🏷️ {escape(alert.category)}")
    if v.title and v.title not in v.description:
        lines.append(f"<i>{escape(_truncate(v.title, 200))}</i>")
    if v.description:
        lines.append(escape(_truncate(v.description, MAX_DESCRIPTION)))
    lines.append("")

    metrics = []
    if v.cvss_score is not None:
        version = f" v{v.cvss_version}" if v.cvss_version else ""
        metrics.append(f"CVSS{version} {v.cvss_score:.1f}")
    if v.epss is not None:
        epss = f"EPSS {v.epss:.2f}"
        if v.epss_percentile is not None:
            top = max(1, round((1 - v.epss_percentile) * 100))
            epss += f" (top {top}%)"
        metrics.append(epss)
    if metrics:
        lines.append("📊 " + " · ".join(metrics))
    if v.kev_due_date:
        lines.append(f"⏰ Prazo CISA para correção: {v.kev_due_date.isoformat()}")
    if v.kev_ransomware:
        lines.append("☠️ Usada em campanhas de ransomware")
    for extra in alert.reasons[1:]:
        if "ransomware" not in extra.lower():
            lines.append(f"• {escape(extra)}")
    if alert.matched_by:
        lines.append(f"🎯 {escape(alert.matched_by)}")

    links = [_link(f"https://nvd.nist.gov/vuln/detail/{v.cve_id}", "NVD")]
    if advisory := _advisory_url(alert):
        links.append(_link(advisory, "Advisory do fabricante"))
    lines.append("🔗 " + " · ".join(link for link in links if link))

    message = "\n".join(lines)
    if len(message) > TELEGRAM_LIMIT:  # salvaguarda: descrição já é truncada antes
        message = message[: TELEGRAM_LIMIT - 1]
    return message


def format_overflow(alerts: list[Alert]) -> str:
    """Resumo dos alertas que passaram do limite por execução (evita flood)."""
    lines = [f"📋 <b>+{len(alerts)} alertas de menor prioridade nesta rodada</b>", ""]
    for a in alerts[:40]:
        name = f" — {escape(a.vulnerability.display_name)}" if a.vulnerability.display_name else ""
        lines.append(f"{a.severity.emoji} {escape(a.vulnerability.cve_id)}{name}")
    if len(alerts) > 40:
        lines.append(f"… e mais {len(alerts) - 40}")
    return "\n".join(lines)
