"""Estado persistente em SQLite (``DB_PATH``) — ADR-0002.

Tabelas:
- ``checkpoints``: último instante processado de cada coletor.
- ``alerts``: maior severidade já enviada por CVE. Só realerta se a severidade SUBIR
  (ex.: CVE avisada como ALTO entra no KEV → novo alerta CRÍTICO).
- ``catalog``: catálogo de toda vuln que caiu no escopo do ambiente, com categoria e
  severidade — inclusive as que não viraram alerta por estarem abaixo dos limiares.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from app.models.alert import Alert, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    source     TEXT PRIMARY KEY,
    value      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    cve_id         TEXT PRIMARY KEY,
    severity       TEXT NOT NULL,
    source         TEXT NOT NULL,
    first_sent_at  TEXT NOT NULL,
    last_sent_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog (
    cve_id         TEXT PRIMARY KEY,
    title          TEXT,
    product        TEXT,
    category       TEXT NOT NULL,
    severity       TEXT NOT NULL,
    cvss           REAL,
    epss           REAL,
    in_kev         INTEGER NOT NULL,
    matched_by     TEXT,
    sources        TEXT NOT NULL,
    published_at   TEXT,
    first_seen_at  TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL
);
"""

UPSERT_CATALOG = (
    "INSERT INTO catalog (cve_id, title, product, category, severity, cvss, epss, "
    "in_kev, matched_by, sources, published_at, first_seen_at, last_seen_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT(cve_id) DO UPDATE SET title = excluded.title, "
    "product = excluded.product, category = excluded.category, "
    "severity = excluded.severity, cvss = excluded.cvss, epss = excluded.epss, "
    "in_kev = excluded.in_kev, matched_by = excluded.matched_by, "
    "sources = excluded.sources, published_at = excluded.published_at, "
    "last_seen_at = excluded.last_seen_at"
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class StateStore:
    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------ checkpoints
    def get_checkpoint(self, source: str) -> datetime | None:
        row = self.conn.execute(
            "SELECT value FROM checkpoints WHERE source = ?", (source,)
        ).fetchone()
        return datetime.fromisoformat(row["value"]) if row else None

    def set_checkpoint(self, source: str, value: datetime) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO checkpoints (source, value) VALUES (?, ?) "
                "ON CONFLICT(source) DO UPDATE SET value = excluded.value",
                (source, value.isoformat()),
            )

    # ------------------------------------------------------------ dedupe
    def sent_severity(self, cve_id: str) -> Severity | None:
        row = self.conn.execute(
            "SELECT severity FROM alerts WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return Severity(row["severity"]) if row else None

    def should_alert(self, alert: Alert) -> bool:
        previous = self.sent_severity(alert.vulnerability.cve_id)
        return previous is None or alert.severity.rank > previous.rank

    def mark_sent(self, alert: Alert) -> None:
        now = _now()
        with self.conn:
            self.conn.execute(
                "INSERT INTO alerts (cve_id, severity, source, first_sent_at, last_sent_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(cve_id) DO UPDATE SET severity = excluded.severity, "
                "source = excluded.source, last_sent_at = excluded.last_sent_at",
                (alert.vulnerability.cve_id, alert.severity.value, alert.source, now, now),
            )

    # ------------------------------------------------------------ catálogo
    def upsert_catalog(self, alerts: list[Alert]) -> None:
        now = _now()
        rows = [
            (
                a.vulnerability.cve_id,
                a.vulnerability.title,
                a.vulnerability.display_name,
                a.category,
                a.severity.value,
                a.vulnerability.cvss_score,
                a.vulnerability.epss,
                int(a.vulnerability.in_kev),
                a.matched_by,
                json.dumps(sorted(a.vulnerability.sources)),
                a.vulnerability.published_at.isoformat() if a.vulnerability.published_at else None,
                now,
                now,
            )
            for a in alerts
        ]
        with self.conn:
            self.conn.executemany(UPSERT_CATALOG, rows)

    def catalog_rows(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM catalog ORDER BY last_seen_at DESC").fetchall()
