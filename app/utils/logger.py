"""Logging estruturado com redação de segredos.

A redação é feita no *formatter*, ou seja, sobre a linha final — inclusive tracebacks,
onde a URL da API do Telegram (que contém o token) costuma vazar.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable

# Formato do token de bot do Telegram: <bot_id>:<35 chars>. Sem ``\b`` no início:
# na URL da API o token vem colado em ``bot`` (``/bot123:AA...``).
TELEGRAM_TOKEN_RE = re.compile(r"(?<!\d)\d{6,12}:[A-Za-z0-9_-]{30,}")
MASK = "***REDACTED***"


class RedactingFormatter(logging.Formatter):
    """Formatter que mascara segredos conhecidos e padrões de token."""

    def __init__(self, fmt: str, secrets: Iterable[str] = ()) -> None:
        super().__init__(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")
        # Ignora valores curtos para não mascarar trechos aleatórios do log.
        self._secrets = sorted({s for s in secrets if s and len(s) >= 8}, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, MASK)
        return TELEGRAM_TOKEN_RE.sub(MASK, text)

    def format(self, record: logging.LogRecord) -> str:
        return self.redact(super().format(record))


def setup_logging(level: str = "INFO", secrets: Iterable[str] = ()) -> None:
    """Configura o logger raiz com nível configurável e redação de segredos."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        RedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s", secrets=secrets)
    )
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
    # urllib3 loga URLs completas em DEBUG — mantemos em WARNING por segurança.
    logging.getLogger("urllib3").setLevel(logging.WARNING)
