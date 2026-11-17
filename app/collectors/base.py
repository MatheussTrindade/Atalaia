"""Contrato comum dos coletores.

Todo coletor deve:
- Usar o cliente HTTP seguro de ``app.utils.http`` (TLS verificado, timeout, retry).
- Respeitar rate limits e os termos de uso da fonte.
- Retornar modelos normalizados (``app.models``), nunca JSON cru.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from app.models.vulnerability import Vulnerability


class SourceError(RuntimeError):
    """Falha ao consultar ou interpretar uma fonte (isolada pelo pipeline)."""


class Collector(Protocol):
    name: str

    def collect(self, since: datetime, until: datetime) -> list[Vulnerability]:
        """Itens novos/alterados na janela ``[since, until]``."""
        ...
