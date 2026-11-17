"""Cliente HTTP seguro e centralizado.

Padrões obrigatórios:
- TLS SEMPRE verificado. Proibido ``verify=False``; atrás de proxy corporativo,
  use ``REQUESTS_CA_BUNDLE`` ou ``truststore``.
- Timeout em toda requisição.
- Retry com backoff exponencial para 429/5xx.
- User-Agent honesto, identificando o projeto.
"""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app import __version__

USER_AGENT = f"Atalaia/{__version__} (+https://github.com/MatheussTrindade/Atalaia)"
DEFAULT_TIMEOUT = 30.0


class SecureSession(requests.Session):
    """``requests.Session`` com timeout padrão e bloqueio de ``verify=False``."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        super().__init__()
        self._timeout = timeout

    def request(self, method: str | bytes, url: str | bytes, *args: Any, **kwargs: Any):  # type: ignore[override]
        if kwargs.get("verify") is False:
            raise ValueError("verify=False é proibido: TLS deve ser sempre verificado")
        kwargs.setdefault("timeout", self._timeout)
        return super().request(method, url, *args, **kwargs)


def build_session(timeout: float = DEFAULT_TIMEOUT, retries: int = 4) -> SecureSession:
    """Cria uma sessão com TLS verificado, timeout, retry/backoff e User-Agent do projeto.

    O retry automático cobre apenas ``GET`` (idempotente). Envios (POST) tratam
    ``429``/``retry_after`` no próprio notifier.
    """
    session = SecureSession(timeout=timeout)
    retry = Retry(
        total=retries,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
    return session
