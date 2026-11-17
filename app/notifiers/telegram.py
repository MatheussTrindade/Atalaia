"""Notifier do Telegram (Bot API).

Regras de segurança:
- Nunca logar o token nem a URL da API (o token faz parte da URL).
- Conteúdo externo sempre escapado (``parse_mode=HTML``).
- Validar a resposta (``ok: true``) antes de considerar o envio feito.
- Respeitar o rate limit (~20 msgs/min por grupo) e o ``retry_after`` do HTTP 429.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import requests
from pydantic import SecretStr

from app.models.alert import Alert
from app.notifiers.formatter import format_alert

log = logging.getLogger(__name__)

API_BASE = "https://api.telegram.org"
MIN_INTERVAL = 3.1  # ~19 msgs/min, abaixo do limite de grupo
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER = 120


class TelegramNotifier:
    def __init__(
        self,
        session: requests.Session,
        token: SecretStr,
        chat_id: str,
        min_interval: float = MIN_INTERVAL,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.session = session
        self._token = token
        self.chat_id = chat_id
        self.min_interval = min_interval
        self._sleep = sleep
        self._clock = clock
        self._last_sent: float | None = None

    def _url(self, method: str) -> str:
        return f"{API_BASE}/bot{self._token.get_secret_value()}/{method}"

    def _throttle(self) -> None:
        if self._last_sent is not None:
            wait = self.min_interval - (self._clock() - self._last_sent)
            if wait > 0:
                self._sleep(wait)

    def send(self, alert: Alert) -> bool:
        return self.send_text(format_alert(alert))

    def send_text(self, text: str) -> bool:
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._throttle()
            try:
                resp = self.session.post(self._url("sendMessage"), json=payload)
            except requests.RequestException as exc:
                # A mensagem da exceção contém a URL (com token): logamos só o tipo.
                log.warning(
                    "Telegram: falha de rede (%s), tentativa %d", type(exc).__name__, attempt
                )
                self._sleep(2**attempt)
                continue
            finally:
                self._last_sent = self._clock()

            try:
                data = resp.json()
            except ValueError:
                data = {}

            if resp.status_code == 429:
                retry_after = int(data.get("parameters", {}).get("retry_after", 5))
                log.warning("Telegram: rate limit, aguardando %ss", retry_after)
                self._sleep(min(retry_after, MAX_RETRY_AFTER))
                continue
            if resp.ok and data.get("ok") is True:
                return True
            log.error(
                "Telegram recusou a mensagem: HTTP %s — %s",
                resp.status_code,
                str(data.get("description", "sem descrição"))[:200],
            )
            if resp.status_code < 500:
                return False  # 4xx (exceto 429) não melhora com retry
            self._sleep(2**attempt)
        return False
