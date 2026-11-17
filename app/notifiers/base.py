"""Contrato comum dos notifiers.

``send(alert) -> bool`` deve retornar ``True`` somente após confirmação do canal.
"""

from __future__ import annotations

import html
import re
from collections.abc import Callable
from typing import Protocol

from app.models.alert import Alert
from app.notifiers.formatter import format_alert


class Notifier(Protocol):
    def send(self, alert: Alert) -> bool: ...

    def send_text(self, text: str) -> bool: ...


class ConsoleNotifier:
    """Imprime os alertas no terminal (``--dry-run``): nada sai para a rede."""

    def __init__(self, write: Callable[[str], None] = print) -> None:
        self._write = write

    def send(self, alert: Alert) -> bool:
        return self.send_text(format_alert(alert))

    def send_text(self, text: str) -> bool:
        plain = html.unescape(re.sub(r"<[^>]+>", "", text))
        self._write(f"{plain}\n{'-' * 60}")
        return True
