"""Entrypoint da aplicação.

- Carrega configurações e watchlist e falha cedo se algo obrigatório faltar.
- Configura o logging com redação de segredos.
- Executa o pipeline em loop (``POLL_INTERVAL_MINUTES``) ou uma vez (``--once``).
- ``--dry-run``: imprime os alertas no terminal, sem Telegram e sem gravar estado.
- Encerra de forma limpa em SIGINT/SIGTERM.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from datetime import timedelta

from app.collectors.cisa_kev import CisaKevCollector
from app.collectors.nvd import NvdCollector
from app.config.settings import Settings
from app.config.watchlist import load_watchlist
from app.core.pipeline import Pipeline
from app.enrichers.epss import EpssEnricher
from app.notifiers.base import ConsoleNotifier, Notifier
from app.notifiers.telegram import TelegramNotifier
from app.storage.state import StateStore
from app.utils.http import build_session
from app.utils.logger import setup_logging

log = logging.getLogger("app")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="atalaia", description="Alertas de vulnerabilidades")
    parser.add_argument("--once", action="store_true", help="executa uma única rodada e sai")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="imprime os alertas no terminal; não envia ao Telegram nem grava estado",
    )
    return parser.parse_args(argv)


def build_pipeline(settings: Settings, dry_run: bool) -> Pipeline:
    watchlist = load_watchlist(settings.watchlist_path)
    session = build_session(timeout=settings.http_timeout_seconds)

    notifier: Notifier
    if dry_run:
        notifier = ConsoleNotifier()
        state = StateStore(":memory:")
    else:
        if settings.telegram_token is None or not settings.telegram_chat_id:
            raise SystemExit(
                "TELEGRAM_TOKEN e TELEGRAM_CHAT_ID são obrigatórios (ou use --dry-run)"
            )
        notifier = TelegramNotifier(session, settings.telegram_token, settings.telegram_chat_id)
        state = StateStore(settings.db_path)

    return Pipeline(
        kev=CisaKevCollector(session),
        nvd=NvdCollector(session, api_key=settings.nvd_api_key),
        epss=EpssEnricher(session),
        notifier=notifier,
        state=state,
        watchlist=watchlist,
        initial_lookback=timedelta(days=settings.initial_lookback_days),
        cve_max_age_days=settings.cve_max_age_days,
        max_alerts_per_run=settings.max_alerts_per_run,
    )


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    settings = Settings()
    setup_logging(settings.log_level, secrets=settings.secret_values())

    try:
        pipeline = build_pipeline(settings, dry_run=args.dry_run)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Configuração inválida: %s", exc)
        sys.exit(2)

    if args.once or args.dry_run:
        report = pipeline.run_once()
        sys.exit(1 if report.failed else 0)

    stop = threading.Event()

    def _handle(signum: int, _frame: object) -> None:
        log.info("Sinal %s recebido, encerrando…", signum)
        stop.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    interval = settings.poll_interval_minutes * 60
    log.info("Atalaia em vigia: rodada a cada %d min", settings.poll_interval_minutes)
    while not stop.is_set():
        try:
            pipeline.run_once()
        except Exception:  # um erro inesperado não pode derrubar a vigia
            log.exception("Erro inesperado na rodada")
        stop.wait(interval)
    pipeline.state.close()
