"""Fixtures compartilhadas do pytest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config.watchlist import Watchlist

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def azure_watchlist() -> Watchlist:
    """Ambiente Azure + M365 + Windows, sem Google Workspace."""
    return Watchlist.model_validate(
        {
            "environment": {"name": "teste", "profiles": ["azure", "microsoft365", "windows"]},
            "alert_all_kev": False,
            "vendors": [{"name": "fortinet", "products": ["fortios"]}],
            "exclude": {"profiles": ["google_workspace"], "keywords": ["google workspace"]},
        }
    )
