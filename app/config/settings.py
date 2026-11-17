"""Configurações tipadas via variáveis de ambiente (pydantic-settings).

Regras de segurança:
- Segredos (tokens, API keys) chegam SOMENTE por variável de ambiente / ``.env``.
- Segredos usam ``SecretStr`` para nunca aparecerem em ``repr``/logs.
- Nenhum valor sensível tem default no código.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Telegram (obrigatório fora do --dry-run) ---
    telegram_token: SecretStr | None = None
    telegram_chat_id: str | None = None

    # --- Fontes ---
    nvd_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None

    # --- Execução ---
    poll_interval_minutes: int = Field(default=30, ge=5)
    log_level: str = "INFO"
    db_path: Path = Path("data/atalaia.db")
    watchlist_path: Path = Path("config/watchlist.yaml")
    http_timeout_seconds: float = Field(default=30.0, gt=0)

    # --- Janela e volume ---
    initial_lookback_days: int = Field(default=3, ge=1, le=120)
    cve_max_age_days: int = Field(default=30, ge=1)
    max_alerts_per_run: int = Field(default=15, ge=1)

    @field_validator(
        "telegram_token",
        "telegram_chat_id",
        "nvd_api_key",
        "github_token",
        "abusech_auth_key",
        mode="before",
    )
    @classmethod
    def _empty_as_none(cls, value: object) -> object:
        # Linhas vazias do .env.example (``NVD_API_KEY=``) viram None, não segredo vazio.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    def secret_values(self) -> list[str]:
        """Valores sensíveis em claro, apenas para alimentar a redação do logger."""
        secrets = [self.telegram_token, self.nvd_api_key, self.github_token, self.abusech_auth_key]
        return [s.get_secret_value() for s in secrets if s is not None]
