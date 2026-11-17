"""Watchlist: o que é o ambiente monitorado e o que deve ficar de fora.

Carregada de ``WATCHLIST_PATH`` (YAML) com ``yaml.safe_load`` e validada por schema.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from app.core.profiles import PROFILES


class VendorRule(BaseModel):
    name: str
    products: list[str] = Field(default_factory=list)  # vazio = qualquer produto


class Environment(BaseModel):
    name: str = "default"
    profiles: list[str] = Field(default_factory=list)

    @field_validator("profiles")
    @classmethod
    def _known_profiles(cls, value: list[str]) -> list[str]:
        return _validate_profiles(value)


class Exclude(BaseModel):
    profiles: list[str] = Field(default_factory=list)
    vendors: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)  # "vendor/produto" ou "produto"
    keywords: list[str] = Field(default_factory=list)  # buscadas no título/descrição

    @field_validator("profiles")
    @classmethod
    def _known_profiles(cls, value: list[str]) -> list[str]:
        return _validate_profiles(value)


class Thresholds(BaseModel):
    min_cvss: float = Field(default=7.0, ge=0, le=10)
    min_epss: float = Field(default=0.10, ge=0, le=1)
    include_unscored: bool = True  # CVE nova sem CVSS/EPSS ainda → alerta como INFO


class ScoringRules(BaseModel):
    high_cvss: float = Field(default=9.0, ge=0, le=10)
    high_epss: float = Field(default=0.5, ge=0, le=1)
    medium_cvss: float = Field(default=7.0, ge=0, le=10)
    medium_epss: float = Field(default=0.1, ge=0, le=1)


class Watchlist(BaseModel):
    environment: Environment = Field(default_factory=Environment)
    alert_all_kev: bool = False
    vendors: list[VendorRule] = Field(default_factory=list)
    exclude: Exclude = Field(default_factory=Exclude)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    scoring: ScoringRules = Field(default_factory=ScoringRules)
    ecosystems: list[str] = Field(default_factory=list)


def _validate_profiles(value: list[str]) -> list[str]:
    unknown = [p for p in value if p not in PROFILES]
    if unknown:
        raise ValueError(f"perfis desconhecidos: {unknown}. Disponíveis: {sorted(PROFILES)}")
    return value


def load_watchlist(path: Path) -> Watchlist:
    if not path.is_file():
        raise FileNotFoundError(
            f"Watchlist não encontrada em {path}. "
            "Copie config/watchlist.example.yaml para config/watchlist.yaml e ajuste."
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Watchlist.model_validate(data)
