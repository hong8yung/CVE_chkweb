from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import dotenv_values


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str
    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_password: str
    initial_lookback_years: int
    incremental_window_days: int
    nvd_results_per_page: int
    nvd_timeout_seconds: int


def _load_config(config_path: str) -> dict[str, str]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}. Copy .env.sample to .env and fill values."
        )
    raw_values: dict[str, Any] = dotenv_values(path)
    return {key: ("" if value is None else str(value)) for key, value in raw_values.items()}


def _require(config: dict[str, str | None], key: str) -> str:
    value = (config.get(key) or "").strip()
    if not value:
        raise ValueError(f"Missing required setting: {key}")
    return value


def _get_int(config: dict[str, str | None], key: str, default: int) -> int:
    raw = (config.get(key) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid integer setting {key}: {raw}") from exc


def load_settings(config_path: str = ".env") -> Settings:
    config = _load_config(config_path)

    return Settings(
        nvd_api_key=_require(config, "NVD_API_KEY"),
        db_host=_require(config, "DB_HOST"),
        db_port=_get_int(config, "DB_PORT", 5432),
        db_name=_require(config, "DB_NAME"),
        db_user=_require(config, "DB_USER"),
        db_password=_require(config, "DB_PASSWORD"),
        initial_lookback_years=_get_int(config, "INITIAL_LOOKBACK_YEARS", 5),
        incremental_window_days=_get_int(config, "INCREMENTAL_WINDOW_DAYS", 14),
        nvd_results_per_page=_get_int(config, "NVD_RESULTS_PER_PAGE", 2000),
        nvd_timeout_seconds=_get_int(config, "NVD_TIMEOUT_SECONDS", 30),
    )


def load_nvd_api_key(config_path: str = ".env") -> str:
    config = _load_config(config_path)
    return _require(config, "NVD_API_KEY")
