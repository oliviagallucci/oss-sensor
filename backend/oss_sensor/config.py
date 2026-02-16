"""Configuration and license-aware storage mode."""

from enum import Enum
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class StorageMode(str, Enum):
    """License-aware storage: what we persist from ingested source/binary/logs."""

    DERIVED_FEATURES_ONLY = "derived_features_only"  # Only extracted features, no raw source/code
    FULL_SOURCE_INTERNAL = "full_source_internal"  # Store full source/code (internal use only)


class Settings(BaseSettings):
    """App settings; env vars override defaults."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    storage_mode: StorageMode = StorageMode.DERIVED_FEATURES_ONLY
    database_url: str = "sqlite+aiosqlite:///./data/oss_sensor.db"
    # Optional LLM: empty = rules-only (no LLM). e.g. "openai", "anthropic"
    llm_provider: str = ""
    llm_api_key: str = ""
    llm_model: str = ""

