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
    # Optional LLM: empty = rules-only (no LLM). Use "openai" or "anthropic".
    # API key: LLM_API_KEY is used if set; else OPENAI_API_KEY / ANTHROPIC_API_KEY per provider.
    llm_provider: str = ""
    llm_api_key: str = ""
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    llm_model: str = ""  # e.g. "gpt-4o-mini", "claude-3-5-sonnet-20241022"; default per provider if empty
    llm_timeout_seconds: float = 60.0

    def get_llm_api_key(self) -> str:
        """Return the API key for the configured provider (LLM_API_KEY or provider-specific)."""
        if self.llm_api_key:
            return self.llm_api_key
        if self.llm_provider == "openai":
            return self.openai_api_key
        if self.llm_provider == "anthropic":
            return self.anthropic_api_key
        return ""

