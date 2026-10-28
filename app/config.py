"""Runtime settings loaded from the process environment and a local .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"Invalid boolean for {name}: {raw}")


@dataclass(frozen=True)
class Settings:
    model_api_key: str = field(repr=False)
    model_name: str
    model_base_url: str
    use_mock_ai: bool


def load_settings(env_file: str | Path | None = None) -> Settings:
    """Load settings. Existing process environment variables take precedence over the file."""
    load_dotenv(dotenv_path=env_file, override=False)
    return Settings(
        model_api_key=os.getenv("MODEL_API_KEY", ""),
        model_name=os.getenv("MODEL_NAME", ""),
        model_base_url=os.getenv("MODEL_BASE_URL", ""),
        use_mock_ai=_env_flag("USE_MOCK_AI", default=False),
    )
