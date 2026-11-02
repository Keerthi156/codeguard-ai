"""Runtime settings loaded from the process environment and a local .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_PROVIDERS = ("meta", "baseten", "fireworks")


def credential_names(provider: str) -> tuple[str, str, str]:
    """Environment variable names for the key, model, and base URL.

    An empty provider keeps the original MODEL_* names.
    """
    if not provider:
        return ("MODEL_API_KEY", "MODEL_NAME", "MODEL_BASE_URL")
    prefix = provider.upper()
    return (f"{prefix}_API_KEY", f"{prefix}_MODEL", f"{prefix}_BASE_URL")


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
    provider: str = ""


def load_settings(env_file: str | Path | None = None, *, provider: str | None = None) -> Settings:
    """Load settings. Existing process environment variables take precedence over the file.

    ``provider`` overrides PROVIDER. When neither is set, MODEL_API_KEY, MODEL_NAME,
    and MODEL_BASE_URL are used and ``provider`` on the result stays empty.
    """
    load_dotenv(dotenv_path=env_file, override=False)
    selected = _provider_name(provider)
    use_mock_ai = _env_flag("USE_MOCK_AI", default=False)
    if not selected:
        return Settings(
            model_api_key=os.getenv("MODEL_API_KEY", ""),
            model_name=os.getenv("MODEL_NAME", ""),
            model_base_url=os.getenv("MODEL_BASE_URL", ""),
            use_mock_ai=use_mock_ai,
        )
    key_name, model_name, url_name = credential_names(selected)
    return Settings(
        model_api_key=os.getenv(key_name, ""),
        model_name=os.getenv(model_name, ""),
        model_base_url=os.getenv(url_name, ""),
        use_mock_ai=use_mock_ai,
        provider=selected,
    )


def _provider_name(override: str | None) -> str:
    """Return a known provider, or '' to keep the MODEL_* fallback."""
    raw = os.getenv("PROVIDER") if override is None else override
    if raw is None or raw.strip() == "":
        return ""
    name = raw.strip().lower()
    if name not in _PROVIDERS:
        raise ValueError("Invalid PROVIDER. Use meta, baseten, or fireworks.")
    return name
