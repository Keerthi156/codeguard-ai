"""Choose the test-plan provider from settings.

MockProvider is for development only and is used when USE_MOCK_AI is true.
Otherwise the OpenAI-compatible provider is used, which needs a key, model name,
and base URL.
"""

from __future__ import annotations

import httpx

from app.ai.llm_provider import LLMProvider
from app.ai.mock_provider import MockProvider
from app.ai.provider import Provider
from app.config import Settings, credential_names, load_settings


def get_provider(
    settings: Settings | None = None,
    *,
    provider: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> Provider:
    """Return the development mock, or the configured model provider.

    A model failure is not replaced with the mock. The mock is used only when
    USE_MOCK_AI is true. ``provider`` overrides PROVIDER when ``settings`` is omitted.
    Meta, Baseten, and Fireworks all use the OpenAI-compatible provider.
    """
    active = settings if settings is not None else load_settings(provider=provider)
    if active.use_mock_ai:
        return MockProvider()
    names = credential_names(active.provider)
    missing = [
        name
        for name, value in zip(
            names,
            (active.model_api_key, active.model_name, active.model_base_url),
            strict=True,
        )
        if not value.strip()
    ]
    if missing:
        raise RuntimeError(
            "USE_MOCK_AI is false and the model settings are missing: " + ", ".join(missing)
        )
    return LLMProvider(active, transport=transport)
