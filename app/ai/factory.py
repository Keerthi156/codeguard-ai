"""Choose the test-plan provider from settings.

MockProvider is for development only and is used when USE_MOCK_AI is true.
Otherwise the OpenAI-compatible provider is used, which needs a key, model name,
and base URL.
"""

from __future__ import annotations

from app.ai.llm_provider import LLMProvider
from app.ai.mock_provider import MockProvider
from app.ai.provider import Provider
from app.config import Settings, load_settings


def get_provider(settings: Settings | None = None) -> Provider:
    """Return the development mock, or the configured model provider."""
    active = settings if settings is not None else load_settings()
    if active.use_mock_ai:
        return MockProvider()
    missing = [
        name
        for name, value in (
            ("MODEL_API_KEY", active.model_api_key),
            ("MODEL_NAME", active.model_name),
            ("MODEL_BASE_URL", active.model_base_url),
        )
        if not value.strip()
    ]
    if missing:
        raise RuntimeError(
            "USE_MOCK_AI is false and the model settings are missing: " + ", ".join(missing)
        )
    return LLMProvider(active)
