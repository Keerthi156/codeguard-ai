"""Choose the test-plan provider from settings.

MockProvider is for development only and is used when USE_MOCK_AI is true.
"""

from __future__ import annotations

from app.ai.mock_provider import MockProvider
from app.ai.provider import Provider
from app.config import Settings, load_settings


def get_provider(settings: Settings | None = None) -> Provider:
    """Return the development mock, or refuse it when the real model should be used."""
    active = settings if settings is not None else load_settings()
    if active.use_mock_ai:
        return MockProvider()
    raise RuntimeError("MockProvider is for development only and USE_MOCK_AI is false.")
