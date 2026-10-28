"""Tests for environment-backed settings."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import load_settings

_ENV_KEYS = ("MODEL_API_KEY", "MODEL_NAME", "MODEL_BASE_URL", "USE_MOCK_AI")


@pytest.fixture
def clear_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_defaults_when_env_is_empty(clear_model_env: None, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")

    settings = load_settings(env_file)

    assert settings.model_api_key == ""
    assert settings.model_name == ""
    assert settings.model_base_url == ""
    assert settings.use_mock_ai is False


def test_reads_values_from_dotenv_file(clear_model_env: None, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "MODEL_API_KEY=test-key",
                "MODEL_NAME=muse-spark-1.3",
                "MODEL_BASE_URL=http://127.0.0.1:9",
                "USE_MOCK_AI=true",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(env_file)

    assert settings.model_api_key == "test-key"
    assert settings.model_name == "muse-spark-1.3"
    assert settings.model_base_url == "http://127.0.0.1:9"
    assert settings.use_mock_ai is True


def test_process_environment_overrides_dotenv(
    clear_model_env: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("USE_MOCK_AI=true\nMODEL_NAME=from-file\n", encoding="utf-8")
    monkeypatch.setenv("USE_MOCK_AI", "0")
    monkeypatch.setenv("MODEL_NAME", "from-process")

    settings = load_settings(env_file)

    assert settings.use_mock_ai is False
    assert settings.model_name == "from-process"


def test_rejects_invalid_mock_flag(clear_model_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "maybe")

    with pytest.raises(ValueError, match="USE_MOCK_AI"):
        load_settings()
