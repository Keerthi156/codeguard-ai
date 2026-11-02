"""Tests for environment-backed settings."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.config import load_settings

_ENV_KEYS = (
    "PROVIDER",
    "MODEL_API_KEY",
    "MODEL_NAME",
    "MODEL_BASE_URL",
    "USE_MOCK_AI",
    "META_API_KEY",
    "META_MODEL",
    "META_BASE_URL",
    "BASETEN_API_KEY",
    "BASETEN_MODEL",
    "BASETEN_BASE_URL",
    "FIREWORKS_API_KEY",
    "FIREWORKS_MODEL",
    "FIREWORKS_BASE_URL",
)


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


def test_settings_display_hides_api_key(clear_model_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MODEL_API_KEY", "fake-secret-key-9f3a")

    settings = load_settings()

    assert "fake-secret-key-9f3a" not in repr(settings)
    assert "fake-secret-key-9f3a" not in str(settings)


def test_rejects_invalid_mock_flag(clear_model_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "maybe")

    with pytest.raises(ValueError, match="USE_MOCK_AI"):
        load_settings()


def test_named_provider_reads_its_own_block(clear_model_env: None, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "PROVIDER=meta",
                "META_API_KEY=meta-secret-key-99",
                "META_MODEL=meta-model",
                "META_BASE_URL=http://meta.test/v1",
                "MODEL_API_KEY=model-secret-key-99",
                "MODEL_NAME=fallback-model",
                "MODEL_BASE_URL=http://fallback.test/v1",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(env_file)

    assert settings.provider == "meta"
    assert settings.model_api_key == "meta-secret-key-99"
    assert settings.model_name == "meta-model"
    assert settings.model_base_url == "http://meta.test/v1"
    shown = repr(settings) + str(settings)
    assert "meta-secret-key-99" not in shown
    assert "model-secret-key-99" not in shown


def test_provider_argument_overrides_provider_in_the_file(clear_model_env: None, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "PROVIDER=baseten",
                "BASETEN_API_KEY=baseten-secret-key-99",
                "BASETEN_MODEL=baseten-model",
                "BASETEN_BASE_URL=http://baseten.test/v1",
                "FIREWORKS_API_KEY=fireworks-secret-key-99",
                "FIREWORKS_MODEL=fireworks-model",
                "FIREWORKS_BASE_URL=http://fireworks.test/v1",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(env_file, provider="fireworks")

    assert settings.provider == "fireworks"
    assert settings.model_name == "fireworks-model"
    assert settings.model_base_url == "http://fireworks.test/v1"
    assert "baseten-secret-key-99" not in repr(settings)
    assert "fireworks-secret-key-99" not in repr(settings)


def test_unset_provider_keeps_the_model_fallback(clear_model_env: None, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "MODEL_API_KEY=model-secret-key-99",
                "MODEL_NAME=fallback-model",
                "MODEL_BASE_URL=http://fallback.test/v1",
                "META_API_KEY=meta-secret-key-99",
                "META_MODEL=meta-model",
                "META_BASE_URL=http://meta.test/v1",
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings(env_file)

    assert settings.provider == ""
    assert settings.model_api_key == "model-secret-key-99"
    assert settings.model_name == "fallback-model"
    assert settings.model_base_url == "http://fallback.test/v1"
    assert "model-secret-key-99" not in repr(settings)
    assert "meta-secret-key-99" not in repr(settings)


def test_invalid_provider_names_no_secret(clear_model_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROVIDER", "meta-secret-key-99")

    with pytest.raises(ValueError, match="Invalid PROVIDER") as raised:
        load_settings()

    assert "meta-secret-key-99" not in str(raised.value)
