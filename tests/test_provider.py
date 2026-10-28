"""Test-plan models, the development mock, and provider selection."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.ai.factory import get_provider
from app.ai.mock_provider import MockProvider
from app.ai.provider import Provider
from app.analyzer.auth_checks import assess_routes
from app.config import Settings
from app.schemas import TestCase, TestPlan
from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]

_EXPECTED = [
    ("get-101-owner-alice", "GET", "alice", "101", "allow"),
    ("get-101-non-owner-bob", "GET", "bob", "101", "deny"),
    ("get-202-owner-bob", "GET", "bob", "202", "allow"),
    ("get-202-non-owner-alice", "GET", "alice", "202", "deny"),
    ("put-101-owner-alice", "PUT", "alice", "101", "allow"),
    ("put-101-non-owner-bob", "PUT", "bob", "101", "deny"),
    ("put-202-owner-bob", "PUT", "bob", "202", "allow"),
    ("put-202-non-owner-alice", "PUT", "alice", "202", "deny"),
]


def _sample_case(**overrides: object) -> TestCase:
    values: dict[str, object] = {
        "id": "get-101-owner-alice",
        "route": "/documents/{id}",
        "method": "GET",
        "identity": "alice",
        "resource_id": "101",
        "expected": "allow",
        "reason": "alice owns 101",
    }
    values.update(overrides)
    return TestCase.model_validate(values)


def test_plan_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _sample_case(token="alice-token")
    case = _sample_case()
    with pytest.raises(ValidationError):
        TestPlan.model_validate({"cases": [case.model_dump()], "note": "extra"})


@pytest.mark.parametrize("fixture_name", ["vulnerable", "secure"])
def test_mock_provider_plans_owner_and_non_owner_checks(fixture_name: str) -> None:
    config = load_target_config(ROOT / "fixtures" / f"codeguard.{fixture_name}.yaml")
    findings = assess_routes(ROOT / "fixtures" / f"{fixture_name}_api")

    first = MockProvider().plan_tests(findings, config.matrix())
    second = MockProvider().plan_tests(findings, config.matrix())

    assert first == second
    assert isinstance(MockProvider(), Provider)
    assert [(case.id, case.method, case.identity, case.resource_id, case.expected) for case in first.cases] == _EXPECTED
    assert {case.route for case in first.cases} == {"/documents/{id}"}
    dumped = first.model_dump_json()
    assert "alice-token" not in dumped
    assert "bob-token" not in dumped
    for case in first.cases:
        assert "planned check" in case.reason
        assert case.expected in {"allow", "deny"}


def test_factory_uses_mock_only_for_development() -> None:
    enabled = Settings(model_api_key="", model_name="", model_base_url="", use_mock_ai=True)
    provider = get_provider(enabled)
    assert isinstance(provider, MockProvider)
    assert isinstance(provider, Provider)

    disabled = Settings(model_api_key="", model_name="", model_base_url="", use_mock_ai=False)
    with pytest.raises(RuntimeError, match="development only"):
        get_provider(disabled)
