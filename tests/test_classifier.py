"""Classification of fixture test results."""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

import fixtures.secure_api.app as secure_api
import fixtures.vulnerable_api.app as vulnerable_api
from app.ai.mock_provider import MockProvider
from app.analyzer.auth_checks import RouteFinding, assess_routes
from app.findings.classifier import classify, evidence_line
from app.runner.executor import TestResult, execute_plan
from app.schemas import Resource, User, default_owner_only_matrix
from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _reset(module: object) -> None:
    documents = module.DOCUMENTS
    documents.clear()
    documents[101] = module.Document(id=101, owner="alice", title="Alice notes", content="alice-private")
    documents[202] = module.Document(id=202, owner="bob", title="Bob notes", content="bob-private")


async def _executed(fixture_name: str, module: object):
    _reset(module)
    config = load_target_config(ROOT / "fixtures" / f"codeguard.{fixture_name}.yaml")
    route_findings = assess_routes(ROOT / "fixtures" / f"{fixture_name}_api")
    cases = MockProvider().plan_tests(route_findings, config.matrix()).cases
    results = await execute_plan(cases, config, transport=httpx.ASGITransport(app=module.app))
    return route_findings, results, config.matrix()


def _is_owner_result(result: TestResult) -> bool:
    return "-owner-" in result.test_id and "non-owner" not in result.test_id


async def test_vulnerable_routes_are_confirmed() -> None:
    route_findings, results, matrix = await _executed("vulnerable", vulnerable_api)

    findings = classify(route_findings, results, matrix)

    by_method = {finding.method: finding for finding in findings}
    assert set(by_method) == {"GET", "PUT"}
    for finding in findings:
        assert finding.route == "/documents/{id}"
        assert finding.status == "Confirmed"
        assert finding.evidence
        exploit = evidence_line(finding.evidence[0])
        assert exploit == (
            f"EXPLOIT: {finding.method} /documents/101 as bob -> 200, body shows owner alice"
        )
        assert evidence_line(finding.evidence[1]) == (
            f"CONTROL: {finding.method} /documents/101 as alice -> 200 (owner access works)"
        )
        assert finding.evidence[0].identity == "bob"
        assert len(finding.evidence[0].body) <= 300
        assert finding.source_lines
        assert finding.created_at.tzinfo is not None
        assert finding.target_revision is None or re.fullmatch(r"[0-9a-f]{7,64}", finding.target_revision)
        assert "alice-token" not in finding.model_dump_json()


async def test_secure_fixture_has_no_confirmed_finding() -> None:
    route_findings, results, matrix = await _executed("secure", secure_api)

    findings = classify(route_findings, results, matrix)

    assert all(finding.status != "Confirmed" for finding in findings)


async def test_failing_owner_control_is_inconclusive() -> None:
    route_findings, results, matrix = await _executed("vulnerable", vulnerable_api)
    mutated = [
        result.model_copy(
            update={
                "outcome": "fail",
                "access": "denied",
                "matches_expected": False,
                "status_code": 404,
                "evidence": result.evidence.model_copy(update={"status_code": 404, "body": "not found"}),
            }
        )
        if _is_owner_result(result)
        else result
        for result in results
    ]

    findings = classify(route_findings, mutated, matrix)

    assert findings
    assert {finding.status for finding in findings} == {"Inconclusive"}


async def test_server_error_is_inconclusive() -> None:
    route_findings, results, matrix = await _executed("vulnerable", vulnerable_api)
    mutated: list[TestResult] = []
    marked = False
    for result in results:
        if not marked and result.evidence.method == "GET":
            mutated.append(
                result.model_copy(
                    update={
                        "outcome": "inconclusive",
                        "access": None,
                        "matches_expected": None,
                        "status_code": 500,
                        "evidence": result.evidence.model_copy(update={"status_code": 500, "body": "unavailable"}),
                    }
                )
            )
            marked = True
            continue
        mutated.append(result)

    findings = classify(route_findings, mutated, matrix)

    get_finding = next(finding for finding in findings if finding.method == "GET")
    assert get_finding.status == "Inconclusive"


def test_correctly_denied_attacks_are_not_reproduced() -> None:
    matrix = default_owner_only_matrix().model_copy(
        update={
            "users": [User(name="alice", token="alice-token"), User(name="bob", token="bob-token")],
            "resources": [Resource(id="101", owner="alice")],
        }
    )
    route = RouteFinding(
        file="app.py",
        function_name="get_document",
        method="GET",
        path="/documents/{id}",
        status="Suspected",
        reason="Static indicator only.",
        confidence="medium",
        line_numbers=[74, 77],
    )
    owner = _result("get-101-owner-alice", "alice", "/documents/101", 200, "allowed", True, "pass")
    other = _result("get-101-non-owner-bob", "bob", "/documents/101", 404, "denied", True, "pass")

    findings = classify([route], [owner, other], matrix)

    assert len(findings) == 1
    assert findings[0].status == "Suspected"
    assert findings[0].reason == "Suspected, not reproduced"


def _result(
    test_id: str,
    identity: str,
    path: str,
    status_code: int,
    access: str,
    matches: bool,
    outcome: str,
) -> TestResult:
    from app.runner.executor import Evidence

    return TestResult(
        test_id=test_id,
        status_code=status_code,
        access=access,  # type: ignore[arg-type]
        matches_expected=matches,
        outcome=outcome,  # type: ignore[arg-type]
        evidence=Evidence(
            method="GET",
            path=path,
            identity=identity,
            status_code=status_code,
            body="body",
        ),
    )
