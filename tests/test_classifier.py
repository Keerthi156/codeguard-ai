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
from app.runner.executor import Evidence, TestResult, execute_plan
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


def test_exploit_and_owner_control_stay_confirmed_when_unauthenticated_is_denied() -> None:
    findings = classify([_route()], [_owner(), _exploit(), _unauthenticated(401, "denied", True, "pass")], _matrix())

    assert len(findings) == 1
    assert findings[0].status == "Confirmed"
    assert findings[0].coverage_gaps == []
    assert evidence_line(findings[0].evidence[0]).startswith("EXPLOIT: GET /documents/101 ")
    assert "GET/documents" not in evidence_line(findings[0].evidence[0])


def test_failing_owner_control_stays_inconclusive_when_the_exploit_was_allowed() -> None:
    owner = _result("get-101-owner-alice", "alice", "/documents/101", 404, "denied", False, "fail")
    findings = classify([_route()], [owner, _exploit(), _unauthenticated(401, "denied", True, "pass")], _matrix())

    assert findings[0].status == "Inconclusive"
    assert findings[0].status != "Confirmed"


def test_server_error_on_an_exploit_is_not_confirmed() -> None:
    crashed = TestResult(
        test_id="get-101-non-owner-bob",
        status_code=500,
        access=None,
        matches_expected=None,
        outcome="inconclusive",
        evidence=Evidence(
            method="GET",
            path="/documents/101",
            identity="bob",
            status_code=500,
            body="unavailable",
        ),
    )

    findings = classify([_route()], [_owner(), crashed], _matrix())

    assert findings[0].status == "Inconclusive"
    assert findings[0].status != "Confirmed"


def test_coverage_gaps_do_not_cancel_a_confirmed_exploit() -> None:
    gap = TestResult(
        test_id="get-101-extra",
        status_code=None,
        access=None,
        matches_expected=None,
        outcome="inconclusive",
        evidence=Evidence(
            method="GET",
            path="/documents/101",
            identity="bob",
            status_code=None,
            body="timeout",
        ),
    )

    findings = classify([_route()], [_owner(), _exploit(), gap], _matrix())

    assert findings[0].status == "Confirmed"
    assert len(findings[0].coverage_gaps) == 1
    assert findings[0].coverage_gaps[0].startswith("GET /documents/101 ")
    from app.cli import _evidence_lines

    assert "Coverage gaps: 1" in _evidence_lines(findings[0])


def test_evidence_line_keeps_a_space_after_the_method() -> None:
    glued = Evidence(
        method="GET",
        path="GET/documents/101",
        identity="unauthenticated",
        status_code=401,
        body="",
        label="DENIED",
    )

    assert evidence_line(glued) == "DENIED: GET /documents/101 as unauthenticated -> 401 (access denied)"


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


def _route() -> RouteFinding:
    return RouteFinding(
        file="app.py",
        function_name="get_document",
        method="GET",
        path="/documents/{id}",
        status="Suspected",
        reason="Static indicator only.",
        confidence="medium",
        line_numbers=[74, 77],
    )


def _matrix():
    return default_owner_only_matrix().model_copy(
        update={
            "users": [User(name="alice", token="alice-token"), User(name="bob", token="bob-token")],
            "resources": [Resource(id="101", owner="alice")],
        }
    )


def _owner() -> TestResult:
    return _result("get-101-owner-alice", "alice", "/documents/101", 200, "allowed", True, "pass")


def _exploit() -> TestResult:
    return _result("get-101-non-owner-bob", "bob", "/documents/101", 200, "allowed", False, "fail")


def _unauthenticated(status_code: int, access: str, matches: bool, outcome: str) -> TestResult:
    return _result(
        "get-101-unauthenticated",
        "unauthenticated",
        "/documents/101",
        status_code,
        access,
        matches,
        outcome,
    )


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
