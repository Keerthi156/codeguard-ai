"""Routes the owner/non-owner model cannot judge."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from app.ai.required_plan import supplement_plan
from app.analyzer.auth_checks import RouteFinding
from app.benchmark_run import RouteRow, describe_route, score, trial_kind
from app.experiment import _route_status
from app.findings.classifier import COLLECTION_STATUS, classify
from app.runner.executor import Evidence, TestResult, execute_plan
from app.schemas import TestCase
from app.target_config import load_target_config, request_timeout_seconds, reset_readiness_seconds

ROOT = Path(__file__).resolve().parents[1]
_CONFIRMED = (
    "A non-owner or unauthenticated caller received access the matrix denies, "
    "and the owner control test for this route passed."
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _finding(method: str, path: str) -> RouteFinding:
    return RouteFinding(
        file="app.py",
        function_name="handler",
        method=method,
        path=path,
        status="Suspected",
        reason="no owner comparison",
        confidence="medium",
        line_numbers=[1],
    )


def _case(route: str, method: str = "GET") -> TestCase:
    return TestCase(
        id=f"{method}-{route}",
        route=route,
        method=method,  # type: ignore[arg-type]
        identity="bob",
        resource_id="101",
        expected="deny",
        reason="non-owner check",
    )


def _result(
    method: str,
    path: str,
    identity: str,
    status: int | None,
    access: str | None,
    outcome: str,
    body: str,
) -> TestResult:
    return TestResult(
        test_id=f"{method}-{identity}-{path}",
        status_code=status,
        access=access,  # type: ignore[arg-type]
        matches_expected=None if access is None else outcome == "pass",
        outcome=outcome,  # type: ignore[arg-type]
        evidence=Evidence(
            method=method,
            path=path,
            identity=identity,
            status_code=status,
            body=body,
        ),
    )


class _CountingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        del request
        self.calls += 1
        return httpx.Response(200, json={"owner": "alice"})


def test_collection_route_is_not_applicable_and_sends_no_exploit() -> None:
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml")
    matrix = config.matrix()
    collection = _finding("GET", "/notes")
    named = _finding("GET", "/documents/{id}")
    model_case = _case("/notes")
    cases, model_count, required = supplement_plan([model_case], [collection, named], matrix, config)

    assert model_count == 0
    assert required > 0
    assert all(case.route == "/documents/{id}" for case in cases)
    assert not any(case.route == "/notes" for case in cases)


@pytest.mark.anyio
async def test_collection_route_is_not_sent_and_not_confirmed() -> None:
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml")
    transport = _CountingTransport()
    results = await execute_plan([_case("/notes"), _case("/notes", "POST")], config, transport=transport)
    sent = await execute_plan([_case("/documents/{id}")], config, transport=transport)

    assert results == []
    assert transport.calls == 1
    assert sent[0].evidence.path.endswith("/documents/101")

    allowed = _result("GET", "/notes", "bob", 200, "allowed", "fail", '{"owner": "alice"}')
    findings = classify([_finding("GET", "/notes")], [allowed], config.matrix())
    assert len(findings) == 1
    assert findings[0].status == "Not applicable"
    assert findings[0].reason == COLLECTION_STATUS
    assert findings[0].evidence == []
    assert findings[0].status not in {"Confirmed", "Inconclusive"}


def test_path_parameter_route_stays_confirmed() -> None:
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml")
    owner = _result("GET", "/documents/101", "alice", 200, "allowed", "pass", '{"owner": "alice"}')
    other = _result("GET", "/documents/101", "bob", 200, "allowed", "fail", '{"owner": "alice"}')
    findings = classify([_finding("GET", "/documents/{id}")], [owner, other], config.matrix())

    assert len(findings) == 1
    assert findings[0].status == "Confirmed"
    assert findings[0].reason == _CONFIRMED
    assert findings[0].evidence[0].label == "EXPLOIT"


def test_destructive_route_reports_restart_timeout_and_timeout_is_not_denial() -> None:
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml")
    timeouts = [
        _result("DELETE", "/documents/101", "alice", None, None, "inconclusive", "timeout"),
        _result("DELETE", "/documents/101", "bob", None, None, "inconclusive", "timeout"),
        _result("DELETE", "/documents/202", "bob", None, None, "inconclusive", "timeout"),
    ]
    findings = classify(
        [_finding("DELETE", "/documents/{id}")],
        timeouts,
        config.matrix(),
        destructive_methods=["DELETE"],
    )
    assert findings[0].status == "Inconclusive"
    assert findings[0].reason == "Inconclusive: target restart timed out (3 restarts)"
    assert findings[0].status != "Confirmed"
    assert {item.label for item in findings[0].evidence} == {"INCONCLUSIVE"}

    owner_timeout = _result("GET", "/documents/101", "alice", None, None, "inconclusive", "timeout")
    other_allowed = _result("GET", "/documents/101", "bob", 200, "allowed", "fail", '{"owner": "alice"}')
    get_findings = classify(
        [_finding("GET", "/documents/{id}")],
        [owner_timeout, other_allowed],
        config.matrix(),
    )
    assert get_findings[0].status == "Inconclusive"
    assert "target restart timed out" not in get_findings[0].reason
    assert get_findings[0].status != "Confirmed"
    timed = [item for item in get_findings[0].evidence if item.body == "timeout"]
    assert [item.label for item in timed] == ["INCONCLUSIVE"]


def test_reports_show_collection_status_and_keep_confirmed() -> None:
    collection, reason, _flagged = describe_route(
        "GET",
        "/notes",
        inventory={("GET", "/notes")},
        flagged_routes={("GET", "/notes")},
        finding_status="Not applicable",
    )
    named, named_reason, _flagged = describe_route(
        "GET",
        "/documents/{id}",
        inventory={("GET", "/documents/{id}")},
        flagged_routes={("GET", "/documents/{id}")},
        finding_status="Confirmed",
        finding_reason=_CONFIRMED,
    )
    phrase = "Inconclusive: target restart timed out (2 restarts)"
    timed_out, timed_reason, _flagged = describe_route(
        "DELETE",
        "/documents/{id}",
        inventory={("DELETE", "/documents/{id}")},
        flagged_routes={("DELETE", "/documents/{id}")},
        finding_status="Inconclusive",
        finding_reason=phrase,
    )

    assert collection == COLLECTION_STATUS
    assert reason == COLLECTION_STATUS
    assert trial_kind(True, collection) == "not_applicable"
    assert named == "Confirmed"
    assert named_reason == _CONFIRMED
    assert timed_out == phrase
    assert timed_reason == phrase
    totals = score(
        [
            RouteRow("app", "GET /notes", True, (collection,), (reason,)),
            RouteRow("app", "GET /documents/{id}", True, (named,), (named_reason,)),
        ]
    )
    assert totals.not_applicable == 1
    assert totals.tp == 1
    assert totals.fn == 0

    inventory = {("GET", "/notes"), ("GET", "/documents/{id}"), ("DELETE", "/documents/{id}")}
    assert _route_status(("GET", "/notes"), {}, inventory, {}) == COLLECTION_STATUS
    assert (
        _route_status(("GET", "/documents/{id}"), {("GET", "/documents/{id}"): "Confirmed"}, inventory, {})
        == "Confirmed"
    )
    assert (
        _route_status(("DELETE", "/documents/{id}"), {("DELETE", "/documents/{id}"): phrase}, inventory, {})
        == phrase
    )


def test_request_and_reset_timeouts_default_and_can_be_set() -> None:
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml")
    assert request_timeout_seconds(config) == 10
    assert reset_readiness_seconds(config) == 20
    changed = config.model_copy(update={"request_timeout": 4, "reset_readiness_timeout": 7})
    assert request_timeout_seconds(changed) == 4
    assert reset_readiness_seconds(changed) == 7


@pytest.mark.anyio
async def test_request_timeout_comes_from_the_config_and_is_not_a_denial() -> None:
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml").model_copy(
        update={"request_timeout": 0.05}
    )
    app = FastAPI()

    @app.get("/documents/{id}")
    async def hang(id: int) -> dict[str, int]:
        await asyncio.sleep(5)
        return {"id": id}

    started = time.monotonic()
    results = await execute_plan([_case("/documents/{id}")], config, transport=httpx.ASGITransport(app=app))
    assert time.monotonic() - started < 2
    assert results[0].access is None
    assert results[0].evidence.body == "timeout"
    assert results[0].outcome == "inconclusive"
