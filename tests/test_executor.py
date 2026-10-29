"""Executor checks against the local document fixtures."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from app.ai.mock_provider import MockProvider
from app.analyzer.auth_checks import assess_routes
from app.runner.executor import TestResult, execute_plan
from app.schemas import TestCase
from app.target_config import TargetConfig, load_target_config
import fixtures.secure_api.app as secure_api
import fixtures.vulnerable_api.app as vulnerable_api

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


def _config(fixture_name: str) -> TargetConfig:
    return load_target_config(ROOT / "fixtures" / f"codeguard.{fixture_name}.yaml")


def _plan(fixture_name: str, config: TargetConfig) -> list[TestCase]:
    findings = assess_routes(ROOT / "fixtures" / f"{fixture_name}_api")
    return MockProvider().plan_tests(findings, config.matrix()).cases


class _CountingTransport(httpx.ASGITransport):
    def __init__(self, app: object) -> None:
        super().__init__(app=app)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return await super().handle_async_request(request)


@pytest.mark.parametrize(
    ("fixture_name", "app_module"),
    [("vulnerable", vulnerable_api), ("secure", secure_api)],
)
async def test_owner_and_non_owner_results(fixture_name: str, app_module: object) -> None:
    _reset(app_module)
    config = _config(fixture_name)
    cases = _plan(fixture_name, config)
    transport = _CountingTransport(app_module.app)

    results = await execute_plan(cases, config, transport=transport)

    assert len(results) == len(cases)
    assert transport.calls == len(cases)
    for case, result in zip(cases, results, strict=True):
        _assert_result_is_sanitized(case, result, config)
        if "non-owner" in case.id and fixture_name == "vulnerable":
            assert result.outcome == "fail"
            assert result.access == "allowed"
            assert result.matches_expected is False
            assert result.status_code == 200
            continue
        assert result.outcome == "pass"
        assert result.matches_expected is True
        if "non-owner" in case.id:
            assert result.access == "denied"
            assert result.status_code == 404
        else:
            assert result.access == "allowed"
            assert result.status_code == 200


async def test_non_localhost_url_is_refused() -> None:
    config = _config("vulnerable")
    case = _plan("vulnerable", config)[0]
    refused = TargetConfig.model_construct(
        base_url="http://example.com",
        users=config.users,
        resources=config.resources,
        routes=config.routes,
    )

    class _BoomTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            raise AssertionError("request was sent")

    with pytest.raises(ValueError, match="127.0.0.1 or http://localhost"):
        await execute_plan([case], refused, transport=_BoomTransport())

    evil = case.model_copy(update={"id": "evil-host", "route": "http://evil.example/documents/{id}"})
    transport = _CountingTransport(vulnerable_api.app)
    _reset(vulnerable_api)
    results = await execute_plan([case, evil], config, transport=transport)

    assert transport.calls == 1
    assert results[0].outcome == "pass"
    assert results[1].outcome == "inconclusive"
    assert results[1].status_code is None
    assert results[1].access is None
    dumped = results[1].model_dump_json()
    assert "evil.example" not in dumped
    assert "alice-token" not in dumped


async def test_timeout_and_server_error_are_inconclusive() -> None:
    config = _config("vulnerable")
    case = _plan("vulnerable", config)[0]

    slow = FastAPI()

    @slow.get("/documents/{id}")
    async def hang(id: int) -> dict[str, int]:
        await asyncio.sleep(0.2)
        return {"id": id}

    broken = FastAPI()

    @broken.get("/documents/{id}")
    def crash(id: int) -> None:
        raise HTTPException(status_code=500, detail="unavailable")

    timed_out = await execute_plan(
        [case],
        config,
        transport=httpx.ASGITransport(app=slow),
        timeout=0.05,
    )
    failed = await execute_plan([case], config, transport=httpx.ASGITransport(app=broken))

    assert timed_out[0].outcome == "inconclusive"
    assert timed_out[0].status_code is None
    assert timed_out[0].matches_expected is None
    assert failed[0].outcome == "inconclusive"
    assert failed[0].status_code == 500
    assert failed[0].access is None
    assert "alice-token" not in failed[0].model_dump_json()


async def test_unauthenticated_identity_sends_no_authorization_header() -> None:
    captured: list[httpx.Headers] = []
    app = FastAPI()

    @app.get("/documents/{id}")
    def read_document(id: int, request: Request) -> None:
        captured.append(request.headers)
        raise HTTPException(status_code=401, detail="Unauthorized")

    config = _config("vulnerable")
    case = TestCase(
        id="get-101-unauthenticated",
        route="/documents/{id}",
        method="GET",
        identity="unauthenticated",
        resource_id="101",
        expected="deny",
        reason="an unauthenticated caller is denied",
    )

    results = await execute_plan([case], config, transport=httpx.ASGITransport(app=app))

    assert results[0].status_code == 401
    assert results[0].access == "denied"
    assert results[0].outcome == "pass"
    assert captured
    assert "authorization" not in {name.lower() for name in captured[0].keys()}
    assert f"{results[0].evidence.method} {results[0].evidence.path}" == "GET /documents/101"


def _assert_result_is_sanitized(case: TestCase, result: TestResult, config: TargetConfig) -> None:
    assert result.test_id == case.id
    assert result.evidence.method == case.method
    assert result.evidence.path == f"/documents/{case.resource_id}"
    assert result.evidence.identity == case.identity
    assert result.evidence.status_code == result.status_code
    assert len(result.evidence.body) <= 300
    dumped = result.model_dump_json()
    for user in config.users:
        assert user.token not in dumped
    assert "Authorization" not in dumped
