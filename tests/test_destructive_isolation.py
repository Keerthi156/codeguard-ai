"""Destructive tests get a fresh target, and a stale 404 is not a denial."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request

from app.ai.model_run import ModelRun
from app.analyzer.auth_checks import RouteFinding
from app.benchmark_run import AppBlock, BenchmarkReport, report_json, score
from app.findings.classifier import Finding, classify
from app.findings.regression import export_verified
from app.runner.executor import (
    CANNOT_RESET,
    STATE_TAINTED,
    ExecutionStats,
    TestResult,
    _execute_one,
    apply_state_taint,
    execute_plan,
)
from app.schemas import Resource, TestCase, User
from app.target_config import TargetConfig, TargetRoute

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _config(*, reset: str | None = None) -> TargetConfig:
    return TargetConfig(
        base_url="http://127.0.0.1:8105",
        users=[User(name="alice", token="alice-token"), User(name="bob", token="bob-token")],
        resources=[Resource(id="101", owner="alice")],
        routes=[TargetRoute(method="DELETE", path="/documents/{id}", operation="write")],
        target_app="fixtures.vulnerable_api.app:app",
        source_dir="fixtures/vulnerable_api",
        reset=reset,
    )


def _case(name: str, identity: str, expected: str) -> TestCase:
    return TestCase(
        id=name,
        route="/documents/{id}",
        method="DELETE",
        identity=identity,
        resource_id="101",
        expected=expected,  # type: ignore[arg-type]
        reason="ownership check",
    )


def _route() -> RouteFinding:
    return RouteFinding(
        file="app.py",
        function_name="delete_document",
        method="DELETE",
        path="/documents/{id}",
        status="Suspected",
        reason="ownership is not checked",
        confidence="medium",
        line_numbers=[1],
    )


def _app(secure: bool) -> tuple[FastAPI, dict[str, int]]:
    documents = {"101": "alice"}
    resets = {"n": 0}

    def restore() -> None:
        documents.clear()
        documents["101"] = "alice"
        resets["n"] += 1

    app = FastAPI()

    @app.delete("/documents/{doc_id}")
    def delete_document(doc_id: str, request: Request) -> dict[str, str]:
        user = _user(request)
        if user is None:
            raise HTTPException(status_code=401)
        owner = documents.get(doc_id)
        if owner is None:
            raise HTTPException(status_code=404)
        if secure and owner != user:
            raise HTTPException(status_code=404)
        documents.pop(doc_id)
        return {"deleted": doc_id}

    app.state.restore = restore  # type: ignore[attr-defined]
    return app, resets


def _user(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header == "Bearer alice-token":
        return "alice"
    if header == "Bearer bob-token":
        return "bob"
    return None


def _digest(root: Path) -> bytes:
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.digest()


async def test_vulnerable_delete_is_confirmed_and_records_resets() -> None:
    app, _resets = _app(secure=False)
    config = _config()
    stats = ExecutionStats()
    cases = [_case("control", "alice", "allow"), _case("exploit", "bob", "deny")]

    results = await execute_plan(
        cases,
        config,
        transport=httpx.ASGITransport(app=app),
        reset=app.state.restore,
        stats=stats,
    )
    findings = classify([_route()], results, config.matrix(), destructive_methods=["DELETE"])

    assert stats.resets == 2
    assert [item.session for item in results] == [1, 2]
    assert results[0].status_code == 200
    assert results[0].outcome == "pass"
    assert results[1].status_code == 200
    assert results[1].access == "allowed"
    confirmed = [item for item in findings if item.status == "Confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0].reason == (
        "A non-owner or unauthenticated caller received access the matrix denies, "
        "and the owner control test for this route passed."
    )
    summary = ModelRun(
        provider="mock",
        model_name="mock",
        calls=0,
        proposed=0,
        accepted=0,
        rejected=0,
        total_tokens=None,
        latency_ms=0,
    ).with_resets(stats.resets)
    assert "Resets: 2" in summary.text()


async def test_repeated_delete_reuses_the_first_result() -> None:
    app, _resets = _app(secure=False)
    config = _config()
    stats = ExecutionStats()
    calls = {"n": 0}

    class _Counting(httpx.ASGITransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return await super().handle_async_request(request)

    first = _case("control", "alice", "allow")
    again = first.model_copy(update={"id": "control-again"})
    results = await execute_plan(
        [first, again],
        config,
        transport=_Counting(app),
        reset=app.state.restore,
        stats=stats,
    )

    assert stats.resets == 1
    assert calls["n"] == 1
    assert [item.test_id for item in results] == ["control", "control-again"]
    assert results[0].status_code == results[1].status_code == 200
    assert [item.session for item in results] == [1, 2]


async def test_secure_delete_has_no_confirmed_finding() -> None:
    app, _resets = _app(secure=True)
    config = _config()
    stats = ExecutionStats()
    cases = [_case("control", "alice", "allow"), _case("exploit", "bob", "deny")]

    results = await execute_plan(
        cases,
        config,
        transport=httpx.ASGITransport(app=app),
        reset=app.state.restore,
        stats=stats,
    )
    findings = classify([_route()], results, config.matrix(), destructive_methods=["DELETE"])

    assert stats.resets == 2
    assert results[0].status_code == 200
    assert results[1].status_code == 404
    assert results[1].access == "denied"
    assert results[1].outcome == "pass"
    assert findings
    assert all(item.status != "Confirmed" for item in findings)


async def test_404_after_an_earlier_delete_is_state_tainted() -> None:
    app, _resets = _app(secure=False)
    config = _config()
    tokens = {user.name: user.token for user in config.users}
    token_values = list(tokens.values())
    cases = [_case("control", "alice", "allow"), _case("exploit", "bob", "deny")]
    raw: list[TestResult] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=config.base_url,
        trust_env=False,
    ) as client:
        for case in cases:
            raw.append(await _execute_one(client, case, config.base_url, tokens, token_values, 2.0))

    tainted = apply_state_taint(raw, ["DELETE"])
    assert tainted[0].outcome == "pass"
    assert tainted[0].status_code == 200
    assert tainted[1].status_code == 404
    assert tainted[1].outcome == "inconclusive"
    assert tainted[1].outcome != "pass"
    assert tainted[1].access is None
    assert tainted[1].matches_expected is None
    assert tainted[1].evidence.body == STATE_TAINTED

    denied = tainted[1].model_copy(
        update={
            "access": "denied",
            "matches_expected": True,
            "outcome": "pass",
            "evidence": tainted[1].evidence.model_copy(update={"body": "missing"}),
        }
    )
    findings = classify([_route()], [tainted[0], denied], config.matrix(), destructive_methods=["DELETE"])
    assert findings[0].status == "Inconclusive"
    assert findings[0].reason == STATE_TAINTED
    assert all(item.label != "DENIED" for item in findings[0].evidence)
    assert not any(item.label == "EXPLOIT" for item in findings[0].evidence)


async def test_no_start_without_reset_is_inconclusive_and_sends_nothing() -> None:
    app, _resets = _app(secure=False)

    class Counting(httpx.ASGITransport):
        def __init__(self) -> None:
            super().__init__(app=app)
            self.calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.calls += 1
            return await super().handle_async_request(request)

    transport = Counting()
    config = _config()
    stats = ExecutionStats()
    results = await execute_plan(
        [_case("control", "alice", "allow"), _case("exploit", "bob", "deny")],
        config,
        transport=transport,
        stats=stats,
    )
    findings = classify([_route()], results, config.matrix(), destructive_methods=["DELETE"])

    assert transport.calls == 0
    assert stats.resets == 0
    assert all(item.outcome == "inconclusive" for item in results)
    assert all(item.evidence.body == CANNOT_RESET for item in results)
    assert findings[0].status == "Inconclusive"
    assert findings[0].reason == CANNOT_RESET


def test_resets_are_in_the_benchmark_json() -> None:
    report = BenchmarkReport(
        commit="abc",
        date="2026-10-30",
        provider="mock",
        model="mock",
        runs=1,
        apps=(AppBlock("delete-app", 1, 1, (), (), (2,)),),
        totals=score([]),
        plan_validity="n/a",
        plan_submissions=0,
        tool_calls=0,
        tokens=None,
        latency_ms=0,
        discovered=1,
        labeled=0,
        misses=(),
        resets=2,
    )
    payload = report_json(report)
    totals = payload["totals"]
    assert isinstance(totals, dict)
    assert totals["resets"] == 2
    apps = payload["apps"]
    assert isinstance(apps, list)
    assert apps[0]["resets"] == [2]


def test_document_sources_stay_byte_identical() -> None:
    before = {
        name: _digest(ROOT / name)
        for name in ("fixtures/vulnerable_api", "fixtures/secure_api", "benchmarks")
    }
    after = {
        name: _digest(ROOT / name)
        for name in ("fixtures/vulnerable_api", "fixtures/secure_api", "benchmarks")
    }
    assert after == before


def test_destructive_regression_uses_a_fresh_app_per_test(tmp_path: Path) -> None:
    config = _config()
    finding = Finding(
        id="delete-documents-id",
        route="/documents/{id}",
        method="DELETE",
        status="Verified",
        reason="non-owner was allowed",
        created_at=datetime(2026, 10, 30, tzinfo=timezone.utc),
        target_revision="abc123",
    )
    path = export_verified(
        finding,
        config,
        root_cause="the handler ignores ownership",
        db_path=tmp_path / "codeguard.db",
        output_dir=tmp_path / "regression_tests",
        when=datetime(2026, 10, 30, tzinfo=timezone.utc),
    )
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "importlib.reload" in text
    assert "def client()" in text
    compile(text, str(path), "exec")

    app_dir = tmp_path / "freshapp"
    app_dir.mkdir()
    (app_dir / "freshapp.py").write_text(
        "\n".join(
            [
                "from fastapi import FastAPI, HTTPException",
                "documents = {'101': 'alice'}",
                "app = FastAPI()",
                "@app.delete('/documents/{doc_id}')",
                "def delete_document(doc_id: str) -> dict[str, str]:",
                "    if doc_id not in documents:",
                "        raise HTTPException(status_code=404)",
                "    documents.pop(doc_id)",
                "    return {'deleted': doc_id}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(app_dir) + os.pathsep + env.get("PYTHONPATH", "")
    env["CODEGUARD_TARGET_APP"] = "freshapp:app"
    env["CODEGUARD_BASE_URL"] = "http://127.0.0.1:9"
    env["CODEGUARD_TOKEN_ALICE"] = "alice-token"
    env["CODEGUARD_TOKEN_BOB"] = "bob-token"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(path),
            "-q",
            "--tb=short",
            "--noconftest",
            f"--rootdir={path.parent}",
        ],
        cwd=path.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    assert "access was allowed with status 200" in output
    assert completed.returncode != 0


class _RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        return httpx.Response(204)


async def test_destructive_request_uses_the_url_after_reset() -> None:
    config = _config()
    seen = _RecordingTransport()

    def restart() -> None:
        config.base_url = "http://127.0.0.1:8106"

    await execute_plan([_case("control", "alice", "allow")], config, transport=seen, reset=restart)

    assert seen.urls
    assert seen.urls[0].startswith("http://127.0.0.1:8106/")
