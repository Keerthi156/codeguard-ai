"""Bypass variants are a fixed localhost-only set, never chosen by the model."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from app.runner.variants import Variant, VariantResult, build_variants, execute_variants, summarize
from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]


def _config():
    config = load_target_config(ROOT / "fixtures" / "codeguard.vulnerable.yaml")
    return config.model_copy(update={"base_url": "http://127.0.0.1:9"})


def _result(variant: Variant, status: int | None) -> VariantResult:
    from app.runner.variants import classify_status

    return VariantResult(
        variant=variant,
        status_code=status,
        classification=classify_status(status),
        body="",
    )


def test_get_and_put_routes_have_the_fixed_set() -> None:
    config = _config()
    get_variants = build_variants("GET", "/documents/{id}", config)
    put_variants = build_variants("PUT", "/documents/{id}", config)

    assert [item.name for item in get_variants] == [
        "trailing-slash",
        "leading-zeros",
        "whitespace-id",
        "method-put",
        "method-delete",
        "method-patch",
        "query-id",
        "double-slash",
        "auth-case",
        "missing-bearer",
        "trailing-slash-unauthenticated",
        "leading-zeros-unauthenticated",
        "query-id-unauthenticated",
        "double-slash-unauthenticated",
    ]
    assert [item.method for item in get_variants if item.name.startswith("method-")] == ["PUT", "DELETE", "PATCH"]
    assert [item.method for item in put_variants if item.name.startswith("method-")] == ["GET", "DELETE", "PATCH"]
    by_name = {item.name: item for item in get_variants}
    assert by_name["trailing-slash"].path == "/documents/101/"
    assert by_name["leading-zeros"].path == "/documents/0101"
    assert by_name["whitespace-id"].path == "/documents/%20101%20"
    assert by_name["query-id"].path == "/documents/101?id=202"
    assert by_name["double-slash"].path == "/documents//101"
    assert by_name["auth-case"].auth == "bearer_case"
    assert by_name["missing-bearer"].auth == "raw"
    assert by_name["trailing-slash-unauthenticated"].auth == "none"
    assert by_name["method-put"].identity == "bob"
    assert all("alice-token" not in item.path and "bob-token" not in item.path for item in get_variants)
    assert build_variants("GET", "/documents/{id}", config) == get_variants


def test_status_rules() -> None:
    variant = Variant("method-put", "PUT", "/documents/101", "bob", "bearer")
    denied = summarize([_result(variant, status) for status in (401, 403, 404, 405, 422, 307)])
    assert denied.outcome == "hardened"
    assert denied.line == "Bypass check: 6 variants, 0 bypasses (HARDENED)"

    opened = summarize([_result(variant, 404), _result(variant, 200)])
    assert opened.outcome == "bypass"
    assert opened.line == "Bypass check: BYPASS FOUND via PUT /documents/101 as bob -> 200"
    assert "PUT /documents/101" in opened.model_feedback
    assert "200" in opened.model_feedback
    assert "Every method on the same resource path needs the same owner check." in opened.model_feedback

    mixed = summarize([_result(variant, 500), _result(variant, 200)])
    assert mixed.outcome == "bypass"
    incomplete = summarize([_result(variant, 500), _result(variant, None)])
    assert incomplete.outcome == "inconclusive"
    assert incomplete.line == "Bypass check: 2 variants, inconclusive"


def test_variants_never_leave_localhost() -> None:
    class Spy(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.calls = 0

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            del request
            self.calls += 1
            return httpx.Response(200)

    spy = Spy()
    config = _config()
    outside = config.model_construct(
        base_url="http://example.com",
        users=config.users,
        resources=config.resources,
        routes=config.routes,
        target_app=config.target_app,
        source_dir=config.source_dir,
    )
    variants = build_variants("GET", "/documents/{id}", config)
    with pytest.raises(ValueError, match="127.0.0.1 or http://localhost"):
        asyncio.run(execute_variants(variants, outside, transport=spy))
    escaped = [Variant("escaped", "GET", "http://example.com/documents/101", "bob", "bearer")]
    with pytest.raises(ValueError, match="127.0.0.1 or http://localhost"):
        asyncio.run(execute_variants(escaped, config, transport=spy))
    assert spy.calls == 0


def test_timeout_stays_on_localhost_and_is_inconclusive() -> None:
    class Spy(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.hosts: list[str] = []

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            self.hosts.append(request.url.host)
            raise httpx.TimeoutException("timed out")

    spy = Spy()
    config = _config()
    variants = build_variants("GET", "/documents/{id}", config)
    results = asyncio.run(execute_variants(variants, config, transport=spy))
    report = summarize(results)

    assert spy.hosts
    assert set(spy.hosts) <= {"127.0.0.1", "localhost"}
    assert report.outcome == "inconclusive"
    assert all(item.classification == "inconclusive" for item in results)
