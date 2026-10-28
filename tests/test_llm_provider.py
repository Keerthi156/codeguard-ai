"""LLM provider tests. The fake transport never opens a network connection."""

from __future__ import annotations

import json
import logging

import httpx
import pytest

from app.ai.factory import get_provider
from app.ai.llm_provider import LLMProvider
from app.ai.provider import Provider
from app.analyzer.auth_checks import RouteFinding
from app.config import Settings
from app.schemas import AuthorizationMatrix, Resource, TestPlan, User, default_owner_only_matrix

_KEY = "sk-test-secret-key"
_REASONING = "private-chain-of-thought-9c1e"
_TOKEN = "alice-token-secret"
_HANDLER = "def get_document(id):\n    return items[id]"

_CASE = {
    "id": "get-101-non-owner-bob",
    "route": "/documents/{id}",
    "method": "GET",
    "identity": "bob",
    "resource_id": "101",
    "expected": "deny",
    "reason": "bob does not own 101",
}


def _settings() -> Settings:
    return Settings(
        model_api_key=_KEY,
        model_name="muse-spark-1.3",
        model_base_url="http://127.0.0.1:9/v1",
        use_mock_ai=False,
    )


def _matrix() -> AuthorizationMatrix:
    return default_owner_only_matrix().model_copy(
        update={
            "users": [User(name="alice", token=_TOKEN), User(name="bob", token="bob-token-secret")],
            "resources": [Resource(id="101", owner="alice")],
        }
    )


def _finding(status: str = "Suspected", path: str = "/documents/{id}", source: str = _HANDLER) -> RouteFinding:
    return RouteFinding(
        file="app.py",
        function_name="get_document",
        method="GET",
        path=path,
        status=status,  # type: ignore[arg-type]
        reason="indicator",
        confidence="medium",
        line_numbers=[1, 2],
        source=source,
    )


def _reply(content: str | None, *, reasoning: str = _REASONING) -> dict[str, object]:
    message: dict[str, object] = {"role": "assistant", "reasoning_content": reasoning}
    if content is not None:
        message["content"] = content
    return {
        "reasoning": reasoning,
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7, "reasoning_tokens": 99},
        "choices": [{"message": message}],
    }


def _transport(
    replies: list[httpx.Response | Exception],
    seen: list[httpx.Request],
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        item = replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return httpx.MockTransport(handler)


def _ok(content: str) -> httpx.Response:
    return httpx.Response(200, json=_reply(content))


def _provider(
    replies: list[httpx.Response | Exception],
    seen: list[httpx.Request],
    *,
    request_cap: int = 6,
) -> LLMProvider:
    return LLMProvider(_settings(), transport=_transport(replies, seen), request_cap=request_cap)


def test_valid_reply_becomes_a_test_plan(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    fenced = "```json\n" + json.dumps({"cases": [_CASE]}) + "\n```"
    provider = _provider([_ok(fenced)], seen)

    plan = provider.plan_tests(
        [_finding(), _finding(status="No issue observed", path="/health", source="def health():\n    return 'hidden'")],
        _matrix(),
    )

    assert isinstance(plan, TestPlan)
    assert [(case.id, case.expected) for case in plan.cases] == [("get-101-non-owner-bob", "deny")]
    assert _REASONING not in plan.model_dump_json()
    assert len(seen) == 1
    payload = json.loads(seen[0].content)
    prompt = json.loads(payload["messages"][1]["content"])
    assert seen[0].url == "http://127.0.0.1:9/v1/chat/completions"
    assert seen[0].headers["Authorization"] == f"Bearer {_KEY}"
    assert payload["max_tokens"] == 4000
    assert payload["model"] == "muse-spark-1.3"
    assert prompt["routes"] == [{"method": "GET", "path": "/documents/{id}", "source": _HANDLER}]
    assert prompt["identities"] == ["alice", "bob"]
    assert prompt["resource_ids"] == ["101"]
    assert _TOKEN not in seen[0].content.decode()
    assert _KEY not in seen[0].content.decode()
    assert _KEY not in caplog.text
    assert _REASONING not in caplog.text
    assert "model=muse-spark-1.3" in caplog.text
    assert "latency_ms=" in caplog.text
    assert "prompt_tokens=3" in caplog.text
    assert "completion_tokens=4" in caplog.text
    assert "reasoning_tokens" not in caplog.text


def test_invalid_json_is_retried_once_then_rejected(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    provider = _provider([_ok("not json"), _ok("still {bad")], seen)

    with pytest.raises(RuntimeError, match="not valid JSON") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 2
    assert _KEY not in str(raised.value)
    assert _REASONING not in str(raised.value)
    assert _REASONING not in caplog.text
    assert _KEY not in caplog.text


def test_extra_fields_are_rejected() -> None:
    seen: list[httpx.Request] = []
    poisoned = {"cases": [{**_CASE, "command": "rm -rf /", "url": "http://evil.example"}]}
    body = json.dumps(poisoned)
    provider = _provider([_ok(body), _ok(body)], seen)

    with pytest.raises(RuntimeError, match="rejected") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 2
    assert _KEY not in str(raised.value)
    assert "rm -rf" not in str(raised.value)
    assert "evil.example" not in str(raised.value)


def test_request_cap_is_enforced() -> None:
    seen: list[httpx.Request] = []
    provider = _provider([_ok("not json"), _ok("not json")], seen, request_cap=1)

    with pytest.raises(RuntimeError, match="request cap of 1 exceeded") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 1
    assert _KEY not in str(raised.value)


def test_reasoning_text_is_not_returned(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    missing = httpx.Response(200, json=_reply(None))
    provider = _provider([missing], seen)

    with pytest.raises(RuntimeError, match="message content") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert _REASONING not in str(raised.value)
    assert _REASONING not in caplog.text
    assert _KEY not in str(raised.value)
    assert _KEY not in caplog.text


def test_server_error_retries_then_uses_the_answer() -> None:
    seen: list[httpx.Request] = []
    failure = httpx.Response(500, json={"error": _KEY, "reasoning": _REASONING})
    provider = _provider([failure, failure, _ok(json.dumps({"cases": [_CASE]}))], seen)

    plan = provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 3
    assert plan.cases[0].id == "get-101-non-owner-bob"


def test_timeout_retries_are_capped() -> None:
    seen: list[httpx.Request] = []
    timeout = httpx.ReadTimeout("timed out")
    provider = _provider([timeout, timeout, timeout, _ok(json.dumps({"cases": [_CASE]}))], seen)

    with pytest.raises(RuntimeError, match="timed out") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 3
    assert _KEY not in str(raised.value)


def test_factory_builds_the_model_provider_or_names_missing_settings() -> None:
    provider = get_provider(_settings())
    assert isinstance(provider, LLMProvider)
    assert isinstance(provider, Provider)

    with pytest.raises(RuntimeError, match="MODEL_NAME") as raised:
        get_provider(
            Settings(
                model_api_key=_KEY,
                model_name="",
                model_base_url="",
                use_mock_ai=False,
            )
        )
    assert _KEY not in str(raised.value)


def test_provider_accepts_a_json_list() -> None:
    seen: list[httpx.Request] = []
    provider = _provider([_ok(json.dumps([_CASE]))], seen)

    plan = provider.plan_tests([_finding()], _matrix())

    assert plan.cases[0].resource_id == "101"
