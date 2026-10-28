"""LLM provider tests. The fake transport never opens a network connection."""

from __future__ import annotations

import json
import logging
import socket
import sqlite3
from pathlib import Path

import httpx
import pytest

from app.ai.factory import get_provider
from app.ai.llm_provider import LLMProvider
from app.ai.mock_provider import MockProvider
from app.ai.provider import Provider
from app.ai.validator import validate_plan
from app.analyzer.auth_checks import RouteFinding, assess_routes
from app.analyzer.routes import discover_routes
from app.cli import main
from app.config import Settings
from app.schemas import AuthorizationMatrix, Resource, TestPlan, User, default_owner_only_matrix
from app.target_config import load_target_config

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


def _function(name: str, arguments: dict[str, object], call_id: str = "call-1") -> dict[str, object]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def _tools_reply(calls: list[dict[str, object]]) -> httpx.Response:
    payload = _reply("")
    message = payload["choices"][0]["message"]
    assert isinstance(message, dict)
    message["tool_calls"] = calls
    return httpx.Response(200, json=payload)


def _submit(plan: object) -> str:
    return json.dumps({"tool": "submit_plan", "args": plan})


_BAD_PLAN = {
    "_meta": {"note": "grouped"},
    "GET /documents/{id}": [],
    "PUT /documents/{id}": [],
    "coverage": {"routes": 2},
    "cases": {"grouped": True},
}


def _provider(
    replies: list[httpx.Response | Exception],
    seen: list[httpx.Request],
    *,
    request_cap: int = 6,
) -> LLMProvider:
    return LLMProvider(_settings(), transport=_transport(replies, seen), request_cap=request_cap)


def test_a_normal_run_uses_the_tools_and_submits_a_plan(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    route = "GET /documents/{id}"
    plan_body = {"cases": [_CASE]}
    replies = [
        _tools_reply([_function("list_routes", {})]),
        _tools_reply([_function("read_handler", {"route_id": route})]),
        _tools_reply([_function("read_handler", {"route_id": route}, "call-2")]),
        _tools_reply([_function("get_matrix", {})]),
        _tools_reply([_function("submit_plan", plan_body)]),
    ]
    provider = _provider(replies, seen)
    hidden = "def health():\n    return 'hidden'"

    plan = provider.plan_tests(
        [_finding(), _finding(status="No issue observed", path="/health", source=hidden)],
        _matrix(),
    )

    assert isinstance(plan, TestPlan)
    assert [(case.id, case.expected) for case in plan.cases] == [("get-101-non-owner-bob", "deny")]
    assert _REASONING not in plan.model_dump_json()
    assert len(seen) == 5
    first = json.loads(seen[0].content)
    names = [item["function"]["name"] for item in first["tools"]]
    assert names == ["list_routes", "read_handler", "get_matrix", "submit_plan"]
    submit = next(item["function"] for item in first["tools"] if item["function"]["name"] == "submit_plan")
    parameters = submit["parameters"]
    case_schema = parameters["properties"]["cases"]["items"]
    assert parameters["additionalProperties"] is False
    assert list(parameters["properties"]) == ["cases"]
    assert parameters["required"] == ["cases"]
    assert case_schema["additionalProperties"] is False
    assert case_schema["required"] == [
        "id",
        "route",
        "method",
        "identity",
        "resource_id",
        "expected",
        "reason",
    ]
    system = first["messages"][0]["content"]
    assert "coverage" in system
    assert "metadata" in system
    assert "per-route" in system
    assert "get-item-owner" in system
    assert "item-1" in system
    assert seen[0].url == "http://127.0.0.1:9/v1/chat/completions"
    assert seen[0].headers["Authorization"] == f"Bearer {_KEY}"
    assert first["max_tokens"] == 4000
    assert first["model"] == "muse-spark-1.3"
    assert "return items[id]" not in seen[0].content.decode()
    assert "return items[id]" not in seen[1].content.decode()
    assert "return items[id]" in seen[2].content.decode()
    assert "alice" not in seen[3].content.decode()
    assert "alice" in seen[4].content.decode()
    assert "bob" in seen[4].content.decode()
    for request in seen:
        body = request.content.decode()
        assert _TOKEN not in body
        assert "bob-token-secret" not in body
        assert _KEY not in body
        assert _REASONING not in body
        assert "return 'hidden'" not in body
    summary = provider.model_run().text()
    assert "Tool mode: function" in summary
    assert "Tools: list_routes, read_handler x2, get_matrix, submit_plan" in summary
    assert "Plan submissions: 1" in summary
    assert [item[0] for item in provider.model_run().tool_trace] == [
        "list_routes",
        "read_handler",
        "read_handler",
        "get_matrix",
        "submit_plan",
    ]
    assert [item[2] for item in provider.model_run().tool_trace] == [1, 2, 3, 4, 5]
    assert _KEY not in caplog.text
    assert _REASONING not in caplog.text
    assert "model=muse-spark-1.3" in caplog.text
    assert "latency_ms=" in caplog.text
    assert "prompt_tokens=3" in caplog.text
    assert "completion_tokens=4" in caplog.text
    assert "reasoning_tokens" not in caplog.text


def test_unknown_tool_is_rejected(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    replies = [
        _tools_reply([_function("shell", {"command": "rm -rf /"})]),
        _tools_reply([_function("shell", {})]),
    ]
    provider = _provider(replies, seen)

    with pytest.raises(RuntimeError, match="tool call was rejected") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 2
    assert "unknown tool" in seen[1].content.decode()
    assert "rm -rf" not in str(raised.value)
    assert _KEY not in str(raised.value)
    assert _REASONING not in str(raised.value)
    assert _REASONING not in seen[1].content.decode()
    assert _KEY not in caplog.text
    assert _REASONING not in caplog.text


def test_read_handler_rejects_an_unknown_route() -> None:
    seen: list[httpx.Request] = []
    replies = [
        _tools_reply([_function("read_handler", {"route_id": "../.env"})]),
        _tools_reply([_function("read_handler", {"route_id": "NOPE"})]),
    ]
    provider = _provider(replies, seen)

    with pytest.raises(RuntimeError, match="tool call was rejected") as raised:
        provider.plan_tests([_finding()], _matrix())

    reported = seen[1].content.decode()
    assert len(seen) == 2
    assert "unknown route" in reported
    assert _HANDLER not in reported
    assert _KEY not in str(raised.value)
    assert _HANDLER not in str(raised.value)


def test_turn_limit_fails_safely() -> None:
    seen: list[httpx.Request] = []
    replies = [_tools_reply([_function("list_routes", {})]) for _ in range(7)]
    provider = _provider(replies, seen, request_cap=18)

    with pytest.raises(RuntimeError, match="model turn limit of 6 exceeded") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 6
    assert provider.submitted_plan is None
    assert _KEY not in str(raised.value)


def test_tool_call_limit_fails_safely() -> None:
    seen: list[httpx.Request] = []
    calls = [_function("list_routes", {}, f"call-{index}") for index in range(7)]
    provider = _provider([_tools_reply(calls)], seen, request_cap=18)

    with pytest.raises(RuntimeError, match="tool call limit of 6 exceeded") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 1
    assert provider.submitted_plan is None
    assert _KEY not in str(raised.value)


def test_extra_keys_are_never_accepted() -> None:
    seen: list[httpx.Request] = []
    poisoned = {"cases": [{**_CASE, "command": "rm -rf /", "url": "http://evil.example"}]}
    provider = _provider([_ok(_submit(poisoned)), _ok(_submit(poisoned))], seen)
    root = Path(__file__).resolve().parents[1]
    config = load_target_config(root / "fixtures" / "codeguard.vulnerable.yaml")
    routes = discover_routes(root / "fixtures" / "vulnerable_api")

    with pytest.raises(RuntimeError, match="validation error") as raised:
        provider.plan_tests([_finding()], config.matrix(), routes=routes, config=config)

    assert len(seen) == 2
    assert "forbidden field 'command'" in str(raised.value)
    assert "rm -rf" not in str(raised.value)
    assert _KEY not in str(raised.value)
    assert provider.submitted_plan is None
    result = validate_plan(poisoned, routes, config.matrix(), config)
    reasons = [reason for item in result.rejected for reason in item.reasons]
    assert result.accepted == []
    assert "forbidden field 'command'" in reasons
    assert all("rm -rf" not in reason for reason in reasons)


def test_invalid_json_is_reported_once_then_rejected(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    provider = _provider([_ok("not json"), _ok("still {bad")], seen)

    with pytest.raises(RuntimeError, match="tool call was rejected") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 2
    assert _KEY not in str(raised.value)
    assert _REASONING not in str(raised.value)
    assert _REASONING not in seen[1].content.decode()
    assert _REASONING not in caplog.text
    assert _KEY not in caplog.text


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
    provider = _provider([missing, missing], seen)

    with pytest.raises(RuntimeError, match="tool call was rejected") as raised:
        provider.plan_tests([_finding()], _matrix())

    assert len(seen) == 2
    assert _REASONING not in str(raised.value)
    assert _REASONING not in seen[1].content.decode()
    assert _REASONING not in caplog.text
    assert _KEY not in str(raised.value)
    assert _KEY not in caplog.text


def test_server_error_retries_then_uses_the_answer() -> None:
    seen: list[httpx.Request] = []
    failure = httpx.Response(500, json={"error": _KEY, "reasoning": _REASONING})
    provider = _provider([failure, failure, _ok(_submit({"cases": [_CASE]}))], seen)

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


def test_scan_summary_names_the_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "fixtures" / "codeguard.vulnerable.yaml").read_text(encoding="utf-8")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config_path = tmp_path / "codeguard.yaml"
    config_path.write_text(source.replace("http://127.0.0.1:8001", f"http://127.0.0.1:{port}"), encoding="utf-8")
    loaded = load_target_config(config_path)
    findings = assess_routes(root / "fixtures" / "vulnerable_api")
    plan = MockProvider().plan_tests(findings, loaded.matrix())
    seen: list[httpx.Request] = []
    provider = LLMProvider(
        _settings(),
        transport=_transport([_ok(_submit(json.loads(plan.model_dump_json())))], seen),
    )
    monkeypatch.setattr("app.cli.get_provider", lambda: provider)
    database = tmp_path / "codeguard.db"

    code = main(["scan", "--config", str(config_path), "--db", str(database), "--no-start"])
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out.index("findings,") < captured.out.index("Model run")
    assert "Provider: llm" in captured.out
    assert "Model: muse-spark-1.3" in captured.out
    assert "Calls: 1" in captured.out
    assert f"Proposed: {len(plan.cases)}" in captured.out
    assert f"Accepted: {len(plan.cases)}" in captured.out
    assert "Rejected: 0" in captured.out
    assert "Tokens: 7" in captured.out
    assert "Tool mode: function" in captured.out
    assert "Tools: submit_plan" in captured.out
    assert "Plan submissions: 1" in captured.out
    assert _KEY not in captured.out
    assert _REASONING not in captured.out
    assert _KEY not in captured.err
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT provider, model_name, model_calls, tests_proposed, tests_accepted,
                   tests_rejected, total_tokens, model_summary, tool_trace
            FROM scan_runs
            """
        ).fetchone()
    assert row is not None
    assert row[0] == "llm"
    assert row[1] == "muse-spark-1.3"
    assert row[2] == 1
    assert row[3] == len(plan.cases)
    assert row[4] == len(plan.cases)
    assert row[5] == 0
    assert row[6] == 7
    assert row[7] in captured.out
    assert "submit_plan" in row[8]
    assert _KEY not in row[7]
    assert _REASONING not in row[7]
    assert _KEY not in row[8]
    assert _REASONING not in row[8]


def test_json_protocol_submits_a_plan() -> None:
    seen: list[httpx.Request] = []
    provider = _provider([_ok(_submit({"cases": [_CASE]}))], seen)

    plan = provider.plan_tests([_finding()], _matrix())

    assert plan.cases[0].resource_id == "101"
    assert "Tool mode: function" in provider.model_run().text()
    assert "Plan submissions: 1" in provider.model_run().text()


def test_tools_fall_back_to_json_when_the_endpoint_rejects_them(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    seen: list[httpx.Request] = []
    failure = httpx.Response(400, json={"error": _KEY, "reasoning": _REASONING})
    provider = _provider([failure, _ok(_submit({"cases": [_CASE]}))], seen)

    plan = provider.plan_tests([_finding()], _matrix())

    first = json.loads(seen[0].content)
    second = json.loads(seen[1].content)
    assert plan.cases[0].id == "get-101-non-owner-bob"
    assert "tools" in first
    assert "tools" not in second
    assert _KEY not in seen[0].content.decode()
    assert _KEY not in seen[1].content.decode()
    assert _REASONING not in seen[1].content.decode()
    assert _KEY not in caplog.text
    assert _REASONING not in caplog.text
    assert "Tool mode: json" in provider.model_run().text()
    assert "Plan submissions: 1" in provider.model_run().text()


def _offline_config(tmp_path: Path) -> Path:
    root = Path(__file__).resolve().parents[1]
    source = (root / "fixtures" / "codeguard.vulnerable.yaml").read_text(encoding="utf-8")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config_path = tmp_path / "codeguard.yaml"
    config_path.write_text(source.replace("http://127.0.0.1:8001", f"http://127.0.0.1:{port}"), encoding="utf-8")
    return config_path


def test_a_corrected_submission_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: list[httpx.Request] = []
    replies = [_ok(_submit(_BAD_PLAN)), _ok(_submit({"cases": [_CASE]}))]
    provider = LLMProvider(_settings(), transport=_transport(replies, seen))
    monkeypatch.setattr("app.cli.get_provider", lambda: provider)

    code = main(["scan", "--config", str(_offline_config(tmp_path)), "--db", str(tmp_path / "codeguard.db"), "--no-start"])
    captured = capsys.readouterr()

    assert code == 0
    assert len(seen) == 2
    assert "unknown field '_meta'" in seen[1].content.decode()
    assert "cases must be a list" in seen[1].content.decode()
    assert "Tool mode: function" in captured.out
    assert "Tools: submit_plan x2" in captured.out
    assert "Plan submissions: 2" in captured.out
    assert "MOCK" not in captured.out
    assert _KEY not in captured.out
    assert _KEY not in captured.err
    assert set(provider.submitted_plan or {}) == {"cases"}


def test_two_malformed_submissions_fail_the_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: list[httpx.Request] = []
    replies = [_ok(_submit(_BAD_PLAN)), _ok(_submit(_BAD_PLAN))]
    provider = LLMProvider(_settings(), transport=_transport(replies, seen))
    monkeypatch.setattr("app.cli.get_provider", lambda: provider)

    code = main(["scan", "--config", str(_offline_config(tmp_path)), "--db", str(tmp_path / "codeguard.db"), "--no-start"])
    captured = capsys.readouterr()

    assert code == 2
    assert len(seen) == 2
    assert "Tool mode: function" in captured.out
    assert "Tools: submit_plan x2" in captured.out
    assert "Plan submissions: 2" in captured.out
    assert "unknown field '_meta'" in captured.err
    assert "unknown field 'GET /documents/{id}'" in captured.err
    assert "unknown field 'PUT /documents/{id}'" in captured.err
    assert "unknown field 'coverage'" in captured.err
    assert "cases must be a list" in captured.err
    assert "MOCK" not in captured.out
    assert "MOCK" not in captured.err
    assert _KEY not in captured.out
    assert _KEY not in captured.err
    assert not (tmp_path / "codeguard.db").exists()


def test_no_suspected_route_skips_the_model() -> None:
    seen: list[httpx.Request] = []
    provider = _provider([_ok("should not be called")], seen)

    plan = provider.plan_tests([_finding(status="No issue observed")], _matrix())

    assert plan.cases == []
    assert seen == []
