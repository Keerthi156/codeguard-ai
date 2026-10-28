"""OpenAI-compatible planner with a bounded, read-only tool loop.

The model may list routes, read a discovered handler, and read the matrix.
It finishes only by calling submit_plan. This module executes those tools.
It never runs commands from the model, never reads arbitrary files, and never
puts the API key or reasoning text in logs or errors.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import httpx
from pydantic import ValidationError

from app.ai import tools
from app.ai.model_run import ModelRun
from app.ai.validator import validate_plan
from app.analyzer.auth_checks import RouteFinding
from app.config import Settings
from app.schemas import AuthorizationMatrix, TestPlan
from app.target_config import TargetConfig

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

DEFAULT_REQUEST_CAP = 18
MAX_TURNS = 6
MAX_TOOL_CALLS = 6
_TIMEOUT_SECONDS = 60.0
_MAX_TOKENS = 4000
_HTTP_ATTEMPTS = 3
_FENCE = re.compile(r"^```[a-zA-Z0-9]*\s*|\s*```$", re.MULTILINE)
_TOOL_NAMES = ("list_routes", "read_handler", "get_matrix", "submit_plan")

_EXAMPLE_PLAN = {
    "cases": [
        {
            "id": "get-item-owner",
            "route": "/items/{id}",
            "method": "GET",
            "identity": "owner",
            "resource_id": "item-1",
            "expected": "allow",
            "reason": "owner may read this item",
        },
        {
            "id": "get-item-other",
            "route": "/items/{id}",
            "method": "GET",
            "identity": "other",
            "resource_id": "item-1",
            "expected": "deny",
            "reason": "another user may not read this item",
        },
    ]
}
_SYSTEM = (
    "You draft authorization test cases as data by calling tools. "
    "The tools are list_routes, read_handler, get_matrix, and submit_plan. "
    "submit_plan is the only way to finish. "
    "Its arguments are one JSON object whose only key is cases, a list of test objects. "
    "Each case has exactly these keys: id, route, method, identity, resource_id, expected, reason. "
    "Extra keys, per-route groupings, metadata, and coverage fields are not allowed. "
    "Do not include commands, code, shell, or URLs. "
    "Example plan: "
    + json.dumps(_EXAMPLE_PLAN, separators=(",", ":"))
    + " If function calling is unavailable, reply with JSON only: "
    '{"tool": "submit_plan", "args": <the same plan object>}.'
)
_SCHEMA_DROP = frozenset({"title", "description", "$defs"})


class _ToolsUnsupported(Exception):
    """The endpoint refused the tools field. Use the JSON protocol instead."""


@dataclass(frozen=True)
class _Call:
    name: str
    args: dict[str, object]
    call_id: str


@dataclass(frozen=True)
class _Assistant:
    content: str
    calls: tuple[_Call, ...]
    raw_calls: tuple[dict[str, object], ...]


class LLMProvider:
    """Draft a test plan through at most six model turns and six tool calls."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        request_cap: int = DEFAULT_REQUEST_CAP,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._request_cap = request_cap
        self._requests = 0
        self._latency_ms = 0
        self._total_tokens: int | None = None
        self._turns = 0
        self._tool_calls = 0
        self._faults = 0
        self._json_mode = False
        self._trace: list[tuple[str, str, int]] = []
        self._tool_mode = ""
        self._plan_submissions = 0
        self._plan_failures = 0
        self._routes: Sequence[object] | None = None
        self._config: TargetConfig | None = None
        self._matrix: AuthorizationMatrix | None = None
        self.submitted_plan: dict[str, object] | None = None

    def plan_tests(
        self,
        findings: Sequence[RouteFinding],
        matrix: AuthorizationMatrix,
        *,
        routes: Sequence[object] | None = None,
        config: object | None = None,
    ) -> TestPlan:
        """Run the tool loop. A plan is returned only after submit_plan passes checks."""
        self._reset()
        self._routes = routes
        self._matrix = matrix
        self._config = config if isinstance(config, TargetConfig) else None
        suspected = [finding for finding in findings if finding.status == "Suspected"]
        if not suspected:
            return TestPlan(cases=[])
        messages: list[dict[str, object]] = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": "Inspect the suspected routes with the tools, then submit_plan."},
        ]
        while self.submitted_plan is None:
            if self._turns >= MAX_TURNS:
                raise RuntimeError(f"model turn limit of {MAX_TURNS} exceeded")
            try:
                assistant = self._call_model(messages, include_tools=not self._json_mode)
            except _ToolsUnsupported:
                self._json_mode = True
                continue
            self._turns += 1
            calls = assistant.calls or _calls_from_content(assistant.content)
            if not calls:
                self._reject(messages, assistant, "invalid tool call")
                continue
            self._append_assistant(messages, assistant)
            for call in calls:
                self._run_call(messages, findings, matrix, self._sanitize(call))
                if self.submitted_plan is not None:
                    break
        try:
            return TestPlan.model_validate(self.submitted_plan)
        except ValidationError:
            raise RuntimeError("validation error: plan did not match the schema") from None

    def model_run(self) -> ModelRun:
        """Counts and the tool trace. The API key is not included."""
        return ModelRun(
            provider="llm",
            model_name=self._settings.model_name,
            calls=self._requests,
            proposed=0,
            accepted=0,
            rejected=0,
            total_tokens=self._total_tokens,
            latency_ms=self._latency_ms,
            tool_trace=tuple(self._trace),
            tool_mode=self._tool_mode,
            plan_submissions=self._plan_submissions,
        )

    def _reset(self) -> None:
        self._requests = 0
        self._latency_ms = 0
        self._total_tokens = None
        self._turns = 0
        self._tool_calls = 0
        self._faults = 0
        self._json_mode = False
        self._trace = []
        self._tool_mode = ""
        self._plan_submissions = 0
        self._plan_failures = 0
        self._routes = None
        self._config = None
        self._matrix = None
        self.submitted_plan = None

    def _sanitize(self, call: _Call) -> _Call:
        args = _redact_tree(call.args, self._settings.model_api_key)
        return _Call(
            name=_redact_key(call.name, self._settings.model_api_key),
            args=args if isinstance(args, dict) else {},
            call_id=call.call_id,
        )

    def _run_call(
        self,
        messages: list[dict[str, object]],
        findings: Sequence[RouteFinding],
        matrix: AuthorizationMatrix,
        call: _Call,
    ) -> None:
        if self._tool_calls >= MAX_TOOL_CALLS:
            raise RuntimeError(f"tool call limit of {MAX_TOOL_CALLS} exceeded")
        self._tool_calls += 1
        summary, result, done = _execute(findings, matrix, call)
        shown = call.name if call.name in _TOOL_NAMES else summary
        self._trace.append((shown, summary if call.name in _TOOL_NAMES else "rejected", self._turns))
        if isinstance(result, tools.ToolError):
            self._faults += 1
            if self._faults > 1:
                raise RuntimeError("tool call was rejected")
            body: object = {"error": str(result)}
        elif done and isinstance(result, dict):
            body = self._review_plan(result)
        else:
            body = result
        redacted = _redact_tree(body, self._settings.model_api_key)
        messages.append(
            {
                "role": "tool" if not self._json_mode else "user",
                "tool_call_id": call.call_id,
                "content": _dump(redacted),
            }
        )

    def _review_plan(self, plan: dict[str, object]) -> dict[str, object]:
        """Check one submission. The first failure is returned; the second stops the scan."""
        self._plan_submissions += 1
        errors = _plan_errors(plan, self._routes, self._matrix, self._config, self._settings.model_api_key)
        if not errors:
            self.submitted_plan = plan
            return {"status": "accepted"}
        self._plan_failures += 1
        if self._plan_failures > 1:
            raise RuntimeError("validation error: " + "; ".join(errors)) from None
        return {"errors": errors}

    def _reject(self, messages: list[dict[str, object]], assistant: _Assistant, reason: str) -> None:
        self._faults += 1
        self._trace.append(("invalid", "rejected", self._turns))
        if self._faults > 1:
            raise RuntimeError("tool call was rejected")
        messages.append({"role": "assistant", "content": _redact_key(assistant.content, self._settings.model_api_key)})
        messages.append({"role": "user", "content": _dump({"error": reason})})

    def _append_assistant(self, messages: list[dict[str, object]], assistant: _Assistant) -> None:
        if assistant.raw_calls and not self._json_mode:
            messages.append(
                {
                    "role": "assistant",
                    "content": _redact_key(assistant.content, self._settings.model_api_key) or None,
                    "tool_calls": list(assistant.raw_calls),
                }
            )
            return
        messages.append(
            {
                "role": "assistant",
                "content": _redact_key(assistant.content, self._settings.model_api_key),
            }
        )

    def _call_model(self, messages: list[dict[str, object]], *, include_tools: bool) -> _Assistant:
        """POST one chat completion and return the tool call, ignoring reasoning."""
        url = f"{self._settings.model_base_url.rstrip('/')}/chat/completions"
        body: dict[str, object] = {
            "model": self._settings.model_name,
            "messages": messages,
            "max_tokens": _MAX_TOKENS,
        }
        if include_tools:
            body["tools"] = _tool_specs()
            body["tool_choice"] = "auto"
        self._tool_mode = "function" if include_tools else "json"
        headers = {"Authorization": f"Bearer {self._settings.model_api_key}"}
        last_error = "model request failed"
        for _attempt in range(_HTTP_ATTEMPTS):
            if self._requests >= self._request_cap:
                raise RuntimeError(f"model request cap of {self._request_cap} exceeded")
            self._requests += 1
            started = time.perf_counter()
            try:
                with httpx.Client(transport=self._transport, timeout=_TIMEOUT_SECONDS, trust_env=False) as client:
                    response = client.post(url, headers=headers, json=body, follow_redirects=False)
            except httpx.TimeoutException:
                self._latency_ms += _elapsed_ms(started)
                last_error = "model request timed out"
                continue
            except httpx.HTTPError:
                self._latency_ms += _elapsed_ms(started)
                raise RuntimeError("model request failed") from None
            latency_ms = _elapsed_ms(started)
            self._latency_ms += latency_ms
            if response.status_code == 400 and include_tools:
                raise _ToolsUnsupported()
            if response.status_code >= 500:
                last_error = f"model request failed with status {response.status_code}"
                _log_call(self._settings.model_name, latency_ms, None)
                continue
            if response.status_code != 200:
                raise RuntimeError(f"model request failed with status {response.status_code}")
            try:
                payload = response.json()
            except json.JSONDecodeError:
                raise RuntimeError("model response was not JSON") from None
            usage = payload.get("usage") if isinstance(payload, dict) else None
            self._record_tokens(usage)
            _log_call(self._settings.model_name, latency_ms, usage)
            return _assistant(payload, self._settings.model_api_key)
        raise RuntimeError(last_error)

    def _record_tokens(self, usage: object) -> None:
        _prompt_tokens, _completion_tokens, total = _usage(usage)
        if total is None:
            return
        self._total_tokens = total if self._total_tokens is None else self._total_tokens + total


def _execute(
    findings: Sequence[RouteFinding],
    matrix: AuthorizationMatrix,
    call: _Call,
) -> tuple[str, dict[str, object] | tools.ToolError, bool]:
    if call.name not in _TOOL_NAMES:
        return _summary(call.name), tools.ToolError("unknown tool"), False
    try:
        if call.name == "list_routes":
            _empty_args(call.args)
            return "", tools.list_routes(findings), False
        if call.name == "read_handler":
            return _route_summary(call.args), tools.read_handler(findings, call.args), False
        if call.name == "get_matrix":
            _empty_args(call.args)
            return "", tools.get_matrix(matrix), False
        plan = tools.submit_plan(call.args)
    except tools.ToolError as exc:
        return "rejected", exc, False
    count = len(plan["cases"]) if isinstance(plan.get("cases"), list) else 0
    summary = f"cases={count}" if isinstance(plan.get("cases"), list) else "rejected"
    return summary, plan, True


def _empty_args(args: dict[str, object]) -> None:
    if args:
        raise tools.ToolError("invalid arguments")


def _route_summary(args: dict[str, object]) -> str:
    route = args.get("route_id")
    if isinstance(route, str) and route.strip() and len(route) <= 80 and "\n" not in route:
        return route.strip()
    return "rejected"


def _summary(name: str) -> str:
    compact = " ".join(name.split())
    if not compact or len(compact) > 40:
        return "rejected"
    return compact


def _assistant(payload: object, key: str) -> _Assistant:
    message = _message(payload)
    content = message.get("content")
    text = content if isinstance(content, str) else ""
    raw_calls: list[dict[str, object]] = []
    calls: list[_Call] = []
    supplied = message.get("tool_calls")
    if isinstance(supplied, list):
        for index, item in enumerate(supplied, start=1):
            parsed = _openai_call(item, index, key)
            if parsed is None:
                continue
            call, raw = parsed
            calls.append(call)
            raw_calls.append(raw)
    return _Assistant(content=_redact_key(text, key), calls=tuple(calls), raw_calls=tuple(raw_calls))


def _message(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {}
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return {}
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return {}
    return message


def _openai_call(item: object, index: int, key: str) -> tuple[_Call, dict[str, object]] | None:
    if not isinstance(item, dict):
        return None
    function = item.get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    if not isinstance(name, str):
        return None
    args, raw_arguments = _arguments(function.get("arguments"), key)
    call_id = item.get("id")
    if not isinstance(call_id, str) or not call_id:
        call_id = f"call-{index}"
    raw = {
        "id": call_id,
        "type": "function",
        "function": {"name": _redact_key(name, key), "arguments": raw_arguments},
    }
    return _Call(name=_redact_key(name, key), args=args, call_id=call_id), raw


def _arguments(value: object, key: str) -> tuple[dict[str, object], str]:
    if isinstance(value, dict):
        cleaned = _redact_tree(value, key)
        if not isinstance(cleaned, dict):
            return {}, "{}"
        return cleaned, _dump(cleaned)
    if not isinstance(value, str) or not value.strip():
        return {}, "{}"
    redacted = _redact_key(value, key)
    try:
        parsed = json.loads(redacted)
    except json.JSONDecodeError:
        return {}, "{}"
    if not isinstance(parsed, dict):
        return {}, "{}"
    return parsed, _dump(parsed)


def _calls_from_content(content: str) -> tuple[_Call, ...]:
    stripped = _FENCE.sub("", content.strip()).strip()
    if not stripped:
        return ()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return ()
    if not isinstance(data, dict) or set(data) != {"tool", "args"}:
        return ()
    name = data.get("tool")
    args = data.get("args")
    if not isinstance(name, str) or not isinstance(args, dict):
        return ()
    return (_Call(name=name, args=args, call_id="call-1"),)


def _plan_schema() -> dict[str, object]:
    """Tool parameters taken from the TestPlan and TestCase models."""
    raw = TestPlan.model_json_schema()
    defs = raw.get("$defs", {})
    if not isinstance(defs, dict):
        defs = {}
    schema = _inline_schema(raw, defs)
    if not isinstance(schema, dict):
        raise RuntimeError("plan schema was not an object")
    return schema


def _inline_schema(node: object, defs: Mapping[str, object]) -> object:
    if isinstance(node, list):
        return [_inline_schema(item, defs) for item in node]
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str):
        return _inline_schema(defs[ref.rsplit("/", 1)[-1]], defs)
    return {
        key: _inline_schema(value, defs)
        for key, value in node.items()
        if key not in _SCHEMA_DROP
    }


def _plan_errors(
    plan: dict[str, object],
    routes: Sequence[object] | None,
    matrix: AuthorizationMatrix | None,
    config: TargetConfig | None,
    key: str,
) -> list[str]:
    errors = _schema_errors(plan)
    if routes is not None and matrix is not None and config is not None:
        result = validate_plan(plan, routes, matrix, config)
        for item in result.rejected:
            errors.extend(item.reasons)
    unique: list[str] = []
    seen: set[str] = set()
    for error in errors:
        redacted = _redact_key(error, key)
        if redacted in seen:
            continue
        seen.add(redacted)
        unique.append(redacted)
    return unique


def _schema_errors(plan: dict[str, object]) -> list[str]:
    try:
        TestPlan.model_validate(plan)
    except ValidationError as exc:
        return [_schema_reason(err) for err in exc.errors()]
    return []


def _schema_reason(err: object) -> str:
    if not isinstance(err, dict):
        return "invalid plan"
    loc = err.get("loc")
    parts = [str(part) for part in loc] if isinstance(loc, tuple) else []
    kind = str(err.get("type", ""))
    if kind == "extra_forbidden" and parts:
        return f"unknown field {parts[-1]!r}"
    if parts == ["cases"] and (kind == "missing" or "list" in kind):
        return "cases must be a list"
    if kind == "missing" and parts:
        return f"missing field {parts[-1]!r}"
    if kind == "value_error":
        return "test case ids must be unique"
    if parts:
        return f"invalid {'.'.join(parts)}"
    return "invalid plan"


def _tool_specs() -> list[dict[str, object]]:
    empty = {"type": "object", "properties": {}, "additionalProperties": False}
    route = {
        "type": "object",
        "properties": {"route_id": {"type": "string"}},
        "required": ["route_id"],
        "additionalProperties": False,
    }
    specs = {
        "list_routes": ("List discovered routes and heuristic findings.", empty),
        "read_handler": ("Return one discovered handler's source and line numbers.", route),
        "get_matrix": ("Return the authorization matrix, identities, and resource ids.", empty),
        "submit_plan": (
            "Finish with the plan object. Only a cases list is allowed. This does not run the tests.",
            _plan_schema(),
        ),
    }
    return [
        {
            "type": "function",
            "function": {"name": name, "description": description, "parameters": parameters},
        }
        for name, (description, parameters) in specs.items()
    ]


def _log_call(model_name: str, latency_ms: int, usage: object) -> None:
    prompt_tokens, completion_tokens, total_tokens = _usage(usage)
    logger.info(
        "model=%s latency_ms=%s prompt_tokens=%s completion_tokens=%s total_tokens=%s",
        model_name,
        latency_ms,
        prompt_tokens,
        completion_tokens,
        total_tokens,
    )


def _usage(usage: object) -> tuple[int | None, int | None, int | None]:
    if not isinstance(usage, dict):
        return None, None, None
    return (
        _token_count(usage.get("prompt_tokens")),
        _token_count(usage.get("completion_tokens")),
        _token_count(usage.get("total_tokens")),
    )


def _token_count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _dump(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def _redact_tree(value: object, key: str) -> object:
    if isinstance(value, str):
        return _redact_key(value, key)
    if isinstance(value, list):
        return [_redact_tree(item, key) for item in value]
    if isinstance(value, dict):
        return {str(name): _redact_tree(item, key) for name, item in value.items()}
    return value


def _redact_key(text: str, key: str) -> str:
    if len(key) < 8:
        return text
    return text.replace(key, "[redacted]")
