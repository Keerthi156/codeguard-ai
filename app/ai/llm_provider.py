"""OpenAI-compatible planner. It returns a TestPlan and never runs model output.

The API key is sent only as the Authorization header. It is not logged, printed,
or included in errors. Reasoning fields on the response are ignored.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Sequence

import httpx
from pydantic import ValidationError

from app.ai.model_run import ModelRun
from app.analyzer.auth_checks import RouteFinding
from app.config import Settings
from app.schemas import AuthorizationMatrix, OperationRules, TestPlan

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

DEFAULT_REQUEST_CAP = 6
_TIMEOUT_SECONDS = 60.0
_MAX_TOKENS = 4000
_HTTP_ATTEMPTS = 3
_FENCE = re.compile(r"^```[a-zA-Z0-9]*\s*|\s*```$", re.MULTILINE)

_SYSTEM = (
    "You draft authorization test cases as data. "
    "Reply with JSON only, with no markdown and no prose. "
    "Do not include commands, code, shell, or URLs. "
    'The JSON object must be {"cases":[{"id","route","method","identity",'
    '"resource_id","expected","reason"}]}. '
    "expected is allow or deny. "
    "Use only the identities and resource ids you are given."
)


class _PlanError(Exception):
    """The model text was not a valid TestPlan."""


class LLMProvider:
    """Draft a test plan from one chat-completions model."""

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

    def plan_tests(self, findings: Sequence[RouteFinding], matrix: AuthorizationMatrix) -> TestPlan:
        """Ask the model for access checks of the suspected routes only."""
        self._requests = 0
        self._latency_ms = 0
        self._total_tokens = None
        suspected = [finding for finding in findings if finding.status == "Suspected"]
        if not suspected:
            return TestPlan(cases=[])
        messages = [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _prompt(suspected, matrix)},
        ]
        raw = self._call_model(messages)
        try:
            return _parse_plan(raw)
        except _PlanError as first:
            retry = [
                *messages,
                {"role": "user", "content": f"The previous JSON was rejected: {first}. Reply with JSON only."},
            ]
            try:
                return _parse_plan(self._call_model(retry))
            except _PlanError as second:
                raise RuntimeError(f"model plan was rejected: {second}") from None

    def model_run(self) -> ModelRun:
        """Counts for the latest plan. The API key is not included."""
        return ModelRun(
            provider="llm",
            model_name=self._settings.model_name,
            calls=self._requests,
            proposed=0,
            accepted=0,
            rejected=0,
            total_tokens=self._total_tokens,
            latency_ms=self._latency_ms,
        )

    def _call_model(self, messages: list[dict[str, str]]) -> str:
        """POST one chat completion and return the answer text."""
        url = f"{self._settings.model_base_url.rstrip('/')}/chat/completions"
        body = {"model": self._settings.model_name, "messages": messages, "max_tokens": _MAX_TOKENS}
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
            return _redact_key(_message_content(payload), self._settings.model_api_key)
        raise RuntimeError(last_error)

    def _record_tokens(self, usage: object) -> None:
        _prompt_tokens, _completion_tokens, total = _usage(usage)
        if total is None:
            return
        self._total_tokens = total if self._total_tokens is None else self._total_tokens + total


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _message_content(payload: object) -> str:
    if not isinstance(payload, dict):
        raise RuntimeError("model response did not include message content")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise RuntimeError("model response did not include message content")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise RuntimeError("model response did not include message content")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("model response did not include message content")
    return content


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
    return (_token_count(usage.get("prompt_tokens")), _token_count(usage.get("completion_tokens")), _token_count(usage.get("total_tokens")))


def _token_count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _prompt(findings: Sequence[RouteFinding], matrix: AuthorizationMatrix) -> str:
    payload = {
        "routes": [
            {"method": finding.method, "path": finding.path, "source": finding.source}
            for finding in findings
        ],
        "identities": [user.name for user in matrix.users],
        "resource_ids": [resource.id for resource in matrix.resources],
        "resources": [{"id": resource.id, "owner": resource.owner} for resource in matrix.resources],
        "read": _rules(matrix.read),
        "write": _rules(matrix.write),
    }
    return json.dumps(payload, sort_keys=True)


def _rules(rules: OperationRules) -> dict[str, str]:
    return {
        "owner": rules.owner.expected,
        "non_owner": rules.non_owner.expected,
        "unauthenticated": rules.unauthenticated.expected,
    }


def _parse_plan(text: str) -> TestPlan:
    stripped = _FENCE.sub("", text.strip()).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise _PlanError(f"not valid JSON ({exc.msg})") from None
    if isinstance(data, list):
        data = {"cases": data}
    if not isinstance(data, dict):
        raise _PlanError("plan must be a JSON object")
    try:
        return TestPlan.model_validate(data)
    except ValidationError as exc:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.get('loc', ()))}: {error.get('msg', 'invalid')}"
            for error in exc.errors()
        )
        raise _PlanError(detail or "invalid plan") from None


def _redact_key(text: str, key: str) -> str:
    if len(key) < 8:
        return text
    return text.replace(key, "[redacted]")
