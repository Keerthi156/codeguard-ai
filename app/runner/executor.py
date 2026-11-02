"""Send validated test cases to the configured localhost target.

The executor builds each request from the test's route, method, identity, and
resource id. It does not run commands or code from the plan, and it does not
store the Authorization header.
"""

from __future__ import annotations

import asyncio
import importlib
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.analyzer.routes import is_collection_route
from app.schemas import TestCase
from app.target_config import TargetConfig, request_timeout_seconds

_BODY_LIMIT = 300
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_SYNTHETIC_BODY = {"title": "synthetic", "content": "synthetic"}
_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_REFUSAL = "request refused because the URL is not http://127.0.0.1 or http://localhost"
CANNOT_RESET = "cannot reset target state"
STATE_TAINTED = "resource deleted earlier in this session"

Access = Literal["allowed", "denied"]
Outcome = Literal["pass", "fail", "inconclusive"]


class Evidence(BaseModel):
    """Sanitized record of one request. No credentials."""

    model_config = ConfigDict(extra="forbid")

    method: str
    path: str
    identity: str
    status_code: int | None
    body: str = Field(max_length=_BODY_LIMIT)
    label: str = ""


class TestResult(BaseModel):
    """Observed result of one executed test."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    test_id: str
    status_code: int | None
    access: Access | None
    matches_expected: bool | None
    outcome: Outcome
    evidence: Evidence
    session: int = 0


class _Refused(Exception):
    """The test tried to address a URL this executor will not call."""


@dataclass
class ExecutionStats:
    """How many times one plan restored the target before a destructive test."""

    resets: int = 0


def destructive_method_set(config: TargetConfig) -> frozenset[str]:
    """Methods that remove a resource. Missing config uses DELETE."""
    try:
        raw = config.destructive_methods
    except AttributeError:
        raw = None
    if raw is None:
        return frozenset({"DELETE"})
    return frozenset(str(item).upper() for item in raw)


def resource_key(path: str) -> str:
    """Identity of the object a request addressed, ignoring a query string."""
    concrete = path.split("?", 1)[0].split("#", 1)[0]
    if len(concrete) > 1 and concrete.endswith("/"):
        concrete = concrete[:-1]
    return concrete


def resolve_reset(
    config: TargetConfig,
    override: Callable[[], object] | None,
) -> Callable[[], object] | None:
    """Use the caller's reset. Otherwise use the configured import path, and nothing else."""
    if override is not None:
        return override
    try:
        spec = config.reset
    except AttributeError:
        spec = None
    if not isinstance(spec, str) or not spec or ":" not in spec:
        return None
    module_name, _, attribute = spec.partition(":")
    if not module_name or not attribute:
        return None

    def call() -> None:
        module = importlib.import_module(module_name)
        function = getattr(module, attribute)
        function()

    return call


def apply_state_taint(
    results: Sequence[TestResult],
    destructive_methods: Sequence[str] | None = None,
) -> list[TestResult]:
    """A later result on a resource deleted earlier in the same session is inconclusive.

    A reset starts a new session, so a fresh target is not tainted by an earlier one.
    A tainted 404 is not a denial and not a pass.
    """
    methods = {item.upper() for item in (destructive_methods or ("DELETE",))}
    deleted: dict[int, set[str]] = {}
    output: list[TestResult] = []
    for result in results:
        key = resource_key(result.evidence.path)
        if key and key in deleted.get(result.session, set()):
            output.append(_tainted(result))
            continue
        output.append(result)
        if key and _removed_resource(result, methods):
            deleted.setdefault(result.session, set()).add(key)
    return output


async def execute_plan(
    tests: Sequence[TestCase],
    config: TargetConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float | None = None,
    reset: Callable[[], object] | None = None,
    stats: ExecutionStats | None = None,
) -> list[TestResult]:
    """Run each test against ``config.base_url`` and return sanitized results.

    Non-destructive tests share one session. Each destructive test runs only
    after the target is restored, in its own session. Without a reset, a
    destructive test is not sent.
    """
    base_url = _require_localhost(config.base_url)
    tokens = {user.name: user.token for user in config.users}
    token_values = [token for token in tokens.values() if token]
    methods = destructive_method_set(config)
    reset_fn = resolve_reset(config, reset)
    counted = stats if stats is not None else ExecutionStats()
    limit = float(timeout) if timeout is not None else request_timeout_seconds(config)
    runnable = [test for test in tests if not is_collection_route(test.route)]
    shared = [test for test in runnable if test.method.upper() not in methods]
    isolated = [test for test in runnable if test.method.upper() in methods]
    results: list[TestResult] = []
    async with httpx.AsyncClient(
        transport=transport,
        base_url=base_url,
        timeout=httpx.Timeout(limit),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        for test in shared:
            result = await _execute_one(client, test, base_url, tokens, token_values, limit)
            results.append(result.model_copy(update={"session": 0}))
        session = 0
        for test in isolated:
            if reset_fn is None:
                results.append(_inconclusive(test, None, CANNOT_RESET, token_values))
                continue
            if not await _call_reset(reset_fn):
                results.append(_inconclusive(test, None, CANNOT_RESET, token_values))
                continue
            counted.resets += 1
            session += 1
            current = _require_localhost(config.base_url)
            client.base_url = current
            result = await _execute_one(client, test, current, tokens, token_values, limit)
            results.append(result.model_copy(update={"session": session}))
    return apply_state_taint(results, methods)


async def _call_reset(reset: Callable[[], object]) -> bool:
    try:
        outcome = reset()
        if isinstance(outcome, Awaitable):
            await outcome
    except Exception:
        return False
    return True


async def _execute_one(
    client: httpx.AsyncClient,
    test: TestCase,
    base_url: str,
    tokens: dict[str, str],
    token_values: list[str],
    timeout: float,
) -> TestResult:
    try:
        path = _local_path(test.route, test.resource_id, base_url)
    except _Refused:
        return _inconclusive(test, None, _REFUSAL, token_values)

    if test.identity == "unauthenticated":
        headers: dict[str, str] = {}
    else:
        token = tokens.get(test.identity)
        if token is None:
            return _inconclusive(test, path, "unknown identity", token_values)
        headers = {"Authorization": f"Bearer {token}"}

    try:
        response = await asyncio.wait_for(
            client.request(
                test.method,
                path,
                headers=headers,
                json=_SYNTHETIC_BODY if test.method in _WRITE_METHODS else None,
            ),
            timeout=timeout,
        )
    except (TimeoutError, httpx.TimeoutException):
        return _inconclusive(test, path, "timeout", token_values)
    except httpx.RequestError:
        return _inconclusive(test, path, "connection failed", token_values)
    except Exception:
        return _inconclusive(test, path, "request failed", token_values)

    body = _sanitize(response.text, token_values)
    return _from_status(test, path, response.status_code, body)


def _from_status(test: TestCase, path: str, status_code: int, body: str) -> TestResult:
    access = _access(status_code)
    if access is None:
        return _result(test, path, status_code, None, None, "inconclusive", body)
    matches = _matches(access, test.expected)
    return _result(test, path, status_code, access, matches, "pass" if matches else "fail", body)


def _access(status_code: int) -> Access | None:
    if 200 <= status_code < 300:
        return "allowed"
    if status_code in {401, 403, 404}:
        return "denied"
    return None


def _matches(access: Access, expected: str) -> bool:
    if expected == "allow":
        return access == "allowed"
    return access == "denied"


def _inconclusive(test: TestCase, path: str | None, body: str, tokens: list[str]) -> TestResult:
    safe_path = path if path is not None else _safe_path(test.route, test.resource_id)
    return _result(test, safe_path, None, None, None, "inconclusive", _sanitize(body, tokens))


def _result(
    test: TestCase,
    path: str,
    status_code: int | None,
    access: Access | None,
    matches_expected: bool | None,
    outcome: Outcome,
    body: str,
) -> TestResult:
    evidence = Evidence(
        method=test.method,
        path=path,
        identity=test.identity,
        status_code=status_code,
        body=body,
    )
    return TestResult(
        test_id=test.id,
        status_code=status_code,
        access=access,
        matches_expected=matches_expected,
        outcome=outcome,
        evidence=evidence,
    )


def _removed_resource(result: TestResult, methods: set[str]) -> bool:
    if result.evidence.method.upper() not in methods:
        return False
    if result.outcome != "pass" or result.access != "allowed":
        return False
    code = result.status_code
    return code is not None and 200 <= code < 300


def _tainted(result: TestResult) -> TestResult:
    evidence = result.evidence.model_copy(update={"body": STATE_TAINTED})
    return result.model_copy(
        update={
            "access": None,
            "matches_expected": None,
            "outcome": "inconclusive",
            "evidence": evidence,
        }
    )


def _require_localhost(base_url: str) -> str:
    parsed = urlsplit(base_url.strip())
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "http"
        or host not in _ALLOWED_HOSTS
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(_REFUSAL)
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"http://{host}{port}"


def _local_path(route: str, resource_id: str, base_url: str) -> str:
    if "://" in route or route.startswith("//"):
        parsed = urlsplit(route if "://" in route else f"http:{route}")
        host = (parsed.hostname or "").lower()
        configured = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", ""}
            or host not in _ALLOWED_HOSTS
            or host != configured.hostname
            or parsed.port != configured.port
            or parsed.username
            or parsed.password
        ):
            raise _Refused(_REFUSAL)
        path = parsed.path or "/"
    else:
        path = route
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
        raise _Refused(_REFUSAL)
    if any(part == ".." for part in path.split("/")):
        raise _Refused(_REFUSAL)
    safe_id = quote(resource_id, safe="")
    return _PLACEHOLDER.sub(safe_id, path)


def _safe_path(route: str, resource_id: str) -> str:
    path = urlsplit(route).path if "://" in route or route.startswith("//") else route
    if not path.startswith("/"):
        return "/"
    return _PLACEHOLDER.sub(quote(resource_id, safe=""), path.split("?", 1)[0].split("#", 1)[0])


def _sanitize(body: str, tokens: list[str]) -> str:
    redacted = body
    for token in sorted(set(tokens), key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return redacted[:_BODY_LIMIT]
