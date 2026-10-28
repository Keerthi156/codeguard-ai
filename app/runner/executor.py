"""Send validated test cases to the configured localhost target.

The executor builds each request from the test's route, method, identity, and
resource id. It does not run commands or code from the plan, and it does not
store the Authorization header.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from typing import Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.schemas import TestCase
from app.target_config import TargetConfig

DEFAULT_TIMEOUT_SECONDS = 2.0
_BODY_LIMIT = 300
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_SYNTHETIC_BODY = {"title": "synthetic", "content": "synthetic"}
_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_REFUSAL = "request refused because the URL is not http://127.0.0.1 or http://localhost"

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


class _Refused(Exception):
    """The test tried to address a URL this executor will not call."""


async def execute_plan(
    tests: Sequence[TestCase],
    config: TargetConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[TestResult]:
    """Run each test against ``config.base_url`` and return sanitized results."""
    base_url = _require_localhost(config.base_url)
    tokens = {user.name: user.token for user in config.users}
    token_values = [token for token in tokens.values() if token]
    results: list[TestResult] = []
    async with httpx.AsyncClient(
        transport=transport,
        base_url=base_url,
        timeout=httpx.Timeout(timeout),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        for test in tests:
            results.append(await _execute_one(client, test, base_url, tokens, token_values, timeout))
    return results


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

    token = tokens.get(test.identity)
    if token is None:
        return _inconclusive(test, path, "unknown identity", token_values)

    try:
        response = await asyncio.wait_for(
            client.request(
                test.method,
                path,
                headers={"Authorization": f"Bearer {token}"},
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
