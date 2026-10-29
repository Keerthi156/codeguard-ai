"""Extra non-owner requests that a patch might still allow.

The set is fixed and built here. The model does not choose these requests.
Every request is sent only to the localhost patched copy.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote, urlsplit

import httpx

from app.schemas import OperationRules
from app.target_config import TargetConfig

_BODY_LIMIT = 300
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_SYNTHETIC_BODY = {"title": "synthetic", "content": "synthetic"}
_REFUSAL = "request refused because the URL is not http://127.0.0.1 or http://localhost"
_OTHER_METHODS = {
    "GET": ("PUT", "DELETE", "PATCH"),
    "PUT": ("GET", "DELETE", "PATCH"),
    "POST": ("GET", "DELETE", "PATCH"),
    "PATCH": ("GET", "PUT", "DELETE"),
    "DELETE": ("GET", "PUT", "PATCH"),
}

Classification = Literal["blocked", "bypass", "inconclusive"]
Outcome = Literal["hardened", "bypass", "inconclusive"]
AuthStyle = Literal["bearer", "bearer_case", "raw", "none"]


@dataclass(frozen=True)
class Variant:
    """One extra request. ``path`` may include a query string."""

    name: str
    method: str
    path: str
    identity: str
    auth: AuthStyle


@dataclass(frozen=True)
class VariantResult:
    """Observed result of one variant. The body is already redacted."""

    variant: Variant
    status_code: int | None
    classification: Classification
    body: str


@dataclass(frozen=True)
class VariantReport:
    """Route-level result of the bypass check."""

    outcome: Outcome
    results: tuple[VariantResult, ...]
    line: str
    reason: str
    model_feedback: str

    def to_json(self) -> str:
        payload = {
            "outcome": self.outcome,
            "line": self.line,
            "variants": [
                {
                    "name": item.variant.name,
                    "method": item.variant.method,
                    "path": item.variant.path,
                    "identity": item.variant.identity,
                    "status_code": item.status_code,
                    "classification": item.classification,
                    "body": item.body,
                }
                for item in self.results
            ],
        }
        return json.dumps(payload)


def build_variants(method: str, route: str, config: TargetConfig) -> list[Variant]:
    """Return the fixed variant set for one route. This does not send anything."""
    verb = method.upper()
    resource = sorted(config.resources, key=lambda item: item.id)[0]
    other_id = next(
        (item.id for item in sorted(config.resources, key=lambda item: item.id) if item.id != resource.id),
        resource.id,
    )
    non_owner = next(
        (user.name for user in sorted(config.users, key=lambda item: item.name) if user.name != resource.owner),
        None,
    )
    rules = _rules(config, verb)
    normal = _render(route, resource.id)
    zeros = resource.id.zfill(len(resource.id) + 1) if resource.id.isdigit() else f"0{resource.id}"
    variants: list[Variant] = []
    if non_owner is not None and rules.non_owner.expected == "deny":
        variants.extend(
            (
                Variant("trailing-slash", verb, _with_slash(normal), non_owner, "bearer"),
                Variant("leading-zeros", verb, _render(route, zeros), non_owner, "bearer"),
                Variant("whitespace-id", verb, _render(route, f"%20{resource.id}%20"), non_owner, "bearer"),
            )
        )
        for alt in _OTHER_METHODS[verb]:
            variants.append(Variant(f"method-{alt.lower()}", alt, normal, non_owner, "bearer"))
        variants.extend(
            (
                Variant("query-id", verb, f"{normal}?id={quote(other_id, safe='')}", non_owner, "bearer"),
                Variant("double-slash", verb, _render(route.replace("/{", "//{", 1), resource.id), non_owner, "bearer"),
                Variant("auth-case", verb, normal, non_owner, "bearer_case"),
                Variant("missing-bearer", verb, normal, non_owner, "raw"),
            )
        )
    if rules.unauthenticated is not None and rules.unauthenticated.expected == "deny":
        variants.extend(
            (
                Variant("trailing-slash-unauthenticated", verb, _with_slash(normal), "unauthenticated", "none"),
                Variant("leading-zeros-unauthenticated", verb, _render(route, zeros), "unauthenticated", "none"),
                Variant(
                    "query-id-unauthenticated",
                    verb,
                    f"{normal}?id={quote(other_id, safe='')}",
                    "unauthenticated",
                    "none",
                ),
                Variant(
                    "double-slash-unauthenticated",
                    verb,
                    _render(route.replace("/{", "//{", 1), resource.id),
                    "unauthenticated",
                    "none",
                ),
            )
        )
    return variants


def summarize(results: Sequence[VariantResult]) -> VariantReport:
    """Classify the route. A 2xx is a bypass. A 5xx or timeout is inconclusive."""
    bypasses = [item for item in results if item.classification == "bypass"]
    if bypasses:
        hit = bypasses[0]
        status = "-" if hit.status_code is None else str(hit.status_code)
        request = f"{hit.variant.method} {hit.variant.path} as {hit.variant.identity}"
        reason = f"bypass found via {request} -> {status}"
        return VariantReport(
            outcome="bypass",
            results=tuple(results),
            line=f"Bypass check: BYPASS FOUND via {request} -> {status}",
            reason=reason,
            model_feedback=(
                f"{reason}\n"
                f"response: {status} {hit.body}\n"
                "Every method on the same resource path needs the same owner check."
            ),
        )
    if not results or any(item.classification == "inconclusive" for item in results):
        return VariantReport(
            outcome="inconclusive",
            results=tuple(results),
            line=f"Bypass check: {len(results)} variants, inconclusive",
            reason="bypass check timed out or returned 5xx",
            model_feedback="",
        )
    return VariantReport(
        outcome="hardened",
        results=tuple(results),
        line=f"Bypass check: {len(results)} variants, 0 bypasses (HARDENED)",
        reason="",
        model_feedback="",
    )


async def execute_variants(
    variants: Sequence[Variant],
    config: TargetConfig,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 2.0,
) -> list[VariantResult]:
    """Send variants to ``config.base_url``. A non-localhost URL sends nothing."""
    base = _localhost_base(config.base_url)
    urls = [_request_url(base, variant.path) for variant in variants]
    tokens = {user.name: user.token for user in config.users}
    token_values = [token for token in tokens.values() if token]
    results: list[VariantResult] = []
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        for variant, url in zip(variants, urls, strict=True):
            results.append(await _one(client, variant, url, tokens, token_values, timeout))
    return results


def classify_status(status_code: int | None) -> Classification:
    """Map one response. Only a 2xx is a bypass. 5xx and a missing status are inconclusive."""
    if status_code is None or status_code >= 500:
        return "inconclusive"
    if 200 <= status_code < 300:
        return "bypass"
    return "blocked"


async def _one(
    client: httpx.AsyncClient,
    variant: Variant,
    url: str,
    tokens: dict[str, str],
    token_values: list[str],
    timeout: float,
) -> VariantResult:
    headers = _headers(variant, tokens)
    if headers is None:
        return _result(variant, None, "unknown identity", token_values)
    try:
        response = await asyncio.wait_for(
            client.request(
                variant.method,
                url,
                headers=headers,
                json=_SYNTHETIC_BODY if variant.method in _WRITE_METHODS else None,
            ),
            timeout=timeout,
        )
    except (TimeoutError, httpx.TimeoutException):
        return _result(variant, None, "timeout", token_values)
    except httpx.RequestError:
        return _result(variant, None, "connection failed", token_values)
    except Exception:
        return _result(variant, None, "request failed", token_values)
    return _result(variant, response.status_code, response.text, token_values)


def _result(variant: Variant, status_code: int | None, body: str, tokens: list[str]) -> VariantResult:
    safe = _redact(body, tokens)[:_BODY_LIMIT]
    return VariantResult(
        variant=variant,
        status_code=status_code,
        classification=classify_status(status_code),
        body=safe,
    )


def _headers(variant: Variant, tokens: dict[str, str]) -> dict[str, str] | None:
    if variant.auth == "none":
        return {}
    token = tokens.get(variant.identity)
    if token is None:
        return None
    if variant.auth == "raw":
        return {"Authorization": token}
    if variant.auth == "bearer_case":
        return {"Authorization": f"bEaReR {token}"}
    return {"Authorization": f"Bearer {token}"}


def _rules(config: TargetConfig, method: str) -> OperationRules:
    matrix = config.matrix()
    if method in {"GET", "HEAD"}:
        return matrix.read
    return matrix.write


def _render(route: str, token: str) -> str:
    rendered = route
    start = rendered.find("{")
    while start != -1:
        end = rendered.find("}", start)
        if end == -1:
            break
        rendered = rendered[:start] + token + rendered[end + 1 :]
        start = rendered.find("{")
    return rendered


def _with_slash(path: str) -> str:
    return path if path.endswith("/") else f"{path}/"


def _localhost_base(base_url: str) -> str:
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


def _request_url(base: str, path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or "\\" in path or "://" in path:
        raise ValueError(_REFUSAL)
    target = urlsplit(base + path)
    allowed = urlsplit(base)
    if (
        target.scheme != "http"
        or (target.hostname or "").lower() != allowed.hostname
        or target.port != allowed.port
        or target.username
        or target.password
        or any(part == ".." for part in target.path.split("/"))
    ):
        raise ValueError(_REFUSAL)
    return base + path


def _redact(body: str, tokens: list[str]) -> str:
    redacted = body
    for token in sorted(set(tokens), key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return redacted
