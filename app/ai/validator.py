"""Reject test plans that are not safe to run against the configured local target.

Plans are data. A case is accepted only when its route, method, identity,
resource, and expected outcome match the discovered routes, the target config,
and the authorization matrix. Commands, code, shell, and off-target hosts are
rejected.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.schemas import AuthorizationMatrix, HttpMethod, TestCase, TestPlan
from app.target_config import TargetConfig

MAX_PLAN_CASES = 32
_FORBIDDEN_FIELDS = frozenset({"command", "code", "shell", "url"})
_CASE_FIELDS = frozenset({"id", "route", "method", "identity", "resource_id", "expected", "reason"})
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_UNAUTHENTICATED = frozenset({"unauthenticated", "anonymous"})
_URL = re.compile(r"(?:https?:)?//[^\s\"'<>]+", re.IGNORECASE)
_READ_METHODS = frozenset({"GET", "HEAD"})


class _RouteRef(Protocol):
    method: str
    path: str


class RejectedTest(BaseModel):
    """A planned test that must not be run, with the reasons it was refused."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    id: str
    reasons: list[str] = Field(min_length=1)


class ValidationResult(BaseModel):
    """Accepted cases and the cases that were rejected."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    accepted: list[TestCase]
    rejected: list[RejectedTest]


def validate_plan(
    plan: TestPlan | Mapping[str, object],
    routes: Sequence[_RouteRef],
    matrix: AuthorizationMatrix,
    config: TargetConfig,
) -> ValidationResult:
    """Split a plan into tests that match policy and tests that are refused."""
    if isinstance(plan, TestPlan):
        raw: dict[str, object] = dict(plan.model_dump())
    elif isinstance(plan, Mapping):
        raw = dict(plan)
    else:
        return ValidationResult(
            accepted=[],
            rejected=[RejectedTest(id="<plan>", reasons=["plan must be an object"])],
        )

    plan_reasons = _plan_reasons(raw, config)
    cases = raw.get("cases")
    if not isinstance(cases, list):
        reasons = [*plan_reasons, "cases must be a list"]
        return ValidationResult(accepted=[], rejected=[RejectedTest(id="<plan>", reasons=reasons)])

    if len(cases) > MAX_PLAN_CASES:
        plan_reasons.append(f"plan has {len(cases)} tests, which exceeds the limit of {MAX_PLAN_CASES}")

    allowed = _allowed_routes(routes, config)
    accepted: list[TestCase] = []
    rejected: list[RejectedTest] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(cases, start=1):
        case_id, reasons, parsed = _validate_case(item, allowed, matrix, config, seen_ids)
        reasons = _merge(plan_reasons, reasons)
        if reasons or parsed is None:
            rejected.append(RejectedTest(id=case_id or f"case-{index}", reasons=reasons or ["invalid test"]))
            continue
        accepted.append(parsed)
    if not cases and plan_reasons:
        rejected.append(RejectedTest(id="<plan>", reasons=plan_reasons))
    return ValidationResult(accepted=accepted, rejected=rejected)


def _plan_reasons(raw: dict[str, object], config: TargetConfig) -> list[str]:
    reasons: list[str] = []
    for key, value in raw.items():
        if key == "cases":
            continue
        _add(reasons, _field_reason(str(key)))
        reasons.extend(_host_reasons(value, config))
    return _unique(reasons)


def _validate_case(
    item: object,
    allowed: set[tuple[str, str]],
    matrix: AuthorizationMatrix,
    config: TargetConfig,
    seen_ids: set[str],
) -> tuple[str, list[str], TestCase | None]:
    if not isinstance(item, Mapping):
        return "", ["test must be an object"], None
    raw = dict(item)
    case_id = raw.get("id")
    label = case_id if isinstance(case_id, str) and case_id else ""
    reasons: list[str] = []
    for key in raw:
        if key not in _CASE_FIELDS:
            _add(reasons, _field_reason(str(key)))
    reasons.extend(_host_reasons(raw, config))

    route = _text(raw.get("route"), "route", reasons)
    method = _method(raw.get("method"), reasons)
    identity = _text(raw.get("identity"), "identity", reasons)
    resource_id = _text(raw.get("resource_id"), "resource_id", reasons)
    expected = _decision(raw.get("expected"), reasons)
    reason = _text(raw.get("reason"), "reason", reasons)
    if not label and isinstance(case_id, str):
        _add(reasons, "id must be a non-empty string")
    elif not isinstance(case_id, str):
        _add(reasons, "id must be a non-empty string")

    path = _path(route, reasons) if route is not None else None
    if method is not None and path is not None and (method, path) not in allowed:
        _add(reasons, _route_reason(method, path, allowed))

    known_users = {user.name for user in matrix.users} & {user.name for user in config.users}
    known_resources = {resource.id: resource for resource in matrix.resources}
    known_resources = {
        resource_id_: resource
        for resource_id_, resource in known_resources.items()
        if resource_id_ in {resource.id for resource in config.resources}
    }
    if identity is not None and identity not in known_users and identity not in _UNAUTHENTICATED:
        _add(reasons, f"unknown identity {identity!r}")
    if resource_id is not None and resource_id not in known_resources:
        _add(reasons, f"unknown resource {resource_id!r}")
    if (
        method is not None
        and identity is not None
        and resource_id is not None
        and resource_id in known_resources
        and (identity in known_users or identity in _UNAUTHENTICATED)
        and expected is not None
    ):
        _add(reasons, _expectation_reason(method, path, identity, known_resources[resource_id].owner, expected, matrix, config))

    if label:
        if label in seen_ids:
            _add(reasons, f"duplicate test id {label!r}")
        seen_ids.add(label)

    if reasons or None in {route, method, identity, resource_id, expected, reason} or not label:
        return label, _unique(reasons), None
    assert route is not None and method is not None and identity is not None
    assert resource_id is not None and expected is not None and reason is not None and path is not None
    return label, [], TestCase(
        id=label,
        route=path,
        method=method,
        identity=identity,
        resource_id=resource_id,
        expected=expected,
        reason=reason,
    )


def _allowed_routes(routes: Sequence[_RouteRef], config: TargetConfig) -> set[tuple[str, str]]:
    discovered = {(route.method.upper(), route.path) for route in routes}
    configured = {(route.method.upper(), route.path) for route in config.routes}
    return discovered & configured


def _expectation_reason(
    method: str,
    path: str | None,
    identity: str,
    owner: str,
    expected: str,
    matrix: AuthorizationMatrix,
    config: TargetConfig,
) -> str:
    operation = _operation(method, path, config)
    rules = matrix.read if operation == "read" else matrix.write
    if identity in _UNAUTHENTICATED:
        condition = "unauthenticated"
        required = rules.unauthenticated.expected
    elif identity == owner:
        condition = "owner"
        required = rules.owner.expected
    else:
        condition = "non_owner"
        required = rules.non_owner.expected
    if expected == required:
        return ""
    return (
        f"expected {expected!r} contradicts the matrix "
        f"({condition} {operation} must be {required})"
    )


def _operation(method: str, path: str | None, config: TargetConfig) -> str:
    if path is not None:
        for route in config.routes:
            if route.method.upper() == method and route.path == path:
                return route.operation
    return "read" if method in _READ_METHODS else "write"


def _route_reason(method: str, path: str, allowed: set[tuple[str, str]]) -> str:
    if method not in _METHODS:
        return f"unknown method {method!r}"
    if path not in {route_path for _, route_path in allowed}:
        return f"unknown route {path!r}"
    return f"unknown method {method!r} for route {path!r}"


def _path(route: str, reasons: list[str]) -> str | None:
    if "://" in route or route.startswith("//"):
        parsed = urlsplit(route if "://" in route else f"http:{route}")
        if parsed.query or parsed.fragment:
            _add(reasons, "route must not include a query or fragment")
        return parsed.path or "/"
    if not route.startswith("/"):
        _add(reasons, f"unknown route {route!r}")
        return None
    if "?" in route or "#" in route:
        _add(reasons, "route must not include a query or fragment")
    return route.split("?", 1)[0].split("#", 1)[0]


def _host_reasons(value: object, config: TargetConfig) -> list[str]:
    reasons: list[str] = []
    target = urlsplit(config.base_url)
    for url in _urls(value):
        parsed = urlsplit(url if "://" in url else f"http:{url}")
        host = (parsed.hostname or "").lower()
        same_host = parsed.scheme == "http" and host == target.hostname and parsed.port == target.port
        if same_host:
            continue
        shown = host or url
        if parsed.port is not None and host:
            shown = f"{host}:{parsed.port}"
        _add(reasons, f"host {shown!r} is not the configured target {config.base_url}")
    return reasons


def _urls(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        found.extend(_URL.findall(value))
    elif isinstance(value, Mapping):
        for item in value.values():
            found.extend(_urls(item))
        for key in value:
            if isinstance(key, str):
                found.extend(_URL.findall(key))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            found.extend(_urls(item))
    return found


def _field_reason(key: str) -> str:
    if key.lower() in _FORBIDDEN_FIELDS:
        return f"forbidden field {key!r}"
    return f"unknown field {key!r}"


def _method(value: object, reasons: list[str]) -> HttpMethod | None:
    if not isinstance(value, str) or not value.strip():
        _add(reasons, "method must be a non-empty string")
        return None
    method = value.upper()
    if method not in _METHODS:
        _add(reasons, f"unknown method {method!r}")
        return None
    return method  # type: ignore[return-value]


def _decision(value: object, reasons: list[str]) -> str | None:
    if value not in {"allow", "deny"}:
        _add(reasons, "expected must be allow or deny")
        return None
    return str(value)


def _text(value: object, field: str, reasons: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        _add(reasons, f"{field} must be a non-empty string")
        return None
    return value


def _merge(plan_reasons: list[str], case_reasons: list[str]) -> list[str]:
    return _unique([*plan_reasons, *case_reasons])


def _add(reasons: list[str], reason: str) -> None:
    if reason and reason not in reasons:
        reasons.append(reason)


def _unique(reasons: list[str]) -> list[str]:
    result: list[str] = []
    for reason in reasons:
        _add(result, reason)
    return result
