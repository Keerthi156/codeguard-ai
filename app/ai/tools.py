"""Read-only tools for the model planning loop.

Every tool reads the findings and matrix already passed into the provider.
Nothing here opens files, runs commands, or makes network calls.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.analyzer.auth_checks import RouteFinding
from app.schemas import AuthorizationMatrix, OperationRules

_ROUTE_KEYS = frozenset({"route_id"})


class ToolError(Exception):
    """The model asked for a tool in a way we will not run."""


def list_routes(findings: Sequence[RouteFinding]) -> dict[str, object]:
    """Discovered routes and the static heuristic for each one."""
    return {
        "routes": [
            {
                "route_id": route_id(finding),
                "method": finding.method,
                "path": finding.path,
                "status": finding.status,
                "function_name": finding.function_name,
                "reason": finding.reason,
                "confidence": finding.confidence,
                "line_numbers": list(finding.line_numbers),
            }
            for finding in findings
        ]
    }


def read_handler(findings: Sequence[RouteFinding], args: dict[str, object]) -> dict[str, object]:
    """Handler source already extracted for one discovered route."""
    _exact_keys(args, _ROUTE_KEYS)
    route = args.get("route_id")
    if not isinstance(route, str) or not route.strip():
        raise ToolError("invalid arguments")
    finding = _by_id(findings).get(route.strip())
    if finding is None:
        raise ToolError("unknown route")
    return {
        "route_id": route_id(finding),
        "source": finding.source,
        "line_numbers": list(finding.line_numbers),
    }


def get_matrix(matrix: AuthorizationMatrix) -> dict[str, object]:
    """Authorization rules and the identities and resource ids tests may use."""
    return {
        "identities": [user.name for user in matrix.users],
        "resource_ids": [resource.id for resource in matrix.resources],
        "resources": [{"id": resource.id, "owner": resource.owner} for resource in matrix.resources],
        "read": _rules(matrix.read),
        "write": _rules(matrix.write),
    }


def submit_plan(args: dict[str, object]) -> dict[str, object]:
    """Return the submitted object. Schema and policy checks happen in the provider."""
    return dict(args)


def route_id(finding: RouteFinding) -> str:
    return f"{finding.method.upper()} {finding.path}"


def _by_id(findings: Sequence[RouteFinding]) -> dict[str, RouteFinding]:
    found: dict[str, RouteFinding] = {}
    for finding in findings:
        found.setdefault(route_id(finding), finding)
    return found


def _exact_keys(args: dict[str, object], allowed: frozenset[str]) -> None:
    if set(args) != allowed:
        raise ToolError("invalid arguments")


def _rules(rules: OperationRules) -> dict[str, str]:
    values = {
        "owner": rules.owner.expected,
        "non_owner": rules.non_owner.expected,
    }
    if rules.unauthenticated is not None:
        values["unauthenticated"] = rules.unauthenticated.expected
    return values
