"""Deterministic checks added after a model plan has been validated.

The model chooses extra cases. These checks are always present for every
suspected route, so a scan does not depend on that choice.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.analyzer.auth_checks import RouteFinding
from app.schemas import AuthorizationMatrix, Decision, OperationRules, TestCase
from app.target_config import TargetConfig

_READ_METHODS = frozenset({"GET", "HEAD"})


def supplement_plan(
    accepted: Sequence[TestCase],
    findings: Sequence[RouteFinding],
    matrix: AuthorizationMatrix,
    config: TargetConfig,
) -> tuple[list[TestCase], int, int]:
    """Return model cases plus any missing required cases.

    The two counts are the accepted model cases and the size of the required set.
    """
    model_cases = [case.model_copy(update={"source": "model"}) for case in accepted]
    present = {
        (case.method.upper(), case.route, case.identity, case.resource_id) for case in model_cases
    }
    used_ids = {case.id for case in model_cases}
    required = _required_cases(findings, matrix, config)
    added: list[TestCase] = []
    for case in required:
        key = (case.method.upper(), case.route, case.identity, case.resource_id)
        if key in present:
            continue
        case_id = _unique_id(case.id, used_ids)
        added.append(case.model_copy(update={"id": case_id}))
        present.add(key)
    return [*model_cases, *added], len(model_cases), len(required)


def _required_cases(
    findings: Sequence[RouteFinding],
    matrix: AuthorizationMatrix,
    config: TargetConfig,
) -> list[TestCase]:
    cases: list[TestCase] = []
    seen: set[tuple[str, str]] = set()
    resources = sorted(matrix.resources, key=lambda item: item.id)
    others = sorted(user.name for user in matrix.users)
    for finding in findings:
        if finding.status != "Suspected":
            continue
        method = finding.method.upper()
        route = finding.path
        if (method, route) in seen or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        seen.add((method, route))
        rules = _rules(method, route, matrix, config)
        for resource in resources:
            cases.append(
                _case(
                    method,
                    route,
                    resource.id,
                    resource.owner,
                    "owner",
                    rules.owner.expected,
                    f"{resource.owner} owns {resource.id}; {method} {route} is a required owner control.",
                )
            )
            non_owner = next((name for name in others if name != resource.owner), "")
            if non_owner:
                cases.append(
                    _case(
                        method,
                        route,
                        resource.id,
                        non_owner,
                        "non-owner",
                        rules.non_owner.expected,
                        (
                            f"{non_owner} does not own {resource.id}; {method} {route} "
                            "is a required non-owner check."
                        ),
                    )
                )
        if resources and rules.unauthenticated is not None:
            resource_id = resources[0].id
            cases.append(
                _case(
                    method,
                    route,
                    resource_id,
                    "unauthenticated",
                    "unauthenticated",
                    rules.unauthenticated.expected,
                    (
                        f"an unauthenticated caller is denied {method} {route} for {resource_id}; "
                        "this is a required check."
                    ),
                )
            )
    return cases


def _case(
    method: str,
    route: str,
    resource_id: str,
    identity: str,
    role: str,
    expected: Decision,
    reason: str,
) -> TestCase:
    return TestCase(
        id=f"required-{method.lower()}-{resource_id}-{role}",
        route=route,
        method=method,  # type: ignore[arg-type]
        identity=identity,
        resource_id=resource_id,
        expected=expected,
        reason=reason,
        source="required",
    )


def _rules(method: str, route: str, matrix: AuthorizationMatrix, config: TargetConfig) -> OperationRules:
    operation = "read" if method in _READ_METHODS else "write"
    for item in config.routes:
        if item.method.upper() == method and item.path == route:
            operation = item.operation
            break
    return matrix.read if operation == "read" else matrix.write


def _unique_id(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    suffix = 2
    while f"{base}-{suffix}" in used:
        suffix += 1
    chosen = f"{base}-{suffix}"
    used.add(chosen)
    return chosen
