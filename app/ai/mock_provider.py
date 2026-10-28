"""Development-only test planner.

MockProvider does not call a model. It builds a fixed plan for the document
fixtures: owner and non-owner checks for GET and PUT /documents/{id}.
"""

from __future__ import annotations

from typing import Literal, Sequence

from app.ai.model_run import ModelRun
from app.analyzer.auth_checks import RouteFinding
from app.schemas import AuthorizationMatrix, Decision, Resource, TestCase, TestPlan

_Method = Literal["GET", "PUT"]
_FIXTURE_ROUTES: tuple[tuple[_Method, str], ...] = (
    ("GET", "/documents/{id}"),
    ("PUT", "/documents/{id}"),
)


class MockProvider:
    """Deterministic planner for local fixture development."""

    def plan_tests(
        self,
        findings: Sequence[RouteFinding],
        matrix: AuthorizationMatrix,
        *,
        routes: Sequence[object] | None = None,
        config: object | None = None,
    ) -> TestPlan:
        del routes, config
        present = {(finding.method.upper(), finding.path) for finding in findings}
        cases: list[TestCase] = []
        for method, route in _FIXTURE_ROUTES:
            if (method, route) not in present:
                continue
            rules = matrix.read if method == "GET" else matrix.write
            for resource in sorted(matrix.resources, key=lambda item: item.id):
                cases.append(
                    _case(method, route, resource, resource.owner, "owner", rules.owner.expected)
                )
                others = sorted(
                    (user.name for user in matrix.users if user.name != resource.owner)
                )
                for identity in others:
                    cases.append(
                        _case(method, route, resource, identity, "non-owner", rules.non_owner.expected)
                    )
        return TestPlan(cases=cases)

    def model_run(self) -> ModelRun:
        """Mock planning does not call a model."""
        return ModelRun(
            provider="mock",
            model_name="",
            calls=0,
            proposed=0,
            accepted=0,
            rejected=0,
            total_tokens=None,
            latency_ms=0,
        )


def _case(
    method: _Method,
    route: str,
    resource: Resource,
    identity: str,
    role: str,
    expected: Decision,
) -> TestCase:
    relation = "owns" if role == "owner" else "does not own"
    return TestCase(
        id=f"{method.lower()}-{resource.id}-{role}-{identity}",
        route=route,
        method=method,
        identity=identity,
        resource_id=resource.id,
        expected=expected,
        reason=(
            f"{identity} {relation} {resource.id}; {method} {route} is expected to {expected} "
            "under the authorization matrix. This is a planned check, not a result."
        ),
    )
