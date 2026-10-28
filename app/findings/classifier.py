"""Turn static route findings and executed tests into finding records.

A route is Confirmed only when a non-owner or unauthenticated caller received
access the matrix denies and the owner control for that route passed. Timeouts,
failed owner controls, and 5xx responses stay Inconclusive.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.analyzer.auth_checks import RouteFinding
from app.runner.executor import Evidence, TestResult
from app.schemas import AuthorizationMatrix, Resource

FindingStatus = Literal[
    "Suspected",
    "Confirmed",
    "Fix proposed",
    "Verification failed",
    "Verified",
    "Inconclusive",
]
_UNAUTHENTICATED = frozenset({"unauthenticated", "anonymous"})
_READ_METHODS = frozenset({"GET", "HEAD"})
_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


class Finding(BaseModel):
    """A classified authorization finding. Evidence is sanitized."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    id: str
    route: str
    method: str
    status: FindingStatus
    reason: str
    evidence: list[Evidence] = Field(default_factory=list)
    source_lines: list[int] = Field(default_factory=list)
    created_at: datetime
    target_revision: str | None = None


@dataclass
class _RouteGroup:
    method: str
    route: str
    suspected: bool = False
    source_lines: list[int] = field(default_factory=list)
    static_reason: str = ""


def classify(
    route_findings: Sequence[RouteFinding],
    test_results: Sequence[TestResult],
    matrix: AuthorizationMatrix,
) -> list[Finding]:
    """Classify each route using the matrix and the executed tests."""
    created_at = datetime.now(timezone.utc)
    revision = git_revision()
    tokens = [user.token for user in matrix.users if user.token]
    findings: list[Finding] = []
    for group in _groups(route_findings):
        matched = _results_for_route(group, test_results, matrix)
        decision = _decide(group, matched, matrix)
        if decision is None:
            continue
        status, reason = decision
        findings.append(
            Finding(
                id=_finding_id(group.method, group.route),
                route=group.route,
                method=group.method,
                status=status,
                reason=reason,
                evidence=[_redact(result.evidence, tokens) for result in matched],
                source_lines=sorted(set(group.source_lines)),
                created_at=created_at,
                target_revision=revision,
            )
        )
    return findings


def git_revision() -> str | None:
    """Return the current git HEAD, or None when git is unavailable."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    revision = completed.stdout.strip()
    return revision or None


def _groups(route_findings: Sequence[RouteFinding]) -> list[_RouteGroup]:
    grouped: dict[tuple[str, str], _RouteGroup] = {}
    for finding in route_findings:
        key = (finding.method.upper(), finding.path)
        group = grouped.get(key)
        if group is None:
            group = _RouteGroup(method=key[0], route=finding.path)
            grouped[key] = group
        if finding.status == "Suspected":
            group.suspected = True
            group.static_reason = finding.reason
        group.source_lines.extend(finding.line_numbers)
    return [grouped[key] for key in sorted(grouped)]


def _results_for_route(
    group: _RouteGroup,
    test_results: Sequence[TestResult],
    matrix: AuthorizationMatrix,
) -> list[TestResult]:
    matched: list[TestResult] = []
    for result in test_results:
        if result.evidence.method.upper() != group.method:
            continue
        if _resource_for_path(group.route, result.evidence.path, matrix.resources) is None:
            continue
        matched.append(result)
    return matched


def _decide(
    group: _RouteGroup,
    results: Sequence[TestResult],
    matrix: AuthorizationMatrix,
) -> tuple[FindingStatus, str] | None:
    users = {user.name for user in matrix.users}
    rules = matrix.read if group.method in _READ_METHODS else matrix.write
    inconclusive = False
    owner_passed = False
    owner_failed = False
    reproduced = False
    denied_correctly = False

    for result in results:
        resource = _resource_for_path(group.route, result.evidence.path, matrix.resources)
        if resource is None:
            continue
        if result.outcome == "inconclusive" or result.access is None or _is_server_error(result.status_code):
            inconclusive = True
            continue
        condition = _condition(result.evidence.identity, resource.owner, users)
        if condition is None:
            continue
        required = getattr(rules, condition).expected
        if condition == "owner" and required == "allow":
            if result.access == "allowed" and result.outcome == "pass":
                owner_passed = True
            else:
                owner_failed = True
        if condition in {"non_owner", "unauthenticated"} and required == "deny":
            if result.access == "allowed":
                reproduced = True
            elif result.access == "denied":
                denied_correctly = True

    if inconclusive:
        return "Inconclusive", "A needed test was inconclusive, so this route is Inconclusive."
    if owner_failed:
        return "Inconclusive", "The owner control test failed, so this route is Inconclusive."
    if reproduced and owner_passed:
        return (
            "Confirmed",
            "A non-owner or unauthenticated caller received access the matrix denies, "
            "and the owner control test for this route passed.",
        )
    if group.suspected and denied_correctly and not reproduced:
        return "Suspected", "Suspected, not reproduced"
    if group.suspected:
        return "Suspected", group.static_reason or "Static heuristics marked this route Suspected."
    return None


def _condition(identity: str, owner: str, users: set[str]) -> str | None:
    if identity in _UNAUTHENTICATED:
        return "unauthenticated"
    if identity == owner:
        return "owner"
    if identity in users:
        return "non_owner"
    return None


def _resource_for_path(template: str, concrete: str, resources: Sequence[Resource]) -> Resource | None:
    for resource in resources:
        filled = _PLACEHOLDER.sub(resource.id, template)
        if filled == concrete:
            return resource
    return None


def _is_server_error(status_code: int | None) -> bool:
    return status_code is not None and status_code >= 500


def _finding_id(method: str, route: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", route.lower()).strip("-")
    return f"{method.lower()}-{slug or 'route'}"


def _redact(evidence: Evidence, tokens: list[str]) -> Evidence:
    body = evidence.body
    for token in sorted(set(tokens), key=len, reverse=True):
        body = body.replace(token, "[redacted]")
    return evidence.model_copy(update={"body": body[:300]})
