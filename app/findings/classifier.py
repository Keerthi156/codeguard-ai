"""Turn static route findings and executed tests into finding records.

A route is Confirmed when an exploit test shows access the matrix denies and
the owner control for that route passed. Other inconclusive tests are coverage
gaps. A failed or inconclusive owner control is never Confirmed. Timeouts,
crashes, and 5xx responses are never exploit evidence.
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
_OWNER_FIELD = re.compile(r'"owner"\s*:\s*"([^"]*)"')
_LABEL_RANK = {"EXPLOIT": 0, "CONTROL": 1, "DENIED": 2, "FAILED": 3, "INCONCLUSIVE": 4, "CHECK": 5}


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
    coverage_gaps: list[str] = Field(default_factory=list)
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
        status, reason, gaps = decision
        findings.append(
            Finding(
                id=_finding_id(group.method, group.route),
                route=group.route,
                method=group.method,
                status=status,
                reason=reason,
                evidence=_ordered_evidence(group, matched, matrix, tokens),
                coverage_gaps=gaps,
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
) -> tuple[FindingStatus, str, list[str]] | None:
    users = {user.name for user in matrix.users}
    rules = matrix.read if group.method in _READ_METHODS else matrix.write
    owner_passed = False
    owner_blocked = False
    reproduced = False
    needed_inconclusive = False
    denied_correctly = False
    gaps: list[str] = []

    for result in results:
        resource = _resource_for_path(group.route, result.evidence.path, matrix.resources)
        condition = None if resource is None else _condition(result.evidence.identity, resource.owner, users)
        rule = None if condition is None else getattr(rules, condition)
        required = None if rule is None else rule.expected
        if _is_inconclusive(result):
            if _is_needed(condition, required):
                if condition == "owner":
                    owner_blocked = True
                else:
                    needed_inconclusive = True
            gaps.append(_gap(result))
            continue
        if condition is None or required is None or result.access is None:
            continue
        if condition == "owner" and required == "allow":
            if result.access == "allowed" and result.outcome == "pass":
                owner_passed = True
            else:
                owner_blocked = True
        if condition in {"non_owner", "unauthenticated"} and required == "deny":
            if result.access == "allowed":
                reproduced = True
            elif result.access == "denied":
                denied_correctly = True

    if owner_blocked:
        return (
            "Inconclusive",
            "The owner control test failed or was inconclusive, so this route is Inconclusive.",
            [],
        )
    if reproduced and owner_passed:
        return (
            "Confirmed",
            "A non-owner or unauthenticated caller received access the matrix denies, "
            "and the owner control test for this route passed.",
            _unique(gaps),
        )
    if not reproduced and needed_inconclusive:
        return "Inconclusive", "A needed test was inconclusive, so this route is Inconclusive.", []
    if group.suspected and denied_correctly and not reproduced:
        return "Suspected", "Suspected, not reproduced", []
    if group.suspected:
        return "Suspected", group.static_reason or "Static heuristics marked this route Suspected.", []
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


def _is_inconclusive(result: TestResult) -> bool:
    if result.outcome == "inconclusive" or result.access is None:
        return True
    return _is_server_error(result.status_code)


def _is_needed(condition: str | None, required: str | None) -> bool:
    if condition == "owner":
        return required == "allow"
    return condition in {"non_owner", "unauthenticated"} and required == "deny"


def _gap(result: TestResult) -> str:
    status = "-" if result.status_code is None else str(result.status_code)
    detail = " ".join(result.evidence.body.split())
    head = f"{_request(result.evidence.method, result.evidence.path)} as {result.evidence.identity} -> {status}"
    return f"{head}, {detail}" if detail else head


def _request(method: str, path: str) -> str:
    """Return ``GET /documents/101``, including when the path was stored glued to the verb."""
    verb = method.strip().upper()
    target = path.strip()
    if target.upper().startswith(verb + "/"):
        target = target[len(verb) :]
    return f"{verb} {target}"


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _is_server_error(status_code: int | None) -> bool:
    return status_code is not None and status_code >= 500


def _finding_id(method: str, route: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", route.lower()).strip("-")
    return f"{method.lower()}-{slug or 'route'}"


def evidence_line(item: Evidence) -> str:
    """One labeled evidence line. The body snippet stays truncated."""
    status = "-" if item.status_code is None else str(item.status_code)
    head = f"{_request(item.method, item.path)} as {item.identity} -> {status}"
    base = f"{item.label}: {head}" if item.label else head
    if item.label == "EXPLOIT":
        owner = _body_owner(item.body)
        if owner:
            return f"{base}, body shows owner {owner}"
        snippet = _snippet(item.body)
        return f"{base}, body {snippet}" if snippet else base
    if item.label == "CONTROL":
        return f"{base} (owner access works)"
    if item.label == "DENIED":
        return f"{base} (access denied)"
    snippet = _snippet(item.body)
    return f"{base}, body {snippet}" if snippet else base


def _ordered_evidence(
    group: _RouteGroup,
    results: Sequence[TestResult],
    matrix: AuthorizationMatrix,
    tokens: list[str],
) -> list[Evidence]:
    ranked: list[tuple[str, int, int, Evidence]] = []
    for index, result in enumerate(results):
        label = _evidence_label(group, result, matrix)
        evidence = _redact(result.evidence, tokens).model_copy(update={"label": label})
        ranked.append((result.evidence.path, _LABEL_RANK[label], index, evidence))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in ranked]


def _evidence_label(group: _RouteGroup, result: TestResult, matrix: AuthorizationMatrix) -> str:
    if result.outcome == "inconclusive" or result.access is None or _is_server_error(result.status_code):
        return "INCONCLUSIVE"
    resource = _resource_for_path(group.route, result.evidence.path, matrix.resources)
    if resource is None:
        return "CHECK"
    users = {user.name for user in matrix.users}
    condition = _condition(result.evidence.identity, resource.owner, users)
    if condition is None:
        return "CHECK"
    rules = matrix.read if group.method in _READ_METHODS else matrix.write
    required = getattr(rules, condition).expected
    if condition in {"non_owner", "unauthenticated"} and required == "deny" and result.access == "allowed":
        return "EXPLOIT"
    if condition == "owner" and required == "allow":
        return "CONTROL" if result.access == "allowed" and result.outcome == "pass" else "FAILED"
    if condition in {"non_owner", "unauthenticated"} and required == "deny" and result.access == "denied":
        return "DENIED"
    return "CHECK"


def _body_owner(body: str) -> str | None:
    match = _OWNER_FIELD.search(body)
    if match is None:
        return None
    owner = match.group(1).strip()
    return owner or None


def _snippet(body: str, limit: int = 80) -> str:
    compact = " ".join(body.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _redact(evidence: Evidence, tokens: list[str]) -> Evidence:
    body = evidence.body
    for token in sorted(set(tokens), key=len, reverse=True):
        body = body.replace(token, "[redacted]")
    return evidence.model_copy(update={"body": body[:300]})
