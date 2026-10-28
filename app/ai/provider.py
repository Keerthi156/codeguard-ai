"""Provider seam for drafting BOLA test plans.

A provider returns a TestPlan. It does not emit commands or code for the runner
to execute.
"""

from __future__ import annotations

from typing import Protocol, Sequence, runtime_checkable

from app.analyzer.auth_checks import RouteFinding
from app.schemas import AuthorizationMatrix, TestPlan


@runtime_checkable
class Provider(Protocol):
    def plan_tests(self, findings: Sequence[RouteFinding], matrix: AuthorizationMatrix) -> TestPlan:
        """Draft access checks from static findings and the authorization matrix."""
