"""Summary of the provider that drafted one scan's test plan."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class ModelRun:
    """Counts for one planning run. No API key and no reasoning text."""

    provider: str
    model_name: str
    calls: int
    proposed: int
    accepted: int
    rejected: int
    total_tokens: int | None
    latency_ms: int
    tool_trace: tuple[tuple[str, str, int], ...] = ()
    tool_mode: str = ""
    plan_submissions: int = 0
    model_tests: int = 0
    required_tests: int = 0

    def with_counts(self, *, proposed: int, accepted: int, rejected: int) -> ModelRun:
        return replace(self, proposed=proposed, accepted=accepted, rejected=rejected)

    def with_sources(self, *, model_tests: int, required_tests: int) -> ModelRun:
        """Record model-proposed cases separately from the required set."""
        return replace(self, model_tests=model_tests, required_tests=required_tests)

    def trace_json(self) -> str:
        """Tool name, argument summary, and turn. No reasoning text and no keys."""
        return json.dumps(
            [{"tool": name, "args": args, "turn": turn} for name, args, turn in self.tool_trace],
            separators=(",", ":"),
        )

    def text(self) -> str:
        if self.provider == "mock":
            provider_line = "Provider: MOCK (development only)"
        else:
            provider_line = f"Provider: {self.provider}"
        tokens = "-" if self.total_tokens is None else str(self.total_tokens)
        model_name = self.model_name or "-"
        return "\n".join(
            (
                "Model run",
                provider_line,
                f"Model: {model_name}",
                f"Calls: {self.calls}",
                f"Proposed: {self.proposed}",
                f"Accepted: {self.accepted}",
                f"Rejected: {self.rejected}",
                f"Tokens: {tokens}",
                f"Latency: {self.latency_ms} ms",
                f"Tool mode: {self.tool_mode or '-'}",
                _tools_line(self.tool_trace),
                f"Plan submissions: {self.plan_submissions}",
                f"Model tests: {self.model_tests}",
                f"Required tests: {self.required_tests}",
            )
        )


def _tools_line(trace: tuple[tuple[str, str, int], ...]) -> str:
    if not trace:
        return "Tools: -"
    parts: list[str] = []
    current = ""
    count = 0
    for name, _args, _turn in trace:
        if name == current:
            count += 1
            continue
        if current:
            parts.append(current if count == 1 else f"{current} x{count}")
        current = name
        count = 1
    if current:
        parts.append(current if count == 1 else f"{current} x{count}")
    return "Tools: " + ", ".join(parts)
