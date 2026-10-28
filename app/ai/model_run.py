"""Summary of the provider that drafted one scan's test plan."""

from __future__ import annotations

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

    def with_counts(self, *, proposed: int, accepted: int, rejected: int) -> ModelRun:
        return replace(self, proposed=proposed, accepted=accepted, rejected=rejected)

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
            )
        )
