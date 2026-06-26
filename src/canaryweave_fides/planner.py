"""Planner-LLM counterfactual showcase.

The Planner LLM is the privileged model the stack protects. It never sees raw
untrusted data in production. Here it appears *only* as an isolated, tool-free
demonstration: "had this prompt reached an unprotected planner, what would it
have done?" — the value-add story for a gateway deployment.

This call is deliberately separate from the Quarantined LLM judge: a different
system framing, a different provider instance, no shared state. It is opt-in and
provider-gated; when not enabled or unavailable it returns ``invoked=False`` with
a note rather than raising, so a render never crashes on a live-call failure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .providers.base import JudgeProviderConfig


@dataclass(frozen=True)
class PlannerShowcase:
    invoked: bool
    response_text: str = ""
    model: str | None = None
    latency_ms: float | None = None
    provider_calls: int = 0
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "invoked": self.invoked,
            "response_text": self.response_text,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "provider_calls": self.provider_calls,
            "note": self.note,
        }


def run_planner_showcase(
    prompt: str,
    *,
    config: JudgeProviderConfig | None,
    enabled: bool,
) -> PlannerShowcase:
    """Run the isolated, tool-free Planner showcase, or report why it didn't run."""
    if not enabled:
        return PlannerShowcase(
            invoked=False, note="planner showcase off (pass --show-planner)"
        )
    if config is None or not config.provider_calls_enabled:
        return PlannerShowcase(
            invoked=False,
            note="planner showcase needs --provider-calls-enabled",
        )
    try:
        from .providers.copilot_sdk import CopilotSdkJudgeProvider

        provider = CopilotSdkJudgeProvider(config)
        started = time.perf_counter()
        text = provider.complete_planner(prompt)
        latency_ms = (time.perf_counter() - started) * 1000.0
        return PlannerShowcase(
            invoked=True,
            response_text=text,
            model=config.model,
            latency_ms=latency_ms,
            provider_calls=1,
        )
    except Exception as exc:  # live provider boundary: never crash the render
        return PlannerShowcase(
            invoked=False, note=f"planner showcase unavailable: {exc}"
        )
