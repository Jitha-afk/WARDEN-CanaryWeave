from __future__ import annotations

from dataclasses import dataclass

from .fides import FidesIFCLayer
from .models import PolicyContext, QueryResult, TraceEvent
from .rule_engine import RuleEngine


@dataclass(frozen=True)
class QueryRequest:
    prompt: str
    trace: tuple[TraceEvent, ...]
    policy: PolicyContext


class DeterministicQuarantinedModelStub:
    def __init__(
        self, output_text: str, output_trace: tuple[TraceEvent, ...] | None = None
    ):
        self.output_text = output_text
        self.output_trace = output_trace
        self.calls = 0

    def complete(self, prompt: str) -> str:
        self.calls += 1
        return self.output_text


def query_llm(
    request: QueryRequest,
    model_client: DeterministicQuarantinedModelStub,
    rule_engine: RuleEngine,
    fides_layer: FidesIFCLayer | None = None,
) -> QueryResult:
    preflight = rule_engine.evaluate(request.trace, request.policy)
    if preflight.final_action == "block":
        return QueryResult(
            allowed=False,
            model_called=False,
            blocked_by="deterministic_preflight",
            preflight=preflight,
            postflight=None,
            fides=None,
            output_text="",
        )

    output_text = model_client.complete(request.prompt)
    output_trace = model_client.output_trace or request.trace
    postflight = rule_engine.evaluate(output_trace, request.policy)
    if postflight.final_action == "block":
        return QueryResult(
            allowed=False,
            model_called=True,
            blocked_by="deterministic_postflight",
            preflight=preflight,
            postflight=postflight,
            fides=None,
            output_text=output_text,
        )

    fides = fides_layer.evaluate(output_trace, request.policy) if fides_layer else None
    if fides and fides.blocks:
        return QueryResult(
            allowed=False,
            model_called=True,
            blocked_by="fides_ifc",
            preflight=preflight,
            postflight=postflight,
            fides=fides,
            output_text=output_text,
        )

    return QueryResult(
        allowed=True,
        model_called=True,
        blocked_by=None,
        preflight=preflight,
        postflight=postflight,
        fides=fides,
        output_text=output_text,
    )
