from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from .rule_schema import JudgeCheck


@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    origin: str
    surface: str
    text: str = ""
    schema_shape: str | None = None
    capability: str | None = None
    sink: str | None = None
    canary_present: bool = False
    integrity: Literal["high", "low"] = "high"
    confidentiality: Literal["public", "restricted"] = "public"
    consequential_action: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def field_value(self, field_name: str) -> Any:
        if hasattr(self, field_name):
            return getattr(self, field_name)
        return self.metadata.get(field_name)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyContext:
    allowed_capabilities: tuple[str, ...] = ()
    allowed_canary_sinks: tuple[str, ...] = ()
    trusted_origins: tuple[str, ...] = ("user", "host_policy", "host", "planner")
    permitted_sinks: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    action: str
    matched_signals: tuple[str, ...]
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PendingFidesCheck:
    rule_id: str
    rule_name: str
    action: str
    checks: tuple[JudgeCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "action": self.action,
            "checks": [asdict(check) for check in self.checks],
        }


@dataclass(frozen=True)
class RuleDecision:
    hits: tuple[RuleHit, ...]
    final_action: Literal["allow", "quarantine", "block"]
    pending_fides: tuple[PendingFidesCheck, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": [hit.to_dict() for hit in self.hits],
            "final_action": self.final_action,
            "pending_fides": [pending.to_dict() for pending in self.pending_fides],
        }


@dataclass(frozen=True)
class FidesVerdict:
    verdict: Literal["safe", "unsafe", "uncertain", "disabled"]
    confidence: float
    blocks: bool
    policy_checks: tuple[str, ...] = ()
    rationale_short: str = ""
    judge_transcript: str | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Verdict export including the raw judge transcript when available."""
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "blocks": self.blocks,
            "policy_checks": list(self.policy_checks),
            "rationale_short": self.rationale_short,
            "judge_transcript": self.judge_transcript,
        }


@dataclass(frozen=True)
class QueryResult:
    allowed: bool
    model_called: bool
    blocked_by: str | None
    preflight: RuleDecision
    postflight: RuleDecision | None
    fides: FidesVerdict | None
    output_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Query result export including model output and any judge transcript."""
        return {
            "allowed": self.allowed,
            "model_called": self.model_called,
            "blocked_by": self.blocked_by,
            "preflight": self.preflight.to_dict(),
            "postflight": self.postflight.to_dict() if self.postflight else None,
            "fides": self.fides.to_dict() if self.fides else None,
            "output_text": self.output_text,
        }
