from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class _StringEnum(str, Enum):
    @classmethod
    def coerce(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        return cls(str(value))


class StackName(_StringEnum):
    NO_GUARD = "no_guard"
    REGEX_BASELINE = "regex_baseline"
    YARA_RULES = "yara_rules"
    RULES_PLUS_FIDES = "rules_plus_fides"
    FIDES_ONLY = "fides_only"


class Decision(_StringEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"


class BlockedBy(_StringEnum):
    REGEX = "regex"
    YARA_RULE = "yara_rule"
    FIDES_IFC = "fides_ifc"
    FIDES_JUDGE = "fides_judge"
    NONE = "none"


class FidesVerdict(_StringEnum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNCERTAIN = "uncertain"
    DISABLED = "disabled"
    NOT_CALLED = "not_called"


@dataclass(frozen=True)
class GateDecision:
    """Single public result schema for all pre-context gate stacks."""

    stack: StackName | str
    decision: Decision | str
    blocked_by: BlockedBy | str = BlockedBy.NONE
    rule_ids: tuple[str, ...] = ()
    fides_verdict: FidesVerdict | str = FidesVerdict.NOT_CALLED
    reason_codes: tuple[str, ...] = ()
    latency_ms: float | None = None
    provider_calls: int = 0
    ifc_verdict: FidesVerdict | str = FidesVerdict.NOT_CALLED
    ifc_policy_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "stack", StackName.coerce(self.stack))
        object.__setattr__(self, "decision", Decision.coerce(self.decision))
        object.__setattr__(self, "blocked_by", BlockedBy.coerce(self.blocked_by))
        object.__setattr__(
            self, "fides_verdict", FidesVerdict.coerce(self.fides_verdict)
        )
        object.__setattr__(
            self, "rule_ids", tuple(str(rule_id) for rule_id in self.rule_ids)
        )
        object.__setattr__(
            self, "reason_codes", tuple(str(code) for code in self.reason_codes)
        )
        if self.latency_ms is not None:
            latency_ms = float(self.latency_ms)
            if latency_ms < 0:
                raise ValueError("latency_ms must be non-negative")
            object.__setattr__(self, "latency_ms", latency_ms)
        provider_calls = int(self.provider_calls)
        if provider_calls < 0:
            raise ValueError("provider_calls must be non-negative")
        object.__setattr__(self, "provider_calls", provider_calls)
        object.__setattr__(self, "ifc_verdict", FidesVerdict.coerce(self.ifc_verdict))
        object.__setattr__(
            self,
            "ifc_policy_checks",
            tuple(str(check) for check in self.ifc_policy_checks),
        )
        if self.decision == Decision.ALLOW and self.blocked_by != BlockedBy.NONE:
            raise ValueError("allowed decisions must use blocked_by=none")

    def to_dict(self) -> dict[str, Any]:
        stack = StackName.coerce(self.stack)
        decision = Decision.coerce(self.decision)
        blocked_by = BlockedBy.coerce(self.blocked_by)
        fides_verdict = FidesVerdict.coerce(self.fides_verdict)
        ifc_verdict = FidesVerdict.coerce(self.ifc_verdict)
        return {
            "stack": stack.value,
            "decision": decision.value,
            "blocked_by": blocked_by.value,
            "rule_ids": list(self.rule_ids),
            "fides_verdict": fides_verdict.value,
            "reason_codes": list(self.reason_codes),
            "latency_ms": self.latency_ms,
            "provider_calls": self.provider_calls,
            "ifc_verdict": ifc_verdict.value,
            "ifc_policy_checks": list(self.ifc_policy_checks),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GateDecision":
        return cls(
            stack=data["stack"],
            decision=data["decision"],
            blocked_by=data.get("blocked_by", BlockedBy.NONE),
            rule_ids=tuple(str(rule_id) for rule_id in data.get("rule_ids", ())),
            fides_verdict=data.get("fides_verdict", FidesVerdict.NOT_CALLED),
            reason_codes=tuple(str(code) for code in data.get("reason_codes", ())),
            latency_ms=data.get("latency_ms"),
            provider_calls=int(data.get("provider_calls", 0)),
            ifc_verdict=data.get("ifc_verdict", FidesVerdict.NOT_CALLED),
            ifc_policy_checks=tuple(
                str(check) for check in data.get("ifc_policy_checks", ())
            ),
        )
