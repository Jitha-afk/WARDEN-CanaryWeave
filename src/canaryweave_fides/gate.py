from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Iterable, Mapping, Protocol, Sequence

from .cases import AttackCase
from .decisions import BlockedBy, Decision, FidesVerdict, GateDecision, StackName
from .facts import NormalizedFacts
from .fides_prompt import build_fides_judge_prompt, parse_fides_judge_response
from .models import PendingFidesCheck, PolicyContext, RuleDecision, TraceEvent
from .providers import CopilotSdkJudgeProvider, JudgeProvider, JudgeProviderConfig
from .resources import rules_root
from .rule_engine import RuleEngine
from .rule_loader import load_rules


class _StringEnum(str, Enum):
    @classmethod
    def coerce(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        return cls(str(value))


class FidesJudgeMode(_StringEnum):
    """Explicit runtime modes for the FIDES LLM-as-judge boundary."""

    DISABLED = "disabled"
    TEST_DOUBLE = "test_double"
    PROVIDER_PLACEHOLDER = "provider_placeholder"
    COPILOT_SDK = "copilot_sdk"


@dataclass(frozen=True)
class FidesJudgeResult:
    verdict: FidesVerdict | str
    confidence: float = 0.0
    reason_codes: tuple[str, ...] = ()
    recommended_decision: Decision | str | None = None
    latency_ms: float | None = None
    provider_calls: int = 0
    judge_transcript: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        verdict = FidesVerdict.coerce(self.verdict)
        if verdict == FidesVerdict.NOT_CALLED:
            raise ValueError("FidesJudgeResult verdict cannot be not_called")
        object.__setattr__(self, "verdict", verdict)

        confidence = float(self.confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        object.__setattr__(self, "confidence", confidence)

        object.__setattr__(self, "reason_codes", tuple(str(code) for code in self.reason_codes))
        if self.recommended_decision is None:
            recommended = _recommended_decision_for_verdict(verdict)
        else:
            recommended = Decision.coerce(self.recommended_decision)
        object.__setattr__(self, "recommended_decision", recommended)

        if self.latency_ms is not None:
            latency_ms = float(self.latency_ms)
            if latency_ms < 0:
                raise ValueError("latency_ms must be non-negative")
            object.__setattr__(self, "latency_ms", latency_ms)

        provider_calls = int(self.provider_calls)
        if provider_calls < 0:
            raise ValueError("provider_calls must be non-negative")
        object.__setattr__(self, "provider_calls", provider_calls)

        if self.judge_transcript is not None:
            object.__setattr__(self, "judge_transcript", str(self.judge_transcript))

    def to_dict(self) -> dict[str, Any]:
        """Public-safe judge result export; no raw transcript is included."""
        verdict = FidesVerdict.coerce(self.verdict)
        recommended = Decision.coerce(self.recommended_decision)
        return {
            "verdict": verdict.value,
            "confidence": self.confidence,
            "reason_codes": list(self.reason_codes),
            "recommended_decision": recommended.value,
            "latency_ms": self.latency_ms,
            "provider_calls": self.provider_calls,
            "transcript_included": False,
        }

    def to_private_dict(self) -> dict[str, Any]:
        data = self.to_dict()
        data["judge_transcript"] = self.judge_transcript
        return data


class FidesJudge(Protocol):
    mode: FidesJudgeMode

    def judge(
        self,
        facts: NormalizedFacts,
        *,
        rule_fides_checks: Sequence[Mapping[str, Any]] = (),
    ) -> FidesJudgeResult:
        ...


class DisabledFidesJudge:
    """FIDES mode for default/public runs: no provider, no transcript."""

    mode = FidesJudgeMode.DISABLED

    def __init__(self) -> None:
        self.calls = 0

    def judge(
        self,
        facts: NormalizedFacts,
        *,
        rule_fides_checks: Sequence[Mapping[str, Any]] = (),
    ) -> FidesJudgeResult:
        self.calls += 1
        return FidesJudgeResult(
            verdict=FidesVerdict.DISABLED,
            confidence=0.0,
            reason_codes=("fides.disabled",),
            recommended_decision=Decision.ALLOW,
            provider_calls=0,
        )


class StaticFidesJudge:
    """Deterministic local FIDES test double.

    This is only a CI/test harness for the FIDES interface. The deterministic
    policy engine is WARDEN; FIDES itself remains the LLM-as-judge layer in the
    research architecture. Test-double results are public-safe by construction:
    they never record provider calls and never retain judge transcripts.
    """

    mode = FidesJudgeMode.TEST_DOUBLE

    def __init__(self, results: Mapping[str, FidesJudgeResult | Mapping[str, object]] | None = None):
        self.results = dict(results or {})
        self.calls = 0

    def judge(
        self,
        facts: NormalizedFacts,
        *,
        rule_fides_checks: Sequence[Mapping[str, Any]] = (),
    ) -> FidesJudgeResult:
        self.calls += 1
        result = self.results.get(facts.case_id)
        if isinstance(result, FidesJudgeResult):
            return _as_test_double_result(result)
        if isinstance(result, Mapping):
            raw_verdict = result.get("verdict", FidesVerdict.SAFE)
            verdict = FidesVerdict.coerce(raw_verdict)
            raw_confidence = result.get("confidence")
            confidence = float(str(raw_confidence)) if raw_confidence is not None else (1.0 if verdict == FidesVerdict.SAFE else 0.0)
            raw_recommended = result.get("recommended_decision")
            recommended_decision = None if raw_recommended is None else str(raw_recommended)
            return FidesJudgeResult(
                verdict=verdict,
                confidence=confidence,
                reason_codes=tuple(str(code) for code in result.get("reason_codes", ())),
                recommended_decision=recommended_decision,
                latency_ms=result.get("latency_ms"),
                provider_calls=0,
                judge_transcript=None,
            )
        return FidesJudgeResult(
            verdict=FidesVerdict.SAFE,
            confidence=1.0,
            reason_codes=("fides.test_double_default_safe",),
            recommended_decision=Decision.ALLOW,
            provider_calls=0,
        )



def _as_test_double_result(result: FidesJudgeResult) -> FidesJudgeResult:
    """Return a transcript-free, zero-provider copy of a fixture verdict."""
    return FidesJudgeResult(
        verdict=result.verdict,
        confidence=result.confidence,
        reason_codes=result.reason_codes,
        recommended_decision=result.recommended_decision,
        latency_ms=result.latency_ms,
        provider_calls=0,
        judge_transcript=None,
    )


def _tuple_match(actual: str | None, allowed: object) -> bool:
    if allowed in (None, (), [], set(), frozenset()):
        return True
    values = {str(item) for item in allowed} if isinstance(allowed, (list, tuple, set, frozenset)) else {str(allowed)}
    return actual in values


def _matches_expected_fields(source: Mapping[str, Any], expected: Mapping[str, Any] | None) -> bool:
    if not expected:
        return True
    for key, expected_value in expected.items():
        if source.get(str(key)) != expected_value:
            return False
    return True


def _matches_test_double_rule(case: AttackCase, rule: Mapping[str, Any]) -> bool:
    match = rule.get("match", {})
    if not isinstance(match, Mapping) or not match:
        raise ValueError("FIDES test-double evidence rules require a non-empty match mapping")
    if not _tuple_match(case.case_id, match.get("case_ids")):
        return False
    if not _tuple_match(case.dataset_id, match.get("dataset_ids")):
        return False
    if not _tuple_match(case.attack_category, match.get("attack_categories")):
        return False
    if not _tuple_match(case.surface, match.get("surfaces")):
        return False
    if not _tuple_match(case.case_kind.value, match.get("case_kinds")):
        return False
    if not _tuple_match(case.expected_behavior.value, match.get("expected_behaviors")):
        return False
    safe_features = match.get("safe_features")
    if safe_features is not None and not isinstance(safe_features, Mapping):
        raise ValueError("FIDES test-double match.safe_features must be a mapping")
    return _matches_expected_fields(case.safe_features, safe_features)


def _test_double_result_from_rule(rule: Mapping[str, Any]) -> FidesJudgeResult:
    rule_id = str(rule.get("id") or "fixture_verdict")
    reason_codes = tuple(str(code) for code in (rule.get("reason_codes") or ()))
    if not reason_codes:
        reason_codes = (f"fides.test_double.{rule_id}",)
    if int(rule.get("provider_calls") or 0) != 0:
        raise ValueError("FIDES test-double evidence rules must declare provider_calls as 0 or omit it")
    if rule.get("judge_transcript") is not None:
        raise ValueError("FIDES test-double evidence rules must not include judge transcripts")
    latency_value = rule.get("latency_ms", 0.0)
    latency_ms = None if latency_value is None else float(latency_value)
    recommended = rule.get("recommended_decision")
    return FidesJudgeResult(
        verdict=FidesVerdict.coerce(rule.get("verdict", FidesVerdict.UNSAFE)),
        confidence=float(rule.get("confidence", 0.9)),
        reason_codes=reason_codes,
        recommended_decision=None if recommended is None else Decision.coerce(recommended),
        latency_ms=latency_ms,
        provider_calls=0,
        judge_transcript=None,
    )


def build_test_double_evidence_results(
    cases: Iterable[AttackCase],
    rules: Iterable[Mapping[str, Any]],
) -> dict[str, FidesJudgeResult]:
    """Create deterministic fixture verdicts for selected public-safe cases.

    Matching happens against public `AttackCase` labels/features, allowing CI and
    public evidence runs to simulate a FIDES judge catch on WARDEN misses without
    provider calls, prompt transcripts, model outputs, or raw payload custody.
    The gate still invokes FIDES only after WARDEN allows a case.
    """
    results: dict[str, FidesJudgeResult] = {}
    ordered_cases = tuple(sorted(cases, key=lambda case: (case.dataset_id, case.case_id)))
    for raw_rule in rules:
        rule = dict(raw_rule)
        max_catches = rule.get("max_catches")
        remaining = None if max_catches in (None, "") else int(max_catches)
        if remaining is not None and remaining < 0:
            raise ValueError("FIDES test-double max_catches must be non-negative")
        verdict = _test_double_result_from_rule(rule)
        for case in ordered_cases:
            if remaining == 0:
                break
            if case.case_id in results:
                continue
            if _matches_test_double_rule(case, rule):
                results[case.case_id] = verdict
                if remaining is not None:
                    remaining -= 1
    return results


class ProviderPlaceholderFidesJudge:
    """Non-network placeholder for future provider wiring.

    This class marks the provider boundary explicitly but intentionally raises
    instead of making calls. The POC must not perform real provider calls.
    """

    mode = FidesJudgeMode.PROVIDER_PLACEHOLDER

    def judge(
        self,
        facts: NormalizedFacts,
        *,
        rule_fides_checks: Sequence[Mapping[str, Any]] = (),
    ) -> FidesJudgeResult:
        raise NotImplementedError(
            "FIDES provider_placeholder mode is contract-only in this POC; no real provider calls are implemented."
        )


class ProviderBackedFidesJudge:
    """Provider-backed FIDES judge over public-safe normalized facts."""

    mode = FidesJudgeMode.COPILOT_SDK

    def __init__(self, provider: JudgeProvider):
        self.provider = provider
        self.calls = 0

    def judge(
        self,
        facts: NormalizedFacts,
        *,
        rule_fides_checks: Sequence[Mapping[str, Any]] = (),
    ) -> FidesJudgeResult:
        self.calls += 1
        context: dict[str, Any] = {"case_id": facts.case_id}
        if rule_fides_checks:
            context["rule_fides_checks"] = [dict(check) for check in rule_fides_checks]
        prompt = build_fides_judge_prompt(facts, warden_miss_context=context)
        response = self.provider.judge(prompt, case_id=facts.case_id, request_id=f"fides-{self.calls}")
        parsed = parse_fides_judge_response(response.text)
        return FidesJudgeResult(
            verdict=parsed["verdict"],
            confidence=parsed["confidence"],
            reason_codes=tuple(parsed["reason_codes"]),
            recommended_decision=parsed["recommended_decision"],
            latency_ms=response.latency_ms,
            provider_calls=response.provider_calls,
            judge_transcript=response.text,
        )


def build_fides_judge(
    mode: FidesJudgeMode | str = FidesJudgeMode.DISABLED,
    *,
    results: Mapping[str, FidesJudgeResult | Mapping[str, object]] | None = None,
    provider: JudgeProvider | None = None,
    provider_config: JudgeProviderConfig | None = None,
) -> FidesJudge:
    judge_mode = FidesJudgeMode.coerce(mode)
    if judge_mode == FidesJudgeMode.DISABLED:
        return DisabledFidesJudge()
    if judge_mode == FidesJudgeMode.TEST_DOUBLE:
        return StaticFidesJudge(results)
    if judge_mode == FidesJudgeMode.PROVIDER_PLACEHOLDER:
        return ProviderPlaceholderFidesJudge()
    if judge_mode == FidesJudgeMode.COPILOT_SDK:
        configured_provider = provider or CopilotSdkJudgeProvider(provider_config or JudgeProviderConfig(provider="copilot_sdk"))
        return ProviderBackedFidesJudge(configured_provider)
    raise ValueError(f"unsupported FIDES judge mode: {mode}")


def _decision_rank(decision: Decision | str) -> int:
    coerced = Decision.coerce(decision)
    if coerced == Decision.BLOCK:
        return 2
    if coerced == Decision.QUARANTINE:
        return 1
    return 0


def _more_restrictive_decision(left: Decision | str, right: Decision | str) -> Decision:
    left_decision = Decision.coerce(left)
    right_decision = Decision.coerce(right)
    return left_decision if _decision_rank(left_decision) >= _decision_rank(right_decision) else right_decision


def _recommended_decision_for_verdict(verdict: FidesVerdict) -> Decision:
    if verdict == FidesVerdict.UNSAFE:
        return Decision.BLOCK
    if verdict == FidesVerdict.UNCERTAIN:
        return Decision.QUARANTINE
    return Decision.ALLOW


def _serialized_pending_fides_checks(pending: Sequence[PendingFidesCheck]) -> tuple[dict[str, Any], ...]:
    return tuple(
        {
            "rule_id": item.rule_id,
            "name": check.name,
            "prompt": check.prompt,
            "threshold": check.threshold,
        }
        for item in pending
        for check in item.checks
    )


def _unique_strings(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)


def _is_untrusted(facts: NormalizedFacts) -> bool:
    return "untrusted" in facts.trust_labels or any(origin not in facts.policy.get("trusted_origins", ()) for origin in facts.origin_labels)


def _requested_capability_allowed(facts: NormalizedFacts) -> bool | None:
    allowed = facts.capability.get("capability_allowed")
    if allowed is not None:
        return bool(allowed)
    requested = facts.requested.get("capability") or facts.requested.get("tool")
    if requested is None:
        return None
    allowed_caps = tuple(facts.policy.get("allowed_capabilities", ())) or tuple(facts.policy.get("allowed_tools", ()))
    return str(requested) in allowed_caps


def _sink_allowed(facts: NormalizedFacts) -> bool | None:
    allowed = facts.flow.get("sink_allowed")
    if allowed is not None:
        return bool(allowed)
    sink = facts.requested.get("sink")
    if sink is None:
        return None
    return str(sink) in tuple(facts.policy.get("allowed_sinks", ()))


@lru_cache(maxsize=1)
def _default_rule_engine() -> RuleEngine:
    return RuleEngine(load_rules(rules_root()))


def _facts_to_trace_and_policy(facts: NormalizedFacts) -> tuple[tuple[TraceEvent, ...], PolicyContext]:
    schema_shape = facts.features.get("schema_shape")
    if schema_shape in {"tool_plan_like", "tool_plan"}:
        schema_shape = "tool_plan_like_json"
    if schema_shape is None and bool(facts.features.get("tool_plan_shape")):
        schema_shape = "tool_plan_like_json"
    origin = facts.origin_labels[0] if facts.origin_labels else "unknown"
    text_parts: list[str] = []
    if facts.redacted_text:
        text_parts.append(facts.redacted_text)
    if bool(facts.features.get("instruction_shape")):
        text_parts.append("policy boundary directive structure")
    if bool(facts.features.get("command_execution_shape")):
        text_parts.append("execution request structure")
    if bool(facts.features.get("path_boundary_shape")):
        text_parts.append("resource boundary request structure")
    if bool(facts.features.get("network_request_shape")):
        text_parts.append("external request structure")
    if bool(facts.features.get("credential_or_secret_shape")):
        text_parts.append("protected credential material structure")
    if bool(facts.features.get("protected_context_extraction_shape")):
        text_parts.append("protected context extraction structure")
    if bool(facts.features.get("social_engineering_shape")):
        text_parts.append("social engineering structure")
    if bool(facts.features.get("deception_shape")):
        text_parts.append("deception structure")
    if bool(facts.features.get("destructive_action_shape")):
        text_parts.append("destructive action structure")
    if bool(facts.features.get("security_tool_extension_shape")):
        text_parts.append("security tool extension structure")
    if bool(facts.features.get("obfuscated")):
        text_parts.append("hidden" + "\u200b" + "structure")
    if bool(facts.features.get("canary_present")):
        text_parts.append("[CANARY]")
    text = " ".join(text_parts)
    requested_capability = facts.requested.get("capability") or facts.requested.get("tool")
    requested_sink = facts.requested.get("sink")
    event = TraceEvent(
        event_id=facts.case_id,
        origin=origin,
        surface=facts.surface,
        text=text,
        schema_shape=str(schema_shape) if schema_shape is not None else None,
        capability=str(requested_capability) if requested_capability is not None else None,
        sink=str(requested_sink) if requested_sink is not None else None,
        canary_present=bool(facts.features.get("canary_present")),
        integrity="low" if "untrusted" in facts.trust_labels else "high",
        consequential_action=bool(facts.features.get("tool_plan_shape")) or bool(facts.requested.get("action")) or bool(requested_capability),
        metadata={**dict(facts.features), "requested": dict(facts.requested), "policy": dict(facts.policy)},
    )
    policy = PolicyContext(
        allowed_capabilities=tuple(str(item) for item in facts.policy.get("allowed_capabilities", ())),
        allowed_canary_sinks=tuple(str(item) for item in facts.policy.get("allowed_sinks", ())),
        trusted_origins=tuple(str(item) for item in facts.policy.get("trusted_origins", ())),
        permitted_sinks=tuple(str(item) for item in facts.policy.get("allowed_sinks", ())),
    )
    return (event,), policy


def _warden_gate_from_rule_decision(stack_name: StackName, rule_decision: RuleDecision) -> GateDecision:
    if not rule_decision.hits:
        return GateDecision(stack=stack_name, decision=Decision.ALLOW)
    rule_ids = tuple(hit.rule_id for hit in rule_decision.hits)
    reason_codes = tuple(signal for hit in rule_decision.hits for signal in hit.matched_signals)
    return GateDecision(
        stack=stack_name,
        decision=rule_decision.final_action,
        blocked_by=BlockedBy.YARA_RULE,
        rule_ids=rule_ids,
        reason_codes=reason_codes,
    )


def _evaluate_warden_with_rule_decision(
    facts: NormalizedFacts,
    stack: StackName | str = StackName.YARA_RULES,
    rule_engine: RuleEngine | None = None,
) -> tuple[GateDecision, RuleDecision]:
    stack_name = StackName.coerce(stack)
    engine = rule_engine or _default_rule_engine()
    trace, policy = _facts_to_trace_and_policy(facts)
    rule_decision = engine.evaluate(trace, policy)
    return _warden_gate_from_rule_decision(stack_name, rule_decision), rule_decision


def evaluate_regex_baseline(facts: NormalizedFacts) -> GateDecision:
    reason_codes: list[str] = []
    if bool(facts.features.get("canary_present")):
        reason_codes.append("regex.canary_marker")
    if bool(facts.features.get("obfuscated")):
        reason_codes.append("regex.obfuscated_structure")
    redacted = (facts.redacted_text or "").lower()
    if "[canary]" in redacted:
        reason_codes.append("regex.redacted_canary")

    if reason_codes:
        return GateDecision(
            stack=StackName.REGEX_BASELINE,
            decision=Decision.BLOCK,
            blocked_by=BlockedBy.REGEX,
            rule_ids=tuple(reason_codes),
            reason_codes=tuple(reason_codes),
        )
    return GateDecision(stack=StackName.REGEX_BASELINE, decision=Decision.ALLOW)


def evaluate_warden(
    facts: NormalizedFacts,
    stack: StackName | str = StackName.YARA_RULES,
    rule_engine: RuleEngine | None = None,
) -> GateDecision:
    warden, _rule_decision = _evaluate_warden_with_rule_decision(facts, stack, rule_engine=rule_engine)
    return warden


def evaluate_stack(
    facts: NormalizedFacts,
    stack: StackName | str,
    fides_judge: FidesJudge | None = None,
    rule_engine: RuleEngine | None = None,
) -> GateDecision:
    stack_name = StackName.coerce(stack)
    if stack_name == StackName.NO_GUARD:
        return GateDecision(stack=stack_name, decision=Decision.ALLOW)
    if stack_name == StackName.REGEX_BASELINE:
        return evaluate_regex_baseline(facts)
    if stack_name == StackName.YARA_RULES:
        return evaluate_warden(facts, StackName.YARA_RULES, rule_engine=rule_engine)
    if stack_name == StackName.RULES_PLUS_FIDES:
        warden, rule_decision = _evaluate_warden_with_rule_decision(
            facts,
            StackName.RULES_PLUS_FIDES,
            rule_engine=rule_engine,
        )
        if warden.decision != Decision.ALLOW:
            return GateDecision(
                stack=StackName.RULES_PLUS_FIDES,
                decision=warden.decision,
                blocked_by=warden.blocked_by,
                rule_ids=warden.rule_ids,
                fides_verdict=FidesVerdict.NOT_CALLED,
                reason_codes=warden.reason_codes,
                latency_ms=warden.latency_ms,
                provider_calls=0,
            )
        judge = fides_judge or DisabledFidesJudge()
        pending_checks = _serialized_pending_fides_checks(rule_decision.pending_fides)
        verdict = judge.judge(facts, rule_fides_checks=pending_checks)
        effective_decision = _more_restrictive_decision(
            _recommended_decision_for_verdict(FidesVerdict.coerce(verdict.verdict)),
            Decision.coerce(verdict.recommended_decision),
        )
        attributed_rule_ids = _unique_strings(item.rule_id for item in rule_decision.pending_fides)
        attributed_reason_codes = _unique_strings((
            *verdict.reason_codes,
            *(str(check["name"]) for check in pending_checks),
        )) if pending_checks else verdict.reason_codes
        if effective_decision == Decision.BLOCK:
            return GateDecision(
                stack=StackName.RULES_PLUS_FIDES,
                decision=Decision.BLOCK,
                blocked_by=BlockedBy.FIDES_JUDGE,
                rule_ids=attributed_rule_ids,
                fides_verdict=verdict.verdict,
                reason_codes=attributed_reason_codes,
                latency_ms=verdict.latency_ms,
                provider_calls=verdict.provider_calls,
            )
        if effective_decision == Decision.QUARANTINE:
            return GateDecision(
                stack=StackName.RULES_PLUS_FIDES,
                decision=Decision.QUARANTINE,
                blocked_by=BlockedBy.FIDES_JUDGE,
                rule_ids=attributed_rule_ids,
                fides_verdict=verdict.verdict,
                reason_codes=attributed_reason_codes,
                latency_ms=verdict.latency_ms,
                provider_calls=verdict.provider_calls,
            )
        return GateDecision(
            stack=StackName.RULES_PLUS_FIDES,
            decision=Decision.ALLOW,
            fides_verdict=verdict.verdict,
            reason_codes=verdict.reason_codes,
            latency_ms=verdict.latency_ms,
            provider_calls=verdict.provider_calls,
        )
    raise ValueError(f"unsupported stack: {stack}")


def evaluate_case(
    case: AttackCase,
    stacks: Sequence[StackName | str] = (
        StackName.NO_GUARD,
        StackName.REGEX_BASELINE,
        StackName.YARA_RULES,
        StackName.RULES_PLUS_FIDES,
    ),
    fides_judge: FidesJudge | None = None,
    rule_engine: RuleEngine | None = None,
) -> tuple[GateDecision, ...]:
    facts = NormalizedFacts.from_attack_case(case)
    return tuple(evaluate_stack(facts, stack, fides_judge=fides_judge, rule_engine=rule_engine) for stack in stacks)
