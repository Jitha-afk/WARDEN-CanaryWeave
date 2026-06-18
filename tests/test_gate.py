import pytest

from canaryweave_fides.cases import AttackCase
from canaryweave_fides.decisions import BlockedBy, Decision, FidesVerdict, StackName
from canaryweave_fides.facts import NormalizedFacts
from canaryweave_fides.gate import (
    DisabledFidesJudge,
    FidesJudgeMode,
    FidesJudgeResult,
    ProviderPlaceholderFidesJudge,
    StaticFidesJudge,
    build_fides_judge,
    evaluate_case,
    evaluate_stack,
)
from canaryweave_fides.rule_engine import RuleEngine


def _case(**safe_features):
    defaults = {
        "origin_labels": ["server_sampling"],
        "trust_labels": ["untrusted"],
        "instruction_shape": True,
        "tool_plan_shape": True,
        "requested_tool": "admin_action",
        "requested_sink": "local_audit",
    }
    defaults.update(safe_features)
    return AttackCase(
        case_id="synthetic.case.001",
        dataset_id="synthetic",
        split="ci",
        case_kind="attack",
        attack_category="origin_authority_confusion",
        surface="mcp_tool",
        safe_features=defaults,
        policy_context={
            "allowed_tools": ["read_task"],
            "allowed_sinks": ["local_audit"],
            "trusted_origins": ["user", "host_policy"],
        },
        expected_behavior="block",
    )


def test_no_guard_allows_case():
    facts = NormalizedFacts.from_attack_case(_case())
    decision = evaluate_stack(facts, StackName.NO_GUARD)

    assert decision.stack is StackName.NO_GUARD
    assert decision.decision is Decision.ALLOW
    assert decision.blocked_by is BlockedBy.NONE
    assert decision.fides_verdict is FidesVerdict.NOT_CALLED


def test_warden_yara_rules_block_untrusted_tool_plan_with_denied_capability():
    facts = NormalizedFacts.from_attack_case(_case())
    decision = evaluate_stack(facts, StackName.YARA_RULES)

    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.YARA_RULE
    assert "cwfr-0001" in decision.rule_ids
    assert all(rule_id.startswith("cwfr-") for rule_id in decision.rule_ids)
    assert not any(rule_id.startswith("warden.") for rule_id in decision.rule_ids)


def test_warden_uses_rule_engine_instead_of_hardcoded_heuristics():
    facts = NormalizedFacts.from_attack_case(_case())
    decision = evaluate_stack(facts, StackName.YARA_RULES, rule_engine=RuleEngine(()))

    assert decision.decision is Decision.ALLOW
    assert decision.rule_ids == ()


def test_rules_plus_fides_does_not_call_fides_when_warden_blocks():
    facts = NormalizedFacts.from_attack_case(_case())
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("would_have_blocked",))})

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES, fides_judge=judge)

    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.YARA_RULE
    assert decision.fides_verdict is FidesVerdict.NOT_CALLED
    assert judge.calls == 0


def test_rules_plus_fides_calls_judge_for_warden_miss_and_blocks_on_unsafe():
    case = _case(
        origin_labels=["user"],
        trust_labels=["trusted"],
        instruction_shape=False,
        tool_plan_shape=False,
        requested_tool="read_task",
        requested_sink="local_audit",
    )
    facts = NormalizedFacts.from_attack_case(case)
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("semantic_policy_violation",))})

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES, fides_judge=judge)

    assert judge.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.FIDES_JUDGE
    assert decision.fides_verdict is FidesVerdict.UNSAFE
    assert "semantic_policy_violation" in decision.reason_codes


def test_warden_blocks_protected_context_extraction_from_untrusted_source():
    facts = NormalizedFacts.from_attack_case(
        _case(
            origin_labels=["tool_output"],
            trust_labels=["untrusted"],
            instruction_shape=False,
            tool_plan_shape=False,
            protected_context_extraction_shape=True,
        )
    )

    decision = evaluate_stack(facts, StackName.YARA_RULES)

    assert decision.decision is Decision.QUARANTINE
    assert "cwfr-0108" in decision.rule_ids


def test_warden_blocks_destructive_action_intent_without_granted_capability():
    facts = NormalizedFacts.from_attack_case(
        _case(
            origin_labels=["tool_output"],
            trust_labels=["untrusted"],
            instruction_shape=False,
            tool_plan_shape=True,
            destructive_action_shape=True,
            requested_tool="admin_action",
            requested_capability="admin_action",
            requested_action="destructive_update",
        )
    )

    decision = evaluate_stack(facts, StackName.YARA_RULES)

    assert decision.decision is Decision.BLOCK
    assert "cwfr-0109" in decision.rule_ids


def test_warden_quarantines_deceptive_social_engineering_tasking_from_untrusted_source():
    facts = NormalizedFacts.from_attack_case(
        _case(
            origin_labels=["tool_output"],
            trust_labels=["untrusted"],
            instruction_shape=False,
            tool_plan_shape=False,
            social_engineering_shape=True,
            deception_shape=True,
        )
    )

    decision = evaluate_stack(facts, StackName.YARA_RULES)

    assert decision.decision is Decision.QUARANTINE
    assert "cwfr-0110" in decision.rule_ids


def test_social_engineering_training_from_trusted_user_is_allowed():
    facts = NormalizedFacts.from_attack_case(
        _case(
            origin_labels=["user"],
            trust_labels=["trusted"],
            instruction_shape=False,
            tool_plan_shape=False,
            social_engineering_shape=True,
            deception_shape=True,
        )
    )

    decision = evaluate_stack(facts, StackName.YARA_RULES)

    assert "cwfr-0110" not in decision.rule_ids


def test_evaluate_case_returns_all_stack_decisions():
    decisions = evaluate_case(_case(), fides_judge=StaticFidesJudge({}))

    assert tuple(decision.stack for decision in decisions) == (
        StackName.NO_GUARD,
        StackName.REGEX_BASELINE,
        StackName.YARA_RULES,
        StackName.RULES_PLUS_FIDES,
    )


def test_rules_plus_fides_default_mode_is_disabled_and_does_not_call_provider():
    case = _case(
        origin_labels=["user"],
        trust_labels=["trusted"],
        instruction_shape=False,
        tool_plan_shape=False,
        requested_tool="read_task",
        requested_sink="local_audit",
    )
    facts = NormalizedFacts.from_attack_case(case)

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES)

    assert decision.decision is Decision.ALLOW
    assert decision.fides_verdict is FidesVerdict.DISABLED
    assert decision.provider_calls == 0
    assert "fides.disabled" in decision.reason_codes


def test_fides_judge_modes_are_explicit():
    assert [mode.value for mode in FidesJudgeMode] == ["disabled", "test_double", "provider_placeholder", "copilot_sdk"]
    assert isinstance(build_fides_judge("disabled"), DisabledFidesJudge)
    assert isinstance(build_fides_judge("test_double"), StaticFidesJudge)
    assert isinstance(build_fides_judge("provider_placeholder"), ProviderPlaceholderFidesJudge)


def test_provider_placeholder_never_makes_real_provider_calls():
    facts = NormalizedFacts.from_attack_case(
        _case(
            origin_labels=["user"],
            trust_labels=["trusted"],
            instruction_shape=False,
            tool_plan_shape=False,
            requested_tool="read_task",
            requested_sink="local_audit",
        )
    )

    with pytest.raises(NotImplementedError, match="provider_placeholder"):
        ProviderPlaceholderFidesJudge().judge(facts)


def test_fides_judge_result_serialization_includes_transcript():
    transcript = "PRIVATE_JUDGE_TRANSCRIPT_SHOULD_NOT_BE_PUBLIC"
    result = FidesJudgeResult(
        verdict="unsafe",
        confidence=0.77,
        reason_codes=("semantic_policy_violation",),
        recommended_decision="block",
        judge_transcript=transcript,
    )

    public = result.to_dict()
    assert public["judge_transcript"] == transcript
