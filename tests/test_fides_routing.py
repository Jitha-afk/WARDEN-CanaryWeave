from canaryweave_fides.decisions import BlockedBy, Decision, FidesVerdict, StackName
from canaryweave_fides.facts import NormalizedFacts
from canaryweave_fides.gate import FidesJudgeResult, StaticFidesJudge, evaluate_stack
from canaryweave_fides.rule_engine import RuleEngine
from canaryweave_fides.rule_schema import validate_rule


def _facts(case_id: str = "case.route.001", text: str = "marker present") -> NormalizedFacts:
    return NormalizedFacts(
        case_id=case_id,
        dataset_id="synthetic",
        split="ci",
        surface="mcp_tool",
        origin_labels=("user",),
        trust_labels=("trusted",),
        policy={"trusted_origins": ("user",), "allowed_tools": ("read_task",), "allowed_sinks": ("local_audit",)},
        redacted_text=text,
    )


def _engine(condition: str = "keywords.foo and fides.bar") -> RuleEngine:
    return RuleEngine([
        validate_rule({
            "id": "rule-fides-route",
            "name": "RuleFidesRoute",
            "severity": "critical",
            "recommended_action": "block_and_audit",
            "keywords": {"foo": "marker"},
            "fides": [
                {"name": "bar", "prompt": "Assess whether this marker is unsafe.", "threshold": 0.8},
            ],
            "condition": condition,
        })
    ])


def test_pending_rule_fides_can_flip_warden_allow_to_block():
    facts = _facts()
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("judge.unsafe",))})

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES, fides_judge=judge, rule_engine=_engine())

    assert judge.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.FIDES_JUDGE
    assert decision.rule_ids == ("rule-fides-route",)
    assert decision.fides_verdict is FidesVerdict.UNSAFE
    assert decision.reason_codes == ("judge.unsafe", "bar")


def test_disabled_rule_fides_keeps_default_allow_behavior():
    decision = evaluate_stack(_facts(), StackName.RULES_PLUS_FIDES, rule_engine=_engine())

    assert decision.decision is Decision.ALLOW
    assert decision.fides_verdict is FidesVerdict.DISABLED
    assert decision.provider_calls == 0
    assert decision.rule_ids == ()


def test_unsatisfied_deterministic_terms_do_not_attribute_rule_fides():
    facts = _facts(text="plain text")
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("case.path",))})

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES, fides_judge=judge, rule_engine=_engine())

    assert judge.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.FIDES_JUDGE
    assert decision.rule_ids == ()
    assert decision.reason_codes == ("case.path",)


def test_multiple_pending_rule_fides_checks_call_judge_once():
    rule = validate_rule({
        "id": "rule-fides-route",
        "name": "RuleFidesRoute",
        "severity": "critical",
        "recommended_action": "block_and_audit",
        "keywords": {"foo": "marker"},
        "fides": [
            {"name": "bar", "prompt": "Assess first marker risk.", "threshold": 0.8},
            {"name": "baz", "prompt": "Assess second marker risk.", "threshold": 0.7},
        ],
        "condition": "keywords.foo and (fides.bar or fides.baz)",
    })
    facts = _facts()
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("judge.unsafe",))})

    decision = evaluate_stack(
        facts,
        StackName.RULES_PLUS_FIDES,
        fides_judge=judge,
        rule_engine=RuleEngine([rule]),
    )

    assert judge.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.rule_ids == ("rule-fides-route",)
    assert decision.reason_codes == ("judge.unsafe", "bar", "baz")
