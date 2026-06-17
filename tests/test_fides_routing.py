from canaryweave_fides.decisions import BlockedBy, Decision, FidesVerdict, StackName
from canaryweave_fides.facts import NormalizedFacts
from canaryweave_fides.gate import FidesJudgeResult, StaticFidesJudge, evaluate_stack
from canaryweave_fides.rule_engine import RuleEngine
from canaryweave_fides.rule_loader import parse_ruleset


_RULE_TEMPLATE = """rule RuleFidesRoute {{
    meta:
        id          = cwfr-route-0001
        kind        = policy
        severity    = critical
        action      = block_and_audit
        technique   = T1059 (Execution, analogical)
        description = "FIDES routing test rule."
    patterns:
        $foo = "marker"
    judge:
{judge}
    condition:
        {condition}
}}
"""

_DEFAULT_JUDGE = '        $bar = "Assess whether this marker is unsafe." (0.80)'


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


def _engine(condition: str = "$foo and $bar", judge: str = _DEFAULT_JUDGE) -> RuleEngine:
    text = _RULE_TEMPLATE.format(judge=judge, condition=condition)
    return RuleEngine(list(parse_ruleset(text)))


def test_pending_rule_fides_can_flip_warden_allow_to_block():
    facts = _facts()
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("judge.unsafe",))})

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES, fides_judge=judge, rule_engine=_engine())

    assert judge.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.FIDES_JUDGE
    assert decision.rule_ids == ("cwfr-route-0001",)
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
    judge_block = (
        '        $bar = "Assess first marker risk." (0.80)\n'
        '        $baz = "Assess second marker risk." (0.70)'
    )
    engine = _engine(condition="$foo and ($bar or $baz)", judge=judge_block)
    facts = _facts()
    judge = StaticFidesJudge({facts.case_id: FidesJudgeResult(verdict="unsafe", reason_codes=("judge.unsafe",))})

    decision = evaluate_stack(facts, StackName.RULES_PLUS_FIDES, fides_judge=judge, rule_engine=engine)

    assert judge.calls == 1
    assert decision.decision is Decision.BLOCK
    assert decision.rule_ids == ("cwfr-route-0001",)
    assert decision.reason_codes == ("judge.unsafe", "bar", "baz")
