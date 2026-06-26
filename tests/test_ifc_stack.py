from canaryweave_fides.cases import AttackCase
from canaryweave_fides.decisions import BlockedBy, Decision, FidesVerdict, StackName
from canaryweave_fides.facts import NormalizedFacts
from canaryweave_fides.gate import evaluate_stack
from canaryweave_fides.planner import run_planner_showcase


def _facts(*, trust: str = "untrusted", origin: str = "server_sampling", **overrides):
    safe_features = {
        "origin_labels": [origin],
        "trust_labels": [trust],
        "instruction_shape": True,
        "tool_plan_shape": True,
        "requested_tool": "admin_action",
        "requested_sink": "local_audit",
    }
    safe_features.update(overrides)
    case = AttackCase(
        case_id="synthetic.ifc.001",
        dataset_id="synthetic",
        split="ci",
        case_kind="attack",
        attack_category="origin_authority_confusion",
        surface="mcp_tool",
        safe_features=safe_features,
        policy_context={
            "allowed_tools": ["read_task"],
            "allowed_sinks": ["local_audit"],
            "trusted_origins": ["user", "host_policy"],
        },
        expected_behavior="block",
        private_data={},
    )
    return NormalizedFacts.from_attack_case(case)


def test_fides_only_blocks_untrusted_consequential_action():
    decision = evaluate_stack(_facts(), StackName.FIDES_ONLY)

    assert decision.stack is StackName.FIDES_ONLY
    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.FIDES_IFC
    assert decision.ifc_verdict is FidesVerdict.UNSAFE
    assert "trusted_action" in decision.ifc_policy_checks


def test_fides_only_allows_trusted_origin():
    decision = evaluate_stack(
        _facts(trust="trusted", origin="user"), StackName.FIDES_ONLY
    )

    assert decision.decision is Decision.ALLOW
    assert decision.blocked_by is BlockedBy.NONE
    assert decision.ifc_verdict is FidesVerdict.SAFE


def test_rules_plus_fides_records_ifc_verdict_even_when_warden_blocks():
    decision = evaluate_stack(_facts(), StackName.RULES_PLUS_FIDES)

    # WARDEN fires deterministically and owns the decision ...
    assert decision.decision is Decision.BLOCK
    assert decision.blocked_by is BlockedBy.YARA_RULE
    # ... but Structural IFC is still always computed and recorded, and the
    # Semantic Judge is correctly not reached.
    assert decision.ifc_verdict is FidesVerdict.UNSAFE
    assert decision.fides_verdict is FidesVerdict.NOT_CALLED


def test_planner_showcase_disabled_returns_not_invoked():
    result = run_planner_showcase("anything", config=None, enabled=False)

    assert result.invoked is False
    assert "show-planner" in result.note


def test_planner_showcase_requires_provider_calls_enabled():
    result = run_planner_showcase("anything", config=None, enabled=True)

    assert result.invoked is False
    assert "provider-calls-enabled" in result.note
