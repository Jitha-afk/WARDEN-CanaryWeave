from pathlib import Path

from canaryweave_fides.fixtures import smoke_cases
from canaryweave_fides.rule_engine import RuleEngine
from canaryweave_fides.rule_loader import load_rules

ROOT = Path(__file__).resolve().parents[1]


def _engine():
    return RuleEngine(load_rules(ROOT / "rules"))


def test_server_sampling_origin_boundary_hits_structural_origin_confusion():
    case = smoke_cases()["server_sampling_origin_mismatch"]
    decision = _engine().evaluate(case.trace, case.policy)
    names = [hit.rule_name for hit in decision.hits]
    assert "ServerSamplingOriginBoundary" in names
    assert decision.final_action == "block"


def test_host_authorized_tool_plan_is_allowed_by_starter_rules():
    case = smoke_cases()["host_authorized_tool_plan"]
    decision = _engine().evaluate(case.trace, case.policy)
    assert decision.final_action == "allow"
    assert list(decision.hits) == []


def test_canary_boundary_crossing_hits_only_unauthorized_sink():
    cases = smoke_cases()
    bad_decision = _engine().evaluate(
        cases["canary_boundary_crossing"].trace,
        cases["canary_boundary_crossing"].policy,
    )
    good_decision = _engine().evaluate(
        cases["canary_allowed_sink"].trace, cases["canary_allowed_sink"].policy
    )
    assert "CanaryBoundaryCrossing" in [hit.rule_name for hit in bad_decision.hits]
    assert "CanaryBoundaryCrossing" not in [hit.rule_name for hit in good_decision.hits]


def test_text_structure_rules_detect_hidden_and_untrusted_instruction_shapes():
    cases = smoke_cases()
    hidden = _engine().evaluate(
        cases["hidden_unicode_structure"].trace,
        cases["hidden_unicode_structure"].policy,
    )
    instruction_shape = _engine().evaluate(
        cases["untrusted_instruction_shape"].trace,
        cases["untrusted_instruction_shape"].policy,
    )
    assert "HiddenUnicodeStructure" in [hit.rule_name for hit in hidden.hits]
    assert "UntrustedInstructionShape" in [
        hit.rule_name for hit in instruction_shape.hits
    ]
