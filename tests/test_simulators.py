from canaryweave_fides.adapters import AdapterConfig, SyntheticAdapter
from canaryweave_fides.decisions import Decision
from canaryweave_fides.gate import StaticFidesJudge
from canaryweave_fides.simulators.api import simulate_api_case
from canaryweave_fides.simulators.mcp import simulate_mcp_case


def _cases():
    return SyntheticAdapter(AdapterConfig()).load().cases


def test_api_simulation_applies_gate_before_context_entry():
    attack = next(case for case in _cases() if case.case_kind.value == "attack")

    result = simulate_api_case(attack, fides_judge=StaticFidesJudge({}))

    assert result.simulator == "api"
    assert result.gate_decision.decision in {Decision.BLOCK, Decision.QUARANTINE}
    assert result.context_entered is False
    assert result.attack_succeeded is False
    assert result.to_dict()["public_safe"] is True


def test_mcp_simulation_allows_benign_case_to_context():
    benign = next(case for case in _cases() if case.case_kind.value == "benign")

    result = simulate_mcp_case(benign, fides_judge=StaticFidesJudge({}))

    assert result.simulator == "mcp"
    assert result.gate_decision.decision is Decision.ALLOW
    assert result.context_entered is True
    assert result.attack_succeeded is False
    assert result.benign_completed is True
