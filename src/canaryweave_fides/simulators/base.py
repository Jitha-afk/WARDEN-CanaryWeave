from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from canaryweave_fides.cases import AttackCase
from canaryweave_fides.decisions import Decision, GateDecision, StackName
from canaryweave_fides.gate import FidesJudge, evaluate_stack
from canaryweave_fides.facts import NormalizedFacts


@dataclass(frozen=True)
class SimulationResult:
    simulator: str
    case_id: str
    dataset_id: str
    gate_decision: GateDecision
    context_entered: bool
    attack_succeeded: bool
    benign_completed: bool
    public_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulator": self.simulator,
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "gate_decision": self.gate_decision.to_dict(),
            "context_entered": self.context_entered,
            "attack_succeeded": self.attack_succeeded,
            "benign_completed": self.benign_completed,
            "public_safe": self.public_safe,
        }


def simulate_case(
    case: AttackCase, simulator: str, fides_judge: FidesJudge | None = None
) -> SimulationResult:
    facts = NormalizedFacts.from_attack_case(case)
    decision = evaluate_stack(
        facts, StackName.RULES_PLUS_FIDES, fides_judge=fides_judge
    )
    context_entered = decision.decision == Decision.ALLOW
    is_attack = case.case_kind.value == "attack"
    attack_succeeded = bool(context_entered and is_attack)
    benign_completed = bool(context_entered and not is_attack)
    return SimulationResult(
        simulator=simulator,
        case_id=case.case_id,
        dataset_id=case.dataset_id,
        gate_decision=decision,
        context_entered=context_entered,
        attack_succeeded=attack_succeeded,
        benign_completed=benign_completed,
    )
