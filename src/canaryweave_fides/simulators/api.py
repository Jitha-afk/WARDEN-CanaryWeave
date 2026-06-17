from __future__ import annotations

from canaryweave_fides.cases import AttackCase
from canaryweave_fides.gate import FidesJudge
from canaryweave_fides.simulators.base import SimulationResult, simulate_case


def simulate_api_case(case: AttackCase, fides_judge: FidesJudge | None = None) -> SimulationResult:
    """Simulate an inbound API/chat message passing through the pre-context gate."""

    return simulate_case(case, simulator="api", fides_judge=fides_judge)
