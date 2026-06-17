from __future__ import annotations

from canaryweave_fides.cases import AttackCase
from canaryweave_fides.gate import FidesJudge
from canaryweave_fides.simulators.base import SimulationResult, simulate_case


def simulate_mcp_case(case: AttackCase, fides_judge: FidesJudge | None = None) -> SimulationResult:
    """Simulate MCP tool/resource/sampling content passing through the gate."""

    return simulate_case(case, simulator="mcp", fides_judge=fides_judge)
