"""CanaryWeave FIDES controlled MCP policy-rule evaluation POC."""

from .adapters import (
    AdapterConfig,
    AdapterResult,
    AdapterStatus,
    AgentDefenseBenchAdapter,
    ASBAdapter,
    DatasetAdapter,
    SyntheticAdapter,
    create_adapter,
    get_adapter_class,
    registered_adapters,
)
from .cases import AttackCase, CaseKind, ExpectedBehavior
from .decisions import BlockedBy, Decision, FidesVerdict, GateDecision, StackName
from .facts import NormalizedFacts
from .gate import (
    DisabledFidesJudge,
    FidesJudgeMode,
    FidesJudgeResult,
    ProviderPlaceholderFidesJudge,
    StaticFidesJudge,
    build_fides_judge,
    evaluate_case,
    evaluate_stack,
)

__version__ = "0.1.0"

__all__ = [
    "AdapterConfig",
    "AdapterResult",
    "AdapterStatus",
    "AgentDefenseBenchAdapter",
    "ASBAdapter",
    "AttackCase",
    "BlockedBy",
    "CaseKind",
    "DatasetAdapter",
    "Decision",
    "DisabledFidesJudge",
    "ExpectedBehavior",
    "FidesJudgeMode",
    "FidesJudgeResult",
    "FidesVerdict",
    "GateDecision",
    "NormalizedFacts",
    "ProviderPlaceholderFidesJudge",
    "StackName",
    "StaticFidesJudge",
    "SyntheticAdapter",
    "build_fides_judge",
    "evaluate_case",
    "evaluate_stack",
    "create_adapter",
    "get_adapter_class",
    "registered_adapters",
]
