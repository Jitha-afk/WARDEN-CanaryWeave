from __future__ import annotations

from typing import Mapping, Type

from .agentdefensebench import AgentDefenseBenchAdapter
from .asb import ASBAdapter
from .base import AdapterConfig, AdapterResult, AdapterStatus, DatasetAdapter
from .synthetic import SyntheticAdapter

_ADAPTERS: dict[str, Type[DatasetAdapter]] = {
    "agentdefensebench": AgentDefenseBenchAdapter,
    "asb": ASBAdapter,
    "synthetic": SyntheticAdapter,
}


def registered_adapters() -> tuple[str, ...]:
    """Return stable registry names for available dataset adapters."""

    return tuple(sorted(_ADAPTERS))


def get_adapter_class(name: str) -> Type[DatasetAdapter]:
    """Return the adapter class registered for name."""

    key = str(name).lower().replace("-", "_")
    aliases = {
        "agent_defense_bench": "agentdefensebench",
        "adb": "agentdefensebench",
    }
    key = aliases.get(key, key)
    try:
        return _ADAPTERS[key]
    except KeyError as exc:
        raise KeyError(f"unknown dataset adapter: {name}") from exc


def create_adapter(
    name: str, config: AdapterConfig | Mapping[str, object] | None = None
) -> DatasetAdapter:
    """Instantiate a registered dataset adapter."""

    return get_adapter_class(name)(config)


__all__ = [
    "AdapterConfig",
    "AdapterResult",
    "AdapterStatus",
    "AgentDefenseBenchAdapter",
    "ASBAdapter",
    "DatasetAdapter",
    "SyntheticAdapter",
    "create_adapter",
    "get_adapter_class",
    "registered_adapters",
]
