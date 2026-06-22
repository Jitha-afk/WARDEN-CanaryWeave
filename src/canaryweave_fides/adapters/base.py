from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from canaryweave_fides.cases import AttackCase


class AdapterStatus(str, Enum):
    """Explicit adapter load status for optional local datasets."""

    LOADED = "loaded"
    EMPTY = "empty"
    SKIPPED_DISABLED = "skipped_disabled"
    SKIPPED_MISSING_LOCAL_PATH = "skipped_missing_local_path"

    @classmethod
    def coerce(cls, value: "AdapterStatus | str") -> "AdapterStatus":
        if isinstance(value, cls):
            return value
        return cls(str(value))


@dataclass(frozen=True)
class AdapterConfig:
    """Runtime configuration shared by dataset adapters.

    root is a private local dataset location. It is intentionally not exported by
    AttackCase.to_dict(); adapters only use it to discover local records.
    """

    root: Path | str | None = None
    split: str | None = None
    enabled: bool = True
    required: bool = False
    max_cases: int | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.root is not None and not isinstance(self.root, Path):
            object.__setattr__(self, "root", Path(self.root))
        if self.split is not None:
            object.__setattr__(self, "split", str(self.split))
        if self.max_cases is not None:
            object.__setattr__(self, "max_cases", int(self.max_cases))
        object.__setattr__(self, "options", dict(self.options or {}))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "AdapterConfig":
        if value is None:
            return cls()
        return cls(
            root=value.get("root") or value.get("path") or value.get("local_path"),
            split=value.get("split"),
            enabled=bool(value.get("enabled", True)),
            required=bool(value.get("required", False)),
            max_cases=value.get("max_cases"),
            options={
                key: item
                for key, item in value.items()
                if key
                not in {
                    "root",
                    "path",
                    "local_path",
                    "split",
                    "enabled",
                    "required",
                    "max_cases",
                }
            },
        )


@dataclass(frozen=True)
class AdapterResult:
    """Adapter output envelope with explicit skip/load status."""

    dataset_id: str
    status: AdapterStatus | str
    cases: Sequence[AttackCase] = ()
    message: str = ""
    safe_metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "dataset_id", str(self.dataset_id))
        object.__setattr__(self, "status", AdapterStatus.coerce(self.status))
        object.__setattr__(self, "cases", tuple(self.cases))
        object.__setattr__(self, "safe_metadata", dict(self.safe_metadata or {}))
        for case in self.cases:
            if not isinstance(case, AttackCase):
                raise TypeError(
                    f"adapter {self.dataset_id} returned non-AttackCase item: {type(case)!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        status = AdapterStatus.coerce(self.status)
        return {
            "dataset_id": self.dataset_id,
            "status": status.value,
            "case_count": len(self.cases),
            "message": self.message,
            "safe_metadata": dict(self.safe_metadata),
            "cases": [case.to_dict() for case in self.cases],
        }


class DatasetAdapter(ABC):
    """Base class for dataset-specific AttackCase adapters."""

    dataset_id: str
    default_env_var: str | None = None

    def __init__(self, config: AdapterConfig | Mapping[str, Any] | None = None) -> None:
        if isinstance(config, AdapterConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = AdapterConfig.from_mapping(config)
        else:
            self.config = AdapterConfig()

    def configured_root(self) -> Path | None:
        if self.config.root is not None:
            return Path(self.config.root)
        if self.default_env_var:
            value = os.environ.get(self.default_env_var)
            if value:
                return Path(value)
        return None

    def missing_result(self, root: Path | None = None) -> AdapterResult:
        return AdapterResult(
            dataset_id=self.dataset_id,
            status=AdapterStatus.SKIPPED_MISSING_LOCAL_PATH,
            cases=(),
            message=f"{self.dataset_id} skipped: missing configured local dataset path",
        )

    def disabled_result(self) -> AdapterResult:
        return AdapterResult(
            dataset_id=self.dataset_id,
            status=AdapterStatus.SKIPPED_DISABLED,
            cases=(),
            message=f"{self.dataset_id} skipped: adapter disabled",
        )

    @abstractmethod
    def load(self) -> AdapterResult:
        """Load dataset records as AttackCase objects or return an explicit skip."""
