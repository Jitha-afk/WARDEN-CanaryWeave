from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class _StringEnum(str, Enum):
    @classmethod
    def coerce(cls, value: Any) -> Any:
        if isinstance(value, cls):
            return value
        return cls(str(value))


class CaseKind(_StringEnum):
    ATTACK = "attack"
    BENIGN = "benign"


class ExpectedBehavior(_StringEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"


@dataclass(frozen=True)
class GroundTruth:
    """Evaluation-only labels kept out of detector facts.

    WARDEN/FIDES receive NormalizedFacts derived from safe_features and
    policy_context. These labels are for scoring/reporting after decisions have
    been made, not for detection.
    """

    case_kind: CaseKind | str
    expected_behavior: ExpectedBehavior | str = ExpectedBehavior.ALLOW
    attack_category: str = "unspecified"
    expected_rule_ids: tuple[str, ...] = ()
    labels: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_kind", CaseKind.coerce(self.case_kind))
        object.__setattr__(self, "expected_behavior", ExpectedBehavior.coerce(self.expected_behavior))
        object.__setattr__(self, "attack_category", str(self.attack_category))
        object.__setattr__(self, "expected_rule_ids", tuple(str(rule_id) for rule_id in self.expected_rule_ids))
        object.__setattr__(self, "labels", _as_mapping(self.labels))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_kind": CaseKind.coerce(self.case_kind).value,
            "expected_behavior": ExpectedBehavior.coerce(self.expected_behavior).value,
            "attack_category": self.attack_category,
            "expected_rule_ids": list(self.expected_rule_ids),
            "labels": _public_safe(self.labels),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "GroundTruth":
        return cls(
            case_kind=data["case_kind"],
            expected_behavior=data.get("expected_behavior", ExpectedBehavior.ALLOW),
            attack_category=str(data.get("attack_category", "unspecified")),
            expected_rule_ids=tuple(str(rule_id) for rule_id in data.get("expected_rule_ids", ())),
            labels=_as_mapping(data.get("labels", {})),
        )


_PRIVATE_KEYS = {"raw_ref", "private_data"}


def _as_mapping(value: Mapping[str, Any] | Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    return dict(value)


def _public_safe(value: Any) -> Any:
    """Return a JSON-safe value with private adapter fields removed."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {
            str(key): _public_safe(item)
            for key, item in value.items()
            if str(key) not in _PRIVATE_KEYS and not str(key).startswith("_")
        }
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_public_safe(item) for item in value]
    return value


@dataclass(frozen=True)
class AttackCase:
    """Dataset-neutral case envelope.

    raw_ref and private_data are intentionally available for local adapters and
    intentionally absent from to_dict(), the public artifact representation.
    """

    case_id: str
    dataset_id: str
    split: str
    case_kind: CaseKind | str
    attack_category: str
    surface: str
    safe_features: Mapping[str, Any] = field(default_factory=dict)
    policy_context: Mapping[str, Any] = field(default_factory=dict)
    expected_behavior: ExpectedBehavior | str = ExpectedBehavior.ALLOW
    ground_truth: GroundTruth | Mapping[str, Any] | None = None
    iteration_seed: int | None = None
    raw_ref: str | None = field(default=None, repr=False, compare=False)
    private_data: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "case_id", str(self.case_id))
        object.__setattr__(self, "dataset_id", str(self.dataset_id))
        object.__setattr__(self, "split", str(self.split))
        object.__setattr__(self, "case_kind", CaseKind.coerce(self.case_kind))
        object.__setattr__(self, "attack_category", str(self.attack_category))
        object.__setattr__(self, "surface", str(self.surface))
        object.__setattr__(self, "expected_behavior", ExpectedBehavior.coerce(self.expected_behavior))
        if self.ground_truth is None:
            ground_truth = GroundTruth(
                case_kind=self.case_kind,
                expected_behavior=self.expected_behavior,
                attack_category=self.attack_category,
            )
        elif isinstance(self.ground_truth, GroundTruth):
            ground_truth = self.ground_truth
        else:
            ground_truth = GroundTruth.from_mapping(self.ground_truth)
        object.__setattr__(self, "ground_truth", ground_truth)
        object.__setattr__(self, "case_kind", ground_truth.case_kind)
        object.__setattr__(self, "expected_behavior", ground_truth.expected_behavior)
        object.__setattr__(self, "attack_category", ground_truth.attack_category)
        object.__setattr__(self, "safe_features", _as_mapping(self.safe_features))
        object.__setattr__(self, "policy_context", _as_mapping(self.policy_context))
        object.__setattr__(self, "private_data", _as_mapping(self.private_data))
        if self.iteration_seed is not None:
            object.__setattr__(self, "iteration_seed", int(self.iteration_seed))
        if self.raw_ref is not None:
            object.__setattr__(self, "raw_ref", str(self.raw_ref))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe export; adapter provenance keys remain excluded."""
        case_kind = CaseKind.coerce(self.case_kind)
        expected_behavior = ExpectedBehavior.coerce(self.expected_behavior)
        return {
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "split": self.split,
            "case_kind": case_kind.value,
            "attack_category": self.attack_category,
            "surface": self.surface,
            "iteration_seed": self.iteration_seed,
            "safe_features": _public_safe(self.safe_features),
            "policy_context": _public_safe(self.policy_context),
            "expected_behavior": expected_behavior.value,
            "ground_truth": self.ground_truth.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AttackCase":
        required = (
            "case_id",
            "dataset_id",
            "split",
            "case_kind",
            "attack_category",
            "surface",
            "expected_behavior",
        )
        missing = [key for key in required if key not in data]
        if missing:
            raise ValueError(f"AttackCase missing required fields: {', '.join(missing)}")
        ground_truth = data.get("ground_truth")
        if ground_truth is None:
            ground_truth = {
                "case_kind": data["case_kind"],
                "expected_behavior": data["expected_behavior"],
                "attack_category": data["attack_category"],
            }
        return cls(
            case_id=str(data["case_id"]),
            dataset_id=str(data["dataset_id"]),
            split=str(data["split"]),
            case_kind=data["case_kind"],
            attack_category=str(data["attack_category"]),
            surface=str(data["surface"]),
            iteration_seed=data.get("iteration_seed"),
            safe_features=_as_mapping(data.get("safe_features", {})),
            policy_context=_as_mapping(data.get("policy_context", {})),
            expected_behavior=data["expected_behavior"],
            ground_truth=ground_truth,
            raw_ref=data.get("raw_ref"),
            private_data=_as_mapping(data.get("private_data", {})),
        )
