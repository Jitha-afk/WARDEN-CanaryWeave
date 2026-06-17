from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class MappingValidationError(ValueError):
    pass


@dataclass(frozen=True)
class CaseRuleMapping:
    mapping_id: str
    case_id: str
    dataset_id: str
    source_tier: str
    policy_violation_id: str
    surface: str
    origin_class: str
    impact_class: tuple[str, ...]
    evasion_class: str
    expected_behavior: str
    expected_rule_ids: tuple[str, ...]
    expected_fides_checks: tuple[str, ...] = ()
    should_not_fire_rule_ids: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    required_correlation: tuple[str, ...] = ()
    benign_near_miss_controls: tuple[str, ...] = ()
    external_mappings: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key in (
            "mapping_id",
            "case_id",
            "dataset_id",
            "source_tier",
            "policy_violation_id",
            "surface",
            "origin_class",
            "evasion_class",
            "expected_behavior",
        ):
            object.__setattr__(self, key, str(getattr(self, key)))
        for key in (
            "impact_class",
            "expected_rule_ids",
            "expected_fides_checks",
            "should_not_fire_rule_ids",
            "required_fields",
            "required_correlation",
            "benign_near_miss_controls",
        ):
            object.__setattr__(self, key, tuple(str(item) for item in getattr(self, key)))
        object.__setattr__(self, "external_mappings", dict(self.external_mappings or {}))

    def to_init_dict(self) -> dict[str, Any]:
        return {
            "mapping_id": self.mapping_id,
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "source_tier": self.source_tier,
            "policy_violation_id": self.policy_violation_id,
            "surface": self.surface,
            "origin_class": self.origin_class,
            "impact_class": self.impact_class,
            "evasion_class": self.evasion_class,
            "expected_behavior": self.expected_behavior,
            "expected_rule_ids": self.expected_rule_ids,
            "expected_fides_checks": self.expected_fides_checks,
            "should_not_fire_rule_ids": self.should_not_fire_rule_ids,
            "required_fields": self.required_fields,
            "required_correlation": self.required_correlation,
            "benign_near_miss_controls": self.benign_near_miss_controls,
            "external_mappings": dict(self.external_mappings),
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.to_init_dict()
        for key in (
            "impact_class",
            "expected_rule_ids",
            "expected_fides_checks",
            "should_not_fire_rule_ids",
            "required_fields",
            "required_correlation",
            "benign_near_miss_controls",
        ):
            data[key] = list(data[key])
        return data


def validate_mappings(mappings: tuple[CaseRuleMapping, ...], *, known_rule_ids: set[str]) -> None:
    seen: set[str] = set()
    for mapping in mappings:
        if mapping.mapping_id in seen:
            raise MappingValidationError(f"duplicate mapping_id: {mapping.mapping_id}")
        seen.add(mapping.mapping_id)
        unknown_expected = set(mapping.expected_rule_ids) - known_rule_ids
        unknown_negative = set(mapping.should_not_fire_rule_ids) - known_rule_ids
        if unknown_expected or unknown_negative:
            unknown = sorted(unknown_expected | unknown_negative)
            raise MappingValidationError(f"unknown rule id in {mapping.mapping_id}: {', '.join(unknown)}")
        if not mapping.required_fields:
            raise MappingValidationError(f"{mapping.mapping_id} required_fields must not be empty")
        if not mapping.benign_near_miss_controls:
            raise MappingValidationError(f"{mapping.mapping_id} benign_near_miss_controls must not be empty")
        if mapping.expected_behavior not in {"allow", "quarantine", "block"}:
            raise MappingValidationError(f"{mapping.mapping_id} invalid expected_behavior: {mapping.expected_behavior}")
