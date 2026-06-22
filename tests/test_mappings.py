import pytest

from canaryweave_fides.mappings import (
    CaseRuleMapping,
    MappingValidationError,
    validate_mappings,
)


def _mapping():
    return CaseRuleMapping(
        mapping_id="map.synthetic.execution.001",
        case_id="synthetic.execution.001",
        dataset_id="synthetic",
        source_tier="synthetic",
        policy_violation_id="cwv.execution.command_or_code_execution_request",
        surface="api_message",
        origin_class="tool_output",
        impact_class=("consequential_action",),
        evasion_class="none",
        expected_behavior="block",
        expected_rule_ids=("cwfr-0106",),
        expected_fides_checks=("unsafe_execution_judge",),
        should_not_fire_rule_ids=("cwfr-0002",),
        required_fields=("features.command_execution_shape", "requested.capability"),
        required_correlation=("same_event:source_to_action",),
        benign_near_miss_controls=("bnm.developer_code_explanation_only",),
        external_mappings={
            "mitre_attack": [
                {"technique_id": "T1059", "mapping_strength": "analogical"}
            ]
        },
    )


def test_case_rule_mapping_public_export_is_payload_free():
    mapping = _mapping()
    exported = mapping.to_dict()

    assert exported["mapping_id"] == "map.synthetic.execution.001"
    assert exported["expected_rule_ids"] == ["cwfr-0106"]
    assert "raw_ref" not in str(exported).lower()
    assert "payload" not in str(exported).lower()


def test_validate_mappings_rejects_unknown_rule_id():
    mapping = _mapping()
    bad = CaseRuleMapping(
        **{**mapping.to_init_dict(), "expected_rule_ids": ("cwfr-missing",)}
    )

    with pytest.raises(MappingValidationError, match="unknown rule id"):
        validate_mappings((bad,), known_rule_ids={"cwfr-0106"})


def test_validate_mappings_requires_telemetry_and_near_miss_controls():
    mapping = _mapping()
    bad = CaseRuleMapping(
        **{
            **mapping.to_init_dict(),
            "required_fields": (),
            "benign_near_miss_controls": (),
        }
    )

    with pytest.raises(MappingValidationError, match="required_fields"):
        validate_mappings((bad,), known_rule_ids={"cwfr-0106", "cwfr-0002"})
