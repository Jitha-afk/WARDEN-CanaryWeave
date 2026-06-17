from pathlib import Path

import pytest

from canaryweave_fides.rule_loader import load_rule_file, load_rules
from canaryweave_fides.rule_schema import RuleValidationError, validate_rule


ROOT = Path(__file__).resolve().parents[1]


def test_load_starter_rule_validates_required_metadata():
    rule = load_rule_file(ROOT / "rules" / "mcp_agentic_misuse" / "server_sampling_origin_boundary.war")
    assert rule.id == "cwfr-0001"
    assert rule.name == "ServerSamplingOriginBoundary"
    assert rule.severity == "high"
    assert {signal.name for signal in rule.signals} == {
        "source_is_server_sampling",
        "output_is_tool_plan_shape",
        "capability_not_granted",
    }


def test_validate_rule_rejects_unknown_condition_signal():
    rule_dict = {
        "id": "cwfr-test",
        "name": "BrokenRule",
        "version": "0.1.0",
        "category": "mcp_agentic_misuse/origin_authority_confusion",
        "severity": "high",
        "scope": "event_window",
        "description": "Broken condition reference.",
        "signals": [{"name": "known", "type": "event_field_equals", "field": "origin", "value": "server"}],
        "condition": "known and missing_signal",
        "recommended_action": "block_and_audit",
        "fixtures": {"positive": [], "negative": []},
        "safety_notes": "Synthetic structural fixture only.",
    }
    with pytest.raises(RuleValidationError, match="missing_signal"):
        validate_rule(rule_dict)


def test_load_rules_rejects_duplicate_rule_ids(tmp_path):
    src = ROOT / "rules" / "mcp_agentic_misuse" / "server_sampling_origin_boundary.war"
    (tmp_path / "a.war").write_text(src.read_text(), encoding="utf-8")
    (tmp_path / "b.war").write_text(src.read_text(), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="Duplicate rule id"):
        load_rules(tmp_path)
