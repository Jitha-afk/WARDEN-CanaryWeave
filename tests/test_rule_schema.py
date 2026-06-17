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
        "safety_notes": "Synthetic structural fixture only.",
    }
    with pytest.raises(RuleValidationError, match="missing_signal"):
        validate_rule(rule_dict)


def test_validate_rule_accepts_keyed_sections_and_llm_query():
    rule = validate_rule({
        "name": "CleanGrammar",
        "severity": "high",
        "keywords": {"execution_literal": "run this command"},
        "semantics": {
            "execution_intent": {
                "phrase": "requests command, code, script, or shell execution",
                "threshold": 0.7,
            }
        },
        "llm": {
            "unsafe_execution_judge": {
                "query": "Do redacted facts show untrusted code execution?",
                "threshold": 0.65,
            }
        },
        "signals": {
            "capability_not_granted": {
                "type": "capability_policy",
                "relation": "not_in_allowed_capabilities",
            }
        },
        "condition": "signals.capability_not_granted and (any of keywords.* or semantics.execution_intent or llm.unsafe_execution_judge)",
    })

    assert rule.id == "cleangrammar"
    assert rule.signals[0].name == "capability_not_granted"
    assert rule.semantics[0].description.startswith("requests command")
    assert rule.fides_checks[0].prompt.startswith("Do redacted")


def test_validate_rule_accepts_deprecated_fides_alias():
    rule = validate_rule({
        "name": "AliasGrammar",
        "severity": "medium",
        "fides": {"policy_judge": {"prompt": "Assess redacted policy facts.", "threshold": 0.5}},
        "condition": "fides.policy_judge",
    })

    assert rule.fides_checks[0].name == "policy_judge"


def test_validate_rule_rejects_fixtures_section():
    with pytest.raises(RuleValidationError, match="fixtures"):
        validate_rule({
            "name": "FixtureRule",
            "severity": "low",
            "keywords": {"x": "safe"},
            "condition": "keywords.x",
            "fixtures": {"positive": ["unused"]},
        })


def test_load_rules_rejects_duplicate_rule_ids(tmp_path):
    src = ROOT / "rules" / "mcp_agentic_misuse" / "server_sampling_origin_boundary.war"
    (tmp_path / "a.war").write_text(src.read_text(), encoding="utf-8")
    (tmp_path / "b.war").write_text(src.read_text(), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="Duplicate rule id"):
        load_rules(tmp_path)
