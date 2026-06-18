from pathlib import Path

import pytest

from canaryweave_fides.rule_loader import load_rule_file, load_rules
from canaryweave_fides.rule_schema import RuleValidationError, validate_rule


ROOT = Path(__file__).resolve().parents[1]


def test_load_starter_rule_validates_required_metadata():
    rules = load_rule_file(ROOT / "rules" / "agentic_boundary.war")
    rule = next(r for r in rules if r.id == "cwfr-0001")
    assert rule.name == "ServerSamplingOriginBoundary"
    assert rule.severity == "high"
    assert set(rule.facts) == {
        "from_untrusted_origin",
        "tool_call_shape",
        "capability_denied",
    }


def test_validate_rule_rejects_unknown_condition_term():
    rule_dict = {
        "name": "BrokenRule",
        "meta": {
            "id": "cwfr-test-0001",
            "severity": "high",
            "action": "block_and_audit",
            "technique": "T1059 (Execution, analogical)",
        },
        "condition": "$from_untrusted_origin and $missing_signal",
    }
    with pytest.raises(RuleValidationError, match="missing_signal"):
        validate_rule(rule_dict)


def test_load_rules_rejects_duplicate_rule_ids(tmp_path):
    src = ROOT / "rules" / "agentic_boundary.war"
    (tmp_path / "a.war").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "b.war").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="Duplicate rule id"):
        load_rules(tmp_path)
