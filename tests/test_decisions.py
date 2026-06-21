import json

import pytest

from canaryweave_fides.decisions import (
    BlockedBy,
    Decision,
    FidesVerdict,
    GateDecision,
    StackName,
)


def test_gate_decision_defaults_are_public_safe_and_json_serializable():
    decision = GateDecision(stack=StackName.NO_GUARD, decision=Decision.ALLOW)

    public = decision.to_dict()

    assert public == {
        "stack": "no_guard",
        "decision": "allow",
        "blocked_by": "none",
        "rule_ids": [],
        "fides_verdict": "not_called",
        "reason_codes": [],
        "latency_ms": None,
        "provider_calls": 0,
    }
    json.dumps(public)


def test_gate_decision_represents_all_required_enum_values():
    assert [stack.value for stack in StackName] == [
        "no_guard",
        "regex_baseline",
        "yara_rules",
        "rules_plus_fides",
    ]
    assert [decision.value for decision in Decision] == ["allow", "quarantine", "block"]
    assert [blocked_by.value for blocked_by in BlockedBy] == [
        "regex",
        "yara_rule",
        "fides_judge",
        "none",
    ]
    assert [verdict.value for verdict in FidesVerdict] == [
        "safe",
        "unsafe",
        "uncertain",
        "disabled",
        "not_called",
    ]


def test_gate_decision_from_dict_accepts_strings_and_round_trips_lists():
    loaded = GateDecision.from_dict(
        {
            "stack": "rules_plus_fides",
            "decision": "block",
            "blocked_by": "fides_judge",
            "rule_ids": ("cwfr.mcp.prompt_boundary.untrusted_instruction_shape",),
            "fides_verdict": "unsafe",
            "reason_codes": ("fides_policy_violation",),
            "latency_ms": 12.5,
            "provider_calls": 1,
        }
    )

    assert loaded.stack is StackName.RULES_PLUS_FIDES
    assert loaded.decision is Decision.BLOCK
    assert loaded.blocked_by is BlockedBy.FIDES_JUDGE
    assert loaded.provider_calls == 1
    assert loaded.to_dict()["rule_ids"] == [
        "cwfr.mcp.prompt_boundary.untrusted_instruction_shape"
    ]
    assert loaded.to_dict()["reason_codes"] == ["fides_policy_violation"]


def test_gate_decision_rejects_inconsistent_blocker_for_allowed_decision():
    with pytest.raises(ValueError, match="allowed decisions must use blocked_by=none"):
        GateDecision(stack="regex_baseline", decision="allow", blocked_by="regex")


def test_gate_decision_rejects_negative_provider_calls():
    with pytest.raises(ValueError, match="provider_calls"):
        GateDecision(stack="rules_plus_fides", decision="quarantine", provider_calls=-1)
