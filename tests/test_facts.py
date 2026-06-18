import json

from canaryweave_fides.cases import AttackCase
from canaryweave_fides.facts import NormalizedFacts


def test_normalized_facts_from_attack_case_uses_safe_features_and_policy_context():
    case = AttackCase(
        case_id="case-010",
        dataset_id="synthetic",
        split="ci",
        case_kind="attack",
        attack_category="origin_authority_confusion",
        surface="mcp_tool",
        iteration_seed=3,
        raw_ref="private-pointer",
        safe_features={
            "origin_labels": ["server_sampling"],
            "role_labels": ["assistant"],
            "trust_labels": ["untrusted"],
            "instruction_shape": True,
            "tool_plan_shape": True,
            "exfiltration_shape": False,
            "obfuscated": True,
            "canary_present": False,
            "requested_tool": "admin_action",
            "requested_action": "delete_record",
            "requested_sink": "external_sink",
            "length": 128,
        },
        policy_context={
            "allowed_tools": ["read_task"],
            "allowed_sinks": ["local_audit"],
            "trusted_origins": ["user", "host_policy"],
            "protected_labels": ["canary"],
            "canary_policy": {"allowed_sinks": ["local_audit"]},
        },
        private_data={"raw_input": "raw attack prompt with CANARY_ALPHA"},
        expected_behavior="block",
    )

    facts = NormalizedFacts.from_attack_case(case)
    public = facts.to_dict()

    assert public["case_id"] == "case-010"
    assert public["origin_labels"] == ["server_sampling"]
    assert public["surface"] == "mcp_tool"
    assert public["features"]["instruction_shape"] is True
    assert public["features"]["tool_plan_shape"] is True
    assert public["features"]["obfuscated"] is True
    assert public["requested"]["tool"] == "admin_action"
    assert public["requested"]["sink"] == "external_sink"
    assert public["policy"]["allowed_tools"] == ["read_task"]
    assert public["capability"]["tool_allowed"] is False
    assert public["flow"]["sink_allowed"] is False
    assert public["text"] == "raw attack prompt with CANARY_ALPHA"
    assert "raw_ref" not in json.dumps(public)
    assert "private-pointer" not in json.dumps(public)


def test_normalized_facts_support_policy_aliases_from_existing_context_names():
    case = AttackCase(
        case_id="case-011",
        dataset_id="synthetic",
        split="ci",
        case_kind="benign",
        attack_category="benign_control",
        surface="tool_result",
        safe_features={
            "origin": "host_policy",
            "requested_capability": "summarize_note",
            "sink": "user_response",
        },
        policy_context={
            "allowed_capabilities": ("summarize_note",),
            "permitted_sinks": ("user_response",),
            "trusted_origins": ("host_policy",),
        },
        expected_behavior="allow",
    )

    facts = NormalizedFacts.from_attack_case(case)

    assert facts.origin_labels == ("host_policy",)
    assert facts.requested["capability"] == "summarize_note"
    assert facts.capability["capability_allowed"] is True
    assert facts.flow["sink_allowed"] is True
    assert facts.policy["trusted_origins"] == ("host_policy",)


def test_normalized_facts_from_dict_round_trips_json_safe_public_view():
    facts = NormalizedFacts(
        case_id="case-012",
        dataset_id="synthetic",
        split="ci",
        surface="prompt",
        origin_labels=("resource_content",),
        trust_labels=("untrusted",),
        role_labels=("user",),
        features={"obfuscated": True},
        requested={"sink": "local_audit"},
        policy={"allowed_sinks": ("local_audit",)},
        capability={"tool_allowed": None},
        flow={"sink_allowed": True},
        text="raw note",
    )

    loaded = NormalizedFacts.from_dict(facts.to_dict())

    assert loaded == facts
    json.dumps(loaded.to_dict())
