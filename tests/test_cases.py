import json

from canaryweave_fides.cases import AttackCase


def test_attack_case_public_export_excludes_private_custody_fields():
    case = AttackCase(
        case_id="case-001",
        dataset_id="synthetic",
        split="ci",
        case_kind="attack",
        attack_category="canary_flow",
        surface="mcp_resource",
        iteration_seed=7,
        raw_ref="local-only-pointer",
        safe_features={
            "length": 42,
            "sha256": "sha256:abc",
            "origin_labels": ("tool_output",),
            "_private_note": "drop-me",
        },
        policy_context={"allowed_sinks": ("local_audit",)},
        expected_behavior="block",
        private_data={"adapter_hint": "drop-me"},
    )

    public = case.to_dict()

    assert "raw_ref" not in public
    assert "private_data" not in public
    assert "_private_note" not in public["safe_features"]
    assert public["safe_features"]["origin_labels"] == ["tool_output"]
    assert public["ground_truth"]["case_kind"] == "attack"
    assert public["ground_truth"]["expected_behavior"] == "block"
    assert public["policy_context"]["allowed_sinks"] == ["local_audit"]
    json.dumps(public)


def test_attack_case_from_dict_round_trips_public_schema_without_raw_ref():
    public = {
        "case_id": "case-002",
        "dataset_id": "agentdefensebench",
        "split": "dev",
        "case_kind": "benign",
        "attack_category": "benign_control",
        "surface": "prompt",
        "safe_features": {"instruction_shape": False},
        "policy_context": {"trusted_origins": ["user"]},
        "expected_behavior": "allow",
    }

    case = AttackCase.from_dict(public)

    assert case.raw_ref is None
    assert case.iteration_seed is None
    assert case.to_dict() == {
        **public,
        "iteration_seed": None,
        "ground_truth": {
            "case_kind": "benign",
            "expected_behavior": "allow",
            "attack_category": "benign_control",
            "expected_rule_ids": [],
            "labels": {},
        },
    }


def test_ground_truth_is_separate_from_safe_features_and_normalized_facts():
    from canaryweave_fides.facts import NormalizedFacts

    case = AttackCase(
        case_id="case-label-separation",
        dataset_id="synthetic",
        split="ci",
        case_kind="attack",
        attack_category="label_only_category",
        surface="prompt",
        safe_features={"origin_labels": ["user"], "instruction_shape": False},
        policy_context={"trusted_origins": ["user"]},
        expected_behavior="block",
    )

    facts_blob = json.dumps(NormalizedFacts.from_attack_case(case).to_dict(), sort_keys=True)

    assert "label_only_category" not in facts_blob
    assert "case_kind" not in facts_blob
    assert "expected_behavior" not in facts_blob
    assert case.to_dict()["ground_truth"]["attack_category"] == "label_only_category"


def test_attack_case_private_import_keeps_raw_ref_but_never_publicly_exports_it():
    case = AttackCase.from_dict(
        {
            "case_id": "case-003",
            "dataset_id": "asb",
            "split": "holdout",
            "case_kind": "attack",
            "attack_category": "tool_misuse",
            "surface": "api_message",
            "iteration_seed": 11,
            "raw_ref": "controlled-local-pointer",
            "safe_features": {"tool_plan_shape": True},
            "policy_context": {},
            "expected_behavior": "quarantine",
            "private_data": {"adapter_hint": "local-only"},
        }
    )

    assert case.raw_ref == "controlled-local-pointer"
    assert case.private_data == {"adapter_hint": "local-only"}
    assert "raw_ref" not in case.to_dict()
    assert "private_data" not in case.to_dict()
